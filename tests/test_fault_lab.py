"""fault_lab.py — inject/revert against a fake Meraki API and a real temp SQLite DB.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import copy
import json
import sqlite3
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import fault_lab as fl   # noqa: E402
# Imported here, not inside a fixture: importing dashboard points fault_lab.DB_PATH
# at the live data/pod_state.db, so it must happen before the fixtures re-point it.
import dashboard as d    # noqa: E402

LIVE_DB = str(d.DB_PATH)

ORG = "501"
NAT_SSID = {"number": 1, "name": "Corp", "enabled": True, "ipAssignmentMode": "NAT mode"}
BRIDGED_SSID = {"number": 1, "name": "Corp", "enabled": True, "ipAssignmentMode": "Bridge mode",
                "useVlanTagging": True, "defaultVlanId": 20}
# What Cloud Fabric leaves on a leaf: 802.1X on 1 and 3, plain access on 2 and 4.
DOT1X_PORT = {"enabled": True, "type": "access", "vlan": 10, "accessPolicyType": "Custom access policy",
              "accessPolicyNumber": 1}
OPEN_PORT = {"enabled": True, "type": "access", "vlan": 10, "accessPolicyType": "Open"}
LAB_RULE = {"comment": "Block guest to mgmt", "policy": "deny", "protocol": "any", "destPort": "any",
            "destCidr": "198.18.1.0/24"}
SWITCH_RULE = {"comment": "Block IoT to mgmt", "policy": "deny", "ipVersion": "ipv4", "protocol": "any",
               "srcCidr": "10.102.255.0/24", "srcPort": "any", "dstCidr": "198.18.1.0/24", "dstPort": "any",
               "vlan": "any"}
# Some API versions append this built-in to a GET; it must never be PUT back.
DEFAULT_RULE = {"comment": "Default rule", "policy": "allow", "protocol": "any", "destPort": "any", "destCidr": "any"}
LEAF_PORTS = {"1": DOT1X_PORT, "2": OPEN_PORT, "3": DOT1X_PORT, "4": OPEN_PORT}


class FakeMeraki:
    """One org: wireless+switch network L_1 (SSID 1 enabled, SSID 2 disabled) with
    leaves LEAF-1 / LEAF-2 and a spine. L_9 and switch OTHER-1 belong to another org.

    fail_put_paths: PUTs to these paths raise; fail_all_puts: every PUT raises."""

    def __init__(self, ssid=NAT_SSID, ports=LEAF_PORTS):
        self.ssids = {1: dict(ssid), 2: {"number": 2, "name": "Guest", "enabled": False}}
        # One dict per port: deepcopy would keep ports 1 and 3 sharing DOT1X_PORT.
        self.ports = {s: {p: copy.deepcopy(v) for p, v in ports.items()} for s in ("LEAF-1", "LEAF-2")}
        self.l3 = {"rules": [dict(LAB_RULE)], "allowLanAccess": False}
        self.acl = {"rules": [dict(SWITCH_RULE)]}
        self.neighbours = {"2": "AP-1", "6": "dcloud-nexus", "47": "Site_105-Border-Spine"}
        self.puts = []
        self.fail_put_paths = set()
        self.fail_all_puts = False

    def _put(self, path, body, store):
        if self.fail_all_puts or path in self.fail_put_paths:
            raise fl.FaultLabError(f"PUT {path} → 400")
        self.puts.append((path, body))
        store.update(body)
        return store

    def call(self, method, path, body=None, params=None):
        if method == "GET" and path == f"/organizations/{ORG}/networks":
            return [{"id": "L_1", "name": "SITE_105", "productTypes": ["switch", "wireless"]},
                    {"id": "L_2", "name": "Lab", "productTypes": ["switch"]}]
        if method == "GET" and path == f"/organizations/{ORG}/devices":
            return [{"serial": "LEAF-1", "name": "Site_105-Leaf1", "networkId": "L_1"},
                    {"serial": "LEAF-2", "name": "Site_105-Leaf2", "networkId": "L_1"},
                    {"serial": "SPINE-1", "name": "Site_105-Border-Spine", "networkId": "L_1"}]
        if method == "GET" and path in ("/networks/L_1", "/networks/L_9"):
            nid = path.rsplit("/", 1)[1]
            return {"id": nid, "name": "SITE_105" if nid == "L_1" else "Other",
                    "organizationId": ORG if nid == "L_1" else "999"}
        if method == "GET" and path.startswith("/devices/") and path.count("/") == 2:
            serial = path.rsplit("/", 1)[1]
            return {"serial": serial, "name": serial, "networkId": "L_9" if serial == "OTHER-1" else "L_1"}
        if method == "GET" and path == "/networks/L_1/wireless/ssids":
            return list(self.ssids.values())
        if path == "/networks/L_1/switch/accessControlLists":
            if method == "GET":
                return {"rules": [dict(r) for r in self.acl["rules"]] + [dict(DEFAULT_RULE)]}
            return self._put(path, body, self.acl)
        if path == "/networks/L_1/wireless/ssids/1/firewall/l3FirewallRules":
            if method == "GET":
                return {"rules": [dict(r) for r in self.l3["rules"]] + [dict(DEFAULT_RULE)],
                        "allowLanAccess": self.l3["allowLanAccess"]}
            return self._put(path, body, self.l3)
        if path.startswith("/networks/L_1/wireless/ssids/"):
            num = int(path.rsplit("/", 1)[1])
            return dict(self.ssids[num]) if method == "GET" else self._put(path, body, self.ssids[num])
        if path.endswith("/lldpCdp"):
            return {"ports": {p: {"cdp": {"deviceId": n}} for p, n in self.neighbours.items()}}
        if "/switch/ports/" in path:
            serial, port = path.split("/")[2], path.rsplit("/", 1)[1]
            store = self.ports[serial][port]
            return dict(store) if method == "GET" else self._put(path, body, store)
        raise AssertionError(f"unexpected {method} {path}")

    def port_puts(self):
        return [p.rsplit("/", 1)[1] for p, _ in self.puts if "/switch/ports/" in p]


@pytest.fixture(autouse=True)
def db(tmp_path, monkeypatch):
    path = tmp_path / "pod_state.db"
    sqlite3.connect(path).close()
    monkeypatch.setattr(fl, "DB_PATH", str(path))
    monkeypatch.setattr(d, "DB_PATH", path)
    monkeypatch.setenv("FAULTLAB_BLACKHOLE_VLAN", "999")
    yield str(path)
    assert fl.DB_PATH != LIVE_DB      # a test must never write to the live database


def ctx(**kw):
    return FakeMeraki(**kw), ORG


def rows():
    return fl._db("faultlab_list")


SSID_1 = {"network_id": "L_1", "ssid": 1}


# ── targets ───────────────────────────────────────────────────────────────────

def test_ssid_targets_list_only_wireless_networks_and_enabled_ssids():
    assert fl.wireless_targets(*ctx()) == [
        {"network_id": "L_1", "network_name": "SITE_105", "ssids": [{"number": 1, "name": "Corp"}]}]


def test_leaf_targets_fall_back_to_names_when_cloud_fabric_never_ran():
    leaves = fl.leaf_targets(*ctx(), "POD-6")
    assert [(l["role"], l["serial"]) for l in leaves] == [("leaf1", "LEAF-1"), ("leaf2", "LEAF-2")]  # no spine


def test_leaf_targets_prefer_recorded_cloud_ids():
    fl._db("cloudfabric_ensure_table")
    fl._db("cloudfabric_device_set", pod_id="POD-6", role="leaf2", serial="LEAF-2")
    fl._db("cloudfabric_device_set", pod_id="POD-6", role="border_spine", serial="SPINE-1")
    assert fl.leaf_targets(*ctx(), "POD-6") == [
        {"role": "leaf2", "serial": "LEAF-2", "name": "Site_105-Leaf2", "network_id": "L_1",
         "host_ports": ["1", "3", "4"]}]


# ── wireless ──────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("original", [NAT_SSID, BRIDGED_SSID])
def test_ssid_inject_then_revert_restores_original(original):
    c = ctx(ssid=original)
    rec = fl.inject("POD-6", "dhcp_failure", SSID_1, 30, _context=c)
    api = c[0]
    assert rec["status"] == "active" and rec["network_name"] == "SITE_105 / Corp"
    assert (api.ssids[1]["ipAssignmentMode"], api.ssids[1]["defaultVlanId"]) == ("Bridge mode", 999)

    fl.revert(rec["id"], _context=c)
    assert api.ssids[1]["ipAssignmentMode"] == original["ipAssignmentMode"]
    if original["ipAssignmentMode"] == "Bridge mode":
        assert api.ssids[1]["defaultVlanId"] == 20
    else:
        assert "defaultVlanId" not in api.puts[-1][1]   # never send a field the SSID lacked
    assert rows() == []


def test_network_from_another_org_is_refused():
    c = ctx()
    with pytest.raises(fl.FaultLabError, match="not in this POD's org"):
        fl.inject("POD-6", "dhcp_failure", {"network_id": "L_9", "ssid": 1}, 30, _context=c)
    assert c[0].puts == [] and rows() == []


def test_double_inject_refused_so_snapshot_is_never_the_faulted_state():
    c = ctx()
    fl.inject("POD-6", "dhcp_failure", SSID_1, 30, _context=c)
    with pytest.raises(fl.FaultLabError, match="already active"):
        fl.inject("POD-6", "dhcp_failure", {"network_id": "L_1", "ssid": "1"}, 30, _context=c)
    assert len(rows()) == 1


def test_failed_inject_is_undone_and_leaves_no_record():
    c = ctx()
    api = c[0]
    orig_put = api._put

    def fail_first_put_only(path, body, store):
        if body.get("defaultVlanId") == 999:          # the inject PUT; the undo PUT succeeds
            raise fl.FaultLabError("PUT → 400")
        return orig_put(path, body, store)

    api._put = fail_first_put_only
    with pytest.raises(fl.FaultLabError):
        fl.inject("POD-6", "dhcp_failure", SSID_1, 30, _context=c)
    assert rows() == []
    assert api.ssids[1]["ipAssignmentMode"] == "NAT mode"


def test_failed_inject_whose_undo_also_fails_is_kept_for_revert():
    c = ctx()
    c[0].fail_all_puts = True
    with pytest.raises(fl.FaultLabError):
        fl.inject("POD-6", "dhcp_failure", SSID_1, 30, _context=c)
    [left] = rows()
    assert left["status"] == "revert_failed" and "undo failed" in left["last_error"]


def test_failed_revert_keeps_the_record_marked():
    c = ctx()
    rec = fl.inject("POD-6", "dhcp_failure", SSID_1, 30, _context=c)
    c[0].fail_all_puts = True
    with pytest.raises(fl.FaultLabError):
        fl.revert(rec["id"], _context=c)
    [left] = rows()
    assert left["status"] == "revert_failed" and "400" in left["last_error"]
    assert json.loads(left["snapshot"])["ipAssignmentMode"] == "NAT mode"


# ── wired (leaf host ports) ───────────────────────────────────────────────────

def test_wired_inject_skips_the_ap_port_and_revert_restores_802_1x():
    c = ctx()
    api = c[0]
    rec = fl.inject("POD-6", "wired_dhcp_failure", {"serial": "LEAF-1", "ports": ["2"]}, 30, _context=c)
    assert rec["network_name"] == "LEAF-1 ports 1, 3, 4"          # port 2 has the AP (CDP neighbour)
    assert json.loads(rec["target"]) == {"serial": "LEAF-1"}     # ports from the request are ignored
    assert sorted(api.port_puts()) == ["1", "3", "4"]
    for port in ("1", "3", "4"):
        assert (api.ports["LEAF-1"][port]["vlan"], api.ports["LEAF-1"][port]["accessPolicyType"]) == (999, "Open")
    assert api.ports["LEAF-1"]["2"] == OPEN_PORT                 # the AP port is untouched

    fl.revert(rec["id"], _context=c)
    assert api.ports["LEAF-1"] == LEAF_PORTS
    assert "2" not in api.port_puts()
    # accessPolicyNumber only goes back where a custom policy was in place
    reverts = {p.rsplit("/", 1)[1]: b for p, b in api.puts[3:]}
    assert reverts["1"]["accessPolicyNumber"] == 1 and "accessPolicyNumber" not in reverts["4"]
    assert rows() == []


def test_host_ports_are_decided_by_neighbours_not_by_number():
    c = ctx()
    api = c[0]
    api.neighbours = {"3": "AP-9"}                                # a POD cabled the way the guide says
    assert fl.leaf_host_ports(api, "LEAF-1") == ["1", "2", "4"]
    api.neighbours = {p: "AP" for p in fl.LEAF_CANDIDATE_PORTS}
    with pytest.raises(fl.FaultLabError, match="no host ports"):
        fl.inject("POD-6", "wired_port_down", {"serial": "LEAF-1"}, 30, _context=c)
    assert api.puts == [] and rows() == []


def test_ports_outside_the_access_block_are_refused_even_from_a_tampered_snapshot():
    c = ctx()
    sc = fl.WiredDhcpFailure(c[0])
    with pytest.raises(fl.FaultLabError, match="refusing to touch port 47"):
        sc.revert({"serial": "LEAF-1"}, {"47": OPEN_PORT})
    assert c[0].puts == []


def test_wired_partial_inject_failure_undoes_the_ports_already_changed():
    c = ctx()
    api = c[0]
    orig_put = api._put

    def fail_port_3_inject(path, body, store):
        if path.endswith("/ports/3") and body.get("vlan") == 999:   # only the inject PUT fails
            raise fl.FaultLabError("PUT → 400")
        return orig_put(path, body, store)

    api._put = fail_port_3_inject
    with pytest.raises(fl.FaultLabError):
        fl.inject("POD-6", "wired_dhcp_failure", {"serial": "LEAF-1"}, 30, _context=c)
    assert api.ports["LEAF-1"] == LEAF_PORTS            # port 1 was changed, then put back
    assert "2" not in api.port_puts()
    assert rows() == []


def test_trunk_ports_are_skipped():
    ports = {**LEAF_PORTS, "3": {"type": "trunk", "vlan": 1, "accessPolicyType": "Open"}}
    c = ctx(ports=ports)
    rec = fl.inject("POD-6", "wired_port_down", {"serial": "LEAF-1"}, 30, _context=c)
    assert rec["network_name"] == "LEAF-1 ports 1, 4"
    assert sorted(c[0].port_puts()) == ["1", "4"]


def test_switch_from_another_org_is_refused():
    c = ctx()
    with pytest.raises(fl.FaultLabError, match="not in this POD's org"):
        fl.inject("POD-6", "wired_dhcp_failure", {"serial": "OTHER-1"}, 30, _context=c)
    assert c[0].puts == []


# ── bulk ──────────────────────────────────────────────────────────────────────

def test_revert_all_expired_only_touches_expired(monkeypatch):
    c = ctx()
    monkeypatch.setattr(fl, "pod_context", lambda pod_id: c)
    fresh = fl.inject("POD-6", "wired_dhcp_failure", {"serial": "LEAF-2"}, 30, _context=c)
    old = fl.inject("POD-6", "dhcp_failure", SSID_1, 30, _context=c)
    fl._db("faultlab_delete", record_id=old["id"])
    fl._db("faultlab_add", **{**{k: old[k] for k in ("pod_id", "scenario", "target", "network_name",
                                                     "snapshot", "injected_at")},
                              "id": "expired1", "expires_at": "2000-01-01T00:00:00Z"})
    fl._db("faultlab_set_status", record_id="expired1", status="active")
    assert fl.revert_all(expired_only=True) == (["expired1"], [])
    assert [r["id"] for r in rows()] == [fresh["id"]]


def test_targets_for_pods_reports_each_pod_separately(monkeypatch):
    c = ctx()

    def per_pod(pod_id):
        if pod_id == "POD-9":
            raise fl.FaultLabError("org_credentials.meraki_org_id is empty for this POD's org")
        return c

    monkeypatch.setattr(fl, "pod_context", per_pod)
    found = fl.targets_for_pods(["POD-6", "POD-9"])
    assert [l["serial"] for l in found["POD-6"]["targets"]["leaf"]] == ["LEAF-1", "LEAF-2"]
    assert "meraki_org_id is empty" in found["POD-9"]["error"]     # one bad POD does not sink the rest


# ── dashboard routes + teardown ───────────────────────────────────────────────

@pytest.fixture
def client(db, monkeypatch):
    c = sqlite3.connect(db)
    c.executescript("""
        CREATE TABLE IF NOT EXISTS pods (pod_id TEXT PRIMARY KEY, pod_number TEXT);
        CREATE TABLE IF NOT EXISTS pipeline_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, pod_id TEXT,
            log_line TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
        INSERT OR IGNORE INTO pods VALUES ('POD-6', '17');
    """)
    c.commit(); c.close()
    fake = ctx()
    monkeypatch.setattr(fl, "pod_context", lambda pod_id: fake)
    return d.app.test_client(), fake[0]


def test_routes_inject_status_revert(client):
    http, api = client
    r = http.post("/api/faultlab/inject/POD-6", json={"scenario": "wired_dhcp_failure", "target": {"serial": "LEAF-1"}})
    assert r.status_code == 200, r.json
    [inj] = http.get("/api/faultlab/status/POD-6").json["injections"]
    assert inj["target"] == {"serial": "LEAF-1"} and "snapshot" not in inj
    assert api.ports["LEAF-1"]["1"]["vlan"] == 999

    assert http.post(f"/api/faultlab/revert/{inj['id']}").status_code == 200
    status = http.get("/api/faultlab/status/POD-6").json
    assert status["injections"] == []
    assert any("reverted wired_dhcp_failure" in l["line"] for l in status["logs"])   # landed in the POD's log


def test_targets_route_returns_ssids_and_leaves(client):
    http, _ = client
    t = http.get("/api/faultlab/targets/POD-6").json["targets"]
    assert [n["network_id"] for n in t["ssid"]] == ["L_1"]
    assert [l["serial"] for l in t["leaf"]] == ["LEAF-1", "LEAF-2"]
    assert t["dns_server"] == [{"server": "198.18.5.102", "name": "AD1"}]


def test_route_refuses_foreign_network_with_400(client):
    http, api = client
    r = http.post("/api/faultlab/inject/POD-6", json={"scenario": "dhcp_failure", "target": {"network_id": "L_9", "ssid": 1}})
    assert r.status_code == 400 and "not in this POD's org" in r.json["message"]
    assert api.puts == []


def test_class_targets_route_lists_every_pod(client):
    http, _ = client
    [pod] = http.get("/api/faultlab/class-targets").json["pods"]
    assert pod["pod_id"] == "POD-6" and pod["pod_number"] == "17"
    assert [l["serial"] for l in pod["targets"]["leaf"]] == ["LEAF-1", "LEAF-2"]


def test_class_inject_uses_the_explicit_per_pod_targets(client):
    import time
    http, api = client
    assert http.post("/api/faultlab/class-inject", json={"scenario": "wired_dhcp_failure", "items": []}).status_code == 400
    r = http.post("/api/faultlab/class-inject", json={"scenario": "wired_dhcp_failure", "items": [
        {"pod_id": "POD-6", "targets": [{"serial": "LEAF-1"}, {"serial": "LEAF-2"}]}]})
    assert r.status_code == 200
    for _ in range(100):
        if not d._FAULTLAB_CLASS["busy"] and d._FAULTLAB_CLASS["results"]:
            break
        time.sleep(0.02)
    assert d._FAULTLAB_CLASS["results"] == [{"pod_id": "POD-6", "ok": True, "message": "2 target(s) faulted"}]
    assert len(rows()) == 2 and "2" not in api.port_puts()


def test_teardown_reverts_and_reports_failures(client):
    http, api = client
    http.post("/api/faultlab/inject/POD-6", json={"scenario": "dhcp_failure", "target": SSID_1})
    api.fail_all_puts = True
    steps, errors = d._faultlab_teardown("POD-6")
    assert steps == [] and len(errors) == 1 and "revert FAILED" in errors[0]
    assert rows()[0]["status"] == "revert_failed"        # kept, so the fault is not forgotten
    api.fail_all_puts = False
    steps, errors = d._faultlab_teardown()
    assert steps == ["fault lab: reverted 1 injection(s)"] and errors == []
    assert api.ssids[1]["ipAssignmentMode"] == "NAT mode"


# ── more scenarios ────────────────────────────────────────────────────────────

def test_catalog_lists_every_scenario_with_its_target_kind():
    assert {c["name"]: c["target_kind"] for c in fl.scenario_catalog()} == {
        "dhcp_failure": "ssid", "dns_failure": "ssid",
        "wired_dhcp_failure": "leaf", "wired_dns_failure": "dns_server", "wired_port_down": "leaf"}


def test_dns_failure_prepends_deny_53_and_revert_restores_rules_exactly():
    c = ctx()
    api = c[0]
    rec = fl.inject("POD-6", "dns_failure", SSID_1, 30, _context=c)
    rules = api.l3["rules"]
    assert [(r["policy"], r["protocol"], r["destPort"]) for r in rules[:2]] == [("deny", "udp", "53"), ("deny", "tcp", "53")]
    assert rules[2] == LAB_RULE and len(rules) == 3          # the lab's own rule is kept, after ours
    assert all(r.get("comment") != "Default rule" for r in rules)
    assert api.l3["allowLanAccess"] is False

    fl.revert(rec["id"], _context=c)
    assert api.l3 == {"rules": [LAB_RULE], "allowLanAccess": False}
    assert rows() == []


def test_dns_failure_refuses_an_ssid_already_carrying_our_rules():
    c = ctx()
    c[0].l3["rules"].insert(0, {"comment": fl.DNS_BLOCK_COMMENT, "policy": "deny", "protocol": "udp",
                                "destPort": "53", "destCidr": "any"})
    with pytest.raises(fl.FaultLabError, match="already carries Fault Lab DNS rules"):
        fl.inject("POD-6", "dns_failure", SSID_1, 30, _context=c)
    assert c[0].puts == []


def test_dns_and_dhcp_faults_on_one_ssid_revert_independently():
    c = ctx()
    api = c[0]
    dns = fl.inject("POD-6", "dns_failure", SSID_1, 30, _context=c)
    dhcp = fl.inject("POD-6", "dhcp_failure", SSID_1, 30, _context=c)
    fl.revert(dns["id"], _context=c)
    assert api.ssids[1]["defaultVlanId"] == 999               # DHCP fault still in place
    fl.revert(dhcp["id"], _context=c)
    assert api.ssids[1]["ipAssignmentMode"] == "NAT mode" and api.l3["rules"] == [LAB_RULE]


def test_port_down_disables_only_host_ports_and_revert_brings_them_back():
    c = ctx()
    api = c[0]
    rec = fl.inject("POD-6", "wired_port_down", {"serial": "LEAF-2"}, 30, _context=c)
    assert [api.ports["LEAF-2"][p]["enabled"] for p in ("1", "2", "3", "4")] == [False, True, False, False]
    assert "2" not in api.port_puts()
    fl.revert(rec["id"], _context=c)
    assert api.ports["LEAF-2"] == LEAF_PORTS
    assert rows() == []


def test_port_down_never_leaves_a_port_down_when_enabled_was_unreported():
    sc = fl.WiredPortDown(ctx()[0])
    assert sc.restore_body({"enabled": None}) == {"enabled": True}
    assert sc.restore_body({"enabled": False}) == {"enabled": False}   # it was down before us


def test_wired_host_subnets_match_what_cloud_fabric_builds():
    import ipaddress
    import cloud_fabric
    built = tuple(str(ipaddress.ip_interface(ip).network) for _, _, ip in cloud_fabric.FABRIC_SUBNETS)
    assert fl.WIRED_HOST_SUBNETS == built


class FakeAD1:
    """Stands in for AD1's WinRM session: tracks the Fault Lab DNS subnet + policy.
    fail_on: a cmdlet name whose script returns a PowerShell error."""

    class _R:
        def __init__(self, out=b"", err=b"", code=0):
            self.std_out, self.std_err, self.status_code = out, err, code

    def __init__(self):
        self.policy = self.subnet = False
        self.scripts, self.pods = [], []
        self.fail_on = None

    def __call__(self, pod_id):            # the ad_session factory
        self.pods.append(pod_id)
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run_ps(self, script):
        self.scripts.append(script)
        if self.fail_on and self.fail_on in script:
            return self._R(err=b'#< CLIXML <Objs><S S="Error">Access is denied._x000D__x000A_</S></Objs>', code=1)
        if "Add-DnsServerClientSubnet" in script:
            self.subnet = True
        if "Add-DnsServerQueryResolutionPolicy" in script:
            self.policy = True
        if "Remove-DnsServerQueryResolutionPolicy" in script:
            self.policy = False
        if "Remove-DnsServerClientSubnet" in script:
            self.subnet = False
        if "'policy=' +" in script:
            return self._R(out=f"policy={self.policy}\nsubnet={self.subnet}".encode())
        return self._R()


@pytest.fixture
def ad1(monkeypatch):
    fake = FakeAD1()
    monkeypatch.setattr(fl, "ad_session", fake)
    return fake


def test_wired_dns_failure_adds_an_ignore_policy_for_the_wired_subnets_and_removes_it(ad1):
    c = ctx()
    rec = fl.inject("POD-6", "wired_dns_failure", {"server": "198.18.5.102"}, 30, _context=c)
    assert rec["network_name"] == "AD1 DNS (198.18.5.102)"
    assert json.loads(rec["target"]) == {"server": "198.18.5.102", "pod_id": "POD-6"}
    assert ad1.policy and ad1.subnet and set(ad1.pods) == {"POD-6"}
    add = next(sc for sc in ad1.scripts if "Add-DnsServerClientSubnet" in sc)
    assert all(cidr in add for cidr in fl.WIRED_HOST_SUBNETS)
    assert "-Action IGNORE" in next(sc for sc in ad1.scripts if "Add-DnsServerQueryResolutionPolicy" in sc)
    assert c[0].puts == []                                  # nothing changes on the Meraki side

    fl.revert(rec["id"], _context=c)
    assert not ad1.policy and not ad1.subnet and rows() == []


def test_wired_dns_failure_refuses_when_the_policy_is_already_on_ad1(ad1):
    ad1.policy = True
    with pytest.raises(fl.FaultLabError, match="already has the FAULTLAB-WiredDNS"):
        fl.inject("POD-6", "wired_dns_failure", {}, 30, _context=ctx())
    assert not any("Add-Dns" in sc for sc in ad1.scripts) and rows() == []


def test_wired_dns_failure_on_two_pods_does_not_collide(ad1):
    fl.inject("POD-6", "wired_dns_failure", {}, 30, _context=ctx())
    ad1.policy = ad1.subnet = False                         # POD-7 has its own AD1
    fl.inject("POD-7", "wired_dns_failure", {}, 30, _context=ctx())
    assert sorted(r["pod_id"] for r in rows()) == ["POD-6", "POD-7"]


def test_wired_dns_failure_half_applied_is_undone(ad1):
    ad1.fail_on = "Add-DnsServerQueryResolutionPolicy"      # the subnet goes in, the policy fails
    with pytest.raises(fl.FaultLabError, match="Access is denied"):
        fl.inject("POD-6", "wired_dns_failure", {}, 30, _context=ctx())
    assert not ad1.subnet and rows() == []                  # the subnet was removed again


def test_wired_dns_failure_reports_winrm_trouble_as_a_fault_lab_error(monkeypatch):
    def broken(pod_id):
        raise RuntimeError("DockerWinRMSession: could not start proxy container: vpn-POD-6 not running")
    monkeypatch.setattr(fl, "ad_session", broken)
    with pytest.raises(fl.FaultLabError, match="vpn-POD-6 not running"):
        fl.inject("POD-6", "wired_dns_failure", {}, 30, _context=ctx())
    assert rows() == []


def test_wired_dns_failure_only_knows_ad1():
    with pytest.raises(fl.FaultLabError, match="only AD1"):
        fl.WiredDnsFailure(ctx()[0], "POD-6").normalize({"server": "8.8.8.8"})
