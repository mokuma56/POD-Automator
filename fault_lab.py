"""
fault_lab.py — Fault Lab tab: reversible Meraki faults for troubleshooting demos
=================================================================================
Breaks something real in a POD's Meraki org so Dashboard reports a genuine
problem, then puts it back. Nothing is simulated: Dashboard shows what the
devices actually see.

Every injection is recorded (with the original config) in pod_state.db BEFORE
the change is made, so it can always be reverted — by the tab, by the class
panel, by the auto-revert sweeper once its TTL passes, or by Delete POD / Full
Reset, which revert a POD's faults before wiping it.

Runs in the dashboard process: Meraki is a cloud API, so unlike Cloud Fabric
there is no switch to reach and no need for the POD's VPN namespace.
"""
import concurrent.futures
import datetime
import json
import os
import re
import subprocess
import time
import uuid

import requests

import hostdb

MERAKI_BASE = "https://api.meraki.com/api/v1"
DB_PATH = ""            # set by the dashboard; "" lets hostdb use its default
DEFAULT_TTL_MINUTES = 30


class FaultLabError(RuntimeError):
    pass


# What a Meraki call or a state op can raise. Revert catches these to mark the
# record revert_failed instead of losing it; anything else is a bug and propagates.
FAULT_ERRORS = (FaultLabError, requests.RequestException, hostdb.HostDBError, KeyError, ValueError)


# ── Meraki ────────────────────────────────────────────────────────────────────

class Meraki:
    """Dashboard API client for one POD's org, honouring 429 Retry-After."""

    def __init__(self, api_key: str):
        self.session = requests.Session()
        self.session.headers.update({"Authorization": f"Bearer {api_key}",
                                     "Accept": "application/json",
                                     "Content-Type": "application/json"})

    def call(self, method: str, path: str, body=None, params=None):
        for _ in range(6):
            r = self.session.request(method, MERAKI_BASE + path, json=body, params=params, timeout=60)
            if r.status_code == 429:
                time.sleep(float(r.headers.get("Retry-After", "2")))
                continue
            if r.status_code >= 400:
                raise FaultLabError(f"{method} {path} → {r.status_code} {r.text[:200]}")
            return r.json() if r.content else None
        raise FaultLabError(f"{method} {path} → still rate-limited after retries")


def pod_context(pod_id: str) -> tuple[Meraki, str]:
    """(client, org_id) for the POD: its own key when one is recorded, else the lab key."""
    creds = hostdb.call("org_creds_for_pod", db_path=DB_PATH, pod_id=pod_id) or {}
    org = str(creds.get("meraki_org_id") or "").strip()
    if not org:
        raise FaultLabError("org_credentials.meraki_org_id is empty for this POD's org "
                            "(import the Meraki Orgs sheet)")
    key = (creds.get("meraki_api_key") or "").strip() or os.environ.get("MERAKI_API_KEY", "")
    if not key:
        raise FaultLabError("no Meraki API key: set MERAKI_API_KEY or the org's meraki_api_key")
    return Meraki(key), org


# ── Scenarios ─────────────────────────────────────────────────────────────────

def blackhole_vlan() -> int:
    """An unused VLAN with no DHCP server or gateway behind it."""
    return int(os.environ.get("FAULTLAB_BLACKHOLE_VLAN", "999"))


class Scenario:
    """snapshot() the fields inject() will change; revert() writes exactly those back.

    target_kind says what the scenario acts on, and so which picker the UI shows:
    "ssid" ({network_id, ssid}) or "leaf" ({serial}).
    """
    name = ""
    label = ""
    target_kind = ""
    summary = ""
    symptoms = ""       # what a presenter should expect in Dashboard, and when

    def __init__(self, api: Meraki, pod_id: str = ""):
        self.api = api
        self.pod_id = pod_id

    def normalize(self, raw: dict) -> dict: raise NotImplementedError
    def resolve(self, target: dict, org: str) -> str:
        """Check the target belongs to *org*; return a display label for it."""
        raise NotImplementedError
    def snapshot(self, target: dict) -> dict: raise NotImplementedError
    def inject(self, target: dict, snapshot: dict) -> None: raise NotImplementedError
    def revert(self, target: dict, snapshot: dict) -> None: raise NotImplementedError


class SsidScenario(Scenario):
    """Acts on one SSID: {network_id, ssid}."""
    target_kind = "ssid"

    def normalize(self, raw):
        return {"network_id": str(raw["network_id"]), "ssid": int(raw["ssid"])}

    def _path(self, target, suffix=""):
        return f"/networks/{target['network_id']}/wireless/ssids/{target['ssid']}{suffix}"

    def resolve(self, target, org):
        net = self.api.call("GET", f"/networks/{target['network_id']}")
        if str(net.get("organizationId")) != org:
            raise FaultLabError(f"network {target['network_id']} is not in this POD's org {org}")
        ssid = self.api.call("GET", self._path(target)) or {}
        return f"{net['name']} / {ssid.get('name') or 'SSID ' + str(target['ssid'])}"

    def _require_enabled(self, target):
        ssid = self.api.call("GET", self._path(target))
        if not ssid.get("enabled"):
            raise FaultLabError(f"SSID {target['ssid']} ({ssid.get('name')}) is disabled; nothing to demo")
        return ssid


class DhcpFailure(SsidScenario):
    """The SSID is bridged into a VLAN with no DHCP server. Clients associate and
    authenticate, then never get an address. Other SSIDs on the APs keep working."""
    name = "dhcp_failure"
    label = "Wireless DHCP Failure"
    summary = "SSID clients connect but never get an IP address"
    symptoms = ("Wireless > Health: DHCP failures on the SSID (5-15 min to populate). "
                "Client connection log: association + auth succeed, DHCP fails. "
                "Needs at least one real client trying to join.")
    TOUCHED_FIELDS = ("ipAssignmentMode", "useVlanTagging", "defaultVlanId")

    def snapshot(self, target):
        current = self._require_enabled(target)
        return {f: current.get(f) for f in self.TOUCHED_FIELDS}

    def inject(self, target, snapshot):
        self.api.call("PUT", self._path(target), {
            "ipAssignmentMode": "Bridge mode", "useVlanTagging": True, "defaultVlanId": blackhole_vlan()})

    def revert(self, target, snapshot):
        # Never send a field the original SSID did not have; Meraki rejects
        # defaultVlanId when tagging is off, and NAT mode ignores tagging entirely.
        body = {k: v for k, v in snapshot.items() if v is not None}
        if not body.get("useVlanTagging"):
            body.pop("defaultVlanId", None)
        self.api.call("PUT", self._path(target), body)


# Built-in rules some API versions append to a GET; never PUT them back.
BUILTIN_L3_COMMENTS = ("Default rule", "Wireless clients accessing LAN")
DNS_BLOCK_COMMENT = "FAULTLAB: block DNS"


class DnsFailure(SsidScenario):
    """DNS is blocked by the SSID's L3 firewall. Clients join and get an address,
    then nothing resolves: the classic "Wi-Fi is up but the internet is down"."""
    name = "dns_failure"
    label = "Wireless DNS Failure"
    summary = "SSID clients get an IP address, but no name resolves"
    symptoms = ("Wireless > Health: DNS failures on the SSID (5-15 min to populate). "
                "Client: connected with an IP, pings to 8.8.8.8 work, websites by name do not. "
                "Wireless > Firewall & traffic shaping shows the DNS deny rules on top.")

    def snapshot(self, target):
        self._require_enabled(target)
        fw = self.api.call("GET", self._path(target, "/firewall/l3FirewallRules")) or {}
        rules = [r for r in fw.get("rules") or [] if r.get("comment") not in BUILTIN_L3_COMMENTS]
        if any(r.get("comment") == DNS_BLOCK_COMMENT for r in rules):
            raise FaultLabError("the SSID already carries Fault Lab DNS rules; revert or remove them first")
        return {"rules": rules, "allowLanAccess": fw.get("allowLanAccess")}

    def inject(self, target, snapshot):
        block = [{"comment": DNS_BLOCK_COMMENT, "policy": "deny", "protocol": proto,
                  "destPort": "53", "destCidr": "any"} for proto in ("udp", "tcp")]
        body = {"rules": block + snapshot["rules"]}
        if snapshot.get("allowLanAccess") is not None:
            body["allowLanAccess"] = snapshot["allowLanAccess"]
        self.api.call("PUT", self._path(target, "/firewall/l3FirewallRules"), body)

    def revert(self, target, snapshot):
        body = {"rules": snapshot["rules"]}
        if snapshot.get("allowLanAccess") is not None:
            body["allowLanAccess"] = snapshot["allowLanAccess"]
        self.api.call("PUT", self._path(target, "/firewall/l3FirewallRules"), body)


# The leaves' access block. Cabling differs between PODs (POD-17 has its APs on
# port 2), so which of these are host ports is decided live, never assumed.
LEAF_CANDIDATE_PORTS = ("1", "2", "3", "4")


def leaf_host_ports(api: Meraki, serial: str) -> list[str]:
    """Candidate ports with no LLDP/CDP neighbour. An AP, a switch or an uplink
    always announces itself; a workstation (or an empty port) does not."""
    neighbours = set(((api.call("GET", f"/devices/{serial}/lldpCdp") or {}).get("ports") or {}).keys())
    return [p for p in LEAF_CANDIDATE_PORTS if p not in neighbours]


class LeafPortScenario(Scenario):
    """Acts on the host ports of one leaf: {serial}. Ports are never taken from
    the request: they are the candidates with no LLDP/CDP neighbour (so never an
    AP or an uplink) that are not trunks, decided when the fault is injected."""
    target_kind = "leaf"
    TOUCHED_FIELDS: tuple = ()

    def normalize(self, raw):
        return {"serial": str(raw["serial"]).strip().upper()}

    def resolve(self, target, org):
        dev = self.api.call("GET", f"/devices/{target['serial']}")
        net = self.api.call("GET", f"/networks/{dev.get('networkId')}") if dev.get("networkId") else {}
        if str(net.get("organizationId")) != org:
            raise FaultLabError(f"switch {target['serial']} is not in this POD's org {org}")
        self._ports = self._host_ports(target)
        return f"{dev.get('name') or target['serial']} ports {', '.join(self._ports)}"

    def _host_ports(self, target):
        ports = []
        for port in leaf_host_ports(self.api, target["serial"]):
            if self.api.call("GET", self._path(target, port)).get("type") != "trunk":
                ports.append(port)
        if not ports:
            raise FaultLabError(f"no host ports on {target['serial']}: every port in "
                                f"{', '.join(LEAF_CANDIDATE_PORTS)} has an AP/switch neighbour or is a trunk")
        return ports

    def _path(self, target, port):
        if port not in LEAF_CANDIDATE_PORTS:
            raise FaultLabError(f"refusing to touch port {port}: outside the access block "
                                f"{', '.join(LEAF_CANDIDATE_PORTS)}")
        return f"/devices/{target['serial']}/switch/ports/{port}"

    def snapshot(self, target):
        ports = getattr(self, "_ports", None) or self._host_ports(target)
        return {port: {f: self.api.call("GET", self._path(target, port)).get(f) for f in self.TOUCHED_FIELDS}
                for port in ports}

    def fault_body(self) -> dict:
        raise NotImplementedError

    def restore_body(self, fields: dict) -> dict:
        return {k: v for k, v in fields.items() if v is not None}

    def inject(self, target, snapshot):
        for port in snapshot:
            self.api.call("PUT", self._path(target, port), self.fault_body())

    def revert(self, target, snapshot):
        failed = []
        for port, fields in snapshot.items():
            try:
                self.api.call("PUT", self._path(target, port), self.restore_body(fields))
            except FAULT_ERRORS as e:          # keep going: restore every port we can
                failed.append(f"port {port}: {str(e)[:120]}")
        if failed:
            raise FaultLabError("; ".join(failed))


class WiredDhcpFailure(LeafPortScenario):
    """Leaf host ports are moved into a VLAN with no DHCP server. The link comes
    up, then the host never gets an address. The access policy is set to Open
    for the duration: Cloud Fabric puts 802.1X (PseudoCo_ISE) on port 1, and an
    ISE-assigned VLAN would otherwise override the change."""
    name = "wired_dhcp_failure"
    label = "Wired DHCP Failure"
    summary = "Hosts on the leaf host ports get link but never an IP address"
    symptoms = ("Switch > Ports: link up, client with no IP (or 169.254.x.x). "
                "Network-wide > Event log: port config change. Needs a wired host on a host port. "
                "Ports with an AP or switch neighbour (LLDP/CDP) are never touched.")
    TOUCHED_FIELDS = ("type", "vlan", "accessPolicyType", "accessPolicyNumber")

    def fault_body(self):
        return {"type": "access", "vlan": blackhole_vlan(), "accessPolicyType": "Open"}

    def restore_body(self, fields):
        body = super().restore_body(fields)
        # accessPolicyNumber is only valid alongside a custom access policy.
        if body.get("accessPolicyType") != "Custom access policy":
            body.pop("accessPolicyNumber", None)
        return body


class WiredPortDown(LeafPortScenario):
    """Leaf host ports are administratively disabled: the host has no link at all."""
    name = "wired_port_down"
    label = "Wired Port Down"
    summary = "Hosts on the leaf host ports lose link entirely"
    symptoms = ("Switch > Ports: host ports shown disabled, no link; the host drops off the client list. "
                "Network-wide > Event log: port config change by an admin. "
                "Ports with an AP or switch neighbour (LLDP/CDP) are never touched.")
    TOUCHED_FIELDS = ("enabled",)

    def fault_body(self):
        return {"enabled": False}

    def restore_body(self, fields):
        # A port Meraki reported without "enabled" was up; never leave it down.
        return {"enabled": fields.get("enabled") is not False}


# The leaves' host subnets, as Cloud Fabric builds them (cloud_fabric.FABRIC_SUBNETS:
# Main 10, PROD 101, IOT 102). A test pins the two lists together.
WIRED_HOST_SUBNETS = ("10.10.255.0/24", "10.101.255.0/24", "10.102.255.0/24")


# AD1 is the fabric's DHCP and DNS server (cloud_fabric.FABRIC_DHCP).
AD1_IP = "198.18.5.102"
AD1_DNS_POLICY = "FAULTLAB-WiredDNS"      # names both the client subnet and the policy


def ad_session(pod_id: str):
    """PowerShell on AD1 through the POD's VPN namespace: the Duo card's own
    WinRM session, so Fault Lab adds no credential handling of its own."""
    import duo_automation
    return duo_automation._winrm_connect_for_pod(pod_id, AD1_IP, log=lambda m: None)


def run_on_ad1(pod_id: str, script: str) -> str:
    """Run *script* on AD1 and return its stdout; any failure is a FaultLabError."""
    if not pod_id:
        raise FaultLabError("AD1 faults need the POD's VPN namespace, but no POD was given")
    try:
        with ad_session(pod_id) as sess:
            r = sess.run_ps("$ProgressPreference = 'SilentlyContinue'\n"
                            "$ErrorActionPreference = 'Stop'\n" + script)
    except (RuntimeError, OSError, subprocess.SubprocessError) as e:
        raise FaultLabError(f"AD1 WinRM via vpn-{pod_id}: {str(e)[:200]}") from e
    out = (r.std_out or b"").decode(errors="replace").strip()
    if r.status_code != 0:
        err = (r.std_err or b"").decode(errors="replace")
        # PowerShell wraps errors in CLIXML; the message text is in the <S S="Error"> runs.
        msg = " ".join(re.findall(r'<S S="Error">(.*?)</S>', err)).replace("_x000D__x000A_", " ") or err
        raise FaultLabError(f"AD1 PowerShell failed: {(msg or out)[:240]}")
    return out


class WiredDnsFailure(Scenario):
    """AD1's DNS server ignores queries from the wired host subnets. Hosts keep
    their link and address; every lookup times out.

    Done on the DNS server because neither Meraki-side option works on a Cloud
    Fabric POD: the network switch ACL is not enforced on traffic routed inside
    the fabric VRFs (POD-17, 2026-10-09), and AD1's Windows Firewall is off on
    every profile, so a firewall block rule would not be enforced either."""
    name = "wired_dns_failure"
    label = "Wired DNS Failure"
    target_kind = "dns_server"
    summary = "Wired hosts get an IP address, but no name resolves"
    symptoms = ("On a wired host: IP from Main/PROD/IOT, ping 198.18.5.102 works, nslookup times out. "
                "Run ipconfig /flushdns first, or cached names keep resolving. Done on AD1 (DNS query "
                "policy FAULTLAB-WiredDNS), so the Meraki side looks clean. Wireless clients are not affected.")

    def normalize(self, raw):
        server = str(raw.get("server") or AD1_IP)
        if server != AD1_IP:
            raise FaultLabError(f"unknown DNS server {server}; only AD1 ({AD1_IP}) is supported")
        # Every POD's AD1 has the same address, so the POD is part of the target:
        # without it, a fault on one POD would block the same fault on the next.
        return {"server": server, "pod_id": self.pod_id}

    def resolve(self, target, org):
        return f"AD1 DNS ({AD1_IP})"

    def _present(self) -> dict:
        out = run_on_ad1(self.pod_id,
            f"'policy=' + [bool](Get-DnsServerQueryResolutionPolicy -Name '{AD1_DNS_POLICY}' -ErrorAction SilentlyContinue)\n"
            f"'subnet=' + [bool](Get-DnsServerClientSubnet -Name '{AD1_DNS_POLICY}' -ErrorAction SilentlyContinue)")
        return {k: v.strip().lower() == "true" for k, v in (line.split("=", 1) for line in out.splitlines() if "=" in line)}

    def snapshot(self, target):
        if any(self._present().values()):
            raise FaultLabError(f"AD1 already has the {AD1_DNS_POLICY} DNS policy; revert or remove it first")
        return {"policy": AD1_DNS_POLICY, "subnets": list(WIRED_HOST_SUBNETS)}

    def inject(self, target, snapshot):
        subnets = ",".join(f"'{c}'" for c in snapshot["subnets"])
        run_on_ad1(self.pod_id,
            f"Add-DnsServerClientSubnet -Name '{AD1_DNS_POLICY}' -IPv4Subnet @({subnets})\n"
            f"Add-DnsServerQueryResolutionPolicy -Name '{AD1_DNS_POLICY}' -Action IGNORE "
            f"-ClientSubnet 'EQ,{AD1_DNS_POLICY}' -ProcessingOrder 1")
        if not all(self._present().values()):
            raise FaultLabError("AD1 accepted the DNS policy but it is not there on read-back")

    def revert(self, target, snapshot):
        name = snapshot.get("policy") or AD1_DNS_POLICY
        run_on_ad1(self.pod_id,
            f"if (Get-DnsServerQueryResolutionPolicy -Name '{name}' -ErrorAction SilentlyContinue) "
            f"{{ Remove-DnsServerQueryResolutionPolicy -Name '{name}' -Force }}\n"
            f"if (Get-DnsServerClientSubnet -Name '{name}' -ErrorAction SilentlyContinue) "
            f"{{ Remove-DnsServerClientSubnet -Name '{name}' -Force }}")
        if any(self._present().values()):
            raise FaultLabError(f"AD1 still has the {name} DNS policy after removal")


SCENARIOS = {cls.name: cls for cls in (DhcpFailure, DnsFailure, WiredDhcpFailure, WiredDnsFailure,
                                       WiredPortDown)}


def scenario_catalog() -> list[dict]:
    return [{"name": c.name, "label": c.label, "target_kind": c.target_kind,
             "summary": c.summary, "symptoms": c.symptoms} for c in SCENARIOS.values()]


# ── Targets ───────────────────────────────────────────────────────────────────

def wireless_targets(api: Meraki, org_id: str) -> list[dict]:
    """Every wireless network in the org with its enabled SSIDs."""
    nets = api.call("GET", f"/organizations/{org_id}/networks", params={"perPage": 1000}) or []
    out = []
    for n in nets:
        if "wireless" not in (n.get("productTypes") or []):
            continue
        ssids = api.call("GET", f"/networks/{n['id']}/wireless/ssids") or []
        out.append({"network_id": n["id"], "network_name": n["name"],
                    "ssids": [{"number": s["number"], "name": s["name"]}
                              for s in ssids if s.get("enabled")]})
    return out


def leaf_targets(api: Meraki, org_id: str, pod_id: str) -> list[dict]:
    """The POD's leaf switches: the Cloud IDs the Cloud Fabric tab recorded, else
    any switch in the org with "leaf" in its name."""
    try:
        recorded = hostdb.call("cloudfabric_devices", db_path=DB_PATH, pod_id=pod_id) or {}
    except hostdb.HostDBError:          # Cloud Fabric never ran on this database
        recorded = {}
    devices = api.call("GET", f"/organizations/{org_id}/devices",
                       params={"productTypes[]": "switch", "perPage": 1000}) or []
    by_serial = {d["serial"]: d for d in devices}
    leaves = [{"role": role, "serial": serial, "name": by_serial[serial].get("name") or role,
               "network_id": by_serial[serial].get("networkId")}
              for role, serial in sorted(recorded.items()) if role.startswith("leaf") and serial in by_serial]
    if not leaves:
        # Infer the role from the name ("Site_105-Leaf2" → leaf2) so the class
        # panel's "set all" matches these PODs and Cloud Fabric ones alike.
        for dv in devices:
            m = re.search(r"leaf[\s_-]*(\d+)", dv.get("name") or "", re.I)
            if m:
                leaves.append({"role": f"leaf{m.group(1)}", "serial": dv["serial"], "name": dv["name"],
                               "network_id": dv.get("networkId")})
        leaves.sort(key=lambda l: l["role"])
    for leaf in leaves:
        try:
            leaf["host_ports"] = leaf_host_ports(api, leaf["serial"])
        except FAULT_ERRORS:
            leaf["host_ports"] = []
    return leaves


def targets_for_pod(pod_id: str) -> dict:
    api, org = pod_context(pod_id)
    leaves = leaf_targets(api, org, pod_id)
    return {"ssid": wireless_targets(api, org), "leaf": leaves,
            "dns_server": [{"server": AD1_IP, "name": "AD1"}]}


# ── Inject / revert ───────────────────────────────────────────────────────────

def _iso(ts: float) -> str:
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _target_key(target: dict) -> str:
    return json.dumps(target, sort_keys=True)


def _db(op: str, **params):
    return hostdb.call(op, db_path=DB_PATH, **params)


def inject(pod_id: str, scenario: str, target: dict, ttl_minutes: int = DEFAULT_TTL_MINUTES,
           log_fn=print, _context=None) -> dict:
    if scenario not in SCENARIOS:
        raise FaultLabError(f"unknown scenario {scenario}")
    api, org = _context or pod_context(pod_id)
    sc = SCENARIOS[scenario](api, pod_id)
    target = sc.normalize(target)
    # The target must belong to THIS POD's org, whatever the browser sent.
    label = sc.resolve(target, org)
    # A second injection would snapshot already-faulted config and make revert a no-op.
    if _db("faultlab_find", scenario=scenario, target=_target_key(target)):
        raise FaultLabError(f"{sc.label} is already active on {label}")

    snapshot = sc.snapshot(target)
    now = time.time()
    record = {"id": uuid.uuid4().hex[:8], "pod_id": pod_id, "scenario": scenario,
              "target": _target_key(target), "network_name": label,
              "snapshot": json.dumps(snapshot),
              "injected_at": _iso(now), "expires_at": _iso(now + ttl_minutes * 60)}
    # Record first: a crash after the PUT must still leave something to revert from.
    _db("faultlab_add", **record)
    try:
        sc.inject(target, snapshot)
    except BaseException as e:
        # A multi-port inject can fail part-way. Put everything back (rewriting a
        # field that never changed is harmless) and only then drop the record.
        try:
            sc.revert(target, snapshot)
        except FAULT_ERRORS as undo:
            _db("faultlab_set_status", record_id=record["id"], status="revert_failed",
                last_error=f"inject failed ({str(e)[:100]}); undo failed: {str(undo)[:180]}")
            log_fn(f"[faultlab] inject of {scenario} on {label} FAILED part-way and could not "
                   f"be undone (id {record['id']}) — revert it from the Fault Lab tab")
            raise
        _db("faultlab_delete", record_id=record["id"])
        raise
    _db("faultlab_set_status", record_id=record["id"], status="active")
    log_fn(f"[faultlab] injected {scenario} on {label} "
           f"(id {record['id']}, auto-revert {record['expires_at']})")
    return _db("faultlab_get", record_id=record["id"])


def revert(record_id: str, log_fn=print, _context=None) -> dict:
    """Restore and delete the record. On failure keep it, marked revert_failed."""
    rec = _db("faultlab_get", record_id=record_id)
    if not rec:
        raise FaultLabError(f"no injection {record_id}")
    _db("faultlab_set_status", record_id=record_id, status="reverting")
    try:
        api, _ = _context or pod_context(rec["pod_id"])
        SCENARIOS[rec["scenario"]](api, rec["pod_id"]).revert(json.loads(rec["target"]), json.loads(rec["snapshot"]))
    except FAULT_ERRORS as e:
        _db("faultlab_set_status", record_id=record_id, status="revert_failed", last_error=str(e)[:300])
        log_fn(f"[faultlab] revert FAILED for {rec['scenario']} on {rec['network_name']} "
               f"(id {record_id}): {str(e)[:200]}")
        raise
    _db("faultlab_delete", record_id=record_id)
    log_fn(f"[faultlab] reverted {rec['scenario']} on {rec['network_name']} (id {record_id})")
    return rec


def revert_all(pod_id: str | None = None, expired_only: bool = False, log_for=None) -> tuple[list, list]:
    """Revert every matching injection. Returns (reverted ids, error strings).

    log_for(pod_id) returns that POD's log function, so each line lands in the
    right POD's log.
    """
    log_for = log_for or (lambda _p: print)
    rows = _db("faultlab_list", pod_id=pod_id) or []
    if expired_only:
        now = _iso(time.time())
        rows = [r for r in rows if r["status"] == "active" and r["expires_at"] <= now]
    done, errors = [], []
    for r in rows:
        try:
            revert(r["id"], log_fn=log_for(r["pod_id"]))
            done.append(r["id"])
        except FAULT_ERRORS as e:
            errors.append(f"{r['pod_id']} {r['scenario']} on {r['network_name']}: {str(e)[:160]}")
    return done, errors


def targets_for_pods(pod_ids: list[str], workers: int = 8) -> dict:
    """Class panel: every POD's targets, fetched in parallel. Each POD is its own
    org (and so its own API rate limit), so this scales with the class size.
    Returns {pod_id: {"targets": {...}} or {"error": "..."}}."""
    def one(pod_id):
        try:
            return pod_id, {"targets": targets_for_pod(pod_id)}
        except FAULT_ERRORS as e:
            return pod_id, {"error": str(e)[:200]}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(one, pod_ids))
