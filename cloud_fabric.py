#!/usr/bin/env python3
"""
Cloud Fabric — Meraki-managed BGP EVPN VXLAN fabric on the Site_105 C9300s.

Follows the "Cloud Fabric" lab guide:

  A. Dashboard & ISE prep    meraki_connect → claim_devices → name_switches →
                             mgmt_interfaces → ise_nads → ise_meraki_integration →
                             adaptive_groups_check →
                             vlan_profile → access_policy → access_ports
  B. Routed underlay         underlay_links → transit_interface → static_route →
                             verify_ospf
  C. Fabric build            fabric_create → fabric_subnets → fabric_deploy →
                             verify_fabric

Guide step 6 (ISE TrustSec ↔ Meraki integration) runs through ISE's admin-UI
API; adaptive_groups_check then waits for its SGTs to land in Meraki, because
the VLAN profile cannot reference groups that do not exist yet.

Part C (Organization → Fabric) has no public API: /api/v1/organizations/{id}/
switch/fabric answers only to a logged-in Dashboard session, never to an API
key. It drives that session, opened through the iDAC card's Meraki tile; the
calls were recorded from a manual build (docs/cloud_fabric_api_capture.md).

Runs inside the POD's VPN namespace (docker run --network container:vpn-<pod>):
the out-of-band SSH and ISE need the tunnel, the Meraki API needs internet.

Secrets come from the environment, never from this file:
  MERAKI_API_KEY   Dashboard API key with access to the POD's org
  LAB_PASS         switch/ISE admin password and the RADIUS shared secret

Usage (inside the container):
  python3 cloud_fabric.py deploy [--from STEP]
  python3 cloud_fabric.py rollback
  python3 cloud_fabric.py --list
"""

import argparse
import base64
import json
import os
import re
import sys
import time

import paramiko
import requests
import urllib3
from playwright.sync_api import Error as PlaywrightError

import hostdb  # every pod_state.db access goes through the host — see db_ops.py

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DB_PATH = os.environ.get("DB_PATH", "data/pod_state.db")
POD_ID  = os.environ.get("POD_ID", "")

MERAKI_BASE = "https://api.meraki.com/api/v1"
NETWORK_NAME = "SITE_105"

SWITCH_USER = "netadmin"
ISE_HOST = "198.18.5.101"
ISE_USER = "admin"

# Out-of-band SSH addresses are only used for the cloud-management conversion;
# cloud configuration factory-resets the switch, after which Dashboard owns it.
SWITCHES = {
    "border_spine": {"name": "Site_105-Border-Spine", "oob": "198.18.128.24",
                     "mgmt_name": "Border-Spine_MGMT", "mgmt_ip": "198.18.1.53"},
    "leaf1":        {"name": "Site_105-Leaf1",        "oob": "198.18.128.22",
                     "mgmt_name": "Leaf1_MGMT",        "mgmt_ip": "198.18.1.51"},
    "leaf2":        {"name": "Site_105-Leaf2",        "oob": "198.18.128.23",
                     "mgmt_name": "Leaf2_MGMT",        "mgmt_ip": "198.18.1.52"},
}
LEAVES = ("leaf1", "leaf2")

MGMT_SUBNET  = "198.18.1.0/24"
MGMT_GATEWAY = "198.18.1.1"

# (role, port, name, subnet, interface IP)
UNDERLAY_LINKS = [
    ("border_spine", "1",  "Border-Spine_to_Leaf1", "173.30.254.0/31", "173.30.254.0"),
    ("border_spine", "2",  "Border-Spine_to_Leaf2", "173.30.254.2/31", "173.30.254.2"),
    ("leaf1",        "47", "Leaf1_to_Border-Spine", "173.30.254.0/31", "173.30.254.1"),
    ("leaf2",        "48", "Leaf2_to_Border-Spine", "173.30.254.2/31", "173.30.254.3"),
]
OSPF_NEIGHBORS = ("173.30.254.1", "173.30.254.3")   # as seen from the Border-Spine

TRANSIT = {"name": "Border-Spine_to_SDWAN_Global", "vlan": 5,
           "subnet": "192.168.255.6/31", "ip": "192.168.255.7"}
STATIC_ROUTE = {"name": "ROUTE_198.18.5.x/24", "subnet": "198.18.5.0/24",
                "next_hop": "192.168.255.6"}

# Named VLAN → (VLAN ID, adaptive policy group name, SGT)
NAMED_VLANS = [("Main", 10, "Main", 16), ("PROD", 101, "Production", 19),
               ("IOT", 102, "IoT", 18)]

ACCESS_POLICY = "PseudoCo_ISE"
ACCESS_PORTS = ("1", "3")


def _lab_pass() -> str:
    pw = os.environ.get("LAB_PASS", "")
    if not pw:
        raise RuntimeError("LAB_PASS is not set — the dashboard passes it from its environment/.env")
    return pw


# ── DB persistence ────────────────────────────────────────────────────────────

def ensure_table():
    hostdb.call("cloudfabric_ensure_table", db_path=DB_PATH)


def _set_step(mode, step, status, result=None):
    if not POD_ID:
        return
    # A dropped completed/failed write leaves the card spinning forever, so a
    # failure here is worth a line in the log rather than silence.
    try:
        hostdb.call("cloudfabric_step_set", db_path=DB_PATH, pod_id=POD_ID, mode=mode,
                    step_name=step, status=status, result=result)
    except hostdb.HostDBError as e:
        print(f"[cloudfabric] WARNING: step write {step}={status} failed: {e}")


def _devices() -> dict:
    """role → serial (Cloud ID) recorded by meraki_connect."""
    return hostdb.call("cloudfabric_devices", db_path=DB_PATH, pod_id=POD_ID) or {}


def _serial(role: str) -> str:
    s = _devices().get(role)
    if not s:
        raise RuntimeError(f"no Cloud ID recorded for {role} — run meraki_connect first")
    return s


# ── Meraki Dashboard API ──────────────────────────────────────────────────────

class MerakiError(RuntimeError):
    pass


_api_session = None


def _api():
    global _api_session
    if _api_session is None:
        key = os.environ.get("MERAKI_API_KEY", "")
        if not key:
            raise RuntimeError("MERAKI_API_KEY is not set — the dashboard passes it from its environment/.env")
        _api_session = requests.Session()
        _api_session.headers.update({"Authorization": f"Bearer {key}",
                                 "Accept": "application/json",
                                 "Content-Type": "application/json"})
    return _api_session


def meraki(method: str, path: str, body=None, params=None, ok=(200, 201, 202, 204)):
    """One Dashboard API call, honouring 429 Retry-After. Returns parsed JSON or None."""
    for _ in range(6):
        r = _api().request(method, MERAKI_BASE + path, json=body, params=params, timeout=60)
        if r.status_code == 429:
            time.sleep(float(r.headers.get("Retry-After", "2")))
            continue
        if r.status_code not in ok:
            raise MerakiError(f"{method} {path} → {r.status_code} {r.text[:300]}")
        return r.json() if r.content else None
    raise MerakiError(f"{method} {path} → still rate-limited after retries")


_ctx = {}


def _org_id() -> str:
    if "org" not in _ctx:
        creds = hostdb.call("org_creds_for_pod", db_path=DB_PATH, pod_id=POD_ID) or {}
        org = str(creds.get("meraki_org_id") or "").strip()
        if not org:
            raise RuntimeError("org_credentials.meraki_org_id is empty for this POD's org "
                               "(import the Meraki Orgs sheet)")
        _ctx["org"] = org
    return _ctx["org"]


def _network_id() -> str:
    if "net" not in _ctx:
        nets = meraki("GET", f"/organizations/{_org_id()}/networks", params={"perPage": 1000})
        match = [n for n in nets if n["name"] == NETWORK_NAME]
        if not match:
            raise RuntimeError(f"network {NETWORK_NAME} not found in Meraki org {_org_id()}")
        _ctx["net"] = match[0]["id"]
    return _ctx["net"]


def _ensure_interface(serial: str, body: dict, log_fn) -> str:
    """Create the L3 interface named body['name'], or update it in place."""
    existing = meraki("GET", f"/devices/{serial}/switch/routing/interfaces") or []
    hit = next((i for i in existing if i.get("name") == body["name"]), None)
    if hit:
        meraki("PUT", f"/devices/{serial}/switch/routing/interfaces/{hit['interfaceId']}", body)
        log_fn(f"    updated {body['name']}")
        return "updated"
    meraki("POST", f"/devices/{serial}/switch/routing/interfaces", body)
    log_fn(f"    created {body['name']}")
    return "created"


# ── Switch SSH (out-of-band, conversion only) ─────────────────────────────────

def _ssh(ip: str, commands, config=False, timeout=30) -> str:
    """Run exec commands (or one config block) over an interactive shell."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username=SWITCH_USER, password=_lab_pass(),
                   look_for_keys=False, allow_agent=False, timeout=15)
    try:
        shell = client.invoke_shell(width=250, height=200)
        time.sleep(1)
        shell.recv(65535)

        def send(cmd, delay=1.0):
            shell.send(cmd + "\n")
            time.sleep(delay)
            out = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if shell.recv_ready():
                    out += shell.recv(65535)
                    tail = out.rstrip()
                    if tail.endswith((b"#", b">")) or tail.lower().endswith(b"password:"):
                        break
                else:
                    time.sleep(0.3)
            return out.decode(errors="ignore")

        # Not every switch lands in privileged EXEC: Site_105-Leaf1 logs netadmin
        # in at ">" (2026-10-06), where show meraki connect and conf t are invalid.
        out = send("terminal length 0")
        if out.rstrip().endswith(">"):
            reply = send("enable")
            if reply.rstrip().lower().endswith("password:"):
                reply = send(_lab_pass())
            if not reply.rstrip().endswith("#"):
                raise RuntimeError(f"{ip}: could not enter privileged EXEC (enable)")
        if config:
            out += send("configure terminal")
        for c in commands:
            out += send(c, delay=2.0)
        if config:
            out += send("end")
        if "% Invalid input" in out or "% Incomplete command" in out:
            raise RuntimeError(f"{ip}: command rejected — {out.strip()[-300:]}")
        return out
    finally:
        client.close()


_CLOUD_ID_RE = re.compile(r"Cloud\s*ID\s*:?\s*([A-Z0-9]{4}-[A-Z0-9]{4}-[A-Z0-9]{4})", re.I)


def parse_meraki_connect(output: str) -> dict:
    """Pull the Cloud ID and registration state out of `show meraki connect`.

    Registered means the guide's two checks: Fetch State "Config fetch
    succeeded" and the Meraki tunnel state(s) Up.
    """
    m = _CLOUD_ID_RE.search(output)
    fetched = bool(re.search(r"Fetch\s+State\s*:\s*Config fetch succeeded", output, re.I))
    # "Meraki Tunnel Config" also has Primary:/Secondary: lines (the tunnel
    # servers), so read Up/Down only inside the "Meraki Tunnel State" section.
    sec = re.search(r"Meraki Tunnel State(.*?)(?:\n\s*\n|\nMeraki |\Z)", output, re.I | re.S)
    states = dict((k.lower(), v.lower()) for k, v in re.findall(
        r"^\s*(Primary|Secondary)\s*:\s*(\S+)", sec.group(1) if sec else "", re.I | re.M))
    tunnel_up = states.get("primary") == "up" and states.get("secondary", "up") == "up"
    return {"cloud_id": m.group(1).upper() if m else "",
            "fetch_ok": fetched, "tunnel_up": tunnel_up,
            "registered": bool(m) and fetched and tunnel_up}


# ── Deploy steps — A. Dashboard & ISE prep ────────────────────────────────────

def step_meraki_connect(log_fn=print):
    """service meraki connect on each switch, wait for registration, record Cloud IDs."""
    known = _devices()
    if all(known.get(r) for r in SWITCHES):
        inv = _inventory(list(known.values()))
        if all(d.get("networkId") == _network_id() for d in inv.values()) and len(inv) == 3:
            return True, "already converted and in " + NETWORK_NAME + " — " + \
                ", ".join(f"{r}={known[r]}" for r in SWITCHES)

        # Rolled back but not reverted to CLI: cloud configuration wiped the
        # out-of-band config, so SSH is gone, but the switches are still
        # registered with Meraki and the recorded Cloud IDs still claim them.
        unreachable = []
        for role, sw in SWITCHES.items():
            try:
                _ssh(sw["oob"], ["show clock"], timeout=15)
            except (paramiko.SSHException, OSError, EOFError):
                unreachable.append(sw["name"])
        if len(unreachable) == len(SWITCHES):
            return True, ("already cloud-managed (OOB SSH gone) — reusing recorded Cloud IDs "
                          + ", ".join(f"{r}={known[r]}" for r in SWITCHES))

    for role, sw in SWITCHES.items():
        log_fn(f"  {sw['name']} ({sw['oob']}): service meraki connect")
        _ssh(sw["oob"], ["service meraki connect"], config=True)

    pending = dict(SWITCHES)
    deadline = time.time() + 600
    last = {}
    while pending and time.time() < deadline:
        time.sleep(30)
        for role in list(pending):
            sw = SWITCHES[role]
            try:
                out = _ssh(sw["oob"], ["show meraki connect"])
            except (paramiko.SSHException, OSError, EOFError) as e:  # SSH drops while it registers
                log_fn(f"    {sw['name']}: ssh retry ({e})")
                continue
            st = parse_meraki_connect(out)
            last[role] = (st, out)
            if st["registered"]:
                hostdb.call("cloudfabric_device_set", db_path=DB_PATH, pod_id=POD_ID,
                            role=role, serial=st["cloud_id"])
                log_fn(f"    ✓ {sw['name']} registered — Cloud ID {st['cloud_id']}")
                del pending[role]
            else:
                log_fn(f"    … {sw['name']}: cloud_id={st['cloud_id'] or '?'} "
                       f"fetch_ok={st['fetch_ok']} tunnel_up={st['tunnel_up']}")
    if pending:
        for role in pending:
            out = last.get(role, ({}, ""))[1]
            log_fn(f"  {SWITCHES[role]['name']} last `show meraki connect`:\n{out[-1500:]}")
        return False, "not registered after 10 min: " + ", ".join(SWITCHES[r]["name"] for r in pending)
    ids = _devices()
    return True, ", ".join(f"{SWITCHES[r]['name']}={ids[r]}" for r in SWITCHES)


def _inventory(serials) -> dict:
    """serial → inventory row, for the serials present in the org's inventory."""
    rows = meraki("GET", f"/organizations/{_org_id()}/inventory/devices",
                  params={"serials[]": list(serials), "perPage": 1000}) or []
    return {d["serial"]: d for d in rows}


def step_claim_devices(log_fn=print):
    """Claim the Cloud IDs into the org and add them to SITE_105 in cloud configuration mode."""
    serials = [_serial(r) for r in SWITCHES]
    net = _network_id()
    inv = _inventory(serials)

    to_org = [s for s in serials if s not in inv]
    if to_org:
        meraki("POST", f"/organizations/{_org_id()}/claim", {"serials": to_org})
        log_fn(f"  claimed into org {_org_id()}: {', '.join(to_org)}")
        inv = _inventory(serials)

    elsewhere = [s for s in serials if inv.get(s, {}).get("networkId") not in (None, net)]
    if elsewhere:
        return False, "already in another network: " + ", ".join(elsewhere)

    to_net = [s for s in serials if inv.get(s, {}).get("networkId") != net]
    if to_net:
        # No detailsByDevice: "device mode" defaults to managed (cloud configuration).
        # "monitored" would be hybrid mode, which is not what the guide wants.
        meraki("POST", f"/networks/{net}/devices/claim", {"serials": to_net})
        log_fn(f"  added to {NETWORK_NAME} (cloud configuration): {', '.join(to_net)}")
    else:
        log_fn(f"  all three already in {NETWORK_NAME}")

    # Cloud configuration upgrades and factory-resets each switch, one or two at
    # a time. "online" is NOT the signal: it goes green ~1 min after the claim,
    # while the switch is still on its CLI config with firmware "Not running
    # configured version" and live tools "unreachable" (POD-17, 2026-10-06).
    # A switch is done once it reports a real firmware and a LAN IP.
    log_fn("  waiting for cloud configuration to finish on each switch (up to 45 min)…")
    deadline = time.time() + 2700
    last = None
    while time.time() < deadline:
        state = {s: meraki("GET", f"/devices/{s}") for s in serials}
        ready = [s for s, d in state.items() if switch_converted(d)]
        line = ", ".join(f"{d.get('name') or s}={'ready' if s in ready else d.get('firmware') or '?'}"
                         for s, d in state.items())
        if line != last:
            log_fn(f"    {len(ready)}/3 converted — {line}")
            last = line
        if len(ready) == len(serials):
            return True, f"3/3 converted to cloud configuration in {NETWORK_NAME}"
        time.sleep(30)
    return False, "cloud configuration not finished within 45 min: " + last


def switch_converted(device: dict) -> bool:
    """True once Dashboard has upgraded/reset the switch into cloud configuration."""
    fw = (device.get("firmware") or "").strip()
    return bool(device.get("lanIp")) and bool(fw) and "not running" not in fw.lower()


def step_name_switches(log_fn=print):
    for role, sw in SWITCHES.items():
        meraki("PUT", f"/devices/{_serial(role)}", {"name": sw["name"]})
        log_fn(f"  {_serial(role)} → {sw['name']}")
    return True, "3 switches named"


def step_mgmt_interfaces(log_fn=print):
    """Static VLAN 1 interface per switch, preferred uplink, so cloud management
    stays on VLAN 1 once the inter-switch links become routed."""
    for role, sw in SWITCHES.items():
        log_fn(f"  {sw['name']}: {sw['mgmt_name']} {sw['mgmt_ip']}")
        _ensure_interface(_serial(role), {
            "name": sw["mgmt_name"], "mode": "vlan", "vlanId": 1,
            "subnet": MGMT_SUBNET, "interfaceIp": sw["mgmt_ip"],
            "defaultGateway": MGMT_GATEWAY, "uplinkV4": True,
            "vrf": {"name": "Default"},
        }, log_fn)
    return True, "VLAN 1 .53/.51/.52 set as preferred uplink"


def step_ise_nads(log_fn=print):
    """Register the three switches' management IPs as ISE network devices (RADIUS).

    Idempotent by IP. The SDA card registers the same names against the
    loopbacks; ISE refuses a duplicate name, so an existing same-name device
    gets the management IP added to its IP list instead.
    """
    secret = _lab_pass()
    s = requests.Session()
    s.verify = False
    s.auth = (ISE_USER, secret)
    s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})
    base = f"https://{ISE_HOST}/ers/config/networkdevice"

    r = s.get(base, params={"size": 100}, timeout=30)
    if r.status_code != 200:
        return False, f"ISE NAD list failed: {r.status_code} {r.text[:200]}"
    by_ip, by_name = {}, {}
    for res in r.json().get("SearchResult", {}).get("resources", []):
        dev = s.get(f"{base}/{res['id']}", timeout=30).json().get("NetworkDevice", {})
        by_name[dev.get("name")] = dev
        for p in dev.get("NetworkDeviceIPList", []):
            by_ip[p.get("ipaddress")] = dev

    added, skipped, merged = 0, 0, 0
    for role, sw in SWITCHES.items():
        ip = sw["mgmt_ip"]
        if ip in by_ip:
            log_fn(f"  {sw['name']} ({ip}) already in ISE as {by_ip[ip].get('name')}")
            skipped += 1
            continue
        if sw["name"] in by_name:
            dev = by_name[sw["name"]]
            dev["NetworkDeviceIPList"] = dev.get("NetworkDeviceIPList", []) + [{"ipaddress": ip, "mask": 32}]
            pr = s.put(f"{base}/{dev['id']}", json={"NetworkDevice": dev}, timeout=30)
            if pr.status_code not in (200, 201):
                return False, f"ISE NAD update failed for {sw['name']}: {pr.status_code} {pr.text[:200]}"
            log_fn(f"  {sw['name']}: added {ip} to the existing device")
            merged += 1
            continue
        payload = {"NetworkDevice": {
            "name": sw["name"],
            "description": "Cloud Fabric switch — auto-registered by pod_automator",
            "authenticationSettings": {"networkProtocol": "RADIUS",
                                       "radiusSharedSecret": secret, "enableKeyWrap": False},
            "NetworkDeviceIPList": [{"ipaddress": ip, "mask": 32}],
            "profileName": "Cisco",
        }}
        pr = s.post(base, json=payload, timeout=30)
        if pr.status_code not in (200, 201):
            return False, f"ISE NAD create failed for {sw['name']}: {pr.status_code} {pr.text[:200]}"
        log_fn(f"  {sw['name']} ({ip}) registered")
        added += 1
    return True, f"{added} added, {merged} merged, {skipped} already present"


# ── ISE TrustSec ↔ Meraki integration (guide part A step 6) ──────────────────
#
# Not in ISE's public OpenAPI (3.5p3): the admin UI drives it through
# /admin/rs/uiapi/trustsec/meraki/*. Writes carry OWASP_CSRFTOKEN, read from the
# page's hidden #CSRFTokenNameValue ("OWASP_CSRFTOKEN=<tok>"). The "Let's do it"
# wizard ends in ONE POST to /summary; contract lifted from ISE's own main.js.

ISE_MERAKI_CONNECTION = "PseudoCo_Cloud_Networking"
ISE_MERAKI_HOST = "api.meraki.com"
ISE_SYNC_INTERVAL = 12
ISE_SYNC_SGTS = ("Main", "IoT", "Production")
# The guide selects no egress policies and leaves DENY_ICMP unselected until the
# end of the lab, when the student syncs it to watch enforcement kick in.
ISE_SYNC_SGACLS = ()
ISE_UI_BASE = f"https://{ISE_HOST}/admin/rs/uiapi/trustsec/meraki"

_JS_ISE_CALL = """async ([method, url, body]) => {
    const el = document.getElementById('CSRFTokenNameValue');
    const tok = el ? String(el.value || el.getAttribute('value') || '').split('=')[1] : '';
    const headers = {'Accept': 'application/json', 'X-Requested-With': 'XMLHttpRequest',
                     'OWASP_CSRFTOKEN': tok || ''};
    if (body !== null) headers['Content-Type'] = 'application/json';
    const r = await fetch(url, {method, headers, body: body === null ? undefined : JSON.stringify(body)});
    return {status: r.status, text: await r.text()};
}"""


class IseUiSession:
    """A logged-in ISE admin tab, for the endpoints only the UI uses."""

    def __init__(self, log_fn=print):
        self.log = log_fn
        self._browser = self.page = None

    def open(self):
        self._browser = _playwright().chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        pg = self._browser.new_context(ignore_https_errors=True).new_page()
        pg.goto(f"https://{ISE_HOST}/admin/", wait_until="domcontentloaded", timeout=60_000)
        pg.wait_for_timeout(3_000)
        accept = pg.locator('button.preLoginAcceptButton, button:has-text("Accept")').first
        if accept.is_visible(timeout=3_000):        # pre-login banner
            accept.click()
            pg.wait_for_timeout(1_500)
        pg.fill('input[name="username"]', ISE_USER, timeout=10_000)
        pg.fill('input[name="password"]', _lab_pass(), timeout=10_000)
        pg.locator('#loginPage_loginSubmit, button:has-text("Login")').first.click()
        pg.wait_for_url(lambda u: "login" not in u.lower(), timeout=45_000)
        # The CSRF holder is rendered by the post-login shell.
        pg.wait_for_selector("#CSRFTokenNameValue", state="attached", timeout=60_000)
        pg.wait_for_timeout(5_000)          # the shell keeps navigating briefly after login
        self.page = pg
        self.log("  ISE admin session open")
        return self

    def call(self, method: str, path: str, body=None, ok=(200, 201, 202, 204)):
        # Without a usable OWASP_CSRFTOKEN, ISE answers 200 with its HTML shell
        # instead of JSON (seen right after login) — re-read the token and retry.
        for attempt in (1, 2):
            res = self.page.evaluate(_JS_ISE_CALL, [method, f"{ISE_UI_BASE}{path}", body])
            if res["status"] not in ok:
                raise RuntimeError(f"[ise-ui] {method} {path} → {res['status']} {res['text'][:300]}")
            text = res["text"].strip()
            if not text:
                return None
            if text[0] in "[{":
                return json.loads(text)
            self.log(f"    [ise-ui] {method} {path}: HTML instead of JSON (attempt {attempt}/2)")
            self.page.wait_for_timeout(5_000)
        raise RuntimeError(f"[ise-ui] {method} {path} → non-JSON reply (CSRF token not accepted)")

    def close(self):
        try:
            self._browser and self._browser.close()
        except PlaywrightError as e:  # best effort at teardown
            self.log(f"    ISE session close: {e}")
        self._browser = self.page = None


def _ise_connection(s: IseUiSession) -> dict | None:
    return next((c for c in (s.call("GET", "/connections") or [])
                 if c.get("name") == ISE_MERAKI_CONNECTION), None)


def build_ise_meraki_summary(api_key: str, org: dict, sgt_ids: list, sgacl_ids: list,
                             egress_ids: list = ()) -> dict:
    """Body of the wizard's final POST /summary (shape from ISE's main.js)."""
    return {"dashboardConnections": {"connections": [{
                "name": ISE_MERAKI_CONNECTION, "url": ISE_MERAKI_HOST, "apiKey": api_key,
                "organizations": [{"id": org["id"], "name": org["name"]}]}]},
            "egressPolicyIds": {"selectedIds": list(egress_ids)},
            "sgaclIds": {"selectedIds": list(sgacl_ids)},
            "sgtIds": {"selectedIds": list(sgt_ids)},
            "settings": {"syncInterval": ISE_SYNC_INTERVAL}}


def step_ise_meraki_integration(log_fn=print):
    """ISE Work Centers → TrustSec → Integrations → Meraki: connect the POD's org and
    sync the IoT/Main/Production SGTs into Meraki Adaptive Policy."""
    s = IseUiSession(log_fn).open()
    try:
        have = _ise_connection(s)
        if have and any(o.get("id") == _org_id() for o in have.get("organizations") or []):
            return True, f"already integrated — {ISE_MERAKI_CONNECTION} connected to org {_org_id()}"
        if have:
            return False, (f"{ISE_MERAKI_CONNECTION} exists but is not linked to org {_org_id()} "
                           f"— delete it (rollback) and rerun")
        # The POD's own key when one is recorded, else the lab key the rest of
        # this module uses.
        creds = hostdb.call("org_creds_for_pod", db_path=DB_PATH, pod_id=POD_ID) or {}
        key = (creds.get("meraki_api_key") or "").strip() or os.environ.get("MERAKI_API_KEY", "")
        # merakiOrganizations answered a one-off 500 "Please contact Cisco support"
        # right after a connection delete, then 200 for the identical request.
        orgs = None
        for attempt in range(4):
            try:
                orgs = s.call("POST", "/merakiOrganizations", {"url": ISE_MERAKI_HOST, "apiKey": key}) or []
                break
            except RuntimeError as e:
                log_fn(f"    merakiOrganizations attempt {attempt + 1}/4: {str(e)[:120]}")
                time.sleep(20)
        if orgs is None:
            return False, "ISE could not list Meraki orgs with the API key (4 attempts)"
        org = next((o for o in orgs if str(o.get("id") or o.get("value")) == _org_id()), None)
        if not org:
            return False, f"API key does not see org {_org_id()} ({len(orgs)} orgs offered)"
        org = {"id": str(org.get("id") or org.get("value")), "name": org.get("name") or org.get("text")}
        sgts = {g["name"]: g["id"] for g in s.call("GET", "/sgts?startAt=1&pageSize=10000&sortBy=name&order=asc") or []}
        missing = [n for n in ISE_SYNC_SGTS if n not in sgts]
        if missing:
            return False, "ISE has no SGT(s) " + ", ".join(missing)
        acls = {a["name"]: a["id"] for a in s.call("GET", "/sgacls?startAt=1&pageSize=10000&sortBy=name&order=asc") or []}
        s.call("POST", "/summary", build_ise_meraki_summary(
            key, org, [sgts[n] for n in ISE_SYNC_SGTS], [acls[n] for n in ISE_SYNC_SGACLS]))
        log_fn(f"  {ISE_MERAKI_CONNECTION} → {org['name']}, SGTs {', '.join(ISE_SYNC_SGTS)}, "
               f"sync every {ISE_SYNC_INTERVAL} min")
        # A new connection kicks off its own first sync; syncNow then answers 409
        # "System is in an incorrect state for this operation". Either way a sync runs.
        s.call("POST", "/syncService/syncNow", ok=(200, 201, 202, 204, 409))
        return True, f"{ISE_MERAKI_CONNECTION} connected to {org['name']}; sync started"
    finally:
        s.close()


def step_delete_ise_meraki(log_fn=print):
    s = IseUiSession(log_fn).open()
    try:
        have = _ise_connection(s)
        if not have:
            return True, f"no {ISE_MERAKI_CONNECTION} in ISE"
        s.call("DELETE", f"/connections/{have['id']}")
        return True, f"{ISE_MERAKI_CONNECTION} deleted from ISE"
    finally:
        s.close()


def _adaptive_groups() -> dict:
    """adaptive policy group name → (id, sgt)."""
    rows = meraki("GET", f"/organizations/{_org_id()}/adaptivePolicy/groups") or []
    return {g["name"]: (g["groupId"], g["sgt"]) for g in rows}


def step_adaptive_groups_check(log_fn=print):
    """Wait for the ISE sync to land IoT/Main/Production in Meraki Adaptive Policy."""
    deadline = time.time() + 900          # one 12-min sync cycle plus slack
    missing = []
    while time.time() < deadline:
        groups = _adaptive_groups()
        missing = [f"{g} ({sgt})" for _, _, g, sgt in NAMED_VLANS
                   if g not in groups or groups[g][1] != sgt]
        if not missing:
            return True, "IoT 18 / Main 16 / Production 19 present"
        log_fn(f"    waiting for ISE sync — missing {', '.join(missing)}")
        time.sleep(30)
    return False, "ISE → Meraki SGT sync did not land within 15 min — missing " + ", ".join(missing)


def step_vlan_profile(log_fn=print):
    """Named VLANs Main/PROD/IOT tagged with their groups; enable named VLANs for RADIUS."""
    net = _network_id()
    groups = _adaptive_groups()
    profiles = meraki("GET", f"/networks/{net}/vlanProfiles") or []
    prof = next((p for p in profiles if p.get("isDefault")), None)
    if not prof:
        return False, "no default VLAN profile in " + NETWORK_NAME

    names = [v for v in prof.get("vlanNames", [])
             if v.get("name") not in {n for n, *_ in NAMED_VLANS}
             and str(v.get("vlanId")) not in {str(i) for _, i, *_ in NAMED_VLANS}]
    for name, vid, group, _ in NAMED_VLANS:
        names.append({"name": name, "vlanId": str(vid),
                      "adaptivePolicyGroup": {"id": groups[group][0]}})
    meraki("PUT", f"/networks/{net}/vlanProfiles/{prof['iname']}", {
        "name": prof["name"], "activeVlans": prof.get("activeVlans") or "all",
        "vlanNames": names, "vlanGroups": prof.get("vlanGroups", []),
    })
    log_fn(f"  {prof['name']}: Main 10 / PROD 101 / IOT 102 tagged")
    meraki("PUT", f"/networks/{net}/settings", {"namedVlans": {"enabled": True}})
    log_fn("  Named VLANs for RADIUS enabled")
    return True, "named VLANs + adaptive policy groups set"


def _access_policy_number() -> str | None:
    pols = meraki("GET", f"/networks/{_network_id()}/switch/accessPolicies") or []
    hit = next((p for p in pols if p.get("name") == ACCESS_POLICY), None)
    return str(hit["accessPolicyNumber"]) if hit else None


def step_access_policy(log_fn=print):
    secret = _lab_pass()
    body = {
        "name": ACCESS_POLICY,
        "radiusServers": [{"host": ISE_HOST, "port": 1812, "secret": secret}],
        "radiusTestingEnabled": True,
        "radiusCoaSupportEnabled": True,
        "radiusAccountingEnabled": True,
        "radiusAccountingServers": [{"host": ISE_HOST, "port": 1813, "secret": secret}],
        "accessPolicyType": "Hybrid authentication",
        "hostMode": "Multi-Auth",
        "increaseAccessSpeed": True,          # "Concurrent Authentication"
        "urlRedirectWalledGardenEnabled": False,
    }
    net = _network_id()
    num = _access_policy_number()
    if num:
        meraki("PUT", f"/networks/{net}/switch/accessPolicies/{num}", body)
        return True, f"{ACCESS_POLICY} updated (#{num})"
    meraki("POST", f"/networks/{net}/switch/accessPolicies", body)
    return True, f"{ACCESS_POLICY} created (#{_access_policy_number()})"


def step_access_ports(log_fn=print):
    num = _access_policy_number()
    if not num:
        return False, f"access policy {ACCESS_POLICY} not found"
    for role in LEAVES:
        for port in ACCESS_PORTS:
            meraki("PUT", f"/devices/{_serial(role)}/switch/ports/{port}", {
                "type": "access", "accessPolicyType": "Custom access policy",
                "accessPolicyNumber": int(num)})
            log_fn(f"  {SWITCHES[role]['name']} port {port} → access, {ACCESS_POLICY}")
    return True, "ports 1 + 3 on both leaves"


# ── Deploy steps — B. Routed underlay ─────────────────────────────────────────

def _ensure_ospf_area0(log_fn):
    net = _network_id()
    ospf = meraki("GET", f"/networks/{net}/switch/routing/ospf") or {}
    areas = ospf.get("areas") or []
    if ospf.get("enabled") and any(str(a.get("areaId")) == "0" for a in areas):
        return
    if not any(str(a.get("areaId")) == "0" for a in areas):
        areas = areas + [{"areaId": "0", "areaName": "Area 0", "areaType": "normal"}]
    meraki("PUT", f"/networks/{net}/switch/routing/ospf", {"enabled": True, "areas": areas})
    log_fn("  OSPF enabled with Area 0")


def step_underlay_links(log_fn=print):
    _ensure_ospf_area0(log_fn)
    for role, port, name, subnet, ip in UNDERLAY_LINKS:
        log_fn(f"  {SWITCHES[role]['name']} port {port}: {name} {ip}")
        _ensure_interface(_serial(role), {
            "name": name, "mode": "routed", "switchPortId": port,
            "subnet": subnet, "interfaceIp": ip, "multicastRouting": "disabled",
            "ospfSettings": {"area": "0", "networkType": "point-to-point"},
            "vrf": {"name": "Default"},
        }, log_fn)
    return True, "4 routed /31 links, OSPF area 0 point-to-point"


def step_transit_interface(log_fn=print):
    _ensure_interface(_serial("border_spine"), {
        "name": TRANSIT["name"], "mode": "vlan", "vlanId": TRANSIT["vlan"],
        "subnet": TRANSIT["subnet"], "interfaceIp": TRANSIT["ip"],
        "multicastRouting": "disabled", "ospfSettings": {"area": "disabled"},
        "vrf": {"name": "Default"},
    }, log_fn)
    return True, f"VLAN {TRANSIT['vlan']} {TRANSIT['ip']}/31"


def step_static_route(log_fn=print):
    serial = _serial("border_spine")
    body = {"name": STATIC_ROUTE["name"], "subnet": STATIC_ROUTE["subnet"],
            "nextHopIp": STATIC_ROUTE["next_hop"],
            "advertiseViaOspfEnabled": True, "preferOverOspfRoutesEnabled": True,
            "vrf": {"name": "Default"}}
    routes = meraki("GET", f"/devices/{serial}/switch/routing/staticRoutes") or []
    hit = next((r for r in routes if r.get("subnet") == STATIC_ROUTE["subnet"]), None)
    if hit:
        meraki("PUT", f"/devices/{serial}/switch/routing/staticRoutes/{hit['staticRouteId']}", body)
        return True, f"{STATIC_ROUTE['subnet']} updated"
    meraki("POST", f"/devices/{serial}/switch/routing/staticRoutes", body)
    return True, f"{STATIC_ROUTE['subnet']} via {STATIC_ROUTE['next_hop']} (OSPF advertised)"


def _ospf_neighbors(serial: str) -> list:
    job = meraki("POST", f"/devices/{serial}/liveTools/ospfNeighbors", {})
    jid = job["ospfNeighborsId"]
    for _ in range(20):
        time.sleep(3)
        res = meraki("GET", f"/devices/{serial}/liveTools/ospfNeighbors/{jid}")
        if res.get("status") in ("complete", "failed"):
            if res.get("status") == "failed" or (res.get("error") and not res.get("routers")):
                raise MerakiError(f"ospfNeighbors live tool: {res.get('error') or 'failed'}")
            return res.get("routers") or []
    raise MerakiError("ospfNeighbors live tool did not complete")


def step_verify_ospf(log_fn=print):
    """Both leaves FULL on the Border-Spine (the guide's `show ip ospf neighbor`)."""
    serial = _serial("border_spine")
    deadline = time.time() + 600
    seen = []
    while time.time() < deadline:
        try:
            seen = _ospf_neighbors(serial)
        except MerakiError as e:
            log_fn(f"    {e}")
            seen = []
        full = {n.get("ip", "").split("/")[0] for n in seen if str(n.get("state", "")).lower() == "full"}
        full |= {n.get("id", "") for n in seen if str(n.get("state", "")).lower() == "full"}
        log_fn(f"    neighbors: " + (", ".join(f"{n.get('ip') or n.get('id')}={n.get('state')}" for n in seen) or "none"))
        if all(ip in full for ip in OSPF_NEIGHBORS):
            return True, "FULL: " + ", ".join(OSPF_NEIGHBORS)
        if sum(1 for n in seen if str(n.get("state", "")).lower() == "full") >= 2:
            return True, f"2 FULL neighbors ({', '.join(sorted(full))})"
        time.sleep(30)
    return False, "OSPF not FULL to both leaves after 10 min"


# ── C. Fabric build — Dashboard session ───────────────────────────────────────
#
# Organization → Fabric lives under /api/v1/organizations/{org}/switch/fabric but
# answers only to a logged-in Dashboard session on the shard host; the API key
# gets 404. The session comes from the iDAC card's Meraki "View" tile (SAML, no
# password, read-only — it does not reprovision anything). Writes need the
# session's CSRF token from /csrf/token as X-CSRF-Token, or they 401 with
# "invalid authenticity token". Request shapes: docs/cloud_fabric_api_capture.md.

FABRIC_NAME = "PseudoCo_Cloud_Fabric"
FABRIC_ASN = "65535"
FABRIC_LOOPBACK_POOL = "172.30.255.0/24"
FABRIC_ROLES = {"border_spine": ["Border", "Spine"], "leaf1": ["Leaf"], "leaf2": ["Leaf"]}
FABRIC_VRFS = ("Main", "PROD", "IOT")
# (name, VRF, VLAN, border interface IP/mask, eBGP neighbor) — guide part C step 5/6
BORDER_HANDOFFS = [("Main", "Main", 10,  "192.168.255.1/31", "192.168.255.0"),
                   ("PROD", "PROD", 101, "192.168.255.3/31", "192.168.255.2"),
                   ("IOT",  "IOT",  102, "192.168.255.5/31", "192.168.255.4")]
BORDER_REMOTE_AS = 65534
BORDER_MTU = 9100
# (name, VLAN, anycast gateway IP/mask) — guide part C step 7, on both leaves
FABRIC_SUBNETS = [("Main", 10,  "10.10.255.1/24"),
                  ("PROD", 101, "10.101.255.1/24"),
                  ("IOT",  102, "10.102.255.1/24")]
FABRIC_DHCP = "198.18.5.102"

_pw_driver = None


def _playwright():
    """One sync Playwright per process: a second sync_playwright().start() while the
    first is alive raises "using Playwright Sync API inside the asyncio loop" —
    which is exactly rollback's delete_fabric (Dashboard) → delete_ise_meraki (ISE)."""
    global _pw_driver
    if _pw_driver is None:
        from playwright.sync_api import sync_playwright
        _pw_driver = sync_playwright().start()
    return _pw_driver


_JS_DASH_CALL = """async ([method, path, body]) => {
    const headers = {'Accept': 'application/json'};
    if (method !== 'GET') {
        const t = await fetch('/csrf/token').then(r => r.json());
        headers['X-CSRF-Token'] = t.csrf_token;
        headers['Content-Type'] = 'application/json';
    }
    const r = await fetch('/api/v1' + path, {method, headers,
                          body: body === null ? undefined : JSON.stringify(body)});
    return {status: r.status, text: await r.text()};
}"""


class DashboardSession:
    """A logged-in Dashboard tab, opened through the iDAC card's Meraki tile."""

    def __init__(self, log_fn=print):
        self.log = log_fn
        self._browser = self.page = None

    def open(self, idac_url: str):
        import duo_automation as da          # the iDAC card helpers live there
        self._browser = _playwright().chromium.launch(headless=True)
        ctx = self._browser.new_context()
        pg = ctx.new_page()
        pg.goto(idac_url, wait_until="load", timeout=45_000)
        pg.wait_for_timeout(4_000)
        # The card lazy-mounts tiles near the viewport, so scroll while looking
        # (same reason as _scc_open_session).
        opener = None
        sections = list(da.IDAC_SCC_SECTIONS) + list(da.IDAC_NON_SCC_SECTIONS)
        for _ in range(24):
            pg.evaluate("window.scrollBy(0, 600)")
            pg.wait_for_timeout(400)
            btns = pg.evaluate(da._JS_IDAC_BTNS, sections) or []
            opener = next((b for b in btns if b.get("section") == "Meraki Dashboard"
                           and re.match(da._IDAC_OPENERS, b.get("label") or "", re.I)), None)
            if opener:
                break
            pg.wait_for_timeout(2_000)
        if not opener:
            raise RuntimeError("iDAC card has no Meraki Dashboard opener after 60s")
        try:
            with ctx.expect_page(timeout=20_000) as pi:
                pg.evaluate(da._JS_IDAC_CLICK, opener["i"])
            tab = pi.value
        except PlaywrightError as e:  # timed out waiting: the tile opened in place
            self.log(f"    no popup ({type(e).__name__}) — following the same tab")
            tab = pg
        for _ in range(40):
            host = tab.url.split("/")[2] if "://" in tab.url else ""
            if host.endswith("dashboard.meraki.com") and "/login" not in tab.url:
                break
            tab.wait_for_timeout(1_500)
        else:
            raise RuntimeError(f"Meraki tile did not land on Dashboard (at {tab.url[:80]})")
        self.page = tab
        self.log(f"  Dashboard session open on {tab.url.split('/')[2]}")
        return self

    def call(self, method: str, path: str, body=None, ok=(200, 201, 202, 204)):
        res = self.page.evaluate(_JS_DASH_CALL, [method, path, body])
        if res["status"] not in ok:
            raise MerakiError(f"[session] {method} {path} → {res['status']} {res['text'][:300]}")
        return json.loads(res["text"]) if res["text"].strip() else None

    def close(self):
        try:
            self._browser and self._browser.close()
        except PlaywrightError as e:  # best effort at teardown
            self.log(f"    session close: {e}")
        self._browser = self.page = None


_dash = None


def _dash_session(log_fn) -> DashboardSession:
    global _dash
    if _dash is None:
        creds = hostdb.call("org_creds_for_pod", db_path=DB_PATH, pod_id=POD_ID) or {}
        idac = (creds.get("idac_url") or "").strip()
        if not idac:
            raise RuntimeError("org_credentials.idac_url is empty — cannot open a Dashboard "
                               "session (never mint one: that reprovisions the orgs)")
        _dash = DashboardSession(log_fn).open(idac)
    return _dash


def close_session():
    global _dash, _pw_driver
    if _dash is not None:
        _dash.close()
        _dash = None
    if _pw_driver is not None:
        try:
            _pw_driver.stop()
        except PlaywrightError as e:
            print(f"    playwright stop: {e}")
        _pw_driver = None


def _fabric_base() -> str:
    return f"/organizations/{_org_id()}/switch/fabric"


def _find_fabric(s: DashboardSession) -> dict | None:
    return next((f for f in (s.call("GET", _fabric_base()) or []) if f.get("name") == FABRIC_NAME), None)


def _org_vrf_ids(log_fn) -> dict:
    """Main/PROD/IOT org VRF ids (public API), creating any that are missing."""
    path = f"/organizations/{_org_id()}/routing/vrfs"
    have = {v["name"]: v["vrfId"] for v in (meraki("GET", path) or {}).get("items", [])}
    for name in FABRIC_VRFS:
        if name not in have:
            v = meraki("POST", path, {"name": name})
            have[name] = v["vrfId"]
            log_fn(f"  created org VRF {name}")
    return {n: have[n] for n in FABRIC_VRFS}


def build_fabric_config(org_id: str, devices: dict, vrf_ids: dict, with_subnets: bool,
                        fabric_id: str = "") -> dict:
    """The decoded `config` blob Dashboard's fabric wizard sends.

    devices: role → public-API device record (serial, mac, lanIp, model, name,
    networkId). Ids inside the blob are client-side placeholders; eBGP rows
    reference their L3 interface by that placeholder id.
    """
    border = devices["border_spine"]["serial"]
    dev_rows = []
    for role, d in devices.items():
        row = {"type": "switch", "id": d["serial"], "serial": d["serial"], "mac": d["mac"],
               "lanIp": d.get("lanIp") or "", "model": d["model"], "name": d["name"],
               "tags": d.get("tags") or [], "stackId": "", "esiMhPairId": "",
               "switchFabricRoles": FABRIC_ROLES[role], "members": [],
               "network": {"id": d["networkId"], "name": NETWORK_NAME}, "online": True}
        if fabric_id:
            row.update(action="create", fabricId=fabric_id)
        dev_rows.append(row)
    l3, ebgp = [], []
    for n, (name, vrf, vlan, ip, nbr) in enumerate(BORDER_HANDOFFS):
        l3.append({"id": str(34 + n), "serial": border, "stackId": "", "esiMhPairId": "",
                   "action": "create", "mode": "vlan", "switchModule": "", "switchPort": "",
                   "name": name, "vrf": vrf, "mtu": BORDER_MTU, "vlan": vlan, "ipv4AndMask": ip,
                   "ipv4MulticastRouting": "disabled", "ipv6": "", "ipv6Eui64Enabled": False,
                   "ipv6Prefix": ""})
        ebgp.append({"id": str(37 + n), "serial": border, "stackId": "", "esiMhPairId": "",
                     "action": "create", "authKey": "", "ip4": nbr, "ip6": "",
                     "remoteAs": BORDER_REMOTE_AS, "sourceInterface": str(34 + n), "vrf": vrf,
                     "ip4NeighborAddressFamilyBindingId": "", "ip6NeighborAddressFamilyBindingId": ""})
    subnets = []
    if with_subnets:
        for n, (name, vlan, ip) in enumerate(FABRIC_SUBNETS):
            for m, role in enumerate(LEAVES):
                subnets.append({
                    "id": str(74 + 2 * n + m), "correlationId": str(44 + n), "name": name,
                    "vlan": vlan, "vlanName": "", "vni": 10000 + vlan, "vrf": name,
                    "ipv4AndMask": ip, "dhcpRelayIps": [FABRIC_DHCP], "dhcpRelayIp6s": [],
                    "useGlobalVrfForDhcpRelay": True, "anycastGatewayEnabled": True,
                    "broadcastReplicationEnabled": False, "ipv6": "", "ipv6Prefix": "",
                    "ipv6Eui64Enabled": False, "serial": devices[role]["serial"],
                    "stackId": "", "esiMhPairId": "", "action": "create"})
    vrfs = [{"organizationId": org_id,
             "payload": {"action": "create", "autoRd": with_subnets, "name": n, "id": vrf_ids[n]}}
            for n in FABRIC_VRFS]
    cfg = {"version": "2", "devices": dev_rows, "ebgp": ebgp, "l3Interfaces": l3,
           "ospf": [], "subnets": subnets, "vrfs": vrfs}
    if fabric_id:
        cfg = {"authKey": "", **cfg}
    return cfg


def _encode(cfg: dict) -> str:
    return base64.b64encode(json.dumps(cfg, separators=(",", ":")).encode()).decode()


def _fabric_inputs(log_fn):
    devices = {}
    for role in SWITCHES:
        d = meraki("GET", f"/devices/{_serial(role)}")
        if d.get("networkId") != _network_id():
            raise RuntimeError(f"{SWITCHES[role]['name']} is not in {NETWORK_NAME}")
        devices[role] = d
    return devices, _org_vrf_ids(log_fn)


def step_fabric_create(log_fn=print):
    """Wizard steps 2–6: fabric, roles, VRFs, border L3 + eBGP — saved to staging."""
    s = _dash_session(log_fn)
    fab = _find_fabric(s)
    if fab:
        return True, f"{FABRIC_NAME} already exists ({fab.get('status')}, id {fab['id']})"
    devices, vrf_ids = _fabric_inputs(log_fn)
    cfg = build_fabric_config(_org_id(), devices, vrf_ids, with_subnets=False)
    fab = s.call("POST", _fabric_base(), {
        "name": FABRIC_NAME, "bgpAsn": FABRIC_ASN, "status": "staged",
        "skipUnderlayGeneration": True,          # custom underlay: parts A/B built it
        "underlayIpPool": "", "underlayLoopbackIpPool": FABRIC_LOOPBACK_POOL,
        "config": _encode(cfg)})
    return True, f"{FABRIC_NAME} staged (id {fab['id']}) — 3 devices, 3 VRFs, 3 L3 + 3 eBGP"


def step_fabric_subnets(log_fn=print):
    """Wizard step 7: Main/PROD/IOT anycast subnets on both leaves, then Save changes."""
    s = _dash_session(log_fn)
    fab = _find_fabric(s)
    if not fab:
        return False, f"{FABRIC_NAME} not found — run fabric_create"
    if fab.get("status") == "deployed":
        return True, "fabric already deployed — subnets are part of it"
    vlans = [v for _, v, _ in FABRIC_SUBNETS]
    if len(set(vlans)) != len(vlans):     # the guide's "VLAN already in use" trap
        return False, f"duplicate fabric subnet VLANs: {vlans}"
    devices, vrf_ids = _fabric_inputs(log_fn)
    cfg = build_fabric_config(_org_id(), devices, vrf_ids, with_subnets=True, fabric_id=fab["id"])
    s.call("PUT", f"{_fabric_base()}/{fab['id']}", {
        "name": FABRIC_NAME, "skipUnderlayGeneration": True, "underlayIpPool": "",
        "underlayLoopbackIpPool": FABRIC_LOOPBACK_POOL, "config": _encode(cfg)})
    return True, "3 subnets × 2 leaves staged (VNI 10010 / 10101 / 10102)"


def step_fabric_deploy(log_fn=print):
    s = _dash_session(log_fn)
    fab = _find_fabric(s)
    if not fab:
        return False, f"{FABRIC_NAME} not found"
    path = f"{_fabric_base()}/{fab['id']}"
    if fab.get("status") != "deployed":
        job = s.call("POST", f"{path}/deploy?async=true",
                     {"devices": [_serial(r) for r in SWITCHES], "stacks": []})
        log_fn(f"  deploy job {job.get('id')} {job.get('status')}")
    deadline = time.time() + 900
    while time.time() < deadline:
        fab = s.call("GET", path)
        job = fab.get("lastJob") or {}
        log_fn(f"    fabric={fab.get('status')} job={job.get('status')}/{job.get('result')}")
        if job.get("errors"):
            return False, "deploy failed: " + "; ".join(map(str, job["errors"]))[:300]
        if fab.get("status") == "deployed" and job.get("status") == "complete":
            return True, "Deployed — last deploy: Success"
        time.sleep(15)
    return False, "deploy did not complete within 15 min"


def step_verify_fabric(log_fn=print):
    """Guide 'Verify & Enforce': summary counts and BGP state."""
    s = _dash_session(log_fn)
    fab = _find_fabric(s)
    if not fab:
        return False, f"{FABRIC_NAME} not found"
    fid, base = fab["id"], _fabric_base()
    # neighborStats is a periodic snapshot, not live: after a deploy it stays empty
    # until the next collection (1.5 min on one run, ~11 min on the next, with the
    # sessions Established the whole time). Wait out a full collection cycle.
    deadline = time.time() + 1500
    detail = ""
    while time.time() < deadline:
        sm = s.call("GET", f"{base}/{fid}/summary")
        ebgp = (s.call("GET", f"{base}/neighborStats?fabricId={fid}&nodeType=ebgp&perPage=1000") or {}).get("items", [])
        ibgp = (s.call("GET", f"{base}/neighborStats?fabricId={fid}&nodeType=ibgp&perPage=1000") or {}).get("items", [])
        counts = (sm["vrfCount"]["deployed"], sm["fabricSubnetCount"]["deployed"],
                  sm["borderConfiguration"]["deployed"])
        e_up = sum(1 for n in ebgp if (n.get("connection") or {}).get("state") == "Established")
        i_up = sum(1 for n in ibgp if (n.get("connection") or {}).get("state") == "Established")
        detail = (f"VRFs {counts[0]}/3, subnets {counts[1]}/6, border {counts[2]}/3, "
                  f"eBGP {e_up}/3, iBGP {i_up}/{len(ibgp)}")
        log_fn(f"    {detail}" + ("  (waiting for Dashboard's BGP stats snapshot)"
                                    if not ebgp and not ibgp else ""))
        # iBGP: the Border-Spine (route reflector) to both leaves is what carries
        # the overlay; a leaf's own row can lag behind in the stats.
        spine_up = sum(1 for n in ibgp if n.get("name") == SWITCHES["border_spine"]["name"]
                       and (n.get("connection") or {}).get("state") == "Established")
        if counts == (3, 6, 3) and e_up == 3 and spine_up >= 2:
            return True, detail
        time.sleep(30)
    return False, "not converged after 25 min: " + detail


def step_delete_fabric(log_fn=print):
    """Must run before the switches leave SITE_105: removal fails while BGP is configured."""
    s = _dash_session(log_fn)
    fab = _find_fabric(s)
    if not fab:
        return True, f"no {FABRIC_NAME} — nothing to delete"
    s.call("DELETE", f"{_fabric_base()}/{fab['id']}")
    return True, f"{FABRIC_NAME} deleted (SVIs, loopbacks, OSPF areas, roles removed)"


DEPLOY_STEPS = [
    ("meraki_connect",        step_meraki_connect),
    ("claim_devices",         step_claim_devices),
    ("name_switches",         step_name_switches),
    ("mgmt_interfaces",       step_mgmt_interfaces),
    ("ise_nads",              step_ise_nads),
    ("ise_meraki_integration", step_ise_meraki_integration),
    ("adaptive_groups_check", step_adaptive_groups_check),
    ("vlan_profile",          step_vlan_profile),
    ("access_policy",         step_access_policy),
    ("access_ports",          step_access_ports),
    ("underlay_links",        step_underlay_links),
    ("transit_interface",     step_transit_interface),
    ("static_route",          step_static_route),
    ("verify_ospf",           step_verify_ospf),
    ("fabric_create",         step_fabric_create),
    ("fabric_subnets",        step_fabric_subnets),
    ("fabric_deploy",         step_fabric_deploy),
    ("verify_fabric",         step_verify_fabric),
]


# ── Rollback steps ────────────────────────────────────────────────────────────

def step_remove_devices(log_fn=print):
    """Take the three switches out of SITE_105."""
    serials = [s for s in (_devices().get(r) for r in SWITCHES) if s]
    if not serials:
        return True, "no Cloud IDs recorded — nothing to remove"
    inv = _inventory(serials)
    removed = 0
    for s in serials:
        net = inv.get(s, {}).get("networkId")
        if not net:
            continue
        meraki("POST", f"/networks/{net}/devices/remove", {"serial": s})
        log_fn(f"  removed {s} from {net}")
        removed += 1
    return True, f"{removed} removed from network"


def step_release_devices(log_fn=print):
    """Unclaim the three switches from the org inventory."""
    serials = [s for s in (_devices().get(r) for r in SWITCHES) if s]
    inv = _inventory(serials)
    present = [s for s in serials if s in inv]
    if not present:
        return True, "not in org inventory"
    meraki("POST", f"/organizations/{_org_id()}/inventory/release", {"serials": present})
    return True, "released: " + ", ".join(present)


ROLLBACK_STEPS = [
    ("delete_fabric",   step_delete_fabric),
    ("delete_ise_meraki", step_delete_ise_meraki),
    ("remove_devices",  step_remove_devices),
    ("release_devices", step_release_devices),
]


# ── Core-pipeline cleanup: leave the Meraki org as the lab starts it ──────────
#
# Runs on EVERY POD after scc_reset_check (onboard.py). It discovers what exists
# rather than trusting what this tab recorded, so it also removes a previous
# student's work. Kept: the org VRFs Main/PROD/IOT, OSPF area 0 and SITE_105
# itself — the guide expects those. Removed: everything the lab builds.

LAB_ACLS = ("DENY_ICMP",)
LAB_GROUPS = {g for _, _, g, _ in NAMED_VLANS}        # Main / Production / IoT


def lab_switches(net_devices: list, recorded: set) -> list:
    """The Site_105 C9300s in SITE_105: recorded Cloud IDs, or the guide's names."""
    names = {sw["name"] for sw in SWITCHES.values()}
    return [d for d in net_devices
            if d.get("serial") in recorded
            or (str(d.get("model", "")).startswith("C9") and d.get("name") in names)]


def lab_vlan_names(vlan_names: list) -> list:
    """The VLAN profile's named VLANs with the lab's Main/PROD/IOT taken out."""
    ours = {n for n, *_ in NAMED_VLANS}
    ids = {str(i) for _, i, *_ in NAMED_VLANS}
    return [v for v in vlan_names if v.get("name") not in ours and str(v.get("vlanId")) not in ids]


def _cleanup_fabric(log_fn):
    creds = hostdb.call("org_creds_for_pod", db_path=DB_PATH, pod_id=POD_ID) or {}
    if not (creds.get("idac_url") or "").strip():
        raise RuntimeError("no idac_url for this org — cannot open a Dashboard session")
    return step_delete_fabric(log_fn)[1]


def _cleanup_switches(log_fn):
    net = _network_id()
    recorded = set(_devices().values())
    found = lab_switches(meraki("GET", f"/networks/{net}/devices") or [], recorded)
    for d in found:
        meraki("POST", f"/networks/{net}/devices/remove", {"serial": d["serial"]})
        log_fn(f"    removed {d.get('name') or d['serial']} from {NETWORK_NAME}")
    serials = {d["serial"] for d in found} | recorded
    inv = _inventory(serials) if serials else {}
    if inv:
        meraki("POST", f"/organizations/{_org_id()}/inventory/release", {"serials": sorted(inv)})
    return f"{len(found)} removed, {len(inv)} unclaimed"


def _cleanup_switching(log_fn):
    net = _network_id()
    done = []
    pols = meraki("GET", f"/networks/{net}/switch/accessPolicies") or []
    for p in pols:
        if p.get("name") == ACCESS_POLICY:
            meraki("DELETE", f"/networks/{net}/switch/accessPolicies/{p['accessPolicyNumber']}")
            done.append(f"access policy {ACCESS_POLICY}")
    for prof in meraki("GET", f"/networks/{net}/vlanProfiles") or []:
        keep = lab_vlan_names(prof.get("vlanNames", []))
        if len(keep) != len(prof.get("vlanNames", [])):
            meraki("PUT", f"/networks/{net}/vlanProfiles/{prof['iname']}", {
                "name": prof["name"], "activeVlans": prof.get("activeVlans") or "all",
                "vlanNames": keep, "vlanGroups": prof.get("vlanGroups", [])})
            done.append(f"named VLANs in {prof['name']}")
    if (meraki("GET", f"/networks/{net}/settings") or {}).get("namedVlans", {}).get("enabled"):
        meraki("PUT", f"/networks/{net}/settings", {"namedVlans": {"enabled": False}})
        done.append("named VLANs for RADIUS off")
    return ", ".join(done) or "nothing to reset"


def _cleanup_adaptive_policy(log_fn):
    """ISE-synced policy, ACL and SGTs. Runs after the ISE connection is gone, or
    ISE would push them straight back on its next sync."""
    org = _org_id()
    base = f"/organizations/{org}/adaptivePolicy"
    done = []
    for p in meraki("GET", f"{base}/policies") or []:
        if {p["sourceGroup"]["name"], p["destinationGroup"]["name"]} & LAB_GROUPS:
            meraki("DELETE", f"{base}/policies/{p['adaptivePolicyId']}")
            done.append(f"policy {p['sourceGroup']['name']}→{p['destinationGroup']['name']}")
    for a in meraki("GET", f"{base}/acls") or []:
        if a["name"] in LAB_ACLS:
            meraki("DELETE", f"{base}/acls/{a['aclId']}")
            done.append(f"ACL {a['name']}")
    for g in meraki("GET", f"{base}/groups") or []:
        if g["name"] in LAB_GROUPS and not g.get("isDefaultGroup"):
            meraki("DELETE", f"{base}/groups/{g['groupId']}")
            done.append(f"group {g['name']} ({g['sgt']})")
    return ", ".join(done) or "nothing synced"


# Order matters: the fabric holds BGP on the switches (removal fails while it
# exists); the ISE connection must go before its SGTs or ISE re-syncs them; the
# VLAN profile references the groups, so it is reset before they are deleted.
CLEANUP_PARTS = [
    ("fabric",           _cleanup_fabric),
    ("ISE integration",  lambda log_fn: step_delete_ise_meraki(log_fn)[1]),
    ("switches",         _cleanup_switches),
    ("switching config", _cleanup_switching),
    ("adaptive policy",  _cleanup_adaptive_policy),
]


def meraki_cleanup(log_fn=print):
    """Core-pipeline step: (ok, summary). Each part is independent — one failing
    is reported but does not stop the rest."""
    results, failed = [], []
    try:
        for name, fn in CLEANUP_PARTS:
            try:
                msg = fn(log_fn)
                log_fn(f"  ✓ {name}: {msg}")
                results.append(f"{name}: {msg}")
            except STEP_ERRORS as e:
                log_fn(f"  ✗ {name}: {type(e).__name__}: {e}")
                failed.append(f"{name}: {str(e)[:120]}")
    finally:
        close_session()
    if POD_ID:   # the Cloud Fabric card no longer describes this org
        ensure_table()
        for mode in ("deploy", "rollback"):
            hostdb.call("cloudfabric_clear_mode", db_path=DB_PATH, pod_id=POD_ID, mode=mode)
    if failed:
        return False, "partial — " + "; ".join(failed)
    return True, "; ".join(results)


# ── Runners ───────────────────────────────────────────────────────────────────

# What a step can raise and still leave the run in a reportable state: API and
# SSH failures, a missing prerequisite, or an unexpected response shape. Anything
# else is a bug and should surface as a traceback in the log.
STEP_ERRORS = (RuntimeError, requests.RequestException, paramiko.SSHException, OSError,
               EOFError, hostdb.HostDBError, KeyError, ValueError, TypeError,
               PlaywrightError)

def _run_steps(mode, steps, start_idx, skip, log_fn):
    for name, fn in steps[start_idx:]:
        if name in skip:
            log_fn(f"── {name}: already completed, skipping")
            continue
        log_fn(f"── {name}")
        _set_step(mode, name, "running")
        try:
            ok, detail = fn(log_fn)
        except STEP_ERRORS as e:
            ok, detail = False, f"{type(e).__name__}: {e}"
        _set_step(mode, name, "completed" if ok else "failed", detail)
        log_fn(f"   {'✓' if ok else '✗'} {name}: {detail}")
        if not ok:
            return False, f"{name}: {detail}"
    return True, "all steps completed"


def run_deploy(from_step=None, log_fn=print):
    try:
        return _run_deploy(from_step, log_fn)
    finally:
        close_session()


def _run_deploy(from_step=None, log_fn=print):
    """Resume from the first step not yet completed, or rerun from `from_step`."""
    ensure_table()
    hostdb.call("cloudfabric_reset_running", db_path=DB_PATH, pod_id=POD_ID, mode="deploy")
    names = [n for n, _ in DEPLOY_STEPS]
    if from_step:
        if from_step not in names:
            return False, f"unknown step {from_step}"
        return _run_steps("deploy", DEPLOY_STEPS, names.index(from_step), set(), log_fn)
    done = set(hostdb.call("cloudfabric_completed", db_path=DB_PATH, pod_id=POD_ID, mode="deploy") or [])
    return _run_steps("deploy", DEPLOY_STEPS, 0, done, log_fn)


def run_rollback(log_fn=print):
    try:
        return _run_rollback(log_fn)
    finally:
        close_session()


def _run_rollback(log_fn=print):
    ensure_table()
    hostdb.call("cloudfabric_clear_mode", db_path=DB_PATH, pod_id=POD_ID, mode="rollback")
    ok, msg = _run_steps("rollback", ROLLBACK_STEPS, 0, set(), log_fn)
    if ok:
        hostdb.call("cloudfabric_clear_mode", db_path=DB_PATH, pod_id=POD_ID, mode="deploy")
    return ok, msg


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Cloud Fabric automation")
    ap.add_argument("mode", nargs="?", choices=["deploy", "rollback"])
    ap.add_argument("--from", dest="from_step")
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list or not a.mode:
        for i, (n, _) in enumerate(DEPLOY_STEPS, 1):
            print(f"{i:2}. {n}")
        print("rollback: " + ", ".join(n for n, _ in ROLLBACK_STEPS))
        sys.exit(0)
    ok, msg = run_deploy(a.from_step) if a.mode == "deploy" else run_rollback()
    print(("OK: " if ok else "FAIL: ") + msg)
    sys.exit(0 if ok else 1)
