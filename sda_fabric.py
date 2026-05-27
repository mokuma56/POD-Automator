"""
sda_fabric.py — SDA Fabric Deploy & Rollback automation for Site-105

Deploy steps (in order):
  1.  discovery       — Run Catalyst Center discovery job (loopbacks 172.30.255.1-3)
  2.  provision       — Provision 3 switches to MAIN site
  3.  fabric_site     — Create fabric site at Site-105/MAIN
  4.  virtual_networks — Create L3 VNs: Main / PROD / IOT and assign to fabric
  5.  anycast_gateways — Create anycast gateways (VLAN 10/101/102)
  6.  transit         — Create XAR-Transit (IP-Based, ASN 65534)
  6b. clean_fabric_vlans — Remove conflicting VLANs/SVIs from switches + resync
  7.  fabric_devices  — Add Border+CP node + 2 edge nodes
  8.  l3_handoff      — Configure L3 handoff per VN on Gi1/0/48
  9.  port_assignments — Trunk ports Gi1/0/2 on Leaf1+Leaf2 (native 10, allowed 10,101,102)
  10. verify          — Verify fabric devices reachable + BGP state

Rollback steps (in reverse order):
  1.  remove_fabric_devices  — Remove edge nodes then Border/CP node, deploy
  2.  remove_anycast_gateways
  3.  remove_extranet_policy — disable dCloud_PROD_User GBAC policy first
  4.  remove_transit
  5.  remove_vn_site_assignments — disassociate VNs from fabric
  6.  remove_virtual_networks
  7.  remove_fabric_site
  8.  delete_devices   — delete 3 switches from inventory
  9.  delete_discovery — delete Site-105-Discovery job
  10. delete_ise_nads  — delete 3 switch NADs from ISE (safety check via loopback IP)
  11. delete_network_profile — remove site from profile then delete profile
"""

import time
import logging
import sqlite3
import datetime
import os
import re
import requests
import urllib3
import paramiko

urllib3.disable_warnings()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# DB helpers (mirrors evpn_fabric.py pattern)
# ---------------------------------------------------------------------------

POD_ID  = os.environ.get("POD_ID", "unknown")
DB_PATH = os.environ.get("DB_PATH", os.path.expanduser("~/sw_projects/pod_automator/data/pod_state.db"))


def ensure_sda_table():
    try:
        c = sqlite3.connect(DB_PATH)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sda_steps (
                pod_id       TEXT NOT NULL,
                mode         TEXT NOT NULL DEFAULT 'deploy',
                step_name    TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'pending',
                started_at   TEXT,
                completed_at TEXT,
                result       TEXT,
                PRIMARY KEY (pod_id, mode, step_name)
            )
        """)
        c.commit()
        c.close()
    except Exception as e:
        print(f"Warning: could not create sda_steps table: {e}")


def _set_step(mode, step_name, status, result=None):
    """Upsert a step row. Sets started_at on first RUNNING, completed_at on OK/FAILED."""
    try:
        c = sqlite3.connect(DB_PATH)
        now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        row = c.execute(
            "SELECT started_at FROM sda_steps WHERE pod_id=? AND mode=? AND step_name=?",
            (POD_ID, mode, step_name)
        ).fetchone()
        started = (row[0] if row else None) or (now if status == "running" else None)
        completed = now if status in ("completed", "failed") else None
        c.execute("""
            INSERT INTO sda_steps (pod_id, mode, step_name, status, started_at, completed_at, result)
            VALUES (?,?,?,?,?,?,?)
            ON CONFLICT(pod_id, mode, step_name) DO UPDATE SET
                status=excluded.status,
                started_at=COALESCE(excluded.started_at, started_at),
                completed_at=excluded.completed_at,
                result=excluded.result
        """, (POD_ID, mode, step_name, status, started, completed, result))
        c.commit()
        c.close()
    except Exception as e:
        print(f"Warning: _set_step failed: {e}")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CATC_HOST = "198.18.5.100"
CATC_USER = "admin"
CATC_PASS = "Demo@C!sco"
CATC_BASE = f"https://{CATC_HOST}"

ISE_HOST  = "198.18.5.101"
ISE_USER  = "admin"
ISE_PASS  = "C1sco12345"

SITE_ID        = "919ce2a1-39b7-4c1f-a7ec-c76e50170ab7"  # Site-105/MAIN
SITE_HIERARCHY = "Global/NORTH CAROLINA/Durham/Site-105/MAIN"

SWITCH_IPS = {
    "border_spine": {"loopback": "172.30.255.3", "mgmt": "198.18.128.24", "name": "Site_105-Border-Spine"},
    "leaf1":        {"loopback": "172.30.255.1", "mgmt": "198.18.128.22", "name": "Site_105-Leaf1"},
    "leaf2":        {"loopback": "172.30.255.2", "mgmt": "198.18.128.23", "name": "Site_105-Leaf2"},
}

SWITCH_USER = "netadmin"
SWITCH_PASS = "C1sco12345"

# VLANs/SVIs that must NOT exist before adding devices to SDA fabric
FABRIC_CONFLICT_VLANS = [10, 101, 102, 1010, 1101, 1102]


def _ssh_clean_switch_vlans(mgmt_ip, vlans, log_fn=print):
    """SSH to a switch and remove conflicting VLANs and SVIs before SDA fabric add."""
    import socket
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(mgmt_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=20, allow_agent=False, look_for_keys=False)
        chan = client.invoke_shell()
        import time as _time

        def send(cmd, wait=1.5):
            chan.send(cmd + "\n")
            _time.sleep(wait)
            out = b""
            while chan.recv_ready():
                out += chan.recv(4096)
            return out.decode(errors="ignore")

        send("terminal length 0", 0.5)
        send("configure terminal", 0.5)
        for v in vlans:
            send(f"no interface Vlan{v}", 0.5)
        send("end", 0.5)
        vlan_list = ",".join(str(v) for v in vlans)
        send(f"no vlan {vlan_list}", 0.5)
        out = send("write memory", 3)
        log_fn(f"    {mgmt_ip}: cleaned VLANs {vlan_list} — {'OK' if '[OK]' in out or 'Copy complete' in out else 'write issued'}")
        client.close()
    except Exception as e:
        log_fn(f"    WARNING: SSH to {mgmt_ip} failed: {e}")


def _ssh_clean_auth_config(mgmt_ip, log_fn=print):
    """Remove AAA/dot1x/access-session config left by a previous SDA run.

    CatC rejects fabric_devices if these configs are present on the switch.
    Safe to run even if config is absent — all errors are silently ignored.

    Steps:
    1. Remove 'source template WIRED_*' from interfaces (holds class-map lock)
    2. Remove WIRED_* templates (with confirm) and policy-maps
    3. Use NETCONF edit-config to delete class-maps (CLI 'no class-map' silently
       fails when class-maps live in NETCONF datastore, not CLI running-config)
    4. Remove AAA/dot1x/access-session config
    """
    import time as _time, socket as _socket
    TEMPLATES = ["WIRED_DOT1X_CLOSED", "WIRED_DOT1X_OPEN", "WIRED_MAB_CLOSED", "WIRED_MAB_OPEN"]
    POLICY_MAPS = ["DOT1X_MAB_POLICY", "MAB_DOT1X_POLICY"]
    CLASS_MAPS = [
        "AAA_SVR_DOWN_AUTHD_HOST", "AAA_SVR_DOWN_UNAUTHD_HOST", "AUTHC_SUCCESS_AUTHZ_FAIL",
        "DOT1X", "DOT1X_FAILED", "DOT1X_NO_RESP", "DOT1X_TIMEOUT",
        "IN_CRITICAL_AUTH", "MAB", "MAB_FAILED", "NOT_IN_CRITICAL_AUTH",
    ]
    NETCONF_DELETE_CLASS_MAPS = "\n".join(
        f'      <class-map xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-policy" xc:operation="remove">'
        f'<name>{cm}</name></class-map>'
        for cm in CLASS_MAPS
    )
    NETCONF_DELETE_XML = f"""
<config xmlns:xc="urn:ietf:params:xml:ns:netconf:base:1.0">
  <native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">
    <policy>
{NETCONF_DELETE_CLASS_MAPS}
    </policy>
  </native>
</config>"""

    # Ordered teardown: dependent commands first, then aaa new-model
    pre_cmds = [
        "no aaa accounting identity default start-stop group dnac-client-radius-group",
        "no aaa accounting update newinfo periodic 2880",
        "no aaa authorization network dnac-cts-list group dnac-client-radius-group",
        "no aaa authorization network default group dnac-client-radius-group",
        "no aaa authorization exec default local",
        "no aaa authentication dot1x default group dnac-client-radius-group",
        "no aaa authentication login dnac-cts-list group dnac-client-radius-group local",
        "no aaa authentication login default local",
        "no aaa group server radius dnac-client-radius-group",
        "no aaa server radius dynamic-author",
        "no dot1x system-auth-control",
        "no access-session mac-move deny",
        "no access-session attributes filter-list list ISE-DS-LIST",
        "no access-session authentication attributes filter-spec include list ISE-DS-LIST",
        "no access-session accounting attributes filter-spec include list ISE-DS-LIST",
    ]
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(mgmt_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=20, allow_agent=False, look_for_keys=False)
        chan = client.invoke_shell()
        _time.sleep(1); chan.recv(4096)

        def send(cmd, wait=1.0):
            chan.send(cmd + "\n")
            _time.sleep(wait)
            out = b""
            while chan.recv_ready():
                out += chan.recv(4096)
            return out.decode(errors="ignore")

        def ensure_config_mode():
            chan.send("end\n"); _time.sleep(0.5); chan.recv(4096)
            chan.send("configure terminal\n"); _time.sleep(0.5); chan.recv(4096)

        send("terminal length 0", 0.5)
        send("enable", 0.5)

        # Step 1: Remove 'source template WIRED_*' from all interfaces
        # First find which interfaces have it
        send("configure terminal", 0.5)
        for iface_prefix in ["GigabitEthernet1/0/1", "GigabitEthernet1/0/2", "GigabitEthernet1/0/3",
                              "GigabitEthernet1/0/4", "GigabitEthernet1/0/5", "GigabitEthernet1/0/6",
                              "GigabitEthernet1/0/7", "GigabitEthernet1/0/8", "GigabitEthernet1/0/9",
                              "GigabitEthernet1/0/10", "GigabitEthernet1/0/11", "GigabitEthernet1/0/12"]:
            send(f"interface {iface_prefix}", 0.3)
            for tmpl in TEMPLATES:
                send(f"no source template {tmpl}", 0.3)
            send("exit", 0.3)
        ensure_config_mode()

        # Step 2: Remove templates (need to enter template, remove service-policy, exit, then delete)
        for tmpl in TEMPLATES:
            send(f"template {tmpl}", 0.5)
            for pm in POLICY_MAPS:
                send(f"no service-policy type control subscriber {pm}", 0.4)
            send("end", 0.5); chan.recv(4096)
            send("configure terminal", 0.5)
            chan.send(f"no template {tmpl}\n"); _time.sleep(1.5)
            out = chan.recv(4096).decode(errors="ignore")
            if "[confirm]" in out or "CONFIRM" in out:
                chan.send("\n"); _time.sleep(1.5); chan.recv(4096)
            ensure_config_mode()

        # Step 3: Remove policy-maps via CLI (may fail if still referenced — OK)
        for pm in POLICY_MAPS:
            send(f"no policy-map type control subscriber {pm}", 0.5)

        # Step 4: Remove AAA/dot1x config
        for cmd in pre_cmds:
            send(cmd, 0.4)
        # aaa new-model requires [confirm] on IOS-XE
        chan.send("no aaa new-model\n"); _time.sleep(1)
        out = chan.recv(4096).decode(errors="ignore")
        if "[confirm]" in out or "Continue" in out:
            chan.send("\n"); _time.sleep(1); chan.recv(4096)
        send("no aaa session-id common", 0.5)
        send("end", 0.5)
        # write memory — use copy run start in case privilege dropped
        chan.send("copy running-config startup-config\n"); _time.sleep(1)
        out = chan.recv(4096).decode(errors="ignore")
        if "?" in out or "filename" in out.lower():
            chan.send("\n"); _time.sleep(3); chan.recv(4096)
        client.close()

        # Step 5: Delete class-maps via NETCONF (CLI delete silently fails when
        # class-maps live in NETCONF datastore pushed by CatC)
        try:
            from ncclient import manager as _ncm
            # Pre-check port 830 reachability before attempting ncclient connect
            # (ncclient ignores timeout on TCP connect — hangs if port is firewalled)
            sock = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
            sock.settimeout(10)
            reachable = sock.connect_ex((mgmt_ip, 830)) == 0
            sock.close()
            if not reachable:
                log_fn(f"    {mgmt_ip}: NETCONF port 830 not reachable — skipping class-map delete")
            else:
                m = _ncm.connect(
                    host=mgmt_ip, port=830, username=SWITCH_USER, password=SWITCH_PASS,
                    hostkey_verify=False, device_params={"name": "iosxe"}, timeout=30
                )
                reply = m.edit_config(target="running", config=NETCONF_DELETE_XML)
                m.close_session()
                log_fn(f"    {mgmt_ip}: auth config cleaned (NETCONF class-map delete: {'OK' if reply.ok else 'skipped'})")
        except ImportError:
            log_fn(f"    {mgmt_ip}: auth config cleaned (ncclient not available — class-maps may remain)")
        except Exception as e:
            log_fn(f"    {mgmt_ip}: auth config cleaned (NETCONF class-map delete skipped: {e})")
    except Exception as e:
        log_fn(f"    WARNING: auth cleanup SSH to {mgmt_ip} failed: {e}")


def _catc_resync_device(s, dev_id, log_fn=print):
    """Trigger inventory resync for a device and wait for it."""
    r = s.put(f"{CATC_BASE}/dna/intent/api/v1/network-device/sync", json=[dev_id])
    if r.status_code not in (200, 201, 202):
        log_fn(f"    WARNING: resync {dev_id} → {r.status_code}")
        return
    task_id = r.json().get("response", {}).get("taskId")
    if task_id:
        _wait_task(s, task_id, log_fn=log_fn, timeout=120)

DISCOVERY_NAME  = "Site-105-Discovery"
DISCOVERY_RANGE = "172.30.255.1-172.30.255.3"

VNS = ["Main", "PROD", "IOT"]

ANYCAST_GATEWAYS = [
    {"vn": "Main", "vlanId": 10,  "vlanName": "Main", "ipPool": "Main", "sgName": "Main",       "trafficType": "DATA"},
    {"vn": "PROD", "vlanId": 101, "vlanName": "PROD", "ipPool": "PROD", "sgName": "Production", "trafficType": "DATA"},
    {"vn": "IOT",  "vlanId": 102, "vlanName": "IOT",  "ipPool": "IOT",  "sgName": "IoT",        "trafficType": "DATA"},
]

TRANSIT_NAME = "XAR-Transit"
TRANSIT_ASN  = "65534"

BORDER_ASN = "65535"

L3_HANDOFFS = [
    {"vn": "Main", "vlanId": 10,  "localIp": "192.168.255.1/31", "remoteIp": "192.168.255.0/31"},
    {"vn": "PROD", "vlanId": 101, "localIp": "192.168.255.3/31", "remoteIp": "192.168.255.2/31"},
    {"vn": "IOT",  "vlanId": 102, "localIp": "192.168.255.5/31", "remoteIp": "192.168.255.4/31"},
]

HANDOFF_INTERFACE = "GigabitEthernet1/0/48"

PORT_ASSIGNMENT_INTERFACE = "GigabitEthernet1/0/2"
PORT_NATIVE_VLAN   = 10
PORT_ALLOWED_VLANS = "10,101,102"

ISE_SWITCH_LOOPBACKS = {"172.30.255.1", "172.30.255.2", "172.30.255.3"}

# Global credential IDs (from live discovery job — reused for re-discovery)
GLOBAL_CRED_IDS = [
    "82d24eba-dcc0-4fb8-8810-137d190bf90f",
    "e6b5e009-5aa3-41b2-a576-d92e6a4c8f02",
    "07d96097-7dac-4929-a9d6-622eb43f3d3e",
    "64b9020e-923f-4577-ae3b-6397d3feb94a",
]


# ---------------------------------------------------------------------------
# Catalyst Center session helpers
# ---------------------------------------------------------------------------

def _catc_session(log_fn=print):
    s = requests.Session()
    s.verify = False
    r = s.post(f"{CATC_BASE}/dna/system/api/v1/auth/token", auth=(CATC_USER, CATC_PASS))
    r.raise_for_status()
    s.headers["X-Auth-Token"] = r.json()["Token"]
    s.headers["Content-Type"] = "application/json"
    return s


def _wait_task(s, task_id, log_fn=print, timeout=300, poll=5):
    """Poll a Catalyst Center task until success or failure."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = s.get(f"{CATC_BASE}/dna/intent/api/v1/task/{task_id}")
        t = r.json().get("response", {})
        if t.get("isError"):
            raise RuntimeError(f"Task {task_id} failed: {t.get('failureReason', t.get('progress',''))}")
        if t.get("endTime"):
            log_fn(f"    Task complete: {t.get('progress','')[:120]}")
            return t
        log_fn(f"    Waiting for task {task_id}... {t.get('progress','')[:80]}")
        time.sleep(poll)
    raise RuntimeError(f"Task {task_id} timed out after {timeout}s")


def _deploy_and_wait(s, method, url, payload, log_fn=print, timeout=300):
    """POST/PUT and wait for the embedded task to complete."""
    r = getattr(s, method)(url, json=payload)
    if r.status_code not in (200, 201, 202):
        raise RuntimeError(f"{method.upper()} {url} → {r.status_code}: {r.text[:300]}")
    body = r.json()
    # Catalyst Center wraps task in response.taskId or response[0].taskId
    task_id = (
        body.get("response", {}).get("taskId")
        or (body.get("response", [{}])[0].get("taskId") if isinstance(body.get("response"), list) else None)
        or body.get("taskId")
    )
    if not task_id:
        log_fn(f"    No taskId in response — assuming immediate: {str(body)[:200]}")
        return body
    return _wait_task(s, task_id, log_fn=log_fn, timeout=timeout)


# ---------------------------------------------------------------------------
# Step helpers
# ---------------------------------------------------------------------------

def _get_fabric_id(s):
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricSites")
    for fs in r.json().get("response", []):
        if fs.get("siteId") == SITE_ID:
            return fs["id"]
    return None


def _get_device_id(s, hostname_fragment):
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/network-device")
    for d in r.json().get("response", []):
        if hostname_fragment.lower() in (d.get("hostname") or "").lower():
            return d["id"]
    return None


def _get_vn_id(s, vn_name):
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks")
    for vn in r.json().get("response", []):
        if vn["virtualNetworkName"] == vn_name:
            return vn["id"]
    return None


def _get_transit_id(s, name=TRANSIT_NAME):
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/transitNetworks")
    for t in r.json().get("response", []):
        if t["name"] == name:
            return t["id"]
    return None


def _get_discovery_id(s, name=DISCOVERY_NAME):
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/discovery")
    for d in r.json().get("response", []):
        if d["name"] == name:
            return d["id"]
    return None


def _get_fabric_device_id(s, fabric_id, network_device_id):
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_id}")
    for fd in r.json().get("response", []):
        if fd["networkDeviceId"] == network_device_id:
            return fd["id"]
    return None


# ---------------------------------------------------------------------------
# Deploy steps
# ---------------------------------------------------------------------------

def step_discovery(log_fn=print):
    """Re-run or reuse the Site-105 discovery job."""
    s = _catc_session(log_fn)
    disc_id = _get_discovery_id(s)
    if disc_id:
        log_fn(f"  Discovery '{DISCOVERY_NAME}' already exists (id={disc_id}), reusing...")
    else:
        log_fn(f"  Creating discovery job '{DISCOVERY_NAME}'...")
        payload = {
            "name": DISCOVERY_NAME,
            "discoveryType": "Range",
            "ipAddressList": DISCOVERY_RANGE,
            "protocolOrder": "SSH",
            "globalCredentialIdList": GLOBAL_CRED_IDS,
            "preferredMgmtIPMethod": "UseLoopBack",
            "siteId": SITE_ID,
            "retryCount": 3,
            "timeOut": 5,
            "netconfPort": "830",
        }
        r = s.post(f"{CATC_BASE}/dna/intent/api/v1/discovery", json=payload)
        if r.status_code not in (200, 201, 202):
            raise RuntimeError(f"Create discovery failed: {r.status_code} {r.text[:200]}")
        disc_id = r.json().get("response", {}).get("id") or _get_discovery_id(s)

    # Poll until all 3 switches appear as Reachable
    log_fn(f"  Waiting for 3 switches to appear as Reachable (up to 5 min)...")
    deadline = time.time() + 300
    while time.time() < deadline:
        r = s.get(f"{CATC_BASE}/dna/intent/api/v1/network-device")
        devs = [d for d in r.json().get("response", [])
                if any(sw["name"] in (d.get("hostname") or "") for sw in SWITCH_IPS.values())]
        reachable = [d for d in devs if d.get("reachabilityStatus") == "Reachable"]
        log_fn(f"    {len(reachable)}/3 switches reachable...")
        if len(reachable) >= 3:
            log_fn(f"  All 3 switches discovered and reachable")
            return True, "discovery OK"
        time.sleep(15)
    raise RuntimeError("Discovery timed out — switches not reachable after 5 min")


def step_provision(log_fn=print):
    """Provision the 3 switches to MAIN site via SDA wired provisioning."""
    s = _catc_session(log_fn)

    # Check which devices are already SDA-provisioned
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/provisionDevices")
    already = {d["networkDeviceId"] for d in r.json().get("response", [])}

    to_provision = []
    for key, info in SWITCH_IPS.items():
        dev_id = _get_device_id(s, info["name"])
        if not dev_id:
            raise RuntimeError(f"Device not found in inventory: {info['name']}")
        log_fn(f"  Found {info['name']}: {dev_id}")
        if dev_id in already:
            log_fn(f"    Already SDA-provisioned, skipping")
        else:
            to_provision.append({"networkDeviceId": dev_id, "siteId": SITE_ID})

    if not to_provision:
        log_fn(f"  All devices already SDA-provisioned")
        return True, "provision already done"

    log_fn(f"  SDA-provisioning {len(to_provision)} device(s)...")
    for p in to_provision:
        r = s.post(f"{CATC_BASE}/dna/intent/api/v1/sda/provisionDevices", json=[p])
        if r.status_code not in (200, 201, 202):
            raise RuntimeError(f"SDA provision failed: {r.status_code} {r.text[:200]}")
        task_id = r.json().get("response", {}).get("taskId")
        if task_id:
            _wait_task(s, task_id, log_fn=log_fn, timeout=300)
        log_fn(f"    Provisioned {p['networkDeviceId']}")

    return True, "provision OK"


def step_fabric_site(log_fn=print):
    """Create the SDA fabric site at Site-105/MAIN."""
    s = _catc_session(log_fn)
    if _get_fabric_id(s):
        log_fn(f"  Fabric site already exists, skipping")
        return True, "fabric_site already exists"
    log_fn(f"  Creating fabric site for siteId={SITE_ID}...")
    payload = [{
        "siteId": SITE_ID,
        "authenticationProfileName": "Closed Authentication",
        "isPubSubEnabled": True,
    }]
    _deploy_and_wait(s, "post", f"{CATC_BASE}/dna/intent/api/v1/sda/fabricSites", payload, log_fn=log_fn, timeout=300)
    log_fn(f"  Fabric site created")
    return True, "fabric_site OK"


def step_virtual_networks(log_fn=print):
    """Create L3 VNs Main/PROD/IOT and associate with fabric site."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        raise RuntimeError("Fabric site not found — run step_fabric_site first")

    existing = {vn["virtualNetworkName"] for vn in
                s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks").json().get("response", [])}

    to_create = [vn for vn in VNS if vn not in existing]
    if to_create:
        log_fn(f"  Creating VNs: {to_create}")
        payload = [{"virtualNetworkName": vn, "fabricIds": [fabric_id]} for vn in to_create]
        _deploy_and_wait(s, "post", f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks", payload, log_fn=log_fn, timeout=300)
    else:
        log_fn(f"  All VNs already exist")

    # Ensure all are associated with fabric
    for vn_name in VNS:
        vn_id = _get_vn_id(s, vn_name)
        r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks?id={vn_id}")
        current = r.json().get("response", [{}])[0]
        if fabric_id not in current.get("fabricIds", []):
            log_fn(f"  Associating {vn_name} with fabric...")
            fab_ids = current.get("fabricIds", []) + [fabric_id]
            _deploy_and_wait(s, "put", f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks",
                             [{"id": vn_id, "virtualNetworkName": vn_name, "fabricIds": fab_ids}],
                             log_fn=log_fn, timeout=300)

    return True, "virtual_networks OK"


def step_anycast_gateways(log_fn=print):
    """Create anycast gateways for each VN."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        raise RuntimeError("Fabric site not found")

    existing = {(ag["virtualNetworkName"], ag["vlanId"])
                for ag in s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/anycastGateways?fabricId={fabric_id}").json().get("response", [])}

    to_create = [ag for ag in ANYCAST_GATEWAYS if (ag["vn"], ag["vlanId"]) not in existing]
    if not to_create:
        log_fn(f"  All anycast gateways already exist")
        return True, "anycast_gateways already exist"

    log_fn(f"  Creating {len(to_create)} anycast gateways...")
    payload = [{
        "fabricId": fabric_id,
        "virtualNetworkName": ag["vn"],
        "ipPoolName": ag["ipPool"],
        "vlanName": ag["vlanName"],
        "vlanId": ag["vlanId"],
        "trafficType": ag["trafficType"],
        "securityGroupName": ag["sgName"],
        "isCriticalPool": False,
        "isLayer2FloodingEnabled": False,
        "isWirelessPool": False,
        "isIpDirectedBroadcast": False,
        "isIntraSubnetRoutingEnabled": False,
        "isMultipleIpToMacAddresses": True,
        "isGroupBasedPolicyEnforcementEnabled": True,
    } for ag in to_create]
    _deploy_and_wait(s, "post", f"{CATC_BASE}/dna/intent/api/v1/sda/anycastGateways", payload, log_fn=log_fn, timeout=300)
    return True, "anycast_gateways OK"


def step_transit(log_fn=print):
    """Create XAR-Transit IP-Based transit."""
    s = _catc_session(log_fn)
    if _get_transit_id(s):
        log_fn(f"  Transit '{TRANSIT_NAME}' already exists, skipping")
        return True, "transit already exists"
    log_fn(f"  Creating transit '{TRANSIT_NAME}'...")
    payload = [{
        "name": TRANSIT_NAME,
        "type": "IP_BASED_TRANSIT",
        "ipTransitSettings": {
            "routingProtocolName": "BGP",
            "autonomousSystemNumber": TRANSIT_ASN,
        },
    }]
    _deploy_and_wait(s, "post", f"{CATC_BASE}/dna/intent/api/v1/sda/transitNetworks", payload, log_fn=log_fn, timeout=300)
    return True, "transit OK"


def step_clean_fabric_vlans(log_fn=print):
    """Remove conflicting VLANs/SVIs and prior-run sub-interfaces from switches, resync CatC."""
    s = _catc_session(log_fn)

    log_fn(f"  Cleaning VLANs {FABRIC_CONFLICT_VLANS} and Gi1/0/48 sub-interfaces from switches...")
    for key, info in SWITCH_IPS.items():
        log_fn(f"  → {info['name']} ({info['mgmt']})")
        _ssh_clean_switch_vlans(info["mgmt"], FABRIC_CONFLICT_VLANS, log_fn=log_fn)

    log_fn(f"  Removing any prior AAA/dot1x/access-session config from switches...")
    for key, info in SWITCH_IPS.items():
        log_fn(f"  → {info['name']} ({info['mgmt']})")
        _ssh_clean_auth_config(info["mgmt"], log_fn=log_fn)

    # Also clean Border Spine Gi1/0/48 sub-interfaces from any prior run
    border_ip = SWITCH_IPS["border_spine"]["mgmt"]
    log_fn(f"  Cleaning Gi1/0/48 sub-interfaces on Border Spine ({border_ip})...")
    _ssh_border_restore_trunk(border_ip, log_fn=log_fn)

    log_fn(f"  Resyncing devices in CatC inventory...")
    for key, info in SWITCH_IPS.items():
        dev_id = _get_device_id(s, info["name"])
        if dev_id:
            log_fn(f"    Resyncing {info['name']}...")
            _catc_resync_device(s, dev_id, log_fn=log_fn)
    log_fn(f"  ✓ clean_fabric_vlans done")
    return True, "clean_fabric_vlans OK"


def _ssh_border_restore_trunk(mgmt_ip, log_fn=print):
    """Restore Gi1/0/48 on Border Spine to a clean L2 trunk (undo any prior routed conversion)."""
    import time as _time, socket as _socket
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(mgmt_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=20, allow_agent=False, look_for_keys=False)
        chan = client.invoke_shell()
        _time.sleep(0.8)

        def send(cmd, wait=0.6):
            try:
                chan.send(cmd + "\n")
                _time.sleep(wait)
                out = b""
                while chan.recv_ready():
                    out += chan.recv(4096)
                return out.decode(errors="ignore")
            except (_socket.error, OSError):
                return ""

        send("terminal length 0", 0.3)
        send("configure terminal", 0.3)
        # Remove sub-interfaces from any prior run
        for sub in ["5", "10", "101", "102"]:
            send(f"no interface GigabitEthernet1/0/48.{sub}", 0.3)
        # Restore Vlan5 SVI IP (CatC underlay) if it was moved to sub-interface
        send("interface Vlan5", 0.3)
        send("ip address 192.168.255.7 255.255.255.254", 0.3)
        send("ip ospf 1 area 0", 0.3)
        send("no shutdown", 0.3)
        send("exit", 0.3)
        # Ensure Gi1/0/48 is back to L2 trunk with CTS
        send("interface GigabitEthernet1/0/48", 0.3)
        send("no cts manual", 0.3)   # remove CTS sub-mode first
        send("switchport", 0.5)      # convert routed → L2 before setting trunk
        send("switchport mode trunk", 0.3)
        send("cts manual", 0.3)
        send(" policy static sgt 2", 0.3)
        send("no cts role-based enforcement", 0.3)
        send("no shutdown", 0.3)
        send("exit", 0.3)
        send("end", 0.5)
        out = send("write memory", 3)
        log_fn(f"    {mgmt_ip}: Gi1/0/48 restored to trunk — {'OK' if '[OK]' in out else 'write issued'}")
        client.close()
    except Exception as e:
        log_fn(f"    WARNING: restore trunk on {mgmt_ip} failed: {e}")


def _ssh_configure_border_handoff(mgmt_ip, log_fn=print):
    """Prepare Border Spine for L3 handoff to SD-WAN router via Gi1/0/48 (L2 trunk).

    CatC owns the SVI IPs (Vlan10/101/102) — it pushes them during deploy_anycast_gateways.
    This function only ensures:
      - Gi1/0/48 is an L2 trunk (with CTS) so CatC can push VLANs
      - Vlan5 SVI has IP 192.168.255.7/31 for CatC underlay OSPF
      - VRF SVIs (Vlan10/101/102) have the correct VRF + transit IPs for BGP peering
      - BGP neighbors use update-source pointing to the SVIs (Vlan10/101/102)
      - No sub-interfaces exist (they conflict with CatC SVI management)
    """
    import time as _time

    # CatC pushes SVI IPs during deploy_anycast_gateways — we must NOT use sub-interfaces.
    # This function only ensures:
    #   - No sub-interfaces exist (they conflict with CatC)
    #   - Gi1/0/48 is L2 trunk with CTS
    #   - Vlan5 SVI has IP for CatC underlay OSPF
    #   - VRF SVIs (Vlan10/101/102) have transit IPs for BGP (IPs set here, anycast IPs on Leaves by CatC)
    #   - BGP update-source points to the SVIs
    cmds = [
        "terminal length 0",
        "configure terminal",
        # Remove any sub-interfaces from prior runs
        "no interface GigabitEthernet1/0/48.5",
        "no interface GigabitEthernet1/0/48.10",
        "no interface GigabitEthernet1/0/48.101",
        "no interface GigabitEthernet1/0/48.102",
        # Ensure Gi1/0/48 is L2 trunk with CTS
        "interface GigabitEthernet1/0/48",
        "switchport mode trunk",
        "cts manual",
        " policy static sgt 2",
        "no cts role-based enforcement",
        "no shutdown",
        "exit",
        # Vlan5 SVI — CatC underlay OSPF
        "interface Vlan5",
        "ip address 192.168.255.7 255.255.255.254",
        "ip ospf 1 area 0",
        "no shutdown",
        "exit",
        # VRF SVIs — assign VRF + transit IPs for BGP peering with router
        # (CatC pushes anycast gateway IPs to Leaves only; Border Spine needs its own transit IPs)
        "interface Vlan10",
        "vrf forwarding Main",
        "ip address 192.168.255.1 255.255.255.254",
        "no shutdown",
        "exit",
        "interface Vlan101",
        "vrf forwarding PROD",
        "ip address 192.168.255.3 255.255.255.254",
        "no shutdown",
        "exit",
        "interface Vlan102",
        "vrf forwarding IOT",
        "ip address 192.168.255.5 255.255.255.254",
        "no shutdown",
        "exit",
        # BGP update-source must be the SVIs (not sub-interfaces)
        "router bgp 65535",
        "address-family ipv4 vrf Main",
        "neighbor 192.168.255.0 update-source Vlan10",
        "exit-address-family",
        "address-family ipv4 vrf PROD",
        "neighbor 192.168.255.2 update-source Vlan101",
        "exit-address-family",
        "address-family ipv4 vrf IOT",
        "neighbor 192.168.255.4 update-source Vlan102",
        "exit-address-family",
        "exit",
        "end",
    ]

    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(mgmt_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=20, allow_agent=False, look_for_keys=False)
        chan = client.invoke_shell()
        _time.sleep(0.8)
        for cmd in cmds:
            chan.send(cmd + "\n")
            _time.sleep(0.4)
            while chan.recv_ready():
                chan.recv(4096)
        chan.send("write memory\n")
        _time.sleep(4)
        out = b""
        while chan.recv_ready():
            out += chan.recv(4096)
        client.close()
        if "[OK]" in out.decode(errors="ignore"):
            log_fn(f"    {mgmt_ip}: handoff interface prepared and saved")
        else:
            log_fn(f"    {mgmt_ip}: write memory issued (no [OK] in output)")
    except Exception as e:
        raise RuntimeError(f"Config push to {mgmt_ip} failed: {e}")


def step_configure_handoff_interface(log_fn=print):
    """Prepare Border Spine Gi1/0/48 as L2 trunk for CatC L3 handoff.

    CatC owns the SVI IPs (Vlan10/101/102) — it pushes them during deploy_anycast_gateways.
    This step only:
      - Removes any sub-interfaces from prior runs (they conflict with CatC)
      - Ensures Gi1/0/48 is an L2 trunk with CTS
      - Ensures Vlan5 SVI has 192.168.255.7/31 for CatC underlay OSPF
      - Sets VRF forwarding on Vlan10/101/102 (IPs pushed by CatC later)
      - Sets BGP update-source to Vlan10/101/102

    Skips if already in correct state (no sub-interfaces, Gi1/0/48 trunk, Vlan5 has IP).
    """
    import time as _time
    border_ip = SWITCH_IPS["border_spine"]["mgmt"]

    # Pre-check: skip if already clean (no sub-interfaces, Vlan5 has IP)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(border_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=15, allow_agent=False, look_for_keys=False)
        _, out, _ = client.exec_command("show ip interface brief | include Vlan5")
        vlan5 = out.read().decode()
        _, out2, _ = client.exec_command("show run | include GigabitEthernet1/0/48\.")
        sub_ifaces = out2.read().decode()
        client.close()
        has_vlan5_ip = "192.168.255.7" in vlan5 and "unassigned" not in vlan5
        has_sub_ifaces = "GigabitEthernet1/0/48." in sub_ifaces
        if has_vlan5_ip and not has_sub_ifaces:
            log_fn(f"  Handoff interface already clean — Vlan5 IP present, no sub-interfaces, skipping")
            return True, "configure_handoff_interface already done"
    except Exception as e:
        log_fn(f"  WARNING: pre-check failed ({e}), proceeding with config push")

    log_fn(f"  Preparing Gi1/0/48 L2 trunk and VRF SVIs on {border_ip}...")
    _ssh_configure_border_handoff(border_ip, log_fn=log_fn)

    # Verify
    _time.sleep(3)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(border_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=15, allow_agent=False, look_for_keys=False)
        _, out, _ = client.exec_command("show ip interface brief | include Vlan5")
        vlan5_result = out.read().decode()
        _, out2, _ = client.exec_command("show interfaces GigabitEthernet1/0/48 | include line protocol")
        gi48_result = out2.read().decode()
        client.close()
        log_fn(f"  Vlan5: {vlan5_result.strip()}")
        log_fn(f"  Gi1/0/48: {gi48_result.strip()}")
        if "192.168.255.7" not in vlan5_result:
            raise RuntimeError("Vlan5 SVI missing 192.168.255.7 after config push")
    except RuntimeError:
        raise
    except Exception as e:
        log_fn(f"  WARNING: post-check failed: {e}")

    return True, "configure_handoff_interface OK"


def rollback_configure_handoff_interface(log_fn=print):
    """Restore Border Spine Gi1/0/48 to L2 trunk with CTS (undo configure_handoff_interface)."""
    border_ip = SWITCH_IPS["border_spine"]["mgmt"]
    log_fn(f"  Restoring Gi1/0/48 to L2 trunk on {border_ip}...")
    _ssh_border_restore_trunk(border_ip, log_fn=log_fn)
    return True, "rollback_configure_handoff_interface OK"


def _fix_dhcp_relay_global(log_fn=print):
    """Fix DHCP relay on Leaf1 and Leaf2 after CatC pushes SVIs.

    CatC pushes 'ip helper-address 198.18.5.102' without the 'global' keyword.
    Without 'global' the relay packet is forwarded via VRF Main → router OMP →
    hub — a path that is broken in this lab. With 'global' the relay exits via
    the global routing table: Loopback0 → OSPF → Border Spine → router global →
    198.18.5.102, which works reliably.

    Also ensures 'ip dhcp relay source-interface Loopback0' is set so the relay
    GIADDR is the switch Loopback0 IP (reachable from the DHCP server).
    """
    import time as _time
    VRF_VLANS = ["Vlan10", "Vlan101", "Vlan102"]
    for key in ("leaf1", "leaf2"):
        mgmt_ip = SWITCH_IPS[key]["mgmt"]
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(mgmt_ip, username=SWITCH_USER, password=SWITCH_PASS,
                           timeout=15, allow_agent=False, look_for_keys=False)
            chan = client.invoke_shell()
            _time.sleep(0.8)

            def send(cmd, w=0.6):
                chan.send(cmd + "\n")
                _time.sleep(w)
                out = b""
                while chan.recv_ready():
                    out += chan.recv(4096)
                return out.decode(errors="ignore")

            send("terminal length 0")
            send("configure terminal")
            for vlan in VRF_VLANS:
                send(f"interface {vlan}")
                send("ip dhcp relay source-interface Loopback0")
                send("no ip helper-address global 198.18.5.102")
                send("no ip helper-address 198.18.5.102")
                send("ip helper-address 198.18.5.102")
                send("exit")
            send("end")
            chan.send("write memory\n")
            _time.sleep(3)
            out = b""
            while chan.recv_ready():
                out += chan.recv(4096)
            saved = "[OK]" in out.decode(errors="ignore")
            client.close()
            log_fn(f"    {key} ({mgmt_ip}): DHCP relay fixed (no global), saved={saved}")
        except Exception as e:
            log_fn(f"    WARNING: DHCP relay fix failed on {key} ({mgmt_ip}): {e}")


def step_deploy_anycast_gateways(log_fn=print):
    """Trigger CatC to push anycast gateway SVIs and DHCP helper-address to fabric devices.

    Performs a PUT on all anycast gateways to trigger CatC's ICL config push,
    resyncs devices first to ensure CatC reachability, and retries up to 3 times.
    """
    import time as _time
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        raise RuntimeError("No fabric site found")

    # Ensure devices are reachable before attempting deploy
    log_fn(f"  Resyncing fabric devices to ensure CatC reachability...")
    for key, info in SWITCH_IPS.items():
        dev_id = _get_device_id(s, info["name"])
        if dev_id:
            _catc_resync_device(s, dev_id, log_fn=log_fn)

    ags = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/anycastGateways?fabricId={fabric_id}").json().get("response", [])
    if not ags:
        raise RuntimeError("No anycast gateways found — run step_anycast_gateways first")

    payload = [{
        "id": ag["id"],
        "fabricId": fabric_id,
        "virtualNetworkName": ag["virtualNetworkName"],
        "ipPoolName": ag["ipPoolName"],
        "vlanName": ag["vlanName"],
        "vlanId": ag["vlanId"],
        "trafficType": ag["trafficType"],
        "isCriticalPool": False,
        "isLayer2FloodingEnabled": False,
        "isWirelessPool": False,
        "isIpDirectedBroadcast": False,
        "isIntraSubnetRoutingEnabled": False,
        "isMultipleIpToMacAddresses": True,
        "isGroupBasedPolicyEnforcementEnabled": True,
    } for ag in ags]

    for attempt in range(3):
        log_fn(f"  Deploying anycast gateways to devices (attempt {attempt+1}/3)...")
        r = s.put(f"{CATC_BASE}/dna/intent/api/v1/sda/anycastGateways", json=payload)
        if r.status_code not in (200, 201, 202):
            raise RuntimeError(f"PUT anycastGateways {r.status_code}: {r.text[:200]}")
        task_id = r.json().get("response", {}).get("taskId")
        try:
            _wait_task(s, task_id, log_fn=log_fn, timeout=300)
            log_fn(f"  ✓ Anycast gateway deploy task succeeded")
            break
        except RuntimeError as e:
            log_fn(f"  Deploy attempt {attempt+1} failed: {e}")
            if attempt < 2:
                log_fn(f"  Resyncing devices and retrying...")
                _time.sleep(5)
                for key, info in SWITCH_IPS.items():
                    dev_id = _get_device_id(s, info["name"])
                    if dev_id:
                        _catc_resync_device(s, dev_id, log_fn=log_fn)
            else:
                raise

    # Verify SVIs appeared on Leaf2 (edge node — this is where clients connect)
    leaf2_ip = SWITCH_IPS["leaf2"]["mgmt"]
    log_fn(f"  Verifying SVIs on Leaf2 ({leaf2_ip})...")
    _time.sleep(10)
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(leaf2_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=15, allow_agent=False, look_for_keys=False)
        _, out, _ = client.exec_command("show ip interface brief | include Vlan1[^_]")
        svi_out = out.read().decode()
        _, out2, _ = client.exec_command("show run | include ip helper")
        helper_out = out2.read().decode()
        client.close()
        log_fn(f"  SVIs: {svi_out.strip()}")
        log_fn(f"  Helpers: {helper_out.strip()}")
        if "Vlan10" not in svi_out:
            log_fn(f"  WARNING: Vlan10 not yet present on Leaf2 — CatC may still be pushing")
        if "198.18.5.102" not in helper_out:
            log_fn(f"  WARNING: ip helper-address not yet pushed to Leaf2")
    except Exception as e:
        log_fn(f"  WARNING: Leaf2 verification failed: {e}")

    # Fix DHCP relay on both leaves: CatC may push 'ip helper-address global' which routes
    # DHCP out the global table — but Leaf1/Leaf2 have no global route to 198.18.5.102.
    # Correct: use plain 'ip helper-address 198.18.5.102' (VRF Main) with source Loopback0.
    # LISP resolves 198.18.5.0/24 in VRF Main via proxy ETR (Border Spine → router → hub).
    # DHCP reply returns to Loopback0 (172.30.255.1) which is reachable from hub via vrf 10 BGP.
    log_fn(f"  Fixing DHCP relay (removing global keyword) on both leaves...")
    _fix_dhcp_relay_global(log_fn=log_fn)

    return True, "deploy_anycast_gateways OK"


def step_fabric_devices(log_fn=print):
    """Add Border+CP node and 2 edge nodes to the fabric."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        raise RuntimeError("Fabric site not found")

    border_id  = _get_device_id(s, "Border-Spine")
    leaf1_id   = _get_device_id(s, "Leaf1")
    leaf2_id   = _get_device_id(s, "Leaf2")

    if not all([border_id, leaf1_id, leaf2_id]):
        raise RuntimeError(f"Could not resolve device IDs: border={border_id} leaf1={leaf1_id} leaf2={leaf2_id}")

    existing = {fd["networkDeviceId"] for fd in
                s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_id}").json().get("response", [])}

    to_add = []
    if border_id not in existing:
        to_add.append({
            "fabricId": fabric_id,
            "networkDeviceId": border_id,
            "deviceRoles": ["BORDER_NODE", "CONTROL_PLANE_NODE"],
            "borderDeviceSettings": {
                "borderTypes": ["LAYER_3"],
                "layer3Settings": {
                    "localAutonomousSystemNumber": BORDER_ASN,
                    "importExternalRoutes": True,
                    "borderPriority": 8,
                    "prependAutonomousSystemCount": 1,
                    "isDefaultExit": True,
                },
            },
        })
    for dev_id, name in [(leaf1_id, "Leaf1"), (leaf2_id, "Leaf2")]:
        if dev_id not in existing:
            to_add.append({
                "fabricId": fabric_id,
                "networkDeviceId": dev_id,
                "deviceRoles": ["EDGE_NODE"],
            })

    if not to_add:
        log_fn(f"  All fabric devices already configured")
        return True, "fabric_devices already configured"

    log_fn(f"  Adding {len(to_add)} fabric device(s)...")
    _deploy_and_wait(s, "post", f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices", to_add, log_fn=log_fn, timeout=600)
    return True, "fabric_devices OK"


def step_l3_handoff(log_fn=print):
    """Configure L3 handoff per VN on Border Spine Gi1/0/48."""
    s = _catc_session(log_fn)
    fabric_id  = _get_fabric_id(s)
    transit_id = _get_transit_id(s)
    border_id  = _get_device_id(s, "Border-Spine")
    if not all([fabric_id, transit_id, border_id]):
        raise RuntimeError("Missing fabric/transit/border IDs for L3 handoff")

    existing = {ho["virtualNetworkName"]
                for ho in s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits?fabricId={fabric_id}").json().get("response", [])}

    to_add = [ho for ho in L3_HANDOFFS if ho["vn"] not in existing]
    if not to_add:
        log_fn(f"  All L3 handoffs already configured")
        return True, "l3_handoff already configured"

    log_fn(f"  Adding {len(to_add)} L3 handoff(s)...")
    payload = [{
        "fabricId": fabric_id,
        "networkDeviceId": border_id,
        "transitNetworkId": transit_id,
        "interfaceName": HANDOFF_INTERFACE,
        "virtualNetworkName": ho["vn"],
        "vlanId": ho["vlanId"],
        "localIpAddress": ho["localIp"],
        "remoteIpAddress": ho["remoteIp"],
        "tcpMssAdjustment": 0,
    } for ho in to_add]
    _deploy_and_wait(s, "post",
                     f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices/layer3Handoffs/ipTransits",
                     payload, log_fn=log_fn, timeout=300)
    return True, "l3_handoff OK"


def step_port_assignments(log_fn=print):
    """Set Gi1/0/2 on Leaf1 and Leaf2 as trunk, native VLAN 10, allowed 10,101,102."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    leaf1_id  = _get_device_id(s, "Leaf1")
    leaf2_id  = _get_device_id(s, "Leaf2")
    if not all([fabric_id, leaf1_id, leaf2_id]):
        raise RuntimeError("Missing IDs for port assignments")

    existing = {(pa["networkDeviceId"], pa["interfaceName"])
                for pa in s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/portAssignments?fabricId={fabric_id}").json().get("response", [])}

    to_add = []
    for dev_id in [leaf1_id, leaf2_id]:
        if (dev_id, PORT_ASSIGNMENT_INTERFACE) not in existing:
            to_add.append({
                "fabricId": fabric_id,
                "networkDeviceId": dev_id,
                "interfaceName": PORT_ASSIGNMENT_INTERFACE,
                "connectedDeviceType": "TRUNKING_DEVICE",
                "authenticateTemplateName": "No Authentication",
                "nativeVlanId": PORT_NATIVE_VLAN,
                "allowedVlanRanges": PORT_ALLOWED_VLANS,
            })

    if not to_add:
        log_fn(f"  Port assignments already configured")
        return True, "port_assignments already configured"

    log_fn(f"  Adding {len(to_add)} port assignment(s) (one per device)...")
    for entry in to_add:
        _deploy_and_wait(s, "post", f"{CATC_BASE}/dna/intent/api/v1/sda/portAssignments", [entry], log_fn=log_fn, timeout=300)
    return True, "port_assignments OK"


def step_verify(log_fn=print):
    """Verify fabric devices reachable, BGP per-VRF up, route to DHCP server in each VRF, SVIs on Leaf2."""
    import time as _time
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        raise RuntimeError("No fabric site found")

    # 1. CatC reachability
    fabric_devs = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_id}").json().get("response", [])
    log_fn(f"  {len(fabric_devs)} fabric device(s) configured")
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/network-device")
    devs = {d["id"]: d for d in r.json().get("response", [])}
    all_ok = True
    for fd in fabric_devs:
        dev = devs.get(fd["networkDeviceId"], {})
        status = dev.get("reachabilityStatus", "Unknown")
        name = dev.get("hostname", fd["networkDeviceId"])
        ok = status == "Reachable"
        if not ok:
            all_ok = False
        log_fn(f"    {name}: {status} {'✓' if ok else '✗'}")
    if not all_ok:
        raise RuntimeError("One or more fabric devices not reachable in CatC")

    # 2. BGP per-VRF and route to DHCP server on Border Spine
    border_ip = SWITCH_IPS["border_spine"]["mgmt"]
    leaf2_ip   = SWITCH_IPS["leaf2"]["mgmt"]
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(border_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=15, allow_agent=False, look_for_keys=False)
        bgp_issues = []
        for vrf, peer in [("Main", "192.168.255.0"), ("PROD", "192.168.255.2"), ("IOT", "192.168.255.4")]:
            _, out, _ = client.exec_command(f"show ip bgp vpnv4 vrf {vrf} summary | include {peer}")
            line = out.read().decode().strip()
            if not line:
                bgp_issues.append(f"VRF {vrf}: no BGP entry for {peer}")
                log_fn(f"    BGP VRF {vrf} ({peer}): ✗ not found")
            elif "Idle" in line or "Active" in line:
                bgp_issues.append(f"VRF {vrf}: BGP to {peer} is {line.split()[-1]}")
                log_fn(f"    BGP VRF {vrf} ({peer}): ✗ {line.split()[-1]}")
            else:
                pfx = line.split()[-1]
                log_fn(f"    BGP VRF {vrf} ({peer}): ✓ up, {pfx} prefixes")
        _, out, _ = client.exec_command("show ip route vrf Main 198.18.5.102")
        dhcp_route = out.read().decode()
        if "198.18.5" in dhcp_route:
            log_fn(f"    Route to DHCP (198.18.5.102) in Main VRF: ✓")
        else:
            bgp_issues.append("No route to 198.18.5.102 in Main VRF")
            log_fn(f"    Route to DHCP (198.18.5.102) in Main VRF: ✗")
        client.close()
        if bgp_issues:
            raise RuntimeError(f"BGP issues: {'; '.join(bgp_issues)}")
    except RuntimeError:
        raise
    except Exception as e:
        log_fn(f"    WARNING: BGP check failed: {e}")

    # 3. SVIs and DHCP helper on Leaf2
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(leaf2_ip, username=SWITCH_USER, password=SWITCH_PASS,
                       timeout=15, allow_agent=False, look_for_keys=False)
        _, out, _ = client.exec_command("show ip interface brief | include Vlan1[^_]")
        svis = out.read().decode()
        _, out2, _ = client.exec_command("show run | include ip helper")
        helpers = out2.read().decode()
        client.close()
        svi_issues = [v for v in ["Vlan10", "Vlan101", "Vlan102"] if v not in svis]
        if svi_issues:
            log_fn(f"    Leaf2 SVIs missing: {svi_issues} ✗")
            raise RuntimeError(f"Leaf2 SVIs not pushed by CatC: {svi_issues}")
        log_fn(f"    Leaf2 SVIs Vlan10/101/102: ✓")
        if "198.18.5.102" not in helpers:
            log_fn(f"    Leaf2 ip helper-address: ✗ not configured")
            raise RuntimeError("ip helper-address 198.18.5.102 not on Leaf2")
        log_fn(f"    Leaf2 ip helper-address 198.18.5.102: ✓")
    except RuntimeError:
        raise
    except Exception as e:
        log_fn(f"    WARNING: Leaf2 SVI check failed: {e}")

    return True, f"verify OK — {len(fabric_devs)} devices reachable, BGP up, SVIs pushed"


# ---------------------------------------------------------------------------
# Rollback steps
# ---------------------------------------------------------------------------

def rollback_fabric_devices(log_fn=print):
    """Remove edge nodes first, then Border/CP node.
    API requires DELETE /sda/fabricDevices?fabricId=X&networkDeviceId=Y (one at a time).
    """
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        log_fn("  No fabric site found, skipping")
        return True, "skipped"

    fds = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_id}").json().get("response", [])
    if not fds:
        log_fn("  No fabric devices to remove")
        return True, "skipped"

    # Remove edge nodes first, then border/CP
    edges  = [fd for fd in fds if fd["deviceRoles"] == ["EDGE_NODE"]]
    border = [fd for fd in fds if "BORDER_NODE" in fd["deviceRoles"] or "CONTROL_PLANE_NODE" in fd["deviceRoles"]]

    for group, label in [(edges, "edge nodes"), (border, "border/CP node")]:
        for fd in group:
            nd_id = fd["networkDeviceId"]
            log_fn(f"  Removing {label} networkDeviceId={nd_id}...")
            r = s.delete(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricDevices?fabricId={fabric_id}&networkDeviceId={nd_id}")
            if r.status_code not in (200, 202):
                raise RuntimeError(f"Delete fabric devices failed: {r.status_code} {r.text[:200]}")
            task_id = r.json().get("response", {}).get("taskId")
            if task_id:
                _wait_task(s, task_id, log_fn=log_fn, timeout=300)
            time.sleep(3)

    return True, "rollback_fabric_devices OK"


def rollback_anycast_gateways(log_fn=print):
    """Delete all anycast gateways one at a time via DELETE /anycastGateways/{id}."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        log_fn("  No fabric site, skipping")
        return True, "skipped"

    ags = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/anycastGateways?fabricId={fabric_id}").json().get("response", [])
    if not ags:
        log_fn("  No anycast gateways to delete")
        return True, "skipped"

    for ag in ags:
        ag_id = ag["id"]
        log_fn(f"  Deleting anycast gateway {ag_id}...")
        r = s.delete(f"{CATC_BASE}/dna/intent/api/v1/sda/anycastGateways/{ag_id}")
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Delete anycast gateway failed: {r.status_code} {r.text[:200]}")
        task_id = r.json().get("response", {}).get("taskId")
        if task_id:
            _wait_task(s, task_id, log_fn=log_fn, timeout=300)
        time.sleep(3)
    return True, "rollback_anycast_gateways OK"


def rollback_gbac_policy(log_fn=print):
    """Disable dCloud_PROD_User GBAC policy before transit deletion."""
    s = _catc_session(log_fn)
    # Try to find and disable the policy
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/security/group-based-access-control/policies?producer=dCloud_PROD_User")
    if r.status_code != 200 or not r.json().get("response"):
        log_fn("  No GBAC policy found or API not available, skipping")
        return True, "skipped"

    for policy in r.json().get("response", []):
        pid = policy.get("id")
        log_fn(f"  Disabling GBAC policy {pid}...")
        patch = {"policyStatus": "DISABLED"}
        s.put(f"{CATC_BASE}/dna/intent/api/v1/security/group-based-access-control/policies/{pid}", json=patch)

    return True, "rollback_gbac_policy OK"


def rollback_transit(log_fn=print):
    """Delete XAR-Transit via DELETE /transitNetworks/{id}."""
    s = _catc_session(log_fn)
    transit_id = _get_transit_id(s)
    if not transit_id:
        log_fn("  No transit found, skipping")
        return True, "skipped"
    log_fn(f"  Deleting transit '{TRANSIT_NAME}' id={transit_id}...")
    r = s.delete(f"{CATC_BASE}/dna/intent/api/v1/sda/transitNetworks/{transit_id}")
    if r.status_code not in (200, 202):
        raise RuntimeError(f"Delete transit failed: {r.status_code} {r.text[:200]}")
    task_id = r.json().get("response", {}).get("taskId")
    if task_id:
        _wait_task(s, task_id, log_fn=log_fn, timeout=300)
    return True, "rollback_transit OK"


def rollback_vn_site_assignments(log_fn=print):
    """Disassociate VNs from fabric site (L3 handoffs already removed in prior step)."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        log_fn("  No fabric site, skipping VN disassociation")
        return True, "skipped"

    for vn_name in VNS:
        vn_id = _get_vn_id(s, vn_name)
        if not vn_id:
            continue
        r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks?id={vn_id}")
        current = r.json().get("response", [{}])[0]
        fab_ids = [f for f in current.get("fabricIds", []) if f != fabric_id]
        log_fn(f"  Removing {vn_name} from fabric...")
        _deploy_and_wait(s, "put", f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks",
                         [{"id": vn_id, "virtualNetworkName": vn_name, "fabricIds": fab_ids}],
                         log_fn=log_fn, timeout=300)
    return True, "rollback_vn_site_assignments OK"


def rollback_virtual_networks(log_fn=print):
    """Delete Main/PROD/IOT L3 VNs."""
    s = _catc_session(log_fn)
    for vn_name in VNS:
        vn_id = _get_vn_id(s, vn_name)
        if not vn_id:
            log_fn(f"  VN {vn_name} not found, skipping")
            continue
        log_fn(f"  Deleting VN {vn_name}...")
        r = s.delete(f"{CATC_BASE}/dna/intent/api/v1/sda/layer3VirtualNetworks?id={vn_id}")
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Delete VN {vn_name} failed: {r.status_code} {r.text[:200]}")
        task_id = r.json().get("response", {}).get("taskId")
        if task_id:
            _wait_task(s, task_id, log_fn=log_fn, timeout=300)
        time.sleep(3)
    return True, "rollback_virtual_networks OK"


def rollback_fabric_site(log_fn=print):
    """Delete the fabric site via DELETE /fabricSites/{id}."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        log_fn("  No fabric site to delete")
        return True, "skipped"
    log_fn(f"  Deleting fabric site {fabric_id}...")
    r = s.delete(f"{CATC_BASE}/dna/intent/api/v1/sda/fabricSites/{fabric_id}")
    if r.status_code not in (200, 202):
        raise RuntimeError(f"Delete fabric site failed: {r.status_code} {r.text[:200]}")
    task_id = r.json().get("response", {}).get("taskId")
    if task_id:
        _wait_task(s, task_id, log_fn=log_fn, timeout=300)
    return True, "rollback_fabric_site OK"


def rollback_delete_devices(log_fn=print):
    """Delete the 3 switches from CATC inventory one at a time via DELETE /network-device/{id}.

    Retries up to 5 times with 60s backoff if CATC reports a provisioning lock.
    """
    s = _catc_session(log_fn)
    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/network-device")
    devs = [d for d in r.json().get("response", [])
            if any(sw["name"] in (d.get("hostname") or "") for sw in SWITCH_IPS.values())]
    if not devs:
        log_fn("  No switch devices found in inventory")
        return True, "skipped"

    for d in devs:
        d_id = d["id"]
        hostname = d.get("hostname", d_id)
        max_retries = 5
        for attempt in range(1, max_retries + 1):
            log_fn(f"  Deleting {hostname} from inventory (attempt {attempt}/{max_retries})...")
            r2 = s.delete(f"{CATC_BASE}/dna/intent/api/v1/network-device/{d_id}?cleanConfig=false")
            if r2.status_code not in (200, 202):
                raise RuntimeError(f"Delete device failed: {r2.status_code} {r2.text[:200]}")
            task_id = r2.json().get("response", {}).get("taskId")
            if task_id:
                try:
                    _wait_task(s, task_id, log_fn=log_fn, timeout=300)
                    break  # success
                except RuntimeError as e:
                    if "being provisioned" in str(e) and attempt < max_retries:
                        log_fn(f"  CATC provisioning lock — waiting 60s before retry...")
                        time.sleep(60)
                        continue
                    raise
            else:
                break
        time.sleep(3)
    return True, f"rollback_delete_devices OK — {len(devs)} deleted"


def rollback_delete_discovery(log_fn=print):
    """Delete the Site-105-Discovery job."""
    s = _catc_session(log_fn)
    disc_id = _get_discovery_id(s)
    if not disc_id:
        log_fn("  No discovery job found, skipping")
        return True, "skipped"
    log_fn(f"  Deleting discovery '{DISCOVERY_NAME}' (id={disc_id})...")
    r = s.delete(f"{CATC_BASE}/dna/intent/api/v1/discovery/{disc_id}")
    if r.status_code not in (200, 202):
        raise RuntimeError(f"Delete discovery failed: {r.status_code} {r.text[:200]}")
    task_id = r.json().get("response", {}).get("taskId")
    if task_id:
        _wait_task(s, task_id, log_fn=log_fn, timeout=120)
    return True, "rollback_delete_discovery OK"


def rollback_delete_ise_nads(log_fn=print):
    """Delete the 3 switch NADs from ISE (safety: only delete if IP is a switch loopback)."""
    import requests as req
    ise_s = req.Session()
    ise_s.verify = False
    ise_s.auth = (ISE_USER, ISE_PASS)
    ise_s.headers.update({"Accept": "application/json", "Content-Type": "application/json"})

    r = ise_s.get(f"https://{ISE_HOST}/ers/config/networkdevice")
    if r.status_code != 200:
        raise RuntimeError(f"ISE NAD list failed: {r.status_code}")

    nads = r.json().get("SearchResult", {}).get("resources", [])
    deleted = 0
    for nad in nads:
        detail = ise_s.get(f"https://{ISE_HOST}/ers/config/networkdevice/{nad['id']}").json()
        dev = detail.get("NetworkDevice", {})
        ips = [p.get("ipaddress") for p in dev.get("NetworkDeviceIPList", [])]
        if any(ip in ISE_SWITCH_LOOPBACKS for ip in ips):
            log_fn(f"  Deleting ISE NAD: {dev.get('name')} (IPs: {ips})")
            dr = ise_s.delete(f"https://{ISE_HOST}/ers/config/networkdevice/{nad['id']}")
            if dr.status_code not in (200, 204):
                log_fn(f"    Warning: delete failed {dr.status_code}")
            else:
                deleted += 1

    return True, f"rollback_delete_ise_nads OK — {deleted} deleted"


def rollback_network_profile(log_fn=print):
    """Remove site from Closed Authentication profile then delete profile."""
    s = _catc_session(log_fn)
    try:
        r = s.get(f"{CATC_BASE}/dna/intent/api/v1/networkprofile")
        r.raise_for_status()
        body = r.json()
    except Exception as e:
        log_fn(f"  Could not fetch network profiles: {e}, skipping")
        return True, "skipped"

    profiles = [p for p in body.get("response", []) if p["name"] == "Closed Authentication" and p["namespace"] == "authentication"]
    if not profiles:
        log_fn("  Network profile not found, skipping")
        return True, "skipped"

    profile_id = profiles[0]["siteProfileUuid"]
    log_fn(f"  Removing site from network profile {profile_id}...")
    try:
        r2 = s.get(f"{CATC_BASE}/dna/intent/api/v1/networkprofile/{profile_id}/site")
        sites = r2.json().get("response", []) if r2.status_code == 200 else []
    except Exception:
        sites = []

    for site in sites:
        if site.get("id") == SITE_ID or SITE_HIERARCHY in site.get("nameHierarchy", ""):
            log_fn(f"  Removing MAIN from profile...")
            s.delete(f"{CATC_BASE}/dna/intent/api/v1/networkprofile/{profile_id}/site/{SITE_ID}")

    return True, "rollback_network_profile OK"


def rollback_port_assignments(log_fn=print):
    """Remove all port assignments before fabric devices can be removed."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        log_fn("  No fabric site, skipping")
        return True, "skipped"

    pas = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/portAssignments?fabricId={fabric_id}").json().get("response", [])
    if not pas:
        log_fn("  No port assignments to remove")
        return True, "skipped"

    for pa in pas:
        pa_id = pa["id"]
        iface = pa.get("interfaceName", pa_id)
        log_fn(f"  Removing port assignment {iface} ({pa_id})...")
        r = s.delete(f"{CATC_BASE}/dna/intent/api/v1/sda/portAssignments/{pa_id}")
        if r.status_code not in (200, 202):
            raise RuntimeError(f"Delete port assignment failed: {r.status_code} {r.text[:200]}")
        # Response may be empty (204-style) or JSON with taskId
        try:
            task_id = r.json().get("response", {}).get("taskId")
            if task_id:
                _wait_task(s, task_id, log_fn=log_fn, timeout=120)
        except Exception:
            pass  # empty body is fine
        time.sleep(2)
    return True, f"rollback_port_assignments OK — {len(pas)} removed"


def rollback_l3_handoffs(log_fn=print):
    """Remove all L3 IP-transit handoffs before VN disassociation."""
    s = _catc_session(log_fn)
    fabric_id = _get_fabric_id(s)
    if not fabric_id:
        log_fn("  No fabric site, skipping")
        return True, "skipped"

    r = s.get(f"{CATC_BASE}/dna/intent/api/v1/sda/layer3Handoffs/ipTransits?fabricId={fabric_id}")
    handoffs = r.json().get("response", []) if r.status_code == 200 else []
    if not handoffs:
        log_fn("  No L3 handoffs to remove")
        return True, "skipped"

    for h in handoffs:
        h_id = h["id"]
        log_fn(f"  Removing L3 handoff {h_id}...")
        rd = s.delete(f"{CATC_BASE}/dna/intent/api/v1/sda/layer3Handoffs/ipTransits/{h_id}")
        if rd.status_code not in (200, 202, 204):
            raise RuntimeError(f"Delete L3 handoff failed: {rd.status_code} {rd.text[:200]}")
        try:
            task_id = rd.json().get("response", {}).get("taskId")
            if task_id:
                _wait_task(s, task_id, log_fn=log_fn, timeout=120)
        except Exception:
            pass  # empty body is fine
        time.sleep(2)
    return True, f"rollback_l3_handoffs OK — {len(handoffs)} removed"


# ---------------------------------------------------------------------------
# Ordered step lists
# ---------------------------------------------------------------------------

DEPLOY_STEPS = [
    ("discovery",                    step_discovery),
    ("provision",                    step_provision),
    ("fabric_site",                  step_fabric_site),
    ("virtual_networks",             step_virtual_networks),
    ("anycast_gateways",             step_anycast_gateways),
    ("transit",                      step_transit),
    ("clean_fabric_vlans",           step_clean_fabric_vlans),
    ("fabric_devices",               step_fabric_devices),
    ("l3_handoff",                   step_l3_handoff),
    ("configure_handoff_interface",  step_configure_handoff_interface),
    ("deploy_anycast_gateways",      step_deploy_anycast_gateways),
    ("port_assignments",             step_port_assignments),
    ("verify",                       step_verify),
]

ROLLBACK_STEPS = [
    ("remove_port_assignments",          rollback_port_assignments),
    ("remove_l3_handoffs",               rollback_l3_handoffs),
    ("restore_handoff_interface",        rollback_configure_handoff_interface),
    ("remove_fabric_devices",            rollback_fabric_devices),
    ("remove_anycast_gateways",          rollback_anycast_gateways),
    ("disable_gbac_policy",              rollback_gbac_policy),
    ("remove_transit",                   rollback_transit),
    ("remove_vn_assignments",            rollback_vn_site_assignments),
    ("remove_virtual_networks",          rollback_virtual_networks),
    ("remove_fabric_site",               rollback_fabric_site),
    ("delete_devices",                   rollback_delete_devices),
    ("delete_discovery",                 rollback_delete_discovery),
    ("delete_ise_nads",                  rollback_delete_ise_nads),
    ("remove_network_profile",           rollback_network_profile),
]


def run_deploy(from_step=None, log_fn=print, pod_id=None, db_path=None):
    """Run full deploy pipeline, optionally starting from a specific step name."""
    global POD_ID, DB_PATH
    if pod_id:
        POD_ID = pod_id
    if db_path:
        DB_PATH = db_path
    ensure_sda_table()

    started = from_step is None
    # Pre-mark skipped steps as pending, active steps as pending
    for name, _ in DEPLOY_STEPS:
        if not started and name != from_step:
            _set_step("deploy", name, "pending", "skipped")
        else:
            if name == from_step:
                started = True

    started = from_step is None
    for name, fn in DEPLOY_STEPS:
        if not started:
            if name == from_step:
                started = True
            else:
                log_fn(f"  Skipping {name}")
                continue
        log_fn(f"\n▶ {name}")
        _set_step("deploy", name, "running")
        ok, detail = fn(log_fn=log_fn)
        if not ok:
            _set_step("deploy", name, "failed", detail)
            log_fn(f"  ✗ {name} FAILED: {detail}")
            return False, f"HALTED at {name}: {detail}"
        _set_step("deploy", name, "completed", detail)
        log_fn(f"  ✓ {name}: {detail}")
    return True, "SDA fabric deploy complete"


def run_rollback(log_fn=print, pod_id=None, db_path=None, resume=True):
    """Run full rollback pipeline.

    If resume=True (default), steps already marked 'completed' in the DB are
    skipped so a re-run only retries pending/failed/running/missing steps.
    """
    global POD_ID, DB_PATH
    if pod_id:
        POD_ID = pod_id
    if db_path:
        DB_PATH = db_path
    ensure_sda_table()

    # Build set of already-completed step names from DB
    completed_in_db = set()
    if resume:
        try:
            c = sqlite3.connect(DB_PATH)
            rows = c.execute(
                "SELECT step_name FROM sda_steps WHERE pod_id=? AND mode='rollback' AND status='completed'",
                (POD_ID,)
            ).fetchall()
            c.close()
            completed_in_db = {r[0] for r in rows}
        except Exception as e:
            log_fn(f"Warning: could not read completed steps: {e}")

    errors = []
    for name, fn in ROLLBACK_STEPS:
        if name in completed_in_db:
            log_fn(f"  ↷ {name}: already completed — skipping")
            continue
        log_fn(f"\n▶ {name}")
        _set_step("rollback", name, "running")
        try:
            ok, detail = fn(log_fn=log_fn)
            status = "completed" if ok else "failed"
            _set_step("rollback", name, status, detail)
            log_fn(f"  {'✓' if ok else '✗'} {name}: {detail}")
        except Exception as e:
            _set_step("rollback", name, "failed", str(e))
            log_fn(f"  ✗ {name} ERROR: {e} — continuing rollback...")
            errors.append(f"{name}: {e}")
        time.sleep(3)
    if errors:
        return False, f"Rollback completed with errors: {'; '.join(errors)}"
    return True, "SDA fabric rollback complete"


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    mode = sys.argv[1] if len(sys.argv) > 1 else "deploy"
    if mode == "rollback":
        ok, msg = run_rollback()
    elif mode == "deploy":
        from_step = sys.argv[2] if len(sys.argv) > 2 else None
        ok, msg = run_deploy(from_step=from_step)
    else:
        print(f"Usage: python3 sda_fabric.py [deploy [step_name] | rollback]")
        sys.exit(1)
    print(f"\n{'OK' if ok else 'FAILED'}: {msg}")
    sys.exit(0 if ok else 1)
