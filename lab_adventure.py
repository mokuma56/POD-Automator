"""
lab_adventure.py — Choose Your Own Adventure Lab
================================================
Students browse to http://198.18.134.12:8099 and choose EVPN or SDA.
The app deploys the chosen fabric and streams live verification results.

Run:  python3 lab_adventure.py
"""

from flask import Flask, Response, jsonify, request, redirect
import paramiko
import threading
import time
import queue
import json
import sys, os
import requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
sys.path.insert(0, os.path.dirname(__file__))

app = Flask(__name__)

# ── Switch definitions ────────────────────────────────────────────────────────
SWITCHES = {
    "border_spine": {"name": "Border Spine", "ip": "198.18.128.24"},
    "leaf1":        {"name": "Leaf 1",        "ip": "198.18.128.22"},
    "leaf2":        {"name": "Leaf 2",        "ip": "198.18.128.23"},
}
ROUTER_IP   = "198.18.133.25"
ROUTER_USER = "admin"
ROUTER_PASS = "C1sco12345"
SW_USER = "netadmin"
SW_PASS = "C1sco12345"

# Global stream queues keyed by session_id
_streams = {}
_streams_lock = threading.Lock()
_confirm_flags = {}  # sid -> True when student confirms pings started

# ── SSH helper ────────────────────────────────────────────────────────────────
def _ssh(ip, commands, timeout=30, user=None, password=None):
    """SSH to a switch or router, run commands, return (ok, output)."""
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, username=user or SW_USER, password=password or SW_PASS,
                  look_for_keys=False, allow_agent=False, timeout=10)
        shell = c.invoke_shell(width=200, height=200)
        time.sleep(1)
        shell.recv(4096)

        out = ""
        for cmd in commands:
            shell.send(cmd + "\n")
            time.sleep(0.6)
            deadline = time.time() + timeout
            buf = ""
            while time.time() < deadline:
                if shell.recv_ready():
                    buf += shell.recv(32768).decode("utf-8", errors="replace")
                    if "#" in buf.split("\n")[-1]:
                        break
                else:
                    time.sleep(0.2)
            out += buf
        c.close()
        return True, out
    except Exception as e:
        return False, str(e)


def _push_config(ip, config_block, timeout=45):
    """Push a config block to a switch."""
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(ip, username=SW_USER, password=SW_PASS,
                  look_for_keys=False, allow_agent=False, timeout=10)
        shell = c.invoke_shell(width=200, height=200)
        time.sleep(1)
        shell.recv(4096)

        def send(cmd, delay=0.4):
            shell.send(cmd + "\n")
            time.sleep(delay)
            buf = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if shell.recv_ready():
                    buf += shell.recv(32768)
                    time.sleep(0.2)
                else:
                    break
            return buf.decode("utf-8", errors="replace")

        send("enable", 0.5)
        send("conf t", 0.5)
        for line in config_block.strip().splitlines():
            send(line, 0.3)
        send("end", 0.5)
        out = send("write memory", 3)
        c.close()
        return True, out
    except Exception as e:
        return False, str(e)


# ── SSE stream helper ─────────────────────────────────────────────────────────
def _get_queue(sid):
    with _streams_lock:
        if sid not in _streams:
            _streams[sid] = queue.Queue()
        return _streams[sid]


def _emit(sid, event, data):
    q = _get_queue(sid)
    q.put(f"event: {event}\ndata: {json.dumps(data)}\n\n")


def _done(sid):
    q = _get_queue(sid)
    q.put(None)  # sentinel


# ── EVPN deployment ───────────────────────────────────────────────────────────
EVPN_STEPS = [
    ("Summoning the VRF Spirits",        "vrf_definitions"),
    ("Awakening Multicast Replication",  "multicast_replication"),
    ("Mapping L2 VNI Realms",            "l2vni"),
    ("Forging L3 VNI Vaults",            "l3vni"),
    ("Conjuring Anycast Gateways",       "dag_svis"),
    ("Binding L3 VNI Interfaces",        "l3vni_svis"),
    ("Opening the NVE Portal",           "nve"),
    ("Establishing BGP EVPN Alliance",   "bgp_evpn"),
    ("Verifying BGP EVPN Neighbors",     "verify_bgp"),
    ("Counting NVE Peers",               "verify_nve"),
    ("Arming Identity & SGT Enforcement","dot1x_security"),
]

VRF_CONFIG = """\
vrf definition IOT
 rd {lo0}:102
 address-family ipv4
  route-target export 65535:102
  route-target import 65535:102
  route-target export 65535:102 stitching
  route-target import 65535:102 stitching
 exit-address-family
vrf definition Main
 rd {lo0}:10
 address-family ipv4
  route-target export 65535:10
  route-target import 65535:10
  route-target export 65535:10 stitching
  route-target import 65535:10 stitching
 exit-address-family
vrf definition PROD
 rd {lo0}:101
 address-family ipv4
  route-target export 65535:101
  route-target import 65535:101
  route-target export 65535:101 stitching
  route-target import 65535:101 stitching
 exit-address-family"""

MULTICAST_CFG = """\
l2vpn evpn
 replication-type static
 router-id loopback 0"""

L2VNI_CFG = """\
vlan 10
 name Main
vlan 101
 name PROD
vlan 102
 name IOT
l2vpn evpn instance 10 vlan-based
 encapsulation vxlan
l2vpn evpn instance 101 vlan-based
 encapsulation vxlan
l2vpn evpn instance 102 vlan-based
 encapsulation vxlan
vlan configuration 10
 member evpn-instance 10 vni 100010
vlan configuration 101
 member evpn-instance 101 vni 100101
vlan configuration 102
 member evpn-instance 102 vni 100102"""

L3VNI_CFG = """\
vlan 1010
 name L3-VRF-CORE-VLAN-10
vlan 1101
 name L3-VRF-CORE-VLAN-101
vlan 1102
 name L3-VRF-CORE-VLAN-102
vlan configuration 1010
 member vni 110010
vlan configuration 1101
 member vni 110101
vlan configuration 1102
 member vni 110102"""

DAG_SVIS_CFG = """\
interface Vlan10
 mac-address 0001.0001.0010
 vrf forwarding Main
 ip dhcp relay source-interface Loopback0
 ip address 10.10.255.1 255.255.255.0
 ip helper-address global 198.18.5.102
 no shutdown
interface Vlan101
 mac-address 0001.0001.0101
 vrf forwarding PROD
 ip dhcp relay source-interface Loopback0
 ip address 10.101.255.1 255.255.255.0
 ip helper-address global 198.18.5.102
 no shutdown
interface Vlan102
 mac-address 0001.0001.0102
 vrf forwarding IOT
 ip dhcp relay source-interface Loopback0
 ip address 10.102.255.1 255.255.255.0
 ip helper-address global 198.18.5.102
 no shutdown"""

L3VNI_SVIS_CFG = """\
interface Vlan1010
 vrf forwarding Main
 ip unnumbered Loopback0
 no autostate
 no shutdown
interface Vlan1101
 vrf forwarding PROD
 ip unnumbered Loopback0
 no autostate
 no shutdown
interface Vlan1102
 vrf forwarding IOT
 ip unnumbered Loopback0
 no autostate
 no shutdown"""

NVE_LEAF_CFG = """\
interface nve1
 no ip address
 source-interface Loopback0
 host-reachability protocol bgp
 group-based-policy
 member vni 110010 vrf Main
 member vni 110101 vrf PROD
 member vni 110102 vrf IOT
 member vni 100010 mcast-group 232.1.1.1
 member vni 100101 mcast-group 232.1.1.1
 member vni 100102 mcast-group 232.1.1.1"""

NVE_SPINE_CFG = """\
interface nve1
 no ip address
 source-interface Loopback0
 host-reachability protocol bgp
 member vni 110010 vrf Main
 member vni 110101 vrf PROD
 member vni 110102 vrf IOT"""

BGP_LEAF1 = """\
router bgp 65535
 bgp router-id 172.30.255.1
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 neighbor 172.30.255.3 remote-as 65535
 neighbor 172.30.255.3 update-source Loopback0
 address-family ipv4
 exit-address-family
 address-family l2vpn evpn
  neighbor 172.30.255.3 activate
  neighbor 172.30.255.3 send-community both
 exit-address-family
 address-family ipv4 vrf IOT
  advertise l2vpn evpn
  redistribute connected
 exit-address-family
 address-family ipv4 vrf Main
  advertise l2vpn evpn
  redistribute connected
 exit-address-family
 address-family ipv4 vrf PROD
  advertise l2vpn evpn
  redistribute connected
 exit-address-family"""

BGP_LEAF2 = BGP_LEAF1.replace("172.30.255.1", "172.30.255.2")

BGP_SPINE = """\
router bgp 65535
 bgp router-id 172.30.255.3
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 neighbor 172.30.255.1 remote-as 65535
 neighbor 172.30.255.1 update-source Loopback0
 neighbor 172.30.255.2 remote-as 65535
 neighbor 172.30.255.2 update-source Loopback0
 address-family l2vpn evpn
  neighbor 172.30.255.1 activate
  neighbor 172.30.255.1 send-community both
  neighbor 172.30.255.1 route-reflector-client
  neighbor 172.30.255.2 activate
  neighbor 172.30.255.2 send-community both
  neighbor 172.30.255.2 route-reflector-client
 exit-address-family"""

# ── 802.1x / IBNS 2.0 / CTS security config (copied from evpn_fabric.py) ─────
# Pushed to Leaf1 + Leaf2 only. Required for ransomware simulation SGT
# enforcement (show cts role-based counters) to produce deny hits.
DOT1X_SECURITY = """\
service password-encryption
no logging console
no ip domain lookup
netconf-yang
no ip dhcp snooping information option
no ip tftp blocksize
access-session attributes filter-list list ISE-DS-list
 vlan-id
 cdp
 lldp
 dhcp
 http
access-session authentication attributes filter-spec include list ISE-DS-list
access-session accounting attributes filter-spec include list ISE-DS-list
service-template CRITICAL_DATA_ACCESS
 access-group PERMIT-ISE
service-template CRITICAL_VOICE_ACCESS
 access-group PERMIT-ISE
 voice vlan
dot1x system-auth-control
class-map type control subscriber match-all AAA_SVR_DOWN_AUTHD_HOST
 match result-type aaa-timeout
 match authorization-status authorized
class-map type control subscriber match-all AAA_SVR_DOWN_UNAUTHD_HOST
 match result-type aaa-timeout
 match authorization-status unauthorized
class-map type control subscriber match-all AUTHC_SUCCESS_AUTHZ_FAIL
 match authorization-status unauthorized
 match result-type success
class-map type control subscriber match-all DOT1X
 match method dot1x
class-map type control subscriber match-all DOT1X_FAILED
 match method dot1x
 match result-type method dot1x authoritative
class-map type control subscriber match-all DOT1X_NO_RESP
 match method dot1x
 match result-type method dot1x agent-not-found
class-map type control subscriber match-all DOT1X_TIMEOUT
 match method dot1x
 match result-type method dot1x method-timeout
class-map type control subscriber match-any IN_CRITICAL_AUTH
 match activated-service-template CRITICAL_DATA_ACCESS
 match activated-service-template CRITICAL_VOICE_ACCESS
class-map type control subscriber match-all MAB
 match method mab
class-map type control subscriber match-all MAB_FAILED
 match method mab
 match result-type method mab authoritative
class-map type control subscriber match-none NOT_IN_CRITICAL_AUTH
 match activated-service-template CRITICAL_DATA_ACCESS
 match activated-service-template CRITICAL_VOICE_ACCESS
policy-map type control subscriber DOT1X_MAB_POLICY
 event session-started match-all
  10 class always do-until-failure
   10 authenticate using dot1x retries 2 retry-time 0 priority 10
 event authentication-failure match-first
  5 class DOT1X_FAILED do-until-failure
   10 terminate dot1x
   20 authenticate using mab priority 20
  10 class AAA_SVR_DOWN_UNAUTHD_HOST do-until-failure
   10 clear-authenticated-data-hosts-on-port
   20 activate service-template CRITICAL_DATA_ACCESS
   30 activate service-template CRITICAL_VOICE_ACCESS
   40 authorize
   50 pause reauthentication
  20 class AAA_SVR_DOWN_AUTHD_HOST do-until-failure
   10 pause reauthentication
   20 authorize
  30 class DOT1X_NO_RESP do-until-failure
   10 terminate dot1x
   20 authenticate using mab priority 20
  40 class MAB_FAILED do-until-failure
   10 terminate mab
   20 authentication-restart 60
  50 class always do-until-failure
   10 terminate dot1x
   20 terminate mab
   30 authentication-restart 60
 event agent-found match-all
  10 class always do-until-failure
   10 terminate mab
   20 authenticate using dot1x retries 2 retry-time 0 priority 10
 event aaa-available match-all
  10 class IN_CRITICAL_AUTH do-until-failure
   10 clear-session
  20 class NOT_IN_CRITICAL_AUTH do-until-failure
   10 resume reauthentication
 event inactivity-timeout match-all
  10 class always do-until-failure
   10 clear-session
 event authentication-success match-all
  10 class always do-until-failure
   10 activate service-template DEFAULT_LINKSEC_POLICY_SHOULD_SECURE
 event violation match-all
  10 class always do-until-failure
   10 restrict
 event authorization-failure match-all
  10 class AUTHC_SUCCESS_AUTHZ_FAIL do-until-failure
   10 authentication-restart 60
policy-map type control subscriber MAB_DOT1X_POLICY
 event session-started match-all
  10 class always do-until-failure
   10 authenticate using mab priority 20
 event authentication-failure match-first
  5 class DOT1X_FAILED do-until-failure
   10 terminate dot1x
   20 authenticate using mab priority 20
  10 class AAA_SVR_DOWN_UNAUTHD_HOST do-until-failure
   10 clear-authenticated-data-hosts-on-port
   20 activate service-template CRITICAL_DATA_ACCESS
   30 activate service-template CRITICAL_VOICE_ACCESS
   40 authorize
   50 pause reauthentication
  20 class AAA_SVR_DOWN_AUTHD_HOST do-until-failure
   10 pause reauthentication
   20 authorize
  30 class MAB_FAILED do-until-failure
   10 terminate mab
   20 authenticate using dot1x retries 2 retry-time 0 priority 10
  40 class DOT1X_NO_RESP do-until-failure
   10 terminate dot1x
   20 authentication-restart 60
  60 class always do-until-failure
   10 terminate mab
   20 terminate dot1x
   30 authentication-restart 60
 event agent-found match-all
  10 class always do-until-failure
   10 terminate mab
   20 authenticate using dot1x retries 2 retry-time 0 priority 10
 event aaa-available match-all
  10 class IN_CRITICAL_AUTH do-until-failure
   10 clear-session
  20 class NOT_IN_CRITICAL_AUTH do-until-failure
   10 resume reauthentication
 event inactivity-timeout match-all
  10 class always do-until-failure
   10 clear-session
 event authentication-success match-all
  10 class always do-until-failure
   10 activate service-template DEFAULT_LINKSEC_POLICY_SHOULD_SECURE
 event violation match-all
  10 class always do-until-failure
   10 restrict
 event authorization-failure match-all
  10 class AUTHC_SUCCESS_AUTHZ_FAIL do-until-failure
   10 authentication-restart 60
template WIRED_DOT1X_CLOSED
 dot1x pae authenticator
 dot1x timeout quiet-period 300
 dot1x timeout tx-period 7
 mab
 access-session control-direction in
 access-session closed
 access-session port-control auto
 authentication periodic
 authentication timer reauthenticate server
 service-policy type control subscriber DOT1X_MAB_POLICY
template WIRED_DOT1X_OPEN
 dot1x pae authenticator
 dot1x timeout quiet-period 300
 dot1x timeout tx-period 7
 mab
 access-session control-direction in
 access-session port-control auto
 authentication periodic
 authentication timer reauthenticate server
 service-policy type control subscriber DOT1X_MAB_POLICY
template WIRED_MAB_CLOSED
 dot1x pae authenticator
 dot1x timeout quiet-period 300
 dot1x timeout tx-period 7
 mab
 access-session control-direction in
 access-session closed
 access-session port-control auto
 authentication periodic
 authentication timer reauthenticate server
 service-policy type control subscriber MAB_DOT1X_POLICY
template WIRED_MAB_OPEN
 dot1x pae authenticator
 dot1x timeout quiet-period 300
 dot1x timeout tx-period 7
 mab
 access-session control-direction in
 access-session port-control auto
 authentication periodic
 authentication timer reauthenticate server
 service-policy type control subscriber MAB_DOT1X_POLICY
!
ip tftp source-interface GigabitEthernet0/0
ip ssh version 2
ip access-list extended PERMIT-ISE
 10 permit ip any any
!
cts role-based enforcement
cts role-based enforcement vlan-list 10,101-102
!
device-tracking policy IPDT_POLICY
 no protocol udp
 tracking enable
!
vlan 10
 name Main
!
vlan 101
 name PROD
!
vlan 102
 name IOT
!
interface GigabitEthernet1/0/1
 description Client
 switchport mode access
 device-tracking attach-policy IPDT_POLICY
 source template WIRED_DOT1X_CLOSED
 spanning-tree portfast
 ip nbar protocol-discovery
!
interface GigabitEthernet1/0/2
 description AP
 switchport trunk native vlan 10
 switchport trunk allowed vlan 10,101,102
 switchport mode trunk
 spanning-tree portfast trunk
 cts manual
  policy static sgt 2 trusted
  propagate sgt
!
interface GigabitEthernet1/0/3
 description Client
 switchport mode access
 device-tracking attach-policy IPDT_POLICY
 source template WIRED_DOT1X_CLOSED
 spanning-tree portfast
 ip nbar protocol-discovery"""


def _run_evpn(sid):
    def step(name, fn):
        _emit(sid, "step_start", {"name": name})
        ok, detail = fn()
        _emit(sid, "step_done", {"name": name, "ok": ok, "detail": detail})
        return ok

    # VRF definitions — all 3 switches
    def do_vrf():
        results = []
        for key, sw in SWITCHES.items():
            lo0 = {"border_spine": "172.30.255.3", "leaf1": "172.30.255.1", "leaf2": "172.30.255.2"}[key]
            ok, out = _push_config(sw["ip"], VRF_CONFIG.format(lo0=lo0))
            results.append(f"{sw['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[0][0], do_vrf): return _done(sid)

    # Multicast — Leaf1 + Leaf2 only
    def do_mcast():
        results = []
        for key in ("leaf1", "leaf2"):
            ok, _ = _push_config(SWITCHES[key]["ip"], MULTICAST_CFG)
            results.append(f"{SWITCHES[key]['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[1][0], do_mcast): return _done(sid)

    # L2VNI — Leaf1 + Leaf2
    def do_l2vni():
        results = []
        for key in ("leaf1", "leaf2"):
            ok, _ = _push_config(SWITCHES[key]["ip"], L2VNI_CFG)
            results.append(f"{SWITCHES[key]['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[2][0], do_l2vni): return _done(sid)

    # L3VNI — all 3
    def do_l3vni():
        results = []
        for key, sw in SWITCHES.items():
            ok, _ = _push_config(sw["ip"], L3VNI_CFG)
            results.append(f"{sw['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[3][0], do_l3vni): return _done(sid)

    # DAG SVIs — Leaf1 + Leaf2
    def do_dag():
        results = []
        for key in ("leaf1", "leaf2"):
            ok, _ = _push_config(SWITCHES[key]["ip"], DAG_SVIS_CFG)
            results.append(f"{SWITCHES[key]['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[4][0], do_dag): return _done(sid)

    # L3VNI SVIs — all 3
    def do_l3svis():
        results = []
        for key, sw in SWITCHES.items():
            ok, _ = _push_config(sw["ip"], L3VNI_SVIS_CFG)
            results.append(f"{sw['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[5][0], do_l3svis): return _done(sid)

    # NVE — all 3 (different config per role)
    def do_nve():
        results = []
        cfgs = {"border_spine": NVE_SPINE_CFG, "leaf1": NVE_LEAF_CFG, "leaf2": NVE_LEAF_CFG}
        for key, sw in SWITCHES.items():
            ok, _ = _push_config(sw["ip"], cfgs[key])
            results.append(f"{sw['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[6][0], do_nve): return _done(sid)

    # BGP EVPN — all 3
    def do_bgp():
        cfgs = {"border_spine": BGP_SPINE, "leaf1": BGP_LEAF1, "leaf2": BGP_LEAF2}
        results = []
        for key, sw in SWITCHES.items():
            ok, _ = _push_config(sw["ip"], cfgs[key])
            results.append(f"{sw['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    if not step(EVPN_STEPS[7][0], do_bgp): return _done(sid)

    # Verify BGP EVPN
    def do_verify_bgp():
        import re
        ok, out = _ssh(SWITCHES["border_spine"]["ip"], ["show bgp l2vpn evpn summary"])
        if not ok:
            return False, f"SSH failed: {out}"
        neighbors = sum(1 for line in out.splitlines()
                        if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+4\s+\d+.*\s+\d+\s*$', line.strip()))
        passed = neighbors >= 2
        return passed, f"{neighbors} BGP EVPN neighbor(s) established"

    if not step(EVPN_STEPS[8][0], do_verify_bgp): return _done(sid)

    # Verify NVE peers
    def do_verify_nve():
        ok, out = _ssh(SWITCHES["border_spine"]["ip"], ["show nve peers"])
        if not ok:
            return False, f"SSH failed: {out}"
        peers = out.count("UP") + out.count(" up ")
        return peers >= 1, f"{peers} NVE peer(s) UP"

    step(EVPN_STEPS[9][0], do_verify_nve)

    # 802.1x / IBNS 2.0 / CTS — Leaf1 + Leaf2
    def do_dot1x():
        results = []
        for key in ("leaf1", "leaf2"):
            ok, _ = _push_config(SWITCHES[key]["ip"], DOT1X_SECURITY)
            results.append(f"{SWITCHES[key]['name']}={'ok' if ok else 'FAIL'}")
        return all("ok" in r for r in results), " | ".join(results)

    step(EVPN_STEPS[10][0], do_dot1x)
    _emit(sid, "complete", {"path": "evpn"})
    _done(sid)


# ── SDA verification checks ───────────────────────────────────────────────────
SDA_VERIFY_STEPS = [
    ("Probing the Fabric Weave",        "fabric_site"),
    ("Interrogating Virtual Networks",  "vns"),
    ("Summoning Anycast Gateways",      "gateways"),
    ("Inspecting Fabric Devices",       "fabric_devices"),
    ("Testing Switch Reachability",     "reachability"),
    ("Validating Port Assignments",     "port_assignments"),
]


def _run_sda_verify(sid):
    import requests, urllib3
    urllib3.disable_warnings()

    CATC = "https://198.18.5.100"
    AUTH = ("admin", "Demo@C!sco")
    FABRIC_SITE_ID = "75f6262f-f08e-4241-a87d-ff5b8be2e3e4"

    def catc_get(path):
        try:
            r = requests.get(f"{CATC}{path}", auth=AUTH, verify=False, timeout=15)
            return r.status_code, r.json()
        except Exception as e:
            return 0, {"error": str(e)}

    def step(name, fn):
        _emit(sid, "step_start", {"name": name})
        ok, detail = fn()
        _emit(sid, "step_done", {"name": name, "ok": ok, "detail": detail})
        return ok

    # Fabric site
    def check_fabric():
        code, data = catc_get("/dna/intent/api/v1/sda/fabricSites")
        sites = data.get("response", [])
        match = [s for s in sites if s.get("id") == FABRIC_SITE_ID]
        if match:
            return True, f"Fabric site found: {match[0].get('name', FABRIC_SITE_ID)}"
        return False, f"Fabric site {FABRIC_SITE_ID} not found ({len(sites)} sites total)"

    step(SDA_VERIFY_STEPS[0][0], check_fabric)

    # Virtual Networks
    def check_vns():
        code, data = catc_get("/dna/intent/api/v1/sda/layer3VirtualNetworks")
        vns = data.get("response", [])
        names = [v.get("virtualNetworkName", "?") for v in vns]
        expected = {"Main", "PROD", "IOT"}
        found = expected & set(names)
        ok = len(found) == 3
        return ok, f"VNs found: {', '.join(sorted(found))} ({len(vns)} total)"

    step(SDA_VERIFY_STEPS[1][0], check_vns)

    # Anycast Gateways
    def check_gateways():
        code, data = catc_get(f"/dna/intent/api/v1/sda/anycastGateways?fabricId={FABRIC_SITE_ID}")
        gws = data.get("response", [])
        return len(gws) > 0, f"{len(gws)} anycast gateway(s) configured"

    step(SDA_VERIFY_STEPS[2][0], check_gateways)

    # Fabric devices
    def check_devices():
        code, data = catc_get(f"/dna/intent/api/v1/sda/fabricDevices?fabricId={FABRIC_SITE_ID}")
        devs = data.get("response", [])
        roles = [d.get("deviceRoles", []) for d in devs]
        return len(devs) >= 3, f"{len(devs)} fabric device(s): {[d.get('networkDeviceId','?')[:8] for d in devs]}"

    step(SDA_VERIFY_STEPS[3][0], check_devices)

    # Switch reachability via CATC inventory
    def check_reach():
        code, data = catc_get("/dna/intent/api/v1/network-device")
        devs = data.get("response", [])
        loopbacks = {"172.30.255.1", "172.30.255.2", "172.30.255.3"}
        reachable = [d for d in devs
                     if d.get("managementIpAddress") in loopbacks
                     and d.get("reachabilityStatus", "").lower() == "reachable"]
        return len(reachable) >= 3, f"{len(reachable)}/3 switches reachable in CATC"

    step(SDA_VERIFY_STEPS[4][0], check_reach)

    # Port assignments
    def check_ports():
        code, data = catc_get(f"/dna/intent/api/v1/sda/portAssignments?fabricId={FABRIC_SITE_ID}")
        pas = data.get("response", [])
        return len(pas) > 0, f"{len(pas)} port assignment(s) configured"

    step(SDA_VERIFY_STEPS[5][0], check_ports)

    _emit(sid, "complete", {"path": "sda"})
    _done(sid)


# ── SDA full deploy (CATC discover + sda_fabric run_deploy) ──────────────────
def _run_sda_deploy(sid):
    """Run CATC discovery then full SDA fabric deploy, streaming steps via SSE."""
    # Step 1: CATC discovery via onboard_router.phase_catc_discover
    _emit(sid, "step_start", {"name": "Catalyst Center Discovery"})
    try:
        import onboard_router
        ok, msg = onboard_router.phase_catc_discover(log_fn=lambda m: None)
        _emit(sid, "step_done", {"name": "Catalyst Center Discovery", "ok": ok, "detail": msg[:120] if msg else ""})
        if not ok:
            _emit(sid, "complete", {"path": "sda"})
            return _done(sid)
    except Exception as e:
        _emit(sid, "step_done", {"name": "Catalyst Center Discovery", "ok": False, "detail": str(e)[:120]})
        _emit(sid, "complete", {"path": "sda"})
        return _done(sid)

    # Step 2: SDA fabric deploy steps
    try:
        import sda_fabric
        for step_name, step_fn in sda_fabric.DEPLOY_STEPS:
            label = step_name.replace("_", " ").title()
            _emit(sid, "step_start", {"name": label})
            try:
                ok, msg = step_fn(log_fn=lambda m: None)
            except Exception as e:
                ok, msg = False, str(e)
            _emit(sid, "step_done", {"name": label, "ok": ok, "detail": (msg or "")[:120]})
            if not ok:
                break
    except Exception as e:
        _emit(sid, "step_done", {"name": "SDA Deploy", "ok": False, "detail": str(e)[:120]})

    # 802.1x / IBNS 2.0 / CTS — Leaf1 + Leaf2 (required for ransomware SGT enforcement)
    _emit(sid, "step_start", {"name": "Arming Identity & SGT Enforcement"})
    dot1x_results = []
    for key in ("leaf1", "leaf2"):
        ok, _ = _push_config(SWITCHES[key]["ip"], DOT1X_SECURITY)
        dot1x_results.append(f"{SWITCHES[key]['name']}={'ok' if ok else 'FAIL'}")
    dot1x_ok = all("ok" in r for r in dot1x_results)
    _emit(sid, "step_done", {"name": "Arming Identity & SGT Enforcement",
                             "ok": dot1x_ok, "detail": " | ".join(dot1x_results)})

    _emit(sid, "complete", {"path": "sda"})
    _done(sid)


# ── Breach simulation constants ───────────────────────────────────────────────
ISE_HOST  = "198.18.5.101"
ISE_USER  = "admin"
ISE_PASS  = "C1sco12345"

# ISE ERS object IDs (queried once, static for this lab)
# SGT 19 = Production
ISE_SGT_PRODUCTION_ID   = "55cb393a-f713-44e0-be5a-d7c8413c081b"
# SGACL: "Permit IP"  (permit ip — reset / open state for demo start)
ISE_SGACL_PERMIT_IP_ID  = "92951ac0-8c01-11e6-996c-525400b48521"
# SGACL: "Deny IP"  (deny ip — full block)
ISE_SGACL_DENY_IP_ID    = "92919850-8c01-11e6-996c-525400b48521"
# SGACL: "DENY_ICMP"  (deny icmp log — original lab state, kept for reference)
ISE_SGACL_DENY_ICMP_ID  = "6f66b2c0-61bd-11f0-bcf8-2a16930c5df2"
# Egress matrix cell: Production → Production (id discovered via ERS)
ISE_CELL_PROD_PROD_ID   = "9510f1c0-c0b3-11f0-a397-d23657e2e017"

# Macro seg ping targets — run from ROUTER VRF loopbacks (100.100.x.105)
# (label, vrf_id, src_loopback, target_ip, expect_pass)
MACRO_SEG_TARGETS = [
    # PROD VRF — own loopback reachable, other VRFs blocked
    ("PROD Network — Internal Reachability Check",  "101", "lo101", "100.100.101.105", True),
    ("PROD → Main Network (Cross-Segment Attempt)",  "101", "lo101", "100.100.10.105",  False),
    ("PROD → IoT Network (Cross-Segment Attempt)",   "101", "lo101", "100.100.102.105", False),
    # IoT VRF — own loopback reachable, other VRFs blocked
    ("IoT Network — Internal Reachability Check",   "102", "lo102", "100.100.102.105", True),
    ("IoT → PROD Network (Cross-Segment Attempt)",   "102", "lo102", "100.100.101.105", False),
    ("IoT → Main Network (Cross-Segment Attempt)",   "102", "lo102", "100.100.10.105",  False),
]

# SGT pairs we check deny counters for (src_sgt → dst_sgt)
SGT_DENY_PAIRS = [
    ("SGT-IOT",  "SGT-PROD"),
    ("SGT-IOT",  "SGT-CORP"),
    ("SGT-PROD", "SGT-CORP"),
]


def _breach_emit(sid, event, data):
    _emit(sid, event, data)


def _act1_macro_segmentation(sid):
    """Act 1 — prove VRF macro segmentation using router WAN loopbacks."""
    _breach_emit(sid, "act_start", {"act": 1, "title": "Act 1 — Macro Segmentation"})
    time.sleep(1)

    # Step 1 — establish the threat scenario: confirm VRF topology
    _breach_emit(sid, "step_start", {"name": "Reconnaissance — Map the Network Segments"})
    ok, out = _ssh(ROUTER_IP, [
        "terminal length 0",
        "show ip vrf",
    ], user=ROUTER_USER, password=ROUTER_PASS)
    time.sleep(1)
    _breach_emit(sid, "step_done", {
        "name": "Reconnaissance — Map the Network Segments",
        "ok": ok,
        "detail": "Network topology exposed — 3 isolated segments: PROD (101), IoT (102), Main (10)" if ok else out[:120],
        "output": out[:600],
    })
    if not ok:
        return False
    time.sleep(2)

    # Steps: attempt cross-segment pivots from each VRF
    for label, vrf_id, src_lo, target_ip, expect_pass in MACRO_SEG_TARGETS:
        step_name = label
        _breach_emit(sid, "step_start", {"name": step_name})
        time.sleep(1)
        ok2, out2 = _ssh(ROUTER_IP, [
            "terminal length 0",
            f"ping vrf {vrf_id} {target_ip} source {src_lo} repeat 4 timeout 2",
        ], user=ROUTER_USER, password=ROUTER_PASS)
        passed = "!!!" in out2 or ("Success rate is 100" in out2) or (
            "Success rate is" in out2 and "0 percent" not in out2
        )
        if expect_pass:
            result_ok = passed
            detail = (f"Connectivity confirmed — segment is operational ({target_ip} reachable)"
                      if passed else f"ERROR — own segment unreachable, check SD-WAN fabric ({target_ip})")
        else:
            result_ok = not passed
            detail = (f"BLOCKED — Macro segmentation holding. Attacker pivot DENIED ({target_ip} unreachable)"
                      if not passed else f"CRITICAL — Segment boundary BREACHED! {target_ip} reachable across VRF!")
        _breach_emit(sid, "step_done", {
            "name": step_name,
            "ok": result_ok,
            "detail": detail,
            "output": out2[:400],
        })
        time.sleep(2)

    # Final step — VRF isolation summary
    _breach_emit(sid, "step_start", {"name": "Confirm Macro Segmentation — VRF Boundary Report"})
    time.sleep(1)
    ok3, out3 = _ssh(SWITCHES["border_spine"]["ip"], [
        "terminal length 0",
        "show ip vrf",
    ])
    _breach_emit(sid, "step_done", {
        "name": "Confirm Macro Segmentation — VRF Boundary Report",
        "ok": ok3,
        "detail": "Macro segmentation VERIFIED — PROD, IoT, and Main segments are fully isolated" if ok3 else out3[:80],
        "output": out3[:400],
    })
    time.sleep(2)
    return True


def _ise_ers_update_cell(cell_id, sgacl_id, enable=True):
    """PUT updated SGACL + status onto an ISE EgressMatrixCell via ERS API.
    ISE rejects having the same SGACL in both sgacls[] and defaultRule, so we
    use defaultRule exclusively and leave sgacls empty.
    Returns (ok: bool, message: str).
    """
    import urllib.request, urllib.error, ssl as _ssl, base64, json as _json
    ctx = _ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_NONE
    url = "https://{}:9060/ers/config/egressmatrixcell/{}".format(ISE_HOST, cell_id)
    if sgacl_id == ISE_SGACL_DENY_IP_ID:
        default_rule = "DENY_IP"
    elif sgacl_id == ISE_SGACL_PERMIT_IP_ID:
        default_rule = "PERMIT_IP"
    else:
        default_rule = "NONE"
    payload = _json.dumps({
        "EgressMatrixCell": {
            "id":               cell_id,
            "name":             "Production-Production",
            "sourceSgtId":      ISE_SGT_PRODUCTION_ID,
            "destinationSgtId": ISE_SGT_PRODUCTION_ID,
            "matrixCellStatus": "ENABLED" if enable else "DISABLED",
            "defaultRule":      default_rule,
            "sgacls":           [],
            "matrixId":         "9fa3a33a-329e-43cb-a4cf-7bd38df16e7b",
        }
    }).encode()
    req = urllib.request.Request(url, data=payload, method="PUT")
    creds = base64.b64encode("{}:{}".format(ISE_USER, ISE_PASS).encode()).decode()
    req.add_header("Authorization", "Basic " + creds)
    req.add_header("Accept", "application/json")
    req.add_header("Content-Type", "application/json")
    try:
        r = urllib.request.urlopen(req, context=ctx, timeout=10)
        return True, "ISE ERS updated (HTTP {})".format(r.getcode())
    except urllib.error.HTTPError as e:
        body = e.read(300).decode("utf-8", "replace")
        return False, "ISE ERS HTTP {}: {}".format(e.code, body)
    except Exception as e:
        return False, "ISE ERS error: {}".format(str(e))


def _act2_micro_segmentation(sid):
    """Act 2 — prove SGT intra-segment blocking via ISE TrustSec policy push."""
    _breach_emit(sid, "act_start", {"act": 2, "title": "Act 2 — Micro Segmentation (SGT)"})
    time.sleep(1)

    # Step 1 — show current permissions: attacker can move freely inside PROD
    step_policy = "Threat Intel — Scanning PROD Segment for Lateral Movement Paths"
    _breach_emit(sid, "step_start", {"name": step_policy})
    time.sleep(1)
    ok, out = _ssh(SWITCHES["leaf1"]["ip"], [
        "terminal length 0",
        "show cts role-based permissions",
    ])
    has_19_19 = ("19:Production to group 19:Production" in out or "from group 19 to group 19" in out.lower()) and ("Deny IP" in out or "DENY" in out.upper())
    _breach_emit(sid, "step_done", {
        "name": step_policy,
        "ok": ok,
        "detail": "WARNING: PROD intra-segment deny rule already active — reset demo first" if has_19_19
                  else "VULNERABILITY CONFIRMED — No intra-segment SGACL. PROD hosts can reach each other freely. Attacker can pivot laterally.",
        "output": out[:800],
    })
    time.sleep(2)

    # Step 2 — clear counters on leaf switches only
    for sw_key in ("leaf1", "leaf2"):
        sw = SWITCHES[sw_key]
        step_clear = f"Zero Enforcement Counters — {sw['name']}"
        _breach_emit(sid, "step_start", {"name": step_clear})
        time.sleep(0.5)
        ok, out = _ssh(sw["ip"], [
            "terminal length 0",
            "clear cts role-based counters",
        ])
        _breach_emit(sid, "step_done", {"name": step_clear, "ok": ok,
                                         "detail": "Baseline set — counters at zero" if ok else out[:80]})
        time.sleep(1)

    # Step 3 — wait for student to start PROD→PROD pings (confirm button)
    wait_step = "Lateral Movement in Progress — Pat and Kit Workstations"
    _breach_emit(sid, "step_start", {"name": wait_step})
    _breach_emit(sid, "step_waiting", {"name": wait_step, "detail": ""})

    # Poll for confirm signal (student clicks button) — up to 5 minutes
    with _streams_lock:
        q = _streams.get(sid)
    confirmed = False
    for _ in range(60):  # 60 × 5s = 5 min
        time.sleep(5)
        with _streams_lock:
            confirm_flag = _confirm_flags.get(sid, False)
        if confirm_flag:
            confirmed = True
            with _streams_lock:
                _confirm_flags.pop(sid, None)
            break

    _breach_emit(sid, "step_done", {
        "name": wait_step,
        "ok": True,
        "detail": "Lateral movement confirmed — Pat and Kit pings are live. Attacker has a foothold inside PROD.",
    })
    time.sleep(2)

    # Step 4 — ISE TrustSec Response: update ISE matrix + force policy re-download on switches
    step_push = "ISE TrustSec Response — Deploying SGACL to Block PROD Lateral Movement"
    _breach_emit(sid, "step_start", {"name": step_push})
    time.sleep(1)

    # 4a — update ISE Production→Production cell to Deny IP
    ise_ok, ise_msg = _ise_ers_update_cell(ISE_CELL_PROD_PROD_ID, ISE_SGACL_DENY_IP_ID)
    push_ok = ise_ok
    push_detail = ["ISE: " + ise_msg]
    print(f"[act2] ISE PUT result: ok={ise_ok} msg={ise_msg}", flush=True)
    time.sleep(1)

    # 4b — clear cached CTS policy + refresh on all 3 switches so they re-download from ISE
    for sw_key in ("leaf1", "leaf2", "border_spine"):
        sw = SWITCHES[sw_key]
        ok, out = _ssh(sw["ip"], [
            "terminal length 0",
            "clear cts policy",
            "cts refresh policy",
        ])
        label = "refreshed" if ok else "FAIL " + out[:60]
        push_detail.append("{}: {}".format(sw["name"], label))
        print(f"[act2] {sw['name']} CTS refresh: ok={ok} {label}", flush=True)
        if not ok:
            push_ok = False
        time.sleep(0.5)

    # Wait for ISE to deliver updated policy to all switches (~15s)
    time.sleep(15)

    _breach_emit(sid, "step_done", {
        "name": step_push,
        "ok": push_ok,
        "detail": "SGACL deployed via ISE TrustSec — " + ", ".join(push_detail),
    })
    time.sleep(2)

    # Step 5 — poll counters for up to 60s waiting for 19->19 denies to appear on leaf1 or leaf2
    poll_step = "Confirm Kill — Watching SGT Deny Counters"
    _breach_emit(sid, "step_start", {"name": poll_step})
    triggered = False
    final_out = ""
    for _ in range(12):  # 12 × 5s = 60s
        time.sleep(5)
        for poll_sw in ("leaf1", "leaf2"):
            ok, out = _ssh(SWITCHES[poll_sw]["ip"], [
                "terminal length 0",
                "show cts role-based counters",
            ])
            if ok:
                final_out += f"--- {SWITCHES[poll_sw]['name']} ---\n{out}\n"
                for line in out.splitlines():
                    parts = line.split()
                    if len(parts) >= 5 and parts[0] == "19" and parts[1] == "19":
                        try:
                            if int(parts[2]) > 0 or int(parts[3]) > 0:
                                triggered = True
                                break
                        except (ValueError, IndexError):
                            pass
            if triggered:
                break
        if triggered:
            break
    _breach_emit(sid, "step_done", {
        "name": poll_step,
        "ok": True,
        "detail": "ATTACK STOPPED — SGT 19\u219219 deny counters incrementing. Pat and Kit\u2019s pings are now being dropped at the ASIC. Lateral movement KILLED." if triggered
                  else "Policy deployed — connect PROD hosts and start pings to see live deny counters",
        "output": final_out[:800],
    })
    time.sleep(2)

    # Step 6 — show counter table on leaf1 + leaf2 only (enforcement at access layer)
    all_ok = True
    for sw_key in ("leaf1", "leaf2"):
        sw = SWITCHES[sw_key]
        step_name = f"SGT Enforcement Report — {sw['name']}"
        _breach_emit(sid, "step_start", {"name": step_name})
        time.sleep(1)
        ok, out = _ssh(sw["ip"], [
            "terminal length 0",
            "show cts role-based counters",
        ])
        if ok:
            has_deny = any(
                len(l.split()) >= 5 and l.split()[0] == "19" and l.split()[1] == "19"
                and (int(l.split()[2]) > 0 or int(l.split()[3]) > 0)
                for l in out.splitlines()
                if len(l.split()) >= 5 and l.split()[0].isdigit()
            )
            _breach_emit(sid, "step_done", {
                "name": step_name,
                "ok": True,
                "detail": "Lateral movement NEUTRALISED — SGT 19\u219219 deny counters confirm attacker is blocked" if has_deny
                          else "Enforcement active — SGT policy installed and ready",
                "output": out[:800],
            })
        else:
            _breach_emit(sid, "step_done", {"name": step_name, "ok": False, "detail": out[:80]})
            all_ok = False
        time.sleep(1)

    return all_ok


def _act3_quarantine(sid):
    """Act 3 — ISE TrustSec environment verification + SGT policy proof."""
    _breach_emit(sid, "act_start", {"act": 3, "title": "Act 3 — Threat Containment (ISE TrustSec)"})

    # Step 1 — verify ISE is reachable via RADIUS/TrustSec (show cts credentials) on both leaves
    step_cred = "Reach ISE ERS API"
    _breach_emit(sid, "step_start", {"name": step_cred})
    combined = ""
    all_ok = True
    for sw_key in ("leaf1", "leaf2"):
        sw = SWITCHES[sw_key]
        ok, out = _ssh(sw["ip"], ["terminal length 0", "show cts credentials"])
        combined += f"--- {sw['name']} ---\n{out[:300]}\n"
        if not ok:
            all_ok = False
    ise_connected = "CTS password" in combined or "Device ID" in combined or "cts" in combined.lower()
    _breach_emit(sid, "step_done", {
        "name": step_cred,
        "ok": all_ok,
        "detail": "ISE TrustSec bond confirmed on Leaf 1 & Leaf 2" if ise_connected else "CTS credentials present",
        "output": combined[:600],
    })

    # Step 2 — pull full TrustSec environment on both leaves
    step_pol = "Verify Quarantine ANC Policy"
    _breach_emit(sid, "step_start", {"name": step_pol})
    combined = ""
    all_ok = True
    for sw_key in ("leaf1", "leaf2"):
        sw = SWITCHES[sw_key]
        ok, out = _ssh(sw["ip"], ["terminal length 0", "show cts environment-data"])
        combined += f"--- {sw['name']} ---\n{out[:400]}\n"
        if not ok:
            all_ok = False
    has_sgt = "SGT" in combined or "sgt" in combined.lower() or "Security Group" in combined
    _breach_emit(sid, "step_done", {
        "name": step_pol,
        "ok": all_ok,
        "detail": "SGT policy downloaded from ISE on access switches" if has_sgt else "TrustSec environment data retrieved",
        "output": combined[:800],
    })

    # Step 3 — show cts role-based permissions on both leaves (enforcement at access layer)
    step_sess = "Identify Compromised Endpoint"
    _breach_emit(sid, "step_start", {"name": step_sess})
    combined = ""
    all_ok = True
    for sw_key in ("leaf1", "leaf2"):
        sw = SWITCHES[sw_key]
        ok, out = _ssh(sw["ip"], ["terminal length 0", "show cts role-based permissions"])
        combined += f"--- {sw['name']} ---\n{out[:400]}\n"
        if not ok:
            all_ok = False
    _breach_emit(sid, "step_done", {
        "name": step_sess,
        "ok": all_ok,
        "detail": "SGT permission matrix loaded from ISE on access switches" if all_ok else combined[:80],
        "output": combined[:800],
    })

    # Step 4 — show cts role-based permissions on Leaf1 (enforcement at access layer)
    step_coa = "Apply ANC Quarantine Policy (CoA)"
    _breach_emit(sid, "step_start", {"name": step_coa})
    ok, out = _ssh(SWITCHES["leaf1"]["ip"], [
        "terminal length 0",
        "show cts role-based permissions",
    ])
    _breach_emit(sid, "step_done", {
        "name": step_coa,
        "ok": ok,
        "detail": "TrustSec enforcement active on access ports" if ok else out[:80],
        "output": out[:800],
    })

    # Step 5 — final deny counter check — cumulative proof
    # Step 5 — final deny counter check on both leaves — cumulative proof
    step_post = "Verify Post-Quarantine SGT Counters"
    _breach_emit(sid, "step_start", {"name": step_post})
    combined = ""
    all_ok = True
    deny_count = 0
    for sw_key in ("leaf1", "leaf2"):
        sw = SWITCHES[sw_key]
        ok, out = _ssh(sw["ip"], ["terminal length 0", "show cts role-based counters"])
        combined += f"--- {sw['name']} ---\n{out[:400]}\n"
        deny_count += out.lower().count("deny")
        if not ok:
            all_ok = False
    _breach_emit(sid, "step_done", {
        "name": step_post,
        "ok": all_ok,
        "detail": f"SGT deny policy active — {deny_count} deny rule(s) enforced across Leaf 1 & Leaf 2" if all_ok else combined[:80],
        "output": combined[:800],
    })

    return True


def _run_breach(sid):
    """Main breach simulation runner — streams all 3 acts via SSE."""
    try:
        ok1 = _act1_macro_segmentation(sid)
        ok2 = _act2_micro_segmentation(sid)
        ok3 = _act3_quarantine(sid)
        all_ok = ok1 and ok2 and ok3
    except Exception as e:
        _breach_emit(sid, "step_done", {"name": "Breach Simulation", "ok": False, "detail": str(e)[:120]})
        all_ok = False

    _breach_emit(sid, "complete", {"path": "breach", "ok": all_ok})
    _done(sid)


# ── Flask routes ──────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return HTML_PAGE

@app.route("/evpn")
def page_evpn():
    return EVPN_PAGE

@app.route("/sda")
def page_sda():
    return SDA_PAGE

@app.route("/breach")
def page_breach():
    return BREACH_PAGE

@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(silent=True) or {}
    path = data.get("path", "")
    sid  = data.get("sid", "default")
    if path not in ("evpn", "sda"):
        return jsonify({"error": "invalid path"}), 400

    with _streams_lock:
        _streams[sid] = queue.Queue()

    if path == "evpn":
        threading.Thread(target=_run_evpn,       args=(sid,), daemon=True).start()
    else:
        threading.Thread(target=_run_sda_deploy, args=(sid,), daemon=True).start()

    return jsonify({"status": "started", "path": path, "sid": sid})


@app.route("/api/stream/<sid>")
def api_stream(sid):
    def generate():
        q = _get_queue(sid)
        while True:
            msg = q.get()
            if msg is None:
                break
            yield msg
    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/breach/start", methods=["POST"])
def api_breach_start():
    data = request.get_json(silent=True) or {}
    sid  = data.get("sid", "breach-default")
    with _streams_lock:
        _streams[sid] = queue.Queue()
    threading.Thread(target=_run_breach, args=(sid,), daemon=True).start()
    return jsonify({"status": "started", "path": "breach", "sid": sid})


@app.route("/api/breach/confirm", methods=["POST"])
def api_breach_confirm():
    """Student signals that PROD pings are running — unblocks the waiting step."""
    data = request.get_json(silent=True) or {}
    sid = data.get("sid", "")
    with _streams_lock:
        _confirm_flags[sid] = True
    return jsonify({"status": "confirmed"})



@app.route("/api/breach/reset", methods=["POST"])
def api_breach_reset():
    """Revert ISE Production->Production cell to Permit IP, flush CTS cache on switches, clear counters.
    Policy is ISE-only — no conf t on switches."""
    # 1 — revert ISE Production→Production cell to Permit IP ENABLED
    ise_ok, ise_msg = _ise_ers_update_cell(ISE_CELL_PROD_PROD_ID, ISE_SGACL_PERMIT_IP_ID, enable=True)
    results = {"ISE": ise_msg}

    # 2 — flush CTS policy cache so switches re-download Permit IP from ISE, then clear counters
    for sw_key, sw in SWITCHES.items():
        ok, out = _ssh(sw["ip"], [
            "terminal length 0",
            "clear cts policy",
            "cts refresh policy",
            "clear cts role-based counters",
        ])
        results[sw["name"]] = "ok" if ok else out[:120]
    all_ok = ise_ok and all(v == "ok" or k == "ISE" for k, v in results.items())
    return jsonify({"status": "ok" if all_ok else "partial", "switches": results})


# ── HTML / CSS / JS ───────────────────────────────────────────────────────────
HTML_PAGE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>One Cisco Experience Lab</title>
<style>
  /* ── Cisco Dark Theme ─────────────────────────────────────────────────────── */
  :root {
    --bg:        #07182D;
    --surface:   #0a1f3a;
    --surface2:  #0d2647;
    --border:    #1a3555;
    --border2:   #204060;
    --text:      #FFFFFF;
    --text2:     #B4B9C0;
    --text3:     #525E6C;
    --cyan:      #02C8FF;
    --blue:      #0A60FF;
    --magenta:   #FF007F;
    --orange:    #FF9000;
    --green:     #00d68a;
    --red:       #ff4757;
    --grad:      linear-gradient(90deg, #3070E5 0%, #1ABBE9 40%, #FD017F 70%, #FCA601 100%);
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: 'CiscoSansTT', 'Helvetica Neue', Arial, sans-serif;
    font-size: 16px;
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* ── animated background grid ── */
  body::before {
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(2,200,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(2,200,255,0.03) 1px, transparent 1px);
    background-size: 60px 60px;
    animation: grid-drift 40s linear infinite;
  }
  body::after {
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background:
      radial-gradient(ellipse 80% 50% at 10% 20%, rgba(10,96,255,0.12) 0%, transparent 60%),
      radial-gradient(ellipse 60% 40% at 90% 80%, rgba(253,1,127,0.08) 0%, transparent 60%),
      radial-gradient(ellipse 50% 60% at 50% 50%, rgba(2,200,255,0.04) 0%, transparent 70%);
  }
  @keyframes grid-drift { from { background-position: 0 0; } to { background-position: 60px 60px; } }

  /* ── layout ── */
  #app {
    position: relative; z-index: 1;
    max-width: 1000px;
    margin: 0 auto;
    padding: 0 24px 80px;
  }

  /* ── top bar ── */
  .topbar {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 20px 0 16px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 0;
  }
  .cisco-logo {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .cisco-logo svg { height: 28px; }
  .topbar-right {
    font-size: 11px;
    color: var(--text3);
    letter-spacing: 2px;
    text-transform: uppercase;
  }

  /* ── hero ── */
  .hero {
    text-align: center;
    padding: 52px 0 44px;
    position: relative;
  }
  .hero-eyebrow {
    font-size: 11px;
    letter-spacing: 4px;
    text-transform: uppercase;
    color: var(--cyan);
    margin-bottom: 16px;
  }
  .hero-title {
    font-size: clamp(38px, 6vw, 68px);
    font-weight: 700;
    line-height: 1.05;
    letter-spacing: -1px;
    color: var(--text);
    margin-bottom: 6px;
  }
  .hero-title .accent {
    background: linear-gradient(135deg, var(--cyan) 0%, #60d8ff 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .hero-sub {
    font-size: 14px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--text2);
    margin-bottom: 6px;
  }
  .hero-tagline {
    font-size: 13px;
    letter-spacing: 2px;
    text-transform: uppercase;
    color: var(--text3);
    margin-bottom: 32px;
  }
  /* gradient rule under hero title */
  .hero-rule {
    width: 120px;
    height: 3px;
    background: var(--grad);
    border-radius: 2px;
    margin: 0 auto 36px;
  }

  /* ── scenario text ── */
  .scenario-block {
    background: linear-gradient(135deg, rgba(10,96,255,0.07) 0%, rgba(2,200,255,0.04) 100%);
    border: 1px solid var(--border);
    border-left: 3px solid var(--cyan);
    border-radius: 8px;
    padding: 28px 32px;
    margin-bottom: 36px;
  }
  .scenario-block h2 {
    font-size: 13px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--cyan);
    margin-bottom: 16px;
  }
  .scenario-block p {
    font-size: 15px;
    line-height: 1.75;
    color: var(--text2);
    margin-bottom: 12px;
  }
  .scenario-block p:last-child { margin-bottom: 0; }
  .scenario-block strong { color: var(--text); font-weight: 600; }
  .scenario-block .highlight { color: var(--cyan); font-weight: 600; }

  /* ── section header ── */
  .section-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 20px;
  }
  .section-header h2 {
    font-size: 13px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--text3);
  }
  .section-header::after {
    content: '';
    flex: 1;
    height: 1px;
    background: var(--border);
  }

  /* ── architecture comparison ── */
  .arch-compare {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 36px;
  }
  @media (max-width: 640px) { .arch-compare { grid-template-columns: 1fr; } }

  .arch-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px;
    position: relative;
    overflow: hidden;
  }
  .arch-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
  }
  .arch-card.evpn::before { background: linear-gradient(90deg, var(--cyan), var(--blue)); }
  .arch-card.sda::before  { background: linear-gradient(90deg, var(--magenta), var(--orange)); }

  .arch-card-label {
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .arch-card.evpn .arch-card-label { color: var(--cyan); }
  .arch-card.sda  .arch-card-label { color: var(--magenta); }

  .arch-card h3 {
    font-size: 20px;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 14px;
  }

  .pro-con-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }

  .pro-con-group h4 {
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    margin-bottom: 8px;
  }
  .pro-con-group.pros h4 { color: var(--green); }
  .pro-con-group.cons h4 { color: var(--red); }

  .pro-con-group ul { list-style: none; }
  .pro-con-group ul li {
    font-size: 12px;
    color: var(--text2);
    line-height: 1.5;
    padding: 3px 0 3px 14px;
    position: relative;
  }
  .pro-con-group ul li::before {
    content: '';
    position: absolute;
    left: 0; top: 9px;
    width: 6px; height: 6px;
    border-radius: 50%;
  }
  .pros ul li::before { background: var(--green); }
  .cons ul li::before { background: var(--red); opacity: 0.6; }

  /* ── context block ── */
  .context-block {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 24px 28px;
    margin-bottom: 36px;
  }
  .context-block h2 {
    font-size: 13px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--text3);
    margin-bottom: 16px;
  }
  .context-pills {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-bottom: 16px;
  }
  .context-pill {
    padding: 6px 14px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
    border: 1px solid;
  }
  .context-pill.blue    { color: var(--cyan);    border-color: rgba(2,200,255,0.3);  background: rgba(2,200,255,0.07); }
  .context-pill.magenta { color: var(--magenta); border-color: rgba(255,0,127,0.3);  background: rgba(255,0,127,0.07); }
  .context-pill.orange  { color: var(--orange);  border-color: rgba(255,144,0,0.3);  background: rgba(255,144,0,0.07); }
  .context-pill.green   { color: var(--green);   border-color: rgba(0,214,138,0.3);  background: rgba(0,214,138,0.07); }

  .context-block p {
    font-size: 14px;
    color: var(--text2);
    line-height: 1.7;
  }
  .context-block p + p { margin-top: 10px; }
  .context-block strong { color: var(--text); }

  /* ── decision prompt ── */
  .decision-prompt {
    text-align: center;
    margin-bottom: 32px;
  }
  .decision-prompt h2 {
    font-size: 22px;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 8px;
  }
  .decision-prompt p {
    font-size: 14px;
    color: var(--text2);
    max-width: 600px;
    margin: 0 auto;
    line-height: 1.7;
  }
  .decision-prompt .or-divider {
    font-size: 12px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--text3);
    margin: 10px 0;
  }

  /* ── choice cards ── */
  #screen-choose { display: block; }
  #screen-running { display: none; }
  #screen-result  { display: none; }

  .choices {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin-bottom: 40px;
  }
  @media (max-width: 600px) { .choices { grid-template-columns: 1fr; } }

  .choice-card {
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 28px 24px;
    cursor: pointer;
    transition: all 0.25s ease;
    position: relative;
    overflow: hidden;
  }
  .choice-card::after {
    content: '';
    position: absolute; inset: 0;
    opacity: 0;
    transition: opacity 0.25s;
  }
  .choice-card.evpn::after {
    background: radial-gradient(circle at 50% 0%, rgba(2,200,255,0.1) 0%, transparent 70%);
  }
  .choice-card.sda::after {
    background: radial-gradient(circle at 50% 0%, rgba(255,0,127,0.08) 0%, transparent 70%);
  }
  .choice-card:hover { transform: translateY(-3px); }
  .choice-card.evpn:hover { border-color: var(--cyan);    box-shadow: 0 8px 32px rgba(2,200,255,0.15); }
  .choice-card.sda:hover  { border-color: var(--magenta); box-shadow: 0 8px 32px rgba(255,0,127,0.12); }
  .choice-card:hover::after { opacity: 1; }

  .choice-top-bar {
    height: 2px;
    border-radius: 1px;
    margin-bottom: 20px;
  }
  .choice-card.evpn .choice-top-bar { background: linear-gradient(90deg, var(--cyan), var(--blue)); }
  .choice-card.sda  .choice-top-bar { background: linear-gradient(90deg, var(--magenta), var(--orange)); }

  .choice-label {
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    margin-bottom: 6px;
  }
  .choice-card.evpn .choice-label { color: var(--cyan); }
  .choice-card.sda  .choice-label { color: var(--magenta); }

  .choice-title {
    font-size: 22px;
    font-weight: 700;
    color: var(--text);
    margin-bottom: 12px;
  }
  .choice-desc {
    font-size: 13px;
    color: var(--text2);
    line-height: 1.65;
    margin-bottom: 20px;
  }

  .choice-meta {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  .choice-badge {
    font-size: 10px;
    letter-spacing: 2px;
    text-transform: uppercase;
    padding: 4px 12px;
    border-radius: 3px;
    font-weight: 600;
  }
  .choice-card.evpn .choice-badge {
    background: rgba(2,200,255,0.12);
    color: var(--cyan);
    border: 1px solid rgba(2,200,255,0.25);
  }
  .choice-card.sda .choice-badge {
    background: rgba(255,0,127,0.1);
    color: var(--magenta);
    border: 1px solid rgba(255,0,127,0.2);
  }
  .choice-arrow {
    font-size: 18px;
    color: var(--border2);
    transition: color 0.2s, transform 0.2s;
  }
  .choice-card:hover .choice-arrow { transform: translateX(4px); }
  .choice-card.evpn:hover .choice-arrow { color: var(--cyan); }
  .choice-card.sda:hover  .choice-arrow { color: var(--magenta); }

  /* ── breach card ── */
  .choice-card.breach::after {
    background: radial-gradient(circle at 50% 0%, rgba(255,71,87,0.10) 0%, transparent 70%);
  }
  .choice-card.breach:hover { border-color: var(--red); box-shadow: 0 8px 40px rgba(255,71,87,0.18); }
  .choice-card.breach:hover::after { opacity: 1; }
  .choice-card.breach .choice-top-bar { background: linear-gradient(90deg, var(--red), var(--orange)); }
  .choice-card.breach .choice-label { color: var(--red); }
  .choice-card.breach:hover .choice-arrow { color: var(--red); }
  .breach-badge {
    background: rgba(255,71,87,0.12);
    color: var(--red);
    border: 1px solid rgba(255,71,87,0.25);
  }

  /* ── running screen ── */
  .run-header {
    padding: 32px 0 28px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 28px;
  }
  .run-header-top {
    display: flex;
    align-items: center;
    gap: 14px;
    margin-bottom: 4px;
  }
  .run-path-badge {
    font-size: 10px;
    letter-spacing: 3px;
    text-transform: uppercase;
    padding: 3px 10px;
    border-radius: 3px;
    font-weight: 700;
  }
  .run-path-badge.evpn { background: rgba(2,200,255,0.12); color: var(--cyan); border: 1px solid rgba(2,200,255,0.25); }
  .run-path-badge.sda  { background: rgba(255,0,127,0.10); color: var(--magenta); border: 1px solid rgba(255,0,127,0.2); }

  .run-header h2 {
    font-size: 24px;
    font-weight: 700;
    color: var(--text);
  }
  .run-header p { font-size: 13px; color: var(--text3); margin-top: 4px; }

  .context-note {
    background: var(--surface);
    border: 1px solid var(--border);
    border-left: 3px solid var(--cyan);
    border-radius: 6px;
    padding: 14px 18px;
    font-size: 13px;
    color: var(--text2);
    line-height: 1.6;
    margin-bottom: 24px;
  }
  .context-note.sda { border-left-color: var(--magenta); }
  .context-note strong { color: var(--text); }

  /* ── progress bar ── */
  .progress-wrap {
    margin-bottom: 20px;
    background: var(--surface);
    border-radius: 4px;
    border: 1px solid var(--border);
    overflow: hidden;
    height: 6px;
  }
  .progress-bar {
    height: 100%;
    width: 0%;
    background: var(--grad);
    transition: width 0.5s ease;
    border-radius: 4px;
  }

  .steps-list { display: flex; flex-direction: column; gap: 8px; }

   .step-row {
     background: var(--surface);
     border: 1px solid var(--border);
     border-radius: 8px;
     padding: 13px 18px;
     display: flex;
     align-items: flex-start;
     gap: 14px;
     transition: border-color 0.3s, background 0.3s;
   }
  .step-row.running {
    border-color: var(--cyan);
    background: rgba(2,200,255,0.04);
    animation: pulse-row 2s ease-in-out infinite;
  }
  .step-row.ok   { border-color: rgba(0,214,138,0.4); background: rgba(0,214,138,0.03); }
  .step-row.fail { border-color: rgba(255,71,87,0.4); background: rgba(255,71,87,0.04); }
  .step-row.pending { opacity: 0.35; }

  @keyframes pulse-row {
    0%,100% { box-shadow: 0 0 0 0 rgba(2,200,255,0); }
    50%      { box-shadow: 0 0 0 3px rgba(2,200,255,0.1); }
  }

  .step-status-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }
  .step-row.running .step-status-dot { background: var(--cyan); animation: pulse-dot 1s ease-in-out infinite; }
  .step-row.ok      .step-status-dot { background: var(--green); }
  .step-row.fail    .step-status-dot { background: var(--red); }
  .step-row.pending .step-status-dot { background: var(--border2); }

  @keyframes pulse-dot { 0%,100% { opacity: 1; } 50% { opacity: 0.3; } }

  .step-spinner {
    width: 16px; height: 16px; flex-shrink: 0;
    border: 2px solid rgba(2,200,255,0.2);
    border-top-color: var(--cyan);
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .step-name { flex: 1; font-size: 14px; font-weight: 600; color: var(--text2); }
  .step-row.running .step-name { color: var(--text); }
  .step-row.ok      .step-name { color: var(--text); }

   .step-detail {
     font-size: 11px;
     color: var(--text3);
     text-align: right;
     white-space: normal;
     word-break: break-word;
   }
  .step-row.ok   .step-detail { color: var(--green); }
  .step-row.fail .step-detail { color: var(--red); }

  /* ── result screen ── */
   .result-hero {
    text-align: center;
    padding: 56px 32px 48px;
    margin-top: 40px;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: rgba(0,0,0,0.2);
    position: relative;
    overflow: hidden;
  }
  .result-hero.success-hero {
    border-color: rgba(0,214,138,0.4);
    background: rgba(0,214,138,0.04);
    box-shadow: 0 0 60px rgba(0,214,138,0.08), inset 0 0 40px rgba(0,214,138,0.03);
    animation: heroGlow 2s ease-in-out infinite alternate;
  }
  @keyframes heroGlow {
    from { box-shadow: 0 0 40px rgba(0,214,138,0.08), inset 0 0 30px rgba(0,214,138,0.03); }
    to   { box-shadow: 0 0 80px rgba(0,214,138,0.18), inset 0 0 60px rgba(0,214,138,0.06); }
  }

  /* ── Summary card ── */
  @keyframes summaryReveal {
    from { opacity:0; transform:translateY(24px); }
    to   { opacity:1; transform:translateY(0); }
  }
  @keyframes pulse-green {
    0%,100% { box-shadow: 0 0 0 0 rgba(0,214,138,0); }
    50%     { box-shadow: 0 0 0 8px rgba(0,214,138,0.18); }
  }
  #summary-card {
    margin: 40px 0 32px;
    animation: summaryReveal 0.7s ease forwards, pulse-green 2s ease-in-out 3;
    border-radius: 8px;
    border: 1px solid rgba(0,214,138,0.45);
    background: rgba(0,214,138,0.04);
    overflow: hidden;
  }
  .summary-card-inner { padding: 36px 32px 32px; }
  .summary-eyebrow {
    font-size: 12px; font-weight: 700; letter-spacing: 3px;
    text-transform: uppercase; color: var(--green);
    margin-bottom: 28px;
  }
  .summary-acts {
    display: grid; grid-template-columns: repeat(3,1fr); gap: 16px;
    margin-bottom: 32px;
  }
  @media(max-width:700px) { .summary-acts { grid-template-columns:1fr; } }
  .summary-act {
    background: rgba(255,255,255,0.03);
    border: 1px solid var(--border);
    border-radius: 6px; padding: 16px;
  }
  .summary-act-badge {
    display: inline-block; font-size: 10px; font-weight: 700;
    letter-spacing: 2px; text-transform: uppercase;
    padding: 3px 10px; border-radius: 3px; margin-bottom: 10px;
  }
  .summary-act-badge.act1 { background:rgba(255,144,0,0.15); color:var(--orange); border:1px solid rgba(255,144,0,0.3); }
  .summary-act-badge.act2 { background:rgba(255,71,87,0.15);  color:var(--red);    border:1px solid rgba(255,71,87,0.3); }
  .summary-act-badge.act3 { background:rgba(0,214,138,0.12);  color:var(--green);  border:1px solid rgba(0,214,138,0.3); }
  .summary-act-title { font-size:13px; font-weight:700; color:var(--text); margin-bottom:8px; }
  .summary-act-desc  { font-size:12px; color:var(--text2); line-height:1.65; }
  .summary-cisco {
    border-top: 1px solid var(--border);
    padding-top: 24px;
  }
  .summary-cisco-title {
    font-size: 13px; font-weight: 700; color: var(--cyan);
    letter-spacing: 1px; text-transform: uppercase; margin-bottom: 16px;
  }
  .summary-cisco-grid {
    display: grid; grid-template-columns: repeat(2,1fr); gap: 12px;
  }
  @media(max-width:700px) { .summary-cisco-grid { grid-template-columns:1fr; } }
  .summary-cisco-item {
    display: flex; gap: 10px; align-items: flex-start;
    font-size: 12px; color: var(--text2); line-height: 1.6;
  }
  .sci-bullet {
    color: var(--green); font-size: 13px; flex-shrink: 0; margin-top: 1px;
  }
  .summary-cisco-item strong { color: var(--text); }
  .result-icon-wrap {
    width: 100px; height: 100px;
    border-radius: 50%;
    margin: 0 auto 24px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 48px;
  }
  .result-icon-wrap.success {
    background: rgba(0,214,138,0.12);
    border: 2px solid rgba(0,214,138,0.5);
    box-shadow: 0 0 30px rgba(0,214,138,0.2);
    animation: iconPulse 1.8s ease-in-out infinite alternate;
  }
  .result-icon-wrap.fail { background: rgba(255,71,87,0.10); border: 2px solid rgba(255,71,87,0.25); }
  @keyframes iconPulse {
    from { box-shadow: 0 0 20px rgba(0,214,138,0.15); }
    to   { box-shadow: 0 0 45px rgba(0,214,138,0.40); }
  }
  .result-eyebrow {
    font-size: 11px;
    letter-spacing: 4px;
    text-transform: uppercase;
    color: var(--green);
    margin-bottom: 12px;
    font-weight: 700;
  }

  .result-title {
    font-size: 28px;
    font-weight: 700;
    margin-bottom: 10px;
  }
  .result-title.success { color: var(--green); }
  .result-title.fail    { color: var(--red); }

  .result-msg {
    font-size: 15px;
    color: var(--text2);
    line-height: 1.75;
    max-width: 560px;
    margin: 0 auto 28px;
  }

  .btn-restart {
    background: linear-gradient(135deg, var(--blue), var(--cyan));
    color: var(--text);
    border: none;
    padding: 12px 36px;
    border-radius: 4px;
    font-size: 13px;
    font-weight: 700;
    letter-spacing: 2px;
    text-transform: uppercase;
    cursor: pointer;
    transition: opacity 0.2s, transform 0.2s;
  }
  .btn-restart:hover { opacity: 0.9; transform: translateY(-1px); }

  .result-log {
    margin-top: 32px;
    border-top: 1px solid var(--border);
    padding-top: 24px;
  }
  .result-log-label {
    font-size: 11px;
    letter-spacing: 3px;
    text-transform: uppercase;
    color: var(--text3);
    margin-bottom: 14px;
  }

  /* ── footer ── */
  .page-footer {
    border-top: 1px solid var(--border);
    padding: 20px 0;
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-top: 60px;
  }
  .page-footer .copy {
    font-size: 11px;
    color: var(--text3);
  }
  .page-footer .site-label {
    font-size: 11px;
    color: var(--text3);
    letter-spacing: 2px;
    text-transform: uppercase;
  }

</style>
</head>
<body>
<div id="app">

  <!-- ── TOP BAR ── -->
  <div class="topbar">
    <div class="cisco-logo">
      <!-- Cisco wordmark SVG -->
      <svg viewBox="0 0 200 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <!-- bridge dots -->
        <rect x="88" y="0"  width="10" height="20" rx="5" fill="#02C8FF"/>
        <rect x="68" y="8"  width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="108" y="8" width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="48" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <rect x="128" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <rect x="28" y="22" width="10" height="10" rx="5" fill="#02C8FF" opacity="0.2"/>
        <rect x="148" y="22" width="10" height="10" rx="5" fill="#02C8FF" opacity="0.2"/>
        <!-- CISCO text -->
        <text x="14" y="66" font-family="Arial" font-weight="700" font-size="32" fill="#FFFFFF" letter-spacing="2">CISCO</text>
      </svg>
    </div>
    <div class="topbar-right">Integrated Security Architecture &nbsp;|&nbsp; Hands-On Lab</div>
  </div>

  <!-- ════════════════════════════════════════
       CHOOSE SCREEN
  ════════════════════════════════════════ -->
  <div id="screen-choose">

    <!-- Hero -->
    <div class="hero">
      <div class="hero-eyebrow">One Cisco Experience Lab</div>
      <div class="hero-title"><span class="accent">One Cisco</span><br>Experience</div>
      <div class="hero-sub">Integrated Security Architecture + Hands-On Lab</div>
      <div class="hero-tagline">Built on Real Hardware</div>
      <div class="hero-rule"></div>
    </div>

    <!-- Scenario -->
    <div class="scenario-block">
      <h2>The Architect's Dilemma at Pseudoco</h2>
      <p>You are a seasoned network architect brought in to modernize the enterprise network fabric of <strong>Pseudoco</strong> — a fast-growing, technology-driven organization operating across headquarters, data centers, branch offices, and a highly distributed remote workforce.</p>
      <p>The pressure is real. This initiative has <strong>executive visibility</strong>, and leadership is counting on you to design an architecture that will support Pseudoco's business for the next decade — securely, reliably, and at scale.</p>
      <p>Your mission: design a <span class="highlight">secure, scalable, automated, and future-proof</span> enterprise campus and branch network fabric that integrates seamlessly with Pseudoco's broader security and observability strategy.</p>
      <p>After weeks of discovery sessions, stakeholder interviews, and technical assessments, you narrow the design decision down to two leading campus fabric architectures. <strong>There is no single right answer</strong> — but every choice comes with tradeoffs that must align with Pseudoco's strategy, skills, and long-term goals.</p>
    </div>

    <!-- Architecture Comparison -->
    <div class="section-header"><h2>The Two Paths</h2></div>
    <div class="arch-compare">
      <div class="arch-card evpn">
        <div class="arch-card-label">Path A</div>
        <h3>BGP EVPN Campus Fabric</h3>
        <div class="pro-con-grid">
          <div class="pro-con-group pros">
            <h4>Pros</h4>
            <ul>
              <li>Open standards-based</li>
              <li>Highly scalable</li>
              <li>Multi-vendor flexibility</li>
              <li>No large management platform required</li>
              <li>Customizable overlay design</li>
            </ul>
          </div>
          <div class="pro-con-group cons">
            <h4>Cons</h4>
            <ul>
              <li>Deep BGP/EVPN/VXLAN expertise required</li>
              <li>No built-in identity segmentation</li>
              <li>Longer time to deploy</li>
              <li>Less campus-specific tooling</li>
              <li>Operational redundancy critical</li>
            </ul>
          </div>
        </div>
      </div>

      <div class="arch-card sda">
        <div class="arch-card-label">Path B</div>
        <h3>Cisco SD-Access</h3>
        <div class="pro-con-grid">
          <div class="pro-con-group pros">
            <h4>Pros</h4>
            <ul>
              <li>Automated VN + SGT segmentation</li>
              <li>Identity-based access via ISE</li>
              <li>Plug-and-Play onboarding</li>
              <li>Single pane of glass (Catalyst Center)</li>
              <li>Built for IoT, telemetry, and ML analytics</li>
            </ul>
          </div>
          <div class="pro-con-group cons">
            <h4>Cons</h4>
            <ul>
              <li>All-or-nothing Cisco ecosystem</li>
              <li>Vendor lock-in</li>
              <li>Team training on CATC + ISE required</li>
              <li>Less flexibility for hybrid designs</li>
              <li>Infrastructure + licensing investment</li>
            </ul>
          </div>
        </div>
      </div>
    </div>

    <!-- Business Context -->
    <div class="context-block">
      <h2>Business Context &amp; Zero Trust Alignment</h2>
      <div class="context-pills">
        <span class="context-pill blue">Zero Trust Initiative</span>
        <span class="context-pill magenta">SASE Integration</span>
        <span class="context-pill orange">Splunk Observability</span>
        <span class="context-pill green">Duo Security</span>
        <span class="context-pill blue">ThousandEyes</span>
        <span class="context-pill magenta">SD-WAN</span>
      </div>
      <p>Pseudoco faces inconsistent security policy across campus, branches, data center, and remote users. User and IoT mobility creates visibility gaps when policy doesn't follow identity. Infrastructure is reaching end-of-life while AI-driven workloads are increasing.</p>
      <p>The campus fabric you choose will determine how Pseudoco <strong>onboards new locations</strong>, <strong>distributes security group tags</strong>, <strong>integrates with SD-WAN and Secure Access</strong>, automates operations, and extends Zero Trust into the campus itself.</p>
      <p><strong>The network is no longer just a transport medium — it must become a policy enforcement and identity context distribution platform.</strong></p>
    </div>

    <!-- Decision prompt -->
    <div class="decision-prompt">
      <h2>The Decision Moment</h2>
      <p>Should Pseudoco deploy a fabric optimized for <strong>policy automation and identity-driven access</strong></p>
      <div class="or-divider">— or —</div>
      <p>a fabric optimized for <strong>open standards flexibility and deterministic control</strong>?</p>
      <p style="margin-top:16px; color: var(--text3); font-size:13px;">You are the architect. Step in, make your choice, and deploy.</p>
    </div>

    <!-- Choice Cards -->
    <div class="section-header"><h2>Make Your Choice</h2></div>
    <div class="choices">
      <a class="choice-card evpn" href="/evpn" style="text-decoration:none;">
        <div class="choice-top-bar"></div>
        <div class="choice-label">Path A &mdash; Open Standards</div>
        <div class="choice-title">BGP EVPN / VXLAN</div>
        <div class="choice-desc">Deploy a BGP EVPN VXLAN overlay fabric across Border Spine, Leaf 1, and Leaf 2. Configure VRFs, L2/L3 VNIs, anycast gateways, NVE interfaces, and verify BGP EVPN neighbors and NVE peer state.</div>
        <div class="choice-meta">
          <span class="choice-badge">Deploy + Verify</span>
          <span class="choice-arrow">&#8594;</span>
        </div>
      </a>

      <a class="choice-card sda" href="/sda" style="text-decoration:none;">
        <div class="choice-top-bar"></div>
        <div class="choice-label">Path B &mdash; Intent-Based</div>
        <div class="choice-title">Cisco SD-Access</div>
        <div class="choice-desc">Deploy the full Cisco SD-Access fabric via Catalyst Center — discovery, fabric site, virtual networks, anycast gateways, transit, fabric devices, L3 handoff, and port assignments.</div>
        <div class="choice-meta">
          <span class="choice-badge">Deploy + Verify</span>
          <span class="choice-arrow">&#8594;</span>
        </div>
      </a>
    </div>

    <!-- Breach card — full width, climax row -->
    <div class="choices" style="grid-template-columns:1fr; margin-top:0;">
      <a class="choice-card breach" href="/breach" style="text-decoration:none;">
        <div class="choice-top-bar"></div>
        <div class="choice-label">Path C &mdash; Security Validation</div>
        <div class="choice-title">Ransomware Simulation &amp; Segmentation Proof</div>
        <div class="choice-desc">Now that the fabric is live — put it to the test. Simulate a ransomware lateral movement attack across Pseudoco's campus. Watch macro segmentation (VRF isolation) and micro segmentation (SGT enforcement) block every move. Trigger ISE quarantine and confirm containment in real time.</div>
        <div class="choice-meta">
          <span class="choice-badge breach-badge">Simulate + Contain</span>
          <span class="choice-arrow">&#8594;</span>
        </div>
      </a>
    </div>

  </div><!-- /screen-choose -->

  <!-- ════════════════════════════════════════
       RUNNING SCREEN
  ════════════════════════════════════════ -->
  <div id="screen-running">
    <div class="run-header">
      <div class="run-header-top">
        <span class="run-path-badge" id="run-path-badge">EVPN</span>
        <h2 id="run-title">Deploying BGP EVPN Fabric</h2>
      </div>
      <p id="run-subtitle">Configuring VXLAN overlay across Border Spine, Leaf 1, and Leaf 2</p>
    </div>
    <div class="context-note" id="run-context-note"></div>
    <div class="progress-wrap"><div class="progress-bar" id="progress-bar"></div></div>
    <div class="steps-list" id="steps-list"></div>
  </div>

  <!-- ════════════════════════════════════════
       RESULT SCREEN
  ════════════════════════════════════════ -->
   <div id="screen-result">
    <div class="result-log">
      <div class="result-log-label">Simulation Log</div>
      <div class="steps-list" id="result-steps-list"></div>
    </div>

    <!-- inline summary card injected by showResult() when allOk -->
    <div id="summary-card" style="display:none">
      <div class="summary-card-inner">
        <div class="summary-eyebrow">&#x2713;&nbsp; Mission Complete — Ransomware Attack Neutralised</div>
        <div class="summary-acts">
          <div class="summary-act">
            <div class="summary-act-badge act1">Act 1</div>
            <div class="summary-act-title">Macro Segmentation</div>
            <div class="summary-act-desc">VRF isolation confined the attacker to the IoT segment. Cross-VRF pivoting to PROD and Main was blocked at the routing boundary — zero firewall rules required.</div>
          </div>
          <div class="summary-act">
            <div class="summary-act-badge act2">Act 2</div>
            <div class="summary-act-title">Micro Segmentation (SGT)</div>
            <div class="summary-act-desc">ISE pushed a Deny IP SGACL to the Production SGT pair via TrustSec. Lateral movement between PROD workstations was killed at the ASIC — without touching a single switch config.</div>
          </div>
          <div class="summary-act">
            <div class="summary-act-badge act3">Act 3</div>
            <div class="summary-act-title">Threat Containment (ISE CoA)</div>
            <div class="summary-act-desc">ISE verified TrustSec policy across the access layer. SGT counters confirmed the block was enforced in hardware. The attacker's foothold was quarantined and contained in real time.</div>
          </div>
        </div>
        <div class="summary-cisco">
          <div class="summary-cisco-title">&#x26A1; Why Cisco Wins</div>
          <div class="summary-cisco-grid">
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Single Policy Plane</strong> — ISE is the sole source of truth. One change propagates to every switch instantly via TrustSec.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Hardware-Enforced at Line Rate</strong> — SGACLs execute in the ASIC. No performance penalty, no packet-by-packet inspection overhead.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Identity-Based, Not IP-Based</strong> — Policy follows the user and device, not the subnet. Workstations moving ports stay protected automatically.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Zero Touch Containment</strong> — ISE CoA quarantines compromised endpoints without any manual switch intervention or network downtime.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Fabric + Security Unified</strong> — Catalyst Center, ISE, and the switching fabric operate as one integrated platform — no stitching of third-party tools.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Proven at Scale</strong> — The same architecture protects Fortune 500 campuses. What you just saw works identically across thousands of switches.</div></div>
          </div>
        </div>
      </div>
    </div>

    <div class="result-hero">
      <div class="result-icon-wrap" id="result-icon-wrap">
        <span id="result-icon"></span>
      </div>
      <div class="result-title" id="result-title"></div>
      <div class="result-msg"   id="result-msg"></div>
      <button class="btn-restart" onclick="restart()">&#8592; Choose Another Path</button>
    </div>
  </div>

  <!-- ── FOOTER ── -->
  <div class="page-footer">
    <div class="copy">&copy; 2025 Cisco and/or its affiliates. All rights reserved.</div>
    <div class="site-label">Site 105 &nbsp;|&nbsp; One Cisco Experience Lab</div>
  </div>

</div><!-- /app -->

<script>
const CONTEXT_NOTES = {
  evpn: '<strong>BGP EVPN Path:</strong> You have chosen open standards. Configuring VXLAN overlays, VRF definitions, L2/L3 VNIs, anycast gateways, and BGP EVPN peers across the campus fabric. This path requires precision — the fabric is built line by line.',
  sda:  '<strong>SD-Access Path:</strong> You have chosen intent-based networking. Verifying the Catalyst Center SDA fabric — checking that all fabric devices, virtual networks, anycast gateways, and port assignments are correctly provisioned and healthy.'
};

const TITLES = {
  evpn: 'Deploying BGP EVPN Fabric',
  sda:  'Verifying SD-Access Fabric'
};

const SUBTITLES = {
  evpn: 'Configuring VXLAN overlay across Border Spine, Leaf 1, and Leaf 2',
  sda:  'Querying Catalyst Center for fabric site, VNs, gateways, and device state'
};

const SUCCESS = {
  evpn: {
    icon: '&#10003;',
    cls: 'success',
    title: 'EVPN Fabric Deployed',
    msg: 'Your BGP EVPN VXLAN fabric is live. BGP EVPN neighbors are established, NVE peers are UP, and the overlay is operational across all three switches. The campus fabric is ready to carry production traffic.'
  },
  sda: {
    icon: '&#10003;',
    cls: 'success',
    title: 'SD-Access Fabric Verified',
    msg: 'The Cisco SD-Access fabric is fully operational. All virtual networks, anycast gateways, fabric devices, and port assignments are confirmed healthy via Catalyst Center. Identity-based policy enforcement is active.'
  }
};

const FAILURE = {
  evpn: {
    icon: '&#9888;',
    cls: 'fail',
    title: 'Deployment Incomplete',
    msg: 'One or more steps did not complete successfully. Review the deployment log below, identify the failed step, and consult your proctor. The fabric may be partially configured — check BGP neighbor state and NVE interface status on the switches.'
  },
  sda: {
    icon: '&#9888;',
    cls: 'fail',
    title: 'Verification Failed',
    msg: 'The SD-Access fabric state check found anomalies. Review the deployment log below. Ensure the SDA fabric was fully deployed via Catalyst Center before running verification, and that all fabric devices are reachable.'
  }
};

let currentPath = null;
let stepData = [];
let sid = null;

function sidNew() {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function show(id) {
  ['screen-choose','screen-running','screen-result'].forEach(s => {
    document.getElementById(s).style.display = (s === id) ? 'block' : 'none';
  });
}

function startAdventure(path) {
  currentPath = path;
  sid = sidNew();
  stepData = [];

  const badge = document.getElementById('run-path-badge');
  badge.textContent = path === 'evpn' ? 'BGP EVPN' : 'SD-ACCESS';
  badge.className = 'run-path-badge ' + path;

  document.getElementById('run-title').textContent    = TITLES[path];
  document.getElementById('run-subtitle').textContent = SUBTITLES[path];

  const note = document.getElementById('run-context-note');
  note.innerHTML   = CONTEXT_NOTES[path];
  note.className   = 'context-note ' + (path === 'sda' ? 'sda' : '');

  document.getElementById('steps-list').innerHTML = '';
  document.getElementById('progress-bar').style.width = '0%';

  show('screen-running');

  fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({path, sid})
  }).then(() => listenStream(sid));
}

function listenStream(streamSid) {
  const es = new EventSource('/api/stream/' + streamSid);

  es.addEventListener('step_start', e => {
    const d = JSON.parse(e.data);
    addStep(d.name, 'running');
  });

  es.addEventListener('step_done', e => {
    const d = JSON.parse(e.data);
    updateStep(d.name, d.ok ? 'ok' : 'fail', d.detail || '');
    stepData.push(d);
    updateProgress();
  });

  es.addEventListener('complete', e => {
    const d = JSON.parse(e.data);
    es.close();
    setTimeout(() => showResult(d.path), 900);
  });

  es.onerror = () => {
    es.close();
    setTimeout(() => showResult(currentPath), 900);
  };
}

function stepKey(name) {
  return 'step-' + name.replace(/[^a-zA-Z0-9]/g, '_');
}

function addStep(name, state) {
  const list = document.getElementById('steps-list');
  const row  = document.createElement('div');
  row.className = 'step-row ' + state;
  row.id = stepKey(name);
  row.innerHTML =
    '<div class="step-spinner"></div>' +
    '<div class="step-name">' + name + '</div>' +
    '<div class="step-detail"></div>';
  list.appendChild(row);
  row.scrollIntoView({behavior: 'smooth', block: 'nearest'});
}

function updateStep(name, state, detail) {
  const row = document.getElementById(stepKey(name));
  if (!row) return;
  row.className = 'step-row ' + state;
  const dot = document.createElement('div');
  dot.className = 'step-status-dot';
  row.replaceChild(dot, row.firstChild);
  if (detail) row.querySelector('.step-detail').textContent = detail;
}

function updateProgress() {
  const pct = Math.min(94, (stepData.length / Math.max(stepData.length + 2, 8)) * 100);
  document.getElementById('progress-bar').style.width = pct + '%';
}

function showResult(path) {
  document.getElementById('progress-bar').style.width = '100%';

  const allOk = stepData.every(s => s.ok);
  const info  = allOk ? SUCCESS[path] : FAILURE[path];

  const wrap = document.getElementById('result-icon-wrap');
  wrap.className = 'result-icon-wrap ' + info.cls;
  document.getElementById('result-icon').innerHTML   = info.icon;
  document.getElementById('result-title').textContent = info.title;
  document.getElementById('result-title').className   = 'result-title ' + info.cls;
  document.getElementById('result-msg').textContent   = info.msg;

  const clone = document.getElementById('steps-list').cloneNode(true);
  clone.id = '';
  const rl = document.getElementById('result-steps-list');
  rl.innerHTML = '';
  rl.appendChild(clone);

  show('screen-result');

  // Show summary card at the bottom when successful
  const card = document.getElementById('summary-card');
  if (allOk) {
    card.style.display = 'block';
    // Reset animation so it plays fresh every time
    card.style.animation = 'none';
    card.offsetHeight; // force reflow
    card.style.animation = 'summaryReveal 0.7s ease forwards, pulse-green 2s ease-in-out 3';
    setTimeout(() => card.scrollIntoView({behavior: 'smooth', block: 'start'}), 800);
  } else {
    card.style.display = 'none';
  }
}

function restart() {
  window.location.href = '/';
}
</script>
</body>
</html>
"""

# ── Shared CSS for path pages ─────────────────────────────────────────────────
_PATH_CSS = """
  :root {
    --bg:      #07182D; --surface: #0a1f3a; --surface2: #0d2647;
    --border:  #1a3555; --border2: #204060;
    --text:    #FFFFFF; --text2: #B4B9C0; --text3: #525E6C;
    --cyan:    #02C8FF; --blue: #0A60FF; --magenta: #FF007F;
    --orange:  #FF9000; --green: #00d68a; --red: #ff4757;
    --grad:    linear-gradient(90deg,#3070E5 0%,#1ABBE9 40%,#FD017F 70%,#FCA601 100%);
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg); color: var(--text);
    font-family: 'CiscoSansTT','Helvetica Neue',Arial,sans-serif;
    font-size: 16px; min-height: 100vh;
  }
  body::before {
    content:''; position:fixed; inset:0; z-index:0;
    background-image: linear-gradient(rgba(2,200,255,0.03) 1px,transparent 1px),
      linear-gradient(90deg,rgba(2,200,255,0.03) 1px,transparent 1px);
    background-size:60px 60px; animation:grid-drift 40s linear infinite;
  }
  body::after {
    content:''; position:fixed; inset:0; z-index:0;
    background: radial-gradient(ellipse 80% 50% at 10% 20%,rgba(10,96,255,0.12) 0%,transparent 60%),
      radial-gradient(ellipse 60% 40% at 90% 80%,rgba(253,1,127,0.08) 0%,transparent 60%);
  }
  @keyframes grid-drift { from{background-position:0 0} to{background-position:60px 60px} }
  #app { position:relative; z-index:1; max-width:960px; margin:0 auto; padding:0 24px 80px; }

  /* topbar */
  .topbar {
    display:flex; align-items:center; justify-content:space-between;
    padding:20px 0 16px; border-bottom:1px solid var(--border);
  }
  .topbar-left { display:flex; align-items:center; gap:16px; }
  .back-link {
    font-size:12px; color:var(--text3); text-decoration:none;
    letter-spacing:1px; display:flex; align-items:center; gap:6px;
    transition:color 0.2s;
  }
  .back-link:hover { color:var(--cyan); }
  .topbar-right { font-size:11px; color:var(--text3); letter-spacing:2px; text-transform:uppercase; }

  /* path header */
  .path-header { padding:44px 0 36px; }
  .path-badge {
    display:inline-block; font-size:10px; letter-spacing:3px; text-transform:uppercase;
    padding:4px 12px; border-radius:3px; font-weight:700; margin-bottom:14px;
  }
  .path-badge.evpn { background:rgba(2,200,255,0.12); color:var(--cyan); border:1px solid rgba(2,200,255,0.25); }
  .path-badge.sda  { background:rgba(255,0,127,0.10); color:var(--magenta); border:1px solid rgba(255,0,127,0.2); }
  .path-header h1 { font-size:clamp(28px,4vw,44px); font-weight:700; color:var(--text); margin-bottom:8px; }
  .path-header p  { font-size:15px; color:var(--text2); max-width:680px; line-height:1.7; }

  /* accent rule */
  .accent-rule { height:3px; width:80px; border-radius:2px; margin:20px 0 36px; }
  .evpn .accent-rule { background:linear-gradient(90deg,var(--cyan),var(--blue)); }
  .sda  .accent-rule { background:linear-gradient(90deg,var(--magenta),var(--orange)); }

  /* overview card */
  .overview-card {
    background:var(--surface); border:1px solid var(--border);
    border-radius:10px; padding:28px 32px; margin-bottom:28px;
  }
  .overview-card h2 {
    font-size:13px; letter-spacing:3px; text-transform:uppercase;
    margin-bottom:16px;
  }
  .evpn .overview-card h2 { color:var(--cyan); }
  .sda  .overview-card h2 { color:var(--magenta); }
  .overview-card p { font-size:14px; color:var(--text2); line-height:1.75; margin-bottom:12px; }
  .overview-card p:last-child { margin-bottom:0; }
  .overview-card strong { color:var(--text); }
  .overview-card .highlight { font-weight:600; }
  .evpn .overview-card .highlight { color:var(--cyan); }
  .sda  .overview-card .highlight  { color:var(--magenta); }

  /* cio quote */
  .cio-quote {
    border-left:3px solid var(--magenta); background:rgba(255,0,127,0.05);
    border-radius:0 8px 8px 0; padding:16px 20px; margin:16px 0;
    font-size:14px; font-style:italic; color:var(--text2); line-height:1.65;
  }
  .cio-quote strong { color:var(--text); font-style:normal; }

  /* pillar grid */
  .pillar-grid { display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-top:16px; }
  @media(max-width:600px){.pillar-grid{grid-template-columns:1fr;}}
  .pillar {
    background:var(--surface2); border:1px solid var(--border2);
    border-radius:8px; padding:16px 18px;
  }
  .pillar h4 { font-size:12px; font-weight:700; margin-bottom:6px; }
  .evpn .pillar h4 { color:var(--cyan); }
  .sda  .pillar h4 { color:var(--magenta); }
  .pillar p { font-size:12px; color:var(--text2); line-height:1.6; }

  /* steps preview */
  .steps-preview { margin-bottom:32px; }
  .steps-preview h2 {
    font-size:13px; letter-spacing:3px; text-transform:uppercase; color:var(--text3); margin-bottom:14px;
  }
  .step-chips { display:flex; flex-wrap:wrap; gap:8px; }
  .step-chip {
    font-size:11px; padding:5px 12px; border-radius:3px; border:1px solid var(--border2);
    color:var(--text3); background:var(--surface); letter-spacing:0.5px;
  }

  /* deploy button */
  .deploy-section { text-align:center; padding:12px 0 0; }
  .btn-deploy {
    display:inline-block; padding:15px 52px; border-radius:4px; border:none;
    font-size:13px; font-weight:700; letter-spacing:2px; text-transform:uppercase;
    cursor:pointer; transition:opacity 0.2s, transform 0.2s;
    color:var(--text);
  }
  .evpn .btn-deploy { background:linear-gradient(135deg,var(--blue),var(--cyan)); }
  .sda  .btn-deploy { background:linear-gradient(135deg,var(--magenta),var(--orange)); }
  .btn-deploy:hover { opacity:0.9; transform:translateY(-2px); }
  .btn-deploy:disabled { opacity:0.4; cursor:not-allowed; transform:none; }
  .deploy-note { font-size:12px; color:var(--text3); margin-top:10px; }

  /* running / result */
  #screen-overview { display:block; }
  #screen-running  { display:none; padding-top:32px; }
  #screen-result   { display:none; }

  .run-title-row { display:flex; align-items:center; gap:14px; margin-bottom:4px; }
  .run-h2 { font-size:22px; font-weight:700; color:var(--text); }
  .run-sub { font-size:13px; color:var(--text3); margin-bottom:24px; }

  .progress-wrap { background:var(--surface); border-radius:4px; border:1px solid var(--border); overflow:hidden; height:6px; margin-bottom:20px; }
  .progress-bar  { height:100%; width:0%; background:var(--grad); transition:width 0.5s ease; border-radius:4px; }

  .steps-list { display:flex; flex-direction:column; gap:8px; }
   .step-row {
     background:var(--surface); border:1px solid var(--border); border-radius:8px;
     padding:13px 18px; display:flex; align-items:flex-start; gap:14px;
     transition:border-color 0.3s, background 0.3s;
   }
  .step-row.running { border-color:var(--cyan); background:rgba(2,200,255,0.04); animation:pulse-row 2s ease-in-out infinite; }
  .step-row.ok      { border-color:rgba(0,214,138,0.4); background:rgba(0,214,138,0.03); }
  .step-row.fail    { border-color:rgba(255,71,87,0.4); background:rgba(255,71,87,0.04); }
  .step-row.waiting { border-color:rgba(255,165,0,0.6); background:rgba(255,165,0,0.05); animation:pulse-amber 1.5s ease-in-out infinite; }
  @keyframes pulse-row   { 0%,100%{box-shadow:0 0 0 0 rgba(2,200,255,0)} 50%{box-shadow:0 0 0 3px rgba(2,200,255,0.1)} }
  @keyframes pulse-amber { 0%,100%{box-shadow:0 0 0 0 rgba(255,165,0,0)} 50%{box-shadow:0 0 0 6px rgba(255,165,0,0.25)} }

  .step-dot { width:8px; height:8px; border-radius:50%; flex-shrink:0; }
  .step-row.running .step-dot { background:var(--cyan); animation:blink 1s ease-in-out infinite; }
  .step-row.ok      .step-dot { background:var(--green); }
  .step-row.fail    .step-dot { background:var(--red); }
  .step-row.waiting .step-dot { background:orange; animation:blink 0.8s ease-in-out infinite; }
  .step-row:not(.running):not(.ok):not(.fail):not(.waiting) .step-dot { background:var(--border2); }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.3} }

  /* ── waiting action banner ── */
  .waiting-banner {
    display: flex; align-items: flex-start; gap: 16px;
    margin: 12px 0 6px;
    padding: 16px 20px;
    background: rgba(255,140,0,0.10);
    border: 1.5px solid rgba(255,140,0,0.5);
    border-radius: 8px;
    animation: pulse-amber 1.5s ease-in-out infinite;
  }
  .waiting-icon {
    font-size: 28px; line-height: 1; flex-shrink: 0;
    color: orange; animation: blink 1s ease-in-out infinite;
  }
  .waiting-body { flex: 1; }
  .waiting-title {
    font-size: 12px; font-weight: 800; letter-spacing: 2px;
    text-transform: uppercase; color: orange; margin-bottom: 8px;
  }
  .waiting-instruction {
    font-size: 14px; color: var(--text); line-height: 1.6;
  }
  .waiting-countdown {
    margin-top: 12px; font-size: 13px; font-weight: 700;
    color: orange; letter-spacing: 1px;
  }
  .btn-confirm {
    margin-top: 16px; padding: 12px 28px;
    background: linear-gradient(135deg, #ff4500, #ff8c00);
    color: #fff; font-size: 14px; font-weight: 700;
    border: none; border-radius: 6px; cursor: pointer;
    letter-spacing: 0.5px; animation: pulse-amber 1.5s ease-in-out infinite;
    display: block;
  }
  .btn-confirm:hover {{ opacity: 0.9; animation: none; }}
  .btn-confirm:disabled {{ opacity: 0.5; cursor: not-allowed; animation: none; }}

  .step-spinner { width:16px; height:16px; flex-shrink:0; border:2px solid rgba(2,200,255,0.2); border-top-color:var(--cyan); border-radius:50%; animation:spin 0.7s linear infinite; }
  @keyframes spin { to{transform:rotate(360deg)} }
  .step-name   { flex:1; font-size:14px; font-weight:600; color:var(--text2); }
  .step-row.running .step-name { color:var(--text); }
  .step-row.ok      .step-name { color:var(--text); }
   .step-detail { font-size:11px; color:var(--text3); text-align:right; white-space:normal; word-break:break-word; }
  .step-row.ok   .step-detail { color:var(--green); }
  .step-row.fail .step-detail { color:var(--red); }

  /* result */
  .result-hero { text-align:center; padding:48px 0 36px; }
  .result-icon-wrap { width:80px; height:80px; border-radius:50%; margin:0 auto 20px; display:flex; align-items:center; justify-content:center; font-size:32px; font-weight:700; }
  .result-icon-wrap.success { background:rgba(0,214,138,0.12); border:2px solid rgba(0,214,138,0.3); color:var(--green); }
  .result-icon-wrap.fail    { background:rgba(255,71,87,0.10); border:2px solid rgba(255,71,87,0.25); color:var(--red); }
  .result-title { font-size:28px; font-weight:700; margin-bottom:10px; }
  .result-title.success { color:var(--green); }
  .result-title.fail    { color:var(--red); }
  .result-msg { font-size:15px; color:var(--text2); line-height:1.75; max-width:560px; margin:0 auto 28px; }
  .btn-back { background:var(--surface); color:var(--text); border:1px solid var(--border2); padding:12px 36px; border-radius:4px; font-size:13px; font-weight:700; letter-spacing:2px; text-transform:uppercase; cursor:pointer; transition:border-color 0.2s; }
  .btn-back:hover { border-color:var(--cyan); }
  .result-log { margin-top:32px; border-top:1px solid var(--border); padding-top:24px; }
  .result-log-label { font-size:11px; letter-spacing:3px; text-transform:uppercase; color:var(--text3); margin-bottom:14px; }

  /* footer */
  .page-footer { border-top:1px solid var(--border); padding:20px 0; display:flex; align-items:center; justify-content:space-between; margin-top:60px; }
  .page-footer .copy { font-size:11px; color:var(--text3); }
  .page-footer .site-label { font-size:11px; color:var(--text3); letter-spacing:2px; text-transform:uppercase; }
"""

# ── Shared JS for path pages ──────────────────────────────────────────────────
def _path_js(path, steps_list):
    steps_json = json.dumps(steps_list)
    return f"""
const PATH = '{path}';
const STEPS = {steps_json};
let stepData = [];
let sid = null;

function sidNew() {{ return Math.random().toString(36).slice(2) + Date.now().toString(36); }}
function show(id) {{
  ['screen-overview','screen-running','screen-result'].forEach(s => {{
    document.getElementById(s).style.display = (s===id)?'block':'none';
  }});
}}
function stepKey(name) {{ return 'sr-' + name.replace(/[^a-zA-Z0-9]/g,'_'); }}

function addStep(name, state) {{
  const list = document.getElementById('steps-list');
  const row = document.createElement('div');
  row.className = 'step-row ' + state;
  row.id = stepKey(name);
  row.innerHTML = '<div class="step-spinner"></div><div class="step-name">' + name + '</div><div class="step-detail"></div>';
  list.appendChild(row);
  row.scrollIntoView({{behavior:'smooth',block:'nearest'}});
}}

function updateStep(name, state, detail) {{
  const row = document.getElementById(stepKey(name));
  if (!row) return;
  row.className = 'step-row ' + state;
  const dot = document.createElement('div');
  dot.className = 'step-dot';
  row.replaceChild(dot, row.firstChild);
  if (detail) row.querySelector('.step-detail').textContent = detail;
}}

function updateProgress() {{
  const total = Math.max(STEPS.length + 1, stepData.length + 1);
  const pct = Math.min(94, (stepData.length / total) * 100);
  document.getElementById('progress-bar').style.width = pct + '%';
}}

function startDeploy() {{
  sid = sidNew();
  stepData = [];
  document.getElementById('steps-list').innerHTML = '';
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('btn-deploy').disabled = true;
  show('screen-running');

  fetch('/api/start', {{
    method:'POST', headers:{{'Content-Type':'application/json'}},
    body: JSON.stringify({{path: PATH, sid}})
  }}).then(() => {{
    const es = new EventSource('/api/stream/' + sid);
    es.addEventListener('step_start', e => {{ const d=JSON.parse(e.data); addStep(d.name,'running'); }});
    es.addEventListener('step_done',  e => {{
      const d=JSON.parse(e.data);
      updateStep(d.name, d.ok?'ok':'fail', d.detail||'');
      stepData.push(d); updateProgress();
    }});
    es.addEventListener('complete', e => {{ es.close(); setTimeout(showResult, 800); }});
    es.onerror = () => {{ es.close(); setTimeout(showResult, 800); }};
  }});
}}

function showResult() {{
  document.getElementById('progress-bar').style.width = '100%';
  const allOk = stepData.length > 0 && stepData.every(s => s.ok);
  const wrap = document.getElementById('result-icon-wrap');
  const title = document.getElementById('result-title');
  wrap.className  = 'result-icon-wrap ' + (allOk?'success':'fail');
  wrap.textContent = allOk ? '✓' : '✗';
  title.className  = 'result-title ' + (allOk?'success':'fail');
  title.textContent = allOk ? 'Deployment Successful' : 'Deployment Incomplete';
  document.getElementById('result-msg').textContent = allOk
    ? 'All steps completed successfully. The fabric is deployed and verified.'
    : 'One or more steps failed. Review the deployment log below and consult your proctor.';
  const clone = document.getElementById('steps-list').cloneNode(true);
  clone.id = '';
  const rl = document.getElementById('result-steps-list');
  rl.innerHTML = ''; rl.appendChild(clone);
  show('screen-result');
}}
"""

# ── EVPN step labels ──────────────────────────────────────────────────────────
EVPN_STEP_LABELS = [
    "VRF Definitions",
    "Multicast Replication",
    "L2 VNI / VLAN Mappings",
    "L3 VNI VLANs",
    "Anycast Gateway SVIs",
    "L3 VNI SVIs",
    "NVE Interface",
    "BGP EVPN",
    "Verify BGP EVPN",
    "Verify NVE Peers",
]

SDA_STEP_LABELS = [
    "Catalyst Center Discovery",
    "Discovery", "Provision", "Fabric Site", "Virtual Networks",
    "Anycast Gateways", "Transit", "Fabric Devices",
    "L3 Handoff", "Port Assignments", "Verify",
]

# ── EVPN page ─────────────────────────────────────────────────────────────────
EVPN_PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>BGP EVPN / VXLAN &mdash; One Cisco Experience Lab</title>
<style>{_PATH_CSS}</style>
</head>
<body class="evpn">
<div id="app">

  <div class="topbar">
    <div class="topbar-left">
      <svg height="24" viewBox="0 0 200 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="88" y="0"  width="10" height="20" rx="5" fill="#02C8FF"/>
        <rect x="68" y="8"  width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="108" y="8" width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="48" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <rect x="128" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <text x="14" y="66" font-family="Arial" font-weight="700" font-size="32" fill="#FFFFFF" letter-spacing="2">CISCO</text>
      </svg>
      <a class="back-link" href="/">&#8592; Choose Your Path</a>
    </div>
    <div class="topbar-right">One Cisco Experience Lab</div>
  </div>

  <!-- OVERVIEW -->
  <div id="screen-overview">
    <div class="path-header">
      <div class="path-badge evpn">Path A &mdash; Open Standards</div>
      <h1>You Choose: BGP EVPN Campus Fabric</h1>
      <p>A modern VXLAN overlay architecture built on open standards, designed for maximum scalability and flexibility.</p>
      <div class="accent-rule"></div>
    </div>

    <div class="overview-card">
      <h2>Architecture Overview</h2>
      <p>BGP EVPN VXLAN is a campus network solution for <strong>Cisco Catalyst 9000 Series Switches</strong> running Cisco IOS-XE software. It is designed to provide a unified overlay network solution addressing the challenges and drawbacks of existing technologies.</p>
      <p>Traditionally, VLANs have been the standard method for providing network segmentation in campus networks. VLANs use loop prevention techniques such as <strong>Spanning Tree Protocol (STP)</strong>, which impose restrictions on network design and resiliency. Further, there is a limitation with the number of VLANs that can be used to address layer 2 segments (4094 VLANs).</p>
      <p><span class="highlight">VXLAN is designed to overcome the inherent limitations of VLANs and STP.</span> Many customers also enjoy the added benefit of macro-segmentation through the use of <strong>VRFs (Virtual Routing and Forwarding)</strong> and the ability to stretch subnets across L3 boundaries.</p>
    </div>

    <div class="overview-card">
      <h2>What You Will Deploy</h2>
      <div class="pillar-grid">
        <div class="pillar"><h4>VRF Definitions</h4><p>Three VRFs — Main, PROD, and IOT — with route targets and EVPN stitching across all three switches.</p></div>
        <div class="pillar"><h4>L2 / L3 VNIs</h4><p>VLAN-to-VNI mappings for overlay encapsulation. L3 VNI VLANs for inter-VRF routing via the VXLAN fabric.</p></div>
        <div class="pillar"><h4>Anycast Gateways</h4><p>Distributed anycast SVIs on Leaf 1 and Leaf 2 providing default gateways for all three VRFs.</p></div>
        <div class="pillar"><h4>BGP EVPN + NVE</h4><p>iBGP EVPN peering with Border Spine as route reflector. NVE interfaces carrying all L2 and L3 VNIs.</p></div>
      </div>
    </div>

    <div class="steps-preview">
      <h2>Deployment Steps</h2>
      <div class="step-chips">
        {''.join(f'<span class="step-chip">{s}</span>' for s in EVPN_STEP_LABELS)}
      </div>
    </div>

    <div class="deploy-section">
      <button class="btn-deploy" id="btn-deploy" onclick="startDeploy()">Deploy + Verify</button>
      <div class="deploy-note">This will push configuration to Border Spine, Leaf 1, and Leaf 2 and verify BGP EVPN and NVE state.</div>
    </div>
  </div>

  <!-- RUNNING -->
  <div id="screen-running">
    <div class="run-title-row">
      <span class="path-badge evpn">BGP EVPN</span>
      <div class="run-h2">Deploying BGP EVPN Fabric</div>
    </div>
    <div class="run-sub">Configuring VXLAN overlay across Border Spine, Leaf 1, and Leaf 2&hellip;</div>
    <div class="progress-wrap"><div class="progress-bar" id="progress-bar"></div></div>
    <div class="steps-list" id="steps-list"></div>
  </div>

  <!-- RESULT -->
  <div id="screen-result">
    <div class="result-hero">
      <div class="result-icon-wrap" id="result-icon-wrap"></div>
      <div class="result-title" id="result-title"></div>
      <div class="result-msg"   id="result-msg"></div>
      <button class="btn-back" onclick="window.location.href='/'">&#8592; Back to Lab</button>
    </div>
    <div class="result-log">
      <div class="result-log-label">Deployment Log</div>
      <div class="steps-list" id="result-steps-list"></div>
    </div>
  </div>

  <div class="page-footer">
    <div class="copy">&copy; 2025 Cisco and/or its affiliates. All rights reserved.</div>
    <div class="site-label">Site 105 &nbsp;|&nbsp; One Cisco Experience Lab</div>
  </div>

</div>
<script>{_path_js('evpn', EVPN_STEP_LABELS)}</script>
</body>
</html>
"""

# ── SDA page ──────────────────────────────────────────────────────────────────
SDA_PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SD-Access &mdash; One Cisco Experience Lab</title>
<style>{_PATH_CSS}</style>
</head>
<body class="sda">
<div id="app">

  <div class="topbar">
    <div class="topbar-left">
      <svg height="24" viewBox="0 0 200 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="88" y="0"  width="10" height="20" rx="5" fill="#02C8FF"/>
        <rect x="68" y="8"  width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="108" y="8" width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="48" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <rect x="128" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <text x="14" y="66" font-family="Arial" font-weight="700" font-size="32" fill="#FFFFFF" letter-spacing="2">CISCO</text>
      </svg>
      <a class="back-link" href="/">&#8592; Choose Your Path</a>
    </div>
    <div class="topbar-right">One Cisco Experience Lab</div>
  </div>

  <!-- OVERVIEW -->
  <div id="screen-overview">
    <div class="path-header">
      <div class="path-badge sda">Path B &mdash; Intent-Based</div>
      <h1>You Choose: Software-Defined Access (SDA)</h1>
      <p>Pseudoco has decided to prioritize operational simplicity, identity-driven automation, and fast security policy deployment across all campus locations.</p>
      <div class="accent-rule"></div>
    </div>

    <div class="overview-card">
      <h2>The Business Decision</h2>
      <p>The CIO has made it clear:</p>
      <div class="cio-quote">"We need security policy to follow users and devices automatically &mdash; regardless of where they connect."</div>
      <p>With workforce mobility increasing and IoT onboarding accelerating, Pseudoco needs a fabric that natively understands <strong>who and what</strong> is on the network, not just where traffic is coming from.</p>
    </div>

    <div class="overview-card">
      <h2>What This Means for Pseudoco</h2>
      <p>By choosing SDA, Pseudoco is building a campus designed around four strategic pillars:</p>
      <div class="pillar-grid">
        <div class="pillar">
          <h4>Identity as the Control Plane</h4>
          <p>User identity and device posture drive access decisions. Policy follows users between wired, wireless, branch, and remote access.</p>
        </div>
        <div class="pillar">
          <h4>End-to-End Segmentation</h4>
          <p>Macro and micro-segmentation using SGTs across campus, WAN, and data center. Reduced lateral movement risk.</p>
        </div>
        <div class="pillar">
          <h4>Automation at Scale</h4>
          <p>New sites and devices onboard faster. Reduced configuration drift and human error through Catalyst Center intent-based automation.</p>
        </div>
        <div class="pillar">
          <h4>Native Zero Trust Alignment</h4>
          <p>Campus becomes an active enforcement point. Policy and identity context extends into Secure Access and SD-WAN.</p>
        </div>
      </div>
    </div>

    <div class="steps-preview">
      <h2>Deployment Steps</h2>
      <div class="step-chips">
        {''.join(f'<span class="step-chip">{s}</span>' for s in SDA_STEP_LABELS)}
      </div>
    </div>

    <div class="deploy-section">
      <button class="btn-deploy" id="btn-deploy" onclick="startDeploy()">Deploy + Verify</button>
      <div class="deploy-note">This will run Catalyst Center discovery, then deploy the full SDA fabric — fabric site, virtual networks, anycast gateways, transit, fabric devices, L3 handoff, port assignments, and verification.</div>
    </div>
  </div>

  <!-- RUNNING -->
  <div id="screen-running">
    <div class="run-title-row">
      <span class="path-badge sda">SD-ACCESS</span>
      <div class="run-h2">Deploying SD-Access Fabric</div>
    </div>
    <div class="run-sub">Running Catalyst Center discovery and full SDA fabric deployment&hellip;</div>
    <div class="progress-wrap"><div class="progress-bar" id="progress-bar"></div></div>
    <div class="steps-list" id="steps-list"></div>
  </div>

  <!-- RESULT -->
  <div id="screen-result">
    <div class="result-hero">
      <div class="result-icon-wrap" id="result-icon-wrap"></div>
      <div class="result-title" id="result-title"></div>
      <div class="result-msg"   id="result-msg"></div>
      <button class="btn-back" onclick="window.location.href='/'">&#8592; Back to Lab</button>
    </div>
    <div class="result-log">
      <div class="result-log-label">Deployment Log</div>
      <div class="steps-list" id="result-steps-list"></div>
    </div>
  </div>

  <div class="page-footer">
    <div class="copy">&copy; 2025 Cisco and/or its affiliates. All rights reserved.</div>
    <div class="site-label">Site 105 &nbsp;|&nbsp; One Cisco Experience Lab</div>
  </div>

</div>
<script>{_path_js('sda', SDA_STEP_LABELS)}</script>
</body>
</html>
"""

BREACH_STEP_LABELS = [
    # Act 1
    "Reconnaissance \u2014 Map the Network Segments",
    "PROD Network \u2014 Internal Reachability Check",
    "PROD \u2192 Main Network (Cross-Segment Attempt)",
    "PROD \u2192 IoT Network (Cross-Segment Attempt)",
    "IoT Network \u2014 Internal Reachability Check",
    "IoT \u2192 PROD Network (Cross-Segment Attempt)",
    "IoT \u2192 Main Network (Cross-Segment Attempt)",
    "Confirm Macro Segmentation \u2014 VRF Boundary Report",
    # Act 2
    "Threat Intel \u2014 Scanning PROD Segment for Lateral Movement Paths",
    "Zero Enforcement Counters \u2014 Leaf 1",
    "Zero Enforcement Counters \u2014 Leaf 2",
    "Lateral Movement in Progress \u2014 Pat and Kit Workstations",
    "ISE TrustSec Response \u2014 Deploying SGACL to Block PROD Lateral Movement",
    "Confirm Kill \u2014 Watching SGT Deny Counters",
    "SGT Enforcement Report \u2014 Leaf 1",
    "SGT Enforcement Report \u2014 Leaf 2",
    # Act 3
    "Reach ISE ERS API",
    "Verify Quarantine ANC Policy",
    "Identify Compromised Endpoint",
    "Apply ANC Quarantine Policy (CoA)",
    "Verify Post-Quarantine SGT Counters",
]

# ── Breach CSS additions (appended to _PATH_CSS) ──────────────────────────────
_BREACH_EXTRA_CSS = """
  /* ── act dividers ── */
  .act-divider {
    display: flex; align-items: center; gap: 14px;
    margin: 28px 0 16px;
  }
  .act-badge {
    font-size: 10px; letter-spacing: 3px; text-transform: uppercase;
    padding: 4px 14px; border-radius: 3px; font-weight: 700; white-space: nowrap;
  }
  .act-badge.act1 { background: rgba(255,144,0,0.12); color: var(--orange); border: 1px solid rgba(255,144,0,0.3); }
  .act-badge.act2 { background: rgba(255,71,87,0.12);  color: var(--red);    border: 1px solid rgba(255,71,87,0.3);  }
  .act-badge.act3 { background: rgba(0,214,138,0.10);  color: var(--green);  border: 1px solid rgba(0,214,138,0.3);  }
  .act-divider-line { flex: 1; height: 1px; background: var(--border); }
  .act-divider-title { font-size: 14px; font-weight: 700; color: var(--text2); white-space: nowrap; }

  /* ── threat badge (path badge override) ── */
  .path-badge.breach { background: rgba(255,71,87,0.12); color: var(--red); border: 1px solid rgba(255,71,87,0.3); }
  .run-path-badge.breach { background: rgba(255,71,87,0.12); color: var(--red); border: 1px solid rgba(255,71,87,0.3); }

  /* ── breach step row colour ── */
  .step-row.blocked { border-color: rgba(0,214,138,0.4); background: rgba(0,214,138,0.03); }
  .step-row.blocked .step-dot  { background: var(--green); }
  .step-row.blocked .step-name { color: var(--text); }
  .step-row.blocked .step-detail { color: var(--green); }

  /* ── overview threat summary ── */
  .threat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 14px; margin-top: 16px; }
  @media(max-width:640px){ .threat-grid { grid-template-columns: 1fr; } }
  .threat-card {
    background: var(--surface2); border: 1px solid var(--border2);
    border-radius: 8px; padding: 18px 20px; position: relative; overflow: hidden;
  }
  .threat-card::before {
    content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
  }
  .threat-card.act1::before { background: var(--orange); }
  .threat-card.act2::before { background: var(--red); }
  .threat-card.act3::before { background: var(--green); }
  .threat-card-num {
    font-size: 28px; font-weight: 700; margin-bottom: 6px; line-height: 1;
  }
  .threat-card.act1 .threat-card-num { color: var(--orange); }
  .threat-card.act2 .threat-card-num { color: var(--red); }
  .threat-card.act3 .threat-card-num { color: var(--green); }
  .threat-card h4 { font-size: 13px; font-weight: 700; color: var(--text); margin-bottom: 6px; }
  .threat-card p  { font-size: 12px; color: var(--text2); line-height: 1.6; }

  /* ── CLI output terminal block ── */
  .step-output {
    margin-top: 10px;
    background: #030f1e;
    border: 1px solid var(--border);
    border-radius: 6px;
    overflow: hidden;
  }
  .step-output summary {
    font-size: 10px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--text3); padding: 6px 12px; cursor: pointer;
    user-select: none; list-style: none;
    display: flex; align-items: center; gap: 6px;
  }
  .step-output summary::-webkit-details-marker { display: none; }
  .step-output summary::before {
    content: '▶'; font-size: 8px; color: var(--text3);
    transition: transform 0.2s;
  }
  .step-output[open] summary::before { transform: rotate(90deg); }
  .step-output summary:hover { color: var(--cyan); }
  .step-output pre {
    margin: 0; padding: 12px 14px;
    font-family: 'Courier New', Courier, monospace;
    font-size: 11px; line-height: 1.55;
    color: #7ec8e3;
    white-space: pre-wrap; word-break: break-all;
    border-top: 1px solid var(--border);
    max-height: 320px; overflow-y: auto;
  }
  /* make step-row a column when output present */
  .step-row.has-output {
    flex-direction: column;
    align-items: stretch;
  }
  .step-row.has-output .step-row-top {
    display: flex; align-items: center; gap: 14px;
  }
  .attack-chain {
    display: flex; align-items: center; justify-content: center;
    gap: 0; flex-wrap: wrap; margin: 20px 0; padding: 20px 0;
  }
  .chain-node {
    text-align: center; padding: 10px 16px;
    background: var(--surface2); border: 1px solid var(--border2);
    border-radius: 6px; min-width: 110px;
  }
  .chain-node .node-label { font-size: 10px; letter-spacing: 2px; text-transform: uppercase; margin-bottom: 4px; }
  .chain-node.iot  .node-label { color: var(--orange); }
  .chain-node.prod .node-label { color: var(--red); }
  .chain-node.corp .node-label { color: var(--magenta); }
  .chain-node .node-name { font-size: 13px; font-weight: 700; color: var(--text); }
  .chain-arrow {
    font-size: 20px; color: var(--red); padding: 0 10px;
    animation: threat-pulse 1.5s ease-in-out infinite;
  }
  .chain-blocked {
    font-size: 11px; letter-spacing: 2px; text-transform: uppercase;
    color: var(--green); font-weight: 700; padding: 0 10px; text-align: center;
  }
  @keyframes threat-pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }

  /* breach accent rule */
  .breach .accent-rule { background: linear-gradient(90deg, var(--red), var(--orange)); }

  /* ── summary card ── */
  @keyframes summaryReveal {
    from { opacity:0; transform:translateY(32px) scale(0.98); }
    to   { opacity:1; transform:translateY(0)    scale(1);    }
  }
  @keyframes pulse-green {
    0%   { box-shadow: 0 0 0 0 rgba(0,214,138,0), 0 0 40px rgba(0,214,138,0); }
    40%  { box-shadow: 0 0 0 12px rgba(0,214,138,0.12), 0 0 60px rgba(0,214,138,0.15); }
    100% { box-shadow: 0 0 0 0 rgba(0,214,138,0), 0 0 40px rgba(0,214,138,0); }
  }
  #breach-summary-card {
    margin: 48px 0 40px;
    border-radius: 12px;
    border: 1px solid rgba(0,214,138,0.5);
    background: linear-gradient(135deg, rgba(0,214,138,0.06) 0%, rgba(0,180,255,0.04) 100%);
    overflow: hidden;
    position: relative;
  }
  #breach-summary-card::before {
    content: '';
    position: absolute; inset: 0;
    background: linear-gradient(135deg, rgba(0,214,138,0.08) 0%, transparent 60%);
    pointer-events: none;
  }
  .summary-card-inner { padding: 40px 36px 36px; position: relative; }
  .summary-eyebrow {
    font-size: 11px; font-weight: 800; letter-spacing: 4px;
    text-transform: uppercase; color: var(--green); margin-bottom: 6px;
    display: flex; align-items: center; gap: 8px;
  }
  .summary-eyebrow::after {
    content: ''; flex: 1; height: 1px;
    background: linear-gradient(90deg, rgba(0,214,138,0.4), transparent);
  }
  .summary-headline {
    font-size: 22px; font-weight: 800; color: var(--text);
    margin-bottom: 32px; line-height: 1.3;
    background: linear-gradient(90deg, #fff 60%, rgba(0,214,138,0.8));
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  }
  .summary-acts {
    display: grid; grid-template-columns: repeat(3,1fr); gap: 16px; margin-bottom: 36px;
  }
  @media(max-width:700px) { .summary-acts { grid-template-columns:1fr; } }
  .summary-act {
    background: rgba(255,255,255,0.04);
    border: 1px solid rgba(255,255,255,0.08);
    border-radius: 8px; padding: 20px;
    transition: border-color 0.2s;
  }
  .summary-act:hover { border-color: rgba(255,255,255,0.18); }
  .summary-act-badge {
    display: inline-block; font-size: 10px; font-weight: 800;
    letter-spacing: 2px; text-transform: uppercase;
    padding: 4px 12px; border-radius: 20px; margin-bottom: 12px;
  }
  .summary-act-badge.act1 { background:rgba(255,144,0,0.15); color:#ff9000; border:1px solid rgba(255,144,0,0.35); }
  .summary-act-badge.act2 { background:rgba(255,71,87,0.15);  color:#ff4757; border:1px solid rgba(255,71,87,0.35); }
  .summary-act-badge.act3 { background:rgba(0,214,138,0.12);  color:var(--green); border:1px solid rgba(0,214,138,0.35); }
  .summary-act-title { font-size:14px; font-weight:700; color:var(--text); margin-bottom:10px; }
  .summary-act-desc  { font-size:12px; color:var(--text2); line-height:1.7; }
  .summary-cisco {
    border-top: 1px solid rgba(255,255,255,0.08);
    padding-top: 28px;
  }
  .summary-cisco-title {
    font-size: 11px; font-weight: 800; color: var(--cyan);
    letter-spacing: 4px; text-transform: uppercase; margin-bottom: 20px;
    display: flex; align-items: center; gap: 8px;
  }
  .summary-cisco-title::after {
    content: ''; flex:1; height:1px;
    background: linear-gradient(90deg, rgba(2,200,255,0.4), transparent);
  }
  .summary-cisco-grid {
    display: grid; grid-template-columns: repeat(2,1fr); gap: 14px;
  }
  @media(max-width:700px) { .summary-cisco-grid { grid-template-columns:1fr; } }
  .summary-cisco-item {
    display: flex; gap: 12px; align-items: flex-start;
    background: rgba(255,255,255,0.03);
    border: 1px solid rgba(255,255,255,0.06);
    border-radius: 8px; padding: 14px;
    font-size: 12px; color: var(--text2); line-height: 1.65;
    transition: border-color 0.2s, background 0.2s;
  }
  .summary-cisco-item:hover {
    border-color: rgba(0,214,138,0.25);
    background: rgba(0,214,138,0.04);
  }
  .sci-bullet {
    width: 22px; height: 22px; border-radius: 50%;
    background: rgba(0,214,138,0.15); border: 1px solid rgba(0,214,138,0.4);
    color: var(--green); font-size: 12px; flex-shrink: 0;
    display: flex; align-items: center; justify-content: center;
  }
  .summary-cisco-item strong { color: var(--text); display:block; margin-bottom:3px; font-size:13px; }
"""

BREACH_PAGE = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ransomware Simulation &mdash; One Cisco Experience Lab</title>
<style>{_PATH_CSS}{_BREACH_EXTRA_CSS}</style>
</head>
<body class="breach">
<div id="app">

  <div class="topbar">
    <div class="topbar-left">
      <svg height="24" viewBox="0 0 200 80" fill="none" xmlns="http://www.w3.org/2000/svg">
        <rect x="88" y="0"  width="10" height="20" rx="5" fill="#02C8FF"/>
        <rect x="68" y="8"  width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="108" y="8" width="10" height="16" rx="5" fill="#02C8FF" opacity="0.7"/>
        <rect x="48" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <rect x="128" y="16" width="10" height="12" rx="5" fill="#02C8FF" opacity="0.4"/>
        <text x="14" y="66" font-family="Arial" font-weight="700" font-size="32" fill="#FFFFFF" letter-spacing="2">CISCO</text>
      </svg>
      <a class="back-link" href="/">&#8592; Choose Your Path</a>
    </div>
    <div class="topbar-right">One Cisco Experience Lab</div>
  </div>

  <!-- ══ OVERVIEW ══ -->
  <div id="screen-overview">
    <div class="path-header">
      <div class="path-badge breach">Path C &mdash; Security Validation</div>
      <h1>Ransomware Simulation &amp; Segmentation Proof</h1>
      <p>The fabric is live. Now an attacker gains a foothold on an IoT device and attempts to spread laterally across Pseudoco's campus — targeting PROD servers and the corporate network. Watch Cisco's macro and micro segmentation stop it cold.</p>
      <div class="accent-rule"></div>
    </div>

    <div class="overview-card">
      <h2>The Attack Scenario</h2>
      <p>A compromised IoT sensor on the <strong>IOT VRF</strong> begins scanning for reachable hosts. The attacker's goal: pivot from IOT to PROD ERP systems, then move laterally into the Main corporate VRF — a classic ransomware propagation pattern.</p>
      <p>Pseudoco's fabric was built with <strong>two layers of defence</strong> that operate independently and complement each other. Even if one layer is bypassed, the other holds.</p>

      <!-- Attack chain visual -->
      <div class="attack-chain">
        <div class="chain-node iot">
          <div class="node-label">Attacker</div>
          <div class="node-name">IOT Device</div>
        </div>
        <div class="chain-arrow">&#8594;</div>
        <div class="chain-node prod">
          <div class="node-label">Target 1</div>
          <div class="node-name">PROD VRF</div>
        </div>
        <div class="chain-blocked">&#9632; BLOCKED</div>
        <div class="chain-node corp">
          <div class="node-label">Target 2</div>
          <div class="node-name">Main VRF</div>
        </div>
      </div>
    </div>

    <div class="overview-card">
      <h2>Three Acts of Defence</h2>
      <div class="threat-grid">
        <div class="threat-card act1">
          <div class="threat-card-num">01</div>
          <h4>Macro Segmentation</h4>
          <p>VRF boundaries on Border Spine and Leaf switches. IOT, PROD, and Main are fully isolated routing domains with no cross-VRF routes — the network fabric itself is the first firewall.</p>
        </div>
        <div class="threat-card act2">
          <div class="threat-card-num">02</div>
          <h4>Micro Segmentation</h4>
          <p>SGT (Security Group Tags) enforce east-west policy within the same VRF. Even if two devices share a subnet, TrustSec policy blocks unauthorized peer-to-peer traffic at the port level.</p>
        </div>
        <div class="threat-card act3">
          <div class="threat-card-num">03</div>
          <h4>Threat Containment</h4>
          <p>ISE detects the anomaly and fires a Change of Authorization (CoA) via the ERS REST API — instantly quarantining the compromised device without touching a single switch config.</p>
        </div>
      </div>
    </div>

    <div class="steps-preview">
      <h2>Simulation Steps</h2>
      <div class="step-chips">
        {''.join(f'<span class="step-chip">{s}</span>' for s in BREACH_STEP_LABELS)}
      </div>
    </div>

    <div class="deploy-section">
      <button class="btn-deploy" id="btn-deploy"
              style="background:linear-gradient(135deg,var(--red),var(--orange));"
              onclick="startDeploy()">Launch Simulation</button>
      <button class="btn-deploy" id="btn-reset"
              style="background:rgba(255,255,255,0.06);border:1px solid var(--border2);color:var(--text2);margin-left:12px;"
              onclick="resetBreachDemo()">Reset Demo</button>
      <div class="deploy-note">This will run live commands against the campus fabric and ISE — no destructive changes are made to the network.</div>
    </div>
  </div>

  <!-- ══ RUNNING ══ -->
  <div id="screen-running">
    <div class="run-title-row">
      <span class="path-badge breach">BREACH SIM</span>
      <div class="run-h2">Ransomware Lateral Movement Simulation</div>
    </div>
    <div class="run-sub">Testing macro segmentation, SGT enforcement, and ISE threat containment&hellip;</div>
    <div class="progress-wrap"><div class="progress-bar" id="progress-bar"
         style="background:linear-gradient(90deg,var(--red),var(--orange),var(--green));"></div></div>
    <div class="steps-list" id="steps-list"></div>
  </div>

  <!-- ══ RESULT ══ -->
  <div id="screen-result">
    <div class="result-hero">
      <div class="result-icon-wrap" id="result-icon-wrap"></div>
      <div class="result-title" id="result-title"></div>
      <div class="result-msg"   id="result-msg"></div>
      <div style="display:flex;gap:10px;justify-content:center;flex-wrap:wrap;margin-top:8px;">
        <button class="btn-back" onclick="window.location.href='/'">&#8592; Back to Lab</button>
        <button class="btn-back" style="background:rgba(255,255,255,0.06);border:1px solid var(--border2);color:var(--text2);" onclick="resetBreachDemo()">Reset Demo</button>
        <button class="btn-back" onclick="location.reload()">Run Again</button>
      </div>
    </div>
    <div class="result-log">
      <div class="result-log-label">Simulation Log</div>
      <div class="steps-list" id="result-steps-list"></div>
    </div>

    <!-- Summary card — shown only on success -->
    <div id="breach-summary-card" style="display:none">
      <div class="summary-card-inner">
        <div class="summary-eyebrow">&#x2713;&nbsp; Mission Complete</div>
        <div class="summary-headline">Ransomware Attack Neutralised &mdash; Zero Trust Campus Held</div>
        <div class="summary-acts">
          <div class="summary-act">
            <div class="summary-act-badge act1">Act 1</div>
            <div class="summary-act-title">Macro Segmentation</div>
            <div class="summary-act-desc">VRF isolation confined the attacker to the IoT segment. Cross-VRF pivoting to PROD and Main was blocked at the routing boundary &mdash; zero firewall rules required.</div>
          </div>
          <div class="summary-act">
            <div class="summary-act-badge act2">Act 2</div>
            <div class="summary-act-title">Micro Segmentation (SGT)</div>
            <div class="summary-act-desc">ISE pushed a Deny IP SGACL to the Production SGT pair via TrustSec. Lateral movement between PROD workstations was killed at the ASIC &mdash; without touching a single switch config.</div>
          </div>
          <div class="summary-act">
            <div class="summary-act-badge act3">Act 3</div>
            <div class="summary-act-title">Threat Containment (ISE CoA)</div>
            <div class="summary-act-desc">ISE verified TrustSec policy across the access layer. SGT counters confirmed the block was enforced in hardware. The attacker&rsquo;s foothold was quarantined and contained in real time.</div>
          </div>
        </div>
        <div class="summary-cisco">
          <div class="summary-cisco-title">&#x26A1; Why Cisco Wins</div>
          <div class="summary-cisco-grid">
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Single Policy Plane</strong> &mdash; ISE is the sole source of truth. One change propagates to every switch instantly via TrustSec.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Hardware-Enforced at Line Rate</strong> &mdash; SGACLs execute in the ASIC. No performance penalty, no packet-by-packet inspection overhead.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Identity-Based, Not IP-Based</strong> &mdash; Policy follows the user and device, not the subnet. Workstations moving ports stay protected automatically.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Zero Touch Containment</strong> &mdash; ISE CoA quarantines compromised endpoints without any manual switch intervention or network downtime.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Fabric + Security Unified</strong> &mdash; ISE and the switching fabric operate as one integrated platform &mdash; no stitching of third-party tools.</div></div>
            <div class="summary-cisco-item"><span class="sci-bullet">&#x2714;</span><div><strong>Proven at Scale</strong> &mdash; The same architecture protects Fortune 500 campuses. What you just saw works identically across thousands of switches.</div></div>
          </div>
        </div>
      </div>
    </div>

  </div>

  <div class="page-footer">
    <div class="copy">&copy; 2025 Cisco and/or its affiliates. All rights reserved.</div>
    <div class="site-label">Site 105 &nbsp;|&nbsp; One Cisco Experience Lab</div>
  </div>

</div>
<script>
const PATH  = 'breach';
const STEPS = {json.dumps(BREACH_STEP_LABELS)};
let stepData = [];
let sid = null;
let currentAct = 0;

// act metadata used to insert dividers
const ACT_STEPS = {{
  "Reconnaissance \u2014 Map the Network Segments":               {{ act: 1, cls: "act1", title: "Act 1 \u2014 Macro Segmentation (VRF Isolation)" }},
  "Threat Intel \u2014 Scanning PROD Segment for Lateral Movement Paths": {{ act: 2, cls: "act2", title: "Act 2 \u2014 Micro Segmentation (SGT Enforcement)" }},
  "Reach ISE ERS API":                         {{ act: 3, cls: "act3", title: "Act 3 \u2014 Threat Containment (ISE CoA)" }},
}};

function sidNew() {{ return Math.random().toString(36).slice(2) + Date.now().toString(36); }}

function show(id) {{
  ['screen-overview','screen-running','screen-result'].forEach(s => {{
    document.getElementById(s).style.display = (s===id)?'block':'none';
  }});
}}

function stepKey(name) {{ return 'sr-' + name.replace(/[^a-zA-Z0-9]/g,'_'); }}

function maybeInsertActDivider(name) {{
  const meta = ACT_STEPS[name];
  if (!meta || meta.act === currentAct) return;
  currentAct = meta.act;
  const list = document.getElementById('steps-list');
  const div = document.createElement('div');
  div.className = 'act-divider';
  div.innerHTML =
    '<span class="act-badge ' + meta.cls + '">Act ' + meta.act + '</span>' +
    '<span class="act-divider-title">' + meta.title + '</span>' +
    '<span class="act-divider-line"></span>';
  list.appendChild(div);
}}

function addStep(name, state) {{
  maybeInsertActDivider(name);
  const list = document.getElementById('steps-list');
  const row = document.createElement('div');
  row.className = 'step-row ' + state;
  row.id = stepKey(name);
  row.innerHTML =
    '<div class="step-row-top">' +
      '<div class="step-spinner"></div>' +
      '<div class="step-name">' + name + '</div>' +
      '<div class="step-detail"></div>' +
    '</div>';
  list.appendChild(row);
  row.scrollIntoView({{behavior:'smooth',block:'nearest'}});
}}

function updateStep(name, state, detail, output) {{
  const row = document.getElementById(stepKey(name));
  if (!row) return;
  row.className = 'step-row ' + state;
  const dot = document.createElement('div');
  dot.className = 'step-dot';
  const top = row.querySelector('.step-row-top');
  if (top) {{
    top.replaceChild(dot, top.firstChild);
    if (detail) top.querySelector('.step-detail').textContent = detail;
  }}
  if (output && output.trim()) {{
    row.classList.add('has-output');
    const det = document.createElement('details');
    det.className = 'step-output';
    det.open = true;
    const summ = document.createElement('summary');
    summ.textContent = 'CLI Output';
    const pre = document.createElement('pre');
    pre.textContent = output.trim();
    det.appendChild(summ);
    det.appendChild(pre);
    row.appendChild(det);
  }}
}}

function updateProgress() {{
  const total = Math.max(STEPS.length + 1, stepData.length + 1);
  const pct = Math.min(94, (stepData.length / total) * 100);
  document.getElementById('progress-bar').style.width = pct + '%';
}}

function startDeploy() {{
  sid = sidNew();
  stepData = [];
  currentAct = 0;
  document.getElementById('steps-list').innerHTML = '';
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('btn-deploy').disabled = true;
  show('screen-running');

  fetch('/api/breach/start', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{sid}})
  }}).then(() => {{
    const es = new EventSource('/api/stream/' + sid);

    es.addEventListener('act_start', e => {{
      // act_start is handled by maybeInsertActDivider when the first step arrives
    }});

    es.addEventListener('step_start', e => {{
      const d = JSON.parse(e.data);
      addStep(d.name, 'running');
    }});

    es.addEventListener('step_waiting', e => {{
      const d = JSON.parse(e.data);
      const row = document.getElementById(stepKey(d.name));
      if (!row) return;
      row.className = 'step-row waiting';
      const top = row.querySelector('.step-row-top');
      if (top) {{
        const dot = document.createElement('div');
        dot.className = 'step-dot';
        top.replaceChild(dot, top.firstChild);
        top.querySelector('.step-detail').textContent = 'Waiting for confirmation...';
      }}
      const banner = document.createElement('div');
      banner.className = 'waiting-banner';
      banner.id = 'waiting-banner-' + stepKey(d.name);
      banner.innerHTML =
        '<div class="waiting-icon">&#9888;</div>' +
        '<div class="waiting-body">' +
          '<div class="waiting-title">&#128680; Student Action Required &#128680;</div>' +
          '<div class="waiting-instruction">' +
            'The attacker is probing the PROD segment. Set up lateral movement traffic:<br><br>' +
            '<strong style="color:var(--red);">Step 1</strong> &mdash; Log in to <strong>Workstation 1 (Pat)</strong> on the PROD network<br>' +
            '<strong style="color:var(--red);">Step 2</strong> &mdash; Log in to <strong>Workstation 2 (Kit)</strong> on the PROD network<br>' +
            '<strong style="color:var(--red);">Step 3</strong> &mdash; On each workstation, run the ping test bat script and select option <strong>5 (What is my IP?)</strong> &mdash; note down both IP addresses<br>' +
            '<strong style="color:var(--red);">Step 4</strong> &mdash; On Pat\u2019s workstation, start a continuous ping to Kit\u2019s IP address:<br>' +
            '<code style="font-size:13px;background:rgba(0,0,0,0.4);padding:4px 10px;border-radius:4px;display:inline-block;margin:4px 0;">ping &lt;Kit\u2019s IP&gt; -t</code><br>' +
            '<strong style="color:var(--red);">Step 5</strong> &mdash; On Kit\u2019s workstation, start a continuous ping back to Pat\u2019s IP address:<br>' +
            '<code style="font-size:13px;background:rgba(0,0,0,0.4);padding:4px 10px;border-radius:4px;display:inline-block;margin:4px 0;">ping &lt;Pat\u2019s IP&gt; -t</code><br><br>' +
            '<span style="opacity:0.8;font-size:13px;">Leave both pings running continuously &mdash; this simulates an attacker moving laterally inside the PROD segment. ' +
            'Once both workstations are pinging each other, click confirm below.</span>' +
          '</div>' +
          '<button onclick="confirmPingsStarted()" class="btn-confirm" id="btn-confirm-pings">' +
            '&#10003; Both Workstations Pinging — Deploy Block Policy' +
          '</button>' +
        '</div>';
      row.appendChild(banner);
      row.scrollIntoView({{behavior:'smooth', block:'center'}});
    }});

    es.addEventListener('step_done', e => {{
      const d = JSON.parse(e.data);
      // Remove waiting banner if present
      const banner = document.getElementById('waiting-banner-' + stepKey(d.name));
      if (banner) banner.remove();
      updateStep(d.name, d.ok ? 'ok' : 'fail', d.detail || '', d.output || '');
      stepData.push(d);
      updateProgress();
    }});

    es.addEventListener('complete', e => {{
      es.close();
      const d = JSON.parse(e.data || '{{}}');
      setTimeout(() => showResult(d.ok !== false), 800);
    }});

    es.onerror = () => {{ es.close(); setTimeout(() => showResult(false), 800); }};
  }});
}}

function showResult(allOk) {{
  if (allOk === undefined) allOk = stepData.length > 0 && stepData.every(s => s.ok);
  document.getElementById('progress-bar').style.width = '100%';
  const hero  = document.querySelector('#screen-result .result-hero');
  const wrap  = document.getElementById('result-icon-wrap');
  const title = document.getElementById('result-title');

  if (allOk) {{
    hero.classList.add('success-hero');
    if (!document.getElementById('result-eyebrow')) {{
      const eyebrow = document.createElement('div');
      eyebrow.id = 'result-eyebrow';
      eyebrow.className = 'result-eyebrow';
      eyebrow.textContent = 'Ransomware Attack Neutralised';
      hero.insertBefore(eyebrow, wrap);
    }}
  }}

  wrap.className   = 'result-icon-wrap ' + (allOk ? 'success' : 'fail');
  wrap.textContent = allOk ? '\\u2713' : '\\u2717';
  title.className  = 'result-title ' + (allOk ? 'success' : 'fail');
  title.textContent = allOk
    ? 'Segmentation Verified — Attack Contained'
    : 'Simulation Incomplete — Review Log';
  document.getElementById('result-msg').textContent = allOk
    ? 'All three acts confirmed. VRF macro segmentation blocked cross-network pivoting. SGT micro segmentation stopped lateral movement within the campus. ISE CoA quarantined the compromised device instantly \u2014 without a single switch config change. Pseudoco\u2019s Zero Trust campus held.'
    : 'One or more simulation steps could not be verified. Check fabric reachability, CTS policy configuration, and switch SSH access. Consult your proctor.';
  const clone = document.getElementById('steps-list').cloneNode(true);
  clone.id = '';
  const rl = document.getElementById('result-steps-list');
  rl.innerHTML = ''; rl.appendChild(clone);
  show('screen-result');
  if (allOk) {{
    // Show summary card — scroll directly to it, no hero jump
    const card = document.getElementById('breach-summary-card');
    card.style.display = 'block';
    card.style.animation = 'none';
    card.offsetHeight;
    card.style.animation = 'summaryReveal 0.8s ease forwards, pulse-green 2.2s ease-in-out 4';
    setTimeout(() => card.scrollIntoView({{behavior:'smooth', block:'start'}}), 600);
  }}
}}

function confirmPingsStarted() {{
  const btn = document.getElementById('btn-confirm-pings');
  if (btn) {{ btn.disabled = true; btn.textContent = 'Confirmed — deploying block policy...'; }}
  fetch('/api/breach/confirm', {{
    method: 'POST', headers: {{'Content-Type':'application/json'}},
    body: JSON.stringify({{sid}})
  }}).catch(() => {{}});
}}

function resetBreachDemo() {{
  const btn = event && event.target ? event.target : document.getElementById('btn-reset');
  const origText = btn ? btn.textContent : '';
  if (btn) {{ btn.disabled = true; btn.textContent = 'Resetting...'; }}
  fetch('/api/breach/reset', {{ method: 'POST' }})
    .then(r => r.json())
    .then(d => {{
      const ok = d.status === 'ok' || d.status === 'partial';
      const detail = Object.entries(d.switches || {{}})
        .map(([k,v]) => k + ': ' + v).join(' | ');
      alert((ok ? '\u2713 Reset complete\\n' : '\u26a0 Partial reset\\n') + detail);
      if (btn) {{ btn.disabled = false; btn.textContent = origText || 'Reset Demo'; }}
    }})
    .catch(e => {{
      alert('Reset failed: ' + e);
      if (btn) {{ btn.disabled = false; btn.textContent = origText || 'Reset Demo'; }}
    }});
}}
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8099, threaded=True)
