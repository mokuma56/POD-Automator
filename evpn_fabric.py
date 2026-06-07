"""
evpn_fabric.py — EVPN VXLAN Fabric automation for the 3-switch lab topology.

Topology:
  Border Spine  (C9300-48U)  198.18.128.24  Loopback0: 172.30.255.3  AS 65535
  Leaf 1        (C9300-48UB) 198.18.128.22  Loopback0: 172.30.255.1  AS 65535
  Leaf 2        (C9300-48P)  198.18.128.23  Loopback0: 172.30.255.2  AS 65535

Steps (run in order):
  1.  vrf_definitions          — VRF Main/PROD/IOT on all 3 switches
  2.  multicast_replication     — l2vpn evpn replication-type static  (Leaf1+2 only)
  3.  l2vni_vlan_mappings       — VLANs 10/101/102 + evpn instances  (Leaf1+2 only)
  4.  l3vni_vlans               — VLANs 1010/1101/1102 + vni mapping  (all 3)
  5.  dag_svis                  — Anycast gateway SVIs 10/101/102     (Leaf1+2 only)
  6.  l3vni_svis                — SVIs 1010/1101/1102 unnumbered      (all 3)
  7.  nve_interface             — NVE1 with L2+L3 VNI members         (all 3, diff config)
  8.  bgp_evpn                  — BGP 65535 + l2vpn evpn AF           (all 3, diff config)
  9.  spine_external_interface  — Gi1/0/48 trunk + VRF-Lite SVIs      (Spine only)
  10. spine_bgp_sdwan           — BGP peering toward SD-WAN router     (Spine only)
  11. access_ports              — Client/AP port configs               (Leaf1+2 only)
  12. dot1x_security            — IBNS 2.0 / 802.1x + device sensor   (Leaf1+2 only)
  13. verify_bgp_evpn           — show bgp l2vpn evpn summary          (Spine verify)
  14. verify_nve_peers          — show nve peers                       (Spine verify)

Usage:
  uv run python3 evpn_fabric.py              # run all steps
  uv run python3 evpn_fabric.py --step 1     # run single step
  uv run python3 evpn_fabric.py --from 5     # resume from step 5
  uv run python3 evpn_fabric.py --verify     # verify-only (steps 12+13)
"""

import argparse
import os
import sys
import time
import paramiko
import sqlite3

# ── Switch definitions ────────────────────────────────────────────────────────
SWITCHES = {
    "border_spine": {
        "name": "Border Spine",
        "ip":   "198.18.128.24",
        "lo0":  "172.30.255.3",
    },
    "leaf1": {
        "name": "Leaf 1",
        "ip":   "198.18.128.22",
        "lo0":  "172.30.255.1",
    },
    "leaf2": {
        "name": "Leaf 2",
        "ip":   "198.18.128.23",
        "lo0":  "172.30.255.2",
    },
}

SWITCH_USER = "netadmin"
SWITCH_PASS = "C1sco12345"

DB_PATH = os.environ.get("DB_PATH", "data/pod_state.db")
POD_ID  = os.environ.get("POD_ID", "")

# ── Per-step config blocks ────────────────────────────────────────────────────

def _vrf_config(lo0):
    """VRF definitions — RD uses the switch's Loopback0 IP."""
    return f"""\
vrf definition IOT
 rd {lo0}:102
 !
 address-family ipv4
  route-target export 65535:102
  route-target import 65535:102
  route-target export 65535:102 stitching
  route-target import 65535:102 stitching
 exit-address-family
!
vrf definition Main
 rd {lo0}:10
 !
 address-family ipv4
  route-target export 65535:10
  route-target import 65535:10
  route-target export 65535:10 stitching
  route-target import 65535:10 stitching
 exit-address-family
!
vrf definition PROD
 rd {lo0}:101
 !
 address-family ipv4
  route-target export 65535:101
  route-target import 65535:101
  route-target export 65535:101 stitching
  route-target import 65535:101 stitching
 exit-address-family
"""

MULTICAST_REPLICATION = """\
l2vpn evpn
 replication-type static
 router-id loopback 0
"""

L2VNI_VLAN_MAPPINGS = """\
vlan 10
 name Main
!
vlan 101
 name PROD
!
vlan 102
 name IOT
!
l2vpn evpn instance 10 vlan-based
 encapsulation vxlan
!
l2vpn evpn instance 101 vlan-based
 encapsulation vxlan
!
l2vpn evpn instance 102 vlan-based
 encapsulation vxlan
!
vlan configuration 10
 member evpn-instance 10 vni 100010
!
vlan configuration 101
 member evpn-instance 101 vni 100101
!
vlan configuration 102
 member evpn-instance 102 vni 100102
"""

L3VNI_VLANS = """\
vlan 1010
 name L3-VRF-CORE-VLAN-10
!
vlan 1101
 name L3-VRF-CORE-VLAN-101
!
vlan 1102
 name L3-VRF-CORE-VLAN-102
!
vlan configuration 1010
 member vni 110010
!
vlan configuration 1101
 member vni 110101
!
vlan configuration 1102
 member vni 110102
"""

DAG_SVIS = """\
interface Vlan10
 mac-address 0001.0001.0010
 vrf forwarding Main
 ip dhcp relay source-interface Loopback0
 ip address 10.10.255.1 255.255.255.0
 ip helper-address global 198.18.5.102
 no shutdown
!
interface Vlan101
 mac-address 0001.0001.0101
 vrf forwarding PROD
 ip dhcp relay source-interface Loopback0
 ip address 10.101.255.1 255.255.255.0
 ip helper-address global 198.18.5.102
 no shutdown
!
interface Vlan102
 mac-address 0001.0001.0102
 vrf forwarding IOT
 ip dhcp relay source-interface Loopback0
 ip address 10.102.255.1 255.255.255.0
 ip helper-address global 198.18.5.102
 no shutdown
"""

L3VNI_SVIS = """\
interface Vlan1010
 vrf forwarding Main
 ip unnumbered Loopback0
 no autostate
 no shutdown
!
interface Vlan1101
 vrf forwarding PROD
 ip unnumbered Loopback0
 no autostate
 no shutdown
!
interface Vlan1102
 vrf forwarding IOT
 ip unnumbered Loopback0
 no autostate
 no shutdown
"""

NVE_LEAF = """\
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
 member vni 100102 mcast-group 232.1.1.1
"""

NVE_SPINE = """\
interface nve1
 no ip address
 source-interface Loopback0
 host-reachability protocol bgp
 member vni 110010 vrf Main
 member vni 110101 vrf PROD
 member vni 110102 vrf IOT
"""

def _bgp_leaf(lo0, spine_lo0="172.30.255.3"):
    return f"""\
router bgp 65535
 bgp router-id {lo0}
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 neighbor {spine_lo0} remote-as 65535
 neighbor {spine_lo0} update-source Loopback0
 !
 address-family ipv4
 exit-address-family
 !
 address-family l2vpn evpn
  neighbor {spine_lo0} activate
  neighbor {spine_lo0} send-community both
 exit-address-family
 !
 address-family ipv4 vrf IOT
  advertise l2vpn evpn
  redistribute connected
 exit-address-family
 !
 address-family ipv4 vrf Main
  advertise l2vpn evpn
  redistribute connected
 exit-address-family
 !
 address-family ipv4 vrf PROD
  advertise l2vpn evpn
  redistribute connected
 exit-address-family
"""

BGP_SPINE = """\
router bgp 65535
 bgp router-id 172.30.255.3
 bgp log-neighbor-changes
 no bgp default ipv4-unicast
 neighbor 172.30.255.1 remote-as 65535
 neighbor 172.30.255.1 update-source Loopback0
 neighbor 172.30.255.2 remote-as 65535
 neighbor 172.30.255.2 update-source Loopback0
 !
 address-family l2vpn evpn
  neighbor 172.30.255.1 activate
  neighbor 172.30.255.1 send-community both
  neighbor 172.30.255.1 route-reflector-client
  neighbor 172.30.255.2 activate
  neighbor 172.30.255.2 send-community both
  neighbor 172.30.255.2 route-reflector-client
 exit-address-family
"""

SPINE_EXTERNAL_INTERFACE = """\
default interface GigabitEthernet1/0/48
"""
# Pause needed after default — interface resets. Then:
SPINE_EXTERNAL_INTERFACE_2 = """\
interface GigabitEthernet1/0/48
 switchport mode trunk
 cts manual
 no shutdown
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
interface Vlan10
 description Main
 vrf forwarding Main
 ip address 192.168.255.1 255.255.255.254
 no shutdown
!
interface Vlan101
 vrf forwarding PROD
 ip address 192.168.255.3 255.255.255.254
 no shutdown
!
interface Vlan102
 vrf forwarding IOT
 ip address 192.168.255.5 255.255.255.254
 no shutdown
"""

SPINE_BGP_SDWAN = """\
router bgp 65535
 neighbor 192.168.255.6 remote-as 65534
 !
 address-family ipv4
  network 172.30.255.1 mask 255.255.255.255
  network 172.30.255.2 mask 255.255.255.255
  network 172.30.255.3 mask 255.255.255.255
  neighbor 192.168.255.6 activate
  neighbor 192.168.255.6 send-community both
 exit-address-family
 !
 address-family ipv4 vrf IOT
  advertise l2vpn evpn
  redistribute connected
  neighbor 192.168.255.4 remote-as 65534
  neighbor 192.168.255.4 activate
  neighbor 192.168.255.4 send-community both
 exit-address-family
 !
 address-family ipv4 vrf Main
  advertise l2vpn evpn
  redistribute connected
  neighbor 192.168.255.0 remote-as 65534
  neighbor 192.168.255.0 activate
  neighbor 192.168.255.0 send-community both
 exit-address-family
 !
 address-family ipv4 vrf PROD
  advertise l2vpn evpn
  redistribute connected
  neighbor 192.168.255.2 remote-as 65534
  neighbor 192.168.255.2 activate
  neighbor 192.168.255.2 send-community both
 exit-address-family
"""

ACCESS_PORTS = """\
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
!
interface GigabitEthernet1/0/3
 description Client
 switchport mode access
 device-tracking attach-policy IPDT_POLICY
 source template WIRED_DOT1X_CLOSED
 spanning-tree portfast
 ip nbar protocol-discovery
"""

# ── 802.1x / IBNS 2.0 security config (Leaf1 + Leaf2 only) ───────────────────
#
# Optimised for IOS XE 17.x + ISE 3.x IBNS 2.0 validated design:
#  - Device Sensor (DHCP/CDP/LLDP) for ISE profiling
#  - IPDT policy required by device-tracking attach-policy on access ports
#  - access-session filter-list for ISE accounting/auth attributes
#  - 4 interface templates: DOT1X/MAB × CLOSED/OPEN
#  - DOT1X_MAB_POLICY (dot1x-first) + MAB_DOT1X_POLICY (mab-first)
#  - CTS role-based enforcement on data VLANs
#  - Critical-auth service templates for ISE AAA-down survivability
#
DOT1X_SECURITY = """\
radius server dnac-radius_198.18.5.101
 address ipv4 198.18.5.101 auth-port 1812 acct-port 1813
 key C1sco12345
aaa group server radius dnac-client-radius-group
 server name dnac-radius_198.18.5.101
 ip radius source-interface Loopback0
aaa authentication dot1x default group dnac-client-radius-group
aaa authorization network default group dnac-client-radius-group
aaa accounting identity default start-stop group dnac-client-radius-group
aaa accounting update newinfo periodic 2880
ip radius source-interface Loopback0
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
!
class-map type control subscriber match-all AAA_SVR_DOWN_UNAUTHD_HOST
 match result-type aaa-timeout
 match authorization-status unauthorized
!
class-map type control subscriber match-all AUTHC_SUCCESS_AUTHZ_FAIL
 match authorization-status unauthorized
 match result-type success
!
class-map type control subscriber match-all DOT1X
 match method dot1x
!
class-map type control subscriber match-all DOT1X_FAILED
 match method dot1x
 match result-type method dot1x authoritative
!
class-map type control subscriber match-all DOT1X_NO_RESP
 match method dot1x
 match result-type method dot1x agent-not-found
!
class-map type control subscriber match-all DOT1X_TIMEOUT
 match method dot1x
 match result-type method dot1x method-timeout
!
class-map type control subscriber match-any IN_CRITICAL_AUTH
 match activated-service-template CRITICAL_DATA_ACCESS
 match activated-service-template CRITICAL_VOICE_ACCESS
!
class-map type control subscriber match-all MAB
 match method mab
!
class-map type control subscriber match-all MAB_FAILED
 match method mab
 match result-type method mab authoritative
!
class-map type control subscriber match-none NOT_IN_CRITICAL_AUTH
 match activated-service-template CRITICAL_DATA_ACCESS
 match activated-service-template CRITICAL_VOICE_ACCESS
!
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
!
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
!
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
!
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
!
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
!
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
device-tracking policy IPDT_POLICY
 no protocol udp
 tracking enable
"""

# ── SSH helpers ───────────────────────────────────────────────────────────────

def _ssh_connect(ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ip,
        username=SWITCH_USER,
        password=SWITCH_PASS,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
    )
    return client


def _send_config(ip, config_block, label="", timeout=30):
    """
    Open an interactive shell, enter config mode, push lines, then
    write memory. Returns (ok, output_snippet).
    """
    try:
        client = _ssh_connect(ip)
        shell = client.invoke_shell(width=200, height=200)
        time.sleep(1)
        shell.recv(4096)  # drain banner

        def _send(cmd, delay=0.5):
            shell.send(cmd + "\n")
            time.sleep(delay)
            out = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if shell.recv_ready():
                    out += shell.recv(8192)
                    # Answer interactive yes/no prompts automatically
                    if b"[yes]:" in out or b"[yes/no]:" in out or b"continue?" in out.lower():
                        shell.send("yes\n")
                        time.sleep(0.5)
                        continue
                    if b"#" in out[-50:]:
                        break
                else:
                    time.sleep(0.2)
            return out.decode(errors="ignore")

        _send("terminal length 0")
        _send("configure terminal", delay=1)

        output = ""
        for line in config_block.strip().splitlines():
            line = line.rstrip()
            if not line or line == "!":
                continue
            output += _send(line, delay=0.3)

        _send("end", delay=1)
        wr_out = _send("write memory", delay=3)
        client.close()

        ok = "[OK]" in wr_out or "Building configuration" in wr_out or "%" not in wr_out
        snippet = wr_out.strip()[-200:]
        return ok, snippet

    except Exception as e:
        return False, str(e)


def _send_raw(ip, commands, timeout=30):
    """Send a list of raw exec-mode commands and return output."""
    try:
        client = _ssh_connect(ip)
        shell = client.invoke_shell(width=200, height=200)
        time.sleep(1)
        shell.recv(4096)

        def _send(cmd, delay=1.0):
            shell.send(cmd + "\n")
            time.sleep(delay)
            out = b""
            deadline = time.time() + timeout
            while time.time() < deadline:
                if shell.recv_ready():
                    out += shell.recv(16384)
                    if b"#" in out[-50:]:
                        break
                else:
                    time.sleep(0.3)
            return out.decode(errors="ignore")

        _send("terminal length 0")
        output = ""
        for cmd in commands:
            output += _send(cmd, delay=1.5)
        client.close()
        return True, output
    except Exception as e:
        return False, str(e)


# ── DB persistence ────────────────────────────────────────────────────────────

def _persist_fabric_step(step_name, status, result=""):
    if not POD_ID:
        return
    # Retry up to 3 times — SQLite "database is locked" can silently drop
    # the completed/failed write if the dashboard is writing simultaneously,
    # leaving the step stuck in 'running' forever.
    for attempt in range(3):
        try:
            c = sqlite3.connect(DB_PATH, timeout=15)
            c.execute("""
                INSERT OR REPLACE INTO fabric_steps
                    (pod_id, step_name, status, started_at, completed_at, result)
                VALUES (?, ?, ?,
                    COALESCE((SELECT started_at FROM fabric_steps WHERE pod_id=? AND step_name=?), datetime('now')),
                    CASE WHEN ? IN ('completed','failed','skipped') THEN datetime('now') ELSE NULL END,
                    ?)
            """, (POD_ID, step_name, status, POD_ID, step_name, status, result))
            c.commit()
            c.close()
            return
        except Exception as e:
            print(f"[fabric] WARNING: _persist_fabric_step({step_name}, {status}) attempt {attempt+1} failed: {e}")
            if attempt < 2:
                import time; time.sleep(0.5)


def _load_completed_fabric_steps():
    if not POD_ID:
        return set()
    try:
        c = sqlite3.connect(DB_PATH)
        rows = c.execute(
            "SELECT step_name FROM fabric_steps WHERE pod_id=? AND status='completed'", (POD_ID,)
        ).fetchall()
        c.close()
        return {r[0] for r in rows}
    except Exception:
        return set()


# ── Step runners ──────────────────────────────────────────────────────────────

def _run(step_name, targets, log_fn=print):
    """
    targets: list of (switch_key, config_block) tuples.
    Pushes config to each switch, returns (ok, detail).
    """
    _persist_fabric_step(step_name, "running")
    results = []
    for sw_key, config in targets:
        sw = SWITCHES[sw_key]
        log_fn(f"  → {sw['name']} ({sw['ip']})...")
        ok, snippet = _send_config(sw["ip"], config, label=f"{step_name}/{sw_key}")
        status = "✓" if ok else "✗"
        log_fn(f"    {status} {sw['name']}: {snippet[-100:].strip()}")
        results.append((sw_key, ok, snippet))

    all_ok = all(r[1] for r in results)
    detail = " | ".join(f"{r[0]}={'ok' if r[1] else 'FAIL'}" for r in results)
    _persist_fabric_step(step_name, "completed" if all_ok else "failed", detail)
    return all_ok, detail


# ── Individual step functions ─────────────────────────────────────────────────

def step_vrf_definitions(log_fn=print):
    log_fn("Step 1: VRF definitions (Main / PROD / IOT) → all 3 switches")
    return _run("vrf_definitions", [
        ("border_spine", _vrf_config(SWITCHES["border_spine"]["lo0"])),
        ("leaf1",        _vrf_config(SWITCHES["leaf1"]["lo0"])),
        ("leaf2",        _vrf_config(SWITCHES["leaf2"]["lo0"])),
    ], log_fn)


def step_multicast_replication(log_fn=print):
    log_fn("Step 2: Static multicast replication → Leaf1 + Leaf2")
    return _run("multicast_replication", [
        ("leaf1", MULTICAST_REPLICATION),
        ("leaf2", MULTICAST_REPLICATION),
    ], log_fn)


def step_l2vni_vlan_mappings(log_fn=print):
    log_fn("Step 3: L2VNI VLAN mappings (VLANs 10/101/102) → Leaf1 + Leaf2")
    return _run("l2vni_vlan_mappings", [
        ("leaf1", L2VNI_VLAN_MAPPINGS),
        ("leaf2", L2VNI_VLAN_MAPPINGS),
    ], log_fn)


def step_l3vni_vlans(log_fn=print):
    log_fn("Step 4: L3VNI VLANs (1010/1101/1102) → all 3 switches")
    return _run("l3vni_vlans", [
        ("border_spine", L3VNI_VLANS),
        ("leaf1",        L3VNI_VLANS),
        ("leaf2",        L3VNI_VLANS),
    ], log_fn)


def step_dag_svis(log_fn=print):
    log_fn("Step 5: Distributed Anycast Gateway SVIs (Vlan10/101/102) → Leaf1 + Leaf2")
    return _run("dag_svis", [
        ("leaf1", DAG_SVIS),
        ("leaf2", DAG_SVIS),
    ], log_fn)


def step_l3vni_svis(log_fn=print):
    log_fn("Step 6: L3VNI SVIs (Vlan1010/1101/1102 unnumbered) → all 3 switches")
    return _run("l3vni_svis", [
        ("border_spine", L3VNI_SVIS),
        ("leaf1",        L3VNI_SVIS),
        ("leaf2",        L3VNI_SVIS),
    ], log_fn)


def step_nve_interface(log_fn=print):
    log_fn("Step 7: NVE1 interface → all 3 switches (Spine config differs)")
    return _run("nve_interface", [
        ("border_spine", NVE_SPINE),
        ("leaf1",        NVE_LEAF),
        ("leaf2",        NVE_LEAF),
    ], log_fn)


def step_bgp_evpn(log_fn=print):
    log_fn("Step 8: BGP EVPN (Leaves peer to Spine RR) → all 3 switches")
    return _run("bgp_evpn", [
        ("border_spine", BGP_SPINE),
        ("leaf1",        _bgp_leaf(SWITCHES["leaf1"]["lo0"])),
        ("leaf2",        _bgp_leaf(SWITCHES["leaf2"]["lo0"])),
    ], log_fn)


def step_spine_external_interface(log_fn=print):
    log_fn("Step 9: Spine external interface Gi1/0/48 + VRF-Lite SVIs → Border Spine")
    # Two-phase: default the interface first (causes a brief disconnect), then configure
    spine_ip = SWITCHES["border_spine"]["ip"]
    log_fn("  → Defaulting Gi1/0/48...")
    ok1, _ = _send_config(spine_ip, SPINE_EXTERNAL_INTERFACE)
    time.sleep(3)
    log_fn("  → Configuring Gi1/0/48 trunk + VRF-Lite SVIs...")
    ok2, snippet = _send_config(spine_ip, SPINE_EXTERNAL_INTERFACE_2)
    ok = ok1 and ok2
    detail = f"border_spine={'ok' if ok else 'FAIL'}: {snippet[-100:].strip()}"
    _persist_fabric_step("spine_external_interface", "completed" if ok else "failed", detail)
    return ok, detail


def step_spine_bgp_sdwan(log_fn=print):
    log_fn("Step 10: Spine BGP peering toward SD-WAN router → Border Spine")
    return _run("spine_bgp_sdwan", [
        ("border_spine", SPINE_BGP_SDWAN),
    ], log_fn)


def step_access_ports(log_fn=print):
    log_fn("Step 11: Access/AP port configs (Gi1/0/1-3) → Leaf1 + Leaf2")
    return _run("access_ports", [
        ("leaf1", ACCESS_PORTS),
        ("leaf2", ACCESS_PORTS),
    ], log_fn)


def step_dot1x_security(log_fn=print):
    log_fn("Step 12: 802.1x / IBNS 2.0 security config → Leaf1 + Leaf2")
    return _run("dot1x_security", [
        ("leaf1", DOT1X_SECURITY),
        ("leaf2", DOT1X_SECURITY),
    ], log_fn)


def step_verify_bgp_evpn(log_fn=print):
    log_fn("Step 12: Verify BGP EVPN summary → Border Spine")
    spine_ip = SWITCHES["border_spine"]["ip"]
    ok, output = _send_raw(spine_ip, ["show bgp l2vpn evpn summary"])
    log_fn(output[-600:])
    # IOS XE shows prefix count (a digit) in State/PfxRcd when neighbor is established
    import re
    established = sum(1 for line in output.splitlines()
                      if re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+4\s+\d+.*\s+\d+\s*$', line.strip()))
    # Also accept explicit "Established" or "Up" keywords (older IOS)
    established += output.count("Established") + output.count("Up/Down") * 0
    passed = ok and established >= 2
    detail = f"{established} BGP EVPN neighbor(s) established\n{output[-800:]}"
    _persist_fabric_step("verify_bgp_evpn", "completed" if passed else "failed", detail)
    return passed, detail


def step_verify_nve_peers(log_fn=print):
    log_fn("Step 13: Verify NVE peers → Border Spine")
    spine_ip = SWITCHES["border_spine"]["ip"]
    ok, output = _send_raw(spine_ip, ["show nve peers"])
    log_fn(output[-600:])
    # Expect at least 1 peer per leaf
    peer_count = output.count("UP") + output.count("up")
    passed = ok and peer_count >= 1
    detail = f"{peer_count} NVE peer(s) UP\n{output[-800:]}"
    _persist_fabric_step("verify_nve_peers", "completed" if passed else "failed", detail)
    return passed, detail


# ── Ordered step list ─────────────────────────────────────────────────────────

FABRIC_STEPS = [
    ("vrf_definitions",           step_vrf_definitions),
    ("multicast_replication",     step_multicast_replication),
    ("l2vni_vlan_mappings",       step_l2vni_vlan_mappings),
    ("l3vni_vlans",               step_l3vni_vlans),
    ("dag_svis",                  step_dag_svis),
    ("l3vni_svis",                step_l3vni_svis),
    ("nve_interface",             step_nve_interface),
    ("bgp_evpn",                  step_bgp_evpn),
    ("spine_external_interface",  step_spine_external_interface),
    ("spine_bgp_sdwan",           step_spine_bgp_sdwan),
    ("access_ports",              step_access_ports),
    ("dot1x_security",            step_dot1x_security),
    ("verify_bgp_evpn",           step_verify_bgp_evpn),
    ("verify_nve_peers",          step_verify_nve_peers),
]

FABRIC_STEP_LABELS = {k: k.replace("_", " ").title() for k, _ in FABRIC_STEPS}


# ── DB schema init ────────────────────────────────────────────────────────────

def ensure_fabric_table():
    try:
        c = sqlite3.connect(DB_PATH)
        c.execute("""
            CREATE TABLE IF NOT EXISTS fabric_steps (
                pod_id       TEXT NOT NULL,
                step_name    TEXT NOT NULL,
                status       TEXT NOT NULL DEFAULT 'pending',
                started_at   TEXT,
                completed_at TEXT,
                result       TEXT,
                PRIMARY KEY (pod_id, step_name)
            )
        """)
        c.commit()
        c.close()
    except Exception as e:
        print(f"Warning: could not create fabric_steps table: {e}")


# ── Public entry point (called from dashboard or CLI) ─────────────────────────

def run_fabric(from_step=1, only_step=None, verify_only=False, log_fn=print, pod_id=None, db_path=None):
    """
    Run the EVPN fabric automation.
    Returns list of (step_name, ok, detail) tuples.
    """
    global POD_ID, DB_PATH
    if pod_id:
        POD_ID = pod_id
    if db_path:
        DB_PATH = db_path
    ensure_fabric_table()
    completed = _load_completed_fabric_steps()
    results = []

    steps_to_run = FABRIC_STEPS
    if verify_only:
        steps_to_run = [(k, f) for k, f in FABRIC_STEPS if k.startswith("verify")]
    elif only_step:
        steps_to_run = [(k, f) for k, f in FABRIC_STEPS if k == only_step]
    else:
        steps_to_run = [(k, f) for i, (k, f) in enumerate(FABRIC_STEPS, 1) if i >= from_step]

    for step_name, func in steps_to_run:
        if step_name in completed and not verify_only:
            log_fn(f"  ↷ {step_name} skipped (already completed)")
            results.append((step_name, True, "skipped"))
            continue

        log_fn(f"\n▶ {step_name}")
        try:
            ok, detail = func(log_fn=log_fn)
        except Exception as e:
            ok, detail = False, str(e)
            _persist_fabric_step(step_name, "failed", detail)

        status = "✓" if ok else "✗"
        log_fn(f"  {status} {step_name}: {detail}")
        results.append((step_name, ok, detail))

        if not ok:
            log_fn(f"\n  HALTED at {step_name} — fix the issue and re-run with --from {FABRIC_STEPS.index((step_name, func)) + 1}")
            break

    return results


# ── CLI entry ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EVPN VXLAN Fabric Automation")
    parser.add_argument("--step",     type=str, help="Run only this step name")
    parser.add_argument("--from",     dest="from_step", type=int, default=1,
                        help="Resume from step number (1-13)")
    parser.add_argument("--verify",   action="store_true", help="Run verify steps only")
    parser.add_argument("--list",     action="store_true", help="List all steps")
    args = parser.parse_args()

    if args.list:
        print("EVPN Fabric Steps:")
        for i, (k, _) in enumerate(FABRIC_STEPS, 1):
            print(f"  {i:2}. {k}")
        sys.exit(0)

    run_fabric(
        from_step=args.from_step,
        only_step=args.step,
        verify_only=args.verify,
    )
