"""
POD Automator — MCP Server for Cisco One Experience Lab POD Preparation.

Provides tools to automate POD prep steps:
  - Device verification (switches, secure router)
  - SD-WAN onboarding / bootstrap
  - SCC / cdFMC checks
  - Config deployment
  - POD state tracking + dashboard
"""

from fastmcp import FastMCP
import json, os, time, sqlite3, csv, io
from datetime import datetime
from pathlib import Path
from typing import Optional

mcp = FastMCP("pod-automator")

DATA_DIR = Path.home() / "sw_projects" / "pod_automator" / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATA_DIR / "pod_state.db"
SPREADSHEET_PATH = DATA_DIR / "hw_pod_status.csv"

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pods (
            pod_id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'pending',
            secure_router_serial TEXT,
            controller_mode TEXT DEFAULT 'no',
            sdwan_online TEXT DEFAULT 'no',
            sdwan_licensed TEXT DEFAULT 'no',
            config_group_deployed TEXT DEFAULT 'no',
            border_spine_ver TEXT,
            border_spine_ok TEXT DEFAULT 'no',
            leaf1_ver TEXT,
            leaf1_ok TEXT DEFAULT 'no',
            leaf2_ver TEXT,
            leaf2_ok TEXT DEFAULT 'no',
            cdftd_registered TEXT DEFAULT 'no',
            scc_org TEXT,
            duo_verified TEXT DEFAULT 'no',
            ad_verified TEXT DEFAULT 'no',
            ping_cc_ok TEXT DEFAULT 'no',
            notes TEXT,
            last_updated TEXT,
            proctor TEXT
        )
    """)
    return conn

def _get_pod(pod_id: str) -> dict:
    conn = _db()
    row = conn.execute("SELECT * FROM pods WHERE pod_id = ?", (pod_id,)).fetchone()
    conn.close()
    return dict(row) if row else {}

def _upsert_pod(pod_id: str, **kwargs):
    conn = _db()
    existing = conn.execute("SELECT * FROM pods WHERE pod_id = ?", (pod_id,)).fetchone()
    kwargs["last_updated"] = datetime.now().isoformat()
    if existing:
        keys = ", ".join(kwargs.keys())
        vals = ", ".join("?" for _ in kwargs)
        set_clause = ", ".join(f"{k} = ?" for k in kwargs)
        conn.execute(f"UPDATE pods SET {set_clause} WHERE pod_id = ?", list(kwargs.values()) + [pod_id])
    else:
        keys = ["pod_id"] + list(kwargs.keys())
        vals = ["?" for _ in keys]
        conn.execute(f"INSERT INTO pods ({', '.join(keys)}) VALUES ({', '.join(vals)})",
                     [pod_id] + list(kwargs.values()))
    conn.commit()
    conn.close()

def _all_pods() -> list[dict]:
    conn = _db()
    rows = conn.execute("SELECT * FROM pods ORDER BY pod_id").fetchall()
    conn.close()
    return [dict(r) for r in rows]

# ---------------------------------------------------------------------------
# MCP Tools - POD Lifecycle
# ---------------------------------------------------------------------------

@mcp.tool()
def pod_claim(pod_id: str, proctor: str = "") -> str:
    """Claim a POD for preparation. Creates state record if new."""
    _upsert_pod(pod_id, status="claimed", proctor=proctor)
    return f"POD {pod_id} claimed by {proctor or 'unknown'}"

@mcp.tool()
def pod_get_status(pod_id: str) -> str:
    """Get full status of a POD."""
    pod = _get_pod(pod_id)
    if not pod:
        return f"No POD {pod_id} found"
    return json.dumps(pod, indent=2, default=str)

@mcp.tool()
def pod_list_all() -> str:
    """List all PODs and their overall status."""
    pods = _all_pods()
    if not pods:
        return "No PODs recorded yet."
    rows = []
    for p in pods:
        ok_flags = [p.get("border_spine_ok"), p.get("leaf1_ok"), p.get("leaf2_ok"),
                    p.get("sdwan_online"), p.get("cdftd_registered")]
        green = sum(1 for f in ok_flags if f == "yes")
        total = len(ok_flags)
        rows.append(f"{p['pod_id']:12s}  {p['status']:10s}  [{green}/{total}]  {p.get('notes','')}")
    return "POD ID        Status     Ready\n" + "\n".join(rows)

# ---------------------------------------------------------------------------
# MCP Tools - Secure Router
# ---------------------------------------------------------------------------

def _build_router_base_config(site_id: str, hostname: str = "BRANCH-SEC-RTR") -> str:
    return f"""!
hostname {hostname}
!
ip domain name corp.pseudoco.com
!
enable secret C1sco12345
aaa new-model
username admin privilege 15 password C1sco12345
!
interface TwoGigabitEthernet0/0/6
 ip address 198.18.4.14 255.255.255.0
 no shutdown
!
interface GigabitEthernet0
 vrf forwarding Mgmt-intf
 ip address 198.18.133.25 255.255.192.0
 negotiation auto
 no shutdown
!
ip ftp source-interface GigabitEthernet0
ip tftp source-interface GigabitEthernet0
ip route 0.0.0.0 0.0.0.0 198.18.4.1
ip route vrf Mgmt-intf 0.0.0.0 0.0.0.0 198.18.128.1
!
line vty 0 4
 login authentication default
 transport input ssh
!
exit
!
crypto key generate rsa modulus 2048
!
end
!"""

@mcp.tool()
def router_get_base_config(site_id: str = "105") -> str:
    """Generate the base configuration for the Secure Router (C8231-G2)."""
    return _build_router_base_config(site_id)

@mcp.tool()
def router_verify_serial_from_inventory(inventory_text: str) -> str:
    """Parse 'show inventory' output and return the chassis serial number.
    
    Args:
        inventory_text: The full output of 'show inventory'
    """
    for line in inventory_text.splitlines():
        if "Cisco C8231-G2 Chassis" in line or "C8231-G2" in line:
            parts = line.split()
            for i, p in enumerate(parts):
                if "FCH" in p or "FCW" in p or len(p) > 8 and p.isascii() and not p.startswith("C"):
                    return p.strip()
    return "SERIAL_NOT_FOUND"

@mcp.tool()
def router_bootstrap_config(serial: str, system_ip: str = "100.100.100.105",
                             site_name: str = "SITE_105") -> str:
    """Generate SD-WAN bootstrap config for the router.
    
    Returns the config to be saved as ciscosdwan.cfg and served via TFTP.
    """
    return f"""!
! Bootstrap config for {serial} / {site_name}
! Generated by POD Automator
!
system-ip {system_ip}
site-id {site_name.replace('SITE_', '')}
!
sdwan
 interface GigabitEthernet0/0/0
  tunnel-interface
   encapsulation ipsec
   color public-internet
   no allow-route-service
!
vmanage-connection
 host 198.18.5.101 port 12346
!
!"""

# ---------------------------------------------------------------------------
# MCP Tools - Switch Verification
# ---------------------------------------------------------------------------

def _check_show_ver(show_ver: str) -> tuple[bool, str]:
    """Check code version is 17.12.x"""
    for line in show_ver.splitlines():
        if "Version" in line and ("17.12" in line or "17.12" in line):
            ver = line.strip()
            return True, ver
    return False, "Version not found or not 17.12.x"

def _check_show_vrf(show_vrf: str) -> tuple[bool, str]:
    """Only Mgmt-vrf should exist."""
    vrfs = [l.strip() for l in show_vrf.splitlines() if l.strip() and not l.startswith("Name") and "VRF" not in l]
    # Filter out header lines
    non_mgmt = [v for v in vrfs if "Mgmt" not in v and v and not v.startswith("-")]
    if not non_mgmt:
        return True, "Only Mgmt-vrf present"
    return False, f"Extra VRFs found: {non_mgmt}"

def _check_show_vlan(show_vlan: str) -> tuple[bool, str]:
    """Only default VLANs (1) and possibly VLAN 5 (spine only)."""
    extra = []
    for line in show_vlan.splitlines():
        parts = line.split()
        if parts and parts[0].isdigit():
            vlan_id = int(parts[0])
            if vlan_id not in (1, 5):
                extra.append(str(vlan_id))
    if not extra:
        return True, "VLANs OK (only 1/5)"
    return False, f"Extra VLANs found: {', '.join(extra)}"

@mcp.tool()
def switch_verify(hostname: str, show_version: str, show_vrf: str,
                  show_vlan: str, show_ospf: str = "") -> str:
    """Verify a switch is properly configured.
    
    Args:
        hostname: Switch hostname (e.g., Site_105-Border-Spine, Site_105-Leaf1)
        show_version: Output of 'show version'
        show_vrf: Output of 'show vrf'
        show_vlan: Output of 'show vlan brief'
        show_ospf: Output of 'show ip ospf neighbor' (required for Border Spine)
    """
    results = []
    
    ver_ok, ver_msg = _check_show_ver(show_version)
    results.append(f"VERSION: {'PASS' if ver_ok else 'FAIL'} - {ver_msg}")
    
    vrf_ok, vrf_msg = _check_show_vrf(show_vrf)
    results.append(f"VRF:    {'PASS' if vrf_ok else 'FAIL'} - {vrf_msg}")
    
    vlan_ok, vlan_msg = _check_show_vlan(show_vlan)
    results.append(f"VLAN:   {'PASS' if vlan_ok else 'FAIL'} - {vlan_msg}")
    
    if "spine" in hostname.lower() or "border" in hostname.lower():
        if show_ospf:
            neighbor_count = show_ospf.count("FULL")
            ospf_ok = neighbor_count >= 2
            results.append(f"OSPF:   {'PASS' if ospf_ok else 'FAIL'} - {neighbor_count} neighbors (need 2+)")
        else:
            results.append("OSPF:   SKIP - no ospf neighbor output provided")
    
    overall = all("PASS" in r for r in results if "SKIP" not in r)
    results.insert(0, f"OVERALL: {'PASS' if overall else 'FAIL'} for {hostname}")
    return "\n".join(results)

# ---------------------------------------------------------------------------
# MCP Tools - SD-WAN Manager Steps
# ---------------------------------------------------------------------------

@mcp.tool()
def sdwan_upload_wan_edge_list_html(serial: str, system_ip: str = "100.100.100.105",
                                     site_name: str = "SITE_105",
                                     site_id: str = "105") -> str:
    """Generate the CSV content for 'Upload WAN Edge List' in SD-WAN Manager.
    Returns CSV that can be saved and uploaded.
    """
    output = io.StringIO()
    w = csv.writer(output)
    w.writerow(["serial", "system-ip", "hostname", "site-id", "latitude", "longitude"])
    w.writerow([serial, system_ip, f"BRANCH-SEC-RTR-{site_id}", site_id, "", ""])
    return output.getvalue()

@mcp.tool()
def sdwan_onboard_steps(serial: str, system_ip: str = "100.100.100.105",
                         site_name: str = "SITE_105") -> str:
    """Return the ordered steps to onboard a Secure Router to SD-WAN Manager."""
    return f"""SD-WAN Onboarding Steps for {serial}:

1. Navigate to Configuration > Devices > WAN Edges
2. Click 'Add WAN Edges' > 'Upload WAN Edge List'
3. Upload the CSV (use sdwan_upload_wan_edge_list_html tool)
4. Click 'Skip for now' > 'Next'
5. Search for serial: {serial}
6. Select router > 'Next'
7. Enter:
   - System-IP: {system_ip}
   - Site Name: {site_name}
8. Click 'Apply' > 'Next' > 'Next' > 'Onboard'

License:
9. Administration > License Management
10. 'Assign Licenses' > 'Catalyst/DNA Licenses'
11. Select router > 'Next'
12. Change Denmark_PNP_LAB VA: 0, CWA SDWAN VA: 1
13. Save > 'Next' > 'Next'

Deploy Config Group:
14. Configuration > Configuration Groups > PseudocoBranches
15. 'Add' under Deployment > Associated
16. Search '{site_name.replace("SITE_", "")}' > Select > 'Save'
17. 'Deploy' > Select router > 'Next'
18. Click 'Import' > select PseudocoBranches_Config-Group-Template.csv
19. 'Next' > 'Deploy'
20. Verify: 'Done - Scheduled'

Bootstrap:
21. Configuration > Devices > WAN Edges > search router
22. Ellipsis > 'Generate Bootstrap Configuration' > 'OK'
23. Download the .cfg file
24. Rename to ciscosdwan.cfg
25. Copy to TFTP-ROOT directory on Jump Host
26. Start TFTP32 server

On Router Console:
27. copy tftp://198.18.133.36/ciscosdwan.cfg flash:
28. wr
29. controller-mode enable
"""

# ---------------------------------------------------------------------------
# MCP Tools - SCC / cdFMC
# ---------------------------------------------------------------------------

@mcp.tool()
def scc_verify_terraform_logs(log_text: str) -> str:
    """Check Terraform automation logs for successful deployment.
    
    Args:
        log_text: Output from 'tail -f terraform.tasks.logs' or 'cat terraform.tasks.logs'
    """
    if "Full Infrastructure deployment" in log_text or "Apply complete" in log_text:
        return "PASS - cdFMC automation deployed successfully"
    if "Error" in log_text or "FAIL" in log_text:
        return f"FAIL - Errors found. Run manual reset: ./cli.py reset && ./cli.py deploy"
    return "INCONCLUSIVE - Check logs manually"

@mcp.tool()
def scc_manual_reset_steps() -> str:
    """Steps to manually reset cdFMC automation."""
    return """Manual Automation Reset:
1. WebRDP to Terraform-Automation workstation on topology
2. Launch Terminal
3. cd Documents/elevateLab
4. ./cli.py reset (wait for completion)
5. ./cli.py deploy (15 min - wait for success)
6. Verify: cat terraform.tasks.logs | grep "Full Infrastructure deployment"
7. Log into SCC > Firewall > Security Devices
8. Verify FTD is 'Online'"""

# ---------------------------------------------------------------------------
# MCP Tools - AD Verification
# ---------------------------------------------------------------------------

@mcp.tool()
def ad_verify_users(duo_tile_text: str, ad_user_props: dict) -> str:
    """Verify AD user emails match Duo tile.
    
    Args:
        duo_tile_text: The email addresses from the Duo tile
        ad_user_props: Dict mapping usernames to their AD properties
    """
    results = []
    expected = [email.strip() for email in duo_tile_text.replace("\n", ",").split(",") if "@" in email]
    for user in ["Kit", "Lee", "Pat", "Nik"]:
        if user in ad_user_props:
            email = ad_user_props[user].get("email", "")
            if email in expected:
                results.append(f"{user}: PASS ({email})")
            else:
                results.append(f"{user}: FAIL - email {email} not in Duo tile: {expected}")
        else:
            results.append(f"{user}: NOT FOUND in AD")
    return "\n".join(results)

# ---------------------------------------------------------------------------
# MCP Tools - POD Report / Export
# ---------------------------------------------------------------------------

@mcp.tool()
def pod_export_csv() -> str:
    """Export all POD status to CSV format."""
    pods = _all_pods()
    if not pods:
        return "No PODs"
    output = io.StringIO()
    if pods:
        w = csv.DictWriter(output, fieldnames=pods[0].keys())
        w.writeheader()
        w.writerows(pods)
    return output.getvalue()

@mcp.tool()
def pod_summary() -> str:
    """Return a summary of ALL POD preparation status."""
    pods = _all_pods()
    if not pods:
        return "No PODs tracked yet."
    
    total = len(pods)
    ready = sum(1 for p in pods if all([
        p.get("border_spine_ok") == "yes",
        p.get("leaf1_ok") == "yes",
        p.get("leaf2_ok") == "yes",
        p.get("sdwan_online") == "yes",
        p.get("cdftd_registered") == "yes",
    ]))
    needs_help = total - ready
    
    lines = [f"=== POD PREP SUMMARY ===",
             f"Total PODs: {total}",
             f"Ready:      {ready}",
             f"Needs Help: {needs_help}",
             ""]
    
    for p in pods:
        checks = []
        checks.append("C" if p.get("border_spine_ok") == "yes" else "c")
        checks.append("L1" if p.get("leaf1_ok") == "yes" else "l1")
        checks.append("L2" if p.get("leaf2_ok") == "yes" else "l2")
        checks.append("SDW" if p.get("sdwan_online") == "yes" else "sdw")
        checks.append("FW" if p.get("cdftd_registered") == "yes" else "fw")
        status = " ".join(checks)
        lines.append(f"  {p['pod_id']:12s} [{p['status']:10s}] {status}")
    
    return "\n".join(lines)

# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
