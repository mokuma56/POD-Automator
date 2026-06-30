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
# MCP Tools - Catalyst Center Template Authoring (CATC-TEMPLATE-RAG)
# ---------------------------------------------------------------------------

# Platform invariants baked in so the LLM can validate without fetching the corpus.
_JINJA2_FORBIDDEN = [
    ("{% break %}", "loopcontrols not enabled — restructure with {% if %} guard"),
    ("{% continue %}", "loopcontrols not enabled — restructure with {% if %} guard"),
    ("{%- break", "loopcontrols not enabled"),
    ("{%- continue", "loopcontrols not enabled"),
]
_VELOCITY_FORBIDDEN = [
    ("#include(", "#include is disabled — use composite templates instead"),
    ("#parse(", "#parse is disabled — use composite templates instead"),
    ("#evaluate(", "#evaluate is not exposed in Catalyst Center"),
    ("#define(", "#define is not exposed in Catalyst Center"),
]
_COMMON_LINT = [
    ("! This", "WARNING: '! ...' is forwarded as IOS CLI, not a template comment"),
    ("! this", "WARNING: '! ...' is forwarded as IOS CLI, not a template comment"),
]

_JINJA2_PLATFORM_LIMITS = """Jinja2 Platform Limits (Catalyst Center):
1. PnP templates cannot use bind variables or __* system variables.
2. Composite templates are DayN-only (never PnP).
3. No {% break %} / {% continue %} — loopcontrols extension is OFF.
4. Undefined variables render as "" (non-strict mode) — guard with 'is defined'.
5. String concatenation uses ~ not + (+ on strings is arithmetic).
6. Bind values always arrive as strings — cast with | int for arithmetic.
7. split filter is CatC-provided (not stock Jinja2): {{ val | split(",") }}
8. {% include %} / {% extends %} / {% import %} ARE supported (resolve into Template Editor project tree).
9. {% do list.append(x) %} works — do extension IS enabled.
10. No filesystem/HTTP access, no shell-out, no interactive prompts from a template.
11. No template-to-template state sharing (no cross-template variables).
12. No regex replace/match — use replace/split/in or EEM.
13. Templates cannot create or modify CatC objects (API orchestration is external)."""

_VELOCITY_PLATFORM_LIMITS = """Velocity Platform Limits (Catalyst Center):
1. #include and #parse are DISABLED — no cross-template inclusion.
2. #stop halts rendering but partial output is still sent to device (not a safe abort).
3. Macros must be defined before first use and at the TOP LEVEL (not inside #if/#foreach).
4. String interpolation only inside double quotes: "Hello $name" (not 'Hello $name').
5. No + operator for strings — use adjacency: "${x}${y}".
6. Bind variables arrive as strings — cast with .parseInt() before arithmetic.
7. In non-strict mode, undefined $ref renders literally as "$ref" (not empty).
8. No global macro library — macros visible only within the template that defines them.
9. PnP templates cannot use bind variables or $__* system variables.
10. Composite templates are DayN-only.
11. No filesystem access, no HTTP fetch, no interactive prompts.
12. #evaluate, #define not exposed in Catalyst Center."""

@mcp.tool()
def catc_template_validate(engine: str, template_text: str) -> str:
    """Validate a Catalyst Center template (Jinja2 or Velocity) against platform constraints.

    Checks for forbidden directives, common mistakes, and platform-specific violations.
    Does NOT check general syntax correctness — use Catalyst Center's Template Editor for that.

    Args:
        engine: "jinja2" or "velocity"
        template_text: The template code to validate
    """
    engine = engine.lower().strip()
    if engine not in ("jinja2", "velocity"):
        return "ERROR: engine must be 'jinja2' or 'velocity'"

    issues = []
    warnings = []

    # Common checks (both engines)
    lines = template_text.splitlines()
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        for pattern, msg in _COMMON_LINT:
            if stripped.startswith(pattern.split()[0]) and "start-ignore-compliance" not in line and "end-ignore-compliance" not in line:
                if stripped.startswith("!") and not stripped.startswith("! @"):
                    warnings.append(f"  Line {i}: {msg}")
                    break

    if engine == "jinja2":
        for pattern, msg in _JINJA2_FORBIDDEN:
            if pattern in template_text:
                issues.append(f"  FORBIDDEN: '{pattern}' — {msg}")
        # Check for + on strings (heuristic: string literal + variable)
        import re
        if re.search(r'"[^"]*"\s*\+|\'[^\']*\'\s*\+|\}\}\s*~?\s*\+', template_text):
            warnings.append("  POSSIBLE: '+' used for string concat — use '~' in Jinja2")
        # PnP + system variable check (heuristic — can't know template type)
        if "__device" in template_text or "__interface" in template_text:
            warnings.append("  INFO: System variables (__device, __interface) require DayN template type — not available in PnP.")
        if "{% break %}" in template_text or "{% continue %}" in template_text:
            issues.append("  FORBIDDEN: loop control break/continue is not available in Catalyst Center Jinja2.")

    elif engine == "velocity":
        for pattern, msg in _VELOCITY_FORBIDDEN:
            if pattern in template_text:
                issues.append(f"  FORBIDDEN: '{pattern}' — {msg}")
        # Check single-quote interpolation (heuristic)
        import re
        sq_refs = re.findall(r"'[^']*\$[A-Za-z_][^']*'", template_text)
        if sq_refs:
            warnings.append(f"  POSSIBLE: {len(sq_refs)} single-quoted string(s) with $ ref — interpolation only works in double quotes.")
        if "$__device" in template_text or "$__interface" in template_text:
            warnings.append("  INFO: System variables ($__device, $__interface) require DayN template type — not available in PnP.")

    result_parts = []
    if issues:
        result_parts.append(f"VALIDATION FAILED ({len(issues)} issue(s)):\n" + "\n".join(issues))
    if warnings:
        result_parts.append(f"WARNINGS ({len(warnings)}):\n" + "\n".join(warnings))
    if not issues and not warnings:
        result_parts.append("VALIDATION PASSED — no forbidden patterns detected.")
    result_parts.append(f"\nPlatform limits for {engine}:\n" + (_JINJA2_PLATFORM_LIMITS if engine == "jinja2" else _VELOCITY_PLATFORM_LIMITS))
    return "\n\n".join(result_parts)


@mcp.tool()
def catc_template_describe(topic: str, engine: str = "shared") -> str:
    """Return authoritative rules for a CatC template authoring topic.

    Use this to look up platform-specific facts before writing or reviewing a template.

    Args:
        engine: "jinja2", "velocity", or "shared"
        topic: One of: constraints, variables, system-variables, includes, macros,
               platform-limits, whitespace, filters, cc-vs-ansible, pnp-vs-dayn,
               composite, eem, markers, common-mistakes
    """
    topic = topic.lower().replace("-", "_").replace(" ", "_")
    engine = engine.lower().strip()

    topics = {
        "constraints": {
            "jinja2": """Jinja2 Constraints Summary:
- Delimiters: {{ expr }}, {% stmt %}, {# comment #}
- ! is NOT a comment — forwarded as IOS CLI. Use {# … #}.
- String concat: use ~ not + (+ is arithmetic)
- Undefined variables render as "" (non-strict). Guard with 'is defined'.
- {% break %} / {% continue %} unavailable (loopcontrols OFF).
- {% do list.append(x) %} works (do extension enabled).
- {% include %} / {% extends %} / {% import %} supported.
- Bind values arrive as strings — cast with | int.
- CC extras: && || ! accepted; split filter provided; .contains() accepted.
- Corpus: github.com/kebaldwi/CATC-TEMPLATE-RAG rules/jinja2/constraints.md""",
            "velocity": """Velocity Constraints Summary:
- References: $Switch, ${Switch}, $!Switch (quiet), ${Switch|'default'}
- ## single-line comment, #* … *# multi-line. ! is NOT a comment.
- String concat: adjacency "${x}${y}" — no + for strings.
- Interpolation ONLY in double quotes "Hello $name" (not single).
- #include and #parse DISABLED.
- Macros must be defined before use, at top level.
- #break exits loop; #stop halts (partial output still sent).
- Non-strict: undefined $ref renders literally as "$ref".
- Bind values arrive as strings — cast with .parseInt().
- Corpus: github.com/kebaldwi/CATC-TEMPLATE-RAG rules/velocity/constraints.md""",
        },
        "variables": {
            "shared": """Variable Taxonomy (both engines):
User-input: declared in template, filled via Input Form
  Jinja2: {{ Hostname }}      Velocity: $Hostname
Bind: user-input bound to Inventory/Settings/Profile/Cloud
  Jinja2: {{ ProductID }}     Velocity: $ProductID
  - Bind display type must be 'Single Select' to work.
  - Values always arrive as strings — cast before arithmetic.
System: built-in CatC objects — DayN ONLY (not in PnP)
  Jinja2: {{ __device.platformId }}   Velocity: $__device.platformId
Local: computed in template
  Jinja2: {% set x = … %}    Velocity: #set( $x = … )
Corpus: github.com/kebaldwi/CATC-TEMPLATE-RAG docs/variables.md""",
        },
        "system_variables": {
            "shared": """System Variables (DayN only — not available in PnP):
__device.hostname                __device.platformId
__device.softwareVersion         __device.managementIpAddress
__device.serialNumber            __device.description
__interface[n].portName          __interface[n].description
__interface[n].ipv4Address       __interface[n].ipv4Mask
__interface[n].vlanId            __interface[n].status
__networkSettings.domainName     __networkSettings.ntpServer[0]
__networkSettings.dnsServer[0]   __networkSettings.syslogServer[0]
__credentials.cliCredential.username
__cloudConnect.*                 (Cloud Connect integration)
Corpus: github.com/kebaldwi/CATC-TEMPLATE-RAG docs/system-variables.md""",
        },
        "includes": {
            "jinja2": """Jinja2 include/extends/import — ALL SUPPORTED in Catalyst Center:
{% include "Project/Template.j2" %}        — embeds another template's output
{% extends "Project/Base.j2" %}            — template inheritance
{% block name %}…{% endblock %}            — named override region
{% import "Project/Macros.j2" as m %}      — import macros without rendering
{% from "Project/Macros.j2" import macro %} — selective import

Paths resolve into the Template Editor project tree (not filesystem).
Composite templates assemble multiple .j2 files at the orchestration level.""",
            "velocity": """Velocity include/parse — BOTH DISABLED in Catalyst Center:
#include is not available — no filesystem access.
#parse is not available — cross-template inclusion not supported.

For composition, use:
1. Composite templates (DayN): sequences multiple templates via *-Composite.yml
2. Multiple template attachments on a Network Profile
3. Self-contained macros within a single template""",
        },
        "macros": {
            "jinja2": """Jinja2 Macros:
{% macro access_interface(vlan_number) %}
  switchport mode access
  switchport access vlan {{ vlan_number }}
  spanning-tree portfast
{% endmacro %}

interface GigabitEthernet1/0/1
  {{ access_interface(20) }}

Rules:
- Define before first use (within same template or imported).
- Call with {{ macro_name(args) }} (double braces — macros are expressions).
- Arguments: positional or keyword; right-to-left defaults.
- Use {% call macro() %}body{% endcall %} to pass a body block.""",
            "velocity": """Velocity Macros (Velocimacros):
#macro( access_interface )
  switchport mode access
  switchport access vlan ${data_vlan_number}
  spanning-tree portfast
#end

interface gi1/0/1
  #access_interface()

Rules:
- Define before first use (top level ONLY — not inside #if/#foreach).
- No global macro library — visible only within the defining template.
- Body macros: #@name() body #end; reference as $!bodyContent inside.
- Match argument count to definition.""",
        },
        "platform_limits": {
            "jinja2": _JINJA2_PLATFORM_LIMITS,
            "velocity": _VELOCITY_PLATFORM_LIMITS,
            "shared": _JINJA2_PLATFORM_LIMITS + "\n\n" + _VELOCITY_PLATFORM_LIMITS,
        },
        "filters": {
            "jinja2": """Jinja2 Filters commonly used in Catalyst Center:
{{ ProductID | split(",") }}          — CatC-provided (not stock Jinja2)
{{ ProductID | split(",") | length }} — chain filters
{{ native_bind | int + 10 }}          — cast string to int
{{ name | upper }}                     — uppercase
{{ name | lower }}                     — lowercase
{{ snmpLocation | default('UNKNOWN') }} — fallback value
{{ vlans | join(",") }}               — join list
{{ count | round('ceil') | int }}     — ceiling round
{{ value | replace("old", "new") }}   — substring replace
{{ "Name: %s" | format(host) }}       — printf-style format
{{ value | e }}                        — HTML-escape (rarely needed for IOS)
Note: 'split' is CatC-provided — not in standard Jinja2.""",
        },
        "cc_vs_ansible": {
            "jinja2": """Catalyst Center Jinja2 vs Ansible Jinja2:
Feature                    | CatC Jinja2         | Ansible Jinja2
---------------------------|---------------------|------------------
&& / || / ! operators      | Accepted            | NOT supported
split filter               | Provided            | Not a builtin
.contains() method         | Accepted            | Not standard
do extension               | Enabled             | Off by default
loopcontrols (break/cont.) | Assume OFF          | Often enabled
include/extends            | YES (project tree)  | YES (filesystem)
Undefined mode             | Non-strict (= "")   | Strict (raises error)
String concat              | ~ operator          | ~ operator
__device, __interface      | Provided (DayN)     | Not available
# CC-specific markers      | YES                 | Not applicable

Critical: Templates that work in Ansible may fail in CatC when they
  - Use {% break %} / {% continue %}
  - Rely on undefined variables raising errors (add 'is defined' guards)
  - Assume filesystem-based include paths
Corpus: github.com/kebaldwi/CATC-TEMPLATE-RAG rules/jinja2/cc-vs-ansible.md""",
        },
        "pnp_vs_dayn": {
            "shared": """PnP (Day-0) vs DayN Templates:
PnP (onboarding):
- Device is NOT yet in Inventory when template renders.
- NO bind variables — no access to Inventory/Settings/Profile data.
- NO system variables (__device, __interface, __networkSettings, etc.)
- Use user-input form variables only.
- Compliance engine does NOT evaluate PnP templates.
- CatC injects mandatory PnP CLI (hostname/IP/controller binding) non-overridably.
- Single .j2 or .vm template only — no composites.

DayN (post-onboarding):
- Device IS in Inventory — bind and system variables available.
- Compliance engine evaluates DayN templates.
- Composite templates allowed (sequence multiple templates via *-Composite.yml).
- System variables: __device.*, __interface[n].*, __networkSettings.*, etc.

Common mistake: using {{ __device.hostname }} in a PnP template → renders as "".""",
        },
        "composite": {
            "shared": """Composite Templates:
A *-Composite.yml sequences multiple DayN templates:

name: BGP-EVPN-BUILD
description: "Full EVPN fabric build"
softwareType: IOS-XE
deviceTypes:
  - productFamily: Switches and Hubs
containingTemplates:
  - name: DEFN-VlanInfo        type: TEMPLATE
  - name: BUILD-InterfaceMacros type: TEMPLATE
  - name: FABRIC-BuildBGPEVPN  type: TEMPLATE

Rules:
- DayN ONLY — not valid for PnP.
- Each member template must be committed before assembling the composite.
- Templates execute in containingTemplates order.
- Each template renders independently (no cross-template variable sharing).
- Use {% include %} within Jinja2 OR Composite YAML — not both for same logic.
- Template version UUID (from commit) is needed for provisioning, not template UUID.""",
        },
        "eem": {
            "shared": """EEM (Embedded Event Manager) from a template:
Use EEM when you need runtime device-side logic that templates cannot provide:
- Read current running config
- React to events after provisioning completes
- Auto-naming based on MAC/IP

Pattern (Jinja2):
#MODE_ENABLE
event manager applet AUTO-NAME
 event none
 action 0010 cli command "enable"
 action 0020 cli command "show interfaces GigabitEthernet0/0 | include Hardware"
 action 0030 regexp "address is ([0-9a-f.]+)" "$_cli_result" match mac
 action 0040 cli command "conf t"
 action 0050 cli command "hostname SW-{{ __device.managementIpAddress | replace('.', '-') }}"
 action 0060 cli command "end"
event manager run AUTO-NAME
#MODE_END_ENABLE

Corpus: github.com/kebaldwi/CATC-TEMPLATE-RAG docs/eem.md
Example: examples/jinja2/AutoNaming-EEM-Scripting.j2""",
        },
        "markers": {
            "shared": """Catalyst Center-specific Markers (both engines):
These markers are emitted as literal text and interpreted by the CatC provisioner.

1. MODE_ENABLE — privileged-EXEC execution:
   #MODE_ENABLE
   switch 1 priority 10
   #MODE_END_ENABLE

2. MLTCMD — multi-line CLI bundle (banners, certs, key chains):
   <MLTCMD>banner login ^
     Authorized access only!
   ^</MLTCMD>

3. Compliance ignore:
   ! @ start-ignore-compliance
   no switchport
   ! @ end-ignore-compliance

Note: These are NOT template engine tags — they cannot be wrapped in
{% if %} / #if to conditionally suppress them from the rendered output.""",
        },
        "common_mistakes": {
            "jinja2": """Jinja2 Common Mistakes:
Wrong                                  | Right
---------------------------------------|------------------------------------------
{{ "Hello " + name }}                  | {{ "Hello " ~ name }}
{% break %} in a for loop              | Use {% if %} guard to skip iteration
! This is a comment                    | {# This is a comment #}
{% set x = 0 %} inside for, read after | {% set ns = namespace(x=0) %}; ns.x = …
{% if var %} where var might be 0/"" | {% if var is defined and var %}
{{ __device.hostname }} in PnP         | Use user-input form variable
Bind var in PnP template               | Move to user-input or to DayN
{{ list.append(x) }}                   | {% do list.append(x) %} (no braces)
string + int: {{ count + 1 }}          | {{ count | int + 1 }} (bind is string)""",
            "velocity": """Velocity Common Mistakes:
Wrong                              | Right
-----------------------------------|------------------------------------------
#set( $a = $x + $y ) for strings  | #set( $a = "${x}${y}" )
#include("other.vm")               | Use composite templates
#macro inside #if or #foreach      | Define macros at top level of template
! This is a comment                | ## This is a comment
'Hello $name' expecting interp.    | "Hello $name" (double quotes only)
$__device in a PnP template        | Use user-input form variable
$list.add($x) returns value        | #set( $foo = $list.add($x) ) to discard
#parse("shared.vm")                | Use composite templates instead""",
        },
    }

    # Normalise topic aliases
    aliases = {
        "system_variable": "system_variables",
        "sysvar": "system_variables",
        "variable": "variables",
        "var": "variables",
        "limit": "platform_limits",
        "limits": "platform_limits",
        "filter": "filters",
        "macro": "macros",
        "include": "includes",
        "pnp": "pnp_vs_dayn",
        "dayn": "pnp_vs_dayn",
        "day_n": "pnp_vs_dayn",
        "day0": "pnp_vs_dayn",
        "composite_template": "composite",
        "ansible": "cc_vs_ansible",
        "vs_ansible": "cc_vs_ansible",
        "marker": "markers",
        "mode_enable": "markers",
        "mltcmd": "markers",
        "mistake": "common_mistakes",
        "mistakes": "common_mistakes",
    }
    topic = aliases.get(topic, topic)

    if topic not in topics:
        available = sorted(topics.keys())
        return f"Unknown topic '{topic}'. Available topics: {', '.join(available)}"

    topic_data = topics[topic]
    # Try engine-specific, fall back to shared, then any
    result = topic_data.get(engine) or topic_data.get("shared") or next(iter(topic_data.values()), "No content.")
    return result


@mcp.tool()
def catc_lifecycle_steps(operation: str = "full") -> str:
    """Return ordered Catalyst Center API automation steps (TECOPS-2599 pattern).

    Args:
        operation: "full" (all 8 steps), or one of:
                   hierarchy, settings, credentials, discovery, assign,
                   templates, profile, provision, deploy, task-polling,
                   idempotency, evpn-architecture
    """
    operation = operation.lower().replace("-", "_").replace(" ", "_")

    steps = {
        "full": """Catalyst Center Automation — 8-Step Lifecycle (TECOPS-2599):

Step 1: Site Hierarchy
  POST /dna/intent/api/v1/site (Area → Building → Floor, parent-before-child)

Step 2: Network Settings
  PUT /dna/intent/api/v1/network/{siteId}
  (DNS, NTP, DHCP, SNMP, Syslog, AAA, banner per site)

Step 3: Global Credentials
  POST /dna/intent/api/v1/global-credential (CLI, SNMP v2c R/W, NETCONF)
  POST /dna/intent/api/v1/credential-to-site/{siteId} (assign to site)

Step 4: Device Discovery
  POST /dna/intent/api/v1/discovery (IP-range, credential binding)
  Poll /dna/intent/api/v1/discovery/{id}/network-device

Step 5: Assign to Site
  POST /dna/system/api/v1/site-member-manage/{siteId}

Step 6a: Create/ensure Template Project
  GET/POST /dna/intent/api/v1/template-programmer/project

Step 6b: Create & Commit Member Template
  POST /dna/intent/api/v1/template-programmer/project/{projectId}/template
  POST /dna/intent/api/v1/template-programmer/template/version (commit)

Step 6c: Create & Commit Composite Template
  POST /dna/intent/api/v1/template-programmer/template {composite: true}
  POST /dna/intent/api/v1/template-programmer/template/version

Step 7: Network Profile
  POST /dna/intent/api/v1/network-profile/switching
  PUT  /dna/intent/api/v1/network-profile/switching/{profileId}/site/{siteId}

Step 8a: Provision Device (SDA Day-0)
  POST /dna/intent/api/v1/business/sda/provision-device

Step 8b: Deploy Composite Template (DayN)
  POST /dna/intent/api/v1/template-programmer/template/deploy

Key: All mutating calls are async — always poll /dna/intent/api/v1/task/{taskId}
Corpus: github.com/kebaldwi/TECOPS-2599 Support/Resources/Python/""",

        "hierarchy": """Step 1 — Site Hierarchy:
Endpoint: POST /dna/intent/api/v1/site
Auth: GET token from POST /dna/system/api/v1/auth/token

Order: always create parent before child (Area → Building → Floor)

Area payload:
  {"type": "area", "site": {"area": {"name": "USA", "parentName": "Global"}}}

Building payload:
  {"type": "building", "site": {"building": {
    "name": "HQ", "parentName": "Global/USA",
    "address": "123 Main St", "latitude": 37.4, "longitude": -122.0
  }}}

Floor payload:
  {"type": "floor", "site": {"floor": {
    "name": "Floor 1", "parentName": "Global/USA/HQ",
    "rfModel": "Cubes And Walled Offices", "width": 100, "length": 100, "height": 10
  }}}

Idempotency: GET /dna/intent/api/v1/site?name=<path> first — skip if exists.
Script: Support/Resources/Python/1.0-Cisco-Catalyst-Center-Site-Hierarchy/site_hierarchy.py""",

        "settings": """Step 2 — Network Settings:
Endpoint: PUT /dna/intent/api/v1/network/{siteId}

Payload structure:
{
  "settings": {
    "dnsServer": {"domainName": "corp.example.com", "primaryIpAddress": "8.8.8.8"},
    "syslogServer": {"ipAddresses": ["10.0.0.1"]},
    "snmpServer": {"ipAddresses": ["10.0.0.1"], "configureDnacIP": true},
    "ntpServer": {"ipAddresses": ["pool.ntp.org"]},
    "messageOfTheday": {"bannerMessage": "Authorized access only", "retainExistingBanner": false},
    "netflowcollector": {"ipAddress": "10.0.0.2", "port": 2055},
    "networkAaa": [{"ipAddress": "10.0.0.3", "network": "10.0.0.0", "protocol": "RADIUS",
                    "servers": "AAA", "sharedSecret": "secret"}]
  }
}

Get siteId: GET /dna/intent/api/v1/site?name=<path> → response[0].id
Script: Support/Resources/Python/2.0-Cisco-Catalyst-Center-Settings/network_settings.py""",

        "credentials": """Step 3 — Global Credentials:
Check existing: GET /dna/intent/api/v1/global-credential?credentialSubType=CLI

Create CLI credential:
  POST /dna/intent/api/v1/global-credential
  {"cli": [{"username": "netadmin", "password": "C1sco12345", "enablePassword": "C1sco12345",
             "credentialType": "GLOBAL", "description": "Lab CLI"}]}

Create SNMP v2c (read):
  {"snmpV2cRead": [{"readCommunity": "public", "credentialType": "GLOBAL"}]}

Create SNMP v2c (write):
  {"snmpV2cWrite": [{"writeCommunity": "private", "credentialType": "GLOBAL"}]}

Assign to site:
  POST /dna/intent/api/v1/credential-to-site/{siteId}
  {"cliType": ["<cred-id>"], "snmpV2ReadType": ["<id>"], "snmpV2WriteType": ["<id>"]}

Script: Support/Resources/Python/3.0-Cisco-Catalyst-Center-Credentials/credentials.py""",

        "discovery": """Step 4 — Device Discovery:
Submit: POST /dna/intent/api/v1/discovery
{
  "name": "Lab-Discovery-01",
  "discoveryType": "Range",
  "ipAddressList": "198.18.128.22-198.18.128.24",
  "globalCredentialIdList": ["<cli-cred-id>", "<snmp-read-id>"],
  "cdpLevel": 16,
  "protocolOrder": "ssh,telnet",
  "timeout": 5,
  "retry": 3
}

Poll: GET /dna/intent/api/v1/discovery/{discoveryId}
  → wait for "discoveryCondition": "Complete"

Get devices: GET /dna/intent/api/v1/discovery/{discoveryId}/network-device
  → array of discovered devices with id, managementIpAddress, hostname

Script: Support/Resources/Python/4.0-Cisco-Catalyst-Center-Device-Discovery/device_discovery.py""",

        "templates": """Step 6 — Template Management:
6.1 Authenticate: GET token from /dna/system/api/v1/auth/token

6.2 Create/ensure project (idempotent):
  GET /dna/intent/api/v1/template-programmer/project?name=<name>
  POST /dna/intent/api/v1/template-programmer/project {"name": "MyProject"}
  → poll taskId → returns projectId in task.data

6.3 Create member template:
  POST /dna/intent/api/v1/template-programmer/project/{projectId}/template
  {
    "name": "DEFN-VlanInfo", "language": "JINJA",
    "softwareType": "IOS-XE",
    "deviceTypes": [{"productFamily": "Switches and Hubs"}],
    "templateContent": "{% for v in Vlans %}\\nvlan {{ v }}\\n{% endfor %}"
  }
  Then commit: POST /dna/intent/api/v1/template-programmer/template/version
    {"templateId": "<uuid>", "comments": "initial commit"}
  → response contains versionId (needed for composite + deploy)

6.4 Create composite template:
  POST (same endpoint) with "composite": true and "containingTemplates": [...]
  Then commit same way.

Script: Support/Resources/Python/6.1–6.4/""",

        "provision": """Step 8 — Provision & Deploy:
Provision device to site (SDA Day-0):
  POST /dna/intent/api/v1/business/sda/provision-device
  {"deviceManagementIpAddress": "198.18.128.24", "siteNameHierarchy": "Global/USA/HQ/Floor 1"}
  → returns taskId; poll to completion.

Deploy composite template (DayN):
  POST /dna/intent/api/v1/template-programmer/template/deploy
  {
    "forcePushTemplate": false,
    "templateId": "<compositeVersionedTemplateId>",
    "targetInfo": [{
      "id": "198.18.128.24",
      "type": "MANAGED_DEVICE_IP",
      "params": {"MgmtVlan": "5", "HostName": "SPINE-01"}
    }]
  }
  → returns {"deploymentId": "..."} — poll
    GET /dna/intent/api/v1/template-programmer/template/deploy/status/{deploymentId}

Idempotency: POST creates record for new devices; PUT re-deploys to already-provisioned.
  If POST returns "already provisioned" error → switch to PUT for that device.

Script: Support/Resources/Python/8.0-Cisco-Catalyst-Center-Provision-Deploy-Composite/""",

        "task_polling": """Task Polling Pattern (used after every mutating CatC API call):

CatC returns: {"response": {"taskId": "abc-123", "url": "/dna/intent/api/v1/task/abc-123"}}

Poll until endTime is set:
  GET /dna/intent/api/v1/task/{taskId}
  → {"response": {"id": "...", "startTime": 1234, "endTime": 5678,
                   "isError": false, "data": "...", "failureReason": null}}

Python pattern:
  import time
  def poll_task(session, base, task_id, timeout=120):
      url = f"{base}/dna/intent/api/v1/task/{task_id}"
      deadline = time.time() + timeout
      while time.time() < deadline:
          t = session.get(url).json()["response"]
          if t.get("endTime"):
              if t.get("isError"):
                  raise RuntimeError(t.get("failureReason", str(t)))
              return t
          time.sleep(3)
      raise TimeoutError(f"Task {task_id} timed out")

Typical task timeouts:
  Hierarchy creation: 30s  |  Discovery: 300s  |  Template commit: 30s
  Provision: 300s          |  Template deploy: 120s""",

        "idempotency": """Idempotency Patterns for Catalyst Center:

1. GET-before-POST (safe create):
   Check if resource exists with GET first, only POST if absent.
   Used for: site hierarchy, template projects, credentials.

2. POST-then-PUT for provisioning (CatC quirk):
   POST creates provision record for new devices.
   PUT re-deploys to already-provisioned devices.
   PUT on a never-provisioned device → HTTP 400.
   Pattern:
     try: POST /business/sda/provision-device
     if "alreadyProvisioned" in error: PUT /business/sda/provision-device

3. Per-device loop for batch operations:
   Never send all devices in one batch — if one is already-provisioned,
   CatC returns that error for the whole batch, skipping other devices.
   Loop individually and handle per-device.

4. Template commit check:
   GET /template-programmer/template — if versionId exists, template is committed.
   Only re-commit if templateContent changed.

5. Token refresh:
   JWT tokens expire (~1 hour). Re-authenticate on 401 responses.""",

        "evpn_architecture": """BGP EVPN Template Architecture (TECOPS-2599):

Projects/BGP_EVPN/DayNTemplates/ naming convention:
  DEFN-*    Data definitions (VLANs, VRFs, loopbacks, VNI offsets, overlay, multicast)
  FUNC-*    Reusable function templates (VRF lookup, port logic)
  FABRIC-*  Top-level fabric build templates (include DEFN and FUNC layers)
  BGP-EVPN-BUILD.yml  Composite descriptor (ordering all FABRIC templates)

Template layering example:
  BGP-EVPN-BUILD.yml (composite) sequences:
    → DEFN-VlanInfo.j2         (define VLANs, L3 VNIs)
    → DEFN-OverlayConfig.j2    (define BGP EVPN overlay params)
    → FUNC-VrfLookup.j2        (reusable VRF resolution helper)
    → FABRIC-BuildBGPEVPN.j2   (assemble everything, push to device)

Within Jinja2 templates, use {% include %} to compose:
  {% include "DayNTemplates/DEFN-VlanInfo.j2" %}
  {% include "DayNTemplates/FUNC-VrfLookup.j2" %}

TRADITIONAL path uses BUILD-MasterBuild.j2 as the top-level entry point
that includes all relevant BUILD-* modules for a device class.

Corpus: github.com/kebaldwi/TECOPS-2599 Projects/BGP_EVPN/ and Projects/TRADITIONAL/""",
    }

    aliases = {
        "all": "full",
        "overview": "full",
        "task": "task_polling",
        "polling": "task_polling",
        "async": "task_polling",
        "assign": "discovery",  # assign is part of discovery flow conceptually
        "profile": "provision",
        "deploy": "provision",
        "evpn": "evpn_architecture",
        "architecture": "evpn_architecture",
        "bgp_evpn": "evpn_architecture",
    }
    operation = aliases.get(operation, operation)

    if operation not in steps:
        available = sorted(steps.keys())
        return f"Unknown operation '{operation}'. Available: {', '.join(available)}"
    return steps[operation]


# ---------------------------------------------------------------------------
# Run
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    mcp.run()
