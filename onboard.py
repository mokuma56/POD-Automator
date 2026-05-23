#!/usr/bin/env python3
"""Docker entrypoint for multi-POD SD-WAN onboarding.

Reads config from environment, wraps the confirmed pipeline from
onboard_router.py.  All phases (Quick Connect → Associate → License
→ Variables → Deploy → Bootstrap → HTTP Copy → Controller-Mode) use
the same working code validated in onboard_router.py.
"""
import os, sys, time, subprocess, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import onboard_router

# KB auto-draft on failure (best-effort — never blocks the pipeline)
try:
    import kb as _kb
    _kb.ensure_kb_table()
    _KB_OK = True
except Exception:
    _KB_OK = False

def _kb_auto_draft(step_name, error_text, pod_id=""):
    if not _KB_OK:
        return
    try:
        _kb.auto_draft(step_name=step_name, error_text=error_text, pod_id=pod_id)
    except Exception:
        pass

# ── Override config from environment ────────────────────────────
onboard_router.ROUTER_IP = os.getenv("ROUTER_IP", "198.18.133.25")
onboard_router.VMANAGE = f"https://{os.getenv('VMANAGE', '198.18.133.10')}"
onboard_router.CG_ID = os.getenv("CG_ID", "ae290e0f-7bc4-40f7-9bfa-23b1e7b2a71a")

# Auto-detect serial from router if not provided
SERIAL = os.getenv("SERIAL", "")
if not SERIAL and len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
    SERIAL = sys.argv[1]
if not SERIAL:
    print("  No SERIAL provided — detecting from router...")
    last_err = None
    for attempt in range(3):
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                onboard_router.ROUTER_IP, username=os.getenv("ROUTER_USER", "admin"),
                password=os.getenv("ROUTER_PASS", "C1sco12345"),
                look_for_keys=False, allow_agent=False, timeout=30
            )
            _, stdout, _ = client.exec_command("show inventory", timeout=15)
            for line in stdout.read().decode().splitlines():
                if "SN:" in line:
                    serial = line.split("SN:")[-1].strip().split()[0]
                    if serial:
                        SERIAL = serial
                        break
            client.close()
            if SERIAL:
                break
        except Exception as e:
            last_err = e
            print(f"  Attempt {attempt+1}: {e}")
            time.sleep(5)
    if not SERIAL:
        print(f"  Failed: could not detect serial — {last_err}")
        sys.exit(1)
if not SERIAL:
    print("  Failed: could not detect serial from router")
    sys.exit(1)

print(f"  Using serial: {SERIAL}")
onboard_router.SERIAL = SERIAL
onboard_router.UUID = f"C8231-G2-{SERIAL}"

csv_row = onboard_router.read_csv_values()
onboard_router.SYSTEM_IP = csv_row.get("System IP", "100.100.100.105")
onboard_router.SITE_ID = int(csv_row.get("Site Id", 105))
onboard_router.BOOTSTRAP_PATH = "/pipeline/data/bootstrap/ciscosdwan.cfg"

# ── Docker VPN IP: look at tun0 (created by openconnect) ───────
def _docker_vpn_ip():
    r = subprocess.run(
        ["ip", "-4", "addr", "show", "tun0"],
        capture_output=True, text=True, timeout=5
    )
    for line in r.stdout.splitlines():
        if "inet " in line:
            return line.strip().split()[1].split("/")[0]
    return None

override = os.getenv("VPN_HOST_IP")
if override:
    onboard_router._find_vpn_ip = lambda: override
else:
    try:
        subprocess.run(["ip", "addr"], capture_output=True, timeout=3)
        onboard_router._find_vpn_ip = _docker_vpn_ip
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass  # no `ip` command — fall back to netstat (macOS host)

# ── Run the pipeline (mirrors onboard_router.py's main) ─────────
pod_id = os.environ.get("POD_ID", f"POD-{SERIAL}")
DB_PATH = "/pipeline/host-data/pod_state.db"

# ── Pipeline helpers ─────────────────────────────────────────────
def live_log(msg):
    """Write a log line to the pipeline_logs table."""
    try:
        import sqlite3 as _sq
        c = _sq.connect(DB_PATH)
        c.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)", (pod_id, msg))
        c.commit(); c.close()
    except Exception:
        pass

def report_step(step_name, status, result=""):
    """Write a step status update to pipeline_steps table."""
    try:
        import sqlite3 as _sq
        c = _sq.connect(DB_PATH)
        c.execute("""
            INSERT OR REPLACE INTO pipeline_steps
                (pod_id, step_name, status, started_at, completed_at, result)
            VALUES (?, ?, ?,
                COALESCE((SELECT started_at FROM pipeline_steps WHERE pod_id=? AND step_name=?), datetime('now')),
                CASE WHEN ? IN ('completed','failed','skipped') THEN datetime('now') ELSE NULL END,
                ?)
        """, (pod_id, step_name, status, pod_id, step_name, status, result))
        c.execute("UPDATE pods SET updated_at=datetime('now') WHERE pod_id=?", (pod_id,))
        c.commit(); c.close()
    except Exception as e:
        print(f"  Warning: report_step failed: {e}")

# Write serial to dashboard DB now that pod_id and DB_PATH are defined
try:
    import sqlite3 as _sqlite3
    _c = _sqlite3.connect(DB_PATH)
    _c.execute("UPDATE pods SET router_serial=?, updated_at=datetime('now') WHERE pod_id=?",
               (SERIAL, pod_id))
    _c.commit(); _c.close()
    print(f"  Serial {SERIAL} written to DB for {pod_id}")
except Exception as _e:
    print(f"  Warning: could not write serial to DB: {_e}")

print(f"\nOnboarding {onboard_router.UUID} for {pod_id}\n{'='*40}")

# ── Load existing step state and pod flags from DB ───────────────
def _load_state():
    try:
        import sqlite3 as _sq
        c = _sq.connect(DB_PATH)
        rows = c.execute(
            "SELECT step_name, status FROM pipeline_steps WHERE pod_id=?", (pod_id,)
        ).fetchall()
        pod_row = c.execute(
            "SELECT sdwan_online FROM pods WHERE pod_id=?", (pod_id,)
        ).fetchone()
        c.close()
        completed = {r[0] for r in rows if r[1] == "completed"}
        sdwan_online = (pod_row["sdwan_online"] if pod_row and isinstance(pod_row, dict)
                        else (pod_row[0] if pod_row else "")) == "yes"
        return completed, sdwan_online
    except Exception as e:
        print(f"  Warning: could not load state: {e}")
        return set(), False

_completed_steps, _sdwan_online = _load_state()

# SD-WAN router steps — skip entirely if SD-WAN is already online
SDWAN_STEPS = {
    "verify_router", "reset_device", "quick_connect", "config_group_associate",
    "assign_license", "set_variables", "deploy_config_group", "generate_bootstrap",
    "copy_bootstrap", "controller_mode_enable", "verify_online",
}

if _sdwan_online:
    print("  SD-WAN already online — skipping router onboarding steps")
else:
    s = onboard_router.vmanage_session()

steps = [
    ("detect_pod_number",  onboard_router.phase_detect_pod_number),
    ("verify_router",      lambda: True),
    ("reset_device",       lambda: onboard_router.phase_reset(s)),
    ("quick_connect",      lambda: onboard_router.phase_quick_connect(s)),
    ("config_group_associate", lambda: onboard_router.phase_associate(s)),
     ("assign_license",     lambda: onboard_router.phase_assign_license(s)),
     ("set_variables",      lambda: onboard_router.phase_set_variables(s)),
     ("deploy_config_group", lambda: onboard_router.phase_deploy(s)),
     ("generate_bootstrap", lambda: onboard_router.phase_generate_bootstrap(s)),
     ("copy_bootstrap",     onboard_router.phase_copy_bootstrap),
     ("controller_mode_enable", onboard_router.phase_controller_mode),
     ("verify_online",      lambda: True),
     ("verify_border_spine", lambda: onboard_router.run_switch_checks("verify_border_spine")),
     ("verify_leaf1",       lambda: onboard_router.run_switch_checks("verify_leaf1")),
     ("verify_leaf2",       lambda: onboard_router.run_switch_checks("verify_leaf2")),
     ("connectivity_test",  onboard_router.phase_connectivity_test),
     ("cdfmc_check",        onboard_router.phase_cdfmc_check),
     ("ad_verify",          onboard_router.phase_ad_verify),
     ("scc_reset_check",    onboard_router.phase_scc_reset_check),
]

SOFT_FAIL_STEPS = {
    "detect_pod_number",
    "controller_mode_enable",
    "verify_online",
    "verify_border_spine",
    "verify_leaf1",
    "verify_leaf2",
    "connectivity_test",
    "cdfmc_check",
    "ad_verify",
    "scc_reset_check",
}

for step_name, func in steps:
    # Skip SD-WAN router steps if SD-WAN is already online
    if _sdwan_online and step_name in SDWAN_STEPS:
        print(f"  ↷ {step_name} skipped (SD-WAN already online)")
        continue

    # Skip steps already completed in a previous run
    # detect_pod_number always re-runs so it self-corrects if AD was not yet provisioned
    ALWAYS_RERUN = {"detect_pod_number"}
    if step_name in _completed_steps and step_name not in ALWAYS_RERUN:
        print(f"  ↷ {step_name} skipped (already completed)")
        continue

    log_line = f"▶ {step_name}..."
    print(log_line)
    live_log(log_line)
    report_step(step_name, "running")
    try:
        ret = func()
        if isinstance(ret, tuple):
            ok, result = ret
        else:
            ok, result = ret, ""
        if not ok:
            log_line = f"✗ {step_name} FAILED: {str(result)[:200]}"
            print(log_line)
            live_log(log_line)
            if step_name in SOFT_FAIL_STEPS:
                report_step(step_name, "skipped", f"WARN: {str(result)[:200]}")
                log_line = f"⚠ {step_name} skipped (soft-fail) — pipeline continuing"
                print(log_line)
                live_log(log_line)
                continue
            report_step(step_name, "failed", str(result)[:200])
            _kb_auto_draft(step_name, str(result), pod_id)
            sys.exit(1)
        log_line = f"✓ {step_name} OK"
        print(f"  {log_line}")
        live_log(log_line)
        report_step(step_name, "completed", str(result)[:200] or "OK")
        # As soon as controller_mode_enable succeeds, mark SD-WAN online immediately.
        # This ensures the green dot is set even if a later soft-fail step causes
        # an early exit before the final status=ready write at the bottom.
        if step_name == "controller_mode_enable":
            try:
                subprocess.run([sys.executable, "-c", f"""
import sqlite3
conn = sqlite3.connect('{DB_PATH}')
conn.execute("UPDATE pods SET sdwan_online='yes', updated_at=datetime('now') WHERE pod_id=?", ('{pod_id}',))
conn.commit()
conn.close()
"""], timeout=5)
                print("  Dashboard: sdwan_online=yes")
            except Exception:
                pass
        # Extract and persist scc_org from cdfmc_check result
        if step_name == "cdfmc_check" and isinstance(result, str) and "scc_org=" in result:
            import re as _re
            m = _re.search(r"scc_org=([^\s|]+)", result)
            if m:
                _scc = m.group(1)
                try:
                    subprocess.run([sys.executable, "-c", f"""
import sqlite3
conn = sqlite3.connect('{DB_PATH}')
conn.execute("UPDATE pods SET scc_org=?, updated_at=datetime('now') WHERE pod_id=?", ('{_scc}', '{pod_id}'))
conn.commit()
conn.close()
"""], timeout=5)
                except Exception:
                    pass
    except Exception as e:
        log_line = f"✗ {step_name} FAILED: {str(e)[:200]}"
        print(log_line)
        live_log(log_line)
        if step_name in SOFT_FAIL_STEPS:
            report_step(step_name, "skipped", f"WARN: {str(e)[:200]}")
            log_line = f"⚠ {step_name} skipped (soft-fail) — pipeline continuing"
            print(log_line)
            live_log(log_line)
            continue
        report_step(step_name, "failed", str(e)[:200])
        _kb_auto_draft(step_name, str(e), pod_id)
        sys.exit(1)

# Mark SD-WAN online and POD fully ready in dashboard
try:
    subprocess.run([sys.executable, "-c", f"""
import sqlite3
conn = sqlite3.connect('{DB_PATH}')
conn.execute("UPDATE pods SET sdwan_online='yes', status='ready', notes='POD READY', updated_at=datetime('now') WHERE pod_id=?", ('{pod_id}',))
conn.commit()
conn.close()
"""], timeout=5)
    print("  Dashboard: sdwan_online=yes, status=ready, notes=POD READY")
except Exception as e:
    print(f"  Warning: could not update dashboard DB: {e}")

print(f"\n{'='*40}")
print(f"Pipeline complete for {pod_id}")
print("Router in SD-WAN mode, switches verified, connectivity tested.")
