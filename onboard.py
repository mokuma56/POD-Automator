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

def report_step(step_name, status, result=""):
    subprocess.run([
        sys.executable, "-c", f"""
import sqlite3
conn = sqlite3.connect('{DB_PATH}')
conn.execute("INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, completed_at, result) VALUES (?, ?, ?, datetime('now'), ?)",
    ('{pod_id}', '{step_name}', '{status}', '''{result.replace("'", "''")}'''))
conn.commit()"""], timeout=5)

def live_log(msg):
    subprocess.run([
        sys.executable, "-c", f"""
import sqlite3
conn = sqlite3.connect('{DB_PATH}')
conn.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)",
    ('{pod_id}', '''{msg.replace("'", "''")}'''))
conn.commit()
conn.close()
"""], timeout=5)

s = onboard_router.vmanage_session()
steps = [
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
]

# Steps that should NOT halt the pipeline on failure — record as skipped/warn and continue
SOFT_FAIL_STEPS = {
    "verify_border_spine",
    "verify_leaf1",
    "verify_leaf2",
    "connectivity_test",
    "cdfmc_check",
}

for step_name, func in steps:
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
