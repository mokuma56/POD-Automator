"""POD Dashboard — upload events CSV, start pipelines, monitor live progress."""

import sqlite3, json, threading, csv, io, os, time, sys
from pathlib import Path
from queue import Queue
from flask import Flask, render_template_string, jsonify, request

sys.path.insert(0, str(Path.home() / "sw_projects" / "pod_automator"))
import onboard_router

DATA_DIR = Path.home() / "sw_projects" / "pod_automator"
DB_PATH = DATA_DIR / "data" / "pod_state.db"

app = Flask(__name__)

# ---- VPN status check ---- #
def check_pod_vpn(pod_id):
    """Check VPN status for a POD — Docker container first, then host fallback."""
    import subprocess, json
    try:
        # Check if Docker compose stack exists for this POD
        r = subprocess.run(
            ["docker", "compose", "-p", pod_id, "ps", "--format=json"],
            capture_output=True, text=True, timeout=8
        )
        if r.returncode == 0 and r.stdout.strip():
            lines = [l for l in r.stdout.strip().splitlines() if l.strip()]
            for line in lines:
                try:
                    data = json.loads(line)
                    if data.get("Service") == "vpn":
                        state = data.get("Status", data.get("State", ""))
                        health = data.get("Health", "")
                        if health == "healthy":
                            return {"status": "connected", "detail": "Docker VPN healthy"}
                        elif "Up" in state:
                            if health in ("starting", ""):
                                return {"status": "connecting", "detail": "Docker VPN starting"}
                            return {"status": "connected", "detail": "Docker VPN up"}
                        else:
                            return {"status": "disconnected", "detail": f"Docker: {state[:40]}"}
                except json.JSONDecodeError:
                    pass
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Fallback: check host VPN
    try:
        r = subprocess.run(["pgrep", "openconnect"], capture_output=True, text=True, timeout=3)
        if r.returncode != 0:
            return {"status": "disconnected", "detail": "Host VPN down"}
        r = subprocess.run(["ping", "-c", "1", "-W", "2", "198.18.133.10"],
                           capture_output=True, timeout=5)
        if r.returncode == 0:
            return {"status": "connected", "detail": "Host VPN up"}
        return {"status": "connecting", "detail": "Host VPN, waiting for routes"}
    except Exception as e:
        return {"status": "error", "detail": str(e)}

# ---- DB helpers ----
def _db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn

def _migrate():
    conn = _db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pods (
            pod_id TEXT PRIMARY KEY,
            status TEXT DEFAULT 'pending',
            sdwan_online TEXT DEFAULT '',
            device_data TEXT DEFAULT '{}',
            router_serial TEXT DEFAULT '',
            vpn_host TEXT DEFAULT '',
            vpn_user TEXT DEFAULT '',
            vpn_pass TEXT DEFAULT '',
            router_ip TEXT DEFAULT '',
            jump_host TEXT DEFAULT '',
            session_id TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pipeline_steps (
            pod_id TEXT, step_name TEXT, status TEXT, started_at TEXT,
            completed_at TEXT, result TEXT DEFAULT '',
            PRIMARY KEY (pod_id, step_name)
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS pipeline_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pod_id TEXT,
            log_line TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

_migrate()

# ---- Background pipeline runner ----
_runners = {}
_runner_logs = {}

def log(pod_id, msg):
    conn = _db()
    conn.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)", (pod_id, msg))
    conn.commit()
    conn.close()

def clear_logs(pod_id):
    conn = _db()
    conn.execute("DELETE FROM pipeline_logs WHERE pod_id = ?", (pod_id,))
    conn.commit()
    conn.close()

def set_step(pod_id, step_name, status, result=""):
    conn = _db()
    conn.execute("""
        INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, completed_at, result)
        VALUES (?, ?, ?, COALESCE((SELECT started_at FROM pipeline_steps WHERE pod_id=? AND step_name=?), datetime('now')),
                datetime('now'), ?)
    """, (pod_id, step_name, status, pod_id, step_name, result))
    conn.execute("UPDATE pods SET updated_at = datetime('now') WHERE pod_id = ?", (pod_id,))
    conn.commit()
    conn.close()

def get_pod_data(pod_id):
    conn = _db()
    p = conn.execute("SELECT * FROM pods WHERE pod_id = ?", (pod_id,)).fetchone()
    conn.close()
    return dict(p) if p else None

def run_onboard_thread(pod_id):
    try:
        log(pod_id, "Starting pipeline...")
        set_step(pod_id, "verify_router", "running", "Checking connectivity...")
        pod = get_pod_data(pod_id)
        serial = (pod or {}).get("router_serial", "") or "FJC300412NA"
        router_ip = (pod or {}).get("router_ip", "") or "198.18.133.25"
        log(pod_id, f"Router serial: {serial}, IP: {router_ip}")

        # Set module globals for this POD
        onboard_router.SERIAL = serial
        onboard_router.UUID = f"C8231-G2-{serial}"
        onboard_router.ROUTER_IP = router_ip
        log(pod_id, f"Using serial {serial}, UUID {onboard_router.UUID}")

        s = onboard_router.vmanage_session()
        log(pod_id, "vManage session OK")
        set_step(pod_id, "verify_router", "completed", "vManage reachable")

        phases = [
            ("config_group_associate", lambda: onboard_router.phase_associate(s)),
            ("set_variables", lambda: onboard_router.phase_set_variables(s)),
            ("assign_license", lambda: onboard_router.phase_assign_license(s)),
            ("deploy_config_group", lambda: onboard_router.phase_deploy(s)),
            ("generate_bootstrap", lambda: onboard_router.phase_generate_bootstrap(s)),
            ("copy_bootstrap", onboard_router.phase_copy_bootstrap),
            ("controller_mode_enable", onboard_router.phase_controller_mode),
        ]

        for step_name, func in phases:
            log(pod_id, f"Running {step_name}...")
            set_step(pod_id, step_name, "running", "")
            try:
                r = func()
                if r:
                    set_step(pod_id, step_name, "completed", "OK")
                    log(pod_id, f"  {step_name}: OK")
                else:
                    set_step(pod_id, step_name, "failed", "Phase returned False")
                    log(pod_id, f"  {step_name}: FAILED")
                    return
            except Exception as e:
                set_step(pod_id, step_name, "failed", str(e)[:200])
                log(pod_id, f"  {step_name}: ERROR {e}")
                return

        set_step(pod_id, "verify_online", "running", "Router rebooting, waiting...")
        log(pod_id, "Router rebooting into SD-WAN mode")
        conn = _db()
        conn.execute("UPDATE pods SET status='in_progress', sdwan_online='waiting', notes='Router booting SD-WAN mode' WHERE pod_id=?", (pod_id,))
        conn.commit()
        conn.close()

        # Verify switches
        for sw_name in ["verify_border_spine", "verify_leaf1", "verify_leaf2"]:
            log(pod_id, f"Running {sw_name}...")
            set_step(pod_id, sw_name, "running", "")
            try:
                ok, result = onboard_router.run_switch_checks(sw_name)
                if ok:
                    set_step(pod_id, sw_name, "completed", result[:200])
                    log(pod_id, f"  {sw_name}: OK")
                else:
                    set_step(pod_id, sw_name, "failed", result[:200])
                    log(pod_id, f"  {sw_name}: FAILED")
            except Exception as e:
                set_step(pod_id, sw_name, "failed", str(e)[:200])
                log(pod_id, f"  {sw_name}: ERROR {e}")

        # Connectivity test
        log(pod_id, "Running connectivity_test...")
        set_step(pod_id, "connectivity_test", "running", "")
        try:
            ok, result = onboard_router.phase_connectivity_test()
            if ok:
                set_step(pod_id, "connectivity_test", "completed", result[:200])
                log(pod_id, f"  connectivity_test: OK")
            else:
                set_step(pod_id, "connectivity_test", "failed", result[:200])
                log(pod_id, f"  connectivity_test: FAILED")
        except Exception as e:
            set_step(pod_id, "connectivity_test", "failed", str(e)[:200])
            log(pod_id, f"  connectivity_test: ERROR {e}")

        conn = _db()
        conn.execute("UPDATE pods SET status='ready', notes='Pipeline complete' WHERE pod_id=?", (pod_id,))
        conn.commit()
        conn.close()
        log(pod_id, "Pipeline complete")
    except Exception as e:
        log(pod_id, f"Pipeline failed: {e}")
        set_step(pod_id, "pipeline", "failed", str(e)[:200])


# ---- Flask routes ----
@app.route("/")
def index():
    return render_template_string(DASHBOARD_HTML)

@app.route("/api/pods")
def api_pods():
    conn = _db()
    pods = conn.execute("SELECT * FROM pods ORDER BY pod_id").fetchall()
    result = []
    for p in pods:
        p = dict(p)
        try:
            steps = conn.execute(
                "SELECT step_name, status, result FROM pipeline_steps WHERE pod_id = ?",
                (p["pod_id"],)
            ).fetchall()
            for s in steps:
                p[s["step_name"]] = s["status"]
                p[f"{s['step_name']}_result"] = (s["result"] or "")[:80]
        except Exception:
            pass
        # Add per-POD VPN status
        vpn = check_pod_vpn(p["pod_id"])
        p["vpn_status"] = vpn["status"]
        p["vpn_detail"] = vpn["detail"]
        result.append(p)
    conn.close()
    return jsonify(result)

@app.route("/api/pipeline/<pod_id>")
def api_pipeline(pod_id):
    conn = _db()
    try:
        steps = conn.execute(
            "SELECT * FROM pipeline_steps WHERE pod_id = ? ORDER BY rowid",
            (pod_id,)
        ).fetchall()
        result = [dict(s) for s in steps]
    except Exception:
        result = []
    conn.close()
    return jsonify(result)

@app.route("/api/logs/<pod_id>")
def api_logs(pod_id):
    conn = _db()
    logs = conn.execute(
        "SELECT id, log_line, timestamp FROM pipeline_logs WHERE pod_id = ? ORDER BY id",
        (pod_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(l) for l in logs])

SWITCH_CHECKS = {
    "border_spine": {"name": "Border Spine", "checks": [
        "OSPF neighbors (expect 2)",
        "VRF (expect Mgmt-vrf only)",
        "Version (expect 17.12.x)",
        "VLAN (expect default + VLAN 5)",
    ]},
    "leaf1": {"name": "Leaf 1", "checks": [
        "Version (expect 17.12.x)",
        "VRF (expect Mgmt-vrf only)",
        "VLAN (expect default only)",
    ]},
    "leaf2": {"name": "Leaf 2", "checks": [
        "Version (expect 17.12.x)",
        "VRF (expect Mgmt-vrf only)",
        "VLAN (expect default only)",
    ]},
}

@app.route("/api/switches/<pod_id>")
def api_switches(pod_id):
    conn = _db()
    steps = conn.execute(
        "SELECT * FROM pipeline_steps WHERE pod_id = ? AND step_name IN ('verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test') ORDER BY rowid",
        (pod_id,)
    ).fetchall()
    conn.close()

    results = {}
    for s in steps:
        name = s["step_name"]
        result_text = s["result"] or ""
        status = s["status"]
        parts = [p.strip() for p in result_text.split("|")]
        results[name] = {"status": status, "parts": parts}

    switch_data = []
    for key, info in SWITCH_CHECKS.items():
        step_name = f"verify_{key}"
        step = results.get(step_name, {})
        checks = []
        for i, label in enumerate(info["checks"]):
            if step.get("status") == "completed" and i < len(step.get("parts", [])):
                part = step["parts"][i]
                if part.startswith("PASS"):
                    checks.append({"label": label, "status": "pass", "result": part.replace("PASS: ", "")})
                elif part.startswith("FAIL"):
                    checks.append({"label": label, "status": "fail", "result": part.replace("FAIL: ", "")})
                else:
                    checks.append({"label": label, "status": "pass", "result": part})
            elif step.get("status") == "running":
                checks.append({"label": label, "status": "na", "result": "checking..."})
            elif step.get("status") == "failed":
                checks.append({"label": label, "status": "fail", "result": "verification failed"})
            else:
                checks.append({"label": label, "status": "na", "result": "pending"})

        # Add model from step parts if available
        model = ""
        if step.get("parts"):
            for p in step["parts"]:
                if p.startswith("MODEL:"):
                    model = p.replace("MODEL: ", "")
                    break

        switch_data.append({
            "name": info["name"],
            "model": model,
            "host": key,
            "checks": checks,
        })

    # Add connectivity test
    ct = results.get("connectivity_test", {})
    conn_checks = []
    if ct.get("status") == "completed" and ct.get("parts"):
        for p in ct["parts"]:
            if p.startswith("PASS"):
                conn_checks.append({"label": "Ping Catalyst Center", "status": "pass", "result": p.replace("PASS: ", "")})
            elif p.startswith("FAIL"):
                conn_checks.append({"label": "Ping Catalyst Center", "status": "fail", "result": p.replace("FAIL: ", "")})
    elif ct.get("status") == "running":
        conn_checks.append({"label": "Ping Catalyst Center", "status": "na", "result": "testing..."})
    elif ct.get("status") == "failed":
        conn_checks.append({"label": "Ping Catalyst Center", "status": "fail", "result": "connectivity failed"})
    else:
        conn_checks.append({"label": "Ping Catalyst Center", "status": "na", "result": "pending"})

    switch_data.append({
        "name": "Catalyst Center",
        "model": "198.18.5.100",
        "host": "connectivity",
        "checks": conn_checks,
    })

    return jsonify(switch_data)

@app.route("/api/upload-event", methods=["POST"])
def upload_event():
    if "file" not in request.files:
        return jsonify({"error": "No file"}), 400
    f = request.files["file"]
    if not f.filename.endswith(".csv"):
        return jsonify({"error": "Must be .csv"}), 400

    content = f.stream.read().decode("utf-8-sig")
    reader = csv.DictReader(io.StringIO(content))
    if not reader.fieldnames:
        return jsonify({"error": "Empty CSV"}), 400

    raw_rows = list(reader)
    cleaned_rows = []
    for r in raw_rows:
        cleaned_rows.append({k.strip(): v for k, v in r.items()})

    rows = cleaned_rows
    created = 0

    # Detect column mapping from header names (case-insensitive)
    def _col(header, *aliases):
        for a in aliases:
            for h in (reader.fieldnames or []):
                if h.strip().lower() == a.lower():
                    return h.strip()
        return None

    vpn_host_col = _col("vpn_host", "vpn host", "vpn-host", "vpn_server", "vpnh")
    vpn_user_col = _col("vpn_user", "username", "vpn username", "vpn-user", "user")
    vpn_pass_col = _col("vpn_pass", "password", "vpn password", "vpn-password", "pass")
    session_col = _col("session_id", "session id", "session", "session_id", "sessionid")
    router_ip_col = _col("router_ip", "router ip", "router-ip", "router_ip", "device ip", "device_ip")

    for row in rows:
        pod_num = None
        for key in ["POD Number", "POD Number", "pod_number", "POD", "Pod", "Session Number"]:
            if key in row and row[key].strip():
                pod_num = row[key].strip()
                break
        if not pod_num:
            continue

        pod_id = f"POD-{pod_num}"

        # Extract device info by scanning columns
        device_data = {}
        router_serial = ""
        for col in row:
            val = row[col].strip()
            if not val:
                continue
            cl = col.lower().strip()
            if "serial" in cl or "chassis" in cl or "sn" == cl:
                device_data[col] = val
                if not router_serial:
                    router_serial = val
                if "C8231" in val or "ISR" in val or "C8000" in val:
                    router_serial = val

        vpn_host = row.get(vpn_host_col, "") if vpn_host_col else ""
        vpn_user = row.get(vpn_user_col, "") if vpn_user_col else ""
        vpn_pass = row.get(vpn_pass_col, "") if vpn_pass_col else ""
        session_id = row.get(session_col, "") if session_col else ""

        router_ip = row.get(router_ip_col, "") if router_ip_col else ""
        if not router_ip:
            try:
                n = int(pod_num)
                router_ip = f"198.18.133.{21 + n}"
            except ValueError:
                router_ip = ""

        conn = _db()
        existing = conn.execute("SELECT pod_id FROM pods WHERE pod_id = ?", (pod_id,)).fetchone()
        if existing:
            conn.execute("""UPDATE pods SET status='pending', device_data=?, router_serial=?,
                vpn_host=?, vpn_user=?, vpn_pass=?, router_ip=?, session_id=?,
                notes='Imported from event CSV', updated_at=datetime('now')
                WHERE pod_id=?""",
                (json.dumps(device_data), router_serial, vpn_host, vpn_user, vpn_pass, router_ip, session_id, pod_id))
        else:
            conn.execute("""INSERT INTO pods
                (pod_id, status, device_data, router_serial, vpn_host, vpn_user, vpn_pass, router_ip, session_id, notes)
                VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, 'Imported from event CSV')""",
                (pod_id, json.dumps(device_data), router_serial, vpn_host, vpn_user, vpn_pass, router_ip, session_id))
        conn.execute("DELETE FROM pipeline_steps WHERE pod_id = ?", (pod_id,))
        conn.commit()
        conn.close()
        created += 1

    return jsonify({"status": "ok", "pods_created": created, "columns": reader.fieldnames})

@app.route("/api/start-pipeline/<pod_id>", methods=["POST"])
def start_pipeline(pod_id):
    if pod_id in _runners and _runners[pod_id].is_alive():
        return jsonify({"error": "Pipeline already running"}), 409
    clear_logs(pod_id)
    conn = _db()
    conn.execute("DELETE FROM pipeline_steps WHERE pod_id = ?", (pod_id,))
    conn.execute("UPDATE pods SET status='running', updated_at=datetime('now') WHERE pod_id = ?", (pod_id,))
    conn.commit()
    conn.close()

    t = threading.Thread(target=run_onboard_thread, args=(pod_id,), daemon=True)
    _runners[pod_id] = t
    t.start()
    return jsonify({"status": "started"})

@app.route("/api/start-all", methods=["POST"])
def start_all():
    conn = _db()
    pods = conn.execute("SELECT pod_id FROM pods WHERE status IN ('pending', 'available', 'ready')").fetchall()
    conn.close()
    started = []
    for p in pods:
        pod_id = p["pod_id"]
        if pod_id in _runners and _runners[pod_id].is_alive():
            continue
        clear_logs(pod_id)
        c = _db()
        c.execute("DELETE FROM pipeline_steps WHERE pod_id = ?", (pod_id,))
        c.execute("UPDATE pods SET status='running', updated_at=datetime('now') WHERE pod_id = ?", (pod_id,))
        c.commit()
        c.close()
        t = threading.Thread(target=run_onboard_thread, args=(pod_id,), daemon=True)
        _runners[pod_id] = t
        t.start()
        started.append(pod_id)
    return jsonify({"status": "ok", "started": started})

@app.route("/api/pipeline-status/<pod_id>")
def pipeline_status(pod_id):
    running = pod_id in _runners and _runners[pod_id].is_alive()
    return jsonify({"running": running})

# ---- HTML template ----
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>POD Automator — Dashboard</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
         background: #0a1628; color: #e0e6ed; padding: 20px; }
  h1 { color: #02c8ff; font-size: 24px; margin-bottom: 4px; display: inline; }
  .subtitle { color: #8899aa; margin-bottom: 20px; font-size: 13px; }

  .upload-section { background: #112240; border-radius: 8px; padding: 16px; margin-bottom: 20px; }
  .upload-section h3 { color: #02c8ff; font-size: 14px; margin-bottom: 10px; }

  .elapsed-timer { font-size: 13px; color: #00e68a; font-weight: normal; margin-left: 12px; }
  .timer-label { color: #667788; margin-right: 4px; }
  .upload-zone { border: 2px dashed #1a2d4a; border-radius: 6px; padding: 20px; text-align: center;
                  cursor: pointer; transition: border-color 0.2s; }
  .upload-zone:hover { border-color: #02c8ff; }
  .upload-zone.dragover { border-color: #00e68a; background: #0a1f3d; }
  .upload-zone input[type=file] { display: none; }
  .upload-zone .hint { color: #667788; font-size: 12px; margin-top: 6px; }
  .upload-result { margin-top: 8px; font-size: 13px; }

  .summary { display: flex; gap: 16px; margin-bottom: 20px; }
  .stat-card { background: #112240; border-radius: 8px; padding: 14px 20px; flex: 1; }
  .stat-card .num { font-size: 28px; font-weight: bold; }
  .stat-card .label { font-size: 11px; color: #8899aa; text-transform: uppercase; }
  .stat-card.green .num { color: #00e68a; }
  .stat-card.red .num { color: #ff4757; }
  .stat-card.yellow .num { color: #ffa502; }

  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th { text-align: left; padding: 8px; background: #112240;
       color: #8899aa; font-weight: 600; text-transform: uppercase; font-size: 11px;
       position: sticky; top: 0; }
  td { padding: 8px; border-bottom: 1px solid #1a2d4a; }
  tr:hover td { background: #1a2d4a; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge.pass { background: #003d2a; color: #00e68a; }
  .badge.fail { background: #3d0000; color: #ff4757; }
  .badge.pending { background: #2a1f00; color: #ffa502; }
  .badge.running { background: #001f3d; color: #02c8ff; }
  .badge.skipped { background: #1a2d4a; color: #667788; }
  .pod-id { font-weight: 600; color: #02c8ff; cursor: pointer; }
  .pod-id:hover { text-decoration: underline; }
  .notes { max-width: 140px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
           color: #8899aa; font-size: 12px; }
  .device-col { text-align: center; }
  .refresh-btn { color: #02c8ff; cursor: pointer; font-size: 13px; margin-left: 12px; }
  .auto-refresh { margin-left: 16px; font-size: 12px; color: #667788; }

  .btn-start { background: #00e68a; color: #003d2a; border: none; border-radius: 4px;
               padding: 4px 12px; font-size: 12px; font-weight: 600; cursor: pointer; }
  .btn-start:hover { background: #00ff9a; }
  .btn-start:disabled { background: #1a2d4a; color: #667788; cursor: not-allowed; }
  .btn-start.running { background: #02c8ff; color: #001f3d; }
  .btn-start-all { background: #02c8ff; color: #001f3d; border: none; border-radius: 6px;
                   padding: 8px 20px; font-size: 14px; font-weight: 700; cursor: pointer; }
  .btn-start-all:hover { background: #00d4ff; }
  .btn-start-all:disabled { background: #1a2d4a; color: #667788; cursor: not-allowed; }
  .btn-start-all.running { animation: pulse 1.5s infinite; }
  @keyframes pulse { 0% { opacity: 1; } 50% { opacity: 0.6; } 100% { opacity: 1; } }

  .progress-mini { width: 60px; height: 12px; background: #0a1628; border-radius: 4px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 6px; }
  .progress-mini-fill { height: 100%; border-radius: 4px; transition: width 0.5s ease; }

  .detail-panel { display: none; margin-top: 20px; }
  .detail-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
  .detail-header h3 { color: #02c8ff; font-size: 16px; }
  .detail-tabs { display: flex; gap: 4px; margin-bottom: 12px; }
  .tab-btn { background: #112240; color: #8899aa; border: none; border-radius: 4px 4px 0 0;
             padding: 6px 14px; font-size: 12px; cursor: pointer; }
  .tab-btn.active { background: #1a2d4a; color: #02c8ff; }
  .tab-content { display: none; background: #112240; border-radius: 0 8px 8px 8px; padding: 16px; }
  .tab-content.active { display: block; }

  .pipeline-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 8px; }
  .step-card { background: #0a1628; border-radius: 6px; padding: 10px; text-align: center; }
  .step-card .step-num { font-size: 11px; color: #667788; }
  .step-card .step-name { font-size: 12px; margin: 4px 0; font-weight: 600; }
  .step-card .step-result { font-size: 10px; color: #667788; word-break: break-all; max-height: 40px; overflow: hidden; }
  .step-dur { font-size: 11px; color: #02c8ff; margin-top: 4px; }
  .elapsed-timer { font-size: 13px; color: #00e68a; font-weight: normal; margin-left: 12px; }
  .timer-label { color: #667788; margin-right: 4px; }

  .progress-wrap { background: #0a1628; border-radius: 8px; padding: 12px; margin-bottom: 12px; }
  .progress-bar-bg { background: #1a2d4a; border-radius: 6px; height: 18px; overflow: hidden; position: relative; }
  .progress-bar-fill { background: linear-gradient(90deg, #02c8ff, #00e68a); height: 100%; border-radius: 6px;
                       transition: width 0.5s ease; width: 0%; }
  .progress-text { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
                   font-size: 11px; font-weight: 700; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.5); }
  .progress-label { font-size: 12px; color: #8899aa; margin-bottom: 6px; }

  .switch-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 12px; }
  .switch-card { background: #0a1628; border-radius: 8px; padding: 14px; }
  .switch-card h4 { color: #02c8ff; font-size: 14px; margin: 0 0 8px 0; }
  .switch-check { display: flex; justify-content: space-between; align-items: center;
                   padding: 4px 0; font-size: 12px; border-bottom: 1px solid #112240; }
  .switch-check:last-child { border-bottom: none; }
  .switch-check .check-label { color: #8899aa; }
  .switch-check .check-result { font-weight: 600; }
  .check-pass { color: #00e68a; }
  .check-fail { color: #ff4757; }
  .check-na { color: #667788; }

  .log-box { background: #0a1628; border-radius: 6px; padding: 12px; max-height: 400px; overflow-y: auto;
             font-family: 'SF Mono', 'Menlo', monospace; font-size: 12px; line-height: 1.5; }
  .log-box .log-line { color: #8899aa; }
  .log-box .log-line.ok { color: #00e68a; }
  .log-box .log-line.err { color: #ff4757; }
  .log-box .log-line.info { color: #02c8ff; }
  .log-time { color: #445566; margin-right: 8px; }
  .close-btn { color: #ff4757; cursor: pointer; font-size: 13px; margin-left: 12px; }
</style>
</head>
<body>
  <h1>POD Automator</h1>
  <span class="refresh-btn" onclick="location.reload()">&#x21bb; Refresh</span>
  <span class="auto-refresh">(auto 5s)</span>

  <div class="upload-section">
    <h3>Upload Event Details CSV</h3>
    <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()"
         ondragover="this.classList.add('dragover'); event.preventDefault()"
         ondragleave="this.classList.remove('dragover')"
         ondrop="event.preventDefault(); handleFile(event.dataTransfer.files[0])">
      <div>Click or drop CSV file here</div>
      <div class="hint">EventsDetails.csv from dCloud — auto-discovers PODs</div>
      <input type="file" id="file-input" accept=".csv" onchange="handleFile(this.files[0])">
    </div>
    <div class="upload-result" id="upload-result"></div>
  </div>

  <div class="summary" id="summary"></div>

  <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;">
    <button class="btn-start-all" id="btn-start-all" onclick="startAllPods()">&#9654; Start All PODs</button>
    <span id="start-all-status" style="font-size:12px;color:#667788;"></span>
  </div>

  <table>
    <thead>
      <tr>
        <th>POD</th>
        <th>Status</th>
        <th>VPN</th>
        <th>Serial</th>
        <th>SD-WAN</th>
        <th>Pipeline</th>
        <th>Actions</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody id="pod-rows"></tbody>
  </table>

  <div class="detail-panel" id="detail-panel">
    <div class="detail-header">
      <h3><span id="detail-pod-id"></span> <span id="elapsed-timer" class="elapsed-timer"></span></h3>
      <span class="close-btn" onclick="closeDetail()">&#x2715; Close</span>
    </div>
    <div class="progress-wrap" id="progress-wrap">
      <div class="progress-label"><span id="progress-label-text">Pipeline progress</span></div>
      <div class="progress-bar-bg">
        <div class="progress-bar-fill" id="progress-bar-fill"></div>
        <div class="progress-text"><span id="progress-text">0%</span></div>
      </div>
    </div>
    <div class="detail-tabs">
      <button class="tab-btn active" onclick="switchTab(this, 'steps')">Pipeline Steps</button>
      <button class="tab-btn" onclick="switchTab(this, 'logs')">Live Logs</button>
      <button class="tab-btn" onclick="switchTab(this, 'switches')">Switches</button>
    </div>
    <div class="tab-content active" id="tab-steps">
      <div class="pipeline-grid" id="pipeline-grid"></div>
    </div>
    <div class="tab-content" id="tab-logs">
      <div class="log-box" id="log-box">Waiting for logs...</div>
    </div>
    <div class="tab-content" id="tab-switches">
      <div class="switch-grid" id="switch-grid">
        <div style="color:#667788;font-size:13px;">Select a POD to load switch verification results</div>
      </div>
    </div>
  </div>

<script>
const PIPELINE_ORDER = [
  "verify_router",
  "config_group_associate",
  "set_variables",
  "assign_license",
  "deploy_config_group",
  "generate_bootstrap",
  "copy_bootstrap",
  "controller_mode_enable",
  "verify_online",
  "verify_border_spine",
  "verify_leaf1",
  "verify_leaf2",
  "connectivity_test",
];

async function handleFile(file) {
  if (!file) return;
  const result = document.getElementById('upload-result');
  result.innerHTML = 'Uploading...';

  const fd = new FormData();
  fd.append('file', file);
  const r = await fetch('/api/upload-event', { method: 'POST', body: fd });
  const data = await r.json();

  if (data.error) {
    result.innerHTML = '<span style="color:#ff4757">Error: ' + data.error + '</span>';
  } else {
    result.innerHTML = '<span style="color:#00e68a">Imported ' + data.pods_created + ' PODs. Columns: ' + (data.columns || []).join(', ') + '</span>';
    load();
  }
}

async function load() {
  const r = await fetch('/api/pods');
  const pods = await r.json();
  renderStats(pods);
  renderTable(pods);
  const detailId = document.getElementById('detail-pod-id').textContent;
  if (detailId) showPipeline(detailId);
}

function renderStats(pods) {
  const total = pods.length;
  const ready = pods.filter(p => p.sdwan_online === 'yes').length;
  const running = pods.filter(p => p.status === 'running' || p.status === 'in_progress').length;
  const pending = pods.filter(p => p.status === 'pending').length;

  document.getElementById('summary').innerHTML =
    `<div class="stat-card green"><div class="num">${ready}</div><div class="label">Ready</div></div>` +
    `<div class="stat-card yellow"><div class="num">${running}</div><div class="label">Running</div></div>` +
    `<div class="stat-card red"><div class="num">${pending}</div><div class="label">Pending</div></div>` +
    `<div class="stat-card"><div class="num">${total}</div><div class="label">Total</div></div>`;
}

function badge(val, yesLabel) {
  if (val === 'yes') return '<span class="badge pass">' + (yesLabel || 'Ready') + '</span>';
  if (val === 'no')  return '<span class="badge fail">FAIL</span>';
  if (val === 'waiting') return '<span class="badge running">Waiting</span>';
  return '<span class="badge pending">?</span>';
}

function pipelineBadge(val) {
  if (val === 'completed') return '<span class="badge pass">Done</span>';
  if (val === 'running')   return '<span class="badge running">Run</span>';
  if (val === 'failed')    return '<span class="badge fail">Fail</span>';
  if (val === 'skipped')   return '<span class="badge skipped">Skip</span>';
  return '<span class="badge pending">Pending</span>';
}

function pipelinePhase(p) {
  const phases = PIPELINE_ORDER;
  let done = 0;
  for (let i = 0; i < phases.length; i++) {
    const v = p[phases[i]];
    if (v === 'completed' || v === 'skipped') done++;
    if (v === 'running') return { pct: Math.round(done / phases.length * 100), text: `${i+1}/${phases.length} running` };
    if (v === 'failed')  return { pct: Math.round(done / phases.length * 100), text: `${i+1}/${phases.length} failed` };
  }
  const pct = Math.round(done / phases.length * 100);
  const txt = done === phases.length ? `${phases.length}/${phases.length} done` : `${done+1}/${phases.length} pending`;
  return { pct, text: txt };
}

function renderTable(pods) {
  const tbody = document.getElementById('pod-rows');
  tbody.innerHTML = pods.map(p => {
    const pipe = pipelinePhase(p);
    const serial = p.router_serial || '-';
    const isRunning = p.status === 'running' || p.status === 'in_progress';
    const barColor = pipe.pct === 100 ? '#00e68a' : pipe.text.includes('fail') ? '#ff4757' : '#02c8ff';
    const miniBar = pipe.pct > 0 ? `<div class="progress-mini"><div class="progress-mini-fill" style="width:${pipe.pct}%;background:${barColor}"></div></div>` : '';
    const pipeLabel = `${miniBar}<span class="badge ${pipe.pct === 100 ? 'pass' : pipe.text.includes('fail') ? 'fail' : pipe.text.includes('running') ? 'running' : 'pending'}">${pipe.text}</span>`;
    const vpn = p.vpn_status || 'disconnected';
    const vpnColor = vpn === 'connected' ? '#00e68a' : vpn === 'connecting' ? '#ffa502' : '#ff4757';
    const vpnLabel = vpn === 'connected' ? 'Connected' : vpn === 'connecting' ? 'Connecting' : 'Offline';
    return `<tr>
      <td class="pod-id" onclick="showPipeline('${p.pod_id}')">${p.pod_id}</td>
      <td><span class="badge ${p.status === 'ready' ? 'pass' : p.status === 'pending' ? 'pending' : 'fail'}">${p.status || 'pending'}</span></td>
      <td style="text-align:center"><span style="color:${vpnColor};font-size:18px;line-height:1" title="${p.vpn_detail || ''}">&#x25cf;</span></td>
      <td style="font-size:11px;color:#667788">${serial}</td>
      <td class="device-col">${badge(p.sdwan_online, 'Online')}</td>
      <td>${pipeLabel}</td>
      <td>
        <button class="btn-start ${isRunning ? 'running' : ''}" id="btn-${p.pod_id}"
          onclick="startPipeline('${p.pod_id}')" ${isRunning ? 'disabled' : ''}>
          ${isRunning ? 'Running...' : 'Start'}
        </button>
      </td>
      <td class="notes" title="${(p.notes||'').replace(/"/g,'&quot;')}">${p.notes || '-'}</td>
    </tr>`;
  }).join('');
}

async function startPipeline(podId) {
  const btn = document.getElementById('btn-' + podId);
  btn.disabled = true;
  btn.textContent = 'Starting...';
  btn.className = 'btn-start running';

  const r = await fetch('/api/start-pipeline/' + podId, { method: 'POST' });
  const data = await r.json();
  if (data.error) {
    btn.textContent = 'Error';
    btn.disabled = false;
    btn.className = 'btn-start';
    return;
  }
  btn.textContent = 'Running';
  showPipeline(podId);
}

async function startAllPods() {
  const btn = document.getElementById('btn-start-all');
  const status = document.getElementById('start-all-status');
  btn.disabled = true;
  btn.classList.add('running');
  btn.textContent = 'Starting all...';
  status.textContent = 'Starting pipelines...';

  const r = await fetch('/api/start-all', { method: 'POST' });
  const data = await r.json();
  if (data.error) {
    status.textContent = 'Error: ' + data.error;
    btn.disabled = false;
    btn.classList.remove('running');
    btn.textContent = '▶ Start All PODs';
    return;
  }
  status.textContent = 'Started ' + data.started.length + ' POD(s): ' + data.started.join(', ');
  btn.textContent = 'Running all...';
  load();
}

let timerInterval = null;

function elapsedStr(ms) {
  if (ms < 0) return '';
  const s = Math.floor(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  const sec = s % 60;
  const min = m % 60;
  if (h > 0) return `${h}h ${min}m ${sec}s`;
  if (m > 0) return `${m}m ${sec}s`;
  return `${sec}s`;
}

function updateTimer(startTime) {
  const el = document.getElementById('elapsed-timer');
  if (!startTime) { el.innerHTML = ''; return; }
  const diff = Date.now() - new Date(startTime).getTime();
  el.innerHTML = `<span class="timer-label">elapsed</span>${elapsedStr(diff)}`;
}

function formatDur(start, end) {
  if (!start) return '';
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  return elapsedStr(e - s);
}

async function showPipeline(podId) {
  const panel = document.getElementById('detail-panel');
  document.getElementById('detail-pod-id').textContent = podId;
  panel.style.display = 'block';

  loadSteps(podId);
  loadLogs(podId);
  loadSwitches(podId);

  // Start elapsed timer
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(() => {
    const el = document.getElementById('pipeline-grid');
    const firstCard = el ? el.querySelector('.step-card .started-at') : null;
    if (firstCard) updateTimer(firstCard.getAttribute('data-time'));
  }, 1000);
}

async function loadSteps(podId) {
  const r = await fetch('/api/pipeline/' + podId);
  const steps = await r.json();

  const total = PIPELINE_ORDER.length;
  const done = steps.filter(s => s.status === 'completed' || s.status === 'skipped').length;
  const running = steps.some(s => s.status === 'running');
  const failed = steps.some(s => s.status === 'failed');
  const pct = Math.round(done / total * 100);

  const firstStep = steps.length > 0 ? steps[0].started_at : null;
  updateTimer(firstStep);

  // Progress bar
  const fill = document.getElementById('progress-bar-fill');
  const txt = document.getElementById('progress-text');
  const lbl = document.getElementById('progress-label-text');
  if (fill) fill.style.width = pct + '%';
  if (txt) txt.textContent = pct + '% (' + done + '/' + total + ')';
  if (lbl) lbl.textContent = failed ? 'Failed at ' + done + '/' + total : running ? 'Running — ' + done + '/' + total : done === total ? 'Complete!' : 'Pending — ' + done + '/' + total;

  const grid = document.getElementById('pipeline-grid');
  grid.innerHTML = PIPELINE_ORDER.map(name => {
    const step = steps.find(s => s.step_name === name);
    const st = step ? step.status : 'pending';
    const result = step && step.result ? step.result.slice(0, 60) : '';
    const idx = PIPELINE_ORDER.indexOf(name) + 1;
    const label = name.replace(/_/g, ' ');
    const duration = formatDur(step?.started_at, step?.completed_at);
    const durHtml = duration ? `<div class="step-dur">${duration}</div>` : '';
    return `<div class="step-card">
      <div class="step-num">Phase ${idx}/${total}</div>
      <div class="step-name">${label}</div>
      ${pipelineBadge(st)}
      <div class="step-result">${result}</div>
      ${durHtml}
      <span class="started-at" data-time="${step?.started_at || ''}" style="display:none"></span>
    </div>`;
  }).join('');
}

let logPollId = null;

async function loadLogs(podId) {
  if (logPollId) clearInterval(logPollId);

  const box = document.getElementById('log-box');
  const r = await fetch('/api/logs/' + podId);
  const logs = await r.json();
  box.innerHTML = logs.map(l => {
    const cls = l.log_line.includes('FAILED') || l.log_line.includes('ERROR') ? 'err'
              : l.log_line.includes('OK') ? 'ok'
              : l.log_line.includes('Running') || l.log_line.includes('Starting') ? 'info'
              : '';
    return `<div class="log-line ${cls}"><span class="log-time">${l.timestamp || ''}</span>${escHtml(l.log_line)}</div>`;
  }).join('') || '<div class="log-line">No logs yet</div>';
  box.scrollTop = box.scrollHeight;

  logPollId = setInterval(() => loadLogs(podId), 2000);
}

async function loadSwitches(podId) {
  const r = await fetch('/api/switches/' + podId);
  const data = await r.json();
  const grid = document.getElementById('switch-grid');

  if (!data || data.length === 0) {
    grid.innerHTML = '<div style="color:#8899aa;font-size:13px;">No switch data for this POD</div>';
    return;
  }

  grid.innerHTML = data.map(sw => {
    const checksHtml = (sw.checks || []).map(c =>
      `<div class="switch-check">
        <span class="check-label">${escHtml(c.label)}</span>
        <span class="check-result ${c.status === 'pass' ? 'check-pass' : c.status === 'fail' ? 'check-fail' : 'check-na'}">${c.status === 'pass' ? '✓' : c.status === 'fail' ? '✗' : '—'} ${escHtml(c.result)}</span>
      </div>`
    ).join('');
    return `<div class="switch-card">
      <h4>${escHtml(sw.name)} <span style="font-weight:normal;font-size:11px;color:#667788">${escHtml(sw.model || '')}</span></h4>
      ${checksHtml}
    </div>`;
  }).join('');
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

function switchTab(btn, name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
}

function closeDetail() {
  document.getElementById('detail-panel').style.display = 'none';
  document.getElementById('detail-pod-id').textContent = '';
  if (logPollId) clearInterval(logPollId);
}

load();
setInterval(load, 5000);
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)
