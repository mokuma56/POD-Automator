"""POD Dashboard — upload events CSV, start pipelines, monitor live progress."""

import sqlite3, json, threading, csv, io, os, time, sys, subprocess
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template_string, jsonify, request

sys.path.insert(0, str(Path(__file__).parent))
import onboard_router
try:
    import kb as _kb
    import kb_seed as _kb_seed
    _kb.ensure_kb_table(_kb.DB_PATH)
    _KB_AVAILABLE = True
except Exception as _kb_err:
    _KB_AVAILABLE = False
    _kb_err_msg = str(_kb_err)

DATA_DIR = Path(__file__).parent
DB_PATH = DATA_DIR / "data" / "pod_state.db"

app = Flask(__name__)

# ---- VPN status check ---- #
def check_pod_vpn(pod_id):
    """Check VPN status for a POD — inspect container directly."""
    import subprocess, json
    container_name = f"vpn-{pod_id}"
    try:
        r = subprocess.run(
            ["docker", "inspect", container_name, "--format", "{{json .State}}"],
            capture_output=True, text=True, timeout=8
        )
        if r.returncode == 0 and r.stdout.strip():
            data = json.loads(r.stdout.strip())
            status = data.get("Status", "")
            health = data.get("Health", {})
            h = health.get("Status", "") if isinstance(health, dict) else ""
            if status == "running":
                if h == "healthy":
                    return {"status": "connected", "detail": "Docker VPN healthy"}
                elif h in ("starting", ""):
                    return {"status": "connecting", "detail": "Docker VPN starting"}
                elif h == "unhealthy":
                    return {"status": "disconnected", "detail": "Docker VPN unhealthy"}
                return {"status": "connecting", "detail": "Docker VPN up"}
            else:
                return {"status": "disconnected", "detail": f"Docker: {status[:80]}"}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return {"status": "disconnected", "detail": "No Docker VPN container"}


# ---- DB helpers ----
def _db():
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=DELETE")
    conn.execute("PRAGMA synchronous=FULL")
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
            scc_org TEXT DEFAULT '',
            assigned_to TEXT DEFAULT '',
            pod_number TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migration: add scc_org if upgrading from older schema
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN scc_org TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN assigned_to TEXT DEFAULT ''")
    except Exception:
        pass
    # Migration: add pod_number — AD-confirmed authoritative POD number
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN pod_number TEXT DEFAULT ''")
    except Exception:
        pass
    # Migration: add SCC API credentials columns
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN scc_api_key TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN scc_api_secret TEXT DEFAULT ''")
    except Exception:
        pass
    # Migration: add Duo Admin API credentials columns
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN duo_ikey TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN duo_skey TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN duo_host TEXT DEFAULT ''")
    except Exception:
        pass
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS upgrade_config (
            device_type TEXT PRIMARY KEY,
            golden_version TEXT NOT NULL,
            image_filename TEXT DEFAULT '',
            image_path TEXT DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Seed defaults if not present
    conn.execute("""
        INSERT OR IGNORE INTO upgrade_config (device_type, golden_version, image_filename, image_path)
        VALUES ('switch', '17.12.1', 'cat9k_iosxe.17.12.01.SPA.bin', '/home/cisco/cat9k_iosxe.17.12.01.SPA.bin')
    """)
    conn.execute("""
        INSERT OR IGNORE INTO upgrade_config (device_type, golden_version, image_filename, image_path)
        VALUES ('router', '17.18.2', '', '')
    """)
    # SCC reset checklist table
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scc_checklist (
            pod_id TEXT,
            item_key TEXT,
            status TEXT DEFAULT 'pending',
            detail TEXT DEFAULT '',
            confirmed_by TEXT DEFAULT '',
            confirmed_at TIMESTAMP,
            PRIMARY KEY (pod_id, item_key)
        )
    """)
    conn.commit()
    conn.close()

_migrate()

# ---- Log helpers ----
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
        # Add SCC checklist all-confirmed flag
        ALL_SCC_KEYS = [
            # 6 automated
            "access_policy_rules", "network_tunnel_groups",
            "zta_profiles", "private_resources", "dns_servers",
            "epp_posture_profiles",
            # 7 manual
            "logging_settings", "ravpn_profiles",
            "dlp_rules", "ravpn_ip_pool", "duo_saml", "ise_pxgrid", "te_integration",
        ]
        try:
            scc_rows = conn.execute(
                "SELECT item_key, status FROM scc_checklist WHERE pod_id=?", (p["pod_id"],)
            ).fetchall()
            scc_map = {r["item_key"]: r["status"] for r in scc_rows}
            p["scc_all_confirmed"] = all(scc_map.get(k) == "completed" for k in ALL_SCC_KEYS)
        except Exception:
            p["scc_all_confirmed"] = False
        result.append(p)
    conn.close()
    return jsonify(result)

@app.route("/api/generate-lab-pdf")
def api_generate_lab_pdf():
    """Generate and stream a Cisco-branded lab details PDF (4 cards per page)."""
    import generate_lab_cards
    from flask import Response
    conn = _db()
    pods_raw = conn.execute("SELECT * FROM pods ORDER BY pod_id").fetchall()
    conn.close()
    pods = []
    for p in pods_raw:
        p = dict(p)
        pods.append({
            "pod_id":       p.get("pod_id", ""),
            "pod_number":   p.get("pod_number", ""),
            "session_id":   p.get("session_id", ""),
            "scc_org":      p.get("scc_org", ""),
            "assigned_to":  p.get("assigned_to", ""),
            "vpn_host":     p.get("vpn_host", ""),
            "vpn_username": p.get("vpn_user", ""),
            "vpn_password": p.get("vpn_pass", ""),
        })
    pdf_bytes = generate_lab_cards.generate_pdf(pods)
    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={"Content-Disposition": "attachment; filename=cisco_lab_details.pdf"}
    )

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
    "border_spine": {"name": "Border Spine", "ip": "198.18.128.24", "checks": [
        "OSPF neighbors (expect 2)",
        "VRF (expect Mgmt-vrf only)",
        "Version (expect 17.12.x)",
        "VLAN (expect default + VLAN 5)",
    ]},
    "leaf1": {"name": "Leaf 1", "ip": "198.18.128.22", "checks": [
        "VRF (expect Mgmt-vrf only)",
        "Version (expect 17.12.x)",
        "VLAN (expect default only)",
    ]},
    "leaf2": {"name": "Leaf 2", "ip": "198.18.128.23", "checks": [
        "VRF (expect Mgmt-vrf only)",
        "Version (expect 17.12.x)",
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
        # Extract MODEL prefix and re-align check indices
        model = ""
        check_parts = step.get("parts", [])[:]
        model = ""
        if check_parts and check_parts[0].startswith("MODEL:"):
            model = check_parts[0].replace("MODEL: ", "")
            check_parts = check_parts[1:]  # remove MODEL prefix, shift indices

        checks = []
        for i, label in enumerate(info["checks"]):
            if step.get("status") == "completed" and i < len(check_parts):
                part = check_parts[i]
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

        passed = sum(1 for c in checks if c["status"] == "pass")
        failed = sum(1 for c in checks if c["status"] == "fail")
        switch_data.append({
            "name": info["name"],
            "model": model,
            "ip": info.get("ip", ""),
            "host": key,
            "checks": checks,
            "passed": passed,
            "failed": failed,
            "total": len(checks),
            "step_status": step.get("status", "pending"),
        })

    # Add connectivity_test as a separate card
    ct_step = results.get("connectivity_test", {})
    ct_status = ct_step.get("status", "pending")
    ct_parts = ct_step.get("parts", [])
    ct_checks = []
    switch_order = [("border_spine", "Border Spine"), ("leaf1", "Leaf 1"), ("leaf2", "Leaf 2")]
    for i, (_, label) in enumerate(switch_order):
        if ct_status == "completed" and i < len(ct_parts):
            part = ct_parts[i]
            if part.startswith("PASS"):
                ct_checks.append({"label": label + " → 198.18.5.100", "status": "pass", "result": part.replace("PASS: ", "")})
            elif part.startswith("FAIL"):
                ct_checks.append({"label": label + " → 198.18.5.100", "status": "fail", "result": part.replace("FAIL: ", "")})
            else:
                ct_checks.append({"label": label + " → 198.18.5.100", "status": "pass", "result": part})
        elif ct_status == "running":
            ct_checks.append({"label": label + " → 198.18.5.100", "status": "na", "result": "checking..."})
        elif ct_status == "failed":
            ct_checks.append({"label": label + " → 198.18.5.100", "status": "fail", "result": "ping failed"})
        else:
            ct_checks.append({"label": label + " → 198.18.5.100", "status": "na", "result": "pending"})

    ct_passed = sum(1 for c in ct_checks if c["status"] == "pass")
    ct_failed = sum(1 for c in ct_checks if c["status"] == "fail")
    switch_data.append({
        "name": "Switch Connectivity",
        "model": "",
        "ip": "",
        "host": "connectivity_test",
        "checks": ct_checks,
        "passed": ct_passed,
        "failed": ct_failed,
        "total": len(ct_checks),
        "step_status": ct_status,
    })

    return jsonify(switch_data)


SWITCH_RECHECK_RUNNERS = {}


def _ensure_pipeline_container(pod_id):
    """Ensure the pipeline container is running for the given POD.
    Launches it via docker compose if not already running. Returns (ok, message)."""
    import os, tempfile
    from docker.generate import generate_compose, read_db

    # Check if already running
    r = subprocess.run(
        ["docker", "inspect", f"pipeline-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode == 0 and r.stdout.strip() == "running":
        return True, "already running"

    # Not running — launch it
    pods = read_db(status_filter=("pending", "available", "ready", "running", "in_progress", ""))
    p = next((x for x in pods if x["pod_id"] == pod_id), None)
    if not p:
        return False, f"POD {pod_id} not found in DB"

    compose = generate_compose(p)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    tmp.write(compose)
    tmp.close()
    try:
        r2 = subprocess.run(
            ["docker", "compose", "-p", pod_id.lower(), "-f", tmp.name, "up", "-d", "pipeline"],
            capture_output=True, text=True, timeout=30
        )
        if r2.returncode == 0:
            time.sleep(3)  # give container a moment to start
            return True, "launched"
        return False, (r2.stderr or r2.stdout)[:300]
    finally:
        os.unlink(tmp.name)


@app.route("/api/switches/recheck/<pod_id>", methods=["POST"])
def api_switches_recheck(pod_id):
    """Re-run switch checks inside the POD's VPN namespace."""
    import threading

    conn = _db()
    row = conn.execute("SELECT * FROM pods WHERE pod_id = ?", (pod_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "POD not found"}), 404
    router_ip = row["router_ip"]
    conn.close()

    # Verify VPN container is running — switch recheck uses docker run --rm
    # against the VPN network namespace directly, no pipeline container needed
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    def _recheck():
        try:
            switches = ["verify_border_spine", "verify_leaf1", "verify_leaf2", "connectivity_test"]
            # Mark ALL steps as running upfront so UI shows spinner with 0/4 done
            _c = _db()
            for step_name in switches:
                _c.execute("INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, completed_at, result) VALUES (?, ?, 'running', datetime('now'), NULL, '')", (pod_id, step_name))
            _c.execute("UPDATE pods SET updated_at=datetime('now') WHERE pod_id=?", (pod_id,))
            _c.commit()
            _c.close()

            for step_name in switches:
                if step_name == "connectivity_test":
                    func_call = "onboard_router.phase_connectivity_test()"
                else:
                    func_call = f"onboard_router.run_switch_checks('{step_name}')"
                script = (
                    "import sys; sys.path.insert(0, '.'); import onboard_router; "
                    f"onboard_router.ROUTER_IP = '{router_ip}'; "
                    f"ok, result = {func_call}; "
                    "print(repr((ok, result)))"
                )
                result = subprocess.run([
                    "docker", "run", "--rm",
                    "--network", f"container:vpn-{pod_id}",
                    "--entrypoint", "python3",
                    "pod-automator:latest", "-c", script
                ], capture_output=True, text=True, timeout=120)
                # Parse the printed repr (last line of stdout)
                stdout = result.stdout.strip()
                stderr = result.stderr.strip()
                last_line = stdout.splitlines()[-1] if stdout else ""
                if last_line.startswith("("):
                    try:
                        ok_val, result_val = eval(last_line)
                        if stderr:
                            result_val += f" | {stderr}"
                    except Exception as e2:
                        ok_val, result_val = False, f"parse error: {e2}"
                else:
                    ok_val, result_val = False, f"no tuple in output: {stdout[:200]}"

                status = "completed" if ok_val else "failed"
                conn2 = _db()
                conn2.execute("""INSERT OR REPLACE INTO pipeline_steps
                    (pod_id, step_name, status, started_at, completed_at, result)
                    VALUES (?, ?, ?, COALESCE((SELECT started_at FROM pipeline_steps WHERE pod_id=? AND step_name=?), datetime('now')),
                            datetime('now'), ?)""",
                    (pod_id, step_name, status, pod_id, step_name, str(result_val)[:500]))
                conn2.execute("UPDATE pods SET updated_at=datetime('now') WHERE pod_id=?", (pod_id,))
                conn2.commit()
                conn2.close()

            # Update notes if all switches passed
            conn3 = _db()
            steps = conn3.execute(
                "SELECT step_name, status FROM pipeline_steps WHERE pod_id=? AND step_name IN ('verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test')",
                (pod_id,)
            ).fetchall()
            switch_statuses = {s["step_name"]: s["status"] for s in steps}
            all_ok = all(v == "completed" for v in switch_statuses.values())
            if all_ok:
                # Check if full pipeline is complete too
                pipe_steps = conn3.execute(
                    "SELECT step_name, status FROM pipeline_steps WHERE pod_id=?",
                    (pod_id,)
                ).fetchall()
                all_done = all(s["status"] == "completed" for s in pipe_steps)
                if all_done:
                    conn3.execute("UPDATE pods SET notes='POD READY', sdwan_online='yes', status='ready', updated_at=datetime('now') WHERE pod_id=?", (pod_id,))
                else:
                    conn3.execute("UPDATE pods SET notes='Switches OK', updated_at=datetime('now') WHERE pod_id=?", (pod_id,))
            conn3.commit()
            conn3.close()
        except Exception as e:
            import traceback
            log(pod_id, f"Re-check error: {e}")
            log(pod_id, traceback.format_exc())
            # Reset any steps stuck in 'running' back to 'failed' so UI doesn't loop forever
            _c = _db()
            _c.execute(
                "UPDATE pipeline_steps SET status='failed', result='Re-check error: ' || ? WHERE pod_id=? AND step_name IN ('verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test') AND status='running'",
                (str(e)[:200], pod_id)
            )
            _c.commit()
            _c.close()

    t = threading.Thread(target=_recheck, daemon=True)
    t.start()
    return jsonify({"status": "ok", "message": "Switch re-check started for " + pod_id})


@app.route("/api/cdfmc/<pod_id>", methods=["GET"])
def api_cdfmc_status(pod_id):
    """Return current cdFMC step result parsed into structured fields."""
    conn = _db()
    row = conn.execute(
        "SELECT status, result FROM pipeline_steps WHERE pod_id=? AND step_name='cdfmc_check'",
        (pod_id,)
    ).fetchone()
    scc_org = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    conn.close()

    result = dict(
        step_status=row["status"] if row else "pending",
        step_result=row["result"] if row else "",
        scc_org=(scc_org["scc_org"] if scc_org else "") or "",
        deployed="unknown",
        ftd_status="",
    )
    if row and row["result"]:
        r = row["result"]
        import re as _re
        m = _re.search(r"deployed=(yes|no)", r)
        if m:
            result["deployed"] = m.group(1)
        m = _re.search(r"ftd=(.+)$", r)
        if m:
            result["ftd_status"] = m.group(1).strip()
        if not result["scc_org"]:
            m = _re.search(r"scc_org=([^\s|]+)", r)
            if m:
                result["scc_org"] = m.group(1)
    return jsonify(result)


@app.route("/api/cdfmc/recheck/<pod_id>", methods=["POST"])
def api_cdfmc_recheck(pod_id):
    """Re-run the cdFMC check inside the POD's VPN namespace."""
    import threading

    conn = _db()
    row = conn.execute("SELECT router_ip FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"status": "error", "message": "POD not found"}), 404

    # Check VPN container is at least running (don't require healthy — tunnel may still work)
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container not running for {pod_id} — connect VPN first"}), 400

    # Mark as running immediately so UI shows feedback right away
    conn2 = _db()
    conn2.execute(
        "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, result) "
        "VALUES (?, 'cdfmc_check', 'running', datetime('now'), 'Checking — please wait...')",
        (pod_id,)
    )
    conn2.commit(); conn2.close()

    def _recheck():
        script = (
            "import sys; sys.path.insert(0, '.'); import onboard_router; "
            f"onboard_router.ROUTER_IP = '{row['router_ip']}'; "
            "ok, result = onboard_router.phase_cdfmc_check(); "
            "print(repr((ok, result)))"
        )
        res = subprocess.run([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "--entrypoint", "python3",
            "pod-automator:latest", "-c", script
        ], capture_output=True, text=True, timeout=120)
        stdout = res.stdout.strip()
        last_line = stdout.splitlines()[-1] if stdout else ""
        ok_val, result_val = False, "no output"
        if last_line.startswith("("):
            try:
                ok_val, result_val = eval(last_line)
            except Exception as e:
                result_val = f"parse error: {e}"
        elif res.stderr:
            result_val = res.stderr.strip()[:300]
        status = "completed" if ok_val else "failed"
        conn3 = _db()
        conn3.execute(
            "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, completed_at, result) "
            "VALUES (?, 'cdfmc_check', ?, datetime('now'), datetime('now'), ?)",
            (pod_id, status, str(result_val)[:500])
        )
        import re as _re
        m = _re.search(r"scc_org=([^\s|]+)", str(result_val))
        if m:
            conn3.execute("UPDATE pods SET scc_org=?, updated_at=datetime('now') WHERE pod_id=?",
                          (m.group(1), pod_id))
        conn3.commit(); conn3.close()
        log(pod_id, f"[cdfmc_check] {'OK' if ok_val else 'FAILED'}: {result_val}")

    threading.Thread(target=_recheck, daemon=True).start()
    return jsonify({"status": "ok", "message": "cdFMC re-check started for " + pod_id})


@app.route("/api/cdfmc/redeploy/<pod_id>", methods=["POST"])
def api_cdfmc_redeploy(pod_id):
    """SSH to automation PC and run cli.py reset then cli.py deploy. Streams output to pipeline_logs."""
    import threading

    conn = _db()
    row = conn.execute("SELECT * FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"status": "error", "message": "POD not found"}), 404

    ok, msg = _ensure_pipeline_container(pod_id)
    if not ok:
        return jsonify({"status": "error", "message": f"Could not start pipeline container: {msg}"}), 400

    def _live_log(msg):
        try:
            c = _db()
            c.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)", (pod_id, msg))
            c.commit(); c.close()
        except Exception:
            pass

    def _redeploy():
        import paramiko as _p
        _live_log("[cdFMC] Starting Reset & Redeploy on automation PC...")
        try:
            client = _p.SSHClient()
            client.set_missing_host_key_policy(_p.AutoAddPolicy())
            client.connect("198.18.134.12", username="cisco", password="C1sco12345",
                           look_for_keys=False, allow_agent=False, timeout=15)
        except Exception as e:
            _live_log(f"[cdFMC] SSH to automation PC failed: {e}")
            return

        lab_dir = "/home/cisco/Documents/elevateLab"
        for label, cmd in [("reset", f"cd {lab_dir} && ./cli.py reset 2>&1"),
                           ("deploy", f"cd {lab_dir} && ./cli.py deploy 2>&1")]:
            _live_log(f"[cdFMC] Running cli.py {label}...")
            try:
                _, stdout, _ = client.exec_command(cmd, timeout=1200)
                for line in iter(stdout.readline, ""):
                    line = line.rstrip()
                    if line:
                        _live_log(f"[cdFMC/{label}] {line}")
                rc = stdout.channel.recv_exit_status()
                if rc != 0:
                    _live_log(f"[cdFMC] cli.py {label} exited with code {rc}")
                    client.close()
                    return
                _live_log(f"[cdFMC] cli.py {label} completed ✓")
            except Exception as e:
                _live_log(f"[cdFMC] Error during {label}: {e}")
                client.close()
                return

        client.close()
        _live_log("[cdFMC] Reset & Redeploy finished — running verification check...")

        # Auto re-check after deploy
        import sys, os
        script = (
            "import sys; sys.path.insert(0, '.'); import onboard_router; "
            f"onboard_router.ROUTER_IP = '{row['router_ip']}'; "
            "ok, result = onboard_router.phase_cdfmc_check(); "
            "print(repr((ok, result)))"
        )
        res = subprocess.run([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "--entrypoint", "python3",
            "pod-automator:latest", "-c", script
        ], capture_output=True, text=True, timeout=120)
        stdout = res.stdout.strip()
        last_line = stdout.splitlines()[-1] if stdout else ""
        ok_val, result_val = False, "no output"
        if last_line.startswith("("):
            try:
                ok_val, result_val = eval(last_line)
            except Exception:
                pass
        status = "completed" if ok_val else "failed"
        c2 = _db()
        c2.execute(
            "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, completed_at, result) "
            "VALUES (?, 'cdfmc_check', ?, datetime('now'), datetime('now'), ?)",
            (pod_id, status, str(result_val)[:500])
        )
        import re as _re
        m = _re.search(r"scc_org=([^\s|]+)", str(result_val))
        if m:
            c2.execute("UPDATE pods SET scc_org=?, updated_at=datetime('now') WHERE pod_id=?",
                       (m.group(1), pod_id))
        c2.commit(); c2.close()
        _live_log(f"[cdFMC] Verification: {'✓ OK' if ok_val else '✗ FAILED'} — {str(result_val)[:200]}")

    threading.Thread(target=_redeploy, daemon=True).start()
    return jsonify({"status": "ok", "message": "Reset & Redeploy started for " + pod_id})


# ---------------------------------------------------------------------------
# AD Verification endpoints
# ---------------------------------------------------------------------------

def _run_ad_phase(pod_id, phase_fn_name):
    """Run an onboard_router AD phase inside the POD's VPN container, return (ok, result)."""
    import subprocess
    script = (
        "import sys; sys.path.insert(0, '.'); import onboard_router; "
        f"ok, result = onboard_router.{phase_fn_name}(); "
        "print(repr((ok, result)))"
    )
    res = subprocess.run([
        "docker", "run", "--rm",
        "--network", f"container:vpn-{pod_id}",
        "--entrypoint", "python3",
        "pod-automator:latest", "-c", script
    ], capture_output=True, text=True, timeout=180)
    stdout = res.stdout.strip()
    last_line = stdout.splitlines()[-1] if stdout else ""
    if last_line.startswith("("):
        try:
            return eval(last_line)
        except Exception:
            pass
    return False, res.stderr.strip()[:300] or "no output"


def _persist_ad_step(pod_id, ok, result, step="ad_verify"):
    c = _db()
    status = "completed" if ok else "failed"
    c.execute(
        "INSERT OR REPLACE INTO pipeline_steps "
        "(pod_id, step_name, status, started_at, completed_at, result) "
        "VALUES (?, ?, ?, datetime('now'), datetime('now'), ?)",
        (pod_id, step, status, str(result)[:500])
    )
    c.commit(); c.close()


@app.route("/api/ad/status/<pod_id>")
def api_ad_status(pod_id):
    """Return latest ad_verify step status for a POD."""
    c = _db()
    row = c.execute(
        "SELECT status, result, completed_at FROM pipeline_steps "
        "WHERE pod_id=? AND step_name='ad_verify' ORDER BY completed_at DESC LIMIT 1",
        (pod_id,)
    ).fetchone()
    c.close()
    if not row:
        return jsonify({"status": "pending", "result": "", "completed_at": ""})
    return jsonify({"status": row["status"], "result": row["result"],
                    "completed_at": row["completed_at"]})


@app.route("/api/ad/recheck/<pod_id>", methods=["POST"])
def api_ad_recheck(pod_id):
    """Re-run AD verification (read-only LDAP query) inside POD VPN namespace."""
    import threading
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container not running for {pod_id}"}), 400

    def _check():
        ok, result = _run_ad_phase(pod_id, "phase_ad_verify")
        _persist_ad_step(pod_id, ok, result, "ad_verify")

    threading.Thread(target=_check, daemon=True).start()
    return jsonify({"status": "ok", "message": f"AD re-check started for {pod_id}"})


@app.route("/api/ad/rerun/<pod_id>", methods=["POST"])
def api_ad_rerun(pod_id):
    """Run ADDuoTenantUserProvisioning.ps1 on Jumphost1 via WinRM, then re-verify."""
    import threading
    ok, msg = _ensure_pipeline_container(pod_id)
    if not ok:
        return jsonify({"status": "error", "message": f"Could not start pipeline container: {msg}"}), 400

    def _rerun():
        def _live_log(msg):
            try:
                c = _db()
                c.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)", (pod_id, msg))
                c.commit(); c.close()
            except Exception:
                pass

        _live_log("[AD] Running ADDuoTenantUserProvisioning.ps1 on Jumphost1...")
        ok, result = _run_ad_phase(pod_id, "phase_ad_rerun")
        _live_log(f"[AD] Result: {'✓ OK' if ok else '✗ FAILED'} — {str(result)[:300]}")
        _persist_ad_step(pod_id, ok, result, "ad_verify")

    threading.Thread(target=_rerun, daemon=True).start()
    return jsonify({"status": "ok", "message": f"AD re-run started for {pod_id}"})


@app.route("/api/scc/status/<pod_id>")
def api_scc_status(pod_id):
    """Return all SCC checklist items for a POD."""
    c = _db()
    rows = c.execute(
        "SELECT item_key, status, detail, confirmed_by, confirmed_at "
        "FROM scc_checklist WHERE pod_id=?", (pod_id,)
    ).fetchall()
    c.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/scc/recheck/<pod_id>", methods=["POST"])
def api_scc_recheck(pod_id):
    """Re-run automated SCC checks directly on host (needs public internet)."""
    import threading, importlib, os as _os

    # Mark as running immediately so UI can poll
    c = _db()
    c.execute(
        "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, result) VALUES (?,?,?,datetime('now'),?)",
        (pod_id, "scc_reset_check", "running", "")
    )
    c.commit(); c.close()
    log(pod_id, "[scc_reset_check] Starting SCC API checks...")

    def _check():
        _os.environ["POD_ID"] = pod_id
        _os.environ["DB_PATH"] = str(Path(__file__).parent / "data" / "pod_state.db")
        _os.environ["SCC_KEYS_DIR"] = str(Path(__file__).parent / "data" / "scc_keys")
        try:
            import onboard_router as _or
            importlib.reload(_or)
            ok, result = _or.phase_scc_reset_check()
            log(pod_id, f"[scc_reset_check] {'OK' if ok else 'FAILED'}: {result}")
            c2 = _db()
            c2.execute(
                "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, result) VALUES (?,?,?,?)",
                (pod_id, "scc_reset_check", "completed" if ok else "failed", result)
            )
            c2.commit(); c2.close()
        except Exception as e:
            msg = f"ERROR: {e}"
            log(pod_id, f"[scc_reset_check] {msg}")
            c3 = _db()
            c3.execute(
                "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, result) VALUES (?,?,?,?)",
                (pod_id, "scc_reset_check", "failed", msg)
            )
            c3.commit(); c3.close()

    threading.Thread(target=_check, daemon=True).start()
    return jsonify({"status": "ok", "message": f"SCC re-check started for {pod_id}"})


@app.route("/api/pipeline-steps/<pod_id>", methods=["GET"])
def api_pipeline_steps(pod_id):
    """Return all pipeline steps for a POD."""
    c = _db()
    rows = c.execute(
        "SELECT step_name, status, result, started_at, completed_at FROM pipeline_steps WHERE pod_id=? ORDER BY rowid",
        (pod_id,)
    ).fetchall()
    c.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/scc/recheck-timeout/<pod_id>", methods=["POST"])
def api_scc_recheck_timeout(pod_id):
    """Mark a stuck SCC recheck as failed (called on cancel or UI timeout)."""
    c = _db()
    c.execute(
        "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, result) VALUES (?,?,?,?)",
        (pod_id, "scc_reset_check", "failed", "Timed out or cancelled — re-check manually")
    )
    c.commit(); c.close()
    log(pod_id, "[scc_reset_check] Timed out or cancelled by user")
    return jsonify({"status": "ok"})


@app.route("/api/scc/run-check-sync/<pod_id>", methods=["POST"])
def api_scc_run_check_sync(pod_id):
    """Run phase_scc_reset_check directly on the host (public internet access for api.sse.cisco.com).
    Called by the pipeline container via host.docker.internal when inside Docker."""
    import sys, os as _os
    sys.path.insert(0, str(Path(__file__).parent))
    _os.environ["POD_ID"] = pod_id
    _os.environ["DB_PATH"] = str(Path(__file__).parent / "data" / "pod_state.db")
    _os.environ["SCC_KEYS_DIR"] = str(Path(__file__).parent / "data" / "scc_keys")
    try:
        import importlib, onboard_router
        importlib.reload(onboard_router)
        ok, result = onboard_router.phase_scc_reset_check()
        return jsonify({"ok": ok, "result": result})
    except Exception as e:
        return jsonify({"ok": False, "result": str(e)}), 500


@app.route("/api/scc/confirm/<pod_id>/<item_key>", methods=["POST"])
def api_scc_confirm(pod_id, item_key):
    """Mark a manual SCC checklist item as confirmed by proctor."""
    data = request.get_json(silent=True) or {}
    confirmed_by = data.get("confirmed_by", "proctor")
    MANUAL_ITEMS = {
        "logging_settings", "ravpn_profiles",
        "dlp_rules", "private_resources", "dns_servers",
        "ravpn_ip_pool", "ise_pxgrid", "epp_manual",
        "duo_saml", "te_integration",
    }
    if item_key not in MANUAL_ITEMS:
        return jsonify({"status": "error", "message": f"Unknown manual item: {item_key}"}), 400
    c = _db()
    c.execute(
        "INSERT OR REPLACE INTO scc_checklist "
        "(pod_id, item_key, status, detail, confirmed_by, confirmed_at) "
        "VALUES (?, ?, 'completed', 'Manually confirmed', ?, datetime('now'))",
        (pod_id, item_key, confirmed_by)
    )
    c.commit(); c.close()
    return jsonify({"status": "ok", "item_key": item_key})


@app.route("/api/scc/unconfirm/<pod_id>/<item_key>", methods=["POST"])
def api_scc_unconfirm(pod_id, item_key):
    """Reset a manual SCC checklist item back to pending."""
    c = _db()
    c.execute(
        "INSERT OR REPLACE INTO scc_checklist "
        "(pod_id, item_key, status, detail, confirmed_by, confirmed_at) "
        "VALUES (?, ?, 'pending', '', '', NULL)",
        (pod_id, item_key)
    )
    c.commit(); c.close()
    return jsonify({"status": "ok", "item_key": item_key})


# ── EVPN Fabric endpoints ─────────────────────────────────────────────────────

@app.route("/api/fabric/status/<pod_id>")
def api_fabric_status(pod_id):
    """Return per-step fabric status for a POD."""
    import evpn_fabric
    evpn_fabric.ensure_fabric_table()
    c = _db()
    rows = c.execute(
        "SELECT step_name, status, result, started_at, completed_at "
        "FROM fabric_steps WHERE pod_id=?", (pod_id,)
    ).fetchall()
    c.close()
    steps = {}
    for row in rows:
        steps[row[0]] = {
            "status":       row[1],
            "result":       row[2] or "",
            "started_at":   row[3] or "",
            "completed_at": row[4] or "",
        }
    return jsonify({"pod_id": pod_id, "steps": steps})


@app.route("/api/fabric/run/<pod_id>", methods=["POST"])
def api_fabric_run(pod_id):
    """Kick off EVPN fabric via docker run inside the VPN network namespace."""
    import threading, evpn_fabric
    evpn_fabric.ensure_fabric_table()

    # Verify VPN container is running
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    data = request.get_json(silent=True) or {}
    from_step = int(data.get("from_step", 1))

    def _run():
        result = subprocess.run([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "-e", f"POD_ID={pod_id}",
            "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
            "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
            "--entrypoint", "python3",
            "pod-automator:latest",
            "evpn_fabric.py", "--from", str(from_step)
        ], capture_output=True, text=True, timeout=600)
        log(pod_id, f"[fabric] stdout: {result.stdout[-500:].strip()}")
        if result.stderr:
            log(pod_id, f"[fabric] stderr: {result.stderr[-300:].strip()}")
        _clear_stuck_running(pod_id, "fabric_steps")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "message": f"Fabric automation started for {pod_id} from step {from_step}"})


@app.route("/api/fabric/verify/<pod_id>", methods=["POST"])
def api_fabric_verify(pod_id):
    """Run verify-only fabric steps via docker run inside the VPN network namespace."""
    import threading, evpn_fabric
    evpn_fabric.ensure_fabric_table()

    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    def _run():
        result = subprocess.run([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "-e", f"POD_ID={pod_id}",
            "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
            "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
            "--entrypoint", "python3",
            "pod-automator:latest",
            "evpn_fabric.py", "--verify"
        ], capture_output=True, text=True, timeout=120)
        log(pod_id, f"[fabric-verify] stdout: {result.stdout[-500:].strip()}")
        if result.stderr:
            log(pod_id, f"[fabric-verify] stderr: {result.stderr[-300:].strip()}")
        _clear_stuck_running(pod_id, "fabric_steps")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "message": f"Fabric verify started for {pod_id}"})


@app.route("/api/fabric/reset/<pod_id>", methods=["POST"])
def api_fabric_reset(pod_id):
    """Clear all fabric steps for a POD so it can be re-run from scratch."""
    import evpn_fabric
    evpn_fabric.ensure_fabric_table()
    c = _db()
    c.execute("DELETE FROM fabric_steps WHERE pod_id=?", (pod_id,))
    c.commit(); c.close()
    return jsonify({"status": "ok", "message": f"Fabric steps reset for {pod_id}"})


# ---------------------------------------------------------------------------
# Watchdog helper — clears stuck 'running' rows after a container exits
# ---------------------------------------------------------------------------

def _clear_stuck_running(pod_id, table, mode=None):
    """After a docker container exits, any row still at status='running' for
    this pod was never updated (container crashed/OOM/killed).  Mark them
    failed so the UI doesn't show a forever-spinning badge.

    Args:
        pod_id: POD identifier string
        table:  'sda_steps' or 'fabric_steps'
        mode:   optional mode column filter (used by sda_steps which has a
                'mode' column — 'deploy' or 'rollback')
    """
    try:
        c = _db()
        if mode:
            c.execute(
                f"UPDATE {table} SET status='failed', result='container exited unexpectedly' "
                "WHERE pod_id=? AND mode=? AND status='running'",
                (pod_id, mode)
            )
        else:
            c.execute(
                f"UPDATE {table} SET status='failed', result='container exited unexpectedly' "
                "WHERE pod_id=? AND status='running'",
                (pod_id,)
            )
        c.commit()
        c.close()
    except Exception as e:
        log(pod_id, f"[watchdog] WARNING: could not clear stuck running rows in {table}: {e}")


# ---------------------------------------------------------------------------
# SDA Fabric API routes
# ---------------------------------------------------------------------------

SDA_DEPLOY_STEPS   = ["discovery", "provision", "fabric_site", "virtual_networks",
                       "anycast_gateways", "transit", "clean_fabric_vlans", "fabric_devices",
                       "l3_handoff", "configure_handoff_interface", "deploy_anycast_gateways",
                       "port_assignments", "verify"]
SDA_ROLLBACK_STEPS = ["remove_port_assignments", "remove_l3_handoffs", "restore_handoff_interface",
                       "remove_fabric_devices", "remove_anycast_gateways", "disable_gbac_policy",
                       "remove_transit", "remove_vn_assignments", "remove_virtual_networks",
                       "remove_fabric_site", "delete_devices", "delete_discovery",
                       "delete_ise_nads", "remove_network_profile"]


SDA_DEPLOY_STEP_KEYS   = ["discovery","provision","fabric_site","virtual_networks","anycast_gateways","transit","clean_fabric_vlans","fabric_devices","l3_handoff","configure_handoff_interface","deploy_anycast_gateways","port_assignments","verify"]
SDA_ROLLBACK_STEP_KEYS = ["remove_port_assignments","remove_l3_handoffs","restore_handoff_interface","remove_fabric_devices","remove_anycast_gateways","disable_gbac_policy","remove_transit","remove_vn_assignments","remove_virtual_networks","remove_fabric_site","delete_devices","delete_discovery","delete_ise_nads","remove_network_profile"]


def _ensure_sda_table():
    import sda_fabric
    sda_fabric.DB_PATH = str(DATA_DIR / "data" / "pod_state.db")
    sda_fabric.ensure_sda_table()


@app.route("/api/sda/status/<pod_id>")
def api_sda_status(pod_id):
    """Return SDA step status from sda_steps table."""
    _ensure_sda_table()
    c = _db()
    rows = c.execute(
        "SELECT mode, step_name, status, result, started_at, completed_at "
        "FROM sda_steps WHERE pod_id=?", (pod_id,)
    ).fetchall()
    c.close()
    steps = {"deploy": {}, "rollback": {}}
    for mode, step_name, status, result, started_at, completed_at in rows:
        steps.setdefault(mode, {})[step_name] = {
            "status":       status or "pending",
            "result":       result or "",
            "started_at":   started_at or "",
            "completed_at": completed_at or "",
        }
    return jsonify({"pod_id": pod_id, "deploy": steps["deploy"], "rollback": steps["rollback"]})


@app.route("/api/sda/deploy/<pod_id>", methods=["POST"])
def api_sda_deploy(pod_id):
    """Run full SDA fabric deploy pipeline."""
    _ensure_sda_table()
    from_step = request.json.get("from_step") if request.is_json else None
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    from_arg = f"from_step='{from_step}'" if from_step else "from_step=None"
    script = (
        "import sys, os; sys.path.insert(0, '.'); import sda_fabric; "
        f"sda_fabric.POD_ID = '{pod_id}'; "
        "sda_fabric.DB_PATH = '/pipeline/host-data/pod_state.db'; "
        f"ok, msg = sda_fabric.run_deploy({from_arg}, log_fn=print); "
        "print(('OK: ' if ok else 'FAIL: ') + str(msg))"
    )

    import threading
    def _run():
        proc = subprocess.Popen([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "-e", f"POD_ID={pod_id}",
            "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
            "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
            "--entrypoint", "python3",
            "pod-automator:latest", "-u", "-c", script
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log(pod_id, f"[sda/log] {line}")
        proc.wait()
        _clear_stuck_running(pod_id, "sda_steps", mode="deploy")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "ok", "message": f"SDA deploy started for {pod_id}"})


@app.route("/api/sda/rollback/<pod_id>", methods=["POST"])
def api_sda_rollback(pod_id):
    """Run full SDA fabric rollback pipeline."""
    _ensure_sda_table()
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    script = (
        "import sys; sys.path.insert(0, '.'); import sda_fabric; "
        f"sda_fabric.POD_ID = '{pod_id}'; "
        "sda_fabric.DB_PATH = '/pipeline/host-data/pod_state.db'; "
        "ok, msg = sda_fabric.run_rollback(log_fn=print); "
        "print(('OK: ' if ok else 'FAIL: ') + str(msg))"
    )

    import threading
    def _run():
        proc = subprocess.Popen([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "-e", f"POD_ID={pod_id}",
            "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
            "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
            "--entrypoint", "python3",
            "pod-automator:latest", "-u", "-c", script
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log(pod_id, f"[sda/log] {line}")
        proc.wait()
        _clear_stuck_running(pod_id, "sda_steps", mode="rollback")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "ok", "message": f"SDA rollback started for {pod_id}"})


@app.route("/api/sda/clear/<pod_id>", methods=["POST"])
def api_sda_clear(pod_id):
    """Clear all SDA step rows and log lines for a POD."""
    _ensure_sda_table()
    c = _db()
    c.execute("DELETE FROM sda_steps WHERE pod_id=?", (pod_id,))
    c.execute("DELETE FROM pipeline_logs WHERE pod_id=? AND log_line LIKE '[sda/%'", (pod_id,))
    c.commit(); c.close()
    return jsonify({"status": "ok", "message": f"SDA state cleared for {pod_id}"})



@app.route("/api/catc/discover/<pod_id>", methods=["POST"])
def api_catc_discover(pod_id):
    """Run Catalyst Center discovery for a POD's switches (manual trigger)."""
    import threading

    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    def _run():
        # Clear previous catc step logs for this pod so re-runs start fresh
        c = _db()
        c.execute("DELETE FROM pipeline_logs WHERE pod_id=? AND log_line LIKE '[catc:step]%'", (pod_id,))
        c.commit(); c.close()

        proc = subprocess.Popen([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "-e", f"POD_ID={pod_id}",
            "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
            "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
            "--entrypoint", "python3",
            "pod-automator:latest", "-u", "-c",
            "import sys; sys.path.insert(0,'/pipeline'); import onboard_router; "
            "ok, r = onboard_router.phase_catc_discover(); "
            "print(('OK: ' if ok else 'FAIL: ') + str(r))"
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log(pod_id, line)  # writes every [catc:step] line to pipeline_logs

        proc.wait()

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "message": f"Catalyst Center discovery started for {pod_id}"})


@app.route("/api/catc/clear/<pod_id>", methods=["POST"])
def api_catc_clear(pod_id):
    """Clear CatC discovery step logs so the tile resets to pending."""
    c = _db()
    c.execute("DELETE FROM pipeline_logs WHERE pod_id=? AND log_line LIKE '[catc:step]%'", (pod_id,))
    c.commit(); c.close()
    return jsonify({"status": "ok", "message": f"CatC discovery reset for {pod_id}"})


@app.route("/api/catc/status/<pod_id>")
def api_catc_status(pod_id):
    """Return per-step CatC discovery status for a POD."""
    c = _db()
    rows = c.execute(
        "SELECT log_line FROM pipeline_logs WHERE pod_id=? AND log_line LIKE '[catc:step]%' ORDER BY rowid",
        (pod_id,)
    ).fetchall()
    c.close()

    # Steps in order
    step_order = ["auth", "check_inventory", "create_discovery", "verify_results", "assign_site", "provision", "discover_wlc", "assign_wlc_site"]
    step_labels = {
        "auth":             "Authenticate to Catalyst Center",
        "check_inventory":  "Check Existing Inventory",
        "create_discovery": "Run Discovery Job",
        "verify_results":   "Verify Reachability",
        "assign_site":      "Assign to Site (MAIN)",
        "provision":        "Provision / Sync with Site",
        "discover_wlc":     "Discover C9800-WLC",
        "assign_wlc_site":  "Assign WLC to Site",
    }

    # Parse log lines: [catc:step] <step> | <status> | <message>
    steps = {}
    for row in rows:
        line = row["log_line"]
        # format: [catc:step] step_name | status | message
        body = line[len("[catc:step] "):]
        parts = [p.strip() for p in body.split("|", 2)]
        if len(parts) < 2:
            continue
        name, status = parts[0], parts[1]
        msg = parts[2] if len(parts) > 2 else ""
        # Last line wins for each step
        steps[name] = {"status": status, "message": msg}

    step_list = []
    overall_running = False
    for key in step_order:
        s = steps.get(key, {"status": "pending", "message": ""})
        if s["status"] == "running":
            overall_running = True
        step_list.append({
            "key":     key,
            "label":   step_labels[key],
            "status":  s["status"],
            "message": s["message"],
        })

    completed = sum(1 for s in step_list if s["status"] == "completed")
    failed    = sum(1 for s in step_list if s["status"] == "failed")
    overall   = "running" if overall_running else ("failed" if failed else ("completed" if completed == len(step_order) else "pending"))

    return jsonify({
        "steps":   step_list,
        "overall": overall,
        "running": overall_running,
        "total":   len(step_order),
        "done":    completed,
    })

BASECONFIG_SWITCHES = {
    "border_spine": {"name": "Border Spine", "ip": "198.18.128.24"},
    "leaf1":        {"name": "Leaf 1",        "ip": "198.18.128.22"},
    "leaf2":        {"name": "Leaf 2",        "ip": "198.18.128.23"},
}

@app.route("/api/baseconfig/status/<pod_id>")
def api_baseconfig_status(pod_id):
    """Return last reset/verify result for each switch from pipeline_logs."""
    result = {}
    c = _db()
    for key in BASECONFIG_SWITCHES:
        # Look for reset result
        rows = c.execute(
            "SELECT log_line FROM pipeline_logs WHERE pod_id=? AND log_line LIKE ? ORDER BY rowid DESC LIMIT 1",
            (pod_id, f"[baseconfig/{key}]%")
        ).fetchall()
        reset_line = rows[0]["log_line"] if rows else None
        # Look for verify result
        vrows = c.execute(
            "SELECT log_line FROM pipeline_logs WHERE pod_id=? AND log_line LIKE ? ORDER BY rowid DESC LIMIT 1",
            (pod_id, f"[verify/{key}]%")
        ).fetchall()
        verify_line = vrows[0]["log_line"] if vrows else None
        result[key] = {"reset": reset_line, "verify": verify_line}
    # ISE cleanup status
    ise_rows = c.execute(
        "SELECT log_line FROM pipeline_logs WHERE pod_id=? AND log_line LIKE '[baseconfig/ise]%' ORDER BY rowid DESC LIMIT 1",
        (pod_id,)
    ).fetchall()
    result["ise"] = {"reset": ise_rows[0]["log_line"] if ise_rows else None, "verify": None}
    # CC cleanup status
    catc_rows = c.execute(
        "SELECT log_line FROM pipeline_logs WHERE pod_id=? AND log_line LIKE '[baseconfig/catc]%' ORDER BY rowid DESC LIMIT 1",
        (pod_id,)
    ).fetchall()
    result["catc"] = {"reset": catc_rows[0]["log_line"] if catc_rows else None, "verify": None}
    c.close()
    return jsonify(result)


@app.route("/api/baseconfig/verify/<pod_id>", methods=["POST"])
def api_baseconfig_verify(pod_id):
    """Verify base config on all 3 switches via docker run in VPN namespace."""
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    def _run():
        for key in BASECONFIG_SWITCHES:
            ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            log(pod_id, f"[verify/{key}] RUNNING started_at={ts}: connecting to {BASECONFIG_SWITCHES[key]['ip']}...")
            script = (
                "import sys, os; sys.path.insert(0, '.'); import onboard_router; "
                f"ok, detail = onboard_router.phase_baseconfig_verify('{key}'); "
                "print(repr((ok, detail)))"
            )
            result = subprocess.run([
                "docker", "run", "--rm",
                "--network", f"container:vpn-{pod_id}",
                "-v", f"{os.path.abspath(DATA_DIR / 'base_configs')}:/pipeline/base_configs:ro",
                "-e", "BASE_CONFIGS_DIR=/pipeline/base_configs",
                "--entrypoint", "python3",
                "pod-automator:latest", "-c", script
            ], capture_output=True, text=True, timeout=120)
            stdout = result.stdout.strip()
            last_line = stdout.splitlines()[-1] if stdout else ""
            try:
                ok_val, detail_val = eval(last_line)
            except Exception:
                ok_val, detail_val = False, f"parse error: {stdout[:200]}"
            status_str = "OK" if ok_val else "FAILED"
            log(pod_id, f"[verify/{key}] {status_str}: {detail_val}")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "message": f"Verify started for all switches on {pod_id}"})

@app.route("/api/baseconfig/reset/<pod_id>/<switch_key>", methods=["POST"])
def api_baseconfig_reset(pod_id, switch_key):
    """Push base config to one switch (or 'all') via docker run in VPN namespace."""
    if switch_key not in BASECONFIG_SWITCHES and switch_key != "all":
        return jsonify({"status": "error", "message": f"Unknown switch: {switch_key}"}), 400

    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    # Leaves first, then Border Spine — leafs are only reachable through the spine's
    # management VLAN, so resetting the spine first would lose reachability to the leafs.
    RESET_ORDER = ["leaf1", "leaf2", "border_spine"]
    keys = [k for k in RESET_ORDER if k in BASECONFIG_SWITCHES] if switch_key == "all" else [switch_key]

    def _sanitize(s):
        """Collapse multiline error strings to a single line for clean card display."""
        return " | ".join(line.strip() for line in str(s).splitlines() if line.strip())[:300]
    def _run():
        for key in keys:
            import datetime as _dt
            ts = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            log(pod_id, f"[baseconfig/{key}] RUNNING started_at={ts}: connecting to {BASECONFIG_SWITCHES[key]['ip']}...")
            script = (
                "import sys, os; sys.path.insert(0, '.'); import onboard_router; "
                f"ok, detail = onboard_router.phase_baseconfig_reset('{key}'); "
                "print(repr((ok, detail)))"
            )
            try:
                result = subprocess.run([
                    "docker", "run", "--rm",
                    "--network", f"container:vpn-{pod_id}",
                    "-v", f"{os.path.abspath(DATA_DIR / 'base_configs')}:/pipeline/base_configs:ro",
                    "-e", "BASE_CONFIGS_DIR=/pipeline/base_configs",
                    "--entrypoint", "python3",
                    "pod-automator:latest", "-c", script
                ], capture_output=True, text=True, timeout=420)
                stdout = result.stdout.strip()
                last_line = stdout.splitlines()[-1] if stdout else ""
                try:
                    ok_val, detail_val = eval(last_line)
                except Exception:
                    ok_val, detail_val = False, f"parse error: {stdout[:200]} stderr: {result.stderr[:100]}"
            except subprocess.TimeoutExpired:
                ok_val, detail_val = False, "timed out after 300s"
            except Exception as e:
                ok_val, detail_val = False, str(e)
            status_str = "OK" if ok_val else "FAILED"
            log(pod_id, f"[baseconfig/{key}] {status_str}: {_sanitize(detail_val)}")

            # Auto-verify after successful reset
            if ok_val:
                import datetime as _dt2
                ts2 = _dt2.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                log(pod_id, f"[verify/{key}] RUNNING started_at={ts2}: connecting to {BASECONFIG_SWITCHES[key]['ip']}...")
                vscript = (
                    "import sys, os; sys.path.insert(0, '.'); import onboard_router; "
                    f"ok, detail = onboard_router.phase_baseconfig_verify('{key}'); "
                    "print(repr((ok, detail)))"
                )
                try:
                    vresult = subprocess.run([
                        "docker", "run", "--rm",
                        "--network", f"container:vpn-{pod_id}",
                        "-v", f"{os.path.abspath(DATA_DIR / 'base_configs')}:/pipeline/base_configs:ro",
                        "-e", "BASE_CONFIGS_DIR=/pipeline/base_configs",
                        "--entrypoint", "python3",
                        "pod-automator:latest", "-c", vscript
                    ], capture_output=True, text=True, timeout=60)
                    vout = vresult.stdout.strip()
                    vlast = vout.splitlines()[-1] if vout else ""
                    try:
                        vok, vdetail = eval(vlast)
                    except Exception:
                        vok, vdetail = False, f"parse error: {vout[:200]}"
                except Exception as ve:
                    vok, vdetail = False, str(ve)
                vstatus = "OK" if vok else "FAILED"
                log(pod_id, f"[verify/{key}] {vstatus}: {_sanitize(vdetail)}")

        # After all switches, clean up ISE NADs (only when resetting all)
        if switch_key == "all":
            import datetime as _dt
            ts = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            log(pod_id, f"[baseconfig/ise] RUNNING started_at={ts}: removing switch NADs from ISE...")
            script = (
                "import sys; sys.path.insert(0, '.'); import onboard_router; "
                "ok, detail = onboard_router.phase_ise_cleanup(); "
                "print(repr((ok, detail)))"
            )
            try:
                result = subprocess.run([
                    "docker", "run", "--rm",
                    "--network", f"container:vpn-{pod_id}",
                    "--entrypoint", "python3",
                    "pod-automator:latest", "-c", script
                ], capture_output=True, text=True, timeout=60)
                stdout = result.stdout.strip()
                last_line = stdout.splitlines()[-1] if stdout else ""
                try:
                    ok_val, detail_val = eval(last_line)
                except Exception:
                    ok_val, detail_val = False, f"parse error: {stdout[:200]} stderr: {result.stderr[:100]}"
            except subprocess.TimeoutExpired:
                ok_val, detail_val = False, "timed out after 60s"
            except Exception as e:
                ok_val, detail_val = False, str(e)
            status_str = "OK" if ok_val else "FAILED"
            log(pod_id, f"[baseconfig/ise] {status_str}: {_sanitize(detail_val)}")

            # Catalyst Center — delete the 3 switches from inventory
            ts = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
            log(pod_id, f"[baseconfig/catc] RUNNING started_at={ts}: removing switches from Catalyst Center...")
            script = (
                "import sys; sys.path.insert(0, '.'); import onboard_router; "
                "ok, detail = onboard_router.phase_catc_cleanup(); "
                "print(repr((ok, detail)))"
            )
            try:
                result = subprocess.run([
                    "docker", "run", "--rm",
                    "--network", f"container:vpn-{pod_id}",
                    "--entrypoint", "python3",
                    "pod-automator:latest", "-c", script
                ], capture_output=True, text=True, timeout=60)
                stdout = result.stdout.strip()
                last_line = stdout.splitlines()[-1] if stdout else ""
                try:
                    ok_val, detail_val = eval(last_line)
                except Exception:
                    ok_val, detail_val = False, f"parse error: {stdout[:200]} stderr: {result.stderr[:100]}"
            except subprocess.TimeoutExpired:
                ok_val, detail_val = False, "timed out after 60s"
            except Exception as e:
                ok_val, detail_val = False, str(e)
            status_str = "OK" if ok_val else "FAILED"
            log(pod_id, f"[baseconfig/catc] {status_str}: {_sanitize(detail_val)}")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "message": f"Base config reset started for {switch_key} on {pod_id}"})


@app.route("/api/baseconfig/service/<pod_id>/<service>", methods=["POST"])
def api_baseconfig_service(pod_id, service):
    """Run ISE or CC cleanup individually for a POD."""
    if service not in ("ise", "catc"):
        return jsonify({"status": "error", "message": f"Unknown service: {service}"}), 400

    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    fn = "phase_ise_cleanup" if service == "ise" else "phase_catc_cleanup"
    label = "ISE NAD cleanup" if service == "ise" else "Catalyst Center cleanup"

    def _run():
        import datetime as _dt
        ts = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        log(pod_id, f"[baseconfig/{service}] RUNNING started_at={ts}: starting {label}...")
        script = (
            f"import sys; sys.path.insert(0, '.'); import onboard_router; "
            f"ok, detail = onboard_router.{fn}(); "
            f"print(repr((ok, detail)))"
        )
        try:
            result = subprocess.run([
                "docker", "run", "--rm",
                "--network", f"container:vpn-{pod_id}",
                "--entrypoint", "python3",
                "pod-automator:latest", "-c", script
            ], capture_output=True, text=True, timeout=60)
            stdout = result.stdout.strip()
            last_line = stdout.splitlines()[-1] if stdout else ""
            try:
                ok_val, detail_val = eval(last_line)
            except Exception:
                ok_val, detail_val = False, f"parse error: {stdout[:200]} stderr: {result.stderr[:100]}"
        except subprocess.TimeoutExpired:
            ok_val, detail_val = False, "timed out after 60s"
        except Exception as e:
            ok_val, detail_val = False, str(e)
        status_str = "OK" if ok_val else "FAILED"
        detail_clean = " | ".join(line.strip() for line in str(detail_val).splitlines() if line.strip())[:300]
        log(pod_id, f"[baseconfig/{service}] {status_str}: {detail_clean}")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "message": f"{label} started for {pod_id}"})


@app.route("/api/baseconfig/clear/<pod_id>", methods=["POST"])
def api_baseconfig_clear(pod_id):
    """Delete all baseconfig and verify log lines for this POD so cards reset to 'Not run'."""
    c = _db()
    c.execute(
        "DELETE FROM pipeline_logs WHERE pod_id=? AND (log_line LIKE '[baseconfig/%' OR log_line LIKE '[verify/%')",
        (pod_id,)
    )
    c.commit()
    c.close()
    return jsonify({"status": "ok", "message": f"Baseconfig status cleared for {pod_id}"})



    """Run a named phase function from onboard_router.py inside the VPN network namespace."""
    script = (
        "import sys, os\n"
        "sys.path.insert(0, '/pipeline')\n"
        f"os.environ['POD_ID'] = '{pod_id}'\n"
        "os.environ['DB_PATH'] = '/pipeline/host-data/pod_state.db'\n"
        "os.environ['SCC_KEYS_DIR'] = '/pipeline/host-data/scc_keys'\n"
        "import onboard_router\n"
        f"fn = getattr(onboard_router, '{phase_fn}')\n"
        "ok, result = fn()\n"
        "print('ok' if ok else 'fail', str(result)[:300])\n"
    )
    subprocess.run(
        ["docker", "run", "--rm",
         "--network", f"container:vpn-{pod_id}",
         "-v", f"{os.path.expanduser('~/sw_projects/pod_automator')}:/pipeline",
         "-v", f"{os.path.expanduser('~/sw_projects/pod_automator/data')}:/pipeline/host-data",
         "-e", f"POD_ID={pod_id}",
         "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
         "-e", "SCC_KEYS_DIR=/pipeline/host-data/scc_keys",
         "pod-automator-pipeline",
         "python3", "-c", script],
        timeout=120
    )


@app.route("/api/ssh/terminal/<pod_id>/<ip>", methods=["POST"])
def api_ssh_terminal(pod_id, ip):
    """Opens macOS Terminal.app with SSH to switch via docker exec through VPN container.
    Writes a temp shell script to avoid quoting issues with sshpass inside osascript."""
    import tempfile, stat
    script_content = (
        "#!/bin/bash\n"
        f"docker exec -it vpn-{pod_id} sshpass -p 'C1sco12345' "
        f"ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null "
        f"netadmin@{ip}\n"
        "echo ''\n"
        "read -p 'Press Enter to close...'\n"
    )
    tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.sh', delete=False, prefix='pod_ssh_')
    tmp.write(script_content)
    tmp.close()
    os.chmod(tmp.name, stat.S_IRWXU)
    apple_script = f'tell application "Terminal" to do script "{tmp.name}"'
    subprocess.Popen(["osascript", "-e", apple_script])
    return jsonify({"status": "ok"})


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
    assigned_col = _col("assigned_to", "assigned", "cco id", "cco_id", "attendee", "student")

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

        vpn_host = row.get(vpn_host_col, "").strip() if vpn_host_col else ""
        vpn_user = row.get(vpn_user_col, "").strip() if vpn_user_col else ""
        vpn_pass = row.get(vpn_pass_col, "").strip() if vpn_pass_col else ""
        session_id = row.get(session_col, "").strip() if session_col else ""
        assigned_to = (row.get(assigned_col, "").strip() if assigned_col else "")

        router_ip = row.get(router_ip_col, "") if router_ip_col else ""
        if not router_ip:
            router_ip = "198.18.133.25"  # all PODs share the same router IP, isolated by per-POD VPN

        conn = _db()
        existing = conn.execute("SELECT pod_id FROM pods WHERE pod_id = ?", (pod_id,)).fetchone()
        if existing:
            # Only overwrite assigned_to if CSV provides a non-blank value
            if assigned_to:
                conn.execute("""UPDATE pods SET status='pending', device_data=?, router_serial=?,
                    vpn_host=?, vpn_user=?, vpn_pass=?, router_ip=?, session_id=?, assigned_to=?,
                    notes='Imported from event CSV', updated_at=datetime('now')
                    WHERE pod_id=?""",
                    (json.dumps(device_data), router_serial, vpn_host, vpn_user, vpn_pass, router_ip, session_id, assigned_to, pod_id))
            else:
                conn.execute("""UPDATE pods SET status='pending', device_data=?, router_serial=?,
                    vpn_host=?, vpn_user=?, vpn_pass=?, router_ip=?, session_id=?,
                    notes='Imported from event CSV', updated_at=datetime('now')
                    WHERE pod_id=?""",
                    (json.dumps(device_data), router_serial, vpn_host, vpn_user, vpn_pass, router_ip, session_id, pod_id))
        else:
            conn.execute("""INSERT INTO pods
                (pod_id, status, device_data, router_serial, vpn_host, vpn_user, vpn_pass, router_ip, session_id, assigned_to, notes)
                VALUES (?, 'pending', ?, ?, ?, ?, ?, ?, ?, ?, 'Imported from event CSV')""",
                (pod_id, json.dumps(device_data), router_serial, vpn_host, vpn_user, vpn_pass, router_ip, session_id, assigned_to))
        conn.execute("DELETE FROM pipeline_steps WHERE pod_id = ?", (pod_id,))
        conn.commit()
        conn.close()
        created += 1

    return jsonify({"status": "ok", "pods_created": created, "columns": reader.fieldnames})


# ---------------------------------------------------------------------------
# Upgrade Config endpoints
# ---------------------------------------------------------------------------

@app.route("/api/upgrade/config", methods=["GET"])
def api_upgrade_config_get():
    c = _db()
    rows = c.execute("SELECT * FROM upgrade_config").fetchall()
    c.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/upgrade/config", methods=["POST"])
def api_upgrade_config_set():
    data = request.json
    device_type = data.get("device_type")
    golden = data.get("golden_version", "").strip()
    if not device_type or not golden:
        return jsonify({"status": "error", "message": "device_type and golden_version required"}), 400
    c = _db()
    c.execute("""INSERT INTO upgrade_config (device_type, golden_version, updated_at)
                 VALUES (?, ?, datetime('now'))
                 ON CONFLICT(device_type) DO UPDATE SET
                     golden_version=excluded.golden_version,
                     updated_at=excluded.updated_at""",
              (device_type, golden))
    c.commit(); c.close()
    return jsonify({"status": "ok"})


@app.route("/api/upgrade/upload-image", methods=["POST"])
def api_upgrade_upload_image():
    """Receive a .bin image and save it locally to data/images/.
    At upgrade time the pipeline container will check Ubuntu PC first,
    and only copy from here if the file is not already there."""
    if "file" not in request.files:
        return jsonify({"status": "error", "message": "No file provided"}), 400
    f = request.files["file"]
    device_type = request.form.get("device_type", "switch")
    if not f.filename.endswith(".bin"):
        return jsonify({"status": "error", "message": "File must be a .bin image"}), 400

    filename = f.filename
    images_dir = Path(__file__).parent / "data" / "images"
    images_dir.mkdir(parents=True, exist_ok=True)
    local_path = images_dir / filename
    f.save(str(local_path))

    # Update DB
    c = _db()
    c.execute("UPDATE upgrade_config SET image_filename=?, image_path=?, updated_at=datetime('now') WHERE device_type=?",
              (filename, f"/home/cisco/{filename}", device_type))
    c.commit(); c.close()

    return jsonify({"status": "ok", "filename": filename, "local_path": str(local_path)})


def _run_upgrade_container(pod_id, step_name, script):
    """
    Run an upgrade script in a docker container, streaming stdout to pipeline_logs
    and updating the step result live. Shared by switch and router upgrade endpoints.
    """
    import subprocess as sp

    # Mark step as running
    c2 = _db()
    c2.execute("INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, result) "
               "VALUES (?, ?, 'running', datetime('now'), 'Starting...')", (pod_id, step_name))
    c2.commit(); c2.close()

    cmd = [
        "docker", "run", "--rm",
        "--network", f"container:vpn-{pod_id}",
        "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
        "--entrypoint", "python3",
        "pod-automator:latest", "-u", "-c", script
    ]

    ok_val, result_val = False, "No output"
    last_progress = ""
    try:
        proc = sp.Popen(cmd, stdout=sp.PIPE, stderr=sp.STDOUT, text=True)
        for raw_line in proc.stdout:
            line = raw_line.rstrip()
            if not line:
                continue
            # Write to live logs
            cx = _db()
            cx.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)",
                       (pod_id, f"[{step_name}] {line}"))
            cx.commit()
            # Update live result field with latest meaningful line
            if not line.startswith("("):
                last_progress = line.strip()
                cx.execute("UPDATE pipeline_steps SET result=? WHERE pod_id=? AND step_name=?",
                           (last_progress[:500], pod_id, step_name))
                cx.commit()
            cx.close()
            # Parse final result tuple
            if line.startswith("("):
                try: ok_val, result_val = eval(line)
                except Exception: pass
        proc.wait(timeout=60)
    except Exception as e:
        result_val = f"Container error: {e}"

    status = "completed" if ok_val else "failed"
    c3 = _db()
    c3.execute("INSERT OR REPLACE INTO pipeline_steps "
               "(pod_id, step_name, status, started_at, completed_at, result) "
               "VALUES (?, ?, ?, datetime('now'), datetime('now'), ?)",
               (pod_id, step_name, status, str(result_val)[:500]))
    c3.commit(); c3.close()


@app.route("/api/upgrade/switch/<pod_id>/<switch_key>", methods=["POST"])
def api_upgrade_switch(pod_id, switch_key):
    """Run switch upgrade for a specific switch in a POD."""
    import threading
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    c = _db()
    cfg = c.execute("SELECT * FROM upgrade_config WHERE device_type='switch'").fetchone()
    c.close()
    if not cfg or not cfg["image_filename"]:
        return jsonify({"status": "error", "message": "No switch image configured — upload one first"}), 400

    golden = cfg["golden_version"]
    image = cfg["image_filename"]

    def _upgrade():
        script = (
            "import sys; sys.path.insert(0, '.'); import onboard_router; "
            f"onboard_router.UPGRADE_IMAGE_SWITCH = '{image}'; "
            f"onboard_router.GOLDEN_VERSION_SWITCH = '{golden}'; "
            f"ok, result = onboard_router.phase_switch_upgrade('{switch_key}'); "
            "print(repr((ok, result)))"
        )
        step_name = f"upgrade_{switch_key}"
        _run_upgrade_container(pod_id, step_name, script)

    threading.Thread(target=_upgrade, daemon=True).start()
    return jsonify({"status": "ok", "message": f"Switch upgrade started for {switch_key} on {pod_id}"})


@app.route("/api/upgrade/router/<pod_id>", methods=["POST"])
def api_upgrade_router(pod_id):
    """Run router upgrade for a POD."""
    import threading
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    c = _db()
    cfg = c.execute("SELECT * FROM upgrade_config WHERE device_type='router'").fetchone()
    pod = c.execute("SELECT router_ip FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    c.close()
    if not cfg or not cfg["image_filename"]:
        return jsonify({"status": "error", "message": "No router image configured — upload one first"}), 400

    golden = cfg["golden_version"]
    image = cfg["image_filename"]
    router_ip = pod["router_ip"] if pod else "198.18.133.25"

    def _upgrade():
        script = (
            "import sys; sys.path.insert(0, '.'); import onboard_router; "
            f"onboard_router.ROUTER_IP = '{router_ip}'; "
            f"onboard_router.UPGRADE_IMAGE_ROUTER = '{image}'; "
            f"onboard_router.GOLDEN_VERSION_ROUTER = '{golden}'; "
            "ok, result = onboard_router.phase_router_upgrade(); "
            "print(repr((ok, result)))"
        )
        step_name = "upgrade_router"
        _run_upgrade_container(pod_id, step_name, script)

    threading.Thread(target=_upgrade, daemon=True).start()
    return jsonify({"status": "ok", "message": f"Router upgrade started for {pod_id}"})


@app.route("/api/upgrade/status/<pod_id>")
def api_upgrade_status(pod_id):
    """Return upgrade step statuses for a POD."""
    c = _db()
    rows = c.execute(
        "SELECT step_name, status, result, completed_at FROM pipeline_steps "
        "WHERE pod_id=? AND step_name LIKE 'upgrade_%'", (pod_id,)
    ).fetchall()
    c.close()
    return jsonify([dict(r) for r in rows])
@app.route("/api/vpn-connect-pod/<pod_id>", methods=["POST"])
def vpn_connect_pod(pod_id):
    """Connect VPN for a single POD (Docker stack, VPN container only)."""
    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, "docker/generate.py", "--db", "--up", "--pod", pod_id, "--vpn-only"],
            capture_output=True, text=True, timeout=300,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        output = (r.stdout + r.stderr)[:2000]
        return jsonify({
            "status": "ok" if r.returncode == 0 else "error",
            "output": output
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "output": "Timed out after 300s"})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)[:500]})

@app.route("/api/vpn/connect/<pod_id>", methods=["POST"])
def api_vpn_connect(pod_id):
    """Reconnect VPN: teardown then bring up fresh (picks up latest image)."""
    import subprocess
    dp_id = pod_id.lower()
    # Tear down existing container if any
    subprocess.run(
        ["docker", "compose", "-p", dp_id, "down", "vpn"],
        capture_output=True, timeout=30
    )
    # Bring up fresh via generate.py
    try:
        r = subprocess.run(
            [sys.executable, "docker/generate.py", "--db", "--up", "--pod", pod_id, "--vpn-only"],
            capture_output=True, text=True, timeout=300,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        output = (r.stdout + r.stderr)[:2000]
        return jsonify({
            "status": "ok" if r.returncode == 0 else "error",
            "output": output
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "output": "Timed out after 300s"})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)[:500]})

@app.route("/api/delete-pod/<pod_id>", methods=["POST"])
def delete_pod(pod_id):
    """Delete a POD and all its data from the DB."""
    conn = _db()
    conn.execute("DELETE FROM pipeline_steps WHERE pod_id=?", (pod_id,))
    conn.execute("DELETE FROM pipeline_logs WHERE pod_id=?", (pod_id,))
    conn.execute("DELETE FROM pods WHERE pod_id=?", (pod_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"{pod_id} deleted"})


@app.route("/api/reset-pipeline/<pod_id>", methods=["POST"])
def reset_pipeline(pod_id):
    """Reset all pipeline steps to pending so the pipeline can be re-run."""
    conn = _db()
    conn.execute("DELETE FROM pipeline_steps WHERE pod_id=?", (pod_id,))
    conn.execute("DELETE FROM pipeline_logs WHERE pod_id=?", (pod_id,))
    conn.execute("""UPDATE pods SET status='pending', sdwan_online='', notes='',
                    updated_at=datetime('now') WHERE pod_id=?""", (pod_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "message": f"{pod_id} pipeline reset — ready to re-run"})


@app.route("/api/pod-assigned/<pod_id>", methods=["POST"])
def pod_assigned(pod_id):
    """Update the assigned_to field for a POD."""
    data = request.get_json(force=True)
    assigned_to = data.get("assigned_to", "")
    conn = _db()
    conn.execute("UPDATE pods SET assigned_to=?, updated_at=datetime('now') WHERE pod_id=?", (assigned_to, pod_id))
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/pod-scc-keys/<pod_id>", methods=["GET"])
def get_scc_keys(pod_id):
    """Return SCC API key/secret for a POD (masked secret)."""
    conn = _db()
    row = conn.execute(
        "SELECT scc_api_key, scc_api_secret FROM pods WHERE pod_id=?", (pod_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"scc_api_key": "", "scc_api_secret": ""})
    return jsonify({"scc_api_key": row["scc_api_key"] or "", "scc_api_secret": row["scc_api_secret"] or ""})


@app.route("/api/pod-scc-keys/<pod_id>", methods=["POST"])
def save_scc_keys(pod_id):
    """Save SCC API key/secret for a POD."""
    data = request.get_json(force=True)
    key = data.get("scc_api_key", "").strip()
    secret = data.get("scc_api_secret", "").strip()
    conn = _db()
    conn.execute(
        "UPDATE pods SET scc_api_key=?, scc_api_secret=?, updated_at=datetime('now') WHERE pod_id=?",
        (key, secret, pod_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/pod-duo-keys/<pod_id>", methods=["GET"])
def get_duo_keys(pod_id):
    """Return Duo Admin API credentials for a POD."""
    conn = _db()
    row = conn.execute(
        "SELECT duo_ikey, duo_skey, duo_host FROM pods WHERE pod_id=?", (pod_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"duo_ikey": "", "duo_skey": "", "duo_host": ""})
    return jsonify({
        "duo_ikey": row["duo_ikey"] or "",
        "duo_skey":  row["duo_skey"] or "",
        "duo_host":  row["duo_host"] or "",
    })


@app.route("/api/pod-duo-keys/<pod_id>", methods=["POST"])
def save_duo_keys(pod_id):
    """Save Duo Admin API credentials for a POD."""
    data = request.get_json(force=True)
    ikey = data.get("duo_ikey", "").strip()
    skey = data.get("duo_skey", "").strip()
    host = data.get("duo_host", "").strip()
    conn = _db()
    conn.execute(
        "UPDATE pods SET duo_ikey=?, duo_skey=?, duo_host=?, updated_at=datetime('now') WHERE pod_id=?",
        (ikey, skey, host, pod_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


@app.route("/api/run-pod/<pod_id>", methods=["POST"])
def run_pod(pod_id):
    """Run the pipeline for a single POD (VPN must already be connected)."""
    import subprocess, os, tempfile
    from docker.generate import generate_compose, read_db
    pods = read_db(status_filter=("pending", "available", "ready", "running", "in_progress", ""))
    p = next((p for p in pods if p["pod_id"] == pod_id), None)
    if not p:
        return jsonify({"status": "error", "message": f"POD {pod_id} not found in DB"})
    compose = generate_compose(p)
    tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
    tmp.write(compose)
    tmp.close()
    try:
        r = subprocess.run(
            ["docker", "compose", "-p", pod_id.lower(), "-f", tmp.name, "up", "-d", "pipeline"],
            capture_output=True, text=True, timeout=30
        )
        return jsonify({
            "status": "ok" if r.returncode == 0 else "error",
            "message": f"Pipeline started for {pod_id}" if r.returncode == 0 else (r.stderr[:300] or r.stdout[:300])
        })
    finally:
        os.unlink(tmp.name)

@app.route("/api/run-all", methods=["POST"])
def run_all():
    """Run pipeline containers for all PODs with connected VPNs."""
    import subprocess, os, tempfile
    from docker.generate import generate_compose, read_db
    pods = read_db(status_filter=("pending", "available", "running", "in_progress", ""))
    if not pods:
        return jsonify({"status": "error", "message": "No PODs found in DB"})
    results = []
    for p in pods:
        pod_id = p["pod_id"]
        compose = generate_compose(p)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False)
        tmp.write(compose)
        tmp.close()
        try:
            r = subprocess.run(
                ["docker", "compose", "-p", pod_id.lower(), "-f", tmp.name, "up", "-d", "pipeline"],
                capture_output=True, text=True, timeout=30
            )
            if r.returncode == 0:
                results.append(f"{pod_id} started")
            else:
                results.append(f"{pod_id} error: {(r.stderr or r.stdout)[:100]}")
        finally:
            os.unlink(tmp.name)
    return jsonify({"status": "ok", "message": "; ".join(results) if results else "No PODs processed"})

@app.route("/api/vpn/disconnect/<pod_id>", methods=["POST"])
def api_vpn_disconnect(pod_id):
    import subprocess
    dp_id = pod_id.lower()
    r = subprocess.run(
        ["docker", "compose", "-p", dp_id, "ps", "--format=json"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode == 0 and r.stdout.strip():
        subprocess.run(
            ["docker", "compose", "-p", dp_id, "stop", "vpn"],
            capture_output=True, timeout=30
        )
        return jsonify({"status": "ok", "message": "Docker VPN stopped"})
    return jsonify({"status": "error", "message": f"No Docker stack found for {pod_id}"})

@app.route("/api/vpn-connect-all", methods=["POST"])
def vpn_connect_all():
    """Connect all POD VPNs (Docker stacks, VPN containers only)."""
    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, "docker/generate.py", "--db", "--up", "--vpn-only"],
            capture_output=True, text=True, timeout=300,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        return jsonify({
            "status": "ok" if r.returncode == 0 else "error",
            "output": (r.stdout + r.stderr)[:2000]
        })
    except subprocess.TimeoutExpired:
        return jsonify({"status": "error", "output": "Timed out after 300s"})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)[:500]})

@app.route("/api/docker-down", methods=["POST"])
def docker_down():
    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, "docker/generate.py", "--db", "--down"],
            capture_output=True, text=True, timeout=120,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        return jsonify({
            "status": "ok" if r.returncode == 0 else "error",
            "output": (r.stdout + r.stderr)[:2000]
        })
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)[:500]})

@app.route("/api/docker-status")
def docker_status():
    import subprocess
    try:
        r = subprocess.run(
            [sys.executable, "docker/generate.py", "--db", "--status"],
            capture_output=True, text=True, timeout=30,
            cwd=os.path.dirname(os.path.abspath(__file__))
        )
        return jsonify({
            "status": "ok",
            "output": (r.stdout + r.stderr)[:2000]
        })
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)[:500]})

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
  th[data-col]:hover { color: #02c8ff; background: #162a45; }
  .sort-icon { font-size: 10px; opacity: 0.6; margin-left: 3px; }
  td { padding: 8px; border-bottom: 1px solid #1a2d4a; }
  tr:hover td { background: #1a2d4a; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge.pass { background: #003d2a; color: #00e68a; }
  .badge.fail { background: #3d0000; color: #ff4757; }
  .badge.pending { background: #3d0000; color: #ff4444; }
  .badge.running { background: #3d2200; color: #ffa500; }
  .badge.skipped { background: #3d2200; color: #ffa502; }
  .badge.warn { background: #3d2200; color: #ffa502; }
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
  .btn-reconnect { background: #1a2d4a; color: #02c8ff; border: 1px solid #02c8ff; border-radius: 4px;
                   padding: 4px 10px; font-size: 11px; font-weight: 600; cursor: pointer; }
  .btn-reconnect:hover { background: #02c8ff; color: #001f3d; }
  .btn-reconnect:disabled { opacity: 0.4; cursor: not-allowed; }
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
  .tab-content { display: none; background: #112240; border-radius: 0 8px 8px 8px; padding: 16px; min-height: 300px; }
  .tab-content.active { display: block; }

  .pipeline-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(130px, 1fr)); gap: 8px; }
  .step-card { background: #0a1628; border-radius: 6px; padding: 10px; text-align: center; }
  .step-card .step-num { font-size: 11px; color: #667788; }
  .step-card .step-name { font-size: 12px; margin: 4px 0; font-weight: 600; }
  .step-card .step-result { font-size: 10px; color: #667788; word-break: break-all; max-height: 40px; overflow: hidden; }
  .step-dur { font-size: 11px; color: #02c8ff; margin-top: 4px; }
  .step-reboot-bar-bg { background: #0f2236; border-radius: 4px; height: 5px; margin-top: 6px; overflow: hidden; }
  .step-reboot-bar-fill { height: 5px; border-radius: 4px; background: linear-gradient(90deg, #00bceb, #00e68a); transition: width 1s linear; }
  .step-reboot-eta { font-size: 10px; color: #667788; margin-top: 3px; }
  .elapsed-timer { font-size: 13px; color: #00e68a; font-weight: normal; margin-left: 12px; }
  .timer-label { color: #667788; margin-right: 4px; }

  .progress-wrap { background: #0a1628; border-radius: 8px; padding: 12px; margin-bottom: 12px; }
  .progress-bar-bg { background: #1a2d4a; border-radius: 6px; height: 18px; overflow: hidden; position: relative; }
  .progress-bar-fill { background: linear-gradient(90deg, #02c8ff, #00e68a); height: 100%; border-radius: 6px;
                       transition: width 0.5s ease; width: 0%; }
  .progress-text { position: absolute; inset: 0; display: flex; align-items: center; justify-content: center;
                   font-size: 11px; font-weight: 700; color: #fff; text-shadow: 0 1px 2px rgba(0,0,0,0.5); }
  .progress-label { font-size: 12px; color: #8899aa; margin-bottom: 6px; }

  .switch-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; }
  .switch-card { background: #0a1628; border-radius: 8px; padding: 12px; border: 1px solid #1a2d4a; display: flex; flex-direction: column; }
  .switch-card.fail { border-color: #3d0000; }
  .switch-card.pass { border-color: #003d2a; }
  .switch-card.warn { border-color: #3d2200; }
  .switch-card-title { display: flex; align-items: center; gap: 6px; margin-bottom: 8px; }
  .switch-card-title .role-tag { font-size: 10px; font-weight: 700; text-transform: uppercase;
                                  letter-spacing: 0.5px; padding: 1px 6px; border-radius: 3px; }
  .switch-card-title .role-tag.border { background: #1a0a3d; color: #a855f7; }
  .switch-card-title .role-tag.leaf { background: #0a2a1a; color: #22c55e; }
  .switch-card-title .role-tag.cc { background: #0a1a3d; color: #3b82f6; }
  .switch-card-title .device-name { color: #e0e6ed; font-size: 13px; font-weight: 600; cursor: pointer; }
  .switch-card-title .device-name:hover { color: #60a5fa; text-decoration: underline; }
  .toast { position: fixed; bottom: 30px; left: 50%; transform: translateX(-50%); background: #1a2332; color: #e0e6ed; padding: 10px 20px; border-radius: 8px; border: 1px solid #2a3a4a; font-size: 12px; z-index: 9999; opacity: 0; transition: opacity 0.3s; pointer-events: none; }
  .toast.show { opacity: 1; }
  .switch-card-title .device-model { color: #667788; font-size: 10px; margin-left: auto; }
  .switch-bar { height: 4px; background: #1a2d4a; border-radius: 2px; margin-bottom: 8px; overflow: hidden; }
  .switch-bar-fill { height: 100%; border-radius: 2px; transition: width 0.5s; }
  .switch-check { display: flex; justify-content: space-between; align-items: center;
                   padding: 3px 0; font-size: 11px; border-bottom: 1px solid #112240; }
  .switch-check:last-child { border-bottom: none; }
  .switch-check .check-label { color: #c0c8d0; }
  .switch-check .check-label .check-icon { margin-right: 4px; font-size: 12px; }
  .switch-check .check-result { font-weight: 600; font-size: 10px; max-width: 50%; text-align: right;
                                 overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .check-pass { color: #00e68a; }
  .check-fail { color: #ff4757; }
  .check-na { color: #445566; }
  .switch-grid-empty { color: #8899aa; font-size: 13px; text-align: center; padding: 40px; }

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

   <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:20px;">

    <!-- CSV Upload -->
    <div class="upload-section" style="margin-bottom:0;">
      <h3>Upload Event Details CSV</h3>
      <div class="upload-zone" id="upload-zone" onclick="document.getElementById('file-input').click()"
           ondragover="this.classList.add('dragover'); event.preventDefault()"
           ondragleave="this.classList.remove('dragover')"
           ondrop="event.preventDefault(); handleFile(event.dataTransfer.files[0])">
        <div>Click or drop CSV file here</div>
        <div class="hint">EventsDetails.csv from dCloud</div>
        <input type="file" id="file-input" accept=".csv" onchange="handleFile(this.files[0])">
      </div>
      <div class="upload-result" id="upload-result"></div>
    </div>

    <!-- Switch Image -->
    <div class="upload-section" style="margin-bottom:0;" id="upgrade-config-section">
      <h3>Switch Image (C9300)</h3>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;">
        <input id="switch-golden-input" type="text" placeholder="Golden e.g. 17.12.1"
          style="flex:1;background:#0a1625;border:1px solid #1a3a5a;color:#e0e8f0;border-radius:4px;padding:5px 8px;font-size:12px;">
        <button onclick="setGoldenVersion('switch')"
          style="padding:5px 10px;background:#1a2a3a;border:1px solid #02c8ff;color:#02c8ff;border-radius:4px;cursor:pointer;font-size:11px;">Set</button>
      </div>
      <div class="upload-zone" style="padding:10px;" onclick="document.getElementById('switch-bin-input').click()"
           ondragover="this.classList.add('dragover');event.preventDefault()"
           ondragleave="this.classList.remove('dragover')"
           ondrop="event.preventDefault();uploadImage(event.dataTransfer.files[0],'switch')">
        <div style="font-size:12px">Click or drop switch .bin here</div>
        <input type="file" id="switch-bin-input" accept=".bin" onchange="uploadImage(this.files[0],'switch')" style="display:none">
      </div>
      <div id="switch-image-status" style="font-size:11px;color:#667788;margin-top:6px;"></div>
    </div>

    <!-- Router Image -->
    <div class="upload-section" style="margin-bottom:0;">
      <h3>Router Image (C8231-G2)</h3>
      <div style="display:flex;gap:8px;align-items:center;margin-bottom:8px;">
        <input id="router-golden-input" type="text" placeholder="Golden e.g. 17.18.2"
          style="flex:1;background:#0a1625;border:1px solid #1a3a5a;color:#e0e8f0;border-radius:4px;padding:5px 8px;font-size:12px;">
        <button onclick="setGoldenVersion('router')"
          style="padding:5px 10px;background:#1a2a3a;border:1px solid #02c8ff;color:#02c8ff;border-radius:4px;cursor:pointer;font-size:11px;">Set</button>
      </div>
      <div class="upload-zone" style="padding:10px;" onclick="document.getElementById('router-bin-input').click()"
           ondragover="this.classList.add('dragover');event.preventDefault()"
           ondragleave="this.classList.remove('dragover')"
           ondrop="event.preventDefault();uploadImage(event.dataTransfer.files[0],'router')">
        <div style="font-size:12px">Click or drop router .bin here</div>
        <input type="file" id="router-bin-input" accept=".bin" onchange="uploadImage(this.files[0],'router')" style="display:none">
      </div>
      <div id="router-image-status" style="font-size:11px;color:#667788;margin-top:6px;"></div>
    </div>

  </div>

  <div class="summary" id="summary"></div>

  <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <button class="btn-start-all" id="btn-vpn-all" onclick="connectAllVpn()">&#9654; Connect All VPN</button>
    <button class="btn-start-all" id="btn-run-all" onclick="runAllPods()" style="background:#7c3aed;color:#fff;">&#9654; Run All POD Automation</button>
    <button class="btn-start-all" id="btn-docker-down" onclick="dockerDown()" style="background:#ff4757;color:#fff;">&#9632; Teardown All</button>
    <button class="btn-start-all" onclick="window.location.href='/api/generate-lab-pdf'" style="background:#0d4f6e;border-color:#00bceb;color:#00bceb;">&#128196; Generate Lab Details</button>
    <span id="docker-status" style="font-size:12px;color:#667788;"></span>
  </div>

  <table>
    <thead>
      <tr id="sort-header">
        <th>POD</th>
        <th>Assigned</th>
        <th>Session</th>
        <th data-col="status" style="cursor:pointer;user-select:none">Status <span id="status-sort-icon">⇅</span></th>
        <th>VPN</th>
        <th>Serial</th>
        <th>SD-WAN</th>
         <th>SCC Org</th>
         <th>Pipeline</th>
         <th>Actions</th>
         <th>Notes</th>
       </tr>
    </thead>
    <tbody id="pod-rows"></tbody>
  </table>

  <div class="detail-panel" id="detail-panel">
    <div class="detail-header">
      <h3><span id="detail-pod-id" data-pod-id=""></span> <span id="elapsed-timer" class="elapsed-timer"></span></h3>
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
      <button class="tab-btn" onclick="switchTab(this, 'cdfmc')">cdFMC</button>
      <button class="tab-btn" onclick="switchTab(this, 'ad')">AD Verify</button>
      <button class="tab-btn" onclick="switchTab(this, 'duo')">Duo Setup</button>
      <button class="tab-btn" onclick="switchTab(this, 'scc')">SCC Reset</button>
       <button class="tab-btn" onclick="switchTab(this, 'fabric')">EVPN Fabric</button>
       <button class="tab-btn" onclick="switchTab(this, 'sda')">SDA Fabric</button>
       <button class="tab-btn" onclick="switchTab(this, 'baseconfig')">&#8635; Base Config Reset</button>
      <button class="tab-btn" onclick="switchTab(this, 'upgrade')">Upgrade</button>
      <button class="tab-btn" onclick="switchTab(this, 'kb')">&#128218; Knowledge Base</button>
    </div>
    <div class="tab-content active" id="tab-steps">
      <div class="pipeline-grid" id="pipeline-grid"></div>
    </div>
    <div class="tab-content" id="tab-logs">
      <div class="log-box" id="log-box">Waiting for logs...</div>
    </div>
    <div class="tab-content" id="tab-switches">
      <div id="toast" class="toast"></div>
      <div class="switch-grid" id="switch-grid">
        <div style="color:#667788;font-size:13px;">Select a POD to load switch verification results</div>
      </div>
    </div>
     <div class="tab-content" id="tab-cdfmc">
       <div id="cdfmc-actions" style="display:none;margin-bottom:10px;padding:0 16px;gap:8px;">
         <button id="cdfmc-recheck-btn" class="btn-reconnect">⟳ Re-check</button>
         <button id="cdfmc-redeploy-btn" class="btn-reconnect" style="color:#ff4757;border-color:#ff4757;">⚠ Reset &amp; Redeploy</button>
       </div>
       <div id="cdfmc-grid" style="padding:16px;">
         <div style="color:#667788;font-size:13px;">Select a POD to load cdFMC status</div>
       </div>
     </div>
     <div class="tab-content" id="tab-ad">
       <div id="ad-actions" style="display:none;margin-bottom:10px;padding:0 16px;gap:8px;">
         <button id="ad-recheck-btn" class="btn-reconnect">⟳ Re-check</button>
         <button id="ad-rerun-btn" class="btn-reconnect" style="color:#ff4757;border-color:#ff4757;">⚠ Re-run AD Automation</button>
       </div>
      <div id="ad-grid" style="padding:16px;">
          <div style="color:#667788;font-size:13px;">Select a POD to load AD verification status</div>
        </div>
      </div>
      <div class="tab-content" id="tab-duo">
        <div id="duo-grid" style="padding:16px;min-height:260px;">
          <div style="color:#667788;font-size:13px;">Select a POD to manage Duo setup</div>
        </div>
      </div>
      <div class="tab-content" id="tab-scc">
       <div id="scc-actions" style="display:none;margin-bottom:10px;">
         <button id="scc-recheck-btn" class="btn-reconnect" onclick="sccRecheckCurrent()">&#x21bb; Re-check Auto</button>
       </div>
       <div id="scc-grid" style="min-height:260px;">
         <div style="color:#667788;font-size:13px;">Select a POD to load SCC reset checklist</div>
       </div>
     </div>
     <div class="tab-content" id="tab-fabric">
       <div id="fabric-grid" style="padding:16px;min-height:260px;">
         <div style="color:#667788;font-size:13px;">Select a POD to load EVPN Fabric status</div>
       </div>
       <div id="catc-tile-container" style="padding:0 16px 16px;"></div>
     </div>

     <div class="tab-content" id="tab-sda">
       <div id="sda-grid" style="padding:16px;min-height:260px;">
         <div style="color:#667788;font-size:13px;">Select a POD to manage SDA Fabric</div>
       </div>
     </div>

    <div class="tab-content" id="tab-baseconfig">
      <div id="baseconfig-grid" style="padding:16px;min-height:260px;">
        <div style="color:#667788;font-size:13px;">Select a POD to manage base configs</div>
      </div>
    </div>

    <div class="tab-content" id="tab-upgrade">
      <div id="upgrade-grid" style="padding:16px;">
        <div style="color:#667788;font-size:13px;">Select a POD to load upgrade status</div>
      </div>
    </div>

    <div class="tab-content" id="tab-kb">
      <div id="kb-grid" style="padding:16px;min-height:300px;">
        <div style="color:#667788;font-size:13px;">Loading knowledge base...</div>
      </div>
    </div>
  </div>

<script>
const PIPELINE_ORDER = [
  "detect_pod_number",
  "verify_router",
  "reset_device",
  "quick_connect",
  "config_group_associate",
  "assign_license",
  "set_variables",
  "deploy_config_group",
  "generate_bootstrap",
  "copy_bootstrap",
  "controller_mode_enable",
  "verify_online",
  "verify_border_spine",
  "verify_leaf1",
  "verify_leaf2",
  "connectivity_test",
  "cdfmc_check",
  "ad_verify",
  "duo_setup",
  "scc_reset_check",
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
  window._lastPods = pods;  // cache for detail panel POD# display
  renderStats(pods);
  renderTable(pods);
  updateSortHeaders();
  if (!document.getElementById('sort-header').dataset.bound) {
    document.getElementById('sort-header').dataset.bound = '1';
    document.querySelector('#sort-header th[data-col="status"]').addEventListener('click', () => {
      statusSortDir = statusSortDir === 'asc' ? 'desc' : 'asc';
      updateSortHeaders();
      renderTable(pods);
    });
  }
  const detailEl = document.getElementById('detail-pod-id');
  const detailId = detailEl ? detailEl.dataset.podId : '';
  if (detailId) {
    // Only refresh the active tab to avoid re-rendering all tabs and causing page jumps
    const activeTab = document.querySelector('.tab-btn.active');
    const tabName = activeTab ? activeTab.getAttribute('onclick').match(/switchTab\(this,\s*'(\w+)'\)/)?.[1] : null;
    if (tabName === 'steps' || tabName === 'pipeline' || !tabName) loadSteps(detailId);
    else if (tabName === 'switches')  loadSwitches(detailId);
    else if (tabName === 'cdfmc')     loadCdfmc(detailId);
    else if (tabName === 'ad')        loadAd(detailId);
    else if (tabName === 'duo')       loadDuoPanel(detailId);
    else if (tabName === 'upgrade')   loadUpgrade(detailId);
    else if (tabName === 'scc')       loadSccChecklist(detailId);
    else if (tabName === 'fabric')    loadFabricStatus(detailId);
    else if (tabName === 'sda')       loadSdaStatus(detailId);
    else if (tabName === 'baseconfig') loadBaseConfig(detailId);
    // logs tab has its own 2s poller; kb tab is static
  }
}

function isFullyReady(p) {
  // All pipeline steps completed (not skipped) + sdwan online
  const phases = PIPELINE_ORDER;
  for (let i = 0; i < phases.length; i++) {
    if (p[phases[i]] !== 'completed') return false;
  }
  return p.sdwan_online === 'yes';
}

function hasSkippedSteps(p) {
  return PIPELINE_ORDER.some(k => p[k] === 'skipped');
}

function renderStats(pods) {
  const total = pods.length;
  const fullyReady  = pods.filter(p => isFullyReady(p)).length;
  const sdwanOk     = pods.filter(p => p.sdwan_online === 'yes').length;
  // Derive running/partial/pending from step data (p.status stays 'pending' during run)
  const running = pods.filter(p => PIPELINE_ORDER.some(k => p[k] === 'running')).length;
  const partial = pods.filter(p => !isFullyReady(p) && p.sdwan_online === 'yes').length;
  const pending = pods.filter(p => p.status === 'pending' && !PIPELINE_ORDER.some(k => p[k] === 'running') && p.sdwan_online !== 'yes').length;

  document.getElementById('summary').innerHTML =
    '<div class="stat-card green"><div class="num">' + fullyReady + '</div><div class="label">Fully Ready</div></div>' +
    '<div class="stat-card" style="border-left:3px solid #00e68a"><div class="num">' + sdwanOk + '</div><div class="label">SD-WAN Online</div></div>' +
    '<div class="stat-card yellow"><div class="num">' + running + '</div><div class="label">Running</div></div>' +
    '<div class="stat-card" style="border-left:3px solid #02c8ff"><div class="num">' + partial + '</div><div class="label">Partial</div></div>' +
    '<div class="stat-card red"><div class="num">' + pending + '</div><div class="label">Pending</div></div>' +
    '<div class="stat-card"><div class="num">' + total + '</div><div class="label">Total</div></div>';
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
  let done = 0, skipped = 0;
  for (let i = 0; i < phases.length; i++) {
    const v = p[phases[i]];
    if (v === 'completed') done++;
    if (v === 'skipped')   { done++; skipped++; }
    if (v === 'running') return { pct: Math.round(done / phases.length * 100), text: (i+1) + '/' + phases.length + ' running', state: 'running', skipped };
    if (v === 'failed')  return { pct: Math.round(done / phases.length * 100), text: (i+1) + '/' + phases.length + ' failed',  state: 'failed',  skipped };
  }
  const pct = Math.round(done / phases.length * 100);
  if (done === phases.length && skipped === 0) return { pct, text: phases.length + '/' + phases.length + ' done', state: 'done', skipped: 0 };
  if (done === phases.length && skipped > 0)  return { pct, text: phases.length + '/' + phases.length + ' (' + skipped + ' warn)', state: 'warn', skipped };
  return { pct, text: (done + 1) + '/' + phases.length + ' pending', state: 'pending', skipped };
}

// ── Sort state ───────────────────────────────────────────────────
let statusSortDir = null; // null=unsorted, 'asc', 'desc'

function statusRank(p) {
  if (p.status !== 'ready') return 2;  // pending
  const hasSkipped = PIPELINE_ORDER.some(k => p[k] === 'skipped');
  if (hasSkipped) return 1;            // ready but warn
  return 0;                            // fully ready
}

function podNum(p) {
  const m = (p.pod_id || '').match(/(\d+)$/);
  return m ? parseInt(m[1]) : 9999;
}

function sortPods(pods) {
  if (!statusSortDir) return pods;
  return [...pods].sort((a, b) => {
    const ra = statusRank(a), rb = statusRank(b);
    if (ra !== rb) return statusSortDir === 'asc' ? ra - rb : rb - ra;
    return 0;
  });
}

function updateSortHeaders() {
  const icon = document.getElementById('status-sort-icon');
  if (!icon) return;
  icon.textContent = statusSortDir === 'asc' ? '↑' : statusSortDir === 'desc' ? '↓' : '⇅';
}

function renderTable(pods) {
  // Apply current sort
  const sorted = sortPods([...pods]);
  const tbody = document.getElementById('pod-rows');
  tbody.innerHTML = sorted.map(p => {
    const pipe = pipelinePhase(p);
    const serial = p.router_serial || '-';
    const barColor = pipe.state === 'done' ? '#00e68a'
                   : pipe.state === 'warn' ? '#ffa502'
                   : pipe.state === 'failed' ? '#ff4757'
                   : pipe.state === 'running' ? '#02c8ff' : '#334455';
    const badgeClass = pipe.state === 'done' ? 'pass'
                     : pipe.state === 'warn' ? 'warn'
                     : pipe.state === 'failed' ? 'fail'
                     : pipe.state === 'running' ? 'running' : 'pending';
    const miniBar = pipe.pct > 0 ? '<div class="progress-mini"><div class="progress-mini-fill" style="width:' + pipe.pct + '%;background:' + barColor + '"></div></div>' : '';
    const pipeLabel = miniBar + '<span class="badge ' + badgeClass + '">' + pipe.text + '</span>';
    const vpn = p.vpn_status || 'disconnected';
    const vpnColor = vpn === 'connected' ? '#00e68a' : vpn === 'connecting' ? '#ffa502' : '#ff4757';
    const readyAll = isFullyReady(p);
    const hasWarn  = hasSkippedSteps(p);
    const readyBadge = readyAll && p.scc_all_confirmed ? '<span class="badge pass">READY</span>'
      : readyAll && !p.scc_all_confirmed ? '<span class="badge warn" title="SCC checklist incomplete">READY*</span>'
      : hasWarn && p.sdwan_online === 'yes' ? '<span class="badge warn">WARN</span>'
      : p.sdwan_online === 'yes'            ? '<span class="badge running">Partial</span>'
      : '<span class="badge pending">Pending</span>';
    return `<tr>
      <td class="pod-id" onclick="showPipeline('${p.pod_id}')">
        ${p.pod_number ? '<span style="color:#00bceb;font-weight:700">POD-' + p.pod_number + '</span><br><span style="color:#445566;font-size:10px">ID:' + p.pod_id.replace('POD-','') + '</span>' : p.pod_id}
      </td>
      <td><input type="text" value="${p.assigned_to||''}" placeholder="CCO ID" style="background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:3px 7px;width:100px;font-size:12px;" onchange="saveAssigned('${p.pod_id}', this.value)" /></td>
      <td style="font-size:11px;color:#667788">${p.session_id || ''}</td>
      <td>${readyBadge}</td>
      <td style="text-align:center"><span style="color:${vpnColor};font-size:18px;line-height:1" title="${p.vpn_detail || ''}">&#x25cf;</span></td>
      <td style="font-size:11px;color:#667788">${serial}</td>
      <td class="device-col" style="font-size:18px;line-height:1;color:${p.sdwan_online === 'yes' ? '#00e68a' : '#ff4757'}">&#x25cf;</td>
      <td style="font-size:11px;color:#667788;max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${p.scc_org||''}">${p.scc_org ? '<span style="color:#02c8ff">&#x25cf;</span> ' + (p.scc_org.match(/pseudoco-(\d+)--/) ? p.scc_org.match(/pseudoco-(\d+)--/)[1] : p.scc_org) : '<span style="color:#667788">—</span>'}</td>
      <td>${pipeLabel}</td>
      <td style="display:flex;gap:4px;flex-wrap:wrap;">
        <button class="btn-start" onclick="connectVpn('${p.pod_id}')">Connect VPN</button>
         <button class="btn-reconnect" onclick="runPod('${p.pod_id}')" style="background:#7c3aed;border-color:#7c3aed;color:#fff;">&#9654; Run Automation</button>
         <button class="btn-reconnect" onclick="resetPipeline('${p.pod_id}')" style="background:#b45309;border-color:#b45309;color:#fff;" title="Clear all pipeline steps and logs so the pipeline can be re-run">&#8635; Reset Pipeline</button>
         <button class="btn-reconnect" onclick="reconnectVpn('${p.pod_id}')">Reconnect VPN</button>
         <button class="btn-reconnect" onclick="disconnectVpn('${p.pod_id}')" style="color:#ff4757;border-color:#ff4757;">Disconnect VPN</button>
         <button class="btn-reconnect" onclick="deletePod('${p.pod_id}')" style="color:#ff4757;border-color:#ff4757;background:#2a0a0a;" title="Delete POD from DB">&#x1F5D1;</button>
      </td>
      <td class="notes" title="${(p.notes||'').replace(/"/g,'&quot;')}">${p.notes || '-'}</td>
    </tr>`;
  }).join('');
}

async function runPod(podId) {
  const status = document.getElementById('docker-status');
  status.textContent = 'Running automation for ' + podId + '...';
  const r = await fetch('/api/run-pod/' + podId, { method: 'POST' });
  const data = await r.json();
  status.textContent = data.message || 'Done';
  setTimeout(() => status.textContent = '', 8000);
  load();
  if (data.status === 'ok') {
    // Open the detail panel and start polling pipeline cards immediately
    await showPipeline(podId);
    if (!stepPollId) {
      stepPollId = setInterval(() => loadSteps(podId), 5000);
    }
  }
}

async function deletePod(podId) {
  if (!confirm('Delete ' + podId + ' from the dashboard? This cannot be undone.')) return;
  const r = await fetch('/api/delete-pod/' + podId, { method: 'POST' });
  const data = await r.json();
  if (data.status === 'ok') {
    load();
  } else {
    alert('Error: ' + (data.message || 'Unknown error'));
  }
}

async function resetPipeline(podId) {
  if (!confirm('Reset pipeline for ' + podId + '? This clears all step statuses and logs so the pipeline can be re-run from scratch.')) return;
  const status = document.getElementById('docker-status');
  status.textContent = 'Resetting pipeline for ' + podId + '...';
  const r = await fetch('/api/reset-pipeline/' + podId, { method: 'POST' });
  const data = await r.json();
  status.textContent = data.message || 'Done';
  setTimeout(() => status.textContent = '', 5000);
  load();
  // Refresh the detail panel if it's open for this POD
  const detailEl = document.getElementById('detail-pod-id');
  if (detailEl && detailEl.dataset.podId === podId) {
    loadSteps(podId);
    loadLogs(podId);
  }
}

async function saveAssigned(podId, value) {
  await fetch('/api/pod-assigned/' + podId, {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({assigned_to: value})
  });
}

async function runAllPods() {
  const status = document.getElementById('docker-status');
  status.textContent = 'Starting all POD automation...';
  const r = await fetch('/api/run-all', { method: 'POST' });
  const data = await r.json();
  status.textContent = data.message || 'Done';
  setTimeout(() => status.textContent = '', 10000);
  load();
}

async function connectVpn(podId) {
  const status = document.getElementById('docker-status');
  status.textContent = 'Connecting VPN for ' + podId + '...';
  const r = await fetch('/api/vpn-connect-pod/' + podId, { method: 'POST' });
  const data = await r.json();
  status.textContent = data.output.slice(0, 200);
  setTimeout(() => { if (status.textContent === data.output.slice(0,200)) status.textContent = ''; }, 8000);
  load();
}

async function reconnectVpn(podId) {
  const status = document.getElementById('docker-status');
  status.textContent = 'Reconnecting VPN for ' + podId + '...';
  const r = await fetch('/api/vpn/connect/' + podId, { method: 'POST' });
  const data = await r.json();
  status.textContent = data.message || data.output || 'Done';
  setTimeout(() => status.textContent = '', 5000);
  load();
}

async function disconnectVpn(podId) {
  const status = document.getElementById('docker-status');
  status.textContent = 'Disconnecting VPN for ' + podId + '...';
  const r = await fetch('/api/vpn/disconnect/' + podId, { method: 'POST' });
  const data = await r.json();
  status.textContent = data.message || data.output || 'Done';
  setTimeout(() => status.textContent = '', 5000);
  load();
}

let timerInterval = null;
let stepPollId = null;

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
  const podData = window._lastPods ? window._lastPods.find(p => p.pod_id === podId) : null;
  const podLabel = (podData && podData.pod_number)
    ? 'POD-' + podData.pod_number + ' (ID:' + podData.pod_id.replace('POD-','') + ')'
    : podId;
  const el = document.getElementById('detail-pod-id');
  el.textContent = podLabel;
  el.dataset.podId = podId;  // always store the real pod_id separately
  panel.style.display = 'block';

   loadSteps(podId);
   loadLogs(podId);
   loadSwitches(podId);
   loadCdfmc(podId);
   loadAd(podId);
   loadUpgrade(podId);
   loadSccChecklist(podId);
   loadFabricStatus(podId);
   loadBaseConfig(podId);

  // Elapsed timer is managed by loadSteps based on running state
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
}

async function loadSteps(podId) {
  const r = await fetch('/api/pipeline/' + podId);
  const steps = await r.json();

  const total = PIPELINE_ORDER.length;
  const done    = steps.filter(s => s.status === 'completed' || s.status === 'skipped').length;
  const skipped = steps.filter(s => s.status === 'skipped').length;
  const running = steps.some(s => s.status === 'running');
  const SOFT_FAIL = new Set(['controller_mode_enable','verify_online','verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test','cdfmc_check','ad_verify','duo_setup','scc_reset_check']);
  const hardFailed = steps.some(s => s.status === 'failed' && !SOFT_FAIL.has(s.step_name));
  const softFailed = steps.some(s => s.status === 'failed' && SOFT_FAIL.has(s.step_name));
  const allAccountedFor = steps.length > 0 && steps.every(s => s.status === 'completed' || s.status === 'skipped' || s.status === 'failed');
  const pct = Math.min(100, Math.round(done / total * 100));

  const firstStep = steps.length > 0 ? steps[0].started_at : null;
  // Only show elapsed timer while pipeline is actively running
  if (running) {
    updateTimer(firstStep);
    if (!timerInterval) {
      timerInterval = setInterval(() => updateTimer(firstStep), 1000);
    }
  } else {
    const el = document.getElementById('elapsed-timer');
    if (el) el.innerHTML = '';
    if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
  }

  // Progress bar
  const fill = document.getElementById('progress-bar-fill');
  const txt  = document.getElementById('progress-text');
  const lbl  = document.getElementById('progress-label-text');
  const barColor = hardFailed ? '#ff4757' : (softFailed && allAccountedFor && !running) ? '#ffa502' : running ? '#02c8ff' : done === total ? '#00e68a' : '#667788';
  if (fill) { fill.style.width = pct + '%'; fill.style.background = barColor; }
  if (txt)  txt.textContent = pct + '% (' + done + '/' + total + (skipped ? ', ' + skipped + ' warn' : '') + ')';
  if (lbl)  lbl.textContent = hardFailed ? 'Failed at ' + done + '/' + total
                             : (softFailed && allAccountedFor && !running) ? 'Complete — check warnings'
                             : skipped > 0 && done === total ? 'Done with ' + skipped + ' warning(s)'
                             : running ? 'Running — ' + done + '/' + total
                             : done === total ? 'Complete!' : 'Pending — ' + done + '/' + total;

  // Estimated duration for controller_mode_enable (router reboot into SD-WAN mode)
  // Based on observed run 2026-05-20: 534s. Round up to 540s for comfort.
  const CTRL_MODE_EST_SECS = 540;

  const grid = document.getElementById('pipeline-grid');
  grid.innerHTML = PIPELINE_ORDER.map(name => {
    const step = steps.find(s => s.step_name === name);
    const st = step ? step.status : 'pending';
    const result = step && step.result ? step.result.slice(0, 60) : '';
    const idx = PIPELINE_ORDER.indexOf(name) + 1;
    const label = name.replace(/_/g, ' ');
    const duration = formatDur(step?.started_at, step?.completed_at);
    const durHtml = duration ? '<div class="step-dur">' + duration + '</div>' : '';
    const cardBorder = st === 'skipped' ? 'border-left:3px solid #ffa502;' : st === 'failed' ? 'border-left:3px solid #ff4757;' : '';

    // Live elapsed + progress bar for controller_mode_enable while running
    let rebootHtml = '';
    if (name === 'controller_mode_enable' && st === 'running' && step?.started_at) {
      const elapsedSec = Math.floor((Date.now() - new Date(step.started_at + 'Z').getTime()) / 1000);
      const pct = Math.min(99, Math.round(elapsedSec / CTRL_MODE_EST_SECS * 100));
      const remaining = Math.max(0, CTRL_MODE_EST_SECS - elapsedSec);
      const remStr = remaining > 0 ? '~' + Math.ceil(remaining / 60) + 'm remaining' : 'any moment now...';
      const elStr = elapsedSec >= 60
        ? Math.floor(elapsedSec/60) + 'm ' + (elapsedSec%60) + 's elapsed'
        : elapsedSec + 's elapsed';
      rebootHtml =
        '<div class="step-dur" style="color:#ffa502">' + elStr + '</div>' +
        '<div class="step-reboot-bar-bg"><div class="step-reboot-bar-fill" style="width:' + pct + '%"></div></div>' +
        '<div class="step-reboot-eta">' + pct + '% &mdash; ' + remStr + '</div>';
    }

    return '<div class="step-card" style="' + cardBorder + '">' +
      '<div class="step-num">Phase ' + idx + '/' + total + '</div>' +
      '<div class="step-name">' + label + '</div>' +
      pipelineBadge(st) +
      '<div class="step-result">' + result + '</div>' +
      durHtml +
      rebootHtml +
      '<span class="started-at" data-time="' + (step?.started_at || '') + '" style="display:none"></span>' +
      '</div>';
  }).join('');

  // Auto-poll steps while pipeline is running (keeps countdown live on any tab)
  if (running) {
    if (!stepPollId) {
      stepPollId = setInterval(() => loadSteps(podId), 5000);
    }
  } else {
    if (stepPollId) { clearInterval(stepPollId); stepPollId = null; }
  }
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

function roleClass(name) {
  if (name.includes('Border')) return 'border';
  if (name.includes('Leaf')) return 'leaf';
  if (name.includes('Catalyst')) return 'cc';
  if (name === 'Switch Connectivity') return 'cc';
  return '';
}

async function loadSwitches(podId) {
  const r = await fetch('/api/switches/' + podId);
  const data = await r.json();
  const grid = document.getElementById('switch-grid');

  if (!data || data.length === 0) {
    grid.innerHTML = '<div class="switch-grid-empty">No switch data for this POD</div>';
    return;
  }

  const hasFail = data.some(sw => (sw.checks || []).some(c => c.status === 'fail'));
  const allPass = data.every(sw => (sw.checks || []).every(c => c.status === 'pass'));

  const recheckBtn = `<button class="btn-reconnect" onclick="recheckSwitches('${podId}')" style="${hasFail ? 'background:#ff4757;border-color:#ff4757;color:#fff' : 'background:#1a2d4a;border-color:#667788;color:#8899aa'};">&#x21bb; Re-check</button>`;

  const totalChecks = data.reduce((s, sw) => s + (sw.checks || []).length, 0);
  const totalPass = data.reduce((s, sw) => s + (sw.passed || 0), 0);
  const totalFail = data.reduce((s, sw) => s + (sw.failed || 0), 0);
  const pct = totalChecks > 0 ? Math.round(totalPass / totalChecks * 100) : 0;

  const summaryHtml = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
      <div style="font-size:13px;font-weight:600;color:${allPass ? '#00e68a' : hasFail ? '#ff4757' : '#8899aa'}">
        ${allPass ? '✓ All passed' : hasFail ? ('✗ ' + totalFail + ' fail') : '— pending'}
      </div>
      <div style="flex:1;min-width:80px;">
        <div style="background:#1a2d4a;border-radius:3px;height:6px;overflow:hidden;">
          <div style="height:100%;width:${pct}%;background:${allPass ? '#00e68a' : hasFail ? '#ff4757' : '#445566'};border-radius:3px;transition:width 0.5s;"></div>
        </div>
      </div>
      <div style="font-size:11px;color:#667788;white-space:nowrap;">${totalPass}/${totalChecks}</div>
      ${recheckBtn}
    </div>`;

  grid.innerHTML = summaryHtml + data.map(sw => {
    const hasAnyFail = (sw.checks || []).some(c => c.status === 'fail');
    const allDevicePass = (sw.checks || []).every(c => c.status === 'pass');
    const devicePct = sw.total > 0 ? Math.round((sw.passed || 0) / sw.total * 100) : 0;
    const barColor = allDevicePass ? '#00e68a' : hasAnyFail ? '#ff4757' : '#445566';

    const checksHtml = (sw.checks || []).map(c => {
      const icon = c.status === 'pass' ? '✓' : c.status === 'fail' ? '✗' : '○';
      const iconColor = c.status === 'pass' ? '#00e68a' : c.status === 'fail' ? '#ff4757' : '#445566';
      return `<div class="switch-check">
        <span class="check-label"><span class="check-icon" style="color:${iconColor}">${icon}</span>${escHtml(c.label)}</span>
        <span class="check-result ${c.status === 'pass' ? 'check-pass' : c.status === 'fail' ? 'check-fail' : 'check-na'}">${escHtml(c.result)}</span>
      </div>`;
    }).join('');

    const roleLabel = sw.name === 'Catalyst Center' ? 'CC' : sw.name === 'Switch Connectivity' ? 'TEST' : sw.name.includes('Border') ? 'Spine' : 'Leaf';


    return '<div class="switch-card ' + (allDevicePass ? 'pass' : hasAnyFail ? 'fail' : sw.step_status === 'skipped' ? 'warn' : '') + '">' +
      '<div class="switch-card-title">' +
        '<span class="role-tag ' + roleClass(sw.name) + '">' + roleLabel + '</span>' +
        '<span class="device-name"' + (sw.ip ? ' data-pod-id="' + escHtml(podId) + '" data-ip="' + escHtml(sw.ip) + '"' : '') + ' title="' + (sw.ip ? 'Click to open SSH terminal' : '') + '">' + escHtml(sw.name) + '</span>' +
        '<span class="device-model">' + escHtml(sw.model || '') + '</span>' +
        (sw.step_status === 'running' ? '<span class="badge" style="margin-left:auto;background:#02c8ff22;color:#02c8ff;border:1px solid #02c8ff55;">⟳ checking</span>' : '') +
        (sw.step_status === 'skipped' ? '<span class="badge warn" style="margin-left:auto">WARN</span>' : '') +
      '</div>' +
      (sw.step_status === 'skipped' ? '<div style="font-size:11px;color:#ffa502;margin-bottom:6px;">⚠ Verification skipped — switch unreachable during pipeline. Click Re-check Switches to retry.</div>' : '') +
      '<div class="switch-bar"><div class="switch-bar-fill" style="width:' + devicePct + '%;background:' + barColor + '"></div></div>' +
      checksHtml +
      '</div>';
  }).join('');

  // Attach click handlers after innerHTML set (avoids inline onclick double-quote quoting issues)
  grid.querySelectorAll('.device-name[data-ip]').forEach(el => {
    el.addEventListener('click', () => openTerminal(el.dataset.podId, el.dataset.ip));
  });
}

async function openTerminal(podId, ip) {
  const t = document.getElementById('toast');
  if (t) { t.textContent = 'Opening Terminal...'; t.classList.add('show'); }
  try {
    await fetch('/api/ssh/terminal/' + podId + '/' + ip, { method: 'POST' });
  } catch(e) {}
  if (t) setTimeout(() => t.classList.remove('show'), 2000);
}

async function recheckSwitches(podId) {
  await fetch('/api/switches/recheck/' + podId, { method: 'POST' });
  let attempts = 0;
  const maxAttempts = 40;

  async function doPoll() {
    attempts++;
    try {
      const switchNames = ['verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test'];
      const r2 = await fetch('/api/pipeline/' + podId);
      const steps = await r2.json();
      const switchSteps = steps.filter(s => switchNames.includes(s.step_name));
      const anyRunning = switchSteps.some(s => s.status === 'running');
      // Always reload the cards so user sees live updates
      await loadSwitches(podId);
      loadSteps(podId);
      if (anyRunning && attempts < maxAttempts) {
        setTimeout(doPoll, 4000);
      }
    } catch(e) {
      loadSwitches(podId);
    }
  }

  setTimeout(doPoll, 2000);
}

async function loadCdfmc(podId) {
  if (window._cdfmcRechecking) return;  // don't interrupt an in-progress recheck
  const grid = document.getElementById('cdfmc-grid');
  if (!grid) return;

  // Wire static action buttons outside the grid
  const actionsDiv = document.getElementById('cdfmc-actions');
  if (actionsDiv) {
    actionsDiv.style.display = 'flex';
    const rb = document.getElementById('cdfmc-recheck-btn');
    if (rb) { rb.onclick = null; rb.onclick = () => recheckCdfmc(podId); }
    const db = document.getElementById('cdfmc-redeploy-btn');
    if (db) { db.onclick = null; db.onclick = () => redeployCdfmc(podId); }
  }

  const r = await fetch('/api/cdfmc/' + podId);
  const d = await r.json();
  const deployed = d.deployed;
  const ftd = d.ftd_status || '—';
  const scc = d.scc_org || '—';
  const stepStatus = d.step_status || 'pending';
  const stepResult = d.step_result || '';

  const statusColor = stepStatus === 'completed' ? '#00e68a' : stepStatus === 'failed' ? '#ff4757' : '#ffa502';
  const statusIcon  = stepStatus === 'completed' ? '✓' : stepStatus === 'failed' ? '✗' : '⟳';
  const deployedBadge = deployed === 'yes'
    ? '<span class="badge pass">Deployed</span>'
    : deployed === 'no'
    ? '<span class="badge fail">Not Deployed</span>'
    : '<span class="badge pending">Unknown</span>';

  grid.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
      <span style="font-size:22px;color:${statusColor}">${statusIcon}</span>
      <span style="font-size:15px;font-weight:600;color:#e0e8f0">cdFMC / Terraform Automation</span>
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:16px;">
      <div style="background:#0d1f2d;border-radius:8px;padding:14px;">
        <div style="font-size:11px;color:#667788;margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">Terraform Deploy</div>
        <div>${deployedBadge}</div>
      </div>
      <div style="background:#0d1f2d;border-radius:8px;padding:14px;">
        <div style="font-size:11px;color:#667788;margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">SCC Org</div>
        <div style="font-size:12px;color:#02c8ff;word-break:break-all">${scc}</div>
      </div>
    </div>
    <div style="background:#0d1f2d;border-radius:8px;padding:14px;margin-bottom:12px;">
      <div style="font-size:11px;color:#667788;margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">FTD Device Status</div>
      <div style="font-size:12px;color:#e0e8f0">${ftd}</div>
    </div>
    ${stepResult ? '<div style="background:#0a1520;border-radius:6px;padding:10px;font-size:11px;color:#667788;font-family:monospace;word-break:break-all">' + escHtml(stepResult) + '</div>' : ''}
  `;
}

async function recheckCdfmc(podId) {
  const grid = document.getElementById('cdfmc-grid');
  grid.innerHTML = '<div style="padding:20px;color:#ffa502;font-size:13px;">⟳ cdFMC re-check started — please wait...</div>';
  window._cdfmcRechecking = true;
  await fetch('/api/cdfmc/recheck/' + podId, { method: 'POST' });
  let polls = 0;
  const poller = setInterval(async () => {
    polls++;
    const r = await fetch('/api/cdfmc/' + podId);
    const d = await r.json();
    if (d.step_status !== 'running' || polls > 60) {
      clearInterval(poller);
      window._cdfmcRechecking = false;
      loadCdfmc(podId);
    } else {
      grid.innerHTML = '<div style="padding:20px;color:#ffa502;font-size:13px;">⟳ cdFMC re-check running — please wait... (' + (polls * 3) + 's)</div>';
    }
  }, 3000);
}

async function redeployCdfmc(podId) {
  if (!confirm('This will run cli.py reset then cli.py deploy on the automation PC (~15 min). Are you sure?')) return;
  const grid = document.getElementById('cdfmc-grid');
  grid.innerHTML = '<div style="padding:20px;color:#ff4757;font-size:13px;">⚠ Reset &amp; Redeploy started — check Live Logs tab for progress (~15 min)...</div>';
  const r = await fetch('/api/cdfmc/redeploy/' + podId, { method: 'POST' });
  const d = await r.json();
  if (d.status !== 'ok') {
    grid.innerHTML = '<div style="padding:20px;color:#ff4757;font-size:13px;">Error: ' + (d.message || 'unknown') + '</div>';
  }
}

async function loadAd(podId) {
  const grid = document.getElementById('ad-grid');
  if (!grid) return;
  const adActions = document.getElementById('ad-actions');
  if (adActions) {
    adActions.style.display = 'flex';
    const rb = document.getElementById('ad-recheck-btn');
    if (rb) { rb.onclick = null; rb.onclick = () => recheckAd(podId); }
    const rr = document.getElementById('ad-rerun-btn');
    if (rr) { rr.onclick = null; rr.onclick = () => rerunAd(podId); }
  }
  const r = await fetch('/api/ad/status/' + podId);
  const d = await r.json();

  const status = d.status || 'pending';
  const result = d.result || '';
  const ts     = d.completed_at || '';

  const statusIcon  = status === 'completed' ? '✓' : status === 'failed' ? '✗' : '…';
  const statusColor = status === 'completed' ? '#2ed573' : status === 'failed' ? '#ff4757' : '#ffa502';

  // Parse user rows from result string  e.g. "All updated | Kit=kit@rtp04... [OK] | Lee=... [OK]"
  const userRows = result.split('|').filter(p => p.includes('=')).map(p => {
    const m = p.trim().match(/^(\w+)=([^\s\[]+)\s*\[(\w+)\]$/);
    if (!m) return `<tr><td colspan="3" style="color:#667788">${escHtml(p.trim())}</td></tr>`;
    const [, name, email, st] = m;
    const color = st === 'OK' ? '#2ed573' : '#ff4757';
    return `<tr>
      <td style="padding:6px 10px;color:#e0e8f0">${escHtml(name)}</td>
      <td style="padding:6px 10px;color:#02c8ff;font-family:monospace">${escHtml(email)}</td>
      <td style="padding:6px 10px;color:${color};font-weight:600">${st}</td>
    </tr>`;
  }).join('');

  const summary = result.split('|')[0].trim();

  grid.innerHTML = `
    <div style="display:flex;align-items:center;gap:12px;margin-bottom:16px;">
      <span style="font-size:22px;color:${statusColor}">${statusIcon}</span>
      <span style="font-size:15px;font-weight:600;color:#e0e8f0">AD User Verification</span>
    </div>
    <div style="background:#0d1f2d;border-radius:8px;padding:14px;margin-bottom:14px;">
      <div style="font-size:11px;color:#667788;margin-bottom:6px;text-transform:uppercase;letter-spacing:.05em">Status</div>
      <div style="font-size:13px;color:${statusColor}">${escHtml(summary || (status === 'pending' ? 'Not checked yet' : result))}</div>
      ${ts ? `<div style="font-size:11px;color:#445566;margin-top:4px">Last checked: ${ts}</div>` : ''}
    </div>
    ${userRows ? `
    <div style="background:#0d1f2d;border-radius:8px;overflow:hidden;">
      <table style="width:100%;border-collapse:collapse;">
        <thead><tr style="border-bottom:1px solid #1a3a5a">
          <th style="padding:6px 10px;color:#667788;font-size:11px;text-align:left;text-transform:uppercase">User</th>
          <th style="padding:6px 10px;color:#667788;font-size:11px;text-align:left;text-transform:uppercase">Email in AD</th>
          <th style="padding:6px 10px;color:#667788;font-size:11px;text-align:left;text-transform:uppercase">Status</th>
        </tr></thead>
        <tbody>${userRows}</tbody>
      </table>
    </div>` : ''}
  `;
}

async function recheckAd(podId) {
  const grid = document.getElementById('ad-grid');
  grid.innerHTML = '<div style="padding:20px;color:#ffa502;font-size:13px;">⟳ Running AD re-check...</div>';
  await fetch('/api/ad/recheck/' + podId, { method: 'POST' });
  setTimeout(() => loadAd(podId), 8000);
}

async function rerunAd(podId) {
  if (!confirm('This will run ADDuoTenantUserProvisioning.ps1 on Jumphost1 via WinRM. Are you sure?')) return;
  const grid = document.getElementById('ad-grid');
  grid.innerHTML = '<div style="padding:20px;color:#ff4757;font-size:13px;">⚠ Re-run AD Automation started — check Live Logs tab for progress...</div>';
  const r = await fetch('/api/ad/rerun/' + podId, { method: 'POST' });
  const d = await r.json();
  if (d.status !== 'ok') {
    grid.innerHTML = '<div style="padding:20px;color:#ff4757;font-size:13px;">Error: ' + (d.message || 'unknown') + '</div>';
    return;
  }
  setTimeout(() => loadAd(podId), 15000);
}

// ---------------------------------------------------------------------------
// Upgrade tab JS
// ---------------------------------------------------------------------------

async function loadUpgradeConfig() {
  const r = await fetch('/api/upgrade/config');
  const cfgs = await r.json();
  cfgs.forEach(c => {
    if (c.device_type === 'switch') {
      document.getElementById('switch-golden-input').value = c.golden_version || '';
      const el = document.getElementById('switch-image-status');
      if (el) el.textContent = c.image_filename ? `Image: ${c.image_filename}` : 'No image uploaded';
    }
    if (c.device_type === 'router') {
      document.getElementById('router-golden-input').value = c.golden_version || '';
      const el = document.getElementById('router-image-status');
      if (el) el.textContent = c.image_filename ? `Image: ${c.image_filename}` : 'No image uploaded';
    }
  });
}

async function setGoldenVersion(deviceType) {
  const val = document.getElementById(`${deviceType}-golden-input`).value.trim();
  if (!val) return alert('Enter a version first');
  const r = await fetch('/api/upgrade/config', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({device_type: deviceType, golden_version: val})
  });
  const d = await r.json();
  alert(d.status === 'ok' ? `Golden version for ${deviceType} set to ${val}` : 'Error: ' + d.message);
}

async function uploadImage(file, deviceType) {
  if (!file) return;
  const statusEl = document.getElementById(`${deviceType}-image-status`);
  statusEl.textContent = `Uploading ${file.name} (${(file.size/1024/1024/1024).toFixed(2)} GB) to Ubuntu PC...`;
  statusEl.style.color = '#ffa502';
  const fd = new FormData();
  fd.append('file', file);
  fd.append('device_type', deviceType);
  try {
    const r = await fetch('/api/upgrade/upload-image', { method: 'POST', body: fd });
    const d = await r.json();
    if (d.status === 'ok') {
      statusEl.textContent = `✓ ${d.filename} uploaded to Ubuntu PC`;
      statusEl.style.color = '#2ed573';
    } else {
      statusEl.textContent = `✗ Upload failed: ${d.message}`;
      statusEl.style.color = '#ff4757';
    }
  } catch(e) {
    statusEl.textContent = `✗ Upload error: ${e}`;
    statusEl.style.color = '#ff4757';
  }
}

async function loadUpgrade(podId) {
  const grid = document.getElementById('upgrade-grid');
  if (!grid) return;

  // Load upgrade config for golden versions
  const cfgR = await fetch('/api/upgrade/config');
  const cfgs = await cfgR.json();
  const switchCfg = cfgs.find(c => c.device_type === 'switch') || {};
  const routerCfg = cfgs.find(c => c.device_type === 'router') || {};

  // Load upgrade step statuses
  const stR = await fetch('/api/upgrade/status/' + podId);
  const steps = await stR.json();
  const byKey = {};
  steps.forEach(s => { byKey[s.step_name] = s; });

  function upgradeCard(label, stepKey, apiPath, golden, imageFile) {
    const st = byKey[stepKey] || {};
    const status = st.status || 'pending';
    const result = st.result || '';
    const color = status === 'completed' ? '#2ed573' : status === 'failed' ? '#ff4757' :
                  status === 'running' ? '#ffa502' : '#667788';
    const icon  = status === 'completed' ? '✓' : status === 'failed' ? '✗' :
                  status === 'running' ? '⟳' : '–';

    // Phase detection from live result text
    const phases = ['Connecting','Checking version','Copying image','Installing','Activating','Reloading','Verifying','done'];
    let phaseIdx = -1;
    if (status === 'running') {
      const rl = result.toLowerCase();
      if (rl.includes('verif') || rl.includes('ssh')) phaseIdx = 6;
      else if (rl.includes('reload') || rl.includes('waiting') || rl.includes('back up')) phaseIdx = 5;
      else if (rl.includes('activat') || rl.includes('commit')) phaseIdx = 4;
      else if (rl.includes('install') || rl.includes('expand') || rl.includes('software install')) phaseIdx = 3;
      else if (rl.includes('cop') || rl.includes('bytes') || rl.includes('elapsed') || rl.includes('http')) phaseIdx = 2;
      else if (rl.includes('version') || rl.includes('golden') || rl.includes('upgrade needed') || rl.includes('no upgrade')) phaseIdx = 1;
      else if (rl.includes('connect') || rl.includes('starting') || rl.includes('ssh')) phaseIdx = 0;
      else phaseIdx = 0;
    } else if (status === 'completed') { phaseIdx = 7; }

    // Build phase progress bar
    let phaseBar = '';
    if (status === 'running' || status === 'completed') {
      const phaseDots = phases.slice(0,7).map((p, i) => {
        const done = phaseIdx > i || status === 'completed';
        const active = phaseIdx === i && status === 'running';
        const pc = done ? '#2ed573' : active ? '#ffa502' : '#334455';
        const fw = active ? '700' : '400';
        return '<span style="color:' + pc + ';font-weight:' + fw + ';font-size:10px">' + (done ? '● ' : active ? '◉ ' : '○ ') + p + '</span>';
      }).join('<span style="color:#334;"> › </span>');
      phaseBar = '<div style="margin-bottom:8px;line-height:1.8;">' + phaseDots + '</div>';
    }

    const noImage = !imageFile;
    const canRun = !noImage && status !== 'running';
    const btnStyle = 'width:100%;padding:6px;background:#1a2a3a;border:1px solid ' + (noImage ? '#334' : '#ffa502') + ';color:' + (noImage ? '#445' : '#ffa502') + ';border-radius:4px;font-size:12px;' + (canRun ? 'cursor:pointer' : 'opacity:0.4;cursor:not-allowed') + ';';
    const btnId = 'upg-btn-' + stepKey;

    const html = [
      '<div style="background:#0d1f2d;border-radius:8px;padding:14px;">',
      '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px;">',
      '<span style="color:' + color + ';font-size:16px">' + icon + '</span>',
      '<span style="color:#e0e8f0;font-size:13px;font-weight:600">' + label + '</span>',
      '<span style="margin-left:auto;font-size:11px;color:#667788">Golden: ' + (golden || '\u2014') + '</span>',
      '</div>',
      phaseBar,
      result ? '<div style="font-size:11px;color:' + color + ';margin-bottom:8px;word-break:break-all;font-style:italic">' + escHtml(result.substring(0,120)) + '</div>' : '',
      noImage ? '<div style="font-size:11px;color:#ff4757;margin-bottom:8px;">\u26a0 No image uploaded \u2014 use the upload card above</div>' : '',
      '<button id="' + btnId + '" style="' + btnStyle + '">',
      status === 'running' ? '\u27f3 Upgrading...' : '\u2b06 Run Upgrade',
      '</button></div>'
    ].join('');

    // Attach click handler after render
    if (canRun) {
      setTimeout(function() {
        const btn = document.getElementById(btnId);
        if (btn) btn.onclick = function() { runUpgrade(podId, apiPath, label); };
      }, 0);
    }
    return html;
  }

  const switchCards = [
    ['Border Spine', 'upgrade_verify_border_spine', `switch/${podId}/verify_border_spine`, switchCfg.golden_version, switchCfg.image_filename],
    ['Leaf 1',       'upgrade_verify_leaf1',         `switch/${podId}/verify_leaf1`,        switchCfg.golden_version, switchCfg.image_filename],
    ['Leaf 2',       'upgrade_verify_leaf2',         `switch/${podId}/verify_leaf2`,        switchCfg.golden_version, switchCfg.image_filename],
  ].map(([l,k,p,g,img]) => upgradeCard(l,k,p,g,img)).join('');

  const routerCard = upgradeCard('Secure Router (C8231-G2)', 'upgrade_router',
    `router/${podId}`, routerCfg.golden_version, routerCfg.image_filename);

  grid.innerHTML = `
    <div style="margin-bottom:14px;">
      <div style="font-size:13px;font-weight:600;color:#e0e8f0;margin-bottom:10px;">Switches</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:10px;">${switchCards}</div>
    </div>
    <div>
      <div style="font-size:13px;font-weight:600;color:#e0e8f0;margin-bottom:10px;">Router</div>
      <div style="display:grid;grid-template-columns:1fr 2fr;gap:10px;">${routerCard}<div style="background:#0d1f2d;border-radius:8px;padding:14px;font-size:12px;color:#667788;">
        Upgrade only runs if current version is older than the golden version.<br><br>
        Versions are compared numerically — newer versions are never downgraded.<br><br>
        Set golden versions and upload images using the <strong style="color:#02c8ff">Software Upgrade Images</strong> card at the top of the dashboard.
      </div></div>
    </div>
  `;
}

async function runUpgrade(podId, apiPath, label) {
  if (!confirm(`Run upgrade on ${label} for ${podId}? This may take 20-30 minutes and the device will reload.`)) return;
  const grid = document.getElementById('upgrade-grid');
  const r = await fetch('/api/upgrade/' + apiPath, { method: 'POST' });
  const d = await r.json();
  if (d.status !== 'ok') {
    alert('Error: ' + (d.message || 'unknown'));
    return;
  }
  // Reload the tab every 5s while running, 30s otherwise
  const poll = setInterval(async () => {
    const stR = await fetch('/api/upgrade/status/' + podId);
    const steps = await stR.json();
    const running = steps.some(s => s.status === 'running');
    loadUpgrade(podId);
    if (!running) clearInterval(poll);
  }, 5000);
  loadUpgrade(podId);
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// ── SCC Reset Checklist ──────────────────────────────────────────
const SCC_AUTO_ITEMS = [
  { key: 'access_policy_rules',  label: 'Access Policy Rules cleared',
    desc: 'Secure Access → Secure → Access Policy. Delete all configured policies.' },
  { key: 'network_tunnel_groups',label: 'Network Tunnel Groups cleared',
    desc: 'Secure Access → Connect → Network Connections → Network Tunnel Groups. Delete Router and Firewall tunnel groups.' },
  { key: 'zta_profiles',         label: 'ZTA Profile deleted',
    desc: 'Secure Access → Connect → End User Connectivity → Zero Trust Access. Delete PseudoCo ZTA Profile.' },
  { key: 'private_resources',    label: 'Private Resources & Groups cleared',
    desc: 'Secure Access → Resources → Private Resources. Delete Contractor and Intranet resources.' },
  { key: 'dns_servers',          label: 'DNS Servers cleared',
    desc: 'Secure Access → Resources → DNS Servers. Delete PseudoCo DNS.' },
  { key: 'epp_posture_profiles', label: 'EPP Posture Profile deleted',
    desc: 'Secure Access → Secure → Endpoint Posture Profile. Delete PseudoCo Windows profile.' },
];
const SCC_MANUAL_ITEMS = [
  { key: 'logging_settings',  label: 'Logging disabled',
    desc: 'Secure Access → Secure → Access Policy. Edit "For all Internet access" — disable Logging.' },
  { key: 'ravpn_profiles',    label: 'RAVPN Profile deleted',
    desc: 'Secure Access → Connect → End User Connectivity → Virtual Private Network. Delete PseudoCo_RA_VPN_Profile.' },
  { key: 'dlp_rules',     label: 'DLP Policy cleared',
    desc: 'Secure Access → Secure → Data Loss Prevention Policy. Delete configured policy.' },
  { key: 'ravpn_ip_pool', label: 'RAVPN IP Pool deleted',
    desc: 'Secure Access → Connect → End User Connectivity → Virtual Private Network. Click Manage under Regions and IP Pools — delete the configured IP Pool.' },
  { key: 'duo_saml',      label: 'Duo / DuoSSO SAML profiles removed',
    desc: 'Secure Access → Connect → Users, Groups, and Endpoint Devices → Configuration Management. Click Edit then Delete on both Duo and DuoSSO profiles (delete Duo first, DuoSSO should follow).' },
  { key: 'ise_pxgrid',    label: 'ISE / pxGrid integration removed',
    desc: 'SCC Platform Management → Platform Integrations. Delete the ISE/pxGrid integration.' },
  { key: 'te_integration',label: 'ThousandEyes integration removed',
    desc: 'Secure Access → Experience and Insights → Account Management. Delete ThousandEyes integration.' },
];

// ── Duo Setup Panel ──────────────────────────────────────────────────────────
async function loadDuoPanel(podId) {
  const grid = document.getElementById('duo-grid');
  if (!grid) return;

  // Preserve inputs if user is typing
  if (window._duoKeysDirty) {
    const ik = document.getElementById('duo-ikey-input');
    const sk = document.getElementById('duo-skey-input');
    const hk = document.getElementById('duo-host-input');
    var savedIkey = ik ? ik.value : '';
    var savedSkey = sk ? sk.value : '';
    var savedHost = hk ? hk.value : '';
  }

  // Fetch stored credentials + latest duo_setup step result
  let keysD = {duo_ikey: '', duo_skey: '', duo_host: ''};
  let stepResult = '';
  let stepStatus = '';
  try {
    const kr = await fetch('/api/pod-duo-keys/' + podId);
    keysD = await kr.json();
  } catch(e) {}
  try {
    const sr = await fetch('/api/steps/' + podId);
    const steps = await sr.json();
    const s = (steps || []).find(x => x.step_name === 'duo_setup');
    if (s) { stepResult = s.result || ''; stepStatus = s.status || ''; }
  } catch(e) {}

  if (window._duoKeysDirty) {
    keysD.duo_ikey = savedIkey;
    keysD.duo_skey = savedSkey;
    keysD.duo_host = savedHost;
  }

  const statusColor = stepStatus === 'completed' ? '#00e68a' : stepStatus === 'failed' ? '#ff4757' : stepStatus === 'running' ? '#ffa502' : '#667788';
  const statusIcon  = stepStatus === 'completed' ? '✓' : stepStatus === 'failed' ? '✗' : stepStatus === 'running' ? '⟳' : '○';

  grid.innerHTML =
    '<div class="switch-card" style="margin-bottom:12px;">'
    + '<div class="switch-card-title"><span class="role-tag cc">KEYS</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">Duo Admin API Credentials</span></div>'
    + '<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px;align-items:center;margin-top:6px;">'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">Integration Key (ikey)</div>'
    + '<input id="duo-ikey-input" type="text" value="' + escHtml(keysD.duo_ikey || '') + '" placeholder="DIRIBLQ..." style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">Secret Key (skey)</div>'
    + '<input id="duo-skey-input" type="password" value="' + escHtml(keysD.duo_skey || '') + '" placeholder="Secret..." style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">API Hostname</div>'
    + '<input id="duo-host-input" type="text" value="' + escHtml(keysD.duo_host || '') + '" placeholder="api-xxxxx.duosecurity.com" style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<button id="duo-keys-save-btn" class="btn-reconnect" style="margin-top:16px;white-space:nowrap;">Save</button>'
    + '</div>'
    + '<div id="duo-keys-status" style="font-size:11px;color:#667788;margin-top:4px;min-height:16px;"></div>'
    + '</div>'
    + '<div class="switch-card">'
    + '<div class="switch-card-title"><span class="role-tag ' + (stepStatus === 'completed' ? 'pass' : 'cc') + '">' + stepStatus.toUpperCase() + '</span>'
    + '<span style="color:#e0e6ed;font-size:13px;font-weight:600;">duo_setup — Last Run</span>'
    + '<span style="margin-left:auto;font-size:18px;color:' + statusColor + ';">' + statusIcon + '</span></div>'
    + (stepResult
        ? '<div style="font-size:12px;font-family:monospace;color:#c0ccd8;background:#0a1628;border-radius:4px;padding:8px 10px;margin-top:6px;white-space:pre-wrap;word-break:break-all;">'
          + escHtml(stepResult.replace(/\s*\|\s*/g, '\n')) + '</div>'
        : '<div style="color:#445566;font-size:12px;margin-top:6px;">No result yet — run the pipeline to execute this step.</div>')
    + '</div>';

  setTimeout(() => {
    const saveBtn = document.getElementById('duo-keys-save-btn');
    if (saveBtn) saveBtn.onclick = async () => {
      const ikey = document.getElementById('duo-ikey-input').value.trim();
      const skey = document.getElementById('duo-skey-input').value.trim();
      const host = document.getElementById('duo-host-input').value.trim();
      const statusEl = document.getElementById('duo-keys-status');
      if (!ikey || !skey || !host) {
        statusEl.style.color = '#ff4757';
        statusEl.textContent = '✗ ikey, skey, and host are all required';
        return;
      }
      statusEl.style.color = '#ffa502';
      statusEl.textContent = 'Saving...';
      try {
        const res = await fetch('/api/pod-duo-keys/' + podId, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({duo_ikey: ikey, duo_skey: skey, duo_host: host})
        });
        const d = await res.json();
        if (d.status === 'ok') {
          window._duoKeysDirty = false;
          statusEl.style.color = '#00e68a';
          statusEl.textContent = '✓ Saved — ready to run duo_setup step';
        } else {
          statusEl.style.color = '#ff4757';
          statusEl.textContent = '✗ Save failed: ' + (d.message || 'unknown error');
        }
      } catch(e) {
        statusEl.style.color = '#ff4757';
        statusEl.textContent = '✗ Save failed: ' + e;
      }
    };
    const ikeyEl = document.getElementById('duo-ikey-input');
    const skeyEl = document.getElementById('duo-skey-input');
    const hostEl = document.getElementById('duo-host-input');
    if (ikeyEl) ikeyEl.addEventListener('input', () => { window._duoKeysDirty = true; });
    if (skeyEl) skeyEl.addEventListener('input', () => { window._duoKeysDirty = true; });
    if (hostEl) hostEl.addEventListener('input', () => { window._duoKeysDirty = true; });
  }, 0);
}

async function loadSccChecklist(podId) {
  const grid = document.getElementById('scc-grid');
  window._sccCurrentPodId = podId;
  const actionsDiv = document.getElementById('scc-actions');
  if (actionsDiv) actionsDiv.style.display = 'block';
  const r = await fetch('/api/scc/status/' + podId);
  const items = await r.json();
  const map = {};
  items.forEach(i => { map[i.item_key] = i; });

  // Load existing SCC keys — but don't overwrite if user is actively typing
  const keysR = await fetch('/api/pod-scc-keys/' + podId);
  const keysD = await keysR.json();
  if (window._sccKeysDirty) {
    // User is typing — preserve their input, just update key/secret from DOM
    const existingKey = document.getElementById('scc-key-input');
    const existingSecret = document.getElementById('scc-secret-input');
    if (existingKey) keysD.scc_api_key = existingKey.value;
    if (existingSecret) keysD.scc_api_secret = existingSecret.value;
  }

  const allItems = [...SCC_AUTO_ITEMS, ...SCC_MANUAL_ITEMS];
  const completedCount = allItems.filter(i => (map[i.key] || {}).status === 'completed').length;
  const allDone = completedCount === allItems.length;
  const hasFail = allItems.some(i => (map[i.key] || {}).status === 'failed');
  const pct = Math.round(completedCount / allItems.length * 100);
  const barColor = allDone ? '#00e68a' : hasFail ? '#ff4757' : '#445566';
  const statusLabel = allDone ? '✓ All cleared' : hasFail ? ('✗ ' + (allItems.length - completedCount) + ' remaining') : '— pending';
  const statusColor = allDone ? '#00e68a' : hasFail ? '#ff4757' : '#8899aa';

  function sccCheck(item, isManual) {
    const d = map[item.key] || { status: 'pending', detail: '', confirmed_by: '' };
    const done = d.status === 'completed';
    const failed = d.status === 'failed';
    const icon = done ? '✓' : failed ? '✗' : '○';
    const iconColor = done ? '#00e68a' : failed ? '#ff4757' : '#445566';
    const result = d.detail || (done ? 'OK' : failed ? 'FAIL' : '—');
    const confirmedBy = (isManual && d.confirmed_by) ? ' — ' + escHtml(d.confirmed_by) : '';
    const btnId = 'scc-btn-' + item.key;
    const btnHtml = isManual
      ? (done
        ? '<button id="' + btnId + '" class="btn-reconnect" style="background:#3d0a0a;border-color:#ff4757;color:#ff4757;padding:2px 8px;font-size:11px;">Undo</button>'
        : '<button id="' + btnId + '" class="btn-reconnect" style="padding:2px 8px;font-size:11px;">Confirm</button>')
      : '';
    if (isManual) {
      setTimeout(() => {
        const btn = document.getElementById(btnId);
        if (btn) btn.onclick = done
          ? () => sccUnconfirm(podId, item.key)
          : () => sccConfirm(podId, item.key);
      }, 0);
    }
    return '<div class="switch-check" style="flex-direction:column;align-items:flex-start;padding:6px 0;">'
      + '<div style="display:flex;align-items:center;width:100%;">'
      + '<span class="check-icon" style="color:' + iconColor + ';flex-shrink:0;">' + icon + '</span>'
      + '<span style="flex:1;font-size:13px;color:#e0e8f0;margin-left:4px;">' + escHtml(item.label)
      + (isManual ? ' <span style="font-size:10px;color:#445566;background:#112240;padding:1px 4px;border-radius:3px;">manual</span>' : '')
      + '</span>'
      + '<span class="check-result ' + (done ? 'check-pass' : failed ? 'check-fail' : 'check-na') + '" style="display:flex;align-items:center;gap:6px;flex-shrink:0;">'
      + escHtml(result) + confirmedBy + btnHtml
      + '</span>'
      + '</div>'
      + (item.desc ? '<div style="font-size:11px;color:#445566;margin-left:20px;margin-top:2px;line-height:1.4;">' + escHtml(item.desc) + '</div>' : '')
      + '</div>';
  }

  grid.innerHTML =
    // SCC API Credentials card
    '<div class="switch-card" style="margin-bottom:12px;">'
    + '<div class="switch-card-title"><span class="role-tag cc">KEYS</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">SCC API Credentials</span></div>'
    + '<div style="display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:center;margin-top:6px;">'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">API Key</div>'
    + '<input id="scc-key-input" type="text" value="' + escHtml(keysD.scc_api_key || '') + '" placeholder="API Key" style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">Key Secret</div>'
    + '<input id="scc-secret-input" type="password" value="' + escHtml(keysD.scc_api_secret || '') + '" placeholder="Key Secret" style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<button id="scc-keys-save-btn" class="btn-reconnect" style="margin-top:16px;white-space:nowrap;">Save Keys</button>'
    + '</div>'
    + '<div id="scc-keys-status" style="font-size:11px;color:#667788;margin-top:4px;min-height:16px;"></div>'
    + '</div>'
    // Summary bar
    + '<div style="display:flex;align-items:center;gap:12px;margin-bottom:12px;flex-wrap:wrap;">'
    + '<div style="font-size:13px;font-weight:600;color:' + statusColor + '">' + statusLabel + '</div>'
    + '<div style="flex:1;min-width:80px;"><div style="background:#1a2d4a;border-radius:3px;height:6px;overflow:hidden;"><div style="height:100%;width:' + pct + '%;background:' + barColor + ';border-radius:3px;transition:width 0.5s;"></div></div></div>'
    + '<div style="font-size:11px;color:#667788;white-space:nowrap;">' + completedCount + '/' + allItems.length + '</div>'
    + '</div>'
    + (allDone ? '<div style="padding:8px 12px;background:#00e68a22;border:1px solid #00e68a;border-radius:6px;color:#00e68a;font-size:13px;margin-bottom:12px;">&#x2713; All 13 items confirmed — POD cleared</div>' : '')
    // Auto card
    + '<div class="switch-card' + (SCC_AUTO_ITEMS.every(i => (map[i.key]||{}).status==='completed') ? ' pass' : SCC_AUTO_ITEMS.some(i => (map[i.key]||{}).status==='failed') ? ' fail' : '') + '" style="margin-bottom:10px;">'
    + '<div class="switch-card-title"><span class="role-tag cc">AUTO</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">Automated API Checks</span></div>'
    + '<div class="switch-bar"><div class="switch-bar-fill" style="width:' + Math.round(SCC_AUTO_ITEMS.filter(i=>(map[i.key]||{}).status==='completed').length/SCC_AUTO_ITEMS.length*100) + '%;background:' + (SCC_AUTO_ITEMS.every(i=>(map[i.key]||{}).status==='completed') ? '#00e68a' : SCC_AUTO_ITEMS.some(i=>(map[i.key]||{}).status==='failed') ? '#ff4757' : '#445566') + '"></div></div>'
    + SCC_AUTO_ITEMS.map(i => sccCheck(i, false)).join('')
    + '</div>'
    // Manual card
    + '<div class="switch-card' + (SCC_MANUAL_ITEMS.every(i => (map[i.key]||{}).status==='completed') ? ' pass' : '') + '">'
    + '<div class="switch-card-title"><span class="role-tag border">MANUAL</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">Proctor Confirmation</span></div>'
    + '<div class="switch-bar"><div class="switch-bar-fill" style="width:' + Math.round(SCC_MANUAL_ITEMS.filter(i=>(map[i.key]||{}).status==='completed').length/SCC_MANUAL_ITEMS.length*100) + '%;background:' + (SCC_MANUAL_ITEMS.every(i=>(map[i.key]||{}).status==='completed') ? '#00e68a' : '#445566') + '"></div></div>'
    + SCC_MANUAL_ITEMS.map(i => sccCheck(i, true)).join('')
    + '</div>';

  setTimeout(() => {
    const saveBtn = document.getElementById('scc-keys-save-btn');
    if (saveBtn) saveBtn.onclick = async () => {
      const key = document.getElementById('scc-key-input').value.trim();
      const secret = document.getElementById('scc-secret-input').value.trim();
      const statusEl = document.getElementById('scc-keys-status');
      if (!key || !secret) {
        statusEl.style.color = '#ff4757';
        statusEl.textContent = '✗ Both API Key and Secret are required';
        return;
      }
      statusEl.style.color = '#ffa502';
      statusEl.textContent = 'Saving...';
      try {
        const res = await fetch('/api/pod-scc-keys/' + podId, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({scc_api_key: key, scc_api_secret: secret})
        });
        const d = await res.json();
        if (d.status === 'ok') {
          window._sccKeysDirty = false;
          statusEl.style.color = '#00e68a';
          statusEl.textContent = '✓ Saved — ready to Re-check';
        } else {
          statusEl.style.color = '#ff4757';
          statusEl.textContent = '✗ Save failed: ' + (d.message || 'unknown error');
        }
      } catch(e) {
        statusEl.style.color = '#ff4757';
        statusEl.textContent = '✗ Save failed: ' + e;
      }
    };

    // Prevent auto-reload from wiping input fields while user is typing
    const keyInput = document.getElementById('scc-key-input');
    const secretInput = document.getElementById('scc-secret-input');
    if (keyInput) keyInput.addEventListener('input', () => { window._sccKeysDirty = true; });
    if (secretInput) secretInput.addEventListener('input', () => { window._sccKeysDirty = true; });
  }, 0);
}

async function sccConfirm(podId, itemKey) {
  await fetch('/api/scc/confirm/' + podId + '/' + itemKey, { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({confirmed_by: 'proctor'}) });
  loadSccChecklist(podId);
}

async function sccUnconfirm(podId, itemKey) {
  await fetch('/api/scc/unconfirm/' + podId + '/' + itemKey, { method: 'POST' });
  loadSccChecklist(podId);
}

async function sccRecheckCurrent() {
  if (window._sccCurrentPodId) sccRecheck(window._sccCurrentPodId);
}

async function sccRecheck(podId) {
  const grid = document.getElementById('scc-grid');
  await fetch('/api/scc/recheck/' + podId, { method: 'POST' });

  // Poll for completion with timeout
  let polls = 0;
  const MAX_POLLS = 24; // 120s timeout (24 x 5s)
  grid.innerHTML = '<div style="padding:20px;color:#02c8ff;font-size:13px;" id="scc-recheck-status">'
    + '&#8635; Re-checking auto items via API...</div>'
    + '<div style="padding:0 20px;"><button onclick="sccRecheckCancel(&quot;' + podId + '&quot;)" '
    + 'class="btn-reconnect" style="background:#3d0a0a;border-color:#ff4757;color:#ff4757;font-size:11px;margin-top:8px;">&#x2715; Cancel</button></div>';

  const poller = setInterval(async () => {
    polls++;
    try {
      const r = await fetch('/api/pipeline-steps/' + podId);
      const steps = await r.json();
      const scc = steps.find(s => s.step_name === 'scc_reset_check');
      const statusEl = document.getElementById('scc-recheck-status');
      if (scc && scc.status !== 'running') {
        clearInterval(poller);
        loadSccChecklist(podId);
        return;
      }
      if (polls >= MAX_POLLS) {
        clearInterval(poller);
        // Write timeout to DB then reload
        await fetch('/api/scc/recheck-timeout/' + podId, { method: 'POST' });
        loadSccChecklist(podId);
        return;
      }
      if (statusEl) statusEl.textContent = '\u21bb Re-checking auto items via API... (' + (polls * 5) + 's)';
    } catch(e) { /* keep polling */ }
  }, 5000);
  window._sccRecheckPoller = poller;
}

async function sccRecheckCancel(podId) {
  if (window._sccRecheckPoller) clearInterval(window._sccRecheckPoller);
  await fetch('/api/scc/recheck-timeout/' + podId, { method: 'POST' });
  loadSccChecklist(podId);
}

function switchTab(btn, name) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (name === 'scc') {
    const podId = document.getElementById('detail-pod-id').dataset.podId;
    if (podId) loadSccChecklist(podId);
  }
  if (name === 'duo') {
    const podId = document.getElementById('detail-pod-id').dataset.podId;
    if (podId) loadDuoPanel(podId);
  }
  if (name === 'fabric') {
    const podId = document.getElementById('detail-pod-id').dataset.podId;
    if (podId) loadFabricStatus(podId);
  }
  if (name === 'baseconfig') {
    const podId = document.getElementById('detail-pod-id').dataset.podId;
    if (podId) loadBaseConfig(podId);
  }
  if (name === 'kb') {
    loadKbTab();
  }
}

const FABRIC_STEPS = [
  "vrf_definitions","multicast_replication","l2vni_vlan_mappings","l3vni_vlans",
  "dag_svis","l3vni_svis","nve_interface","bgp_evpn",
  "spine_external_interface","spine_bgp_sdwan","access_ports",
  "dot1x_security",
  "verify_bgp_evpn","verify_nve_peers"
];
const FABRIC_STEP_LABELS = {
  vrf_definitions: "VRF Definitions",
  multicast_replication: "Multicast Replication",
  l2vni_vlan_mappings: "L2VNI VLAN Mappings",
  l3vni_vlans: "L3VNI VLANs",
  dag_svis: "Anycast Gateway SVIs",
  l3vni_svis: "L3VNI SVIs",
  nve_interface: "NVE Interface",
  bgp_evpn: "BGP EVPN",
  spine_external_interface: "Spine External Interface",
  spine_bgp_sdwan: "Spine BGP SD-WAN",
  access_ports: "Access / AP Ports",
  dot1x_security: "802.1x / IBNS 2.0",
  verify_bgp_evpn: "Verify BGP EVPN",
  verify_nve_peers: "Verify NVE Peers",
};
const FABRIC_STEP_TARGETS = {
  vrf_definitions: "All 3 switches",
  multicast_replication: "Leaf1 + Leaf2",
  l2vni_vlan_mappings: "Leaf1 + Leaf2",
  l3vni_vlans: "All 3 switches",
  dag_svis: "Leaf1 + Leaf2",
  l3vni_svis: "All 3 switches",
  nve_interface: "All 3 switches",
  bgp_evpn: "All 3 switches",
  spine_external_interface: "Border Spine",
  spine_bgp_sdwan: "Border Spine",
  access_ports: "Leaf1 + Leaf2",
  dot1x_security: "Leaf1 + Leaf2",
  verify_bgp_evpn: "Border Spine",
  verify_nve_peers: "Border Spine",
};
const FABRIC_STEP_COMMANDS = {
  verify_bgp_evpn:  "show bgp l2vpn evpn summary",
  verify_nve_peers: "show nve peers",
};

async function loadFabricStatus(podId) {
  const grid = document.getElementById('fabric-grid');
  if (!podId) { if (grid) grid.innerHTML = '<div style="color:#667788;padding:20px;">No POD selected.</div>'; return; }
  if (!grid._lastHtml) grid.innerHTML = '<div style="color:#667788;font-size:13px;">Loading...</div>';
  const r = await fetch('/api/fabric/status/' + podId);
  const data = await r.json();
  renderFabricGrid(podId, data.steps || {});
}

function renderFabricGrid(podId, steps) {
  const grid = document.getElementById('fabric-grid');
  const total = FABRIC_STEPS.length;
  const done    = FABRIC_STEPS.filter(s => (steps[s]||{}).status === 'completed').length;
  const failed  = FABRIC_STEPS.filter(s => (steps[s]||{}).status === 'failed').length;
  const running = FABRIC_STEPS.some(s => (steps[s]||{}).status === 'running');
  const pct     = Math.min(100, Math.round(done / total * 100));
  const barColor = failed ? '#ff4757' : running ? '#02c8ff' : done === total ? '#00e68a' : '#667788';
  const labelText = failed  ? 'Failed at step ' + (done + 1) + '/' + total
                  : running ? 'Running \u2014 ' + done + '/' + total
                  : done === total ? 'Complete! All ' + total + ' steps done'
                  : done === 0    ? 'Not started'
                  : 'Paused \u2014 ' + done + '/' + total;

  let html = '';

  // ── Header row ──────────────────────────────────────────────────────────────
  html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  html += '<span style="font-size:14px;font-weight:600;color:#cdd6e0;">EVPN VXLAN Fabric</span>';
  html += '<div style="display:flex;gap:8px;">';
  html += '<button id="fabric-run-btn" style="background:#02c8ff;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">&#9654; Run Fabric</button>';
  html += '<button id="fabric-verify-btn" style="background:#27ae60;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;">&#10003; Verify Only</button>';
  html += '<button id="fabric-reset-btn" style="background:#e74c3c;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;">&#8635; Reset</button>';
  html += '</div></div>';

  // ── Status bar ───────────────────────────────────────────────────────────────
  html += '<div style="margin-bottom:14px;">';
  html += '<div style="display:flex;justify-content:space-between;font-size:11px;color:#8899aa;margin-bottom:4px;">';
  html += '<span>' + labelText + '</span>';
  html += '<span>' + pct + '% (' + done + '/' + total + ')</span>';
  html += '</div>';
  html += '<div style="background:#0d1117;border-radius:4px;height:8px;overflow:hidden;">';
  html += '<div style="height:100%;border-radius:4px;background:' + barColor + ';width:' + pct + '%;transition:width 0.4s;"></div>';
  html += '</div></div>';

  // ── Config step cards (11) ───────────────────────────────────────────────────
  const configSteps  = FABRIC_STEPS.filter(s => !s.startsWith('verify_'));
  const verifySteps  = FABRIC_STEPS.filter(s =>  s.startsWith('verify_'));

  html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-bottom:12px;">';
  configSteps.forEach((s, i) => {
    const info   = steps[s] || {};
    const st     = info.status || 'pending';
    const result = (info.result || '').substring(0, 200);
    const dur    = formatDur(info.started_at, info.completed_at);
    const cardBorder = st === 'failed'    ? 'border-left:3px solid #ff4757;'
                     : st === 'running'   ? 'border-left:3px solid #02c8ff;'
                     : st === 'completed' ? 'border-left:3px solid #00e68a;' : '';
    html += '<div class="step-card" style="' + cardBorder + '">';
    html += '<div class="step-num">Step ' + (FABRIC_STEPS.indexOf(s)+1) + '/' + total + '</div>';
    html += '<div class="step-name">' + (FABRIC_STEP_LABELS[s]||s) + '</div>';
    html += '<div style="font-size:10px;color:#556677;margin-bottom:3px;">' + (FABRIC_STEP_TARGETS[s]||'') + '</div>';
    html += pipelineBadge(st);
    if (result) html += '<div class="step-result">' + result.split('\\n')[0] + '</div>';
    if (dur)    html += '<div class="step-dur">' + dur + '</div>';
    html += '</div>';
  });
  html += '</div>';

  // ── Verify cards (2) — full width, side by side ───────────────────────────
  html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">';
  verifySteps.forEach((s) => {
    const info   = steps[s] || {};
    const st     = info.status || 'pending';
    const result = (info.result || '').substring(0, 2000);
    const dur    = formatDur(info.started_at, info.completed_at);
    const cardBorder = st === 'failed'    ? 'border-left:3px solid #ff4757;'
                     : st === 'running'   ? 'border-left:3px solid #02c8ff;'
                     : st === 'completed' ? 'border-left:3px solid #00e68a;' : '';
    html += '<div class="step-card" style="' + cardBorder + 'padding:14px;">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">';
    html += '<div>';
    html += '<div class="step-num">Step ' + (FABRIC_STEPS.indexOf(s)+1) + '/' + total + '</div>';
    html += '<div class="step-name" style="font-size:13px;">' + (FABRIC_STEP_LABELS[s]||s) + '</div>';
    html += '<div style="font-size:10px;color:#556677;">' + (FABRIC_STEP_TARGETS[s]||'') + '</div>';
    html += '</div>';
    html += '<div style="text-align:right;">';
    html += pipelineBadge(st);
    if (dur) html += '<div class="step-dur">' + dur + '</div>';
    html += '</div></div>';
    if (FABRIC_STEP_COMMANDS[s]) {
      html += '<div style="font-size:10px;color:#02c8ff;font-family:monospace;background:#0a1628;border-radius:3px;padding:3px 7px;margin-bottom:8px;display:inline-block;">' + FABRIC_STEP_COMMANDS[s] + '</div>';
    }
    const parts = result.split('\\n');
    const summary = parts[0];
    const rawOutput = parts.slice(1).join('\\n').trim();
    if (summary) html += '<div class="step-result" style="margin-bottom:6px;">' + summary + '</div>';
    if (rawOutput) {
      html += '<pre style="font-size:10px;color:#aabbcc;background:#060d18;border:1px solid #1e3050;border-radius:4px;padding:8px;height:200px;overflow-y:auto;white-space:pre;margin:0;text-align:left;">' + rawOutput.replace(/</g,'&lt;').replace(/>/g,'&gt;') + '</pre>';
    }
    html += '</div>';
  });
  html += '</div>';

  // Only update DOM if content changed — prevents scroll jump on re-render
  // Also force re-render when podId changes so button handlers are re-attached
  const newHtml = html;
  if (grid._lastHtml === newHtml && grid._lastPodId === podId) return;
  grid._lastHtml = newHtml;
  grid._lastPodId = podId;
  grid.innerHTML = newHtml;

  setTimeout(() => {
    const runBtn    = document.getElementById('fabric-run-btn');
    const resetBtn  = document.getElementById('fabric-reset-btn');
    const verifyBtn = document.getElementById('fabric-verify-btn');
    if (runBtn)    runBtn.onclick    = () => triggerFabric(podId, 'run');
    if (resetBtn)  resetBtn.onclick  = () => { if(confirm('Reset all fabric steps for ' + podId + '?')) triggerFabric(podId, 'reset'); };
    if (verifyBtn) verifyBtn.onclick = () => triggerFabric(podId, 'verify');
  }, 0);

  // Render the CatC tile inside the container we just created
  renderCatcTile(podId);
}

// ── Base Config Reset ─────────────────────────────────────────────────────────

const BASECONFIG_SWITCHES = {
  border_spine: { name: 'Border Spine', ip: '198.18.128.24' },
  leaf1:        { name: 'Leaf 1',        ip: '198.18.128.22' },
  leaf2:        { name: 'Leaf 2',        ip: '198.18.128.23' },
};

// ---------------------------------------------------------------------------
// SDA Fabric Tab
// ---------------------------------------------------------------------------

const SDA_DEPLOY_STEP_KEYS = [
  "discovery","provision","fabric_site","virtual_networks",
  "anycast_gateways","transit","clean_fabric_vlans","fabric_devices","l3_handoff",
  "configure_handoff_interface","deploy_anycast_gateways",
  "port_assignments","verify"
];
const SDA_DEPLOY_STEP_LABELS = {
  discovery:                    "Discovery (Loopbacks)",
  provision:                    "Provision to MAIN Site",
  fabric_site:                  "Create Fabric Site",
  virtual_networks:             "Create L3 VNs",
  anycast_gateways:             "Anycast Gateways",
  transit:                      "XAR-Transit",
  clean_fabric_vlans:           "Clean Conflicting VLANs",
  fabric_devices:               "Fabric Devices",
  l3_handoff:                   "L3 Handoff",
  configure_handoff_interface:  "Configure Handoff Interface",
  deploy_anycast_gateways:      "Deploy Anycast Gateways",
  port_assignments:             "Trunk Port Assignments",
  verify:                       "Verify Fabric",
};
const SDA_DEPLOY_STEP_TARGETS = {
  discovery:                    "172.30.255.1–3",
  provision:                    "All 3 switches",
  fabric_site:                  "Site-105/MAIN",
  virtual_networks:             "Main / PROD / IOT",
  anycast_gateways:             "VLAN 10 / 101 / 102",
  transit:                      "BGP ASN 65534",
  clean_fabric_vlans:           "All 3 switches",
  fabric_devices:               "Border+CP + Leaf1+Leaf2",
  l3_handoff:                   "CatC API",
  configure_handoff_interface:  "Gi1/0/48 sub-ints",
  deploy_anycast_gateways:      "CatC → Leaf2 SVIs",
  port_assignments:             "Gi1/0/2 Leaf1+Leaf2",
  verify:                       "Catalyst Center",
};

const SDA_ROLLBACK_STEP_KEYS = [
  "remove_port_assignments","remove_l3_handoffs","restore_handoff_interface",
  "remove_fabric_devices","remove_anycast_gateways","disable_gbac_policy",
  "remove_transit","remove_vn_assignments","remove_virtual_networks",
  "remove_fabric_site","delete_devices","delete_discovery",
  "delete_ise_nads","remove_network_profile"
];
const SDA_ROLLBACK_STEP_LABELS = {
  remove_port_assignments:     "Remove Port Assignments",
  remove_l3_handoffs:          "Remove L3 Handoffs",
  restore_handoff_interface:   "Restore Gi1/0/48 to Trunk",
  remove_fabric_devices:       "Remove Fabric Devices",
  remove_anycast_gateways:     "Remove Anycast Gateways",
  disable_gbac_policy:         "Disable GBAC Policy",
  remove_transit:              "Remove XAR-Transit",
  remove_vn_assignments:       "Remove VN Site Assignments",
  remove_virtual_networks:     "Delete L3 VNs",
  remove_fabric_site:          "Delete Fabric Site",
  delete_devices:              "Delete from Inventory",
  delete_discovery:            "Delete Discovery Job",
  delete_ise_nads:             "Delete ISE NADs",
  remove_network_profile:      "Remove Network Profile",
};
const SDA_ROLLBACK_STEP_TARGETS = {
  remove_port_assignments:     "Gi1/0/2 Leaf1+Leaf2",
  remove_l3_handoffs:          "CatC API",
  restore_handoff_interface:   "Border Spine Gi1/0/48",
  remove_fabric_devices:   "Edge nodes first",
  remove_anycast_gateways: "VLAN 10 / 101 / 102",
  disable_gbac_policy:     "CATC GBAC",
  remove_transit:          "XAR-Transit",
  remove_vn_assignments:   "Main / PROD / IOT",
  remove_virtual_networks: "Main / PROD / IOT",
  remove_fabric_site:      "Site-105/MAIN",
  delete_devices:          "All 3 switches",
  delete_discovery:        "Site-105-Discovery",
  delete_ise_nads:         "ISE loopback NADs",
  remove_network_profile:  "Site network profile",
};

function renderSdaGrid(podId, data) {
  const grid = document.getElementById('sda-grid');
  if (!grid) return;

  const deploy   = data.deploy   || {};
  const rollback = data.rollback || {};

  // ── Compute overall state ────────────────────────────────────────────────
  const dSteps   = SDA_DEPLOY_STEP_KEYS;
  const dDone    = dSteps.filter(s => (deploy[s]||{}).status === 'completed').length;
  const dFailed  = dSteps.filter(s => (deploy[s]||{}).status === 'failed').length;
  const dRunning = dSteps.some(s => (deploy[s]||{}).status === 'running');
  const dTotal   = dSteps.length;
  const dPct     = Math.min(100, Math.round(dDone / dTotal * 100));
  const barColor = dFailed  ? '#ff4757'
                 : dRunning ? '#02c8ff'
                 : dDone === dTotal && dDone > 0 ? '#00e68a' : '#445566';
  const labelText = dFailed  ? 'Failed at step ' + (dDone + 1) + '/' + dTotal
                  : dRunning ? 'Running \u2014 ' + dDone + '/' + dTotal
                  : dDone === dTotal && dDone > 0 ? 'Complete! All ' + dTotal + ' steps done'
                  : dDone === 0 ? 'Not started'
                  : 'Paused \u2014 ' + dDone + '/' + dTotal;

  let html = '';

  // ── CatC Discovery tile container ─────────────────────────────────────────
  html += '<div id="sda-catc-tile-container" style="margin-bottom:14px;"></div>';

  // ── Header row ────────────────────────────────────────────────────────────
  html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  html += '<span style="font-size:14px;font-weight:600;color:#cdd6e0;">SDA Fabric — Deploy</span>';
  html += '<div style="display:flex;gap:8px;">';
  html += '<button id="sda-deploy-btn" style="background:#02c8ff;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">&#9654; Run Deploy</button>';
  html += '<button id="sda-rollback-btn" style="background:#e74c3c;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;">&#8635; Rollback</button>';
  html += '<button id="sda-clear-btn" style="background:#1a2d4a;color:#8899aa;border:1px solid #2a3d5a;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:12px;">&#10005; Clear</button>';
  html += '</div></div>';

  // ── Progress bar ──────────────────────────────────────────────────────────
  html += '<div style="margin-bottom:14px;">';
  html += '<div style="display:flex;justify-content:space-between;font-size:11px;color:#8899aa;margin-bottom:4px;">';
  html += '<span id="sda-deploy-label">' + labelText + '</span>';
  html += '<span id="sda-deploy-pct">' + dPct + '% (' + dDone + '/' + dTotal + ')</span>';
  html += '</div>';
  html += '<div style="background:#0d1117;border-radius:4px;height:8px;overflow:hidden;">';
  html += '<div id="sda-deploy-bar" style="height:100%;border-radius:4px;background:' + barColor + ';width:' + dPct + '%;transition:width 0.4s;"></div>';
  html += '</div></div>';

  // ── Deploy step cards ─────────────────────────────────────────────────────
  html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;margin-bottom:18px;">';
  dSteps.forEach((s, i) => {
    const info   = deploy[s] || {};
    const st     = info.status || 'pending';
    const result = (info.result || '').substring(0, 200);
    const dur    = formatDur(info.started_at, info.completed_at);
    const borderColor = st === 'failed' ? '#ff4757' : st === 'running' ? '#02c8ff' : st === 'completed' ? '#00e68a' : 'transparent';
    html += '<div id="sda-card-deploy-' + s + '" class="step-card" style="border-left:3px solid ' + borderColor + ';">';
    html += '<div class="step-num">Step ' + (i + 1) + '/' + dTotal + '</div>';
    html += '<div class="step-name">' + (SDA_DEPLOY_STEP_LABELS[s] || s) + '</div>';
    html += '<div style="font-size:10px;color:#556677;margin-bottom:3px;">' + (SDA_DEPLOY_STEP_TARGETS[s] || '') + '</div>';
    html += '<span class="sda-badge">' + pipelineBadge(st) + '</span>';
    if (result) html += '<div class="step-result">' + result.split('\\n')[0] + '</div>';
    if (dur)    html += '<div class="step-dur">' + dur + '</div>';
    html += '</div>';
  });
  html += '</div>';

  // ── Rollback section ──────────────────────────────────────────────────────
  const rSteps   = SDA_ROLLBACK_STEP_KEYS;
  const rDone    = rSteps.filter(s => (rollback[s]||{}).status === 'completed').length;
  const rFailed  = rSteps.filter(s => (rollback[s]||{}).status === 'failed').length;
  const rRunning = rSteps.some(s => (rollback[s]||{}).status === 'running');
  const rTotal   = rSteps.length;
  const rPct     = Math.min(100, Math.round(rDone / rTotal * 100));
  const rBarColor = rFailed  ? '#ff4757' : rRunning ? '#e67e22' : rDone === rTotal && rDone > 0 ? '#00e68a' : '#445566';
  const rLabel    = rFailed  ? 'Rollback failed at step ' + (rDone + 1) + '/' + rTotal
                  : rRunning ? 'Rolling back \u2014 ' + rDone + '/' + rTotal
                  : rDone === rTotal && rDone > 0 ? 'Rollback complete! All ' + rTotal + ' steps done'
                  : rDone === 0 ? 'Not started'
                  : 'Paused \u2014 ' + rDone + '/' + rTotal;

  html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px;">';
  html += '<span style="font-size:13px;font-weight:600;color:#cdd6e0;">Rollback</span>';
  html += '<span style="font-size:11px;color:#8899aa;">' + rPct + '% (' + rDone + '/' + rTotal + ')</span>';
  html += '</div>';
  html += '<div style="background:#0d1117;border-radius:4px;height:5px;overflow:hidden;margin-bottom:10px;">';
  html += '<div style="height:100%;border-radius:4px;background:' + rBarColor + ';width:' + rPct + '%;transition:width 0.4s;"></div>';
  html += '</div>';
  html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;">';
  rSteps.forEach((s, i) => {
    const info   = rollback[s] || {};
    const st     = info.status || 'pending';
    const result = (info.result || '').substring(0, 200);
    const dur    = formatDur(info.started_at, info.completed_at);
    const borderColor = st === 'failed' ? '#ff4757' : st === 'running' ? '#e67e22' : st === 'completed' ? '#00e68a' : 'transparent';
    html += '<div id="sda-card-rollback-' + s + '" class="step-card" style="border-left:3px solid ' + borderColor + ';">';
    html += '<div class="step-num">Step ' + (i + 1) + '/' + rTotal + '</div>';
    html += '<div class="step-name">' + (SDA_ROLLBACK_STEP_LABELS[s] || s) + '</div>';
    html += '<div style="font-size:10px;color:#556677;margin-bottom:3px;">' + (SDA_ROLLBACK_STEP_TARGETS[s] || '') + '</div>';
    html += '<span class="sda-badge">' + pipelineBadge(st) + '</span>';
    if (result) html += '<div class="step-result">' + result.split('\\n')[0] + '</div>';
    if (dur)    html += '<div class="step-dur">' + dur + '</div>';
    html += '</div>';
  });
  html += '</div>';

  if (grid._lastHtml === html && grid._lastPodId === podId) return;
  grid._lastHtml = html;
  grid._lastPodId = podId;
  grid.innerHTML = html;

  // Wire buttons
  setTimeout(() => {
    const deployBtn   = document.getElementById('sda-deploy-btn');
    const rollbackBtn = document.getElementById('sda-rollback-btn');
    const clearBtn    = document.getElementById('sda-clear-btn');
    if (deployBtn)   deployBtn.onclick   = () => triggerSda(podId, 'deploy');
    if (rollbackBtn) rollbackBtn.onclick = () => { if (confirm('Roll back SDA fabric for ' + podId + '? This will remove all SDA config.')) triggerSda(podId, 'rollback'); };
    if (clearBtn)    clearBtn.onclick    = () => clearSda(podId);
  }, 0);

  // Render CatC tile inside the container we just created
  renderSdaCatcTile(podId);
}

function renderSdaCatcTile(podId) {
  const container = document.getElementById('sda-catc-tile-container');
  if (!container || !podId) return;

  // Only build the shell once — avoids re-wiring buttons and flickering on every poll
  if (!container._initialized) {
    container._initialized = true;
    container.innerHTML =
      '<div style="background:#0a1628;border:1px solid #1a2d4a;border-radius:8px;padding:14px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">' +
          '<div>' +
            '<span style="font-size:13px;font-weight:600;color:#cdd6e0;">Catalyst Center Discovery</span>' +
            '<span style="font-size:10px;color:#667788;margin-left:8px;">198.18.5.100</span>' +
          '</div>' +
          '<div style="display:flex;gap:6px;">' +
            '<button id="sda-catc-discover-btn" style="background:#7b4fff;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">&#128269; Discover</button>' +
            '<button id="sda-catc-rerun-btn" style="background:#1a2d4a;color:#8899aa;border:1px solid #2a3d5a;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;">&#8635; Re-run</button>' +
            '<button id="sda-catc-reset-btn" style="background:#1a2d4a;color:#e74c3c;border:1px solid #e74c3c;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;">&#10006; Reset</button>' +
          '</div>' +
        '</div>' +
        '<div id="sda-catc-progress-area"></div>' +
      '</div>';

    document.getElementById('sda-catc-discover-btn').addEventListener('click', () => triggerSdaCatcDiscover(podId));
    document.getElementById('sda-catc-rerun-btn').addEventListener('click',    () => triggerSdaCatcDiscover(podId));
    document.getElementById('sda-catc-reset-btn').addEventListener('click',    () => resetSdaCatcDiscover(podId));
  }

  loadSdaCatcStatus(podId);
}

async function loadSdaCatcStatus(podId) {
  let data;
  try { data = await fetch('/api/catc/status/' + podId).then(r => r.json()); }
  catch(e) { return null; }

  const steps   = data.steps   || [];
  const done    = data.done    || 0;
  const total   = data.total   || 6;
  const overall = data.overall || 'pending';
  const pct      = total > 0 ? Math.round(done / total * 100) : 0;
  const barColor = overall === 'completed' ? '#00e68a' : overall === 'failed' ? '#ff4757' : overall === 'running' ? '#02c8ff' : '#445566';
  const labelText = overall === 'completed' ? 'Complete \u2014 all ' + total + ' steps done'
                  : overall === 'failed'    ? 'Failed'
                  : overall === 'running'   ? 'Running...'
                  : 'Not started';

  let h = '';
  h += '<div style="margin-bottom:10px;">';
  h += '<div style="display:flex;justify-content:space-between;font-size:11px;color:#8899aa;margin-bottom:4px;">';
  h += '<span>' + labelText + '</span><span>' + pct + '% (' + done + '/' + total + ')</span>';
  h += '</div>';
  h += '<div style="background:#0d1117;border-radius:4px;height:6px;overflow:hidden;">';
  h += '<div style="height:100%;border-radius:4px;background:' + barColor + ';width:' + pct + '%;transition:width 0.4s;"></div>';
  h += '</div></div>';
  h += '<div style="display:flex;flex-direction:column;gap:5px;">';
  steps.forEach(s => {
    const icon  = s.status === 'completed' ? '&#10003;' : s.status === 'failed' ? '&#10007;' : s.status === 'running' ? '&#9696;' : '&#9675;';
    const color = s.status === 'completed' ? '#00e68a'  : s.status === 'failed' ? '#ff4757'  : s.status === 'running' ? '#02c8ff' : '#445566';
    h += '<div style="display:flex;align-items:flex-start;gap:8px;font-size:11px;">';
    h += '<span style="color:' + color + ';min-width:12px;margin-top:1px;">' + icon + '</span>';
    h += '<span style="color:#cdd6e0;min-width:170px;">' + s.label + '</span>';
    if (s.message) h += '<span style="color:#8899aa;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + s.message.replace(/"/g, '&quot;') + '">' + s.message + '</span>';
    h += '</div>';
  });
  h += '</div>';

  const area = document.getElementById('sda-catc-progress-area');
  if (area) area.innerHTML = h;
  return data;
}

async function triggerSdaCatcDiscover(podId) {
  const btn   = document.getElementById('sda-catc-discover-btn');
  const rerun = document.getElementById('sda-catc-rerun-btn');
  const area  = document.getElementById('sda-catc-progress-area');
  if (btn)   { btn.disabled   = true;  btn.textContent = 'Running...'; }
  if (rerun) { rerun.disabled = true; }
  if (area)  { area.innerHTML = '<div style="color:#8899aa;font-size:11px;">Starting...</div>'; }

  const r = await fetch('/api/catc/discover/' + podId, { method: 'POST' });
  const resp = await r.json();
  if (resp.status === 'error') {
    if (area) area.innerHTML = '<div style="color:#ff4757;font-size:11px;">&#10007; ' + (resp.message || 'Error') + '</div>';
    if (btn)   { btn.disabled = false;   btn.innerHTML = '&#128269; Discover'; }
    if (rerun) { rerun.disabled = false; }
    return;
  }

  let polls = 0;
  const poll = setInterval(async () => {
    polls++;
    const sr = await loadSdaCatcStatus(podId);
    if (!sr || !sr.running || polls >= 60) {
      clearInterval(poll);
      // Final refresh to ensure terminal state is rendered
      await loadSdaCatcStatus(podId);
      if (btn)   { btn.disabled = false;   btn.innerHTML = '&#128269; Discover'; }
      if (rerun) { rerun.disabled = false; }
    }
  }, 3000);
}

async function resetSdaCatcDiscover(podId) {
  if (!confirm('Reset Catalyst Center discovery for ' + podId + '? This clears the step log so you can re-run from scratch.')) return;
  const btn  = document.getElementById('sda-catc-reset-btn');
  const area = document.getElementById('sda-catc-progress-area');
  if (btn)  { btn.disabled = true; btn.textContent = 'Resetting...'; }
  await fetch('/api/catc/clear/' + podId, { method: 'POST' });
  if (area) area.innerHTML = '<div style="color:#8899aa;font-size:11px;">Reset — ready to discover.</div>';
  if (btn)  { btn.disabled = false; btn.innerHTML = '&#10006; Reset'; }
  loadSdaCatcStatus(podId);
}

async function loadSdaStatus(podId) {
  const grid = document.getElementById('sda-grid');
  if (!podId) { if (grid) grid.innerHTML = '<div style="color:#667788;padding:20px;">No POD selected.</div>'; return; }
  const data = await fetch('/api/sda/status/' + podId).then(r => r.json());
  renderSdaGrid(podId, data);
  // Only start poller if something is genuinely running
  const isRunning = s => (s || {}).status === 'running';
  const anyRunning = [...Object.values(data.deploy || {}), ...Object.values(data.rollback || {})].some(isRunning);
  if (anyRunning) _sdaStartPoller(podId);
}

function _sdaStartPoller(podId) {
  if (window._sdaPoller) clearInterval(window._sdaPoller);
  let polls = 0;
  const isRunning = s => (s || {}).status === 'running';
  window._sdaPoller = setInterval(async () => {
    polls++;
    const data = await fetch('/api/sda/status/' + podId).then(r => r.json());
    const anyRunning = [...Object.values(data.deploy || {}), ...Object.values(data.rollback || {})].some(isRunning);
    if (!anyRunning || polls > 300) {
      clearInterval(window._sdaPoller);
      window._sdaPoller = null;
      renderSdaGrid(podId, data);
      return;
    }
    _sdaUpdateCards(data);
  }, 3000);
}

function _sdaUpdateCards(data) {
  const deploy   = data.deploy   || {};
  const rollback = data.rollback || {};

  // Update progress bar text + fill
  const dSteps  = SDA_DEPLOY_STEP_KEYS;
  const dDone   = dSteps.filter(s => (deploy[s]||{}).status === 'completed').length;
  const dFailed = dSteps.filter(s => (deploy[s]||{}).status === 'failed').length > 0;
  const dRun    = dSteps.some(s => (deploy[s]||{}).status === 'running');
  const dTotal  = dSteps.length;
  const dPct    = Math.min(100, Math.round(dDone / dTotal * 100));
  const barColor = dFailed ? '#ff4757' : dRun ? '#02c8ff' : dDone === dTotal && dDone > 0 ? '#00e68a' : '#445566';
  const labelText = dFailed ? 'Failed at step ' + (dDone + 1) + '/' + dTotal
                  : dRun    ? 'Running \u2014 ' + dDone + '/' + dTotal
                  : dDone === dTotal && dDone > 0 ? 'Complete! All ' + dTotal + ' steps done'
                  : dDone === 0 ? 'Not started' : 'Paused \u2014 ' + dDone + '/' + dTotal;

  const bar = document.getElementById('sda-deploy-bar');
  const barLabel = document.getElementById('sda-deploy-label');
  const barPct   = document.getElementById('sda-deploy-pct');
  if (bar)      { bar.style.width = dPct + '%'; bar.style.background = barColor; }
  if (barLabel) barLabel.textContent = labelText;
  if (barPct)   barPct.textContent   = dPct + '% (' + dDone + '/' + dTotal + ')';

  // Update each deploy step card in-place
  dSteps.forEach(s => {
    const info = deploy[s] || {};
    const st   = info.status || 'pending';
    const card = document.getElementById('sda-card-deploy-' + s);
    if (!card) return;
    const borderColor = st === 'failed' ? '#ff4757' : st === 'running' ? '#02c8ff' : st === 'completed' ? '#00e68a' : 'transparent';
    card.style.borderLeftColor = borderColor;
    const badge = card.querySelector('.sda-badge');
    if (badge) badge.outerHTML = '<span class="sda-badge">' + pipelineBadge(st) + '</span>';
    const res = card.querySelector('.step-result');
    const resText = (info.result || '').substring(0, 200).split('\\n')[0];
    if (res) res.textContent = resText;
    else if (resText) {
      const dur = card.querySelector('.step-dur');
      if (dur) dur.insertAdjacentHTML('beforebegin', '<div class="step-result">' + resText + '</div>');
    }
  });

  // Update rollback cards
  const rSteps = SDA_ROLLBACK_STEP_KEYS;
  rSteps.forEach(s => {
    const info = rollback[s] || {};
    const st   = info.status || 'pending';
    const card = document.getElementById('sda-card-rollback-' + s);
    if (!card) return;
    const borderColor = st === 'failed' ? '#ff4757' : st === 'running' ? '#e67e22' : st === 'completed' ? '#00e68a' : 'transparent';
    card.style.borderLeftColor = borderColor;
    const badge = card.querySelector('.sda-badge');
    if (badge) badge.outerHTML = '<span class="sda-badge">' + pipelineBadge(st) + '</span>';
  });
}

async function triggerSda(podId, action) {
  const grid = document.getElementById('sda-grid');
  if (grid) grid._lastHtml = null;
  await fetch('/api/sda/clear/' + podId, { method: 'POST' });
  await fetch('/api/sda/' + action + '/' + podId, { method: 'POST', headers: {'Content-Type':'application/json'}, body: '{}' });
  _sdaStartPoller(podId);
}

async function clearSda(podId) {
  await fetch('/api/sda/clear/' + podId, { method: 'POST' });
  loadSdaStatus(podId);
}

// Tick running switch-reset timers every second without a full re-render.
// _bcRunningTimers is a map of key -> startedAt (ms) set by renderBaseConfigGrid.
window._bcRunningTimers = {};
function _bcTickTimers() {
  const now = Date.now();
  Object.entries(window._bcRunningTimers).forEach(([key, tsMs]) => {
    const timerEl = document.getElementById('bc-timer-' + key);
    const barEl   = document.getElementById('bc-bar-'   + key);
    if (!timerEl) return;
    const elapsed = Math.floor((now - tsMs) / 1000);
    const elStr = elapsed >= 60 ? Math.floor(elapsed/60) + 'm ' + (elapsed%60) + 's' : elapsed + 's';
    const phase = elapsed < 20  ? '① Connecting via Telnet...'
                : elapsed < 50  ? '② Pushing config lines...'
                : elapsed < 70  ? '③ Saving + reloading...'
                : elapsed < 310 ? '④ Waiting for reboot... (' + Math.max(0, 310-elapsed) + 's left)'
                : elapsed < 370 ? '⑤ Reconnecting via SSH...'
                : '⑥ RSA keys + final save...';
    timerEl.textContent = phase + ' — ' + elStr + ' elapsed';
    if (barEl) barEl.style.width = Math.min(99, Math.round(elapsed / 390 * 100)) + '%';
  });
}
setInterval(_bcTickTimers, 1000);

async function loadBaseConfig(podId) {
  const grid = document.getElementById('baseconfig-grid');
  if (!podId) { if (grid) grid.innerHTML = '<div style="color:#667788;padding:20px;">No POD selected.</div>'; return; }
  const r = await fetch('/api/baseconfig/status/' + podId);
  const data = await r.json();
  renderBaseConfigGrid(podId, data);
  // If something is already running (e.g. page refresh mid-reset), start a poller
  const anyRunning = Object.values(data || {}).some(s => (s.reset||'').includes('RUNNING') || (s.verify||'').includes('RUNNING'));
  if (anyRunning) {
    const logEl = document.getElementById('baseconfig-log');
    if (logEl) logEl.style.display = 'block';
    let polls = 0;
    const poll = setInterval(async () => {
      polls++;
      const [lr, sr] = await Promise.all([
        fetch('/api/logs/' + podId).then(r => r.json()),
        fetch('/api/baseconfig/status/' + podId).then(r => r.json()),
      ]);
      const relevant = lr.filter(l => l.includes('[baseconfig/')).slice(-12);
      if (logEl) logEl.textContent = relevant.join('\\n');
      renderBaseConfigGrid(podId, sr);
      const stillRunning = Object.values(sr || {}).some(s => (s.reset||'').includes('RUNNING') || (s.verify||'').includes('RUNNING'));
      if ((!stillRunning && polls > 5) || polls > 200) { clearInterval(poll); window._bcRunningTimers = {}; }
    }, 3000);
  }
}

function _bcStatusBadge(line) {
  if (!line) return { color: '#667788', text: 'Not run', short: '', running: false, startedAt: null };
  if (line.includes('RUNNING')) {
    const m = line.match(/started_at=(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)/);
    const startedAt = m ? m[1] : null;
    const ts = startedAt ? new Date(startedAt).getTime() : NaN;
    if (!isNaN(ts)) {
      const elapsed = Math.floor((Date.now() - ts) / 1000);
      if (elapsed > 600) {
        return { color: '#e74c3c', text: '&#10007; Stale', short: 'Did not complete — try again', running: false, startedAt: null };
      }
    }
    const shortMsg = line.replace(/^\[.*?\]\s*RUNNING\s+started_at=[\w\-:TZ]+:\s*/, '').trim();
    return { color: '#f39c12', text: '&#9696; Running...', short: shortMsg, running: true, startedAt: startedAt };
  }
  // Extract text after the closing bracket tag
  const afterTag = line.replace(/^\[.*?\]\s*/, '');
  if (line.includes('FAILED')) return { color: '#e74c3c', text: '&#10007; FAILED', short: afterTag.replace(/^FAILED:\s*/i, '').substring(0, 120).trim(), running: false, startedAt: null };
  return { color: '#00e68a', text: '&#10003; OK', short: afterTag.replace(/^OK:\s*/i, '').substring(0, 120).trim(), running: false, startedAt: null };
}

function renderBaseConfigGrid(podId, statusData) {
  const grid = document.getElementById('baseconfig-grid');
  if (!grid) return;

  let html = '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px;">';
  html += '<span style="font-size:14px;font-weight:600;color:#cdd6e0;">Switch Base Config Reset</span>';
  html += '<div style="display:flex;gap:8px;">';
  html += '<button id="baseconfig-verify-btn" style="background:#1a6e3c;color:#fff;border:none;padding:6px 16px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">&#10003; Verify All</button>';
  html += '<button id="baseconfig-clear-btn" style="background:#445566;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">&#215; Clear Status</button>';
  html += '<button id="baseconfig-all-btn" style="background:#e74c3c;color:#fff;border:none;padding:6px 18px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">&#8635; Reset Infrastructure</button>';
  html += '</div></div>';

  html += '<div style="background:#12202f;border:1px solid #e74c3c44;border-radius:6px;padding:10px 14px;margin-bottom:14px;font-size:11px;color:#e74c3c;">';
  html += '&#9888;  This will overwrite the running config on the selected switch(es) with the known-good base config and save to NVRAM. Fabric config will be removed.';
  html += '</div>';

  html += '<div style="display:grid;grid-template-columns:repeat(5,1fr);gap:12px;">';

  // Determine if Border Spine is currently running — blocks leaf resets
  const spineStatus = (statusData && statusData.border_spine) ? statusData.border_spine : {};
  const spineRunning = _bcStatusBadge(spineStatus.reset || null).running;

  // Helper: render one card
  function _bcCard(key, title, ip, roleClass, roleLabel, resetBadge, verifyBadge, btnId, btnLabel, blocked, blockedMsg) {
    const isOk   = resetBadge.text.includes('OK');
    const isFail = resetBadge.text.includes('FAILED') || resetBadge.text.includes('Stale');
    const cardClass = 'switch-card' + (isOk ? ' pass' : isFail ? ' fail' : '');
    const detailStyle = 'font-size:10px;color:#667788;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:100%;display:block;margin-bottom:4px;';
    let h = '<div class="' + cardClass + '">';
    // Title row
    h += '<div class="switch-card-title">';
    h += '<span class="role-tag ' + roleClass + '">' + roleLabel + '</span>';
    h += '<span style="color:#e0e6ed;font-size:12px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">' + title + '</span>';
    h += '<span class="device-model">' + ip + '</span>';
    h += '</div>';
    // Reset row
    h += '<div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;margin-bottom:2px;">';
    h += '<span style="color:#8899aa;">Reset</span>';
    h += '<span style="color:' + resetBadge.color + ';font-weight:600;">' + resetBadge.text + '</span>';
    h += '</div>';
    // Detail / progress under reset
    if (resetBadge.running && resetBadge.startedAt) {
      const ts = new Date(resetBadge.startedAt).getTime();
      const elapsed = isNaN(ts) ? 0 : Math.floor((Date.now() - ts) / 1000);
      const elStr = elapsed >= 60 ? Math.floor(elapsed/60) + 'm ' + (elapsed%60) + 's' : elapsed + 's';
      const phase = elapsed < 20  ? '① Connecting via Telnet...'
                  : elapsed < 50  ? '② Pushing config lines...'
                  : elapsed < 70  ? '③ Saving + reloading...'
                  : elapsed < 310 ? '④ Waiting for reboot... (' + Math.max(0, 310-elapsed) + 's left)'
                  : elapsed < 370 ? '⑤ Reconnecting via SSH...'
                  : '⑥ RSA keys + final save...';
      h += '<div id="bc-timer-' + key + '" style="' + detailStyle + 'color:#f39c12;"></div>';
      h += '<div class="switch-bar" style="margin-bottom:4px;"><div id="bc-bar-' + key + '" class="switch-bar-fill" style="width:0%;background:#f39c12;"></div></div>';
    } else {
      const txt = (resetBadge.short || '').substring(0, 60);
      h += '<div style="' + detailStyle + '" title="' + (resetBadge.short||'').replace(/"/g,'&quot;') + '">' + (txt || '&nbsp;') + '</div>';
      h += '<div style="height:4px;margin-bottom:4px;"></div>';
    }
    // Verify row — always rendered for uniform height
    if (verifyBadge !== null) {
      h += '<div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;margin-bottom:2px;">';
      h += '<span style="color:#8899aa;">Verify</span>';
      h += '<span style="color:' + verifyBadge.color + ';font-weight:600;">' + verifyBadge.text + '</span>';
      h += '</div>';
      const vtxt = (verifyBadge.short || '').substring(0, 60);
      h += '<div style="' + detailStyle + '" title="' + (verifyBadge.short||'').replace(/"/g,'&quot;') + '">' + (vtxt || '&nbsp;') + '</div>';
    } else {
      h += '<div style="display:flex;justify-content:space-between;align-items:center;font-size:11px;margin-bottom:2px;">';
      h += '<span style="color:#8899aa;">Verify</span>';
      h += '<span style="color:#334455;font-weight:600;">N/A</span>';
      h += '</div>';
      h += '<div style="' + detailStyle + '">&nbsp;</div>';
    }
    // Button pinned to bottom
    if (blocked) {
      h += '<button disabled style="margin-top:auto;background:#1a2d4a;color:#445566;border:1px solid #1e3050;padding:5px 10px;border-radius:4px;font-size:11px;width:100%;cursor:not-allowed;">&#9203; Spine Resetting...</button>';
    } else {
      h += '<button id="' + btnId + '" style="margin-top:auto;background:#c0392b;color:#fff;border:none;padding:5px 10px;border-radius:4px;cursor:pointer;font-size:11px;width:100%;">&#8635; ' + btnLabel + '</button>';
    }
    h += '</div>';
    return h;
  }

  for (const [key, info] of Object.entries(BASECONFIG_SWITCHES)) {
    const s = (statusData && statusData[key]) ? statusData[key] : {};
    const resetBadge  = _bcStatusBadge(s.reset  || null);
    const verifyBadge = _bcStatusBadge(s.verify || null);
    const isLeaf = key === 'leaf1' || key === 'leaf2';
    const blocked = isLeaf && spineRunning;
    const role = key === 'border_spine' ? 'border' : 'leaf';
    const roleLabel = key === 'border_spine' ? 'SPINE' : 'LEAF';
    html += _bcCard(key, info.name, info.ip, role, roleLabel, resetBadge, verifyBadge,
                    'baseconfig-btn-' + key, 'Reset', blocked, '');
  }

  // ISE card
  const iseS = (statusData && statusData.ise) ? statusData.ise : {};
  const iseBadge = _bcStatusBadge(iseS.reset || null);
  html += _bcCard('ise', 'ISE', '198.18.5.101', 'cc', 'ISE', iseBadge, null,
                  'baseconfig-btn-ise', 'Cleanup NADs', false, '');

  // Catalyst Center card
  const catcS = (statusData && statusData.catc) ? statusData.catc : {};
  const catcBadge = _bcStatusBadge(catcS.reset || null);
  html += _bcCard('catc', 'Catalyst Center', '198.18.5.100', 'cc', 'CATC', catcBadge, null,
                  'baseconfig-btn-catc', 'Cleanup Devices', false, '');

  html += '</div>';

  html += '<div id="baseconfig-log" style="margin-top:14px;background:#0d1117;border:1px solid #2a3040;border-radius:4px;padding:10px;font-size:11px;font-family:monospace;color:#8899aa;max-height:160px;overflow-y:auto;display:none;"></div>';

  // Only rebuild DOM if content changed
  if (grid._lastHtml === html && grid._lastPodId === podId) return;
  grid._lastHtml = html;
  grid._lastPodId = podId;
  grid.innerHTML = html;

  // Rebuild the 1-second timer registry from the current status data
  window._bcRunningTimers = {};
  for (const [key, s] of Object.entries(statusData || {})) {
    const badge = _bcStatusBadge(s.reset || null);
    if (badge.running && badge.startedAt) {
      window._bcRunningTimers[key] = new Date(badge.startedAt).getTime();
    }
  }
  // Tick immediately so the timer shows correct value before the next 1-second interval
  _bcTickTimers();

  // Wire buttons — must run after every innerHTML replacement
  _bcWireButtons(podId);
}

function _bcWireButtons(podId) {
  const allBtn = document.getElementById('baseconfig-all-btn');
  if (allBtn) allBtn.onclick = () => triggerBaseConfig(podId, 'all');
  const verifyBtn = document.getElementById('baseconfig-verify-btn');
  if (verifyBtn) verifyBtn.onclick = () => triggerBaseConfigVerify(podId);
  const clearBtn = document.getElementById('baseconfig-clear-btn');
  if (clearBtn) clearBtn.onclick = () => clearBaseConfigStatus(podId);
  for (const key of Object.keys(BASECONFIG_SWITCHES)) {
    const btn = document.getElementById('baseconfig-btn-' + key);
    if (btn) btn.onclick = () => triggerBaseConfig(podId, key);
  }
  const iseBtn = document.getElementById('baseconfig-btn-ise');
  if (iseBtn) iseBtn.onclick = () => triggerBaseConfigService(podId, 'ise');
  const catcBtn = document.getElementById('baseconfig-btn-catc');
  if (catcBtn) catcBtn.onclick = () => triggerBaseConfigService(podId, 'catc');
}

async function triggerBaseConfig(podId, switchKey) {
  const grid = document.getElementById('baseconfig-grid');
  if (grid) grid._lastHtml = null;  // force re-render so log area shows
  const logEl = document.getElementById('baseconfig-log');
  if (logEl) { logEl.style.display = 'block'; logEl.textContent = 'Starting base config reset for ' + switchKey + '...\\n'; }
  const r = await fetch('/api/baseconfig/reset/' + podId + '/' + switchKey, { method: 'POST' });
  const data = await r.json();
  if (logEl) logEl.textContent += (data.message || JSON.stringify(data)) + '\\n';
  // Poll status cards + log — runs until no RUNNING state or 10 min max (200 x 3s)
  let polls = 0;
  const poll = setInterval(async () => {
    polls++;
    const [lr, sr] = await Promise.all([
      fetch('/api/logs/' + podId).then(r => r.json()),
      fetch('/api/baseconfig/status/' + podId).then(r => r.json()),
    ]);
    const relevant = lr.filter(l => l.includes('[baseconfig/')).slice(-12);
    if (logEl) logEl.textContent = relevant.join('\\n');
    renderBaseConfigGrid(podId, sr);
    const stillRunning = Object.values(sr || {}).some(s => (s.reset||'').includes('RUNNING') || (s.verify||'').includes('RUNNING'));
    if ((!stillRunning && polls > 5) || polls > 200) clearInterval(poll);
  }, 3000);
}

async function triggerBaseConfigService(podId, service) {
  const grid = document.getElementById('baseconfig-grid');
  if (grid) grid._lastHtml = null;
  const logEl = document.getElementById('baseconfig-log');
  if (logEl) { logEl.style.display = 'block'; logEl.textContent = 'Starting ' + service.toUpperCase() + ' cleanup...\\n'; }
  const r = await fetch('/api/baseconfig/service/' + podId + '/' + service, { method: 'POST' });
  const data = await r.json();
  if (logEl) logEl.textContent += (data.message || JSON.stringify(data)) + '\\n';
  let polls = 0;
  const poll = setInterval(async () => {
    polls++;
    const [lr, sr] = await Promise.all([
      fetch('/api/logs/' + podId).then(r => r.json()),
      fetch('/api/baseconfig/status/' + podId).then(r => r.json()),
    ]);
    const relevant = lr.filter(l => l.includes('[baseconfig/' + service + ']')).slice(-8);
    if (logEl) logEl.textContent = relevant.join('\\n');
    renderBaseConfigGrid(podId, sr);
    const badge = _bcStatusBadge(sr[service] ? sr[service].reset : null);
    if (!badge.running || polls > 20) clearInterval(poll);
  }, 3000);
}

async function triggerBaseConfigVerify(podId) {
  const grid = document.getElementById('baseconfig-grid');
  if (grid) grid._lastHtml = null;
  const logEl = document.getElementById('baseconfig-log');
  if (logEl) { logEl.style.display = 'block'; logEl.textContent = 'Starting verify...\\n'; }
  const r = await fetch('/api/baseconfig/verify/' + podId, { method: 'POST' });
  const data = await r.json();
  if (logEl) logEl.textContent += (data.message || JSON.stringify(data)) + '\\n';
  let polls = 0;
  const poll = setInterval(async () => {
    polls++;
    const [lr, sr] = await Promise.all([
      fetch('/api/logs/' + podId).then(r => r.json()),
      fetch('/api/baseconfig/status/' + podId).then(r => r.json()),
    ]);
    const relevant = lr.filter(l => l.includes('[verify/')).slice(-12);
    if (logEl) logEl.textContent = relevant.join('\\n');
    renderBaseConfigGrid(podId, sr);
    // Stop only when all switch verify results are present and none are still RUNNING
    const switchKeys = Object.keys(BASECONFIG_SWITCHES);
    const allDone = switchKeys.every(k => {
      const v = (sr[k] && sr[k].verify) || '';
      return v && !v.includes('RUNNING');
    });
    if ((allDone && polls > 2) || polls > 60) clearInterval(poll);
  }, 3000);
}

async function clearBaseConfigStatus(podId) {
  await fetch('/api/baseconfig/clear/' + podId, { method: 'POST' });
  const grid = document.getElementById('baseconfig-grid');
  if (grid) grid._lastHtml = null;
  loadBaseConfig(podId);
}

async function triggerFabric(podId, action) {
  const logEl = document.getElementById('fabric-log');
  if (logEl) { logEl.style.display = 'block'; logEl.textContent = 'Starting ' + action + '...\\n'; }
  const r = await fetch('/api/fabric/' + action + '/' + podId, { method: 'POST' });
  const data = await r.json();
  if (logEl) logEl.textContent += (data.message || JSON.stringify(data)) + '\\n';
  // Clear _lastHtml so the next global poll forces a re-render with running state
  const grid = document.getElementById('fabric-grid');
  if (grid) grid._lastHtml = null;
  // Immediate refresh to show running state
  await loadFabricStatus(podId);
}

async function loadCatcStatus(podId) {
  // Returns parsed step data; also updates #catc-progress-area if it exists
  let data;
  try {
    data = await fetch('/api/catc/status/' + podId).then(r => r.json());
  } catch(e) { return null; }

  const steps   = data.steps   || [];
  const done    = data.done    || 0;
  const total = data.total || 6;
  const overall = data.overall || 'pending';

  const pct      = total > 0 ? Math.round(done / total * 100) : 0;
  const barColor = overall === 'completed' ? '#00e68a'
                 : overall === 'failed'    ? '#ff4757'
                 : overall === 'running'   ? '#02c8ff' : '#445566';
  const labelText = overall === 'completed' ? 'Complete \u2014 all ' + total + ' steps done'
                  : overall === 'failed'    ? 'Failed'
                  : overall === 'running'   ? 'Running...'
                  : overall === 'pending'   ? 'Not started' : overall;

  let h = '';
  h += '<div style="margin-bottom:10px;">';
  h += '<div style="display:flex;justify-content:space-between;font-size:11px;color:#8899aa;margin-bottom:4px;">';
  h += '<span>' + labelText + '</span>';
  h += '<span>' + pct + '% (' + done + '/' + total + ')</span>';
  h += '</div>';
  h += '<div style="background:#0d1117;border-radius:4px;height:6px;overflow:hidden;">';
  h += '<div style="height:100%;border-radius:4px;background:' + barColor + ';width:' + pct + '%;transition:width 0.4s;"></div>';
  h += '</div></div>';
  h += '<div style="display:flex;flex-direction:column;gap:5px;">';
  steps.forEach(s => {
    const icon  = s.status === 'completed' ? '&#10003;' : s.status === 'failed' ? '&#10007;' : s.status === 'running' ? '&#9696;' : '&#9675;';
    const color = s.status === 'completed' ? '#00e68a'  : s.status === 'failed' ? '#ff4757'  : s.status === 'running' ? '#02c8ff' : '#445566';
    h += '<div style="display:flex;align-items:flex-start;gap:8px;font-size:11px;">';
    h += '<span style="color:' + color + ';min-width:12px;margin-top:1px;">' + icon + '</span>';
    h += '<span style="color:#cdd6e0;min-width:170px;">' + s.label + '</span>';
    if (s.message) h += '<span style="color:#8899aa;flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;" title="' + s.message.replace(/"/g, '&quot;') + '">' + s.message + '</span>';
    h += '</div>';
  });
  h += '</div>';

  const area = document.getElementById('catc-progress-area');
  if (area) area.innerHTML = h;
  return data;
}

function renderCatcTile(podId) {
  const container = document.getElementById('catc-tile-container');
  if (!container || !podId) return;

  // Only build the shell once — avoids re-wiring buttons and flickering on every poll
  if (!container._initialized) {
    container._initialized = true;
    container.innerHTML =
      '<div style="background:#0a1628;border:1px solid #1a2d4a;border-radius:8px;padding:14px;">' +
        '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">' +
          '<div>' +
            '<span style="font-size:13px;font-weight:600;color:#cdd6e0;">Catalyst Center Discovery</span>' +
            '<span style="font-size:10px;color:#667788;margin-left:8px;">198.18.5.100</span>' +
          '</div>' +
          '<div style="display:flex;gap:6px;">' +
            '<button id="catc-discover-btn" style="background:#7b4fff;color:#fff;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">&#128269; Discover</button>' +
            '<button id="catc-rerun-btn" style="background:#1a2d4a;color:#8899aa;border:1px solid #2a3d5a;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;">&#8635; Re-run</button>' +
            '<button id="catc-reset-btn" style="background:#1a2d4a;color:#e74c3c;border:1px solid #e74c3c;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;">&#10006; Reset</button>' +
          '</div>' +
        '</div>' +
        '<div id="catc-progress-area"></div>' +
      '</div>';

    document.getElementById('catc-discover-btn').addEventListener('click', () => triggerCatcDiscover(podId));
    document.getElementById('catc-rerun-btn').addEventListener('click',    () => triggerCatcDiscover(podId));
    document.getElementById('catc-reset-btn').addEventListener('click',    () => resetCatcDiscover(podId));
  }

  loadCatcStatus(podId);
}

async function triggerCatcDiscover(podId) {
  const btn   = document.getElementById('catc-discover-btn');
  const rerun = document.getElementById('catc-rerun-btn');
  const area  = document.getElementById('catc-progress-area');
  if (btn)   { btn.disabled   = true;  btn.textContent = 'Running...'; }
  if (rerun) { rerun.disabled = true; }
  if (area)  { area.innerHTML = '<div style="color:#8899aa;font-size:11px;">Starting...</div>'; }

  const r = await fetch('/api/catc/discover/' + podId, { method: 'POST' });
  const data = await r.json();
  if (data.status === 'error') {
    if (area) area.innerHTML = '<div style="color:#ff4757;font-size:11px;">&#10007; ' + (data.message || 'Error') + '</div>';
    if (btn)   { btn.disabled = false;   btn.innerHTML = '&#128269; Discover'; }
    if (rerun) { rerun.disabled = false; }
    return;
  }

  // Poll until done
  let polls = 0;
  const poll = setInterval(async () => {
    polls++;
    const sr = await loadCatcStatus(podId);
    if (!sr || !sr.running || polls >= 60) {
      clearInterval(poll);
      // Final refresh to ensure terminal state is rendered
      await loadCatcStatus(podId);
      if (btn)   { btn.disabled = false;   btn.innerHTML = '&#128269; Discover'; }
      if (rerun) { rerun.disabled = false; }
    }
  }, 3000);
}

async function resetCatcDiscover(podId) {
  if (!confirm('Reset Catalyst Center discovery for ' + podId + '? This clears the step log so you can re-run from scratch.')) return;
  const btn   = document.getElementById('catc-reset-btn');
  const area  = document.getElementById('catc-progress-area');
  if (btn)  { btn.disabled = true; btn.textContent = 'Resetting...'; }
  await fetch('/api/catc/clear/' + podId, { method: 'POST' });
  if (area) area.innerHTML = '<div style="color:#8899aa;font-size:11px;">Reset — ready to discover.</div>';
  if (btn)  { btn.disabled = false; btn.innerHTML = '&#10006; Reset'; }
  loadCatcStatus(podId);
}

function closeDetail() {
  document.getElementById('detail-panel').style.display = 'none';
  const el = document.getElementById('detail-pod-id');
  el.textContent = '';
  el.dataset.podId = '';
  if (logPollId) clearInterval(logPollId);
  if (stepPollId) { clearInterval(stepPollId); stepPollId = null; }
}

async function connectAllVpn() {
  const btn = document.getElementById('btn-vpn-all');
  const status = document.getElementById('docker-status');
  btn.disabled = true;
  btn.textContent = 'Connecting...';
  status.textContent = 'Connecting all VPNs...';

  const r = await fetch('/api/vpn-connect-all', { method: 'POST' });
  const data = await r.json();
  status.textContent = data.output.slice(0, 300);
  btn.disabled = false;
  btn.textContent = '▶ Connect All VPN';
  setTimeout(() => status.textContent = '', 10000);
  load();
}

async function dockerDown() {
  const btn = document.getElementById('btn-docker-down');
  const status = document.getElementById('docker-status');
  btn.disabled = true;
  btn.textContent = 'Tearing down...';
  status.textContent = 'Tearing down Docker stacks...';

  const r = await fetch('/api/docker-down', { method: 'POST' });
  const data = await r.json();
  status.textContent = data.output.slice(0, 300);
  btn.disabled = false;
  btn.textContent = '■ Teardown All';
  setTimeout(() => status.textContent = '', 10000);
  load();
}

load();
setInterval(load, 5000);
loadUpgradeConfig();

// ── Knowledge Base ────────────────────────────────────────────────────────────
let _kbCurrentId = null;

async function loadKbTab() {
  const grid = document.getElementById('kb-grid');
  if (!grid) return;

  let st = {};
  try { const r = await fetch('/api/kb/status'); st = await r.json(); } catch(e) {}

  let html = '<div style="display:flex;align-items:center;gap:12px;margin-bottom:14px;">'
    + '<span style="font-size:18px;font-weight:700;color:#00bceb;">&#128218; Proctor Knowledge Base</span>'
    + '<span style="font-size:12px;color:#667788;">' + (st.published||0) + ' articles</span>'
    + '<button id="kb-add-btn" style="margin-left:auto;background:#27ae60;color:#fff;border:none;padding:7px 16px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">+ New Article</button>'
    + '</div>';

  // Search bar
  html += '<div style="display:flex;gap:8px;margin-bottom:14px;">'
    + '<input id="kb-search-input" type="text" placeholder="Search articles..." '
    + 'style="flex:1;background:#0d1117;border:1px solid #2a3040;color:#c9d1d9;padding:8px 12px;border-radius:4px;font-size:13px;">'
    + '<button id="kb-search-btn" style="background:#02c8ff;color:#000;border:none;padding:8px 16px;border-radius:4px;cursor:pointer;font-weight:600;font-size:13px;">Search</button>'
    + '</div>'
    + '<div id="kb-answer" style="display:none;background:#0d1117;border:1px solid #2a3040;border-radius:4px;padding:12px;margin-bottom:14px;font-size:13px;color:#c9d1d9;white-space:pre-wrap;"></div>';

  html += '<div id="kb-articles-list"></div>';

  // Article modal
  html += '<div id="kb-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:9999;align-items:center;justify-content:center;">'
    + '<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;padding:24px;width:680px;max-height:85vh;overflow-y:auto;">'
    + '<div style="font-size:16px;font-weight:700;color:#00bceb;margin-bottom:14px;" id="kb-modal-title">New Article</div>'
    + '<input id="kb-m-title" placeholder="Title" style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:8px 10px;border-radius:4px;font-size:14px;margin-bottom:10px;box-sizing:border-box;">'
    + '<textarea id="kb-m-body" rows="14" placeholder="Write your notes here..." style="width:100%;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:8px 10px;border-radius:4px;font-size:13px;font-family:monospace;margin-bottom:10px;box-sizing:border-box;resize:vertical;"></textarea>'
    + '<div style="display:flex;gap:8px;margin-bottom:14px;">'
    + '<input id="kb-m-tags" placeholder="Tags (comma separated)" style="flex:1;background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 10px;border-radius:4px;font-size:12px;">'
    + '<select id="kb-m-category" style="background:#0d1117;border:1px solid #30363d;color:#c9d1d9;padding:7px 8px;border-radius:4px;font-size:12px;">'
    + '<option>general</option><option>sdwan</option><option>switches</option><option>infrastructure</option>'
    + '<option>troubleshooting</option><option>procedure</option></select>'
    + '</div>'
    + '<div style="display:flex;gap:8px;justify-content:flex-end;">'
    + '<button id="kb-m-delete" style="background:#c0392b;color:#fff;border:none;padding:7px 16px;border-radius:4px;cursor:pointer;display:none;">Delete</button>'
    + '<button id="kb-m-cancel" style="background:#21262d;color:#c9d1d9;border:1px solid #30363d;padding:7px 16px;border-radius:4px;cursor:pointer;margin-left:auto;">Cancel</button>'
    + '<button id="kb-m-save" style="background:#00bceb;color:#000;border:none;padding:7px 20px;border-radius:4px;cursor:pointer;font-weight:700;">Save</button>'
    + '</div></div></div>';

  grid.innerHTML = html;
  await refreshKbList();

  setTimeout(() => {
    const searchInput = document.getElementById('kb-search-input');
    const searchBtn   = document.getElementById('kb-search-btn');
    const addBtn      = document.getElementById('kb-add-btn');
    if (addBtn)      addBtn.onclick      = () => kbOpenModal(null);
    if (searchBtn)   searchBtn.onclick   = () => refreshKbList();
    if (searchInput) searchInput.onkeydown = e => { if (e.key === 'Enter') refreshKbList(); };

    const mCancel = document.getElementById('kb-m-cancel');
    const mSave   = document.getElementById('kb-m-save');
    const mDelete = document.getElementById('kb-m-delete');
    if (mCancel) mCancel.onclick = () => { document.getElementById('kb-modal').style.display = 'none'; };
    if (mSave)   mSave.onclick   = kbSaveModal;
    if (mDelete) mDelete.onclick = kbDeleteArticle;
  }, 0);
}

async function refreshKbList() {
  const el = document.getElementById('kb-articles-list');
  if (!el) return;
  const q = (document.getElementById('kb-search-input') || {value:''}).value.trim();

  let articles = [];
  try {
    if (q) {
      const r = await fetch('/api/kb/search?q=' + encodeURIComponent(q) + '&status=published&top_k=20');
      const d = await r.json();
      articles = d.results || [];
    } else {
      const r = await fetch('/api/kb/articles?status=published&limit=200');
      articles = await r.json();
    }
  } catch(e) {
    el.innerHTML = '<div style="color:#e74c3c;padding:20px;">Error loading articles: ' + e + '</div>';
    return;
  }

  if (!articles.length) {
    el.innerHTML = q
      ? '<div style="color:#667788;padding:20px;">No articles matched your search.</div>'
      : '<div style="color:#667788;padding:20px;">No articles yet. Click <b style="color:#00bceb">+ New Article</b> to add your first one.</div>';
    return;
  }

  const catColors = {
    'sdwan':'#00bceb','switches':'#2ecc71','infrastructure':'#f39c12',
    'troubleshooting':'#e74c3c','procedure':'#9b59b6','general':'#667788'
  };

  el.innerHTML = articles.map(a => {
    const cat = a.category || 'general';
    const cc  = catColors[cat] || '#667788';
    const score = a.score != null ? ' <span style="color:#556677;font-size:10px;">&#8212; ' + (a.score*100).toFixed(0) + '% match</span>' : '';
    const preview = (a.body||'').replace(/[#*`]/g,'').substring(0,120).trim();
    return '<div style="background:#0d1117;border:1px solid #1e2d40;border-radius:6px;padding:12px 16px;margin-bottom:8px;cursor:pointer;" '
      + 'onclick="kbViewArticle(' + a.id + ')">'
      + '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px;">'
      + '<span style="background:' + cc + '22;color:' + cc + ';border:1px solid ' + cc + '44;border-radius:3px;padding:1px 7px;font-size:10px;font-weight:700;text-transform:uppercase;">' + cat + '</span>'
      + '<span style="font-size:13px;font-weight:600;color:#c9d1d9;">' + a.title + score + '</span>'
      + (a.tags ? '<span style="margin-left:auto;font-size:10px;color:#445566;">' + a.tags + '</span>' : '')
      + '</div>'
      + (preview ? '<div style="font-size:11px;color:#556677;margin-top:2px;">' + preview + (a.body.length > 120 ? '...' : '') + '</div>' : '')
      + '</div>';
  }).join('');
}

async function kbViewArticle(id) {
  _kbCurrentId = id;
  const r   = await fetch('/api/kb/article/' + id);
  const art = await r.json();
  kbOpenModal(art);
}

function kbOpenModal(art) {
  const modal   = document.getElementById('kb-modal');
  const delBtn  = document.getElementById('kb-m-delete');
  document.getElementById('kb-modal-title').textContent = art ? 'Edit Article' : 'New Article';
  document.getElementById('kb-m-title').value    = art ? (art.title||'')    : '';
  document.getElementById('kb-m-body').value     = art ? (art.body||'')     : '';
  document.getElementById('kb-m-tags').value     = art ? (art.tags||'')     : '';
  document.getElementById('kb-m-category').value = art ? (art.category||'general') : 'general';
  if (!art) _kbCurrentId = null;
  if (delBtn) delBtn.style.display = art ? 'inline-block' : 'none';
  modal.style.display = 'flex';
}

async function kbSaveModal() {
  const payload = {
    title:    document.getElementById('kb-m-title').value.trim(),
    body:     document.getElementById('kb-m-body').value.trim(),
    tags:     document.getElementById('kb-m-tags').value.trim(),
    category: document.getElementById('kb-m-category').value,
    status:   'published',
  };
  if (!payload.title || !payload.body) { alert('Title and body are required.'); return; }
  const saveBtn = document.getElementById('kb-m-save');
  saveBtn.textContent = 'Saving...'; saveBtn.disabled = true;
  if (_kbCurrentId) {
    await fetch('/api/kb/article/' + _kbCurrentId, {method:'PUT', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  } else {
    await fetch('/api/kb/article', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  }
  saveBtn.textContent = 'Save'; saveBtn.disabled = false;
  document.getElementById('kb-modal').style.display = 'none';
  _kbCurrentId = null;
  await refreshKbList();
  const r = await fetch('/api/kb/status'); const st = await r.json();
  const countEl = document.querySelector('#kb-grid span[style*="667788"]');
  if (countEl) countEl.textContent = (st.published||0) + ' articles';
}

async function kbDeleteArticle() {
  if (!_kbCurrentId) return;
  if (!confirm('Delete this article? This cannot be undone.')) return;
  await fetch('/api/kb/article/' + _kbCurrentId, {method:'DELETE'});
  document.getElementById('kb-modal').style.display = 'none';
  _kbCurrentId = null;
  await refreshKbList();
  loadKbTab();
}

// Hook into switchTab to load KB when selected
const _origSwitchTab = typeof switchTab === 'function' ? switchTab : null;
</script>
</body>
</html>
"""

# ── Knowledge Base API ────────────────────────────────────────────────────────

@app.route("/api/kb/status")
def api_kb_status():
    if not _KB_AVAILABLE:
        return jsonify({"available": False, "error": _kb_err_msg})
    ollama = _kb.ollama_status()
    arts = _kb.list_articles(status=None, limit=1000)
    published = sum(1 for a in arts if a["status"] == "published")
    drafts    = sum(1 for a in arts if a["status"] == "draft")
    return jsonify({"available": True, "ollama": ollama,
                    "total": len(arts), "published": published, "drafts": drafts})

@app.route("/api/kb/articles")
def api_kb_articles():
    if not _KB_AVAILABLE:
        return jsonify([])
    status   = request.args.get("status")       # published | draft | None=all
    category = request.args.get("category")
    limit    = int(request.args.get("limit", 200))
    return jsonify(_kb.list_articles(status=status, category=category, limit=limit))

@app.route("/api/kb/article/<int:article_id>")
def api_kb_article(article_id):
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    art = _kb.get_article(article_id=article_id)
    if not art:
        return jsonify({"error": "not found"}), 404
    art.pop("embedding", None)
    return jsonify(art)

@app.route("/api/kb/article", methods=["POST"])
def api_kb_add():
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    data = request.json or {}
    aid = _kb.add_article(
        title=data.get("title", "Untitled"),
        body=data.get("body", ""),
        tags=data.get("tags", ""),
        category=data.get("category", "general"),
        status=data.get("status", "draft"),
    )
    return jsonify({"id": aid})

@app.route("/api/kb/article/<int:article_id>", methods=["PUT"])
def api_kb_update(article_id):
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    data = request.json or {}
    _kb.update_article(article_id=article_id, **data)
    return jsonify({"ok": True})

@app.route("/api/kb/article/<int:article_id>/publish", methods=["POST"])
def api_kb_publish(article_id):
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    _kb.publish_article(article_id=article_id)
    return jsonify({"ok": True})

@app.route("/api/kb/article/<int:article_id>", methods=["DELETE"])
def api_kb_delete(article_id):
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    _kb.delete_article(article_id=article_id)
    return jsonify({"ok": True})

@app.route("/api/kb/search")
def api_kb_search():
    if not _KB_AVAILABLE:
        return jsonify({"results": [], "error": "KB unavailable"})
    q      = request.args.get("q", "")
    top_k  = int(request.args.get("top_k", 5))
    status = request.args.get("status", "published")
    if not q:
        return jsonify({"results": []})
    results = _kb.search(query=q, top_k=top_k, status=status)
    for r in results:
        r.pop("embedding", None)
    return jsonify({"results": results})

@app.route("/api/kb/ask", methods=["POST"])
def api_kb_ask():
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    data     = request.json or {}
    question = data.get("question", "")
    model    = data.get("model")
    if not question:
        return jsonify({"error": "question required"}), 400
    result = _kb.ask(question=question, model=model)
    return jsonify(result)

@app.route("/api/kb/ingest", methods=["POST"])
def api_kb_ingest():
    """Paste-to-KB: ingest raw text submitted from dashboard or chat."""
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    data     = request.json or {}
    title    = data.get("title", "Pasted Document")
    text     = data.get("text", "")
    tags     = data.get("tags", "")
    category = data.get("category", "documentation")
    status   = data.get("status", "published")
    if not text.strip():
        return jsonify({"error": "text required"}), 400
    ids = _kb_seed.ingest_text(title=title, text=text, tags=tags,
                               category=category, status=status)
    return jsonify({"ids": ids, "count": len(ids)})

@app.route("/api/kb/seed", methods=["POST"])
def api_kb_seed():
    """Seed KB from AGENTS.md — idempotent."""
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    _kb_seed.seed_from_agents_md()
    arts = _kb.list_articles(status=None, limit=1000)
    return jsonify({"ok": True, "total": len(arts)})

@app.route("/api/kb/reembed", methods=["POST"])
def api_kb_reembed():
    """Rebuild all embeddings (background thread)."""
    if not _KB_AVAILABLE:
        return jsonify({"error": "KB unavailable"}), 503
    threading.Thread(target=_kb.reembed_all, daemon=True).start()
    return jsonify({"ok": True, "message": "Re-embedding started in background"})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)
