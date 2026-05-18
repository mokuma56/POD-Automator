"""POD Dashboard — upload events CSV, start pipelines, monitor live progress."""

import sqlite3, json, threading, csv, io, os, time, sys, subprocess
from pathlib import Path
from flask import Flask, render_template_string, jsonify, request

sys.path.insert(0, str(Path.home() / "sw_projects" / "pod_automator"))
import onboard_router

DATA_DIR = Path.home() / "sw_projects" / "pod_automator"
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
                return {"status": "connected", "detail": "Docker VPN up"}
            else:
                return {"status": "disconnected", "detail": f"Docker: {status[:80]}"}
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return {"status": "disconnected", "detail": "No Docker VPN container"}


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
            scc_org TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migration: add scc_org if upgrading from older schema
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN scc_org TEXT DEFAULT ''")
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
        })

    # Add connectivity test — show per-switch labels
    ct = results.get("connectivity_test", {})
    conn_checks = []
    if ct.get("status") == "completed" and ct.get("parts"):
        for p in ct["parts"]:
            sw_name = p.split("(")[0].replace("PASS: ", "").replace("FAIL: ", "").strip() if "(" in p else ""
            label = f"{sw_name} -> Ping Catalyst Center" if sw_name else "Ping Catalyst Center"
            if p.startswith("PASS"):
                conn_checks.append({"label": label, "status": "pass", "result": "Success"})
            elif p.startswith("FAIL"):
                conn_checks.append({"label": label, "status": "fail", "result": "Failed"})
    elif ct.get("status") == "running":
        conn_checks.append({"label": "Ping Catalyst Center", "status": "na", "result": "testing..."})
    elif ct.get("status") == "failed":
        conn_checks.append({"label": "Ping Catalyst Center", "status": "fail", "result": "Failed"})
    else:
        conn_checks.append({"label": "Ping Catalyst Center", "status": "na", "result": "pending"})

    ct_passed = sum(1 for c in conn_checks if c["status"] == "pass")
    ct_failed = sum(1 for c in conn_checks if c["status"] == "fail")
    switch_data.append({
        "name": "Catalyst Center",
        "model": "198.18.5.100",
        "host": "connectivity",
        "checks": conn_checks,
        "passed": ct_passed,
        "failed": ct_failed,
        "total": len(conn_checks),
    })

    return jsonify(switch_data)


SWITCH_RECHECK_RUNNERS = {}


@app.route("/api/switches/recheck/<pod_id>", methods=["POST"])
def api_switches_recheck(pod_id):
    """Re-run switch checks inside the POD's VPN namespace."""
    import subprocess, threading

    conn = _db()
    row = conn.execute("SELECT * FROM pods WHERE pod_id = ?", (pod_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"status": "error", "message": "POD not found"}), 404
    router_ip = row["router_ip"]
    conn.close()

    dp_id = pod_id.lower()
    # Verify VPN container is running
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": "VPN container not running for " + pod_id}), 400

    def _recheck():
        try:
            switches = ["verify_border_spine", "verify_leaf1", "verify_leaf2", "connectivity_test"]
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
    import subprocess, threading

    conn = _db()
    row = conn.execute("SELECT router_ip FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"status": "error", "message": "POD not found"}), 404

    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": "VPN container not running for " + pod_id}), 400

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
        status = "completed" if ok_val else "failed"
        conn2 = _db()
        conn2.execute(
            "INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, completed_at, result) "
            "VALUES (?, 'cdfmc_check', ?, datetime('now'), datetime('now'), ?)",
            (pod_id, status, str(result_val)[:500])
        )
        # Parse and persist scc_org
        import re as _re
        m = _re.search(r"scc_org=([^\s|]+)", str(result_val))
        if m:
            conn2.execute("UPDATE pods SET scc_org=?, updated_at=datetime('now') WHERE pod_id=?",
                          (m.group(1), pod_id))
        conn2.commit()
        conn2.close()

    threading.Thread(target=_recheck, daemon=True).start()
    return jsonify({"status": "ok", "message": "cdFMC re-check started for " + pod_id})


@app.route("/api/cdfmc/redeploy/<pod_id>", methods=["POST"])
def api_cdfmc_redeploy(pod_id):
    """SSH to automation PC and run cli.py reset then cli.py deploy. Streams output to pipeline_logs."""
    import subprocess, threading

    conn = _db()
    row = conn.execute("SELECT * FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"status": "error", "message": "POD not found"}), 404

    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": "VPN container not running for " + pod_id}), 400

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
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=8
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container not running for {pod_id}"}), 400

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


def api_ssh_terminal(pod_id, ip):
    """Opens macOS Terminal.app with SSH to switch via docker exec through VPN container."""
    cmd = f"docker exec -it vpn-{pod_id} sshpass -p 'C1sco12345' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null netadmin@{ip}"
    script = f'tell app "Terminal" to do script "{cmd}"'
    subprocess.Popen(["osascript", "-e", script])
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

# ---- Docker per-POD launch ---- #
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
    pods = read_db(status_filter=("pending", "available", "ready", "running", "in_progress", ""))
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
  td { padding: 8px; border-bottom: 1px solid #1a2d4a; }
  tr:hover td { background: #1a2d4a; }
  .badge { display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 11px; font-weight: 600; }
  .badge.pass { background: #003d2a; color: #00e68a; }
  .badge.fail { background: #3d0000; color: #ff4757; }
  .badge.pending { background: #3d0000; color: #ff4444; }
  .badge.running { background: #3d2200; color: #ffa500; }
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

  .switch-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 10px; }
  .switch-card { background: #0a1628; border-radius: 8px; padding: 12px; border: 1px solid #1a2d4a; }
  .switch-card.fail { border-color: #3d0000; }
  .switch-card.pass { border-color: #003d2a; }
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

  <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
    <button class="btn-start-all" id="btn-vpn-all" onclick="connectAllVpn()">&#9654; Connect All VPN</button>
    <button class="btn-start-all" id="btn-run-all" onclick="runAllPods()" style="background:#7c3aed;color:#fff;">&#9654; Run All POD Automation</button>
    <button class="btn-start-all" id="btn-docker-down" onclick="dockerDown()" style="background:#ff4757;color:#fff;">&#9632; Teardown All</button>
    <span id="docker-status" style="font-size:12px;color:#667788;"></span>
  </div>

  <table>
    <thead>
      <tr>
        <th>POD</th>
        <th>Session</th>
        <th>Status</th>
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
      <button class="tab-btn" onclick="switchTab(this, 'cdfmc')">cdFMC</button>
      <button class="tab-btn" onclick="switchTab(this, 'ad')">AD Verify</button>
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
      <div id="cdfmc-grid" style="padding:16px;">
        <div style="color:#667788;font-size:13px;">Select a POD to load cdFMC status</div>
      </div>
    </div>
    <div class="tab-content" id="tab-ad">
      <div id="ad-grid" style="padding:16px;">
        <div style="color:#667788;font-size:13px;">Select a POD to load AD verification status</div>
      </div>
    </div>
  </div>

<script>
const PIPELINE_ORDER = [
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

function isFullyReady(p) {
  // All pipeline steps + sdwan = yes + switch checks passed
  const phases = PIPELINE_ORDER;
  for (let i = 0; i < phases.length; i++) {
    if (p[phases[i]] !== 'completed') return false;
  }
  return p.sdwan_online === 'yes';
}

function renderStats(pods) {
  const total = pods.length;
  const fullyReady = pods.filter(p => isFullyReady(p)).length;
  const sdwanOk = pods.filter(p => p.sdwan_online === 'yes').length;
  const running = pods.filter(p => p.status === 'running' || p.status === 'in_progress').length;
  const pending = pods.filter(p => p.status === 'pending').length;

  document.getElementById('summary').innerHTML =
    `<div class="stat-card green"><div class="num">${fullyReady}</div><div class="label">Fully Ready</div></div>` +
    `<div class="stat-card" style="border-left:3px solid #00e68a"><div class="num">${sdwanOk}</div><div class="label">SD-WAN Online</div></div>` +
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
    const barColor = pipe.pct === 100 ? '#00e68a' : pipe.text.includes('fail') ? '#ff4757' : '#02c8ff';
    const miniBar = pipe.pct > 0 ? `<div class="progress-mini"><div class="progress-mini-fill" style="width:${pipe.pct}%;background:${barColor}"></div></div>` : '';
    const pipeLabel = `${miniBar}<span class="badge ${pipe.pct === 100 ? 'pass' : pipe.text.includes('fail') ? 'fail' : pipe.text.includes('running') ? 'running' : 'pending'}">${pipe.text}</span>`;
    const vpn = p.vpn_status || 'disconnected';
    const vpnColor = vpn === 'connected' ? '#00e68a' : vpn === 'connecting' ? '#ffa502' : '#ff4757';
    const vpnLabel = vpn === 'connected' ? 'Connected' : vpn === 'connecting' ? 'Connecting' : 'Offline';
    const readyAll = isFullyReady(p);
    const readyBadge = readyAll ? '<span class="badge pass">READY</span>'
      : p.sdwan_online === 'yes' ? '<span class="badge running">Partial</span>'
      : '<span class="badge pending">Pending</span>';
    return `<tr>
      <td class="pod-id" onclick="showPipeline('${p.pod_id}')">${p.pod_id}</td>
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
        <button class="btn-reconnect" onclick="reconnectVpn('${p.pod_id}')">Reconnect VPN</button>
        <button class="btn-reconnect" onclick="disconnectVpn('${p.pod_id}')" style="color:#ff4757;border-color:#ff4757;">Disconnect VPN</button>
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
   loadCdfmc(podId);
   loadAd(podId);

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

function roleClass(name) {
  if (name.includes('Border')) return 'border';
  if (name.includes('Leaf')) return 'leaf';
  if (name.includes('Catalyst')) return 'cc';
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
        ${allPass ? '✓ All passed' : hasFail ? `✗ ${totalFail} fail` : '— pending'}
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

    const roleLabel = sw.name === 'Catalyst Center' ? 'CC' : sw.name.includes('Border') ? 'Spine' : 'Leaf';


    return `<div class="switch-card ${allDevicePass ? 'pass' : hasAnyFail ? 'fail' : ''}">
      <div class="switch-card-title">
        <span class="role-tag ${roleClass(sw.name)}">${roleLabel}</span>
        <span class="device-name" onclick="${sw.ip ? `openTerminal('${escHtml(podId)}','${sw.ip}')` : ''}" title="${sw.ip ? 'Click to open SSH terminal' : ''}">${escHtml(sw.name)}</span>
        <span class="device-model">${escHtml(sw.model || '')}</span>
      </div>
      <div class="switch-bar"><div class="switch-bar-fill" style="width:${devicePct}%;background:${barColor}"></div></div>
      ${checksHtml}
    </div>`;
  }).join('');
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
  const grid = document.getElementById('switch-grid');
  grid.innerHTML = '<div class="switch-grid-empty" style="color:#ffa502;">⟳ Running switch re-check...</div>';
  const r = await fetch('/api/switches/recheck/' + podId, { method: 'POST' });
  const data = await r.json();
  setTimeout(() => loadSwitches(podId), 5000);
}

async function loadCdfmc(podId) {
  const grid = document.getElementById('cdfmc-grid');
  if (!grid) return;
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
      <button onclick="recheckCdfmc('${podId}')" style="margin-left:auto;padding:5px 14px;background:#1a2a3a;border:1px solid #02c8ff;color:#02c8ff;border-radius:6px;cursor:pointer;font-size:12px;">⟳ Re-check</button>
      <button onclick="redeployCdfmc('${podId}')" style="padding:5px 14px;background:#1a2a3a;border:1px solid #ff4757;color:#ff4757;border-radius:6px;cursor:pointer;font-size:12px;">⚠ Reset &amp; Redeploy</button>
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
  grid.innerHTML = '<div style="padding:20px;color:#ffa502;font-size:13px;">⟳ Running cdFMC re-check...</div>';
  await fetch('/api/cdfmc/recheck/' + podId, { method: 'POST' });
  setTimeout(() => loadCdfmc(podId), 5000);
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
      <button onclick="recheckAd('${podId}')" style="margin-left:auto;padding:5px 14px;background:#1a2a3a;border:1px solid #02c8ff;color:#02c8ff;border-radius:6px;cursor:pointer;font-size:12px;">⟳ Re-check</button>
      <button onclick="rerunAd('${podId}')" style="padding:5px 14px;background:#1a2a3a;border:1px solid #ff4757;color:#ff4757;border-radius:6px;cursor:pointer;font-size:12px;">⚠ Re-run AD Automation</button>
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
  grid.innerHTML = '<div style="padding:20px;color:#ff4757;font-size:13px;">⚠ Re-run PS1 started — check Live Logs tab for progress...</div>';
  const r = await fetch('/api/ad/rerun/' + podId, { method: 'POST' });
  const d = await r.json();
  if (d.status !== 'ok') {
    grid.innerHTML = '<div style="padding:20px;color:#ff4757;font-size:13px;">Error: ' + (d.message || 'unknown') + '</div>';
    return;
  }
  setTimeout(() => loadAd(podId), 15000);
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
</script>
</body>
</html>
"""

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=False, use_reloader=False)
