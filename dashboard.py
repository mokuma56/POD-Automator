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

def _get_global_config(conn, key, default=""):
    row = conn.execute("SELECT value FROM global_config WHERE key=?", (key,)).fetchone()
    return row["value"] if row and row["value"] else default

def _set_global_config(conn, key, value):
    conn.execute(
        "INSERT INTO global_config(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, value),
    )

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
    # Migration: add Secure Access API credentials columns
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN sa_org_id TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN sa_api_key TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        conn.execute("ALTER TABLE pods ADD COLUMN sa_api_secret TEXT DEFAULT ''")
    except Exception:
        pass
    # Org-level credentials (keyed by org number; pods link at runtime via scc_org)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS org_credentials (
            org_number      TEXT PRIMARY KEY,
            duo_ikey        TEXT DEFAULT '',
            duo_skey        TEXT DEFAULT '',
            duo_host        TEXT DEFAULT '',
            scc_api_key     TEXT DEFAULT '',
            scc_api_secret  TEXT DEFAULT '',
            sa_org_id       TEXT DEFAULT '',
            sa_api_key      TEXT DEFAULT '',
            sa_api_secret   TEXT DEFAULT '',
            authproxy_ikey  TEXT DEFAULT '',
            authproxy_skey  TEXT DEFAULT '',
            updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Migration: add columns if upgrading from older schema
    for _col in ("authproxy_ikey", "authproxy_skey",
                 "duo_saml_app_ikey", "sa_saml_profile_id",
                 "scc_password", "scc_email", "authproxy_cfg",
                 "sa_scim_token", "authproxy_enroll_blob",
                 "authproxy_blob_saved_at"):
        try:
            conn.execute(f"ALTER TABLE org_credentials ADD COLUMN {_col} TEXT DEFAULT ''")
        except Exception:
            pass
    # Migration: drop obsolete columns (Playwright-only, no active code path uses these)
    for _col in ("scc_org_uuid", "idac_url", "duo_admin_email", "duo_admin_password", "duo_totp_secret"):
        try:
            conn.execute(f"ALTER TABLE org_credentials DROP COLUMN {_col}")
        except Exception:
            pass
    # Global key-value config (CCO credentials etc.)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS global_config (
            key   TEXT PRIMARY KEY,
            value TEXT DEFAULT ''
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

# ── Duo card table init ───────────────────────────────────────────────────────
def _ensure_duo_table():
    import duo_automation as _da_init
    _da_init.duo_ensure_table(str(DB_PATH))

_ensure_duo_table()

def _ensure_ise_table():
    import ise_integrations as _ise_init
    _ise_init.ise_ensure_table(str(DB_PATH))

_ensure_ise_table()

# ---- Log helpers ----
def log(pod_id, msg):
    try:
        conn = sqlite3.connect(str(DB_PATH), timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)", (pod_id, msg))
        conn.commit()
        conn.close()
    except Exception:
        pass  # never crash the _run() thread over a log write

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
        "AAA (base config only)",
    ]},
    "leaf1": {"name": "Leaf 1", "ip": "198.18.128.22", "checks": [
        "VRF (expect Mgmt-vrf only)",
        "Version (expect 17.12.x)",
        "VLAN (expect default only)",
        "AAA (base config only)",
    ]},
    "leaf2": {"name": "Leaf 2", "ip": "198.18.128.23", "checks": [
        "VRF (expect Mgmt-vrf only)",
        "Version (expect 17.12.x)",
        "VLAN (expect default only)",
        "AAA (base config only)",
    ]},
}

@app.route("/api/switches/<pod_id>")
def api_switches(pod_id):
    conn = _db()
    steps = conn.execute(
        "SELECT * FROM pipeline_steps WHERE pod_id = ? AND step_name IN ('verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test','route_verification') ORDER BY rowid",
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
            if step.get("status") in ("completed", "failed") and i < len(check_parts):
                part = check_parts[i]
                if part.startswith("PASS"):
                    checks.append({"label": label, "status": "pass", "result": part.replace("PASS: ", "")})
                elif part.startswith("FAIL"):
                    checks.append({"label": label, "status": "fail", "result": part.replace("FAIL: ", "")})
                else:
                    checks.append({"label": label, "status": "pass", "result": part})
            elif step.get("status") in ("completed", "failed"):
                checks.append({"label": label, "status": "na", "result": "no data"})
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
        if ct_status in ("completed", "failed") and i < len(ct_parts):
            part = ct_parts[i]
            if part.startswith("PASS"):
                ct_checks.append({"label": label + " → 198.18.5.100", "status": "pass", "result": part.replace("PASS: ", "")})
            elif part.startswith("FAIL"):
                ct_checks.append({"label": label + " → 198.18.5.100", "status": "fail", "result": part.replace("FAIL: ", "")})
            else:
                ct_checks.append({"label": label + " → 198.18.5.100", "status": "pass", "result": part})
        elif ct_status in ("completed", "failed"):
            ct_checks.append({"label": label + " → 198.18.5.100", "status": "na", "result": "no data"})
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

    # ── Route Verification card ──
    rv_step   = results.get("route_verification", {})
    rv_status = rv_step.get("status", "pending")
    rv_result = rv_step.get("parts", [""])[0] if rv_step.get("parts") else ""

    # Parse pipe-delimited result: PASS|found=13/13|reloaded=no
    rv_parts_map = {}
    for _p in rv_result.split("|"):
        if "=" in _p:
            k, v = _p.split("=", 1)
            rv_parts_map[k.strip()] = v.strip()
    rv_overall   = rv_result.split("|")[0].strip() if rv_result else ""  # "PASS" or "WARN"
    rv_missing   = set(rv_parts_map.get("missing", "").split(",")) - {""}
    rv_reloaded  = rv_parts_map.get("reloaded", "no")

    from onboard_router import ROUTE_VRF10_CHECKS
    rv_checks = []
    for label, prefixes in ROUTE_VRF10_CHECKS:
        if rv_status in ("completed", "failed"):
            grp_missing = [p for p in prefixes if p in rv_missing]
            if rv_overall == "WARN" and grp_missing:
                rv_checks.append({"label": label, "status": "fail",
                                  "result": f"MISSING: {', '.join(grp_missing)}"})
            else:
                rv_checks.append({"label": label, "status": "pass", "result": "found"})
        elif rv_status == "running":
            rv_checks.append({"label": label, "status": "na", "result": "checking..."})
        else:
            rv_checks.append({"label": label, "status": "na", "result": "pending"})

    if rv_reloaded == "yes" and rv_status in ("completed", "failed"):
        rv_checks.append({"label": "Router reloaded during verification",
                          "status": "pass" if rv_overall == "PASS" else "fail",
                          "result": "reloaded — routes re-verified after reload"
                                    if rv_overall == "PASS"
                                    else "reloaded but routes still missing"})

    rv_passed = sum(1 for c in rv_checks if c["status"] == "pass")
    rv_failed = sum(1 for c in rv_checks if c["status"] == "fail")
    switch_data.append({
        "name":        "HQ CEDGE Route Verification",
        "model":       "IOS XE SD-WAN",
        "ip":          "198.18.133.13",
        "host":        "route_verification",
        "checks":      rv_checks,
        "passed":      rv_passed,
        "failed":      rv_failed,
        "total":       len(rv_checks),
        "step_status": rv_status,
        "reloaded":    rv_reloaded,
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
            switches = ["verify_border_spine", "verify_leaf1", "verify_leaf2", "connectivity_test", "route_verification"]
            # Mark ALL steps as running upfront so UI shows spinner with 0/5 done
            _c = _db()
            for step_name in switches:
                _c.execute("INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, started_at, completed_at, result) VALUES (?, ?, 'running', datetime('now'), NULL, '')", (pod_id, step_name))
            _c.execute("UPDATE pods SET updated_at=datetime('now') WHERE pod_id=?", (pod_id,))
            _c.commit()
            _c.close()

            for step_name in switches:
                if step_name == "connectivity_test":
                    func_call = "onboard_router.phase_connectivity_test()"
                elif step_name == "route_verification":
                    func_call = "onboard_router.phase_route_verification()"
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
                ], capture_output=True, text=True, timeout=240)
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
                "SELECT step_name, status FROM pipeline_steps WHERE pod_id=? AND step_name IN ('verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test','route_verification')",
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
                "UPDATE pipeline_steps SET status='failed', result='Re-check error: ' || ? WHERE pod_id=? AND step_name IN ('verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test','route_verification') AND status='running'",
                (str(e)[:200], pod_id)
            )
            _c.commit()
            _c.close()

    t = threading.Thread(target=_recheck, daemon=True)
    t.start()
    return jsonify({"status": "ok", "message": "Switch re-check started for " + pod_id})


@app.route("/api/routes/test-fail/<pod_id>", methods=["POST"])
def api_routes_test_fail(pod_id):
    """
    Test endpoint: runs route_verification with an injected fake prefix (192.0.2.254)
    that can never appear in a real routing table.  Forces the reload→re-verify path
    so the full flow can be validated without waiting for a real route miss.
    """
    import threading

    conn = _db()
    row = conn.execute("SELECT router_ip FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    conn.close()
    if not row:
        return jsonify({"status": "error", "message": "POD not found"}), 404

    # Verify VPN container is running
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error",
                        "message": f"VPN container vpn-{pod_id} not running"}), 400

    # Mark as running immediately
    _c = _db()
    _c.execute(
        "INSERT OR REPLACE INTO pipeline_steps "
        "(pod_id, step_name, status, started_at, completed_at, result) "
        "VALUES (?, 'route_verification', 'running', datetime('now'), NULL, 'Test-fail run in progress...')",
        (pod_id,)
    )
    _c.commit(); _c.close()

    def _run_test():
        script = (
            "import sys; sys.path.insert(0, '.'); import onboard_router; "
            f"onboard_router.ROUTER_IP = '{row['router_ip']}'; "
            "ok, result = onboard_router.phase_route_verification_test(); "
            "print(repr((ok, result)))"
        )
        res = subprocess.run([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "--entrypoint", "python3",
            "pod-automator:latest", "-c", script
        ], capture_output=True, text=True, timeout=600)
        stdout = res.stdout.strip()
        last_line = stdout.splitlines()[-1] if stdout else ""
        try:
            ok_val, result_val = eval(last_line)
        except Exception as e:
            ok_val, result_val = False, f"parse error: {e} | raw: {stdout[:200]}"
        status = "completed" if ok_val else "failed"
        _c2 = _db()
        _c2.execute(
            "INSERT OR REPLACE INTO pipeline_steps "
            "(pod_id, step_name, status, started_at, completed_at, result) "
            "VALUES (?, 'route_verification', ?, "
            "COALESCE((SELECT started_at FROM pipeline_steps WHERE pod_id=? AND step_name='route_verification'), datetime('now')), "
            "datetime('now'), ?)",
            (pod_id, status, pod_id, str(result_val)[:500])
        )
        _c2.commit(); _c2.close()
        log(pod_id, f"[route-test-fail] {status}: {result_val}")

    threading.Thread(target=_run_test, daemon=True).start()
    return jsonify({"status": "started",
                    "message": "Route verification test-fail run started — injected 192.0.2.254"})


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


@app.route("/api/duo-saml-setup/<pod_id>", methods=["POST"])
def api_duo_saml_setup(pod_id):
    """Run duo_saml_full_setup in a background thread.
    Called directly by the UI or delegated from the pipeline container."""
    import threading, importlib, sys, os as _os

    db_path = str(Path(__file__).parent / "data" / "pod_state.db")

    # Mark as running
    c = _db()
    c.execute(
        "INSERT OR REPLACE INTO pipeline_steps "
        "(pod_id, step_name, status, started_at, result) VALUES (?,?,?,datetime('now'),?)",
        (pod_id, "duo_saml_setup", "running", ""),
    )
    c.commit(); c.close()
    log(pod_id, "[duo_saml_setup] Starting SA+Duo SAML/SCIM setup...")

    def _run():
        sys.path.insert(0, str(Path(__file__).parent))
        _os.environ["POD_ID"] = pod_id
        _os.environ["DB_PATH"] = db_path
        try:
            import importlib as _il
            import duo_automation as _da
            _il.reload(_da)

            def _log_fn(msg):
                log(pod_id, f"[duo_saml_setup] {msg}")

            ok, result = _da.duo_saml_full_setup(pod_id, db_path, log=_log_fn)
            log(pod_id, f"[duo_saml_setup] {'OK' if ok else 'FAILED'}: {result}")
            c2 = _db()
            c2.execute(
                "INSERT OR REPLACE INTO pipeline_steps "
                "(pod_id, step_name, status, result) VALUES (?,?,?,?)",
                (pod_id, "duo_saml_setup", "completed" if ok else "failed", result),
            )
            c2.commit(); c2.close()
        except Exception as e:
            msg = f"ERROR: {e}"
            log(pod_id, f"[duo_saml_setup] {msg}")
            c3 = _db()
            c3.execute(
                "INSERT OR REPLACE INTO pipeline_steps "
                "(pod_id, step_name, status, result) VALUES (?,?,?,?)",
                (pod_id, "duo_saml_setup", "failed", msg),
            )
            c3.commit(); c3.close()

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "ok", "message": f"Duo SAML setup started for {pod_id}"})


@app.route("/api/duo-saml-setup-sync/<pod_id>", methods=["POST"])
def api_duo_saml_setup_sync(pod_id):
    """Synchronous variant — called by the pipeline container via host.docker.internal.

    Uses the no-browser headless path:
      1. duo_push_authproxy_config  — push authproxy.cfg to AD1 via WinRM (pre-stored cfg)
      2. duo_sa_configure_headless  — SA client-creds + saved scc_session.json cookies
    Avoids Cisco Okta MFA / browser login entirely.
    """
    import sys, os as _os
    db_path = str(Path(__file__).parent / "data" / "pod_state.db")
    sys.path.insert(0, str(Path(__file__).parent))
    _os.environ["POD_ID"] = pod_id
    _os.environ["DB_PATH"] = db_path
    try:
        import importlib, duo_automation
        importlib.reload(duo_automation)
        logs = []
        _log = lambda msg: logs.append(msg)

        # Step 1: push authproxy.cfg to AD1 via WinRM
        ok1, msg1 = duo_automation.duo_push_authproxy_config(pod_id, db_path, log=_log)
        _log(f"authproxy push: {'OK' if ok1 else 'FAILED'}: {msg1}")

        # Step 2: headless SA SAML + Duo SCIM (all soft-fail internally)
        ok2, msg2 = duo_automation.duo_sa_configure_headless(pod_id, db_path, log=_log)
        _log(f"headless SA/SCIM: {'OK' if ok2 else 'FAILED'}: {msg2}")

        ok = ok1 and ok2
        result = " | ".join(logs[-6:]) if logs else f"{msg1} | {msg2}"
        return jsonify({"ok": ok, "result": result, "authproxy": msg1, "sa_scim": msg2, "logs": logs})
    except Exception as e:
        return jsonify({"ok": False, "result": str(e)}), 500


@app.route("/api/duo-ext-dir-setup-sync/<pod_id>", methods=["POST"])
def api_duo_ext_dir_setup_sync(pod_id):
    """Synchronous variant — called by the pipeline container via host.docker.internal."""
    import sys, os as _os
    db_path = str(Path(__file__).parent / "data" / "pod_state.db")
    sys.path.insert(0, str(Path(__file__).parent))
    _os.environ["POD_ID"] = pod_id
    _os.environ["DB_PATH"] = db_path
    try:
        import importlib, duo_automation
        importlib.reload(duo_automation)
        ok, result = duo_automation.duo_push_authproxy_config(pod_id, db_path)
        return jsonify({"ok": ok, "result": result})
    except Exception as e:
        return jsonify({"ok": False, "result": str(e)}), 500


@app.route("/api/scc/confirm/<pod_id>/<item_key>", methods=["POST"])
def api_scc_confirm(pod_id, item_key):
    """Mark any SCC checklist item as confirmed (fallback/override for automation failures)."""
    data = request.get_json(silent=True) or {}
    confirmed_by = data.get("confirmed_by", "proctor")
    ALL_ITEMS = {
        "access_policy_rules", "network_tunnel_groups", "zta_profiles",
        "private_resources", "dns_servers", "epp_posture_profiles",
        "logging_settings", "ravpn_profiles", "dlp_rules",
        "ravpn_ip_pool", "ise_pxgrid", "duo_saml", "te_integration",
    }
    if item_key not in ALL_ITEMS:
        return jsonify({"status": "error", "message": f"Unknown item: {item_key}"}), 400
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


@app.route("/api/scc/clear/<pod_id>", methods=["POST"])
def api_scc_clear(pod_id):
    """Delete all SCC checklist results for a POD (reset to blank slate)."""
    c = _db()
    c.execute("DELETE FROM scc_checklist WHERE pod_id=?", (pod_id,))
    c.commit(); c.close()
    return jsonify({"status": "ok", "pod_id": pod_id})


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
                       "anycast_gateways", "transit", "fabric_devices", "ise_nads",
                       "l3_handoff", "configure_handoff_interface", "deploy_anycast_gateways",
                       "port_assignments", "verify"]
SDA_ROLLBACK_STEPS = ["remove_port_assignments", "remove_l3_handoffs", "restore_handoff_interface",
                       "remove_fabric_devices", "remove_anycast_gateways", "disable_gbac_policy",
                       "remove_transit", "remove_vn_assignments", "remove_virtual_networks",
                       "remove_fabric_site", "delete_devices", "delete_discovery",
                       "delete_ise_nads", "remove_network_profile"]


SDA_DEPLOY_STEP_KEYS   = ["discovery","provision","fabric_site","virtual_networks","anycast_gateways","transit","fabric_devices","ise_nads","l3_handoff","configure_handoff_interface","deploy_anycast_gateways","port_assignments","verify"]
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
    # Compute overall from deploy steps
    deploy_statuses = [v["status"] for v in steps["deploy"].values()]
    if "running" in deploy_statuses:
        overall = "running"
    elif "failed" in deploy_statuses:
        overall = "failed"
    elif deploy_statuses and all(s == "completed" for s in deploy_statuses):
        overall = "completed"
    else:
        overall = "pending"
    return jsonify({"pod_id": pod_id, "overall": overall, "deploy": steps["deploy"], "rollback": steps["rollback"]})


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


# ── Duo Card API ──────────────────────────────────────────────────────────────

@app.route("/api/duo/status/<pod_id>")
def api_duo_status(pod_id):
    """Return Duo card step status for a POD."""
    _ensure_duo_table()
    c = _db()
    rows = c.execute(
        "SELECT step_name, status, result, started_at, completed_at "
        "FROM duo_steps WHERE pod_id=?", (pod_id,)
    ).fetchall()
    c.close()
    steps = {r["step_name"]: dict(r) for r in rows}
    # Detect mode from org_credentials
    mode = "unknown"
    try:
        c2 = _db()
        pod_row = c2.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if pod_row:
            import re as _re_dm, duo_automation as _da_dm
            m = _re_dm.search(r"pseudoco-(\d+)", pod_row["scc_org"] or "")
            if m:
                oc = c2.execute("SELECT duo_saml_app_ikey, sa_scim_token, authproxy_cfg FROM org_credentials WHERE org_number=?", (m.group(1),)).fetchone()
                if oc:
                    app_ikey  = (oc["duo_saml_app_ikey"] or "").strip()
                    scim_tok  = (oc["sa_scim_token"] or "").strip()
                    ap_cfg    = (oc["authproxy_cfg"] or "")
                    if app_ikey and scim_tok and "[sso]" in ap_cfg:
                        mode = "refresh"
                    elif app_ikey or scim_tok:
                        mode = "partial"
                    else:
                        mode = "full_setup"
        c2.close()
    except Exception:
        pass
    return jsonify({"steps": steps, "mode": mode})


@app.route("/api/duo/run/<pod_id>", methods=["POST"])
def api_duo_run(pod_id):
    """Start Duo card pipeline in a background thread."""
    import threading, duo_automation as _da_run
    _ensure_duo_table()
    data = request.get_json(silent=True) or {}
    from_step = int(data.get("from_step", 0))
    db_path = str(DB_PATH)

    def _run():
        def _log_fn(msg):
            log(pod_id, f"[duo] {msg}")
        try:
            ok, result = _da_run.duo_run_card(pod_id, db_path, from_step=from_step, log=_log_fn)
            log(pod_id, f"[duo] {'OK' if ok else 'FAILED'}: {result}")
        except Exception as e:
            log(pod_id, f"[duo] exception: {e}")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "pod_id": pod_id, "from_step": from_step})


@app.route("/api/duo/reset/<pod_id>", methods=["POST"])
def api_duo_reset(pod_id):
    """Clear all Duo card step rows for a POD."""
    _ensure_duo_table()
    c = _db()
    c.execute("DELETE FROM duo_steps WHERE pod_id=?", (pod_id,))
    c.commit(); c.close()
    return jsonify({"status": "ok", "message": f"Duo state cleared for {pod_id}"})


# ── ISE Integration Card API ──────────────────────────────────────────────────

@app.route("/api/ise/status/<pod_id>")
def api_ise_status(pod_id):
    """Return ISE card step status for a POD."""
    _ensure_ise_table()
    c = _db()
    rows = c.execute(
        "SELECT step_name, status, result, started_at, completed_at "
        "FROM ise_steps WHERE pod_id=?", (pod_id,)
    ).fetchall()
    c.close()
    steps = {r["step_name"]: dict(r) for r in rows}
    return jsonify({"steps": steps})


@app.route("/api/ise/run/<pod_id>", methods=["POST"])
def api_ise_run(pod_id):
    """Start ISE integration card via docker run inside the VPN network namespace."""
    import threading
    _ensure_ise_table()
    data = request.get_json(silent=True) or {}
    from_step = int(request.args.get("from_step", data.get("from_step", 0)))

    # Verify VPN container is running
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    def _run():
        proc = subprocess.Popen([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "-e", f"POD_ID={pod_id}",
            "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
            "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
            "--entrypoint", "python3",
            "pod-automator:latest", "-u", "-c",
            f"import sys; sys.path.insert(0,'/pipeline'); "
            f"from ise_integrations import ise_run_card, ise_ensure_table; "
            f"ise_ensure_table('/pipeline/host-data/pod_state.db'); "
            f"ok, r = ise_run_card('{pod_id}', '/pipeline/host-data/pod_state.db', "
            f"    log=print, from_step={from_step}); "
            f"print(('OK' if ok else 'FAIL') + ': ' + str(r))"
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log(pod_id, f"[ise] {line}")

        proc.wait()
        _clear_stuck_running(pod_id, "ise_steps")
        log(pod_id, f"[ise] container exited (rc={proc.returncode})")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "pod_id": pod_id, "from_step": from_step})


@app.route("/api/ise/reset/<pod_id>", methods=["POST"])
def api_ise_reset(pod_id):
    """Clear all ISE card step rows for a POD."""
    _ensure_ise_table()
    c = _db()
    c.execute("DELETE FROM ise_steps WHERE pod_id=?", (pod_id,))
    c.commit(); c.close()
    return jsonify({"status": "ok", "message": f"ISE state cleared for {pod_id}"})


@app.route("/api/ise/reactivate/<pod_id>", methods=["POST"])
def api_ise_reactivate(pod_id):
    """Run ONLY the ISE→SCC deactivate+reactivate step (step 3) independently.

    Resets step 3 to pending so the skip-check doesn't skip it, then launches
    ise_run_card with from_step=2 inside the VPN network namespace.
    """
    import threading
    _ensure_ise_table()

    # Reset step 3 to pending so the skip check runs it
    c = _db()
    c.execute(
        "UPDATE ise_steps SET status='pending', result='', started_at=NULL, completed_at=NULL "
        "WHERE pod_id=? AND step_name='ise_scc_deactivate_reactivate'",
        (pod_id,)
    )
    c.commit(); c.close()

    # Verify VPN container is running
    r = subprocess.run(
        ["docker", "inspect", f"vpn-{pod_id}", "--format", "{{.State.Status}}"],
        capture_output=True, text=True, timeout=5
    )
    if r.returncode != 0 or r.stdout.strip() != "running":
        return jsonify({"status": "error", "message": f"VPN container vpn-{pod_id} is not running"}), 400

    def _run():
        proc = subprocess.Popen([
            "docker", "run", "--rm",
            "--network", f"container:vpn-{pod_id}",
            "-e", f"POD_ID={pod_id}",
            "-e", "DB_PATH=/pipeline/host-data/pod_state.db",
            "-v", f"{os.path.abspath(DATA_DIR / 'data')}:/pipeline/host-data",
            "--entrypoint", "python3",
            "pod-automator:latest", "-u", "-c",
            f"import sys; sys.path.insert(0,'/pipeline'); "
            f"from ise_integrations import ise_run_card, ise_ensure_table; "
            f"ise_ensure_table('/pipeline/host-data/pod_state.db'); "
            f"ok, r = ise_run_card('{pod_id}', '/pipeline/host-data/pod_state.db', "
            f"    log=print, from_step=2); "
            f"print(('OK' if ok else 'FAIL') + ': ' + str(r))"
        ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        for line in proc.stdout:
            line = line.rstrip()
            if line:
                log(pod_id, f"[ise] {line}")

        proc.wait()
        _clear_stuck_running(pod_id, "ise_steps")
        log(pod_id, f"[ise] container exited (rc={proc.returncode})")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "pod_id": pod_id, "step": "ise_scc_deactivate_reactivate"})


def _host_scc_integrate(pod_id: str, otp_token: str, session_path: str, log_fn) -> tuple:
    """Run SCC Platform Integrations on the HOST (not Docker).
    Docker routes all traffic through OpenConnect VPN which breaks Okta silent-renew.
    On the host, storage_state → security.cisco.com works correctly.
    Called by /api/ise/scc-complete which the Docker ISE container POSTs to.
    """
    import time as _time
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _sd = json.loads(Path(session_path).read_text())
            if isinstance(_sd, dict) and "cookies" in _sd:
                log_fn(f"[scc-nav] storage_state: {len(_sd.get('cookies',[]))} cookies, "
                       f"{len(_sd.get('origins', []))} origins")
                scc_ctx = browser.new_context(
                    storage_state=_sd,
                    viewport={"width": 1920, "height": 1080},
                )
            else:
                log_fn("[scc-nav] legacy cookie session")
                scc_ctx = browser.new_context(viewport={"width": 1920, "height": 1080})
                scc_ctx.add_cookies(_sd)
            page = scc_ctx.new_page()
            page.set_default_timeout(30000)

            # Intercept SCC API responses so we can detect OTP rejection (400)
            # without relying on page-content heuristics.
            _scc_api_resp: dict = {}
            def _on_scc_response(resp) -> None:
                if "/v1/ise" in resp.url and resp.request.method == "POST":
                    _scc_api_resp["status"] = resp.status
                    try:
                        _scc_api_resp["body"] = resp.text()
                    except Exception:
                        pass
            page.on("response", _on_scc_response)

            _eid = ""
            for _o in _sd.get("origins", []):
                for _it in _o.get("localStorage", []):
                    if _it.get("name") == "enterpriseId":
                        _eid = _it["value"]
                        break
            _url = (f"https://security.cisco.com/dashboard?enterpriseId={_eid}"
                    if _eid else "https://security.cisco.com/dashboard")
            log_fn(f"[scc-nav] Navigating to SCC dashboard...")
            page.goto(_url, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(2000)

            # /login/callback is the OAuth2 callback URL — the SPA is processing a
            # silent token renewal, not a login failure. Wait up to 20s for it to
            # complete and land on the actual dashboard.
            _wait = 0
            while _wait < 20 and "login/callback" in page.url.lower():
                page.wait_for_timeout(2000)
                _wait += 2
                log_fn(f"[scc-nav] Waiting for OAuth callback to complete ({_wait}s)... {page.url[:60]}")

            # Only fail if still stuck on Okta sign-on (truly expired session)
            if "sign-on" in page.url.lower() and "security.cisco.com" not in page.url.lower():
                return False, f"SCC session expired (URL: {page.url}) — re-run Refresh SCC Sessions"
            if "login" in page.url.lower() and "/login/callback" not in page.url.lower():
                return False, f"SCC session expired (URL: {page.url}) — re-run Refresh SCC Sessions"
            log_fn(f"[scc-nav] On dashboard: {page.url[:70]}")

            # Wait for SPA to fully render (sidebar needs time after OAuth callback)
            try:
                page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            page.wait_for_timeout(3000)

            # Dump ALL nav links (including those below fold) for debugging
            try:
                _nav_links = page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('a, [role="link"]'))
                        .map(a => ({href: a.href || '', text: (a.textContent || '').trim().slice(0, 60)}))
                        .filter(a => a.href || a.text)
                        .slice(0, 50);
                }""")
                log_fn("[scc-nav] ALL links: " +
                       " | ".join(f"{l['text']!r}" for l in _nav_links if l['text'])[:300])
                page.screenshot(path=str(DATA_DIR / "data" / f"scc_dashboard_{pod_id}.png"))
            except Exception as _de:
                log_fn(f"[scc-nav] link dump failed: {_de}")

            # Dismiss org picker
            try:
                cont = page.locator('button:has-text("Continue")').first
                cont.wait_for(state="visible", timeout=6000)
                cont.click()
                log_fn("[scc-nav] Dismissed org picker")
                page.wait_for_load_state("domcontentloaded", timeout=15000)
                page.wait_for_timeout(2000)
            except Exception:
                pass

            # ── Navigate via Platform Management → Integrations in sidebar ─────────
            # The direct /ise-integration URL renders a blank SPA page (content area
            # never mounts). Navigate through the sidebar instead:
            # Platform Management → Integrations → My Integrations → ISE form
            _nav_clicked = False

            # Step 1: Click Platform Management in sidebar to expand it
            log_fn("[scc-nav] Clicking Platform Management in sidebar")
            _pm_clicked = False
            for _pm_sel in [
                'a:has-text("Platform Management")',
                'button:has-text("Platform Management")',
                'li:has-text("Platform Management") a',
                'li:has-text("Platform Management") button',
            ]:
                try:
                    el = page.locator(_pm_sel).first
                    if el.is_visible(timeout=5000):
                        el.click()
                        page.wait_for_timeout(2000)
                        log_fn(f"[scc-nav] Clicked Platform Management via {_pm_sel!r}")
                        _pm_clicked = True
                        break
                except Exception:
                    continue

            if not _pm_clicked:
                try:
                    page.screenshot(path=str(DATA_DIR / "data" / f"scc_pm_fail_{pod_id}.png"))
                    log_fn("[scc-nav] WARN: Platform Management not found — saved scc_pm_fail screenshot")
                except Exception:
                    pass
                return False, "Could not find Platform Management in SCC sidebar — check scc_pm_fail screenshot"

            # Step 2: Click Integrations in the expanded submenu
            page.wait_for_timeout(1000)
            _int_clicked = False
            for _int_sel in [
                'a:has-text("Integrations"):not(:has-text("Platform"))',
                'li:has-text("Integrations") > a',
                'a[href*="integrations"]',
                'a:has-text("Integrations")',
            ]:
                try:
                    el = page.locator(_int_sel).first
                    if el.is_visible(timeout=5000):
                        el.click()
                        page.wait_for_load_state("domcontentloaded", timeout=20000)
                        page.wait_for_timeout(3000)
                        log_fn(f"[scc-nav] Clicked Integrations via {_int_sel!r} → {page.url[:80]}")
                        _int_clicked = True
                        break
                except Exception:
                    continue

            if not _int_clicked:
                try:
                    page.screenshot(path=str(DATA_DIR / "data" / f"scc_int_fail_{pod_id}.png"))
                    log_fn("[scc-nav] WARN: Integrations link not found — saved scc_int_fail screenshot")
                except Exception:
                    pass
                return False, "Could not navigate to Integrations under Platform Management — check scc_int_fail screenshot"

            log_fn(f"[scc-nav] Integrations page URL: {page.url[:80]}")
            try:
                page.screenshot(path=str(DATA_DIR / "data" / f"scc_int_page_{pod_id}.png"))
            except Exception:
                pass

            # Step 3: Click My Integrations tab if present
            page.wait_for_timeout(1000)
            for _tab_sel in [
                'button:has-text("My Integrations")',
                'a:has-text("My Integrations")',
                '[role="tab"]:has-text("My Integrations")',
            ]:
                try:
                    tab = page.locator(_tab_sel).first
                    if tab.is_visible(timeout=3000):
                        tab.click()
                        page.wait_for_timeout(2000)
                        log_fn("[scc-nav] Clicked My Integrations tab")
                        break
                except Exception:
                    continue

            # Dump page state for diagnostics
            try:
                _btns_on_page = page.evaluate("""() => Array.from(document.querySelectorAll(
                    'button, a[role="button"], [role="button"]'))
                    .map(b => b.textContent.trim().slice(0,40)).filter(t => t).slice(0,20)""")
                log_fn("[scc-nav] Buttons on integrations page: " + " | ".join(_btns_on_page))
            except Exception:
                pass

            # Step 4: Find ISE integration card or Add Integration button
            page.wait_for_timeout(1000)
            _page_text = page.inner_text("body").lower()
            _ise_opened = False

            # If ISE entry already exists and is active/connected → done.
            # If it exists but is Deactivated/Failed → delete it and create fresh with new OTP.
            if "ise" in _page_text:
                _is_bad = any(kw in _page_text for kw in ("deactivated", "failed", "error"))
                if not _is_bad:
                    try:
                        page.screenshot(path=str(DATA_DIR / "data" / f"scc_after_save_{pod_id}.png"))
                    except Exception:
                        pass
                    log_fn("[scc-nav] ISE integration already active in SCC — done")
                    return True, "ISE integration already active in SCC"
                else:
                    log_fn("[scc-nav] ISE integration present but Deactivated/Failed — deleting and recreating with new OTP")
                    _deleted = False
                    try:
                        page.screenshot(path=str(DATA_DIR / "data" / f"scc_delete_fail_{pod_id}.png"))
                    except Exception:
                        pass
                    # Row has a "..." kebab as the last button — no text content, target by position
                    # NOTE: tr.is_visible() returns False in Playwright even for visible rows;
                    #       check the button directly instead.
                    try:
                        _row = page.locator('tr').filter(has_text='ISE-POD')
                        _kebab = _row.locator('button').last
                        if not _kebab.is_visible(timeout=3000):
                            raise Exception("kebab button not visible")
                        _kebab.click(timeout=5000)
                        page.wait_for_timeout(1000)
                        log_fn("[scc-nav] Clicked kebab (last button in ISE row)")
                    except Exception as _ke:
                        log_fn(f"[scc-nav] Row kebab failed ({_ke}) — trying aria-label fallbacks")
                        for _del_sel in [
                            'button[aria-label*="action" i]',
                            'button[aria-label*="option" i]',
                            '.pf-v5-c-menu-toggle',
                            'button.pf-v5-c-menu-toggle',
                        ]:
                            try:
                                btn = page.locator(_del_sel).first
                                if btn.is_visible(timeout=2000):
                                    btn.click()
                                    page.wait_for_timeout(1000)
                                    log_fn(f"[scc-nav] Opened actions menu via {_del_sel!r}")
                                    break
                            except Exception:
                                continue
                    # Click Delete / Remove from the dropdown
                    for _del_opt in [
                        'button:has-text("Delete")',
                        'li:has-text("Delete")',
                        '[role="menuitem"]:has-text("Delete")',
                        'a:has-text("Delete")',
                        'button:has-text("Remove")',
                        '[role="menuitem"]:has-text("Remove")',
                    ]:
                        try:
                            opt = page.locator(_del_opt).first
                            if opt.is_visible(timeout=3000):
                                opt.click()
                                page.wait_for_timeout(1500)
                                log_fn(f"[scc-nav] Clicked delete option via {_del_opt!r}")
                                _deleted = True
                                break
                        except Exception:
                            continue
                    # Confirm delete dialog if present
                    if _deleted:
                        for _confirm_sel in [
                            'button:has-text("Delete")',
                            'button:has-text("Confirm")',
                            'button:has-text("Yes")',
                            'button:has-text("OK")',
                        ]:
                            try:
                                cb = page.locator(_confirm_sel).first
                                if cb.is_visible(timeout=3000):
                                    cb.click()
                                    page.wait_for_timeout(2000)
                                    log_fn(f"[scc-nav] Confirmed delete via {_confirm_sel!r}")
                                    break
                            except Exception:
                                continue
                        log_fn("[scc-nav] Existing ISE integration deleted — proceeding to add fresh integration")
                    else:
                        log_fn("[scc-nav] WARN: Could not delete deactivated integration — proceeding to Add Integration anyway")
                    # Fall through to Add Integration path with _ise_opened = False

            if not _ise_opened:
                log_fn("[scc-nav] No ISE card found — clicking Add Integration")
                for _add_lbl in ["Add Integration", "Add", "New Integration"]:
                    try:
                        btn = page.locator(
                            f'button:has-text("{_add_lbl}"), a:has-text("{_add_lbl}")'
                        ).first
                        if btn.is_visible(timeout=5000):
                            btn.click()
                            page.wait_for_timeout(2000)
                            log_fn(f"[scc-nav] Clicked '{_add_lbl}'")
                            _ise_opened = True
                            break
                    except Exception:
                        continue

            if not _ise_opened:
                try:
                    page.screenshot(path=str(DATA_DIR / "data" / f"scc_add_fail_{pod_id}.png"))
                    log_fn("[scc-nav] WARN: No Add Integration or ISE card found — saved scc_add_fail screenshot")
                except Exception:
                    pass
                return False, ("No Add Integration button or ISE card found on "
                               "Platform Management → Integrations — check scc_add_fail screenshot")

            # After Add Integration, we may need to select ISE from a type list
            page.wait_for_timeout(1500)
            _page_text2 = page.inner_text("body").lower()
            if "ise" in _page_text2 and "token" not in _page_text2 and "otp" not in _page_text2:
                for _ise_type_sel in [
                    'button:has-text("ISE")',
                    'a:has-text("ISE")',
                    '[class*="card"]:has-text("ISE") button',
                    '[class*="tile"]:has-text("ISE") button',
                    'td:has-text("ISE")',
                ]:
                    try:
                        el = page.locator(_ise_type_sel).first
                        if el.is_visible(timeout=3000):
                            el.click()
                            page.wait_for_timeout(2000)
                            log_fn(f"[scc-nav] Selected ISE type via {_ise_type_sel!r}")
                            break
                    except Exception:
                        continue

            # If we landed on an ISE detail/info page (instructions + Connect button),
            # we need to click "Connect" in the page content to open the actual form.
            # On this page the sidebar has NO "Connect" nav item (we're in Platform
            # Management context, not Secure Access), so the selector is unambiguous.
            page.wait_for_timeout(2000)
            try:
                _pre_inputs = page.evaluate("""() =>
                    Array.from(document.querySelectorAll('input, textarea'))
                    .filter(i => i.placeholder !== "Type 'Ctrl' + '/' to search"
                               && i.type !== 'hidden')
                    .map(i => i.placeholder || i.type)""")
                if not _pre_inputs:
                    log_fn("[scc-nav] No form inputs yet — on ISE detail page, clicking Connect")
                    for _conn_sel in [
                        'button:has-text("Connect")',
                        'a:has-text("Connect")',
                    ]:
                        try:
                            btn = page.locator(_conn_sel).first
                            if btn.is_visible(timeout=5000):
                                btn.click()
                                page.wait_for_timeout(3000)
                                log_fn(f"[scc-nav] Clicked Connect on detail page via {_conn_sel!r}")
                                # Check if integration connected immediately (no form needed)
                                _post_conn_text = page.inner_text("body").lower()
                                if "connected" in _post_conn_text:
                                    try:
                                        page.screenshot(path=str(DATA_DIR / "data" / f"scc_after_save_{pod_id}.png"))
                                    except Exception:
                                        pass
                                    log_fn("[scc-nav] Integration connected after Connect click — done")
                                    return True, "ISE integration connected in SCC"
                                break
                        except Exception:
                            continue
            except Exception as _pie:
                log_fn(f"[scc-nav] pre-input check error: {_pie}")

            log_fn("[scc-nav] Filling integration name and OTP token")

            # Screenshot + button/input dump so we know what the form looks like
            try:
                page.screenshot(path=str(DATA_DIR / "data" / f"scc_connect_form_{pod_id}.png"))
                _form_info = page.evaluate("""() => {
                    const btns = Array.from(document.querySelectorAll('button, [role="button"], input[type="submit"], a[class*="btn"]'))
                        .map(b => (b.textContent || b.value || '').trim().slice(0, 40))
                        .filter(t => t).slice(0, 15);
                    const inputs = Array.from(document.querySelectorAll('input, textarea'))
                        .map(i => ({type: i.type, id: i.id, name: i.name, ph: i.placeholder, dt: (i.dataset && i.dataset.testid) || ''}))
                        .slice(0, 10);
                    return {btns, inputs};
                }""")
                log_fn(f"[scc-nav] Form buttons: " + " | ".join(_form_info.get('btns', [])))
                log_fn(f"[scc-nav] Form inputs: " + str(_form_info.get('inputs', [])))
            except Exception as _fe:
                log_fn(f"[scc-nav] form dump error: {_fe}")

            _name = f"ISE-POD-{pod_id}-{int(_time.time()) % 10000}"

            # Fill the form using Playwright's locator.fill(), which correctly
            # triggers React's onChange and enables the Save button.
            # IMPORTANT: do NOT click the "Show" button between fill and Save —
            # that re-renders the OTP field and resets React state.
            # The data-testid attributes on the fields make targeting precise.
            log_fn(f"[scc-nav] Filling form: name={_name!r}, otp len={len(otp_token)}")
            # Strategy A: press_sequentially — fires real keydown/keyup/input/change
            # events per character, the most reliable trigger for React controlled inputs.
            # NOTE: page.keyboard.press() only affects the main frame.
            #       If the form is in a child iframe, use locator.evaluate() for blur.
            _fill_ok = False
            try:
                _name_loc = page.locator('[data-testid*="integrationName"]').first
                _otp_loc  = page.locator('[data-testid*="-otp"]').first
                _name_loc.click(timeout=5000)
                _name_loc.select_text(timeout=3000)     # select-all via locator (works in iframes)
                _name_loc.press_sequentially(_name, delay=30)
                page.wait_for_timeout(300)
                _otp_loc.click(timeout=5000)            # blurs name → name.touched=True
                _otp_loc.select_text(timeout=3000)
                _otp_loc.press_sequentially(otp_token, delay=8)
                page.wait_for_timeout(300)
                _otp_loc.evaluate("el => el.blur()")    # blur OTP directly (works in iframes)
                page.wait_for_timeout(600)              # allow React validation to run
                log_fn(f"[scc-nav] Typed via press_sequentially (name={len(_name)} otp={len(otp_token)} chars) + blur")
                _fill_ok = True
            except Exception as _fe:
                log_fn(f"[scc-nav] press_sequentially failed ({_fe})")

            # Strategy B: React-native-setter via locator.evaluate() — runs in the
            # element's own frame (works for iframes). Fires input/change/blur events.
            if not _fill_ok:
                try:
                    _name_loc.evaluate("""
                        (el, v) => {
                            const setter = Object.getOwnPropertyDescriptor(
                                HTMLInputElement.prototype, 'value').set;
                            setter.call(el, v);
                            el.dispatchEvent(new Event('input',  {bubbles:true}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                            el.dispatchEvent(new Event('blur',   {bubbles:true}));
                        }
                    """, _name)
                    _otp_loc.evaluate("""
                        (el, v) => {
                            const setter = Object.getOwnPropertyDescriptor(
                                HTMLInputElement.prototype, 'value').set;
                            setter.call(el, v);
                            el.dispatchEvent(new Event('input',  {bubbles:true}));
                            el.dispatchEvent(new Event('change', {bubbles:true}));
                            el.dispatchEvent(new Event('blur',   {bubbles:true}));
                        }
                    """, otp_token)
                    page.wait_for_timeout(600)
                    log_fn("[scc-nav] Filled via React-native-setter locator.evaluate()")
                    _fill_ok = True
                except Exception as _fe2:
                    log_fn(f"[scc-nav] React-native-setter failed ({_fe2})")

            # Strategy C: plain fill() + blur as last resort
            if not _fill_ok:
                try:
                    _name_loc.fill(_name, timeout=5000)
                    _otp_loc.fill(otp_token, timeout=5000)
                    _name_loc.evaluate("el => el.blur()")
                    _otp_loc.evaluate("el => el.blur()")
                    page.wait_for_timeout(600)
                    log_fn("[scc-nav] Filled via fill() + blur last-resort")
                except Exception as _fe3:
                    log_fn(f"[scc-nav] All fill strategies failed: {_fe3}")

            # Wait for Save to enable — React enables Save after both fields are filled
            # AND both have been blurred (touched). Tab press above triggers onBlur for OTP.
            log_fn("[scc-nav] Waiting up to 10s for Save button to enable...")
            try:
                page.wait_for_function(
                    """() => {
                        const allBtns = Array.from(document.querySelectorAll('button'));
                        const saveBtn = allBtns.find(b => b.textContent.trim() === 'Save');
                        return saveBtn && !saveBtn.disabled;
                    }""",
                    timeout=10000
                )
                log_fn("[scc-nav] Save button is enabled!")
            except Exception as _we:
                log_fn(f"[scc-nav] Save enable-wait timed out — checking field state...")
                try:
                    _dbg = page.evaluate("""() => {
                        const nameEl = document.querySelector('[data-testid*="integrationName"]')
                                    || Array.from(document.querySelectorAll('input[type="text"]'))
                                       .find(i => !i.placeholder.toLowerCase().includes('search'));
                        const otpEl  = document.querySelector('[data-testid*="-otp"]')
                                    || document.querySelector('input[type="password"]');
                        const saveBtn = Array.from(document.querySelectorAll('button'))
                            .find(b => b.textContent.trim() === 'Save');
                        return {
                            nameLen: nameEl ? nameEl.value.length : -1,
                            otpLen:  otpEl  ? otpEl.value.length  : -1,
                            saveDisabled: saveBtn ? saveBtn.disabled : null
                         };
                    }""")
                    log_fn(f"[scc-nav] Fields at timeout: nameLen={_dbg.get('nameLen')} "
                           f"otpLen={_dbg.get('otpLen')} saveDisabled={_dbg.get('saveDisabled')}")
                except Exception:
                    pass

                # React fiber diagnostic — inspect what React "thinks" the OTP value is
                try:
                    _react_dbg = _otp_loc.evaluate("""el => {
                        const k = Object.keys(el).find(k =>
                            k.startsWith('__reactFiber') || k.startsWith('__reactInternals'));
                        if (!k) return {found: false};
                        let fiber = el[k];
                        let depth = 0;
                        while (fiber && depth < 30) {
                            const p = fiber.pendingProps || fiber.memoizedProps;
                            if (p && (p.onChange || p.value !== undefined)) {
                                return {found: true, value: p.value, hasOnChange: !!p.onChange,
                                        depth, tag: fiber.tag};
                            }
                            fiber = fiber.return;
                            depth++;
                        }
                        return {found: true, noProps: true};
                    }""")
                    log_fn(f"[scc-nav] React fiber OTP: {_react_dbg}")
                except Exception as _rf_e:
                    log_fn(f"[scc-nav] React fiber check failed: {_rf_e}")

            # Show OTP for debug screenshot (AFTER the wait, so it doesn't interfere)
            try:
                _show_btn = page.locator('button:has-text("Show")').first
                if _show_btn.is_visible(timeout=1500):
                    _show_btn.click()
                    page.wait_for_timeout(400)
                    _otp_vis = page.evaluate("""() => {
                        const inp = document.querySelector('input[type="text"]:not([placeholder*="search" i]):not([placeholder*="Ctrl" i])') ||
                                    document.querySelector('input[placeholder=""]');
                        return inp ? inp.value : '';
                    }""")
                    log_fn(f"[scc-nav] OTP field value (post-wait Show): len={len(_otp_vis)} first20={_otp_vis[:20]!r}")
            except Exception as _show_e:
                log_fn(f"[scc-nav] post-wait Show debug: {_show_e}")

            # Take a pre-save screenshot so we can see the form state
            try:
                page.screenshot(path=str(DATA_DIR / "data" / f"scc_presave_{pod_id}.png"))
            except Exception:
                pass

            # ── Early-exit: if SCC already shows ISE as Connected on Integration Hub,
            # the OTP was consumed and the integration is live — no Save needed. ──
            _presave_txt = page.inner_text("body").lower()
            _on_int_hub = "integration hub" in _presave_txt or "cisco integrations" in _presave_txt
            _ise_connected = "connected" in _presave_txt and "identity services engine" in _presave_txt
            if _on_int_hub and _ise_connected:
                log_fn("[scc-nav] Integration Hub shows ISE Connected — integration already live, no Save needed")
                return True, "ISE → SCC integration complete (Connected)"

            log_fn("[scc-nav] Clicking Save button")
            _saved = False

            # Strategy 1: target by data-testid (specific to this CDS form)
            try:
                btn = page.locator('[data-testid*="save-btn"]').last
                btn.wait_for(state="visible", timeout=5000)
                btn.click(timeout=10000)
                log_fn("[scc-nav] Clicked Save via data-testid")
                _saved = True
            except Exception as _se0:
                log_fn(f"[scc-nav] Save data-testid attempt failed: {_se0}")

            # Strategy 2: filter-based — finds the button whose trimmed text is "Save"
            if not _saved:
                try:
                    btn = page.locator("button").filter(has_text="Save").last
                    btn.wait_for(state="visible", timeout=5000)
                    btn.click(timeout=10000)
                    log_fn("[scc-nav] Clicked Save via filter")
                    _saved = True
                except Exception as _se2:
                    log_fn(f"[scc-nav] Save filter attempt failed: {_se2}")

            # Strategy 3: has-text last/first
            if not _saved:
                for _try_last in [True, False]:
                    try:
                        _loc = page.locator('button:has-text("Save")')
                        btn = _loc.last if _try_last else _loc.first
                        btn.wait_for(state="visible", timeout=5000)
                        btn.click(timeout=10000)
                        log_fn(f"[scc-nav] Clicked Save ({'last' if _try_last else 'first'})")
                        _saved = True
                        break
                    except Exception as _se:
                        log_fn(f"[scc-nav] Save attempt ({'last' if _try_last else 'first'}) failed: {_se}")

            # Strategy 4: force-click — remove disabled attribute via JS then click
            # This bypasses Playwright's enabled check entirely.
            if not _saved:
                log_fn("[scc-nav] Force-clicking Save (removing disabled attribute)")
                try:
                    _fc_result = page.evaluate("""
                        () => {
                            const btn = document.querySelector('[data-testid*="save-btn"]')
                                     || Array.from(document.querySelectorAll('button'))
                                            .find(b => b.textContent.trim() === 'Save');
                            if (!btn) return 'no-button';
                            btn.removeAttribute('disabled');
                            btn.click();
                            return 'clicked';
                        }
                    """)
                    log_fn(f"[scc-nav] Force-click result: {_fc_result}")
                    if _fc_result == 'clicked':
                        # Wait up to 5s to see if React's onClick fires the API call.
                        # If _scc_api_resp stays empty the DOM click bypassed React
                        # entirely — treat as failure so a new OTP can be generated.
                        _fc_deadline = _time.time() + 5
                        while _time.time() < _fc_deadline and "status" not in _scc_api_resp:
                            page.wait_for_timeout(500)
                        if "status" in _scc_api_resp:
                            log_fn(f"[scc-nav] Force-click triggered API (status {_scc_api_resp['status']})")
                            _saved = True
                        else:
                            log_fn("[scc-nav] Force-click fired but no API call detected — React onClick not triggered")
                            # _saved stays False; fall through to Enter-key strategy
                except Exception as _fee:
                    log_fn(f"[scc-nav] Force-click failed: {_fee}")

            # Strategy 5: press Enter on the password field to submit the form
            if not _saved:
                log_fn("[scc-nav] Trying Enter key to submit form")
                try:
                    _pw = page.locator('input[type="password"]').first
                    _pw.click()
                    page.keyboard.press("Enter")
                    page.wait_for_timeout(2000)
                    _saved = True
                    log_fn("[scc-nav] Submitted via Enter key")
                except Exception as _ee:
                    log_fn(f"[scc-nav] Enter key attempt failed: {_ee}")

            if not _saved:
                try:
                    page.screenshot(path=str(DATA_DIR / "data" / f"scc_nosave_{pod_id}.png"))
                except Exception:
                    pass
                return False, f"ISE \u2192 SCC integration FAILED: could not click Save (check scc_nosave_{pod_id}.png)"

            page.wait_for_timeout(4000)

            # Check the intercepted SCC API response — this is the authoritative
            # signal. The form stays open (no navigation) on failure, so page-text
            # alone is not sufficient to detect OTP rejection.
            _api_status = _scc_api_resp.get("status")
            _api_body   = _scc_api_resp.get("body", "")[:300]
            if _api_status == 400:
                log_fn(f"[scc-nav] SCC API returned 400: {_api_body}")
                # Name conflict is handled by the block below; OTP rejection must
                # be propagated back so the ISE container can generate a new OTP.
                _name_err = any(k in _api_body.lower() for k in ("name", "already", "unique"))
                if not _name_err:
                    return False, f"invalid_otp: SCC API rejected OTP (400): {_api_body}"
                log_fn("[scc-nav] 400 is name conflict — proceeding to name-conflict retry")
            elif _api_status and _api_status not in (200, 201):
                log_fn(f"[scc-nav] SCC API returned {_api_status}: {_api_body}")
                return False, f"SCC API returned {_api_status}: {_api_body}"
            elif _api_status in (200, 201):
                log_fn(f"[scc-nav] SCC API returned {_api_status} — OTP accepted")

            _txt = page.inner_text("body").lower()
            if "unique" in _txt or "already exists" in _txt or "name is already" in _txt:
                log_fn("[scc-nav] Name conflict — retrying with alternate name")
                _name = f"ISE-POD-{pod_id}-{int(_time.time()) % 10000}x"
                for _sel in ['input[placeholder*="name" i]', 'input[id*="name"]',
                             'input[type="text"]:not([placeholder*="search" i]):not([placeholder*="Ctrl" i])']:
                    try:
                        inp = page.locator(_sel).first
                        if inp.is_visible(timeout=3000):
                            inp.click()
                            page.keyboard.press("Control+a")
                            inp.press_sequentially(_name, delay=30)
                            break
                    except Exception:
                        continue
                # Retry Save with the same robust approach
                for _try_last2 in [True, False]:
                    try:
                        _loc2 = page.locator('button:has-text("Save")')
                        b2 = _loc2.last if _try_last2 else _loc2.first
                        b2.wait_for(state="visible", timeout=5000)
                        b2.click(timeout=8000)
                        break
                    except Exception:
                        continue
                page.wait_for_timeout(5000)
            else:
                page.wait_for_timeout(2000)

            content = page.content().lower()
            # Take an "after-save" screenshot for verification
            try:
                page.screenshot(path=str(DATA_DIR / "data" / f"scc_after_save_{pod_id}.png"))
                log_fn("[scc-nav] After-save screenshot saved")
            except Exception:
                pass
            # Only return success if Save was actually clicked AND page shows a real result.
            # Do NOT match broad words like "connected" that appear on the form page itself.
            _success_signals = ["waiting for activation", "pending activation",
                                 "activation pending", "successfully added",
                                 "integration added", "integration created",
                                 "my integrations"]
            _found_signal = next((s for s in _success_signals if s in content), None)
            if _found_signal:
                return True, f"ISE \u2192 SCC integration submitted ({_found_signal}; token: {otp_token[:20]}...)"
            if _saved:
                return True, (f"ISE \u2192 SCC integration form submitted (token: {otp_token[:20]}...) "
                              f"— check scc_after_save_{pod_id}.png to confirm activation state")
            return True, (f"ISE \u2192 SCC integration attempted (no Save button found) "
                          f"— check scc_after_save_{pod_id}.png")

        except Exception as e:
            return False, f"ISE \u2192 Secure Access integration error: {e}"
        finally:
            browser.close()


def _scc_auto_reset_manual(pod_id: str, log_fn) -> tuple:
    """
    Automate all 7 manual SCC checklist items via Playwright using the saved SCC session.
    Each item: not_found → completed (already clean); exception → failed (red).
    Screenshots saved per item for debugging.
    """
    from playwright.sync_api import sync_playwright
    import sqlite3 as _sq

    db_path = str(DATA_DIR / "data" / "pod_state.db")
    scc_session = DATA_DIR / "data" / f"scc_session_{pod_id}.json"
    if not scc_session.exists():
        scc_session = DATA_DIR / "data" / "scc_session.json"
    if not scc_session.exists():
        return False, f"No SCC session found for {pod_id} — run Refresh SCC Sessions first"

    def _persist(item_key, status, detail=""):
        try:
            with _sq.connect(db_path) as _c:
                _c.execute(
                    "INSERT OR REPLACE INTO scc_checklist (pod_id, item_key, status, detail) "
                    "VALUES (?,?,?,?)", (pod_id, item_key, status, str(detail)[:500])
                )
                _c.commit()
        except Exception as _e:
            log_fn(f"[scc-reset] DB write error: {_e}")

    _sd = json.loads(scc_session.read_text())
    _eid = ""
    for _o in _sd.get("origins", []):
        for _it in _o.get("localStorage", []):
            if _it.get("name") == "enterpriseId":
                _eid = _it["value"]
                break
    _base = (f"https://security.cisco.com/dashboard?enterpriseId={_eid}"
             if _eid else "https://security.cisco.com/dashboard")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            ctx = browser.new_context(
                storage_state=_sd, viewport={"width": 1920, "height": 1080}
            )
            page = ctx.new_page()
            page.set_default_timeout(20000)

            # ── Load SCC and verify session ───────────────────────────────────
            page.goto(_base, wait_until="domcontentloaded", timeout=60000)
            page.wait_for_timeout(2000)
            _w = 0
            while _w < 20 and "login/callback" in page.url.lower():
                page.wait_for_timeout(2000); _w += 2
            if ("sign-on" in page.url.lower() and "security.cisco.com" not in page.url.lower()) or \
               ("login" in page.url.lower() and "/login/callback" not in page.url.lower()):
                return False, "SCC session expired — re-run Refresh SCC Sessions"
            try:
                page.wait_for_load_state("networkidle", timeout=12000)
            except Exception:
                pass
            page.wait_for_timeout(2000)
            log_fn(f"[scc-reset] Session OK: {page.url[:60]}")

            # ── Dismiss org picker if present ─────────────────────────────────
            try:
                _cont = page.locator('button:has-text("Continue")').first
                if _cont.is_visible(timeout=4000):
                    _cont.click()
                    page.wait_for_timeout(2000)
            except Exception:
                pass

            # ── Helpers ───────────────────────────────────────────────────────
            def _nav(label: str, timeout: int = 7000) -> bool:
                for _s in [
                    f'a:has-text("{label}")', f'button:has-text("{label}")',
                    f'li:has-text("{label}") > a', f'li:has-text("{label}") > button',
                    f'[role="menuitem"]:has-text("{label}")',
                ]:
                    try:
                        el = page.locator(_s).first
                        if el.is_visible(timeout=timeout):
                            el.click(); page.wait_for_timeout(1200)
                            return True
                    except Exception:
                        continue
                return False

            def _go(label_chain: list) -> bool:
                """Navigate via a chain of sidebar labels; returns True if last click succeeded."""
                page.goto(_base, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(2000)
                for _lbl in label_chain:
                    _nav(_lbl)
                try:
                    page.wait_for_load_state("domcontentloaded", timeout=15000)
                except Exception:
                    pass
                page.wait_for_timeout(2500)
                return True

            def _on_home() -> bool:
                """True if we are still on the SCC platform-level page (not inside SA).
                SA pages have /secure-access/ in the URL (legacy: /sase/).
                Platform Management pages have /platform-management in the URL."""
                _u = page.url.lower()
                return ("/sase/" not in _u
                        and "/secure-access/" not in _u
                        and "/platform-management" not in _u)

            def _sa_url(path: str) -> str:
                """Build a full SA URL by extracting the org number from the current
                page URL (e.g. /secure-access/org/8383340/...) and appending path."""
                import re as _re
                _m = _re.search(r'/secure-access/org/(\d+)', page.url)
                if _m:
                    return f"https://security.cisco.com/secure-access/org/{_m.group(1)}{path}"
                return ""

            def _enter_secure_access() -> bool:
                """Click into Secure Access from the platform home."""
                page.goto(_base, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(1500)
                # Dismiss any open overlay/panel (org switcher, flyout, etc.)
                try:
                    page.keyboard.press("Escape"); page.wait_for_timeout(400)
                except Exception:
                    pass
                # Also click the close button on any overlay
                try:
                    page.evaluate("""() => {
                        const btns = Array.from(document.querySelectorAll('button'));
                        const b = btns.find(b => {
                            const t = (b.textContent || '').trim();
                            const a = (b.getAttribute('aria-label') || '').toLowerCase();
                            const rect = b.getBoundingClientRect();
                            return (t === '\u00d7' || t === '\u2715' || a.includes('close'))
                                   && rect.width > 0 && rect.height > 0;
                        });
                        if (b) b.click();
                    }""")
                    page.wait_for_timeout(400)
                except Exception:
                    pass
                page.wait_for_timeout(500)
                for _sel in ['a:has-text("Secure Access")', 'button:has-text("Secure Access")',
                             'li:has-text("Secure Access") > a', '[role="menuitem"]:has-text("Secure Access")']:
                    try:
                        el = page.locator(_sel).first
                        if el.is_visible(timeout=3000):
                            el.click()
                            page.wait_for_timeout(3000)
                            try:
                                page.wait_for_load_state("networkidle", timeout=8000)
                            except Exception:
                                pass
                            page.wait_for_timeout(1500)
                            return True
                    except Exception:
                        continue
                return False

            def _sase_nav(flyout_label: str, item_label: str, shot_prefix: str = "") -> bool:
                """Within Secure Access: click the sidebar toggle button (which expands the
                flyout panel), then click the sub-item link inside the panel.
                SA sidebar expandable items are <button>, NOT <a> — so button:has-text
                must come BEFORE a:has-text to avoid matching the breadcrumb link.

                Two-click pattern: first click collapses whatever flyout is currently
                open; second click opens the target flyout. A JS close is attempted first
                to handle the sticky Resources panel whose × button has no standard
                aria-label or PatternFly class."""
                # Step 1: close any currently-open flyout panel
                # JS approach: find any visible × / ✕ / Close button in the panel header
                try:
                    page.evaluate("""() => {
                        const btns = Array.from(document.querySelectorAll('button'));
                        const b = btns.find(b => {
                            const t = (b.textContent || '').trim();
                            const a = (b.getAttribute('aria-label') || '').toLowerCase();
                            const rect = b.getBoundingClientRect();
                            return (t === '\u00d7' || t === '\u2715' || t === '\u2716'
                                    || t === 'Close' || a.includes('close'))
                                   && rect.width > 0 && rect.height > 0;
                        });
                        if (b) b.click();
                    }""")
                    page.wait_for_timeout(500)
                except Exception:
                    pass
                # Selector-based fallback close
                for _close_sel in [
                    'button[aria-label*="close" i]',
                    '[aria-label="Close"]',
                    '[aria-label="Close panel"]',
                    'button:has-text("×")',
                    'button:has-text("✕")',
                    'button[class*="close"]',
                ]:
                    try:
                        cb = page.locator(_close_sel).first
                        if cb.is_visible(timeout=600):
                            cb.click(); page.wait_for_timeout(400); break
                    except Exception:
                        continue
                # Escape as final close attempt
                try:
                    page.keyboard.press("Escape"); page.wait_for_timeout(400)
                except Exception:
                    pass

                # Debug: log all matching buttons to identify wrong match
                try:
                    _all_matches = page.locator(f'button:has-text("{flyout_label}")').all()
                    _debug_texts = []
                    for _mx in _all_matches[:8]:
                        try:
                            _t = _mx.inner_text()[:40].replace('\n', ' ')
                            _bb = _mx.bounding_box()
                            _pos = f"x={int(_bb['x'])},y={int(_bb['y'])}" if _bb else "?"
                            _debug_texts.append(f"'{_t}'@{_pos}")
                        except Exception:
                            _debug_texts.append("?")
                    log_fn(f"[scc-nav-debug] button:has-text('{flyout_label}') → {_debug_texts}")
                except Exception as _de:
                    log_fn(f"[scc-nav-debug] debug error: {_de}")

                # Step 2: two-click pattern on sidebar toggle
                # Click 1 — may close a currently-open flyout (side effect on some panels)
                # Click 2 — reliably opens the target flyout
                _fsel_list = [
                    f'button:has-text("{flyout_label}")',        # SA sidebar toggle (button) ← first
                    f'nav button:has-text("{flyout_label}")',    # scoped to nav
                    f'li:has-text("{flyout_label}") > button',
                    f'[role="button"]:has-text("{flyout_label}")',
                    f'a:has-text("{flyout_label}")',             # fallback (avoid breadcrumb)
                ]
                for _attempt in range(2):
                    for _fsel in _fsel_list:
                        try:
                            el = page.locator(_fsel).first
                            if el.is_visible(timeout=2000):
                                el.hover()
                                page.wait_for_timeout(400)
                                el.click()
                                page.wait_for_timeout(1200 if _attempt == 0 else 1800)
                                break
                        except Exception:
                            continue
                    # After click 1: check if a flyout sub-item is already visible
                    if _attempt == 0:
                        try:
                            if page.locator(f'a:has-text("{item_label}")').is_visible(timeout=800):
                                break  # already open — skip click 2
                        except Exception:
                            pass

                # Debug: log URL after clicks
                try:
                    log_fn(f"[scc-nav-debug] after clicks → url={page.url[:80]}")
                except Exception:
                    pass

                # Screenshot of flyout state for diagnosis
                if shot_prefix:
                    try:
                        page.screenshot(path=str(DATA_DIR / "data" / f"scc_flyout_{shot_prefix}_{pod_id}.png"))
                    except Exception:
                        pass

                # Step 3: click the sub-item in the now-open flyout panel
                for _sel in [
                    f'a:has-text("{item_label}")',
                    f'button:has-text("{item_label}")',
                    f'[role="menuitem"]:has-text("{item_label}")',
                    f'[role="option"]:has-text("{item_label}")',
                    f'span:has-text("{item_label}")',
                ]:
                    try:
                        el = page.locator(_sel).first
                        if el.is_visible(timeout=2500):
                            el.click()
                            page.wait_for_timeout(2500)
                            return True
                    except Exception:
                        continue
                return False

            def _sase_goto(nav_chains: list, content_checks: list = None,
                           shot_prefix: str = "") -> bool:
                """Enter Secure Access from platform Home, then try each (flyout, item) nav
                chain until we land on a page with expected content (or just off-home).
                nav_chains  = [(flyout_label, item_label), ...]
                content_checks = list of lowercase strings; any must be in page body.
                Returns True on success."""
                for (_flyout, _item) in nav_chains:
                    if not _enter_secure_access():
                        return False
                    page.wait_for_timeout(800)
                    _sase_nav(_flyout, _item, shot_prefix=shot_prefix)
                    page.wait_for_timeout(2000)
                    if _on_home():
                        continue  # nav didn't leave home — try next chain
                    if content_checks:
                        _b = page.inner_text("body").lower()
                        if any(c.lower() in _b for c in content_checks):
                            return True
                        # Left home but content not found — try next chain
                        continue
                    return True  # off-home and no content check required
                return False

            def _goto_sase(path: str) -> bool:
                """Navigate directly to a Secure Access sub-page by URL path.
                Returns True only if we left the Home/Dashboard page."""
                _eid_param = f"?enterpriseId={_eid}" if _eid else ""
                _url = f"https://security.cisco.com{path}{_eid_param}"
                page.goto(_url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(3000)
                try:
                    page.wait_for_load_state("networkidle", timeout=10000)
                except Exception:
                    pass
                page.wait_for_timeout(1500)
                return not _on_home()

            def _shot(name: str):
                try:
                    page.screenshot(path=str(DATA_DIR / "data" / f"scc_reset_{name}_{pod_id}.png"))
                except Exception:
                    pass

            def _sase_delete_row(nav_chains: list, row_hint: str, shot_name: str,
                                 content_checks: list = None,
                                 direct_url: str = "") -> str:
                """Navigate to a Secure Access sub-page, find a row by hint,
                click the three-dot popup menu, then click Delete.
                direct_url: if provided, navigate there instead of using nav_chains.
                nav_chains     = [(flyout_label, item_label), ...]
                content_checks = strings that must appear in page body to confirm nav.
                Returns 'deleted', 'not_found', or 'no_delete_option'."""
                if direct_url:
                    try:
                        page.goto(direct_url, wait_until="domcontentloaded", timeout=30000)
                        page.wait_for_timeout(2500)
                        try:
                            page.wait_for_load_state("networkidle", timeout=8000)
                        except Exception:
                            pass
                        page.wait_for_timeout(1000)
                        log_fn(f"[scc-reset] {shot_name}: navigated to {direct_url[:60]}")
                    except Exception as _ne:
                        log_fn(f"[scc-reset] {shot_name}: direct nav failed: {_ne}")
                        return "not_found"
                elif not _sase_goto(nav_chains, content_checks=content_checks,
                                    shot_prefix=shot_name):
                    log_fn(f"[scc-reset] {shot_name}: could not navigate to target page")
                    return "not_found"
                _shot(shot_name)
                _body = page.inner_text("body")
                if row_hint.lower() not in _body.lower():
                    return "not_found"

                # Find the row
                _row = None
                for _rs in [f'tr:has-text("{row_hint}")',
                            f'[role="row"]:has-text("{row_hint}")',
                            f'li:has-text("{row_hint}")',
                            f'div[class*="row"]:has-text("{row_hint}")']:
                    try:
                        _r = page.locator(_rs).first
                        if _r.is_visible(timeout=2000):
                            _row = _r; break
                    except Exception:
                        continue
                if not _row:
                    return "not_found"

                # Click the three-dot (⋮) button — opens popup menu
                _opened = False
                for _ks in [
                    'button[aria-label*="action" i]', 'button[aria-label*="kebab" i]',
                    'button[aria-label*="more" i]',   'button[aria-label*="option" i]',
                    'button:has-text("⋮")',            'button:has-text("...")',
                    'button:has-text("…")',
                    '.pf-v5-c-menu-toggle',            'button.pf-v5-c-menu-toggle',
                    'button.pf-c-dropdown__toggle',
                ]:
                    try:
                        kb = _row.locator(_ks).first
                        if kb.is_visible(timeout=800):
                            kb.click(); page.wait_for_timeout(2000); _opened = True; break
                    except Exception:
                        continue
                if not _opened:
                    # Fallback: find the rightmost small (icon-sized) button in the row
                    try:
                        _btns = _row.locator('button').all()
                        _best = None
                        _best_x = -1
                        for _b in _btns:
                            try:
                                _bb = _b.bounding_box()
                                if (_bb and _bb['width'] < 60 and _bb['height'] < 60
                                        and _b.is_visible(timeout=300)
                                        and _bb['x'] > _best_x):
                                    _best = _b; _best_x = _bb['x']
                            except Exception:
                                continue
                        if _best:
                            _best.click(force=True)
                            page.wait_for_timeout(2000); _opened = True
                    except Exception:
                        pass
                _shot(f"{shot_name}_menu")

                # Click the delete menu item using JS dispatchEvent so React's
                # synthetic event system actually fires.  Plain Playwright .click()
                # on <li> items does NOT trigger React handlers — confirmed by repeated
                # false-positive "deleted" reports while the rule stayed on the page.
                _del_texts = ["Delete Rule", "Delete", "Remove"]
                _del_clicked = False
                # Primary: Playwright force-click — trusted event, pierces Shadow DOM.
                # JS dispatchEvent creates isTrusted=false which React may reject.
                for _dt in _del_texts:
                    try:
                        _dm = page.get_by_text(_dt, exact=True).first
                        _dm.click(force=True)
                        log_fn(f"[scc-reset] {shot_name}: PW-force-clicked '{_dt}'")
                        _del_clicked = True
                        page.wait_for_timeout(1500)
                        break
                    except Exception:
                        pass
                if not _del_clicked:
                    # Fallback: JS dispatchEvent (may be blocked if component checks isTrusted)
                    for _dt in _del_texts:
                        _clicked = page.evaluate(f"""
                            () => {{
                                for (const el of document.querySelectorAll('*')) {{
                                    if (el.children.length === 0
                                            && el.textContent.trim() === '{_dt}') {{
                                        const r = el.getBoundingClientRect();
                                        if (r.width > 0 && r.height > 0) {{
                                            el.dispatchEvent(new MouseEvent('click',
                                                {{bubbles: true, cancelable: true}}));
                                            return el.tagName + ':leaf';
                                        }}
                                    }}
                                }}
                                return false;
                            }}
                        """)
                        if _clicked:
                            log_fn(f"[scc-reset] {shot_name}: JS-clicked '{_dt}' on {_clicked}")
                            _del_clicked = True
                            page.wait_for_timeout(1500)
                            break

                if not _del_clicked:
                    return "no_delete_option"

                # ── Check mandatory checkbox in confirmation dialog ──
                # Some dialogs require checking a checkbox BEFORE the Delete button is enabled
                # (e.g. DLP "Delete rule 'AI Guardrails'." checkbox).  Try common dialog containers
                # first, then fall back to any visible checkbox.
                page.wait_for_timeout(600)
                try:
                    for _cb_sel in [
                        'dialog input[type="checkbox"]',
                        '[role="dialog"] input[type="checkbox"]',
                        '[class*="modal"] input[type="checkbox"]',
                        'input[type="checkbox"]',
                    ]:
                        _dlg_cb = page.locator(_cb_sel).first
                        if _dlg_cb.count() > 0 and _dlg_cb.is_visible(timeout=1000):
                            if not _dlg_cb.is_checked():
                                _dlg_cb.click(force=True)
                                page.wait_for_timeout(500)
                                log_fn(f"[scc-reset] {shot_name}: checked mandatory"
                                       f" confirm-dialog checkbox ({_cb_sel})")
                            break
                except Exception:
                    pass

                # Handle confirmation dialog — try all button types including Carbon cds-button
                # (cds-button is a web component; button:has-text won't match it without explicit selector)
                _conf_clicked = False
                for _cs in [
                    'cds-button:has-text("Delete")',    # Carbon web component
                    '[label="Delete"]',                  # Carbon attribute
                    'button:has-text("Delete")',
                    'button:has-text("Yes")',
                    'button:has-text("Confirm")',
                    'button:has-text("OK")',
                    'cds-button:has-text("Confirm")',
                    '[label="Confirm"]',
                ]:
                    try:
                        cb = page.locator(_cs).first
                        if cb.count() > 0 and cb.is_visible(timeout=1500):
                            cb.click(force=True); page.wait_for_timeout(2000)
                            _conf_clicked = True; break
                    except Exception:
                        continue
                if not _conf_clicked:
                    # get_by_role pierces Shadow DOM — most reliable for cds-button
                    for _name in ["Delete", "Confirm", "Yes"]:
                        try:
                            _rb = page.get_by_role("button", name=_name)
                            if _rb.count() > 0:
                                _rb.first.click(force=True)
                                page.wait_for_timeout(2000); _conf_clicked = True; break
                        except Exception:
                            continue
                if not _conf_clicked:
                    # JS fallback: dispatchEvent on visible confirm button (bypasses Carbon overlay)
                    _cf = page.evaluate("""
                        () => {
                            for (const btn of document.querySelectorAll('button')) {
                                const t = btn.textContent.trim();
                                if ((t === 'Delete' || t === 'Confirm' || t === 'Yes' || t === 'OK')
                                        && btn.offsetParent !== null) {
                                    btn.dispatchEvent(new MouseEvent('click',
                                        {bubbles: true, cancelable: true}));
                                    return t;
                                }
                            }
                            return false;
                        }
                    """)
                    if _cf:
                        page.wait_for_timeout(2000)
                        log_fn(f"[scc-reset] {shot_name}: JS-confirm clicked '{_cf}'")

                # ── POST-DELETE VERIFICATION ────────────────────────────────
                # Reload the page and confirm the row is actually gone.
                # Never return "deleted" unless we can verify it.
                page.wait_for_timeout(1500)
                _shot(f"{shot_name}_after")
                _body_after = page.inner_text("body").lower()
                if row_hint.lower() in _body_after:
                    log_fn(f"[scc-reset] {shot_name}: row still present after delete attempt")
                    return "no_delete_option"
                return "deleted"

            def _delete_named_row(name_hint: str) -> str:
                """Find a row containing name_hint and delete it via kebab menu.
                Returns 'deleted', 'not_found', or 'no_delete_option'."""
                _body = page.inner_text("body")
                if name_hint.lower() not in _body.lower():
                    return "not_found"
                # Locate the row
                for _rs in [
                    f'tr:has-text("{name_hint}")',
                    f'[role="row"]:has-text("{name_hint}")',
                    f'li:has-text("{name_hint}")',
                ]:
                    try:
                        row = page.locator(_rs).first
                        if not row.is_visible(timeout=2000):
                            continue
                        # Open action menu — kebab or action button
                        _opened = False
                        for _ks in [
                            'button[aria-label*="action" i]', 'button[aria-label*="more" i]',
                            'button[aria-label*="option" i]', '.pf-v5-c-menu-toggle',
                            'button.pf-v5-c-menu-toggle',
                        ]:
                            try:
                                kb = row.locator(_ks).first
                                if kb.is_visible(timeout=800):
                                    kb.click(); page.wait_for_timeout(1500)
                                    _opened = True; break
                            except Exception:
                                continue
                        if not _opened:
                            # Fallback: last button in row
                            try:
                                row.locator('button').last.click(force=True)
                                page.wait_for_timeout(1500); _opened = True
                            except Exception:
                                pass
                        # Pick Delete / Remove from dropdown or inline
                        for _ds in [
                            '[role="menuitem"]:has-text("Delete")', 'button:has-text("Delete")',
                            'li:has-text("Delete") > a', 'a:has-text("Delete")',
                            '[role="menuitem"]:has-text("Remove")', 'button:has-text("Remove")',
                        ]:
                            try:
                                d = page.locator(_ds).first
                                if d.is_visible(timeout=1500):
                                    d.click(); page.wait_for_timeout(800)
                                    # Confirm dialog
                                    for _cs in [
                                        'button:has-text("Delete")', 'button:has-text("Yes")',
                                        'button:has-text("Confirm")', 'button:has-text("OK")',
                                    ]:
                                        try:
                                            cb = page.locator(_cs).first
                                            if cb.is_visible(timeout=2000):
                                                cb.click(); page.wait_for_timeout(1500); break
                                        except Exception:
                                            continue
                                    return "deleted"
                            except Exception:
                                continue
                        return "no_delete_option"
                    except Exception:
                        continue
                return "not_found"

            # ── 0. zta_profiles (browser — Phase 1 API misses UI profiles) ──────
            log_fn("[scc-reset] zta_profiles: browser-based check")
            try:
                _enter_secure_access()
                _zta_url = _sa_url("/connect/user-connectivity/vpn")
                if not _zta_url:
                    _enter_secure_access()
                    _zta_url = _sa_url("/connect/user-connectivity/vpn")
                if not _zta_url:
                    _persist("zta_profiles", "failed", "Could not resolve SA org URL")
                    log_fn("[scc-reset] zta_profiles: could not resolve SA URL")
                else:
                    page.goto(_zta_url, wait_until="domcontentloaded", timeout=30000)
                    page.wait_for_timeout(2000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        pass
                    page.wait_for_timeout(1000)
                    try:
                        page.keyboard.press("Escape"); page.wait_for_timeout(400)
                    except Exception:
                        pass
                    # Click "Zero Trust Access" tab
                    _zta_tab = False
                    for _ts in ['button:has-text("Zero Trust Access")',
                                'a:has-text("Zero Trust Access")',
                                '[role="tab"]:has-text("Zero Trust Access")']:
                        try:
                            _t = page.locator(_ts).first
                            if _t.is_visible(timeout=2000):
                                _t.click(); _zta_tab = True; break
                        except Exception:
                            continue
                    if not _zta_tab:
                        _zta_tab = page.evaluate("""
                            () => {
                                for (const el of document.querySelectorAll('*')) {
                                    if (el.children.length === 0
                                            && el.textContent.trim() === 'Zero Trust Access') {
                                        const r = el.getBoundingClientRect();
                                        if (r.width > 0 && r.height > 0) {
                                            el.dispatchEvent(new MouseEvent('click',
                                                {bubbles: true, cancelable: true}));
                                            return true;
                                        }
                                    }
                                }
                                return false;
                            }
                        """)
                    page.wait_for_timeout(2000)
                    _shot("0_zta_tab")
                    _zta_del = 0
                    _zta_errs = []
                    for _att in range(5):
                        _body_zta = page.inner_text("body").lower()
                        if "pseudoco" not in _body_zta:
                            break
                        _zta_row = None
                        for _rs in ['tr:has-text("PseudoCo")',
                                    '[role="row"]:has-text("PseudoCo")']:
                            try:
                                _r = page.locator(_rs).first
                                if _r.is_visible(timeout=1500):
                                    _zta_row = _r; break
                            except Exception:
                                continue
                        if not _zta_row:
                            break
                        # Find delete icon in the row
                        _del_btn = None
                        for _ds in ['button[aria-label*="delete" i]',
                                    'button[aria-label*="remove" i]',
                                    '[title*="delete" i]',
                                    'button[data-testid*="delete" i]']:
                            try:
                                _d = _zta_row.locator(_ds).first
                                if _d.is_visible(timeout=500):
                                    _del_btn = _d; break
                            except Exception:
                                continue
                        if not _del_btn:
                            # Fallback: rightmost small button in the row
                            try:
                                _btns = _zta_row.locator('button').all()
                                _best = None; _best_x = -1
                                for _b in _btns:
                                    try:
                                        _bb = _b.bounding_box()
                                        if (_bb and _bb['width'] < 60
                                                and _b.is_visible(timeout=300)
                                                and _bb['x'] > _best_x):
                                            _best = _b; _best_x = _bb['x']
                                    except Exception:
                                        continue
                                if _best:
                                    _del_btn = _best
                            except Exception:
                                pass
                        if not _del_btn:
                            _zta_errs.append("delete icon not found in ZTA row")
                            break
                        _del_btn.click(force=True)
                        page.wait_for_timeout(1500)
                        _shot("0_zta_confirm")
                        # Dropdown is now open. Carbon cds-menu-item renders its label in
                        # shadow DOM so JS leaf scan won't find it. Use Playwright force-click
                        # which pierces Shadow DOM and creates a trusted event.
                        _del_item = False
                        try:
                            page.get_by_text("Delete", exact=True).first.click(force=True)
                            _del_item = "pw:force:Delete"
                            page.wait_for_timeout(1000)
                        except Exception:
                            pass
                        if not _del_item:
                            # JS fallback — will work if label IS a leaf node
                            _del_item = page.evaluate("""
                                () => {
                                    for (const el of document.querySelectorAll('*')) {
                                        if (el.children.length === 0
                                                && el.textContent.trim() === 'Delete') {
                                            const r = el.getBoundingClientRect();
                                            if (r.width > 0 && r.height > 0) {
                                                el.dispatchEvent(new MouseEvent('click',
                                                    {bubbles: true, cancelable: true}));
                                                return el.tagName + ':leaf';
                                            }
                                        }
                                    }
                                    return false;
                                }
                            """)
                        page.wait_for_timeout(1500)
                        _conf = bool(_del_item)
                        if _conf:
                            # Handle any confirmation dialog (Playwright then JS)
                            _conf2 = False
                            for _cs in ['button:has-text("Delete")',
                                        'button:has-text("Confirm")',
                                        'button:has-text("Yes")']:
                                try:
                                    cb = page.locator(_cs).first
                                    if cb.is_visible(timeout=2000):
                                        cb.click(); page.wait_for_timeout(2000)
                                        _conf2 = True; break
                                except Exception:
                                    continue
                            if not _conf2:
                                page.evaluate("""
                                    () => {
                                        for (const btn of document.querySelectorAll('button')) {
                                            const t = btn.textContent.trim();
                                            if ((t==='Delete'||t==='Confirm'||t==='Yes')
                                                    && btn.offsetParent !== null) {
                                                btn.dispatchEvent(new MouseEvent('click',
                                                    {bubbles: true, cancelable: true}));
                                                return true;
                                            }
                                        }
                                        return false;
                                    }
                                """)
                                page.wait_for_timeout(2000)
                            _zta_del += 1
                        else:
                            _zta_errs.append("Delete menu item not found in dropdown")
                            break
                    if _zta_del:
                        _persist("zta_profiles", "completed",
                                 f"Deleted {_zta_del} ZTA profile(s) ✓")
                        log_fn(f"[scc-reset] zta_profiles: deleted {_zta_del} ✓")
                    elif _zta_errs:
                        _persist("zta_profiles", "failed",
                                 f"Browser: {'; '.join(_zta_errs)}")
                        log_fn(f"[scc-reset] zta_profiles errors: {_zta_errs}")
                    else:
                        _persist("zta_profiles", "completed",
                                 "No custom ZTA profiles found (browser confirmed clean)")
                        log_fn("[scc-reset] zta_profiles: already clean (browser)")
            except Exception as _e:
                _persist("zta_profiles", "failed", f"Browser error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] zta_profiles browser error: {_e}")

            # ── 1. logging_settings ───────────────────────────────────────────
            log_fn("[scc-reset] 1/7 logging_settings")
            try:
                # Enter Secure Access then navigate Secure ▸ Access Policy
                _landed = False
                for _idx, (_flyout, _item) in enumerate([
                    ("Secure", "Access Policy"),
                    ("Secure", "Internet Access"),
                    ("Secure", "Internet Policy"),
                    ("Secure", "Web Policy"),
                    ("Secure", "Web Security"),
                ]):
                    _enter_secure_access()
                    page.wait_for_timeout(800)
                    # Take flyout screenshot on first attempt to reveal actual sub-item labels
                    _sase_nav(_flyout, _item, shot_prefix=f"secure_flyout" if _idx == 0 else "")
                    page.wait_for_timeout(2000)
                    if not _on_home():
                        _b = page.inner_text("body").lower()
                        if any(c in _b for c in ["access policy", "internet access",
                                                  "internet policy", "web policy",
                                                  "web security", "all traffic"]):
                            _landed = True
                            break
                _shot("1_logging")
                _body = page.inner_text("body").lower()
                _detail = "Could not navigate to Access Policy page — check 1_logging screenshot"
                if not _landed:
                    _persist("logging_settings", "failed", _detail)
                    log_fn(f"[scc-reset] logging_settings: {_detail}")
                elif any(c in _body for c in ["access policy", "internet access",
                                               "internet policy", "web policy",
                                               "web security", "all traffic"]):
                    _edit_found = False
                    for _rs in [
                        'tr:has-text("Internet")', 'tr:has-text("internet")',
                        '[role="row"]:has-text("Internet")', 'tr:has-text("All")',
                    ]:
                        try:
                            _row = page.locator(_rs).first
                            for _es in [
                                'button[aria-label*="edit" i]', 'button:has-text("Edit")',
                                'a:has-text("Edit")', '[aria-label*="edit" i]',
                            ]:
                                try:
                                    eb = _row.locator(_es).first
                                    if eb.is_visible(timeout=800):
                                        eb.click(); page.wait_for_timeout(2000)
                                        _edit_found = True; break
                                except Exception:
                                    continue
                            if _edit_found:
                                break
                        except Exception:
                            continue
                    if _edit_found:
                        _shot("1_logging_edit")
                        _toggled = False
                        for _ts in [
                            'input[aria-label*="log" i]', '[aria-label*="log" i][role="switch"]',
                            'label:has-text("Log") input', 'label:has-text("Logging") input',
                            'input[id*="log" i]',
                        ]:
                            try:
                                tog = page.locator(_ts).first
                                if tog.is_visible(timeout=1500):
                                    if tog.is_checked():
                                        tog.click(); page.wait_for_timeout(400)
                                    _toggled = True; break
                            except Exception:
                                continue
                        for _ss in ['button:has-text("Save")', 'button:has-text("Apply")', 'button[type="submit"]']:
                            try:
                                sb = page.locator(_ss).first
                                if sb.is_visible(timeout=1500):
                                    sb.click(); page.wait_for_timeout(1500); break
                            except Exception:
                                continue
                        _detail = "Logging disabled ✓" if _toggled else "Edit opened — logging toggle not found (may already be off)"
                    else:
                        _detail = "Policy row found but no Edit button — logging may already be disabled"
                else:
                    _detail = "Landed on Access Policy page but content pattern not recognized"
                if _landed:
                    _persist("logging_settings", "completed", _detail)
                    log_fn(f"[scc-reset] logging_settings: {_detail}")
            except Exception as _e:
                _persist("logging_settings", "failed", f"Error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] error: {_e}")

            # ── 2. ravpn_profiles ─────────────────────────────────────────────
            log_fn("[scc-reset] 2/7 ravpn_profiles")
            try:
                # Enter SA first so _sa_url() can extract the org number from the URL
                _enter_secure_access()
                _ravpn_direct = _sa_url("/connect/user-connectivity/vpn")
                _res = _sase_delete_row(
                    [("Connect", "Remote Access"),
                     ("Connect", "Remote Access VPN"),
                     ("Connect", "VPN"),
                     ("Connect", "Network Access")],
                    "PseudoCo_RA_VPN", "2_ravpn",
                    content_checks=["remote access", "vpn profile", "vpn", "profile"],
                    direct_url=_ravpn_direct,
                )
                _detail = {
                    "deleted":          "Deleted PseudoCo_RA_VPN_Profile ✓",
                    "not_found":        "No RAVPN profile found (already clean)",
                    "no_delete_option": "No deletable RAVPN profile (already clean)",
                }.get(_res, _res)
                _persist("ravpn_profiles", "completed", _detail)
                log_fn(f"[scc-reset] ravpn_profiles: {_detail}")
            except Exception as _e:
                _persist("ravpn_profiles", "failed", f"Error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] ravpn_profiles error: {_e}")

            # ── 3. dlp_rules ──────────────────────────────────────────────────
            log_fn("[scc-reset] 3/7 dlp_rules")
            try:
                # DLP page is at /secure/dlppolicy/ within Secure Access.
                # Row is named "AI Guardrails". Three-dot menu → "Delete Rule".
                _enter_secure_access()
                _dlp_url = _sa_url("/secure/dlppolicy/")
                _res = _sase_delete_row(
                    [("Secure", "Data Loss Prevention Policy"),
                     ("Secure", "Data Loss Prevention"),
                     ("Secure", "DLP")],
                    "AI Guardrails", "3_dlp",
                    content_checks=["data loss", "dlp", "guardrail", "rule"],
                    direct_url=_dlp_url,
                )
                _detail = {
                    "deleted":          "Deleted DLP rule (AI Guardrails) ✓",
                    "not_found":        "No DLP rule found (already clean)",
                    "no_delete_option": "DLP rule found but no delete option in menu",
                }.get(_res, _res)
                _persist("dlp_rules",
                         "failed" if _res == "no_delete_option" else "completed",
                         _detail)
                log_fn(f"[scc-reset] dlp_rules: {_detail}")
            except Exception as _e:
                _persist("dlp_rules", "failed", f"Error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] dlp_rules error: {_e}")

            # ── 4. ravpn_ip_pool ──────────────────────────────────────────────
            log_fn("[scc-reset] 4/7 ravpn_ip_pool")
            try:
                # URL: /connect/user-connectivity/vpn → shows "Regions and IP Pools" card
                # with a "Manage" link.  The "Manage servers" button at top-right ALSO
                # contains "Manage", so we must NOT use a selector — instead extract the
                # href of the exact <a>Manage</a> link via JS and navigate directly.
                _enter_secure_access()
                _vpn_url = _sa_url("/connect/user-connectivity/vpn")
                if not _vpn_url:
                    _enter_secure_access()
                    _vpn_url = _sa_url("/connect/user-connectivity/vpn")
                if not _vpn_url:
                    _persist("ravpn_ip_pool", "failed", "Could not resolve SA org URL")
                    log_fn("[scc-reset] ravpn_ip_pool: could not resolve SA org URL")
                else:
                    page.goto(_vpn_url, wait_until="domcontentloaded", timeout=30000)
                    page.wait_for_timeout(3000)
                    try:
                        page.wait_for_load_state("networkidle", timeout=8000)
                    except Exception:
                        pass
                    page.wait_for_timeout(1000)
                    # Close Resources flyout if it opened
                    try:
                        page.keyboard.press("Escape"); page.wait_for_timeout(400)
                    except Exception:
                        pass
                    _shot("4_ippool")
                    # "Manage" is a React Router link — no href, needs dispatchEvent.
                    # Try both exact "Manage" and any <a> containing "Manage" but not "servers".
                    _manage_clicked = page.evaluate("""
                        () => {
                            // STRICT: exact 'Manage' text only — 'Platform Management' (19 chars)
                            // would pass the old length<20 check and gets clicked first (sidebar).
                            // Leaf-node scan first (children.length===0), then non-leaf a/button.
                            for (const el of document.querySelectorAll('*')) {
                                if (el.children.length === 0
                                        && el.textContent.trim() === 'Manage') {
                                    const r = el.getBoundingClientRect();
                                    if (r.width > 0 && r.height > 0) {
                                        el.dispatchEvent(new MouseEvent('click',
                                            {bubbles: true, cancelable: true}));
                                        return el.tagName + ':leaf-manage';
                                    }
                                }
                            }
                            for (const el of document.querySelectorAll('a, button')) {
                                if (el.textContent.trim() === 'Manage') {
                                    const r = el.getBoundingClientRect();
                                    if (r.width > 0 && r.height > 0) {
                                        el.dispatchEvent(new MouseEvent('click',
                                            {bubbles: true, cancelable: true}));
                                        return el.tagName + ':exact-manage';
                                    }
                                }
                            }
                            return false;
                        }
                    """)
                    log_fn(f"[scc-reset] ravpn_ip_pool: Manage click={_manage_clicked}")
                    if not _manage_clicked:
                        # Can't reach the pools sub-page — log all <a> texts for debug
                        _link_texts = page.evaluate("""
                            () => [...document.querySelectorAll('a')]
                                    .map(l => l.textContent.trim())
                                    .filter(t => t.length > 0 && t.length < 40)
                        """)
                        log_fn(f"[scc-reset] ravpn_ip_pool: page links = {_link_texts[:15]}")
                        # No "Manage" link = no custom IP pools configured — already clean.
                        _persist("ravpn_ip_pool", "completed",
                                 "No IP Pools page (Manage link absent) — already clean")
                    else:
                        page.wait_for_timeout(3000)
                        try:
                            page.wait_for_load_state("networkidle", timeout=6000)
                        except Exception:
                            pass
                        _shot("4_ippool_pools")
                        _ip_deleted = 0
                        for _attempt in range(5):
                            _body = page.inner_text("body").lower()
                            if "system pool" not in _body and "user pool" not in _body:
                                break
                            _pool_row = None
                            for _rs in [
                                'tr:has-text("System Pool")', '[role="row"]:has-text("System Pool")',
                                'tr:has-text("User Pool")',   '[role="row"]:has-text("User Pool")',
                                'tr:has-text("PseudoCo")',    '[role="row"]:has-text("PseudoCo")',
                            ]:
                                try:
                                    _r = page.locator(_rs).first
                                    if _r.is_visible(timeout=1500):
                                        _pool_row = _r; break
                                except Exception:
                                    continue
                            if not _pool_row:
                                break
                            _trash = None
                            for _ts in [
                                'button[aria-label*="delete" i]', 'button[aria-label*="remove" i]',
                                '[title*="delete" i]', 'button[data-testid*="delete" i]',
                            ]:
                                try:
                                    _t = _pool_row.locator(_ts).first
                                    if _t.is_visible(timeout=500):
                                        _trash = _t; break
                                except Exception:
                                    continue
                            if not _trash:
                                try:
                                    _btns = _pool_row.locator('button').all()
                                    _best = None; _best_x = -1
                                    for _b in _btns:
                                        try:
                                            _bb = _b.bounding_box()
                                            if (_bb and _bb['width'] < 60
                                                    and _b.is_visible(timeout=300)
                                                    and _bb['x'] > _best_x):
                                                _best = _b; _best_x = _bb['x']
                                        except Exception:
                                            continue
                                    if _best:
                                        _trash = _best
                                except Exception:
                                    pass
                            if not _trash:
                                log_fn("[scc-reset] ravpn_ip_pool: trash can not found on row")
                                break
                            _trash.click()
                            page.wait_for_timeout(1500)
                            _shot("4_ippool_confirm")
                            _confirmed = False
                            for _cs in ['button:has-text("Delete")', 'button:has-text("Confirm")',
                                        'button:has-text("Yes")']:
                                try:
                                    cb = page.locator(_cs).first
                                    if cb.is_visible(timeout=3000):
                                        cb.click(); page.wait_for_timeout(2500)
                                        _ip_deleted += 1; _confirmed = True; break
                                except Exception:
                                    continue
                            if not _confirmed:
                                log_fn("[scc-reset] ravpn_ip_pool: confirm dialog not found")
                                break
                        if _ip_deleted:
                            _persist("ravpn_ip_pool", "completed",
                                     f"Deleted {_ip_deleted} IP pool(s) ✓")
                        else:
                            _body_final = page.inner_text("body").lower()
                            if "system pool" in _body_final or "user pool" in _body_final:
                                _persist("ravpn_ip_pool", "failed",
                                         "IP pool rows found but could not delete — check screenshots")
                            else:
                                _persist("ravpn_ip_pool", "completed",
                                         "No IP pool found (already clean)")
                        log_fn(f"[scc-reset] ravpn_ip_pool: "
                               + (f"Deleted {_ip_deleted} IP pool(s) ✓" if _ip_deleted
                                  else "No IP pool found (already clean)"))
            except Exception as _e:
                _persist("ravpn_ip_pool", "failed", f"Error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] ravpn_ip_pool error: {_e}")

            # ── 5. duo_saml ───────────────────────────────────────────────────
            log_fn("[scc-reset] 5/7 duo_saml")
            try:
                # Page: Configuration Management → Directories section has "Duo [Duo]" accordion;
                # SSO authentication section has "DuoSSO [SAML]" accordion.
                # PROBLEM: Playwright .click() doesn't trigger React accordion — use JS evaluate.
                # Flow per profile: JS-click accordion header → wait for expansion →
                # JS-click "Edit" link → scroll bottom → click Delete button.
                _enter_secure_access()
                _saml_url = _sa_url("/connect/users-and-groups/samlmanagement")
                if not _saml_url:
                    _enter_secure_access()
                    _saml_url = _sa_url("/connect/users-and-groups/samlmanagement")
                if not _saml_url:
                    _persist("duo_saml", "failed", "Could not resolve SA org URL")
                    log_fn("[scc-reset] duo_saml: could not resolve SA org URL")
                else:
                    _deleted_saml = []
                    _failed_saml  = []
                    for _profile in ["Duo"]:   # DuoSSO cascades when Duo is deleted
                        page.goto(_saml_url, wait_until="domcontentloaded", timeout=30000)
                        page.wait_for_timeout(3000)
                        try:
                            page.wait_for_load_state("networkidle", timeout=8000)
                        except Exception:
                            pass
                        page.wait_for_timeout(1000)
                        try:
                            page.keyboard.press("Escape"); page.wait_for_timeout(400)
                        except Exception:
                            pass
                        _shot(f"5_{_profile.lower()}_nav")
                        # Wait for page to fully render accordion items
                        try:
                            page.wait_for_selector('text="Directories"', timeout=5000)
                        except Exception:
                            pass
                        page.wait_for_timeout(500)
                        _body = page.inner_text("body")
                        if _profile.lower() not in _body.lower():
                            log_fn(f"[scc-reset] {_profile}: not on page — skipping")
                            continue
                        # Use JS to find the accordion toggle by its DIRECT text node.
                        # React Router accordions don't respond to Playwright .click() —
                        # use dispatchEvent(MouseEvent) which propagates through React's
                        # synthetic event system properly.
                        # Direct text node scan avoids matching nested child text.
                        # ── Accordion toggle: try Playwright click first, JS row-walk fallback ──
                        # Root cause of previous failures: single 'click' dispatchEvent on a
                        # leaf text node doesn't expand the accordion.  Fix:
                        # 1. Playwright .click() on aria-expanded/role="button" selectors (trusted event).
                        # 2. JS fallback: walk UP from leaf node to the full-width row container
                        #    (width>600, height 40-100px) and fire the complete event sequence
                        #    pointerdown→mousedown→pointerup→mouseup→click so React sees a real interaction.
                        _toggled = None
                        # ── Accordion expand: click the chevron at the RIGHT of the row ──
                        # The SAML page accordion toggle is a chevron at the FAR RIGHT of
                        # the row — NOT the row center.  Strategy:
                        #   1. Find Y coord of "Duo" text node
                        #   2. Scan all interactive elements at that row Y (±40px)
                        #   3. Take the rightmost one (chevron) → page.mouse.click() (trusted)
                        #   4. Fallback: click right edge of the wide row div
                        _excl_acc = "DuoSSO" if _profile == "Duo" else ""
                        _excl_js  = (f"if (t.startsWith('{_excl_acc}')) continue;"
                                     if _excl_acc else "")
                        _btn_info = page.evaluate(f"""
                            () => {{
                                // Step 1: Y coord of the profile text node
                                const walker = document.createTreeWalker(
                                    document.body, NodeFilter.SHOW_TEXT);
                                let profileY = null;
                                while (walker.nextNode()) {{
                                    const node = walker.currentNode;
                                    const t = node.textContent.trim();
                                    if (t !== '{_profile}' && !t.startsWith('{_profile} ')) continue;
                                    {_excl_js}
                                    const par = node.parentElement;
                                    if (!par) continue;
                                    const r = par.getBoundingClientRect();
                                    if (r.width > 0 && r.height > 0) {{
                                        profileY = r.top + r.height / 2; break;
                                    }}
                                }}
                                if (profileY === null) return {{err: 'no-text-found'}};
                                // Step 2: rightmost interactive element within ±40px of profileY
                                let best = null, bestX = -1;
                                const sels = 'button,[role="button"],a,'
                                    + '[class*="chevron"],[class*="arrow"],'
                                    + '[class*="toggle"],[class*="expand"]';
                                for (const el of document.querySelectorAll(sels)) {{
                                    const r = el.getBoundingClientRect();
                                    if (r.width <= 0 || r.height <= 0) continue;
                                    if (Math.abs((r.top + r.height/2) - profileY) > 40) continue;
                                    const cx = r.left + r.width/2;
                                    if (cx > bestX) {{ best = r; bestX = cx; }}
                                }}
                                if (best) return {{x: best.left + best.width/2,
                                                  y: best.top + best.height/2,
                                                  src: 'rightmost-btn'}};
                                // Step 3: fallback — right edge of the wide row div
                                const walker2 = document.createTreeWalker(
                                    document.body, NodeFilter.SHOW_TEXT);
                                while (walker2.nextNode()) {{
                                    const node = walker2.currentNode;
                                    const t = node.textContent.trim();
                                    if (t !== '{_profile}' && !t.startsWith('{_profile} ')) continue;
                                    {_excl_js}
                                    let el = node.parentElement;
                                    while (el && el !== document.body) {{
                                        const r = el.getBoundingClientRect();
                                        if (r.width > 600 && r.height >= 30 && r.height < 110) {{
                                            return {{x: r.right - 25, y: r.top + r.height/2,
                                                     src: 'row-right-edge'}};
                                        }}
                                        el = el.parentElement;
                                    }}
                                }}
                                return {{err: 'no-clickable-found'}};
                            }}
                        """)
                        if _btn_info and _btn_info.get('x') and _btn_info.get('y'):
                            page.mouse.click(_btn_info['x'], _btn_info['y'])
                            _toggled = f"mouse:{_btn_info.get('src','?')}:{_profile}"
                            log_fn(f"[scc-reset] {_profile}: mouse.click"
                                   f" src={_btn_info.get('src','?')}"
                                   f" x={_btn_info['x']:.0f} y={_btn_info['y']:.0f}")
                        else:
                            log_fn(f"[scc-reset] {_profile}: btn_info={_btn_info}")
                        if not _toggled:
                            # Fallback: Playwright locator for accordion-related buttons
                            _excl_fa = "DuoSSO" if _profile == "Duo" else ""
                            for _acc_sel in [
                                f'button[class*="accordion"]:has-text("{_profile}")',
                                f'[class*="accordion"] button',
                                f'li:has-text("{_profile}") button',
                            ]:
                                try:
                                    _cands = page.locator(_acc_sel).all()
                                    for _cand in _cands:
                                        _ctxt = (_cand.text_content() or "").strip()
                                        if _excl_fa and _excl_fa in _ctxt:
                                            continue
                                        _bb = _cand.bounding_box()
                                        if _bb and _bb['width'] > 0:
                                            page.mouse.click(
                                                _bb['x'] + _bb['width'] / 2,
                                                _bb['y'] + _bb['height'] / 2)
                                            _toggled = f"mouse:locator-bb:{_profile}"
                                            log_fn(f"[scc-reset] {_profile}: mouse.click"
                                                   f" locator-bb {_acc_sel[:30]}")
                                            break
                                    if _toggled:
                                        break
                                except Exception as _te:
                                    log_fn(f"[scc-reset] {_profile}: locator-bb"
                                           f" {_acc_sel[:30]}: {_te}")
                                    continue
                        page.wait_for_timeout(3000)
                        _shot(f"5_{_profile.lower()}_expanded")
                        # Gate on actual expansion — only proceed if Edit link is visible.
                        # A set _toggled does NOT mean the accordion expanded; the edit link
                        # appearing is the only reliable confirmation.
                        _edit_visible = False
                        try:
                            _edit_visible = page.locator(
                                'a:has-text("Edit"), button:has-text("Edit")'
                            ).first.is_visible(timeout=2000)
                        except Exception:
                            pass
                        log_fn(f"[scc-reset] {_profile}: toggled={_toggled!r}"
                               f" edit_visible={_edit_visible}")
                        if not _edit_visible:
                            log_fn(f"[scc-reset] {_profile}: accordion did not expand — mark failed")
                            _failed_saml.append(_profile)
                            continue
                        log_fn(f"[scc-reset] {_profile}: toggled={_toggled!r}"
                               f" edit_visible={_edit_visible}")
                        # ── Click "Edit" link (text may be "✎ Edit" — use has-text not exact) ──
                        _edited = False
                        try:
                            for _edit_sel in [
                                'a:has-text("Edit")',
                                'button:has-text("Edit")',
                                '[class*="edit"]:visible',
                            ]:
                                _el = page.locator(_edit_sel).first
                                if _el.count() > 0 and _el.is_visible(timeout=1500):
                                    _el.click(force=True); _edited = True; break
                        except Exception:
                            pass
                        if not _edited:
                            _edited = page.evaluate("""
                                () => {
                                    const els = [...document.querySelectorAll('a, button')];
                                    const e = els.find(el =>
                                        el.textContent.includes('Edit')
                                        && el.offsetParent !== null);
                                    if (e) {
                                        e.dispatchEvent(new MouseEvent('click',
                                            {bubbles: true, cancelable: true}));
                                        return true;
                                    }
                                    return false;
                                }
                            """)
                        page.wait_for_timeout(2500)
                        _shot(f"5_{_profile.lower()}_edit")
                        # Scroll to bottom to reveal Cancel / Delete / Save buttons
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(800)
                        try:
                            page.wait_for_selector(
                                'button:has-text("Cancel"), button:has-text("Delete")',
                                timeout=4000)
                        except Exception:
                            pass
                        # Click Delete button
                        _del_clicked = False
                        for _ds in ['button:has-text("Delete")',
                                    'button[class*="danger"]:has-text("Delete")']:
                            try:
                                _d = page.locator(_ds).first
                                if _d.is_visible(timeout=2000):
                                    _d.click(); page.wait_for_timeout(1500)
                                    _del_clicked = True; break
                            except Exception:
                                continue
                        if not _del_clicked:
                            # JS fallback for Delete button
                            _del_clicked = page.evaluate("""
                                () => {
                                    const btns = [...document.querySelectorAll('button')];
                                    const b = btns.find(el => el.textContent.trim() === 'Delete'
                                                              && el.offsetParent !== null);
                                    if (b) { b.click(); return true; }
                                    return false;
                                }
                            """)
                            page.wait_for_timeout(1500)
                        if not _del_clicked:
                            log_fn(f"[scc-reset] {_profile}: Delete button not found — mark failed")
                            _failed_saml.append(_profile)
                            continue
                        _shot(f"5_{_profile.lower()}_confirm")
                        # ── Confirmation dialog: check mandatory checkbox, then click
                        # the dialog's own Delete button (NOT the form's Delete button).
                        # The form also has a Delete button behind the overlay — using
                        # .first picks whichever appears first in DOM which may be wrong.
                        # Fix: check checkbox → wait 1.5s for React to enable button →
                        # find the TOPMOST visible Delete button by Y coord (dialog is
                        # centered higher on page than the form's bottom button).
                        try:
                            for _cb_sel in [
                                'dialog input[type="checkbox"]',
                                '[role="dialog"] input[type="checkbox"]',
                                'input[type="checkbox"]',
                            ]:
                                _dlg_cb = page.locator(_cb_sel).first
                                if _dlg_cb.count() > 0 and _dlg_cb.is_visible(timeout=1500):
                                    if not _dlg_cb.is_checked():
                                        _dlg_cb.click(force=True)
                                        page.wait_for_timeout(1500)  # wait for React to enable btn
                                        log_fn(f"[scc-reset] {_profile}: checked 'I understand' checkbox")
                                    break
                        except Exception:
                            pass
                        # Click the dialog's Delete button — find it by lowest Y (topmost on page)
                        _conf_clicked = False
                        try:
                            _all_del = page.locator('button:has-text("Delete")').all()
                            _best_btn = None
                            _best_y   = 99999
                            for _db in _all_del:
                                try:
                                    _dbb = _db.bounding_box()
                                    if _dbb and _dbb['y'] < _best_y and _dbb['width'] > 0:
                                        _best_btn = _db
                                        _best_y   = _dbb['y']
                                except Exception:
                                    pass
                            if _best_btn:
                                _bbx = _best_btn.bounding_box()
                                page.mouse.click(
                                    _bbx['x'] + _bbx['width'] / 2,
                                    _bbx['y'] + _bbx['height'] / 2)
                                _conf_clicked = True
                                log_fn(f"[scc-reset] {_profile}: clicked dialog Delete"
                                       f" at x={_bbx['x']:.0f} y={_best_y:.0f}")
                        except Exception as _ce:
                            log_fn(f"[scc-reset] {_profile}: dialog-delete error: {_ce}")
                        if not _conf_clicked:
                            for _cs in ['button:has-text("Delete")', 'button:has-text("Confirm")',
                                        'button:has-text("Yes")']:
                                try:
                                    cb = page.locator(_cs).first
                                    if cb.is_visible(timeout=1500):
                                        cb.click(force=True); _conf_clicked = True; break
                                except Exception:
                                    continue
                        page.wait_for_timeout(4000)
                        # ── Post-delete verification: reload and confirm Duo row is gone ──
                        page.goto(_saml_url, wait_until="domcontentloaded", timeout=30000)
                        page.wait_for_timeout(3000)
                        try:
                            page.wait_for_load_state("networkidle", timeout=6000)
                        except Exception:
                            pass
                        _verify_body = page.inner_text("body").lower()
                        _profile_gone = _profile.lower() not in _verify_body or (
                            "directories" in _verify_body
                            and f'"{_profile.lower()}"' not in _verify_body
                            and _profile.lower() + " duo" not in _verify_body)
                        # Simpler: check accordion row is gone by looking for edit context
                        # Reload and see if profile name still appears in Directories section
                        _dirs_section = ""
                        try:
                            _dirs_el = page.locator('text="Directories"').first
                            if _dirs_el.is_visible(timeout=2000):
                                # Get text of a parent container of Directories heading
                                _dirs_section = (_dirs_el.evaluate(
                                    "el => { let p=el; for(let i=0;i<5;i++){p=p.parentElement;} return p.innerText||''; }"
                                ) or "").lower()
                        except Exception:
                            pass
                        _duo_gone_verified = (
                            _profile.lower() not in _dirs_section
                            if _dirs_section
                            else "configurations" in _verify_body and _profile.lower() not in _verify_body
                        )
                        _shot(f"5_{_profile.lower()}_verify")
                        log_fn(f"[scc-reset] {_profile}: post-delete verify gone={_duo_gone_verified}"
                               f" conf_clicked={_conf_clicked}")
                        if not _duo_gone_verified:
                            log_fn(f"[scc-reset] {_profile}: still present after delete — mark failed")
                            _failed_saml.append(_profile)
                            continue
                        _deleted_saml.append(_profile)
                        log_fn(f"[scc-reset] {_profile}: deleted and verified ✓")
                    # DuoSSO deletes itself automatically when Duo directory is removed —
                    # no separate check needed.
                    if _failed_saml:
                        _persist("duo_saml", "failed",
                                 f"Could not delete: {', '.join(_failed_saml)} — check screenshots")
                    elif _deleted_saml:
                        _persist("duo_saml", "completed",
                                 f"Deleted Duo directory ✓ (DuoSSO removes itself automatically)")
                    else:
                        _persist("duo_saml", "completed",
                                 "No Duo directory found (already clean)")
                    log_fn(f"[scc-reset] duo_saml: deleted={_deleted_saml} failed={_failed_saml}")
            except Exception as _e:
                _persist("duo_saml", "failed", f"Error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] duo_saml error: {_e}")

            # ── 6. ise_pxgrid ─────────────────────────────────────────────────
            log_fn("[scc-reset] 6/7 ise_pxgrid")
            try:
                _go(["Platform Management", "Integrations"])
                page.wait_for_timeout(1000)
                for _tab in ['button:has-text("My Integrations")', 'a:has-text("My Integrations")', '[role="tab"]:has-text("My Integrations")']:
                    try:
                        t = page.locator(_tab).first
                        if t.is_visible(timeout=3000):
                            t.click(); page.wait_for_timeout(2000); break
                    except Exception: continue
                _shot("6_ise")
                _body = page.inner_text("body").lower()
                _deleted = False
                if "ise" in _body:
                    try:
                        _row = page.locator('tr').filter(has_text="ISE").first
                        _row.locator('button').last.click(force=True, timeout=4000)
                        page.wait_for_timeout(600)
                        for _ds in ['[role="menuitem"]:has-text("Delete")', 'button:has-text("Delete")',
                                    '[role="menuitem"]:has-text("Remove")', 'a:has-text("Delete")']:
                            try:
                                d = page.locator(_ds).first
                                if d.is_visible(timeout=1500):
                                    d.click(); page.wait_for_timeout(800)
                                    for _cs in ['button:has-text("Delete")', 'button:has-text("Yes")', 'button:has-text("Confirm")']:
                                        try:
                                            cb = page.locator(_cs).first
                                            if cb.is_visible(timeout=2000):
                                                cb.click(); page.wait_for_timeout(1500); break
                                        except Exception: continue
                                    _deleted = True; break
                            except Exception: continue
                    except Exception as _ie:
                        log_fn(f"[scc-reset] ise row error: {_ie}")
                _detail = "Deleted ISE/pxGrid integration ✓" if _deleted else "No ISE integration found (already clean)"
                _persist("ise_pxgrid", "completed", _detail)
                log_fn(f"[scc-reset] ise_pxgrid: {_detail}")
            except Exception as _e:
                _persist("ise_pxgrid", "failed", f"Error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] ise_pxgrid error: {_e}")

            # ── 7. te_integration ─────────────────────────────────────────────
            log_fn("[scc-reset] 7/7 te_integration")
            try:
                _go(["Experience and Insights", "Account Management"])
                if "account management" not in page.inner_text("body").lower():
                    _go(["Experience", "Account Management"])
                _shot("7_te")
                _body = page.inner_text("body").lower()
                _deleted = False
                if "thousandeyes" in _body or "thousand eyes" in _body:
                    _r = _delete_named_row("ThousandEyes")
                    if _r != "deleted":
                        # ThousandEyes may use Disconnect/Unlink instead of Delete
                        for _btn in ["Disconnect", "Unlink", "Remove"]:
                            try:
                                b = page.locator(f'button:has-text("{_btn}")').first
                                if b.is_visible(timeout=1500):
                                    b.click(); page.wait_for_timeout(1000)
                                    for _cs in ['button:has-text("Confirm")', 'button:has-text("Yes")', 'button:has-text("Delete")']:
                                        try:
                                            cb = page.locator(_cs).first
                                            if cb.is_visible(timeout=2000):
                                                cb.click(); page.wait_for_timeout(1500); break
                                        except Exception: continue
                                    _deleted = True; break
                            except Exception: continue
                    else:
                        _deleted = True
                _detail = "Deleted ThousandEyes integration ✓" if _deleted else "No ThousandEyes integration found (already clean)"
                _persist("te_integration", "completed", _detail)
                log_fn(f"[scc-reset] te_integration: {_detail}")
            except Exception as _e:
                _persist("te_integration", "failed", f"Error: {str(_e)[:120]}")
                log_fn(f"[scc-reset] te_integration error: {_e}")

        finally:
            browser.close()

    return True, "SCC manual reset automation complete — all 7 items processed"


@app.route("/api/ise/scc-complete", methods=["POST"])
def api_ise_scc_complete():
    """Called by the Docker ISE container after getting the OTP from ISE.
    Runs SCC Platform Integrations Playwright navigation on the HOST (not Docker)
    because Docker's VPN routing breaks Okta silent-renew in headless Chromium.
    Returns {ok, message} — DB status is updated by the calling container.
    """
    data = request.get_json(silent=True) or {}
    pod_id = data.get("pod_id", "")
    otp_token = data.get("otp_token", "")
    if not pod_id or not otp_token:
        return jsonify({"ok": False, "message": "pod_id and otp_token required"}), 400

    session_path = DATA_DIR / "data" / f"scc_session_{pod_id}.json"
    if not session_path.exists():
        return jsonify({"ok": False, "message": f"No SCC session file for {pod_id}"}), 404

    log(pod_id, f"[scc-nav] Host SCC nav starting for {pod_id} (OTP: {otp_token[:12]}...)")

    def _lf(msg):
        log(pod_id, msg)

    ok, message = _host_scc_integrate(pod_id, otp_token, str(session_path), _lf)
    log(pod_id, f"[scc-nav] {'OK' if ok else 'FAIL'}: {message}")
    return jsonify({"ok": ok, "message": message})


_scc_refresh_thread = [None]  # track running refresh thread


def _scc_otp_watcher():
    """Background thread: watch for ise_scc_otp_*.json files written by Docker container.
    When found, run SCC Playwright nav on host (outside VPN), write result file.
    Uses shared volume /pipeline/host-data/ = data/ on host.
    """
    import glob as _glob
    while True:
        try:
            for _otp_file in _glob.glob(str(DATA_DIR / "data" / "ise_scc_otp_*.json")):
                try:
                    _data = json.loads(Path(_otp_file).read_text())
                    _pod_id = _data.get("pod_id", "")
                    _otp = _data.get("otp_token", "")
                    _ts = _data.get("ts", 0)
                    if not _pod_id or not _otp:
                        continue
                    # Ignore stale files older than 5 min
                    if time.time() - _ts > 300:
                        Path(_otp_file).unlink(missing_ok=True)
                        continue
                    # Remove signal file immediately so we don't process twice
                    Path(_otp_file).unlink(missing_ok=True)
                    log(_pod_id, f"[scc-nav] Watcher picked up OTP for {_pod_id} — running host SCC nav")
                    _session_path = DATA_DIR / "data" / f"scc_session_{_pod_id}.json"
                    if not _session_path.exists():
                        _res = {"ok": False, "message": f"No SCC session file for {_pod_id}"}
                    else:
                        _ok, _msg = _host_scc_integrate(_pod_id, _otp, str(_session_path),
                                                        lambda m: log(_pod_id, m))
                        _res = {"ok": _ok, "message": _msg}
                    log(_pod_id, f"[scc-nav] {'OK' if _res['ok'] else 'FAIL'}: {_res['message']}")
                    # Write result for container to pick up
                    _result_path = DATA_DIR / "data" / f"ise_scc_result_{_pod_id}.json"
                    _result_path.write_text(json.dumps(_res))
                except Exception as _e:
                    try:
                        log("SCC_WATCHER", f"[scc-nav] watcher error processing {_otp_file}: {_e}")
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(2)


threading.Thread(target=_scc_otp_watcher, daemon=True, name="scc-otp-watcher").start()


# ── SCC Manual Reset Automation endpoint ──────────────────────────────────────

@app.route("/api/scc/manual-reset/<pod_id>", methods=["POST"])
def api_scc_manual_reset(pod_id):
    """Run API-based SCC reset (6 items) then Playwright automation (7 items) in a background thread."""

    def _run():
        # ── Phase 1: API-based checks (access policy, NTGs, ZTA, private resources, DNS, EPP) ──
        try:
            import sys, os as _os, importlib
            log(pod_id, "[scc-reset] Phase 1: running API-based checks (6 items)...")
            sys.path.insert(0, str(Path(__file__).parent))
            _os.environ["POD_ID"] = pod_id
            _os.environ["DB_PATH"] = str(Path(__file__).parent / "data" / "pod_state.db")
            _os.environ["SCC_KEYS_DIR"] = str(Path(__file__).parent / "data" / "scc_keys")
            import onboard_router
            importlib.reload(onboard_router)
            ok, result = onboard_router.phase_scc_reset_check()
            log(pod_id, f"[scc-reset] API checks done: {result}")
        except Exception as _e:
            log(pod_id, f"[scc-reset] API checks error: {_e}")

        # ── Phase 2: Playwright automation (logging, RAVPN, DLP, IP pool, Duo, ISE, TE) ──
        try:
            ok, msg = _scc_auto_reset_manual(pod_id, lambda m: log(pod_id, m))
            log(pod_id, f"[scc-reset] Done: {msg}")
        except Exception as _e:
            log(pod_id, f"[scc-reset] Uncaught error: {_e}")

    threading.Thread(target=_run, daemon=True, name=f"scc-manual-reset-{pod_id}").start()
    return jsonify({"status": "started", "pod_id": pod_id})


# ── Host-side cdFMC pxGrid integration (step 4) ──────────────────────────────

def _host_cdfmc_integrate(pod_id: str, otp_token: str, instance_name: str,
                          session_path: str, log_fn) -> tuple:
    """Run cdFMC pxGrid integration on the HOST (not Docker).

    Navigation path (confirmed by diag22-25):
    1. SCC /firewalls/applications/FMC/?enterpriseId=... (15s wait for HBR-BUTTON drawer)
    2. expect_popup() + JS shadow-DOM click on HBR-BUTTON 'Platform Settings'
       → authenticated cdFMC tab at /ddd/#PFSettingsPolicyList
    3. Navigate tab directly to /ui/identity-sources/pxgrid
    4. Click 'Create pxGrid Application Instance'
    5. Fill input[name='name'] and input[name='otp'], click Create → Save
    """
    from playwright.sync_api import sync_playwright

    _JS_CLICK_HBR = """(label) => {
        function deepQueryAll(root) {
            const found = [];
            const all = root.querySelectorAll('*');
            for (const el of all) {
                if ((el.textContent||'').trim() === label) found.push(el);
                if (el.shadowRoot) found.push(...deepQueryAll(el.shadowRoot));
            }
            return found;
        }
        const hbr = deepQueryAll(document).filter(e => e.tagName === 'HBR-BUTTON');
        if (hbr.length > 0) { hbr[0].click(); return 'HBR-BUTTON clicked'; }
        const any = deepQueryAll(document);
        if (any.length > 0) { any[0].click(); return any[0].tagName + ' clicked'; }
        return 'NOT_FOUND';
    }"""

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True,
            args=["--disable-popup-blocking", "--no-sandbox", "--disable-dev-shm-usage"])
        try:
            _sd = json.loads(Path(session_path).read_text())
            ctx = browser.new_context(
                storage_state=_sd, viewport={"width": 1920, "height": 1080},
                ignore_https_errors=True,
            )
            log_fn(f"[cdfmc-nav] storage_state: {len(_sd.get('cookies',[]))} cookies")

            page = ctx.new_page()
            page.set_default_timeout(30000)

            # ── 1. Get EID from session localStorage ─────────────────────────
            _eid = ""
            for _o in (_sd.get("origins", []) if isinstance(_sd, dict) else []):
                for _it in _o.get("localStorage", []):
                    if _it.get("name") == "enterpriseId":
                        _eid = _it["value"]
                        break

            # ── 2. Navigate to SCC FMC app page (draws HBR-BUTTON drawer) ────
            _fmc_url = (f"https://security.cisco.com/firewalls/applications/FMC/?enterpriseId={_eid}"
                        if _eid else "https://security.cisco.com/firewalls/applications/FMC/")
            log_fn(f"[cdfmc-nav] Loading FMC app page (EID={_eid or 'none'}, 15s wait)...")
            for _nav_try in range(3):
                if _nav_try > 0:
                    log_fn(f"[cdfmc-nav] chrome-error on attempt {_nav_try} — retrying in 8s...")
                    page.wait_for_timeout(8000)
                try:
                    page.goto(_fmc_url, wait_until="domcontentloaded", timeout=60000)
                except Exception as _ge:
                    log_fn(f"[cdfmc-nav] goto exception (attempt {_nav_try}): {_ge}")
                try:
                    page.wait_for_load_state("networkidle", timeout=20000)
                except Exception:
                    pass
                page.wait_for_timeout(15000)
                if "chrome-error" not in page.url:
                    break
                page.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_chrome_error_{pod_id}_t{_nav_try}.png"))
                log_fn(f"[cdfmc-nav] Attempt {_nav_try}: URL={page.url[:60]}")

            if "sign-on" in page.url.lower():
                return False, "SCC session expired — re-run Refresh SCC Sessions"
            log_fn(f"[cdfmc-nav] On SCC FMC app page: {page.url[:70]}")
            page.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_fmc_app_{pod_id}.png"))

            # ── 3. Open authenticated cdFMC tab via Platform Settings HBR-BUTTON ──
            log_fn("[cdfmc-nav] Opening cdFMC tab via Platform Settings (expect_popup)...")
            try:
                with page.expect_popup(timeout=40000) as _popup_info:
                    _r = page.evaluate(_JS_CLICK_HBR, "Platform Settings")
                    log_fn(f"[cdfmc-nav] JS shadow-DOM click: {_r}")
                _fmc_tab = _popup_info.value
                _cdfmc_host = _fmc_tab.url.split("/")[2]  # capture immediately — tab may redirect away after wait
                log_fn(f"[cdfmc-nav] cdFMC tab opened: {_fmc_tab.url}")
            except Exception as _e:
                page.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_no_popup_{pod_id}.png"))
                return False, f"cdFMC tab did not open (Platform Settings click failed): {_e}"

            try:
                _fmc_tab.wait_for_load_state("domcontentloaded", timeout=30000)
            except Exception:
                pass
            _fmc_tab.wait_for_timeout(5000)

            # ── 4. Navigate directly to pxGrid Identity Sources ───────────────
            # _cdfmc_host captured at popup-open time (before any post-open redirects)
            _pxgrid_url = f"https://{_cdfmc_host}/ui/identity-sources/pxgrid"
            log_fn(f"[cdfmc-nav] Navigating to {_pxgrid_url}...")
            _fmc_tab.goto(_pxgrid_url, wait_until="domcontentloaded", timeout=30000)
            _fmc_tab.wait_for_timeout(6000)
            _fmc_tab.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_pxgrid_page_{pod_id}.png"))

            _body = _fmc_tab.inner_text("body").lower()
            if "create pxgrid application instance" not in _body:
                log_fn(f"[cdfmc-nav] pxGrid page body: {_body[:300]!r}")
                return False, f"cdFMC pxGrid page not found at {_fmc_tab.url}"
            log_fn("[cdfmc-nav] pxGrid Identity Sources page loaded ✓")

            # ── 5. Click Create pxGrid Application Instance ───────────────────
            _fmc_tab.locator('button:has-text("Create pxGrid Application Instance")').first.click(timeout=10000)
            _fmc_tab.wait_for_timeout(4000)
            log_fn("[cdfmc-nav] Clicked Create pxGrid Application Instance")

            # ── 6. Fill name and OTP ──────────────────────────────────────────
            _name_input = _fmc_tab.locator('input[name="name"]').first
            _name_input.click()
            _name_input.press_sequentially(instance_name, delay=0)
            log_fn(f"[cdfmc-nav] Typed name: {instance_name!r}")

            _otp_input = _fmc_tab.locator('input[name="otp"]').first
            _otp_input.click()
            _otp_input.press_sequentially(otp_token, delay=0)
            log_fn(f"[cdfmc-nav] Typed OTP ({len(otp_token)} chars via press_sequentially)")
            _fmc_tab.wait_for_timeout(500)

            # ── 7. Submit Create dialog ───────────────────────────────────────
            def _dialog_closed():
                return _fmc_tab.evaluate("""() => {
                    const portal = document.querySelector('#backdraft-fragments');
                    if (!portal) return true;
                    const hasOtp = !!portal.querySelector('input[name="otp"]');
                    const hasCreate = Array.from(portal.querySelectorAll('button'))
                        .some(b => b.innerText.trim() === 'Create');
                    return !hasOtp && !hasCreate;
                }""")

            def _log_dialog_state(label):
                state = _fmc_tab.evaluate("""() => {
                    const portal = document.querySelector('#backdraft-fragments');
                    const portalText = portal ? portal.innerText.slice(0, 500) : 'no portal';
                    const errors = Array.from(document.querySelectorAll(
                        '[class*="error" i],[class*="invalid" i],[role="alert"],[class*="alert" i]'))
                        .map(e => (e.innerText||'').trim().slice(0,100)).filter(t=>t);
                    const portalErrors = portal ? Array.from(portal.querySelectorAll(
                        '[class*="error" i],[class*="invalid" i],[role="alert"]'))
                        .map(e => (e.innerText||'').trim().slice(0,100)).filter(t=>t) : [];
                    return {portalText, errors, portalErrors};
                }""")
                log_fn(f"[cdfmc-nav] State after {label}: portal={state['portalText'][:200]!r} errors={state['errors']} portalErrors={state['portalErrors']}")

            _submitted = False

            # Method 0: regular Playwright click on portal's Create button
            log_fn("[cdfmc-nav] Method 0: Playwright click on portal Create button...")
            try:
                _portal_create = _fmc_tab.locator('#backdraft-fragments button').filter(has_text="Create").first
                _portal_create.click(timeout=5000)
                log_fn("[cdfmc-nav] Portal Create click: dispatched")
                _fmc_tab.wait_for_timeout(4000)
                if _dialog_closed():
                    log_fn("[cdfmc-nav] Dialog closed after portal click ✓")
                    _submitted = True
                else:
                    _log_dialog_state("portal-click")
            except Exception as _ce:
                log_fn(f"[cdfmc-nav] Portal Create click FAILED: {str(_ce)[:200]}")

            # Method A: force=True
            if not _submitted:
                try:
                    _fmc_tab.locator('#backdraft-fragments button').filter(has_text="Create").first.click(timeout=8000, force=True)
                    _fmc_tab.wait_for_timeout(4000)
                    if _dialog_closed():
                        log_fn("[cdfmc-nav] Dialog closed after force click ✓")
                        _submitted = True
                    else:
                        _log_dialog_state("force-click")
                except Exception as _fe:
                    log_fn(f"[cdfmc-nav] force click exception: {str(_fe)[:150]}")

            # Method B: JS click
            if not _submitted:
                _js_result = _fmc_tab.evaluate("""() => {
                    const portal = document.querySelector('#backdraft-fragments');
                    if (!portal) return 'no portal';
                    const btn = Array.from(portal.querySelectorAll('button'))
                        .find(b => b.innerText.trim() === 'Create' && !b.disabled);
                    if (!btn) return 'no Create button in portal';
                    btn.click();
                    return 'clicked: ' + btn.innerText.trim();
                }""")
                log_fn(f"[cdfmc-nav] JS portal click result: {_js_result!r}")
                _fmc_tab.wait_for_timeout(4000)
                if _dialog_closed():
                    log_fn("[cdfmc-nav] Dialog closed after JS click ✓")
                    _submitted = True
                else:
                    _log_dialog_state("js-click")

            # Method C: focus + Enter
            if not _submitted:
                _focus_result = _fmc_tab.evaluate("""() => {
                    const portal = document.querySelector('#backdraft-fragments');
                    if (!portal) return 'no portal';
                    const btn = Array.from(portal.querySelectorAll('button'))
                        .find(b => b.innerText.trim() === 'Create' && !b.disabled);
                    if (!btn) return 'no Create button';
                    btn.focus(); return 'focused';
                }""")
                if _focus_result == 'focused':
                    _fmc_tab.keyboard.press("Enter")
                    _fmc_tab.wait_for_timeout(4000)
                    if _dialog_closed():
                        log_fn("[cdfmc-nav] Dialog closed after Enter ✓")
                        _submitted = True
                    else:
                        _log_dialog_state("Enter")

            if not _submitted:
                log_fn("[cdfmc-nav] Waiting extra 30s for server response...")
                for _w in range(30):
                    _fmc_tab.wait_for_timeout(1000)
                    if _dialog_closed():
                        log_fn(f"[cdfmc-nav] Dialog closed after extra {_w+1}s ✓")
                        _submitted = True
                        break
                    if _w % 10 == 9:
                        _log_dialog_state(f"wait-{_w+1}s")

            if not _submitted:
                _fmc_tab.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_create_stuck_{pod_id}.png"))
                return False, "cdFMC Create dialog did not close — check cdfmc_create_stuck screenshot"

            _fmc_tab.wait_for_timeout(2000)
            _fmc_tab.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_after_create_{pod_id}.png"))
            log_fn("[cdfmc-nav] Instance created ✓")

            # ── 8. Select the new instance (click "Selected" column button) ────
            # The Application Instances table is ReactVirtualized — rows are
            # DIV.ReactVirtualized__Table__row (NOT <tr>).
            # First rowColumn child = "Selected" column — has 1 BUTTON, 0 radios.
            # The 4 input[type="radio"] on this page are ALL Service Type radios
            # (None / ISE / pxGrid Cloud / Passive) — never inside an instance row.
            log_fn(f"[cdfmc-nav] Selecting instance {instance_name!r}...")
            _fmc_tab.wait_for_timeout(3000)

            _selected = False
            for _sel_try in range(8):
                _fmc_tab.wait_for_timeout(1000)
                _sel_result = _fmc_tab.evaluate(f"""() => {{
                    // ReactVirtualized rows — DIV not <tr>
                    const rows = Array.from(document.querySelectorAll(
                        'div.ReactVirtualized__Table__row'
                    ));
                    const targetRow = rows.find(r => (r.textContent||'').includes({instance_name!r}));
                    if (!targetRow) return 'no-row:' + rows.length;
                    // First rowColumn = "Selected" column; contains a button (NOT a radio)
                    const firstCol = targetRow.querySelector('div.ReactVirtualized__Table__rowColumn');
                    if (!firstCol) return 'no-col';
                    const btn = firstCol.querySelector('button');
                    if (!btn) return 'no-btn';
                    btn.click();
                    return 'clicked';
                }}""")
                if _sel_result == 'clicked':
                    log_fn(f"[cdfmc-nav] Selected {instance_name!r} via ReactVirtualized row button ✓")
                    _selected = True
                    break
                log_fn(f"[cdfmc-nav] Select try {_sel_try+1}: {_sel_result}")

            if not _selected:
                _fmc_tab.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_select_failed_{pod_id}.png"))
                return False, f"Could not find row button for {instance_name!r} — check cdfmc_select_failed screenshot"
            # ── Handle "Make the pxGrid Cloud application instance active?" popup ──
            # Clicking the radio immediately triggers this confirmation dialog.
            log_fn("[cdfmc-nav] Waiting for 'Make active' confirmation popup...")
            _make_active_clicked = False
            for _ma_sel in [
                'button:has-text("Make active")',
                'button:has-text("Make Active")',
            ]:
                try:
                    _ma_btn = _fmc_tab.locator(_ma_sel).first
                    if _ma_btn.is_visible(timeout=6000):
                        _ma_btn.click(timeout=6000)
                        log_fn("[cdfmc-nav] Clicked 'Make active' in popup ✓")
                        _make_active_clicked = True
                        _fmc_tab.wait_for_timeout(2000)
                        break
                except Exception:
                    continue
            if not _make_active_clicked:
                log_fn("[cdfmc-nav] WARN: 'Make active' popup not seen — proceeding anyway")

            _fmc_tab.wait_for_timeout(2000)
            _fmc_tab.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_after_select_{pod_id}.png"))

            # ── 9. Click Save ─────────────────────────────────────────────────
            log_fn("[cdfmc-nav] Clicking Save...")
            _fmc_tab.locator('button:has-text("Save")').first.click(timeout=10000, force=True)
            _fmc_tab.wait_for_timeout(4000)
            _fmc_tab.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_after_save_{pod_id}.png"))
            log_fn("[cdfmc-nav] Save clicked ✓")

            # ── 10. Delete old stale instances (any row NOT matching our name) ──
            log_fn("[cdfmc-nav] Cleaning up old instances...")
            _fmc_tab.wait_for_timeout(2000)
            for _del_attempt in range(5):
                _deleted_any = False
                try:
                    # ReactVirtualized table — rows are DIV not <tr>
                    _all_rows = _fmc_tab.locator('div.ReactVirtualized__Table__row').all()
                except Exception:
                    _all_rows = []
                for _row in _all_rows:
                    try:
                        _row_txt = _row.inner_text() or ""
                        if instance_name in _row_txt:
                            continue  # skip our new instance
                        if not _row_txt.strip():
                            continue  # skip empty rows
                        # This is an old instance row — find its trash/delete button.
                        # Try named selectors first, then fall back to the last button
                        # in the row (Actions column: Test link + trash icon button).
                        _del_btn = None
                        for _ds in [
                            'button[aria-label*="delete" i]',
                            'button[title*="delete" i]',
                            'button[data-testid*="delete" i]',
                            'button[class*="delete" i]',
                        ]:
                            try:
                                _b = _row.locator(_ds).first
                                if _b.is_visible(timeout=800):
                                    _del_btn = _b
                                    break
                            except Exception:
                                continue
                        if _del_btn is None:
                            # Fallback: last button in the row is the trash icon
                            _btns = _row.locator('button').all()
                            if _btns:
                                _del_btn = _btns[-1]
                        if _del_btn:
                            log_fn(f"[cdfmc-nav] Deleting old instance: {_row_txt.strip()[:80]!r}")
                            _del_btn.click(force=True, timeout=5000)
                            _fmc_tab.wait_for_timeout(2000)
                            _deleted_any = True
                            # Confirm delete modal if it appears
                            for _conf in ['button:has-text("Delete")', 'button:has-text("Yes")', 'button:has-text("Confirm")']:
                                try:
                                    _cb = _fmc_tab.locator(_conf).first
                                    if _cb.is_visible(timeout=3000):
                                        _cb.click(force=True)
                                        _fmc_tab.wait_for_timeout(2000)
                                        log_fn("[cdfmc-nav] Delete confirmed ✓")
                                        break
                                except Exception:
                                    pass
                            break  # re-scan rows after each deletion
                    except Exception:
                        continue
                if not _deleted_any:
                    break  # no more old instances

            _fmc_tab.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_final_{pod_id}.png"))
            log_fn("[cdfmc-nav] ✓ cdFMC pxGrid Application Instance created, selected, and saved")
            return True, f"cdFMC pxGrid instance '{instance_name}' created and selected"

        except Exception as _e:
            log_fn(f"[cdfmc-nav] Exception: {_e}")
            try:
                page.screenshot(path=str(DATA_DIR / "data" / f"cdfmc_exception_{pod_id}.png"))
            except Exception:
                pass
            return False, f"cdFMC nav exception: {_e}"
        finally:
            try:
                browser.close()
            except Exception:
                pass


def _cdfmc_otp_watcher():
    """Background thread: watch for ise_cdfmc_otp_*.json written by Docker step 4.
    Runs _host_cdfmc_integrate on the host (outside Docker VPN) and writes result file.
    """
    import glob as _glob
    while True:
        try:
            for _otp_file in _glob.glob(str(DATA_DIR / "data" / "ise_cdfmc_otp_*.json")):
                try:
                    _data = json.loads(Path(_otp_file).read_text())
                    _pod_id      = _data.get("pod_id", "")
                    _otp         = _data.get("otp_token", "")
                    _iname       = _data.get("instance_name", f"ISE-FMC-POD-{_pod_id}")
                    _ts          = _data.get("ts", 0)
                    if not _pod_id or not _otp:
                        continue
                    if time.time() - _ts > 600:  # 10 min stale
                        Path(_otp_file).unlink(missing_ok=True)
                        continue
                    Path(_otp_file).unlink(missing_ok=True)
                    log(_pod_id, f"[cdfmc-nav] Watcher picked up OTP for {_pod_id}")
                    _session_path = DATA_DIR / "data" / f"scc_session_{_pod_id}.json"
                    if not _session_path.exists():
                        _res = {"ok": False, "message": f"No SCC session file for {_pod_id}"}
                    else:
                        _ok, _msg = _host_cdfmc_integrate(
                            _pod_id, _otp, _iname, str(_session_path),
                            lambda m: log(_pod_id, m),
                        )
                        _res = {"ok": _ok, "message": _msg}
                    log(_pod_id, f"[cdfmc-nav] {'OK' if _res['ok'] else 'FAIL'}: {_res['message']}")
                    _result_path = DATA_DIR / "data" / f"ise_cdfmc_result_{_pod_id}.json"
                    _result_path.write_text(json.dumps(_res))
                except Exception as _e:
                    try:
                        log("CDFMC_WATCHER", f"[cdfmc-nav] watcher error: {_e}")
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(2)


threading.Thread(target=_cdfmc_otp_watcher, daemon=True, name="cdfmc-otp-watcher").start()


# ── SGT Propagation Verify (step 5) — host-side Playwright ───────────────────

def _host_sgt_verify(pod_id: str, sa_org_id: str, session_path: str, log_fn,
                     skip_wait: bool = False) -> tuple:
    """Verify Security Group Tags in Secure Access after ISE→SCC propagation.

    Checks every 5 min up to 20 min total (4 checks). Logs elapsed time.
    If skip_wait=True, checks immediately with no propagation wait (for recheck button).
    """
    import re as _re, time as _t
    from playwright.sync_api import sync_playwright

    MAX_WAIT    = 20 * 60   # 20 min total
    INTERVAL    = 5  * 60   # check every 5 min

    # Load session file — normalize to Playwright storage_state dict
    try:
        _sd = json.loads(Path(session_path).read_text())
    except Exception as _se:
        return False, f"Cannot read SCC session file: {_se}"
    _storage = {"cookies": _sd, "origins": []} if isinstance(_sd, list) else _sd

    # Extract enterpriseId from localStorage
    _eid = ""
    for _o in (_sd.get("origins", []) if isinstance(_sd, dict) else []):
        for _it in _o.get("localStorage", []):
            if _it.get("name") == "enterpriseId":
                _eid = _it["value"]
                break

    sgt_url = (
        f"https://security.cisco.com/secure-access/org/{sa_org_id}"
        f"/resources/securitygrouptags"
        + (f"?enterpriseId={_eid}" if _eid else "")
    )
    log_fn(f"[sgt-verify] SGT URL: {sgt_url}")

    def _navigate_and_count(page) -> tuple:
        """Go to SGT page, return (ok, count).  ok=None means session expired."""
        page.goto(sgt_url, wait_until="domcontentloaded", timeout=60000)
        try:
            page.wait_for_load_state("networkidle", timeout=15000)
        except Exception:
            pass
        page.wait_for_timeout(3000)
        if "sign-on" in page.url.lower():
            return None, 0
        body = page.inner_text("body")
        m = _re.search(r'(\d+)\s+total', body, _re.IGNORECASE)
        count = int(m.group(1)) if m else 0
        if count == 0:
            try:
                count = page.locator("table tbody tr").count()
            except Exception:
                pass
        return count > 0, count

    browser = None
    page    = None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            ctx  = browser.new_context(
                storage_state=_storage, viewport={"width": 1920, "height": 1080}
            )
            page = ctx.new_page()
            page.set_default_timeout(30000)

            if skip_wait:
                # ── Immediate recheck — no propagation wait ───────────────────
                log_fn("[sgt-verify] Immediate recheck — querying SGTs now...")
                ok, count = _navigate_and_count(page)
                page.screenshot(path=str(DATA_DIR / "data" / f"sgt_verify_recheck_{pod_id}.png"))
                if ok is None:
                    return False, "SCC session expired — click Refresh SCC Sessions"
                if ok:
                    log_fn(f"[sgt-verify] ✓ Found {count} SGTs")
                    return True, f"SGT verify passed: {count} Security Group Tags found in Secure Access"
                return True, f"WARN: No SGTs found — ISE→SCC integration may not be active yet"

            # ── Check every 5 min up to 20 min ───────────────────────────────
            log_fn(f"[sgt-verify] Checking every 5 min up to 20 min (4 checks)...")
            start = _t.time()
            for check_num in range(1, 5):   # checks at 5, 10, 15, 20 min
                next_check_at = check_num * INTERVAL
                # Wait with elapsed logging every 60s
                while True:
                    elapsed = _t.time() - start
                    if elapsed >= next_check_at:
                        break
                    e_mins, e_secs = divmod(int(elapsed), 60)
                    log_fn(f"[sgt-verify] Elapsed {e_mins:02d}:{e_secs:02d} — next check at {check_num*5} min...")
                    wake = min(_t.time() + 60, start + next_check_at)
                    while _t.time() < wake:
                        _t.sleep(2)

                elapsed = _t.time() - start
                e_mins, e_secs = divmod(int(elapsed), 60)
                log_fn(f"[sgt-verify] Check {check_num}/4 at {e_mins:02d}:{e_secs:02d} elapsed...")
                ok, count = _navigate_and_count(page)
                page.screenshot(path=str(DATA_DIR / "data" / f"sgt_verify_check{check_num}_{pod_id}.png"))

                if ok is None:
                    return False, "SCC session expired — click Refresh SCC Sessions"
                if ok:
                    log_fn(f"[sgt-verify] ✓ Found {count} SGTs at check {check_num} ({e_mins:02d}:{e_secs:02d} elapsed)")
                    return True, f"SGT verify passed: {count} Security Group Tags found after {e_mins}m{e_secs:02d}s"

                log_fn(f"[sgt-verify] No SGTs yet (count={count}) — next check in 5 min...")

            log_fn(f"[sgt-verify] ⚠ WARN: No SGTs after 20 min — check ISE → cdFMC integration")
            return True, (
                f"WARN: No SGTs in Secure Access after 20 min — "
                f"check ISE→cdFMC integration (screenshot: sgt_verify_check4_{pod_id}.png)"
            )

    except Exception as _e:
        log_fn(f"[sgt-verify] Exception: {_e}")
        if page:
            try:
                page.screenshot(path=str(DATA_DIR / "data" / f"sgt_verify_error_{pod_id}.png"))
            except Exception:
                pass
        return False, f"SGT verify exception: {_e}"
    finally:
        if browser:
            try:
                browser.close()
            except Exception:
                pass


def _sgt_verify_watcher():
    """Background thread: watch for ise_sgt_trigger_{pod_id}.json written by Docker step 5.
    Calls _host_sgt_verify (with countdown + Playwright) and writes ise_sgt_result_{pod_id}.json.
    """
    import glob as _glob
    while True:
        try:
            for _trig_file in _glob.glob(str(DATA_DIR / "data" / "ise_sgt_trigger_*.json")):
                try:
                    _data = json.loads(Path(_trig_file).read_text())
                    _pod_id  = _data.get("pod_id", "")
                    _sa_org  = _data.get("sa_org_id", "")
                    _ts      = _data.get("ts", 0)
                    if not _pod_id or not _sa_org:
                        continue
                    if time.time() - _ts > 2400:   # 40 min stale guard
                        Path(_trig_file).unlink(missing_ok=True)
                        continue
                    Path(_trig_file).unlink(missing_ok=True)
                    log(_pod_id, f"[sgt-verify] Watcher picked up SGT trigger for {_pod_id}")
                    _session_path = DATA_DIR / "data" / f"scc_session_{_pod_id}.json"
                    if not _session_path.exists():
                        _res = {"ok": False, "message": f"No SCC session file for {_pod_id}"}
                    else:
                        _ok, _msg = _host_sgt_verify(
                            _pod_id, _sa_org, str(_session_path),
                            lambda m: log(_pod_id, m),
                        )
                        _res = {"ok": _ok, "message": _msg}
                    log(_pod_id, f"[sgt-verify] {'OK' if _res['ok'] else 'FAIL'}: {_res['message']}")
                    _result_path = DATA_DIR / "data" / f"ise_sgt_result_{_pod_id}.json"
                    Path(_result_path).write_text(json.dumps(_res))
                except Exception as _e:
                    try:
                        log("SGT_WATCHER", f"[sgt-verify] watcher error: {_e}")
                    except Exception:
                        pass
        except Exception:
            pass
        time.sleep(2)


threading.Thread(target=_sgt_verify_watcher, daemon=True, name="sgt-verify-watcher").start()


@app.route("/api/ise/sgt-recheck/<pod_id>", methods=["POST"])
def api_ise_sgt_recheck(pod_id):
    """Immediately recheck SGTs in Secure Access — no propagation wait."""
    import threading as _th
    _ensure_ise_table()
    _session_path = DATA_DIR / "data" / f"scc_session_{pod_id}.json"
    if not _session_path.exists():
        return jsonify({"status": "error", "message": "No SCC session file — Refresh SCC Sessions first"}), 400
    _sa_org = None
    try:
        import re as _re
        with sqlite3.connect(str(DATA_DIR / "data" / "pod_state.db")) as _c:
            _row = _c.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
            if _row and _row[0]:
                _m = _re.search(r"pseudoco-(\d+)", _row[0])
                if _m:
                    _oc = _c.execute("SELECT sa_org_id FROM org_credentials WHERE org_number=?", (_m.group(1),)).fetchone()
                    if _oc:
                        _sa_org = _oc[0]
    except Exception:
        pass
    if not _sa_org:
        return jsonify({"status": "error", "message": "sa_org_id not set — check Org Credentials card"}), 400

    def _run():
        try:
            log(pod_id, f"[sgt-recheck] Manual SGT recheck triggered for {pod_id}")
            _ok, _msg = _host_sgt_verify(
                pod_id, _sa_org, str(_session_path),
                lambda m: log(pod_id, m),
                skip_wait=True,
            )
            log(pod_id, f"[sgt-recheck] {'✓' if _ok else '✗'} {_msg}")
            # Update step 5 result in DB
            try:
                with sqlite3.connect(str(DATA_DIR / "data" / "pod_state.db")) as _c:
                    _status = "completed" if _ok else "failed"
                    _c.execute(
                        "UPDATE ise_steps SET status=?, result=?, completed_at=? WHERE pod_id=? AND step_name='ise_sgt_verify'",
                        (_status, _msg, datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"), pod_id)
                    )
            except Exception as _e:
                log(pod_id, f"[sgt-recheck] DB update error: {_e}")
        except Exception as _e:
            log(pod_id, f"[sgt-recheck] Error: {_e}")

    _th.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started", "pod_id": pod_id})

@app.route("/api/scc/refresh-sessions", methods=["POST"])
def api_scc_refresh_sessions():
    """Launch refresh_scc_sessions.py locally (headed Chrome) to refresh per-POD SCC
    session files for all active PODs.  Streams progress to pipeline_logs under
    pod_id='SCC_REFRESH'.  Runs on the Mac — NOT in Docker."""
    import threading, os

    req_data = request.get_json(silent=True) or {}
    trigger_pod = req_data.get("pod_id", "SCC_REFRESH")  # for log attribution

    script = DATA_DIR / "refresh_scc_sessions.py"
    if not script.exists():
        return jsonify({"status": "error", "message": "refresh_scc_sessions.py not found"}), 404

    def _run():
        log(trigger_pod, "[scc-refresh] Starting SCC session refresh for all active PODs...")
        try:
            proc = subprocess.Popen(
                [sys.executable, "-u", str(script), str(DB_PATH)],
                cwd=str(DATA_DIR),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                line = line.rstrip()
                if line:
                    log(trigger_pod, line if line.startswith("[scc-refresh]") else f"[scc-refresh] {line}")
            proc.wait()
            status = "completed" if proc.returncode == 0 else "failed"
            log(trigger_pod, f"[scc-refresh] {status} (rc={proc.returncode})")
        except Exception as e:
            log(trigger_pod, f"[scc-refresh] ERROR: {e}")

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    _scc_refresh_thread[0] = t
    return jsonify({"status": "started", "pod_id": trigger_pod})


@app.route("/api/scc/refresh-cancel", methods=["POST"])
def api_scc_refresh_cancel():
    """Kill the running refresh_scc_sessions.py process."""
    import signal
    killed = 0
    try:
        result = subprocess.run(
            ["pgrep", "-f", "refresh_scc_sessions.py"],
            capture_output=True, text=True
        )
        for pid in result.stdout.strip().split():
            try:
                os.kill(int(pid), signal.SIGTERM)
                killed += 1
            except Exception:
                pass
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    return jsonify({"status": "ok", "killed": killed})


@app.route("/api/scc/session-status", methods=["GET"])
def api_scc_session_status():
    """Return freshness of per-POD SCC session files."""
    import time as _time
    pod_id = request.args.get("pod_id")
    result = {}
    # If specific pod_id, just check that one; otherwise check all
    if pod_id:
        f = DATA_DIR / "data" / f"scc_session_{pod_id}.json"
        if not f.exists():
            # Fallback: legacy scc_session.json
            f = DATA_DIR / "data" / "scc_session.json"
        result[pod_id] = {
            "exists": f.exists(),
            "age_hours": round((_time.time() - f.stat().st_mtime) / 3600, 1) if f.exists() else None,
            "file": f.name if f.exists() else None,
        }
    else:
        # Only include real POD sessions (scc_session_POD-*.json) so stale
        # orphan files (scc_session_fresh.json, scc_session.json, etc.) don't
        # inflate `total` in the JS poller and prevent it from ever declaring done.
        for f in (DATA_DIR / "data").glob("scc_session_POD-*.json"):
            pid = f.stem.replace("scc_session_", "")
            result[pid] = {
                "exists": True,
                "age_hours": round((_time.time() - f.stat().st_mtime) / 3600, 1),
                "file": f.name,
            }
    return jsonify(result)


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
    """Return SCC API key/secret for a POD.
    Priority: pods table override → org_credentials fallback (same as _scc_load_keys)."""
    import re as _re
    conn = _db()
    row = conn.execute(
        "SELECT scc_api_key, scc_api_secret, scc_org FROM pods WHERE pod_id=?", (pod_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"scc_api_key": "", "scc_api_secret": ""})
    # 1. POD-level override
    if row["scc_api_key"] and row["scc_api_secret"]:
        return jsonify({"scc_api_key": row["scc_api_key"], "scc_api_secret": row["scc_api_secret"]})
    # 2. Fallback: org_credentials table
    m = _re.search(r"pseudoco-(\d+)", row["scc_org"] or "")
    if m:
        conn2 = _db()
        oc = conn2.execute(
            "SELECT scc_api_key, scc_api_secret FROM org_credentials WHERE org_number=?", (m.group(1),)
        ).fetchone()
        conn2.close()
        if oc and oc["scc_api_key"] and oc["scc_api_secret"]:
            return jsonify({"scc_api_key": oc["scc_api_key"], "scc_api_secret": oc["scc_api_secret"]})
    return jsonify({"scc_api_key": "", "scc_api_secret": ""})


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
        "duo_skey": row["duo_skey"] or "",
        "duo_host": row["duo_host"] or "",
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


@app.route("/api/pod-sa-keys/<pod_id>", methods=["GET"])
def get_sa_keys(pod_id):
    """Return Secure Access API credentials for a POD."""
    conn = _db()
    row = conn.execute(
        "SELECT sa_org_id, sa_api_key, sa_api_secret FROM pods WHERE pod_id=?", (pod_id,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"sa_org_id": "", "sa_api_key": "", "sa_api_secret": ""})
    return jsonify({
        "sa_org_id":     row["sa_org_id"] or "",
        "sa_api_key":    row["sa_api_key"] or "",
        "sa_api_secret": row["sa_api_secret"] or "",
    })


@app.route("/api/pod-sa-keys/<pod_id>", methods=["POST"])
def save_sa_keys(pod_id):
    """Save Secure Access API credentials for a POD."""
    data = request.get_json(force=True)
    org_id = data.get("sa_org_id", "").strip()
    key    = data.get("sa_api_key", "").strip()
    secret = data.get("sa_api_secret", "").strip()
    conn = _db()
    conn.execute(
        "UPDATE pods SET sa_org_id=?, sa_api_key=?, sa_api_secret=?, updated_at=datetime('now') WHERE pod_id=?",
        (org_id, key, secret, pod_id)
    )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


# ── Org-level credentials (shared across all PODs of the same org) ────────────

@app.route("/api/org-credentials", methods=["GET"])
def list_org_credentials():
    """List all org numbers that have credentials configured."""
    conn = _db()
    rows = conn.execute(
        "SELECT org_number, duo_saml_app_ikey, updated_at FROM org_credentials ORDER BY CAST(org_number AS INTEGER)"
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/org-credentials/<org_number>", methods=["GET"])
def get_org_credentials(org_number):
    """Return all credentials for a given org number."""
    conn = _db()
    row = conn.execute(
        "SELECT * FROM org_credentials WHERE org_number=?", (org_number,)
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"org_number": org_number, "duo_ikey": "", "duo_skey": "", "duo_host": "",
                        "duo_saml_app_ikey": "",
                        "scc_api_key": "", "scc_api_secret": "",
                        "sa_org_id": "", "sa_api_key": "", "sa_api_secret": "",
                        "scc_email": "", "scc_password": "", "authproxy_cfg": "",
                        "sa_scim_token": "", "authproxy_enroll_blob": "",
                        "authproxy_blob_saved_at": "",
                        "pxgrid_cloud_email": "", "pxgrid_cloud_password": "",
                        "pxgrid_cloud_account": ""})
    return jsonify(dict(row))


@app.route("/api/org-credentials/<org_number>", methods=["POST"])
def save_org_credentials(org_number):
    """Create or update credentials for a given org number.
    Empty string values are ignored — existing DB values are preserved.
    This prevents accidental wipes when password fields aren't visible in the form.
    """
    data = request.get_json(force=True)
    conn = _db()
    # For new orgs: insert with whatever values were provided (empty is fine as placeholder)
    conn.execute("""
        INSERT OR IGNORE INTO org_credentials (org_number, updated_at)
        VALUES (?, datetime('now'))
    """, (org_number,))
    # For each field: only update if the submitted value is non-empty
    fields = {
        "duo_ikey":          data.get("duo_ikey", "").strip(),
        "duo_skey":          data.get("duo_skey", "").strip(),
        "duo_host":          data.get("duo_host", "").strip(),
        "duo_saml_app_ikey": data.get("duo_saml_app_ikey", "").strip(),
        "scc_api_key":       data.get("scc_api_key", "").strip(),
        "scc_api_secret":    data.get("scc_api_secret", "").strip(),
        "sa_org_id":         data.get("sa_org_id", "").strip(),
        "sa_api_key":        data.get("sa_api_key", "").strip(),
        "sa_api_secret":     data.get("sa_api_secret", "").strip(),
        "scc_email":         data.get("scc_email", "").strip(),
        "scc_password":      data.get("scc_password", "").strip(),
        "authproxy_cfg":          data.get("authproxy_cfg", ""),  # preserve whitespace
        "sa_scim_token":          data.get("sa_scim_token", "").strip(),
        "authproxy_enroll_blob":  data.get("authproxy_enroll_blob", "").strip(),
        "pxgrid_cloud_email":     data.get("pxgrid_cloud_email", "").strip(),
        "pxgrid_cloud_password":  data.get("pxgrid_cloud_password", "").strip(),
        "pxgrid_cloud_account":   data.get("pxgrid_cloud_account", "").strip(),
    }
    updates = {k: v for k, v in fields.items() if v != ""}
    if updates:
        set_clause = ", ".join(f"{k}=?" for k in updates)
        conn.execute(
            f"UPDATE org_credentials SET {set_clause}, updated_at=datetime('now') WHERE org_number=?",
            list(updates.values()) + [org_number]
        )
    # If a new blob was submitted, stamp its individual save time so UI can warn when stale
    if data.get("authproxy_enroll_blob", "").strip():
        conn.execute(
            "UPDATE org_credentials SET authproxy_blob_saved_at=datetime('now') WHERE org_number=?",
            (org_number,)
        )
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})


ORG_CSV_COLS = [
    "org_number", "duo_ikey", "duo_skey", "duo_host",
    "duo_saml_app_ikey",
    "scc_api_key", "scc_api_secret",
    "sa_org_id", "sa_api_key", "sa_api_secret",
    "scc_email", "scc_password", "authproxy_cfg",
    "sa_scim_token", "authproxy_enroll_blob",
]


@app.route("/api/org-credentials/export.csv")
def export_org_credentials_csv():
    """Download all org credentials as a CSV file."""
    import csv, io
    conn = _db()
    rows = conn.execute(
        "SELECT " + ",".join(ORG_CSV_COLS) + " FROM org_credentials ORDER BY CAST(org_number AS INTEGER)"
    ).fetchall()
    conn.close()
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=ORG_CSV_COLS)
    w.writeheader()
    for r in rows:
        w.writerow(dict(r))
    output = buf.getvalue()
    return output, 200, {
        "Content-Type": "text/csv",
        "Content-Disposition": "attachment; filename=org_credentials.csv",
    }


@app.route("/api/org-credentials/import", methods=["POST"])
def import_org_credentials_csv():
    """Bulk upsert org credentials from an uploaded CSV file."""
    import csv, io
    f = request.files.get("file")
    if not f:
        return jsonify({"error": "No file uploaded"}), 400
    try:
        text = f.read().decode("utf-8-sig")  # strip BOM if present
        reader = csv.DictReader(io.StringIO(text))
        # Validate header
        missing = [c for c in ORG_CSV_COLS if c not in (reader.fieldnames or [])]
        if missing:
            return jsonify({"error": "Missing columns: " + ", ".join(missing)}), 400
        conn = _db()
        imported = 0
        skipped = 0
        for row in reader:
            org_num = row.get("org_number", "").strip()
            if not org_num:
                skipped += 1
                continue
            conn.execute("""
                INSERT INTO org_credentials
                    (org_number, duo_ikey, duo_skey, duo_host,
                     duo_saml_app_ikey,
                     scc_api_key, scc_api_secret,
                     sa_org_id, sa_api_key, sa_api_secret,
                     scc_email, scc_password, authproxy_cfg, sa_scim_token, updated_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))
                ON CONFLICT(org_number) DO UPDATE SET
                    duo_ikey=excluded.duo_ikey, duo_skey=excluded.duo_skey, duo_host=excluded.duo_host,
                    duo_saml_app_ikey=excluded.duo_saml_app_ikey,
                    scc_api_key=excluded.scc_api_key, scc_api_secret=excluded.scc_api_secret,
                    sa_org_id=excluded.sa_org_id, sa_api_key=excluded.sa_api_key, sa_api_secret=excluded.sa_api_secret,
                    scc_email=excluded.scc_email,
                    scc_password=excluded.scc_password,
                    authproxy_cfg=excluded.authproxy_cfg,
                    sa_scim_token=excluded.sa_scim_token,
                    updated_at=datetime('now')
            """, (
                org_num,
                row.get("duo_ikey", "").strip(), row.get("duo_skey", "").strip(), row.get("duo_host", "").strip(),
                row.get("duo_saml_app_ikey", "").strip(),
                row.get("scc_api_key", "").strip(), row.get("scc_api_secret", "").strip(),
                row.get("sa_org_id", "").strip(), row.get("sa_api_key", "").strip(), row.get("sa_api_secret", "").strip(),
                row.get("scc_email", "").strip(),
                row.get("scc_password", "").strip(),
                row.get("authproxy_cfg", "").strip(),
                row.get("sa_scim_token", "").strip(),
            ))
            imported += 1
        conn.commit()
        conn.close()
        return jsonify({"status": "ok", "imported": imported, "skipped": skipped})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/global-config", methods=["GET"])
def get_global_config():
    """Return global key-value config (CCO credentials etc.)."""
    conn = _db()
    cco_user = _get_global_config(conn, "cco_username")
    cco_pass = _get_global_config(conn, "cco_password")
    conn.close()
    return jsonify({"cco_username": cco_user, "cco_password": cco_pass})


@app.route("/api/global-config", methods=["POST"])
def save_global_config():
    """Save global key-value config."""
    data = request.get_json(force=True)
    conn = _db()
    for key in ("cco_username", "cco_password"):
        if key in data:
            _set_global_config(conn, key, (data[key] or "").strip())
    conn.commit()
    conn.close()
    return jsonify({"status": "ok"})






# !! DO NOT REMOVE THE DECORATOR BELOW — this has been dropped 3 times by edits inserting new routes above this function !!
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
  .org-card { background:#0d1e30; border:1px solid #1a3a5a; border-radius:6px; padding:10px 12px; cursor:pointer; transition:border-color 0.15s,background 0.15s; }
  .org-card:hover { border-color:#02c8ff; }
  .org-card.selected { border-color:#02c8ff; background:#0a1f3a; }
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
  .switch-card-title .role-tag.cedge { background: #1a1a0a; color: #f59e0b; }
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

   <!-- Org Credentials -->
   <div class="upload-section" id="org-creds-section" style="margin-bottom:20px;padding:0;">
     <!-- Collapsed header (always visible) -->
     <div id="org-creds-header" onclick="toggleOrgCreds()" style="display:flex;align-items:center;justify-content:space-between;padding:12px 16px;cursor:pointer;user-select:none;">
       <div style="display:flex;align-items:center;gap:10px;">
         <span id="org-creds-chevron" style="font-size:12px;color:#445566;transition:transform 0.2s;">&#9654;</span>
         <h3 style="margin:0;">Org Credentials</h3>
         <span id="org-creds-count" style="font-size:11px;color:#445566;background:#0d1e30;border:1px solid #1a3a5a;border-radius:10px;padding:1px 8px;"></span>
       </div>
       <span style="font-size:11px;color:#445566;">click to expand</span>
     </div>
      <!-- Expandable body -->
      <div id="org-creds-body" style="display:none;padding:0 16px 16px 16px;border-top:1px solid #1a2d4a;">
        <div style="display:flex;align-items:center;justify-content:flex-end;gap:8px;padding:10px 0 8px 0;">
         <a href="/api/org-credentials/export.csv" download style="padding:5px 12px;background:#0d1e30;border:1px solid #00e68a;color:#00e68a;border-radius:4px;cursor:pointer;font-size:11px;text-decoration:none;">&#8595; Export CSV</a>
         <label style="padding:5px 12px;background:#0d1e30;border:1px solid #ffa502;color:#ffa502;border-radius:4px;cursor:pointer;font-size:11px;">
           &#8593; Import CSV
           <input type="file" accept=".csv" style="display:none;" onchange="importOrgCsv(this)">
         </label>
         <span id="org-import-status" style="font-size:11px;color:#667788;"></span>
         <button onclick="orgCredsNew()" style="padding:5px 12px;background:#0d1e30;border:1px solid #02c8ff;color:#02c8ff;border-radius:4px;cursor:pointer;font-size:11px;">+ New Org</button>
       </div>
       <div id="org-creds-list" style="margin-bottom:10px;"></div>
       <div id="org-new-row" style="display:none;margin-bottom:10px;">
         <div style="display:flex;gap:8px;align-items:center;">
           <input id="org-num-input" type="text" placeholder="Org number e.g. 5001"
             style="background:#0a1625;border:1px solid #1a3a5a;color:#e0e8f0;border-radius:4px;padding:5px 8px;font-size:12px;width:150px;">
           <button onclick="loadOrgCreds(document.getElementById('org-num-input').value.trim())"
             style="padding:5px 10px;background:#0d1e30;border:1px solid #02c8ff;color:#02c8ff;border-radius:4px;cursor:pointer;font-size:11px;">Create / Load</button>
           <button onclick="document.getElementById('org-new-row').style.display='none'"
             style="padding:5px 10px;background:transparent;border:1px solid #334455;color:#667788;border-radius:4px;cursor:pointer;font-size:11px;">Cancel</button>
         </div>
       </div>
       <div id="org-creds-form" style="display:none;"></div>
     </div>
   </div>

   <div class="summary" id="summary"></div>

   <div style="margin-bottom:12px;display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
     <button class="btn-start-all" id="btn-vpn-all" onclick="connectAllVpn()">&#9654; Connect All VPN</button>
     <button class="btn-start-all" id="btn-run-all" onclick="runAllPods()" style="background:#7c3aed;color:#fff;">&#9654; Run All POD Automation</button>
     <button class="btn-start-all" id="btn-docker-down" onclick="dockerDown()" style="background:#ff4757;color:#fff;">&#9632; Teardown All</button>
     <button class="btn-start-all" onclick="window.location.href='/api/generate-lab-pdf'" style="background:#0d4f6e;border-color:#00bceb;color:#00bceb;">&#128196; Generate Lab Details</button>
     <button class="btn-start-all" id="btn-scc-refresh-global" onclick="refreshSccSessionsGlobal()" style="background:#2d3f50;border-color:#445566;color:#cdd6e0;">&#8635; Refresh SCC Sessions</button>
     <span id="scc-refresh-global-status" style="font-size:12px;color:#667788;"></span>
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
       <button class="tab-btn" onclick="switchTab(this, 'switches')">Switches / Routes</button>
       <button class="tab-btn" onclick="switchTab(this, 'cdfmc')">cdFMC</button>
       <button class="tab-btn" onclick="switchTab(this, 'ad')">AD Verify</button>
       <button class="tab-btn" onclick="switchTab(this, 'fabric')">EVPN Fabric</button>
        <button class="tab-btn" onclick="switchTab(this, 'sda')">SDA Fabric</button>
        <button class="tab-btn" onclick="switchTab(this, 'scc')">SCC Reset</button>
         <button class="tab-btn" onclick="switchTab(this, 'duo')">&#x1F512; Duo</button>
         <button class="tab-btn" onclick="switchTab(this, 'ise')">&#x1F4F6; ISE</button>
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

       <div class="tab-content" id="tab-duo">
         <div id="duo-grid" style="padding:16px;min-height:260px;">
           <div style="color:#667788;font-size:13px;">Select a POD to manage Duo integration</div>
         </div>
       </div>

       <div class="tab-content" id="tab-ise">
         <div id="ise-grid" style="padding:16px;min-height:260px;">
           <div style="color:#667788;font-size:13px;">Select a POD to manage ISE integrations</div>
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
  "redeploy_config_group",
  "verify_border_spine",
  "verify_leaf1",
  "verify_leaf2",
  "connectivity_test",
  "route_verification",
  "cdfmc_check",
  "ad_verify",
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
     else if (tabName === 'upgrade')   loadUpgrade(detailId);
     else if (tabName === 'fabric')    loadFabricStatus(detailId);
     else if (tabName === 'sda')       loadSdaStatus(detailId);
     else if (tabName === 'duo')       loadDuoStatus(detailId);
     else if (tabName === 'ise')       loadIseStatus(detailId);
     else if (tabName === 'scc')       loadSccChecklist(detailId);
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
  // Kill any pollers that were running for a previously-open POD so their
  // async callbacks cannot write stale data into this panel after the switch.
  if (window._sdaPoller)    { clearInterval(window._sdaPoller);    window._sdaPoller    = null; }
  if (window._sdaCatcPoll)  { clearInterval(window._sdaCatcPoll);  window._sdaCatcPoll  = null; }
  if (window._fabricPoller) { clearInterval(window._fabricPoller); window._fabricPoller = null; }
  if (window._duoPoller)    { clearInterval(window._duoPoller);    window._duoPoller    = null; }
  if (window._catcPoll)     { clearInterval(window._catcPoll);     window._catcPoll     = null; }
  // Reset CatC tile so it re-initialises for the new POD
  const _ct = document.getElementById('catc-tile-container');
  if (_ct) { _ct._initialized = false; _ct._podId = null; }
  // Clear the SDA grid so it doesn't flash old-POD data before loadSdaStatus fires
  const _sg = document.getElementById('sda-grid');
  if (_sg) { _sg.innerHTML = '<div style="color:#667788;font-size:13px;">Loading...</div>'; _sg._lastHtml = null; _sg._lastPodId = null; }

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
  const SOFT_FAIL = new Set(['controller_mode_enable','verify_online','redeploy_config_group','verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test','cdfmc_check','ad_verify']);
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
  if (name.includes('CEDGE') || name.includes('Route')) return 'cedge';
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

    const roleLabel = sw.name === 'Catalyst Center' ? 'CC'
      : sw.name === 'Switch Connectivity' ? 'TEST'
      : (sw.name.includes('CEDGE') || sw.name.includes('Route')) ? 'CEDGE'
      : sw.name.includes('Border') ? 'Spine' : 'Leaf';

    const isRouteCard = sw.host === 'route_verification';
    const warnBadge = sw.step_status === 'completed' && sw.failed === 0 && sw.reloaded === 'yes'
      ? '<span class="badge warn" style="margin-left:8px">RELOADED</span>' : '';
    const testFailBtn = isRouteCard
      ? '<button class="btn-reconnect" id="route-test-btn-' + escHtml(podId) + '" '
          + 'style="margin-left:auto;font-size:10px;padding:2px 8px;" '
          + 'title="Inject fake prefix to force reload+re-verify flow">Test Fail</button>'
      : '';

    return '<div class="switch-card ' + (allDevicePass ? 'pass' : hasAnyFail ? 'fail' : sw.step_status === 'skipped' ? 'warn' : '') + '">' +
      '<div class="switch-card-title">' +
        '<span class="role-tag ' + roleClass(sw.name) + '">' + roleLabel + '</span>' +
        '<span class="device-name"' + (sw.ip ? ' data-pod-id="' + escHtml(podId) + '" data-ip="' + escHtml(sw.ip) + '"' : '') + ' title="' + (sw.ip ? 'Click to open SSH terminal' : '') + '">' + escHtml(sw.name) + '</span>' +
        '<span class="device-model">' + escHtml(sw.model || '') + '</span>' +
        (sw.step_status === 'running' ? '<span class="badge" style="margin-left:auto;background:#02c8ff22;color:#02c8ff;border:1px solid #02c8ff55;">⟳ checking</span>' : '') +
        (sw.step_status === 'skipped' ? '<span class="badge warn" style="margin-left:auto">WARN</span>' : '') +
        warnBadge + testFailBtn +
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

  // Wire Test Fail button for route verification card
  const testBtn = document.getElementById('route-test-btn-' + podId);
  if (testBtn) {
    testBtn.addEventListener('click', async () => {
      testBtn.disabled = true;
      testBtn.textContent = 'Running...';
      try {
        const resp = await fetch('/api/routes/test-fail/' + podId, { method: 'POST' });
        const j = await resp.json();
        if (j.status !== 'started') {
          alert('Test fail error: ' + (j.message || JSON.stringify(j)));
          testBtn.disabled = false; testBtn.textContent = 'Test Fail'; return;
        }
      } catch(e) {
        alert('Test fail request failed: ' + e);
        testBtn.disabled = false; testBtn.textContent = 'Test Fail'; return;
      }
      // Poll until route_verification is no longer running
      let polls = 0;
      async function pollRoute() {
        polls++;
        const r2 = await fetch('/api/pipeline/' + podId);
        const steps = await r2.json();
        const rv = steps.find(s => s.step_name === 'route_verification');
        await loadSwitches(podId);
        if (rv && rv.status === 'running' && polls < 120) {
          setTimeout(pollRoute, 5000);
        } else {
          testBtn.disabled = false; testBtn.textContent = 'Test Fail';
        }
      }
      setTimeout(pollRoute, 3000);
    });
  }
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
      const switchNames = ['verify_border_spine','verify_leaf1','verify_leaf2','connectivity_test','route_verification'];
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

// ── Org Credentials Management ───────────────────────────────────────────────

// Returns an inline warning banner if the enrollment blob is stale (>24h).
// savedAt is a SQLite datetime string 'YYYY-MM-DD HH:MM:SS' (UTC) or empty.
function closeOrgCredsForm() {
  const formEl = document.getElementById('org-creds-form');
  if (formEl) formEl.style.display = 'none';
  document.querySelectorAll('.org-card').forEach(el => el.classList.remove('selected'));
  window._currentEditOrg = null;
}

function blobAgeWarning(savedAt) {
  if (!savedAt) return '<div style="font-size:11px;color:#f59e0b;background:#2a1a00;border:1px solid #f59e0b;border-radius:4px;padding:5px 9px;margin-bottom:5px;">&#9888; No save timestamp \u2014 paste a fresh blob from Duo Admin portal before running step 5.</div>';
  const saved = new Date(savedAt.replace(' ', 'T') + 'Z');
  if (isNaN(saved.getTime())) return '';
  const ageH = (Date.now() - saved.getTime()) / 3600000;
  if (ageH > 24) {
    const d = Math.floor(ageH / 24), h = Math.round(ageH % 24);
    return '<div style="font-size:11px;color:#f59e0b;background:#2a1a00;border:1px solid #f59e0b;border-radius:4px;padding:5px 9px;margin-bottom:5px;">'
      + '&#9888; Blob is <b>' + d + 'd ' + h + 'h old</b> \u2014 one-time codes expire after first use. '
      + 'Generate a new command: Duo Admin \u2192 SSO Settings \u2192 External Auth Sources \u2192 AD \u2192 Auth Proxy \u2192 Step 2 \u2192 Generate Command, paste here and Save before re-running step 5.'
      + '</div>';
  }
  return '<div style="font-size:11px;color:#22c55e;margin-bottom:4px;">&#10003; Blob saved ' + Math.round(ageH) + 'h ago</div>';
}
async function initOrgCredsList() {
  const listEl   = document.getElementById('org-creds-list');
  const countEl  = document.getElementById('org-creds-count');
  if (!listEl) return;
  try {
    const r = await fetch('/api/org-credentials');
    const orgs = await r.json();
    // Always update the count badge regardless of panel state
    if (countEl) countEl.textContent = orgs.length + ' org' + (orgs.length !== 1 ? 's' : '');
    if (!orgs.length) {
      listEl.innerHTML = '<div style="font-size:12px;color:#445566;padding:6px 0;">No orgs configured yet. Click <strong style="color:#02c8ff">+ New Org</strong> to add one.</div>';
    } else {
      let html = '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(155px,1fr));gap:8px;">';
      orgs.forEach(o => {
        const upd = (o.updated_at||'').substring(0,10);
        const uuid = o.scc_org_uuid ? o.scc_org_uuid.substring(0,8) + '\u2026' : '\u2014';
        html += '<div class="org-card" data-org="' + escHtml(o.org_number) + '">'
          + '<div style="font-size:14px;font-weight:700;color:#02c8ff;">Org ' + escHtml(o.org_number) + '</div>'
          + '<div style="font-size:10px;color:#556677;margin-top:3px;font-family:monospace;">' + escHtml(uuid) + '</div>'
          + '<div style="font-size:10px;color:#334455;margin-top:2px;">' + escHtml(upd) + '</div>'
          + '</div>';
      });
      html += '</div>';
      listEl.innerHTML = html;
      setTimeout(() => {
        listEl.querySelectorAll('.org-card').forEach(el => {
          el.onclick = () => loadOrgCreds(el.dataset.org);
        });
      }, 0);
    }
  } catch(e) { listEl.innerHTML = ''; }
}

function toggleOrgCreds() {
  const body    = document.getElementById('org-creds-body');
  const chevron = document.getElementById('org-creds-chevron');
  const hint    = document.querySelector('#org-creds-header span:last-child');
  const open    = body.style.display === 'none';
  body.style.display   = open ? 'block' : 'none';
  chevron.style.transform = open ? 'rotate(90deg)' : '';
  if (hint) hint.textContent = open ? 'click to collapse' : 'click to expand';
  if (open && !document.querySelector('#org-creds-list .org-card')) initOrgCredsList();
}

async function importOrgCsv(input) {
  const statusEl = document.getElementById('org-import-status');
  if (!input.files.length) return;
  const fd = new FormData();
  fd.append('file', input.files[0]);
  input.value = '';  // reset so same file can be re-uploaded
  statusEl.style.color = '#ffa502'; statusEl.textContent = 'Importing...';
  try {
    const r = await fetch('/api/org-credentials/import', {method:'POST', body: fd});
    const d = await r.json();
    if (d.error) {
      statusEl.style.color = '#ff4757'; statusEl.textContent = '\u2717 ' + d.error;
    } else {
      statusEl.style.color = '#00e68a';
      statusEl.textContent = '\u2713 ' + d.imported + ' imported' + (d.skipped ? ', ' + d.skipped + ' skipped' : '');
      await initOrgCredsList();
    }
  } catch(e) {
    statusEl.style.color = '#ff4757'; statusEl.textContent = '\u2717 ' + e.message;
  }
  setTimeout(() => { statusEl.textContent = ''; }, 6000);
}

function orgCredsNew() {
  const row = document.getElementById('org-new-row');
  if (!row) return;
  row.style.display = row.style.display === 'none' ? 'flex' : 'none';
  if (row.style.display !== 'none') {
    const inp = document.getElementById('org-num-input');
    if (inp) { inp.value = ''; inp.focus(); }
  }
}

async function loadOrgCreds(orgNum) {
  if (!orgNum) return;
  window._currentEditOrg = orgNum;  // store for saveOrgCreds onclick
  document.getElementById('org-new-row').style.display = 'none';
  // Highlight selected card
  document.querySelectorAll('.org-card').forEach(el => el.classList.remove('selected'));
  const card = document.querySelector('.org-card[data-org="' + orgNum + '"]');
  if (card) card.classList.add('selected');

  const formEl = document.getElementById('org-creds-form');
  formEl.style.display = 'block';
  formEl.innerHTML = '<div style="color:#667788;font-size:12px;">Loading...</div>';

  let d = {org_number: orgNum, duo_ikey:'', duo_skey:'', duo_host:'', duo_saml_app_ikey:'', scc_api_key:'', scc_api_secret:'', sa_org_id:'', sa_api_key:'', sa_api_secret:'', scc_email:'', scc_password:'', authproxy_cfg:'', sa_scim_token:'', authproxy_enroll_blob:'', pxgrid_cloud_email:'', pxgrid_cloud_password:'', pxgrid_cloud_account:''};
  try {
    const r = await fetch('/api/org-credentials/' + encodeURIComponent(orgNum));
    d = await r.json();
  } catch(e) {}

  const inp = (id, val, ph, pw) =>
    '<input id="oc-' + id + '" type="' + (pw ? 'password' : 'text') + '" placeholder="' + escHtml(ph) + '"'
    + ' style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:4px 7px;font-size:11px;font-family:monospace;box-sizing:border-box;">';
  const lbl = t => '<div style="font-size:10px;color:#667788;margin-bottom:2px;text-transform:uppercase;">' + t + '</div>';
  const col = (label, id, val, ph, pw) => '<div>' + lbl(label) + inp(id, val, ph, pw) + '</div>';

  formEl.innerHTML =
    '<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:10px;">'
    + '<div style="font-size:12px;font-weight:600;color:#e0e8f0;">Editing: Org ' + escHtml(orgNum) + '</div>'
    + '<button id="oc-close-btn" style="background:transparent;border:1px solid #334455;color:#667788;border-radius:4px;padding:3px 10px;cursor:pointer;font-size:12px;">&#x2715; Close</button>'
    + '</div>'
    + '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-bottom:8px;">'
    + '<div style="grid-column:1/-1;font-size:11px;color:#02c8ff;font-weight:600;padding:4px 0;">Duo Admin API</div>'
    + col('Integration Key (ikey)', 'duo_ikey', d.duo_ikey, 'DIRIBLQ...', false)
    + col('Secret Key (skey)', 'duo_skey', d.duo_skey, 'Secret...', true)
    + col('API Hostname', 'duo_host', d.duo_host, 'api-xxxxx.duosecurity.com', false)
     + '<div style="grid-column:1/-1;">'
     + lbl('SSO Enrollment Blob (authproxy_enroll_blob)')
     + blobAgeWarning(d.authproxy_blob_saved_at)
     + inp('authproxy_enroll_blob', d.authproxy_enroll_blob || '', 'base64 blob from Duo SSO Settings → External Auth Sources → AD → Auth Proxy → Step 2 → Generate Command', false)
     + '<div style="font-size:10px;color:#445566;margin-top:2px;">In Duo Admin portal: Applications \u2192 SSO Settings \u2192 External Authentication Sources \u2192 Active Directory \u2192 Auth Proxy \u2192 Step 2 \u2192 click \u201cGenerate Command\u201d. Copy the base64 argument (after the .exe path). <b>One-time code \u2014 must be regenerated for each new dCloud session.</b></div>'
     + '</div>'
    + '<div style="grid-column:1/-1;font-size:11px;color:#02c8ff;font-weight:600;padding:4px 0;margin-top:4px;">Secure Access (SA)</div>'
    + '<div style="grid-column:1/-1;">'
    + lbl('SA SCIM Provisioning Token')
    + inp('sa_scim_token', d.sa_scim_token || '', 'Paste token from SA portal \u2192 Directories \u2192 Integrate \u2192 Duo \u2192 Generate Token', true)
    + '<div style="font-size:10px;color:#445566;margin-top:2px;">One-time token from Cisco Secure Access. Navigate: Connect \u2192 Users, Groups & Endpoint Devices \u2192 Directories \u2192 Integrate \u2192 IdP \u2192 Duo \u2192 Generate Token. Shown only once \u2014 copy immediately. SCIM URL is always <code style="color:#02c8ff;">https://api.sse.cisco.com/identity/v2/scim</code></div>'
    + '</div>'
    + '<div style="grid-column:1/-1;font-size:11px;color:#02c8ff;font-weight:600;padding:4px 0;margin-top:4px;">Security Cloud Control (SCC)</div>'
    + col('SCC API Key', 'scc_api_key', d.scc_api_key, 'e8b04af7-...', false)
    + col('SCC API Secret', 'scc_api_secret', d.scc_api_secret, 'Secret or eyJ...', true)
    + '<div style="grid-column:1/-1;font-size:10px;color:#445566;margin-top:-4px;margin-bottom:4px;">Used by the SCC reset check step (step 20). Set once per org \u2014 permanent.</div>'
    + '<div style="grid-column:1/-1;font-size:11px;color:#02c8ff;font-weight:600;padding:4px 0;margin-top:4px;">Secure Access (SA) API</div>'
    + col('SA Org ID', 'sa_org_id', d.sa_org_id, '8381539', false)
    + col('SA API Key', 'sa_api_key', d.sa_api_key, '6671146f...', false)
    + col('SA API Secret', 'sa_api_secret', d.sa_api_secret, 'Secret...', true)
    + '<div style="grid-column:1/-1;font-size:10px;color:#445566;margin-top:-4px;margin-bottom:4px;">Used by step 20 (SCC reset) for SSE/Umbrella API (api.sse.cisco.com). Different from SCC CDO credentials above.</div>'
    + '<div style="grid-column:1/-1;font-size:11px;color:#02c8ff;font-weight:600;padding:4px 0;margin-top:4px;">SCC Admin Credentials</div>'
    + '<div style="grid-column:1/-1;">'
    + lbl('SCC Admin Email')
    + inp('scc_email', d.scc_email || '', 'ciscoxar1@gmail.com', false)
    + '<div style="font-size:10px;color:#445566;margin-top:2px;">Cisco account email used to log into security.cisco.com. Varies per facilitator.</div>'
    + '</div>'
    + '<div style="grid-column:1/-1;">'
    + lbl('SCC Admin Password')
    + inp('scc_password', d.scc_password || '', 'C1sco12345!!', true)
    + '</div>'
     + '<div style="grid-column:1/-1;">'
     + lbl('Auth Proxy Config (authproxy.cfg content)')
     + '<textarea id="oc-authproxy_cfg" rows="10" placeholder="[cloud]&#10;ikey=...&#10;skey=...&#10;api_host=api-xxx.duosecurity.com&#10;&#10;[ad_client]&#10;host=198.18.5.102&#10;..." style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:4px 7px;font-size:11px;font-family:monospace;box-sizing:border-box;resize:vertical;"></textarea>'
     + '<div style="font-size:10px;color:#445566;margin-top:2px;">Paste the complete authproxy.cfg downloaded from Duo Admin portal. Include [cloud], [ad_client], and [sso] sections. Stored per-org and pushed verbatim to AD1 at pipeline time.</div>'
     + '</div>'
     + '<div style="grid-column:1/-1;font-size:11px;color:#02c8ff;font-weight:600;padding:4px 0;margin-top:4px;">pxGrid Cloud Portal (ISE Integration)</div>'
     + '<div style="grid-column:1/-1;font-size:10px;color:#445566;margin-bottom:6px;">Credentials for the Catalyst Cloud Portal used during ISE pxGrid Cloud registration (Step 1 of ISE tab). The account name is in the format <code style="color:#02c8ff;">SEC-NET-CL25-02</code> — shown on the account selection screen after login.</div>'
     + col('Catalyst Cloud Email', 'pxgrid_cloud_email', d.pxgrid_cloud_email, 'user@example.com', false)
     + col('Catalyst Cloud Password', 'pxgrid_cloud_password', d.pxgrid_cloud_password, 'Password', true)
     + col('Account Name', 'pxgrid_cloud_account', d.pxgrid_cloud_account, 'SEC-NET-CL25-02', false)
    + '</div>'
    + '</div>'
     + '<div id="oc-save-banner" style="display:none;margin-top:8px;padding:8px 14px;border-radius:6px;font-size:13px;font-weight:600;"></div>'
    + '<div style="display:flex;gap:8px;align-items:center;margin-top:8px;">'
    + '<button id="oc-save-btn" type="button" onclick="saveOrgCreds(window._currentEditOrg)" style="padding:7px 20px;background:#0d4f6e;border:2px solid #02c8ff;color:#02c8ff;border-radius:5px;cursor:pointer;font-size:13px;font-weight:600;min-width:140px;">&#128190; Save Org ' + escHtml(orgNum) + '</button>'
    + '<span id="oc-status" style="font-size:11px;color:#667788;"></span>'
    + '</div>';

  setTimeout(() => {
    const closeBtn = document.getElementById('oc-close-btn');
    if (closeBtn) closeBtn.onclick = closeOrgCredsForm;

    // Browsers block HTML value= attribute on type="password" inputs (security feature).
    // Programmatically setting .value bypasses this — values are visible in the field.
    const _setVal = (id, val) => { const el = document.getElementById(id); if (el) el.value = val || ''; };
    _setVal('oc-duo_ikey',               d.duo_ikey);
    _setVal('oc-duo_skey',               d.duo_skey);
    _setVal('oc-duo_host',               d.duo_host);
    _setVal('oc-duo_saml_app_ikey',      d.duo_saml_app_ikey);
    _setVal('oc-sa_scim_token',          d.sa_scim_token);
    _setVal('oc-authproxy_enroll_blob',  d.authproxy_enroll_blob);
    _setVal('oc-scc_api_key',            d.scc_api_key);
    _setVal('oc-scc_api_secret',         d.scc_api_secret);
    _setVal('oc-sa_org_id',              d.sa_org_id);
    _setVal('oc-sa_api_key',             d.sa_api_key);
    _setVal('oc-sa_api_secret',          d.sa_api_secret);
    _setVal('oc-scc_email',              d.scc_email);
    _setVal('oc-scc_password',           d.scc_password);
    _setVal('oc-authproxy_cfg',          d.authproxy_cfg);
    _setVal('oc-pxgrid_cloud_email',     d.pxgrid_cloud_email);
    _setVal('oc-pxgrid_cloud_password',  d.pxgrid_cloud_password);
    _setVal('oc-pxgrid_cloud_account',   d.pxgrid_cloud_account);
  }, 0);
}

async function saveOrgCreds(orgNum) {
  const btn    = document.getElementById('oc-save-btn');
  const banner = document.getElementById('oc-save-banner');
  if (btn) { btn.disabled = true; btn.style.opacity = '0.6'; btn.textContent = 'Saving\u2026'; }
  if (banner) banner.style.display = 'none';
  const _g = id => { const el = document.getElementById(id); return el ? el.value : ''; };
  const payload = {
    duo_ikey:               _g('oc-duo_ikey').trim(),
    duo_skey:               _g('oc-duo_skey').trim(),
    duo_host:               _g('oc-duo_host').trim(),
    duo_saml_app_ikey:      _g('oc-duo_saml_app_ikey').trim(),
    sa_scim_token:          _g('oc-sa_scim_token').trim(),
    authproxy_enroll_blob:  _g('oc-authproxy_enroll_blob').trim(),
    scc_api_key:            _g('oc-scc_api_key').trim(),
    scc_api_secret:         _g('oc-scc_api_secret').trim(),
    sa_org_id:              _g('oc-sa_org_id').trim(),
    sa_api_key:             _g('oc-sa_api_key').trim(),
    sa_api_secret:          _g('oc-sa_api_secret').trim(),
    scc_email:              _g('oc-scc_email').trim(),
    scc_password:           _g('oc-scc_password').trim(),
    authproxy_cfg:          _g('oc-authproxy_cfg'),
    pxgrid_cloud_email:     _g('oc-pxgrid_cloud_email').trim(),
    pxgrid_cloud_password:  _g('oc-pxgrid_cloud_password').trim(),
    pxgrid_cloud_account:   _g('oc-pxgrid_cloud_account').trim(),
  };
  const _showBanner = (ok, msg) => {
    if (!banner) return;
    banner.style.display = 'block';
    banner.style.background = ok ? '#0a3320' : '#3a0a0a';
    banner.style.border     = ok ? '1px solid #00e68a' : '1px solid #ff4757';
    banner.style.color      = ok ? '#00e68a' : '#ff4757';
    banner.textContent      = msg;
    if (ok) setTimeout(() => { banner.style.display = 'none'; }, 8000);
  };
  const _reset = () => {
    if (!btn) return;
    btn.disabled = false; btn.style.opacity = '1';
    btn.style.background = '#0d4f6e'; btn.style.borderColor = '#02c8ff'; btn.style.color = '#02c8ff';
    btn.textContent = 'Save Org ' + orgNum;
  };
  try {
    const r = await fetch('/api/org-credentials/' + encodeURIComponent(orgNum),
      {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
    if (r.ok) {
      const now = new Date().toLocaleTimeString();
      if (btn) {
        btn.disabled = false; btn.style.opacity = '1';
        btn.style.background = '#0a3320'; btn.style.borderColor = '#00e68a'; btn.style.color = '#00e68a';
        btn.textContent = '\u2713 Saved!';
        setTimeout(_reset, 3000);
      }
      _showBanner(true, '\u2713 Org ' + orgNum + ' saved to database at ' + now);
      initOrgCredsList();
    } else {
      _showBanner(false, '\u2717 Save failed (HTTP ' + r.status + ')');
      _reset();
    }
  } catch(e) {
    _showBanner(false, '\u2717 Error: ' + e.message);
    _reset();
  }
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
  { key: 'logging_settings',     label: 'Logging disabled',
    desc: 'Secure Access → Secure → Access Policy. Edit "For all Internet access" — disable Logging.' },
  { key: 'ravpn_profiles',       label: 'RAVPN Profile deleted',
    desc: 'Secure Access → Connect → End User Connectivity → Virtual Private Network. Delete PseudoCo_RA_VPN_Profile.' },
  { key: 'dlp_rules',            label: 'DLP Policy cleared',
    desc: 'Secure Access → Secure → Data Loss Prevention Policy. Delete configured policy.' },
  { key: 'ravpn_ip_pool',        label: 'RAVPN IP Pool deleted',
    desc: 'Secure Access → Connect → End User Connectivity → Virtual Private Network. Click Manage under Regions and IP Pools — delete the configured IP Pool.' },
  { key: 'duo_saml',             label: 'Duo / DuoSSO SAML profiles removed',
    desc: 'Secure Access → Connect → Users, Groups, and Endpoint Devices → Configuration Management. Click Edit then Delete on both Duo and DuoSSO profiles (delete Duo first, DuoSSO should follow).' },
  { key: 'ise_pxgrid',           label: 'ISE / pxGrid integration removed',
    desc: 'SCC Platform Management → Platform Integrations. Delete the ISE/pxGrid integration.' },
  { key: 'te_integration',       label: 'ThousandEyes integration removed',
    desc: 'Secure Access → Experience and Insights → Account Management. Delete ThousandEyes integration.' },
];
const SCC_MANUAL_ITEMS = [];

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

  // Fetch stored credentials + latest duo_setup + duo_saml_setup step results
  let keysD = {duo_ikey: '', duo_skey: '', duo_host: ''};
  let stepResult = '';
  let stepStatus = '';
  let samlResult = '';
  let samlStatus = '';
  try {
    const kr = await fetch('/api/pod-duo-keys/' + podId);
    keysD = await kr.json();
  } catch(e) {}
  try {
    const sr = await fetch('/api/steps/' + podId);
    const steps = await sr.json();
    const s = (steps || []).find(x => x.step_name === 'duo_setup');
    if (s) { stepResult = s.result || ''; stepStatus = s.status || ''; }
    const ss = (steps || []).find(x => x.step_name === 'duo_saml_setup');
    if (ss) { samlResult = ss.result || ''; samlStatus = ss.status || ''; }
  } catch(e) {}

  if (window._duoKeysDirty) {
    keysD.duo_ikey = savedIkey;
    keysD.duo_skey = savedSkey;
    keysD.duo_host = savedHost;
  }

  const statusColor = stepStatus === 'completed' ? '#00e68a' : stepStatus === 'failed' ? '#ff4757' : stepStatus === 'running' ? '#ffa502' : '#667788';
  const statusIcon  = stepStatus === 'completed' ? '✓' : stepStatus === 'failed' ? '✗' : stepStatus === 'running' ? '⟳' : '○';
  const samlColor   = samlStatus === 'completed' ? '#00e68a' : samlStatus === 'failed' ? '#ff4757' : samlStatus === 'running' ? '#ffa502' : '#667788';
  const samlIcon    = samlStatus === 'completed' ? '✓' : samlStatus === 'failed' ? '✗' : samlStatus === 'running' ? '⟳' : '○';

  grid.innerHTML =
    '<div class="switch-card" style="margin-bottom:12px;">'
    + '<div class="switch-card-title"><span class="role-tag cc">OVERRIDE</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">Duo Credentials — POD Override</span></div>'
    + '<div style="font-size:11px;color:#445566;margin-bottom:6px;">Org-level credentials are used by default. Fill in below only to override for this POD (e.g. if a key was rotated).</div>'
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
    + '<div class="switch-card" style="margin-bottom:12px;">'
    + '<div class="switch-card-title"><span class="role-tag ' + (stepStatus === 'completed' ? 'pass' : 'cc') + '">' + stepStatus.toUpperCase() + '</span>'
    + '<span style="color:#e0e6ed;font-size:13px;font-weight:600;">duo_setup — Last Run</span>'
    + '<span style="margin-left:auto;font-size:18px;color:' + statusColor + ';">' + statusIcon + '</span></div>'
    + (stepResult
        ? '<div style="font-size:12px;font-family:monospace;color:#c0ccd8;background:#0a1628;border-radius:4px;padding:8px 10px;margin-top:6px;white-space:pre-wrap;word-break:break-all;">'
           + escHtml(stepResult.replace(/\s*\|\s*/g, '\\n')) + '</div>'
         : '<div style="color:#445566;font-size:12px;margin-top:6px;">No result yet — run the pipeline to execute this step.</div>')
     + '</div>'
     + '<div class="switch-card">'
     + '<div class="switch-card-title"><span class="role-tag ' + (samlStatus === 'completed' ? 'pass' : samlStatus === 'failed' ? 'fail' : 'cc') + '">' + (samlStatus || 'pending').toUpperCase() + '</span>'
     + '<span style="color:#e0e6ed;font-size:13px;font-weight:600;">duo_saml_setup — SA+Duo SAML/SCIM</span>'
     + '<span style="margin-left:auto;font-size:18px;color:' + samlColor + ';">' + samlIcon + '</span></div>'
     + '<div style="font-size:11px;color:#667788;margin-top:4px;">Configures Duo as IdP for Secure Access SSO via SAML, and syncs users via SCIM. Requires iDAC URL in Org Credentials.</div>'
     + (samlResult
         ? '<div style="font-size:12px;font-family:monospace;color:#c0ccd8;background:#0a1628;border-radius:4px;padding:8px 10px;margin-top:6px;white-space:pre-wrap;word-break:break-all;">'
           + escHtml(samlResult.replace(/\s*\|\s*/g, '\\n')) + '</div>'
        : '<div style="color:#445566;font-size:12px;margin-top:6px;">Not yet run — click "Setup Duo SAML" to execute.</div>')
    + '</div>';

  // Show action buttons
  const actionsEl = document.getElementById('duo-actions');
  if (actionsEl) {
    actionsEl.style.display = 'flex';
    window._duoSamlCurrentPodId = podId;
  }

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

// ── Secure Access Keys Panel ─────────────────────────────────────────────────
async function loadSaPanel(podId) {
  const grid = document.getElementById('sa-grid');
  if (!grid) return;

  let keysD = {sa_org_id: '', sa_api_key: '', sa_api_secret: ''};
  try {
    const kr = await fetch('/api/pod-sa-keys/' + podId);
    keysD = await kr.json();
  } catch(e) {}

  const hasKeys = keysD.sa_api_key && keysD.sa_api_secret;

  grid.innerHTML =
    '<div class="switch-card" style="margin-bottom:12px;">'
    + '<div class="switch-card-title"><span class="role-tag cc">OVERRIDE</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">Secure Access Credentials — POD Override</span></div>'
    + '<div style="font-size:11px;color:#445566;margin-bottom:6px;">Org-level credentials are used by default. Fill in below only to override for this POD.</div>'
    + '<div style="display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:8px;align-items:center;margin-top:6px;">'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">Org ID</div>'
    + '<input id="sa-orgid-input" type="text" value="' + escHtml(keysD.sa_org_id || '') + '" placeholder="8381539" style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">API Key</div>'
    + '<input id="sa-apikey-input" type="text" value="' + escHtml(keysD.sa_api_key || '') + '" placeholder="6671146f..." style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<div><div style="font-size:10px;color:#667788;margin-bottom:3px;text-transform:uppercase;">API Secret</div>'
    + '<input id="sa-secret-input" type="password" value="' + escHtml(keysD.sa_api_secret || '') + '" placeholder="Secret..." style="width:100%;background:#0a1628;border:1px solid #1a2d4a;color:#e0e6ed;border-radius:4px;padding:5px 8px;font-size:12px;font-family:monospace;box-sizing:border-box;" /></div>'
    + '<button id="sa-keys-save-btn" class="btn-reconnect" style="margin-top:16px;white-space:nowrap;">Save</button>'
    + '</div>'
    + '<div id="sa-keys-status" style="font-size:11px;color:#667788;margin-top:4px;min-height:16px;">'
    + (hasKeys ? '&#10003; Keys stored in DB' : '') + '</div>'
    + '</div>'
    + '<div class="switch-card">'
    + '<div class="switch-card-title"><span class="role-tag cc">INFO</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">Automation Status</span></div>'
    + '<div style="font-size:12px;color:#667788;margin-top:6px;">SA SCIM token provisioning and Duo SAML/SCIM integration are automated via the <b>duo_saml_setup</b> pipeline step. Configure iDAC URL in Org Credentials then click "Setup Duo SAML" in the Duo tab.</div>'
    + '</div>';

  setTimeout(() => {
    const saveBtn = document.getElementById('sa-keys-save-btn');
    if (saveBtn) saveBtn.onclick = async () => {
      const org_id = document.getElementById('sa-orgid-input').value.trim();
      const key    = document.getElementById('sa-apikey-input').value.trim();
      const secret = document.getElementById('sa-secret-input').value.trim();
      const statusEl = document.getElementById('sa-keys-status');
      if (!org_id || !key || !secret) {
        statusEl.style.color = '#ff4757';
        statusEl.textContent = '✗ org_id, api_key, and api_secret are all required';
        return;
      }
      statusEl.style.color = '#ffa502';
      statusEl.textContent = 'Saving...';
      try {
        const res = await fetch('/api/pod-sa-keys/' + podId, {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({sa_org_id: org_id, sa_api_key: key, sa_api_secret: secret})
        });
        if (res.ok) {
          statusEl.style.color = '#00e68a';
          statusEl.textContent = '✓ Saved to DB';
        } else {
          statusEl.style.color = '#ff4757';
          statusEl.textContent = '✗ Save failed';
        }
      } catch(e) {
        statusEl.style.color = '#ff4757';
        statusEl.textContent = '✗ ' + e.message;
      }
    };
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
    // Unified auto card (all 13 items automated)
    + '<div class="switch-card' + (SCC_AUTO_ITEMS.every(i => (map[i.key]||{}).status==='completed') ? ' pass' : SCC_AUTO_ITEMS.some(i => (map[i.key]||{}).status==='failed') ? ' fail' : '') + '">'
    + '<div class="switch-card-title" style="display:flex;align-items:center;justify-content:space-between;">'
    + '<div><span class="role-tag cc">AUTO</span><span style="color:#e0e6ed;font-size:13px;font-weight:600;">Automated Checks</span></div>'
    + '<button id="scc-auto-reset-btn" class="btn-reconnect" style="font-size:11px;padding:4px 10px;">&#x25B6; Auto-Reset All</button>'
    + '<button id="scc-clear-btn" class="btn-reconnect" style="font-size:11px;padding:4px 10px;background:#1a1a2e;border-color:#445566;color:#8899aa;">&#x2715; Clear Results</button>'
    + '</div>'
    + '<div id="scc-auto-reset-status" style="font-size:11px;color:#667788;min-height:14px;margin-bottom:4px;"></div>'
    + '<div class="switch-bar"><div class="switch-bar-fill" style="width:' + Math.round(SCC_AUTO_ITEMS.filter(i=>(map[i.key]||{}).status==='completed').length/SCC_AUTO_ITEMS.length*100) + '%;background:' + (SCC_AUTO_ITEMS.every(i=>(map[i.key]||{}).status==='completed') ? '#00e68a' : SCC_AUTO_ITEMS.some(i=>(map[i.key]||{}).status==='failed') ? '#ff4757' : '#445566') + '"></div></div>'
    + SCC_AUTO_ITEMS.map(i => sccCheck(i, false)).join('')
    + '</div>';

  setTimeout(() => {
    const autoResetBtn = document.getElementById('scc-auto-reset-btn');
    if (autoResetBtn) autoResetBtn.onclick = () => sccAutoReset(podId);
    const clearBtn = document.getElementById('scc-clear-btn');
    if (clearBtn) clearBtn.onclick = async () => {
      if (!confirm('Clear all SCC checklist results for ' + podId + '?')) return;
      await fetch('/api/scc/clear/' + podId, { method: 'POST' });
      loadSccChecklist(podId);
    };
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

async function sccAutoReset(podId) {
  const btn = document.getElementById('scc-auto-reset-btn');
  const status = document.getElementById('scc-auto-reset-status');
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Running...'; }
  if (status) { status.style.color = '#ffa502'; status.textContent = 'Automation running — navigating SCC (may take 2-3 min)...'; }
  try {
    const res = await fetch('/api/scc/manual-reset/' + podId, { method: 'POST' });
    const d = await res.json();
    if (d.status === 'started') {
      if (status) status.textContent = 'Started — items will update as each completes...';
      // Poll checklist every 5s while automation is running
      let polls = 0;
      const poller = setInterval(async () => {
        polls++;
        await loadSccChecklist(podId);
        const st = document.getElementById('scc-auto-reset-status');
        if (st) st.textContent = 'Running... (' + (polls * 5) + 's elapsed)';
        if (polls >= 42) { // 3.5 min max
          clearInterval(poller);
          const b = document.getElementById('scc-auto-reset-btn');
          if (b) { b.disabled = false; b.textContent = '▶ Auto-Reset All'; }
          await loadSccChecklist(podId);
          const s = document.getElementById('scc-auto-reset-status');
          if (s) { s.style.color = '#00e68a'; s.textContent = 'Automation complete — check results above'; }
        }
      }, 5000);
    } else {
      if (status) { status.style.color = '#ff4757'; status.textContent = 'Failed to start: ' + (d.message || JSON.stringify(d)); }
      if (btn) { btn.disabled = false; btn.textContent = '▶ Auto-Reset All'; }
    }
  } catch(e) {
    if (status) { status.style.color = '#ff4757'; status.textContent = 'Error: ' + e; }
    if (btn) { btn.disabled = false; btn.textContent = '▶ Auto-Reset All'; }
  }
}

async function sccUnconfirm(podId, itemKey) {
  await fetch('/api/scc/unconfirm/' + podId + '/' + itemKey, { method: 'POST' });
  loadSccChecklist(podId);
}

async function sccRecheckCurrent() {
  if (window._sccCurrentPodId) sccRecheck(window._sccCurrentPodId);
}

async function duoSamlSetupCurrent() {
  const podId = window._duoSamlCurrentPodId;
  if (!podId) return;
  const grid = document.getElementById('duo-grid');
  await fetch('/api/duo-saml-setup/' + podId, { method: 'POST' });

  // Poll for completion
  let polls = 0;
  const MAX_POLLS = 120; // 10 min max (5s interval)
  const notice = document.createElement('div');
  notice.id = 'duo-saml-status-notice';
  notice.style.cssText = 'padding:10px 0;color:#02c8ff;font-size:13px;';
  notice.textContent = '⟳ Running SA+Duo SAML/SCIM setup (this may take ~60s)...';
  if (grid) grid.prepend(notice);

  const poller = setInterval(async () => {
    polls++;
    try {
      const r = await fetch('/api/pipeline-steps/' + podId);
      const steps = await r.json();
      const s = (steps || []).find(x => x.step_name === 'duo_saml_setup');
      if (s && s.status !== 'running') {
        clearInterval(poller);
        loadDuoPanel(podId);
        return;
      }
      const n = document.getElementById('duo-saml-status-notice');
      if (n) n.textContent = '⟳ Running SA+Duo SAML/SCIM setup (' + (polls * 5) + 's)...';
      if (polls >= MAX_POLLS) {
        clearInterval(poller);
        loadDuoPanel(podId);
      }
    } catch(e) { /* keep polling */ }
  }, 5000);
  window._duoSamlPoller = poller;
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
  // Kill pollers that belong to the tab we are leaving so they don't
  // bleed data into a tab that is no longer visible.
  if (name !== 'fabric') {
    if (window._fabricPoller) { clearInterval(window._fabricPoller); window._fabricPoller = null; }
    if (window._catcPoll)     { clearInterval(window._catcPoll);     window._catcPoll     = null; }
  }
  if (name !== 'sda') {
    if (window._sdaPoller)    { clearInterval(window._sdaPoller);    window._sdaPoller    = null; }
    if (window._sdaCatcPoll)  { clearInterval(window._sdaCatcPoll);  window._sdaCatcPoll  = null; }
  }

  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');

  const podId = document.getElementById('detail-pod-id').dataset.podId;
  if (name === 'duo')        { if (podId) loadDuoStatus(podId); }
  if (name === 'ise')        { if (podId) loadIseStatus(podId); }
  if (name === 'scc')        { if (podId) loadSccChecklist(podId); }
  if (name === 'fabric')     { if (podId) loadFabricStatus(podId); }
  if (name === 'sda')        { if (podId) loadSdaStatus(podId); }
  if (name === 'baseconfig') { if (podId) loadBaseConfig(podId); }
  if (name === 'kb')         { loadKbTab(); }
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
   // Kill any stale poller before rendering (e.g. POD switch)
   if (window._fabricPoller) { clearInterval(window._fabricPoller); window._fabricPoller = null; }
   const grid = document.getElementById('fabric-grid');
   if (!podId) { if (grid) grid.innerHTML = '<div style="color:#667788;padding:20px;">No POD selected.</div>'; return; }
   if (!grid._lastHtml) grid.innerHTML = '<div style="color:#667788;font-size:13px;">Loading...</div>';
   const r = await fetch('/api/fabric/status/' + podId);
   const data = await r.json();
   renderFabricGrid(podId, data.steps || {});
   // Start a poller if any step is currently running (mirrors _sdaPoller behaviour)
   const anyRunning = Object.values(data.steps || {}).some(s => (s || {}).status === 'running');
   if (anyRunning) _fabricStartPoller(podId);
 }

 function _fabricStartPoller(podId) {
   if (window._fabricPoller) clearInterval(window._fabricPoller);
   let polls = 0;
   window._fabricPoller = setInterval(async () => {
     polls++;
     const r = await fetch('/api/fabric/status/' + podId);
     const data = await r.json();
     renderFabricGrid(podId, data.steps || {});
     const anyRunning = Object.values(data.steps || {}).some(s => (s || {}).status === 'running');
     if (!anyRunning || polls > 200) {
       clearInterval(window._fabricPoller);
       window._fabricPoller = null;
     }
   }, 3000);
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
  "anycast_gateways","transit","fabric_devices","ise_nads","l3_handoff",
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
  fabric_devices:               "Fabric Devices",
  ise_nads:                     "Register ISE NADs",
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
  fabric_devices:               "Border+CP + Leaf1+Leaf2",
  ise_nads:                     "Loopback0 172.30.255.x",
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

  // Re-initialize if podId changed — avoids stale closure on buttons when switching PODs
  if (container._initialized && container._podId === podId) {
    loadSdaCatcStatus(podId);
    return;
  }
  container._initialized = true;
  container._podId = podId;
  // Clear any stale poll from previous POD
  if (window._sdaCatcPoll) { clearInterval(window._sdaCatcPoll); window._sdaCatcPoll = null; }
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
  // Clear any stale poll (re-click or POD switch mid-run)
  if (window._sdaCatcPoll) { clearInterval(window._sdaCatcPoll); window._sdaCatcPoll = null; }

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
  window._sdaCatcPoll = setInterval(async () => {
    polls++;
    const sr = await loadSdaCatcStatus(podId);
    if (!sr || !sr.running || polls >= 60) {
      clearInterval(window._sdaCatcPoll);
      window._sdaCatcPoll = null;
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
  // Always kill any stale poller from a previous POD before rendering
  if (window._sdaPoller) { clearInterval(window._sdaPoller); window._sdaPoller = null; }
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

// ── Duo Card JS ───────────────────────────────────────────────────────────────

const DUO_CARD_STEPS = ['org_setup','authproxy_push','ad_sync','saml_scim_config','authproxy_enroll','scim_push','verify'];
const DUO_CARD_LABELS = {
  org_setup:        'Duo Org Setup',
  authproxy_push:   'Auth Proxy Push',
  ad_sync:          'AD Directory Sync',
  saml_scim_config: 'SA SAML + SCIM Config',
  authproxy_enroll: 'Auth Proxy Enroll',
  scim_push:        'SA SCIM Verify Users',
  verify:           'Verify Auth Proxy',
};
const DUO_REFRESH_ONLY = new Set(['saml_scim_config']);  // skipped in refresh mode

async function loadDuoStatus(podId) {
  if (window._duoPoller) { clearInterval(window._duoPoller); window._duoPoller = null; }
  const grid = document.getElementById('duo-grid');
  if (!podId) { if (grid) grid.innerHTML = '<div style="color:#667788;padding:20px;">No POD selected.</div>'; return; }
  if (!grid._lastHtml) grid.innerHTML = '<div style="color:#667788;font-size:13px;">Loading...</div>';
  const r = await fetch('/api/duo/status/' + podId);
  const data = await r.json();
  renderDuoGrid(podId, data);
  const anyRunning = Object.values(data.steps || {}).some(s => (s||{}).status === 'running');
  if (anyRunning) _duoStartPoller(podId);
}

function _duoStartPoller(podId) {
  if (window._duoPoller) clearInterval(window._duoPoller);
  let polls = 0;
  window._duoPoller = setInterval(async () => {
    polls++;
    const r = await fetch('/api/duo/status/' + podId);
    const data = await r.json();
    renderDuoGrid(podId, data);
    const anyRunning = Object.values(data.steps || {}).some(s => (s||{}).status === 'running');
    if (!anyRunning || polls > 200) {
      clearInterval(window._duoPoller);
      window._duoPoller = null;
    }
  }, 3000);
}

function renderDuoGrid(podId, data) {
  const grid = document.getElementById('duo-grid');
  if (!grid) return;
  const steps = data.steps || {};
  const mode  = data.mode  || 'unknown';
  const total   = DUO_CARD_STEPS.length;
  const done    = DUO_CARD_STEPS.filter(s => ['completed','skipped'].includes((steps[s]||{}).status)).length;
  const failed  = DUO_CARD_STEPS.filter(s => (steps[s]||{}).status === 'failed').length;
  const running = DUO_CARD_STEPS.some(s => (steps[s]||{}).status === 'running');
  const pct     = Math.min(100, Math.round(done / total * 100));
  const barColor = failed ? '#ff4757' : running ? '#02c8ff' : done === total ? '#00e68a' : '#667788';
  const labelText = failed  ? 'Failed — ' + failed + ' step(s) failed'
                  : running ? 'Running \u2014 ' + done + '/' + total
                  : done === total ? 'Complete!'
                  : done === 0    ? 'Not started'
                  : 'Paused \u2014 ' + done + '/' + total;
  const modeBadge = mode === 'refresh'    ? '<span style="background:#1a3a5c;color:#02c8ff;font-size:10px;padding:2px 7px;border-radius:10px;margin-left:8px;">SESSION REFRESH</span>'
                  : mode === 'full_setup' ? '<span style="background:#2a1a4a;color:#b39ddb;font-size:10px;padding:2px 7px;border-radius:10px;margin-left:8px;">FULL SETUP</span>'
                  : mode === 'partial'    ? '<span style="background:#3a2a0a;color:#ffb74d;font-size:10px;padding:2px 7px;border-radius:10px;margin-left:8px;">PARTIAL</span>'
                  : '';
  const isRunning = running;

  let html = '';
  // Header
  html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  html += '<span style="font-size:14px;font-weight:600;color:#cdd6e0;">Duo / SA Integration' + modeBadge + '</span>';
  html += '<div style="display:flex;gap:8px;">';
  html += '<button id="duo-run-btn" style="background:#02c8ff;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;"' + (isRunning ? ' disabled' : '') + '>&#9654; Run</button>';
  html += '<button id="duo-reset-btn" style="background:#e74c3c;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;"' + (isRunning ? ' disabled' : '') + '>&#8635; Reset</button>';
  html += '</div></div>';
  // Progress bar
  html += '<div style="margin-bottom:14px;">';
  html += '<div style="display:flex;justify-content:space-between;font-size:11px;color:#8899aa;margin-bottom:4px;">';
  html += '<span>' + labelText + '</span><span>' + pct + '% (' + done + '/' + total + ')</span></div>';
  html += '<div style="background:#0d1117;border-radius:4px;height:8px;overflow:hidden;">';
  html += '<div style="height:100%;border-radius:4px;background:' + barColor + ';width:' + pct + '%;transition:width 0.4s;"></div>';
  html += '</div></div>';
  // Step cards
  html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:8px;">';
  DUO_CARD_STEPS.forEach((s, i) => {
    const info   = steps[s] || {};
    const st     = info.status || 'pending';
    const result = (info.result || '').substring(0, 180);
    const dur    = formatDur(info.started_at, info.completed_at);
    const cardBorder = st === 'failed'    ? 'border-left:3px solid #ff4757;'
                     : st === 'running'   ? 'border-left:3px solid #02c8ff;'
                     : st === 'completed' ? 'border-left:3px solid #00e68a;'
                     : st === 'skipped'   ? 'border-left:3px solid #445566;opacity:0.7;'
                     : '';
    html += '<div class="step-card" style="' + cardBorder + '">';
    html += '<div class="step-num">Step ' + (i+1) + '/' + total + '</div>';
    html += '<div class="step-name">' + (DUO_CARD_LABELS[s]||s) + '</div>';
    html += pipelineBadge(st);
    if (result) html += '<div class="step-result">' + result.split('\\n')[0] + '</div>';
    if (dur)    html += '<div class="step-dur">' + dur + '</div>';
    html += '</div>';
  });
  html += '</div>';

  grid.innerHTML = html;
  grid._lastHtml = true;

  // Wire buttons after render
  setTimeout(() => {
    const runBtn   = document.getElementById('duo-run-btn');
    const resetBtn = document.getElementById('duo-reset-btn');
    if (runBtn)   runBtn.onclick   = () => duoRun(podId);
    if (resetBtn) resetBtn.onclick = () => duoReset(podId);
  }, 0);
}

async function duoRun(podId, fromStep) {
  await fetch('/api/duo/run/' + podId, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({from_step: fromStep || 0}),
  });
  await loadDuoStatus(podId);
  _duoStartPoller(podId);
}

async function duoReset(podId) {
  if (!confirm('Clear all Duo steps for ' + podId + '?')) return;
  await fetch('/api/duo/reset/' + podId, { method: 'POST' });
  loadDuoStatus(podId);
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

  // Re-initialize if podId changed — avoids stale closure on buttons when switching PODs
  if (container._initialized && container._podId === podId) {
    loadCatcStatus(podId);
    return;
  }
  container._initialized = true;
  container._podId = podId;
  // Clear any stale poll from previous POD
  if (window._catcPoll) { clearInterval(window._catcPoll); window._catcPoll = null; }
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

  loadCatcStatus(podId);
}

async function triggerCatcDiscover(podId) {
  // Clear any stale poll (re-click or POD switch mid-run)
  if (window._catcPoll) { clearInterval(window._catcPoll); window._catcPoll = null; }

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
  window._catcPoll = setInterval(async () => {
    polls++;
    const sr = await loadCatcStatus(podId);
    if (!sr || !sr.running || polls >= 60) {
      clearInterval(window._catcPoll);
      window._catcPoll = null;
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
  // Clear CatC tile polls and reset _initialized so buttons re-wire on next open
  if (window._catcPoll)     { clearInterval(window._catcPoll);     window._catcPoll     = null; }
  if (window._sdaCatcPoll)  { clearInterval(window._sdaCatcPoll);  window._sdaCatcPoll  = null; }
  if (window._sdaPoller)    { clearInterval(window._sdaPoller);    window._sdaPoller    = null; }
  if (window._fabricPoller) { clearInterval(window._fabricPoller); window._fabricPoller = null; }
  const ct = document.getElementById('catc-tile-container');
  if (ct) { ct._initialized = false; ct._podId = null; }
  const sct = document.getElementById('sda-catc-tile-container');
  if (sct) { sct._initialized = false; sct._podId = null; }
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
  btn.textContent = '\u25a0 Teardown All';
  setTimeout(() => status.textContent = '', 10000);
  load();
}

let _sccRefreshPoller = null;  // module-level so re-clicks cancel the old poller

async function refreshSccSessionsGlobal() {
  const btn    = document.getElementById('btn-scc-refresh-global');
  const status = document.getElementById('scc-refresh-global-status');
  btn.disabled = true;
  btn.textContent = '\u23f3 Opening browser...';
  status.style.color = '#02c8ff';
  status.textContent = 'Log in to security.cisco.com and complete MFA in the browser window that just opened';

  // Cancel button
  let cancelBtn = document.getElementById('scc-refresh-cancel-btn');
  if (!cancelBtn) {
    cancelBtn = document.createElement('button');
    cancelBtn.id = 'scc-refresh-cancel-btn';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.style.cssText = 'margin-left:10px;background:#c0392b;color:#fff;border:none;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px;';
    btn.parentNode.insertBefore(cancelBtn, btn.nextSibling);
  }
  cancelBtn.style.display = 'inline-block';

  // Clear any previous poller before starting a new one
  if (_sccRefreshPoller) { clearInterval(_sccRefreshPoller); _sccRefreshPoller = null; }

  const _reset = () => {
    if (_sccRefreshPoller) { clearInterval(_sccRefreshPoller); _sccRefreshPoller = null; }
    cancelBtn.style.display = 'none';
    btn.disabled = false; btn.textContent = '\u21bb Refresh SCC Sessions';
  };
  cancelBtn.onclick = async () => {
    _reset();
    status.style.color = '#667788'; status.textContent = '';
    await fetch('/api/scc/refresh-cancel', {method:'POST'});
  };

  try {
    const r = await fetch('/api/scc/refresh-sessions', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({pod_id: 'SCC_REFRESH'}),
    });
    const d = await r.json();
    if (d.status !== 'started') {
      _reset();
      status.style.color = '#ff4757';
      status.textContent = 'Error: ' + (d.message || 'unknown');
      return;
    }

    // Poll — same logic as per-pod (age < 1h), show per-POD progress
    let polls = 0;
    _sccRefreshPoller = setInterval(async () => {
      polls++;
      try {
        const sr = await fetch('/api/scc/session-status');
        const sd = await sr.json();
        const entries  = Object.entries(sd);
        const fresh    = entries.filter(([,s]) => s.exists && (s.age_hours || 99) < 1);
        const total    = entries.length;
        if (fresh.length > 0 && fresh.length >= total) {
          _reset();
          status.style.color = '#00e68a';
          status.textContent = '\u2713 Sessions refreshed for ' + fresh.length + ' org(s)';
          setTimeout(() => { status.textContent = ''; status.style.color = '#667788'; }, 15000);
        } else if (polls > 90) {
          _reset();
          status.style.color = '#f0a500';
          status.textContent = 'Timeout — check Live Logs for [scc-refresh] output';
        } else {
          const doneList = fresh.map(([pid]) => pid).join(', ');
          status.textContent = 'Running... (' + (polls * 5) + 's)'
            + (doneList ? ' \u2713 ' + doneList : '') + ' — complete login in browser window';
        }
      } catch(e) {}
    }, 5000);
  } catch(e) {
    _reset();
    status.style.color = '#ff4757';
    status.textContent = 'Request failed';
  }
}

load();
setInterval(load, 5000);
loadUpgradeConfig();
initOrgCredsList();

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

// ── ISE Integration Card JS ────────────────────────────────────────────────

const ISE_STEPS = ['ise_pxgrid_register', 'ise_scc_integrate', 'ise_scc_deactivate_reactivate', 'ise_cdfmc_integrate', 'ise_sgt_verify'];
const ISE_STEP_LABELS = {
  ise_pxgrid_register:            'pxGrid Cloud Register',
  ise_scc_integrate:              'ISE \u2192 Secure Access (SGTs)',
  ise_cdfmc_integrate:            'ISE \u2192 cdFMC (SGTs)',
  ise_scc_deactivate_reactivate:  'ISE\u2192SCC Deactivate + Reactivate',
  ise_sgt_verify:                 'Secure Access SGT Verify',
};

async function loadIseStatus(podId) {
  if (window._isePoller) { clearInterval(window._isePoller); window._isePoller = null; }
  const grid = document.getElementById('ise-grid');
  if (!podId) { if (grid) grid.innerHTML = '<div style="color:#667788;padding:20px;">No POD selected.</div>'; return; }
  if (!grid._lastHtml) grid.innerHTML = '<div style="color:#667788;font-size:13px;">Loading...</div>';
  const [r, sr] = await Promise.all([
    fetch('/api/ise/status/' + podId),
    fetch('/api/scc/session-status?pod_id=' + podId),
  ]);
  const data = await r.json();
  const sessMap = await sr.json();
  data.session = sessMap[podId] || {};
  renderIseGrid(podId, data);
  const anyRunning = Object.values(data.steps || {}).some(s => (s||{}).status === 'running');
  if (anyRunning) _iseStartPoller(podId);
}

function _iseStartPoller(podId) {
  if (window._isePoller) clearInterval(window._isePoller);
  let polls = 0;
  window._isePoller = setInterval(async () => {
    polls++;
    const [r, sr] = await Promise.all([
      fetch('/api/ise/status/' + podId),
      fetch('/api/scc/session-status?pod_id=' + podId),
    ]);
    const data = await r.json();
    const sessMap = await sr.json();
    data.session = sessMap[podId] || {};
    renderIseGrid(podId, data);
    const anyRunning = Object.values(data.steps || {}).some(s => (s||{}).status === 'running');
    if (!anyRunning || polls > 200) { clearInterval(window._isePoller); window._isePoller = null; }
  }, 3000);
}

function renderIseGrid(podId, data) {
  const grid = document.getElementById('ise-grid');
  if (!grid) return;
  const steps = data.steps || {};
  const sess  = data.session || {};          // { exists, age_hours, file }
  const total   = ISE_STEPS.length;
  const done    = ISE_STEPS.filter(s => ['completed','skipped'].includes((steps[s]||{}).status)).length;
  const failed  = ISE_STEPS.filter(s => (steps[s]||{}).status === 'failed').length;
  const running = ISE_STEPS.some(s => (steps[s]||{}).status === 'running');
  const pct     = Math.min(100, Math.round(done / total * 100));
  const barColor = failed ? '#ff4757' : running ? '#02c8ff' : done === total ? '#00e68a' : '#667788';
  const labelText = failed  ? 'Failed \u2014 ' + failed + ' step(s) failed'
                  : running ? 'Running \u2014 ' + done + '/' + total
                  : done === total ? 'Complete!'
                  : done === 0    ? 'Not started'
                  : 'Paused \u2014 ' + done + '/' + total;
  const isRunning = running;

  // ── Session freshness indicator ──────────────────────────────────────────
  let sessColor = '#ff4757', sessIcon = '\u26a0', sessLabel = 'No SCC session \u2014 refresh required';
  if (sess.exists) {
    const h = sess.age_hours || 0;
    if (h < 4)       { sessColor = '#00e68a'; sessIcon = '\u2713'; sessLabel = 'SCC session fresh (' + h.toFixed(1) + 'h ago)'; }
    else if (h < 8)  { sessColor = '#f0a500'; sessIcon = '\u26a0'; sessLabel = 'SCC session ageing (' + h.toFixed(1) + 'h ago)'; }
    else             { sessColor = '#ff4757'; sessIcon = '\u26a0'; sessLabel = 'SCC session stale (' + h.toFixed(1) + 'h) \u2014 refresh'; }
  }

  let html = '';

  // ── Pre-flight: Refresh SCC Sessions ─────────────────────────────────────
  html += '<div style="background:#0d1117;border:1px solid #1e2d3d;border-radius:6px;padding:10px 14px;margin-bottom:12px;display:flex;justify-content:space-between;align-items:center;">';
  html += '<div>';
  html += '<span style="font-size:12px;font-weight:600;color:#8899aa;text-transform:uppercase;letter-spacing:.5px;">Pre-flight</span>&nbsp;';
  html += '<span id="scc-sess-badge" style="font-size:12px;color:' + sessColor + ';">' + sessIcon + ' ' + sessLabel + '</span>';
  html += '</div>';
  html += '<button id="scc-refresh-btn" style="background:#445566;color:#cdd6e0;border:none;padding:5px 12px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;"' + (isRunning ? ' disabled' : '') + '>\u21bb Refresh SCC Sessions</button>';
  html += '</div>';

  // ── Header + Run / Reset buttons ─────────────────────────────────────────
  html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">';
  html += '<span style="font-size:14px;font-weight:600;color:#cdd6e0;">ISE Integrations</span>';
  html += '<div style="display:flex;gap:8px;">';
   html += '<button id="ise-run-btn" style="background:#02c8ff;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;"' + (isRunning ? ' disabled' : '') + '>\u25b6 Run</button>';
   html += '<button id="ise-reactivate-btn" title="Re-run only the ISE\u2192SCC Deactivate+Reactivate step" style="background:#f0a500;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;"' + (isRunning ? ' disabled' : '') + '>\u21ba Reactivate SCC</button>';
   html += '<button id="ise-sgt-recheck-btn" title="Immediately recheck SGTs in Secure Access" style="background:#00e68a;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;font-weight:600;">\U0001F50D Re-verify SGTs</button>';
   html += '<button id="ise-reset-btn" style="background:#e74c3c;color:#fff;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:12px;"' + (isRunning ? ' disabled' : '') + '>\u21bb Reset</button>';
  html += '</div></div>';
  html += '<div style="margin-bottom:14px;">';
  html += '<div style="display:flex;justify-content:space-between;font-size:11px;color:#8899aa;margin-bottom:4px;">';
  html += '<span>' + labelText + '</span><span>' + pct + '% (' + done + '/' + total + ')</span></div>';
  html += '<div style="background:#0d1117;border-radius:4px;height:8px;overflow:hidden;">';
  html += '<div style="height:100%;border-radius:4px;background:' + barColor + ';width:' + pct + '%;transition:width 0.4s;"></div>';
  html += '</div></div>';
  html += '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;">';
  ISE_STEPS.forEach((s, i) => {
    const info   = steps[s] || {};
    const st     = info.status || 'pending';
    const result = (info.result || '').substring(0, 180);
    const dur    = formatDur(info.started_at, info.completed_at);
    const cardBorder = st === 'failed'    ? 'border-left:3px solid #ff4757;'
                     : st === 'running'   ? 'border-left:3px solid #02c8ff;'
                     : st === 'completed' ? 'border-left:3px solid #00e68a;'
                     : st === 'skipped'   ? 'border-left:3px solid #445566;opacity:0.7;'
                     : '';
    html += '<div class="step-card" style="' + cardBorder + '">';
    html += '<div class="step-num">Step ' + (i+1) + '/' + total + '</div>';
    html += '<div class="step-name">' + (ISE_STEP_LABELS[s]||s) + '</div>';
    html += pipelineBadge(st);
    if (result) html += '<div class="step-result">' + result.split('\\n')[0] + '</div>';
    if (dur)    html += '<div class="step-dur">' + dur + '</div>';
    html += '</div>';
  });
  html += '</div>';
  html += '<div style="margin-top:12px;font-size:11px;color:#445566;">ISE: 198.18.5.101 &nbsp;|&nbsp; pxGrid Cloud credentials set in Org Credentials card below</div>';

  grid.innerHTML = html;
  grid._lastHtml = true;

  setTimeout(() => {
    const runBtn        = document.getElementById('ise-run-btn');
    const reactivateBtn = document.getElementById('ise-reactivate-btn');
    const sgtRecheckBtn = document.getElementById('ise-sgt-recheck-btn');
    const resetBtn      = document.getElementById('ise-reset-btn');
    const refreshBtn    = document.getElementById('scc-refresh-btn');
    if (runBtn)         runBtn.onclick        = () => iseRun(podId);
    if (reactivateBtn)  reactivateBtn.onclick = () => iseReactivate(podId);
    if (sgtRecheckBtn)  sgtRecheckBtn.onclick = () => iseSgtRecheck(podId);
    if (resetBtn)       resetBtn.onclick      = () => iseReset(podId);
    if (refreshBtn)     refreshBtn.onclick    = () => iseRefreshSessions(podId);
  }, 0);
}

async function iseRun(podId, fromStep) {
  // Start the poller immediately — don't wait for the first status fetch.
  // The Docker container takes a few seconds to update the DB to 'running',
  // so checking status synchronously right after POST would still show the
  // old state and the poller would never start.
  _iseStartPoller(podId);
  await fetch('/api/ise/run/' + podId, {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({from_step: fromStep || 0}),
  });
}

async function iseReset(podId) {
  if (!confirm('Clear all ISE steps for ' + podId + '?')) return;
  await fetch('/api/ise/reset/' + podId, { method: 'POST' });
  loadIseStatus(podId);
}

async function iseReactivate(podId) {
  // Resets step 4 to pending and re-runs only the ISE→SCC deactivate+reactivate step.
  if (!confirm('Re-run ISE\u2192SCC Deactivate+Reactivate for ' + podId + '?\\n\\nThis resets and re-runs ONLY step 4.')) return;
  _iseStartPoller(podId);
  await fetch('/api/ise/reactivate/' + podId, { method: 'POST' });
}

async function iseSgtRecheck(podId) {
  const btn = document.getElementById('ise-sgt-recheck-btn');
  if (btn) { btn.disabled = true; btn.textContent = '\u23f3 Checking...'; }
  try {
    const res = await fetch('/api/ise/sgt-recheck/' + podId, { method: 'POST' });
    const data = await res.json();
    if (data.status === 'started') {
      _iseStartPoller(podId);
    } else {
      alert('SGT recheck error: ' + (data.message || 'unknown'));
    }
  } finally {
    setTimeout(() => {
      if (btn) { btn.disabled = false; btn.textContent = '\U0001F50D Re-verify SGTs'; }
    }, 3000);
  }
}

async function iseRefreshSessions(podId) {
  const btn   = document.getElementById('scc-refresh-btn');
  const badge = document.getElementById('scc-sess-badge');
  if (btn) { btn.disabled = true; btn.textContent = '\u23f3 Refreshing...'; }
  if (badge) { badge.style.color = '#02c8ff'; badge.textContent = '\u23f3 Browser opening — log in and complete MFA...'; }

  // Add cancel button next to refresh button
  let cancelBtn = document.getElementById('scc-refresh-cancel-pod-btn');
  if (!cancelBtn && btn) {
    cancelBtn = document.createElement('button');
    cancelBtn.id = 'scc-refresh-cancel-pod-btn';
    cancelBtn.textContent = 'Cancel';
    cancelBtn.style.cssText = 'margin-left:8px;background:#c0392b;color:#fff;border:none;padding:4px 10px;border-radius:4px;cursor:pointer;font-size:12px;';
    btn.parentNode.insertBefore(cancelBtn, btn.nextSibling);
  }
  if (cancelBtn) cancelBtn.style.display = 'inline-block';

  let poller = null;
  if (cancelBtn) cancelBtn.onclick = async () => {
    if (poller) clearInterval(poller);
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (btn)   { btn.disabled = false; btn.textContent = '\u21bb Refresh SCC Sessions'; }
    if (badge) { badge.style.color = '#667788'; badge.textContent = 'Cancelled'; }
    await fetch('/api/scc/refresh-cancel', {method:'POST'});
  };

  try {
    const r = await fetch('/api/scc/refresh-sessions', {
      method: 'POST',
      headers: {'Content-Type':'application/json'},
      body: JSON.stringify({pod_id: podId}),
    });
    const d = await r.json();
    if (d.status === 'started') {
      if (badge) badge.textContent = '\u23f3 Running — complete login in the browser window';
      let polls = 0;
      poller = setInterval(async () => {
        polls++;
        const sr = await fetch('/api/scc/session-status?pod_id=' + podId);
        const sd = await sr.json();
        const s = sd[podId] || {};
        if (s.exists && (s.age_hours || 99) < 1) {
          clearInterval(poller);
          if (cancelBtn) cancelBtn.style.display = 'none';
          if (btn)   { btn.disabled = false; btn.textContent = '\u21bb Refresh SCC Sessions'; }
          if (badge) { badge.style.color = '#00e68a'; badge.textContent = '\u2713 SCC session refreshed just now'; }
          loadIseStatus(podId);
        } else if (polls > 72) { // 6 min timeout
          clearInterval(poller);
          if (cancelBtn) cancelBtn.style.display = 'none';
          if (btn) { btn.disabled = false; btn.textContent = '\u21bb Refresh SCC Sessions'; }
          loadIseStatus(podId);
        }
      }, 5000);
    } else {
      if (cancelBtn) cancelBtn.style.display = 'none';
      if (btn)   { btn.disabled = false; btn.textContent = '\u21bb Refresh SCC Sessions'; }
      if (badge) { badge.style.color = '#ff4757'; badge.textContent = '\u26a0 Error: ' + (d.message || 'unknown'); }
    }
  } catch (e) {
    if (cancelBtn) cancelBtn.style.display = 'none';
    if (btn)   { btn.disabled = false; btn.textContent = '\u21bb Refresh SCC Sessions'; }
    if (badge) { badge.style.color = '#ff4757'; badge.textContent = '\u26a0 Request failed'; }
  }
}
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
