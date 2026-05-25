#!/usr/bin/env python3
"""
POD Automator — Multi-POD Docker Launcher

Two modes:
  1. CSV mode:   uv run python3 docker/generate.py pods.csv --up
  2. DB mode:    uv run python3 docker/generate.py --db --up
                 (reads PODs from dashboard SQLite DB — after CSV upload)

The DB mode reads the same data the dashboard stores from your
EventsDetails.csv upload (POD number, VPN host/user/pass, serial, router IP).

Build once: docker compose -f docker-compose.yml build
"""

import argparse, csv, json, os, sqlite3, subprocess, sys, tempfile, time
from pathlib import Path

HERE = Path(__file__).parent
PROJECT_ROOT = HERE.parent
TEMPLATE = HERE / "compose-template.yml"
IMAGE = "pod-automator:latest"
DB_PATH = PROJECT_ROOT / "data" / "pod_state.db"

DEFAULTS = {
    "vmanage_ip": "198.18.133.10",
    "vmanage_user": "admin",
    "vmanage_pass": "C1sco12345",
    "router_ip": "198.18.133.25",
    "router_user": "admin",
    "router_pass": "C1sco12345",
}
REQUIRED_CSV = ["pod_id", "vpn_host", "vpn_user", "vpn_pass", "router_ip", "router_serial"]


# ── POD loading ──────────────────────────────────────────────

def read_csv(path):
    pods = []
    with open(path) as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            row = {k.strip(): v.strip() for k, v in row.items()}
            # Accept either "serial" or "router_serial"
            serial = row.get("serial", "") or row.get("router_serial", "")
            row["router_serial"] = serial
            missing = [k for k in REQUIRED_CSV if k not in row or not row[k]]
            if missing:
                print(f"  WARNING: row {i+1} missing {missing}, skipping")
                continue
            merged = dict(DEFAULTS)
            merged.update({k: v for k, v in row.items() if v})
            merged["router_ip"] = DEFAULTS["router_ip"]
            merged["serial"] = merged["router_serial"]
            merged["host_data"] = str(PROJECT_ROOT / "data")
            # Assign a unique 172.x subnet per POD
            try:
                pod_num = int(row["pod_id"].split("-")[-1])
            except (ValueError, IndexError):
                pod_num = len(pods) + 20
            merged["pod_subnet"] = str(40 + pod_num)
            pods.append(merged)
    return pods


def read_db(status_filter=("pending", "available", "ready", "")):
    """Read PODs from dashboard SQLite DB."""
    if not DB_PATH.exists():
        print(f"  DB not found: {DB_PATH}")
        return []
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    if status_filter:
        rows = conn.execute(
            "SELECT * FROM pods WHERE status IN ({}) ORDER BY pod_id".format(
                ",".join("?" for _ in status_filter)
            ),
            list(status_filter)
        ).fetchall()
    else:
        rows = conn.execute("SELECT * FROM pods ORDER BY pod_id").fetchall()
    conn.close()

    pods = []
    for r in rows:
        d = dict(r)
        if not d.get("vpn_host") or not d.get("vpn_user"):
            print(f"  WARNING: {d['pod_id']} missing VPN credentials, skipping")
            continue
        merged = dict(DEFAULTS)
        merged["pod_id"] = d["pod_id"]
        merged["vpn_host"] = d["vpn_host"]
        merged["vpn_user"] = d["vpn_user"]
        merged["vpn_pass"] = d["vpn_pass"]
        merged["router_ip"] = DEFAULTS["router_ip"]
        merged["router_serial"] = d.get("router_serial", "")
        merged["serial"] = merged["router_serial"]
        merged["session_id"] = d.get("session_id", "")
        merged["host_data"] = str(PROJECT_ROOT / "data")
        # Assign a unique 172.x subnet per POD (172.20, 172.21, 172.22, ...)
        try:
            pod_num = int(d["pod_id"].split("-")[-1])
        except (ValueError, IndexError):
            pod_num = len(pods) + 20
        merged["pod_subnet"] = str(40 + pod_num)
        pods.append(merged)
    return pods


# ── Compose rendering ────────────────────────────────────────

def generate_compose(pod_conf):
    with open(TEMPLATE) as f:
        tmpl = f.read()
    import re
    def _repl(m):
        key = m.group(1)
        val = pod_conf.get(key)
        if val is None:
            raise KeyError(f"Missing template variable: {key}")
        return str(val)
    return re.sub(r"\{\{(\w+)\}\}", _repl, tmpl)


# ── Docker actions ───────────────────────────────────────────

def build_image():
    r = subprocess.run(
        ["docker", "images", "-q", IMAGE],
        capture_output=True, text=True, timeout=15
    )
    if r.stdout.strip():
        return True
    print("  Building pod-automator image (one-time)...")
    r = subprocess.run(
        ["docker", "compose", "-f", str(PROJECT_ROOT / "docker-compose.yml"), "build"],
        capture_output=True, text=True, timeout=300
    )
    if r.returncode != 0:
        print(f"  Build failed: {r.stderr[:300]}")
        return False
    print("  Image built!")
    return True


def action_up(pods, vpn_only=False):
    if not build_image():
        return
    successes = 0
    for p in pods:
        pod_id = p["pod_id"]
        proj_name = pod_id.lower()
        compose_data = generate_compose(p)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(compose_data); tmp_path = f.name
        try:
            label = "VPN" if vpn_only else "full stack"
            print(f"  Launching {pod_id} ({label})...", end="", flush=True)
            cmd = ["docker", "compose", "-p", proj_name, "-f", tmp_path, "up", "-d"]
            if vpn_only:
                cmd.append("vpn")
            r = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            os.unlink(tmp_path)
            if r.returncode == 0:
                print(" ✅")
                successes += 1
            else:
                err = r.stderr.strip() or r.stdout.strip()
                print(f" ❌ {err[:120]}")
        except Exception as e:
            os.unlink(tmp_path)
            print(f" ❌ {e}")
    print(f"\n── {successes}/{len(pods)} PODs up ──")
    for p in pods:
        proj_name = p["pod_id"].lower()
        print(f"  docker compose -p {proj_name} logs -f pipeline")


def action_down(pods):
    for p in pods:
        pod_id = p["pod_id"]
        proj_name = pod_id.lower()
        compose_data = generate_compose(p)
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
            f.write(compose_data); tmp_path = f.name
        try:
            print(f"  Tearing down {pod_id}...", end="", flush=True)
            r = subprocess.run(
                ["docker", "compose", "-p", proj_name, "-f", tmp_path, "down", "-v"],
                capture_output=True, text=True, timeout=60
            )
            os.unlink(tmp_path)
            print(" ✅" if r.returncode == 0 else " ❌")
        except Exception as e:
            os.unlink(tmp_path)
            print(f" ❌ {e}")
        time.sleep(0.3)

    # Reset DB state for all torn-down PODs
    try:
        import sqlite3 as _sqlite3
        db_path = Path(__file__).parent.parent / "data" / "pod_state.db"
        if db_path.exists():
            pod_ids = [p["pod_id"] for p in pods]
            conn = _sqlite3.connect(str(db_path))
            conn.execute("PRAGMA journal_mode=WAL")
            for pod_id in pod_ids:
                conn.execute("DELETE FROM pipeline_steps WHERE pod_id=?", (pod_id,))
                conn.execute("DELETE FROM pipeline_logs WHERE pod_id=?", (pod_id,))
                conn.execute("UPDATE pods SET status='pending', updated_at=datetime('now') WHERE pod_id=?", (pod_id,))
            conn.commit()
            conn.close()
            print(f"  DB state reset for {len(pod_ids)} POD(s) ✅")
    except Exception as e:
        print(f"  DB reset failed: {e}")


def action_status(pods):
    for p in pods:
        pod_id = p["pod_id"]
        proj_name = pod_id.lower()
        r = subprocess.run(
            ["docker", "compose", "-p", proj_name, "ps", "--format=json"],
            capture_output=True, text=True, timeout=15
        )
        lines = [l for l in r.stdout.strip().splitlines() if l.strip()]
        results = []
        for line in lines:
            try:
                data = json.loads(line)
                svc = data.get("Service", "?")
                state = data.get("Status", data.get("State", "?"))
                health = data.get("Health", "")
                label = f"{svc}:{state.split()[0] if state != '?' else '?'}"
                if health.lower() in ("healthy",):
                    label += "(ok)"
                elif health.lower() in ("unhealthy", "starting"):
                    label += f"({health})"
                results.append(label)
            except json.JSONDecodeError:
                pass
        if results:
            ok = all(
                "(ok)" in r or "up" in r.split(":")[-1].split()[0].lower()
                for r in results
            )
            print(f"  {pod_id:12s} {'✅' if ok else '⚠️'}  {' | '.join(results)}")
        else:
            print(f"  {pod_id:12s} ⚪  not running")


def action_logs(pods, pod_id_target):
    for p in pods:
        if p["pod_id"] == pod_id_target:
            proj_name = pod_id_target.lower()
            compose_data = generate_compose(p)
            with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as f:
                f.write(compose_data); tmp_path = f.name
            try:
                subprocess.run(
                    ["docker", "compose", "-p", proj_name, "-f", tmp_path,
                     "logs", "-f"],
                    timeout=3600
                )
            except KeyboardInterrupt:
                pass
            finally:
                os.unlink(tmp_path)
            return
    print(f"POD '{pod_id_target}' not found")


def action_generate(pods, out_dir):
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    for p in pods:
        path = out / f"{p['pod_id'].lower()}.yml"
        path.write_text(generate_compose(p))
        print(f"  {path}")
    print(f"\nLaunch: for f in {out_dir}/*.yml; do docker compose -p \"$(basename \"$f\" .yml)\" -f \"$f\" up -d; done")


# ── Main ─────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="POD Automator — parallel SD-WAN onboarding"
    )
    parser.add_argument("source", nargs="?", help="CSV file (omit for DB mode)")
    parser.add_argument("--db", action="store_true",
                        help="Read from dashboard SQLite DB instead of CSV")
    parser.add_argument("--up", action="store_true", help="Launch all PODs")
    parser.add_argument("--down", action="store_true", help="Teardown all PODs")
    parser.add_argument("--status", action="store_true", help="Show POD status")
    parser.add_argument("--logs", metavar="POD_ID", help="Tail logs for a POD")
    parser.add_argument("--generate", metavar="DIR",
                        help="Write compose files to DIR")
    parser.add_argument("--pod", metavar="POD_ID",
                        help="Single POD ID to act on (e.g. POD-4)")
    parser.add_argument("--vpn-only", action="store_true",
                        help="Start VPN containers only (no pipeline)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print compose content only")

    args = parser.parse_args()

    # Load PODs from CSV or DB
    if args.db or not args.source:
        # DB mode
        if args.pod:
            pods = read_db(status_filter=())
            pods = [p for p in pods if p["pod_id"] == args.pod]
            if not pods:
                print(f"POD '{args.pod}' not found in dashboard DB")
                sys.exit(1)
            # Override status — allow running/in_progress for single POD ops
            print(f"Loaded 1 POD ({args.pod}) from dashboard DB")
        else:
            pods = read_db()
            if not pods:
                print("No pending PODs found in dashboard DB")
                print(f"  DB: {DB_PATH}")
                print("Upload EventsDetails.csv via dashboard first, then run this.")
                sys.exit(1)
            print(f"Loaded {len(pods)} POD(s) from dashboard DB")
    else:
        # CSV mode
        path = Path(args.source)
        if not path.exists():
            print(f"CSV not found: {args.source}")
            print("\nColumns: pod_id,vpn_host,vpn_user,vpn_pass,router_ip,router_serial")
            sys.exit(1)
        pods = read_csv(str(path))
        if not pods:
            print("No valid PODs found in CSV")
            sys.exit(1)
        print(f"Loaded {len(pods)} POD(s) from {path}")
        if args.pod:
            pods = [p for p in pods if p["pod_id"] == args.pod]
            if not pods:
                print(f"POD '{args.pod}' not found in CSV")
                sys.exit(1)

    if args.dry_run:
        for p in pods:
            print(f"\n── {p['pod_id']} ──")
            print(generate_compose(p)[:300] + "...")
        return

    if args.generate:
        action_generate(pods, args.generate)
    elif args.status:
        action_status(pods)
    elif args.logs:
        action_logs(pods, args.logs)
    elif args.up:
        action_up(pods, vpn_only=args.vpn_only)
    elif args.down:
        action_down(pods)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
