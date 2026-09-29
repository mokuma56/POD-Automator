"""update.sh — the dashboard's "Check for Updates" button.

Found broken on 2026-09-29 while setting up the Linux automator host:
  * the image rebuild ran `docker/docker-compose.yml`, which does not exist
    (the compose file is at the repo root) — any update touching pipeline code
    would abort mid-way;
  * it only rebuilt for onboard*.py changes, missing ise_integrations.py,
    duo_automation.py, hostdb.py, db_ops.py … — stale container code;
  * it relaunched the dashboard itself even under launchd/systemd, starting a
    second copy;
  * it restarted mid-run, killing in-flight Duo/ISE steps.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import re
import sqlite3
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = (ROOT / "update.sh").read_text()


def _section(start, end):
    return SCRIPT[SCRIPT.index(start):SCRIPT.index(end)]


def test_syntax():
    assert subprocess.run(["bash", "-n", str(ROOT / "update.sh")]).returncode == 0


def test_compose_file_it_builds_exists():
    for path in re.findall(r"docker compose -f (\S+) build", SCRIPT):
        assert (ROOT / path).exists(), path


def test_rebuild_list_is_every_file_the_image_copies():
    snippet = _section("IMAGE_FILES=$(", "\nNEED_DOCKER=0")
    out = subprocess.run(["bash", "-c", snippet + '\necho "$IMAGE_FILES"'],
                         cwd=ROOT, capture_output=True, text=True).stdout.split()
    for f in ("ise_integrations.py", "duo_automation.py", "hostdb.py", "db_ops.py",
              "onboard.py", "onboard_router.py", "evpn_fabric.py", "sda_fabric.py",
              "base_configs"):
        assert f in out, f
    assert "data" not in out, "data/ is bind-mounted; it must not force rebuilds"


def _needs_rebuild(changed: str) -> bool:
    snippet = _section("IMAGE_FILES=$(", 'if [ "$NEED_DOCKER" = "1" ]')
    r = subprocess.run(["bash", "-c", f'log(){{ :; }}; CHANGED="{changed}"\n'
                        + snippet + 'echo "NEED=$NEED_DOCKER"'],
                       cwd=ROOT, capture_output=True, text=True)
    return "NEED=1" in r.stdout


def test_an_ise_change_rebuilds_the_image():
    assert _needs_rebuild("ise_integrations.py")
    assert _needs_rebuild("base_configs/leaf1.txt")
    assert _needs_rebuild("docker/Dockerfile")


def test_dashboard_or_docs_only_change_does_not_rebuild():
    assert not _needs_rebuild("dashboard.py\nSETUP_CHECK.md\ntests/test_x.py")


def _guard(tmp_path, running: bool):
    (tmp_path / "data").mkdir()
    db = tmp_path / "data" / "pod_state.db"
    c = sqlite3.connect(db)
    for t in ("duo_steps", "ise_steps", "pipeline_steps"):
        c.execute(f"CREATE TABLE {t} (pod_id TEXT, step_name TEXT, status TEXT)")
    if running:
        c.execute("INSERT INTO ise_steps VALUES ('POD-5','ise_sgt_verify','running')")
    c.commit(); c.close()
    snippet = _section("DB=\"$SCRIPT_DIR/data/pod_state.db\"", "# ── 2. Fetch")
    return subprocess.run(["bash", "-c", f'log(){{ :; }}; SCRIPT_DIR="{tmp_path}"\n'
                           + snippet + "echo PASSED"],
                          capture_output=True, text=True)


def test_refuses_to_update_during_a_run(tmp_path):
    r = _guard(tmp_path, running=True)
    assert r.returncode == 1 and "ERROR:Runs in progress" in r.stdout
    assert "POD-5:ise_sgt_verify" in r.stdout and "PASSED" not in r.stdout


def test_idle_host_passes_the_guard(tmp_path):
    r = _guard(tmp_path, running=False)
    assert "PASSED" in r.stdout


def test_supervised_restart_does_not_launch_a_second_dashboard():
    restart = SCRIPT[SCRIPT.index("SUPERVISED=0"):]
    assert "INVOCATION_ID" in restart and "XPC_SERVICE_NAME" in restart
    assert restart.index('if [ "$SUPERVISED" = "0" ]') < restart.index("nohup uv run")
