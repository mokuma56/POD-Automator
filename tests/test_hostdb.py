"""Host-writes-only database access (db_ops + hostdb + /api/hostdb/<op>).

Regression cover for the pod_state.db "wedge": WAL across the Docker Desktop
bind mount let a container's checkpoint reset the -wal file while the host
dashboard's shared-memory index still pointed into it, after which every new
connection in the dashboard failed with "disk I/O error" (2026-09-28: three
times in ~30 minutes while POD-2/POD-6 pipelines ran). Containers now never
open the file; they call named ops the dashboard runs.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import io
import json
import os
import re
import sqlite3
import sys
import types
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import db_ops   # noqa: E402
import hostdb   # noqa: E402

SCHEMA = """
CREATE TABLE pods (pod_id TEXT PRIMARY KEY, status TEXT, sdwan_online TEXT,
    router_serial TEXT, vpn_host TEXT, notes TEXT, updated_at TEXT, scc_org TEXT,
    pod_number TEXT, pod_site TEXT, scc_api_key TEXT, duo_skey TEXT);
CREATE TABLE pipeline_steps (pod_id TEXT, step_name TEXT, status TEXT, started_at TEXT,
    completed_at TEXT, result TEXT DEFAULT '', PRIMARY KEY (pod_id, step_name));
CREATE TABLE pipeline_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, pod_id TEXT,
    log_line TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE org_credentials (org_number TEXT PRIMARY KEY, duo_ikey TEXT,
    scc_org_uuid TEXT);
INSERT INTO pods (pod_id, vpn_host, scc_org, sdwan_online)
    VALUES ('POD-6', 'dcloud-sjc-anyconnect.cisco.com',
            'cisco-pseudoco-501--t8zbm7.app.us.cdo.cisco.com', 'yes');
INSERT INTO org_credentials VALUES ('501', 'DIKQ1SD3', 'ABCD-UUID');
"""


@pytest.fixture
def db(tmp_path):
    path = tmp_path / "pod_state.db"
    c = sqlite3.connect(path)
    c.executescript(SCHEMA)
    c.commit()
    c.close()
    return str(path)


def _q(db, sql, args=()):
    c = sqlite3.connect(db)
    try:
        return c.execute(sql, args).fetchall()
    finally:
        c.close()


def _run(db, op, **kw):
    c = sqlite3.connect(db)
    try:
        return db_ops.run(op, c, **kw)
    finally:
        c.close()


# ── db_ops: behaviour lifted from the call sites ──────────────────────────────

def test_step_upsert_keeps_started_at_and_stamps_completion(db):
    _run(db, "pipeline_step_set", pod_id="POD-6", step_name="copy_bootstrap", status="running")
    started = _q(db, "SELECT started_at, completed_at FROM pipeline_steps")[0]
    assert started[0] and started[1] is None
    _run(db, "pipeline_step_set", pod_id="POD-6", step_name="copy_bootstrap",
         status="completed", result="OK")
    row = _q(db, "SELECT started_at, completed_at, status, result FROM pipeline_steps")[0]
    assert row[0] == started[0], "a re-report must not move started_at"
    assert row[1] and row[2:] == ("completed", "OK")


def test_pipeline_state_is_what_the_skip_guard_reads(db):
    _run(db, "pipeline_step_set", pod_id="POD-6", step_name="a", status="completed")
    _run(db, "pipeline_step_set", pod_id="POD-6", step_name="b", status="failed")
    assert _run(db, "pipeline_state", pod_id="POD-6") == {
        "completed": ["a"], "sdwan_online": True}
    assert _run(db, "pipeline_state", pod_id="POD-99") == {
        "completed": [], "sdwan_online": False}


def test_pod_update_refuses_credential_columns(db):
    """A container may record progress on its POD, never rewrite its secrets."""
    with pytest.raises(ValueError):
        _run(db, "pod_update", pod_id="POD-6", fields={"scc_api_key": "x"})
    with pytest.raises(ValueError):
        _run(db, "pod_get", pod_id="POD-6", fields=["duo_skey"])


def test_pod_update_drops_columns_an_older_db_lacks(tmp_path):
    """Replaces phase_detect_pod_number's 'older DB without pod_site' fallback."""
    path = tmp_path / "old.db"
    c = sqlite3.connect(path)
    c.executescript("CREATE TABLE pods (pod_id TEXT, pod_number TEXT, updated_at TEXT);"
                    "INSERT INTO pods (pod_id) VALUES ('POD-1');")
    c.commit()
    assert db_ops.run("pod_update", c, pod_id="POD-1",
                      fields={"pod_number": "13", "pod_site": "rtp"}) == 1
    assert c.execute("SELECT pod_number FROM pods").fetchone()[0] == "13"
    c.close()


def test_org_creds_for_pod_resolves_via_scc_org(db):
    oc = _run(db, "org_creds_for_pod", pod_id="POD-6")
    assert oc["org_number"] == "501" and oc["duo_ikey"] == "DIKQ1SD3"
    assert oc["scc_org"].startswith("cisco-pseudoco-501")
    assert _run(db, "org_creds_for_pod", pod_id="POD-99") is None


def test_ise_steps_round_trip(db):
    _run(db, "ise_ensure_table")
    _run(db, "ise_step_set", pod_id="POD-6", step="ise_scc_integrate", status="running")
    got = _run(db, "ise_step_get", pod_id="POD-6", step="ise_scc_integrate")
    assert got["status"] == "running" and got["started_at"]
    _run(db, "ise_step_set", pod_id="POD-6", step="ise_scc_integrate",
         status="completed", result="done")
    after = _run(db, "ise_step_get", pod_id="POD-6", step="ise_scc_integrate")
    assert after["started_at"] == got["started_at"] and after["result"] == "done"
    assert _run(db, "ise_steps_clear", pod_id="POD-6") == 1


def test_sda_step_keeps_first_running_time(db):
    _run(db, "sda_ensure_table")
    _run(db, "sda_step_set", pod_id="POD-6", mode="deploy", step_name="s1", status="running")
    t0 = _q(db, "SELECT started_at FROM sda_steps")[0][0]
    _run(db, "sda_step_set", pod_id="POD-6", mode="deploy", step_name="s1", status="completed")
    assert _q(db, "SELECT started_at, status FROM sda_steps")[0] == (t0, "completed")
    _run(db, "sda_step_set", pod_id="POD-6", mode="deploy", step_name="s2", status="running")
    assert _run(db, "sda_reset_running", pod_id="POD-6", mode="deploy") == 1
    assert _run(db, "sda_completed", pod_id="POD-6", mode="deploy") == ["s1"]


def test_run_rolls_back_a_failed_op(db):
    with pytest.raises(sqlite3.Error):
        _run(db, "log_append", pod_id="POD-6", line=object())   # unbindable
    assert _q(db, "SELECT COUNT(*) FROM pipeline_logs")[0][0] == 0


def test_unknown_op_is_refused(db):
    with pytest.raises(db_ops.UnknownOp):
        _run(db, "DROP TABLE pods")


# ── hostdb client ─────────────────────────────────────────────────────────────

def test_host_side_runs_the_op_directly(db, monkeypatch):
    monkeypatch.setattr(hostdb, "in_container", lambda: False)
    hostdb.call("log_append", db_path=db, pod_id="POD-6", line="hello")
    assert _q(db, "SELECT log_line FROM pipeline_logs") == [("hello",)]


def test_host_side_wraps_errors(db, monkeypatch):
    monkeypatch.setattr(hostdb, "in_container", lambda: False)
    with pytest.raises(hostdb.HostDBError):
        hostdb.call("pod_update", db_path=db, pod_id="POD-6", fields={"duo_skey": "x"})


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def test_http_retries_while_the_dashboard_restarts():
    """launchd restarts the dashboard in ~3s — a step write must ride through it."""
    calls, slept = [], []

    def opener(req, timeout):
        calls.append(json.loads(req.data))
        if len(calls) < 3:
            raise urllib.error.URLError("connection refused")
        return _Resp(json.dumps({"ok": True, "result": 7}).encode())

    assert hostdb._call_http("pod_update", {"pod_id": "POD-6"},
                             _sleep=slept.append, _urlopen=opener) == 7
    assert len(calls) == 3 and slept == list(hostdb.RETRY_DELAYS[:2])


def test_http_4xx_is_a_bug_and_is_not_retried():
    calls = []

    def opener(req, timeout):
        calls.append(1)
        raise urllib.error.HTTPError(req.full_url, 400, "bad", {},
                                     io.BytesIO(b'{"error": "not writable"}'))

    with pytest.raises(hostdb.HostDBError, match="not writable"):
        hostdb._call_http("pod_update", {}, _sleep=lambda s: None, _urlopen=opener)
    assert calls == [1]


def test_http_gives_up_loudly_when_the_host_never_answers():
    def opener(req, timeout):
        raise urllib.error.URLError("no route")

    with pytest.raises(hostdb.HostDBError, match="unreachable"):
        hostdb._call_http("log_append", {}, _sleep=lambda s: None, _urlopen=opener)


# ── container tripwire ────────────────────────────────────────────────────────

def _fake_sqlite():
    opened = []
    mod = types.SimpleNamespace(OperationalError=sqlite3.OperationalError,
                                connect=lambda p, *a, **k: opened.append(p) or "conn")
    return mod, opened


def test_guard_refuses_the_shared_db_and_its_wal_files():
    mod, opened = _fake_sqlite()
    hostdb.install_container_guard(mod)
    for p in ("/pipeline/host-data/pod_state.db", "pod_state.db-wal",
              Path("/x/pod_state.db-shm")):
        with pytest.raises(sqlite3.OperationalError, match="hostdb.call"):
            mod.connect(p)
    assert opened == []


def test_guard_leaves_other_databases_alone_and_is_idempotent():
    mod, opened = _fake_sqlite()
    hostdb.install_container_guard(mod)
    hostdb.install_container_guard(mod)
    assert mod.connect(":memory:") == "conn" and mod.connect("/tmp/other.db") == "conn"
    assert opened == [":memory:", "/tmp/other.db"]


# ── the dashboard route ───────────────────────────────────────────────────────

@pytest.fixture
def client(db, monkeypatch):
    import dashboard as d
    monkeypatch.setattr(d, "DB_PATH", Path(db))
    return d.app.test_client()


def test_route_runs_a_registered_op(client, db):
    r = client.post("/api/hostdb/pod_update",
                    json={"pod_id": "POD-6", "fields": {"sdwan_online": ""}})
    assert r.status_code == 200 and r.get_json() == {"ok": True, "result": 1}
    assert _q(db, "SELECT sdwan_online FROM pods")[0][0] == ""


def test_route_refuses_unknown_ops_and_bad_calls(client):
    assert client.post("/api/hostdb/exec_sql", json={}).status_code == 404
    assert client.post("/api/hostdb/pod_update",
                       json={"pod_id": "POD-6", "fields": {"scc_api_key": "x"}}).status_code == 400
    assert client.post("/api/hostdb/pod_update", json={"nope": 1}).status_code == 400
    assert client.post("/api/hostdb/pod_update", data="[]",
                       content_type="application/json").status_code == 400



def test_cloudfabric_steps_round_trip(db):
    _run(db, "cloudfabric_ensure_table")
    _run(db, "cloudfabric_step_set", pod_id="POD-6", mode="deploy", step_name="claim_devices",
         status="running")
    t0 = _q(db, "SELECT started_at FROM cloudfabric_steps")[0][0]
    _run(db, "cloudfabric_step_set", pod_id="POD-6", mode="deploy", step_name="claim_devices",
         status="completed", result="3/3 online")
    assert _q(db, "SELECT started_at, status, result FROM cloudfabric_steps")[0] == (
        t0, "completed", "3/3 online")
    _run(db, "cloudfabric_step_set", pod_id="POD-6", mode="deploy", step_name="name_switches",
         status="running")
    assert _run(db, "cloudfabric_reset_running", pod_id="POD-6", mode="deploy") == 1
    assert _run(db, "cloudfabric_completed", pod_id="POD-6", mode="deploy") == ["claim_devices"]
    assert _run(db, "cloudfabric_clear_mode", pod_id="POD-6", mode="deploy") == 2


def test_cloudfabric_cloud_ids_survive_step_clear(db):
    """Clear/Rollback wipe step rows only: once a switch is in cloud config its
    OOB SSH is gone and the recorded Cloud ID is the only way to re-claim it."""
    _run(db, "cloudfabric_ensure_table")
    _run(db, "cloudfabric_device_set", pod_id="POD-6", role="leaf1", serial="Q5VJ-JL9A-5MW7")
    _run(db, "cloudfabric_device_set", pod_id="POD-6", role="leaf1", serial="Q5VJ-JL9A-0000")
    _run(db, "cloudfabric_clear_mode", pod_id="POD-6", mode="deploy")
    assert _run(db, "cloudfabric_devices", pod_id="POD-6") == {"leaf1": "Q5VJ-JL9A-0000"}
    assert _run(db, "cloudfabric_devices", pod_id="POD-7") == {}


def test_cloudfabric_org_link_only_when_no_scc_org(db):
    _run(db, "cloudfabric_ensure_table")
    with sqlite3.connect(db) as c:
        c.execute("INSERT INTO pods (pod_id) VALUES ('POD-18')")
    assert _run(db, "cloudfabric_org_creds", pod_id="POD-18") is None
    _run(db, "cloudfabric_device_set", pod_id="POD-18", role="_org", serial="501")
    assert _run(db, "cloudfabric_org_creds", pod_id="POD-18")["org_number"] == "501"
    # a POD with a discovered scc_org keeps using it
    assert _run(db, "cloudfabric_org_creds", pod_id="POD-6")["scc_org"].startswith("cisco-pseudoco-501")

# ── nothing that runs in a container opens the file itself ────────────────────

CONTAINER_MODULES = ["onboard.py", "ise_integrations.py", "evpn_fabric.py", "sda_fabric.py",
                     "cloud_fabric.py"]


@pytest.mark.parametrize("name", CONTAINER_MODULES)
def test_container_modules_never_open_sqlite(name):
    src = (ROOT / name).read_text()
    assert not re.search(r"\bsqlite3\b|\.connect\((DB_PATH|db_path)", src), (
        f"{name} runs in a container and must use hostdb.call, not sqlite3")
    assert "import hostdb" in src, f"{name} must import hostdb so the tripwire is armed"


def test_detect_pod_number_uses_the_host():
    src = (ROOT / "onboard_router.py").read_text()
    body = src[src.index("def phase_detect_pod_number"):]
    body = body[:body.index("\ndef ", 1)]
    assert "sqlite3" not in body and "hostdb.call" in body


def test_image_ships_the_client():
    copy = next(l for l in (ROOT / "docker" / "Dockerfile").read_text().splitlines()
                if l.startswith("COPY onboard.py"))
    assert "hostdb.py" in copy and "db_ops.py" in copy
