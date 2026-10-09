"""Named database operations — the ONLY SQL a container may cause to run.

Why this module exists
    data/pod_state.db is WAL-mode SQLite shared between the host dashboard and
    the per-POD containers through a Docker Desktop bind mount. WAL needs the
    -shm index to be coherently shared memory for every process touching the
    file, and a Mac host process and a process inside Docker's Linux VM do not
    get that. Under concurrent writes the dashboard's view of the WAL index
    went stale and every new connection in that process failed with
    "disk I/O error" (the "wedge"), while a fresh CLI integrity_check said ok.

    The fix is host-writes-only: only the dashboard process opens the file.
    Containers send a named operation over HTTP (hostdb.call) and the
    dashboard runs it here, on its own connection (POST /api/hostdb/<op>).

Rules for ops
    * One op per access pattern, parameterised — no SQL crosses the wire, so the
      endpoint cannot be used to run arbitrary statements.
    * The SQL is lifted verbatim from the call site it replaced, so behaviour is
      unchanged; where a call site had a comment explaining the SQL, the
      comment moved here with it.
    * Every op takes the connection first and returns something JSON-able.
    * Ops do not commit; run() does, once, so each op is one transaction.
"""
import datetime
import re
import sqlite3

# ── registry ──────────────────────────────────────────────────────────────────

OPS = {}


def op(fn):
    OPS[fn.__name__] = fn
    return fn


class UnknownOp(KeyError):
    pass


def run(name: str, conn: sqlite3.Connection, **params):
    """Run op *name* on *conn* as one transaction and return its result."""
    fn = OPS.get(name)
    if fn is None:
        raise UnknownOp(name)
    try:
        result = fn(conn, **params)
        conn.commit()
        return result
    except BaseException:
        conn.rollback()
        raise


def _utcnow() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _cols(conn, table: str) -> set:
    return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}


# ── pods ──────────────────────────────────────────────────────────────────────

# Columns a container may write on its own POD row. Deliberately narrow: the
# credential columns (scc_api_*, duo_*, sa_*, vpn_*) are the dashboard's alone.
POD_WRITABLE = frozenset({
    "router_serial", "sdwan_online", "status", "notes", "scc_org",
    "pod_number", "pod_site",
})
POD_READABLE = POD_WRITABLE | {"vpn_host", "pod_id"}


@op
def pod_update(conn, pod_id: str, fields: dict) -> int:
    """UPDATE pods SET <fields>, updated_at=now WHERE pod_id=?  -> rows changed.

    Columns this DB does not have are dropped rather than failing the write:
    phase_detect_pod_number used to fall back to writing pod_number alone on
    an older DB without pod_site, and the number is still worth recording.
    """
    bad = set(fields) - POD_WRITABLE
    if bad:
        raise ValueError(f"pod_update: column(s) not writable from a container: {sorted(bad)}")
    have = _cols(conn, "pods")
    use = {k: v for k, v in fields.items() if k in have}
    if not use:
        return 0
    sets = ", ".join(f"{k}=?" for k in use)
    cur = conn.execute(
        f"UPDATE pods SET {sets}, updated_at=datetime('now') WHERE pod_id=?",
        list(use.values()) + [pod_id])
    return cur.rowcount


@op
def pod_get(conn, pod_id: str, fields: list) -> dict | None:
    """Selected columns of one POD row, or None if the POD does not exist."""
    bad = set(fields) - POD_READABLE
    if bad:
        raise ValueError(f"pod_get: column(s) not readable from a container: {sorted(bad)}")
    have = _cols(conn, "pods")
    use = [f for f in fields if f in have]
    if not use:
        return {}
    row = conn.execute(f"SELECT {', '.join(use)} FROM pods WHERE pod_id=?",
                       (pod_id,)).fetchone()
    return dict(zip(use, row)) if row else None


# ── core pipeline (onboard.py) ────────────────────────────────────────────────

@op
def log_append(conn, pod_id: str, line: str) -> None:
    conn.execute("INSERT INTO pipeline_logs (pod_id, log_line) VALUES (?, ?)",
                 (pod_id, line))


@op
def pipeline_step_set(conn, pod_id: str, step_name: str, status: str,
                      result: str = "") -> None:
    """onboard.py's report_step: keep started_at, stamp completed_at on a
    terminal status, touch the POD row so the dashboard sees activity."""
    conn.execute("""
        INSERT OR REPLACE INTO pipeline_steps
            (pod_id, step_name, status, started_at, completed_at, result)
        VALUES (?, ?, ?,
            COALESCE((SELECT started_at FROM pipeline_steps WHERE pod_id=? AND step_name=?), datetime('now')),
            CASE WHEN ? IN ('completed','failed','skipped') THEN datetime('now') ELSE NULL END,
            ?)
    """, (pod_id, step_name, status, pod_id, step_name, status, result))
    conn.execute("UPDATE pods SET updated_at=datetime('now') WHERE pod_id=?", (pod_id,))


@op
def pipeline_state(conn, pod_id: str) -> dict:
    """What onboard.py's skip logic needs: completed steps + the sdwan flag."""
    rows = conn.execute("SELECT step_name, status FROM pipeline_steps WHERE pod_id=?",
                        (pod_id,)).fetchall()
    pod = conn.execute("SELECT sdwan_online FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    return {
        "completed": sorted(r[0] for r in rows if r[1] == "completed"),
        "sdwan_online": bool(pod) and (pod[0] or "") == "yes",
    }


# ── ISE card (ise_integrations.py) ────────────────────────────────────────────

@op
def ise_ensure_table(conn) -> None:
    """Create ise_steps; add pxGrid Cloud columns to org_credentials if missing."""
    conn.execute("""
        CREATE TABLE IF NOT EXISTS ise_steps (
            pod_id        TEXT,
            step_name     TEXT,
            status        TEXT DEFAULT 'pending',
            result        TEXT DEFAULT '',
            started_at    TEXT,
            completed_at  TEXT,
            PRIMARY KEY (pod_id, step_name)
        )
    """)
    cols = _cols(conn, "org_credentials")
    for col in ["pxgrid_cloud_email", "pxgrid_cloud_password", "pxgrid_cloud_account"]:
        if col not in cols:
            conn.execute(f"ALTER TABLE org_credentials ADD COLUMN {col} TEXT DEFAULT ''")


@op
def ise_step_set(conn, pod_id: str, step: str, status: str, result: str = "") -> None:
    now = _utcnow()
    conn.execute("""
        INSERT INTO ise_steps (pod_id, step_name, status, result, started_at, completed_at)
        VALUES (?,?,?,?,?,?)
        ON CONFLICT(pod_id, step_name) DO UPDATE SET
            status=excluded.status, result=excluded.result,
            started_at=COALESCE(excluded.started_at, started_at),
            completed_at=excluded.completed_at
    """, (
        pod_id, step, status, result,
        now if status == "running" else None,
        now if status in ("completed", "failed", "skipped") else None,
    ))


@op
def ise_step_get(conn, pod_id: str, step: str) -> dict | None:
    row = conn.execute(
        "SELECT status, result, started_at FROM ise_steps WHERE pod_id=? AND step_name=?",
        (pod_id, step)).fetchone()
    return {"status": row[0], "result": row[1], "started_at": row[2]} if row else None


@op
def ise_steps_clear(conn, pod_id: str) -> int:
    return conn.execute("DELETE FROM ise_steps WHERE pod_id=?", (pod_id,)).rowcount


@op
def org_creds_for_pod(conn, pod_id: str) -> dict | None:
    """org_credentials for the POD's SCC org, plus scc_org; None if unresolvable.

    Carries secrets, like the existing /api/pod-scc-keys route does. The ISE
    card cannot run without them, so this only moves where they are read.
    """
    pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
    if not pod:
        return None
    scc_org = pod[0] or ""
    m = re.search(r"pseudoco-(\d+)", scc_org)
    if not m:
        return None
    cur = conn.execute("SELECT * FROM org_credentials WHERE org_number=?", (m.group(1),))
    row = cur.fetchone()
    result = dict(zip([d[0] for d in cur.description], row)) if row else {}
    result["scc_org"] = scc_org  # always inject so steps can navigate directly
    return result


@op
def known_scc_org_uuids(conn) -> list:
    return sorted({(r[0] or "").strip().lower() for r in conn.execute(
        "SELECT scc_org_uuid FROM org_credentials "
        "WHERE scc_org_uuid IS NOT NULL AND scc_org_uuid != ''")})


# ── EVPN fabric card (evpn_fabric.py) ─────────────────────────────────────────

@op
def fabric_ensure_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS fabric_steps (
            pod_id       TEXT NOT NULL,
            step_name    TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            started_at   TEXT,
            completed_at TEXT,
            result       TEXT,
            PRIMARY KEY (pod_id, step_name)
        )
    """)


@op
def fabric_step_set(conn, pod_id: str, step_name: str, status: str,
                    result: str = "") -> None:
    conn.execute("""
        INSERT OR REPLACE INTO fabric_steps
            (pod_id, step_name, status, started_at, completed_at, result)
        VALUES (?, ?, ?,
            COALESCE((SELECT started_at FROM fabric_steps WHERE pod_id=? AND step_name=?), datetime('now')),
            CASE WHEN ? IN ('completed','failed','skipped') THEN datetime('now') ELSE NULL END,
            ?)
    """, (pod_id, step_name, status, pod_id, step_name, status, result))


@op
def fabric_completed(conn, pod_id: str) -> list:
    return sorted(r[0] for r in conn.execute(
        "SELECT step_name FROM fabric_steps WHERE pod_id=? AND status='completed'",
        (pod_id,)))


# ── SDA fabric card (sda_fabric.py) ───────────────────────────────────────────

@op
def sda_ensure_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sda_steps (
            pod_id       TEXT NOT NULL,
            mode         TEXT NOT NULL DEFAULT 'deploy',
            step_name    TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            started_at   TEXT,
            completed_at TEXT,
            result       TEXT,
            PRIMARY KEY (pod_id, mode, step_name)
        )
    """)


@op
def sda_step_set(conn, pod_id: str, mode: str, step_name: str, status: str,
                 result=None) -> None:
    """Sets started_at on first RUNNING, completed_at on completed/failed."""
    now = _utcnow()
    row = conn.execute(
        "SELECT started_at FROM sda_steps WHERE pod_id=? AND mode=? AND step_name=?",
        (pod_id, mode, step_name)).fetchone()
    started = (row[0] if row else None) or (now if status == "running" else None)
    completed = now if status in ("completed", "failed") else None
    conn.execute("""
        INSERT INTO sda_steps (pod_id, mode, step_name, status, started_at, completed_at, result)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(pod_id, mode, step_name) DO UPDATE SET
            status=excluded.status,
            started_at=COALESCE(excluded.started_at, started_at),
            completed_at=excluded.completed_at,
            result=excluded.result
    """, (pod_id, mode, step_name, status, started, completed, result))


@op
def sda_reset_running(conn, pod_id: str, mode: str) -> int:
    """Stale 'running' rows from a crashed run go back to pending."""
    return conn.execute(
        "UPDATE sda_steps SET status='pending', completed_at=NULL "
        "WHERE pod_id=? AND mode=? AND status='running'", (pod_id, mode)).rowcount


@op
def sda_completed(conn, pod_id: str, mode: str) -> list:
    return sorted(r[0] for r in conn.execute(
        "SELECT step_name FROM sda_steps WHERE pod_id=? AND mode=? AND status='completed'",
        (pod_id, mode)))


# ── Cloud Fabric card (cloud_fabric.py) ───────────────────────────────────────

@op
def cloudfabric_ensure_table(conn) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cloudfabric_steps (
            pod_id       TEXT NOT NULL,
            mode         TEXT NOT NULL DEFAULT 'deploy',
            step_name    TEXT NOT NULL,
            status       TEXT NOT NULL DEFAULT 'pending',
            started_at   TEXT,
            completed_at TEXT,
            result       TEXT,
            PRIMARY KEY (pod_id, mode, step_name)
        )
    """)
    # Cloud IDs read off each switch by `show meraki connect`. Kept apart from
    # the step rows so Clear/Rollback do not lose them: once a switch has been
    # factory-reset into cloud config its out-of-band SSH is gone, and the
    # Cloud ID is the only handle left to claim it again.
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cloudfabric_devices (
            pod_id     TEXT NOT NULL,
            role       TEXT NOT NULL,
            serial     TEXT NOT NULL,
            updated_at TEXT,
            PRIMARY KEY (pod_id, role)
        )
    """)


@op
def cloudfabric_step_set(conn, pod_id: str, mode: str, step_name: str, status: str,
                         result=None) -> None:
    """Sets started_at on first RUNNING, completed_at on completed/failed."""
    now = _utcnow()
    row = conn.execute(
        "SELECT started_at FROM cloudfabric_steps WHERE pod_id=? AND mode=? AND step_name=?",
        (pod_id, mode, step_name)).fetchone()
    started = (row[0] if row else None) or (now if status == "running" else None)
    completed = now if status in ("completed", "failed") else None
    conn.execute("""
        INSERT INTO cloudfabric_steps (pod_id, mode, step_name, status, started_at, completed_at, result)
        VALUES (?,?,?,?,?,?,?)
        ON CONFLICT(pod_id, mode, step_name) DO UPDATE SET
            status=excluded.status,
            started_at=COALESCE(excluded.started_at, started_at),
            completed_at=excluded.completed_at,
            result=excluded.result
    """, (pod_id, mode, step_name, status, started, completed, result))


@op
def cloudfabric_reset_running(conn, pod_id: str, mode: str) -> int:
    """Stale 'running' rows from a crashed run go back to pending."""
    return conn.execute(
        "UPDATE cloudfabric_steps SET status='pending', completed_at=NULL "
        "WHERE pod_id=? AND mode=? AND status='running'", (pod_id, mode)).rowcount


@op
def cloudfabric_completed(conn, pod_id: str, mode: str) -> list:
    return sorted(r[0] for r in conn.execute(
        "SELECT step_name FROM cloudfabric_steps WHERE pod_id=? AND mode=? AND status='completed'",
        (pod_id, mode)))


@op
def cloudfabric_clear_mode(conn, pod_id: str, mode: str) -> int:
    """A finished rollback clears the deploy rows, so the next Deploy starts over."""
    return conn.execute(
        "DELETE FROM cloudfabric_steps WHERE pod_id=? AND mode=?", (pod_id, mode)).rowcount


@op
def cloudfabric_device_set(conn, pod_id: str, role: str, serial: str) -> None:
    conn.execute("""
        INSERT INTO cloudfabric_devices (pod_id, role, serial, updated_at) VALUES (?,?,?,?)
        ON CONFLICT(pod_id, role) DO UPDATE SET serial=excluded.serial, updated_at=excluded.updated_at
    """, (pod_id, role, serial, _utcnow()))


@op
def cloudfabric_devices(conn, pod_id: str) -> dict:
    return {r[0]: r[1] for r in conn.execute(
        "SELECT role, serial FROM cloudfabric_devices WHERE pod_id=?", (pod_id,))}



@op
def cloudfabric_org_creds(conn, pod_id: str) -> dict | None:
    """org_credentials for a POD's Cloud Fabric work.

    Normally the SCC org (org_creds_for_pod). A POD whose core pipeline has not
    run yet has no scc_org; for those, an org number recorded for the Cloud
    Fabric tab (cloudfabric_devices role "_org") links it without writing
    pods.scc_org, which the SCC/cdFMC steps treat as discovered fact.
    """
    creds = org_creds_for_pod(conn, pod_id)
    if creds:
        return creds
    row = conn.execute("SELECT serial FROM cloudfabric_devices WHERE pod_id=? AND role='_org'",
                       (pod_id,)).fetchone()
    if not row:
        return None
    cur = conn.execute("SELECT * FROM org_credentials WHERE org_number=?", (row[0],))
    hit = cur.fetchone()
    return dict(zip([d[0] for d in cur.description], hit)) if hit else None
