"""Phase 1 of the remediation plan: detect, classify, escalate. No remediation.

When a step fails, record a FINGERPRINT and a BUNDLE so that a week from now we
can answer "which failures actually recur?" with data instead of memory. Nothing
here changes automation behaviour — it only observes.

WHY THIS IS ITS OWN TABLE
    The step tables (pipeline_steps / duo_steps / ise_steps) hold current state
    only, and every reset or re-run overwrites them. On 2026-08-31 a day's worth
    of real failures — four distinct shapes, several recurring — was already
    unrecoverable by that evening: the rows had been overwritten and the log
    rows trimmed. `failure_events` is append-only and is never touched by a
    reset, so the evidence outlives the run that produced it.

WHAT A FINGERPRINT IS FOR
    Two failures with the same fingerprint are "the same failure". That is what
    makes counting possible: it separates a one-off from a pattern, and it tells
    us whether something is OUR bug (it hits many PODs) or the lab (it hits one).
    So the normaliser must strip everything incidental — pod numbers, org
    numbers, generated instance names, timestamps, byte counts — while keeping
    the part that identifies the failure.
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from typing import Iterable

SCHEMA = """
CREATE TABLE IF NOT EXISTS failure_events (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,
    pod_id       TEXT NOT NULL,
    phase        TEXT NOT NULL,      -- pipeline | duo | ise | scc
    step_name    TEXT NOT NULL,
    status       TEXT NOT NULL,      -- failed | degraded (soft-fail)
    fingerprint  TEXT NOT NULL,      -- stable id for "the same failure"
    signature    TEXT NOT NULL,      -- human-readable normalised form
    result       TEXT,               -- verbatim result text
    log_tail     TEXT,               -- surrounding log lines
    image_stale  INTEGER DEFAULT 0,  -- was the container image behind source?
    org          TEXT,
    -- Dedup key. The sweeper runs on the dashboard's 5s poll, so without this
    -- one failure would be written every 5 seconds until the row changed. A
    -- step execution is uniquely identified by when it finished, so the same
    -- (pod, step, completed_at) is one event — while a genuine RE-run produces
    -- a new completed_at and is correctly recorded as a recurrence.
    step_done_at TEXT,
    UNIQUE (pod_id, step_name, step_done_at)
);
CREATE INDEX IF NOT EXISTS idx_failure_fp   ON failure_events(fingerprint);
CREATE INDEX IF NOT EXISTS idx_failure_pod  ON failure_events(pod_id, ts);
"""

# Order matters: strip the most specific things first.
_SCRUB = [
    (re.compile(r"POD-\d+", re.I), "POD-N"),
    (re.compile(r"pseudoco-\d+", re.I), "pseudoco-N"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "UUID"),
    (re.compile(r"\b[0-9a-f]{32,}\b", re.I), "HEX"),
    (re.compile(r"\b[A-Z0-9]{20}\b"), "IKEY"),          # Duo ikey / app id shapes
    (re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}Z?"), "TS"),
    (re.compile(r"\b\d+(\.\d+)?\s*(ms|s|m|h|GB|MB|KB|chars|bytes|rows?|users?|SGTs?)\b", re.I), "N UNIT"),
    (re.compile(r"'[^']{0,80}'"), "'X'"),               # quoted names/ids
    (re.compile(r'"[^"]{0,80}"'), '"X"'),
    (re.compile(r"\b\d+\b"), "N"),
    (re.compile(r"\s+"), " "),
]


def normalise(text: str) -> str:
    """Reduce a result string to what identifies the FAILURE, not the instance."""
    s = (text or "").strip()
    s = re.sub(r"^\[soft-fail\]\s*", "", s, flags=re.I)
    for pat, repl in _SCRUB:
        s = pat.sub(repl, s)
    return s.strip()[:200]


def fingerprint(phase: str, step: str, result: str) -> tuple[str, str]:
    """Return (fingerprint, human-readable signature)."""
    sig = f"{phase}/{step}: {normalise(result)}"
    fp = hashlib.sha1(sig.encode("utf-8")).hexdigest()[:12]
    return fp, sig


def ensure_table(conn: sqlite3.Connection) -> None:
    conn.executescript(SCHEMA)
    conn.commit()


def record(conn: sqlite3.Connection, *, pod_id: str, phase: str, step_name: str,
           status: str, result: str, log_tail: str = "", image_stale: bool = False,
           org: str = "", ts: str = "", step_done_at: str = "") -> str | None:
    """Append one failure event. Returns its fingerprint, or None if this exact
    step execution was already recorded.

    Append-only by design — a recurrence must never overwrite the earlier
    occurrence, because counting recurrences is the entire point. The only
    suppression is per step EXECUTION (see step_done_at), so the sweeper can run
    repeatedly without duplicating a single failure.
    """
    ensure_table(conn)
    fp, sig = fingerprint(phase, step_name, result)
    try:
        conn.execute(
            "INSERT INTO failure_events (ts, pod_id, phase, step_name, status, "
            "fingerprint, signature, result, log_tail, image_stale, org, step_done_at) "
            "VALUES (COALESCE(NULLIF(?,''), datetime('now')),?,?,?,?,?,?,?,?,?,?,?)",
            (ts, pod_id, phase, step_name, status, fp, sig,
             (result or "")[:4000], (log_tail or "")[:8000],
             1 if image_stale else 0, org, step_done_at or ""),
        )
        conn.commit()
        return fp
    except sqlite3.IntegrityError:
        return None       # already recorded this execution — not a new event


def incidence(conn: sqlite3.Connection, days: int = 7) -> list[dict]:
    """Which failures recur, and do they span PODs?

    Cross-POD spread is the signal that separates our bug from the lab's: a
    fingerprint on many PODs is code, one that only ever hits a single POD is
    usually that POD's environment.
    """
    ensure_table(conn)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT fingerprint, signature, phase, step_name, "
        "       COUNT(*) AS hits, COUNT(DISTINCT pod_id) AS pods, "
        "       MIN(ts) AS first_seen, MAX(ts) AS last_seen, "
        "       SUM(image_stale) AS stale_hits "
        "FROM failure_events "
        f"WHERE ts >= datetime('now', '-{int(days)} days') "
        "GROUP BY fingerprint ORDER BY hits DESC, pods DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def recent(conn: sqlite3.Connection, limit: int = 50) -> list[dict]:
    ensure_table(conn)
    conn.row_factory = sqlite3.Row
    return [dict(r) for r in conn.execute(
        "SELECT * FROM failure_events ORDER BY id DESC LIMIT ?", (limit,))]
