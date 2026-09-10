"""Wiping must survive a database that lacks the optional step tables.

sda_steps and fabric_steps are created lazily -- by sda_fabric.py and
evpn_fabric.py -- so an install that has never run the fabric cards does not
have them. Full Reset used to wipe the whole list in one loop, so on those
machines it raised "no such table: sda_steps", abandoned every table AFTER it
(duo_steps, ise_steps kept their rows), and reported a hard failure for a
condition that is entirely normal.
"""
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# The list Full Reset wipes, in order. sda_steps sits BEFORE duo_steps and
# ise_steps, which is why its absence used to cost their rows.
TABLES = ("pods", "pipeline_steps", "pipeline_logs", "scc_checklist",
          "fabric_steps", "sda_steps", "duo_steps", "ise_steps")


def _db(tables):
    """An in-memory DB containing only `tables`, each seeded with two PODs."""
    conn = sqlite3.connect(":memory:")
    for t in tables:
        conn.execute(f"CREATE TABLE {t} (pod_id TEXT, val TEXT)")
        conn.execute(f"INSERT INTO {t} (pod_id,val) VALUES ('POD-1','x')")
        conn.execute(f"INSERT INTO {t} (pod_id,val) VALUES ('POD-2','y')")
    conn.commit()
    return conn


def _import():
    import importlib
    return importlib.import_module("dashboard")


def test_missing_table_does_not_stop_the_tables_after_it():
    """The reported bug: no sda_steps -> duo_steps and ise_steps kept their rows."""
    d = _import()
    present = [t for t in TABLES if t not in ("sda_steps", "fabric_steps")]
    conn = _db(present)
    wiped, missing, failed = d._wipe_tables(conn, TABLES)
    assert failed == []
    assert set(missing) == {"sda_steps", "fabric_steps"}
    # everything that DOES exist is emptied, including the two that follow
    # sda_steps in the list
    for t in present:
        assert conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0] == 0, t
    assert "duo_steps" in wiped and "ise_steps" in wiped


def test_absent_tables_are_reported_as_missing_not_failed():
    """A table that does not exist has no rows to delete. That is a note."""
    d = _import()
    conn = _db([t for t in TABLES if t != "sda_steps"])
    _, missing, failed = d._wipe_tables(conn, TABLES)
    assert missing == ["sda_steps"]
    assert failed == []


def test_a_complete_database_wipes_everything():
    d = _import()
    conn = _db(TABLES)
    wiped, missing, failed = d._wipe_tables(conn, TABLES)
    assert set(wiped) == set(TABLES)
    assert missing == [] and failed == []


def test_pod_scoped_wipe_only_touches_that_pod():
    d = _import()
    conn = _db(TABLES)
    d._wipe_tables(conn, TABLES, pod_id="POD-1")
    for t in TABLES:
        rows = conn.execute(f"SELECT pod_id FROM {t}").fetchall()
        assert [r[0] for r in rows] == ["POD-2"], t


def test_pod_scoped_wipe_also_tolerates_a_missing_table():
    d = _import()
    conn = _db([t for t in TABLES if t != "sda_steps"])
    wiped, missing, failed = d._wipe_tables(conn, TABLES, pod_id="POD-1")
    assert missing == ["sda_steps"] and failed == []
    assert conn.execute("SELECT COUNT(*) FROM ise_steps").fetchone()[0] == 1


def test_counting_skips_absent_tables_rather_than_raising():
    """Verification used to raise 'no such table' and report the whole reset as
    unverifiable even when the wipe had succeeded."""
    d = _import()
    conn = _db([t for t in TABLES if t != "sda_steps"])
    counts = d._count_rows(conn, TABLES)
    assert "sda_steps" not in counts
    assert counts["duo_steps"] == 2


def test_counting_is_pod_scoped_when_asked():
    d = _import()
    conn = _db(TABLES)
    assert d._count_rows(conn, TABLES, pod_id="POD-1")["pods"] == 1


def test_existing_tables_reflects_the_database():
    d = _import()
    conn = _db(["pods", "duo_steps"])
    assert d._existing_tables(conn) == {"pods", "duo_steps"}
