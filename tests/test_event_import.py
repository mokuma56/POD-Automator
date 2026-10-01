"""Event-CSV import and the single-POD form.

The raw dCloud EventsDetails export has no POD Number and no VPN host column.
PODs are numbered in session-ID order from a start number, and the VPN host is
derived from the session ID's first digit: 1 = RTP, 4 = SJC.
"""
import csv
import io
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard as d  # noqa: E402

RTP = "dcloud-rtp-anyconnect.cisco.com"
SJC = "dcloud-sjc-anyconnect.cisco.com"

# Shape of a real export: spaces after commas, a trailing space on "Password ",
# rows out of session order. Values are fake.
RAW_EXPORT = (
    "Event Id, Event Timezone, Session Id, Session Name, Users, Username, Password \n"
    "410955, America/Costa_Rica,1360505, Lab, None, v3user1, ccc333\n"
    "410955, America/Costa_Rica,4360503, Lab, None, v1user1, aaa111\n"
    "410955, America/Costa_Rica,1360504, Lab, None, v2user1, bbb222\n"
)


def _parse(text, start_pod=1):
    reader = csv.DictReader(io.StringIO(text))
    return d._parse_event_rows(reader.fieldnames, list(reader), start_pod)


def test_vpn_host_from_session_prefix():
    assert d._vpn_host_for_session("1360503") == RTP
    assert d._vpn_host_for_session(" 4123456") == SJC
    assert d._vpn_host_for_session("7123456") == ""
    assert d._vpn_host_for_session("") == ""


def test_raw_export_numbered_in_session_order_with_derived_vpn():
    recs, warnings = _parse(RAW_EXPORT)
    assert warnings == []
    assert [(r["pod_id"], r["session_id"], r["vpn_host"]) for r in recs] == [
        ("POD-1", "1360504", RTP),
        ("POD-2", "1360505", RTP),
        ("POD-3", "4360503", SJC),
    ]
    # "Username" wins over the "Users" column; the trailing-space header is found.
    assert (recs[0]["vpn_user"], recs[0]["vpn_pass"]) == ("v2user1", "bbb222")


def test_raw_export_start_pod_offset():
    recs, _ = _parse(RAW_EXPORT, start_pod=8)
    assert [r["pod_id"] for r in recs] == ["POD-8", "POD-9", "POD-10"]


def test_unknown_prefix_is_warned_not_dropped():
    recs, warnings = _parse("Session Id,Username,Password\n9000001,u,p\n")
    assert recs[0]["vpn_host"] == "" and len(warnings) == 1


def test_handbuilt_format_still_uses_its_columns():
    text = ("Session Id,POD Number,vpn host,Username,Password,router_serial\n"
            "4329155,4,custom-host.example,v1,p1,FJC300412NA\n"
            "1329155,5,,v2,p2,\n")
    recs, _ = _parse(text, start_pod=50)  # start_pod ignored with a POD column
    assert [(r["pod_id"], r["vpn_host"]) for r in recs] == [
        ("POD-4", "custom-host.example"), ("POD-5", RTP)]
    assert recs[0]["router_serial"] == "FJC300412NA"


@pytest.fixture
def client(tmp_path, monkeypatch):
    db = tmp_path / "pods.db"
    conn = sqlite3.connect(db)
    conn.execute("""CREATE TABLE pods (pod_id TEXT PRIMARY KEY, status TEXT, device_data TEXT,
        router_serial TEXT, vpn_host TEXT, vpn_user TEXT, vpn_pass TEXT, router_ip TEXT,
        session_id TEXT, assigned_to TEXT, notes TEXT, updated_at TEXT)""")
    conn.execute("CREATE TABLE pipeline_steps (pod_id TEXT, step TEXT)")
    conn.execute("INSERT INTO pipeline_steps VALUES ('POD-3', 'old')")
    conn.commit(); conn.close()

    def _db():
        c = sqlite3.connect(db)
        c.row_factory = sqlite3.Row
        return c
    monkeypatch.setattr(d, "_db", _db)
    return d.app.test_client(), _db


def test_upload_raw_export(client):
    c, db = client
    r = c.post("/api/upload-event", data={
        "file": (io.BytesIO(RAW_EXPORT.encode()), "EventsDetails.csv"), "start_pod": "3"})
    assert r.status_code == 200 and r.json["pods_created"] == 3
    rows = db().execute("SELECT pod_id, vpn_host FROM pods ORDER BY session_id").fetchall()
    assert [tuple(x) for x in rows] == [("POD-3", RTP), ("POD-4", RTP), ("POD-5", SJC)]
    # Loading a new session onto POD-3 clears its old step rows.
    assert db().execute("SELECT COUNT(*) FROM pipeline_steps").fetchone()[0] == 0


def test_add_single_pod(client):
    c, db = client
    r = c.post("/api/add-pod", json={"pod_number": "12", "session_id": "4555555",
                                     "vpn_user": "v9user1", "vpn_pass": "x"})
    assert r.status_code == 200 and r.json["pod_id"] == "POD-12"
    row = db().execute("SELECT vpn_host, status, router_ip FROM pods WHERE pod_id='POD-12'").fetchone()
    assert tuple(row) == (SJC, "pending", d.DEFAULT_ROUTER_IP)


def test_add_single_pod_validation(client):
    c, _ = client
    assert c.post("/api/add-pod", json={"pod_number": "x"}).status_code == 400
    r = c.post("/api/add-pod", json={"pod_number": "1", "session_id": "1"})
    assert r.status_code == 400 and "Username" in r.json["error"]
    r = c.post("/api/add-pod", json={"pod_number": "1", "session_id": "7000",
                                     "vpn_user": "u", "vpn_pass": "p"})
    assert r.status_code == 400 and "VPN host" in r.json["error"]
    r = c.post("/api/add-pod", json={"pod_number": "1", "session_id": "7000", "vpn_user": "u",
                                     "vpn_pass": "p", "vpn_host": "other.example"})
    assert r.status_code == 200
