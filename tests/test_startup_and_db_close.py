"""Two host-process fixes from 2026-10-12.

1. At login launchd starts the dashboard before Docker Desktop, and the image
   check reported "image pod-automator:latest not found — build it" for an
   image that existed. Docker being down must not read as a missing image.
2. `with sqlite3.connect(...) as c:` commits but does NOT close, so every
   /api/duo/status poll (via duo_ensure_table) left a connection open until the
   garbage collector ran — 29 open handles minutes after boot.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sqlite3
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dashboard as d  # noqa: E402
import duo_automation as da  # noqa: E402


class _Done:
    def __init__(self, rc, out=""):
        self.returncode, self.stdout, self.stderr = rc, out, ""


def test_docker_down_is_not_a_missing_image(monkeypatch):
    monkeypatch.setattr(d.subprocess, "run", lambda *a, **k: _Done(1))
    st = d._image_staleness()
    assert st["docker_down"] is True
    assert st["stale"] is False
    assert "not found" not in st["reason"]


def test_missing_image_still_reported_when_docker_is_up(monkeypatch):
    def fake(cmd, **k):
        return _Done(0, "28.3.2") if cmd[:2] == ["docker", "info"] else _Done(1)
    monkeypatch.setattr(d.subprocess, "run", fake)
    st = d._image_staleness()
    assert st["stale"] is True and "not found" in st["reason"]


def test_docker_up_survives_a_missing_binary(monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError("docker")
    monkeypatch.setattr(d.subprocess, "run", boom)
    assert d._docker_up() is False


def test_duo_ensure_table_closes_its_connection(tmp_path, monkeypatch):
    opened = []
    real = sqlite3.connect

    class Tracked(sqlite3.Connection):
        closed = False

        def close(self):
            self.closed = True
            super().close()

    def spy(*a, **k):
        k["factory"] = Tracked
        c = real(*a, **k)
        opened.append(c)
        return c

    db = tmp_path / "t.db"
    with real(db) as c:
        c.execute("CREATE TABLE org_credentials (org_number TEXT)")
    monkeypatch.setattr(sqlite3, "connect", spy)
    da.duo_ensure_table(str(db))
    assert opened and all(c.closed for c in opened)
