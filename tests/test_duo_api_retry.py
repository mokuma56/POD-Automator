"""Transient Duo Admin API failures must not hard-fail a card.

On 2026-11-16 Duo's API stalled for a few minutes: POD-13's org_setup died on
one 20s read timeout and POD-8's authproxy_push said only "Could not find or
create Auth Proxy integration" — both passed on a plain re-run.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import duo_automation as da  # noqa: E402


class _Resp:
    def __init__(self, code=200, body=None):
        self.status_code, self._body = code, body or {"stat": "OK", "response": {}}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}")

    def json(self):
        return self._body


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    monkeypatch.setattr(da.time, "sleep", lambda s: None)
    monkeypatch.setattr(da, "_sign_request", lambda *a, **k: {})


def test_get_survives_a_read_timeout(monkeypatch):
    calls = []

    def fake_get(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise requests.ReadTimeout("read timed out")
        return _Resp(body={"stat": "OK", "response": {"admin_count": 1}})
    monkeypatch.setattr(da.requests, "get", fake_get)
    assert da._duo_request("i", "s", "h", "GET", "/admin/v1/info/summary")["response"]["admin_count"] == 1
    assert len(calls) == 2


def test_get_retries_a_5xx_then_gives_up(monkeypatch):
    calls = []
    monkeypatch.setattr(da.requests, "get", lambda *a, **k: calls.append(1) or _Resp(503))
    with pytest.raises(requests.HTTPError):
        da._duo_request("i", "s", "h", "GET", "/x")
    assert len(calls) == 3


def test_post_is_not_blindly_retried(monkeypatch):
    calls = []

    def fake_post(*a, **k):
        calls.append(1)
        raise requests.ReadTimeout("read timed out")
    monkeypatch.setattr(da.requests, "post", fake_post)
    with pytest.raises(requests.ReadTimeout):
        da._duo_request("i", "s", "h", "POST", "/admin/v1/integrations")
    assert len(calls) == 1


def test_create_uses_an_integration_that_landed_despite_a_timeout(monkeypatch):
    logs = []
    monkeypatch.setattr(da, "_duo_request",
                        lambda *a, **k: (_ for _ in ()).throw(requests.ReadTimeout("t")))
    monkeypatch.setattr(da, "duo_get_authproxy_creds",
                        lambda *a, **k: {"ikey": "DIX", "skey": "sk", "host": "h"})
    got = da.duo_create_authproxy_integration("i", "s", "h", log=logs.append)
    assert got["ikey"] == "DIX"
    assert any("ReadTimeout" in m for m in logs)


def test_create_retries_once_then_reports_why(monkeypatch):
    posts, logs = [], []

    def fake(*a, **k):
        posts.append(1)
        raise requests.ConnectionError("reset")
    monkeypatch.setattr(da, "_duo_request", fake)
    monkeypatch.setattr(da, "duo_get_authproxy_creds", lambda *a, **k: None)
    assert da.duo_create_authproxy_integration("i", "s", "h", log=logs.append) is None
    assert len(posts) == 2
    assert sum("ConnectionError" in m for m in logs) == 2
