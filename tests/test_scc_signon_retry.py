"""SCC login through the iDAC card: a stalled Cisco sign-on is retried, not skipped.

POD-19, 2026-09-28: at sso_test the iDAC "View" tab sat on
sign-on.security.cisco.com/sso/saml2/... for the whole 90s, was written off as
"not SCC", and — the card's other "View" being Meraki — the step failed. The
same button had signed in three times earlier in that run and a re-run got in
within 11s. Now a sign-on stall gets 60s more and one fresh click; a tab that
opened anything else is still skipped at once.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import contextlib
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import duo_automation as da  # noqa: E402

SIGNON = "https://sign-on.security.cisco.com/sso/saml2/0oa3widewzm6eklvx357"
SCC = "https://security.cisco.com/workflows?x=1"
MERAKI = "https://n219.dashboard.meraki.com/o/rkcvZb/manage/organization/overview"


class FakeTab:
    """A popup whose URL moves on as time passes (one step per 5s wait)."""

    def __init__(self, urls):
        self._urls, self._i, self.closed = list(urls), 0, False

    @property
    def url(self):
        return self._urls[min(self._i, len(self._urls) - 1)]

    def wait_for_timeout(self, ms):
        self._i += 1

    def wait_for_load_state(self, *a, **k):
        pass

    def close(self):
        self.closed = True


class FakeCtx:
    """The iDAC card page + the popups each click opens, in order."""

    def __init__(self, tabs):
        self.tabs, self.clicks = list(tabs), []
        ctx = self

        class Card:
            def goto(self, *a, **k):
                pass

            def wait_for_timeout(self, ms):
                pass

            def evaluate(self, js, arg=None):
                if js == da._JS_IDAC_CLICK:
                    ctx.clicks.append(arg)
                    return True
                return []

        self.card = Card()

    def new_page(self):
        return self.card

    @contextlib.contextmanager
    def expect_page(self, timeout=None):
        info = type("Info", (), {})()
        yield info
        info.value = self.tabs.pop(0)


@pytest.fixture(autouse=True)
def two_view_buttons(monkeypatch):
    # The live card: two "View" buttons, the first is SCC, the second Meraki.
    monkeypatch.setattr(da, "_idac_scc_candidates",
                        lambda btns: [{"label": "View", "i": 0}, {"label": "View", "i": 1}])
    monkeypatch.setattr(da, "_scc_enterprise_id", lambda t, db_path="": "de0bd323-ent")


def _open(ctx):
    logs = []
    try:
        return da._scc_open_session(ctx, "https://idac.example/x", log=logs.append), logs
    except RuntimeError as e:
        return e, logs


def test_a_stalled_signon_gets_one_fresh_click_and_succeeds():
    stalled = FakeTab([SIGNON])                 # never leaves sign-on
    fresh = FakeTab([SIGNON, SCC])              # second click signs in
    ctx = FakeCtx([stalled, fresh])
    (tab, ent), logs = _open(ctx)
    assert tab is fresh and ent == "de0bd323-ent"
    assert ctx.clicks == [0, 0], "same button clicked twice"
    assert stalled.closed
    assert any("clicking it once more" in m for m in logs)


def test_a_slow_signon_that_finishes_in_the_extra_minute_needs_no_reclick():
    slow = FakeTab([SIGNON] * 20 + [SCC])       # lands after ~100s
    ctx = FakeCtx([slow])
    (tab, _), logs = _open(ctx)
    assert tab is slow and ctx.clicks == [0]
    assert any("60s more" in m for m in logs)


def test_the_wrong_button_is_still_skipped_at_once():
    """Meraki is not a slow login — waiting or re-clicking cannot help."""
    meraki, scc = FakeTab([MERAKI]), FakeTab([SCC])
    ctx = FakeCtx([meraki, scc])
    (tab, _), logs = _open(ctx)
    assert tab is scc and ctx.clicks == [0, 1], "no retry of the Meraki button"
    assert any("not SCC, trying next" in m for m in logs)


def test_gives_up_only_after_both_tries_stall_and_says_so():
    ctx = FakeCtx([FakeTab([SIGNON]), FakeTab([SIGNON]), FakeTab([MERAKI])])
    err, _ = _open(ctx)
    assert isinstance(err, RuntimeError)
    assert "stalled on Cisco sign-on" in str(err) and "on both tries" in str(err)
    assert "meraki" in str(err)
    assert ctx.clicks == [0, 0, 1]


def test_the_ise_container_copy_has_the_same_rule():
    src = (ROOT / "ise_integrations.py").read_text()
    body = src[src.index("async def _scc_open_session_async"):]
    body = body[:body.index("\nasync def ", 10)]
    assert "def _is_signon(" in body
    assert "for _try in range(2):" in body
    assert "on both tries" in body
