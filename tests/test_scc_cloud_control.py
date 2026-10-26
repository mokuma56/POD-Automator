"""SCC login: a session that bounces to a password page is not a session, and
Cisco Cloud Control's Security entry is a working way in.

2026-10-26, all 11 PODs: the iDAC SCC "Login" reached security.cisco.com
/dashboard, resolved an enterprise id, was logged "SCC session established",
and ~5s later the SPA redirected to a Webex idbroker "Enter your password"
page. Every SCC step then timed out on a page that could never render. The
iDAC card's Cisco Cloud Control Login still signs in, and its Security nav
opens SCC on that session.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import contextlib
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import duo_automation as da  # noqa: E402

SCC = "https://security.cisco.com/dashboard"
IDBROKER = "https://idbroker-b-us.webex.com/idb/saml2/jsp/doSSO.jsp?realm=x"
CC_HOME = "https://cloud.cisco.com/home/assistant"


class FakeTab:
    """A popup whose URL moves on one step per wait; clicking Security on a
    Cloud Control tab sends it to `after_security`."""

    def __init__(self, urls, after_security=None, has_security=True):
        self._urls, self._i, self.closed = list(urls), 0, False
        self._after, self._has_security = after_security, has_security

    @property
    def url(self):
        return self._urls[min(self._i, len(self._urls) - 1)]

    def wait_for_timeout(self, ms):
        self._i += 1

    def wait_for_load_state(self, *a, **k):
        pass

    def close(self):
        self.closed = True

    def goto(self, url, **k):
        self.gotos = getattr(self, "gotos", 0) + 1
        self._urls, self._i = [CC_HOME], 0
        if getattr(self, "_after_retry", None):
            self._after = self._after_retry

    def get_by_text(self, text, exact=False):
        tab = self

        class Loc:
            def count(self):
                return 1 if (text == "Security" and tab._has_security) else 0

            @property
            def first(self):
                return self

            def click(self):
                tab._urls, tab._i = list(tab._after), 0

        return Loc()


class FakeCtx:
    def __init__(self, tabs):
        self.tabs, self.clicks, self.pages = list(tabs), [], []
        ctx = self

        class Card:
            url = "https://idac.example/x"

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
        self.pages.append(self.card)

    def new_page(self):
        return self.card

    @contextlib.contextmanager
    def expect_page(self, timeout=None):
        info = type("Info", (), {})()
        yield info
        info.value = self.tabs.pop(0)
        self.pages.append(info.value)


@pytest.fixture(autouse=True)
def scc_then_cloud_control(monkeypatch):
    monkeypatch.setattr(da, "_idac_scc_candidates", lambda btns: [
        {"label": "Login", "i": 6, "section": "Cisco Security Cloud Control"},
        {"label": "Login", "i": 7, "section": "Cisco Cloud Control"},
    ])
    monkeypatch.setattr(da, "_scc_enterprise_id", lambda t, db_path="": "abbc5ad1-ent")


def _open(ctx):
    logs = []
    try:
        return da._scc_open_session(ctx, "https://idac.example/x", log=logs.append), logs
    except RuntimeError as e:
        return e, logs


def test_scc_that_bounces_to_a_password_page_is_not_established():
    bounced = FakeTab([SCC, IDBROKER])
    via_cc = FakeTab([CC_HOME], after_security=[SCC])
    ctx = FakeCtx([bounced, via_cc])
    (tab, ent), logs = _open(ctx)
    assert bounced.closed
    assert tab is via_cc and ent == "abbc5ad1-ent"
    assert ctx.clicks == [6, 7]
    assert any("did not hold" in m for m in logs)
    assert any("Cisco Cloud Control" in m and "established" in m for m in logs)


def test_scc_that_holds_is_used_without_trying_cloud_control():
    held = FakeTab([SCC])
    ctx = FakeCtx([held])
    (tab, _), _ = _open(ctx)
    assert tab is held and ctx.clicks == [6]


def test_cloud_control_without_a_security_entry_fails_and_says_why():
    ctx = FakeCtx([FakeTab([SCC, IDBROKER]),
                   FakeTab([CC_HOME], has_security=False)])
    err, _ = _open(ctx)
    assert isinstance(err, RuntimeError)
    assert "for a password" in str(err)
    assert "Security entry never reached SCC" in str(err)


def test_security_that_also_bounces_is_rejected():
    """Cloud Control reaching SCC only to bounce must not be trusted either."""
    ctx = FakeCtx([FakeTab([SCC, IDBROKER]),
                   FakeTab([CC_HOME], after_security=[SCC, IDBROKER])])
    err, _ = _open(ctx)
    assert isinstance(err, RuntimeError)


def test_cdfmc_placeholder_host_is_not_an_org():
    """POD-11: tfvars still read cdfmc_host = "Insert Host"."""
    from onboard_router import _cdfmc_host_is_real
    assert not _cdfmc_host_is_real("Insert Host")
    assert not _cdfmc_host_is_real("")
    assert _cdfmc_host_is_real("cisco-pseudoco-537--t92frl.app.us.cdo.cisco.com")


def test_scc_ise_row_check_matches_only_this_pods_row():
    """POD-3, 2026-10-26: `"ise" in page_text` matched "Enterprise" and a
    stale ISE-POD-POD-1-3908 row, so POD-3's OTP was never entered."""
    import dashboard
    page = ("Organization PseudoCo-537 | Enterprise | Add integration | "
            "ISE-POD-POD-1-3908 | Connected")
    assert not dashboard._scc_has_own_ise_row(page, "POD-3")
    assert dashboard._scc_has_own_ise_row(page, "POD-1")
    assert not dashboard._scc_has_own_ise_row("ISE-POD-POD-12-77 | Connected", "POD-1")
    assert dashboard._scc_has_own_ise_row("ise-pod-pod-3-6175 connected", "POD-3")
    assert not dashboard._scc_has_own_ise_row("Enterprise Promise", "POD-3")


def test_a_dropped_security_load_is_retried_once_from_cloud_control_home():
    """POD-7: the Security click left the tab on chrome-error://chromewebdata/."""
    cc = FakeTab([CC_HOME], after_security=["chrome-error://chromewebdata/"])
    cc._after_retry = [SCC]
    ctx = FakeCtx([FakeTab([SCC, IDBROKER]), cc])
    (tab, _), logs = _open(ctx)
    assert tab is cc and cc.gotos == 1
    assert any("retrying from cloud.cisco.com/home" in m for m in logs)
