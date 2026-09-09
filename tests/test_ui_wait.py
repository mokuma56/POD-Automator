"""The distinction ui_wait exists to preserve: "not there" vs "not yet".

Four separate failures this month were misdiagnosed because a message said
something was absent when the real state was a login page, a page still
navigating, or a shell that had painted nothing but loaders. These tests pin
each of those cases apart.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui_wait import _classify, absent_message, wait_for  # noqa: E402


def _info(controls=(), skeletons=0, body_chars=5000, error=None):
    d = {"controls": list(controls), "control_count": len(controls),
         "skeletons": skeletons, "body_chars": body_chars}
    if error is not None:
        d["error"] = error
    return d


class _FakePage:
    """Minimal stand-in: counts sleeps so we can assert on polling."""

    def __init__(self, url="https://security.cisco.com/dashboard"):
        self.url = url
        self.sleeps = 0

    def wait_for_timeout(self, ms):
        self.sleeps += 1


# ── classification ────────────────────────────────────────────────────────────

def test_login_page_is_detected_from_ise_url():
    d = _classify("https://198.18.5.101/admin/login.jsp", _info(["a", "b"]))
    assert d["login_page"] is True


def test_scc_sign_on_host_is_a_login_page():
    d = _classify("https://sign-on.security.cisco.com/", _info(["Sign In"]))
    assert d["login_page"] is True


def test_normal_scc_dashboard_is_not_a_login_page():
    d = _classify("https://security.cisco.com/dashboard",
                  _info(["Home", "Products", "Platform Management"]))
    assert d["login_page"] is False
    assert d["skeleton"] is False


def test_skeleton_detected_from_loading_placeholders():
    """The SCC sidebar failure: one link, page full of grey bars."""
    d = _classify("https://security.cisco.com/dashboard",
                  _info(["Security Cloud Control"], skeletons=24, body_chars=400))
    assert d["skeleton"] is True


def test_skeleton_detected_from_a_nearly_empty_page():
    """Even with no skeleton classes, one control and a tiny body is 'too early'."""
    d = _classify("https://security.cisco.com/dashboard",
                  _info(["Security Cloud Control"], skeletons=0, body_chars=300))
    assert d["skeleton"] is True


def test_a_rendered_page_with_many_controls_is_not_skeleton():
    d = _classify("https://security.cisco.com/dashboard",
                  _info([f"c{i}" for i in range(12)], body_chars=9000))
    assert d["skeleton"] is False


def test_unreadable_page_is_flagged_rather_than_called_empty():
    """page.content() raising while navigating must not read as 'absent'."""
    d = _classify("https://security.cisco.com/dashboard",
                  _info(error="Unable to retrieve content because the page is navigating"))
    assert d["unreadable"] is True


# ── messages ──────────────────────────────────────────────────────────────────

def test_message_blames_the_lost_session_not_the_element():
    d = _classify("https://198.18.5.101/admin/login.jsp", _info(["Login"]))
    msg = absent_message("ise node link", diag=d)
    assert "LOGIN page" in msg
    assert "session was lost" in msg


def test_message_says_too_early_for_a_skeleton_page():
    d = _classify("https://security.cisco.com/dashboard",
                  _info(["Security Cloud Control"], skeletons=24, body_chars=400))
    msg = absent_message("Platform Management", diag=d)
    assert "not 'absent'" in msg
    assert "placeholder" in msg


def test_message_admits_genuine_absence_when_the_page_is_rendered():
    d = _classify("https://security.cisco.com/dashboard",
                  _info([f"c{i}" for i in range(12)], body_chars=9000))
    msg = absent_message("Platform Management", diag=d)
    assert "looks rendered" in msg


def test_message_always_carries_the_url_and_controls_seen():
    """A bare 'not found' is what made four different failures look identical."""
    d = _classify("https://security.cisco.com/dashboard", _info(["Home", "Products"]))
    msg = absent_message("Integrations", diag=d)
    assert "url=https://security.cisco.com/dashboard" in msg
    assert "Home" in msg


# ── polling ───────────────────────────────────────────────────────────────────

def test_returns_the_probe_value_immediately_when_ready():
    page = _FakePage()
    assert wait_for(page, "thing", lambda: {"x": 1}, timeout=30, interval=5) == {"x": 1}
    assert page.sleeps == 0


def test_keeps_polling_until_the_control_appears():
    page = _FakePage()
    calls = {"n": 0}

    def probe():
        calls["n"] += 1
        return "here" if calls["n"] >= 3 else None

    assert wait_for(page, "thing", probe, timeout=30, interval=5) == "here"
    assert calls["n"] == 3


def test_a_raising_probe_means_not_yet_not_absent():
    """The bug introduced while fixing the others: content() raised mid-navigation
    and the exception escaped as a failed login."""
    page = _FakePage()
    calls = {"n": 0}

    def probe():
        calls["n"] += 1
        if calls["n"] < 3:
            raise RuntimeError("the page is navigating and changing the content")
        return "here"

    assert wait_for(page, "thing", probe, timeout=30, interval=5) == "here"


def test_gives_up_and_returns_none_rather_than_raising():
    page = _FakePage()
    assert wait_for(page, "thing", lambda: None, timeout=15, interval=5) is None


def test_a_permanently_raising_probe_still_returns_none():
    page = _FakePage()
    assert wait_for(page, "thing", lambda: 1 / 0, timeout=15, interval=5) is None


def test_probe_errors_are_logged_once_not_every_poll():
    """A noisy probe must not bury the log; a broken one must still be visible."""
    page = _FakePage()
    seen = []
    wait_for(page, "thing", lambda: 1 / 0, timeout=30, interval=5, log=seen.append)
    assert sum(1 for s in seen if "not ready yet" in s) == 1


# ── blocking dialogs ──────────────────────────────────────────────────────────

def test_a_blocking_dialog_is_named_as_the_cause_not_the_symptom():
    """SCC's org picker holds the page skeletal indefinitely. "Still rendering"
    is true but unactionable; "dismiss this dialog" is the real answer."""
    d = _classify("https://security.cisco.com/dashboard",
                  dict(_info(["Organization", "Continue"], skeletons=31, body_chars=400),
                       dialog="Organization PseudoCo-525 Continue"))
    msg = absent_message("Platform Management", diag=d)
    assert "dialog is blocking" in msg
    assert "must be dismissed" in msg


def test_login_page_still_outranks_a_dialog():
    d = _classify("https://198.18.5.101/admin/login.jsp",
                  dict(_info(["Login"]), dialog="Session expired"))
    assert "LOGIN page" in absent_message("node link", diag=d)


def test_no_dialog_key_is_harmless():
    d = _classify("https://security.cisco.com/dashboard", _info(["Home", "Products"]))
    assert "dialog is blocking" not in absent_message("Integrations", diag=d)
