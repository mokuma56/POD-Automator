"""Tests for the [sso] stanza guard.

Regression cover for the bug that took POD-5's DuoAuthProxy down mid-run:
_pw_get_copy_content matched on the label "1.2", and :has-text() matches
ANCESTORS as well as the element, so it returned the config FILE PATH instead of
the stanza. Those 69 characters were appended into authproxy.cfg, which
invalidated the [cloud] section — Duo logged "No valid cloud sections could be
found", the service died, and the failure surfaced four steps later as sso_test
reporting "Invalid credentials".

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from duo_automation import _looks_like_sso_stanza  # noqa: E402

# The exact value captured on POD-5, 2026-08-31 12:53:59.
POD5_BAD_CAPTURE = r"C:\Program Files\Duo Security Authentication Proxy\conf\authproxy.cfg"

REAL_STANZA = (
    "[sso]\n"
    "; Remote Identity Key for Active Directory\n"
    "rikey=DIXXXXXXXXXXXXXXXXXX\n"
    "; Uncomment the service_account_username and service_account_password\n"
    "; Then, enter your Active Directory service account username\n"
    "; service_account_username=\n"
    "; service_account_password=\n"
)


def test_rejects_the_capture_that_broke_pod5():
    """The whole point: a filesystem path must never reach authproxy.cfg."""
    assert _looks_like_sso_stanza(POD5_BAD_CAPTURE) is False


def test_accepts_a_real_stanza():
    assert _looks_like_sso_stanza(REAL_STANZA) is True


def test_accepts_a_stanza_identified_only_by_rikey():
    """Some captures omit the [sso] header but carry the key that matters."""
    body = "rikey=DIXXXXXXXXXXXXXXXXXX\n" + "; padding to clear the length floor\n" * 3
    assert _looks_like_sso_stanza(body) is True


def test_rejects_empty_and_none():
    assert _looks_like_sso_stanza("") is False
    assert _looks_like_sso_stanza(None) is False


def test_rejects_something_too_short_to_be_a_stanza():
    assert _looks_like_sso_stanza("short") is False


def test_rejects_any_bare_windows_path_not_just_that_one():
    for p in (r"D:\some\other\path.cfg",
              r"C:\Users\Public\Desktop\Duo-Login.html"):
        assert _looks_like_sso_stanza(p) is False, p


def test_a_path_mentioned_inside_a_real_stanza_is_still_accepted():
    """Only a stanza that STARTS with a path is bogus; one that merely
    references a path in a comment is legitimate."""
    body = REAL_STANZA + "; see C:\\Program Files\\Duo Security\\conf\\authproxy.cfg\n"
    assert _looks_like_sso_stanza(body) is True
