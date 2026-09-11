"""Switch version acceptance: MIN_SWITCH_VERSION or newer.

POD-18 on 2026-09-11 soft-failed verify_border_spine on a switch running
17.18.03 — a NEWER image than the golden 17.12.01, with every other check on
that line passing — because the test was the substring "17.12" in the version
string. A newer image read exactly like an ancient one.

The trap in fixing it is comparing as text: "17.9.1" sorts ABOVE "17.12.1" as a
string while being the older release, so a string comparison would accept
precisely the images this check exists to catch. Hence tuples of ints, and
hence this file.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import onboard_router as o  # noqa: E402


def _show(ver):
    return f"Cisco IOS XE Software, Version {ver}\nsome other line\n"


def _ok(ver):
    return o._parse_version_str(_show(ver))[0]


# ── the reported case ─────────────────────────────────────────────────────────

def test_a_newer_image_is_accepted():
    """The POD-18 failure: 17.18.03 is newer than golden and must pass."""
    assert _ok("17.18.03") is True


def test_the_golden_image_is_accepted():
    assert _ok("17.12.01") is True
    assert _ok("17.12.1") is True


def test_a_letter_suffix_does_not_break_it():
    assert _ok("17.12.01a") is True


# ── the trap ──────────────────────────────────────────────────────────────────

def test_an_older_release_that_sorts_higher_as_text_is_rejected():
    """'17.9.1' > '17.12.1' as strings, but 17.9 predates 17.12."""
    assert "17.9.1" > "17.12.1"          # the text comparison really is backwards
    assert _ok("17.9.1") is False        # and we do not fall for it


def test_older_majors_are_rejected():
    assert _ok("16.12.4") is False
    assert _ok("17.11.99") is False


def test_a_newer_patch_within_the_floor_release_is_accepted():
    assert _ok("17.12.2") is True
    assert _ok("17.12.04") is True


def test_a_newer_major_is_accepted():
    assert _ok("18.1.1") is True


# ── edges ─────────────────────────────────────────────────────────────────────

def test_a_bare_major_minor_is_not_evidence_of_the_patch_floor():
    """"17.12" could be 17.12.0; it is not proof of >= 17.12.1."""
    assert _ok("17.12") is False


def test_an_unreadable_version_is_reported_as_unreadable_not_as_old():
    """Two different problems; only one of them is about the image."""
    ok, ver = o._parse_version_str("nothing resembling a version here")
    assert ok is False
    assert "no version line" in ver


def test_the_version_string_is_returned_for_the_message():
    """The step message prints this, so it must carry the real value."""
    ok, ver = o._parse_version_str(_show("17.18.03"))
    assert ok is True and ver == "17.18.03"


# ── the normaliser ────────────────────────────────────────────────────────────

def test_tuple3_pads_and_truncates():
    assert o._version_tuple3("17.12.01") == (17, 12, 1)
    assert o._version_tuple3("17.12") == (17, 12, 0)
    assert o._version_tuple3("17") == (17, 0, 0)
    assert o._version_tuple3("17.12.1.9") == (17, 12, 1)


def test_tuple3_on_junk_is_zeros_not_an_exception():
    assert o._version_tuple3("??") == (0, 0, 0)
    assert o._version_tuple3("") == (0, 0, 0)


def test_the_floor_is_what_we_think_it_is():
    assert o.MIN_SWITCH_VERSION == (17, 12, 1)


# ── the MCP switch_verify helper must agree ──────────────────────────────────

def test_the_mcp_helper_shares_the_same_rule():
    """pod_automator._check_show_ver backs the switch_verify MCP tool. It had
    its own substring test (written as `"17.12" in line or "17.12" in line`),
    so it would have kept reporting a newer image as a failure after this fix
    landed elsewhere."""
    import pod_automator as pa
    assert pa._check_show_ver(_show("17.18.03"))[0] is True
    assert pa._check_show_ver(_show("17.12.01"))[0] is True
    assert pa._check_show_ver(_show("17.9.1"))[0] is False


def test_the_mcp_helper_says_why_it_failed():
    import pod_automator as pa
    ok, msg = pa._check_show_ver(_show("16.12.4"))
    assert ok is False
    assert "17.12.1" in msg and "minimum" in msg
