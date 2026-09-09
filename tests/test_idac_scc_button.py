"""Which iDAC control opens Security Cloud Control.

Both card versions are in the field while dCloud migrates the template: older
sessions label the SCC control "View", newer ones "Login". Neither label is
unique — "View" is also the Meraki Dashboard's, and there are three "Login"s
(Webex, Duo, SCC) — so the picker orders by SECTION and only then falls back to
label, and it must never offer a button belonging to a section we know is not
SCC.

Getting this wrong is not a visible error: clicking Meraki's "View" opens a
real, authenticated Meraki dashboard, and the failure surfaced much later as
"SCC session never settled".
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from duo_automation import _idac_scc_candidates  # noqa: E402


def _btn(i, label, section=""):
    return {"i": i, "label": label, "section": section}


# The card as it renders after the migration: Meraki owns "View", SCC owns
# "Login". This is the shape that broke the original /^view$/i lookup.
NEW_CARD = [
    _btn(0, "Go to account", "Cisco SaaS Accounts - ThousandEyes"),
    _btn(1, "Send Request", ""),
    _btn(2, "Go to Control Hub", "Webex Credentials"),
    _btn(3, "Activate Account", "Cisco Duo"),
    _btn(4, "Login", "Cisco Duo"),
    _btn(5, "View", "Meraki Dashboard"),
    _btn(6, "Login", "Cisco Security Cloud Control"),
    _btn(7, "Login", "Cisco Cloud Control"),
]

# Pre-migration: SCC's own control is labelled "View" and there is no Meraki
# section at all.
OLD_CARD = [
    _btn(0, "Go to account", "Cisco SaaS Accounts - ThousandEyes"),
    _btn(1, "Activate Account", "Cisco Duo"),
    _btn(2, "Login", "Cisco Duo"),
    _btn(3, "View", "Cisco Security Cloud Control"),
]


def test_new_card_picks_the_scc_login_first():
    first = _idac_scc_candidates(NEW_CARD)[0]
    assert first["i"] == 6
    assert first["section"] == "Cisco Security Cloud Control"


def test_old_card_picks_the_scc_view_first():
    """The label changed; the section did not. Old cards must still work."""
    first = _idac_scc_candidates(OLD_CARD)[0]
    assert first["i"] == 3
    assert first["label"] == "View"


def test_meraki_view_is_never_offered():
    """The whole bug: Meraki's View opens a real dashboard, so a wrong guess
    looks like a success and fails 90s later somewhere else."""
    assert all(c["i"] != 5 for c in _idac_scc_candidates(NEW_CARD))


def test_duo_and_webex_logins_are_never_offered():
    """Why matching 'view|login' by label is not good enough on its own."""
    offered = {c["i"] for c in _idac_scc_candidates(NEW_CARD)}
    assert 4 not in offered      # Duo's Login
    assert 2 not in offered      # Webex's Go to Control Hub


def test_scc_section_outranks_the_similarly_named_one():
    """'Cisco Cloud Control' also carries a Login; SCC's must come first."""
    order = [c["i"] for c in _idac_scc_candidates(NEW_CARD)]
    assert order.index(6) < order.index(7)


def test_unsectioned_opener_is_a_fallback_not_a_first_choice():
    """If a card renders no recognisable section we still try openers, because
    a stale section name must not leave us with nothing to click."""
    cands = _idac_scc_candidates([
        _btn(0, "View", ""),
        _btn(1, "Login", "Cisco Security Cloud Control"),
    ])
    assert cands[0]["i"] == 1
    assert 0 in {c["i"] for c in cands}


def test_only_openers_are_offered():
    """Activate Account creates a Duo admin — it must never be clicked."""
    labels = {c["label"] for c in _idac_scc_candidates(NEW_CARD)}
    assert "Activate Account" not in labels
    assert "Send Request" not in labels


def test_no_controls_yields_no_candidates():
    """An unrendered card must produce nothing, so the caller raises rather
    than clicking whatever happens to be on the page."""
    assert _idac_scc_candidates([]) == []


def test_candidates_are_unique():
    dup = NEW_CARD + [_btn(6, "Login", "Cisco Security Cloud Control")]
    idxs = [c["i"] for c in _idac_scc_candidates(dup)]
    assert len(idxs) == len(set(idxs))


def test_login_spelled_with_a_space_is_accepted():
    cands = _idac_scc_candidates([_btn(0, "Log In", "Cisco Security Cloud Control")])
    assert cands and cands[0]["i"] == 0
