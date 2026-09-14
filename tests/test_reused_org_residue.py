"""Four faults that share one cause: SCC/Duo orgs are reused between sessions.

A recycled org arrives carrying objects from whoever had it last — a cdFMC
pxGrid instance, a directory sync, TOTP tokens, an admin. Every check here
existed in some form already and asked the almost-right question:

  * "does this tenant have an active cdFMC instance" instead of "is it ours"
  * "is this step already completed" instead of "did it actually work"
  * "is duo_admin_totp_secret set" instead of "does Duo have the token"
  * "what number is in the user's email" instead of "which site AND number"

Each answered yes on a POD that was broken, and the yes was believed.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard as d  # noqa: E402
import onboard_router as o  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DASH = open(os.path.join(_ROOT, "dashboard.py")).read()
_ISE = open(os.path.join(_ROOT, "ise_integrations.py")).read()
_DUO = open(os.path.join(_ROOT, "duo_automation.py")).read()


# ── 1. the cdFMC guard must ask whether the instance is OURS ────────────────

def test_cdfmc_guard_distinguishes_our_instance_from_a_leftover():
    """POD-2 skipped onto 'ISE-FMC-POD-POD-18-0741' and POD-6 onto
    'PsuedoCo-520-FMC-20260728', a July artifact. Both reported success and
    both left ISE pending with no SGTs."""
    assert "_ours = f\"{OURS_PREFIX}{pod_id}-\"" in _DASH
    assert "_existing.startswith(_ours)" in _DASH


def test_a_foreign_active_instance_is_flagged_not_silently_passed():
    """It cannot be deleted — cdFMC is shared — but it must not read as green."""
    assert "WARN: cdFMC pxGrid instance" in _DASH
    # the WARN prefix is what makes api_pods count it as degraded
    assert d._result_contradicts_success(
        "WARN: cdFMC pxGrid instance 'X' is active for PseudoCo-520 but was "
        "not created by this POD")


def test_ours_prefix_is_defined_before_it_is_used():
    """It used to be defined further down, so the guard referencing it would
    have raised NameError on the first POD that hit this path."""
    assert _DASH.index('OURS_PREFIX = "ISE-FMC-POD-"') < _DASH.index('_ours = f"{OURS_PREFIX}')


# ── 2. a green step with a bad result must be re-runnable ───────────────────

def test_a_completed_step_reporting_a_bad_outcome_is_retried():
    """After the operator deleted the stale cdFMC instances, POD-2's re-run
    logged 'already completed, skipping' for steps 4 and 5, so the fix went
    untested. POD-6 and POD-8 needed their rows deleted by hand."""
    assert "_green_but_wrong" in _ISE
    assert "and not _green_but_wrong" in _ISE


def test_the_two_marker_lists_stay_in_step():
    """ise_run_card decides what to retry; api_pods decides what shows
    degraded. If they drift, a step goes amber but can never be re-run."""
    m = re.search(r"_CONTRADICTS = \((.*?)\)", _ISE, re.S)
    assert m, "ise_integrations._CONTRADICTS not found"
    ise = {x.strip().strip('"') for x in m.group(1).split(",") if x.strip()}
    assert ise == set(d._GREEN_BUT_WRONG)


def test_an_idempotent_skip_is_still_skipped():
    """'already integrated' and 'already registered' are steps finding nothing
    to do. Retrying those on every run would be wasteful and, for step 3,
    actively disruptive."""
    assert not d._result_contradicts_success(
        "pxGrid Cloud already registered and connected")
    assert not d._result_contradicts_success(
        "cdFMC pxGrid already integrated: instance 'X' active")


# ── 3. Duo verify must ask Duo, and must not overclaim ──────────────────────

def test_verify_checks_duo_for_the_token_not_only_our_column():
    """POD-7 had duo_admin_totp_secret populated from an earlier session, so
    bootstrap skipped provisioning and verify passed, while the admin had
    phones=0 tokens=0 and only a virtual passkey. Nobody could log in."""
    assert "/admin/v1/tokens" in _DUO
    assert "the stored secret is stale" in _DUO


def test_verify_does_not_claim_the_token_is_attached():
    """Duo's Admin API exposes no admin-to-token binding, so 'TOTP token
    present' was a claim the check could not support."""
    # Match the assignment, not the phrase: the old wording is quoted in the
    # comment that explains why it went, and a substring test on the prose
    # fails on its own explanation.
    assert 'msg += "; TOTP token + jump host login page present"' not in _DUO
    assert "cannot confirm the token is attached" in _DUO


def test_verify_reads_duo_credentials_from_the_db():
    """step_bootstrap rebinds duo_ikey/duo_skey LOCALLY when it re-creates the
    Admin API application, so the closure can hold the pre-rotation pair."""
    assert "SELECT duo_admin_totp_secret, duo_ikey, " in _DUO


# ── 4. pod_number is not unique ─────────────────────────────────────────────

def test_the_site_prefix_is_captured_not_discarded():
    """POD-1 from kit@rtp13... and POD-8 from kit@sjc13... both became '13'."""
    pat = re.compile(r"@([a-z]+)(\d+)\.corp\.pseudoco\.com", re.I)
    a = pat.search("kit@rtp13.corp.pseudoco.com")
    b = pat.search("kit@sjc13.corp.pseudoco.com")
    assert a and b
    assert a.group(2) == b.group(2) == "13"        # the number really does collide
    assert a.group(1) != b.group(1)                # the site is what separates them
    assert "@([a-z]+)(\\d+)\\.corp\\.pseudoco\\.com" in open(
        os.path.join(_ROOT, "onboard_router.py")).read()


def test_persist_accepts_and_stores_the_site():
    src = open(os.path.join(_ROOT, "onboard_router.py")).read()
    assert "def _persist(pod_number, source, site=\"\")" in src
    assert "pod_site=?" in src


def test_a_db_without_pod_site_still_records_the_number():
    """The column is a migration; an older DB must not lose the POD number
    over a failed UPDATE."""
    src = open(os.path.join(_ROOT, "onboard_router.py")).read()
    i = src.index("def _persist(pod_number, source")
    body = src[i:i + 1600]
    assert "except sqlite3.OperationalError:" in body
    assert body.count("UPDATE pods SET pod_number=?") >= 1
