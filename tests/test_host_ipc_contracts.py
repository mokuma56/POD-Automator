"""The container/host contracts that broke the 2026-09-14 eight-POD run.

Two of them, and both are the same shape: one side's assumption about the
other drifted, silently, and only showed up as a "failure" on a POD where
nothing was actually wrong.

  * a container waits N seconds for work the host performs. The host watchers
    are single-threaded per step type, so N must cover the QUEUE as well as
    the work. 180s covered neither once a second POD arrived.

  * a step reports status 'completed' while its own result text says the thing
    did not happen. That is worse than a failure, because nothing looks wrong.

These are pinned as tests because a comment did not hold: the SGT client
carried "15 min initial + 10 min retry + 5 min buffer = 30 min" long after the
host had moved to four checks over 20 minutes.
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard as d  # noqa: E402

_ISE_SRC = open(os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "ise_integrations.py")).read()
_DASH_SRC = open(os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "dashboard.py")).read()


def _deadlines():
    """Every '_deadline = _t.time() + N' in the container-side IPC helpers."""
    return [int(n) for n in
            re.findall(r"_deadline = _t\.time\(\) \+ (\d+)", _ISE_SRC)]


# ── the client budgets must outlast the host's own schedule ──────────────────

def test_every_ipc_deadline_allows_real_queue_time():
    """The work itself measured 84-130s; 180s left only ~50s for queueing,
    which is why the 6th and 8th PODs to arrive timed out."""
    for secs in _deadlines():
        assert secs >= 600, f"{secs}s is too short to absorb a queue wait"


def test_sgt_client_outlasts_the_host_check_schedule():
    """The host checks at 5/10/15/20 min (MAX_WAIT = 20 * 60) and only starts
    once the single sgt-verify watcher reaches this POD. A client budget that
    merely equals the host's own schedule leaves nothing for that wait — POD-1
    gave the host 4 of its 20 minutes and then declared it unresponsive."""
    m = re.search(r"MAX_WAIT\s*=\s*(\d+)\s*\*\s*60", _DASH_SRC)
    assert m, "could not find the host-side MAX_WAIT"
    host_budget = int(m.group(1)) * 60
    sgt_deadline = max(_deadlines())
    assert sgt_deadline > host_budget, (
        f"client {sgt_deadline}s does not even cover the host's own "
        f"{host_budget}s of checking")
    assert sgt_deadline - host_budget >= 20 * 60, (
        "less than 20 min of queue tolerance over the host schedule")


def test_the_timeout_messages_do_not_assert_an_untested_cause():
    """The old text asked 'is dashboard running?' — a cause it never checked,
    and which was false every time: the dashboard was busy doing this very
    job for another POD, and finished it seconds later."""
    assert "is dashboard running?" not in _ISE_SRC
    assert "scc-nav" in _ISE_SRC          # points at the evidence instead


# ── a green status must not contradict its own message ──────────────────────

def test_warn_and_pending_results_are_not_counted_as_done():
    """POD-6 read 4/5 with a green ISE dot while saying 'ISE instance pending'
    and 'WARN: No SGTs in Secure Access after 20 min'."""
    assert d._result_contradicts_success(
        "WARN: No SGTs in Secure Access after 20 min")
    assert d._result_contradicts_success(
        "ISE -> SCC Deactivate+Reactivate completed — ISE instance pending")


def test_an_unverified_pass_is_flagged():
    """verify() now passes when it could not perform a check, but says so."""
    assert d._result_contradicts_success(
        "Auth Proxy healthy; NOT VERIFIED: could not check the jump host")


def test_clean_results_are_not_flagged():
    for ok in ("SGT verify passed: 24 Security Group Tags found after 5m01s",
               "ISE -> SCC Deactivate+Reactivate completed — ISE instance Active",
               "pxGrid Cloud registered and connected",
               ""):
        assert not d._result_contradicts_success(ok), ok


def test_an_idempotent_rerun_is_deliberately_not_flagged():
    """'already integrated' is the normal output of re-running a step that has
    nothing to do. Flagging it would fire on every healthy repeat run, and a
    warning that fires constantly is one nobody reads."""
    assert not d._result_contradicts_success(
        "cdFMC pxGrid already integrated: instance 'X' active for PseudoCo-520")


# ── the Duo cap is not a host-browser cap ───────────────────────────────────

def test_duo_slots_are_reported_separately_from_host_browsers():
    """The gauge divided all host Playwright browsers by DUO_MAX_CONCURRENT
    and read 5/5 while two Duo slots were free — 3 Duo cards plus 2
    scc_reset_check browsers. They are different populations."""
    assert hasattr(d, "_duo_slots_held")
    assert "duo_slots_held" in _DASH_SRC and "duo_slots_max" in _DASH_SRC


def test_the_cap_is_what_we_think_it_is():
    assert d.DUO_MAX_CONCURRENT == 5
