"""Tests for the ISE card's outcome reporting.

Regression cover for the bug that made this card useless as a signal: it ended
with `return True, "All ISE integration steps completed"` regardless of what
happened, so a run in which one step failed and three were stepped over still
reported success and rendered green.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ise_integrations import ISE_STEPS, SOFT_FAIL_STEPS, _summarise_outcomes  # noqa: E402


def test_all_completed_is_success():
    ok, msg = _summarise_outcomes([(s, "completed", "done") for s in ISE_STEPS])
    assert ok is True
    assert msg == "5/5 completed"


def test_deliberate_self_skip_is_success():
    """A step returning "SKIP: ..." decided it had nothing to do."""
    outcomes = [(s, "completed", "done") for s in ISE_STEPS[:-1]]
    outcomes.append((ISE_STEPS[-1], "skipped", "SKIP: nothing to do"))
    ok, msg = _summarise_outcomes(outcomes)
    assert ok is True
    assert "1 skipped (nothing to do)" in msg


def test_degraded_step_is_not_success():
    """The core regression: a stepped-over failure must not report success."""
    outcomes = [(s, "completed", "done") for s in ISE_STEPS[:-1]]
    outcomes.append((ISE_STEPS[-1], "degraded", "no SCC session"))
    ok, msg = _summarise_outcomes(outcomes)
    assert ok is False
    assert "DEGRADED" in msg


def test_reproduced_failure_reports_honestly():
    """The exact shape of the run recorded on POD-17.

    Previously reported "OK: All ISE integration steps completed" over a POD on
    which no ISE integration had happened at all.
    """
    ok, msg = _summarise_outcomes([
        ("ise_scc_integrate", "failed", "container exited unexpectedly"),
        ("ise_scc_deactivate_reactivate", "degraded", "no Cisco Security Cloud link"),
        ("ise_cdfmc_integrate", "degraded", "FMC not found in catalog"),
        ("ise_sgt_verify", "degraded", "No SCC session file"),
    ])
    assert ok is False
    assert msg.startswith("0/4 completed")
    assert "3 DEGRADED" in msg
    assert "FAILED" in msg


def test_failure_names_the_step_and_reason():
    ok, msg = _summarise_outcomes([
        ("ise_pxgrid_register", "failed", "credentials not set"),
    ])
    assert ok is False
    assert "pxGrid Cloud Register" in msg
    assert "credentials not set" in msg


def test_empty_run_is_not_reported_as_success():
    """No steps ran (everything below from_step) — nothing was verified."""
    ok, msg = _summarise_outcomes([])
    assert ok is True, "an empty run has no failures to report"
    assert msg == "0/0 completed"


def test_soft_fail_steps_are_the_internet_dependent_ones():
    """Guard the constant against accidental widening.

    Adding a step here silently converts its failures into non-blocking ones,
    which is how a broken step stays invisible.
    """
    assert set(SOFT_FAIL_STEPS) == {
        "ise_cdfmc_integrate",
        "ise_scc_deactivate_reactivate",
        "ise_sgt_verify",
    }
    assert all(s in ISE_STEPS for s in SOFT_FAIL_STEPS)
