"""Host-browser admission: Duo slots, SCC-reset slots, and the memory gate.

2026-09-28 re-measure: a Duo card peaks at ~1 GB of host Chromium (five at
once: 4.5-5.1 GB), an SCC browser reset holds a host browser ~3.5-4 min, and
this Mac leaves ~8 GB for host Chromium. Two gaps were found:
  * /api/duo/run — the Duo card's own Run button — never took a Duo slot, so
    DUO_MAX_CONCURRENT only bounded runs started from run-pod-full;
  * SCC browser resets were uncapped (seven pipelines finishing together
    opened seven at once).

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import os
import re
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard as d  # noqa: E402

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DASH = open(os.path.join(_ROOT, "dashboard.py")).read()
_OR = open(os.path.join(_ROOT, "onboard_router.py")).read()


# ── memory gate ───────────────────────────────────────────────────────────────

def test_memory_gate_passes_straight_through_when_there_is_room():
    logs = []
    assert d._wait_for_host_memory(logs.append, "x", _read=lambda: 51,
                                   _sleep=lambda s: None) == 0
    assert logs == []


def test_memory_gate_waits_while_the_host_is_short_then_starts():
    readings = iter([12, 15, 18, 35])
    logs, slept = [], []
    waited = d._wait_for_host_memory(logs.append, "the Duo card",
                                     _read=lambda: next(readings),
                                     _sleep=slept.append, poll_s=15)
    assert waited == 45 and slept == [15, 15, 15]
    assert "waiting for host memory" in logs[0] and "12% free" in logs[0]
    assert "back to 35% free" in logs[-1]


def test_unreadable_memory_never_blocks():
    """A check that cannot run is not a failed check (same rule as preflight)."""
    assert d._wait_for_host_memory(lambda m: None, "x", _read=lambda: None,
                                   _sleep=lambda s: pytest.fail("slept")) == 0


def test_the_real_reading_is_a_percentage():
    pct = d._host_mem_free_pct()
    assert pct is None or 0 <= pct <= 100


# ── Duo slots ─────────────────────────────────────────────────────────────────

@pytest.fixture
def one_slot(monkeypatch):
    monkeypatch.setattr(d, "_duo_slots", threading.Semaphore(1))
    monkeypatch.setattr(d, "_duo_slots_held", 0)
    monkeypatch.setattr(d, "_wait_for_host_memory", lambda *a, **k: 0)


def test_duo_slot_counts_and_releases(one_slot):
    with d._duo_slot(lambda m: None):
        assert d._duo_slots_held == 1
        assert not d._duo_slots.acquire(blocking=False), "slot should be taken"
    assert d._duo_slots_held == 0
    assert d._duo_slots.acquire(blocking=False)


def test_duo_slot_is_released_when_the_card_raises(one_slot):
    with pytest.raises(RuntimeError):
        with d._duo_slot(lambda m: None):
            raise RuntimeError("card blew up")
    assert d._duo_slots_held == 0 and d._duo_slots.acquire(blocking=False)


def test_a_second_card_queues_and_says_so(one_slot):
    logs, entered = [], threading.Event()
    with d._duo_slot(lambda m: None):
        t = threading.Thread(target=lambda: d._duo_slot(logs.append).__enter__()
                             or entered.set(), daemon=True)
        t.start()
        t.join(0.3)
        assert not entered.is_set(), "second card must wait for the slot"
        assert any("queued for a Duo slot" in m for m in logs)
    t.join(2)
    assert entered.is_set()


def test_every_duo_start_takes_a_slot():
    """The card's own Run button was the path that bypassed the cap."""
    run = _DASH[_DASH.index("def api_duo_run("):]
    run = run[:run.index("\n@app.route", 1)]
    assert "with _duo_slot(" in run
    full = _DASH[_DASH.index("def _run_full_automation("):]
    full = full[:full.index("\ndef ", 1)]
    assert "with _duo_slot(" in full
    helper = _DASH[_DASH.index("def _duo_slot("):]
    helper = helper[:helper.index("\n_duo_slots_held = 0")]
    outside = _DASH.replace(helper, "")
    assert not re.search(r"_duo_slots\.(acquire|release)\(", outside), (
        "take Duo slots only through _duo_slot()")


# ── SCC browser resets ────────────────────────────────────────────────────────

def test_scc_browser_reset_is_capped():
    body = _DASH[_DASH.index("def api_scc_run_check_sync("):]
    body = body[:body.index("\n@app.route", 1)]
    i_acq = body.index("_scc_reset_slots.acquire(")
    i_run = body.index("_scc_auto_reset_manual(pod_id")
    i_rel = body.index("_scc_reset_slots.release()")
    assert i_acq < i_run < i_rel


def test_pipeline_waits_long_enough_for_the_scc_queue():
    """Container budget must cover a full queue ahead of it plus its own run."""
    m = re.search(r"run-check-sync.*?urlopen\(req, timeout=(\d+)\)", _OR, re.S)
    budget = int(m.group(1))
    per_reset_s = 4 * 60 + 60              # measured ~3.5-4 min, plus slack
    rounds_ahead = 2                       # e.g. 7 PODs finishing together, 3 at a time
    assert budget >= (rounds_ahead + 1) * per_reset_s, budget
    assert d.SCC_RESET_MAX_CONCURRENT >= 2


# ── ISE host-half watchers: parallel workers (A, B, C) ────────────────────────
import time as _time  # noqa: E402


@pytest.fixture
def quiet_log(monkeypatch):
    logs = []
    monkeypatch.setattr(d, "log", lambda pod, m: logs.append((pod, m)))
    return logs


def _dispatch(slots, pod, job, queued, inflight):
    return d._dispatch_host_job(slots, pod, "t", job, queued, "[t]", "test", inflight)


def test_workers_run_pods_in_parallel_up_to_the_cap(quiet_log):
    slots, queued, inflight = threading.Semaphore(2), set(), set()
    gate, started = threading.Event(), []
    job = lambda p: (lambda: (started.append(p), gate.wait(5)))
    assert _dispatch(slots, "POD-1", job("POD-1"), queued, inflight)
    assert _dispatch(slots, "POD-2", job("POD-2"), queued, inflight)
    assert not _dispatch(slots, "POD-3", job("POD-3"), queued, inflight), "cap is 2"
    assert ("POD-3", "[t] queued — all test workers busy") in quiet_log
    _time.sleep(0.2)
    assert sorted(started) == ["POD-1", "POD-2"]
    gate.set()
    for _ in range(50):
        if not inflight:
            break
        _time.sleep(0.05)
    assert _dispatch(slots, "POD-3", lambda: None, queued, inflight), "slot freed"


def test_one_job_per_pod_so_a_rerun_cannot_race_itself(quiet_log):
    slots, queued, inflight = threading.Semaphore(4), set(), set()
    gate = threading.Event()
    assert _dispatch(slots, "POD-5", lambda: gate.wait(5), queued, inflight)
    assert not _dispatch(slots, "POD-5", lambda: None, queued, inflight)
    gate.set()


def test_a_failing_job_frees_its_slot(quiet_log):
    slots, queued, inflight = threading.Semaphore(1), set(), set()

    def boom():
        raise RuntimeError("browser died")

    assert _dispatch(slots, "POD-7", boom, queued, inflight)
    for _ in range(50):
        if not inflight:
            break
        _time.sleep(0.05)
    assert not inflight and slots.acquire(blocking=False)
    assert any("worker error: browser died" in m for _, m in quiet_log)


def _card_wait(marker):
    """The ISE card's own deadline (seconds) right after the log line `marker`."""
    src = open(os.path.join(_ROOT, "ise_integrations.py")).read()
    after = src[src.index(marker):]
    return int(re.search(r"_deadline = _t\.time\(\) \+ (\d+)", after).group(1))


def test_step2_queue_limit_fits_inside_the_cards_wait():
    """It used to drop at 300s while the card waited 600s."""
    card = _card_wait("ise_scc_result_")
    assert 300 < d.SCC_OTP_MAX_AGE_S < card
    assert d.SCC_NAV_WORKERS >= 2


def test_step4_queue_limit_and_workers():
    assert d.CDFMC_OTP_MAX_AGE_S <= _card_wait("cdFMC OTP written to shared volume")
    assert d.CDFMC_NAV_WORKERS >= 2


def test_step5_runs_in_parallel_and_holds_no_browser_between_checks():
    assert d.SGT_VERIFY_WORKERS >= 4
    assert d.SGT_TRIGGER_MAX_AGE_S < _card_wait("ise_sgt_trigger_")
    body = _DASH[_DASH.index("def _host_sgt_verify("):_DASH.index("def _sgt_verify_job(")]
    # The browser is launched inside the per-check helper, not around the wait.
    check = body[body.index("def _check_once("):body.index("_no_session =")]
    assert "chromium.launch(" in check
    assert body.count("chromium.launch(") == 1
    assert "_t.sleep(2)" not in check


def test_watchers_hand_work_to_workers():
    for w in ("_scc_otp_watcher", "_cdfmc_otp_watcher", "_sgt_verify_watcher"):
        body = _DASH[_DASH.index(f"def {w}("):]
        body = body[:body.index("\nthreading.Thread(", 1)]
        assert "_dispatch_host_job(" in body, w
        assert "_host_scc_integrate(" not in body and "_host_sgt_verify(" not in body \
            and "_host_cdfmc_integrate(" not in body, f"{w} must not run the job inline"
