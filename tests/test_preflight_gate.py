"""The pre-run reachability gate.

A VPN tunnel being up says nothing about the lab behind it. On 2026-09-10 the
tunnel was healthy for 43 minutes while the whole 198.18.5.0/24 segment — AD1,
ISE and Catalyst Center — answered "No route to host". The run reached 19/21 on
the pipeline and then lost nine Duo steps and every ISE step to a condition a
20-second check would have caught before it started.

Two properties matter most and are easy to get backwards:

  * the gate is scoped BY PHASE, so a pipeline-only run is not blocked because
    AD1 is down, and a Duo run is not blocked because a switch is down;
  * a probe that could not RUN does not block. "I could not check" is not "the
    check failed" — conflating those two is the single most expensive mistake
    in this project's history, so it is pinned here.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard as d  # noqa: E402


def _targets_for(phases, kinds=("required", "advisory")):
    wanted = [ph for ph in ("pipeline", "duo", "ise") if ph in phases]
    out, seen = [], set()
    for ph in wanted:
        spec = d.PREFLIGHT_TARGETS.get(ph) or {}
        for kind in kinds:
            for t in spec.get(kind, []):
                if t[0] not in seen:
                    seen.add(t[0])
                    out.append(t[0])
    return out


def _required_for(phases):
    return _targets_for(phases, kinds=("required",))


def _gate(monkeypatch, phases, results, probe_error=""):
    monkeypatch.setattr(d, "_preflight_probe",
                        lambda pod, targets: (results, probe_error))
    return d._preflight_gate("POD-TEST", phases, log_fn=lambda m: None)


# ── phase scoping ─────────────────────────────────────────────────────────────

def test_pipeline_only_does_not_require_ad1_or_ise():
    t = _targets_for(["pipeline"])
    assert "AD1 WinRM" not in t and "ISE" not in t
    assert "vManage" in t and "border spine" in t


def test_the_router_is_required_for_the_pipeline():
    """onboard_router has its own hard preflight and aborts with "Could not
    reach router ... Pipeline cannot start", so the router is the one host the
    pipeline truly cannot begin without. The first version of this gate did not
    check it at all."""
    assert "router" in _required_for(["pipeline"])


def test_the_switches_are_advisory_not_required():
    """All three switch verifies are in onboard.SOFT_FAIL_STEPS: an unreachable
    switch degrades a run, it does not stop one. Blocking on them stopped a
    pipeline that would have completed."""
    req = _required_for(["pipeline"])
    for sw in ("border spine", "leaf1", "leaf2"):
        assert sw not in req, sw
        assert sw in _targets_for(["pipeline"]), sw   # still probed and reported


def test_duo_requires_ad1_but_not_the_switches():
    t = _targets_for(["duo"])
    assert "AD1 WinRM" in _required_for(["duo"])
    assert "border spine" not in t and "vManage" not in t


def test_ise_requires_ise():
    assert _required_for(["ise"]) == ["ISE"]


def test_a_full_run_covers_every_phase_without_duplicates():
    t = _targets_for(["pipeline", "duo", "ise"])
    assert "vManage" in t and "AD1 WinRM" in t and "ISE" in t and "router" in t
    assert len(t) == len(set(t))          # jump host appears in two phases


def test_unknown_phases_are_ignored_rather_than_trusted():
    assert _targets_for(["nonsense"]) == []


# ── blocking ──────────────────────────────────────────────────────────────────

def test_all_reachable_passes(monkeypatch):
    ok, _ = _gate(monkeypatch, ["ise"], {"ISE": ""})
    assert ok is True


def test_an_unreachable_required_host_blocks(monkeypatch):
    ok, msg = _gate(monkeypatch, ["ise"], {"ISE": "OSError: No route to host"})
    assert ok is False
    assert "ISE" in msg


def test_the_message_names_only_what_failed(monkeypatch):
    ok, msg = _gate(monkeypatch, ["duo"],
                    {"AD1 WinRM": "TimeoutError: timed out",
                     "AD1 LDAP": "",
                     "jump host": ""})
    assert ok is False
    assert "AD1 WinRM" in msg
    # the two healthy hosts must not be listed as problems
    assert "jump host" not in msg


def test_the_message_tells_the_operator_what_to_do(monkeypatch):
    """A blocked run must not read as an automation bug — the lab is booting."""
    _, msg = _gate(monkeypatch, ["ise"], {"ISE": "OSError: No route to host"})
    assert "VPN tunnel is up" in msg
    assert "booting" in msg


# ── the distinction that matters most ────────────────────────────────────────

def test_a_probe_that_could_not_run_does_NOT_block(monkeypatch):
    """"I could not check" is not "the check failed"."""
    ok, msg = _gate(monkeypatch, ["ise"], {}, probe_error="No such container")
    assert ok is True
    assert "skipped" in msg


def test_probe_failure_wins_over_empty_results(monkeypatch):
    """An empty result set with an error must never read as 'nothing is down'."""
    ok, _ = _gate(monkeypatch, ["pipeline", "duo", "ise"], {},
                  probe_error="docker daemon unreachable")
    assert ok is True


def test_no_targets_is_not_a_failure(monkeypatch):
    ok, _ = _gate(monkeypatch, [], {})
    assert ok is True


# ── required vs advisory, and the override ───────────────────────────────────

def test_an_advisory_host_being_down_does_NOT_block(monkeypatch):
    """The whole point of the split: unreachable switches must not stop a
    pipeline whose switch checks soft-fail anyway."""
    ok, msg = _gate(monkeypatch, ["pipeline"],
                    {"router": "", "vManage": "", "jump host": "",
                     "border spine": "TimeoutError: timed out",
                     "leaf1": "ConnectionRefusedError: refused",
                     "leaf2": "ConnectionRefusedError: refused"})
    assert ok is True
    assert "not blocking" in msg
    assert "border spine" in msg          # still reported, just not fatal


def test_a_required_host_being_down_does_block(monkeypatch):
    ok, msg = _gate(monkeypatch, ["pipeline"],
                    {"router": "TimeoutError: timed out", "vManage": "",
                     "jump host": "", "border spine": "", "leaf1": "", "leaf2": ""})
    assert ok is False
    assert "router" in msg


def test_a_block_message_mentions_advisory_failures_too(monkeypatch):
    """So the operator sees the whole picture, not just the blocking host."""
    ok, msg = _gate(monkeypatch, ["pipeline"],
                    {"router": "TimeoutError: timed out", "vManage": "",
                     "jump host": "", "border spine": "TimeoutError: timed out",
                     "leaf1": "", "leaf2": ""})
    assert ok is False
    assert "router" in msg and "border spine" in msg
    assert "not blocking" in msg


def test_override_lets_a_blocked_run_proceed(monkeypatch):
    """The reported case: the operator knows a host is down and wants
    the run to proceed regardless."""
    monkeypatch.setattr(d, "_preflight_probe",
                        lambda pod, targets: ({"router": "TimeoutError: x",
                                               "vManage": "", "jump host": "",
                                               "border spine": "", "leaf1": "",
                                               "leaf2": ""}, ""))
    ok, msg = d._preflight_gate("POD-TEST", ["pipeline"], log_fn=lambda m: None,
                                allow_override=True)
    assert ok is True
    assert "overridden" in msg.lower()
    assert "router" in msg              # says what was ignored


def test_override_does_not_invent_a_pass(monkeypatch):
    """An overridden run must not read as a clean pre-check afterwards."""
    monkeypatch.setattr(d, "_preflight_probe",
                        lambda pod, targets: ({"router": "TimeoutError: x",
                                               "vManage": "", "jump host": "",
                                               "border spine": "", "leaf1": "",
                                               "leaf2": ""}, ""))
    _, msg = d._preflight_gate("POD-TEST", ["pipeline"], log_fn=lambda m: None,
                               allow_override=True)
    assert "reachable" not in msg.split("unreachable")[0]
