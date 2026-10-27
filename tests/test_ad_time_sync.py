"""AD1 clock: pointed at the dCloud NTP gateway and verified, as a pipeline step.

POD-5 (2026-10-22) and POD-9 (2026-10-23): AD1 had no NTP source and ran 331s
and 343s fast. Kerberos allows 300s, so ISE's AD join failed and 802.1X/TEAP
was rejected with 24708. Fixed by hand over WinRM both times; the step makes it
automatic. The resync steps the clock by minutes, which drops the WinRM session
mid-command, and on POD-9 the source did not persist until a second pass.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import re
import struct
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import onboard_router as orr  # noqa: E402

PEER = orr.AD_NTP_PEER


# ── pure helpers ──────────────────────────────────────────────────────────────

def _ntp_packet(epoch: float) -> bytes:
    secs = int(epoch) + orr._NTP_EPOCH
    frac = int((epoch - int(epoch)) * 2**32)
    return b"\x1c" + 39 * b"\0" + struct.pack("!II", secs, frac)


def test_ntp_transmit_time_round_trips():
    # Plain arithmetic, not pytest.approx: approx imports numpy, and another
    # test can leave numpy half-imported, failing this one depending on order.
    assert abs(orr._ntp_transmit_time(_ntp_packet(1793037600.25)) - 1793037600.25) < 1e-6


def test_ntp_reply_without_a_timestamp_is_rejected():
    with pytest.raises(ValueError):
        orr._ntp_transmit_time(b"\x1c" + 47 * b"\0")
    with pytest.raises(ValueError):
        orr._ntp_transmit_time(b"short")


@pytest.mark.parametrize("source,expected", [
    (f"{PEER},0x8", True),
    (f"{PEER}\r\n", True),
    ("Local CMOS Clock", False),
    ("Free-running System Clock", False),
    ("198.18.128.10,0x8", False),
    ("", False),
])
def test_w32tm_source_match(source, expected):
    assert orr._w32tm_source_is(source, PEER) is expected


def test_verdict_needs_both_the_peer_and_a_good_clock():
    assert orr._ad_time_verdict(f"{PEER},0x8", 2)[0]
    # The POD-5/POD-9 state: no source AND five-plus minutes fast.
    ok, why = orr._ad_time_verdict("Local CMOS Clock", 331)
    assert not ok and "Local CMOS Clock" in why and "+331s" in why
    # A right clock that will drift back is still not done...
    assert not orr._ad_time_verdict("Free-running System Clock", 0)[0]
    # ...nor the right source on a clock that has not converged yet.
    assert not orr._ad_time_verdict(f"{PEER},0x8", -45)[0]


# ── the phase, against a fake AD1 ─────────────────────────────────────────────

class FakeAD1:
    """AD1's w32time as WinRM sees it. `persist_on` = which apply pass makes the
    source stick (POD-9: 2). The apply that steps the clock drops the session."""

    def __init__(self, skew, source="Local CMOS Clock", persist_on=1,
                 drop_on_step=True, peer_works=True):
        self.skew, self.source = skew, source
        self.persist_on, self.drop_on_step = persist_on, drop_on_step
        self.peer_works, self.applies, self.set_dates = peer_works, 0, 0

    def run_ps(self, ps):
        import datetime as dt
        import time as t
        if ps.startswith("w32tm /query /source"):
            now = dt.datetime.fromtimestamp(t.time() + self.skew, dt.timezone.utc)
            out = f"{self.source}\r\n{now.isoformat()}\r\n"
            return types.SimpleNamespace(std_out=out.encode(), std_err=b"", status_code=0)
        if ps.startswith("w32tm /config"):
            self.applies += 1
            stepped = self.peer_works and abs(self.skew) > 1
            if self.peer_works:
                self.skew = 0.4
                if self.applies >= self.persist_on:
                    self.source = f"{PEER},0x8"
            if stepped and self.drop_on_step:
                raise ConnectionError("400 Bad Request — clock stepped mid-command")
            return types.SimpleNamespace(std_out=b"The command completed successfully.",
                                         std_err=b"", status_code=0)
        if "Set-Date" in ps:
            self.set_dates += 1
            self.skew = 0.2
            raise ConnectionError("400 Bad Request — clock stepped mid-command")
        raise AssertionError(f"unexpected PowerShell: {ps[:80]}")


@pytest.fixture
def ad1(monkeypatch):
    holder = {}
    fake_winrm = types.SimpleNamespace(Session=lambda *a, **k: holder["ad"])
    monkeypatch.setitem(sys.modules, "winrm", fake_winrm)
    monkeypatch.setattr(orr.time, "sleep", lambda s: None)
    monkeypatch.setattr(orr, "_ntp_offset", lambda host, timeout=3.0: 0.0)

    def make(**kw):
        holder["ad"] = FakeAD1(**kw)
        return holder["ad"]
    return make


def test_healthy_ad1_is_left_alone(ad1):
    ad = ad1(skew=1, source=f"{PEER},0x8")
    ok, msg = orr.phase_ad_time_sync()
    assert ok and msg.startswith("already in sync")
    assert ad.applies == 0


def test_pod5_shape_fixed_despite_the_dropped_session(ad1):
    ad = ad1(skew=331)
    ok, msg = orr.phase_ad_time_sync()
    assert ok, msg
    assert "was +331s" in msg and f"source {PEER}" in msg
    assert ad.applies == 1


def test_pod9_shape_needs_the_second_pass(ad1):
    """Clock fixed on pass 1 but the source did not persist until pass 2."""
    ad = ad1(skew=343, persist_on=2)
    ok, msg = orr.phase_ad_time_sync()
    assert ok, msg
    assert ad.applies == 2


def test_no_reachable_peer_sets_the_clock_but_still_fails(ad1):
    """Kerberos works this session, but with no NTP source it will drift."""
    ad = ad1(skew=331, peer_works=False)
    ok, msg = orr.phase_ad_time_sync()
    assert not ok
    assert ad.set_dates == 1
    assert "was +331s" in msg and "will drift" in msg


def test_unreachable_ad1_fails_with_the_reason(monkeypatch):
    def _boom(*a, **k):
        raise ConnectionError("WinRM 5985 refused")
    monkeypatch.setitem(sys.modules, "winrm", types.SimpleNamespace(Session=_boom))
    monkeypatch.setattr(orr, "_ntp_offset", lambda host, timeout=3.0: 0.0)
    ok, msg = orr.phase_ad_time_sync()
    assert not ok and "could not read AD1's clock" in msg


# ── the step list is mirrored in five places; keep them in step ──────────────

def _names(text: str) -> list:
    return re.findall(r"""["']([a-z_0-9]+)["']""", text)


def _block(src: str, start: str, end: str) -> str:
    i = src.index(start)
    return src[i:src.index(end, i)]


def test_pipeline_step_lists_agree():
    onboard = (ROOT / "onboard.py").read_text()
    dash = (ROOT / "dashboard.py").read_text()
    order = [n for n in re.findall(r'^\s*\("([a-z_0-9]+)",', _block(onboard, "\nsteps = [", "\n]\n"),
                                   re.M)]
    assert "ad_time_sync" in order
    assert order.index("ad_time_sync") == order.index("ad_verify") - 1
    assert _names(_block(dash, "PIPELINE_STEP_NAMES = [", "]")) == order
    assert _names(_block(dash, "const PIPELINE_ORDER = [", "];")) == order

    soft = set(_names(_block(onboard, "SOFT_FAIL_STEPS = {", "}")))
    assert "ad_time_sync" in soft
    assert set(_names(_block(dash, "PIPELINE_SOFT_FAIL = {", "}"))) == soft
    assert set(_names(_block(dash, "const SOFT_FAIL_STEPS = new Set([", "]);"))) == soft
