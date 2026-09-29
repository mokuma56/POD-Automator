"""ISE step 3 and step 4 fixes from the 2026-09-28 multi-POD run.

Step 3 (ise_scc_deactivate_reactivate): POD-6's page showed "Activation
Unresponsive" — an Activate button on "Existing instances", no Deactivate. The
status reader recognised Inactive/Connected/Active only ("Activation" is not
\\bActive\\b), so it read None, assumed Active, and soft-failed "Deactivate
button not found" on an integration that went Active by itself.

Step 4 (host half _host_cdfmc_integrate): on POD-10 and POD-7 the SCC FMC app
page stayed on its grey skeleton for the whole 90s wait; a plain re-run then
rendered at once. It now reloads between rounds.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_ISE = (ROOT / "ise_integrations.py").read_text()
_DASH = (ROOT / "dashboard.py").read_text()


def _step3_body():
    i = _ISE.index("async def _phase_ise_scc_deactivate_reactivate_async")
    return _ISE[i:_ISE.index("\nasync def ", i + 10)]


def _status_reader(page_text):
    """Evaluate the step's own JS status patterns, in their own order.

    The JS lives in a non-raw Python string, so '\\\\b' in the file is '\\b' in
    the browser; the ASCII \\b / \\s semantics are the same in Python's re.
    """
    body = _step3_body()
    js = body[body.index("_status_text = await page.evaluate"):]
    js = js[:js.index("return null;")]
    rules = re.findall(r"if \(/(.+?)/(i?)\.test\(t\)\) return '(\w+)';", js)
    assert rules, "status patterns not found in step 3"
    for pat, flags, label in rules:
        pat = pat.replace("\\\\", "\\")
        if re.search(pat, page_text, re.I if flags else 0):
            return label
    return None


def test_activation_unresponsive_is_recognised():
    # The text of data/ise_deactivate_fail_POD-6.png's App configuration block.
    page = ("App configuration Application status Activation Unresponsive Instance "
            "Existing instances New instance Select instance ISE-POD-POD-6-124 Activate")
    assert _status_reader(page) == "Unresponsive"


def test_existing_states_still_read_the_same():
    assert _status_reader("Application status Inactive Activate") == "Inactive"
    assert _status_reader("Application status Connected Deactivate") == "Connected"
    assert _status_reader("Application status Active Deactivate") == "Active"
    # 'Activate' alone must never read as Active.
    assert _status_reader("Application status Activate") is None


def test_unresponsive_takes_the_inactive_path():
    body = _step3_body()
    assert "_already_inactive = _status_text in ('Inactive', 'Unresponsive')" in body


def test_deactivate_is_only_skipped_when_the_page_offers_activate_instead():
    """The deactivate+reactivate cycle is the SCC workaround — never skip it
    while a Deactivate control is on the page."""
    body = _step3_body()
    ctl = body[body.index("for _ctl_try in range"):body.index("if _already_inactive:\n")]
    assert ctl.index('if _ctl.get("deactivate"):') < ctl.index('if _ctl.get("activate"):')
    assert "_already_inactive = True" in ctl


def _cdfmc_wait_block():
    i = _DASH.index("# ── 3. Open authenticated cdFMC tab via Platform Settings HBR-BUTTON")
    return _DASH[i:_DASH.index("Opening cdFMC tab via Platform Settings", i)]


def test_cdfmc_wait_reloads_between_rounds():
    block = _cdfmc_wait_block()
    assert "for _round in range(3):" in block
    assert "page.goto(_fmc_url" in block, "a stuck skeleton needs a fresh navigation"


def test_cdfmc_wait_fits_inside_the_cards_budget():
    """The ISE container waits up to 10 min for the host half, and the host
    watcher is serial, so this wait must leave most of that for login, the
    rest of the step and any queue."""
    block = _cdfmc_wait_block()
    rounds = int(re.search(r"for _round in range\((\d+)\)", block).group(1))
    probes = int(re.search(r"for _probe in range\((\d+)\)", block).group(1))
    fresh_signin_s = 90          # new browser + iDAC SCC sign-in + 15s settle
    total = rounds * probes * 5 + 10 + fresh_signin_s
    assert total <= 5 * 60, f"Platform Settings wait is {total}s"
    after = _ISE[_ISE.index("cdFMC OTP written to shared volume"):]
    budget = int(re.search(r"_deadline = _t\.time\(\) \+ (\d+)", after).group(1))
    assert total < budget / 2, f"{total}s of a {budget}s card budget"


def test_cdfmc_last_round_starts_a_fresh_session():
    """POD-14, 2026-09-29: two reloads in the same session stayed on the
    skeleton; a new browser + sign-in (a re-run) rendered at once."""
    block = _cdfmc_wait_block()
    last = block[block.index("elif _round == 2:"):block.index("for _probe in range(")]
    i_close = last.index("browser.close()")
    i_launch = last.index("browser = p.chromium.launch(")
    i_signin = last.index("_host_scc_open(browser")
    i_goto = last.index("page.goto(_fmc_url")
    assert i_close < i_launch < i_signin < i_goto
    # The URL is rebuilt from the NEW session's enterprise id.
    assert last.index("_fmc_url = ") < i_goto
