"""Wait for a vendor UI control to really exist, then say what was there.

Why this module exists
----------------------
This project drives three vendor SPAs it does not control — ISE's Dijit admin
UI, Security Cloud Control's React UI, and Duo's admin UI — through roughly 140
DOM interaction sites and 44 text selectors. Across those modules there are
~560 fixed waits against ~40 polling loops, so most waiting is a bet that a
page renders within N seconds.

Those bets started losing when SCC and ISE got slower, and the losses did not
look like timing problems. A fixed wait followed by a lookup produces a
failure that names the LOOKUP:

    "SCC session never settled"          -> had clicked Meraki's button
    "Could not click ise node link"      -> the session had been logged out
    "Platform Management not found"      -> page was still grey skeletons
    "iDAC login unavailable"             -> login succeeded, page was navigating
    "no SSO configuration listed"        -> the row had not rendered yet

Every one of those cost an hour to diagnose, because the message described the
last thing attempted rather than what was wrong. The page had the answer the
whole time — the URL, whether it was a login page, whether anything had
painted, which controls did exist — and none of it was captured.

So: poll for the thing, treat an unreadable page as "not yet" rather than
"absent", and when giving up, report the page's actual state.

Usage
-----
    from ui_wait import wait_for, absent_message

    hit = wait_for(page, "Platform Management",
                   lambda: page.evaluate(JS_HAS_PM), log=log_fn)
    if not hit:
        return False, absent_message("Platform Management", page)

`probe` may raise — a page mid-navigation raises from content() and evaluate(),
and that means "not ready", never "not there". The first such error is logged
once so a genuinely broken probe is still visible.
"""

# Vendor SPAs here paint their shells 30-120s before their content, so these
# defaults are deliberately generous. A step that waits 90s and succeeds beats
# one that fails in 6s and costs a lab session.
SETTLE_TIMEOUT = 90
POLL_INTERVAL = 5

# Skeleton loaders are how both SCC and ISE render "not yet". Treating one as a
# finished page is the specific mistake this module exists to prevent.
_SKELETON_HINTS = ("skeleton", "placeholder", "shimmer", "loading")

_JS_DESCRIBE = """() => {
    const vis = (e) => e.getClientRects().length > 0;
    const controls = Array.from(document.querySelectorAll(
            'a,button,[role="button"],[role="link"]'))
        .filter(vis)
        .map(e => (e.textContent || '').trim())
        .filter(Boolean)
        .slice(0, 14);
    // A shell that has painted nothing but loaders looks identical to a page
    // whose content is genuinely absent, unless you ask.
    const skeletons = document.querySelectorAll(
        '[class*="skeleton" i],[class*="placeholder" i],[class*="shimmer" i]'
    ).length;
    // A modal keeps the page behind it skeletal forever, so "still rendering"
    // is true but useless -- the actionable fact is that something must be
    // dismissed first. SCC's org picker does exactly this.
    const dlg = Array.from(document.querySelectorAll(
            '[role="dialog"],[aria-modal="true"],.modal,[class*="dialog" i]'))
        .find(e => e.getClientRects().length);
    return {
        controls: controls,
        control_count: controls.length,
        skeletons: skeletons,
        dialog: dlg ? (dlg.innerText || '').trim().replace(/\\s+/g, ' ').slice(0, 90) : null,
        body_chars: (document.body ? (document.body.innerText || '').length : 0),
    };
}"""


def _classify(url: str, info: dict) -> dict:
    """Turn raw page facts into the distinctions the callers actually need.

    Pure, so it can be tested without a browser.
    """
    u = (url or "").lower()
    host = url.split("/")[2] if "://" in (url or "") else ""
    info = dict(info or {})
    info["url"] = url
    info["host"] = host
    info["login_page"] = ("login.jsp" in u or "loginpage" in u
                          or "sign-on" in host or "/login/" in u)
    # Few controls plus visible loaders means the shell is up and the content
    # is not. That is "too early", which is a different bug from "absent".
    info["skeleton"] = bool(info.get("skeletons")) or (
        info.get("control_count", 0) <= 1 and info.get("body_chars", 0) < 1200)
    info["unreadable"] = info.get("error") is not None
    return info


def _describe_fallback(url: str, err: Exception) -> dict:
    return _classify(url, {"error": str(err)[:80], "controls": [],
                           "control_count": 0, "skeletons": 0, "body_chars": 0})


def describe_page(page) -> dict:
    """What is actually on this page right now (sync Playwright)."""
    try:
        return _classify(page.url, page.evaluate(_JS_DESCRIBE))
    except Exception as e:                      # navigating, or context torn down
        try:
            return _describe_fallback(page.url, e)
        except Exception:
            return _describe_fallback("", e)


async def describe_page_async(page) -> dict:
    """What is actually on this page right now (async Playwright)."""
    try:
        return _classify(page.url, await page.evaluate(_JS_DESCRIBE))
    except Exception as e:
        try:
            return _describe_fallback(page.url, e)
        except Exception:
            return _describe_fallback("", e)


def absent_message(what: str, page=None, diag: dict = None, extra: str = "") -> str:
    """A failure message that distinguishes 'not there' from 'not yet'.

    Pass either a live page or an already-collected diag. The result always
    names the URL, because "not found" without a URL is what made four separate
    failures this month indistinguishable from one another.
    """
    d = diag if diag is not None else (describe_page(page) if page is not None else {})
    bits = []
    if d.get("login_page"):
        bits.append("the page is a LOGIN page — the session was lost, "
                    f"so {what} could not be there")
    elif d.get("dialog"):
        # Named before the skeleton case on purpose: a blocking dialog is the
        # cause, and "still rendering" is only its symptom.
        bits.append(f"a dialog is blocking the page and must be dismissed first "
                    f"({d['dialog']!r}) — {what} cannot render behind it")
    elif d.get("unreadable"):
        bits.append(f"the page could not be read ({d.get('error')}) — it was "
                    "probably still navigating")
    elif d.get("skeleton"):
        bits.append(f"the page had not finished rendering ({d.get('skeletons', 0)} "
                    f"loading placeholder(s), {d.get('control_count', 0)} control(s) "
                    f"visible) — this is 'too early', not 'absent'")
    else:
        bits.append(f"the page looks rendered ({d.get('control_count', 0)} controls) "
                    f"but {what} is not on it")
    if d.get("controls"):
        bits.append(f"controls seen={d['controls']}")
    if d.get("url"):
        bits.append(f"url={d['url'][:100]}")
    if extra:
        bits.append(extra)
    return f"{what} not found after waiting: " + "; ".join(bits)


def wait_for(page, what: str, probe, timeout: int = SETTLE_TIMEOUT,
             interval: int = POLL_INTERVAL, log=None):
    """Poll `probe` until it returns something truthy; return that, else None.

    `probe` raising is treated as "not ready yet". That is the whole point: a
    page mid-redirect raises from evaluate() and content(), and letting that
    escape reported a successful login as "iDAC login unavailable".
    """
    _log = log or (lambda s: None)
    tries = max(1, int(timeout / max(1, interval)))
    first_err = None
    for i in range(tries):
        try:
            got = probe()
            if got:
                if i:
                    _log(f"{what} appeared after ~{i * interval}s")
                return got
        except Exception as e:
            if first_err is None:
                first_err = e
                _log(f"{what}: probe not ready yet ({str(e)[:70]})")
        if i < tries - 1:
            try:
                page.wait_for_timeout(interval * 1000)
            except Exception:
                return None                     # page/context gone
    return None


async def wait_for_async(page, what: str, probe, timeout: int = SETTLE_TIMEOUT,
                         interval: int = POLL_INTERVAL, log=None):
    """Async twin of wait_for. `probe` may be sync or a coroutine function."""
    import inspect

    _log = log or (lambda s: None)
    tries = max(1, int(timeout / max(1, interval)))
    first_err = None
    for i in range(tries):
        try:
            got = probe()
            if inspect.isawaitable(got):
                got = await got
            if got:
                if i:
                    _log(f"{what} appeared after ~{i * interval}s")
                return got
        except Exception as e:
            if first_err is None:
                first_err = e
                _log(f"{what}: probe not ready yet ({str(e)[:70]})")
        if i < tries - 1:
            try:
                await page.wait_for_timeout(interval * 1000)
            except Exception:
                return None
    return None
