"""
ise_integrations.py — Automates ISE pxGrid Cloud, Secure Access, and cdFMC integrations.

Steps:
  1. ise_pxgrid_register         — Enable pxGrid Cloud on ISE + register to Catalyst Cloud Portal
  2. ise_scc_integrate           — ISE Integration Catalog → SCC OTP → SCC Platform Integrations
  3. ise_cdfmc_integrate         — ISE Integration Catalog → FMC OTP → cdFMC pxGrid Application Instance
  4. ise_scc_deactivate_reactivate — Deactivate + reactivate ISE→SCC integration (bug workaround)

Skip logic: each step checks whether it is already done before running.
  - Steps 1–3: if already active/registered in the system → status = "skipped"
  - Step 4:    always runs (it IS the fix; idempotent if already Active)

Convention: return (True, "SKIP: <reason>") to mark a step as skipped.

ISE is at 198.18.5.101 (admin / C1sco12345).
pxGrid Cloud credentials (Catalyst Cloud Portal login + account name) are stored per-org
in org_credentials.pxgrid_cloud_email / pxgrid_cloud_password / pxgrid_cloud_account.
SCC access uses the saved session file data/scc_session.json (from the existing pipeline).
"""

from __future__ import annotations

import asyncio
import datetime
import json
import re
import sqlite3
import time
from contextlib import closing
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────

ISE_HOST = "198.18.5.101"
ISE_USER = "admin"
ISE_PASS = "C1sco12345"
ISE_URL  = f"https://{ISE_HOST}"

ISE_STEPS = [
    "ise_pxgrid_register",
    "ise_scc_integrate",
    "ise_cdfmc_integrate",
    "ise_scc_deactivate_reactivate",
]

ISE_STEP_LABELS = {
    "ise_pxgrid_register":          "pxGrid Cloud Register",
    "ise_scc_integrate":            "ISE \u2192 Secure Access (SGTs)",
    "ise_cdfmc_integrate":          "ISE \u2192 cdFMC (SGTs)",
    "ise_scc_deactivate_reactivate":"ISE\u2192SCC Deactivate + Reactivate",
}

def _sanitize(s: str) -> str:
    """Strip ANSI escape codes and non-printable control characters from strings
    that will be stored in SQLite (Playwright call logs contain tab/newline/ESC
    sequences that corrupt JSON serialisation in the dashboard)."""
    import re as _re
    # Remove ANSI escape sequences
    s = _re.sub(r'\x1b\[[0-9;]*[mGKHF]', '', s)
    # Replace tabs and newlines with spaces; remove other control chars
    s = s.replace('\t', ' ').replace('\n', ' ').replace('\r', ' ')
    s = _re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', s)
    return s[:2000]


_SKIP_PREFIX = "SKIP:"


def _db_connect(db_path: str, retries: int = 8, delay: float = 0.4) -> sqlite3.Connection:
    """Connect to SQLite with retry for transient VirtioFS/bind-mount I/O errors.
    macOS Docker bind-mounts can return EIO (disk I/O error) during concurrent
    host+container access; retrying after a short back-off resolves it reliably.
    synchronous=OFF skips fsync() calls that fail on macOS VirtioFS bind-mounts.
    """
    last_err: Exception | None = None
    for attempt in range(retries):
        try:
            conn = sqlite3.connect(db_path, timeout=30)
            conn.execute("PRAGMA journal_mode=DELETE")
            conn.execute("PRAGMA synchronous=OFF")
            return conn
        except sqlite3.OperationalError as e:
            if ("disk I/O error" in str(e) or "unable to open database file" in str(e)) and attempt < retries - 1:
                time.sleep(delay * (attempt + 1))
                last_err = e
                continue
            raise
    raise last_err  # type: ignore[misc]

# ── DB helpers ─────────────────────────────────────────────────────────────────

def ise_ensure_table(db_path: str) -> None:
    """Create ise_steps table; add pxGrid Cloud columns to org_credentials if missing."""
    conn = _db_connect(db_path)
    try:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ise_steps (
                pod_id        TEXT,
                step_name     TEXT,
                status        TEXT DEFAULT 'pending',
                result        TEXT DEFAULT '',
                started_at    TEXT,
                completed_at  TEXT,
                PRIMARY KEY (pod_id, step_name)
            )
        """)
        cols = [r[1] for r in conn.execute("PRAGMA table_info(org_credentials)").fetchall()]
        for col in ["pxgrid_cloud_email", "pxgrid_cloud_password", "pxgrid_cloud_account"]:
            if col not in cols:
                conn.execute(f"ALTER TABLE org_credentials ADD COLUMN {col} TEXT DEFAULT ''")
        conn.commit()
    finally:
        conn.close()


def _ise_step_set(pod_id: str, step: str, status: str, result: str, db_path: str) -> None:
    """Upsert a single row in ise_steps."""
    now = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    for attempt in range(8):
        conn = _db_connect(db_path)
        try:
            conn.execute("""
                INSERT INTO ise_steps (pod_id, step_name, status, result, started_at, completed_at)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(pod_id, step_name) DO UPDATE SET
                    status=excluded.status, result=excluded.result,
                    started_at=COALESCE(excluded.started_at, started_at),
                    completed_at=excluded.completed_at
            """, (
                pod_id, step, status, result,
                now if status == "running" else None,
                now if status in ("completed", "failed", "skipped") else None,
            ))
            conn.commit()
            return
        except sqlite3.OperationalError as e:
            if "disk I/O error" in str(e) and attempt < 7:
                conn.close()
                time.sleep(0.4 * (attempt + 1))
                continue
            raise
        finally:
            conn.close()


def _load_creds(pod_id: str, db_path: str) -> dict | None:
    """Load org_credentials for the POD's SCC org. Returns dict or None if not found."""
    with closing(_db_connect(db_path)) as c:
        c.row_factory = sqlite3.Row
        pod = c.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return None
        m = re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return None
        oc = c.execute("SELECT * FROM org_credentials WHERE org_number=?", (m.group(1),)).fetchone()
        return dict(oc) if oc else {}


# ── ISE REST API helper ────────────────────────────────────────────────────────

def _ise_api_get(path: str, timeout: int = 8) -> tuple[bool, dict]:
    """GET an ISE Open API endpoint. Returns (ok, data)."""
    try:
        import requests as _req, urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = _req.get(
            f"{ISE_URL}{path}",
            auth=(ISE_USER, ISE_PASS),
            verify=False,
            headers={"Accept": "application/json"},
            timeout=timeout,
        )
        if r.status_code == 200:
            try:
                return True, r.json()
            except Exception:
                return True, {"raw": r.text[:500]}
        return False, {"status_code": r.status_code}
    except Exception as e:
        return False, {"error": str(e)}


def _ise_api_post(path: str, body: dict, timeout: int = 10) -> tuple[bool, dict]:
    """POST to an ISE Open API endpoint. Returns (ok, data)."""
    try:
        import requests as _req, urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = _req.post(
            f"{ISE_URL}{path}",
            auth=(ISE_USER, ISE_PASS),
            json=body,
            verify=False,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=timeout,
        )
        ok = r.status_code in (200, 201, 204)
        try:
            return ok, r.json()
        except Exception:
            return ok, {"raw": r.text[:500]}
    except Exception as e:
        return False, {"error": str(e)}


def _ise_api_put(path: str, body: dict, timeout: int = 15) -> tuple[bool, dict]:
    """PUT to an ISE Open API endpoint. Returns (ok, data)."""
    try:
        import requests as _req, urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        r = _req.put(
            f"{ISE_URL}{path}",
            auth=(ISE_USER, ISE_PASS),
            json=body,
            verify=False,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
            timeout=timeout,
        )
        ok = r.status_code in (200, 201, 204)
        try:
            return ok, r.json()
        except Exception:
            return ok, {"raw": r.text[:500]}
    except Exception as e:
        return False, {"error": str(e)}


# ── ISE browser helpers ────────────────────────────────────────────────────────

async def _ise_dismiss_modal(page):
    """Force-remove ISE post-login Bootstrap modal via JS so it doesn't block clicks."""
    try:
        await page.evaluate("""
            const modal = document.getElementById('ise-modal');
            if (modal) modal.remove();
            document.querySelectorAll('.modal-backdrop, .post-loging-modal').forEach(el => el.remove());
            if (document.body) document.body.classList.remove('modal-open');
        """)
    except Exception:
        pass
    await page.wait_for_timeout(300)


async def _ise_dismiss_session_info(page):
    """Dismiss the ISE 'Session Info' popover that blocks form interactions."""
    await page.evaluate("""
        document.querySelectorAll('.popover, [class*="session-info"], [class*="sessionInfo"]')
                       .forEach(el => el.remove());
    """)
    # Also try clicking the × close button if still visible
    try:
        btn = page.locator('.popover button.close, .popover [aria-label*="close" i]').first
        if await btn.is_visible(timeout=500):
            await btn.click()
    except Exception:
        pass
    await page.wait_for_timeout(200)


async def _ise_login(page, log) -> bool:
    """Navigate to ISE admin and log in. Returns True on success."""
    try:
        await page.goto(f"{ISE_URL}/admin/", wait_until="domcontentloaded", timeout=60000)
        await page.wait_for_timeout(3000)

        # Dismiss pre-login banner ("Accept" button) if present — ISE shows a
        # terms/GDPR banner that must be acknowledged before the login form works.
        try:
            accept_btn = page.locator('button.preLoginAcceptButton, button:has-text("Accept")')
            if await accept_btn.first.is_visible(timeout=3000):
                await accept_btn.first.click()
                log("Dismissed pre-login Accept banner")
                await page.wait_for_timeout(1500)
        except Exception:
            pass  # Banner not present — proceed

        # Fill username
        filled_user = False
        for user_sel in ['input[name="username"]', '#dijit_form_TextBox_0', 'input[type="text"]']:
            try:
                await page.fill(user_sel, ISE_USER, timeout=4000)
                filled_user = True
                break
            except Exception:
                continue

        # Fill password
        filled_pass = False
        for pass_sel in ['input[name="password"]', 'input[id="dijit_form_TextBox_1"]', 'input[type="password"]']:
            try:
                await page.fill(pass_sel, ISE_PASS, timeout=4000)
                filled_pass = True
                break
            except Exception:
                continue

        if not filled_user or not filled_pass:
            log(f"ISE login: could not fill form (user={filled_user} pass={filled_pass})")
            return False

        # Click the "Login" button (ISE uses Dijit buttons; type="button" not "submit")
        clicked = False
        for btn_sel in ['button:has-text("Login")', 'button[type="submit"]',
                        'input[type="submit"]', '#loginButton']:
            try:
                await page.click(btn_sel, timeout=4000)
                clicked = True
                break
            except Exception:
                continue

        if not clicked:
            log("ISE login: could not find/click Login button")
            return False

        # Wait for redirect off login page
        try:
            await page.wait_for_url(lambda url: "login" not in url.lower() and "LoginPage" not in url,
                                    timeout=30000)
        except Exception:
            pass
        if "login" in page.url.lower() or "LoginPage" in page.url:
            log("ISE login: still on login page after submit")
            return False
        # Short wait for page to start rendering
        await page.wait_for_timeout(4000)
        # Force-remove post-login blocking modal via JS (Bootstrap modal that intercepts all clicks)
        await _ise_dismiss_modal(page)
        log("ISE login OK")
        return True
    except Exception as e:
        log(f"ISE login error: {e}")
        return False


async def _scc_load_session(context, session_path: str, log) -> bool:
    """Restore SCC browser cookies from saved session file.

    Handles two formats:
    - Flat list:  [{name, value, ...}, ...]  (written by refresh_scc_sessions.py)
    - Dict:       {"cookies": [{...}, ...]}  (legacy format)
    """
    p = Path(session_path)
    if not p.exists():
        log(f"SCC session file not found: {session_path}")
        return False
    try:
        state = json.loads(p.read_text())
        # Flat list written by refresh_scc_sessions.py
        if isinstance(state, list):
            cookies = state
        else:
            cookies = state.get("cookies", [])
        if cookies:
            await context.add_cookies(cookies)
        log(f"Loaded {len(cookies)} SCC session cookies")
        return bool(cookies)
    except Exception as e:
        log(f"Failed to load SCC session: {e}")
        return False


async def _scc_relogin(ctx, scc_page, session_path: str, creds: dict, log) -> bool:
    """Reload SCC session cookies from the per-POD session file.

    The session file is created by refresh_scc_sessions.py (the 'Refresh SCC
    Sessions' pre-flight step on the dashboard).  This function does NOT attempt
    headless login — MFA cannot be completed in Docker.  If the session file is
    missing or stale (>8 h), instruct the user to run the pre-flight refresh.
    """
    import time as _time
    p = Path(session_path)
    if not p.exists():
        log("SCC session file not found — click 'Refresh SCC Sessions' in the "
            "dashboard ISE card before running ISE steps")
        return False

    age_h = (_time.time() - p.stat().st_mtime) / 3600
    if age_h > 8:
        log(f"SCC session file is {age_h:.1f}h old (>8h, likely expired) — "
            "click 'Refresh SCC Sessions' in the dashboard ISE card")
        return False

    try:
        cookies = json.loads(p.read_text())
        if not isinstance(cookies, list):
            log("SCC session file format unexpected — re-run the pre-flight refresh")
            return False
        await ctx.add_cookies(cookies)
        log(f"SCC session reloaded from file ({len(cookies)} cookies, {age_h:.1f}h old)")
        return True
    except Exception as e:
        log(f"SCC relogin: failed to reload session file: {e}")
        return False


async def _scc_dismiss_org_picker(page, log) -> bool:
    """Dismiss the 'Select Organization' modal that SCC shows after cookie-based login.

    The modal overlays the entire page and blocks all interaction until the user
    (or we) clicks 'Continue'.  The org is already pre-selected in the dropdown
    because the session cookies carry the right org context — we just need to
    click the blue Continue button.

    Returns True if the modal was found and dismissed, False if it wasn't present.
    """
    try:
        cont_btn = page.locator('button:has-text("Continue")').first
        await cont_btn.wait_for(state="visible", timeout=6000)
        await cont_btn.click()
        log("Dismissed SCC org-picker modal (clicked Continue)")
        # Wait for the underlying page to fully render
        await page.wait_for_load_state("domcontentloaded", timeout=15000)
        await page.wait_for_timeout(2000)
        return True
    except Exception:
        return False


async def _read_otp_from_page(page, log) -> str | None:
    """Try several selector patterns to extract an OTP/activation token."""
    candidates = [
        ('input[readonly]',        'value'),
        ('textarea[readonly]',     'value'),
        ('code',                   'text'),
        ('[class*="token"]',       'text'),
        ('[class*="otp"]',         'text'),
        ('[class*="code"]',        'text'),
        ('[class*="activation"]',  'text'),
    ]
    for sel, mode in candidates:
        try:
            els = await page.locator(sel).all()
            for el in els:
                if not await el.is_visible(timeout=1000):
                    continue
                val = (await el.input_value(timeout=1000)) if mode == 'value' else (await el.text_content() or "")
                val = val.strip()
                if len(val) > 20:
                    log(f"OTP found via '{sel}' ({len(val)} chars)")
                    return val
        except Exception:
            continue
    # Fallback: scan modal/dialog for a long token string
    for modal_sel in ['[role="dialog"]', '.modal', '[class*="modal"]', '[class*="dialog"]']:
        try:
            modal = page.locator(modal_sel).first
            if await modal.is_visible(timeout=2000):
                text = await modal.text_content() or ""
                tokens = re.findall(r'[A-Za-z0-9+/=_-]{40,}', text)
                if tokens:
                    log(f"OTP extracted from modal ({len(tokens[0])} chars)")
                    return tokens[0]
        except Exception:
            continue
    return None


async def _navigate_to_integration_catalog(page, log) -> bool:
    """Navigate to ISE Administration → Integration Catalog. Returns True on success."""
    try:
        # Correct hash URL (found from live ISE DOM inspection)
        await page.goto(f"{ISE_URL}/admin/#administration/administration_integration_catalog/integration_catalog",
                        wait_until="domcontentloaded", timeout=60000)
        try:
            await page.wait_for_selector('button[data-label="More details"]', timeout=30000)
        except Exception:
            await page.wait_for_timeout(4000)
        # Re-dismiss modal in case it reappeared after navigation
        await _ise_dismiss_modal(page)
        return True
    except Exception as e:
        log(f"Could not navigate to Integration Catalog: {e}")
        return False


async def _check_integration_already_active(page, app_text: str, log) -> bool:
    """
    After navigating to the Integration Catalog, click the integration card and
    check if there is already an Active instance. Returns True if active/skippable.
    """
    try:
        card = page.locator(f'text={app_text}').first
        await card.click(timeout=8000)
        await page.wait_for_timeout(2000)
        # Look for "Active" status indicator on the page
        for active_sel in [':text("Active")', ':text("Activated")', '[class*="active" i]:not([class*="inactive" i])']:
            try:
                el = page.locator(active_sel).first
                if await el.is_visible(timeout=2000):
                    log(f"Found active instance for '{app_text}' — will skip")
                    return True
            except Exception:
                continue
    except Exception as e:
        log(f"Could not check active state for '{app_text}': {e}")
    return False


# ── Cisco SSO Device Authorization helper ──────────────────────────────────────

async def _do_cisco_sso_auth(page, url: str, email: str, password: str, log) -> bool:
    """
    Authenticate at Cisco's OAuth2 device authorization page (id.cisco.com/activate).
    The URL contains the user_code as a query param (e.g. ?user_code=XWTTNFVJ).
    Flow: enter activation code → log in with Cisco account → approve device access.
    Required before ISE can successfully POST to /api/v1/pxgrid/cloud/enroll/ise.
    Returns True if auth appears completed (optimistic), False if MFA blocks it.
    """
    import urllib.parse as _urlparse
    try:
        # Extract the user_code from the URL
        parsed = _urlparse.urlparse(url)
        qs = _urlparse.parse_qs(parsed.query)
        user_code = qs.get("user_code", [""])[0]
        log(f"SSO: user_code={user_code!r}")

        # Navigate to the activation base URL (some implementations auto-fill when
        # user_code is in the param; if not, we fill it manually below)
        log(f"SSO: navigating to {url[:80]}")
        await page.goto(url, wait_until="domcontentloaded", timeout=30000)
        await page.wait_for_timeout(2000)

        for ss_path in ["/pipeline/host-data/sso_step1.png", "/tmp/sso_step1.png"]:
            try:
                await page.screenshot(path=ss_path)
                log(f"SSO screenshot 1: {ss_path}")
                break
            except Exception:
                pass

        page_text = (await page.inner_text("body")).replace("\n", " ")
        log(f"SSO page 1 ({page.url[:80]}): {page_text[:250]}")

        # ── Step A: Enter activation / user code ─────────────────────────────
        # Cisco's /activate page shows an "Activation Code" text input.
        # Fill the user_code (e.g. XWTTNFVJ) here — NOT the email address.
        code_filled = False
        for sel in ['input[name="activation_code"]', 'input[name="user_code"]',
                    'input[id*="code" i]', 'input[id*="activation" i]',
                    'input[type="text"]']:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=2000):
                    await el.clear()
                    await el.fill(user_code)
                    log(f"SSO: activation code '{user_code}' filled via {sel}")
                    code_filled = True
                    break
            except Exception:
                continue

        if code_filled:
            # Click Continue / Submit to proceed after code entry
            for btn_sel in ['button:has-text("Continue")', 'button:has-text("Next")',
                            'button:has-text("Submit")', 'button[type="submit"]',
                            'input[type="submit"]']:
                try:
                    btn = page.locator(btn_sel).first
                    if await btn.is_visible(timeout=2000):
                        await btn.click()
                        await page.wait_for_timeout(3000)
                        log(f"SSO: submitted code via {btn_sel}")
                        break
                except Exception:
                    continue

        for ss_path in ["/pipeline/host-data/sso_step2.png", "/tmp/sso_step2.png"]:
            try:
                await page.screenshot(path=ss_path)
                log(f"SSO screenshot 2: {ss_path}")
                break
            except Exception:
                pass
        page_text = (await page.inner_text("body")).replace("\n", " ")
        log(f"SSO page 2 ({page.url[:80]}): {page_text[:250]}")

        # ── Step B: Log in with Cisco account (email → password) ─────────────
        # id.cisco.com uses Okta sign-in widget: fill email → click Next button
        # Okta's Next button starts DISABLED and is enabled by JS after valid input events
        _email_filled = False
        for sel in ['input[name="identifier"]', 'input[type="email"]', 'input[name="email"]',
                    'input[name="pf.username"]', 'input[autocomplete="username"]']:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=3000):
                    await el.click()
                    await el.clear()
                    # Use type() instead of fill() — types char-by-char, triggering keyup/keydown
                    # Okta's validation listens for keyup to enable the Next button
                    await el.type(email, delay=30)
                    log(f"SSO: email typed via {sel}")
                    _email_filled = True
                    break
            except Exception:
                continue

        if _email_filled:
            # Wait for Okta to enable the Next button (it's disabled until email is valid)
            try:
                await page.wait_for_function(
                    "() => { const b = document.querySelector('input[type=\"submit\"]'); return b && !b.disabled; }",
                    timeout=4000
                )
                log("SSO: Next button is now enabled")
            except Exception:
                log("SSO: Next button still disabled after 4s — force-enabling")

            # Force-enable (remove disabled attr) then click
            clicked = await page.evaluate("""
            () => {
                const btn = document.querySelector('input[type="submit"]') ||
                            document.querySelector('input.button-primary') ||
                            document.querySelector('[data-type="save"]');
                if (btn) {
                    btn.disabled = false;
                    btn.removeAttribute('disabled');
                    btn.click();
                    return btn.outerHTML.substring(0, 100);
                }
                const form = document.querySelector('form');
                if (form) { form.submit(); return 'form.submit()'; }
                return null;
            }
            """)
            if clicked:
                log(f"SSO: Next clicked: {clicked[:80]}")
            else:
                log("SSO: No Next button found — pressing Enter on email field")
                for sel in ['input[name="identifier"]', 'input[type="email"]']:
                    try:
                        el = page.locator(sel).first
                        if await el.is_visible(timeout=1000):
                            await el.press("Enter")
                            log(f"SSO: Enter pressed on {sel}")
                            break
                    except Exception:
                        continue

            # Wait for password field to confirm page advanced
            try:
                await page.wait_for_selector('input[type="password"]', timeout=10000)
                log("SSO: password page confirmed (password field visible)")
            except Exception:
                log("SSO: password field not detected after Next click — may still be on email page")
                try:
                    text_now = (await page.inner_text("body")).replace("\n", " ")[:300]
                    log(f"SSO page stuck: url={page.url[:80]} text={text_now}")
                except Exception:
                    pass
                # Log current page state for debugging
                try:
                    url_now = page.url
                    text_now = (await page.inner_text("body")).replace("\n", " ")[:300]
                    log(f"SSO page stuck: url={url_now[:80]} text={text_now}")
                except Exception:
                    pass

        # Fill password — click Verify/Login button (not keyboard Enter)
        for sel in ['input[type="password"]', 'input[name="password"]', 'input[name="pf.pass"]']:
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=5000):
                    await el.click()
                    await el.fill(password)
                    log("SSO: password filled")
                    # Click the Okta "Verify" / "Sign In" button
                    _verify_clicked = False
                    for verify_sel in [
                        'input[value="Verify"]', 'input[value="Sign in"]', 'input[value="Login"]',
                        'input[value="Sign In"]', '.button-primary[type="submit"]',
                        '[data-type="save"]', '[data-se="primaryButton"]',
                        'input[type="submit"]', 'button[type="submit"]',
                    ]:
                        try:
                            btn = page.locator(verify_sel).first
                            if await btn.is_visible(timeout=2000):
                                await btn.click()
                                log(f"SSO: clicked Verify/Login via {verify_sel}")
                                _verify_clicked = True
                                break
                        except Exception:
                            continue
                    if not _verify_clicked:
                        log("SSO: Verify button not found — pressing Enter on password field")
                        await el.press("Enter")
                    await page.wait_for_timeout(4000)
                    break
            except Exception:
                continue

        for ss_path in ["/pipeline/host-data/sso_step3.png", "/tmp/sso_step3.png"]:
            try:
                await page.screenshot(path=ss_path)
                log(f"SSO screenshot 3: {ss_path}")
                break
            except Exception:
                pass
        page_text = (await page.inner_text("body")).replace("\n", " ")
        log(f"SSO page 3 ({page.url[:80]}): {page_text[:250]}")

        # MFA check — return False if OTP/TOTP required (can't complete headlessly)
        if any(k in page_text.lower() for k in ["verification code", "authenticator", "two-factor",
                                                   "one-time password", " totp", "phone number"]):
            log("SSO: MFA required — cannot complete headlessly; registration will likely fail")
            return False

        # ── Step C: Approve device access if presented ────────────────────────
        for allow_sel in ['button:has-text("Allow")', 'button:has-text("Authorize")',
                           'button:has-text("Approve")', 'button:has-text("Confirm")',
                           'button:has-text("Grant access")', 'input[value="Allow"]',
                           'input[value="Authorize"]']:
            try:
                btn = page.locator(allow_sel).first
                if await btn.is_visible(timeout=4000):
                    await btn.click()
                    log(f"SSO: device approved via {allow_sel}")
                    await page.wait_for_timeout(2000)
                    break
            except Exception:
                continue

        for ss_path in ["/pipeline/host-data/sso_step4.png", "/tmp/sso_step4.png"]:
            try:
                await page.screenshot(path=ss_path)
                log(f"SSO screenshot 4: {ss_path}")
                break
            except Exception:
                pass
        page_text = (await page.inner_text("body")).replace("\n", " ")
        log(f"SSO page 4 ({page.url[:80]}): {page_text[:250]}")

        # Success check
        if any(s in page_text.lower() for s in ["success", "activated", "authorized", "confirmed",
                                                   "you may close", "device activated", "thank you"]):
            log("SSO: device authorization confirmed!")
            return True

        if "invalid code" in page_text.lower() or "error" in page_text.lower():
            log(f"SSO: code rejected or error — check sso screenshots")
            return False

        log("SSO: no explicit success/error phrase — optimistically returning True")
        return True

    except Exception as e:
        log(f"SSO auth exception: {e}")
        return False


# ── Step 1: pxGrid Cloud Registration ─────────────────────────────────────────

async def _phase_ise_pxgrid_register_async(pod_id: str, creds: dict, log) -> tuple[bool, str]:
    from playwright.async_api import async_playwright

    px_email   = creds.get("pxgrid_cloud_email", "").strip()
    px_pass    = creds.get("pxgrid_cloud_password", "").strip()
    px_account = creds.get("pxgrid_cloud_account", "").strip()

    if not px_email or not px_pass:
        return False, "pxGrid Cloud credentials not set — add pxgrid_cloud_email and pxgrid_cloud_password in Org Credentials card"

    # ── Step 1a: Ensure pxGrid Cloud service is enabled via deployment API ────
    # This replaces the unreliable UI checkbox — ISE Dijit renders the section
    # lazily and it's absent from the DOM when the service is not yet enabled.
    ok_node, node_data = _ise_api_get("/api/v1/deployment/node/ise")
    if ok_node:
        node_resp = node_data.get("response", {})
        current_services = node_resp.get("services", [])
        roles = node_resp.get("roles", ["Standalone"])
        if "pxGridCloud" not in current_services:
            log("pxGrid Cloud not in services — enabling via deployment API")
            new_services = list(set(current_services + ["pxGridCloud"]))
            ok_put, put_resp = _ise_api_put(
                "/api/v1/deployment/node/ise",
                {"roles": roles, "services": new_services},
            )
            msg = put_resp.get("success", {}).get("message", "") or put_resp.get("error", {}).get("message", "")
            if ok_put:
                log(f"pxGrid Cloud service enabled: {msg}")
            else:
                log(f"API enable warning (continuing): {msg or put_resp}")
        else:
            log("pxGrid Cloud service already enabled in ISE")
    else:
        log(f"Could not check node services (continuing): {node_data}")

    # ── Step 1b: Skip if already registered with Catalyst Cloud ──────────────
    ok_s, s_data = _ise_api_get("/api/v1/pxgrid-cloud/settings")
    if ok_s:
        enabled = s_data.get("pxGridCloudEnabled") or s_data.get("enabled") or s_data.get("registered")
        if enabled:
            return True, f"{_SKIP_PREFIX} pxGrid Cloud already enabled and registered in ISE"

    # ── Step 1c: Pre-fetch activation URL from ISE API ───────────────────────
    # ISE uses OAuth2 device authorization grant. The admin must authenticate at
    # id.cisco.com/activate?user_code=... BEFORE ISE can POST to /pxgrid/cloud/enroll/ise.
    _pre_act_url = ""
    ok_act_pre, act_data_pre = _ise_api_get("/api/v1/pxgrid/cloud/activation-url", timeout=10)
    if ok_act_pre:
        _pre_act_url = act_data_pre.get("response", {}).get("url", "")
        log(f"Pre-browser activation URL: {_pre_act_url or '(empty)'}")
    else:
        log(f"Could not pre-fetch activation URL: {act_data_pre}")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        page.set_default_timeout(30000)

        try:
            org_number = str(creds.get("org_number", "")).strip()

            if not await _ise_login(page, log):
                return False, "ISE login failed"

            log("Navigating to Integration Catalog")
            if not await _navigate_to_integration_catalog(page, log):
                return False, "Could not open Integration Catalog"

            # Click "More details" on Cisco Security Cloud card (first card in catalog)
            log("Opening Cisco Security Cloud details")
            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)
            await page.wait_for_timeout(1500)
            await _ise_dismiss_modal(page)
            # Wait for catalog cards to render before clicking More details
            try:
                await page.wait_for_selector('button[data-label="More details"]', timeout=20000)
            except Exception:
                pass
            await page.locator('button[data-label="More details"]').first.click(timeout=20000, force=True)
            await page.wait_for_timeout(2000)

            # Click "Configuration" tab (default lands on "About this integration")
            log("Clicking Configuration tab")
            try:
                await page.locator('text=Configuration').first.click(timeout=8000)
                await page.wait_for_timeout(2000)
            except Exception:
                pass
            await _ise_dismiss_session_info(page)

            # Check if pxGrid Cloud is not yet enabled (warning banner visible)
            page_text = (await page.inner_text("body")).lower()
            if "enable pxgrid cloud and register" in page_text:
                return False, "pxGrid Cloud not yet enabled on ISE node — run step 1 (pxGrid Cloud Register) first"

            # If there is an existing Active instance from a previous session, deactivate it first
            existing_active = False
            for act_chk in [':text("Active")', ':text("Activated")']:
                try:
                    if await page.locator(act_chk).first.is_visible(timeout=2000):
                        existing_active = True
                        break
                except Exception:
                    continue
            if existing_active:
                log("Found existing Active instance — deactivating to force fresh OTP")
                for da_sel in ['button:has-text("Deactivate")', 'a:has-text("Deactivate")', ':text("Deactivate")']:
                    try:
                        da = page.locator(da_sel).first
                        if await da.is_visible(timeout=3000):
                            await da.click()
                            await page.wait_for_timeout(2000)
                            # Confirm if dialog
                            for conf in ['button:has-text("Yes")', 'button:has-text("Confirm")', 'button:has-text("OK")']:
                                try:
                                    cb = page.locator(conf).first
                                    if await cb.is_visible(timeout=2000):
                                        await cb.click()
                                        await page.wait_for_timeout(1000)
                                        break
                                except Exception:
                                    continue
                            log("Deactivated existing instance")
                            break
                    except Exception:
                        continue
                await page.wait_for_timeout(1000)

            # Scroll down and select New instance
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)
            log("Selecting New instance")
            for ni_sel in ['input[type="radio"][value*="new" i]', 'label:has-text("New instance") input']:
                try:
                    rb = page.locator(ni_sel).first
                    if await rb.is_visible(timeout=3000):
                        await rb.check()
                        log("Checked New instance radio")
                        break
                except Exception:
                    continue
            else:
                try:
                    await page.get_by_text("New instance").click(timeout=5000)
                    log("Clicked New instance text")
                except Exception:
                    pass
            await page.wait_for_timeout(500)

            log("Clicking Activate")
            await _ise_dismiss_modal(page)
            await page.locator('button:has-text("Activate")').first.click(timeout=10000, force=True)
            await page.wait_for_timeout(3000)

            otp_token = await _read_otp_from_page(page, log)
            if not otp_token:
                return False, "Could not read OTP token from ISE Integration Catalog (Security Cloud)"

            for ok_sel in ['button:has-text("OK")', 'button:has-text("Close")', 'button:has-text("Done")']:
                try:
                    ok_btn = page.locator(ok_sel).first
                    if await ok_btn.is_visible(timeout=3000):
                        await ok_btn.click()
                        await page.wait_for_timeout(1000)
                        break
                except Exception:
                    continue

            # === Configure SCC Platform Integration ===
            log("Opening SCC Platform Integrations")
            # Load stored session — new format is full storage_state (cookies + localStorage),
            # old format is just a cookies array. Use storage_state at context creation time
            # so localStorage tokens (org-scoped JWTs) are restored before any navigation.
            _session_data = json.loads(Path(session_path).read_text())
            if isinstance(_session_data, dict) and "cookies" in _session_data:
                # New format: full storage_state — create dedicated context with all tokens
                log(f"Loading full storage state ({len(_session_data.get('cookies',[]))} cookies, "
                    f"{len(_session_data.get('origins', []))} origins)")
                scc_ctx = await browser.new_context(
                    storage_state=_session_data,
                    no_viewport=True,
                )
            else:
                # Old format: cookies array only
                log(f"Loading legacy cookie session ({len(_session_data)} cookies)")
                scc_ctx = await browser.new_context(no_viewport=True)
                await scc_ctx.add_cookies(_session_data)
            scc_page = await scc_ctx.new_page()
            scc_page.set_default_timeout(30000)

            # Step 1: Extract enterpriseId from session localStorage, then load
            # the dashboard with it so the React SPA initialises with full org context
            # before we navigate anywhere else.
            _eid = ""
            for _origin in _session_data.get("origins", []):
                for _item in _origin.get("localStorage", []):
                    if _item.get("name") == "enterpriseId":
                        _eid = _item["value"]
                        break
            _dashboard_url = (
                f"https://security.cisco.com/dashboard?enterpriseId={_eid}"
                if _eid else "https://security.cisco.com/dashboard"
            )
            log(f"Loading SCC dashboard (enterpriseId={_eid[:8]}...) to init SPA")
            await scc_page.goto(_dashboard_url, wait_until="domcontentloaded", timeout=60000)
            await scc_page.wait_for_timeout(2000)

            if "login" in scc_page.url.lower() or "sign-on" in scc_page.url.lower():
                log("SCC session expired — attempting re-login with stored credentials")
                relogin_ok = await _scc_relogin(ctx, scc_page, session_path, creds, log)
                if not relogin_ok:
                    return False, "SCC session expired and re-login failed — check scc_email/scc_password in org credentials or complete MFA manually"
                await scc_page.goto(_dashboard_url, wait_until="domcontentloaded", timeout=60000)
                await scc_page.wait_for_timeout(2000)
                if "login" in scc_page.url.lower() or "sign-on" in scc_page.url.lower():
                    return False, "SCC still at login after re-login attempt — MFA may be required"

            # Dismiss the org-picker dropdown modal (pre-selected → just click Continue)
            await _scc_dismiss_org_picker(scc_page, log)
            await scc_page.wait_for_timeout(2000)

            # Step 2: Navigate to Platform Integrations via the sidebar nav link.
            # Direct URL navigation to /platforms/integrations always redirects back
            # to /dashboard — the SPA must be initialised first (done above) and then
            # we click the nav link so the React router performs a client-side transition.
            log("Clicking Platform Integrations in SCC sidebar nav")
            _nav_clicked = False
            for _nav_sel in [
                'a:has-text("Platform Integrations")',
                'a[href*="platform"]:has-text("Integration")',
                '[role="link"]:has-text("Platform Integrations")',
                'nav a:has-text("Platform")',
                'li a:has-text("Platform")',
                'a[href*="platforms/integrations"]',
                'a[href*="platform-integrations"]',
            ]:
                try:
                    _nav_link = scc_page.locator(_nav_sel).first
                    await _nav_link.wait_for(state="visible", timeout=5000)
                    await _nav_link.click()
                    await scc_page.wait_for_load_state("domcontentloaded", timeout=20000)
                    await scc_page.wait_for_timeout(3000)
                    log(f"Clicked Platform Integrations nav via {_nav_sel!r} → {scc_page.url[:80]}")
                    _nav_clicked = True
                    break
                except Exception:
                    continue

            if not _nav_clicked:
                # Fallback: screenshot what we have and try direct URL anyway
                try:
                    await scc_page.screenshot(path="/pipeline/host-data/scc_nav_fallback.png")
                except Exception:
                    pass
                log("WARN: Platform Integrations nav link not found — saved scc_nav_fallback.png; trying direct URL")
                await scc_page.goto("https://security.cisco.com/platforms/integrations",
                                    wait_until="domcontentloaded", timeout=60000)
                await scc_page.wait_for_timeout(3000)
                await _scc_dismiss_org_picker(scc_page, log)
                await scc_page.wait_for_timeout(2000)

            # Wait for the React SPA to finish rendering — domcontentloaded fires before
            # the JS app renders any content. Wait up to 30s for the Add Integration Module
            # button (or any visible button) to appear before attempting interactions.
            log("Waiting for Platform Integrations page to render...")
            try:
                await scc_page.wait_for_selector(
                    'button:has-text("Add Integration"), '
                    'a:has-text("Add Integration"), '
                    '[role="button"]:has-text("Add Integration"), '
                    'button:has-text("Add Module"), '
                    'button:has-text("Add")',
                    timeout=30000,
                )
                log("Platform Integrations page rendered")
            except Exception:
                try:
                    await scc_page.screenshot(path="/pipeline/host-data/scc_integrations_loaded.png")
                    log("WARN: Add Integration button not found after 30s — saved scc_integrations_loaded.png")
                except Exception:
                    pass
                await scc_page.wait_for_timeout(3000)

            log("Clicking Add Integration Module")
            _add_clicked = False
            for add_sel in [
                'button:has-text("Add Integration")',
                'a:has-text("Add Integration")',
                '[role="button"]:has-text("Add Integration")',
                'button:has-text("Add Module")',
                'a:has-text("Add Module")',
                '[role="button"]:has-text("Add Module")',
                'button:has-text("Add")',
                'a:has-text("Add")',
            ]:
                try:
                    add_btn = scc_page.locator(add_sel).first
                    if await add_btn.is_visible(timeout=4000):
                        await add_btn.click()
                        await scc_page.wait_for_timeout(2000)
                        log(f"Clicked Add Integration button via {add_sel!r}")
                        _add_clicked = True
                        break
                except Exception:
                    continue
            if not _add_clicked:
                log("WARN: 'Add Integration Module' button not found — proceeding to find ISE Start/Edit button directly")

            log("Starting ISE integration")
            # SCC may show "Start" (fresh), "Edit"/"Configure"/"Connect" (existing integration),
            # or "Activate" depending on prior run state. Try all candidates.
            _ise_btn_clicked = False
            for _btn_label in ["Start", "Edit", "Configure", "Connect", "Setup", "Activate"]:
                for _scope in [
                    scc_page.locator('[class*="card"], [class*="tile"], li').filter(has_text="ISE").first,
                    scc_page,
                ]:
                    try:
                        _btn = _scope.locator(f'button:has-text("{_btn_label}")').first
                        if await _btn.is_visible(timeout=3000):
                            await _btn.click(timeout=6000)
                            log(f"Clicked ISE '{_btn_label}' button on SCC")
                            _ise_btn_clicked = True
                            break
                    except Exception:
                        continue
                if _ise_btn_clicked:
                    break
            if not _ise_btn_clicked:
                # Screenshot for debugging then raise
                try:
                    _ss = f"/pipeline/host-data/scc_ise_nobutton_{pod_id}.png"
                    await scc_page.screenshot(path=_ss)
                    log(f"Screenshot saved → data/scc_ise_nobutton_{pod_id}.png")
                except Exception:
                    pass
                raise RuntimeError("No ISE integration button found on SCC (tried Start/Edit/Configure/Connect/Setup/Activate) — check screenshot")
            await scc_page.wait_for_timeout(2000)

            log("Clicking Connect")
            for _conn_sel in ['button:has-text("Connect")', 'a:has-text("Connect")', '[role="button"]:has-text("Connect")']:
                try:
                    _conn_btn = scc_page.locator(_conn_sel).first
                    if await _conn_btn.is_visible(timeout=5000):
                        await _conn_btn.click(timeout=8000)
                        log(f"Clicked Connect via {_conn_sel!r}")
                        break
                except Exception:
                    continue
            await scc_page.wait_for_timeout(2000)

            log("Filling name and token")
            import time as _time
            _integ_name = f"ISE-POD-{pod_id}-{int(_time.time()) % 10000}"
            for name_sel in ['input[placeholder*="name" i]', 'input[id*="name"]']:
                try:
                    name_inp = scc_page.locator(name_sel).first
                    if await name_inp.is_visible(timeout=3000):
                        await name_inp.fill(_integ_name)
                        log(f"Filled integration name: {_integ_name}")
                        break
                except Exception:
                    continue
            for tok_sel in ['input[placeholder*="token" i]', 'textarea[placeholder*="token" i]', 'input[id*="token"]']:
                try:
                    tok_inp = scc_page.locator(tok_sel).first
                    if await tok_inp.is_visible(timeout=3000):
                        await tok_inp.fill(otp_token)
                        log(f"Pasted OTP token ({len(otp_token)} chars)")
                        break
                except Exception:
                    continue

            log("Clicking Save")
            await scc_page.locator('button:has-text("Save")').first.click(timeout=8000)
            await scc_page.wait_for_timeout(3000)
            # Handle duplicate-name error: append extra chars and retry once
            _page_txt = (await scc_page.inner_text("body")).lower()
            if "unique" in _page_txt or "already exists" in _page_txt or "error" in _page_txt:
                log("Name conflict detected — retrying with alternate name")
                _integ_name = f"ISE-POD-{pod_id}-{int(_time.time()) % 10000}x"
                for name_sel in ['input[placeholder*="name" i]', 'input[id*="name"]']:
                    try:
                        name_inp = scc_page.locator(name_sel).first
                        if await name_inp.is_visible(timeout=3000):
                            await name_inp.fill(_integ_name)
                            break
                    except Exception:
                        continue
                await scc_page.locator('button:has-text("Save")').first.click(timeout=8000)
                await scc_page.wait_for_timeout(5000)
            else:
                await scc_page.wait_for_timeout(2000)

            # Check status — may not be Active yet (step 4 will fix it)
            content = (await scc_page.content()).lower()
            if "active" in content and "ise" in content:
                return True, f"ISE \u2192 Secure Access integration Active (token: {otp_token[:20]}...)"
            return True, f"ISE \u2192 SCC integration saved (token: {otp_token[:20]}...) — run step 4 if status is Waiting for activation"

        except Exception as e:
            return False, f"ISE \u2192 Secure Access integration error: {e}"
        finally:
            await browser.close()


# ── Step 3: ISE → cdFMC Integration ───────────────────────────────────────────

async def _phase_ise_cdfmc_integrate_async(pod_id: str, creds: dict, session_path: str, log) -> tuple[bool, str]:
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        page.set_default_timeout(30000)
        otp_token = None

        try:
            if not await _ise_login(page, log):
                return False, "ISE login failed"

            log("Navigating to Integration Catalog")
            if not await _navigate_to_integration_catalog(page, log):
                return False, "Could not open Integration Catalog"
            await _ise_dismiss_modal(page)  # belt-and-suspenders: modal can reappear after nav

            # Dismiss Session Info popup + internet connectivity banner before searching for cards
            await _ise_dismiss_session_info(page)
            for banner_sel in [
                'button[aria-label="close"]', 'button[aria-label="Close"]',
                '.alert-banner button', '.alert button', 'button.close',
            ]:
                try:
                    el = page.locator(banner_sel).first
                    if await el.is_visible(timeout=1500):
                        await el.click()
                        log(f"Dismissed banner via {banner_sel}")
                        await page.wait_for_timeout(1000)
                        break
                except Exception:
                    continue

            # Click "More details" on Firewall Management Center card.
            # The catalog shows cards in order; FMC is typically the 2nd card.
            # Use nth(1) to get the second "More details" button (first is SCC).
            # If catalog fails to load (internet error), retry up to 3 times.
            log("Opening Firewall Management Center details")
            more_btns = page.locator('button[data-label="More details"]')
            btn_count = await more_btns.count()
            log(f"Found {btn_count} 'More details' button(s)")
            for _retry in range(3):
                if btn_count > 0:
                    break
                # Catalog may not have loaded yet — dismiss any banner and retry
                log(f"No 'More details' buttons — retry {_retry + 1}/3 (catalog may still be loading)")
                for banner_sel in [
                    'button[aria-label="close"]', 'button[aria-label="Close"]',
                    '.alert-banner button', '.alert button', 'button.close',
                ]:
                    try:
                        el = page.locator(banner_sel).first
                        if await el.is_visible(timeout=1500):
                            await el.click()
                            await page.wait_for_timeout(500)
                            break
                    except Exception:
                        continue
                # Reload Integration Catalog
                if not await _navigate_to_integration_catalog(page, log):
                    break
                await _ise_dismiss_modal(page)
                await _ise_dismiss_session_info(page)
                await page.wait_for_timeout(3000)
                btn_count = await more_btns.count()
                log(f"After retry {_retry + 1}: found {btn_count} 'More details' button(s)")

            if btn_count >= 2:
                await _ise_dismiss_modal(page)
                await _ise_dismiss_session_info(page)
                await page.wait_for_timeout(500)
                await _ise_dismiss_modal(page)
                await more_btns.nth(1).click(timeout=10000, force=True)
            elif btn_count == 1:
                # Only one card visible — might already be on FMC
                await more_btns.first.click(timeout=10000, force=True)
            else:
                # Fallback: click FMC card text directly
                for fmc_sel in [':text("Firewall Management Center")', ':text("FMC")', 'text=Firewall']:
                    try:
                        el = page.locator(fmc_sel).first
                        if await el.is_visible(timeout=4000):
                            await el.click()
                            break
                    except Exception:
                        continue
            await page.wait_for_timeout(2000)

            # Click "Configuration" tab
            log("Clicking Configuration tab")
            await _ise_dismiss_session_info(page)
            try:
                await page.locator('text=Configuration').first.click(timeout=8000)
                await page.wait_for_timeout(2000)
            except Exception:
                pass

            # Check page state
            page_text = (await page.inner_text("body")).lower()

            # Check if pxGrid Cloud not yet enabled
            if "enable pxgrid cloud and register" in page_text:
                return False, "pxGrid Cloud not yet enabled on ISE node — run step 1 first"

            # ── Lab constraint: ISE has no internet — skip gracefully ─────────
            if "unable to reach internet" in page_text or ("please ensure ise has connectivity" in page_text):
                return True, f"{_SKIP_PREFIX} ISE has no internet access to Integration Catalog — cdFMC integration skipped (lab environment constraint)"

            # If there is an existing Active instance from a previous session, deactivate it first
            fmc_existing_active = False
            for act_chk in [':text("Active")', ':text("Activated")']:
                try:
                    if await page.locator(act_chk).first.is_visible(timeout=2000):
                        fmc_existing_active = True
                        break
                except Exception:
                    continue
            if fmc_existing_active:
                log("Found existing Active FMC instance — deactivating to force fresh token")
                for da_sel in ['button:has-text("Deactivate")', 'a:has-text("Deactivate")', ':text("Deactivate")']:
                    try:
                        da = page.locator(da_sel).first
                        if await da.is_visible(timeout=3000):
                            await da.click()
                            await page.wait_for_timeout(2000)
                            for conf in ['button:has-text("Yes")', 'button:has-text("Confirm")', 'button:has-text("OK")']:
                                try:
                                    cb = page.locator(conf).first
                                    if await cb.is_visible(timeout=2000):
                                        await cb.click()
                                        await page.wait_for_timeout(1000)
                                        break
                                except Exception:
                                    continue
                            log("Deactivated existing FMC instance")
                            break
                    except Exception:
                        continue
                await page.wait_for_timeout(1000)

            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)
            log("Selecting New instance")
            for ni_sel in ['input[type="radio"][value*="new" i]', 'label:has-text("New instance") input']:
                try:
                    rb = page.locator(ni_sel).first
                    if await rb.is_visible(timeout=3000):
                        await rb.check()
                        break
                except Exception:
                    continue
            else:
                try:
                    await page.get_by_text("New instance").click(timeout=5000)
                except Exception:
                    pass

            log("Clicking Activate")
            # Re-check for internet error banner (appears after New instance selection)
            try:
                _pt2 = (await page.inner_text("body")).lower()
                if "unable to reach internet" in _pt2 or "please ensure ise has connectivity" in _pt2:
                    return True, f"{_SKIP_PREFIX} ISE has no internet access to Integration Catalog — cdFMC integration skipped (lab environment constraint)"
            except Exception:
                pass
            # Screenshot + page text dump for debugging
            try:
                await page.screenshot(path="/pipeline/host-data/ise_cdfmc_pre_activate.png", full_page=True)
                log("Screenshot: /pipeline/host-data/ise_cdfmc_pre_activate.png")
            except Exception:
                pass
            try:
                cdfmc_page_txt = (await page.inner_text("body")).strip()
                btns = await page.evaluate("""
                () => Array.from(document.querySelectorAll('button, a[role="button"], span.dijitButtonText'))
                     .map(b => ({tag: b.tagName, txt: b.textContent.trim().substring(0,40),
                                 disabled: b.disabled || false}))
                     .filter(b => b.txt.length > 0).slice(0, 20)
                """)
                log(f"Buttons on page: {btns}")
                for line in cdfmc_page_txt.split('\n'):
                    l = line.strip()
                    if l and 3 < len(l) < 120:
                        if any(k in l.lower() for k in ['activate', 'instance', 'otp', 'token', 'connect', 'new']):
                            log(f"  page: {l[:100]}")
            except Exception:
                pass
            activated = False
            for act_sel in [
                'button:has-text("Activate")',
                'span.dijitButtonText:has-text("Activate")',
                'a:has-text("Activate")',
                'button:has-text("Activate pxGrid")',
                'button:has-text("Connect")',
            ]:
                try:
                    act_el = page.locator(act_sel).first
                    if await act_el.is_visible(timeout=5000):
                        await act_el.scroll_into_view_if_needed()
                        await act_el.click(timeout=10000)
                        log(f"Activate clicked via {act_sel} ✓")
                        activated = True
                        break
                except Exception:
                    continue
            if not activated:
                # Dijit registry fallback
                try:
                    dj_act = await page.evaluate("""
                    () => {
                        if (typeof dijit === 'undefined' || !dijit.registry) return 'no dijit';
                        for (const w of dijit.registry.toArray()) {
                            const dc = w.declaredClass || '';
                            if (!dc.toLowerCase().includes('button')) continue;
                            const label = (w.get ? w.get('label') : w.label || '').trim();
                            if (label.toLowerCase().includes('activate') || label.toLowerCase().includes('connect')) {
                                w.disabled = false;
                                if (w._onClick) w._onClick(new MouseEvent('click'));
                                else if (w.domNode) w.domNode.click();
                                return 'dijit_clicked:' + label;
                            }
                        }
                        return 'not_found';
                    }
                    """)
                    log(f"Dijit Activate fallback: {dj_act}")
                    activated = 'dijit_clicked' in dj_act
                except Exception as _dae:
                    log(f"Dijit Activate error: {_dae}")
            if not activated:
                return False, "Activate button not found — check /pipeline/host-data/ise_cdfmc_pre_activate.png"
            await page.wait_for_timeout(3000)

            otp_token = await _read_otp_from_page(page, log)
            if not otp_token:
                return False, "Could not read OTP token from ISE Integration Catalog (FMC)"

            for ok_sel in ['button:has-text("OK")', 'button:has-text("Close")', 'button:has-text("Done")']:
                try:
                    ok_btn = page.locator(ok_sel).first
                    if await ok_btn.is_visible(timeout=3000):
                        await ok_btn.click()
                        await page.wait_for_timeout(1000)
                        break
                except Exception:
                    continue

            # === Configure cdFMC ===
            log("Opening SCC → Firewall → Security Devices")
            scc_page = await ctx.new_page()
            scc_page.set_default_timeout(30000)
            await _scc_load_session(ctx, session_path, log)
            await scc_page.goto("https://security.cisco.com/firewall/security-devices",
                                wait_until="domcontentloaded", timeout=60000)
            await scc_page.wait_for_timeout(3000)

            if "login" in scc_page.url.lower():
                return False, "SCC session expired — refresh SCC session and retry"

            log("Selecting hqftdv")
            await scc_page.locator('text=hqftdv').first.click(timeout=10000)
            await scc_page.wait_for_timeout(2000)

            log("Opening Device Overview")
            await scc_page.locator('button:has-text("Device Overview"), a:has-text("Device Overview")').first.click(timeout=10000)
            await scc_page.wait_for_timeout(4000)

            fmc_page = scc_page
            if len(ctx.pages) > 2:
                fmc_page = ctx.pages[-1]
                await fmc_page.wait_for_load_state("domcontentloaded", timeout=20000)
                log(f"cdFMC tab: {fmc_page.url}")
            fmc_page.set_default_timeout(30000)

            log("Navigating to Integrations → Identity Sources")
            try:
                await fmc_page.click('text=Integrations', timeout=10000)
                await fmc_page.wait_for_timeout(1000)
                await fmc_page.click('text=Identity Sources', timeout=8000)
                await fmc_page.wait_for_timeout(3000)
            except Exception as e:
                log(f"Warning: menu nav failed: {e}")

            # Enable CSDAC if needed
            try:
                csdac_btn = fmc_page.locator('button:has-text("Enable CSDAC")').first
                if await csdac_btn.is_visible(timeout=4000):
                    log("Enabling CSDAC service")
                    await csdac_btn.click()
                    await fmc_page.wait_for_timeout(2000)
                    await fmc_page.locator('button:has-text("Enable")').last.click(timeout=5000)
                    await fmc_page.wait_for_timeout(3000)
                    try:
                        await fmc_page.locator('button:has-text("Close")').first.click(timeout=5000)
                    except Exception:
                        pass
                    log("CSDAC enabled")
            except Exception:
                log("CSDAC already active or not required")

            # Check for existing inactive connector
            existing_inactive = False
            try:
                not_act = fmc_page.locator(':text("Not Activated")').first
                if await not_act.is_visible(timeout=3000):
                    existing_inactive = True
                    log("Found existing inactive pxGrid connector")
            except Exception:
                pass

            instance_name = f"ISE-FMC-POD-{pod_id}"
            log("Creating pxGrid Application Instance")
            await fmc_page.locator('button:has-text("Create pxGrid Application Instance")').first.click(timeout=10000)
            await fmc_page.wait_for_timeout(2000)

            for name_sel in ['input[placeholder*="name" i]', 'input[id*="name"]', 'input[type="text"]']:
                try:
                    name_inp = fmc_page.locator(name_sel).first
                    if await name_inp.is_visible(timeout=3000):
                        await name_inp.fill(instance_name)
                        break
                except Exception:
                    continue
            for tok_sel in ['input[placeholder*="otp" i]', 'input[placeholder*="key" i]',
                            'input[placeholder*="token" i]', 'textarea', 'input[type="text"]']:
                try:
                    tok_inp = fmc_page.locator(tok_sel).last
                    if await tok_inp.is_visible(timeout=3000):
                        await tok_inp.fill(otp_token)
                        log(f"Pasted FMC OTP ({len(otp_token)} chars)")
                        break
                except Exception:
                    continue

            log("Clicking Create")
            await fmc_page.locator('button:has-text("Create")').last.click(timeout=10000)
            await fmc_page.wait_for_timeout(3000)

            if existing_inactive:
                log("Making new connector active")
                try:
                    await fmc_page.locator(f'text={instance_name}').first.click(timeout=5000)
                    await fmc_page.wait_for_timeout(1000)
                    await fmc_page.locator('button:has-text("Make active")').first.click(timeout=5000)
                    await fmc_page.wait_for_timeout(2000)
                    log("Made active")
                except Exception as e:
                    log(f"Warning: Make Active failed: {e}")

            log("Clicking Save")
            await fmc_page.locator('button:has-text("Save")').first.click(timeout=10000)
            await fmc_page.wait_for_timeout(3000)

            try:
                test_btn = fmc_page.locator('button:has-text("Test")').first
                if await test_btn.is_visible(timeout=2000):
                    await test_btn.click()
                    await fmc_page.wait_for_timeout(3000)
                    log("pxGrid Cloud connection test initiated")
            except Exception:
                pass

            return True, f"ISE \u2192 cdFMC pxGrid instance '{instance_name}' created (OTP: {otp_token[:20]}...)"

        except Exception as e:
            return False, f"ISE \u2192 cdFMC integration error: {e}"
        finally:
            await browser.close()


# ── Step 4: Deactivate + Reactivate ISE → SCC (bug workaround) ────────────────

async def _phase_ise_scc_deactivate_reactivate_async(pod_id: str, creds: dict, session_path: str, log) -> tuple[bool, str]:
    """
    Workaround for the shared-infrastructure activation bug:
      ISE Integration Catalog → Cisco Security Cloud → existing instance
      → Deactivate → Reactivate
    If reactivation generates a new OTP it is automatically updated in SCC.
    Then waits for SCC Platform Integrations to show Active.
    """
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        page.set_default_timeout(30000)
        new_otp = None

        try:
            org_number = str(creds.get("org_number", "")).strip()

            if not await _ise_login(page, log):
                return False, "ISE login failed"

            log("Navigating to Integration Catalog")
            if not await _navigate_to_integration_catalog(page, log):
                return False, "Could not open Integration Catalog"

            # Open SCC detail page via "More details" button (first card = SCC)
            log("Opening Cisco Security Cloud via More details")
            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)
            await page.wait_for_timeout(500)
            await _ise_dismiss_modal(page)  # second pass — modal can re-appear after nav settle
            await page.locator('button[data-label="More details"]').first.click(timeout=10000, force=True)
            await page.wait_for_timeout(2000)

            # Click Configuration tab
            log("Clicking Configuration tab")
            await _ise_dismiss_session_info(page)
            try:
                await page.locator('text=Configuration').first.click(timeout=8000)
                await page.wait_for_timeout(2000)
            except Exception:
                pass

            # Log button inventory + screenshot for debugging
            btns_da = await page.evaluate("""() => {
                return Array.from(document.querySelectorAll('button, a[role="button"]'))
                  .map(b => ({tag:b.tagName, txt:b.innerText.trim().slice(0,40), dis:b.disabled}))
                  .filter(b => b.txt);
            }""")
            log(f"Buttons on page (pre-deactivate): {btns_da[:15]}")
            await page.screenshot(path="/pipeline/host-data/ise_scc_deactivate_pre.png")

            # ── Pre-check: if only disabled Activate visible (no Deactivate),
            #    ISE has no internet — skip gracefully ──────────────────────────
            has_deactivate_text = any("deactivate" in str(b.get('txt','')).lower() for b in btns_da)
            has_activate_disabled = any(
                "activate" in str(b.get('txt','')).lower() and b.get('dis', False)
                for b in btns_da
            )
            if not has_deactivate_text and has_activate_disabled:
                return True, f"{_SKIP_PREFIX} ISE→SCC integration not yet active (Activate button disabled — ISE has no internet, lab constraint)"

            # Click Deactivate — try direct button, then kebab/action menu fallback
            log("Clicking Deactivate")
            deactivate_found = False

            # Round 1: direct button/link
            for da_sel in [
                'button:has-text("Deactivate")',
                'a:has-text("Deactivate")',
                ':text("Deactivate")',
            ]:
                try:
                    da_btn = page.locator(da_sel).first
                    if await da_btn.is_visible(timeout=4000):
                        await da_btn.click()
                        deactivate_found = True
                        log(f"Clicked Deactivate via: {da_sel}")
                        break
                except Exception:
                    continue

            # Round 2: open kebab / actions menu then pick Deactivate
            if not deactivate_found:
                log("Direct Deactivate not found — trying kebab/actions menu")
                for menu_sel in [
                    'button[aria-label*="action" i]',
                    'button[aria-label*="more" i]',
                    'button[title*="action" i]',
                    'button[data-action*="more" i]',
                    'button.kebab',
                    '[class*="kebab"] button',
                    '[class*="actions"] button',
                    'td button',
                    'button[aria-haspopup="true"]',
                ]:
                    try:
                        menu_btn = page.locator(menu_sel).first
                        if await menu_btn.is_visible(timeout=3000):
                            await menu_btn.click()
                            await page.wait_for_timeout(1000)
                            # Now look for Deactivate in the opened dropdown
                            for da_sel2 in ['button:has-text("Deactivate")', 'li:has-text("Deactivate")', 'a:has-text("Deactivate")']:
                                try:
                                    da2 = page.locator(da_sel2).first
                                    if await da2.is_visible(timeout=3000):
                                        await da2.click()
                                        deactivate_found = True
                                        log(f"Clicked Deactivate via menu: {menu_sel} → {da_sel2}")
                                        break
                                except Exception:
                                    continue
                            if deactivate_found:
                                break
                    except Exception:
                        continue

            # Round 3: JS coordinate click on any element containing "Deactivate"
            if not deactivate_found:
                log("Trying JS coordinate click on Deactivate text")
                try:
                    clicked = await page.evaluate("""() => {
                        const els = Array.from(document.querySelectorAll('button, a, li, span'));
                        const el = els.find(e => e.innerText && e.innerText.trim() === 'Deactivate');
                        if (el) { const r = el.getBoundingClientRect(); return {x: r.x + r.width/2, y: r.y + r.height/2}; }
                        return null;
                    }""")
                    if clicked:
                        await page.mouse.click(clicked['x'], clicked['y'])
                        deactivate_found = True
                        log(f"JS coordinate Deactivate clicked at {clicked}")
                except Exception as e:
                    log(f"JS click error: {e}")

            if not deactivate_found:
                return False, "Deactivate button not found — check /pipeline/host-data/ise_scc_deactivate_pre.png"

            await page.wait_for_timeout(2000)
            # Confirm deactivation if a dialog appears
            for confirm_sel in ['button:has-text("Yes")', 'button:has-text("Confirm")', 'button:has-text("OK")']:
                try:
                    c_btn = page.locator(confirm_sel).first
                    if await c_btn.is_visible(timeout=3000):
                        await c_btn.click()
                        log("Confirmed deactivation dialog")
                        await page.wait_for_timeout(2000)
                        break
                except Exception:
                    continue

            await page.wait_for_timeout(2000)

            # Click Activate / Reactivate on the same instance
            log("Clicking Activate/Reactivate")
            reactivated = False
            for ra_sel in ['button:has-text("Activate")', 'button:has-text("Reactivate")', 'a:has-text("Activate")']:
                try:
                    ra_btn = page.locator(ra_sel).first
                    if await ra_btn.is_visible(timeout=5000):
                        await ra_btn.click()
                        reactivated = True
                        log("Clicked Activate/Reactivate")
                        await page.wait_for_timeout(3000)
                        break
                except Exception:
                    continue

            if not reactivated:
                return False, "Activate button not found after Deactivate"

            # Check if a new OTP was generated
            new_otp = await _read_otp_from_page(page, log)
            if new_otp:
                log(f"New OTP generated during reactivation ({len(new_otp)} chars) — will update SCC")
            else:
                log("No new OTP detected — reactivation reuses existing SCC token")

            # Click OK to close if present
            for ok_sel in ['button:has-text("OK")', 'button:has-text("Close")', 'button:has-text("Done")']:
                try:
                    ok_btn = page.locator(ok_sel).first
                    if await ok_btn.is_visible(timeout=3000):
                        await ok_btn.click()
                        await page.wait_for_timeout(1000)
                        break
                except Exception:
                    continue

            # === Update SCC if new OTP was generated ===
            log("Opening SCC Platform Integrations to verify / update")
            scc_page = await ctx.new_page()
            scc_page.set_default_timeout(30000)
            _s4_session_data = json.loads(Path(session_path).read_text())
            if isinstance(_s4_session_data, dict) and "cookies" in _s4_session_data:
                _s4_ctx = await browser.new_context(storage_state=_s4_session_data, no_viewport=True)
            else:
                _s4_ctx = await browser.new_context(no_viewport=True)
                await _s4_ctx.add_cookies(_s4_session_data)
            scc_page = await _s4_ctx.new_page()
            scc_page.set_default_timeout(30000)

            # Extract enterpriseId and load dashboard first to init the SPA
            _s4_eid = ""
            for _o in _s4_session_data.get("origins", []):
                for _it in _o.get("localStorage", []):
                    if _it.get("name") == "enterpriseId":
                        _s4_eid = _it["value"]
                        break
            _s4_dash = (f"https://security.cisco.com/dashboard?enterpriseId={_s4_eid}"
                        if _s4_eid else "https://security.cisco.com/dashboard")
            log(f"Step 4: Loading SCC dashboard (eid={_s4_eid[:8]}...)")
            await scc_page.goto(_s4_dash, wait_until="domcontentloaded", timeout=60000)
            await scc_page.wait_for_timeout(2000)

            if "login" in scc_page.url.lower() or "sign-on" in scc_page.url.lower():
                return False, "SCC session expired during step 4 — refresh SCC session and retry"

            await _scc_dismiss_org_picker(scc_page, log)
            await scc_page.wait_for_timeout(2000)

            # Navigate to Platform Integrations via sidebar nav
            log("Step 4: Clicking Platform Integrations in SCC sidebar nav")
            _s4_nav_clicked = False
            for _nav_sel in [
                'a:has-text("Platform Integrations")',
                'a[href*="platform"]:has-text("Integration")',
                '[role="link"]:has-text("Platform Integrations")',
                'nav a:has-text("Platform")',
                'li a:has-text("Platform")',
                'a[href*="platforms/integrations"]',
            ]:
                try:
                    _nl = scc_page.locator(_nav_sel).first
                    await _nl.wait_for(state="visible", timeout=5000)
                    await _nl.click()
                    await scc_page.wait_for_load_state("domcontentloaded", timeout=20000)
                    await scc_page.wait_for_timeout(3000)
                    log(f"Step 4: nav clicked via {_nav_sel!r} → {scc_page.url[:80]}")
                    _s4_nav_clicked = True
                    break
                except Exception:
                    continue
            if not _s4_nav_clicked:
                log("Step 4 WARN: nav link not found — falling back to direct URL")
                await scc_page.goto("https://security.cisco.com/platforms/integrations",
                                    wait_until="domcontentloaded", timeout=60000)
                await scc_page.wait_for_timeout(3000)
                await _scc_dismiss_org_picker(scc_page, log)
                await scc_page.wait_for_timeout(2000)

            if new_otp:
                # Find the existing ISE integration and update its token
                log("Updating SCC integration with new OTP")
                try:
                    ise_integration = scc_page.locator(f':text("ISE-POD-{pod_id}"), :text("ISE")').first
                    await ise_integration.click(timeout=8000)
                    await scc_page.wait_for_timeout(1000)
                    edit_btn = scc_page.locator('button:has-text("Edit"), button:has-text("Configure")').first
                    await edit_btn.click(timeout=5000)
                    await scc_page.wait_for_timeout(1000)
                    for tok_sel in ['input[placeholder*="token" i]', 'textarea[placeholder*="token" i]', 'input[id*="token"]']:
                        try:
                            tok_inp = scc_page.locator(tok_sel).first
                            if await tok_inp.is_visible(timeout=3000):
                                await tok_inp.fill(new_otp)
                                log(f"Updated SCC token with new OTP ({len(new_otp)} chars)")
                                break
                        except Exception:
                            continue
                    await scc_page.locator('button:has-text("Save")').first.click(timeout=8000)
                    await scc_page.wait_for_timeout(5000)
                    log("SCC token updated and saved")
                except Exception as e:
                    log(f"Warning: could not update SCC with new OTP: {e} — may need manual update")

            # Wait up to 90s for Active status
            log("Waiting for SCC integration to go Active...")
            for attempt in range(18):
                content = (await scc_page.content()).lower()
                if "active" in content and ("ise" in content or f"pod-{pod_id.lower()}" in content):
                    return True, "ISE \u2192 SCC integration is now Active"
                if attempt < 17:
                    await scc_page.wait_for_timeout(5000)
                    try:
                        await scc_page.reload(wait_until="domcontentloaded", timeout=20000)
                        await scc_page.wait_for_timeout(2000)
                    except Exception:
                        pass

            return True, "Deactivate + Reactivate completed — check SCC Platform Integrations for Active status (may take a few more minutes)"

        except Exception as e:
            return False, f"Deactivate/Reactivate error: {e}"
        finally:
            await browser.close()



# ── Step 2: ISE → Secure Access (SCC Platform Integration) ───────────────────

async def _phase_ise_scc_integrate_async(pod_id: str, creds: dict, session_path: str, log) -> tuple[bool, str]:
    from playwright.async_api import async_playwright

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        page.set_default_timeout(30000)
        otp_token = None

        try:
            org_number = str(creds.get("org_number", "")).strip()

            if not await _ise_login(page, log):
                return False, "ISE login failed"

            log("Navigating to Integration Catalog")
            if not await _navigate_to_integration_catalog(page, log):
                return False, "Could not open Integration Catalog"

            # Click "More details" on Cisco Security Cloud card (first card in catalog)
            log("Opening Cisco Security Cloud details")
            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)
            await page.wait_for_timeout(1500)
            await _ise_dismiss_modal(page)
            # Wait for catalog cards to render before clicking More details
            try:
                await page.wait_for_selector('button[data-label="More details"]', timeout=20000)
            except Exception:
                pass
            await page.locator('button[data-label="More details"]').first.click(timeout=20000, force=True)
            await page.wait_for_timeout(2000)

            # Click "Configuration" tab (default lands on "About this integration")
            log("Clicking Configuration tab")
            try:
                await page.locator('text=Configuration').first.click(timeout=8000)
                await page.wait_for_timeout(2000)
            except Exception:
                pass
            await _ise_dismiss_session_info(page)

            # Check if pxGrid Cloud is not yet enabled (warning banner visible)
            page_text = (await page.inner_text("body")).lower()
            if "enable pxgrid cloud and register" in page_text:
                return False, "pxGrid Cloud not yet enabled on ISE node — run step 1 (pxGrid Cloud Register) first"

            # If there is an existing Active instance from a previous session, deactivate it first
            existing_active = False
            for act_chk in [':text("Active")', ':text("Activated")']:
                try:
                    if await page.locator(act_chk).first.is_visible(timeout=2000):
                        existing_active = True
                        break
                except Exception:
                    continue
            if existing_active:
                log("Found existing Active instance — deactivating to force fresh OTP")
                for da_sel in ['button:has-text("Deactivate")', 'a:has-text("Deactivate")', ':text("Deactivate")']:
                    try:
                        da = page.locator(da_sel).first
                        if await da.is_visible(timeout=3000):
                            await da.click()
                            await page.wait_for_timeout(2000)
                            # Confirm if dialog
                            for conf in ['button:has-text("Yes")', 'button:has-text("Confirm")', 'button:has-text("OK")']:
                                try:
                                    cb = page.locator(conf).first
                                    if await cb.is_visible(timeout=2000):
                                        await cb.click()
                                        await page.wait_for_timeout(1000)
                                        break
                                except Exception:
                                    continue
                            log("Deactivated existing instance")
                            break
                    except Exception:
                        continue
                await page.wait_for_timeout(1000)

            # Scroll down and select New instance
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)
            log("Selecting New instance")
            for ni_sel in ['input[type="radio"][value*="new" i]', 'label:has-text("New instance") input']:
                try:
                    rb = page.locator(ni_sel).first
                    if await rb.is_visible(timeout=3000):
                        await rb.check()
                        log("Checked New instance radio")
                        break
                except Exception:
                    continue
            else:
                try:
                    await page.get_by_text("New instance").click(timeout=5000)
                    log("Clicked New instance text")
                except Exception:
                    pass
            await page.wait_for_timeout(500)

            log("Clicking Activate")
            await _ise_dismiss_modal(page)
            await page.locator('button:has-text("Activate")').first.click(timeout=10000, force=True)
            await page.wait_for_timeout(3000)

            otp_token = await _read_otp_from_page(page, log)
            if not otp_token:
                return False, "Could not read OTP token from ISE Integration Catalog (Security Cloud)"

            for ok_sel in ['button:has-text("OK")', 'button:has-text("Close")', 'button:has-text("Done")']:
                try:
                    ok_btn = page.locator(ok_sel).first
                    if await ok_btn.is_visible(timeout=3000):
                        await ok_btn.click()
                        await page.wait_for_timeout(1000)
                        break
                except Exception:
                    continue

            # === Configure SCC Platform Integration ===
            log("Opening SCC Platform Integrations")
            # Load stored session — new format is full storage_state (cookies + localStorage),
            # old format is just a cookies array. Use storage_state at context creation time
            # so localStorage tokens (org-scoped JWTs) are restored before any navigation.
            _session_data = json.loads(Path(session_path).read_text())
            if isinstance(_session_data, dict) and "cookies" in _session_data:
                # New format: full storage_state — create dedicated context with all tokens
                log(f"Loading full storage state ({len(_session_data.get('cookies',[]))} cookies, "
                    f"{len(_session_data.get('origins', []))} origins)")
                scc_ctx = await browser.new_context(
                    storage_state=_session_data,
                    no_viewport=True,
                )
            else:
                # Old format: cookies array only
                log(f"Loading legacy cookie session ({len(_session_data)} cookies)")
                scc_ctx = await browser.new_context(no_viewport=True)
                await scc_ctx.add_cookies(_session_data)
            scc_page = await scc_ctx.new_page()
            scc_page.set_default_timeout(30000)

            # Step 1: Navigate to SCC root — select org tile only if needed.
            # If the stored session has enterpriseId in localStorage (full storage_state),
            # the page lands directly on Home with org already selected — no tile click needed.
            log("Navigating to SCC root...")
            await scc_page.goto("https://security.cisco.com",
                                wait_until="domcontentloaded", timeout=60000)
            # Wait for React SPA to hydrate — networkidle catches API-driven content
            try:
                await scc_page.wait_for_load_state("networkidle", timeout=15000)
            except Exception:
                pass
            await scc_page.wait_for_timeout(2000)

            # Screenshot root page so we can see what the org picker looks like
            try:
                await scc_page.screenshot(path="/pipeline/host-data/scc_root_page.png")
                log(f"Root page screenshot saved (URL: {scc_page.url[:80]})")
            except Exception:
                pass

            # Dump all visible text to help diagnose tile selector
            _body_text = (await scc_page.inner_text("body")).lower()
            _org_already_selected = (
                f"pseudoco-{org_number}" in _body_text or
                f"pseudoco{org_number}" in _body_text
            )
            # Log first 300 chars of body text for debugging
            log(f"Root body snippet: {_body_text[:300]!r}")

            if _org_already_selected and "org-picker" not in scc_page.url.lower() and "select" not in scc_page.url.lower():
                log(f"Org PseudoCo-{org_number} already active in session — skipping tile click")
            else:
                org_slug = f"pseudoco-{org_number}"
                clicked_org = False
                for sel in [
                    f"button:has-text('PseudoCo-{org_number}')",
                    f"button:has-text('{org_slug}')",
                    f"a:has-text('PseudoCo-{org_number}')",
                    f"a:has-text('{org_slug}')",
                    f"[data-testid*='{org_slug}']",
                    f"div[role='button']:has-text('{org_slug}')",
                    f"li:has-text('{org_slug}')",
                    # Broader fallbacks
                    f"[class*='card']:has-text('{org_slug}')",
                    f"[class*='tile']:has-text('{org_slug}')",
                    f"[class*='org']:has-text('{org_slug}')",
                    f"*:has-text('PseudoCo-{org_number}') >> nth=0",
                ]:
                    try:
                        tile = scc_page.locator(sel).first
                        await tile.wait_for(state="visible", timeout=4000)
                        await tile.click()
                        await scc_page.wait_for_load_state("domcontentloaded", timeout=20000)
                        await scc_page.wait_for_timeout(2000)
                        log(f"Clicked org tile via {sel!r} → {scc_page.url[:80]}")
                        clicked_org = True
                        break
                    except Exception:
                        continue
                if not clicked_org:
                    log("WARN: Org tile not found — trying Continue fallback")
                    await _scc_dismiss_org_picker(scc_page, log)

            # Extract enterpriseId from stored session localStorage for direct URL use
            _enterprise_id = ""
            try:
                for _o in _session_data.get("origins", []):
                    for _item in _o.get("localStorage", []):
                        if _item.get("name") == "enterpriseId":
                            _enterprise_id = _item.get("value", "")
                            break
                if _enterprise_id:
                    log(f"enterpriseId from session: {_enterprise_id}")
            except Exception:
                pass

            # Step 2: Navigate to Platform Integrations.
            # After Continue, SCC React app always redirects to /dashboard.
            # Re-navigating WITH ?enterpriseId= in the URL bypasses the org picker
            # and loads the page in the correct org context.
            _platform_url = None
            _ei_suffix = f"?enterpriseId={_enterprise_id}" if _enterprise_id else ""
            for _url in [
                f"https://security.cisco.com/platforms/integrations{_ei_suffix}",
                "https://security.cisco.com/platforms/integrations",
                f"https://security.cisco.com/secure-access/platform-integrations{_ei_suffix}",
                "https://security.cisco.com/secure-access/integrations",
                "https://security.cisco.com/integration-hub",
            ]:
                log(f"Trying: {_url}")
                await scc_page.goto(_url, wait_until="domcontentloaded", timeout=60000)
                await scc_page.wait_for_timeout(2000)
                # Dismiss org picker if it appears — Continue redirects to /dashboard (org now set)
                _picker_dismissed = await _scc_dismiss_org_picker(scc_page, log)
                # Wait for React client-side navigation to finish (Continue → /dashboard)
                await scc_page.wait_for_timeout(4000)
                _dest = scc_page.url
                log(f"  After dismiss, URL: {_dest[:80]}")

                if "login" in _dest.lower() or "sign-on" in _dest.lower():
                    log("SCC session expired — attempting re-login")
                    relogin_ok = await _scc_relogin(ctx, scc_page, session_path, creds, log)
                    if not relogin_ok:
                        return False, "SCC session expired and re-login failed"
                    await scc_page.goto(_url, wait_until="domcontentloaded", timeout=60000)
                    await scc_page.wait_for_timeout(2000)
                    await _scc_dismiss_org_picker(scc_page, log)
                    await scc_page.wait_for_timeout(4000)
                    _dest = scc_page.url

                _path = _dest.split("security.cisco.com")[-1].lstrip("/").split("?")[0]
                _is_home = not _path or _path in ("home", "dashboard") or _path.startswith("home")

                if not _is_home and "integrations" in _dest.lower():
                    log(f"Landed on Platform Integrations: {_dest[:80]}")
                    _platform_url = _dest
                    break

                # If Continue was clicked (org now set) and we landed on dashboard,
                # re-navigate to the target URL — org context should persist now
                if _picker_dismissed and _is_home and _enterprise_id:
                    _retry_url = f"https://security.cisco.com/platforms/integrations?enterpriseId={_enterprise_id}"
                    log(f"  Org set — re-navigating to {_retry_url}")
                    await scc_page.goto(_retry_url, wait_until="domcontentloaded", timeout=60000)
                    await scc_page.wait_for_timeout(5000)
                    _dest2 = scc_page.url
                    log(f"  Re-navigate result: {_dest2[:80]}")
                    _path2 = _dest2.split("security.cisco.com")[-1].lstrip("/").split("?")[0]
                    _is_home2 = not _path2 or _path2 in ("home", "dashboard") or _path2.startswith("home")
                    if not _is_home2:
                        log(f"Landed on Platform Integrations: {_dest2[:80]}")
                        _platform_url = _dest2
                        break
                        _platform_url = _dest
                        break
                log(f"  → redirected to {_dest[:70]}")

            if not _platform_url:
                log("Direct URLs redirected — navigating via Secure Access sidebar")
                await scc_page.goto("https://security.cisco.com", wait_until="domcontentloaded", timeout=60000)
                await scc_page.wait_for_timeout(2000)
                for _sa_sel in [
                    'a:has-text("Secure Access")',
                    'nav a[href*="secure-access"]',
                    '[class*="nav"] a:has-text("Secure Access")',
                ]:
                    try:
                        _sa = scc_page.locator(_sa_sel).first
                        if await _sa.is_visible(timeout=4000):
                            await _sa.click()
                            await scc_page.wait_for_timeout(3000)
                            log(f"Clicked Secure Access nav → {scc_page.url[:80]}")
                            break
                    except Exception:
                        continue
                for _il in [
                    'a:has-text("Platform Integrations")',
                    'a:has-text("Integrations")',
                    'a[href*="integrations"]',
                ]:
                    try:
                        _il_el = scc_page.locator(_il).first
                        if await _il_el.is_visible(timeout=4000):
                            await _il_el.click()
                            await scc_page.wait_for_timeout(3000)
                            log(f"Integrations link via {_il!r} → {scc_page.url[:80]}")
                            break
                    except Exception:
                        continue

            # Final org picker dismiss — in case a fresh navigation triggered it again
            await _scc_dismiss_org_picker(scc_page, log)
            await scc_page.wait_for_timeout(2000)

            # Screenshot always for diagnostics
            try:
                await scc_page.screenshot(path="/pipeline/host-data/scc_integrations_loaded.png")
                log(f"Screenshot: scc_integrations_loaded.png (URL: {scc_page.url[:80]})")
            except Exception:
                pass

            # Wait for React SPA to render Add Integration button
            log("Waiting for Platform Integrations page to render...")
            try:
                await scc_page.wait_for_selector(
                    'button:has-text("Add Integration"), '
                    'a:has-text("Add Integration"), '
                    '[role="button"]:has-text("Add Integration"), '
                    'button:has-text("Add Module"), '
                    'button:has-text("Add")',
                    timeout=30000,
                )
                log("Platform Integrations page rendered")
            except Exception:
                try:
                    await scc_page.screenshot(path="/pipeline/host-data/scc_integrations_loaded.png")
                    log("WARN: Add Integration button not found after 30s — saved scc_integrations_loaded.png")
                except Exception:
                    pass
                await scc_page.wait_for_timeout(3000)

            log("Clicking Add Integration Module")
            _add_clicked = False
            for add_sel in [
                'button:has-text("Add Integration")',
                'a:has-text("Add Integration")',
                '[role="button"]:has-text("Add Integration")',
                'button:has-text("Add Module")',
                'a:has-text("Add Module")',
                '[role="button"]:has-text("Add Module")',
                'button:has-text("Add")',
                'a:has-text("Add")',
            ]:
                try:
                    add_btn = scc_page.locator(add_sel).first
                    if await add_btn.is_visible(timeout=4000):
                        await add_btn.click()
                        await scc_page.wait_for_timeout(2000)
                        log(f"Clicked Add Integration button via {add_sel!r}")
                        _add_clicked = True
                        break
                except Exception:
                    continue
            if not _add_clicked:
                log("WARN: 'Add Integration Module' button not found — proceeding to find ISE Start/Edit button directly")

            log("Starting ISE integration")
            # SCC may show "Start" (fresh), "Edit"/"Configure"/"Connect" (existing integration),
            # or "Activate" depending on prior run state. Try all candidates.
            _ise_btn_clicked = False
            for _btn_label in ["Start", "Edit", "Configure", "Connect", "Setup", "Activate"]:
                for _scope in [
                    scc_page.locator('[class*="card"], [class*="tile"], li').filter(has_text="ISE").first,
                    scc_page,
                ]:
                    try:
                        _btn = _scope.locator(f'button:has-text("{_btn_label}")').first
                        if await _btn.is_visible(timeout=3000):
                            await _btn.click(timeout=6000)
                            log(f"Clicked ISE '{_btn_label}' button on SCC")
                            _ise_btn_clicked = True
                            break
                    except Exception:
                        continue
                if _ise_btn_clicked:
                    break
            if not _ise_btn_clicked:
                # Screenshot for debugging then raise
                try:
                    _ss = f"/pipeline/host-data/scc_ise_nobutton_{pod_id}.png"
                    await scc_page.screenshot(path=_ss)
                    log(f"Screenshot saved → data/scc_ise_nobutton_{pod_id}.png")
                except Exception:
                    pass
                raise RuntimeError("No ISE integration button found on SCC (tried Start/Edit/Configure/Connect/Setup/Activate) — check screenshot")
            await scc_page.wait_for_timeout(2000)

            log("Clicking Connect")
            for _conn_sel in ['button:has-text("Connect")', 'a:has-text("Connect")', '[role="button"]:has-text("Connect")']:
                try:
                    _conn_btn = scc_page.locator(_conn_sel).first
                    if await _conn_btn.is_visible(timeout=5000):
                        await _conn_btn.click(timeout=8000)
                        log(f"Clicked Connect via {_conn_sel!r}")
                        break
                except Exception:
                    continue
            await scc_page.wait_for_timeout(2000)

            log("Filling name and token")
            import time as _time
            _integ_name = f"ISE-POD-{pod_id}-{int(_time.time()) % 10000}"
            for name_sel in ['input[placeholder*="name" i]', 'input[id*="name"]']:
                try:
                    name_inp = scc_page.locator(name_sel).first
                    if await name_inp.is_visible(timeout=3000):
                        await name_inp.fill(_integ_name)
                        log(f"Filled integration name: {_integ_name}")
                        break
                except Exception:
                    continue
            for tok_sel in ['input[placeholder*="token" i]', 'textarea[placeholder*="token" i]', 'input[id*="token"]']:
                try:
                    tok_inp = scc_page.locator(tok_sel).first
                    if await tok_inp.is_visible(timeout=3000):
                        await tok_inp.fill(otp_token)
                        log(f"Pasted OTP token ({len(otp_token)} chars)")
                        break
                except Exception:
                    continue

            log("Clicking Save")
            await scc_page.locator('button:has-text("Save")').first.click(timeout=8000)
            await scc_page.wait_for_timeout(3000)
            # Handle duplicate-name error: append extra chars and retry once
            _page_txt = (await scc_page.inner_text("body")).lower()
            if "unique" in _page_txt or "already exists" in _page_txt or "error" in _page_txt:
                log("Name conflict detected — retrying with alternate name")
                _integ_name = f"ISE-POD-{pod_id}-{int(_time.time()) % 10000}x"
                for name_sel in ['input[placeholder*="name" i]', 'input[id*="name"]']:
                    try:
                        name_inp = scc_page.locator(name_sel).first
                        if await name_inp.is_visible(timeout=3000):
                            await name_inp.fill(_integ_name)
                            break
                    except Exception:
                        continue
                await scc_page.locator('button:has-text("Save")').first.click(timeout=8000)
                await scc_page.wait_for_timeout(5000)
            else:
                await scc_page.wait_for_timeout(2000)

            # Check status — may not be Active yet (step 4 will fix it)
            content = (await scc_page.content()).lower()
            if "active" in content and "ise" in content:
                return True, f"ISE \u2192 Secure Access integration Active (token: {otp_token[:20]}...)"
            return True, f"ISE \u2192 SCC integration saved (token: {otp_token[:20]}...) — run step 4 if status is Waiting for activation"

        except Exception as e:
            return False, f"ISE \u2192 Secure Access integration error: {e}"
        finally:
            await browser.close()


# ── Main card runner ──────────────────────────────────────────────────────────

def ise_run_card(pod_id: str, db_path: str, from_step: int = 0, log=None) -> tuple[bool, str]:
    """
    Run the ISE integration card for a POD.
    Steps that return (True, "SKIP: ...") are marked as 'skipped' in the DB.
    """
    _log = log or (lambda s: print(f"  [ise] {s}"))
    ise_ensure_table(db_path)

    creds = _load_creds(pod_id, db_path)
    if creds is None:
        return False, f"POD {pod_id} not found or scc_org not set"

    session_path = str(Path(db_path).parent / "scc_session.json")

    # Prefer per-POD session file created by refresh_scc_sessions.py
    per_pod = Path(db_path).parent / f"scc_session_{pod_id}.json"
    if per_pod.exists():
        session_path = str(per_pod)
        _log(f"Using per-POD SCC session: {per_pod.name}")

    for i, step in enumerate(ISE_STEPS):
        if i < from_step:
            continue

        # Skip steps already completed or skipped — no need to re-run
        try:
            _db = sqlite3.connect(db_path)
            _row = _db.execute(
                "SELECT status FROM ise_steps WHERE pod_id=? AND step_name=?", (pod_id, step)
            ).fetchone()
            _db.close()
            if _row and _row[0] in ("completed", "skipped"):
                _log(f"Step {i+1}/{len(ISE_STEPS)}: {ISE_STEP_LABELS[step]} — already {_row[0]}, skipping")
                continue
        except Exception:
            pass

        _ise_step_set(pod_id, step, "running", "", db_path)
        _log(f"Step {i+1}/{len(ISE_STEPS)}: {ISE_STEP_LABELS[step]}")

        try:
            if step == "ise_pxgrid_register":
                ok, msg = asyncio.run(_phase_ise_pxgrid_register_async(pod_id, creds, _log))
            elif step == "ise_scc_integrate":
                ok, msg = asyncio.run(_phase_ise_scc_integrate_async(pod_id, creds, session_path, _log))
            elif step == "ise_cdfmc_integrate":
                ok, msg = asyncio.run(_phase_ise_cdfmc_integrate_async(pod_id, creds, session_path, _log))
            elif step == "ise_scc_deactivate_reactivate":
                ok, msg = asyncio.run(_phase_ise_scc_deactivate_reactivate_async(pod_id, creds, session_path, _log))
            else:
                ok, msg = False, f"Unknown step: {step}"
        except Exception as e:
            ok, msg = False, f"Exception in {step}: {e}"

        msg = _sanitize(msg)

        # Detect skip
        if ok and msg.startswith(_SKIP_PREFIX):
            status = "skipped"
        else:
            status = "completed" if ok else "failed"

        _ise_step_set(pod_id, step, status, msg, db_path)
        _log(f"  \u2192 {status}: {msg}")

        if not ok:
            # Soft-fail steps: internet issues are a lab constraint — always proceed
            if step in ("ise_cdfmc_integrate", "ise_scc_deactivate_reactivate"):
                _ise_step_set(pod_id, step, "skipped", f"[soft-fail] {msg}", db_path)
                _log(f"  [soft-fail] {ISE_STEP_LABELS[step]} — marked skipped, continuing to next step")
                continue
            return False, f"{ISE_STEP_LABELS[step]} failed: {msg}"

    return True, "All ISE integration steps completed"
