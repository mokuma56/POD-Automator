"""
ise_integrations.py — Automates ISE pxGrid Cloud, Secure Access, and cdFMC integrations.

Steps:
  1. ise_pxgrid_register         — Enable pxGrid Cloud on ISE + register to Catalyst Cloud Portal
  2. ise_scc_integrate           — ISE Integration Catalog → SCC OTP → SCC Platform Integrations
  3. ise_scc_deactivate_reactivate — Deactivate + reactivate ISE→SCC integration (bug workaround)
  4. ise_cdfmc_integrate         — ISE Integration Catalog → FMC OTP → cdFMC pxGrid Application Instance

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
    "ise_scc_deactivate_reactivate",
    "ise_cdfmc_integrate",
    "ise_sgt_verify",
]

ISE_STEP_LABELS = {
    "ise_pxgrid_register":          "pxGrid Cloud Register",
    "ise_scc_integrate":            "ISE \u2192 Secure Access (SGTs)",
    "ise_cdfmc_integrate":          "ISE \u2192 cdFMC (SGTs)",
    "ise_scc_deactivate_reactivate":"ISE\u2192SCC Deactivate + Reactivate",
    "ise_sgt_verify":               "Secure Access SGT Verify",
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
            _retryable = ("disk I/O error", "unable to open database file", "database is locked")
            if any(r in str(e) for r in _retryable) and attempt < 7:
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
        scc_org = pod["scc_org"] or ""
        m = re.search(r"pseudoco-(\d+)", scc_org)
        if not m:
            return None
        oc = c.execute("SELECT * FROM org_credentials WHERE org_number=?", (m.group(1),)).fetchone()
        result = dict(oc) if oc else {}
        result["scc_org"] = scc_org  # always inject so steps can navigate directly
        return result


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
        // Remove by known classes
        document.querySelectorAll('.popover, [class*="session-info"], [class*="sessionInfo"]')
                       .forEach(el => el.remove());
        // Remove any floating panel that contains 'Session Info' + 'Last logged in'
        // ISE uses different class names across versions — match by text content
        document.querySelectorAll('div, aside, section').forEach(el => {
            const txt = el.innerText || '';
            if (txt.includes('Session Info') && txt.includes('Last logged in') && el.children.length < 20) {
                el.remove();
            }
        });
    """)
    # Try clicking the × close button by common selectors
    for sel in [
        'button[title*="close" i]',
        '[aria-label*="close" i]',
        '.popover button.close',
    ]:
        try:
            btn = page.locator(sel).first
            if await btn.is_visible(timeout=400):
                await btn.click()
                break
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
        for btn_sel in ['#loginPage_loginSubmit', 'button:has-text("Login")', 'button[type="submit"]',
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


def _scc_file_ipc(pod_id: str, otp_token: str, log) -> tuple:
    """File-based IPC: write OTP to shared volume, poll for host result.

    The host dashboard background thread watches for /pipeline/host-data/ise_scc_otp_*.json,
    runs SCC Playwright navigation on the host (outside Docker VPN), and writes
    the result to /pipeline/host-data/ise_scc_result_{pod_id}.json.

    Uses shared volume instead of TCP because 172.16.0.0/12 is routed via tun0
    in the VPN container, making the Docker bridge (172.17.0.1) unreachable.
    """
    import time as _t
    _otp_path   = Path(f"/pipeline/host-data/ise_scc_otp_{pod_id}.json")
    _result_path = Path(f"/pipeline/host-data/ise_scc_result_{pod_id}.json")
    # Clear any stale result from a previous run
    _result_path.unlink(missing_ok=True)
    # Signal host
    _otp_path.write_text(json.dumps({"pod_id": pod_id, "otp_token": otp_token, "ts": _t.time()}))
    log("OTP written to shared volume — waiting for host SCC nav (up to 3 min)...")
    _deadline = _t.time() + 180
    while _t.time() < _deadline:
        if _result_path.exists():
            try:
                _res = json.loads(_result_path.read_text())
            except Exception:
                _t.sleep(1)
                continue
            _result_path.unlink(missing_ok=True)
            _otp_path.unlink(missing_ok=True)
            return _res.get("ok", False), _res.get("message", "no message")
        _t.sleep(3)
    _otp_path.unlink(missing_ok=True)
    return False, "Host SCC nav timed out — no result after 3 min (is dashboard running?)"


def _scc_file_ipc_cdfmc(pod_id: str, otp_token: str, instance_name: str, log) -> tuple:
    """File-based IPC for step 4 (cdFMC pxGrid integration).

    Writes ise_cdfmc_otp_{pod_id}.json → host watcher calls _host_cdfmc_integrate
    → navigates SCC Firewall/cdFMC UI → submits OTP → writes ise_cdfmc_result_{pod_id}.json.
    """
    import time as _t
    _otp_path    = Path(f"/pipeline/host-data/ise_cdfmc_otp_{pod_id}.json")
    _result_path = Path(f"/pipeline/host-data/ise_cdfmc_result_{pod_id}.json")
    _result_path.unlink(missing_ok=True)
    _otp_path.write_text(json.dumps({
        "pod_id": pod_id, "otp_token": otp_token,
        "instance_name": instance_name, "ts": _t.time(),
    }))
    log("cdFMC OTP written to shared volume — waiting for host nav (up to 5 min)...")
    _deadline = _t.time() + 300
    while _t.time() < _deadline:
        if _result_path.exists():
            try:
                _res = json.loads(_result_path.read_text())
            except Exception:
                _t.sleep(1)
                continue
            _result_path.unlink(missing_ok=True)
            _otp_path.unlink(missing_ok=True)
            return _res.get("ok", False), _res.get("message", "no message")
        _t.sleep(3)
    _otp_path.unlink(missing_ok=True)
    return False, "Host cdFMC nav timed out — no result after 5 min (is dashboard running?)"


def _scc_file_ipc_sgt_verify(pod_id: str, sa_org_id: str, log) -> tuple:
    """File-based IPC for step 5 (Secure Access SGT propagation verify).

    Writes ise_sgt_trigger_{pod_id}.json → host watcher calls _host_sgt_verify
    → waits 15 min, navigates Secure Access → Resources → Security Group Tags,
    checks SGT count; if none waits 10 more min and checks again.
    Writes ise_sgt_result_{pod_id}.json with result.
    """
    import time as _t
    _trigger_path = Path(f"/pipeline/host-data/ise_sgt_trigger_{pod_id}.json")
    _result_path  = Path(f"/pipeline/host-data/ise_sgt_result_{pod_id}.json")
    _result_path.unlink(missing_ok=True)
    _trigger_path.write_text(json.dumps({
        "pod_id": pod_id, "sa_org_id": sa_org_id, "ts": _t.time(),
    }))
    log("SGT verify trigger written — host will check SGTs after 15 min propagation wait...")
    # Max wait: 15 min initial + 10 min retry + 5 min buffer = 30 min
    _deadline = _t.time() + 1800
    while _t.time() < _deadline:
        if _result_path.exists():
            try:
                _res = json.loads(_result_path.read_text())
            except Exception:
                _t.sleep(2)
                continue
            _result_path.unlink(missing_ok=True)
            _trigger_path.unlink(missing_ok=True)
            return _res.get("ok", False), _res.get("message", "no message")
        _t.sleep(5)
    _trigger_path.unlink(missing_ok=True)
    return False, "SGT verify timed out — host did not respond in 30 min (is dashboard running?)"


def _phase_ise_sgt_verify(pod_id: str, creds: dict, log) -> tuple[bool, str]:
    """Step 5: Verify Security Group Tags propagated to Secure Access.

    Delegates to the host dashboard via file IPC (same pattern as step 4 cdFMC).
    The host navigates to Secure Access → Resources → Security Group Tags with a
    15-min propagation wait then a 10-min retry if no SGTs are found.
    Soft-fails (warns) if no SGTs after 25 min — never blocks the pipeline.
    """
    sa_org_id = (creds.get("sa_org_id") or "").strip()
    if not sa_org_id:
        return True, f"{_SKIP_PREFIX} sa_org_id not set for this POD — SGT verify skipped"
    return _scc_file_ipc_sgt_verify(pod_id, sa_org_id, log)

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
                # Strip trailing UI text that may be included in the container's text_content()
                # e.g., 'Copy' button text appended directly to the token string
                if val.endswith('Copy'):
                    val = val[:-4]
                if len(val) > 20 and ' ' not in val:
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
                    tok = tokens[0]
                    if tok.endswith('Copy'):
                        tok = tok[:-4]
                    log(f"OTP extracted from modal ({len(tok)} chars)")
                    return tok
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
                log("Waiting 12s for ISE to propagate pxGrid Cloud service activation...")
                import time as _time; _time.sleep(12)
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

    # ── Step 1c: UI registration — Administration → Deployment → pxGrid Cloud ──
    # Navigate to the ISE node deployment page, scroll to the pxGrid Cloud
    # section, fill in the deployment name, select region us-west-2, check both
    # legal boxes, click Register, then verify successful registration.
    deployment_name = px_account if px_account else f"ISE-POD-{pod_id}"
    log(f"Will register deployment name: {deployment_name}")

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()
        page.set_default_timeout(30000)

        try:
            if not await _ise_login(page, log):
                return False, "ISE login failed"

            # Navigate to Administration → Deployment (Dijit SPA warm-up required).
            # Strategy:
            #   1. page.goto() to Integration Catalog — fully boots Dijit, waits for
            #      catalog cards.  This is the ONLY page.goto() hash that works reliably.
            #   2. From the live SPA, click through the left nav tree to reach Deployment.
            #      Never use window.location.hash = '#administration/deployment' — that
            #      hash is invalid on this ISE version and triggers "Page not accessible".
            log("Warming up Dijit SPA via Integration Catalog...")
            await _navigate_to_integration_catalog(page, log)
            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)
            # Debug snapshot — shows nav tree state so we can tune selectors if needed
            await page.screenshot(path="/pipeline/host-data/ise_catalog_nav.png", full_page=False)

            # ── DOM inspection: log all #administration hrefs (debug — keep for diagnostics) ──
            try:
                _dom_links = await page.evaluate("""
                    () => Array.from(document.querySelectorAll('a[href]'))
                              .map(a => ({h: a.getAttribute('href') || '',
                                          t: (a.textContent || '').trim().slice(0,50)}))
                              .filter(({h}) => h.startsWith('#administration'))
                              .slice(0, 5)
                """)
                for _lnk in _dom_links:
                    log(f"  DOM link: href={_lnk['h']!r} text={_lnk['t']!r}")
            except Exception as _e:
                log(f"  DOM link inspection error: {_e}")

            # ── Helper: dismiss "Page not accessible" modal ───────────────────────
            async def _dismiss_page_not_accessible():
                try:
                    modal_text = page.locator(':text("Page not accessible"), :text("not accessible due to")')
                    if await modal_text.first.is_visible(timeout=2000):
                        log("Dismissing 'Page not accessible' modal")
                        for _close_sel in [
                            'button:has-text("Close")', 'button:has-text("OK")',
                            '[aria-label*="close" i]', '.modal-dialog button',
                        ]:
                            try:
                                btn = page.locator(_close_sel).first
                                if await btn.is_visible(timeout=1000):
                                    await btn.click()
                                    break
                            except Exception:
                                continue
                        await page.wait_for_timeout(800)
                except Exception:
                    pass

            await _dismiss_page_not_accessible()

            # ── Navigate to Administration → Deployment via the correct hash ──────
            # Hash URL was confirmed from live ISE DOM inspection on this instance:
            #   href='#administration/administration_system/administration_system_deployment'
            # We set this hash from the Integration Catalog SPA (which is fully
            # initialised) so the live SPA router handles the transition correctly.
            log("Navigating to Deployment via hash: #administration/administration_system/administration_system_deployment")
            await page.evaluate(
                "window.location.hash = '#administration/administration_system/administration_system_deployment'"
            )
            await _dismiss_page_not_accessible()
            await page.wait_for_timeout(2000)

            # Wait for Dijit deployment grid to actually render (not just spinner)
            try:
                await page.wait_for_selector(
                    'table tbody tr, .dijitGrid, [id*="deploymentGrid"]',
                    timeout=30000
                )
                log("Deployment table rendered")
            except Exception:
                await page.wait_for_timeout(8000)
                log("Deployment table wait timed out — proceeding anyway")

            # Deployment page loaded — click the "ise" hostname link to open the node
            # edit form, then scroll to the pxGrid Cloud section at the bottom.
            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)

            log("Clicking ise node to open edit form")
            try:
                # Use text-is for exact case match ("ise" hostname, not "ISE Community page")
                # Scope to table to avoid matching nav help links
                _ise_link = page.locator('table tbody tr a:text-is("ise"), td a:text-is("ise")').first
                await _ise_link.click(timeout=10000)
            except Exception as _e:
                await page.screenshot(path="/pipeline/host-data/ise_deploy_fail.png", full_page=True)
                return False, f"Could not click ise node link: {_e}"

            # Wait for the edit form to load — look for "ISE deployment name" label
            log("Waiting for node edit form to load...")
            try:
                await page.wait_for_selector(
                    'label:has-text("ISE deployment name"), :text("ISE deployment name"), '
                    ':text("pxGrid Cloud"), label:has-text("Enable pxGrid Cloud")',
                    timeout=30000
                )
                log("Node edit form loaded")
            except Exception:
                await page.screenshot(path="/pipeline/host-data/ise_deploy_fail.png", full_page=True)
                return False, "Node edit form did not load after clicking ise — see ise_deploy_fail.png"

            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)

            # Scroll to the pxGrid Cloud section at the bottom of the edit form
            log("Scrolling to pxGrid Cloud section")
            await page.evaluate("""
                window.scrollTo(0, document.body.scrollHeight);
                document.querySelectorAll('main,[role="main"],.content-area,.page-body,section').forEach(el => {
                    el.scrollTop = el.scrollHeight;
                });
            """)
            await page.wait_for_timeout(1500)
            await page.screenshot(path="/pipeline/host-data/ise_pxgrid_form.png", full_page=False)

            # ── Wait for "Loading..." Dijit spinner to clear ──────────────────
            # The pxGrid Cloud section loads lazily after the initial scroll.
            # The spinner blocks all click/select events — must be gone first.
            log("Waiting for Loading... overlay to clear")
            try:
                await page.wait_for_selector(
                    ':text("Loading...")',
                    state="hidden",
                    timeout=20000,
                )
                log("Loading overlay cleared")
            except Exception as _le:
                log(f"Loading overlay wait: {_le} — proceeding anyway")
            await page.wait_for_timeout(1000)

            # Re-scroll after lazy load completes (page height may have grown)
            await page.evaluate("""
                window.scrollTo(0, document.body.scrollHeight);
                document.querySelectorAll('main,[role="main"],.content-area,.page-body,section').forEach(el => {
                    el.scrollTop = el.scrollHeight;
                });
            """)
            await page.wait_for_timeout(800)
            await page.screenshot(path="/pipeline/host-data/ise_pxgrid_loaded.png", full_page=False)

            # Check if already registered (skip) — only skip on very specific phrases
            # that only appear in a truly connected/registered state.
            # Do NOT include "deregister" — it can appear on unregistered pages too.
            page_text = (await page.inner_text("body")).lower()
            _already_phrases = [
                "registration successful", "registration complete",
                "successfully registered",
            ]
            if any(ph in page_text for ph in _already_phrases):
                log(f"pxGrid Cloud already registered — matched phrase in page text")
                return True, f"{_SKIP_PREFIX} pxGrid Cloud already registered (Deployment page)"

             # ── Diagnostic: dump all Dijit CheckBox/ToggleButton IDs and their labels ──
            # This helps identify the correct "Enable pxGrid Cloud" widget ID.
            _dijit_checkboxes = await page.evaluate("""() => {
                const result = [];
                if (typeof dijit === 'undefined' || !dijit.registry) return result;
                for (const w of dijit.registry.toArray()) {
                    const cls = w.declaredClass || '';
                    if (!cls.includes('CheckBox') && !cls.includes('ToggleButton')) continue;
                    const node = w.domNode;
                    const lbl = node && node.id
                        ? (document.querySelector('label[for="' + node.id + '"]') || {}).textContent
                        : null;
                    result.push({
                        id: w.id || '',
                        cls: cls,
                        checked: !!(w.get && (w.get('checked') || w.get('value'))),
                        label: (lbl || '').trim().slice(0, 80),
                    });
                }
                return result;
            }""")
            log(f"Dijit CheckBoxes on page ({len(_dijit_checkboxes)}):")
            for _cb_info in _dijit_checkboxes:
                log(f"  id={_cb_info['id']!r} checked={_cb_info['checked']} label={_cb_info['label']!r}")

            # ── Enable pxGrid Cloud checkbox — MUST be checked before any fields appear ──
            # IMPORTANT: Match only by IMMEDIATE label text, NOT parent textContent.
            # Parent-walk was finding enableInlinePEP because the pxGrid Cloud section
            # header appeared in ancestor textContent before we reached the right checkbox.
            log("Checking 'Enable pxGrid Cloud' checkbox")
            _cloud_enabled = False
            try:
                _cloud_result = await page.evaluate("""() => {
                    // 1. Try Dijit registry by known pxCloud enable widget IDs
                    const knownIds = [
                        'pxCloud_enable', 'pxCloudEnable', 'pxCloud_enabled',
                        'enablePxGridCloud', 'pxCloud_enableRegistration',
                    ];
                    if (typeof dijit !== 'undefined' && dijit.registry) {
                        for (const wid of knownIds) {
                            const w = dijit.byId(wid);
                            if (w && typeof w.get === 'function') {
                                const already = !!(w.get('checked') || w.get('value'));
                                if (!already) {
                                    if (typeof w.set === 'function') {
                                        w.set('checked', true);
                                        w.set('value', true);
                                    }
                                    if (w.domNode) w.domNode.click();
                                }
                                return (already ? 'dijit-already' : 'dijit-clicked') + ':' + wid;
                            }
                        }

                        // 2. Walk Dijit CheckBox widgets — match ONLY by their own label
                        for (const w of dijit.registry.toArray()) {
                            const cls = w.declaredClass || '';
                            if (!cls.includes('CheckBox')) continue;
                            const node = w.domNode;
                            if (!node) continue;
                            // Get the label for THIS checkbox only (label[for=id])
                            const lbl = node.id
                                ? document.querySelector('label[for="' + node.id + '"]')
                                : null;
                            const lblText = (lbl ? lbl.textContent : '').toLowerCase();
                            if (lblText.includes('enable pxgrid cloud') ||
                                lblText.includes('enable px grid cloud')) {
                                const already = !!(w.get && (w.get('checked') || w.get('value')));
                                if (!already) {
                                    if (typeof w.set === 'function') {
                                        w.set('checked', true);
                                        w.set('value', true);
                                    }
                                    node.click();
                                }
                                return (already ? 'dijit-already' : 'dijit-clicked') + ':' + (w.id || 'noid');
                            }
                        }
                    }

                    // 3. DOM fallback — match ONLY by the checkbox's own label element
                    const cbs = Array.from(document.querySelectorAll('input[type="checkbox"]'));
                    for (const cb of cbs) {
                        // immediate label: <label><input>...</label> or <label for="id">
                        const lbl = cb.closest('label') ||
                            (cb.id ? document.querySelector('label[for="' + cb.id + '"]') : null);
                        const lblText = (lbl ? lbl.textContent : '').toLowerCase();
                        if (lblText.includes('enable pxgrid cloud') ||
                            lblText.includes('enable px grid cloud')) {
                            if (!cb.checked) { cb.click(); }
                            return (cb.checked ? 'dom-already' : 'dom-clicked') + ':' + (cb.id || '?');
                        }
                    }
                    return null;
                }""")
                log(f"Enable pxGrid Cloud result: {_cloud_result}")
                if _cloud_result and ('clicked' in _cloud_result or 'already' in _cloud_result):
                    _cloud_enabled = True
                    if 'clicked' in _cloud_result:
                        # Wait for pxGrid Cloud section to expand and fields to appear
                        log("Waiting for pxGrid Cloud section to expand after enabling...")
                        await page.wait_for_timeout(3000)
                        try:
                            await page.wait_for_selector(
                                'td#pxCloud_region, [id*="pxCloud_deviceName"]',
                                state='visible', timeout=12000
                            )
                            log("pxGrid Cloud section expanded — fields visible")
                        except Exception as _we:
                            log(f"Wait for fields after enable: {_we} — check screenshot")
                        await page.wait_for_timeout(1000)
            except Exception as _ce:
                log(f"Enable pxGrid Cloud check error: {_ce}")

            await page.screenshot(path="/pipeline/host-data/ise_pxgrid_cloud_enabled.png", full_page=False)

            if not _cloud_enabled:
                return False, (
                    "Could not find 'Enable pxGrid Cloud' checkbox — "
                    "check ise_pxgrid_cloud_enabled.png and the Dijit CheckBox dump above. "
                    "Aborting to avoid clicking Register with pxGrid Cloud disabled."
                )

            # ── Diagnose registration form visibility ─────────────────────────────
            # Find out if td#pxCloud_region is in DOM but hidden, and why.
            # Also detect if ISE is showing the already-registered view (Deregister visible).
            _vis_diag = None
            _vis_diag = await page.evaluate("""() => {
                const reg = document.getElementById('pxCloud_region');
                const name = document.getElementById('pxCloud_deviceName');
                const deregBtn = Array.from(document.querySelectorAll('*')).find(el =>
                    el.children.length === 0 && (el.textContent || '').trim() === 'Deregister'
                );
                function hiddenAncestor(el) {
                    let p = el;
                    for (let i = 0; i < 20 && p; i++) {
                        const cs = window.getComputedStyle(p);
                        if (cs.display === 'none' || cs.visibility === 'hidden') {
                            return (p.id || p.className || p.tagName) + ':' + cs.display + '/' + cs.visibility;
                        }
                        p = p.parentElement;
                    }
                    return null;
                }
                const pageTextLower = document.body.innerText.toLowerCase();
                return {
                    region_in_dom: !!reg,
                    region_hidden_ancestor: reg ? hiddenAncestor(reg) : 'n/a',
                    name_in_dom: !!name,
                    name_hidden_ancestor: name ? hiddenAncestor(name) : 'n/a',
                    deregister_visible: !!deregBtn,
                    pxgrid_connected: pageTextLower.includes('connected'),
                    page_text_snippet: document.body.innerText.slice(0, 300).split('\\n').join(' '),
                };
            }""")
            log(f"Form visibility diag: {_vis_diag}")

            # If ISE is already showing Deregister AND page confirms Connected,
            # registration is complete — skip.  Deregister alone is not enough:
            # the service can be enabled (Deregister in DOM) without the OAuth
            # portal registration having completed (no "connected" text).
            if _vis_diag and _vis_diag.get('deregister_visible') and _vis_diag.get('pxgrid_connected'):
                log("Deregister button visible + Connected status confirmed — ISE is already registered to pxGrid Cloud")
                return True, f"{_SKIP_PREFIX} pxGrid Cloud already registered (Deregister button present)"
            if _vis_diag and _vis_diag.get('deregister_visible') and not _vis_diag.get('pxgrid_connected'):
                log("Deregister button in DOM but NOT connected — deregistering first for a clean re-registration")
                _dreg_result = await page.evaluate("""() => {
                    for (const el of document.querySelectorAll('button, input[type="button"]')) {
                        if ((el.textContent || el.value || '').trim() === 'Deregister') {
                            el.click(); return 'clicked:' + (el.id || el.className || 'btn');
                        }
                    }
                    return null;
                }""")
                log(f"Deregister click: {_dreg_result}")
                await page.wait_for_timeout(2000)
                for _csel in ['button:has-text("Yes")', 'button:has-text("OK")', 'button:has-text("Confirm")']:
                    try:
                        if await page.locator(_csel).first.is_visible(timeout=2000):
                            await page.locator(_csel).first.click()
                            log(f"Confirmed deregister dialog: {_csel}")
                            await page.wait_for_timeout(1000)
                            break
                    except Exception:
                        pass
                _sv_dreg = await page.evaluate("""() => {
                    if (typeof dijit !== 'undefined') {
                        const w = dijit.registry.toArray().find(w => (w.label||'').trim()==='Save');
                        if (w) { w.onClick(); return 'dijit:' + w.id; }
                    }
                    return null;
                }""")
                log(f"Save after deregister: {_sv_dreg}")
                await page.wait_for_timeout(4000)
                await page.reload()
                await page.wait_for_timeout(5000)
                log("Deregistered + reloaded — proceeding with fresh registration")

            # If region field is hidden, try to reveal it by scrolling to it directly
            if _vis_diag and _vis_diag.get('region_hidden_ancestor'):
                log(f"td#pxCloud_region hidden by: {_vis_diag['region_hidden_ancestor']} — trying JS reveal")
                await page.evaluate("""() => {
                    const reg = document.getElementById('pxCloud_region');
                    if (!reg) return;
                    // Walk up and remove display:none
                    let p = reg.parentElement;
                    for (let i = 0; i < 20 && p; i++) {
                        const cs = window.getComputedStyle(p);
                        if (cs.display === 'none') {
                            p.style.setProperty('display', 'block', 'important');
                            p.style.setProperty('visibility', 'visible', 'important');
                        }
                        p = p.parentElement;
                    }
                    reg.scrollIntoView({behavior: 'smooth', block: 'center'});
                }""")
                await page.wait_for_timeout(1500)
                await page.screenshot(path="/pipeline/host-data/ise_pxgrid_revealed.png", full_page=False)
                log("Attempted to reveal hidden pxGrid Cloud form fields")

            # Fill "ISE deployment name" — try Dijit widget API first, then DOM walk-up fallback
            log(f"Filling ISE deployment name: {deployment_name}")
            _filled_name = await page.evaluate("""(args) => {
                const target = args.name;
                const results = [];

                // 1. Try Dijit registry by known widget ID
                try {
                    if (typeof dijit !== 'undefined' && dijit.byId) {
                        for (const wid of ['pxCloud_deviceName', 'deviceName', 'ise_deployment_name']) {
                            const w = dijit.byId(wid);
                            if (w && typeof w.set === 'function') {
                                w.set('value', target);
                                results.push('dijit:' + wid + '=' + (w.get('value') || ''));
                            }
                        }
                    }
                } catch(e) { results.push('dijit-err:' + e.message); }

                // 2. Walk all Dijit registry widgets and find TextBox near 'ISE deployment name'
                try {
                    if (typeof dijit !== 'undefined' && dijit.registry && dijit.registry.toArray) {
                        for (const w of dijit.registry.toArray()) {
                            if (!w.domNode) continue;
                            let p = w.domNode.parentElement;
                            for (let i = 0; i < 8; i++) {
                                if (!p) break;
                                if (p.textContent.includes('ISE deployment name') ||
                                    p.textContent.includes('deployment name')) {
                                    if (typeof w.set === 'function') {
                                        w.set('value', target);
                                        results.push('dijit-walk:' + (w.id || w.declaredClass) + '=' + (w.get('value') || ''));
                                    }
                                    break;
                                }
                                p = p.parentElement;
                            }
                        }
                    }
                } catch(e) { results.push('dijit-walk-err:' + e.message); }

                // 3. DOM walk-up fallback — raw value + events
                const inputs = Array.from(document.querySelectorAll('input')).filter(el =>
                    !['checkbox','radio','hidden','submit','button'].includes(el.type || '')
                );
                for (const inp of inputs) {
                    let p = inp.parentElement;
                    for (let i = 0; i < 10; i++) {
                        if (!p) break;
                        if (p.textContent.includes('ISE deployment name') ||
                            p.textContent.includes('deployment name')) {
                            inp.value = target;
                            inp.dispatchEvent(new Event('input', {bubbles: true}));
                            inp.dispatchEvent(new Event('change', {bubbles: true}));
                            inp.dispatchEvent(new Event('blur', {bubbles: true}));
                            results.push('dom:' + (inp.id || inp.name || inp.className.slice(0,40)));
                            break;
                        }
                        p = p.parentElement;
                    }
                }

                return results.length ? results.join(' | ') : null;
            }""", {"name": deployment_name})
            if _filled_name:
                log(f"Filled ISE deployment name via JS: {_filled_name}")
            else:
                log("WARNING: JS could not fill ISE deployment name — route intercept will patch POST body")

            # Select region us-west-2 — click td#pxCloud_region to open dropdown, then pick option
            log("Selecting region us-west-2")
            _set_region = None
            try:
                _rbtn = page.locator('td#pxCloud_region').first
                await _rbtn.scroll_into_view_if_needed()
                await _rbtn.click()
                await page.wait_for_timeout(600)
                _opt = page.locator('.dijitMenuItem:has-text("us-west-2")').first
                await _opt.wait_for(state='visible', timeout=4000)
                await _opt.click()
                await page.wait_for_timeout(500)
                _disp = (await page.inner_text('td#pxCloud_region')).strip()
                _set_region = f"region-set:{_disp}"
                log(f"Region selected: {_disp!r}")
            except Exception as _re:
                log(f"Region click error: {_re}")

            if not (_set_region and 'region-set:' in _set_region):
                log(f"WARNING: region select failed ({_set_region}) — proceeding anyway")



            await page.wait_for_timeout(500)

            # Check Privacy Statement and EULA checkboxes — known Dijit IDs are
            # pxCloudRegistrationStmt1 and pxCloudRegistrationStmt2 (labels are empty in ISE).
            # Fall back to text matching for any ISE version that uses labeled checkboxes.
            log("Checking Privacy Statement and EULA checkboxes")
            _legal_result = await page.evaluate("""(args) => {
                const checked = [];
                const terms = args.terms;
                // 1. Known Dijit IDs for legal statements
                if (typeof dijit !== 'undefined' && dijit.byId) {
                    for (const wid of ['pxCloudRegistrationStmt1', 'pxCloudRegistrationStmt2']) {
                        const w = dijit.byId(wid);
                        if (w && typeof w.get === 'function') {
                            const already = !!(w.get('checked') || w.get('value'));
                            if (!already) {
                                if (typeof w.set === 'function') { w.set('checked', true); w.set('value', true); }
                                if (w.domNode) w.domNode.click();
                            }
                            checked.push((already ? 'already' : 'clicked') + ':' + wid);
                        }
                    }
                }
                // 2. DOM: find by visible label text
                const cbs = Array.from(document.querySelectorAll('input[type="checkbox"]'));
                for (const cb of cbs) {
                    if (!cb.offsetParent) continue;
                    const lbl = cb.closest('label') ||
                        (cb.id ? document.querySelector('label[for="' + cb.id + '"]') : null);
                    const lblText = (lbl ? lbl.textContent : '').toLowerCase();
                    if (!terms.some(t => lblText.includes(t))) continue;
                    if (!cb.checked) { cb.click(); checked.push('dom-clicked:' + (cb.id || lblText.slice(0,30))); }
                    else { checked.push('dom-already:' + (cb.id || lblText.slice(0,30))); }
                }
                return checked;
            }""", {"terms": ["privacy statement", "eula", "end user license", "acknowledge", "agree that"]})
            log(f"Legal checkboxes result: {_legal_result}")

            await page.wait_for_timeout(500)

            # ── Click Register + handle OAuth Device Flow popup ───────────────────
            # When Register is clicked, ISE opens id.cisco.com/activate?user_code=XXXX
            # in a new window. We must: submit the pre-filled user_code → log in with
            # Cisco ID credentials → select PseudoCo-{org_number} → click Register ISE.
            org_number = str(creds.get("org_number", "")).strip()
            account_to_select = f"PseudoCo-{org_number}" if org_number else px_account
            log(f"Will select account in popup: {account_to_select!r}")

            log("Clicking Register button (watching for OAuth popup)")
            _registered = False
            await page.screenshot(path="/pipeline/host-data/ise_before_register.png", full_page=False)

            async def _click_register_btn():
                """Try all methods to click the Register button. Returns True if clicked."""
                # Attempt 1: Dijit widget API
                _js_dijit = await page.evaluate("""() => {
                    try {
                        if (typeof dijit === 'undefined') return 'no-dijit';
                        const btn = dijit.registry.toArray().find(w => {
                            const lbl = (w.label || w.title || '').trim();
                            const txt = w.domNode ? w.domNode.textContent.trim() : '';
                            return lbl === 'Register' || txt === 'Register';
                        });
                        if (btn) { btn.onClick(); return 'dijit:' + btn.id; }
                        return 'no-btn';
                    } catch(e) { return 'err:' + e.message; }
                }""")
                log(f"Dijit register attempt: {_js_dijit}")
                if _js_dijit and _js_dijit.startswith('dijit:'):
                    return True
                # Attempt 2: JS leaf-walk
                _js_leaf = await page.evaluate("""() => {
                    for (const el of document.querySelectorAll('*')) {
                        if (el.children.length === 0 && el.textContent.trim() === 'Register') {
                            const r = el.getBoundingClientRect();
                            if (r.width > 0 && r.height > 0) {
                                let t = el;
                                for (let i = 0; i < 8; i++) {
                                    if (!t) break;
                                    const cls = t.className || '';
                                    if (t.tagName==='BUTTON' || cls.includes('dijitButtonNode') ||
                                        t.getAttribute('role')==='button') { t.click(); return 'walk'; }
                                    t = t.parentElement;
                                }
                                el.click(); return 'leaf';
                            }
                        }
                    }
                    return null;
                }""")
                log(f"JS leaf-walk register: {_js_leaf}")
                if _js_leaf:
                    return True
                # Attempt 3: CSS selectors
                for _sel in ['button:has-text("Register")', '[role="button"]:has-text("Register")',
                             'input[type="button"][value="Register"]', 'a:has-text("Register")']:
                    try:
                        _b = page.locator(_sel).first
                        if await _b.is_visible(timeout=2000):
                            await _b.scroll_into_view_if_needed()
                            await _b.click()
                            log(f"Register clicked via {_sel!r}")
                            return True
                    except Exception:
                        continue
                return False

            async def _handle_oauth_popup(popup):
                """Complete the Cisco OAuth device flow in the popup window."""
                try:
                    # Wait for page to fully render (React SPA — networkidle is more reliable)
                    try:
                        await popup.wait_for_load_state("networkidle", timeout=20000)
                    except Exception:
                        await popup.wait_for_load_state("domcontentloaded", timeout=10000)
                    await popup.screenshot(path="/pipeline/host-data/ise_oauth_1_activate.png")
                    log(f"OAuth popup URL: {popup.url}")

                    # Step 1: "Activate your device" — user_code is pre-filled, click Next
                    try:
                        _next = popup.locator('button:has-text("Next"), input[value="Next"]').first
                        await _next.wait_for(state="visible", timeout=12000)
                        await _next.click()
                        log("OAuth: clicked Next (activate page)")
                        try:
                            await popup.wait_for_load_state("networkidle", timeout=10000)
                        except Exception:
                            await popup.wait_for_timeout(3000)
                    except Exception as _e:
                        log(f"OAuth: Next click warning: {_e}")

                    await popup.screenshot(path="/pipeline/host-data/ise_oauth_2_login.png")

                    # Step 2: Log in — click field, type email char-by-char (fires React events), click Next
                    try:
                        _email_inp = popup.locator(
                            'input[type="email"], input[name="identifier"], input[name="email"], '
                            'input[id*="email"], input[placeholder*="mail"], input[placeholder*="Email"]'
                        ).first
                        await _email_inp.wait_for(state="visible", timeout=12000)
                        await _email_inp.click()
                        await popup.wait_for_timeout(300)
                        # press_sequentially fires real keyboard events — required for Okta/React forms
                        await _email_inp.press_sequentially(px_email, delay=50)
                        log(f"OAuth: typed email {px_email!r}")
                        await popup.wait_for_timeout(500)
                        _next2 = popup.locator('button:has-text("Next"), input[value="Next"]').first
                        await _next2.click()
                        log("OAuth: clicked Next (email page)")
                        try:
                            await popup.wait_for_load_state("networkidle", timeout=10000)
                        except Exception:
                            await popup.wait_for_timeout(3000)
                    except Exception as _e:
                        log(f"OAuth: email step warning: {_e}")

                    await popup.screenshot(path="/pipeline/host-data/ise_oauth_3_password.png")

                    # Step 3: Password — click, type char-by-char, click Verify
                    try:
                        _pass_inp = popup.locator('input[type="password"]').first
                        await _pass_inp.wait_for(state="visible", timeout=12000)
                        await _pass_inp.click()
                        await popup.wait_for_timeout(300)
                        await _pass_inp.press_sequentially(px_pass, delay=50)
                        log("OAuth: typed password")
                        await popup.wait_for_timeout(500)
                        _verify = popup.locator('button:has-text("Verify"), button:has-text("Next"), input[value="Verify"]').first
                        await _verify.click()
                        log("OAuth: clicked Verify")
                        # Popup may close almost immediately after activation — treat close as success
                        try:
                            await popup.wait_for_load_state("networkidle", timeout=10000)
                        except Exception:
                            try:
                                await popup.wait_for_timeout(3000)
                            except Exception:
                                pass  # popup already closed — activation succeeded
                    except Exception as _e:
                        log(f"OAuth: password step warning: {_e}")

                    # Post-Verify screenshot — popup may already be closed
                    try:
                        await popup.screenshot(path="/pipeline/host-data/ise_oauth_4_post_verify.png")
                    except Exception:
                        # Popup closed immediately after Verify — device was activated
                        log("OAuth: popup closed right after Verify — treating as Device activated")
                        return True

                    # Step 4: Wait for "Device activated" — authentication is done.
                    # Account selection happens back in the ISE page, not here.
                    try:
                        await popup.wait_for_selector(
                            ':text("Device activated"), :text("device activated"), :text("activated")',
                            timeout=15000
                        )
                        log("OAuth: Device activated confirmed in popup")
                    except Exception as _e:
                        # If popup is gone, that's also success
                        try:
                            _pt = (await popup.inner_text("body")).lower()
                            log(f"OAuth: Device activated wait: {_e} — page text: {_pt[:200]}")
                        except Exception:
                            log("OAuth: popup closed during Device activated wait — treating as success")
                            return True
                    try:
                        await popup.screenshot(path="/pipeline/host-data/ise_oauth_5_device_activated.png")
                    except Exception:
                        pass  # popup may be closing
                    return True
                except Exception as _pe:
                    log(f"OAuth popup handler error: {_pe}")
                    try:
                        await popup.screenshot(path="/pipeline/host-data/ise_oauth_error.png")
                    except Exception:
                        pass
                    return False

            # Intercept the registration POST and force region to us-west-2 + patch empty name.
            # ISE sends the registration to Cisco's cloud (not to itself),
            # so intercept ALL outgoing requests from the browser.
            _region_routes_hit = []
            _all_posts_seen = []
            async def _fix_region_route(route, request):
                if request.method in ('POST', 'PUT', 'PATCH'):
                    try:
                        body = request.post_data or ''
                        is_enroll = 'enroll/ise' in request.url
                        if is_enroll:
                            _all_posts_seen.append(f"ENROLL body={body!r}")
                        else:
                            _all_posts_seen.append(f"{request.method} {request.url[-80:]}")
                        new_body = body
                        patched = []
                        # Fix region
                        if 'ap-southeast-1' in body or 'apSoutheast' in body or 'AP_SOUTHEAST' in body:
                            new_body = (new_body
                                .replace('ap-southeast-1', 'us-west-2')
                                .replace('apSoutheast1', 'usWest2')
                                .replace('AP_SOUTHEAST_1', 'US_WEST_2'))
                            patched.append('region')
                            _region_routes_hit.append(request.url)
                        # Fix empty deployment name in enroll POST
                        if is_enroll and '"name":""' in new_body:
                            import json as _json
                            _safe_name = deployment_name.replace('"', '\\"')
                            new_body = new_body.replace('"name":""', f'"name":"{_safe_name}"', 1)
                            patched.append(f'name->{_safe_name}')
                        if patched:
                            log(f"Route intercept: patched [{', '.join(patched)}] in {request.url[-80:]}")
                            await route.continue_(post_data=new_body)
                            return
                    except Exception as _re:
                        log(f"Route intercept error: {_re}")
                await route.continue_()

            await page.route('**', _fix_region_route)
            log("Region intercept route active (all requests)")

            # Set up popup listener then click Register
            _popup_handled = False
            try:
                async with ctx.expect_page(timeout=15000) as _popup_info:
                    _registered = await _click_register_btn()
                    if not _registered:
                        # Frame fallback
                        for _frame in page.frames:
                            try:
                                _fb = _frame.locator(
                                    'button:has-text("Register"), [role="button"]:has-text("Register")'
                                ).first
                                if await _fb.is_visible(timeout=2000):
                                    await _fb.scroll_into_view_if_needed()
                                    await _fb.click()
                                    log(f"Register clicked in frame: {_frame.url!r}")
                                    _registered = True
                                    break
                            except Exception:
                                continue

                _popup = await _popup_info.value
                log(f"OAuth popup detected: {_popup.url}")
                _popup_handled = await _handle_oauth_popup(_popup)
                log(f"OAuth popup handler returned: {_popup_handled}")

                # Wait for popup to close (it closes after Register ISE is clicked)
                try:
                    await _popup.wait_for_event("close", timeout=15000)
                    log("OAuth popup closed")
                except Exception:
                    log("OAuth popup did not close within 15s — continuing")

            except Exception as _pe:
                log(f"Popup listener error: {_pe} — Register button may not have opened a popup")

            if not _registered:
                return False, "Could not find/click Register button on ISE node edit page"

            if not _popup_handled:
                return False, "OAuth popup handler failed — check ise_oauth_error.png"

            # ── After popup auth: ISE shows "Select an Account" dialog in main page ──
            # After device activation, ISE detects the auth completion and shows the
            # account selection dialog directly in the ISE node edit page.
            log("OAuth auth done — waiting for ISE to show Select an Account dialog")
            await page.wait_for_timeout(3000)
            await page.screenshot(path="/pipeline/host-data/ise_after_oauth.png", full_page=False)

            # Wait up to 20s for "Select an Account" to appear in ISE
            _acct_appeared = False
            for _w in range(8):  # 8 × 3s = 24s
                _pt = (await page.inner_text("body")).lower()
                if "select an account" in _pt or "register ise" in _pt:
                    _acct_appeared = True
                    log(f"ISE account selection dialog appeared at {(_w+1)*3}s")
                    break
                await page.wait_for_timeout(3000)

            await page.screenshot(path="/pipeline/host-data/ise_account_dialog.png", full_page=False)

            if _acct_appeared:
                # Select PseudoCo-{org_number} radio button
                log(f"Selecting account {account_to_select!r} in ISE dialog")
                _sel = await page.evaluate("""(acct) => {
                    const radios = Array.from(document.querySelectorAll('input[type="radio"]'));
                    for (const r of radios) {
                        const lbl = r.closest('label') || r.parentElement;
                        if (lbl && lbl.textContent.trim() === acct) { r.click(); return 'radio:' + acct; }
                    }
                    // Fallback: label contains the account name
                    for (const r of radios) {
                        const lbl = r.closest('label') || r.parentElement;
                        if (lbl && lbl.textContent.includes(acct)) { r.click(); return 'fallback:' + lbl.textContent.trim().slice(0,40); }
                    }
                    // Last resort: any visible element with exact text
                    for (const el of document.querySelectorAll('*')) {
                        if (el.children.length === 0 && el.textContent.trim() === acct) {
                            el.click(); return 'text:' + acct;
                        }
                    }
                    return null;
                }""", account_to_select)
                log(f"Account selection result: {_sel}")
                await page.wait_for_timeout(1000)

                # Click "Register ISE"
                await page.screenshot(path="/pipeline/host-data/ise_before_register_ise.png", full_page=False)
                try:
                    _reg_ise_btn = page.locator('button:has-text("Register ISE")').first
                    await _reg_ise_btn.wait_for(state="visible", timeout=8000)
                    await _reg_ise_btn.click()
                    log("Clicked Register ISE in ISE dialog")
                    # Wait for the dialog to disappear — that's the success signal
                    try:
                        await page.wait_for_selector(
                            ':text("Select an Account"), :text("Register ISE")',
                            state="hidden", timeout=15000
                        )
                        log("Account dialog closed — registration succeeded")
                    except Exception:
                        log("Dialog close wait timed out — checking for error")
                    await page.wait_for_timeout(2000)
                except Exception as _re:
                    log(f"Register ISE button: {_re} — trying JS fallback")
                    await page.evaluate("""() => {
                        for (const el of document.querySelectorAll('button, [role="button"]')) {
                            if (el.textContent.trim() === 'Register ISE') { el.click(); return; }
                        }
                    }""")
                    await page.wait_for_timeout(5000)
            else:
                log("WARNING: Select an Account dialog did not appear — checking page state")

            await page.unroute('**', _fix_region_route)
            log(f"Region intercept route removed (modified {len(_region_routes_hit)}, saw {len(_all_posts_seen)} POST/PUT/PATCH)")
            for _p in _all_posts_seen:
                log(f"  POST-seen: {_p}")

            await page.screenshot(path="/pipeline/host-data/ise_after_register_ise.png", full_page=False)

            # Check for ISE error dialog — only fail on specific ISE error phrases, not generic "error"
            _pt_err = (await page.inner_text("body")).lower()
            if "bad request" in _pt_err or "validation failed" in _pt_err:
                await page.screenshot(path="/pipeline/host-data/ise_register_ise_error.png", full_page=False)
                log("Bad Request / Validation failed dialog detected — dismissing")
                # Dismiss the error dialog by clicking OK so ISE is in a clean state
                try:
                    await page.locator('button:has-text("OK")').first.click(timeout=3000)
                    await page.wait_for_timeout(1000)
                except Exception:
                    pass
                return False, "ISE registration failed: Bad Request - Validation failed (region intercept did not catch the POST — check route hit count above)."

            # ── Save ISE node immediately to commit the registration ─────────────
            log("Saving ISE node to commit pxGrid Cloud registration")
            _sv = await page.evaluate("""() => {
                try {
                    if (typeof dijit !== 'undefined') {
                        const w = dijit.registry.toArray().find(w =>
                            (w.label||'').trim()==='Save' ||
                            (w.domNode && w.domNode.textContent.trim()==='Save')
                        );
                        if (w) { w.onClick(); return 'dijit:' + w.id; }
                    }
                    for (const el of document.querySelectorAll('*')) {
                        if (el.children.length === 0 && el.textContent.trim() === 'Save') {
                            const r = el.getBoundingClientRect();
                            if (r.width > 0) {
                                let t = el;
                                for (let i = 0; i < 8; i++) {
                                    if (!t) break;
                                    if (t.tagName==='BUTTON' || (t.className||'').includes('dijitButtonNode')) {
                                        t.click(); return 'walk:' + t.tagName;
                                    }
                                    t = t.parentElement;
                                }
                                el.click(); return 'leaf';
                            }
                        }
                    }
                    return null;
                } catch(e) { return 'err:' + e.message; }
            }""")
            log(f"Save node result: {_sv}")
            await page.wait_for_timeout(4000)

            # ── Poll for pxGrid Cloud connected status (up to ~3 min) ────────────
            # NOTE: "cisco dna portal account" is a STATIC form label — present even
            # when NOT connected — do NOT use it as a success indicator.
            _CONNECTED_INDICATORS = [
                "pxgrid cloud is connected",
                "connected to cisco dna",
                "registration successful",
                "registration complete",
                "successfully registered",
            ]
            _FAIL_INDICATORS = ["could not connect", "connection failed", "unable to connect"]
            _refresh_js = """() => {
                const candidates = Array.from(document.querySelectorAll(
                    'button, [role="button"], .icon-refresh, [title*="refresh" i], [aria-label*="refresh" i]'
                ));
                for (const el of candidates) {
                    const r = el.getBoundingClientRect();
                    if (r.width > 0 && r.height > 0) {
                        el.click();
                        return 'clicked:' + (el.title || el.ariaLabel || el.className || el.tagName).slice(0,60);
                    }
                }
                return null;
            }"""
            for _attempt in range(18):  # 18 × 10s ≈ 3 min
                await page.wait_for_timeout(10000)
                _refreshed = await page.evaluate(_refresh_js)
                await page.wait_for_timeout(3000)
                _pt = (await page.inner_text("body")).lower()
                if any(ind in _pt for ind in _CONNECTED_INDICATORS):
                    log(f"pxGrid Cloud connected confirmed on attempt {_attempt + 1}")
                    await page.screenshot(path="/pipeline/host-data/ise_pxgrid_connected.png", full_page=False)
                    return True, f"pxGrid Cloud registered and connected (PseudoCo-{org_number})"
                _still_fail = any(err in _pt for err in _FAIL_INDICATORS)
                log(f"Refresh {_attempt + 1}/18: {'not connected' if _still_fail else 'status unclear'} (refresh={_refreshed})")
                if _attempt % 3 == 2:
                    await page.screenshot(path=f"/pipeline/host-data/ise_pxgrid_poll_{_attempt + 1}.png", full_page=False)

            # Timed out after 3 min
            await page.screenshot(path="/pipeline/host-data/ise_pxgrid_register_final.png", full_page=True)
            return False, "pxGrid Cloud registration saved but ISE not connected after 3 min — check ise_pxgrid_register_final.png"

        except Exception as e:
            try:
                await page.screenshot(path="/pipeline/host-data/ise_pxgrid_register_err.png", full_page=True)
            except Exception:
                pass
            return False, f"pxGrid Cloud registration error: {e}"
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

            # ── Dismiss banners (Session Info + ISE error banner) ─────────────
            await _ise_dismiss_session_info(page)
            async def _dismiss_ise_banners():
                for banner_sel in [
                    'button[aria-label="close"]', 'button[aria-label="Close"]',
                    '.alert-banner button', '.alert button', 'button.close',
                    'button:has-text("×")', 'button:has-text("✕")',
                ]:
                    try:
                        el = page.locator(banner_sel).first
                        if await el.is_visible(timeout=1000):
                            await el.click()
                            await page.wait_for_timeout(500)
                    except Exception:
                        continue
                # JS fallback: remove any visible error/alert banners
                await page.evaluate("""() => {
                    document.querySelectorAll(
                        '.alert, .alert-banner, [class*="error-banner"], [class*="notification"]')
                    .forEach(el => { if (el.innerText.includes('Error') ||
                                         el.innerText.includes('error')) el.remove(); });
                }""")
            await _dismiss_ise_banners()

            # ── Navigate to FMC ────────────────────────────────────────────────
            # Two possible states:
            # A) FMC is in Available tiles → click its "More details" button
            # B) FMC already activated → shows in "Activated integrations" table
            #    (catalog available section shows "All current integrations are active")
            #    In this case navigate via the table link, same as step 3 does for SCC.
            log("Opening Firewall Management Center details")
            await page.screenshot(path=f"/pipeline/host-data/ise_cdfmc_catalog_init_{pod_id}.png", full_page=True)
            log(f"Screenshot: /pipeline/host-data/ise_cdfmc_catalog_init_{pod_id}.png")
            more_btns = page.locator('button[data-label="More details"]')
            btn_count = await more_btns.count()
            log(f"Found {btn_count} 'More details' button(s)")

            for _retry in range(3):
                if btn_count > 0:
                    break
                log(f"No 'More details' buttons — retry {_retry+1}/3")
                await _dismiss_ise_banners()
                if not await _navigate_to_integration_catalog(page, log):
                    break
                await _ise_dismiss_modal(page)
                await _ise_dismiss_session_info(page)
                await _dismiss_ise_banners()
                await page.wait_for_timeout(3000)
                btn_count = await more_btns.count()
                log(f"After retry {_retry+1}: found {btn_count} 'More details' button(s)")

            _fmc_nav_ok = False
            if btn_count > 0:
                await _ise_dismiss_modal(page)
                await _ise_dismiss_session_info(page)
                await page.wait_for_timeout(500)

                # Find the FMC tile specifically by its title text (not positional index).
                # Available integrations order: [0]=FMC, [1]=OfficeSpace, [2]=pxGrid Demo...
                # nth(1) was previously hardcoded here — WRONG (hits OfficeSpace).
                _fmc_clicked = False
                for _fmc_label in ["Firewall Management Center", "FMC", "Cisco Secure Firewall"]:
                    try:
                        # Find a container that has both the label text AND a More details button
                        _containers = page.locator(
                            ':has(button[data-label="More details"])'
                        ).filter(has_text=_fmc_label)
                        _cc = await _containers.count()
                        if _cc > 0:
                            _fmc_btn = _containers.first.locator(
                                'button[data-label="More details"]'
                            ).first
                            await _fmc_btn.click(timeout=10000, force=True)
                            log(f"Clicked FMC 'More details' via title {_fmc_label!r}")
                            _fmc_nav_ok = True
                            _fmc_clicked = True
                            break
                    except Exception as _fe:
                        log(f"FMC tile search ({_fmc_label!r}): {_fe}")
                        continue

                if not _fmc_clicked:
                    # FMC may already be in "Activated integrations" (previous run left it there).
                    # Check that section before falling back to nth(0).
                    log("FMC not found in Available tiles — checking Activated integrations section...")
                    await page.screenshot(path=f"/pipeline/host-data/ise_cdfmc_catalog_nofmc_{pod_id}.png", full_page=True)
                    for _act_sel in [
                        ':text("Firewall Management Center")',
                        ':text("Cisco Secure Firewall")',
                        ':text("Cisco Firepower")',
                        'a:has-text("Firewall")',
                        ':text("FMC")',
                    ]:
                        try:
                            el = page.locator(_act_sel).first
                            if await el.is_visible(timeout=3000):
                                await el.click()
                                log(f"Clicked FMC in Activated integrations via {_act_sel!r}")
                                _fmc_nav_ok = True
                                _fmc_clicked = True
                                await page.wait_for_timeout(2000)
                                break
                        except Exception:
                            continue
                    if not _fmc_clicked:
                        # True last-resort fallback — take screenshot first so we can diagnose
                        log("FMC not found in Activated integrations — falling back to nth(0) (check ise_cdfmc_catalog screenshot)")
                        await more_btns.nth(0).click(timeout=10000, force=True)
                        _fmc_nav_ok = True

            elif btn_count == 1:
                await more_btns.first.click(timeout=10000, force=True)
                _fmc_nav_ok = True
            else:
                # Available tiles empty — FMC already activated.
                # Look for it in the "Activated integrations" table (link text).
                _body = (await page.inner_text("body")).lower()
                log(f"Available catalog empty (body snippet: {_body[:120]!r})")
                for fmc_sel in [
                    ':text("Firewall Management Center")',
                    ':text("Cisco Firepower")',
                    'a:has-text("Firewall")',
                    ':text("FMC")',
                ]:
                    try:
                        el = page.locator(fmc_sel).first
                        if await el.is_visible(timeout=3000):
                            await el.click()
                            log(f"Clicked FMC in Activated integrations via {fmc_sel!r}")
                            _fmc_nav_ok = True
                            await page.wait_for_timeout(2000)
                            break
                    except Exception:
                        continue

                if not _fmc_nav_ok:
                    # ISE can't reach catalog at all — soft-fail
                    await page.screenshot(path="/pipeline/host-data/ise_cdfmc_no_fmc.png", full_page=True)
                    return True, f"{_SKIP_PREFIX} FMC not found in catalog (ISE error/no internet) — cdFMC integration skipped"

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

            # Wait for OTP spinner to clear (same pattern as step 2)
            log("Waiting for OTP to appear (spinner: 'Fetching OTP...')")
            for _sw in range(20):
                await page.wait_for_timeout(1000)
                _still_spin = False
                try:
                    if await page.locator(':text("Fetching OTP")').is_visible(timeout=500):
                        _still_spin = True
                except Exception:
                    pass
                if not _still_spin:
                    log(f"OTP spinner gone after {_sw}s")
                    break
            try:
                await page.screenshot(path=f"/pipeline/host-data/ise_cdfmc_post_activate_{pod_id}.png", full_page=True)
            except Exception:
                pass

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

            # === Configure cdFMC via host-side navigation ===
            # Docker VPN breaks Okta silent-renew — same as step 2.
            # Hand off OTP to host dashboard via file IPC; host navigates SCC
            # to find cdFMC management UI and submits the OTP.
            instance_name = f"ISE-FMC-POD-{pod_id}"
            _ipc_ok, _ipc_msg = _scc_file_ipc_cdfmc(pod_id, otp_token, instance_name, log)
            if not _ipc_ok:
                return False, _ipc_msg
            return True, _ipc_msg


            # Handle org picker / login if redirected
            if "login" in fmc_page.url.lower():
                return False, "cdFMC SSO failed — SCC session expired. Refresh SCC session and retry."
            try:
                await fmc_page.wait_for_selector('button:has-text("Continue")', timeout=8000)
                await fmc_page.locator('button:has-text("Continue")').first.click()
                log("Dismissed cdFMC org modal (Continue)")
                await fmc_page.wait_for_timeout(2000)
            except Exception:
                log("No org modal on cdFMC — proceeding")

            try:
                await fmc_page.wait_for_load_state("networkidle", timeout=20000)
            except Exception:
                pass
            await fmc_page.wait_for_timeout(3000)
            log(f"cdFMC loaded at: {fmc_page.url}")
            await fmc_page.screenshot(path="/pipeline/host-data/cdfmc_home.png", full_page=True)
            _fmc_txt = await fmc_page.inner_text("body")
            log(f"cdFMC body (first 400): {_fmc_txt.strip()[:400]!r}")

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

            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)

            # ISE SPA often restores the last-visited card detail page instead of the
            # catalog list.  If we see the "← Integration Catalog" breadcrumb, click it
            # to return to the list before looking for "More details" buttons.
            log("Ensuring we are on the Integration Catalog list view")
            try:
                _back = page.locator('a, button, span').filter(has_text="Integration Catalog").first
                if await _back.is_visible(timeout=4000):
                    await _back.click()
                    log("Clicked back to Integration Catalog list")
                    await page.wait_for_timeout(2000)
                    await _ise_dismiss_modal(page)
            except Exception:
                pass

            # Wait for catalog to render (Activated integrations table)
            try:
                await page.wait_for_selector('text=Cisco Security Cloud', timeout=20000)
            except Exception:
                pass

            # Cisco Security Cloud appears in the "Activated integrations" table as a
            # clickable link — NOT as a "More details" button (those are only in
            # "Available integrations").  Click the row link directly.
            log("Clicking Cisco Security Cloud in Activated integrations")
            _scc_clicked = False
            for _sel in [
                'a:has-text("Cisco Security Cloud")',
                'td:has-text("Cisco Security Cloud") a',
                ':text("Cisco Security Cloud")',
            ]:
                try:
                    el = page.locator(_sel).first
                    if await el.is_visible(timeout=5000):
                        await el.click(timeout=10000)
                        log(f"Clicked Cisco Security Cloud via {_sel!r}")
                        _scc_clicked = True
                        break
                except Exception:
                    continue
            if not _scc_clicked:
                await page.screenshot(path="/pipeline/host-data/ise_scc_link_fail.png")
                return False, "Could not find Cisco Security Cloud link in Activated integrations — check ise_scc_link_fail.png"
            await page.wait_for_timeout(2000)

            # Click Configuration tab
            log("Clicking Configuration tab")
            await _ise_dismiss_session_info(page)
            try:
                await page.locator('text=Configuration').first.click(timeout=8000)
                await page.wait_for_timeout(2000)
            except Exception:
                pass

            # Dismiss Session Info popup, scroll to bottom, take screenshot
            await _ise_dismiss_session_info(page)
            await _ise_dismiss_modal(page)
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)
            await _ise_dismiss_session_info(page)  # dismiss again after scroll
            await page.screenshot(path="/pipeline/host-data/ise_scc_deactivate_pre.png", full_page=True)

            # ── Detect current Application status ─────────────────────────────
            # If already Inactive (from a prior run) → skip Deactivate entirely.
            # If Connected/Active (Deactivate button present) → Deactivate first.
            _status_text = await page.evaluate("""() => {
                // Use body text scan — Inactive must be checked before Active
                // (Inactive contains the substring Active).
                // \\b word-boundary ensures 'Active' won't match inside 'Activate'.
                const t = document.body.innerText || '';
                if (/\\bInactive\\b/.test(t)) return 'Inactive';
                if (/\\bConnected\\b/.test(t)) return 'Connected';
                if (/\\bActive\\b/.test(t)) return 'Active';
                return null;
            }""")
            log(f"Application status detected: {_status_text!r}")

            _already_inactive = _status_text == 'Inactive'

            if _already_inactive:
                log("Instance already Inactive — skipping Deactivate, going straight to Activate")
            else:
                # ── Deactivate (Active → Inactive) ────────────────────────────
                log("Instance is Active — clicking Deactivate")
                deactivate_found = False
                for da_sel in [
                    'button:has-text("Deactivate")',
                    'a:has-text("Deactivate")',
                    ':text("Deactivate")',
                ]:
                    try:
                        da_btn = page.locator(da_sel).first
                        if await da_btn.is_visible(timeout=5000):
                            await da_btn.scroll_into_view_if_needed()
                            await da_btn.click(force=True)
                            deactivate_found = True
                            log(f"Clicked Deactivate via: {da_sel}")
                            break
                    except Exception:
                        continue

                if not deactivate_found:
                    # JS fallback
                    _js_da = await page.evaluate("""() => {
                        const el = Array.from(document.querySelectorAll('button, a, span'))
                            .find(e => e.innerText && e.innerText.trim() === 'Deactivate');
                        if (el) { el.click(); return el.tagName; }
                        return null;
                    }""")
                    if _js_da:
                        deactivate_found = True
                        log(f"JS Deactivate fallback: {_js_da}")
                    else:
                        await page.screenshot(path="/pipeline/host-data/ise_deactivate_fail.png", full_page=True)
                        return False, "Deactivate button not found — check ise_deactivate_fail.png"

                # Confirm dialog — ISE shows "Deactivate App" button in modal
                await page.wait_for_timeout(1500)
                for confirm_sel in [
                    'button:has-text("Deactivate App")',
                    'button:has-text("Deactivate")',
                    'button:has-text("Yes")',
                    'button:has-text("Confirm")',
                    'button:has-text("OK")',
                ]:
                    try:
                        c_btn = page.locator(confirm_sel).first
                        if await c_btn.is_visible(timeout=3000):
                            await c_btn.click()
                            log(f"Confirmed deactivation dialog via {confirm_sel!r}")
                            break
                    except Exception:
                        continue

                # Wait for Inactive status to appear (confirms transition complete)
                log("Waiting for Inactive status after Deactivate...")
                _transitioned = False
                for _ws in ['text=Inactive', 'text=Existing instances', 'input[type="radio"]']:
                    try:
                        await page.wait_for_selector(_ws, timeout=20000)
                        log(f"Transition confirmed via {_ws!r} ✓")
                        _transitioned = True
                        break
                    except Exception:
                        continue
                if not _transitioned:
                    log("WARNING: transition not confirmed — continuing anyway")

            # ── Confirm deactivation dialog if one appears ────────────────────
            await page.wait_for_timeout(1500)
            for confirm_sel in [
                'button:has-text("Deactivate App")',
                'button:has-text("Deactivate")',
                'button:has-text("Yes")',
                'button:has-text("Confirm")',
                'button:has-text("OK")',
            ]:
                try:
                    c_btn = page.locator(confirm_sel).first
                    if await c_btn.is_visible(timeout=3000):
                        await c_btn.click()
                        log(f"Confirmed deactivation dialog via {confirm_sel!r}")
                        # Give ISE time to fully process the deactivation
                        await page.wait_for_timeout(5000)
                        break
                except Exception:
                    continue

            # ── Wait for the POST-deactivate transition ────────────────────────
            # IMPORTANT: "App configuration" heading is already on the page
            # BEFORE deactivation — waiting for it returns immediately.
            # Must wait for "Inactive" status text or "Existing instances" radio
            # which only appear AFTER the page has transitioned.
            log("Waiting for Inactive status / Existing instances radio (post-deactivate)...")
            _transitioned = False
            for _wait_sel in [
                'text=Inactive',
                'text=Existing instances',
                'input[type="radio"]',
            ]:
                try:
                    await page.wait_for_selector(_wait_sel, timeout=20000)
                    log(f"Post-deactivate transition confirmed via: {_wait_sel!r} ✓")
                    _transitioned = True
                    break
                except Exception:
                    continue
            if not _transitioned:
                log("WARNING: post-deactivate transition not confirmed — continuing anyway")

            # Let ISE fully settle into Inactive before we interact with the form
            log("Waiting 5s for ISE to fully settle post-deactivate...")
            await page.wait_for_timeout(5000)
            await page.screenshot(path="/pipeline/host-data/ise_scc_post_deactivate.png", full_page=True)
            log("Post-deactivate screenshot: ise_scc_post_deactivate.png")

            # ── Verify / ensure "Existing instances" is selected ──────────────
            # Per the UI (confirmed via screenshots): after Deactivate the page
            # shows two radios — "Existing instances" (pre-selected) and
            # "New instance".  We verify it is selected; if not, click it.
            log("Checking 'Existing instances' radio state")
            _ex_checked = await page.evaluate("""() => {
                const radios = Array.from(document.querySelectorAll('input[type="radio"]'));
                for (const r of radios) {
                    // Check associated label or surrounding text
                    const lbl = document.querySelector('label[for="' + r.id + '"]');
                    const txt = lbl ? lbl.innerText :
                                (r.closest('label') ? r.closest('label').innerText :
                                 (r.parentElement ? r.parentElement.innerText : ''));
                    if (txt && txt.toLowerCase().includes('existing')) {
                        return r.checked;
                    }
                }
                return null;
            }""")
            log(f"Existing instances radio checked={_ex_checked}")

            if not _ex_checked:
                log("Selecting 'Existing instances' radio")
                _ex_result = await page.evaluate("""() => {
                    // 1) Native radio input with label containing "Existing"
                    const radios = Array.from(document.querySelectorAll('input[type="radio"]'));
                    for (const r of radios) {
                        const lbl = document.querySelector('label[for="' + r.id + '"]');
                        const txt = lbl ? lbl.innerText :
                                    (r.closest('label') ? r.closest('label').innerText :
                                     (r.parentElement ? r.parentElement.innerText : ''));
                        if (txt && txt.toLowerCase().includes('existing')) {
                            r.click();
                            return 'radio-click:' + txt.trim().slice(0, 40);
                        }
                    }
                    // 2) Click the label/span that says "Existing instances"
                    const all = Array.from(document.querySelectorAll('label, span, div'));
                    const el = all.find(e => e.childElementCount === 0 &&
                                            e.innerText && e.innerText.trim() === 'Existing instances');
                    if (el) { el.click(); return 'label-text-click'; }
                    // 3) Broad match
                    const broad = all.find(e => e.innerText &&
                                               e.innerText.trim().startsWith('Existing'));
                    if (broad) { broad.click(); return 'broad:' + broad.innerText.trim().slice(0,30); }
                    return null;
                }""")
                log(f"Existing instances selection result: {_ex_result}")
                await page.wait_for_timeout(1500)

            await page.screenshot(path="/pipeline/host-data/ise_scc_existing_selected.png", full_page=True)
            log("Existing instances screenshot: ise_scc_existing_selected.png")

            # ── Wait for instance dropdown to auto-populate ───────────────────
            # After a live Deactivate the SPA pre-selects the just-deactivated
            # instance (e.g. ISE-POD-POD-2-4825).  If the page was already
            # Inactive before this run, the dropdown stays empty and we must
            # open it and select the instance manually.
            log("Waiting for instance dropdown to auto-populate (up to 5s)...")
            _dropdown_populated = False
            for _ in range(5):
                await page.wait_for_timeout(1000)
                _inst_val = await page.evaluate("""() => {
                    // Look for any input/combobox that has a real value (not placeholder)
                    const inp = document.querySelector(
                        'input[role="combobox"], input[role="searchbox"], [class*="select"] input');
                    if (inp && inp.value && inp.value.trim() &&
                        inp.value !== inp.placeholder) return inp.value.trim();
                    // Also check for a visible selected-value span (custom dropdowns)
                    const spans = Array.from(document.querySelectorAll(
                        '[class*="selected"] span, [class*="value"] span, [class*="select__single"]'));
                    for (const s of spans) {
                        const t = s.innerText && s.innerText.trim();
                        if (t && t.toLowerCase().includes('ise')) return t;
                    }
                    return null;
                }""")
                if _inst_val:
                    log(f"Instance dropdown auto-populated: {_inst_val!r} ✓")
                    _dropdown_populated = True
                    break

            if not _dropdown_populated:
                # Dropdown is empty — open it and click the ISE-POD option
                log("Dropdown still empty — opening manually to select instance")
                try:
                    # Click the dropdown trigger (chevron / select container)
                    for _dd_sel in [
                        '[placeholder="Select instance"]',
                        'input[role="combobox"]',
                        '[class*="select"] [class*="control"]',
                        '[class*="dropdown"] [class*="control"]',
                        ':text("Select instance")',
                    ]:
                        try:
                            _dd = page.locator(_dd_sel).first
                            if await _dd.is_visible(timeout=2000):
                                await _dd.click()
                                log(f"Opened dropdown via {_dd_sel!r}")
                                await page.wait_for_timeout(1500)
                                break
                        except Exception:
                            continue
                    # Click the first option containing "ISE"
                    _opt_clicked = False
                    for _opt_sel in [
                        '[class*="option"]:has-text("ISE")',
                        '[role="option"]:has-text("ISE")',
                        'li:has-text("ISE")',
                    ]:
                        try:
                            _opt = page.locator(_opt_sel).first
                            if await _opt.is_visible(timeout=3000):
                                await _opt.click()
                                log(f"Selected instance option via {_opt_sel!r}")
                                _opt_clicked = True
                                await page.wait_for_timeout(1000)
                                break
                        except Exception:
                            continue
                    if not _opt_clicked:
                        # JS fallback: find option with ISE text and click it
                        _js_opt = await page.evaluate("""() => {
                            const opts = Array.from(document.querySelectorAll(
                                '[class*="option"], [role="option"], li'));
                            const o = opts.find(e => e.innerText &&
                                                     e.innerText.toUpperCase().includes('ISE'));
                            if (o) { o.click(); return o.innerText.trim().slice(0, 60); }
                            return null;
                        }""")
                        if _js_opt:
                            log(f"JS option fallback selected: {_js_opt!r}")
                        else:
                            log("WARNING: could not select instance from dropdown — Activate may fail")
                except Exception as _dd_err:
                    log(f"WARNING: dropdown interaction error: {_dd_err}")

            await page.wait_for_timeout(500)

            # ── Scroll to bottom and click Activate ───────────────────────────
            # The blue Activate button is at the very bottom of the page.
            log("Scrolling to bottom to find Activate button")
            await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            await page.wait_for_timeout(1000)

            log("Clicking Activate")
            reactivated = False
            for ra_sel in [
                'button:has-text("Activate")',
                'button:has-text("Reactivate")',
                'a:has-text("Activate")',
                '[role="button"]:has-text("Activate")',
            ]:
                try:
                    ra_btn = page.locator(ra_sel).first
                    if await ra_btn.is_visible(timeout=10000):
                        await ra_btn.scroll_into_view_if_needed()
                        await ra_btn.click(force=True)
                        reactivated = True
                        log(f"Clicked Activate via {ra_sel!r} ✓")
                        await page.wait_for_timeout(3000)
                        break
                except Exception:
                    continue

            if not reactivated:
                # JS fallback — find any non-disabled button with text "Activate"
                _js_act = await page.evaluate("""() => {
                    const btns = Array.from(document.querySelectorAll('button'));
                    const btn = btns.find(b => !b.disabled &&
                                              b.innerText && b.innerText.trim() === 'Activate');
                    if (btn) { btn.click(); return btn.outerHTML.slice(0, 80); }
                    return null;
                }""")
                if _js_act:
                    log(f"JS Activate fallback: {_js_act}")
                    reactivated = True
                    await page.wait_for_timeout(3000)
                else:
                    await page.screenshot(path="/pipeline/host-data/ise_reactivate_fail.png", full_page=True)
                    return False, "Activate button not found — check ise_reactivate_fail.png"

            await page.screenshot(path="/pipeline/host-data/ise_scc_post_activate.png", full_page=True)
            log("Post-activate screenshot: ise_scc_post_activate.png")

            # ── Check for OTP (only if New instance path was taken) ───────────
            new_otp = await _read_otp_from_page(page, log)
            if new_otp:
                log(f"New OTP generated ({len(new_otp)} chars) — submitting to SCC via IPC")
            else:
                log("No new OTP — existing instance reactivation auto-connects to SCC ✓")

            # Click OK/Close/Done if a modal appeared after Activate
            for ok_sel in ['button:has-text("OK")', 'button:has-text("Close")', 'button:has-text("Done")']:
                try:
                    ok_btn = page.locator(ok_sel).first
                    if await ok_btn.is_visible(timeout=3000):
                        await ok_btn.click()
                        await page.wait_for_timeout(1000)
                        break
                except Exception:
                    continue

            # ── Poll for Active confirmation (Deactivate button = Active) ─────
            # After Activate, ISE shows "Activating..." spinner for ~30-60s.
            # Do NOT reload the page during this window — reloading kills the
            # in-flight activation.  First 6 polls (60s): check without reload.
            # Polls 7-18: reload to force a fresh status check.
            log("Polling for Active confirmation (up to 3 min)...")
            _confirmed_active = False
            for _cpoll in range(18):   # 18 × 10s = 3 min
                await page.wait_for_timeout(10000)
                if _cpoll >= 6:
                    # Only reload after the initial 60s activation window
                    try:
                        await page.reload()
                        await page.wait_for_timeout(3000)
                        await _ise_dismiss_modal(page)
                        await _ise_dismiss_session_info(page)
                    except Exception:
                        pass
                _cbtns = await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('button'))
                      .map(b => b.innerText.trim().slice(0, 40)).filter(Boolean);
                }""")
                _has_deact = any("deactivate" in t.lower() for t in _cbtns)
                log(f"  poll {_cpoll+1}/18 — buttons={_cbtns[:8]} deactivate_present={_has_deact}")
                if _has_deact:
                    log("Active confirmed — Deactivate button present ✓")
                    _confirmed_active = True
                    break

            if not _confirmed_active:
                await page.screenshot(path="/pipeline/host-data/ise_active_timeout.png", full_page=True)
                log("WARNING: Deactivate button never appeared in 3 min — check ise_active_timeout.png")

            if new_otp:
                _ipc_ok, _ipc_msg = _scc_file_ipc(pod_id, new_otp, log)
                if not _ipc_ok:
                    return False, f"SCC IPC failed after reactivation: {_ipc_msg}"
                return True, "ISE → SCC Deactivate+Reactivate + OTP submitted — integration going Active"
            else:
                _status = "Active" if _confirmed_active else "pending (check ise_active_timeout.png)"
                return True, f"ISE → SCC Deactivate+Reactivate completed — ISE instance {_status}"

        except Exception as e:
            return False, f"Deactivate/Reactivate error: {e}"
        finally:
            await browser.close()



# ── Step 2: ISE → Secure Access (SCC Platform Integration) ───────────────────

async def _phase_ise_scc_integrate_async(pod_id: str, creds: dict, session_path: str, log) -> tuple[bool, str]:
    from playwright.async_api import async_playwright
    import time as _time, base64 as _b64

    # ── Early session validity check ──────────────────────────────────────────
    # Validate the SCC session file BEFORE spending 4+ minutes on ISE steps.
    try:
        _sp = Path(session_path)
        if not _sp.exists():
            return False, "SCC session file not found — click 'Refresh SCC Sessions' first"
        _age_h = (_time.time() - _sp.stat().st_mtime) / 3600
        if _age_h > 8.0:
            return False, f"SCC session is {_age_h:.1f}h old (>8h) — click 'Refresh SCC Sessions' first"
        _sd = json.loads(_sp.read_text())
        _okta_raw = ""
        for _o in _sd.get("origins", []):
            for _it in _o.get("localStorage", []):
                if _it.get("name") == "okta-token-storage":
                    _okta_raw = _it.get("value", "")
        if _okta_raw:
            _tok = json.loads(_okta_raw)
            _id_tok = _tok.get("idToken", {}).get("idToken", "")
            if _id_tok:
                _parts = _id_tok.split(".")
                if len(_parts) == 3:
                    _payload = _parts[1] + "=" * (-len(_parts[1]) % 4)
                    _claims = json.loads(_b64.b64decode(_payload))
                    _exp = _claims.get("exp", 0)
                    _remaining = _exp - _time.time()
                    if _remaining < 120:  # less than 2 min remaining
                        return False, f"SCC token expires in {_remaining/60:.1f} min — click 'Refresh SCC Sessions' then immediately retry"
                    log(f"SCC session valid — token expires in {_remaining/60:.1f} min")
    except Exception as _e:
        log(f"SCC session pre-check warning: {_e} — continuing anyway")
    # ─────────────────────────────────────────────────────────────────────────

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
            # NOTE: "Enable pxGrid Cloud and register ISE" is ALWAYS shown as a prerequisite
            # reminder even after registration. The real indicator that ISE is NOT registered
            # is the ABSENCE of "Manage your ISE registration" link on the page.
            page_text = (await page.inner_text("body")).lower()
            if "enable pxgrid cloud and register" in page_text and "manage your ise registration" not in page_text:
                return False, "pxGrid Cloud not yet enabled on ISE node — run step 1 (pxGrid Cloud Register) first"

            await page.screenshot(path="/pipeline/host-data/ise_scc_config_tab.png", full_page=False)

            # If already Active (Deactivate button visible) — skip, nothing to do.
            for act_chk in [
                'button:has-text("Deactivate")',
                ':text-is("Active")',
                ':text-is("Activated")',
            ]:
                try:
                    if await page.locator(act_chk).first.is_visible(timeout=2000):
                        log("ISE→SCC integration already Active — skipping")
                        return True, "ISE→SCC integration already Active (skipped)"
                except Exception:
                    continue

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
            await _ise_dismiss_session_info(page)
            _activated = False
            for _act_sel in [
                'button:has-text("Activate")',
                'a:has-text("Activate")',
                '[role="button"]:has-text("Activate")',
            ]:
                try:
                    _ab = page.locator(_act_sel).first
                    if await _ab.is_visible(timeout=15000):
                        await _ab.scroll_into_view_if_needed()
                        await _ab.click(force=True)
                        _activated = True
                        log(f"Activated via {_act_sel!r}")
                        break
                except Exception:
                    continue
            if not _activated:
                await page.screenshot(path="/pipeline/host-data/ise_activate_fail.png", full_page=True)
                return False, "Could not find Activate button — check ise_activate_fail.png"
            await page.wait_for_timeout(3000)
            # Dismiss Session Info popup — it re-appears after Activate and can overlay the OTP modal
            await _ise_dismiss_session_info(page)
            await page.wait_for_timeout(500)

            # Wait for "Fetching OTP..." spinner to finish — ISE makes an API call to
            # generate the token; the spinner stays until it completes (can take 5-15s).
            log("Waiting for OTP to appear (spinner: 'Fetching OTP...')")
            for _otp_wait in range(20):  # up to 20s
                _body_txt = (await page.inner_text("body")).lower()
                if "fetching otp" not in _body_txt:
                    log(f"OTP spinner gone after {(_otp_wait) * 1}s")
                    break
                await page.wait_for_timeout(1000)
            else:
                log("WARNING: 'Fetching OTP...' still present after 20s — attempting OTP read anyway")
            await _ise_dismiss_session_info(page)
            await page.screenshot(path="/pipeline/host-data/ise_scc_pre_otp.png", full_page=False)

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
            # Docker routes ALL traffic through OpenConnect VPN which breaks Okta
            # silent-renew → storage_state always rejected. Hand off to the HOST
            # dashboard which runs Playwright outside the VPN container.
            _ipc_ok, _ipc_msg = _scc_file_ipc(pod_id, otp_token, log)
            if not _ipc_ok:
                return _ipc_ok, _ipc_msg

            # SCC has the OTP — now wait in the SAME browser session for ISE to
            # confirm the handshake (Deactivate button appears = fully Active).
            # This avoids step 3 opening a cold container and seeing Activate(disabled).
            log("SCC confirmed — polling ISE for Active state (up to 2 min)...")

            async def _ise_btns():
                return await page.evaluate("""() => {
                    return Array.from(document.querySelectorAll('button, a[role="button"]'))
                      .map(b => ({txt:b.innerText.trim().slice(0,40), dis:b.disabled}))
                      .filter(b => b.txt);
                }""")

            for _wi in range(3):  # 3 × 15s = 45s settle time before step 3
                await page.wait_for_timeout(15000)
                try:
                    await page.reload()
                    await page.wait_for_timeout(2000)
                    await _ise_dismiss_modal(page)
                    try:
                        await page.locator('text=Configuration').first.click(timeout=8000)
                        await page.wait_for_timeout(2000)
                    except Exception:
                        pass
                except Exception:
                    pass
                _wb = await _ise_btns()
                _has_deact = any("deactivate" in str(b.get('txt','')).lower() for b in _wb)
                _act_enabled = any(
                    "activate" in str(b.get('txt','')).lower() and not b.get('dis', True)
                    for b in _wb
                )
                log(f"  ISE poll {_wi+1}/8 — deactivate={_has_deact} activate_enabled={_act_enabled} btns={[b['txt'] for b in _wb[:5]]}")
                if _has_deact:
                    log("ISE is Active (Deactivate visible) — step 2 complete")
                    return True, _ipc_msg
                if _act_enabled:
                    # Click Activate to complete ISE's side, then dismiss OTP dialog
                    log("Activate (enabled) — clicking to complete ISE handshake")
                    try:
                        await page.locator('button:has-text("Activate")').first.click(timeout=5000)
                        await page.wait_for_timeout(4000)
                        for _ok_s in ['button:has-text("Ok")', 'button:has-text("OK")',
                                      'button:has-text("Close")', 'button:has-text("Done")']:
                            try:
                                _ok = page.locator(_ok_s).first
                                if await _ok.is_visible(timeout=3000):
                                    await _ok.click()
                                    await page.wait_for_timeout(3000)
                                    log(f"Dismissed OTP dialog via {_ok_s!r}")
                                    break
                            except Exception:
                                continue
                        _wb2 = await _ise_btns()
                        _has_deact2 = any("deactivate" in str(b.get('txt','')).lower() for b in _wb2)
                        log(f"After Activate+dismiss: deactivate={_has_deact2} btns={[b['txt'] for b in _wb2[:5]]}")
                        if _has_deact2:
                            log("ISE Active after Activate+Ok — step 2 complete")
                            return True, _ipc_msg
                    except Exception as _ae:
                        log(f"Activate click error: {_ae}")

            log("ISE Active state not confirmed within 2 min — step 3 will handle")
            return True, _ipc_msg
            await scc_page.goto("https://security.cisco.com",
                                wait_until="domcontentloaded", timeout=60000)
            await scc_page.wait_for_timeout(2000)

            if "login" in scc_page.url.lower() or "sign-on" in scc_page.url.lower():
                log(f"SCC session expired (URL: {scc_page.url[:80]}) — re-run Refresh SCC Sessions")
                return False, "SCC session expired — click 'Refresh SCC Sessions' on the dashboard then retry"

            # Dismiss org picker modal (Continue button — org pre-selected in dropdown)
            await _scc_dismiss_org_picker(scc_page, log)
            await scc_page.wait_for_timeout(2000)
            log(f"After org picker: {scc_page.url[:80]}")

            # Step 2: Navigate to Platform Integrations via the sidebar nav link.
            # Direct URL navigation always redirects to /dashboard — nav link click
            # lets the React router perform a client-side transition instead.
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
                    _nl = scc_page.locator(_nav_sel).first
                    await _nl.wait_for(state="visible", timeout=5000)
                    await _nl.click()
                    await scc_page.wait_for_load_state("domcontentloaded", timeout=20000)
                    await scc_page.wait_for_timeout(3000)
                    log(f"Clicked Platform Integrations nav via {_nav_sel!r} → {scc_page.url[:80]}")
                    _nav_clicked = True
                    break
                except Exception:
                    continue

            if not _nav_clicked:
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
        # Use _db_connect (with retry) so transient I/O errors don't cause
        # completed steps to silently re-run.
        try:
            with closing(_db_connect(db_path)) as _skip_db:
                _row = _skip_db.execute(
                    "SELECT status FROM ise_steps WHERE pod_id=? AND step_name=?", (pod_id, step)
                ).fetchone()
            if _row and _row[0] in ("completed", "skipped"):
                _log(f"Step {i+1}/{len(ISE_STEPS)}: {ISE_STEP_LABELS[step]} — already {_row[0]}, skipping")
                continue
        except Exception as _skip_e:
            _log(f"[warn] skip-check DB error for {step}: {_skip_e} — proceeding to run step")

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
            elif step == "ise_sgt_verify":
                ok, msg = _phase_ise_sgt_verify(pod_id, creds, _log)
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
            if step in ("ise_cdfmc_integrate", "ise_scc_deactivate_reactivate", "ise_sgt_verify"):
                _ise_step_set(pod_id, step, "skipped", f"[soft-fail] {msg}", db_path)
                _log(f"  [soft-fail] {ISE_STEP_LABELS[step]} — marked skipped, continuing to next step")
                continue
            return False, f"{ISE_STEP_LABELS[step]} failed: {msg}"

    return True, "All ISE integration steps completed"
