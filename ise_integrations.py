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
# pxGrid Cloud region the lab guide specifies. The Dijit Select defaults to
# ap-southeast-1, so this must be actively set and verified.
PXGRID_REGION = "us-west-2"

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
            # WAL, matching dashboard.py's _db(). These MUST agree: flipping a
            # WAL database back to DELETE needs an exclusive lock, so with the
            # dashboard connected this raised "database is locked" and took the
            # whole dashboard down at import time.
            # Was synchronous=OFF. In WAL that risks a corrupt file on an OS
            # crash or power loss, and this database was already corrupted once
            # on 2026-09-01 by concurrent writers. NORMAL is the standard WAL
            # setting: safe against corruption, at worst losing the last commits.
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=15000")
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
    """Clear anything that would intercept clicks: the post-login Bootstrap modal
    AND any leftover Dijit dialog underlay.

    The Dijit half matters as much as the Bootstrap half. On the Deployment page
    a dialog called `deployInfo` leaves DIV#deployInfo_underlay behind with
    display:block and pointer-events:auto, and it never clears — still there
    after 25s. The `ise` node link is present and visible underneath it, so the
    selector matches, but document.elementFromPoint() at the link's centre
    returns the underlay. Playwright's actionability check then waits for the
    link to receive events and times out:

        Could not click ise node link: Locator.click: Timeout 10000ms exceeded

    which reads like a missing element when the element was there all along.
    Closing the dialog through Dijit lets the widget tear its own underlay down;
    the second pass neutralises anything still covering the page.
    """
    try:
        await page.evaluate("""
            const modal = document.getElementById('ise-modal');
            if (modal) modal.remove();
            document.querySelectorAll('.modal-backdrop, .post-loging-modal').forEach(el => el.remove());
            if (document.body) document.body.classList.remove('modal-open');

            let reg = null;
            if (window.dijit && window.dijit.byId) reg = window.dijit;
            else if (window.require) { try { reg = window.require('dijit/registry'); } catch (e) {} }

            document.querySelectorAll('.dijitDialogUnderlay').forEach(u => {
                const id = (u.id || '').replace(/_underlay$/, '');
                if (reg && reg.byId && id) {
                    const w = reg.byId(id);
                    if (w && typeof w.hide === 'function') { try { w.hide(); } catch (e) {} }
                }
            });
            document.querySelectorAll('.dijitDialogUnderlay, .dijitDialogUnderlayWrapper').forEach(u => {
                if (u.getClientRects().length) {
                    u.style.display = 'none';
                    u.style.pointerEvents = 'none';
                }
            });
        """)
    except Exception:
        pass

    # ISE's "Information" dialog, which the lab guide does not mention:
    #
    #   This node is in Standalone mode. To register other nodes, you must
    #   first edit this node and change its Administration Role to Primary
    #                    [ ] Do not show this message again        [ OK ]
    #
    # It is purely informational — the pod is a single standalone ISE and never
    # registers other nodes — but it is a MODAL, so while it is up every click
    # on the Deployment page lands on its underlay instead of the node link.
    # It does not appear on every POD, which is worse than if it always did:
    # the same code passes on one pod and mysteriously times out on another.
    #
    # Tick "Do not show this message again" before OK so the pod stops raising
    # it for the rest of the session, then click OK. Both are best-effort: a POD
    # that never shows the dialog must not be slowed down or failed by this.
    try:
        _info = await page.evaluate("""() => {
            const dlgs = Array.from(document.querySelectorAll(
                '.dijitDialog, [role="dialog"], .modal'));
            for (const d of dlgs) {
                if (!d.getClientRects().length) continue;
                const txt = (d.innerText || '');
                if (!/standalone mode/i.test(txt)) continue;
                // Suppress future occurrences if the box is offered.
                for (const cb of d.querySelectorAll('input[type="checkbox"]')) {
                    const lbl = (cb.closest('label') || cb.parentElement || {}).innerText || '';
                    if (/do not show/i.test(lbl) && !cb.checked) { cb.click(); }
                }
                for (const b of d.querySelectorAll('button,[role="button"],.dijitButtonNode')) {
                    if ((b.textContent || '').trim().toUpperCase() === 'OK') {
                        b.click();
                        return 'dismissed';
                    }
                }
                return 'found-no-ok';
            }
            return '';
        }""")
        if _info == "dismissed":
            await page.wait_for_timeout(700)
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
    log(f"cdFMC OTP written to shared volume — waiting for host nav "
        f"(up to 10 min), watching {_result_path}")
    _deadline = _t.time() + 600
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
    # Say what was actually on the volume, so a repeat is diagnosable in one shot
    # instead of needing a forensic pass over timestamps.
    try:
        _seen = sorted(x.name for x in Path("/pipeline/host-data").glob("ise_cdfmc_*"))
    except Exception as _le:
        _seen = [f"<listing failed: {_le}>"]
    log(f"cdFMC IPC timeout — /pipeline/host-data holds: {_seen}")
    return False, ("Host cdFMC nav timed out — no result after 10 min. "
                   f"Volume held: {_seen}. Check the [cdfmc-nav] lines: if they end "
                   "in OK the SCC work SUCCEEDED and only this handoff failed.")


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


async def _catalog_is_populated(page) -> int:
    """How many integration cards the catalog is currently showing.

    0 means the list never loaded. Used to assert that navigation actually
    worked instead of assuming it did.
    """
    try:
        return await page.evaluate(
            """() => document.querySelectorAll('button[data-label="More details"]').length""")
    except Exception:
        return 0


async def _open_integration(page, name: str, log) -> bool:
    """Open a named integration's detail page from the Integration Catalog.

    The catalog has two sections and an integration appears in exactly one of
    them: "Activated integrations" is a TABLE whose Integration column is a
    link, while "Available integrations" is a grid of CARDS each carrying its
    own "More details" button.

    Step 2 used to do:

        # Click "More details" on Cisco Security Cloud card (first card)
        page.locator('button[data-label="More details"]').first.click()

    which assumed the wanted integration was the first Available card. Once
    Cisco Security Cloud is activated it leaves the Available grid entirely, so
    `.first` is whatever happens to lead the grid -- on POD-17 that is Firewall
    Management Center. The step then drove the wrong integration while logging
    that it had opened the right one.

    Tries the activated link first, then the matching card, then asserts the
    detail page really is the requested integration.
    """
    # 1. Activated integrations table -- the name is a link.
    try:
        link = page.locator(f':text("{name}")').first
        if await link.is_visible(timeout=5_000):
            await link.click(timeout=8_000)
            await page.wait_for_timeout(3_000)
            body = (await page.evaluate("() => document.body.innerText") or "")
            if name.lower() in body.lower():
                log(f"Opened {name!r} from Activated integrations")
                return True
    except Exception:
        pass

    # 2. Available grid -- find the CARD holding this title and click ITS button,
    #    never a positional .first.
    try:
        clicked = await page.evaluate("""(name) => {
            const btns = Array.from(document.querySelectorAll('button[data-label="More details"]'));
            for (const b of btns) {
                let el = b;
                for (let i = 0; i < 8 && el; i++) {
                    const t = (el.innerText || '');
                    if (t.toLowerCase().includes(name.toLowerCase())) { b.click(); return true; }
                    el = el.parentElement;
                }
            }
            return false;
        }""", name)
        if clicked:
            await page.wait_for_timeout(3_000)
            body = (await page.evaluate("() => document.body.innerText") or "")
            if name.lower() in body.lower():
                log(f"Opened {name!r} from Available integrations")
                return True
    except Exception as e:
        log(f"Could not open {name!r} from the Available grid: {e}")

    log(f"Integration {name!r} not found in the catalog")
    return False


async def _navigate_to_integration_catalog(page, log) -> bool:
    """Navigate to ISE Administration -> Integration Catalog. Returns True on success.

    This MUST go through the menu. Loading the hash URL directly
    (#administration/administration_integration_catalog/integration_catalog)
    renders the page shell but the integration list never loads -- the route
    settles on the empty state "All current integrations are active", with zero
    "More details" buttons and no Activated section at all. Measured on POD-17:

        hash URL -> body 437 chars,  0 "More details" buttons
        menu     -> body 2416 chars, 4 "More details" buttons, Activated section

    That empty page is what made three separate steps report three unrelated
    causes -- ise_scc_integrate timing out on "More details",
    ise_cdfmc_integrate reporting "FMC not found in catalog (ISE error/no
    internet)", and ise_scc_deactivate_reactivate reporting "Could not find
    Cisco Security Cloud link in Activated integrations". All three were
    reading a catalog that had simply never been populated.

    The old version also returned True when the catalog never rendered, so the
    caller could not tell that navigation had failed. It now asserts.
    """
    try:
        # Land on the admin UI first; the menu only exists once it has loaded.
        if "/admin/" not in page.url:
            await page.goto(f"{ISE_URL}/admin/", wait_until="domcontentloaded",
                            timeout=60000)
            await page.wait_for_timeout(8000)
        await _ise_dismiss_session_info(page)
        await _ise_dismiss_modal(page)
        await page.wait_for_timeout(2000)

        CLICK = """(lbl) => {
            const el = Array.from(document.querySelectorAll('a,button,span,div,li'))
                .filter(e => e.getClientRects().length &&
                             (e.innerText || '').trim() === lbl)
                .pop();
            if (!el) return false;
            el.click();
            return true;
        }"""
        HAS = """(lbl) => Array.from(document.querySelectorAll('a,button,span,div,li'))
            .some(e => e.getClientRects().length && (e.innerText || '').trim() === lbl)"""

        async def _wait_for_menu(lbl, timeout_s=60):
            """Wait for a menu item to actually exist before clicking it.

            The click used to fire immediately. ISE renders its left nav
            asynchronously, and this function skips the post-login settle
            whenever the URL is already /admin/ -- so on a slow or
            service-restarting ISE the item simply is not there yet and the step
            failed with "menu item 'Administration' not found". Repeated
            activate/deactivate cycles trigger restartAction.do, which is
            exactly when the UI is slowest.
            """
            for i in range(timeout_s // 3):
                if await page.evaluate(HAS, lbl):
                    if i:
                        log(f"menu item {lbl!r} appeared after ~{i * 3}s")
                    return True
                # A collapsed nav hides the labels entirely -- open it and retry.
                if i == 2:
                    try:
                        await page.evaluate("""() => {
                            const b = document.querySelector(
                                '[class*="hamburger"], [aria-label*="menu" i], '
                                + '[class*="menu-toggle"], button[class*="nav"]');
                            if (b) b.click();
                        }""")
                    except Exception:
                        pass
                await page.wait_for_timeout(3000)
            return False

        for label in ("Administration", "Integration Catalog"):
            if not await _wait_for_menu(label):
                try:
                    await page.screenshot(
                        path=f"/pipeline/host-data/ise_menu_missing_{label.split()[0]}.png",
                        full_page=False)
                    _snip = (await page.inner_text("body"))[:220].replace("\n", " | ")
                except Exception:
                    _snip = "<unreadable>"
                log(f"Integration Catalog nav: menu item {label!r} not found after 60s "
                    f"(url={page.url}) body: {_snip!r}")
                return False
            if not await page.evaluate(CLICK, label):
                log(f"Integration Catalog nav: menu item {label!r} vanished before click")
                return False
            await page.wait_for_timeout(9000)

        await _ise_dismiss_session_info(page)
        await _ise_dismiss_modal(page)

        # Assert the list actually rendered -- an unpopulated catalog is a
        # navigation failure, not an empty catalog.
        for _ in range(6):
            n = await _catalog_is_populated(page)
            if n:
                log(f"Integration Catalog loaded ({n} integration card(s))")
                return True
            await page.wait_for_timeout(5000)

        log("Integration Catalog did not populate -- the list never loaded")
        return False
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

# ── pxGrid Cloud registration panel ───────────────────────────────────────────
# ISE renders the registered state as label/value pairs plus a Deregister button:
#
#     Cisco DNA Portal account   PseudoCo-502     Status             Connected
#     ISE deployment name        PseudoCo-502     Registered region  us-west-2
#     Description                --               Mode               Active
#
# It never prints "registration successful" / "registration complete" /
# "successfully registered", which is what both the idempotency guard and the
# connect poll used to look for. So a fully registered, Connected ISE looked
# unregistered to the guard (it re-ran the whole flow) and unconnected to the
# poll (it failed after 3 minutes). One reader now serves both.
_PXGRID_PANEL_JS = """() => {
    const body = document.body.innerText || '';
    const grab = (label) => {
        const re = new RegExp(label + '\\s*\\n\\s*([^\\n]+)', 'i');
        const m = re.exec(body);
        return m ? m[1].trim() : '';
    };
    const deregister = Array.from(document.querySelectorAll('button,a,[role=button]'))
        .some(e => e.getClientRects().length &&
                   /^deregister$/i.test((e.innerText || '').trim()));
    return {
        status:  grab('Status'),
        account: grab('Cisco DNA Portal account'),
        name:    grab('ISE deployment name'),
        region:  grab('Registered region'),
        mode:    grab('Mode'),
        deregister,
    };
}"""


async def _ise_pxcloud_checked(page):
    """Current state of the Enable pxGrid Cloud box, or None if unreadable."""
    try:
        return await page.evaluate("""() => {
            const i = document.getElementById('enablePxCloudServices');
            return i ? !!i.checked : null;
        }""")
    except Exception:
        return None


async def _ise_click_pxcloud_checkbox(page, log, want: bool) -> bool:
    """Click Enable pxGrid Cloud and confirm it reached `want`.

    Coordinates MUST be recomputed on every click. An earlier version cached
    them before the off-click and reused them for the on-click; the confirmation
    dialog shifts the layout, so the second click landed elsewhere, the box
    never came back on, and the form never built ("section did not finish
    loading within 90s") while the log still claimed it had been re-enabled.
    """
    for attempt in range(3):
        coords = await page.evaluate("""() => {
            const inp = document.getElementById('enablePxCloudServices');
            if (!inp) return null;
            const wrap = inp.closest('.dijitCheckBox') || inp.parentElement;
            const icon = wrap.querySelector('.dijitCheckBoxIcon') || wrap;
            icon.scrollIntoView({behavior: 'instant', block: 'center'});
            const r = icon.getBoundingClientRect();
            return r.width > 0
                ? {x: r.left + r.width / 2, y: r.top + r.height / 2} : null;
        }""")
        if not coords:
            log("Enable pxGrid Cloud checkbox not clickable")
            return False
        await page.mouse.click(coords["x"], coords["y"])
        await page.wait_for_timeout(1500)

        # Turning it OFF raises a confirmation; turning it ON does not.
        if want is False:
            for sel in ('button:has-text("Disable")', 'span:has-text("Disable")'):
                try:
                    await page.locator(sel).first.click(timeout=3000)
                    break
                except Exception:
                    continue
        else:
            await _ise_cancel_pxgrid_disable(page, log)
        await page.wait_for_timeout(2000)

        state = await _ise_pxcloud_checked(page)
        if state is want:
            log(f"Enable pxGrid Cloud is now {'ON' if want else 'OFF'}")
            return True
        log(f"checkbox still {state!r}, wanted {want} — retry {attempt + 1}/3")
    return False


async def _ise_pxgrid_section_built(page) -> bool:
    """True once ISE has finished constructing the pxGrid Cloud form."""
    try:
        return bool(await page.evaluate("""() => {
            const sec = document.getElementById('pxCloud_region_section');
            const reg = document.getElementById('pxCloud_region');
            if (!sec) return false;
            const r = reg ? reg.getBoundingClientRect() : null;
            return sec.innerHTML.length > 0 && !!r && r.width > 0 && r.height > 0;
        }"""))
    except Exception:
        return False


async def _ise_reopen_node(page, log) -> bool:
    """Reload the node edit page so the pxGrid panel shows CURRENT state.

    The connect poll refreshes by re-opening this page. When that click failed
    the poll silently kept re-reading the SAME DOM, so it reported ISE's
    transient "Cisco ISE could not connect to pxGrid." for 47 straight rounds
    while a fresh browser session showed Connected. Extending the poll window
    does not help that — it just makes the wrong answer take longer. So this
    retries, and reports whether the panel was actually refreshed.
    """
    # The navigation was never the problem — the CLICK on the node link was. On
    # POD-24 it timed out at 12s on all three attempts, twice in two sessions, so
    # every poll re-read the previous DOM and reported "Cisco ISE could not
    # connect to pxGrid." for 30+ rounds while an out-of-band read of the same
    # node showed status='Connected', mode='Active'. The lab was fine; the read
    # was not.
    #
    # A standalone probe doing the identical sequence with a 20s click and longer
    # settles succeeded first time, so the deployment grid on this box is simply
    # slower to become clickable than 12s allows. Give it room, wait for the row
    # to be actionable rather than merely present, and grow the budget per retry.
    for _try in range(3):
        try:
            await page.goto(
                f"{ISE_URL}/admin/#administration/administration_system"
                f"/administration_system_deployment",
                wait_until="domcontentloaded", timeout=60000)
            await page.wait_for_timeout(6000)
            await _ise_dismiss_session_info(page)
            await _ise_dismiss_modal(page)
            try:
                await page.wait_for_selector('table tbody tr, .dijitGrid', timeout=30000)
            except Exception:
                await page.wait_for_timeout(4000)
            await _ise_dismiss_modal(page)
            node = page.locator(
                'table tbody tr a:text-is("ise"), td a:text-is("ise")').first
            # Present is not the same as clickable under Dojo: the grid renders
            # the row before it wires the handler, and clicking in that window is
            # what times out.
            try:
                await node.wait_for(state="visible", timeout=20000 + _try * 10000)
            except Exception:
                pass
            await node.click(timeout=20000 + _try * 10000)
            await page.wait_for_timeout(8000)
            await _ise_dismiss_modal(page)
            return True
        except Exception as e:
            log(f"re-open node attempt {_try + 1}/3 failed: {str(e).splitlines()[0][:110]}")
            await page.wait_for_timeout(3000 + _try * 3000)
    return False


async def _ise_wait_pxgrid_region(page, log, timeout_s: int = 90) -> bool:
    """Wait for the region dropdown to finish loading.

    ISE builds this section ASYNCHRONOUSLY behind a "Loading..." overlay and
    it takes ~15s. The old code probed for td#pxCloud_region immediately,
    logged "Could not locate pxCloud_region element", and clicked Register
    with no region set — which is why registration produced
    "Fail to receive server response" and never sent an enrollment request.
    Measured on POD-5: not present at t+10s, present at t+15s.
    """
    for i in range(timeout_s // 5):
        if await _ise_pxgrid_section_built(page):
            log(f"pxGrid Cloud section built after ~{(i + 1) * 5}s "
                "(region dropdown present)")
            return True
        await page.wait_for_timeout(5000)
    log(f"WARNING: pxGrid Cloud section did not finish loading within {timeout_s}s")
    return False


async def _ise_cancel_pxgrid_disable(page, log) -> bool:
    """Cancel ISE's "disable the pxGrid Cloud?" confirmation if it is showing.

    Answering Disable — or leaving the modal up — silently defeats the whole
    step: the dialog is modal, so Register stays greyed out and no enrollment
    request is ever sent. Always Cancel, never Disable.
    """
    try:
        body = (await page.inner_text("body")).lower()
    except Exception:
        return False
    if "disable the pxgrid cloud" not in body:
        return False
    log("ISE is asking to DISABLE pxGrid Cloud — answering Cancel")
    for sel in ('button:has-text("Cancel")', '[role="button"]:has-text("Cancel")',
                'span:has-text("Cancel")', 'a:has-text("Cancel")'):
        try:
            await page.locator(sel).first.click(timeout=3000)
            await page.wait_for_timeout(1000)
            log("Cancelled the pxGrid Cloud disable confirmation")
            return True
        except Exception:
            continue
    log("WARNING: could not click Cancel on the disable confirmation")
    return False


async def _pxgrid_panel(page) -> dict:
    """Read the pxGrid Cloud registration panel. {} if it cannot be read."""
    try:
        return await page.evaluate(_PXGRID_PANEL_JS)
    except Exception:
        return {}


def _pxgrid_is_registered(panel: dict) -> bool:
    """A live registration offers Deregister AND reports Connected.

    Requiring both avoids two traps: "Cisco DNA Portal account" is a static
    label present even when unregistered, and a Deregister control alone was
    judged unreliable by earlier work here.
    """
    return bool(panel.get("deregister")) and "connected" in (panel.get("status") or "").lower()


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
            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_catalog_nav.png"), full_page=False)

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
                await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_deploy_fail.png"), full_page=True)
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
                await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_deploy_fail.png"), full_page=True)
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
            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_form.png"), full_page=False)

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
            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_loaded.png"), full_page=False)

            # Check if already registered (skip) — only skip on very specific phrases
            # that only appear in a truly connected/registered state.
            # Do NOT include "deregister" — it can appear on unregistered pages too.
            _panel = await _pxgrid_panel(page)
            if _pxgrid_is_registered(_panel):
                log(f"pxGrid Cloud already registered: {_panel}")
                return True, (f"{_SKIP_PREFIX} pxGrid Cloud already registered and connected "
                              f"(account {_panel.get('account')}, name {_panel.get('name')}, "
                              f"region {_panel.get('region')})")

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
            # ── Enable pxGrid Cloud checkbox — physical mouse click ───────────────
            # JS set()/node.click() silently fails on Dijit CheckBox in newer ISE.
            # Use JS to locate the checkbox coordinates, then page.mouse.click() for
            # a trusted physical event that Dijit's onChange handler fires on.
            _cloud_enabled = False
            try:
                _enable_coords = await page.evaluate("""() => {
                    // 1. Known Dijit widget IDs
                    const knownIds = ['pxCloud_enable','pxCloudEnable','pxCloud_enabled',
                                      'enablePxGridCloud','pxCloud_enableRegistration'];
                    if (typeof dijit !== 'undefined' && dijit.registry) {
                        for (const wid of knownIds) {
                            const w = dijit.byId(wid);
                            if (w && w.domNode) {
                                const r = w.domNode.getBoundingClientRect();
                                if (r.width > 0) {
                                    const already = !!(w.get && (w.get('checked') || w.get('value')));
                                    return {x: r.left + r.width/2, y: r.top + r.height/2, id: wid, already};
                                }
                            }
                        }
                        // 2. Walk all CheckBox widgets, match by immediate label
                        for (const w of dijit.registry.toArray()) {
                            if (!(w.declaredClass || '').includes('CheckBox')) continue;
                            const node = w.domNode;
                            if (!node) continue;
                            const lbl = node.id ? document.querySelector('label[for="' + node.id + '"]') : null;
                            const lblText = (lbl ? lbl.textContent : '').toLowerCase();
                            if (lblText.includes('enable pxgrid cloud') || lblText.includes('enable px grid')) {
                                const r = node.getBoundingClientRect();
                                if (r.width > 0) {
                                    const already = !!(w.get && (w.get('checked') || w.get('value')));
                                    return {x: r.left + r.width/2, y: r.top + r.height/2, id: w.id || 'noid', already};
                                }
                            }
                        }
                    }
                    // 3. DOM fallback — all visible checkboxes, match by label text
                    for (const cb of document.querySelectorAll('input[type="checkbox"]')) {
                        if (!cb.offsetParent) continue;
                        const lbl = cb.closest('label') || (cb.id ? document.querySelector('label[for="'+cb.id+'"]') : null);
                        const lblText = (lbl ? lbl.textContent : '').toLowerCase();
                        if (lblText.includes('enable pxgrid cloud') || lblText.includes('enable px grid')) {
                            const r = cb.getBoundingClientRect();
                            if (r.width > 0) return {x: r.left + r.width/2, y: r.top + r.height/2, id: cb.id || '?', already: cb.checked};
                        }
                    }
                    // 4. Last resort — find any visible checkbox near text "pxGrid Cloud"
                    const allText = Array.from(document.querySelectorAll('*')).find(el =>
                        el.children.length === 0 && (el.textContent || '').toLowerCase().includes('enable pxgrid cloud')
                    );
                    if (allText) {
                        let p = allText.parentElement;
                        for (let i = 0; i < 6 && p; i++) {
                            const cb = p.querySelector('input[type="checkbox"]');
                            if (cb) {
                                const r = cb.getBoundingClientRect();
                                if (r.width > 0) return {x: r.left + r.width/2, y: r.top + r.height/2, id: cb.id || 'last-resort', already: cb.checked};
                            }
                            p = p.parentElement;
                        }
                    }
                    return null;
                }""")

                if _enable_coords:
                    # Force Dijit internal state AND click the visible checkbox icon span
                    # The domNode is the outer wrapper div — we need the dijitCheckBoxIcon
                    # span inside it which is the actual clickable element that triggers
                    # Dijit's onChange and expands the pxGrid Cloud form section.
                    # Read the REAL state before touching anything.
                    #
                    # This block used to set checked=true and THEN physically click
                    # the icon as belt-and-braces. A click on a checkbox is a TOGGLE,
                    # so on an ISE where pxGrid Cloud was already enabled the pair
                    # turned it OFF and ISE raised a modal:
                    #   "Are you sure you want to disable the pxGrid Cloud?"
                    # That modal then blocked the whole page — Register stayed greyed
                    # out, no ENROLL request was ever sent ("modified 0"), the
                    # "Select an Account" dialog never appeared, and the connect poll
                    # read status='' 18 times. The trailing set('checked', true)
                    # restored the widget state but could not dismiss the dialog.
                    # Click ONLY when the box is genuinely unchecked.
                    _already_on = await page.evaluate("""(id) => {
                        if (typeof dijit !== 'undefined' && dijit.byId) {
                            const w = dijit.byId(id);
                            if (w && typeof w.get === 'function') return !!w.get('checked');
                        }
                        const el = document.getElementById(id);
                        if (el) {
                            const cb = el.matches('input[type="checkbox"]')
                                ? el : el.querySelector('input[type="checkbox"]');
                            if (cb) return !!cb.checked;
                        }
                        return null;
                    }""", _enable_coords['id'])
                    log(f"Enable pxGrid Cloud (id={_enable_coords['id']!r}) currently checked={_already_on}")

                    # Then physically click the dijitCheckBoxIcon span (the visible box)
                    # — but ONLY when it is off. Clicking an already-enabled box
                    # disables pxGrid Cloud (see above).
                    _icon_coords = None if _already_on else await page.evaluate("""(id) => {
                        if (typeof dijit !== 'undefined' && dijit.byId) {
                            const w = dijit.byId(id);
                            if (w && w.domNode) {
                                // Try the icon span first
                                const icon = w.domNode.querySelector('.dijitCheckBoxIcon, .dijitToggleButtonIconChar, input[type="checkbox"]');
                                const target = icon || w.domNode;
                                target.scrollIntoView({behavior: 'instant', block: 'center'});
                                const r = target.getBoundingClientRect();
                                if (r.width > 0) return {x: r.left + r.width/2, y: r.top + r.height/2};
                            }
                        }
                        return null;
                    }""", _enable_coords['id'])

                    if _already_on:
                        # Checked — but ISE only BUILDS the name/region form on a
                        # real unchecked->checked transition. On a box left checked
                        # by an earlier run the section stays empty forever, so the
                        # region dropdown never exists. Cycle it in that case:
                        # off (accepting ISE's confirmation, safe because nothing is
                        # registered yet) then straight back on.
                        if await _ise_pxgrid_section_built(page):
                            log("pxGrid Cloud already enabled and form built — not clicking")
                        else:
                            log("pxGrid Cloud checked but form never built — cycling it "
                                "off/on so ISE constructs the region dropdown")
                            if await _ise_click_pxcloud_checkbox(page, log, False):
                                await _ise_click_pxcloud_checkbox(page, log, True)
                            else:
                                log("WARNING: could not turn pxGrid Cloud off to rebuild the form")
                    elif _icon_coords:
                        await page.mouse.click(_icon_coords['x'], _icon_coords['y'])
                        log(f"Clicked dijitCheckBoxIcon at ({_icon_coords['x']:.0f},{_icon_coords['y']:.0f})")
                    else:
                        await page.mouse.click(_enable_coords['x'], _enable_coords['y'])
                        log(f"Clicked wrapper at ({_enable_coords['x']:.0f},{_enable_coords['y']:.0f})")

                    await page.wait_for_timeout(500)
                    await _ise_cancel_pxgrid_disable(page, log)
                    # The form loads asynchronously (~15s) — wait before probing it.
                    await _ise_wait_pxgrid_region(page, log)

                    # Final Dijit set() to ensure state sticks after click
                    await page.evaluate("""(id) => {
                        if (typeof dijit !== 'undefined' && dijit.byId) {
                            const w = dijit.byId(id);
                            if (w && typeof w.set === 'function') {
                                w.set('checked', true);
                                w.set('value', true);
                            }
                        }
                    }""", _enable_coords['id'])
                    _cloud_enabled = True
                    # Wait for form fields to expand
                    await page.wait_for_timeout(2000)
                    try:
                        await page.wait_for_selector(
                            'td#pxCloud_region, [id*="pxCloud_deviceName"]',
                            state='visible', timeout=12000
                        )
                        log("pxGrid Cloud section expanded — fields visible")
                    except Exception as _we:
                        log(f"Wait for fields after enable: {_we} — continuing anyway")
                    await page.wait_for_timeout(1000)
                else:
                    log("WARNING: Could not locate Enable pxGrid Cloud checkbox via JS — trying physical scroll + click on any visible checkbox")
                    # Scroll to bottom and try clicking first visible unchecked checkbox
                    await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                    await page.wait_for_timeout(1000)
                    _fallback_coords = await page.evaluate("""() => {
                        const cbs = Array.from(document.querySelectorAll('input[type="checkbox"]')).filter(c => c.offsetParent && !c.checked);
                        if (!cbs.length) return null;
                        const r = cbs[cbs.length-1].getBoundingClientRect();
                        return r.width > 0 ? {x: r.left + r.width/2, y: r.top + r.height/2} : null;
                    }""")
                    if _fallback_coords:
                        await page.mouse.click(_fallback_coords['x'], _fallback_coords['y'])
                        await page.wait_for_timeout(2000)
                        log("Fallback: clicked last visible unchecked checkbox")
                        _cloud_enabled = True
            except Exception as _ce:
                log(f"Enable pxGrid Cloud check error: {_ce}")

            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_cloud_enabled.png"), full_page=False)

            if not _cloud_enabled:
                return False, (
                    "Could not find or click 'Enable pxGrid Cloud' checkbox — "
                    "check ise_pxgrid_cloud_enabled.png"
                )

            # ── Diagnose registration form visibility ─────────────────────────────
            # Find out if td#pxCloud_region is in DOM but hidden, and why.
            # Only skip if ISE is fully registered AND connected — both must be true.
            # Never attempt to deregister: ISE is always in a fresh/unregistered state
            # when this step runs. Any deregister logic causes false resets.
            _vis_diag = None
            _vis_diag = await page.evaluate("""() => {
                const reg = document.getElementById('pxCloud_region');
                const name = document.getElementById('pxCloud_deviceName');

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

                // Scope "connected" check to pxCloudRegistrationForm only
                const form = document.getElementById('pxCloudRegistrationForm');
                const pxSectionText = form ? form.innerText.toLowerCase() : '';

                return {
                    region_in_dom: !!reg,
                    region_hidden_ancestor: reg ? hiddenAncestor(reg) : 'n/a',
                    name_in_dom: !!name,
                    name_hidden_ancestor: name ? hiddenAncestor(name) : 'n/a',
                    pxgrid_connected: pxSectionText.includes('connected'),
                    page_text_snippet: document.body.innerText.slice(0, 300).split('\\n').join(' '),
                };
            }""")
            log(f"Form visibility diag: {_vis_diag}")

            # Skip only if ISE confirms already registered AND connected
            if _vis_diag and _vis_diag.get('pxgrid_connected'):
                log("Connected status confirmed in pxCloudRegistrationForm — ISE is already registered")
                return True, f"{_SKIP_PREFIX} pxGrid Cloud already registered and connected — skipping"

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
                await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_revealed.png"), full_page=False)
                log("Attempted to reveal hidden pxGrid Cloud form fields")

            # Fill "ISE deployment name" — try Dijit widget API first, then DOM walk-up fallback
            # ── Fill deployment name — physical click + press_sequentially ────────
            # JS set() / fill() silently fails on Dijit TextBox widgets in newer ISE.
            # Physical mouse click fires the Dijit focus handler; press_sequentially
            # types char-by-char triggering all keydown/keyup/input events Dijit needs.
            log(f"Filling ISE deployment name: {deployment_name}")
            _filled_name = False
            # Strategy 1: JS coordinate lookup → physical mouse click on the input
            _name_coords = await page.evaluate("""() => {
                // Try known Dijit widget first to get its input node
                try {
                    if (typeof dijit !== 'undefined' && dijit.byId) {
                        for (const wid of ['pxCloud_deviceName', 'deviceName', 'ise_deployment_name']) {
                            const w = dijit.byId(wid);
                            if (w && w.domNode) {
                                const inp = w.domNode.querySelector('input') || w.domNode;
                                const r = inp.getBoundingClientRect();
                                if (r.width > 0) return {x: r.left + r.width/2, y: r.top + r.height/2, method: 'dijit:' + wid};
                            }
                        }
                    }
                } catch(e) {}
                // DOM walk-up: find input near 'ISE deployment name' label
                const inputs = Array.from(document.querySelectorAll('input')).filter(el =>
                    !['checkbox','radio','hidden','submit','button'].includes(el.type || '') && el.offsetParent
                );
                for (const inp of inputs) {
                    let p = inp.parentElement;
                    for (let i = 0; i < 10; i++) {
                        if (!p) break;
                        if (p.textContent.includes('ISE deployment name') || p.textContent.includes('deployment name')) {
                            const r = inp.getBoundingClientRect();
                            if (r.width > 0) return {x: r.left + r.width/2, y: r.top + r.height/2, method: 'dom:' + (inp.id || inp.name || '?')};
                        }
                        p = p.parentElement;
                    }
                }
                return null;
            }""")
            if _name_coords:
                log(f"Name field found via {_name_coords['method']} — clicking and typing")
                await page.mouse.click(_name_coords['x'], _name_coords['y'])
                await page.wait_for_timeout(300)
                # Select all existing text and replace
                await page.keyboard.press('Control+a')
                await page.keyboard.press('Meta+a')
                await page.wait_for_timeout(100)
                await page.keyboard.press('Backspace')
                await page.wait_for_timeout(100)
                await page.keyboard.type(deployment_name, delay=60)
                await page.wait_for_timeout(300)
                await page.mouse.click(_name_coords['x'], _name_coords['y'] + 40)  # click away to trigger blur
                await page.wait_for_timeout(400)
                _filled_name = True
                log(f"Deployment name typed via physical click: {deployment_name!r}")
            else:
                log("WARNING: Could not locate deployment name input — route intercept will patch POST body")

            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_name_filled.png"), full_page=False)

            # ── Select region us-west-2 — physical mouse click on dropdown ────────
            # td#pxCloud_region is the Dijit Select widget's display cell.
            # Physical click opens the dropdown; then click the us-west-2 menu item.
            # The guide is explicit: "Make sure you Select the Region us-west-2".
            # ISE defaults this cell to ap-southeast-1. Make sure the section has
            # finished loading first — probing early is what made this step fail.
            if not await _ise_pxgrid_section_built(page):
                await _ise_wait_pxgrid_region(page, log)
            log("Selecting region us-west-2")
            _set_region = False
            _region_coords = await page.evaluate("""() => {
                const el = document.getElementById('pxCloud_region');
                if (!el) return null;
                el.scrollIntoView({behavior: 'instant', block: 'center'});
                const r = el.getBoundingClientRect();
                if (r.width > 0) return {x: r.left + r.width/2, y: r.top + r.height/2};
                return null;
            }""")
            if _region_coords:
                await page.mouse.click(_region_coords['x'], _region_coords['y'])
                await page.wait_for_timeout(800)
                # Find and click us-west-2 menu item
                _opt_clicked = False
                for _opt_sel in ['.dijitMenuItem:has-text("us-west-2")', '[class*="MenuItem"]:has-text("us-west-2")',
                                  'td:has-text("us-west-2")', '*:has-text("us-west-2")']:
                    try:
                        _opt = page.locator(_opt_sel).first
                        if await _opt.is_visible(timeout=2000):
                            _opt_bb = await _opt.bounding_box()
                            if _opt_bb:
                                await page.mouse.click(_opt_bb['x'] + _opt_bb['width']/2, _opt_bb['y'] + _opt_bb['height']/2)
                                _opt_clicked = True
                                log(f"Region us-west-2 clicked via {_opt_sel!r}")
                                break
                    except Exception:
                        continue
                await page.wait_for_timeout(500)
                _disp = (await page.inner_text('td#pxCloud_region')).strip()
                log(f"Region field now shows: {_disp!r}")
                # NOTE: the displayed value is NOT authoritative. The Dijit Select
                # cell often keeps showing the default (ap-southeast-1) while the
                # request that actually reaches Cisco is corrected in flight by the
                # region intercept below -- registrations confirmed landing in
                # us-west-2 despite this field reading ap-southeast-1. Do not make
                # this display check fatal; it fails runs that would have succeeded.
                if PXGRID_REGION in _disp or _opt_clicked:
                    _set_region = True
            else:
                log("WARNING: Could not locate pxCloud_region element")

            if not _set_region:
                log("WARNING: region select may have failed — proceeding anyway (route intercept patches body)")

            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_region_set.png"), full_page=False)
            await page.wait_for_timeout(500)

            # ── Check Privacy Statement and EULA checkboxes — physical mouse clicks ──
            # Dijit CheckBox set('checked', true) silently fails in newer ISE.
            # JS coordinate lookup + page.mouse.click() fires trusted synthetic events
            # that Dijit's onChange handler actually responds to.
            log("Checking Privacy Statement and EULA checkboxes")
            _legal_result = []
            _cb_coords = await page.evaluate("""() => {
                const results = [];
                // ONLY use known Dijit widget IDs — never fall back to all visible
                // checkboxes as that grabs unrelated ISE node checkboxes (enablePAP etc.)
                if (typeof dijit !== 'undefined' && dijit.byId) {
                    for (const wid of ['pxCloudRegistrationStmt1', 'pxCloudRegistrationStmt2']) {
                        const w = dijit.byId(wid);
                        if (w && w.domNode) {
                            const already = !!(w.get && (w.get('checked') || w.get('value')));
                            // Target the icon span, not the wrapper div
                            const icon = w.domNode.querySelector('.dijitCheckBoxIcon') || w.domNode;
                            icon.scrollIntoView({behavior: 'instant', block: 'center'});
                            const r = icon.getBoundingClientRect();
                            if (r.width > 0) {
                                results.push({x: r.left + r.width/2, y: r.top + r.height/2, id: wid, already});
                            }
                        }
                    }
                }
                return results;
            }""")
            for _cb in _cb_coords:
                if _cb.get('already'):
                    log(f"Checkbox {_cb['id']!r} already checked — skipping")
                    _legal_result.append(f"already:{_cb['id']}")
                else:
                    await page.mouse.click(_cb['x'], _cb['y'])
                    await page.wait_for_timeout(400)
                    log(f"Checkbox {_cb['id']!r} clicked via physical mouse at ({_cb['x']:.0f},{_cb['y']:.0f})")
                    _legal_result.append(f"clicked:{_cb['id']}")
            log(f"Legal checkboxes result: {_legal_result}")
            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_checkboxes.png"), full_page=False)

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
            await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_before_register.png"), full_page=False)

            async def _click_register_btn():
                """Try all methods to click the Register button. Returns True if clicked."""
                # Attempt 0: a TRUSTED click, via real mouse coordinates.
                #
                # This must come first. Register opens the pxGrid Cloud OAuth
                # flow in a POPUP, and browsers only allow window.open() from a
                # user-initiated gesture. Every method below drives the widget
                # programmatically — btn.onClick() from page.evaluate(), or
                # el.click() — which is untrusted, so Chromium suppresses the
                # popup silently. The click "succeeds", no window appears, and
                # ctx.expect_page() times out after 15s reporting "Register
                # opened no OAuth popup" while the form looks perfectly filled.
                # That is exactly how POD-5 failed twice on 2026-09-02 with
                # region us-west-2 correctly selected.
                #
                # page.mouse.click() dispatches through the browser's real input
                # pipeline, so the gesture is trusted and window.open() is
                # permitted. Same reason CLAUDE.md prescribes a coordinate click
                # for SCC's React controls.
                try:
                    _box = await page.evaluate("""() => {
                        const hit = (el) => {
                            const r = el.getBoundingClientRect();
                            return r.width > 0 && r.height > 0 ? r : null;
                        };
                        // Prefer the Dijit button node so we click the widget's
                        // own clickable surface rather than a text span.
                        if (typeof dijit !== 'undefined') {
                            const w = dijit.registry.toArray().find(w => {
                                const lbl = (w.label || w.title || '').trim();
                                const txt = w.domNode ? w.domNode.textContent.trim() : '';
                                return lbl === 'Register' || txt === 'Register';
                            });
                            if (w && w.domNode) {
                                w.domNode.scrollIntoView({block: 'center'});
                                const r = hit(w.domNode);
                                if (r) return {x: r.left + r.width/2, y: r.top + r.height/2};
                            }
                        }
                        for (const el of document.querySelectorAll(
                                'button,[role="button"],.dijitButtonNode')) {
                            if ((el.textContent || '').trim() !== 'Register') continue;
                            el.scrollIntoView({block: 'center'});
                            const r = hit(el);
                            if (r) return {x: r.left + r.width/2, y: r.top + r.height/2};
                        }
                        return null;
                    }""")
                    if _box:
                        await page.mouse.click(_box["x"], _box["y"])
                        log(f"Register clicked as a TRUSTED mouse event at "
                            f"({_box['x']:.0f}, {_box['y']:.0f}) — required for the "
                            f"OAuth popup to be allowed")
                        return True
                    log("Register button has no clickable box — falling back to Dijit")
                except Exception as _mc:
                    log(f"trusted mouse click failed ({type(_mc).__name__}: "
                        f"{str(_mc).splitlines()[0][:90]}) — falling back to Dijit")

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
            _popup_err = ""
            _popup_handled = False
            try:
                # 90s, not 15s. Register does not open the OAuth popup
                # immediately: ISE first shows a "Registering..." spinner while it
                # submits the enrolment, and only then opens the window. On
                # 2026-09-02 POD-5 failed three times with "Register opened no
                # OAuth popup" while a screenshot taken at the moment of failure
                # showed that spinner still turning — we were abandoning a
                # registration that was working. The same snapshot also read the
                # region field as empty, because the form re-renders during
                # submit, which sent two earlier diagnoses down the wrong path.
                async with ctx.expect_page(timeout=90000) as _popup_info:
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

                # Cisco's activate page normally closes the popup itself once the
                # device is activated, and ISE then raises its "Select an Account"
                # dialog in the MAIN page. When the popup lingers that handoff
                # never happens: on POD-5 the popup stayed open, the account
                # dialog never appeared, and the enrollment request was never
                # sent at all — "Region intercept route removed (modified 0)"
                # with no ENROLL POST among the 13 seen. Close it ourselves
                # rather than only waiting for it.
                try:
                    await _popup.wait_for_event("close", timeout=15000)
                    log("OAuth popup closed")
                except Exception:
                    log("OAuth popup did not close on its own — closing it so ISE "
                        "can show the account dialog")
                    try:
                        await _popup.close()
                        await page.wait_for_timeout(2000)
                        log("OAuth popup closed by us")
                    except Exception as _ce:
                        log(f"could not close the OAuth popup: {_ce}")

            except Exception as _pe:
                _popup_err = str(_pe).split("\n")[0][:160]
                log(f"Popup listener error: {_pe} — Register button may not have opened a popup")

            if not _registered:
                return False, "Could not find/click Register button on ISE node edit page"

            if not _popup_handled:
                # Capture the MAIN page here. The only screenshot this step took
                # was inside the popup handler, so when no popup ever opened
                # nothing was written and the message sent the reader to a file
                # that could be months old.
                _shot = "/pipeline/host-data/ise_pxgrid_no_popup.png"
                try:
                    await page.screenshot(path=_shot, full_page=True)
                except Exception as _se:
                    log(f"could not capture failure screenshot: {_se}")
                    _shot = "(screenshot failed)"
                # Report what the form actually looked like — a Register click
                # that opens no popup usually means the form was not accepted,
                # not that the popup was missed.
                try:
                    _state = await page.evaluate("""() => {
                        const g = (id) => {
                            const e = document.getElementById(id);
                            if (!e) return 'absent';
                            const r = e.getBoundingClientRect();
                            const vis = (r.width > 0 && r.height > 0) ? 'visible' : 'hidden';
                            return vis + (e.type === 'checkbox' ? (e.checked ? '/checked' : '/unchecked')
                                                                : '/' + JSON.stringify(e.value || ''));
                        };
                        return {
                            enable: g('enablePxCloudServices'),
                            name:   g('pxCloud_deviceName'),
                            region: g('pxCloud_region'),
                            eula1:  g('pxCloudRegistrationStmt1'),
                            eula2:  g('pxCloudRegistrationStmt2'),
                        };
                    }""")
                except Exception:
                    _state = {}
                log(f"pxGrid form state at failure: {_state}")
                return False, (f"Register opened no OAuth popup ({_popup_err or 'no error'}) "
                               f"— form state {_state}; screenshot {_shot}")

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
                await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_before_register_ise.png"), full_page=False)
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

            # ── Do NOT Save the ISE node after registration ──────────────────────
            # The registration ENROLL POST commits directly to Cisco's cloud — no Save
            # needed. Clicking Save causes ISE to commit the entire node form including
            # enablePxCloudServices=false (Dijit checkbox state doesn't persist through
            # the form submit), which wipes pxGrid Cloud config immediately after
            # registration. ISE already triggers restartAction.do automatically.
            log("Skipping ISE node Save — registration committed directly to Cisco cloud (Save would wipe enablePxCloudServices)")
            await page.wait_for_timeout(2000)

            # ── Poll for pxGrid Cloud connected status (up to ~3 min) ────────────
            # Read the registration panel's own fields. Two earlier bugs lived here:
            #
            #  1. the "refresh" clicked the FIRST visible button matching a very
            #     broad selector, which on this page is the form's Reset button --
            #     so every poll reset the form instead of refreshing status
            #     ("refresh=clicked:dijitReset dijitButtonContents" in the logs);
            #  2. success was matched against phrases like "pxgrid cloud is
            #     connected" / "registration successful" that ISE never renders.
            #     The panel simply shows "Status" / "Connected".
            #
            # Together they made a registration that HAD succeeded -- account
            # PseudoCo-502, region us-west-2, Mode Active, Deregister offered --
            # report "not connected after 3 min".
            _panel = {}
            # 10 minutes, not 3. ISE reports its own transient
            # "Cisco ISE could not connect to pxGrid." while the cloud link is
            # still settling; that is NOT terminal. POD-24 was failed at the
            # 3-minute mark and verified Connected (PseudoCo-524, us-west-2,
            # Active, Deregister present) shortly after — the registration had
            # succeeded and only this check was wrong.
            _refreshed = True   # the panel was just loaded by the register flow
            for _attempt in range(60):  # 60 × 10s = 10 min
                await page.wait_for_timeout(10000)
                _panel = await _pxgrid_panel(page)
                if _pxgrid_is_registered(_panel):
                    log(f"pxGrid Cloud connected on attempt {_attempt + 1}: {_panel}")
                    await page.screenshot(
                        path="/pipeline/host-data/ise_pxgrid_connected.png", full_page=False)

                    # Now that the panel exposes them, assert the registration is
                    # the one we asked for rather than merely present.
                    _bad = []
                    if deployment_name and _panel.get("name") != deployment_name:
                        _bad.append(f"deployment name {_panel.get('name')!r} != {deployment_name!r}")
                    if PXGRID_REGION not in (_panel.get("region") or ""):
                        _bad.append(f"region {_panel.get('region')!r} != {PXGRID_REGION!r}")
                    if _bad:
                        return False, ("pxGrid Cloud connected but registered wrongly: "
                                       + "; ".join(_bad))
                    return True, (f"pxGrid Cloud registered and connected "
                                  f"(account {_panel.get('account')}, "
                                  f"name {_panel.get('name')}, region {_panel.get('region')})")

                log(f"Poll {_attempt + 1}/60: status={_panel.get('status')!r} "
                    f"deregister={_panel.get('deregister')} "
                    f"(panel refreshed: {_refreshed})")

                # Re-navigate periodically: the panel is populated when the node
                # edit page loads, so a stale page can sit on pre-registration
                # content indefinitely.
                if _attempt % 6 == 5:
                    _refreshed = await _ise_reopen_node(page, log)
                    if _refreshed:
                        log("Re-opened node edit page to refresh the pxGrid panel")
                    else:
                        log("WARNING: could not refresh the panel — the status above "
                            "may be stale, NOT the live registration state")

            # FINAL AUTHORITATIVE READ before declaring failure.
            #
            # Twice on 2026-08-31 this step failed a registration that was
            # actually live: POD-24 polled 47 times reporting "Cisco ISE could
            # not connect to pxGrid." while a FRESH browser session showed
            # Connected / PseudoCo-524 / us-west-2 / Active. The poll had lost
            # its ability to refresh the page and was re-reading a stale DOM,
            # so no amount of extra waiting could ever have produced the right
            # answer. A clean re-navigation is the only read worth failing on.
            log("Poll exhausted — doing one clean re-navigation before failing")
            if await _ise_reopen_node(page, log):
                _panel = await _pxgrid_panel(page)
                log(f"authoritative panel read: {_panel}")
                if _pxgrid_is_registered(_panel):
                    _bad = []
                    if deployment_name and _panel.get("name") != deployment_name:
                        _bad.append(f"deployment name {_panel.get('name')!r} != {deployment_name!r}")
                    if PXGRID_REGION not in (_panel.get("region") or ""):
                        _bad.append(f"region {_panel.get('region')!r} != {PXGRID_REGION!r}")
                    if _bad:
                        return False, ("pxGrid Cloud connected but registered wrongly: "
                                       + "; ".join(_bad))
                    return True, (f"pxGrid Cloud registered and connected "
                                  f"(account {_panel.get('account')}, "
                                  f"name {_panel.get('name')}, region {_panel.get('region')}) "
                                  f"— confirmed on the final re-read after a stale poll")
            else:
                # LAST RESORT: a brand-new browser context.
                #
                # If we get here the page is unusable for reading state, so the
                # panel in hand proves nothing — and failing on it is how this
                # step twice marked a live registration as broken (POD-24, both
                # 2026-08-31 and 2026-09-01, while an independent fresh-context
                # read of the same node returned Connected / Active). A new
                # context cannot inherit the stale DOM, and re-logging in is
                # cheap next to falsely failing the step.
                log("could not re-navigate for the final read — retrying in a "
                    "brand-new browser context")
                _ctx2 = _p2 = None
                try:
                    _ctx2 = await page.context.browser.new_context(
                        ignore_https_errors=True)
                    _p2 = await _ctx2.new_page()
                    if await _ise_login(_p2, log):
                        await _p2.goto(
                            f"{ISE_URL}/admin/#administration/administration_system"
                            f"/administration_system_deployment",
                            wait_until="domcontentloaded", timeout=60000)
                        await _p2.wait_for_timeout(5000)
                        await _ise_dismiss_session_info(_p2)
                        await _ise_dismiss_modal(_p2)
                        try:
                            await _p2.wait_for_selector(
                                'table tbody tr, .dijitGrid', timeout=30000)
                        except Exception:
                            await _p2.wait_for_timeout(6000)
                        await _ise_dismiss_modal(_p2)
                        await _p2.locator(
                            'table tbody tr a:text-is("ise"), td a:text-is("ise")'
                        ).first.click(timeout=25000)
                        await _p2.wait_for_timeout(7000)
                        await _ise_dismiss_modal(_p2)
                        _fresh = await _pxgrid_panel(_p2)
                        log(f"fresh-context panel read: {_fresh}")
                        if _pxgrid_is_registered(_fresh):
                            _bad = []
                            if deployment_name and _fresh.get("name") != deployment_name:
                                _bad.append(f"deployment name {_fresh.get('name')!r} "
                                            f"!= {deployment_name!r}")
                            if PXGRID_REGION not in (_fresh.get("region") or ""):
                                _bad.append(f"region {_fresh.get('region')!r} "
                                            f"!= {PXGRID_REGION!r}")
                            if _bad:
                                return False, ("pxGrid Cloud connected but registered "
                                               "wrongly: " + "; ".join(_bad))
                            return True, (f"pxGrid Cloud registered and connected "
                                          f"(account {_fresh.get('account')}, "
                                          f"name {_fresh.get('name')}, "
                                          f"region {_fresh.get('region')}) — confirmed "
                                          f"in a fresh browser context after the poll "
                                          f"lost the ability to refresh")
                        _panel = _fresh   # fail on a read we can actually trust
                except Exception as _fe:
                    log(f"fresh-context read failed too: {type(_fe).__name__}: "
                        f"{str(_fe).splitlines()[0][:110]}")
                finally:
                    for _o in (_ctx2,):
                        try:
                            if _o:
                                await _o.close()
                        except Exception:
                            pass

            # Timed out. Report what the panel actually said -- the old message
            # pointed at a screenshot that could be months old.
            _shot = "/pipeline/host-data/ise_pxgrid_register_final.png"
            try:
                await page.screenshot(path=_shot, full_page=True)
            except Exception:
                _shot = "(screenshot failed)"
            return False, (f"pxGrid Cloud registration saved but not Connected after 10 min "
                           f"— panel: {_panel}; screenshot {_shot}. NOTE the registration "
                           f"itself may still have succeeded: check the ISE node pxGrid panel "
                           f"for Status=Connected before re-running.")

        except Exception as e:
            try:
                await page.screenshot(path=str(Path(__file__).parent / "data" / "ise_pxgrid_register_err.png"), full_page=True)
            except Exception:
                pass
            return False, f"pxGrid Cloud registration error: {e}"
        finally:
            await browser.close()


# ── Step 3: ISE → cdFMC Integration ───────────────────────────────────────────

async def _ise_config_tab_open(page) -> bool:
    """True when the integration's Configuration panel is actually showing.

    The Configuration panel is the only one carrying the instance radios and
    the Data scopes, so their presence is the signal. The "About this
    integration" panel shows Overview/Provider/Supported regions instead.
    """
    try:
        return bool(await page.evaluate("""() => {
            const t = (document.body.innerText || '').toLowerCase();
            return t.includes('new instance') || t.includes('existing instance')
                || t.includes('data scope');
        }"""))
    except Exception:
        return False


async def _ise_open_configuration_tab(page, log) -> bool:
    """Switch to the Configuration tab and CONFIRM the panel rendered.

    The old code did page.locator('text=Configuration').first.click() inside a
    try/except that swallowed failures. 'text=' is a substring match, so .first
    could resolve to "Profiling Configuration" or any wrapper containing the
    word, and nothing verified the switch. On POD-5 the tab never changed: the
    step ran the whole Activate hunt against the "About this integration"
    panel, which has no radios and no Activate button, and reported
    "Activate button not found" with only a 'Push' button on the page.
    """
    for attempt in range(3):
        if await _ise_config_tab_open(page):
            log("Configuration tab is open")
            return True
        for sel in ('[role="tab"]:text-is("Configuration")',
                    'a:text-is("Configuration")',
                    'span:text-is("Configuration")',
                    'div:text-is("Configuration")',
                    ':text-is("Configuration")'):
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=2500):
                    await el.scroll_into_view_if_needed()
                    await el.click(timeout=5000, force=True)
                    await page.wait_for_timeout(2500)
                    if await _ise_config_tab_open(page):
                        log(f"Configuration tab opened via {sel!r}")
                        return True
            except Exception:
                continue
        log(f"Configuration tab not open yet — retry {attempt + 1}/3")
        await page.wait_for_timeout(2500)
    return False


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
                # Available tiles empty — all integrations already activated.
                # FMC appears in the "Activated integrations" table as a clickable
                # link — same pattern as step 3 uses for Cisco Security Cloud.
                # Wait for the table to render before searching (up to 20s).
                log("Available catalog empty — waiting for Activated integrations table to render...")
                try:
                    await page.wait_for_selector(
                        ':text("Firewall Management Center")', timeout=20000)
                except Exception:
                    pass

                _body = (await page.inner_text("body")).lower()
                log(f"Available catalog empty (body snippet: {_body[:200]!r})")

                for fmc_sel in [
                    'a:has-text("Firewall Management Center")',
                    'td:has-text("Firewall Management Center") a',
                    ':text("Firewall Management Center")',
                    'a:has-text("Cisco Secure Firewall Management Center")',
                    ':text("Cisco Secure Firewall Management Center")',
                    'a:has-text("Firewall")',
                    ':text("Cisco Firepower")',
                ]:
                    try:
                        el = page.locator(fmc_sel).first
                        if await el.is_visible(timeout=5000):
                            await el.scroll_into_view_if_needed()
                            await el.click(timeout=10000)
                            log(f"Clicked FMC in Activated integrations via {fmc_sel!r}")
                            _fmc_nav_ok = True
                            await page.wait_for_timeout(2000)
                            break
                    except Exception:
                        continue

                if not _fmc_nav_ok:
                    await page.screenshot(path="/pipeline/host-data/ise_cdfmc_no_fmc.png", full_page=True)
                    return True, f"{_SKIP_PREFIX} FMC not found in catalog (ISE error/no internet) — cdFMC integration skipped"

            await page.wait_for_timeout(2000)

            # Click "Configuration" tab — and verify it actually switched.
            log("Clicking Configuration tab")
            await _ise_dismiss_session_info(page)
            await _ise_dismiss_modal(page)
            if not await _ise_open_configuration_tab(page, log):
                await page.screenshot(
                    path="/pipeline/host-data/ise_cdfmc_no_config_tab.png", full_page=True)
                return False, ("Could not open the FMC Configuration tab — the "
                               "'About this integration' panel stayed active "
                               "(see ise_cdfmc_no_config_tab.png)")

            # Check page state
            page_text = (await page.inner_text("body")).lower()

            # ── If already Active → Deactivate first to get a fresh OTP ────────
            # An existing active instance causes cdFMC to reject the new OTP with
            # "OTP was issued for a different application". Deactivating here ensures
            # ISE issues a clean OTP tied to the new cdFMC instance name.
            try:
                _deact_vis = await page.locator('button:has-text("Deactivate")').first.is_visible(timeout=3000)
            except Exception:
                _deact_vis = False
            if _deact_vis:
                log("FMC → cdFMC integration already Active — deactivating first to obtain a fresh OTP...")
                _da_found = False
                for _da_sel in ['button:has-text("Deactivate")', 'a:has-text("Deactivate")', ':text("Deactivate")']:
                    try:
                        _da_btn = page.locator(_da_sel).first
                        if await _da_btn.is_visible(timeout=5000):
                            await _da_btn.scroll_into_view_if_needed()
                            await _da_btn.click(force=True)
                            _da_found = True
                            log(f"Clicked Deactivate via: {_da_sel}")
                            break
                    except Exception:
                        continue
                if not _da_found:
                    _js_da = await page.evaluate("""() => {
                        const el = Array.from(document.querySelectorAll('button, a, span'))
                            .find(e => e.innerText && e.innerText.trim() === 'Deactivate');
                        if (el) { el.click(); return el.tagName; }
                        return null;
                    }""")
                    if _js_da:
                        log(f"JS Deactivate fallback: {_js_da}")
                    else:
                        log("WARNING: Deactivate button not found — proceeding anyway")
                # Confirm deactivation dialog if one appears
                await page.wait_for_timeout(1500)
                for _conf_sel in ['button:has-text("Deactivate App")', 'button:has-text("Deactivate")',
                                   'button:has-text("Yes")', 'button:has-text("OK")']:
                    try:
                        _c = page.locator(_conf_sel).first
                        if await _c.is_visible(timeout=3000):
                            await _c.click()
                            log(f"Confirmed deactivation dialog via {_conf_sel!r}")
                            break
                    except Exception:
                        continue
                # Wait for Inactive state (page must transition before we can Activate)
                log("Waiting for Inactive status / Existing instances radio (post-deactivate)...")
                for _ws in ['text=Inactive', 'text=Existing instances', 'input[type="radio"]']:
                    try:
                        await page.wait_for_selector(_ws, timeout=20000)
                        log(f"Post-deactivate transition confirmed via {_ws!r} ✓")
                        break
                    except Exception:
                        continue
                log("Waiting 5s for ISE to fully settle post-deactivate...")
                await page.wait_for_timeout(5000)
                await page.screenshot(path="/pipeline/host-data/ise_cdfmc_post_deactivate.png", full_page=True)
                log("Post-deactivate screenshot: ise_cdfmc_post_deactivate.png")

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
            # Unique per run. A fixed name made every re-run collide: cdFMC
            # rejects duplicates with 'PxgridInstance with "..." name already
            # exists', the Create dialog then never closes, and the step reports
            # failure even though the PREVIOUS run had created, activated and
            # saved the instance successfully. The cleanup pass below deletes the
            # superseded instances, which is the guide's "you may now Delete the
            # Application Instance after the new one is saved".
            import time as _tn
            instance_name = f"ISE-FMC-POD-{pod_id}-{int(_tn.time()) % 10000:04d}"
            log(f"cdFMC instance name for this run: {instance_name}")
            _ipc_ok, _ipc_msg = _scc_file_ipc_cdfmc(pod_id, otp_token, instance_name, log)
            if not _ipc_ok:
                return False, _ipc_msg
            return True, _ipc_msg


            # Handle org picker / login if redirected

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

    # ── Early pre-flight ──────────────────────────────────────────────────────
    # The SCC half of this step runs on the host, which now mints its own
    # session from the org's iDAC URL (see dashboard._host_scc_open). The old
    # checks here — file present, under 8h old, Okta token not near expiry —
    # described a stored session that is no longer the primary credential, and
    # they refused runs that would have succeeded: the file is routinely absent
    # or months stale while the iDAC login works fine.
    #
    # What still matters is that the host will have *something* to log in with,
    # so fail fast (before 4+ minutes of ISE navigation) only when it will not.
    if not (creds.get("idac_url") or "").strip() and not Path(session_path).exists():
        return False, ("no iDAC URL for this org and no stored SCC session — "
                       "set the iDAC URL in Org Credentials, or click 'Refresh SCC Sessions'")
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

            # Open Cisco Security Cloud BY NAME. It may sit in either catalog
            # section, so never click a positional "More details" -- see
            # _open_integration.
            log("Opening Cisco Security Cloud details")
            await _ise_dismiss_modal(page)
            await _ise_dismiss_session_info(page)
            await page.wait_for_timeout(1500)
            await _ise_dismiss_modal(page)
            if not await _open_integration(page, "Cisco Security Cloud", log):
                return False, "Cisco Security Cloud not found in the ISE Integration Catalog"
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

            # Is the integration already Active, in which case there is nothing
            # to create?
            #
            # This used to accept ':text-is("Active")' or ':text-is("Activated")'
            # matching ANY element on the page — a column header, a legend, an
            # unrelated component's status — and returned success on the first
            # hit. Two problems with that, and the second is the serious one:
            #
            #   1. The selectors were unscoped. "Active" is one of the most
            #      common words on an ISE admin page.
            #   2. It only ever consulted ISE's HALF of a two-sided integration.
            #      ISE goes on reporting Active after the SCC end is deleted, so
            #      on 2026-09-01 POD-5 skipped this step with nothing in SCC at
            #      all — the SCC reset had removed ISE-POD-POD-5-493 an hour
            #      earlier and ISE never noticed.
            #
            # Require the Deactivate CONTROL specifically. Unlike the word
            # "Active", a Deactivate button only exists when this panel has a
            # live registration to deactivate, so it is evidence about this
            # integration rather than about the page. Ambiguous states now fall
            # through and re-create, which is safe: step 3 deactivates and
            # reactivates immediately afterwards and must always run anyway (SCC
            # never reaches Active without that cycle).
            _already_active = False
            for act_chk in ['button:has-text("Deactivate")',
                            '[role="button"]:has-text("Deactivate")',
                            'a:has-text("Deactivate")']:
                try:
                    if await page.locator(act_chk).first.is_visible(timeout=2000):
                        _already_active = True
                        break
                except Exception:
                    continue
            if _already_active:
                # Even a Deactivate control only proves ISE's side. Say so, so a
                # green here is never mistaken for "verified in SCC" — the host
                # half checks the Active Integrations table, this cannot.
                log("Deactivate control present — ISE side already Active; skipping create")
                return True, ("ISE→SCC integration already Active on the ISE side "
                              "(skipped create; SCC side not verified here)")
            log("no Deactivate control — treating as not yet integrated, creating")

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

        except Exception as e:
            return False, f"ISE \u2192 Secure Access integration error: {e}"
        finally:
            await browser.close()


# ── Main card runner ──────────────────────────────────────────────────────────

# These three depend on lab internet access, which is outside our control, so a
# failure must not abort the rest of the card. They are stepped over — but a
# failure that is stepped over is still a failure and is reported as 'degraded',
# never as a success. See _summarise_outcomes.
SOFT_FAIL_STEPS = (
    "ise_cdfmc_integrate",
    "ise_scc_deactivate_reactivate",
    "ise_sgt_verify",
)


def _summarise_outcomes(outcomes: list) -> tuple[bool, str]:
    """Turn per-step outcomes into an honest (ok, message) pair.

    Only 'completed' and a deliberate self-skip ("SKIP: ...", which means the
    step decided it had nothing to do) count as success. A step that failed and
    was stepped over counts as 'degraded'.

    This exists because the card used to `return True, "All ISE integration
    steps completed"` unconditionally: a run where one step failed and three
    were stepped over still reported success, so the card showed green over a
    POD on which no ISE integration had actually happened.
    """
    done     = [s for s, st, _ in outcomes if st == "completed"]
    skipped  = [s for s, st, _ in outcomes if st == "skipped"]
    degraded = [(s, m) for s, st, m in outcomes if st == "degraded"]
    failed   = [(s, m) for s, st, m in outcomes if st == "failed"]

    def names(items):
        return ", ".join(ISE_STEP_LABELS.get(s, s) for s, _ in items)

    parts = [f"{len(done)}/{len(outcomes)} completed"]
    if skipped:
        parts.append(f"{len(skipped)} skipped (nothing to do)")
    if degraded:
        parts.append(f"{len(degraded)} DEGRADED: {names(degraded)}")
    if failed:
        parts.append("FAILED: " + "; ".join(
            f"{ISE_STEP_LABELS.get(s, s)} — {m}" for s, m in failed))
    return (not failed and not degraded), " | ".join(parts)


def ise_run_card(pod_id: str, db_path: str, from_step: int = 0, log=None) -> tuple[bool, str]:
    """
    Run the ISE integration card for a POD.

    from_step is a 0-indexed offset into ISE_STEPS: from_step=2 starts at the
    third step. Steps that return (True, "SKIP: ...") are marked 'skipped'.

    Returns (ok, summary). ok is True only when every step that ran either
    completed or skipped itself deliberately.
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

    outcomes: list = []

    for i, step in enumerate(ISE_STEPS):
        if i < from_step:
            continue

        # Skip steps already completed or skipped — no need to re-run
        # Use _db_connect (with retry) so transient I/O errors don't cause
        # completed steps to silently re-run.
        try:
            with closing(_db_connect(db_path)) as _skip_db:
                _row = _skip_db.execute(
                    "SELECT status, result FROM ise_steps WHERE pod_id=? AND step_name=?",
                    (pod_id, step)
                ).fetchone()
            _prev_status = _row[0] if _row else ""
            _prev_result = (_row[1] or "") if _row else ""
            _was_soft_fail = _prev_result.startswith("[soft-fail]")

            # A '[soft-fail]' row is a FAILURE that was stepped over, not a step
            # that decided it had nothing to do. It must be retried.
            #
            # This code already recognised the distinction — it labelled such a
            # row "degraded" — and then skipped it anyway, so a soft-failed step
            # could never re-run. Once cdFMC soft-failed on POD-5 (an ISE login
            # that failed inside the database-corruption window, minutes after
            # three clean logins), every subsequent re-run reported "already
            # skipped, skipping" and the POD kept its failure permanently. The
            # only way out was editing the row by hand, which is not a workflow.
            #
            # A deliberate self-skip is different — "pxGrid Cloud already
            # registered and connected" is a step verifying live state and
            # finding nothing to do. Those still count as done.
            if _row and _prev_status in ("completed", "skipped") and not _was_soft_fail:
                _log(f"Step {i+1}/{len(ISE_STEPS)}: {ISE_STEP_LABELS[step]} — "
                     f"already {_prev_status}, skipping")
                outcomes.append((step, _prev_status, _prev_result or f"already {_prev_status}"))
                continue
            if _was_soft_fail:
                _log(f"Step {i+1}/{len(ISE_STEPS)}: {ISE_STEP_LABELS[step]} — "
                     f"retrying a previously soft-failed step "
                     f"({_prev_result[:80]})")
        except Exception as _skip_e:
            _log(f"[warn] skip-check DB error for {step}: {_skip_e} — proceeding to run step")

        _ise_step_set(pod_id, step, "running", "", db_path)
        # Confirm the mark actually landed. POD-24's ise_scc_integrate showed
        # 'pending' with no started_at for the whole time it was running, so the
        # card looked idle during a multi-minute step. The UPSERT is correct in
        # isolation, so log what the row really says — next time this happens it
        # is diagnosable instead of gone with the run.
        try:
            with closing(_db_connect(db_path)) as _vdb:
                _vr = _vdb.execute(
                    "SELECT status, started_at FROM ise_steps WHERE pod_id=? AND step_name=?",
                    (pod_id, step)).fetchone()
            if not _vr or _vr[0] != "running":
                _log(f"[warn] {step} did not take the 'running' mark — row reads "
                     f"{_vr[0] if _vr else 'MISSING'!r}; the card will look idle")
        except Exception as _ve:
            _log(f"[warn] could not verify the running mark for {step}: {_ve}")
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

        if ok:
            # "SKIP: ..." means the step decided it had nothing to do, which is
            # a success. Anything else that returned ok is a completion.
            status = "skipped" if msg.startswith(_SKIP_PREFIX) else "completed"
            _ise_step_set(pod_id, step, status, msg, db_path)
            _log(f"  \u2192 {status}: {msg}")
            outcomes.append((step, status, msg))
            continue

        if step in SOFT_FAIL_STEPS:
            # Step over it, but record it as degraded so the card cannot report
            # success. The DB row stays 'skipped' so the UI still renders it
            # amber rather than red; the [soft-fail] prefix is what marks it as
            # a carried-over failure on any later re-run.
            _ise_step_set(pod_id, step, "skipped", f"[soft-fail] {msg}", db_path)
            _log(f"  \u2192 DEGRADED (soft-fail, continuing): {msg}")
            outcomes.append((step, "degraded", msg))
            continue

        _ise_step_set(pod_id, step, "failed", msg, db_path)
        _log(f"  \u2192 failed: {msg}")
        outcomes.append((step, "failed", msg))
        return _summarise_outcomes(outcomes)

    return _summarise_outcomes(outcomes)


# ══════════════════════════════════════════════════════════════════════════════
# ISE TEARDOWN
#
# Removes everything the ISE card creates, so a clean-org re-test is possible
# without hand-deleting through three consoles.
#
# Runs entirely inside the pipeline container. The card's forward path bounces
# SCC work to the host over file IPC because Okta *silent renew* fails under the
# VPN, but that only affects restoring a saved session — a fresh iDAC SAML login
# performs no silent renew and works from in here (verified on POD-17, async, on
# the pod's VPN namespace). Keeping teardown in one process means one log stream
# and one error path instead of a request/result file round-trip.
#
# Every stage asserts the object is GONE by re-reading state, rather than
# treating "the click did not raise" as success.
# ══════════════════════════════════════════════════════════════════════════════

async def _scc_open_session_async(ctx, idac_url: str, log):
    """Async twin of duo_automation._scc_open_session.

    Opens an authenticated SCC tab through the iDAC card's SAML auto-login and
    returns (page, enterprise_id). No password, no stored session; loading a
    stored iDAC URL is read-only (only idac_sdk reprovisions).
    """
    pg = await ctx.new_page()
    await pg.goto(idac_url, wait_until="load", timeout=45_000)
    await pg.wait_for_timeout(5_000)
    async with ctx.expect_page(timeout=25_000) as info:
        await pg.evaluate("""() => {const b=Array.from(document.querySelectorAll('button,a'))
            .find(x=>/^view$/i.test((x.innerText||'').trim())); if(b)b.click();}""")
    tab = await info.value
    await tab.wait_for_load_state("load", timeout=30_000)
    for _ in range(18):
        await tab.wait_for_timeout(5_000)
        if "enterpriseId=" in tab.url:
            break
    if "enterpriseId=" not in tab.url:
        raise RuntimeError(f"SCC session never settled (url={tab.url[:120]})")
    ent = tab.url.split("enterpriseId=")[1].split("&")[0]
    log(f"SCC session established (enterprise {ent[:8]}...)")
    return tab, ent


async def _scc_count_ise_integrations(page, eid: str) -> int:
    """How many ISE integrations SCC currently lists. Reloads before counting."""
    # The Active Integrations table lives at /integrations/main/my-integrations.
    # Plain /integrations renders a different view whose table is empty, so
    # counting there reports 0 rows while integrations plainly exist -- which
    # would make the teardown below report "already clean" and delete nothing.
    await page.goto(
        f"https://security.cisco.com/integrations/main/my-integrations?enterpriseId={eid}",
        wait_until="domcontentloaded", timeout=60_000)
    for _ in range(12):
        await page.wait_for_timeout(5_000)
        body = (await page.evaluate("() => document.body.innerText") or "")
        if len(body.strip()) > 200:
            break
    return await page.evaluate("""() => Array.from(document.querySelectorAll('tr'))
        .filter(r => /\\bISE\\b|pxgrid/i.test(r.innerText || '')).length""")


async def _scc_delete_ise_integrations(page, eid: str, log) -> tuple[bool, str]:
    """Delete every ISE/pxGrid integration in SCC. Verifies by re-counting."""
    before = await _scc_count_ise_integrations(page, eid)
    log(f"SCC integrations hub: {before} ISE row(s) present")
    if not before:
        return True, "SCC: no ISE integration present (already clean)"

    # The row's action menu is its LAST button — it is an icon-only kebab with
    # no text and no stable test id.
    for attempt in range(before + 2):
        n = await _scc_count_ise_integrations(page, eid)
        if not n:
            break
        try:
            row = page.locator("tr").filter(has_text="ISE").first
            await row.locator("button").last.click(force=True, timeout=5_000)
            await page.wait_for_timeout(900)
        except Exception as e:
            log(f"SCC: could not open row menu on attempt {attempt + 1}: {e}")
            break

        clicked = False
        for sel in ('[role="menuitem"]:has-text("Delete")', 'button:has-text("Delete")',
                    '[role="menuitem"]:has-text("Remove")', 'a:has-text("Delete")'):
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=1_500):
                    await el.click()
                    await page.wait_for_timeout(900)
                    clicked = True
                    break
            except Exception:
                continue
        if not clicked:
            log("SCC: no Delete item in the row menu")
            break

        for sel in ('button:has-text("Delete")', 'button:has-text("Yes")',
                    'button:has-text("Confirm")'):
            try:
                el = page.locator(sel).first
                if await el.is_visible(timeout=2_000):
                    await el.click()
                    await page.wait_for_timeout(2_000)
                    break
            except Exception:
                continue
        await page.wait_for_timeout(3_000)

    after = await _scc_count_ise_integrations(page, eid)
    if after:
        return False, f"SCC: {after} ISE integration(s) still present after delete"
    return True, f"SCC: deleted {before} ISE integration(s)"


async def _ise_deactivate_scc(page, log) -> tuple[bool, str]:
    """Deactivate the Cisco Security Cloud integration on ISE. Verifies the state flipped."""
    if not await _navigate_to_integration_catalog(page, log):
        return False, "ISE: Integration Catalog did not load"

    body = (await page.evaluate("() => document.body.innerText") or "")
    if "cisco security cloud" not in body.lower():
        return True, "ISE: Cisco Security Cloud not in catalog (already clean)"

    try:
        await page.locator(':text("Cisco Security Cloud")').first.click(timeout=8_000)
        await page.wait_for_timeout(2_500)
    except Exception as e:
        return False, f"ISE: could not open Cisco Security Cloud: {e}"

    for sel in ('text=Configuration', 'button:has-text("Configuration")'):
        try:
            el = page.locator(sel).first
            if await el.is_visible(timeout=3_000):
                await el.click()
                await page.wait_for_timeout(2_500)
                break
        except Exception:
            continue

    body = (await page.evaluate("() => document.body.innerText") or "")
    if "deactivate" not in body.lower():
        return True, "ISE: no Active instance to deactivate (already clean)"

    try:
        await page.locator('button:has-text("Deactivate")').first.click(timeout=8_000)
        await page.wait_for_timeout(1_500)
    except Exception as e:
        return False, f"ISE: Deactivate click failed: {e}"

    # The confirm dialog repeats the word, so try the specific label first.
    for sel in ('button:has-text("Deactivate App")', 'button:has-text("Deactivate")',
                'button:has-text("Confirm")', 'button:has-text("Yes")'):
        try:
            el = page.locator(sel).last
            if await el.is_visible(timeout=2_500):
                await el.click()
                await page.wait_for_timeout(2_000)
                break
        except Exception:
            continue

    # Assert: Active is gone. "Existing instances" or a visible Activate button
    # both mean the instance is no longer live.
    for _ in range(12):
        await page.wait_for_timeout(5_000)
        body = (await page.evaluate("() => document.body.innerText") or "").lower()
        if "existing instances" in body or ("activate" in body and "deactivate" not in body):
            return True, "ISE: Cisco Security Cloud deactivated"
    return False, "ISE: still shows Deactivate — instance did not go inactive"


async def _ise_teardown_async(pod_id: str, creds: dict, log) -> tuple[bool, str]:
    from playwright.async_api import async_playwright

    idac = (creds.get("idac_url") or "").strip()
    results: list = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(
            headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = await browser.new_context(ignore_https_errors=True,
                                        viewport={"width": 1920, "height": 1080})
        try:
            # ── 1. ISE: deactivate the integration first ──────────────────────
            # Before SCC, so ISE stops pushing; deleting on the SCC side first
            # leaves ISE holding a stale Active instance that confuses the next run.
            page = await ctx.new_page()
            page.set_default_timeout(30_000)
            if not await _ise_login(page, log):
                return False, "ISE login failed"
            ok, msg = await _ise_deactivate_scc(page, log)
            log(f"  {msg}")
            results.append(("ise", ok, msg))

            # ── 2. SCC: delete the integration rows ───────────────────────────
            if not idac:
                results.append(("scc", False, "SCC: no idac_url for this org — cannot log in"))
                log("  SCC: no idac_url for this org — cannot log in")
            else:
                scc_page, eid = await _scc_open_session_async(ctx, idac, log)
                ok, msg = await _scc_delete_ise_integrations(scc_page, eid, log)
                log(f"  {msg}")
                results.append(("scc", ok, msg))
        finally:
            await ctx.close()
            await browser.close()

    failed = [m for _, ok, m in results if not ok]
    summary = " | ".join(m for _, _, m in results)
    return (not failed), summary


def ise_teardown(pod_id: str, db_path: str, log=None) -> tuple[bool, str]:
    """Remove everything the ISE card creates, for a clean-org re-test.

    Deactivates Cisco Security Cloud on ISE, then deletes the ISE integration
    rows in SCC. Each stage re-reads state to confirm the object is gone.

    Does NOT touch the cdFMC pxGrid instance — that lives in a separate console
    and its delete flow has not been established yet; it is reported as manual.
    """
    _log = log or (lambda s: print(f"  [ise-teardown] {s}"))
    creds = _load_creds(pod_id, db_path)
    if creds is None:
        return False, f"POD {pod_id} not found or scc_org not set"

    _log(f"Tearing down ISE integrations for {pod_id}")
    try:
        ok, msg = asyncio.run(_ise_teardown_async(pod_id, creds, _log))
    except Exception as e:
        return False, f"teardown error: {e}"

    # Clear the card's step rows so the next run starts genuinely fresh.
    if ok:
        try:
            with closing(_db_connect(db_path)) as c:
                c.execute("DELETE FROM ise_steps WHERE pod_id=?", (pod_id,))
                c.commit()
            _log("Cleared ise_steps rows")
        except sqlite3.Error as e:
            _log(f"[warn] could not clear ise_steps: {e}")

    return ok, msg + " | cdFMC pxGrid instance must still be removed by hand"
