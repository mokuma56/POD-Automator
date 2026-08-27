#!/usr/bin/env python3
"""
Refresh the authproxy enrollment blob for a POD's Duo org.

Uses the persistent Chrome profile (same one as refresh_scc_sessions.py) to:
  1. Navigate to SCC (auto-auth via saved Chrome profile)
  2. Open Duo admin portal via SSO
  3. SSO Settings → External Authentication Sources → Active Directory
     → Auth Proxy → Generate Command → extract new blob
  4. Also extract Okta token → get SA management JWT → regenerate SA SCIM token
  5. Save both blob + scim_token to org_credentials in DB
  6. Reset authproxy_enroll / scim_push / verify to pending in duo_steps

Usage:
  uv run python3 refresh_authproxy_blob.py [pod_id] [db_path]
  uv run python3 refresh_authproxy_blob.py POD-2

After this runs, trigger the Duo card re-run from the dashboard (from authproxy_enroll).
"""

import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

DATA_DIR    = Path(__file__).parent / "data"
PROFILE_DIR = DATA_DIR / "scc_chrome_profile"
DEFAULT_DB  = DATA_DIR / "pod_state.db"

# ────────────────────────────────────────────────────────────────────────────
def log(msg: str) -> None:
    print(f"[blob-refresh] {msg}", flush=True)


def _get_copy_content(page, hint: str) -> str:
    """Extract text near a hint label from pre/code/textarea elements."""
    for sel in [
        f"*:has-text('{hint}') pre",
        f"*:has-text('{hint}') code",
        f"*:has-text('{hint}') textarea",
        f"*:has-text('{hint}') .highlight",
    ]:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                t = loc.inner_text(timeout=3000).strip()
                if t and len(t) > 10:
                    return t
        except Exception:
            pass

    # Fallback: click Copy button near hint and read clipboard
    try:
        btn = page.locator(f"*:has-text('{hint}') button:has-text('Copy')").first
        if btn.count() > 0:
            btn.click(timeout=5000)
            page.wait_for_timeout(500)
            # Read clipboard via JS
            t = page.evaluate(
                "async () => { try { return await navigator.clipboard.readText(); } "
                "catch(e) { return ''; } }"
            )
            if isinstance(t, str) and len(t) > 10:
                return t
    except Exception:
        pass

    # Scan all pre/code for authproxy markers
    try:
        for el in reversed(page.locator("pre, code, textarea").all()):
            try:
                t = el.inner_text(timeout=2000).strip()
                # Blob is a base64 JSON containing api_host + signing_skey
                if len(t) > 40 and re.match(r'^[A-Za-z0-9+/=]+$', t.replace('\n', '')):
                    return t.replace('\n', '')
            except Exception:
                pass
    except Exception:
        pass

    return ""


def _click_first(page, selectors: list, timeout: int = 8000, required=False) -> bool:
    for sel in selectors:
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                loc.scroll_into_view_if_needed(timeout=2000)
                loc.click(timeout=timeout)
                log(f"  clicked: {sel!r}")
                return True
        except Exception:
            pass
    if required:
        log(f"  WARN: could not click any of {selectors}")
    return False


def _navigate_to_duo_admin(page, duo_host: str) -> bool:
    """Navigate to Duo admin portal, handling SCC SSO redirect if needed."""
    admin_url = f"https://{duo_host}/admin"
    log(f"navigating to Duo admin: {admin_url}")
    try:
        page.goto(admin_url, timeout=30_000, wait_until="domcontentloaded")
    except Exception as e:
        log(f"  navigation warning: {e}")

    page.wait_for_timeout(3000)
    cur = page.url
    log(f"  URL after navigate: {cur[:100]}")

    # Already in Duo admin dashboard
    if duo_host in cur and "/login" not in cur:
        log("  already in Duo admin dashboard")
        return True

    # Redirected to SCC login or Duo login
    if "security.cisco.com" in cur or "sign-on" in cur or "id.cisco.com" in cur:
        log("  SCC auth required — waiting for login (up to 3 min) ...")
        deadline = time.time() + 180
        while time.time() < deadline:
            time.sleep(3)
            cur = page.url
            if duo_host in cur and "/login" not in cur:
                log(f"  Duo admin authenticated: {cur[:80]}")
                return True
            if "security.cisco.com" in cur and "login" not in cur:
                # On SCC dashboard — navigate to Duo via Products menu
                log("  On SCC — navigating to Duo admin via Products menu ...")
                try:
                    page.goto(
                        "https://security.cisco.com/duo/admin",
                        timeout=20_000, wait_until="domcontentloaded",
                    )
                except Exception:
                    pass
                page.wait_for_timeout(3000)
                # Also try clicking Products → Duo Security
                for sel in [
                    "a:has-text('Duo Security')", "a:has-text('Duo Admin')",
                    "*[href*='duo']", "a:has-text('Duo')",
                ]:
                    try:
                        loc = page.locator(sel).first
                        if loc.is_visible(timeout=2000):
                            loc.click()
                            page.wait_for_timeout(3000)
                            break
                    except Exception:
                        pass
        log("  WARN: timed out waiting for Duo admin portal")
        return duo_host in page.url

    # Duo login page — try direct login (may work with SSO session)
    if "/login" in cur and "duosecurity" in cur:
        log("  Duo login page — attempting direct email/password login ...")
        return duo_host in page.url  # handled by caller

    return duo_host in page.url


def _get_enrollment_blob_from_portal(page, duo_host: str, ctx=None) -> str:
    """Navigate SSO Settings → External Auth Sources → AD → Auth Proxy → get blob."""

    base = f"https://{duo_host}"

    # Helper: get the active live page (might be a new tab after navigation)
    def _active_page():
        if ctx:
            pages = ctx.pages
            if pages:
                # Return the most recently created page
                return pages[-1]
        return page

    # 1. Navigate to /admin/sso — use current page URL + fragment if possible
    log("navigating to /admin/sso ...")
    active = _active_page()
    try:
        active.goto(f"{base}/admin/sso", timeout=20_000, wait_until="domcontentloaded")
        active.wait_for_timeout(2000)
    except Exception as e:
        log(f"  /admin/sso navigation issue: {e}")
        # If page closed, a new tab might have opened
        active = _active_page()
        if active.url != "about:blank":
            log(f"  new active page URL: {active.url[:100]}")
        else:
            log("  no active page found after navigation error")
            return ""

    # Re-check active page after navigation
    active = _active_page()
    log(f"  URL after sso nav: {active.url[:80]}")

    # If redirected to login, we can't proceed automatically
    if "login" in active.url and duo_host not in active.url:
        log("  WARN: redirected to login — session may have expired")
        try:
            active.screenshot(path=str(DATA_DIR / "blob_refresh_login_redir.png"))
        except Exception:
            pass
        return ""

    # 2. Click External Authentication Sources tab
    log("clicking External Authentication Sources ...")
    _click_first(page, [
        "a:has-text('External Authentication Sources')",
        "button:has-text('External Authentication Sources')",
        "[role='tab']:has-text('External')",
        ".nav-tabs a:has-text('External')",
        "a[href*='ext_auth']",
    ], timeout=10_000)
    page.wait_for_timeout(3000)  # extra wait for async tab content

    # Screenshot to diagnose what page looks like
    try:
        page.screenshot(path=str(DATA_DIR / "blob_refresh_ext_auth_tab.png"))
        log("  screenshot: data/blob_refresh_ext_auth_tab.png")
    except Exception:
        pass

    body = ""
    try:
        body = page.inner_text("body")
    except Exception:
        pass
    log(f"  page text snippet: {body[:200].replace(chr(10), ' ')!r}")

    # 3. Check if AD already configured or needs to be added
    ad_present = "Active Directory" in body

    if ad_present:
        log("AD source already present — clicking Active Directory link ...")
        _click_first(page, [
            "a:has-text('Active Directory')",
            "td:has-text('Active Directory') a",
            "tr:has-text('Active Directory') a",
        ], timeout=8000)
        page.wait_for_timeout(2000)
    else:
        log("AD source not present — adding ...")
        _click_first(page, [
            "button:has-text('Add Source')", "a:has-text('Add Source')",
            "button:has-text('+ Add Source')",
        ], required=True)
        page.wait_for_timeout(800)
        _click_first(page, [
            "button:has-text('Add Active Directory')",
            "a:has-text('Active Directory')",
            "li:has-text('Active Directory')",
        ], required=True)
        page.wait_for_timeout(1500)
        _click_first(page, ["button:has-text('Accept')", "button:has-text('Agree')"])
        page.wait_for_timeout(800)
        _click_first(page, [
            "button:has-text('Configure Active Directory')",
            "a:has-text('Configure Active Directory')",
        ], required=True)
        page.wait_for_timeout(2000)

    log(f"AD page URL: {page.url[:80]}")

    # 4. Add/find Authentication Proxy
    body = page.inner_text("body") if page.locator("body").count() else ""
    proxy_present = "Authentication Proxy" in body and ("Connected" in body or "Step 1" in body or "Add Authentication Proxy" not in body)
    
    log("clicking Add Authentication Proxy (or finding existing) ...")
    _click_first(page, [
        "button:has-text('Add Authentication Proxy')",
        "a:has-text('Add Authentication Proxy')",
        "button:has-text('+ Add Authentication Proxy')",
        "a:has-text('Authentication Proxy')",
    ])
    page.wait_for_timeout(2500)
    log(f"  URL after proxy click: {page.url[:80]}")

    # Take a diagnostic screenshot
    try:
        page.screenshot(path=str(DATA_DIR / "blob_refresh_proxy_page.png"))
        log("  screenshot: data/blob_refresh_proxy_page.png")
    except Exception:
        pass

    # 5. Try to find "Generate Command" button and click it
    log("looking for Generate Command button ...")
    gen_clicked = _click_first(page, [
        "button:has-text('Generate Command')",
        "a:has-text('Generate Command')",
        ":text('Generate Command')",
        "button:has-text('Generate')",
    ], timeout=8000)
    if gen_clicked:
        page.wait_for_timeout(2000)
        log("  Generate Command clicked")
        try:
            page.screenshot(path=str(DATA_DIR / "blob_refresh_after_generate.png"))
        except Exception:
            pass

    # 6. Extract the blob from Step 2 area
    log("extracting enrollment blob ...")
    blob = (
        _get_copy_content(page, "Generate Command")
        or _get_copy_content(page, "2.")
        or _get_copy_content(page, "Step 2")
        or _get_copy_content(page, "Connect the Authentication")
        or _get_copy_content(page, "enroll")
    )

    if not blob:
        # Scan all base64-like content on page
        log("  scanning page for base64 blob ...")
        try:
            all_text = page.content()
            # Look for JSON blob pattern (base64-encoded JSON with api_host key)
            m = re.search(
                r'"([A-Za-z0-9+/]{60,}={0,2})"',
                all_text
            )
            if m:
                candidate = m.group(1)
                # Verify it decodes to something with api_host
                try:
                    import base64
                    decoded = base64.b64decode(candidate).decode()
                    if "api_host" in decoded or "sso" in decoded:
                        blob = candidate
                        log(f"  found blob via HTML scan (len={len(blob)})")
                except Exception:
                    pass
        except Exception:
            pass

    if blob:
        # Clean up the blob: strip EXE path prefix if present
        # authproxy_update_sso_enrollment_code.exe <blob>
        import re as _re
        m = _re.search(r'\.exe["\s]+([A-Za-z0-9+/=]{20,})', blob)
        if m:
            blob = m.group(1)
            log(f"  stripped EXE prefix → blob len={len(blob)}")
        # Validate: try to decode
        try:
            import base64 as _b64
            decoded = json.loads(_b64.b64decode(blob).decode())
            if "api_host" in decoded:
                log(f"  blob valid: api_host={decoded.get('api_host')}, "
                    f"proxy_key={decoded.get('proxy_key', '')[:10]}...")
        except Exception as e:
            log(f"  WARN: blob does not decode to expected JSON: {e}")

    return blob


def _get_okta_token_from_page(ctx) -> str:
    """Extract Okta access token from localStorage of any SCC origin."""
    try:
        state = ctx.storage_state()
        for origin in state.get("origins", []):
            for item in origin.get("localStorage", []):
                if item.get("name") == "okta-token-storage":
                    try:
                        tok_data = json.loads(item.get("value", "{}"))
                        access = tok_data.get("accessToken", {})
                        if access:
                            t = access.get("accessToken", "") or access.get("value", "")
                            if t:
                                log(f"  Okta accessToken extracted (len={len(t)})")
                                return t
                    except Exception:
                        pass
    except Exception:
        pass
    return ""


def _generate_sa_scim_token(okta_token: str, sa_org_id: str) -> str:
    """Exchange Okta token → SA mgmt JWT → generate new SCIM token."""
    import requests
    if not okta_token or not sa_org_id:
        return ""
    try:
        log(f"  exchanging Okta token for SA mgmt JWT (org={sa_org_id}) ...")
        r = requests.post(
            "https://api.umbrella.com/auth/v2/oauth2/jwt-bearer/token",
            data={
                "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
                "assertion":  okta_token,
                "scope":      f"org/{sa_org_id}",
            },
            timeout=15,
        )
        if not r.ok:
            log(f"  mgmt JWT exchange: HTTP {r.status_code} — {r.text[:100]}")
            return ""
        mgmt_jwt = r.json().get("access_token", "")
        if not mgmt_jwt:
            log("  mgmt JWT not found in response")
            return ""
        log(f"  mgmt JWT obtained (len={len(mgmt_jwt)})")

        # Generate SCIM token
        r2 = requests.post(
            f"https://management.api.umbrella.com/auth/v2/organizations/{sa_org_id}/apikeys",
            headers={"Authorization": f"Bearer {mgmt_jwt}", "Content-Type": "application/json"},
            json={"label": "Duo SCIM Token"},
            timeout=15,
        )
        if not r2.ok:
            log(f"  SCIM token gen: HTTP {r2.status_code} — {r2.text[:100]}")
            return ""
        data = r2.json()
        token = (data.get("auth_key") or data.get("token") or
                 data.get("key") or data.get("access_token") or "")
        if token:
            log(f"  SA SCIM token generated (len={len(token)})")
        return token
    except Exception as e:
        log(f"  SA SCIM token error: {e}")
        return ""


def run(pod_id: str = "POD-2", db_path: str = str(DEFAULT_DB)) -> bool:
    log(f"Starting authproxy blob refresh for {pod_id} (db={db_path})")

    # ── Load creds from DB ────────────────────────────────────────────────────
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        pod_row = conn.execute(
            "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
        ).fetchone()
        if not pod_row:
            log(f"ERROR: POD {pod_id} not found in DB")
            return False
        scc_org = pod_row["scc_org"] or ""
        m = re.search(r"pseudoco-(\d+)", scc_org)
        if not m:
            log(f"ERROR: cannot extract org number from scc_org={scc_org!r}")
            return False
        org_num = m.group(1)
        oc = dict(conn.execute(
            "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
        ).fetchone() or {})

    duo_host  = oc.get("duo_host", "").strip()
    sa_org_id = oc.get("sa_org_id", "").strip()

    m_host = re.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    admin_host = f"admin-{m_host.group(1)}.duosecurity.com" if m_host else duo_host.replace("api-", "admin-")
    log(f"Duo admin host: {admin_host}, SA org: {sa_org_id}")

    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    log(f"Using persistent Chrome profile: {PROFILE_DIR}")

    blob = ""
    scim_token = ""

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        # Use Playwright's own Chromium (NOT system Chrome via channel="chrome")
        # to avoid profile lock conflicts when Chrome.app is already running.
        ctx = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            headless=False,
            no_viewport=True,
            args=[
                "--start-maximized",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-blink-features=AutomationControlled",
            ],
        )
        try:
            subprocess.run(
                ["osascript", "-e", 'tell application "Chromium" to activate'],
                check=False, capture_output=True,
            )
        except Exception:
            pass

        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        log("Browser launched. If MFA is required, approve it in the browser window.")

        # ── Step 1: get into Duo admin portal ────────────────────────────────
        ok = _navigate_to_duo_admin(page, admin_host)
        if not ok:
            log("WARN: could not confirm Duo admin portal login — attempting to proceed")

        # Wait for Duo admin URL
        deadline = time.time() + 60
        while time.time() < deadline:
            if admin_host in page.url and "/login" not in page.url:
                break
            time.sleep(2)
        log(f"Duo admin URL: {page.url[:100]}")

        # ── Step 2: get enrollment blob ───────────────────────────────────────
        if admin_host in page.url:
            try:
                blob = _get_enrollment_blob_from_portal(page, admin_host)
            except Exception as e:
                log(f"  ERROR in blob extraction: {e}")
                try:
                    page.screenshot(path=str(DATA_DIR / "blob_refresh_crash.png"))
                    log("  screenshot: data/blob_refresh_crash.png")
                except Exception:
                    pass
            if blob:
                log(f"Enrollment blob extracted (len={len(blob)})")
            else:
                log("ERROR: could not extract enrollment blob from portal")
                try:
                    page.screenshot(path=str(DATA_DIR / "blob_refresh_fail.png"))
                    log("  screenshot: data/blob_refresh_fail.png")
                except Exception:
                    pass
        else:
            log("ERROR: not on Duo admin portal — cannot extract blob")

        # ── Step 3: get Okta token for SA SCIM ───────────────────────────────
        # Navigate to SCC to get fresh Okta token
        log("navigating to SCC to get Okta token for SA SCIM ...")
        try:
            page.goto("https://security.cisco.com", timeout=30_000,
                      wait_until="domcontentloaded")
            page.wait_for_timeout(3000)
            # Dismiss org picker
            try:
                cont = page.locator('button:has-text("Continue")').first
                cont.wait_for(state="visible", timeout=5000)
                cont.click()
                page.wait_for_timeout(1500)
            except Exception:
                pass
        except Exception as e:
            log(f"  SCC navigation warning: {e}")

        okta_token = _get_okta_token_from_page(ctx)
        if okta_token and sa_org_id:
            scim_token = _generate_sa_scim_token(okta_token, sa_org_id)
        else:
            log(f"  skipping SCIM regen: okta_token={'yes' if okta_token else 'missing'}, "
                f"sa_org_id={sa_org_id or 'missing'}")

        ctx.close()

    # ── Step 4: save to DB ────────────────────────────────────────────────────
    if not blob:
        log("FAIL: no blob extracted — cannot update DB")
        return False

    log("Saving to DB ...")
    with sqlite3.connect(db_path) as conn:
        if scim_token:
            conn.execute(
                "UPDATE org_credentials "
                "SET authproxy_enroll_blob=?, authproxy_blob_saved_at=datetime('now'), "
                "    sa_scim_token=?, updated_at=datetime('now') "
                "WHERE org_number=?",
                (blob, scim_token, org_num),
            )
            log(f"  saved blob (len={len(blob)}) + scim_token (len={len(scim_token)})")
        else:
            conn.execute(
                "UPDATE org_credentials "
                "SET authproxy_enroll_blob=?, authproxy_blob_saved_at=datetime('now'), "
                "    updated_at=datetime('now') "
                "WHERE org_number=?",
                (blob, org_num),
            )
            log(f"  saved blob (len={len(blob)}) only (scim_token not updated)")

        # Reset Duo step statuses to pending
        for step in ("authproxy_enroll", "scim_push", "verify"):
            conn.execute(
                "UPDATE duo_steps SET status='pending', result='', "
                "started_at=NULL, completed_at=NULL "
                "WHERE pod_id=? AND step_name=?",
                (pod_id, step),
            )
        log("  reset authproxy_enroll / scim_push / verify → pending")

    log("Done. Now trigger Duo card re-run from the dashboard (from authproxy_enroll step).")
    log("Or run manually:")
    log(f"  docker run --rm --network container:vpn-{pod_id} "
        f"-e POD_ID={pod_id} -e DB_PATH=/pipeline/host-data/pod_state.db "
        f"-v $(pwd)/data:/pipeline/host-data --entrypoint python3 pod-automator:latest "
        f"-u -c \"import sys; sys.path.insert(0,'/pipeline'); "
        f"from duo_automation import duo_run_card, duo_ensure_table; "
        f"duo_ensure_table('/pipeline/host-data/pod_state.db'); "
        f"ok, r = duo_run_card('{pod_id}', '/pipeline/host-data/pod_state.db', "
        f"log=print, from_step=4); print(('OK' if ok else 'FAIL') + ': ' + str(r))\"")
    return True


if __name__ == "__main__":
    pod  = sys.argv[1] if len(sys.argv) > 1 else "POD-2"
    db   = sys.argv[2] if len(sys.argv) > 2 else str(DEFAULT_DB)
    ok   = run(pod, db)
    sys.exit(0 if ok else 1)
