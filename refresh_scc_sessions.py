#!/usr/bin/env python3
"""
Refresh SCC (security.cisco.com) session for all active PODs.

Uses a PERSISTENT Chrome profile (data/scc_chrome_profile/) so you only
ever need to log in once. On subsequent runs the profile is already
authenticated — no MFA required.

Usage:
  python3 refresh_scc_sessions.py [db_path]
  uv run python3 refresh_scc_sessions.py

Called by the dashboard /api/scc/refresh-sessions endpoint.
"""

import json
import re
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

DATA_DIR    = Path(__file__).parent / "data"
PROFILE_DIR = DATA_DIR / "scc_chrome_profile"   # persistent login lives here
DEFAULT_DB  = DATA_DIR / "pod_state.db"


def run(db_path: str, log=None):
    _log = log or (lambda s: print(f"[scc-refresh] {s}", flush=True))

    # ── 1. Load all PODs with scc_org configured ─────────────────────────────
    try:
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
        pods = db.execute(
            "SELECT pod_id, scc_org FROM pods WHERE scc_org IS NOT NULL AND scc_org != '';"
        ).fetchall()
        db.close()
    except Exception as e:
        _log(f"DB error: {e}")
        return False, f"DB error: {e}"

    if not pods:
        _log("No PODs with scc_org configured — nothing to refresh")
        return True, "No PODs to refresh"

    pod_orgs = []
    for pod in pods:
        m = re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if m:
            pod_orgs.append((pod["pod_id"], m.group(1), pod["scc_org"]))
        else:
            _log(f"WARN: Cannot extract org number from '{pod['scc_org']}' — skipping {pod['pod_id']}")

    if not pod_orgs:
        _log("No PODs with parseable org numbers — nothing to refresh")
        return False, "No parseable org numbers"

    _log(f"PODs to refresh: {[(p, o) for p, o, _ in pod_orgs]}")
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    _log(f"Using persistent profile: {PROFILE_DIR}")

    # ── 2. Launch persistent Chrome ───────────────────────────────────────────
    from playwright.sync_api import sync_playwright

    results = {}

    with sync_playwright() as p:
        # launch_persistent_context keeps cookies/localStorage across runs.
        # On first run: user logs in; on subsequent runs: already authenticated.
        ctx = p.chromium.launch_persistent_context(
            user_data_dir=str(PROFILE_DIR),
            channel="chrome",
            headless=False,
            no_viewport=True,
            args=["--start-maximized", "--no-first-run", "--no-default-browser-check"],
        )

        # Bring the browser window to the front on macOS
        try:
            subprocess.run(["osascript", "-e",
                'tell application "Google Chrome" to activate'], check=False)
        except Exception:
            pass

        page = ctx.pages[0] if ctx.pages else ctx.new_page()

        _log("Navigating to https://security.cisco.com ...")
        _log(">>> INTERACT WITH THE CHROME WINDOW THAT JUST OPENED <<<")
        try:
            page.goto("https://security.cisco.com", timeout=60_000,
                      wait_until="domcontentloaded")
        except Exception as e:
            _log(f"  Initial navigation warning (continuing): {e}")

        # ── 3. Wait until authenticated (okta-token-storage non-empty) ───────
        # Detection uses ctx.storage_state() — checks ALL origins including
        # security.cisco.com even if the active page is still on sign-on domain
        # (e.g. during the OAuth callback redirect chain).
        _log("Waiting for authentication (up to 5 minutes)...")
        deadline = time.time() + 300
        org_page_ready = False

        while time.time() < deadline:
            time.sleep(2)

            # Primary: check storage_state for okta tokens in any origin
            try:
                _state = ctx.storage_state()
                for _origin in _state.get("origins", []):
                    for _item in _origin.get("localStorage", []):
                        if _item.get("name") == "okta-token-storage":
                            try:
                                _tok = json.loads(_item.get("value", "{}"))
                                if _tok and len(_tok) > 0:
                                    _cur_url = ctx.pages[0].url if ctx.pages else "unknown"
                                    _log(f"Authenticated (storage_state) — URL: {_cur_url[:80]}")
                                    try:
                                        ctx.pages[0].screenshot(
                                            path=str(DATA_DIR / "scc_auth_state.png"))
                                    except Exception:
                                        pass
                                    org_page_ready = True
                            except Exception:
                                pass
                if org_page_ready:
                    break
            except Exception as _e:
                pass  # context not ready yet

            # Fallback: log current page URLs for diagnostics
            try:
                for pg in ctx.pages:
                    try:
                        url = pg.url
                        if "sign-on" in url or "duosecurity" in url:
                            _log(f"  Waiting for login... ({url[:80]})")
                        elif "security.cisco.com" in url:
                            _log(f"  On SCC, waiting for tokens... ({url[:60]})")
                    except Exception:
                        pass
            except Exception:
                pass

        if not org_page_ready:
            _log("ERROR: Timeout — did not reach authenticated security.cisco.com within 5 minutes")
            ctx.close()
            return False, "Login timeout"

        def _clean_storage(raw: dict) -> dict:
            """Strip mid-auth-flow cookies and non-SCC origins that cause headless
            Chromium to re-trigger OAuth when the session is loaded.

            Keep only:
            - Cookies whose domain ends with .security.cisco.com or security.cisco.com
              (excludes sign-on.security.cisco.com, id.cisco.com, duosecurity.com)
            - Cookies that are NOT oktaStateToken / JSESSIONID (auth-flow temporaries)
            - Only the https://security.cisco.com localStorage origin
            """
            _keep_cookies = []
            for c in raw.get("cookies", []):
                dom = c.get("domain", "")
                name = c.get("name", "")
                # Skip sign-on, id.cisco.com, duosecurity cookies
                if any(x in dom for x in ["sign-on", "id.cisco.com", "duosecurity", "login.cisco"]):
                    continue
                # Skip mid-flow temp tokens
                if name in ("oktaStateToken", "JSESSIONID", "DT"):
                    continue
                _keep_cookies.append(c)

            _keep_origins = [
                o for o in raw.get("origins", [])
                if o.get("origin", "") == "https://security.cisco.com"
            ]

            return {"cookies": _keep_cookies, "origins": _keep_origins}

        # ── 4. Capture auth storage state and save immediately ───────────────
        auth_storage = _clean_storage(ctx.storage_state())
        _log(f"Captured (cleaned): {len(auth_storage.get('cookies', []))} cookies, "
             f"{len(auth_storage.get('origins', []))} origins")
        for pod_id, org_number, scc_org in pod_orgs:
            _early_path = DATA_DIR / f"scc_session_{pod_id}.json"
            try:
                _early_path.write_text(json.dumps(auth_storage, indent=2))
                _log(f"Early save → {_early_path.name}")
            except Exception as _e:
                _log(f"Early save failed for {pod_id}: {_e}")

        # ── 5. Per-POD: select org via dropdown modal, save ──────────────────
        # Navigate to root (NOT /dashboard?enterpriseId= — that triggers Okta
        # re-auth in some browser contexts). Dismiss the org picker Continue
        # button, then capture and overwrite with org-scoped storage_state.
        for pod_id, org_number, scc_org in pod_orgs:
            _log(f"--- {pod_id} (org {org_number}) ---")
            session_path = DATA_DIR / f"scc_session_{pod_id}.json"

            try:
                pg = ctx.pages[0] if ctx.pages else ctx.new_page()

                _log(f"  Navigating to SCC root for org context...")
                pg.goto("https://security.cisco.com", timeout=30_000,
                        wait_until="domcontentloaded")
                pg.wait_for_timeout(2000)

                # Dismiss org picker modal (pre-selected dropdown → just Continue)
                try:
                    cont = pg.locator('button:has-text("Continue")').first
                    cont.wait_for(state="visible", timeout=5000)
                    cont.click()
                    pg.wait_for_load_state("domcontentloaded", timeout=15000)
                    pg.wait_for_timeout(1500)
                    _log(f"  Dismissed org picker → {pg.url[:80]}")
                except Exception:
                    _log(f"  No org picker modal → {pg.url[:80]}")

                pod_storage = _clean_storage(ctx.storage_state())
                n_cookies = len(pod_storage.get("cookies", []))
                n_origins = len(pod_storage.get("origins", []))
                session_path.write_text(json.dumps(pod_storage, indent=2))
                _log(f"  Saved: {n_cookies} cookies, {n_origins} origins → {session_path.name}")
                results[pod_id] = "ok"

            except Exception as e:
                _log(f"  ERROR for {pod_id}: {e} — early save still valid")
                results[pod_id] = "ok (early-save only)"

        ctx.close()

    ok_count = sum(1 for v in results.values() if v == "ok")
    summary = f"Refreshed {ok_count}/{len(pod_orgs)} POD(s)"
    for pid, res in results.items():
        _log(f"  {pid}: {res}")
    _log(summary)
    return ok_count == len(pod_orgs), f"{summary}: {results}"


if __name__ == "__main__":
    db = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_DB)
    ok, msg = run(db)
    print(f"[scc-refresh] {'OK' if ok else 'FAIL'}: {msg}", flush=True)
    sys.exit(0 if ok else 1)
