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

    # ── 0. Upfront diagnostics ────────────────────────────────────────────────
    import sys as _sys
    _log(f"Python: {_sys.executable}")
    try:
        import playwright as _pw
        _log(f"Playwright: installed ({_pw.__file__})")
    except ImportError:
        _log("ERROR: Playwright not installed in this Python env — run: uv run playwright install chromium")
        return False, "Playwright not installed — run dashboard with 'uv run python3 dashboard.py'"

    # ── 1. Load all PODs with scc_org configured ─────────────────────────────
    try:
        db = sqlite3.connect(db_path)
        db.row_factory = sqlite3.Row
        pods = db.execute(
            "SELECT pod_id, scc_org FROM pods WHERE scc_org IS NOT NULL AND scc_org != '';"
        ).fetchall()
        all_pods = db.execute("SELECT pod_id FROM pods;").fetchall()
        db.close()
    except Exception as e:
        _log(f"DB error: {e}")
        return False, f"DB error: {e}"

    _log(f"Total PODs in DB: {len(all_pods)} — PODs with scc_org set: {len(pods)}")

    if not pods:
        _log("No PODs with scc_org configured — Chrome will not launch.")
        _log("scc_org is set automatically when the pipeline runs 'detect_pod_number'.")
        _log("Ensure the pipeline has run at least through step 1 for your PODs.")
        return True, "No PODs to refresh — scc_org not set (run pipeline detect_pod_number first)"

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
        # Try Google Chrome first (best compatibility with existing profiles);
        # fall back to Playwright's bundled Chromium so the script works on
        # machines where Chrome is not installed.
        _launch_kwargs = dict(
            user_data_dir=str(PROFILE_DIR),
            headless=False,
            no_viewport=True,
            args=["--start-maximized", "--no-first-run", "--no-default-browser-check"],
        )
        ctx = None
        for _channel in ("chrome", None):
            try:
                if _channel:
                    ctx = p.chromium.launch_persistent_context(channel=_channel, **_launch_kwargs)
                    _log(f"Browser: Google Chrome")
                else:
                    # Ensure bundled Chromium binaries are present
                    try:
                        import subprocess as _sp
                        _sp.run(
                            [sys.executable, "-m", "playwright", "install", "chromium"],
                            capture_output=True, timeout=120,
                        )
                    except Exception:
                        pass
                    ctx = p.chromium.launch_persistent_context(**_launch_kwargs)
                    _log(f"Browser: Playwright bundled Chromium (Chrome not found on this machine)")
                break
            except Exception as _e:
                if _channel:
                    _log(f"Chrome not available ({_e}) — trying bundled Chromium...")
                else:
                    _log(f"ERROR: Could not launch any browser: {_e}")
                    return False, f"No browser available: {_e}"

        if ctx is None:
            return False, "Failed to launch browser (Chrome and bundled Chromium both unavailable)"

        # Bring the browser window to the front on macOS
        try:
            subprocess.run(["osascript", "-e",
                'tell application "Google Chrome" to activate'], check=False)
        except Exception:
            pass
        try:
            subprocess.run(["osascript", "-e",
                'tell application "Chromium" to activate'], check=False)
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

        # ── 3. Wait until authenticated on security.cisco.com ────────────────
        # SCC may redirect to Application Portal (appcenter.cisco.com) after
        # Okta SSO login. We detect either:
        #   A) Already on security.cisco.com with okta tokens
        #   B) On appcenter.cisco.com (Application Portal) — click the
        #      Secure Access / Security Cloud tile to navigate to SCC
        _log("Waiting for authentication (up to 5 minutes)...")
        deadline = time.time() + 300
        org_page_ready = False

        while time.time() < deadline:
            time.sleep(2)

            try:
                cur_url = ctx.pages[0].url if ctx.pages else ""
            except Exception:
                cur_url = ""

            # Case A: already on SCC — check for okta tokens in ANY origin
            if "security.cisco.com" in cur_url:
                try:
                    _state = ctx.storage_state()
                    # Check all origins — SCC may store tokens under its own origin
                    # or under an auth subdomain
                    for _origin in _state.get("origins", []):
                        for _item in _origin.get("localStorage", []):
                            if _item.get("name") == "okta-token-storage":
                                try:
                                    _tok = json.loads(_item.get("value", "{}"))
                                    if _tok and len(_tok) > 0:
                                        _log(f"Authenticated on SCC (origin={_origin.get('origin','?')[:50]}) — URL: {cur_url[:80]}")
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

                    # Fallback: if we're on SCC and cookies exist, that's enough
                    # (some SCC versions use cookie-only auth, no localStorage tokens)
                    if not org_page_ready:
                        _cookies = _state.get("cookies", [])
                        _scc_cookies = [c for c in _cookies if "cisco.com" in c.get("domain", "")]
                        if len(_scc_cookies) >= 5:
                            _log(f"Authenticated on SCC via cookies ({len(_scc_cookies)} cisco.com cookies) — URL: {cur_url[:80]}")
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

                # On SCC but no tokens yet — page may still be loading
                _log(f"  On SCC, waiting for tokens... ({cur_url[:60]})")
                continue

            # Case B: Application Portal — find and click Secure Access tile
            if "appcenter.cisco.com" in cur_url or "myapps.cisco.com" in cur_url:
                _log(f"  On Application Portal ({cur_url[:60]}) — looking for Secure Access tile...")
                try:
                    pg = ctx.pages[0]
                    # Try various selectors for the SCC/Secure Access app tile
                    _clicked = False
                    for _sel in [
                        'a[href*="security.cisco.com"]',
                        'a[href*="secure-access"]',
                        '[title*="Secure Access"]',
                        '[aria-label*="Secure Access"]',
                        'text=Secure Access',
                        'text=Security Cloud',
                        'text=Cisco Security Cloud',
                    ]:
                        try:
                            el = pg.locator(_sel).first
                            if el.is_visible(timeout=1000):
                                el.click()
                                _log(f"  Clicked tile: {_sel}")
                                pg.wait_for_load_state("domcontentloaded", timeout=15000)
                                _clicked = True
                                break
                        except Exception:
                            pass

                    if not _clicked:
                        # JS scan for any link containing security.cisco.com
                        try:
                            _href = pg.evaluate("""() => {
                                const links = Array.from(document.querySelectorAll('a[href]'));
                                const scc = links.find(l => l.href && l.href.includes('security.cisco.com'));
                                if (scc) { scc.click(); return scc.href; }
                                return null;
                            }""")
                            if _href:
                                _log(f"  JS clicked SCC link: {_href[:60]}")
                                pg.wait_for_load_state("domcontentloaded", timeout=15000)
                                _clicked = True
                        except Exception:
                            pass

                    if not _clicked:
                        _log("  Could not find SCC tile — please click 'Secure Access' in the browser window")
                    time.sleep(2)
                    continue
                except Exception as _e:
                    _log(f"  App Portal navigation error: {_e}")
                    continue

            # Still on login/SSO/Duo pages — just log and wait
            try:
                for pg in ctx.pages:
                    try:
                        url = pg.url
                        if "sign-on" in url or "duosecurity" in url or "okta" in url:
                            _log(f"  Waiting for login... ({url[:80]})")
                        elif "appcenter" in url or "myapps" in url:
                            pass  # handled above next loop
                        else:
                            _log(f"  Waiting... ({url[:60]})")
                    except Exception:
                        pass
            except Exception:
                pass

        if not org_page_ready:
            _log("ERROR: Timeout — did not reach authenticated security.cisco.com within 5 minutes")
            ctx.close()
            return False, "Login timeout"

        def _clean_storage(raw: dict) -> dict:
            """Keep all cross-domain cookies (Okta sid etc. needed for silent renew)
            but strip only:
            - In-progress auth-flow cookie: oktaStateToken, DT
            - Extra localStorage origins beyond security.cisco.com (Duo/id.cisco.com
              localStorage conflicts cause the SPA to re-trigger OAuth)
            The Jun 16 working session: 27 multi-domain cookies + 1 origin — this
            pattern is what we want to preserve.
            """
            _keep_cookies = [
                c for c in raw.get("cookies", [])
                if c.get("name", "") not in ("oktaStateToken", "DT")
            ]

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

        # ── 5. Per-POD: select correct org, save org-scoped session ─────────
        # For each POD: navigate to SCC root, select PseudoCo-{org_number}
        # from the org picker, click Continue, then save the storage state.
        # This ensures each session file has the correct enterpriseId for
        # the POD org — not the manager org.
        for pod_id, org_number, scc_org in pod_orgs:
            _log(f"--- {pod_id} (org {org_number}) ---")
            session_path = DATA_DIR / f"scc_session_{pod_id}.json"
            _try_labels = [
                f"PseudoCo-{org_number}",   # "PseudoCo-535"
                f"pseudoco-{org_number}",   # "pseudoco-535"
                f"pseudoco{org_number}",    # "pseudoco535"
            ]

            try:
                pg = ctx.pages[0] if ctx.pages else ctx.new_page()

                _log(f"  Navigating to SCC root...")
                pg.goto("https://security.cisco.com", timeout=30_000,
                        wait_until="domcontentloaded")
                pg.wait_for_timeout(2500)

                # If redirected to Application Portal, click through to SCC
                _nav_deadline = time.time() + 30
                while time.time() < _nav_deadline:
                    _pg_url = pg.url
                    if "security.cisco.com" in _pg_url:
                        break
                    if "appcenter.cisco.com" in _pg_url or "myapps.cisco.com" in _pg_url:
                        _log(f"  Redirected to App Portal — clicking through to SCC...")
                        _clicked = False
                        for _sel in [
                            'a[href*="security.cisco.com"]',
                            'text=Secure Access',
                            'text=Security Cloud',
                            '[title*="Secure Access"]',
                        ]:
                            try:
                                el = pg.locator(_sel).first
                                if el.is_visible(timeout=800):
                                    el.click()
                                    pg.wait_for_load_state("domcontentloaded", timeout=15000)
                                    _clicked = True
                                    break
                            except Exception:
                                pass
                        if not _clicked:
                            try:
                                pg.evaluate("""() => {
                                    const l = Array.from(document.querySelectorAll('a[href]'))
                                        .find(a => a.href.includes('security.cisco.com'));
                                    if (l) l.click();
                                }""")
                                pg.wait_for_load_state("domcontentloaded", timeout=15000)
                            except Exception:
                                pass
                    pg.wait_for_timeout(1500)
                _log(f"  SCC navigation complete → {pg.url[:80]}")

                # ── Select the correct POD org in the picker ──────────────────
                _switched = False

                # Option A: native <select>
                for _lbl in _try_labels:
                    try:
                        pg.select_option("select", label=_lbl, timeout=1500)
                        _switched = True
                        _log(f"  org picker: <select> '{_lbl}'")
                        break
                    except Exception:
                        pass

                # Option B: React combobox / listbox
                if not _switched:
                    for _csel in ['[role="combobox"]', '[aria-haspopup="listbox"]']:
                        try:
                            cb = pg.locator(_csel).first
                            if cb.is_visible(timeout=1500):
                                cb.click()
                                pg.wait_for_timeout(600)
                                for _lbl in _try_labels:
                                    for _osel in [
                                        f'[role="option"]:has-text("{_lbl}")',
                                        f'li[role="option"]:has-text("{_lbl}")',
                                        f'li:has-text("{_lbl}")',
                                    ]:
                                        try:
                                            oel = pg.locator(_osel).first
                                            if oel.is_visible(timeout=800):
                                                oel.click()
                                                pg.wait_for_timeout(500)
                                                _switched = True
                                                _log(f"  org picker: combobox '{_lbl}'")
                                                break
                                        except Exception:
                                            pass
                                    if _switched:
                                        break
                                break
                        except Exception:
                            continue

                # Option C: JS scan
                if not _switched:
                    for _lbl in [l.lower() for l in _try_labels]:
                        try:
                            _ok = pg.evaluate(f"""() => {{
                                const els = Array.from(document.querySelectorAll(
                                    '[role="option"], li, option'));
                                const el = els.find(e =>
                                    (e.textContent || '').toLowerCase().includes('{_lbl}'));
                                if (el && el.getBoundingClientRect().width > 0) {{
                                    el.click(); return true;
                                }}
                                return false;
                            }}""")
                            if _ok:
                                pg.wait_for_timeout(500)
                                _switched = True
                                _log(f"  org picker: JS '{_lbl}'")
                                break
                        except Exception:
                            pass

                _log(f"  org picker: switched={_switched}, clicking Continue...")

                # Click Continue
                try:
                    cont = pg.locator('button:has-text("Continue")').first
                    cont.wait_for(state="visible", timeout=5000)
                    cont.click()
                    pg.wait_for_load_state("domcontentloaded", timeout=15000)
                    pg.wait_for_timeout(2000)
                    _log(f"  Dismissed org picker → {pg.url[:80]}")
                except Exception:
                    _log(f"  No Continue button found → {pg.url[:80]}")

                # Log the enterpriseId that was set
                try:
                    _eid = pg.evaluate("() => localStorage.getItem('enterpriseId') || ''")
                    _log(f"  enterpriseId: {_eid[:16]}..." if _eid else "  enterpriseId: (empty)")
                except Exception:
                    pass

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
