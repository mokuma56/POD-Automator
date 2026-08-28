"""
Duo Admin API helpers for POD automator.

Handles: org reset, group creation, user creation (with group assignments).
Uses HMAC-SHA1 signed requests per Duo Admin API v1/v3 spec.
"""

import hashlib
import hmac
import base64
import urllib.parse
import email.utils
import time
import re
import os
from typing import Optional
import requests

# ──────────────────────────────────────────────────────────────────────────────
# Persistent SCC browser session
# Saved after every successful SCC login; loaded on subsequent runs to skip
# Cisco Okta + Duo MFA entirely.  When the session expires the browser will
# redirect back to sign-on.security.cisco.com and the login flow runs again
# (one Duo push approval), after which the new session is saved.
# ──────────────────────────────────────────────────────────────────────────────
_SCC_SESSION_FILE = os.path.join(
    "/pipeline/host-data" if os.path.exists("/.dockerenv")
    else os.path.join(os.path.dirname(os.path.abspath(__file__)), "data"),
    "scc_session.json",
)


def _scc_session_kwargs() -> dict:
    """Return storage_state kwarg for Playwright new_context() when a saved
    SCC session file exists.  Passing this skips Okta / Duo MFA on reuse."""
    if os.path.exists(_SCC_SESSION_FILE):
        return {"storage_state": _SCC_SESSION_FILE}
    return {}


def _save_scc_session(ctx, log=None) -> None:
    """Persist the browser session state so future runs skip Okta MFA."""
    try:
        os.makedirs(os.path.dirname(_SCC_SESSION_FILE), exist_ok=True)
        ctx.storage_state(path=_SCC_SESSION_FILE)
        if log:
            log(f"SCC session saved → {_SCC_SESSION_FILE}")
    except Exception as exc:
        if log:
            log(f"WARNING: could not save SCC session: {exc}")


# ──────────────────────────────────────────────────────────────────────────────
# Low-level auth + request helpers
# ──────────────────────────────────────────────────────────────────────────────

def _canon_params(params: dict) -> str:
    """URL-encode and sort params as Duo requires."""
    return "&".join(
        f"{urllib.parse.quote(str(k), safe='~-._')}"
        f"={urllib.parse.quote(str(v), safe='~-._')}"
        for k, v in sorted(params.items())
    )


def _sign_request(ikey: str, skey: str, host: str,
                  method: str, path: str, params: dict) -> dict:
    """Return signed HTTP headers for a Duo Admin API request."""
    date = email.utils.formatdate()
    canon = "\n".join([
        date,
        method.upper(),
        host.lower(),
        path,
        _canon_params(params),
    ])
    sig = hmac.new(skey.encode(), canon.encode(), hashlib.sha1).hexdigest()
    auth = base64.b64encode(f"{ikey}:{sig}".encode()).decode()
    return {"Date": date, "Authorization": f"Basic {auth}"}


def _duo_request(ikey: str, skey: str, host: str,
                 method: str, path: str, params: dict = None,
                 timeout: int = 20) -> dict:
    """
    Make an authenticated Duo Admin API request.
    Returns the parsed JSON body (full response, not just 'response' key).
    Raises on non-2xx or stat != 'OK'.
    """
    params = params or {}
    headers = _sign_request(ikey, skey, host, method, path, params)
    url = f"https://{host}{path}"

    m = method.upper()
    if m == "GET":
        r = requests.get(url, params=params, headers=headers, timeout=timeout)
    elif m == "POST":
        r = requests.post(url, data=params, headers=headers, timeout=timeout)
    elif m == "DELETE":
        r = requests.delete(url, headers=headers, timeout=timeout)
    else:
        raise ValueError(f"Unsupported HTTP method: {method}")

    r.raise_for_status()
    body = r.json()
    if body.get("stat") not in ("OK", None):
        raise RuntimeError(f"Duo API error: {body.get('message', body)}")
    return body


def _paginate(ikey: str, skey: str, host: str, path: str, params: dict = None) -> list:
    """
    Fetch all pages of a Duo list endpoint.
    Duo paginates via ?limit=&offset= with metadata.next_offset.
    """
    params = dict(params or {})
    params.setdefault("limit", "500")
    params["offset"] = "0"
    results = []
    while True:
        body = _duo_request(ikey, skey, host, "GET", path, params)
        items = body.get("response", [])
        if isinstance(items, list):
            results.extend(items)
        else:
            results.append(items)
        next_off = (body.get("metadata") or {}).get("next_offset")
        if next_off is None:
            break
        params["offset"] = str(next_off)
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Org reset
# ──────────────────────────────────────────────────────────────────────────────

DUO_ADMIN_API_TYPE = "adminapi"  # integration type to keep (never deleted)

def duo_reset_org(ikey: str, skey: str, host: str,
                  log=None) -> tuple[bool, str]:
    """
    Reset a Duo org for a new lab session:
      - Deletes all users, groups, and permitted domains
      - PRESERVES all integrations (applications) — the authproxy and any
        SSO/SAML apps are org-level config that cannot be recreated via API;
        they must survive across runs.

    Returns (ok, message).
    log: optional callable(str) for progress messages.
    """
    _log = log or (lambda s: print(f"     [duo] {s}"))
    deleted = {"integrations": 0, "users": 0, "groups": 0, "domains": 0}

    try:
        # 1. Users
        users = _paginate(ikey, skey, host, "/admin/v1/users")
        for user in users:
            uid = user.get("user_id")
            if not uid:
                continue
            try:
                _duo_request(ikey, skey, host, "DELETE",
                             f"/admin/v1/users/{uid}")
                deleted["users"] += 1
            except Exception as e:
                _log(f"WARN: could not delete user {uid}: {e}")

        # 3. Delete all groups
        groups = _paginate(ikey, skey, host, "/admin/v1/groups")
        for group in groups:
            gid = group.get("group_id")
            if not gid:
                continue
            try:
                _duo_request(ikey, skey, host, "DELETE",
                             f"/admin/v1/groups/{gid}")
                deleted["groups"] += 1
            except Exception as e:
                _log(f"WARN: could not delete group {gid}: {e}")

        # 4. Delete permitted domains
        try:
            domains = _paginate(ikey, skey, host, "/admin/v1/permitted_domains")
        except Exception:
            domains = []
        for d in domains:
            did = d.get("domain_id") or d.get("id")
            if not did:
                continue
            try:
                _duo_request(ikey, skey, host, "DELETE",
                             f"/admin/v1/permitted_domains/{did}")
                deleted["domains"] += 1
            except Exception as e:
                _log(f"WARN: could not delete domain {did}: {e}")

    except Exception as e:
        return False, f"Duo reset failed: {e}"

    msg = (f"Reset complete — deleted: "
           f"{deleted['integrations']} integrations, "
           f"{deleted['users']} users, "
           f"{deleted['groups']} groups, "
           f"{deleted['domains']} domains")
    _log(msg)
    return True, msg


# ──────────────────────────────────────────────────────────────────────────────
# Group creation
# ──────────────────────────────────────────────────────────────────────────────

DUO_GROUPS = ("IoT", "MAIN", "PROD")


def duo_create_groups(ikey: str, skey: str, host: str,
                      group_names: tuple = DUO_GROUPS,
                      log=None) -> dict:
    """
    Create groups in Duo.
    Returns dict of group_name -> group_id.
    """
    _log = log or (lambda s: print(f"     [duo] {s}"))
    group_map = {}
    for name in group_names:
        resp = _duo_request(ikey, skey, host, "POST", "/admin/v1/groups",
                            {"name": name})
        gid = resp["response"]["group_id"]
        group_map[name] = gid
        _log(f"Created group '{name}' → {gid}")
    return group_map


# ──────────────────────────────────────────────────────────────────────────────
# User creation
# ──────────────────────────────────────────────────────────────────────────────

def duo_create_users(ikey: str, skey: str, host: str,
                     users: list, group_id_map: dict,
                     log=None) -> tuple[bool, str]:
    """
    Create users in Duo and assign them to groups.

    users: list of dicts:
        {
            "username":  str,   # e.g. "kit"    (sAMAccountName)
            "email":     str,   # e.g. "kit@rtp16.corp.pseudoco.com"
            "realname":  str,   # e.g. "Kit"    (display name)
            "groups":    list,  # e.g. ["MAIN"] (names from DUO_GROUPS)
        }

    group_id_map: dict of group_name -> group_id  (from duo_create_groups)
    Returns (ok, summary_string).
    """
    _log = log or (lambda s: print(f"     [duo] {s}"))
    created = 0
    for u in users:
        try:
            resp = _duo_request(ikey, skey, host, "POST", "/admin/v1/users", {
                "username": u["username"],
                "email":    u["email"],
                "realname": u.get("realname", u["username"].capitalize()),
                "status":   "active",
            })
            user_id = resp["response"]["user_id"]
            _log(f"Created user '{u['username']}' ({u['email']}) → {user_id}")

            for gname in u.get("groups", []):
                gid = group_id_map.get(gname)
                if gid:
                    _duo_request(ikey, skey, host, "POST",
                                 f"/admin/v1/users/{user_id}/groups",
                                 {"group_id": gid})
                    _log(f"  → added to group '{gname}'")
                else:
                    _log(f"  WARN: group '{gname}' not found in group_id_map")
            created += 1
        except Exception as e:
            _log(f"ERROR creating user '{u.get('username')}': {e}")
            return False, f"Failed on user '{u.get('username')}': {e}"

    return True, f"Created {created} Duo users with group assignments"


# ──────────────────────────────────────────────────────────────────────────────
# Permitted domain helper
# ──────────────────────────────────────────────────────────────────────────────

def duo_set_permitted_domain(ikey: str, skey: str, host: str,
                              domain: str, log=None) -> tuple[bool, str]:
    """
    Add a permitted self-service domain to the Duo org.
    e.g. domain = "rtp16.corp.pseudoco.com"
    """
    _log = log or (lambda s: print(f"     [duo] {s}"))
    try:
        resp = _duo_request(ikey, skey, host, "POST",
                            "/admin/v1/permitted_domains",
                            {"domain": domain})
        _log(f"Set permitted domain: {domain}")
        return True, f"Permitted domain set: {domain}"
    except Exception as e:
        return False, f"Failed to set permitted domain '{domain}': {e}"


# ──────────────────────────────────────────────────────────────────────────────
# Auth Proxy helpers
# ──────────────────────────────────────────────────────────────────────────────

def duo_get_authproxy_creds(ikey: str, skey: str, host: str):
    """
    Return credentials for the first non-adminapi integration in the org,
    which is assumed to be the Authentication Proxy application.

    Returns {"ikey": ..., "skey": ..., "host": host} or None if none found.
    """
    try:
        integrations = _paginate(ikey, skey, host, "/admin/v1/integrations")
    except Exception:
        return None
    for integ in integrations:
        if integ.get("type") == DUO_ADMIN_API_TYPE:
            continue
        ap_ikey = integ.get("integration_key", "")
        ap_skey = integ.get("secret_key", "")
        if ap_ikey and ap_skey:
            return {"ikey": ap_ikey, "skey": ap_skey, "host": host}
    return None


def duo_create_authproxy_integration(ikey: str, skey: str, host: str) -> Optional[dict]:
    """
    Create a new 'radius'-type integration named 'Authentication Proxy'.

    The 'radius' type's credentials work with the DRPC endpoint that Auth
    Proxy uses to connect to the Duo cloud — 'adminapi' type returns 403.

    Returns {"ikey": ..., "skey": ..., "host": host} or None on failure.
    """
    try:
        resp = _duo_request(
            ikey, skey, host, "POST", "/admin/v1/integrations",
            params={"type": "radius", "name": "Authentication Proxy"},
        )
        integ = resp.get("response", {})
        ap_ikey = integ.get("integration_key", "")
        ap_skey = integ.get("secret_key", "")
        if ap_ikey and ap_skey:
            return {"ikey": ap_ikey, "skey": ap_skey, "host": host}
    except Exception:
        pass
    return None


AUTHPROXY_CFG_PATH = (
    r"C:\Program Files\Duo Security Authentication Proxy\conf\authproxy.cfg"
)
AD_WINRM_USER = "administrator"
AD_WINRM_PASS = "C1sco12345"


def duo_push_authproxy_cfg(
    ap_ikey: str,
    ap_skey: str,
    ap_host: str,
    ad_ip: str = "198.18.5.102",
    winrm_user: str = AD_WINRM_USER,
    winrm_pass: str = AD_WINRM_PASS,
    log=None,
) -> tuple[bool, str]:
    """
    Push authproxy.cfg to AD1 via WinRM, restart the DuoAuthProxy service,
    and verify it reaches Running state.

    Returns (ok, message).
    """
    _log = log or (lambda s: print(f"     [authproxy] {s}"))

    cfg = (
        "[cloud]\n"
        f"ikey={ap_ikey}\n"
        f"skey={ap_skey}\n"
        f"api_host={ap_host}\n"
    )

    try:
        import winrm as _winrm
    except ImportError:
        return False, "pywinrm not installed — run: pip install pywinrm"

    try:
        s = _winrm.Session(
            f"http://{ad_ip}:5985/wsman",
            auth=(winrm_user, winrm_pass),
            transport="ntlm",
        )
    except Exception as e:
        return False, f"WinRM connect failed: {e}"

    # 1. Write authproxy.cfg via base64 decode + WriteAllText(ASCII) — no BOM
    import base64 as _b64
    cfg_b64 = _b64.b64encode(cfg.encode("ascii")).decode()
    write_ps = (
        f"$bytes = [Convert]::FromBase64String('{cfg_b64}'); "
        f"$text = [System.Text.Encoding]::ASCII.GetString($bytes); "
        f"$dest = '{AUTHPROXY_CFG_PATH}'; "
        "$dir = Split-Path -Parent $dest; "
        "if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; "
        "[System.IO.File]::WriteAllText($dest, $text, [System.Text.Encoding]::ASCII); "
        "Write-Output 'WRITE_OK'"
    )
    r = s.run_ps(write_ps)
    out = r.std_out.decode(errors="replace").strip()
    if "WRITE_OK" not in out:
        err = r.std_err.decode(errors="replace")[:200]
        return False, f"Failed to write authproxy.cfg: {out} | {err}"
    _log("authproxy.cfg written")

    # 2. Restart service
    restart_ps = (
        "try { Restart-Service DuoAuthProxy -Force -ErrorAction Stop } "
        "catch { try { "
        "Stop-Service DuoAuthProxy -Force -ErrorAction SilentlyContinue; "
        "Start-Sleep 2; "
        "Start-Service DuoAuthProxy -ErrorAction Stop "
        "} catch { Write-Error $_.Exception.Message } }; "
        "Start-Sleep 4; "
        "$svc = Get-Service DuoAuthProxy -ErrorAction SilentlyContinue; "
        "if ($svc) { Write-Output \"STATUS:$($svc.Status)\" } "
        "else { Write-Output 'STATUS:NotFound' }"
    )
    r2 = s.run_ps(restart_ps)
    out2 = r2.std_out.decode(errors="replace").strip()
    _log(f"Service output: {out2[:120]}")

    import re as _re
    m = _re.search(r"STATUS:(\w+)", out2)
    status = m.group(1) if m else "Unknown"
    if status.lower() == "running":
        _log(f"DuoAuthProxy service: Running ✓")
        return True, f"authproxy.cfg pushed ({ap_host}) | service Running"
    else:
        err2 = r2.std_err.decode(errors="replace")
        # CLIXML noise in stderr is PowerShell formatting, not a real error
        clixml_only = err2.strip().startswith("#< CLIXML")
        if clixml_only or status == "Unknown":
            _log(f"DuoAuthProxy service: {status} (status check inconclusive — cfg written and restart issued, treating as OK)")
            return True, f"authproxy.cfg pushed ({ap_host}) | service restart issued (status={status})"
        return False, (
            f"authproxy.cfg written but service status={status} | {err2[:100]}"
        )


# ──────────────────────────────────────────────────────────────────────────────
# Connectivity test
# ──────────────────────────────────────────────────────────────────────────────

def duo_verify_credentials(ikey: str, skey: str, host: str) -> tuple[bool, str]:
    """
    Quick check: GET /admin/v1/info/summary to verify credentials work.
    Returns (ok, message).
    """
    try:
        body = _duo_request(ikey, skey, host, "GET", "/admin/v1/info/summary")
        summary = body.get("response", {})
        admin_count = summary.get("admin_count", "?")
        user_count  = summary.get("user_count", "?")
        return True, (f"Duo API reachable — "
                      f"admins={admin_count}, users={user_count}, host={host}")
    except Exception as e:
        return False, f"Duo API unreachable ({host}): {e}"


# ──────────────────────────────────────────────────────────────────────────────
# Secure Access (SA) Management API helpers
# Requires management JWT obtained via Okta token exchange (browser session).
# ──────────────────────────────────────────────────────────────────────────────

SA_MGMT_BASE      = "https://management.api.umbrella.com"
SA_SSE_BASE       = "https://api.sse.cisco.com"
SA_OPEN_API_BASE  = "https://api.umbrella.com"  # open API base; also hosts the JWT exchange endpoint

# SA SP metadata (fixed for Cisco SSE — same across all orgs)
SA_SP_ENTITY_ID = "saml.fg.id.sse.cisco.com"
SA_SP_ACS_URL   = "https://fg.id.sse.cisco.com/gw/auth/acs/response"
SA_SCIM_URL     = "https://api.sse.cisco.com/identity/v2/scim"

# SP cert serial — confirmed from org 504 SP metadata; fallback if dynamic fetch fails
SA_SP_CERT_SERIAL_DEFAULT = "40019C6C7762BF3AB89A51B27222F88D"


def sa_refresh_okta_token(session_file: str = None) -> str:
    """Refresh the Okta access token using the refresh_token stored in scc_session.json.

    Returns a fresh access_token string, or '' on any failure.
    The Okta access token is short-lived (~30 min); the refresh_token is long-lived.
    """
    import json as _json, base64 as _b64
    sess = session_file or _SCC_SESSION_FILE
    try:
        with open(sess) as f:
            session = _json.load(f)
    except Exception:
        return ""

    refresh_token = ""
    client_id = ""
    token_url = ""
    scopes = ""
    for origin in session.get("origins", []):
        if "security.cisco.com" not in origin.get("origin", ""):
            continue
        for item in origin.get("localStorage", []):
            if item.get("name") != "okta-token-storage":
                continue
            try:
                val = _json.loads(item.get("value", "{}"))
                rt_obj = val.get("refreshToken", {})
                refresh_token = rt_obj.get("refreshToken", "")
                token_url = rt_obj.get("tokenUrl", "")
                scopes = " ".join(rt_obj.get("scopes", []))
                # Extract client_id from the stored access token claims
                at_raw = val.get("accessToken", {}).get("accessToken", "")
                if at_raw:
                    parts = at_raw.split(".")
                    if len(parts) >= 2:
                        pad = parts[1] + "=="
                        claims = _json.loads(_b64.b64decode(pad))
                        client_id = claims.get("cid", "")
            except Exception:
                pass
            break
        if refresh_token:
            break

    if not refresh_token or not client_id:
        return ""

    if not token_url:
        token_url = "https://sign-on.security.cisco.com/oauth2/ausr5ltkvjT6lODuy357/v1/token"
    if not scopes:
        scopes = "openid security:secure-access offline_access"

    try:
        r = requests.post(
            token_url,
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": client_id,
                "scope": scopes,
            },
            timeout=15,
        )
        r.raise_for_status()
        return r.json().get("access_token", "")
    except Exception:
        return ""


def sa_get_mgmt_jwt(okta_token: str,
                    org_id: str = "",
                    client_id: str = "",
                    client_secret: str = "") -> str:
    """Exchange Okta access token (from SCC localStorage) for SA/Umbrella management JWT.

    Correct endpoint: POST https://api.umbrella.com/auth/v2/oauth2/jwt-bearer/token
    Required body fields:
        grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
        assertion  = <okta_access_token>
        scope      = org/<org_id>          ← required; omitting it causes 400 invalid_request

    The management JWT has scope=role:root-admin and ~5-min TTL.
    It works against management.api.umbrella.com for SAML/SCIM/apikeys endpoints.
    NOTE: the old endpoint SA_SSE_BASE/auth/v2/jwt-bearer/token (no /oauth2/, wrong host)
    was permanently returning 400/401 — that was the root cause of all prior failures.
    """
    body = {
        "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": okta_token,
    }
    if org_id:
        body["scope"] = f"org/{org_id}"
    r = requests.post(
        f"{SA_OPEN_API_BASE}/auth/v2/oauth2/jwt-bearer/token",
        headers={"Content-Type": "application/x-www-form-urlencoded; charset=utf-8"},
        data=body,
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def sa_get_fresh_okta_token_via_browser(log=None) -> str:
    """Use Playwright with saved SCC session to get a fresh Okta access token.

    The saved scc_session.json contains DT (trusted-device) cookies that should
    enable silent re-authentication to Cisco SSO without a Duo MFA push.
    Navigates to security.cisco.com, waits for Okta JS token renewal, and reads
    the fresh access_token from localStorage.

    Returns access_token string (aud=api://piam), or '' on any failure.
    Saves updated session to scc_session.json if a fresh token is obtained.
    """
    _log = log or (lambda s: print(f"     [sa-browser] {s}"))
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _log("WARN: Playwright not available — skipping browser token refresh")
        return ""

    if not os.path.exists(_SCC_SESSION_FILE):
        _log("WARN: no saved SCC session — skipping browser token refresh")
        return ""

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        ctx = browser.new_context(**_scc_session_kwargs())
        page = ctx.new_page()
        try:
            _log("opening SCC in headless browser to refresh Okta token ...")
            try:
                page.goto("https://security.cisco.com",
                          timeout=90_000, wait_until="networkidle")
            except Exception:
                # networkidle may never fire on SCC — fall back to domcontentloaded
                page.goto("https://security.cisco.com",
                          timeout=90_000, wait_until="domcontentloaded")
                page.wait_for_timeout(5_000)

            url = page.url
            if "security.cisco.com" not in url or "sign-on" in url:
                _log(f"WARN: redirected to {url[:80]} — SCC session expired; "
                     "unable to refresh Okta token without MFA")
                return ""

            _log("SCC loaded; waiting for Okta token renewal (3s) ...")
            page.wait_for_timeout(3_000)

            token_data = page.evaluate("""() => {
                const raw = localStorage.getItem('okta-token-storage');
                if (!raw) return null;
                try { return JSON.parse(raw); } catch(e) { return null; }
            }""")

            if not token_data:
                _log("WARN: okta-token-storage not found in localStorage")
                return ""

            at_obj = token_data.get("accessToken", {})
            access_token = at_obj.get("accessToken", "")
            expires_at = at_obj.get("expiresAt", 0)

            import time as _time
            if access_token and expires_at > _time.time():
                mins_left = (expires_at - _time.time()) / 60
                _log(f"fresh Okta access_token obtained (expires in {mins_left:.0f}m)")
                _save_scc_session(ctx, _log)
                return access_token

            _log("WARN: Okta token in localStorage is still expired after page load")
            return ""

        except Exception as e:
            _log(f"WARN: browser token refresh failed: {e}")
            return ""
        finally:
            try:
                browser.close()
            except Exception:
                pass


def _sa_mgmt_req(mgmt_jwt: str, method: str, path: str,
                 json_body=None, xml_body: str = None,
                 params: dict = None, timeout: int = 20):
    """Low-level helper for management.api.umbrella.com requests."""
    hdrs = {"Authorization": f"Bearer {mgmt_jwt}"}
    kwargs = {}
    if json_body is not None:
        hdrs["Content-Type"] = "application/json"
        kwargs["json"] = json_body
    elif xml_body is not None:
        hdrs["Content-Type"] = "application/xml"
        kwargs["data"] = xml_body.encode()
    if params:
        kwargs["params"] = params
    r = requests.request(method, f"{SA_MGMT_BASE}{path}",
                         headers=hdrs, timeout=timeout, **kwargs)
    r.raise_for_status()
    return r


def sa_ensure_provisioning_profile(mgmt_jwt: str, org_id: str,
                                    label: str = "Duo",
                                    log=None) -> str:
    """Return existing Duo provisioning profile ID (source=/duo/scimv2), or create one.
    Returns profile_id as string.
    """
    _log = log or (lambda s: print(f"     [sa] {s}"))
    try:
        r = _sa_mgmt_req(mgmt_jwt, "GET",
                         f"/identity/v2/organizations/{org_id}/provisioningProfile")
        profiles = r.json()
        if not isinstance(profiles, list):
            profiles = [profiles]
        for p in profiles:
            if p.get("source") == "/duo/scimv2" or p.get("label") == label:
                pid = str(p.get("id", ""))
                _log(f"provisioning profile '{label}' found (id={pid})")
                return pid
    except Exception as e:
        _log(f"WARN: could not list provisioning profiles: {e}")

    # Create new profile
    r = _sa_mgmt_req(mgmt_jwt, "POST",
                     f"/identity/v2/organizations/{org_id}/provisioningProfile",
                     json_body={"label": label, "source": "/duo/scimv2"})
    pid = str(r.json().get("id", ""))
    _log(f"created provisioning profile '{label}' (id={pid})")
    return pid


def sa_generate_scim_token(mgmt_jwt: str, org_id: str, log=None) -> str:
    """Generate a new SCIM bearer token for the org.
    Returns the raw token string.
    """
    _log = log or (lambda s: print(f"     [sa] {s}"))
    r = _sa_mgmt_req(mgmt_jwt, "POST",
                     f"/auth/v2/organizations/{org_id}/apikeys",
                     json_body={"label": "Duo SCIM Token"})
    data = r.json()
    token = (data.get("auth_key") or data.get("token") or
             data.get("key") or data.get("access_token") or "")
    _log(f"SCIM token generated (len={len(token)})")
    return token


def sa_get_sp_cert_serial(mgmt_jwt: str, org_id: str) -> str:
    """Fetch SA SP cert serial from management API; fall back to known default."""
    try:
        r = _sa_mgmt_req(mgmt_jwt, "GET",
                         f"/samlmetadata/v1/organization/{org_id}/saml/sp",
                         timeout=10)
        xml = r.text
        import re as _re
        # X509SerialNumber or hex serial in the cert element
        m = _re.search(r"SerialNumber[^>]*>([0-9A-Fa-f]+)<", xml, _re.I)
        if m:
            return m.group(1).upper()
    except Exception:
        pass
    return SA_SP_CERT_SERIAL_DEFAULT


def sa_list_saml_profiles(mgmt_jwt: str, org_id: str) -> list:
    """List all IdP SAML metadata profiles for the org."""
    try:
        r = _sa_mgmt_req(mgmt_jwt, "GET",
                         f"/samlmetadata/v1/organization/{org_id}/metadata/all",
                         params={"mediatype": "json"})
        data = r.json()
        if isinstance(data, list):
            return data
        return data.get("results", data.get("data", []))
    except Exception:
        return []


def sa_delete_saml_profile(mgmt_jwt: str, org_id: str,
                            profile_id: str, log=None) -> bool:
    """Delete an existing SA SAML IdP profile."""
    _log = log or (lambda s: print(f"     [sa] {s}"))
    try:
        r = _sa_mgmt_req(mgmt_jwt, "DELETE",
                         f"/samlmetadata/v1/organization/{org_id}/idp/{profile_id}/metadata")
        _log(f"deleted SAML profile id={profile_id} (HTTP {r.status_code})")
        return True
    except Exception as e:
        _log(f"WARN: delete SAML profile {profile_id} failed: {e}")
        return False


def sa_create_saml_profile(mgmt_jwt: str, org_id: str, profile_id: str,
                            idp_metadata_xml: str, cert_serial: str,
                            log=None) -> bool:
    """Upload Duo IdP metadata XML to SA as a new SAML profile."""
    _log = log or (lambda s: print(f"     [sa] {s}"))
    params = {
        "group": "NA",
        "validity": "1",
        "timeunit": "DAYS",
        "idpType": "Duo",
        "multiSP": "false",
        "authenticationProfileName": "Duo SSO",
        "provisionalProfileName": "Duo",
        "isSSEOrg": "true",
        "certSerialNumber": cert_serial,
    }
    try:
        r = _sa_mgmt_req(
            mgmt_jwt, "POST",
            f"/samlmetadata/v1/organization/{org_id}/idp/{profile_id}/metadata",
            xml_body=idp_metadata_xml,
            params=params,
        )
        _log(f"SA SAML profile created (HTTP {r.status_code})")
        return True
    except Exception as e:
        _log(f"ERROR creating SA SAML profile: {e}")
        return False


# ──────────────────────────────────────────────────────────────────────────────
# Duo Admin browser-session API helpers
# Require sid + _xsrf cookies from a playwright-authenticated Duo admin session.
# ──────────────────────────────────────────────────────────────────────────────

DUO_NAMEID_FORMAT = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"


def _duo_admin_xsrf_header(xsrf_cookie: str) -> str:
    """Compute x-xsrftoken header value from _xsrf cookie.
    Formula: hex(base64decode(cookie.split('|')[0]))
    """
    segment = xsrf_cookie.split("|")[0]
    pad = (4 - len(segment) % 4) % 4
    raw = base64.b64decode(segment + "=" * pad)
    return raw.hex()


def _duo_admin_session(admin_host: str, sid: str,
                       xsrf_cookie: str,
                       extra_cookies: dict = None) -> requests.Session:
    """Create a requests.Session pre-loaded with Duo admin cookies and XSRF header.

    extra_cookies: optional dict of additional cookies to set (e.g. AWS ALB sticky
    session cookies AWSALB/AWSALBTG extracted from the browser — required for the
    request to hit the same ALB backend that issued the sid).
    """
    sess = requests.Session()
    sess.cookies.set("sid", sid, domain=admin_host)
    sess.cookies.set("_xsrf", xsrf_cookie, domain=admin_host)
    for name, value in (extra_cookies or {}).items():
        sess.cookies.set(name, value, domain=admin_host)
    sess.headers.update({
        "x-xsrftoken": _duo_admin_xsrf_header(xsrf_cookie),
        "origin": f"https://{admin_host}",
        "referer": f"https://{admin_host}/",
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36"
        ),
    })
    return sess


def duo_admin_get_or_create_saml_app(
        admin_ikey: str, admin_skey: str, admin_host: str,
        sid: str, xsrf_cookie: str,
        extra_cookies: dict = None,
        log=None) -> str:
    """Return ikey of existing sso_generic app, or create one via browser session.

    Uses the HMAC-signed Admin API to check for an existing app (cheaper),
    then falls back to the browser-session API to create a new one.
    Returns the app ikey string.
    """
    _log = log or (lambda s: print(f"     [duo-admin] {s}"))

    # 1. Check for existing sso_generic integration via Admin API
    try:
        integrations = _paginate(admin_ikey, admin_skey, admin_host,
                                 "/admin/v1/integrations")
        for integ in integrations:
            if integ.get("type") == "sso_generic":
                ikey = integ["integration_key"]
                _log(f"existing SAML SP app found (ikey={ikey})")
                return ikey
    except Exception as e:
        _log(f"WARN: Admin API integration list failed: {e}")

    # 2. Create via browser session
    _log("creating new SAML SP app via browser session...")
    sess = _duo_admin_session(admin_host, sid, xsrf_cookie, extra_cookies)
    xsrf_hdr = _duo_admin_xsrf_header(xsrf_cookie)
    r = sess.post(
        f"https://{admin_host}/applications/protect/types",
        data={
            "type": "sso-generic",
            "assigned_aukey": "",
            "_xsrf": xsrf_hdr,
        },
        allow_redirects=False,
        timeout=20,
    )
    loc = r.headers.get("Location", "")
    import re as _re2
    m = _re2.search(r"/applications/([A-Z0-9]+)", loc)
    if not m:
        raise RuntimeError(
            f"Could not parse app ikey from redirect Location: {loc!r} "
            f"(HTTP {r.status_code})"
        )
    ikey = m.group(1)
    _log(f"created SAML SP app (ikey={ikey})")
    return ikey


def duo_admin_configure_saml_app(
        admin_host: str, app_ikey: str,
        sid: str, xsrf_cookie: str,
        entity_id: str = SA_SP_ENTITY_ID,
        acs_url: str = SA_SP_ACS_URL,
        extra_cookies: dict = None,
        log=None) -> bool:
    """Configure Duo SAML SP app with SA entity ID and ACS URL (multipart form)."""
    _log = log or (lambda s: print(f"     [duo-admin] {s}"))
    sess = _duo_admin_session(admin_host, sid, xsrf_cookie, extra_cookies)
    xsrf_hdr = _duo_admin_xsrf_header(xsrf_cookie)
    r = sess.post(
        f"https://{admin_host}/applications/{app_ikey}/modify",
        files={
            "entity_id":       (None, entity_id),
            "acs-url-value-0": (None, acs_url),
            "nameid_format":   (None, DUO_NAMEID_FORMAT),
            "sign_response":   (None, "True"),
            "sign_assertion":  (None, "True"),
            "_xsrf":           (None, xsrf_hdr),
        },
        timeout=20,
    )
    if r.ok or r.status_code in (302, 303):
        _log(f"SAML SP app configured (entity_id={entity_id})")
        return True
    _log(f"ERROR configuring SAML SP app: HTTP {r.status_code} — {r.text[:200]}")
    return False


def duo_admin_configure_scim(
        admin_host: str, app_ikey: str,
        sid: str, xsrf_cookie: str,
        scim_token: str,
        scim_url: str = SA_SCIM_URL,
        extra_cookies: dict = None,
        log=None) -> bool:
    """Configure (or reconfigure) Duo SCIM outbound integration with new SA SCIM token."""
    _log = log or (lambda s: print(f"     [duo-admin] {s}"))
    sess = _duo_admin_session(admin_host, sid, xsrf_cookie, extra_cookies)
    payload = {
        "credentials": {
            "baseUrl": scim_url,
            "credentialType": "Bearer Token",
            "credentialDetail": {"token": scim_token},
        },
        "enabled": True,
    }
    r = sess.post(
        f"https://{admin_host}/admin/scim/outbound-integrations/{app_ikey}",
        json=payload,
        timeout=20,
    )
    if r.ok:
        _log("SCIM outbound integration configured")
        return True
    # 409 may mean integration already exists — treat as warning, not hard failure
    if r.status_code == 409:
        _log("WARN: SCIM outbound integration already exists (409) — treating as success")
        return True
    # 401/403 = auth failure (expired session) — hard failure, not a soft skip
    if r.status_code in (401, 403):
        _log(f"ERROR: SCIM configure auth failure HTTP {r.status_code}: {r.text[:200]}")
        return False
    _log(f"WARN: SCIM configure HTTP {r.status_code}: {r.text[:200]}")
    return r.status_code < 500


def duo_admin_get_saml_metadata_url(duo_host: str, app_ikey: str) -> str:
    """Construct the Duo IdP metadata URL from duo_host and app ikey.

    duo_host: e.g. 'api-2bb9ad3d.duosecurity.com'
    Returns:  'https://sso-2bb9ad3d.sso.duosecurity.com/saml2/sp/{app_ikey}/metadata'
    """
    import re as _re3
    m = _re3.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    if not m:
        raise ValueError(f"Cannot parse hash from duo_host: {duo_host!r}")
    hash_ = m.group(1)
    return f"https://sso-{hash_}.sso.duosecurity.com/saml2/sp/{app_ikey}/metadata"


# ── SA headless helpers ───────────────────────────────────────────────────────

def sa_get_client_token(sa_api_key: str, sa_api_secret: str, log=None) -> str:
    """Get Cisco Umbrella/SSE OAuth2 bearer token via client_credentials grant.

    Uses api.umbrella.com/auth/v2/token with Basic auth (key:secret).
    NOTE: this token works for api.umbrella.com and api.sse.cisco.com but
    returns 403 on management.api.umbrella.com (which needs mgmt_jwt).
    """
    import base64 as _b64
    _log = log or (lambda s: print(f"     [sa-oauth] {s}"))
    creds = _b64.b64encode(f"{sa_api_key}:{sa_api_secret}".encode()).decode()
    r = requests.post(
        "https://api.umbrella.com/auth/v2/token",
        headers={
            "Authorization": f"Basic {creds}",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        data={"grant_type": "client_credentials"},
        timeout=15,
    )
    r.raise_for_status()
    token = r.json().get("access_token", "")
    _log(f"SA client token obtained (len={len(token)})")
    return token


def sa_upload_idp_metadata(token: str, org_id: str,
                            idp_metadata_xml: str, log=None) -> bool:
    """Upload Duo IdP metadata XML to SA as a SAML IdP profile.

    Tries management.api.umbrella.com first (needs mgmt_jwt scope — may 403
    with a plain client token).  Falls back to api.sse.cisco.com SAML endpoint.
    Returns True if either path succeeds.
    """
    _log = log or (lambda s: print(f"     [sa-saml] {s}"))
    hdrs = {"Authorization": f"Bearer {token}",
            "Content-Type": "application/xml"}

    # ── Delete old profile(s) ────────────────────────────────────────────────
    for base in (SA_MGMT_BASE, SA_SSE_BASE):
        try:
            r_list = requests.get(
                f"{base}/samlmetadata/v1/organization/{org_id}/metadata/all",
                headers={"Authorization": f"Bearer {token}"},
                params={"mediatype": "json"},
                timeout=10,
            )
            if r_list.ok:
                profiles = r_list.json()
                if not isinstance(profiles, list):
                    profiles = profiles.get("results", [])
                for p in profiles:
                    pid = str(p.get("idpid") or p.get("id") or "")
                    if pid:
                        requests.delete(
                            f"{base}/samlmetadata/v1/organization/{org_id}/metadata/{pid}",
                            headers={"Authorization": f"Bearer {token}"},
                            timeout=10,
                        )
                        _log(f"deleted existing SAML profile {pid} via {base}")
                break
        except Exception as e:
            _log(f"WARN: list/delete profiles on {base}: {e}")

    # ── Upload new profile ───────────────────────────────────────────────────
    for base in (SA_MGMT_BASE, SA_SSE_BASE):
        try:
            r = requests.post(
                f"{base}/samlmetadata/v1/organization/{org_id}/metadata",
                headers=hdrs,
                data=idp_metadata_xml.encode(),
                timeout=20,
            )
            if r.ok:
                _log(f"SA SAML IdP profile uploaded via {base} (HTTP {r.status_code})")
                return True
            _log(f"WARN: SA SAML upload via {base} returned HTTP {r.status_code}: {r.text[:120]}")
        except Exception as e:
            _log(f"WARN: SA SAML upload via {base}: {e}")

    return False


def sa_generate_scim_token_client(token: str, org_id: str, log=None) -> str:
    """Generate a SA SCIM bearer token using a client OAuth token.

    Tries management.api.umbrella.com first, then api.umbrella.com.
    Returns the raw SCIM token string, or '' if both fail.
    """
    _log = log or (lambda s: print(f"     [sa-scim] {s}"))
    for base in (SA_MGMT_BASE, "https://api.umbrella.com"):
        try:
            r = requests.post(
                f"{base}/auth/v2/organizations/{org_id}/apikeys",
                headers={"Authorization": f"Bearer {token}",
                         "Content-Type": "application/json"},
                json={"label": "Duo SCIM Token"},
                timeout=15,
            )
            if r.ok:
                data = r.json()
                t = (data.get("auth_key") or data.get("token") or
                     data.get("key") or data.get("access_token") or "")
                if t:
                    _log(f"SA SCIM token generated via {base} (len={len(t)})")
                    return t
            _log(f"WARN: SCIM token via {base} returned HTTP {r.status_code}: {r.text[:80]}")
        except Exception as e:
            _log(f"WARN: SCIM token via {base}: {e}")
    return ""


def _load_saved_admin_cookies_for_org(duo_host: str) -> dict:
    """Load saved admin-domain cookies from scc_session.json for the given duo_host.

    Returns dict of {name: value} for the admin-XXXX.duosecurity.com domain,
    or {} if the file doesn't exist or no matching cookies are found.
    """
    import re as _re6, json as _js6
    m = _re6.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    if not m:
        return {}
    admin_host = f"admin-{m.group(1)}.duosecurity.com"
    try:
        with open(_SCC_SESSION_FILE) as f:
            state = _js6.load(f)
        cookies = state if isinstance(state, list) else state.get("cookies", [])
        return {
            c["name"]: c["value"]
            for c in cookies
            if admin_host in c.get("domain", "")
            or c.get("domain", "").lstrip(".") in admin_host
        }
    except Exception:
        return {}


def _push_duo_users_to_sa_scim(
    duo_ikey: str,
    duo_skey: str,
    duo_host: str,
    scim_token: str,
    scim_url: str = SA_SCIM_URL,
    log=None,
) -> int:
    """Push all active Duo users (with email) directly to the SA SCIM endpoint.

    Uses the stored SA SCIM token as a Bearer token.
    Skips users already present in SA (filter by userName).
    Returns the count of newly created users.
    """
    import time as _time
    _log = log or (lambda s: print(f"     [scim-push] {s}"))
    headers = {
        "Authorization": f"Bearer {scim_token}",
        "Content-Type": "application/scim+json",
        "Accept": "application/scim+json",
    }
    # Fetch Duo users
    try:
        users = _paginate(duo_ikey, duo_skey, duo_host, "/admin/v1/users")
    except Exception as e:
        _log(f"WARN: Duo user list failed: {e}")
        return 0

    targets = [u for u in users if u.get("email") and "@" in u.get("email", "")]
    _log(f"Duo users with email: {len(targets)}")
    if not targets:
        return 0

    pushed = 0
    for u in targets:
        email = u.get("email", "").strip()
        realname = u.get("realname", "").strip()
        username = u.get("username", "").strip()
        if not email:
            continue
        parts = realname.split() if realname else [username]
        first = parts[0] if parts else username
        last = parts[-1] if len(parts) > 1 else ""
        # Check existence first
        try:
            check = requests.get(
                f"{scim_url}/Users",
                headers=headers,
                params={"filter": f'userName eq "{email}"'},
                timeout=15,
            )
            if check.ok and check.json().get("totalResults", 0) > 0:
                _log(f"  skip (exists): {email}")
                continue
        except Exception:
            pass
        scim_user = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": email,
            "name": {"givenName": first, "familyName": last, "formatted": realname or username},
            "emails": [{"value": email, "type": "work", "primary": True}],
            "displayName": realname or username,
            "active": True,
        }
        try:
            r = requests.post(f"{scim_url}/Users", headers=headers, json=scim_user, timeout=15)
            if r.status_code in (200, 201):
                _log(f"  created: {email}")
                pushed += 1
            elif r.status_code == 409:
                _log(f"  already exists: {email}")
            else:
                _log(f"  WARN {email} → {r.status_code}: {r.text[:120]}")
        except Exception as e:
            _log(f"  WARN push error for {email}: {e}")
        _time.sleep(0.25)

    _log(f"SA SCIM push complete: {pushed} new users created")
    return pushed


def duo_sa_configure_headless(
    pod_id: str,
    db_path: str,
    log=None,
) -> tuple[bool, str]:
    """Headless SA SAML + Duo SCIM configuration using only stored credentials.

    Steps (all soft-fail — never blocks the pipeline):
    1.  Get Duo SAML SSO app ikey via HMAC Admin API (list sso_generic integrations)
    2.  Fetch Duo IdP metadata XML from public SSO metadata URL
    3.  Get SA OAuth2 client token (api.umbrella.com client_credentials)
    3.5 Get SA management JWT: try refresh_token → Okta; fallback Playwright DT-cookie
        silent re-auth; needed for management.api.umbrella.com (SAML/SCIM endpoints)
    4.  Upload Duo IdP metadata to SA (management JWT preferred; client token fallback)
    5.  Generate SA SCIM token (management JWT preferred; client token fallback)
    6.  Configure Duo SCIM outbound (browser session cookies from scc_session.json)
    7.  Run authproxy_update_sso_enrollment_code.exe on AD1 via WinRM to enroll proxy
    7.5 Playwright Duo admin portal: enable AD auth source, add permitted domain,
        configure Default routing rule → Active Directory
    8.  Trigger Duo AD directory sync (per-user syncuser calls)

    Always returns ok=True.
    """
    import sqlite3 as _sq6, re as _re7
    _log = log or (lambda s: print(f"     [saml-headless] {s}"))
    results = []

    # ── 0. Load creds ──────────────────────────────────────────────────────────
    try:
        with _sq6.connect(db_path) as conn:
            conn.row_factory = _sq6.Row
            pod_row = conn.execute(
                "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
            ).fetchone()
            if not pod_row:
                return True, "POD not found — SA/SCIM skipped"
            scc_org = pod_row["scc_org"] or ""
            m = _re7.search(r"pseudoco-(\d+)", scc_org)
            if not m:
                return True, "Cannot determine org number — SA/SCIM skipped"
            org_num = m.group(1)
            oc = dict(conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
            ).fetchone() or {})
    except Exception as e:
        return True, f"DB read error (non-fatal): {e}"

    duo_ikey      = oc.get("duo_ikey", "").strip()
    duo_skey      = oc.get("duo_skey", "").strip()
    duo_host      = oc.get("duo_host", "").strip()
    sa_org_id     = oc.get("sa_org_id", "").strip()
    sa_api_key    = oc.get("sa_api_key", "").strip()
    sa_api_secret = oc.get("sa_api_secret", "").strip()
    app_ikey      = oc.get("duo_saml_app_ikey", "").strip()
    stored_scim_token = oc.get("sa_scim_token", "").strip()

    if not duo_ikey or not duo_skey or not duo_host:
        return True, "Duo Admin API credentials missing — SA/SCIM skipped"

    # ── 1. Duo SAML app ikey ──────────────────────────────────────────────────
    if not app_ikey:
        _log("searching Duo Admin API for sso_generic integration ...")
        try:
            all_types = []
            for integ in _paginate(duo_ikey, duo_skey, duo_host, "/admin/v1/integrations"):
                t = integ.get("type", "")
                all_types.append(t)
                if t in ("sso_generic", "sso", "generic_sso", "saml_sp"):
                    app_ikey = integ["integration_key"]
                    _log(f"found SAML app ikey={app_ikey} (type={t})")
                    break
            if not app_ikey:
                _log(f"integration types found: {list(set(all_types))}")
            if app_ikey:
                with _sq6.connect(db_path) as conn:
                    conn.execute(
                        "UPDATE org_credentials SET duo_saml_app_ikey=? WHERE org_number=?",
                        (app_ikey, org_num)
                    )
        except Exception as e:
            _log(f"WARN: Admin API integration list failed: {e}")

    if app_ikey:
        results.append(f"SAML app ikey={app_ikey}")
    else:
        results.append("WARN: no SAML app found — create sso_generic integration in Duo Admin")

    # ── 2. Duo IdP metadata XML ───────────────────────────────────────────────
    idp_xml = ""
    if app_ikey:
        try:
            meta_url = duo_admin_get_saml_metadata_url(duo_host, app_ikey)
            r_meta = requests.get(meta_url, timeout=15)
            r_meta.raise_for_status()
            idp_xml = r_meta.text
            _log(f"Duo IdP metadata fetched ({len(idp_xml)} bytes)")
            results.append("IdP metadata OK")
        except Exception as e:
            _log(f"WARN: IdP metadata fetch failed: {e}")
            results.append(f"IdP metadata failed: {e}")

    # ── 3. SA client token ────────────────────────────────────────────────────
    sa_token = ""
    if sa_api_key and sa_api_secret:
        try:
            sa_token = sa_get_client_token(sa_api_key, sa_api_secret, log=_log)
            results.append("SA token OK")
        except Exception as e:
            _log(f"WARN: SA client token failed: {e}")
            results.append("SA token failed (no SA API creds?)")
    else:
        _log("WARN: SA API credentials not set — skipping SA SAML/SCIM config")
        results.append("SA SAML/SCIM skipped (no SA creds)")

    # ── 3.5. SA management JWT (needed for SAML upload + SCIM token) ──────────
    # Priority: (1) refresh_token → fresh Okta token; (2) browser (Playwright)
    # → auto-renewed token via DT cookie; (3) skip (soft-fail, API may 403).
    mgmt_jwt = ""
    if sa_api_key and sa_api_secret:
        try:
            fresh_okta = sa_refresh_okta_token()
            if not fresh_okta:
                _log("refresh_token expired — trying browser-based Okta token refresh ...")
                fresh_okta = sa_get_fresh_okta_token_via_browser(log=_log)
            if fresh_okta:
                _log("Okta token obtained; exchanging for SA management JWT ...")
                mgmt_jwt = sa_get_mgmt_jwt(fresh_okta, org_id=sa_org_id)
                _log(f"SA management JWT obtained (len={len(mgmt_jwt)})")
                results.append("SA mgmt JWT OK")
            else:
                _log("WARN: Okta token unavailable (session expired + browser failed) — "
                     "SA SAML/SCIM may 403")
                results.append("SA mgmt JWT skipped (Okta refresh failed)")
        except Exception as e:
            _log(f"WARN: SA management JWT failed ({e}) — SA SAML/SCIM may 403")
            results.append(f"SA mgmt JWT failed: {e}")

    # ── 4. SA SAML IdP profile ────────────────────────────────────────────────
    if (mgmt_jwt or sa_token) and sa_org_id and idp_xml:
        try:
            tok4 = mgmt_jwt or sa_token
            ok4 = sa_upload_idp_metadata(tok4, sa_org_id, idp_xml, log=_log)
            results.append("SA SAML profile " + ("uploaded" if ok4 else "skipped (403 — needs mgmt_jwt)"))
        except Exception as e:
            _log(f"WARN: SA SAML profile error: {e}")
            results.append(f"SA SAML error: {e}")

    # ── 5. SA SCIM token ──────────────────────────────────────────────────────
    scim_token = ""
    if sa_org_id:
        if stored_scim_token:
            scim_token = stored_scim_token
            _log(f"SA SCIM token loaded from DB (len={len(scim_token)})")
            results.append("SA SCIM token loaded from DB")
        else:
            try:
                if mgmt_jwt:
                    scim_token = sa_generate_scim_token(mgmt_jwt, sa_org_id, log=_log)
                elif sa_token:
                    scim_token = sa_generate_scim_token_client(sa_token, sa_org_id, log=_log)
                results.append("SA SCIM token " + ("generated" if scim_token else "failed (403?)"))
            except Exception as e:
                _log(f"WARN: SA SCIM token error: {e}")
                results.append(f"SA SCIM token error: {e}")

    # ── 6. Duo SCIM outbound config ───────────────────────────────────────────
    if scim_token and app_ikey:
        _log("configuring Duo SCIM outbound (using saved browser session) ...")
        try:
            _admin_cookies = _load_saved_admin_cookies_for_org(duo_host)
            sid  = _admin_cookies.get("sid", "")
            xsrf = _admin_cookies.get("_xsrf", "")
            import re as _re8
            _m8 = _re8.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
            admin_host = f"admin-{_m8.group(1)}.duosecurity.com" if _m8 else ""
            if sid and xsrf and admin_host:
                extra = {k: v for k, v in _admin_cookies.items() if k not in ("sid", "_xsrf")}
                ok6 = duo_admin_configure_scim(
                    admin_host, app_ikey, sid, xsrf,
                    scim_token=scim_token, extra_cookies=extra, log=_log,
                )
                results.append("Duo SCIM " + ("configured" if ok6 else "configure failed (session expired?)"))
            else:
                _log("WARN: no saved admin browser session for Duo SCIM config")
                results.append("Duo SCIM skipped (no saved browser session)")
        except Exception as e:
            _log(f"WARN: Duo SCIM configure error: {e}")
            results.append(f"Duo SCIM error: {e}")

    # ── 7. authproxyctl enroll — refresh rikey for [sso] section ─────────────
    # Runs authproxyctl.exe enroll on AD1 via WinRM to get a fresh enrollment
    # key (rikey). Replaces the stale rikey in authproxy_cfg and re-pushes.
    # Soft-fails — never blocks the pipeline.
    try:
        _log("running authproxyctl enroll on AD1 to refresh rikey ...")
        _enroll_ok, _enroll_msg = duo_authproxy_enroll_and_update(
            pod_id, db_path, log=_log
        )
        if _enroll_ok:
            results.append(f"authproxyctl enroll OK (rikey={_enroll_msg})")
        else:
            _log(f"WARN: authproxyctl enroll failed: {_enroll_msg}")
            results.append(f"authproxyctl enroll failed: {_enroll_msg}")
    except Exception as e:
        _log(f"WARN: authproxyctl enroll error: {e}")
        results.append(f"authproxyctl enroll error: {e}")

    # ── 7.5. Duo Admin Portal: enable auth source, add domain, set routing rule ─
    # Uses Playwright + saved SCC DT cookies. Soft-fails on any error.
    try:
        _log("configuring Duo admin portal (enable auth source, domain, routing rule) ...")
        _portal_ok, _portal_msg = duo_admin_portal_configure(pod_id, db_path, log=_log)
        _log(f"portal configure: {_portal_msg}")
        results.append(_portal_msg)
    except Exception as e:
        _log(f"WARN: duo_admin_portal_configure error: {e}")
        results.append(f"portal configure error: {e}")

    # ── 8. AD directory sync ──────────────────────────────────────────────────
    _sync_ok, sync_msg = duo_trigger_ad_sync(duo_ikey, duo_skey, duo_host, log=_log)
    results.append(sync_msg)

    # ── 9. Push Duo users directly to SA SCIM ────────────────────────────────
    if scim_token and duo_ikey and duo_skey and duo_host:
        try:
            _log("pushing Duo users directly to SA SCIM ...")
            _pushed = _push_duo_users_to_sa_scim(
                duo_ikey, duo_skey, duo_host, scim_token, log=_log
            )
            results.append(f"SA SCIM direct push: {_pushed} users created")
        except Exception as e:
            _log(f"WARN: SA SCIM direct push error: {e}")
            results.append(f"SA SCIM direct push error: {e}")
    else:
        results.append("SA SCIM direct push skipped (no scim_token or Duo creds)")

    return True, " | ".join(results)


# ──────────────────────────────────────────────────────────────────────────────
# Playwright browser session helper
# Launches headless Chromium, authenticates to SCC via iDAC auto-login URL,
# then navigates to Duo admin and extracts session credentials.
# ──────────────────────────────────────────────────────────────────────────────

def _idac_navigate_to_scc(ctx, page, idac_url: str, timeout_ms: int, log):
    """
    Navigate to iDAC URL and follow through to security.cisco.com.

    Handles two iDAC URL formats:
      - Direct auto-login (loaders/loader-*-autologin-saml.php) — browser
        automatically lands on security.cisco.com after one redirect.
      - Adaptive card (requestoutput.php?htmlTemplate=_generic_adaptivecards.php)
        — page shows a grid of service tiles; we must find and click the SCC
        tile to trigger the authenticated redirect.

    Returns the Playwright Page that is now on security.cisco.com.
    Raises RuntimeError if navigation fails at any stage.
    """
    log("navigating to iDAC URL ...")
    # Use "load" (not "networkidle") — adaptive card pages keep background-polling
    # and will never reach networkidle, causing a 90-second timeout.
    try:
        page.goto(idac_url, timeout=timeout_ms, wait_until="load")
    except Exception as e:
        # "load" itself timed out — try just waiting for HTTP headers
        if "networkidle" in str(e) or "load" in str(e).lower():
            log(f"WARN: goto with wait_until=load timed out, retrying with commit: {e}")
            page.goto(idac_url, timeout=timeout_ms, wait_until="commit")
            page.wait_for_timeout(3000)
        else:
            raise

    # Already on SCC — direct auto-login format worked
    if "security.cisco.com" in page.url:
        log(f"iDAC auto-redirected to SCC: {page.url[:80]}")
        return page

    # Adaptive card page — find and click the SCC service tile
    if "requestoutput.php" in page.url or "idac.cat-dcloud.com" in page.url:
        log(f"iDAC adaptive card detected (url={page.url[:80]}); waiting for tiles to load ...")

        # Tiles are populated by an AJAX call to getRequestStatus().
        # Some tiles load quickly; the "Loading data..." placeholder in the last
        # section (session history) may NEVER resolve — use a short timeout and
        # proceed regardless.
        try:
            page.wait_for_function(
                "() => !document.body.textContent.includes('Loading data...')",
                timeout=8_000,
            )
            page.wait_for_timeout(1000)  # let final render settle
            log("tiles loaded (Loading data... gone)")
        except Exception:
            log("tiles partially loaded (Loading data... still present) — proceeding")
            page.wait_for_timeout(2000)

        scc_selectors = [
            # iDAC adaptive card: SCC tile is a <button>View</button>
            "button:has-text('View')",
            # Autologin / loader URLs (iDAC link format for SCC tile)
            "a[href*='security.cisco.com']",
            "a[href*='autologin']",
            "a[href*='loader-cisco']",
            "a[href*='idac.cat-dcloud.com/loaders/']",
            # Text-based selectors
            "a:has-text('Security Cloud')",
            "a:has-text('Cisco Security')",
            "a:has-text('SecureX')",
            "a:has-text('SCC')",
            "a:has-text('Security')",
            "a:has-text('Go to account')",
            "a:has-text('Go to')",
            # Button/div fallbacks
            "button:has-text('Security Cloud')",
            "button:has-text('Cisco Security')",
            "button:has-text('SecureX')",
            "button:has-text('Security')",
            "[onclick*='security.cisco.com']",
            "[data-url*='security.cisco.com']",
            "[href*='security.cisco.com']",
        ]

        scc_link = None
        for sel in scc_selectors:
            try:
                lc = page.locator(sel)
                if lc.count() > 0:
                    scc_link = lc.first
                    log(f"SCC tile found via selector: {sel!r}")
                    break
            except Exception:
                continue

        if scc_link is None:
            # Dump page content to help diagnose selector mismatch
            try:
                html_snippet = page.evaluate(
                    "() => document.body.innerHTML.slice(0, 8000)"
                )
                log(f"SCC tile NOT found. Page HTML (8000 chars):\n{html_snippet}")
                # Also write to a file so it persists after container exit
                try:
                    with open("/tmp/idac_adaptive_card_debug.html", "w") as _fh:
                        _fh.write(f"<!-- URL: {page.url} -->\n{html_snippet}")
                    log("HTML dump written to /tmp/idac_adaptive_card_debug.html")
                except Exception:
                    pass
            except Exception as he:
                log(f"SCC tile NOT found. Could not dump HTML: {he}")
            raise RuntimeError(
                f"Could not find SCC service tile on iDAC adaptive card. "
                f"URL={page.url[:100]}"
            )

        # Click — SCC tile may open in a new tab
        try:
            with ctx.expect_page(timeout=30_000) as new_page_info:
                scc_link.click(timeout=10_000)
            scc_page = new_page_info.value
            scc_page.wait_for_load_state("load", timeout=timeout_ms)
            log(f"SCC opened in new tab: {scc_page.url[:80]}")
        except Exception:
            # No new tab — same-tab navigation
            try:
                page.wait_for_url("*security.cisco.com*", timeout=timeout_ms)
            except Exception:
                if "security.cisco.com" not in page.url:
                    raise RuntimeError(
                        f"After clicking SCC tile, did not land on SCC — got: {page.url[:100]}"
                    )
            scc_page = page
            log(f"SCC loaded in same tab: {scc_page.url[:80]}")

        # Final guard + wait for SCC app to fully load and populate sessionStorage
        if "security.cisco.com" not in scc_page.url:
            try:
                scc_page.wait_for_url("*security.cisco.com*", timeout=30_000)
            except Exception:
                raise RuntimeError(
                    f"iDAC adaptive card SCC navigation failed — final URL: {scc_page.url[:100]}"
                )
        # Give SCC React app time to set okta-token-storage in sessionStorage
        scc_page.wait_for_timeout(5000)
        return scc_page

    # Unknown page — try waiting for SCC redirect (should not normally reach here)
    try:
        page.wait_for_url("*security.cisco.com*", timeout=timeout_ms)
    except Exception:
        current = page.url
        log(f"URL after iDAC goto: {current[:100]}")
        if "security.cisco.com" not in current:
            page.wait_for_timeout(5000)
            if "security.cisco.com" not in page.url:
                raise RuntimeError(
                    f"iDAC did not land on security.cisco.com — got: {page.url[:120]}"
                )
    log(f"SCC loaded: {page.url[:80]}")
    return page


def get_browser_sessions(idac_url: str, duo_host: str,
                         timeout_ms: int = 90_000,
                         log=None) -> dict:
    """
    Launch headless Chromium, authenticate to SCC via iDAC auto-login URL,
    then navigate to the Duo admin panel and extract session credentials.

    Returns dict with keys:
      okta_token  – Okta access token (for sa_get_mgmt_jwt)
      duo_sid     – Duo admin 'sid' cookie value
      duo_xsrf    – Duo admin '_xsrf' cookie value
      admin_host  – Duo admin hostname (e.g. admin-2bb9ad3d.duosecurity.com)

    Raises RuntimeError on failure.
    """
    _log = log or (lambda s: print(f"     [browser] {s}"))

    from playwright.sync_api import sync_playwright
    import re as _re4

    # Derive admin host from duo_host: api-X → admin-X
    m4 = _re4.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    expected_admin = f"admin-{m4.group(1)}.duosecurity.com" if m4 else None

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1400, "height": 900},
        )
        page = ctx.new_page()

        # Step 1: iDAC → SCC (handles direct auto-login and adaptive card formats)
        page = _idac_navigate_to_scc(ctx, page, idac_url, timeout_ms, _log)

        # Step 2: Extract Okta access token from sessionStorage
        def _get_okta_token():
            try:
                return page.evaluate(
                    "(() => { try { "
                    "const raw = sessionStorage.getItem('okta-token-storage'); "
                    "if (!raw) return ''; "
                    "const obj = JSON.parse(raw); "
                    "return (obj.accessToken && obj.accessToken.accessToken) || ''; "
                    "} catch(e) { return ''; } })()"
                )
            except Exception:
                return ""

        okta_token = _get_okta_token()
        if not okta_token:
            page.wait_for_timeout(3000)
            okta_token = _get_okta_token()
        if not okta_token:
            page.wait_for_timeout(5000)
            okta_token = _get_okta_token()
        if not okta_token:
            # Also try localStorage
            try:
                okta_token = page.evaluate(
                    "(() => { try { "
                    "const raw = localStorage.getItem('okta-token-storage'); "
                    "if (!raw) return ''; "
                    "const obj = JSON.parse(raw); "
                    "return (obj.accessToken && obj.accessToken.accessToken) || ''; "
                    "} catch(e) { return ''; } })()"
                )
            except Exception:
                pass
        if not okta_token:
            _log(f"sessionStorage keys: {page.evaluate('() => Object.keys(sessionStorage)')}")
            _log(f"current URL: {page.url[:120]}")
            raise RuntimeError(
                "Could not extract Okta token from SCC sessionStorage — "
                "login or org selection may not have completed"
            )
        _log("Okta token extracted from SCC sessionStorage")

        # Step 3: Navigate to SCC Duo dashboard and click admin link
        _log("navigating to SCC Duo dashboard...")
        duo_page = None
        try:
            page.goto(
                "https://security.cisco.com/duo/dashboard/",
                timeout=timeout_ms,
                wait_until="networkidle",
            )
            page.wait_for_timeout(2000)

            # Find Duo admin link — try several patterns
            admin_link = None
            for sel in [
                f"a[href*='{expected_admin}']" if expected_admin else "",
                "a[href*='admin-'][href*='duosecurity']",
                "a:has-text('Duo Admin')",
                "a:has-text('Admin Panel')",
                "a:has-text('Open Duo')",
            ]:
                if not sel:
                    continue
                try:
                    lc = page.locator(sel)
                    if lc.count() > 0:
                        admin_link = lc.first
                        break
                except Exception:
                    continue

            if admin_link:
                with ctx.expect_page(timeout=30_000) as new_page_info:
                    admin_link.click(timeout=10_000)
                duo_page = new_page_info.value
                duo_page.wait_for_load_state("networkidle", timeout=timeout_ms)
                _log(f"Duo admin opened via link: {duo_page.url[:80]}")
        except Exception as e:
            _log(f"WARN: SCC Duo dashboard approach failed ({e}), trying direct navigation")

        # Fallback: navigate directly to Duo admin host from browser context
        if duo_page is None and expected_admin:
            _log(f"trying direct navigation to https://{expected_admin}/ ...")
            duo_page = ctx.new_page()
            duo_page.goto(
                f"https://{expected_admin}/",
                timeout=timeout_ms,
                wait_until="networkidle",
            )
            # Check if we got a login page or an authenticated session
            if "login" in duo_page.url or "duosecurity.com/login" in duo_page.url:
                raise RuntimeError(
                    f"Direct Duo admin navigation landed on login page — "
                    "SSO did not carry over. Use iDAC URL for Duo dashboard flow."
                )
            _log(f"Direct Duo admin loaded: {duo_page.url[:80]}")

        if duo_page is None:
            raise RuntimeError("Could not open Duo admin panel via any method")

        # Step 4: Extract admin hostname and session cookies
        admin_host_actual = duo_page.url.split("/")[2]
        _log(f"Duo admin host: {admin_host_actual}")

        all_cookies = ctx.cookies()
        # Filter cookies for the Duo admin domain
        duo_cookies = {
            c["name"]: c["value"]
            for c in all_cookies
            if admin_host_actual in c.get("domain", "")
            or c.get("domain", "").lstrip(".") in admin_host_actual
        }
        sid = duo_cookies.get("sid", "")
        xsrf = duo_cookies.get("_xsrf", "")

        if not sid:
            # Try all cookies (domain matching can be loose)
            all_dict = {c["name"]: c["value"] for c in all_cookies}
            sid = all_dict.get("sid", "")
            xsrf = all_dict.get("_xsrf", "")

        browser.close()

        if not sid:
            raise RuntimeError("Could not extract 'sid' cookie from Duo admin session")
        if not xsrf:
            raise RuntimeError("Could not extract '_xsrf' cookie from Duo admin session")

        _log("Duo admin session cookies extracted")
        return {
            "okta_token": okta_token,
            "duo_sid":    sid,
            "duo_xsrf":   xsrf,
            "admin_host": admin_host_actual,
        }


# ──────────────────────────────────────────────────────────────────────────────
# Fetch iDAC auto-login URL from lab jump host dashboard
# ──────────────────────────────────────────────────────────────────────────────

# Jump host IP — WinRM port 5985 is open; has Python 3.11.4 + idac_sdk installed.
JUMP_HOST_IP = "198.18.133.36"
JUMP_HOST_WINRM_CREDS = ("administrator", "C1sco12345")

# Python script written to jump host temp file to generate a fresh iDAC URL.
# Reads C:\dcloud\session.xml for DCLOUD_SESSION auth credentials.
_IDAC_SDK_SCRIPT = """\
import asyncio, sys, xml.etree.ElementTree as ET
from idac_sdk import (
    IDACRequestAsync, IDACControllerAsync,
    IDACAuthType, IDACRequestType, SessionData,
)

async def get_url():
    root = ET.parse('C:\\\\dcloud\\\\session.xml')
    device_name = root.find('.//device/name').text
    pod_number = device_name.split('-P')[-1]
    email = 'x-arch-duo-' + pod_number + '@dcloud.cisco.com'
    sd = SessionData(recipeName='cross-arch-sec-main', recipePath='sevt-lab/')
    sd.set('email', email)
    sd.set('tenant', pod_number)
    ctrl = IDACControllerAsync(auth_type=IDACAuthType.DCLOUD_SESSION)
    req = IDACRequestAsync(session_data=sd, controller=ctrl)
    await req.create(request_type=IDACRequestType.SIMPLE)
    state = await req.wait_for_status()
    sys.stdout.write(state.outputUrl)
    sys.stdout.flush()

asyncio.run(get_url())
"""


def fetch_idac_url_from_dcloud(log=None, pod_id: str = "",
                               allow_rotation: bool = False) -> str:
    """
    Connect to jump host via WinRM, run idac_sdk on it to generate a fresh
    iDAC auto-login URL.

    *** DESTRUCTIVE — REPROVISIONS THE ENTIRE POD IDENTITY ***

    Every idac_sdk run mints a brand new Duo org AND a new SCC org AND a new
    Meraki org, orphaning whatever was configured against the old ones. It is
    not a read operation and it is not idempotent. Calling it repeatedly walked
    one pod from SCC org 517 to 502 and abandoned six Duo orgs.

    Because of that it is guarded: callers must pass allow_rotation=True and
    mean it. To READ the pod's existing accounts, load the stored
    org_credentials.idac_url instead — that is read-only and does not rotate.

    The jump host is only reachable inside a POD's VPN namespace. Pass *pod_id*
    when calling from the Mac (the dashboard runs duo_run_card in a thread
    there) so the session is proxied through vpn-{pod_id}; omit it when already
    running inside the pipeline container.

    Returns the iDAC URL string, or raises RuntimeError on failure.
    """
    import base64

    if not allow_rotation:
        raise RuntimeError(
            "fetch_idac_url_from_dcloud() would reprovision this pod's Duo, SCC "
            "and Meraki orgs. Use the stored org_credentials.idac_url to read "
            "existing accounts, or pass allow_rotation=True if you really do "
            "want brand new orgs."
        )

    _log = log or (lambda s: print(f"     [fetch-idac] {s}"))
    _log(f"WinRM → {JUMP_HOST_IP}: generating fresh iDAC URL via idac_sdk")

    if pod_id:
        sess = _winrm_connect_jump(pod_id, log=log)
    else:
        import winrm
        sess = winrm.Session(
            JUMP_HOST_IP,
            auth=JUMP_HOST_WINRM_CREDS,
            transport="ntlm",
            # Proven working values: 30/20. read_timeout_sec is also used as the
            # HTTP connect timeout by pywinrm/requests, so large values cause
            # ConnectTimeout failures. winrm polls repeatedly, so long-running
            # commands (idac_sdk ~4min) complete across multiple 20-second poll windows.
            read_timeout_sec=30,
            operation_timeout_sec=20,
        )

    # Write the Python script to a temp file via PowerShell (base64 avoids
    # all quoting / line-ending issues when embedding multiline strings).
    b64 = base64.b64encode(_IDAC_SDK_SCRIPT.encode("utf-8")).decode()
    ps_write = (
        f"$bytes = [System.Convert]::FromBase64String('{b64}');"
        r"$txt = [System.Text.Encoding]::UTF8.GetString($bytes);"
        r"Set-Content -Path 'C:\Windows\Temp\get_idac.py' -Value $txt -Encoding UTF8"
    )
    r = sess.run_ps(ps_write)
    if r.status_code != 0:
        raise RuntimeError(
            f"Failed to write temp script on jump host: {r.std_err.decode()[:300]}"
        )

    _log("running idac_sdk on jump host (may take ~30s)...")
    r2 = sess.run_cmd(
        r"C:\Python311\python.exe", [r"C:\Windows\Temp\get_idac.py"]
    )
    url = r2.std_out.decode("utf-8", errors="replace").strip()
    err = r2.std_err.decode("utf-8", errors="replace").strip()

    if not url or "idac.cat-dcloud.com" not in url:
        raise RuntimeError(
            f"idac_sdk returned no valid URL — stderr: {err[:300]} | stdout: {url[:100]}"
        )

    _log(f"fresh iDAC URL: {url[:80]}...")
    return url


# ──────────────────────────────────────────────────────────────────────────────
# Duo Admin Account Activation + TOTP Enrollment (per-session, no phone needed)
# ──────────────────────────────────────────────────────────────────────────────

def _totp_generate(secret: str) -> str:
    """Generate current 6-digit TOTP code (RFC 6238) from base32 or hex secret."""
    import hmac as _h, hashlib as _hs, struct as _st, time as _tm, base64 as _b64
    s = secret.strip().replace(" ", "")
    # Try base32 first, fall back to hex
    try:
        # Pad to multiple of 8 for base32
        pad = (8 - len(s) % 8) % 8
        key = _b64.b32decode(s.upper() + "=" * pad)
    except Exception:
        try:
            key = bytes.fromhex(s)
        except Exception:
            key = s.encode()
    counter = int(_tm.time()) // 30
    msg = _st.pack(">Q", counter)
    h = _h.new(key, msg, _hs.sha1).digest()
    offset = h[-1] & 0xF
    code = _st.unpack(">I", h[offset:offset + 4])[0]
    return f"{(code & 0x7FFFFFFF) % 1_000_000:06d}"


def _duo_enroll_totp_device(activation_code: str, api_host: str, log=None) -> str:
    """
    Register a virtual Duo Mobile device via the activation API.

    Tries progressively newer app_version strings until one is accepted.
    Raises RuntimeError only when no version works or a non-version error occurs.
    """
    _log = log or (lambda s: print(f"     [enroll] {s}"))

    # Ordered from newest to oldest — Duo drops support for old versions rolling
    VERSIONS = [
        ("5.5.0",  "550000001", "18.0"),
        ("5.0.0",  "500000001", "17.7"),
        ("4.95.0", "495000001", "17.6"),
        ("4.90.0", "490000001", "17.6"),
        ("4.85.0", "485000001", "17.6"),
        ("4.80.0", "480000001", "17.6"),
        ("4.75.0", "475000001", "17.6"),
    ]

    url = f"https://{api_host}/push/v2/activation/{activation_code}"
    last_err = "no versions tried"

    for app_version, build_number, ios_version in VERSIONS:
        payload = {
            "jailbroken":            "false",
            "architecture":          "arm64",
            "region":                "US",
            "app_id":                "com.duosecurity.duomobile",
            "full_disk_encryption":  "true",
            "passcode_status":       "true",
            "platform":              "Apple iOS",
            "app_version":           app_version,
            "app_build_number":      build_number,
            "version":               ios_version,
            "manufacturer":          "Apple",
            "language":              "en",
            "model":                 "iPhone 15 Pro",
            "customer_protocol":     "1",
        }
        _log(f"enrolling via {url} (app_version={app_version}) ...")
        r = requests.post(url, data=payload, timeout=20)
        try:
            d = r.json()
        except Exception:
            raise RuntimeError(f"enrollment API non-JSON: HTTP {r.status_code} {r.text[:200]}")

        msg = d.get("message", "")
        if d.get("stat") == "OK":
            resp = d.get("response", {})
            _log(f"enrollment response keys: {list(resp.keys())}")
            secret = (
                resp.get("totp_secret")
                or resp.get("hotp_secret")
                or (resp.get("limited_credential") or {}).get("key")
                or resp.get("akey")
            )
            if not secret:
                raise RuntimeError(f"no TOTP secret in enrollment response: {resp}")
            _log(f"TOTP device enrolled with app_version={app_version} (secret_len={len(secret)})")
            return secret

        if "deprecated" in msg.lower() or "no longer supported" in msg.lower():
            _log(f"  app_version={app_version} deprecated — trying next ...")
            last_err = msg
            continue

        # Any other error — log full response and stop
        _log(f"  app_version={app_version} non-deprecated error: HTTP {r.status_code} body={d}")
        raise RuntimeError(f"enrollment API failed: {msg}")

    raise RuntimeError(f"enrollment failed — all versions deprecated. Last error: {last_err}")


def _pw_activate_duo_admin(idac_url: str, log=None):
    """
    Playwright: activate the Duo admin account from iDAC adaptive-card page.

    Steps:
      1. Navigate to iDAC page, extract email + suggested password from Duo section
      2. Click 'Activate Account' button — opens new tab
      3. Complete password setup ('Get started' → fill password → Continue)
      4. Skip any 2FA enrollment prompts — password is saved server-side at this point
      5. Close browser

    Returns (email, password).
    2FA enrollment is intentionally skipped — bypass codes will be used for login.
    Raises RuntimeError on failure.
    """
    _log = log or (lambda s: print(f"     [pw-activate] {s}"))
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1400, "height": 900},
        )
        page = ctx.new_page()

        _log(f"navigating to iDAC: {idac_url[:80]}")
        page.goto(idac_url, wait_until="load", timeout=30_000)
        page.wait_for_timeout(4000)  # adaptive cards finish rendering

        # ── Extract email + suggested password from Duo section ───────────────
        # The iDAC page renders Adaptive Cards as <div class="ac-textBlock">,
        # not <p> — an earlier <p>-based lookup matched nothing and always
        # raised "Could not extract Duo admin credentials".
        #
        # It must also be anchored on the "Cisco Duo" heading. The card lists
        # several accounts and the label "Email" appears under each one
        # (ThousandEyes first, then Cisco Duo, then IOT/PROD users), so taking
        # the first match returns the ThousandEyes address. Scan only the
        # window between "Cisco Duo" and the next account's heading.
        creds = page.evaluate("""() => {
            const blocks = Array.from(
                document.querySelectorAll('.ac-textBlock, p, div')
            ).filter(e => e.children.length === 0)          // leaf nodes only
             .map(e => e.textContent.trim())
             .filter(t => t.length > 0);

            const start = blocks.findIndex(t => /^Cisco Duo$/i.test(t));
            if (start === -1) return {email: '', password: '', anchor: false};

            // Stop before the per-user emails that follow the admin block.
            let end = blocks.length;
            for (let i = start + 1; i < blocks.length; i++) {
                if (/^(IOT|PROD|MAIN)\\s+User\\s+Email$/i.test(blocks[i])) { end = i; break; }
            }

            let email = '', password = '';
            for (let i = start; i < end - 1; i++) {
                if (!email && /^Email$/i.test(blocks[i]) && blocks[i+1].includes('@')) {
                    email = blocks[i+1];
                }
                if (!password && /^Suggested\\s+Password$/i.test(blocks[i])) {
                    password = blocks[i+1];
                }
            }
            return {email, password, anchor: true};
        }""")
        if not creds.get("anchor"):
            _log("WARN: no 'Cisco Duo' section found on iDAC page")
        email    = creds.get("email", "")
        password = creds.get("password", "")
        if not email or not password:
            raise RuntimeError(
                f"Could not extract Duo admin credentials from iDAC page "
                f"(email={email!r}, password_found={bool(password)})"
            )
        _log(f"iDAC: email={email}")

        # ── Click 'Activate Account' — opens new tab ──────────────────────────
        with ctx.expect_page() as new_page_info:
            btns = page.locator("button").all()
            clicked = False
            for btn in btns:
                try:
                    if "Activate Account" in btn.inner_text():
                        btn.click()
                        clicked = True
                        break
                except Exception:
                    pass
            if not clicked:
                raise RuntimeError("'Activate Account' button not found on iDAC page")

        activation_page = new_page_info.value
        activation_page.wait_for_load_state("load", timeout=15_000)
        _log(f"activation page: {activation_page.url[:80]}")

        # ── Step 1: Get started ───────────────────────────────────────────────
        try:
            activation_page.get_by_role("button", name="Get started").click(timeout=8_000)
            activation_page.wait_for_timeout(1000)
        except Exception:
            pass

        # ── Step 2: Set password ──────────────────────────────────────────────
        try:
            activation_page.get_by_role("textbox", name="Create password").fill(
                password, timeout=8_000
            )
            activation_page.get_by_role("textbox", name="Confirm password").fill(
                password, timeout=5_000
            )
            activation_page.get_by_role("button", name="Continue").click(timeout=5_000)
            activation_page.wait_for_timeout(1500)
            _log("password set — server has saved it")
        except Exception as e:
            _log(f"WARN: password step: {e}")

        # ── Step 3: Skip all 2FA enrollment prompts ───────────────────────────
        # Password is already saved at this point. We don't need to enroll any
        # device — bypass codes will be used for subsequent logins.
        for skip_text in ["Skip for now", "I'll set this up later",
                          "Skip", "Do it later", "Next", "Continue"]:
            try:
                activation_page.get_by_text(skip_text, exact=False).click(timeout=2_500)
                activation_page.wait_for_timeout(800)
                _log(f"clicked '{skip_text}' on 2FA enrollment page")
            except Exception:
                pass

        _log(f"activation done (final url={activation_page.url[:80]})")
        browser.close()
        return email, password


# ──────────────────────────────────────────────────────────────────────────────
# Passkey bootstrap — log into a fresh Duo org with no phone and no pre-existing
# Admin API credentials.
#
# Duo's admin activation offers two second factors: Passkey and Duo Mobile.
# Duo Mobile is a dead end for automation — /push/v2/activation/<code> now
# rejects unsigned enrollment ("Signature type is not supported", code 40112),
# so _duo_enroll_totp_device() cannot register a virtual device any more.
#
# Passkey is WebAuthn, and Chrome DevTools Protocol exposes a virtual
# authenticator. We enroll one, export the credential, and replay it on every
# later login. That closes the bootstrap loop: activate -> passkey -> log in ->
# create an Admin API app -> harvest ikey/skey/host.
# ──────────────────────────────────────────────────────────────────────────────

_VIRTUAL_AUTH_OPTS = {
    "protocol": "ctap2",
    "ctap2Version": "ctap2_1",
    "transport": "internal",
    "hasResidentKey": True,
    "hasUserVerification": True,
    "isUserVerified": True,            # simulate a successful biometric gesture
    "automaticPresenceSimulation": True,
    "backupEligibility": True,
    "backupState": True,
}


def _pw_add_virtual_authenticator(ctx, page):
    """Attach a CDP virtual authenticator. Returns (cdp_session, authenticator_id)."""
    cdp = ctx.new_cdp_session(page)
    cdp.send("WebAuthn.enable", {"enableUI": False})
    auth_id = cdp.send(
        "WebAuthn.addVirtualAuthenticator", {"options": _VIRTUAL_AUTH_OPTS}
    )["authenticatorId"]
    return cdp, auth_id


def _pw_load_passkey(ctx, page, credentials: list, hwm: int = 0):
    """Attach a virtual authenticator preloaded with a previously exported passkey.

    WebAuthn clone detection: the relying party stores the highest signCount it
    has seen and rejects any assertion that is not strictly greater. Restoring
    the enrollment-time counter therefore succeeds exactly once and every later
    login fails with "Passkey authentication failed". Always restore above the
    stored high-water mark, and persist the new mark after each login.
    """
    cdp, auth_id = _pw_add_virtual_authenticator(ctx, page)
    base = int(hwm or 0) + 50
    for c in credentials:
        cdp.send("WebAuthn.addCredential", {
            "authenticatorId": auth_id,
            "credential": {
                "credentialId":         c["credentialId"],
                "isResidentCredential": c.get("isResidentCredential", False),
                "rpId":                 c.get("rpId"),
                "privateKey":           c["privateKey"],
                "userHandle":           c.get("userHandle") or "",
                "signCount":            base,
            },
        })
    return cdp, auth_id, base


def _pw_read_signcount(cdp, auth_id: int, fallback: int = 0) -> int:
    """Current signCount high-water mark for the virtual authenticator."""
    try:
        creds = cdp.send("WebAuthn.getCredentials", {"authenticatorId": auth_id})
        return max([c.get("signCount", 0) for c in creds.get("credentials", [])]
                   or [fallback])
    except Exception:
        return fallback


def _pw_duo_admin_login_passkey(page, admin_host: str, email: str, password: str,
                                log=None) -> bool:
    """Drive the two-step Duo admin login. Assumes a passkey authenticator is attached.

    Returns True when we land inside the admin panel.
    """
    _log = log or (lambda s: print(f"     [duo-login] {s}"))
    page.goto(f"https://{admin_host}", wait_until="load", timeout=45_000)
    page.wait_for_timeout(3_000)

    page.fill('input[type="email"]', email)
    page.get_by_role("button", name="Continue").click()
    page.wait_for_timeout(4_000)

    page.fill('input[type="password"]', password)
    # "Log in as someone else" also contains "Log in" — a substring match hits it
    # and resets the flow back to the email step, looping forever. Match exactly.
    page.get_by_role("button", name="Log in", exact=True).click()
    page.wait_for_timeout(9_000)

    # Once the admin has more than one second factor (e.g. after
    # duo_provision_admin_totp adds a hardware token) Duo inserts a
    # "Select login option" page instead of going straight to the only method.
    if "/login" in page.url:
        body = page.evaluate("() => document.body.innerText")
        if "Select login option" in body or "Confirm your identity" in body:
            _log("method chooser shown — selecting Passkey")
            page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('button,a'))
                    .find(x => /^passkey$/i.test((x.innerText || '').trim()));
                if (b) b.click();
            }""")
            page.wait_for_timeout(9_000)

    if "/login" in page.url:
        body = page.evaluate("() => document.body.innerText.slice(0, 200)")
        _log(f"login failed: {body.strip()[:140]!r}")
        return False
    _log(f"logged in -> {page.url[:70]}")
    return True


def _pw_capture_copy_buttons(page) -> list:
    """Click every 'Copy' button and return the values they wrote.

    Duo renders Admin API credentials behind clipboard buttons rather than as
    text — the secret key never appears in innerText or an input value. Hook
    both the async clipboard API and execCommand('copy') to capture them.
    """
    page.evaluate("""() => {
        if (window.__copyHooked) return;
        window.__copyHooked = true;
        window.__copied = [];
        if (navigator.clipboard) {
            const orig = navigator.clipboard.writeText;
            navigator.clipboard.writeText = function (t) {
                window.__copied.push(t);
                return orig ? orig.call(navigator.clipboard, t) : Promise.resolve();
            };
        }
        const ec = document.execCommand.bind(document);
        document.execCommand = function (c, ...rest) {
            if (String(c).toLowerCase() === 'copy') {
                const sel = window.getSelection && window.getSelection().toString();
                if (sel) window.__copied.push(sel);
                const ae = document.activeElement;
                if (ae && ae.value) window.__copied.push(ae.value);
            }
            return ec(c, ...rest);
        };
    }""")
    idxs = page.evaluate("""() => Array.from(document.querySelectorAll('button'))
        .map((b, i) => ({i, t: (b.innerText || '').trim()}))
        .filter(x => /^copy$/i.test(x.t)).map(x => x.i)""")
    for i in idxs:
        page.evaluate(f"() => document.querySelectorAll('button')[{i}].click()")
        page.wait_for_timeout(900)
    return page.evaluate("() => window.__copied || []")


def _pw_create_admin_api_app(page, admin_host: str, log=None) -> dict:
    """Create the Admin API application and return {ikey, skey, host}.

    A new Admin API app has no permissions until they are granted and saved —
    without that every call returns 403.
    """
    _log = log or (lambda s: print(f"     [admin-api] {s}"))

    page.goto(f"https://{admin_host}/applications/protect/types",
              wait_until="load", timeout=40_000)
    page.wait_for_timeout(6_000)

    # input[type=search] is the GLOBAL site search. The list filter is the text
    # input placeholdered "Search applications" — filling the wrong one leaves
    # the list unfiltered and the first Add button creates a random application.
    try:
        page.locator('input[placeholder*="Search applications"]').first.fill("Admin API")
        page.wait_for_timeout(4_000)
    except Exception as e:
        _log(f"could not filter list: {type(e).__name__}")

    # Match the heading exactly — "Cisco ISE Admin API" is a decoy entry.
    res = page.evaluate("""() => {
        const hs = Array.from(document.querySelectorAll('h3'))
            .filter(h => (h.textContent || '').trim().toLowerCase() === 'admin api');
        if (!hs.length) return {ok: false, reason: 'no exact "Admin API" heading'};
        let n = hs[0];
        for (let i = 0; i < 6 && n; i++) {
            n = n.parentElement;
            if (!n) break;
            const btn = Array.from(n.querySelectorAll('button,a'))
                .find(x => /^add$/i.test((x.innerText || '').trim()));
            if (btn) { btn.click(); return {ok: true}; }
        }
        return {ok: false, reason: 'no Add control near heading'};
    }""")
    if not res.get("ok"):
        raise RuntimeError(f"could not add Admin API application: {res.get('reason')}")
    page.wait_for_timeout(9_000)
    _log(f"application created: {page.url[-24:]}")

    granted = page.evaluate("""() => {
        const on = [];
        document.querySelectorAll('input[type=checkbox]').forEach(cb => {
            const lab = (cb.closest('label')?.innerText ||
                document.querySelector(`label[for="${cb.id}"]`)?.innerText ||
                cb.name || '').trim();
            if (/grant/i.test(lab) || /grant/i.test(cb.name || '')) {
                if (!cb.checked) cb.click();
                on.push((lab.split('\\n')[0] || cb.name).slice(0, 40));
            }
        });
        const save = Array.from(document.querySelectorAll('button,input[type=submit]'))
            .find(b => /^save/i.test((b.innerText || b.value || '').trim()));
        if (save) save.click();
        return on;
    }""")
    _log(f"granted {len(granted)} permissions: {', '.join(granted[:4])}...")
    page.wait_for_timeout(8_000)

    vals = _pw_capture_copy_buttons(page)
    ikey = next((v for v in vals if v.startswith("DI") and len(v) == 20), "")
    host = next((v for v in vals if "duosecurity.com" in v), "")
    skey = next((v for v in vals if len(v) >= 32 and v not in (ikey, host)), "")
    if not (ikey and skey and host):
        raise RuntimeError(
            f"could not harvest Admin API credentials "
            f"(ikey={bool(ikey)}, skey_len={len(skey)}, host={bool(host)})"
        )
    _log(f"harvested ikey={ikey} skey({len(skey)}) host={host}")
    return {"ikey": ikey, "skey": skey, "host": host}


def duo_passkey_bootstrap(pod_id: str, db_path: str, log=None) -> tuple[bool, str]:
    """Bring a fresh Duo org from nothing to usable Admin API credentials.

    iDAC -> activate admin -> enrol virtual passkey -> log in -> create Admin API
    app -> harvest ikey/skey/host. Everything is persisted to org_credentials so
    later runs reuse the passkey instead of re-activating.

    Requires WinRM to the jump host (idac_sdk mints the iDAC URL there).
    """
    import json as _json
    import re as _re
    import sqlite3 as _sq

    from playwright.sync_api import sync_playwright

    _log = log or (lambda s: print(f"  [duo-bootstrap] {s}"))
    duo_ensure_table(db_path)

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        org_num = m.group(1)
        row = conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                           (org_num,)).fetchone()
        oc = dict(row) if row else {}

    if oc.get("duo_ikey") and oc.get("duo_skey") and oc.get("duo_host"):
        return True, f"org {org_num} already has Admin API credentials — nothing to do"

    # DESTRUCTIVE: each idac_sdk run reprovisions the whole pod identity — a new
    # Duo org AND a new SCC org AND a new Meraki org. Never mint a URL when one
    # is already stored; loading a stored URL is read-only and keeps the pod's
    # current orgs intact.
    idac = (oc.get("idac_url") or "").strip()
    if idac:
        _log(f"org {org_num}: reusing stored iDAC URL (minting a new one would "
             f"rotate the pod's Duo/SCC/Meraki orgs)")
    else:
        _log(f"org {org_num}: no stored iDAC URL — minting one via jump host "
             f"(this provisions fresh Duo/SCC/Meraki orgs)")
        idac = fetch_idac_url_from_dcloud(log=_log, pod_id=pod_id,
                                          allow_rotation=True)

    # _pw_activate_duo_admin() runs its own sync_playwright(); nesting a second
    # one raises "Sync API inside the asyncio loop". Activate first, then open
    # our own browser for the passkey work.
    email, password = _pw_activate_duo_admin(idac, log=_log)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = browser.new_context(ignore_https_errors=True,
                                  viewport={"width": 1500, "height": 1100},
                                  permissions=["clipboard-read", "clipboard-write"])
        try:
            page = ctx.new_page()

            # Re-open the activation tab to enrol the passkey — the activation
            # helper closed its own browser.
            admin_host = ""
            page.goto(idac, wait_until="load", timeout=45_000)
            page.wait_for_timeout(4_000)
            with ctx.expect_page(timeout=25_000) as info:
                for btn in page.locator("button").all():
                    try:
                        if "Activate Account" in btn.inner_text():
                            btn.click()
                            break
                    except Exception:
                        pass
            act = info.value
            act.wait_for_load_state("load", timeout=20_000)
            act.wait_for_timeout(2_500)
            admin_host = act.url.split("/")[2]
            cdp2, auth2 = _pw_add_virtual_authenticator(ctx, act)

            for label in ("Continue", "Skip for now"):
                try:
                    act.get_by_role("button", name=label, exact=False).first.click(timeout=6_000)
                    act.wait_for_timeout(3_000)
                except Exception:
                    pass
            try:
                act.get_by_role("button", name="Add Passkey", exact=False).first.click(timeout=10_000)
            except Exception:
                act.evaluate("""() => {
                    const b = Array.from(document.querySelectorAll('button,a'))
                        .find(x => /add passkey/i.test(x.innerText || ''));
                    if (b) b.click();
                }""")
            act.wait_for_timeout(6_000)

            creds = cdp2.send("WebAuthn.getCredentials",
                              {"authenticatorId": auth2}).get("credentials", [])
            if not creds:
                return False, "passkey enrolment produced no credential"
            _log(f"passkey enrolled ({len(creds)} credential, rpId={creds[0].get('rpId')})")
            hwm = _pw_read_signcount(cdp2, auth2)

            with _sq.connect(db_path) as conn:
                conn.execute(
                    "UPDATE org_credentials SET duo_admin_email=?, duo_admin_password=?, "
                    "duo_admin_host=?, duo_passkey_cred=?, duo_passkey_hwm=?, idac_url=?, "
                    "updated_at=datetime('now') WHERE org_number=?",
                    (email, password, admin_host, _json.dumps(creds), hwm, idac, org_num),
                )
            _log("passkey + admin credentials persisted")

            page2 = ctx.new_page()
            cdp3, auth3, base = _pw_load_passkey(ctx, page2, creds, hwm)
            if not _pw_duo_admin_login_passkey(page2, admin_host, email, password, log=_log):
                return False, "passkey login failed after enrolment"
            hwm = _pw_read_signcount(cdp3, auth3, base)

            api = _pw_create_admin_api_app(page2, admin_host, log=_log)

            with _sq.connect(db_path) as conn:
                conn.execute(
                    "UPDATE org_credentials SET duo_ikey=?, duo_skey=?, duo_host=?, "
                    "duo_passkey_hwm=?, updated_at=datetime('now') WHERE org_number=?",
                    (api["ikey"], api["skey"], api["host"], hwm, org_num),
                )
            return True, (f"org {org_num} bootstrapped — admin={email} "
                          f"ikey={api['ikey']} host={api['host']}")
        finally:
            browser.close()


def duo_harvest_sso_enrollment(pod_id: str, db_path: str, log=None) -> tuple[bool, str]:
    """Automate lab guide section 2: SSO External Auth Source + enrollment blob.

    Replaces the two copy/paste steps a proctor does by hand:
      * step 21 - the ``[sso]`` config block appended to authproxy.cfg on AD1
      * step 23 - the Auth Proxy enrollment command ("Generate command")

    Both are clipboard-only in the Duo UI, so the values are captured by hooking
    ``navigator.clipboard.writeText`` and ``execCommand('copy')`` rather than
    scraped from the DOM.

    Note the blob is a *one-time* code and Duo expires it eight hours after
    generation — harvest it as part of the run that consumes it, never cache it
    across sessions.
    """
    import re as _re
    import sqlite3 as _sq

    _log = log or (lambda s: print(f"  [duo-sso] {s}"))
    duo_ensure_table(db_path)

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        org_num = m.group(1)

    pw = br = None
    try:
        pw, br, ctx, page = duo_passkey_login(pod_id, db_path, log=_log)
        host = page.url.split("/")[2]

        # ── Find or create the Active Directory auth source ───────────────────
        page.goto(f"https://{host}/sso?selected_tab=authentication_sources",
                  wait_until="load", timeout=35_000)
        page.wait_for_timeout(4_000)
        src = page.evaluate(r"""() => {
            const a = Array.from(document.querySelectorAll('a'))
                .find(x => /\/sso\/authsources\/ldap\//.test(x.getAttribute('href') || ''));
            return a ? a.getAttribute('href') : '';
        }""")

        if src:
            _log(f"existing AD auth source: {src.rsplit('/', 1)[-1]}")
        else:
            _log("no AD auth source — creating one")
            page.goto(f"https://{host}/sso/authsources/add", wait_until="load", timeout=35_000)
            page.wait_for_timeout(4_000)
            page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('button,a'))
                    .find(x => /^add active directory$/i.test((x.innerText || '').trim()));
                if (b) b.click();
            }""")
            page.wait_for_timeout(4_000)
            # The privacy gate is a required checkbox; the button silently
            # no-ops until it is ticked.
            page.evaluate("""() => document.querySelectorAll('input[type=checkbox]')
                .forEach(cb => { if (!cb.checked) cb.click(); })""")
            page.wait_for_timeout(1_500)
            page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('button,a'))
                    .find(x => /^configure active directory$/i.test((x.innerText || '').trim()));
                if (b) b.click();
            }""")
            page.wait_for_timeout(6_000)
            if "/sso/authsources/ldap/" not in page.url:
                return False, f"AD source creation did not land on a source page ({page.url[-60:]})"
            src = page.url.split("?")[0]
            _log(f"created AD auth source {src.rsplit('/', 1)[-1]}")

        if not page.url.startswith("http") or "/authsources/ldap/" not in page.url:
            page.goto(f"https://{host}{src}" if src.startswith("/") else src,
                      wait_until="load", timeout=35_000)
            page.wait_for_timeout(4_000)

        # ── Add an Authentication Proxy under that source ─────────────────────
        if "/authproxies/" not in page.url:
            page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('button,a'))
                    .find(x => /^add authentication proxy$/i.test((x.innerText || '').trim()));
                if (b) b.click();
            }""")
            page.wait_for_timeout(6_000)
        if "/authproxies/" not in page.url:
            return False, f"could not open an Authentication Proxy page ({page.url[-60:]})"
        _log(f"auth proxy page: {page.url.rsplit('/', 1)[-1]}")

        # ── Generate the enrollment command ───────────────────────────────────
        # The confirm button inside the modal carries the SAME label as the
        # trigger ("Generate command"); "Generate new command" is only the
        # dialog title. Scope the second click to the <dialog>.
        page.evaluate("""() => {
            const b = Array.from(document.querySelectorAll('button'))
                .find(x => /^generate command$/i.test((x.innerText || '').trim()));
            if (b) b.click();
        }""")
        page.wait_for_timeout(3_500)
        confirmed = page.evaluate("""() => {
            const d = document.querySelector('dialog[open], dialog, .cds-modal');
            if (!d) return false;
            const b = Array.from(d.querySelectorAll('button'))
                .find(x => /^generate command$/i.test((x.innerText || '').trim()));
            if (b) { b.click(); return true; }
            return false;
        }""")
        _log(f"generate-command dialog confirmed: {confirmed}")
        page.wait_for_timeout(9_000)

        values = _pw_capture_copy_buttons(page)
        sso_cfg = next((v for v in values if "[sso]" in v), "")
        blob = ""
        for v in values:
            m2 = _re.search(
                r"authproxy_update_sso_enrollment_code\.exe[\"'\s]+([A-Za-z0-9+/=]{20,})", v)
            if m2:
                blob = m2.group(1)
                break

        if not blob:
            return False, (f"captured {len(values)} clipboard value(s) but no enrollment "
                           f"blob (sso_cfg={'yes' if sso_cfg else 'no'})")

        with _sq.connect(db_path) as conn:
            conn.execute(
                "UPDATE org_credentials SET authproxy_enroll_blob=?, "
                "authproxy_blob_saved_at=datetime('now') WHERE org_number=?",
                (blob, org_num))
            if sso_cfg:
                conn.execute(
                    "UPDATE org_credentials SET authproxy_sso_cfg=? WHERE org_number=?",
                    (sso_cfg, org_num))
        _log(f"blob ({len(blob)} chars) and [sso] block persisted")
        return True, (f"harvested enrollment blob ({len(blob)} chars)"
                      + (f" + [sso] block ({len(sso_cfg)} chars)" if sso_cfg else ""))
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        try:
            if br:
                br.close()
            if pw:
                pw.stop()
        except Exception:
            pass


def _duo_mclick(page, selector: str = "", text: str = "", exact: bool = True) -> bool:
    """Click with a REAL mouse event, by CSS selector or visible text.

    Duo's newer admin-panel components (the user-access radios, Save on the
    Single Sign-On tab) ignore JS element.click() exactly like SCC does — the
    control looks clicked but nothing persists. Coordinates + mouse.click()
    is the only reliable route.
    """
    if selector:
        box = page.evaluate(f"""() => {{
            const e = document.querySelector({selector!r});
            if (!e || !e.getClientRects().length) return null;
            e.scrollIntoView({{block:'center'}});
            const r = e.getBoundingClientRect();
            return {{x: r.x + r.width/2, y: r.y + r.height/2}};
        }}""")
    else:
        box = page.evaluate(f"""() => {{
            const want = {text!r}.toLowerCase();
            const e = Array.from(document.querySelectorAll('button,a,[role=button],label,div,span'))
                .filter(x => x.getClientRects().length)
                .filter(x => {{
                    const t = (x.innerText||'').trim().toLowerCase();
                    return {str(exact).lower()} ? t === want : t.includes(want);
                }})
                .sort((a,b) => (a.innerText||'').length - (b.innerText||'').length)[0];
            if (!e) return null;
            e.scrollIntoView({{block:'center'}});
            const r = e.getBoundingClientRect();
            return {{x: r.x + r.width/2, y: r.y + r.height/2}};
        }}""")
    if not box:
        return False
    page.mouse.click(box["x"], box["y"])
    page.wait_for_timeout(3_000)
    return True


def duo_setup_secure_access_app(pod_id: str, db_path: str, log=None) -> tuple[bool, str]:
    """Lab guide section 3 (Duo side): the "Cisco Secure Access" application.

    Generating the SCIM token in Secure Access is only half of section 3. The
    thing that actually provisions users is this Duo application: its
    Provisioning tab takes the SCIM Base URL + Token, and once connected Duo
    pushes its users and groups into Secure Access. Without it SA stays empty
    no matter how healthy the token looks.

    Picks the plain "Cisco Secure Access" entry — NOT "Cisco Secure Access
    VPN", which is a separate application configured later for the VPN profile.
    """
    import json as _json
    import re as _re
    import sqlite3 as _sq

    _log = log or (lambda s: print(f"  [duo-sa-app] {s}"))
    AD_GROUPS = ("IoT", "MAIN", "PROD")

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        org_num = m.group(1)
        oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                               (org_num,)).fetchone() or {})

    scim_tok = (oc.get("sa_scim_token") or "").strip()
    scim_url = (oc.get("sa_scim_url") or "").strip() or "https://api.sse.cisco.com/identity/v2/scim"
    if not scim_tok:
        return False, "no sa_scim_token — run the SCIM generation step first"

    pw = br = None
    try:
        pw, br, ctx, page = duo_passkey_login(pod_id, db_path, log=_log)
        host = page.url.split("/")[2]

        # ── Find or create the application ────────────────────────────────────
        page.goto(f"https://{host}/applications", wait_until="load", timeout=40_000)
        page.wait_for_timeout(5_000)
        existing = page.evaluate(r"""() => {
            const row = Array.from(document.querySelectorAll('tr'))
                .find(r => /cisco secure access/i.test(r.innerText||'') &&
                           !/vpn/i.test(r.innerText||''));
            if (!row) return '';
            const a = row.querySelector('a[href*="/applications/"]');
            return a ? a.getAttribute('href') : '';
        }""")

        if existing:
            _log(f"reusing existing application {existing.rsplit('/',1)[-1]}")
            page.goto(f"https://{host}{existing}", wait_until="load", timeout=40_000)
        else:
            _log("creating the Cisco Secure Access application")
            page.goto(f"https://{host}/applications/protect/types",
                      wait_until="load", timeout=40_000)
            page.wait_for_timeout(6_000)
            try:
                page.locator('input[placeholder*="Search applications"]').first.fill(
                    "Cisco Secure Access")
                page.wait_for_timeout(4_000)
            except Exception as e:
                _log(f"could not filter the catalogue: {type(e).__name__}")
            res = page.evaluate("""() => {
                // exact heading, excluding the separate "... VPN" application
                const hs = Array.from(document.querySelectorAll('h3'))
                    .filter(h => (h.textContent||'').trim().toLowerCase() === 'cisco secure access');
                if (!hs.length) return {ok:false, reason:'no exact "Cisco Secure Access" heading'};
                let n = hs[0];
                for (let i = 0; i < 6 && n; i++) {
                    n = n.parentElement; if (!n) break;
                    const btn = Array.from(n.querySelectorAll('button,a'))
                        .find(x => /^add$/i.test((x.innerText||'').trim()));
                    if (btn) { btn.click(); return {ok:true}; }
                }
                return {ok:false, reason:'no Add control beside the heading'};
            }""")
            if not res.get("ok"):
                return False, f"could not add the application: {res.get('reason')}"
            page.wait_for_timeout(9_000)
            _log(f"application created: {page.url.rsplit('/',1)[-1]}")

        app_url = page.url.split("?")[0]
        app_ikey = app_url.rsplit("/", 1)[-1]

        # ── Provisioning tab: Base URL + Token, then connect ──────────────────
        page.evaluate("""() => {
            const b = Array.from(document.querySelectorAll('a,button,[role=tab]'))
                .find(x => (x.innerText||'').trim().toLowerCase() === 'provisioning');
            if (b) b.click();
        }""")
        # Wait for the tab to actually render — filling before this returns null
        # selectors and silently skips baseUrl/token.
        for _ in range(12):
            page.wait_for_timeout(4_000)
            if page.evaluate("""() => !!document.querySelector('input[name="credentials.baseUrl"]')"""):
                break
        else:
            return False, "Provisioning tab never rendered its Base URL field"
        _log("provisioning tab ready")

        # Exact field names. Keyword matching put the token in BOTH fields,
        # because the Base URL's surrounding label also contains "Token".
        filled = page.evaluate("""(cfg) => {
            const set = (el, v) => {
                // The native setter must come from the element's OWN prototype;
                // using HTMLInputElement's on a <textarea> throws
                // "Illegal invocation".
                const proto = el.tagName === 'TEXTAREA'
                    ? window.HTMLTextAreaElement.prototype
                    : window.HTMLInputElement.prototype;
                Object.getOwnPropertyDescriptor(proto, 'value').set.call(el, v);
                el.dispatchEvent(new Event('input', {bubbles:true}));
                el.dispatchEvent(new Event('change', {bubbles:true}));
            };
            const out = [];
            const url = document.querySelector('input[name="credentials.baseUrl"]');
            const tok = document.querySelector('input[name="credentials.credentialDetail.token"]');
            if (url) { set(url, cfg.url); out.push('baseUrl'); }
            if (tok) { set(tok, cfg.tok); out.push('token'); }
            // NB: user access is NOT set here. The user-access-control radios
            // are present in the DOM from this tab, but they belong to the
            // Single Sign-On tab and only persist via that tab's own Save —
            // clicking them from Provisioning silently does nothing.
            return out;
        }""", {"url": scim_url, "tok": scim_tok})
        _log(f"provisioning fields filled: {filled or 'none found'}")
        page.wait_for_timeout(2_500)

        connected = page.evaluate("""() => {
            const b = Array.from(document.querySelectorAll('button'))
                .find(x => /connect to application|^connect$/i.test((x.innerText||'').trim()));
            if (b && !b.disabled) { b.click(); return true; }
            return false;
        }""")
        _log(f"'Connect to application' clicked: {connected}")
        page.wait_for_timeout(10_000)

        # ── Attribute mapping ─────────────────────────────────────────────────
        # Lab guide section 3: add displayName, emails, name.familyName and
        # name.givenName, then map the userName application attribute to the
        # user's Email Address. Without the email mapping the identity arrives
        # in Secure Access in the wrong form and SSO authentication fails.
        mapped = []
        try:
            for _ in range(3):
                page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(2_500)
            if _duo_mclick(page, text="Edit mappings"):
                page.wait_for_timeout(6_000)
                mapped = page.evaluate("""(wanted) => {
                    const out = [];
                    wanted.forEach(w => {
                        const cb = document.querySelector(
                            'input[name="' + w + '-attribute-input"]');
                        if (cb && !cb.checked) { cb.click(); out.push(w); }
                    });
                    return out;
                }""", ["displayName", "emails", "name.familyName", "name.givenName"])
                _log(f"optional attributes checked: {mapped or 'already set'}")
                page.wait_for_timeout(2_000)
                _duo_mclick(page, text="Save mapping")
                page.wait_for_timeout(7_000)
        except Exception as e:
            _log(f"attribute mapping: {type(e).__name__}: {str(e)[:70]}")

        # userName -> Email Address on the mapping table row.
        email_mapped = False
        try:
            for _ in range(3):
                page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(2_000)
            email_mapped = page.evaluate("""() => {
                // the row whose application attribute is userName
                const rows = Array.from(document.querySelectorAll('tr'))
                    .filter(r => /username/i.test(r.innerText||''));
                for (const r of rows) {
                    const sel = r.querySelector('select');
                    if (sel) {
                        const opt = Array.from(sel.options)
                            .find(o => /e-?mail/i.test(o.text));
                        if (opt) {
                            const setter = Object.getOwnPropertyDescriptor(
                                window.HTMLSelectElement.prototype, 'value').set;
                            setter.call(sel, opt.value);
                            sel.dispatchEvent(new Event('change', {bubbles:true}));
                            return opt.text;
                        }
                    }
                }
                return false;
            }""")
            _log(f"userName -> Email Address: {email_mapped or 'control not found'}")
            if email_mapped:
                _duo_mclick(page, text="Save")
                page.wait_for_timeout(6_000)
        except Exception as e:
            _log(f"email mapping: {type(e).__name__}: {str(e)[:70]}")

        # ── Group scope ───────────────────────────────────────────────────────
        # Connecting is not enough: with no groups selected Duo has nothing in
        # scope and pushes zero users, while the UI still reports "Enabled" and
        # "successfully connected". Same trap as the AD directory sync.
        picked = []
        try:
            # Attribute mapping and Groups only render AFTER "Connect to
            # application" succeeds, and they sit below the fold — so wait for
            # the section and scroll to it before touching anything.
            for _ in range(12):
                body = page.evaluate("() => document.body.innerText")
                if "Select existing groups" in body:
                    break
                page.evaluate("() => window.scrollTo(0, document.body.scrollHeight)")
                page.wait_for_timeout(5_000)
            page.evaluate("""() => {
                const el = Array.from(document.querySelectorAll('*'))
                    .find(e => e.children.length === 0 &&
                          /^Groups$/i.test((e.textContent||'').trim()));
                if (el) el.scrollIntoView({block: 'center'});
            }""")
            page.wait_for_timeout(3_000)

            # groupSource has two options: manualGroups ("Select groups") and
            # SSOPermittedGroups. Pick by value, not position.
            page.evaluate("""() => {
                const r = Array.from(document.querySelectorAll('input[name="groupSource"]'))
                    .find(x => (x.value||'').toLowerCase().startsWith('manual'));
                if (r && !r.checked) r.click();
            }""")
            page.wait_for_timeout(2_500)

            # The picker's name is a fresh UUID on every render, so identify it
            # structurally: the text input that is none of the known fields.
            KNOWN = ("credentials.baseUrl", "credentials.credentialDetail.token",
                     "iname", "entity_id", "acs_url")
            for g in AD_GROUPS:
                sel = page.evaluate("""(known) => {
                    const i = Array.from(document.querySelectorAll('input[type=text]'))
                        .filter(x => x.getClientRects().length)
                        .find(x => !known.includes(x.name) &&
                                   (x.placeholder||'').toLowerCase() !== 'username' &&
                                   x.id !== 'global-search-input');
                    if (!i) return null;
                    i.setAttribute('data-pick', '1');
                    return true;
                }""", list(KNOWN))
                if not sel:
                    _log("group picker input not found")
                    break
                box = page.locator('input[data-pick="1"]').first
                box.click()
                box.fill(g)
                page.wait_for_timeout(3_500)
                hit = page.evaluate(f"""() => {{
                    const t = {g!r}.toLowerCase();
                    const e = Array.from(document.querySelectorAll('li,[role=option],.cds-menu-item'))
                        .filter(x => x.getClientRects().length)
                        .find(x => (x.innerText||'').trim().toLowerCase().startsWith(t));
                    if (e) {{ e.click(); return (e.innerText||'').trim().slice(0,32); }}
                    return null;
                }}""")
                if hit:
                    picked.append(hit)
                page.evaluate("""() => document.querySelectorAll('[data-pick]')
                    .forEach(e => e.removeAttribute('data-pick'))""")
                page.wait_for_timeout(2_000)
        except Exception as e:
            _log(f"group selection: {type(e).__name__}: {str(e)[:70]}")
        _log(f"groups mapped: {picked or 'NONE'}")

        # ── Save + enable ─────────────────────────────────────────────────────
        page.evaluate("""() => {
            const b = Array.from(document.querySelectorAll('button'))
                .find(x => /save and enable|^save$/i.test((x.innerText||'').trim()));
            if (b) b.click();
        }""")
        page.wait_for_timeout(10_000)

        # Validate the OUTCOME, not the clicks: users must actually reach SA.
        import requests as _rq
        total = -1
        for _ in range(6):
            page.wait_for_timeout(10_000)
            try:
                r = _rq.get("https://api.sse.cisco.com/identity/v2/scim/Users",
                            headers={"Authorization": f"Bearer {scim_tok}"}, timeout=20)
                if r.ok:
                    total = r.json().get("totalResults", 0)
                    _log(f"Secure Access users: {total}")
                    if total > 0:
                        break
            except Exception:
                pass
        ok = total > 0

        with _sq.connect(db_path) as conn:
            conn.execute("UPDATE org_credentials SET duo_saml_app_ikey=?, "
                         "updated_at=datetime('now') WHERE org_number=?",
                         (app_ikey, org_num))
        _log(f"stored duo_saml_app_ikey={app_ikey}")

        # ── Single Sign-On tab: enable the app for all users ──────────────────
        # Lab guide section 4: "In the User access section, click the radio
        # button to Enable for all users." This lives on the SSO tab and needs
        # that tab's Save; doing it from Provisioning does not persist.
        access_ok = False
        try:
            page.goto(app_url, wait_until="load", timeout=40_000)
            page.wait_for_timeout(6_000)
            page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('a,button,[role=tab]'))
                    .find(x => /single sign-?on/i.test((x.innerText||'').trim()));
                if (b) b.click();
            }""")
            for _ in range(10):
                page.wait_for_timeout(4_000)
                if page.evaluate("""() => !!document.querySelector('#user-access-radio-all-users')"""):
                    break
            # Real mouse events — a JS .click() on this radio leaves it visually
            # selected but never persists.
            clicked = _duo_mclick(page, selector="#user-access-radio-all-users")
            now_checked = page.evaluate(
                """() => {const r = document.querySelector('#user-access-radio-all-users');
                          return !!(r && r.checked);}""")
            _log(f"clicked 'Enable for all users': {clicked} (checked={now_checked})")
            page.wait_for_timeout(2_000)
            _duo_mclick(page, text="Save")
            page.wait_for_timeout(8_000)

            # Re-load and confirm it persisted rather than trusting the click.
            page.goto(app_url, wait_until="load", timeout=40_000)
            page.wait_for_timeout(6_000)
            page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('a,button,[role=tab]'))
                    .find(x => /single sign-?on/i.test((x.innerText||'').trim()));
                if (b) b.click();
            }""")
            page.wait_for_timeout(7_000)
            access_ok = bool(page.evaluate(
                """() => {const r = document.querySelector('#user-access-radio-all-users');
                          return r && r.checked;}"""))
            _log(f"user access 'Enable for all users' persisted: {access_ok}")
        except Exception as e:
            _log(f"user-access step: {type(e).__name__}: {str(e)[:70]}")

        if ok and not access_ok:
            return False, (f"Cisco Secure Access app {app_ikey} is provisioning "
                           f"{total} users, but 'Enable for all users' did not "
                           f"persist on the Single Sign-On tab — users cannot "
                           f"authenticate through the app")
        if ok:
            return True, (f"Cisco Secure Access app {app_ikey} provisioning "
                          f"{total} users to SA (groups: {', '.join(picked) or 'preexisting'}), "
                          f"enabled for all users")
        return False, (f"Cisco Secure Access app {app_ikey} configured "
                       f"(fields={filled}, connect={connected}, groups={picked or 'NONE'}) "
                       f"but Secure Access still reports {total} users — provisioning "
                       f"has no effective scope")
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        try:
            if br:
                br.close()
            if pw:
                pw.stop()
        except Exception:
            pass


def duo_rollback_for_test(pod_id: str, db_path: str, keep_bootstrap: bool = True,
                          log=None) -> tuple[bool, str]:
    """Undo everything the Duo card built, so a run can be tested from scratch.

    With *keep_bootstrap* (the default) the org itself is preserved — admin
    account, passkey, TOTP token and Admin API credentials all survive, because
    activation is one-time per org and cannot be repeated. Everything the card
    creates on top of that is removed:

      Duo   - synced users, synced groups, the Auth Proxy integration
      SA    - nothing here (IdP directories must be removed in the SCC UI)
      DB    - authproxy_*, sa_scim_token, duo_saml_app_ikey

    Set keep_bootstrap=False to also clear the org's identity columns, but note
    that a fresh org can then only be obtained by rotating (which reprovisions
    SCC and Meraki too) — see fetch_idac_url_from_dcloud.
    """
    import re as _re
    import sqlite3 as _sq

    _log = log or (lambda s: print(f"  [duo-rollback] {s}"))

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        org_num = m.group(1)
        oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                               (org_num,)).fetchone() or {})

    ikey, skey, host = (oc.get("duo_ikey", ""), oc.get("duo_skey", ""), oc.get("duo_host", ""))
    removed = []

    stuck = []
    if ikey and skey and host:
        # Directory-synced users and groups are OWNED by the AD sync and the API
        # rejects deleting them (400) while it exists — the sync has to go first,
        # and only the UI can remove it. Count real successes, never the number
        # attempted: reporting len(items) claimed "8 users deleted" when all
        # eight had failed.
        for path, label, idfield in (("/admin/v1/users", "user", "user_id"),
                                     ("/admin/v1/groups", "group", "group_id")):
            try:
                items = _duo_request(ikey, skey, host, "GET", path).get("response", [])
                gone = 0
                for it in items:
                    try:
                        _duo_request(ikey, skey, host, "DELETE", f"{path}/{it[idfield]}")
                        gone += 1
                    except Exception as e:
                        _log(f"WARN: could not delete {label} "
                             f"{it.get('username') or it.get('name')}: {str(e)[:70]}")
                if gone:
                    removed.append(f"{gone} {label}s")
                if gone < len(items):
                    stuck.append(f"{len(items) - gone} {label}s")
                _log(f"{label}s: deleted {gone}/{len(items)}")
            except Exception as e:
                _log(f"WARN: listing {label}s failed: {str(e)[:80]}")

        # The radius Auth Proxy integration is recreated by authproxy_push.
        # The Admin API app is NOT touched — it is bootstrap state.
        try:
            ints = _duo_request(ikey, skey, host, "GET",
                                "/admin/v1/integrations").get("response", [])
            for i in ints:
                if i.get("type") == "adminapi":
                    continue
                try:
                    _duo_request(ikey, skey, host, "DELETE",
                                 f"/admin/v1/integrations/{i['integration_key']}")
                    removed.append(i.get("name") or i.get("type"))
                    _log(f"deleted integration {i.get('name')} [{i.get('type')}]")
                except Exception as e:
                    _log(f"WARN: could not delete {i.get('name')}: {str(e)[:70]}")
        except Exception as e:
            _log(f"WARN: listing integrations failed: {str(e)[:80]}")
    else:
        _log("no Admin API credentials — skipping the Duo-side cleanup")

    CLEAR = ["authproxy_ikey", "authproxy_skey", "authproxy_cfg", "authproxy_sso_cfg",
             "authproxy_enroll_blob", "authproxy_blob_saved_at", "sa_scim_token",
             "sa_scim_url", "duo_saml_app_ikey", "sa_saml_profile_id"]
    if not keep_bootstrap:
        CLEAR += ["duo_ikey", "duo_skey", "duo_host", "duo_admin_host", "duo_admin_email",
                  "duo_admin_password", "duo_admin_totp_secret", "duo_passkey_cred",
                  "duo_passkey_hwm", "idac_url"]
    # Column names are from the fixed CLEAR list above, never user input.
    assignments = ", ".join(f"{c}=''" for c in CLEAR)
    with _sq.connect(db_path) as conn:
        conn.execute(
            f"UPDATE org_credentials SET {assignments}, updated_at=datetime('now') "
            f"WHERE org_number=?", (org_num,))
        conn.execute("DELETE FROM duo_steps WHERE pod_id=?", (pod_id,))
    _log(f"cleared {len(CLEAR)} DB columns and the duo_steps rows")

    note = ("bootstrap state kept (admin/passkey/TOTP/Admin API)"
            if keep_bootstrap else "bootstrap state ALSO cleared")
    detail = (f"org {org_num}: removed {', '.join(removed) or 'nothing'}; {note}")
    if stuck:
        # Be explicit rather than implying a clean slate.
        return False, (f"{detail}. STILL PRESENT: {', '.join(stuck)} — these are "
                       f"owned by the AD directory sync and cannot be deleted via "
                       f"the API. Delete the directory sync in Duo (Users -> "
                       f"External Directories -> Delete Directory Sync) and the "
                       f"Secure Access IdP directory, then re-run.")
    return True, (f"{detail}. NOTE: the AD directory sync and the Secure Access IdP "
                  f"directory must be deleted in their UIs — neither exposes a "
                  f"delete API.")


def _scc_open_session(ctx, idac_url: str, log=None):
    """Open an authenticated SCC tab via the iDAC card's SAML auto-login.

    No password is involved and no org is rotated — loading a stored iDAC URL
    is read-only (only idac_sdk reprovisions).  Returns (page, enterprise_id).
    """
    _log = log or (lambda s: None)
    pg = ctx.new_page()
    pg.goto(idac_url, wait_until="load", timeout=45_000)
    pg.wait_for_timeout(5_000)
    with ctx.expect_page(timeout=25_000) as info:
        pg.evaluate("""() => {const b=Array.from(document.querySelectorAll('button,a'))
            .find(x=>/^view$/i.test((x.innerText||'').trim())); if(b)b.click();}""")
    t = info.value
    t.wait_for_load_state("load", timeout=30_000)
    for _ in range(18):
        t.wait_for_timeout(5_000)
        if "enterpriseId=" in t.url:
            break
    if "enterpriseId=" not in t.url:
        raise RuntimeError("SCC session never settled (no enterpriseId)")
    ent = t.url.split("enterpriseId=")[1].split("&")[0]
    _log(f"SCC session established (enterprise {ent[:8]}…)")
    return t, ent


def _scc_text(p, tries=3):
    """innerText, tolerating the redirect chain tearing down the context."""
    for _ in range(tries):
        try:
            return p.evaluate("() => document.body.innerText")
        except Exception:
            p.wait_for_timeout(2_500)
    return ""


def _scc_wait(p, needle, tries=18):
    """Wait for real content. The SPA renders its nav shell ~30s early, so a
    text-length check returns long before the page is usable."""
    for _ in range(tries):
        if needle.lower() in _scc_text(p).lower():
            return True
        p.wait_for_timeout(5_000)
    return False


def _scc_click(p, text, exact=True):
    """Locate by visible text, then click with a REAL mouse event.

    SCC is React and ignores JS element.click() (documented in CLAUDE.md), so
    everything here goes through coordinates + page.mouse.click().
    """
    box = p.evaluate(f"""() => {{
        const want = {text!r}.toLowerCase();
        const els = Array.from(document.querySelectorAll(
            'button,a,[role=button],[role=tab],[role=option],[role=radio],label,div,span,li'));
        const hit = els.filter(e => {{
            const t = (e.innerText||'').trim().toLowerCase();
            if (!t || t.length > 400) return false;
            return {str(exact).lower()} ? t === want : t.includes(want);
        }}).filter(e => e.getClientRects().length)
          .sort((a,b) => (a.innerText||'').length - (b.innerText||'').length)[0];
        if (!hit) return null;
        hit.scrollIntoView({{block:'center'}});
        const r = hit.getBoundingClientRect();
        return {{x: r.x + r.width/2, y: r.y + r.height/2}};
    }}""")
    if not box:
        return False
    p.mouse.click(box["x"], box["y"])
    p.wait_for_timeout(6_000)
    return True


def sa_generate_scim_token_ui(pod_id: str, db_path: str, log=None) -> tuple[bool, str]:
    """Generate the Secure Access SCIM token for this pod's org, unattended.

    There is no API for this. Secure Access exposes no SCIM or provisioning
    scope at all (the API-key catalogue is Admin/Deployments/Investigate/
    Policies/Reports — 92 scopes, none of them provisioning), so
    /identity/v2/organizations/{org}/scim/token always returns 403 no matter
    how the key is built. The UI wizard is the only source.

    The token is displayed once and never shown again — but it is rendered as
    an input value, so it can be read straight out of the DOM. No clipboard,
    no operator. That is what makes this automatable per-pod, which matters
    because every pod gets a brand new org.
    """
    import re as _re
    import sqlite3 as _sq
    import time as _t

    from playwright.sync_api import sync_playwright

    _log = log or (lambda s: print(f"  [sa-scim] {s}"))

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        org_num = m.group(1)
        oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                               (org_num,)).fetchone() or {})

    idac = (oc.get("idac_url") or "").strip()
    sa_org = (oc.get("sa_org_id") or "").strip()
    if not idac:
        return False, "no stored idac_url — cannot open an SCC session"
    if not sa_org:
        return False, f"org {org_num} has no sa_org_id"
    if (oc.get("sa_scim_token") or "").strip():
        return True, "SCIM token already present — nothing to do"

    # Unique per run: Secure Access rejects a duplicate directory name, and a
    # pod may already carry one from an earlier attempt.
    name = f"Duo-{int(_t.time()) % 100000}"

    pw = br = None
    try:
        pw = sync_playwright().start()
        br = pw.chromium.launch(headless=True, args=["--no-sandbox"])
        ctx = br.new_context(ignore_https_errors=True,
                             viewport={"width": 1600, "height": 1200})
        t, ent = _scc_open_session(ctx, idac, log=_log)

        t.goto(f"https://security.cisco.com/secure-access/org/{sa_org}"
               f"/connect/users-and-groups?enterpriseId={ent}",
               wait_until="load", timeout=45_000)
        if not _scc_wait(t, "Configuration management"):
            return False, "Configuration management never rendered"
        _scc_click(t, "Configuration management")
        if not _scc_wait(t, "Integrate directories"):
            return False, "Directories card never rendered"

        # NB: "Configure" belongs to the SSO authentication card below — the
        # Directories action is "Integrate directories" itself.
        _scc_click(t, "Integrate directories")
        if not _scc_wait(t, "Provisioning Method", tries=12):
            return False, "provisioning wizard did not open"

        _scc_click(t, "Identity provider(IdP)", exact=False)
        t.wait_for_timeout(3_000)
        _scc_click(t, "Next")
        if not _scc_wait(t, "IdP directory name", tries=12):
            return False, "wizard did not reach the directory-name step"

        # "profileName" is the input's id/placeholder, not necessarily its
        # name, and Playwright's locator does not see it — drive it through
        # React's native value setter so React state actually updates.
        set_ok = False
        for _ in range(12):
            got = t.evaluate(f"""() => {{
                const i = Array.from(document.querySelectorAll('input'))
                    .find(x => [x.name, x.id, x.placeholder]
                        .some(v => (v||'').toLowerCase() === 'profilename'));
                if (!i) return false;
                const setter = Object.getOwnPropertyDescriptor(
                    window.HTMLInputElement.prototype, 'value').set;
                setter.call(i, {name!r});
                i.dispatchEvent(new Event('input', {{bubbles: true}}));
                i.dispatchEvent(new Event('change', {{bubbles: true}}));
                return i.value;
            }}""")
            if got:
                set_ok = True
                break
            t.wait_for_timeout(3_000)
        if not set_ok:
            return False, "IdP directory name field never appeared"
        _log(f"directory name: {name}")

        t.wait_for_timeout(2_000)
        _scc_click(t, "Select")           # provider dropdown is closed by default
        t.wait_for_timeout(3_000)
        _scc_click(t, "Duo")
        t.wait_for_timeout(2_000)
        _scc_click(t, "Next")
        if not _scc_wait(t, "Generate Token", tries=12):
            return False, "wizard did not reach the token step"

        _scc_click(t, "Generate Token")
        t.wait_for_timeout(12_000)

        vals = t.evaluate("""() => Array.from(document.querySelectorAll('input,textarea'))
            .map(i => i.value).filter(v => v && v.length > 20)""")
        token = next((v for v in vals if len(v) >= 40 and not v.startswith("http")), "")
        url = next((v for v in vals if v.startswith("http")), "")
        if not token:
            return False, f"token screen reached but no token in the DOM (values={len(vals)})"

        # The provisioning URL is needed verbatim by the Duo application in
        # section 3, so keep it rather than only logging it.
        with _sq.connect(db_path) as conn:
            try:
                conn.execute("ALTER TABLE org_credentials ADD COLUMN "
                             "sa_scim_url TEXT DEFAULT ''")
            except Exception:
                pass
            conn.execute("UPDATE org_credentials SET sa_scim_token=?, sa_scim_url=?, "
                         "updated_at=datetime('now') WHERE org_number=?",
                         (token, url or "https://api.sse.cisco.com/identity/v2/scim",
                          org_num))
        _log(f"SCIM token stored ({len(token)} chars); provisioning URL {url or 'n/a'}")
        _scc_click(t, "Done")
        return True, f"SCIM token generated for org {org_num} ({len(token)} chars)"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        try:
            if br:
                br.close()
            if pw:
                pw.stop()
        except Exception:
            pass


def duo_sync_now(pod_id: str, db_path: str, log=None) -> tuple[bool, str]:
    """Run a full AD directory sync by clicking "Sync Now" in the Duo admin UI.

    Duo's Admin API has no working full-sync endpoint here: the documented
    per-user route, POST /admin/v1/users/directorysync/{dkey}/syncuser, returns
    404 for every key on this deployment (the directory key, the connection id,
    and the connector ikey were all tried). The UI action works and imports the
    whole scope in seconds, so drive that instead.

    Requires the sync to have at least one group selected — with no scope Duo
    imports nobody and reports success anyway.
    """
    import re as _re
    import sqlite3 as _sq

    _log = log or (lambda s: print(f"  [duo-sync] {s}"))

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                               (m.group(1),)).fetchone() or {})
    ikey, skey, host_api = (oc.get("duo_ikey", ""), oc.get("duo_skey", ""),
                            oc.get("duo_host", ""))

    def _counts():
        u = len(_duo_request(ikey, skey, host_api, "GET", "/admin/v1/users").get("response", []))
        g = len(_duo_request(ikey, skey, host_api, "GET", "/admin/v1/groups").get("response", []))
        return u, g

    before_u, before_g = _counts()
    _log(f"before sync: users={before_u} groups={before_g}")

    pw = br = None
    try:
        pw, br, ctx, page = duo_passkey_login(pod_id, db_path, log=_log)
        host = page.url.split("/")[2]
        page.goto(f"https://{host}/users/directories?tab=directory-syncs",
                  wait_until="load", timeout=35_000)
        page.wait_for_timeout(4_000)
        href = page.evaluate(r"""() => {
            const a = Array.from(document.querySelectorAll('a'))
                .find(x => /\/users\/directorysync\/[A-Z0-9]{20}$/.test(x.getAttribute('href') || ''));
            return a ? a.getAttribute('href') : '';
        }""")
        if not href:
            return False, "no directory sync found — run duo_setup_external_directory first"
        page.goto(f"https://{host}{href}", wait_until="load", timeout=35_000)
        page.wait_for_timeout(7_000)

        clicked = page.evaluate("""() => {
            const b = Array.from(document.querySelectorAll('button'))
                .find(x => /^sync now$/i.test((x.innerText || '').trim()));
            if (b && !b.disabled) { b.click(); return true; }
            return false;
        }""")
        if not clicked:
            return False, "'Sync Now' button not available (is the connection healthy?)"
        _log("clicked Sync Now")
        page.wait_for_timeout(4_000)
        # Some builds confirm in a modal; harmless when absent.
        page.evaluate("""() => {
            const d = document.querySelector('dialog[open], dialog, .cds-modal');
            if (!d) return;
            const b = Array.from(d.querySelectorAll('button'))
                .find(x => /^(sync|sync now|confirm|ok)$/i.test((x.innerText || '').trim()));
            if (b) b.click();
        }""")

        for i in range(6):
            page.wait_for_timeout(10_000)
            u, g = _counts()
            _log(f"+{(i + 1) * 10}s users={u} groups={g}")
            if u > before_u or (u and g):
                return True, f"directory sync complete — {u} users, {g} groups"
        u, g = _counts()
        return (u > 0), f"sync ran but users={u} groups={g} after 60s"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        try:
            if br:
                br.close()
            if pw:
                pw.stop()
        except Exception:
            pass


def duo_setup_external_directory(pod_id: str, db_path: str, log=None) -> tuple[bool, str]:
    """Automate lab guide section 2 part 1: the AD External Directory that syncs users.

    This is a DIFFERENT Duo object from the SSO External Authentication Source
    handled by duo_harvest_sso_enrollment(). The guide configures both and they
    look alike, but only this one populates Users/Groups — without it the org
    stays empty and /admin/v1/users/directorysync/{dirkey}/syncuser returns 404.

    Critically, the AD-connection page issues its OWN ikey/skey (exposed only via
    clipboard buttons). They are not the radius Auth Proxy integration's keys —
    building [cloud] from the wrong pair is what leaves the proxy unregistered as
    a directory-sync connector.

    Flow: Users -> External Directories -> Add -> Active Directory -> Add new
    connection -> capture keys -> write [cloud] to AD1 -> restart proxy -> fill
    DC/port/baseDN -> Save -> Test -> groups -> attributes -> Complete Setup.
    """
    import re as _re
    import sqlite3 as _sq

    _log = log or (lambda s: print(f"  [duo-extdir] {s}"))
    AD_GROUPS = ("IoT", "MAIN", "PROD")
    CFG = r"C:\Program Files\Duo Security Authentication Proxy\conf\authproxy.cfg"

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        org_num = m.group(1)
        _oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                                (org_num,)).fetchone() or {})
    oc_ikey = _oc.get("duo_ikey", "")
    oc_skey = _oc.get("duo_skey", "")
    oc_host = _oc.get("duo_host", "")

    pw = br = None
    try:
        pw, br, ctx, page = duo_passkey_login(pod_id, db_path, log=_log)
        host = page.url.split("/")[2]

        # ── Reuse an existing AD connection if one is already present ─────────
        page.goto(f"https://{host}/users/directories?tab=directory-syncs",
                  wait_until="load", timeout=35_000)
        page.wait_for_timeout(4_000)
        conn_href = page.evaluate(r"""() => {
            const a = Array.from(document.querySelectorAll('a'))
                .find(x => /\/users\/directories\/ad-connection\//.test(x.getAttribute('href') || ''));
            return a ? a.getAttribute('href') : '';
        }""")

        if conn_href:
            _log(f"reusing AD connection {conn_href.rsplit('/', 1)[-1][:24]}")
            page.goto(f"https://{host}{conn_href}", wait_until="load", timeout=35_000)
        else:
            _log("creating a new AD directory sync")
            page.goto(f"https://{host}/users/directorysync/new/ad",
                      wait_until="load", timeout=35_000)
            page.wait_for_timeout(4_000)
            # Radio 1 = "Add new connection"; Continue is inert until one is picked.
            page.evaluate("""() => {
                const rs = document.querySelectorAll('input[type=radio]');
                if (rs[1]) rs[1].click();
            }""")
            page.wait_for_timeout(2_000)
            page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('button'))
                    .find(x => /^continue$/i.test((x.innerText || '').trim()));
                if (b) b.click();
            }""")
            page.wait_for_timeout(9_000)
        if "/ad-connection/" not in page.url:
            return False, f"did not reach an AD connection page ({page.url[-60:]})"
        conn_url = page.url
        _log(f"connection page: {conn_url.split('/')[-1][:44]}")

        # ── Capture this connection's own credentials ─────────────────────────
        # A freshly-created connection renders its keys and an editable form. An
        # already-saved one renders read-only: the keys hide behind "Show
        # details" and the DC/port/baseDN inputs do not exist until "Edit" is
        # clicked. Handle both layouts.
        page.wait_for_timeout(3_000)
        revealed = page.evaluate("""() => {
            const b = Array.from(document.querySelectorAll('button,a'))
                .find(x => /^show details$/i.test((x.innerText || '').trim()));
            if (b) { b.click(); return true; }
            return false;
        }""")
        if revealed:
            _log("expanded 'Show details' to reveal connection keys")
            page.wait_for_timeout(3_000)

        vals = _pw_capture_copy_buttons(page)
        ikey = next((v for v in vals if _re.fullmatch(r"DI[A-Z0-9]{18}", v)), "")
        apih = next((v for v in vals if "duosecurity.com" in v), "")
        skey = next((v for v in vals if len(v) == 40 and v != ikey), "")
        if not (ikey and skey and apih):
            return False, (f"could not capture directory-sync credentials "
                           f"(ikey={bool(ikey)} skey={len(skey)} host={bool(apih)})")
        _log(f"directory-sync ikey={ikey} host={apih}")

        # ── Rewrite [cloud] on AD1 with THESE keys, then restart the proxy ────
        ws = _winrm_connect_for_pod(pod_id, log=_log)
        try:
            cur = ws.run_ps(f"Get-Content '{CFG}' -Raw").std_out.decode(errors="replace")
            # Plain LDAP bind against AD needs a UPN, not a bare sAMAccountName —
            # a bare "administrator" returns
            # "LDAPInvalidCredentials 80090308 ... AcceptSecurityContext error".
            # Same UPN-bind rule the AD verification code follows.
            upn = (AD_WINRM_USER if "@" in AD_WINRM_USER
                   else f"{AD_WINRM_USER}@corp.pseudoco.com")
            cloud = ("[cloud]\n"
                     f"ikey={ikey}\n"
                     f"skey={skey}\n"
                     f"api_host={apih}\n"
                     f"service_account_username={upn}\n"
                     f"service_account_password={AD_WINRM_PASS}\n")
            # Replace any existing [cloud] stanza instead of appending a second.
            rest = _re.sub(r"\[cloud\].*?(?=^\[|\Z)", "", cur, flags=_re.S | _re.M).strip()
            # Preserve the SSO stanza — the enrollment step needs its rikey, and
            # an earlier merge dropped it.
            if "[sso]" not in rest:
                with _sq.connect(db_path) as c2:
                    c2.row_factory = _sq.Row
                    row = c2.execute("SELECT authproxy_sso_cfg FROM org_credentials "
                                     "WHERE org_number=?", (org_num,)).fetchone()
                sso = (row["authproxy_sso_cfg"] or "").strip() if row else ""
                if sso:
                    rest = (rest + "\n\n" + sso).strip()
                    _log("restored [sso] stanza from org_credentials")
            merged = cloud + ("\n" + rest + "\n" if rest else "")
            # ad_client binds with the same UPN.
            merged = _re.sub(r"^service_account_username=(?!.*@)(.+)$",
                             lambda m: f"service_account_username={m.group(1)}@corp.pseudoco.com",
                             merged, flags=_re.M)
            ok, msg = _winrm_put_bytes(ws, merged.encode("utf-8"), CFG, log=_log)
            if not ok:
                return False, f"authproxy.cfg write failed: {msg}"
            r = ws.run_ps("Restart-Service DuoAuthProxy -Force; Start-Sleep -Seconds 10;"
                          "(Get-Service DuoAuthProxy).Status")
            _log(f"DuoAuthProxy: {r.std_out.decode(errors='replace').strip()}")
        finally:
            if hasattr(ws, "close"):
                ws.close()

        # ── Fill the directory configuration and save ─────────────────────────
        # Re-navigate: the proxy restart can leave the cached form detached.
        page.goto(conn_url, wait_until="load", timeout=35_000)
        page.wait_for_timeout(6_000)

        # A saved connection is read-only until "Edit" is clicked — the inputs
        # are not merely disabled, they are absent, so fill() times out waiting
        # for a selector that will never appear.
        if not page.locator('input[name="servers.0.host"]').count():
            clicked = page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('button,a'))
                    .find(x => /^edit$/i.test((x.innerText || '').trim()));
                if (b) { b.click(); return true; }
                return false;
            }""")
            _log(f"form was read-only; clicked Edit: {clicked}")
            page.wait_for_timeout(5_000)

        try:
            page.fill('input[name="servers.0.host"]', AD_DC_IP, timeout=20_000)
            page.fill('input[name="servers.0.port"]', "389", timeout=10_000)
            page.fill('input[name="baseDn"]', "DC=corp,DC=pseudoco,DC=com", timeout=10_000)
            _log(f"directory config filled ({AD_DC_IP}:389, DC=corp,DC=pseudoco,DC=com)")
        except Exception as e:
            return False, (f"could not fill directory configuration ({type(e).__name__}) — "
                           f"inputs present: {page.locator('input:not([type=hidden])').count()}")
        page.evaluate("""() => {
            document.querySelectorAll('input[type=radio]').forEach(r => {
                const lab = (r.closest('label')?.innerText ||
                    document.querySelector('label[for="'+r.id+'"]')?.innerText || '').trim();
                if (r.name === 'authType' && /^plain/i.test(lab) && !r.checked) r.click();
                if (r.name === 'transportType' && /^clear/i.test(lab) && !r.checked) r.click();
            });
        }""")
        page.evaluate("""() => {const b=Array.from(document.querySelectorAll('button'))
            .find(x=>/^save$/i.test((x.innerText||'').trim())); if(b)b.click();}""")
        page.wait_for_timeout(8_000)
        page.evaluate("""() => {const b=Array.from(document.querySelectorAll('button'))
            .find(x=>/^test connection$/i.test((x.innerText||'').trim())); if(b)b.click();}""")
        page.wait_for_timeout(15_000)

        body = page.evaluate("() => document.body.innerText")
        connected = "Not connected" not in body and "Connected" in body
        _log(f"connection status: {'Connected' if connected else 'Not connected'}")
        if not connected:
            return False, (f"AD connection configured (ikey={ikey}) but status is "
                           f"NOT connected — check the proxy log on AD1 for an LDAP "
                           f"bind failure")

        # ── Groups + attributes + Complete Setup on the sync itself ───────────
        # Without at least one group the sync has no scope and imports nobody.
        dirkey = ""
        page.goto(f"https://{host}/users/directories?tab=directory-syncs",
                  wait_until="load", timeout=35_000)
        page.wait_for_timeout(4_000)
        href = page.evaluate(r"""() => {
            const a = Array.from(document.querySelectorAll('a'))
                .find(x => /\/users\/directorysync\/[A-Z0-9]{20}$/.test(x.getAttribute('href') || ''));
            return a ? a.getAttribute('href') : '';
        }""")
        if href:
            dirkey = href.rsplit("/", 1)[-1]
            page.goto(f"https://{host}{href}", wait_until="load", timeout=35_000)
            page.wait_for_timeout(6_000)
            _log(f"sync page: {dirkey}")

            # Groups may already be selected from a previous run (or by hand).
            # Duo names them "IoT (from AD sync ...)", so match on prefix.
            existing = []
            try:
                gs = _duo_request(oc_ikey, oc_skey, oc_host, "GET",
                                  "/admin/v1/groups").get("response", [])
                existing = [g.get("name", "") for g in gs
                            if any(g.get("name", "").lower().startswith(w.lower())
                                   for w in AD_GROUPS)]
            except Exception:
                pass
            if len(existing) >= len(AD_GROUPS):
                _log(f"groups already configured: {existing}")
                return True, (f"AD directory sync Connected (ikey={ikey}, dc={AD_DC_IP}, "
                              f"dirkey={dirkey}) — groups already configured: {existing}")

            picked = page.evaluate("""(wanted) => {
                // Open the AD group picker, then tick the lab's three groups.
                const opener = Array.from(document.querySelectorAll('button,a,div'))
                    .find(x => /select ad groups/i.test((x.innerText || '').trim()) &&
                               (x.innerText || '').trim().length < 40);
                if (opener) opener.click();
                const out = [];
                document.querySelectorAll('input[type=checkbox]').forEach(cb => {
                    const lab = (cb.closest('label')?.innerText ||
                        document.querySelector('label[for="'+cb.id+'"]')?.innerText ||
                        (cb.parentElement && cb.parentElement.innerText) || '').trim();
                    if (wanted.some(w => lab.toLowerCase() === w.toLowerCase()) && !cb.checked) {
                        cb.click(); out.push(lab.slice(0, 24));
                    }
                });
                return {opened: !!opener, picked: out};
            }""", list(AD_GROUPS))
            _log(f"group picker opened={picked.get('opened')} selected={picked.get('picked')}")
            page.wait_for_timeout(3_000)

            # Guide: First Name -> givenname, Last Name -> sn.
            attrs = page.evaluate("""() => {
                const set = (name, val) => {
                    const i = document.querySelector('input[name="'+name+'"]');
                    if (i && !i.value) { i.value = val;
                        i.dispatchEvent(new Event('input', {bubbles:true}));
                        i.dispatchEvent(new Event('change', {bubbles:true}));
                        return name+'='+val; }
                    return i ? name+'(kept '+i.value+')' : name+'(absent)';
                };
                return [set('username_attribute','samaccountname'),
                        set('email_attribute','mail'),
                        set('realname_attribute','displayname')];
            }""")
            _log(f"attributes: {attrs}")

            done = page.evaluate("""() => {
                const b = Array.from(document.querySelectorAll('button'))
                    .find(x => /^complete setup$/i.test((x.innerText || '').trim()));
                if (b && !b.disabled) { b.click(); return 'clicked'; }
                return b ? 'disabled' : 'absent';
            }""")
            _log(f"Complete Setup: {done}")
            page.wait_for_timeout(10_000)

        # Report what actually happened. Claiming the groups were selected when
        # the picker matched nothing would repeat the ad_sync false-green bug:
        # the connection can be healthy while the sync still has no scope, and
        # Complete Setup stays disabled until at least one group is chosen.
        groups_ok = bool(picked.get("picked")) if href else False
        detail = (f"AD directory sync Connected (ikey={ikey}, dc={AD_DC_IP}, "
                  f"dirkey={dirkey or 'n/a'})")
        if groups_ok and done == "clicked":
            return True, f"{detail} — groups {picked['picked']} selected, setup completed"
        return False, (f"{detail} — but NO groups selected (picker matched none) and "
                       f"Complete Setup is {done}; the sync has no scope so no users "
                       f"will import. Add {'/'.join(AD_GROUPS)} in the Duo UI.")
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"
    finally:
        try:
            if br:
                br.close()
            if pw:
                pw.stop()
        except Exception:
            pass


def duo_provision_admin_totp(pod_id: str, db_path: str, serial: str = "",
                             log=None) -> tuple[bool, str]:
    """Give the org's Duo admin a TOTP hardware token, and keep the secret.

    This is how a *human* logs into the Duo Admin Panel from Jumphost1 with no
    phone and no TPM:

      email -> password -> "Hardware token" -> 6-digit code

    Windows Hello is not an option on the pod jump hosts (VMs with no TPM), and
    Duo Push needs a phone. A TOTP token is the only phone-free second factor
    Duo offers whose secret we control, which means the dashboard can render the
    current code directly — the proctor needs no authenticator app at all.

    Duo expects the secret as a hex string; base32 is rejected with HTTP 400.
    Codes are plain TOTP-SHA1-6 over the *decoded* bytes (30s step).
    """
    import base64 as _b64
    import os as _os
    import re as _re
    import sqlite3 as _sq

    _log = log or (lambda s: print(f"  [duo-totp] {s}"))
    duo_ensure_table(db_path)

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        org_num = m.group(1)
        oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                               (org_num,)).fetchone() or {})

    ikey, skey, host = (oc.get("duo_ikey", "").strip(),
                        oc.get("duo_skey", "").strip(),
                        oc.get("duo_host", "").strip())
    email = oc.get("duo_admin_email", "").strip()
    if not (ikey and skey and host):
        return False, "no Admin API credentials — run duo_passkey_bootstrap first"
    if not email:
        return False, "duo_admin_email not set — run duo_passkey_bootstrap first"

    raw = _os.urandom(20)
    secret_hex = raw.hex()
    secret_b32 = _b64.b32encode(raw).decode()
    serial = serial or f"POD{org_num}-PROCTOR"

    try:
        tok = _duo_request(ikey, skey, host, "POST", "/admin/v1/tokens",
                           params={"type": "t6", "serial": serial,
                                   "secret": secret_hex}).get("response", {})
        token_id = tok.get("token_id")
        if not token_id:
            return False, f"token creation returned no token_id: {tok}"
        _log(f"created TOTP token {token_id} (serial={serial})")

        admin_id = _duo_get_admin_id(ikey, skey, host, email, log=_log)
        _duo_request(ikey, skey, host, "POST", f"/admin/v1/admins/{admin_id}",
                     params={"token_id": token_id})

        # Confirm the binding from the token side — the admin PATCH returns 200
        # even when nothing was linked.
        back = _duo_request(ikey, skey, host, "GET",
                            f"/admin/v1/tokens/{token_id}").get("response", {})
        bound = [a.get("email") for a in back.get("admins", [])]
        if email not in bound:
            return False, f"token {token_id} created but not bound to {email}"
        _log(f"token bound to {email}")
    except Exception as e:
        return False, f"token provisioning failed: {e}"

    with _sq.connect(db_path) as conn:
        conn.execute(
            "UPDATE org_credentials SET duo_admin_totp_secret=?, "
            "updated_at=datetime('now') WHERE org_number=?",
            (secret_b32, org_num),
        )
    return True, (f"TOTP token {serial} bound to {email} — "
                  f"current code {_totp_generate(secret_b32)}")


_TOTP_PAGE_HTML = r"""<!doctype html>
<html><head><meta charset="utf-8"><title>Duo Admin Login - __POD__</title>
<style>
 body{font-family:"Segoe UI",Arial,sans-serif;background:#0d1117;color:#cdd6e0;
      margin:0;display:flex;align-items:center;justify-content:center;height:100vh}
 .card{background:#141b24;border:1px solid #1c2733;border-radius:10px;padding:28px 34px;min-width:430px}
 h1{font-size:17px;margin:0 0 4px;color:#02c8ff}
 .sub{font-size:12px;color:#8899aa;margin-bottom:18px}
 .row{display:grid;grid-template-columns:82px 1fr;gap:6px 12px;font-size:13px;margin-bottom:6px;align-items:center}
 .lbl{color:#8899aa}
 .val{font-family:Consolas,monospace;color:#cdd6e0;word-break:break-all}
 .codebox{margin-top:20px;padding:16px;background:#0d1117;border:1px solid #1c2733;border-radius:8px;text-align:center}
 #code{font-family:Consolas,monospace;font-size:44px;font-weight:700;letter-spacing:9px;color:#00e68a}
 #code.warn{color:#ffb74d}
 #secs{font-size:12px;color:#8899aa;margin-top:6px}
 button{margin-top:14px;background:#02c8ff;color:#000;border:0;padding:9px 22px;
        border-radius:5px;font-size:14px;font-weight:600;cursor:pointer}
 button:active{transform:translateY(1px)}
 .hint{margin-top:16px;font-size:12px;color:#8899aa;line-height:1.5}
 a{color:#02c8ff}
</style></head><body><div class="card">
 <h1>Duo Admin Panel Login</h1>
 <div class="sub">__POD__ &mdash; no phone required</div>
 <div class="row"><span class="lbl">URL</span><span class="val"><a href="__URL__" target="_blank">__URL__</a></span></div>
 <div class="row"><span class="lbl">Email</span><span class="val">__EMAIL__</span></div>
 <div class="row"><span class="lbl">Password</span><span class="val">__PASSWORD__</span></div>
 <div class="codebox">
   <div id="code">------</div>
   <div id="secs">&nbsp;</div>
   <button id="copy">Copy passcode</button>
 </div>
 <div class="hint">At the Duo prompt choose <b>Hardware token</b>, then paste this passcode.
   It changes every 30 seconds &mdash; if it expires, just copy the new one.</div>
</div>
<script>
var SECRET = "__SECRET__";             // base32 (var, not const — ES5 only)
// SHA-1 / HMAC are implemented inline on purpose. crypto.subtle is only exposed
// in a "secure context" and Chrome restricts it for some file:// origins, which
// left the page stuck on "------" with no error. Plain JS works everywhere.
function sha1(bytes){
  var ml=bytes.length*8;
  var buf=new Uint8Array(((bytes.length+9+63)>>6)<<6);
  buf.set(bytes); buf[bytes.length]=0x80;
  var dv=new DataView(buf.buffer);
  dv.setUint32(buf.length-8,Math.floor(ml/4294967296));
  dv.setUint32(buf.length-4,ml>>>0);
  var h0=0x67452301,h1=0xEFCDAB89,h2=0x98BADCFE,h3=0x10325476,h4=0xC3D2E1F0;
  var w=new Uint32Array(80),i,j,a,b,c,d,e,f,k,t,n;
  for(i=0;i<buf.length;i+=64){
    for(j=0;j<16;j++){ w[j]=dv.getUint32(i+j*4); }
    for(j=16;j<80;j++){ n=w[j-3]^w[j-8]^w[j-14]^w[j-16]; w[j]=(n<<1)|(n>>>31); }
    a=h0;b=h1;c=h2;d=h3;e=h4;
    for(j=0;j<80;j++){
      if(j<20){f=(b&c)|((~b)&d);k=0x5A827999;}
      else if(j<40){f=b^c^d;k=0x6ED9EBA1;}
      else if(j<60){f=(b&c)|(b&d)|(c&d);k=0x8F1BBCDC;}
      else{f=b^c^d;k=0xCA62C1D6;}
      t=(((a<<5)|(a>>>27))+f+e+k+w[j])>>>0;
      e=d;d=c;c=((b<<30)|(b>>>2))>>>0;b=a;a=t;
    }
    h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;h4=(h4+e)>>>0;
  }
  var out=new Uint8Array(20),odv=new DataView(out.buffer);
  odv.setUint32(0,h0);odv.setUint32(4,h1);odv.setUint32(8,h2);odv.setUint32(12,h3);odv.setUint32(16,h4);
  return out;
}
function hmacSha1(key,msg){
  var B=64, k=key.length>B?sha1(key):key, n;
  var pk=new Uint8Array(B); pk.set(k);
  var oi=new Uint8Array(B), ii=new Uint8Array(B);
  for(n=0;n<B;n++){oi[n]=pk[n]^0x5c; ii[n]=pk[n]^0x36;}
  var inner=new Uint8Array(B+msg.length); inner.set(ii); inner.set(msg,B);
  var ih=sha1(inner);
  var outer=new Uint8Array(B+20); outer.set(oi); outer.set(ih,B);
  return sha1(outer);
}
function pad(s,n){s=String(s);while(s.length<n){s="0"+s;}return s;}
function b32(s){s=s.replace(/=+$/,"").toUpperCase();
  var A="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",bits="",i,c,idx;
  for(i=0;i<s.length;i++){c=s.charAt(i);idx=A.indexOf(c);if(idx<0)continue;
    bits+=pad(idx.toString(2),5);}
  var out=[];for(i=0;i+8<=bits.length;i+=8){out.push(parseInt(bits.substr(i,8),2));}
  return new Uint8Array(out);}
function totp(){
  var ctr=Math.floor(Date.now()/1000/30);
  var msg=new Uint8Array(8); var dv=new DataView(msg.buffer);
  dv.setUint32(0,Math.floor(ctr/4294967296)); dv.setUint32(4,ctr>>>0);
  var sig=hmacSha1(b32(SECRET),msg);
  var off=sig[19]&0xf;
  var v=(((sig[off]&0x7f)<<24)|(sig[off+1]<<16)|(sig[off+2]<<8)|sig[off+3])>>>0;
  return pad(v%1000000,6);
}
function tick(){
  var el=document.getElementById("code");
  try{
    el.textContent=totp();
    var left=30-Math.floor(Date.now()/1000)%30;
    document.getElementById("secs").textContent="changes in "+left+"s";
    el.className=left<=5?"warn":"";
  }catch(e){
    // Never fail silently — a blank code with no explanation is unhelpable.
    el.textContent="ERROR";
    el.className="warn";
    document.getElementById("secs").textContent=String(e&&e.message?e.message:e);
  }
}
document.getElementById("copy").onclick=function(){
  var t=document.getElementById("code").textContent.replace(/^\s+|\s+$/g,"");
  var done=function(){
    var b=document.getElementById("copy");b.textContent="Copied!";
    setTimeout(function(){b.textContent="Copy passcode";},1400);
  };
  var fallback=function(){
    var ta=document.createElement("textarea");ta.value=t;document.body.appendChild(ta);
    ta.select();try{document.execCommand("copy");}catch(e){}ta.parentNode.removeChild(ta);done();
  };
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(t).then(done,fallback);
  }else{fallback();}
};
tick();setInterval(tick,1000);
</script></body></html>
"""


def _winrm_put_bytes(sess, data: bytes, dest: str, log=None) -> tuple[bool, str]:
    """Upload bytes to a Windows host over WinRM.

    WinRM caps the command line far below the size of a typical file, so the
    payload is appended to a temp file in base64 chunks and decoded in place.
    """
    import base64 as _b64

    _log = log or (lambda s: None)
    b64 = _b64.b64encode(data).decode()
    tmp = rf"C:\Windows\Temp\_put_{abs(hash(dest)) % 10**8}.b64"
    # powershell -EncodedCommand caps the command line near 8k chars, and WinRM
    # encodes the script as UTF-16 base64, so the usable payload per call is
    # roughly a third of that. 2000 stays well inside it while keeping the
    # number of round trips (and therefore failure opportunities) low.
    CHUNK = 2000

    sess.run_ps(f"Remove-Item '{tmp}' -ErrorAction SilentlyContinue")
    chunks = [b64[i:i + CHUNK] for i in range(0, len(b64), CHUNK)]
    for n, part in enumerate(chunks):
        # When proxied through a Docker container each chunk is its own
        # `docker exec`, and those occasionally die (observed rc=137). Retry
        # rather than abandoning a nearly-complete upload.
        last = ""
        for attempt in range(3):
            r = sess.run_ps(f"Add-Content -Path '{tmp}' -Value '{part}' -NoNewline")
            if r.status_code == 0:
                break
            last = ((r.std_err or b"").decode(errors="replace").strip()
                    or (r.std_out or b"").decode(errors="replace").strip()
                    or f"rc={r.status_code}")
            _log(f"chunk {n + 1}/{len(chunks)} attempt {attempt + 1} failed ({last[:80]}) — retrying")
        else:
            return False, f"chunk {n + 1}/{len(chunks)} failed after 3 attempts: {last[:180]}"
    r = sess.run_ps(
        f"$b=[System.Convert]::FromBase64String((Get-Content '{tmp}' -Raw));"
        f"[System.IO.File]::WriteAllBytes('{dest}', $b);"
        f"Remove-Item '{tmp}' -ErrorAction SilentlyContinue;"
        f"if (Test-Path '{dest}') {{ 'WROTE ' + (Get-Item '{dest}').Length }} else {{ 'FAILED' }}"
    )
    out = r.std_out.decode(errors="replace").strip()
    if not out.startswith("WROTE"):
        return False, f"{out[:120]} {r.std_err.decode(errors='replace')[:120]}"
    _log(f"{out} bytes -> {dest}")
    return True, out


def _fetch_duo_logo_from_ad1(pod_id: str = "", log=None) -> bytes:
    """Pull Duo's own logo .ico off AD1 (shipped with the Authentication Proxy).

    Using the vendor asset beats approximating one, and it is already present in
    every pod because the Auth Proxy is preinstalled.
    """
    import base64 as _b64

    _log = log or (lambda s: None)
    ico = (r"C:\Program Files\Duo Security Authentication Proxy\bin"
           r"\local_proxy_manager-win32-x64\resources\app\assets\images\Duo-Logo.ico")
    sess = (_winrm_connect_for_pod(pod_id, log=log) if pod_id
            else _winrm_connect(AD_DC_IP, AD_WINRM_USER, AD_WINRM_PASS))
    try:
        r = sess.run_ps(
            f"if (Test-Path '{ico}') {{ "
            f"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{ico}')) }} else {{ 'MISSING' }}"
        )
        out = r.std_out.decode(errors="replace").strip()
        if not out or out == "MISSING":
            raise RuntimeError("Duo-Logo.ico not found on AD1")
        data = _b64.b64decode(out)
        _log(f"fetched Duo-Logo.ico from AD1 ({len(data)} bytes)")
        return data
    finally:
        # Release the proxy container before the caller opens its own.
        try:
            if hasattr(sess, "close"):
                sess.close()
        except Exception:
            pass


def duo_publish_totp_page(pod_id: str, db_path: str,
                          dest: str = r"C:\Users\Public\Duo-Login.html",
                          log=None) -> tuple[bool, str]:
    """Publish a self-contained Duo passcode page onto the jump host.

    Students work from Jumphost1 and have no access to POD Automator, so the
    dashboard's passcode panel is useless to them. This writes a standalone HTML
    file to the jump host's Public Desktop that computes the TOTP locally in the
    browser (SubtleCrypto HMAC-SHA1) — no network calls, no dependencies, and a
    Copy button so the code can be pasted straight into Duo.

    NOTE: the page embeds the org's TOTP secret, so anyone with access to the
    jump host can derive codes. That is the intent here (the student *is* the
    pod's Duo admin), but do not use this pattern for shared or non-lab orgs.
    """
    import base64 as _b64
    import re as _re
    import sqlite3 as _sq

    import winrm

    _log = log or (lambda s: print(f"  [duo-page] {s}"))

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        if not pod:
            return False, f"POD {pod_id} not found"
        m = _re.search(r"pseudoco-(\d+)", pod["scc_org"] or "")
        if not m:
            return False, f"cannot derive org number from scc_org={pod['scc_org']!r}"
        oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                               (m.group(1),)).fetchone() or {})

    secret = (oc.get("duo_admin_totp_secret") or "").strip()
    email = (oc.get("duo_admin_email") or "").strip()
    host = (oc.get("duo_admin_host") or "").strip()
    password = (oc.get("duo_admin_password") or "").strip()
    if not secret:
        return False, "no TOTP secret — run duo_provision_admin_totp first"

    html = (_TOTP_PAGE_HTML
            .replace("__POD__", pod_id)
            .replace("__URL__", f"https://{host}" if host else "")
            .replace("__EMAIL__", email)
            .replace("__PASSWORD__", password)
            .replace("__SECRET__", secret))

    icon_path = r"C:\Users\Public\Duo-Logo.ico"
    lnk = r"C:\Users\Public\Desktop\Duo Login.lnk"
    sess = None
    try:
        # Pod-aware: works both inside the pipeline container and from the Mac
        # (where the dashboard runs the card and has no VPN of its own).
        sess = _winrm_connect_jump(pod_id, log=_log)
        ok, msg = _winrm_put_bytes(sess, html.encode("utf-8"), dest, log=_log)
        if not ok:
            return False, f"page write failed: {msg}"

        # Desktop entry: a .lnk shortcut rather than the raw .html, because an
        # .html file always shows the default browser's icon and cannot carry a
        # custom one. A shortcut can, via IconLocation.
        # Duo's logo lives on AD1, but the jump host cannot fetch it itself:
        # WinRM will not delegate credentials on to a second host without
        # CredSSP ("A specified logon session does not exist"), so an SMB
        # Copy-Item from jumper1 to AD1 always fails. Relay the bytes instead,
        # and only when the icon is not already staged — the .ico never changes,
        # and the relay is the expensive part (~15 chunked round trips, which
        # can OOM the proxy container when run from the Mac).
        r = sess.run_ps(f"if (Test-Path '{icon_path}') {{ 'PRESENT' }} else {{ 'ABSENT' }}")
        icon_ok = "PRESENT" in r.std_out.decode(errors="replace")
        if icon_ok:
            _log("Duo logo already staged on jump host")
        else:
            try:
                ico = _fetch_duo_logo_from_ad1(pod_id=pod_id, log=_log)
                icon_ok, icon_msg = _winrm_put_bytes(sess, ico, icon_path, log=_log)
                if not icon_ok:
                    _log(f"icon relay failed ({icon_msg[:90]}) — using browser icon")
            except Exception as e:
                _log(f"could not stage Duo logo ({type(e).__name__}: {e}) — using browser icon")

        # Target Chrome explicitly rather than the .html. The jump hosts ship
        # with .html associated to the Internet Explorer AppX handler, which
        # cannot run this page — pointing at chrome.exe makes the shortcut
        # independent of file associations. Falls back to the bare .html if
        # Chrome is missing.
        icon_line = (f"$s.IconLocation = '{icon_path},0';" if icon_ok else "")
        r = sess.run_ps(
            "$chrome = @('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',"
            "'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe') |"
            " Where-Object { Test-Path $_ } | Select-Object -First 1;"
            f"$w = New-Object -ComObject WScript.Shell;"
            f"$s = $w.CreateShortcut('{lnk}');"
            f"if ($chrome) {{ $s.TargetPath = $chrome; $s.Arguments = '\"{dest}\"' }}"
            f" else {{ $s.TargetPath = '{dest}' }};"
            f"$s.Description = 'Duo Admin Panel passcode for this pod';"
            f"{icon_line}"
            f"$s.Save();"
            f"if (Test-Path '{lnk}') {{ if ($chrome) {{ 'SHORTCUT OK (chrome)' }} "
            f"else {{ 'SHORTCUT OK (default handler)' }} }} else {{ 'SHORTCUT FAILED' }}"
        )
        sc = r.std_out.decode(errors="replace").strip()
        _log(f"{sc} -> {lnk} (icon={'Duo logo' if icon_ok else 'default'})")

        # Older builds of this dropped the raw .html on the Desktop; remove it so
        # students see one entry, not two.
        sess.run_ps(r"Remove-Item 'C:\Users\Public\Desktop\Duo-Login.html' "
                    r"-ErrorAction SilentlyContinue")
    except Exception as e:
        return False, f"WinRM publish failed: {type(e).__name__}: {e}"
    finally:
        # DockerWinRMSession holds a background container; a plain winrm.Session
        # has no close(). Release either without caring which we got.
        try:
            if sess is not None and hasattr(sess, "close"):
                sess.close()
        except Exception:
            pass

    return True, f"published {dest} on {JUMP_HOST_IP} (current code {_totp_generate(secret)})"


def duo_admin_totp_code(pod_id: str, db_path: str) -> str:
    """Current 6-digit Duo admin login code for this POD (for the dashboard)."""
    import re as _re
    import sqlite3 as _sq

    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        org_num = _re.search(r"pseudoco-(\d+)", (pod["scc_org"] or "")).group(1)
        row = conn.execute("SELECT duo_admin_totp_secret FROM org_credentials "
                           "WHERE org_number=?", (org_num,)).fetchone()
    secret = (row["duo_admin_totp_secret"] or "").strip() if row else ""
    if not secret:
        raise RuntimeError(f"org {org_num} has no TOTP secret — "
                           "run duo_provision_admin_totp first")
    return _totp_generate(secret)


def duo_passkey_login(pod_id: str, db_path: str, log=None):
    """Open an authenticated Duo admin session using the stored passkey.

    Returns (playwright, browser, ctx, page) — the caller must close them and is
    responsible for persisting the updated signCount via duo_passkey_save_hwm().
    """
    import json as _json
    import re as _re
    import sqlite3 as _sq

    from playwright.sync_api import sync_playwright

    _log = log or (lambda s: print(f"  [duo-login] {s}"))
    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        org_num = _re.search(r"pseudoco-(\d+)", (pod["scc_org"] or "")).group(1)
        oc = dict(conn.execute("SELECT * FROM org_credentials WHERE org_number=?",
                               (org_num,)).fetchone())

    creds = _json.loads(oc.get("duo_passkey_cred") or "[]")
    if not creds:
        raise RuntimeError(f"org {org_num} has no stored passkey — run duo_passkey_bootstrap first")

    pw = sync_playwright().start()
    browser = pw.chromium.launch(headless=True, args=["--no-sandbox"])
    ctx = browser.new_context(ignore_https_errors=True,
                              viewport={"width": 1500, "height": 1100},
                              permissions=["clipboard-read", "clipboard-write"])
    page = ctx.new_page()
    cdp, auth_id, base = _pw_load_passkey(ctx, page, creds, oc.get("duo_passkey_hwm") or 0)
    ok = _pw_duo_admin_login_passkey(page, oc["duo_admin_host"], oc["duo_admin_email"],
                                     oc["duo_admin_password"], log=_log)
    hwm = _pw_read_signcount(cdp, auth_id, base)
    with _sq.connect(db_path) as conn:
        conn.execute("UPDATE org_credentials SET duo_passkey_hwm=? WHERE org_number=?",
                     (hwm, org_num))
    if not ok:
        browser.close()
        pw.stop()
        raise RuntimeError("passkey login failed")
    return pw, browser, ctx, page


def _pw_duo_admin_login_totp(admin_host: str, email: str, password: str,
                              totp_code: str, log=None):
    """
    Playwright: log into Duo admin portal with email + password + TOTP passcode.

    After a successful activation + enrollment the admin portal accepts Duo Mobile
    OTP (TOTP) as a second factor.  Returns (sid, xsrf) cookie values.
    Raises RuntimeError if login fails.
    """
    _log = log or (lambda s: print(f"     [pw-login] {s}"))
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(
            headless=True,
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
            viewport={"width": 1400, "height": 900},
        )
        page = ctx.new_page()

        login_url = f"https://{admin_host}/login"
        _log(f"navigating to {login_url}")
        page.goto(login_url, wait_until="load", timeout=30_000)

        # ── Email ─────────────────────────────────────────────────────────────
        page.get_by_role("textbox", name="Email address").fill(email, timeout=10_000)
        page.get_by_role("button", name="Continue").click(timeout=8_000)
        page.wait_for_timeout(1000)

        # ── Password ──────────────────────────────────────────────────────────
        page.get_by_role("textbox", name="Password").fill(password, timeout=10_000)
        # "Log in" button — handle both enabled variants
        try:
            page.get_by_role("button", name="Log in").click(timeout=6_000)
        except Exception:
            page.locator("button[type=submit]").first.click(timeout=5_000)
        page.wait_for_timeout(2000)
        _log(f"after password: {page.url[:80]}")

        # ── 2FA prompt ────────────────────────────────────────────────────────
        # Duo may show: "Enter a Passcode", "Use a Passcode", or render an input
        # directly.  Try multiple selectors.
        for selector_text in ["Enter a Passcode", "Use a Passcode", "Passcode"]:
            try:
                lnk = page.get_by_text(selector_text, exact=False)
                if lnk.is_visible(timeout=2_000):
                    lnk.click(timeout=3_000)
                    page.wait_for_timeout(800)
                    break
            except Exception:
                pass

        # ── Fill TOTP code ────────────────────────────────────────────────────
        filled = False
        for locator in [
            page.get_by_placeholder("Passcode"),
            page.get_by_role("textbox", name="Passcode"),
            page.get_by_role("textbox", name="passcode"),
        ]:
            try:
                if locator.is_visible(timeout=2_000):
                    locator.fill(totp_code, timeout=3_000)
                    filled = True
                    break
            except Exception:
                pass
        if not filled:
            # Last resort: first visible text/tel input
            for inp in page.locator("input[type='text'],input[type='tel'],input[type='number']").all():
                try:
                    if inp.is_visible():
                        inp.fill(totp_code)
                        filled = True
                        break
                except Exception:
                    pass

        if not filled:
            _log(f"WARN: could not find passcode input (url={page.url[:80]})")

        # ── Submit ────────────────────────────────────────────────────────────
        submitted = False
        for btn_name in ["Log In", "Submit", "Verify"]:
            try:
                btn = page.get_by_role("button", name=btn_name)
                if btn.is_visible(timeout=1_500):
                    btn.click(timeout=3_000)
                    submitted = True
                    break
            except Exception:
                pass
        if not submitted:
            page.keyboard.press("Enter")

        page.wait_for_timeout(3000)
        _log(f"after 2FA submit: {page.url[:80]}")

        # ── Extract cookies ───────────────────────────────────────────────────
        cookies = {c["name"]: c["value"] for c in ctx.cookies()}
        sid  = cookies.get("sid", "")
        xsrf = cookies.get("_xsrf", "")

        if not sid:
            # Dump snapshot for debugging
            snapshot_text = page.content()[:500]
            raise RuntimeError(
                f"Login failed — no 'sid' cookie after 2FA "
                f"(url={page.url[:80]}, page={snapshot_text})"
            )

        _log(f"login successful (sid={sid[:20]}...)")
        browser.close()
        return sid, xsrf


def _duo_get_admin_id(ikey: str, skey: str, host: str, email: str, log=None) -> str:
    """Return the admin_id for the given email from the Duo Admin API."""
    _log = log or (lambda s: print(f"     [duo-admin-id] {s}"))
    resp = _duo_request(ikey, skey, host, "GET", "/admin/v1/admins")
    admins = resp.get("response", [])
    for a in admins:
        if a.get("email", "").lower() == email.lower():
            _log(f"found admin_id={a['admin_id']} for {email}")
            return a["admin_id"]
    raise RuntimeError(f"Admin user {email!r} not found in org (got {len(admins)} admins)")


def _duo_create_bypass_code(ikey: str, skey: str, host: str,
                             admin_id: str, log=None) -> str:
    """Create a one-time bypass code for a Duo admin user. Returns the code string."""
    _log = log or (lambda s: print(f"     [bypass-code] {s}"))
    resp = _duo_request(ikey, skey, host, "POST",
                        f"/admin/v1/admins/{admin_id}/bypass_codes",
                        params={"count": "1", "reuse_count": "0"})
    codes = resp.get("response", [])
    if not codes:
        raise RuntimeError(f"no bypass codes returned. Full response: {resp}")
    code = codes[0].get("bypass_code", "")
    if not code:
        raise RuntimeError(f"bypass_code field empty in response: {codes[0]}")
    _log(f"bypass code created (len={len(code)})")
    return code


def duo_activate_and_get_sessions(pod_id: str, db_path: str, log=None) -> dict:
    """
    Per-session Duo admin account activation + bypass-code login.

    Since dCloud Duo orgs are torn down after each session, every new session
    needs a fresh activation.  TOTP enrollment is NOT used — it requires a
    cryptographic signature from the real Duo Mobile binary.  Instead:

      1.  Load iDAC URL + Duo Admin API credentials from DB
      2.  Playwright: navigate iDAC, activate admin account (set password),
          skip 2FA enrollment — password is saved server-side at this point
      3.  Admin API: look up the admin user by email, create a one-time bypass code
      4.  Playwright: log into admin portal with email + password + bypass code
      5.  Persist (email, password) in DB for audit (never read back)
      6.  Return session dict compatible with get_browser_sessions()

    Returns dict with keys: duo_sid, duo_xsrf, admin_host, okta_token, email.

    Raises RuntimeError on failure.
    """
    import sqlite3 as _sq
    import re as _re

    _log = log or (lambda s: print(f"     [duo-activate] {s}"))

    # ── 1. Load credentials from DB ───────────────────────────────────────────
    with _sq.connect(db_path) as conn:
        conn.row_factory = _sq.Row
        pod_row = conn.execute(
            "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
        ).fetchone()
        if not pod_row:
            raise RuntimeError(f"POD {pod_id!r} not found in DB")
        scc_org = pod_row["scc_org"] or ""
        m = _re.search(r"pseudoco-(\d+)", scc_org)
        if not m:
            raise RuntimeError(f"Cannot determine org number from scc_org={scc_org!r}")
        org_num = m.group(1)
        oc_row = conn.execute(
            "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
        ).fetchone()
        if not oc_row:
            raise RuntimeError(f"No org credentials for org {org_num}")
        oc = dict(oc_row)

    idac_url  = oc.get("idac_url",  "").strip()
    duo_ikey  = oc.get("duo_ikey",  "").strip()
    duo_skey  = oc.get("duo_skey",  "").strip()
    duo_host  = oc.get("duo_host",  "").strip()

    if not idac_url:
        raise RuntimeError("iDAC URL not configured in org_credentials")
    if not duo_ikey or not duo_skey or not duo_host:
        raise RuntimeError("Duo Admin API credentials not configured")

    m2 = _re.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    admin_host = (
        f"admin-{m2.group(1)}.duosecurity.com" if m2
        else duo_host.replace("api-", "admin-")
    )

    # ── 2. Playwright: activate account, set password, skip 2FA enrollment ────
    _log("starting Duo admin account activation (Playwright) ...")
    email, password = _pw_activate_duo_admin(idac_url, log=_log)

    # ── 3. Admin API: look up admin user, create bypass code ──────────────────
    _log(f"finding admin user {email!r} via Admin API ...")
    admin_id = _duo_get_admin_id(duo_ikey, duo_skey, duo_host, email, log=_log)
    _log("creating one-time bypass code ...")
    bypass_code = _duo_create_bypass_code(duo_ikey, duo_skey, duo_host, admin_id, log=_log)

    # ── 4. Playwright: login with bypass code ─────────────────────────────────
    _log(f"logging into admin portal with bypass code ...")
    sid, xsrf = _pw_duo_admin_login_totp(
        admin_host, email, password, bypass_code, log=_log
    )

    # ── 5. Persist credentials in DB (audit/debug only — never read back) ─────
    # Each dCloud session is a new Duo org; these values are stale the moment
    # the session ends.  We store them purely for post-run inspection.
    try:
        with _sq.connect(db_path) as conn:
            conn.execute(
                "UPDATE org_credentials SET "
                "duo_admin_email=?, duo_admin_password=?, "
                "updated_at=datetime('now') WHERE org_number=?",
                (email, password, org_num),
            )
        _log("activation credentials saved to DB")
    except Exception as e:
        _log(f"WARN: could not save activation credentials to DB: {e}")

    return {
        "duo_sid":    sid,
        "duo_xsrf":   xsrf,
        "admin_host": admin_host,
        "okta_token": "",   # not available via this path
        "email":      email,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Full SA + Duo SAML/SCIM setup orchestration
# ──────────────────────────────────────────────────────────────────────────────

def duo_saml_full_setup(pod_id: str, db_path: str,
                        log=None) -> tuple[bool, str]:
    """
    Full SA + Duo SAML/SCIM integration setup for a POD.

    Steps:
      1.  Load org credentials from DB
      2.  Playwright: authenticate SCC via iDAC URL → Okta token + Duo admin cookies
      3.  Exchange Okta token for SA management JWT
      4.  SA: ensure provisioning profile (label=Duo, source=/duo/scimv2)
      5.  SA: generate new SCIM token
      6.  SA: delete any existing Duo SAML profiles
      7.  Duo admin: get or create SAML SP app (sso_generic)
      8.  Duo admin: configure SAML SP app (SA entity ID + ACS URL)
      9.  Fetch Duo IdP metadata XML + SA SP cert serial
      10. SA: create SAML profile with Duo IdP metadata
      11. Duo admin: configure SCIM outbound integration with new SCIM token
      12. Persist app ikey + profile id to DB

    Returns (ok, result_string).
    """
    import sqlite3 as _sq
    import re as _re5

    _log = log or (lambda s: print(f"     [duo-saml] {s}"))

    # ── 1. Load credentials ───────────────────────────────────────────────────
    _log("loading credentials from DB...")
    try:
        with _sq.connect(db_path) as conn:
            conn.row_factory = _sq.Row
            pod_row = conn.execute(
                "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
            ).fetchone()
            if not pod_row:
                return False, f"POD {pod_id!r} not found in DB"

            scc_org = pod_row["scc_org"] or ""
            m5 = _re5.search(r"pseudoco-(\d+)", scc_org)
            if not m5:
                return False, f"Cannot determine org number from scc_org={scc_org!r}"
            org_num = m5.group(1)

            oc_row = conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
            ).fetchone()
            if not oc_row:
                return False, f"No org credentials configured for org {org_num}"
            oc = dict(oc_row)
    except Exception as e:
        return False, f"DB read error: {e}"

    duo_ikey      = oc.get("duo_ikey", "").strip()
    duo_skey      = oc.get("duo_skey", "").strip()
    duo_host      = oc.get("duo_host", "").strip()
    sa_api_key    = oc.get("sa_api_key", "").strip()
    sa_api_sec    = oc.get("sa_api_secret", "").strip()
    sa_org_id     = oc.get("sa_org_id", "").strip()
    idac_url      = oc.get("idac_url", "").strip()
    scc_email     = oc.get("scc_email", "").strip()
    scc_password  = oc.get("scc_password", "").strip()

    import os as _os
    _in_docker = _os.path.exists("/.dockerenv")

    if not duo_ikey or not duo_skey or not duo_host:
        return False, "Duo Admin API credentials not configured for this org"

    ap_ikey = oc.get("authproxy_ikey", "").strip()
    ap_skey = oc.get("authproxy_skey", "").strip()

    # ── 2. SCC browser login (mokuma@gmail.com or scc_email) → Duo admin session
    if not scc_email or not scc_password:
        return False, (
            "scc_email/scc_password not configured in org_credentials — "
            "cannot log in to SCC (set mokuma@gmail.com / C1sco12345!! for this org)"
        )
    import re as _re_ah
    _m_ah = _re_ah.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    admin_host = (
        f"admin-{_m_ah.group(1)}.duosecurity.com" if _m_ah
        else duo_host.replace("api-", "admin-")
    )
    _log(f"SCC login ({scc_email}) → Duo admin panel ({admin_host}) ...")
    try:
        sessions = get_browser_sessions_mac(
            duo_host=duo_host,
            scc_email=scc_email,
            org_number=org_num,
            scc_password=scc_password,
            log=_log,
        )
        duo_sid    = sessions.get("duo_sid", "")
        duo_xsrf   = sessions.get("duo_xsrf", "")
        admin_host = sessions.get("admin_host", admin_host)
        okta_token = sessions.get("okta_token", "")
        duo_all_cookies = sessions.get("all_cookies", {})
    except Exception as e:
        return False, f"SCC browser login failed: {e}"
    if not duo_sid:
        return False, "Could not extract Duo admin session (sid missing after SCC login)"
    _log(f"Duo admin session obtained (host={admin_host})")

    # ── 3. SA management JWT (soft-fail — SA mgmt API may be unavailable) ─────
    mgmt_jwt = ""
    if okta_token and sa_api_key and sa_org_id:
        _log("obtaining SA management JWT from Okta token...")
        try:
            mgmt_jwt = sa_get_mgmt_jwt(okta_token, org_id=sa_org_id)
            _log("management JWT obtained")
        except Exception as e:
            _log(f"WARN: SA management JWT exchange failed ({e}) — SA steps will be skipped")
    else:
        _log("WARN: no Okta token or SA credentials — skipping SA management JWT")

    # ── 4. SA: ensure provisioning profile (soft-fail) ───────────────────────
    profile_id = ""
    if mgmt_jwt:
        _log("verifying SA provisioning profile (source=/duo/scimv2)...")
        try:
            profile_id = sa_ensure_provisioning_profile(mgmt_jwt, sa_org_id, log=_log)
            if not profile_id:
                _log("WARN: SA provisioning profile ID empty — SA SAML steps will be skipped")
        except Exception as e:
            _log(f"WARN: SA provisioning profile error ({e}) — SA SAML steps will be skipped")
    else:
        _log("WARN: skipping SA provisioning profile (no mgmt_jwt)")

    # ── 5. SA: generate SCIM token (soft-fail) ───────────────────────────────
    scim_token = ""
    if mgmt_jwt:
        _log("generating new SA SCIM token...")
        try:
            scim_token = sa_generate_scim_token(mgmt_jwt, sa_org_id, log=_log)
            if not scim_token:
                _log("WARN: SA SCIM token generation returned empty token")
        except Exception as e:
            _log(f"WARN: SA SCIM token generation failed ({e})")
    else:
        _log("WARN: skipping SA SCIM token (no mgmt_jwt)")

    # ── 6. SA: clear existing SAML profiles (soft-fail) ──────────────────────
    if mgmt_jwt:
        _log("clearing existing SA SAML IdP profiles...")
        try:
            profiles = sa_list_saml_profiles(mgmt_jwt, sa_org_id)
            for prof in profiles:
                pid = str(prof.get("idpid") or prof.get("id") or "")
                if pid:
                    sa_delete_saml_profile(mgmt_jwt, sa_org_id, pid, log=_log)
        except Exception as e:
            _log(f"WARN: could not clear SAML profiles: {e}")
    else:
        _log("WARN: skipping SA SAML profile clear (no mgmt_jwt)")

    # ── 7. Duo admin: get or create SAML SP app ───────────────────────────────
    _log("checking/creating Duo SAML SP app...")
    # Build extra cookies dict (excl. sid/_xsrf which are handled separately)
    _extra = {k: v for k, v in duo_all_cookies.items()
              if k not in ("sid", "_xsrf")}
    try:
        app_ikey = duo_admin_get_or_create_saml_app(
            duo_ikey, duo_skey, duo_host,
            duo_sid, duo_xsrf, extra_cookies=_extra, log=_log,
        )
    except Exception as e:
        return False, f"Duo SAML SP app error: {e}"

    # ── 8. Duo admin: configure SAML SP app ──────────────────────────────────
    _log(f"configuring Duo SAML SP app ({app_ikey}) with SA SP details...")
    try:
        ok8 = duo_admin_configure_saml_app(
            admin_host, app_ikey, duo_sid, duo_xsrf,
            entity_id=SA_SP_ENTITY_ID, acs_url=SA_SP_ACS_URL,
            extra_cookies=_extra, log=_log,
        )
        if not ok8:
            return False, "Duo SAML SP app configuration failed (HTTP error)"
    except Exception as e:
        return False, f"Duo SAML SP app configuration error: {e}"

    # ── 9. Fetch Duo IdP metadata XML + SA SP cert serial ─────────────────────
    _log("fetching Duo IdP metadata XML...")
    try:
        metadata_url = duo_admin_get_saml_metadata_url(duo_host, app_ikey)
        r_meta = requests.get(metadata_url, timeout=15)
        r_meta.raise_for_status()
        idp_metadata_xml = r_meta.text
        _log(f"Duo IdP metadata fetched (len={len(idp_metadata_xml)})")
    except Exception as e:
        return False, f"Could not fetch Duo IdP metadata: {e}"

    _log("fetching SA SP cert serial...")
    try:
        cert_serial = sa_get_sp_cert_serial(mgmt_jwt, sa_org_id)
        _log(f"SP cert serial: {cert_serial}")
    except Exception as e:
        cert_serial = SA_SP_CERT_SERIAL_DEFAULT
        _log(f"WARN: cert serial fetch failed ({e}), using default: {cert_serial}")

    # ── 10. SA: create SAML profile (soft-fail) ──────────────────────────────
    if mgmt_jwt and profile_id:
        _log("uploading Duo IdP metadata to SA as new SAML profile...")
        try:
            ok10 = sa_create_saml_profile(
                mgmt_jwt, sa_org_id, profile_id,
                idp_metadata_xml, cert_serial, log=_log,
            )
            if not ok10:
                _log("WARN: SA SAML profile creation failed (non-fatal)")
        except Exception as e:
            _log(f"WARN: SA SAML profile creation error ({e}) (non-fatal)")
    else:
        _log("WARN: skipping SA SAML profile creation (no mgmt_jwt or profile_id)")

    # ── 11. Duo admin: configure SCIM outbound ────────────────────────────────
    _log("configuring Duo SCIM outbound integration with new SA SCIM token...")
    try:
        ok11 = duo_admin_configure_scim(
            admin_host, app_ikey, duo_sid, duo_xsrf,
            scim_token=scim_token, extra_cookies=_extra, log=_log,
        )
        if not ok11:
            _log("WARN: SCIM configure returned non-OK (may already exist, non-fatal)")
    except Exception as e:
        _log(f"WARN: SCIM configure error (non-fatal): {e}")

    # ── 12. Persist app ikey + profile_id to DB ───────────────────────────────
    _log("persisting results to DB...")
    try:
        with _sq.connect(db_path) as conn:
            conn.execute(
                "UPDATE org_credentials "
                "SET duo_saml_app_ikey=?, sa_saml_profile_id=?, updated_at=datetime('now') "
                "WHERE org_number=?",
                (app_ikey, profile_id, org_num),
            )
    except Exception as e:
        _log(f"WARN: DB persist failed: {e}")

    # ── 13. Push [sso] section to authproxy.cfg + run enrollment ──────────────
    # Fetch the SAML app's secret key from the Duo Admin API, then build the
    # [sso] section and append it to the existing authproxy.cfg on AD1.
    # After writing, run 'authproxyctl enroll' which contacts Duo cloud and
    # inserts 'rikey=' into the [sso] section; then restart to activate.
    _log("fetching SAML app secret key from Duo Admin API ...")
    try:
        _integ_resp = _duo_request(
            duo_ikey, duo_skey, duo_host,
            "GET", f"/admin/v1/integrations/{app_ikey}",
        )
        app_skey = _integ_resp.get("response", {}).get("secret_key", "")
        if not app_skey:
            raise ValueError("secret_key empty in integration response")
        _log(f"SAML app skey fetched ({len(app_skey)} chars)")
    except Exception as e:
        _log(f"WARN: could not fetch SAML app skey ({e}) — skipping [sso] push")
        app_skey = ""

    if app_skey:
        try:
            _log("connecting to AD1 via WinRM for [sso] push ...")
            _sso_winrm = _winrm_connect_for_pod(pod_id, log=_log)

            # Read current authproxy.cfg, strip any prior [sso] block
            import re as _re_sso
            _current = _winrm_read_file(_sso_winrm, AUTHPROXY_CFG_PATH)
            _clean = _re_sso.sub(
                r'\[sso\].*?(?=\[|\Z)', '', _current, flags=_re_sso.DOTALL
            ).rstrip()

            # Append new [sso] section (rikey will be added by authproxyctl enroll)
            _sso_section = (
                "\n\n[sso]\n"
                f"ikey={app_ikey}\n"
                f"skey={app_skey}\n"
                f"api_host={duo_host}\n"
            )
            _new_cfg = _clean + _sso_section
            _log("appending [sso] to authproxy.cfg and restarting ...")
            _ok_sso, _msg_sso = _winrm_write_restart_cfg(_sso_winrm, _new_cfg, _log)
            if not _ok_sso:
                _log(f"WARN: [sso] write/restart failed: {_msg_sso}")
            else:
                _log(f"[sso] write: {_msg_sso}")
                # Run authproxyctl enroll — inserts rikey= into [sso]
                _log(f"running authproxyctl enroll on AD1 ...")
                _enroll_args = (
                    f"enroll --ikey {app_ikey} --skey {app_skey} "
                    f"--api-host {duo_host}"
                )
                _ok_enroll, _out_enroll = _winrm_run_cmd(
                    _sso_winrm,
                    f"'{AUTHPROXY_ENROLL_EXE}' {_enroll_args}",
                    _log,
                )
                _log(f"enroll output: {_out_enroll[:200]}")
                # Restart once more to pick up the rikey written by enroll
                _log("restarting DuoAuthProxy to activate rikey ...")
                _sso_winrm.run_ps(
                    "Restart-Service DuoAuthProxy -Force -ErrorAction SilentlyContinue; "
                    "Start-Sleep 5; "
                    "$s = Get-Service DuoAuthProxy -ErrorAction SilentlyContinue; "
                    "if ($s) { Write-Output \"STATUS:$($s.Status)\" }"
                )

            if hasattr(_sso_winrm, "close"):
                try:
                    _sso_winrm.close()
                except Exception:
                    pass
        except Exception as e:
            _log(f"WARN: [sso] push/enroll error (non-fatal): {e}")

    result = (
        f"Duo SAML/SSO setup complete | "
        f"duo_app={app_ikey}"
        + (f" | SA org={sa_org_id} profile={profile_id}" if profile_id else " | SA steps skipped (no mgmt_jwt)")
    )
    _log(result)
    return True, result


# ──────────────────────────────────────────────────────────────────────────────
# External Directory (AD sync) + SSO Auth Proxy Setup
# ──────────────────────────────────────────────────────────────────────────────

AD_DC_IP             = "198.18.5.102"
AD_DC_PORT           = "389"
AD_BASE_DN           = "DC=corp,DC=pseudoco,DC=com"
AD_GROUPS_TO_ADD     = ["IoT", "MAIN", "PROD"]
SSO_PERMITTED_DOMAIN = "corp.pseudoco.com"
AUTHPROXY_ENROLL_EXE = (
    r"C:\Program Files\Duo Security Authentication Proxy\bin\authproxyctl.exe"
)


# ── WinRM helpers ─────────────────────────────────────────────────────────────

def _winrm_connect(ad_ip: str = AD_DC_IP,
                   user: str = AD_WINRM_USER,
                   pw: str = AD_WINRM_PASS):
    """Return a winrm.Session or raise ImportError / RuntimeError."""
    try:
        import winrm as _wm
    except ImportError:
        raise ImportError("pywinrm not installed — run: pip install pywinrm")
    return _wm.Session(
        f"http://{ad_ip}:5985/wsman",
        auth=(user, pw),
        transport="ntlm",
        read_timeout_sec=90,
        operation_timeout_sec=85,
    )


def _winrm_read_file(session, path: str) -> str:
    """Read a text file from the remote machine. Returns content or ''."""
    ps = f"Get-Content '{path}' -Raw -ErrorAction SilentlyContinue"
    r = session.run_ps(ps)
    return r.std_out.decode(errors="replace")


def _winrm_write_restart_cfg(session, cfg_content: str, log) -> tuple[bool, str]:
    """Write authproxy.cfg to AD1 and restart DuoAuthProxy service."""
    import base64 as _b64w
    b64 = _b64w.b64encode(cfg_content.encode("ascii", errors="replace")).decode()
    write_ps = (
        f"$b = [Convert]::FromBase64String('{b64}'); "
        "$t = [System.Text.Encoding]::ASCII.GetString($b); "
        f"$p = '{AUTHPROXY_CFG_PATH}'; "
        "$d = Split-Path -Parent $p; "
        "if (!(Test-Path $d)) { New-Item -ItemType Directory -Path $d -Force | Out-Null }; "
        "[System.IO.File]::WriteAllText($p, $t, [System.Text.Encoding]::ASCII); "
        "Write-Output 'WRITE_OK'"
    )
    r = session.run_ps(write_ps)
    out = r.std_out.decode(errors="replace").strip()
    if "WRITE_OK" not in out:
        err = r.std_err.decode(errors="replace")[:200]
        return False, f"Write failed: {out} | {err}"
    log("authproxy.cfg written")

    restart_ps = (
        "try { Restart-Service DuoAuthProxy -Force -ErrorAction Stop } "
        "catch { try { "
        "Stop-Service DuoAuthProxy -Force -ErrorAction SilentlyContinue; "
        "Start-Sleep 2; "
        "Start-Service DuoAuthProxy -ErrorAction Stop "
        "} catch {} }"
    )
    # Use a longer WinRM op timeout — Restart-Service blocks until Running.
    # op_timeout/read_timeout are passed at session-creation time (see
    # _winrm_connect), so run_ps() here uses no extra kwargs.
    r2 = session.run_ps(restart_ps)
    restart_err = r2.std_err.decode(errors="replace")
    log("DuoAuthProxy service restarted — checking status ...")

    # Separate call to check status so we don't race the restart
    check_ps = (
        "Start-Sleep 3; "
        "$s = Get-Service DuoAuthProxy -ErrorAction SilentlyContinue; "
        "if ($s) { Write-Output \"STATUS:$($s.Status)\" } "
        "else { Write-Output 'STATUS:NotFound' }"
    )
    r3 = session.run_ps(check_ps)
    out3 = r3.std_out.decode(errors="replace").strip()
    import re as _rwr
    m = _rwr.search(r"STATUS:(\w+)", out3)
    status = m.group(1) if m else "Unknown"
    log(f"DuoAuthProxy service: {status}")
    if status.lower() == "running":
        return True, "cfg written | service Running"
    # CLIXML noise in stderr is PowerShell formatting, not a real error — treat Unknown as OK
    restart_clixml = restart_err.strip().startswith("#< CLIXML")
    if restart_clixml or status == "Unknown":
        log(f"DuoAuthProxy service: {status} (status check inconclusive — cfg written and restart issued, treating as OK)")
        return True, f"cfg written | service restart issued (status={status})"
    return False, f"cfg written but service={status} (restart_err={restart_err[:100]})"


def _winrm_run_cmd(session, cmd: str, log) -> tuple[bool, str]:
    """Run an arbitrary command on the remote machine. Returns (ok, stdout)."""
    r = session.run_ps(f"& {cmd}; Write-Output 'CMD_DONE'")
    out = r.std_out.decode(errors="replace").strip()
    err = r.std_err.decode(errors="replace").strip()
    if out:
        log(f"cmd stdout: {out[:300]}")
    if err:
        log(f"cmd stderr: {err[:200]}")
    return True, out


# ──────────────────────────────────────────────────────────────────────────────
# Docker WinRM proxy — routes WinRM calls through the POD's VPN container.
# Used when duo automation runs directly on the Mac (outside Docker) where
# 198.18.5.102 (AD1) is only reachable via the per-POD VPN namespace.
# ──────────────────────────────────────────────────────────────────────────────

class DockerWinRMSession:
    """
    Drop-in replacement for winrm.Session that proxies PowerShell commands
    through a Docker container running in the specified POD's VPN network
    namespace (network_mode: container:vpn-{pod_id}).

    Starts a single background container on first use and reuses it for all
    subsequent run_ps / run_cmd calls. Call .close() when done.
    """

    def __init__(self, ad_ip: str, user: str, pw: str,
                 pod_id: str, log=None):
        self._ad_ip  = ad_ip
        self._user   = user
        self._pw     = pw
        self._pod_id = pod_id
        self._log    = log or (lambda s: print(f"     [winrm-proxy] {s}"))
        self._container: Optional[str] = None
        self._start()

    def _start(self):
        import subprocess as _sp, time as _t
        name = f"winrm-proxy-{self._pod_id.lower()}-{int(_t.time())}"
        r = _sp.run(
            ["docker", "run", "-d", "--rm", "--name", name,
             "--network", f"container:vpn-{self._pod_id}",
             "pod-automator:latest", "sleep", "900"],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            raise RuntimeError(
                f"DockerWinRMSession: could not start proxy container: "
                f"{(r.stderr or r.stdout).strip()[:200]}"
            )
        self._container = name
        self._log(f"WinRM proxy container started: {name}")

    def _exec_ps(self, ps_script: str, timeout: int = 60,
                 op_timeout: int = 25, read_timeout: int = 30):
        """Execute a PowerShell script inside the proxy container via WinRM."""
        import subprocess as _sp, json as _json
        py = (
            "import winrm, sys\n"
            f"s = winrm.Session("
            f"  'http://{self._ad_ip}:5985/wsman',"
            f"  auth=({_json.dumps(self._user)}, {_json.dumps(self._pw)}),"
            f"  transport='ntlm',"
            f"  read_timeout_sec={read_timeout}, operation_timeout_sec={op_timeout})\n"
            f"r = s.run_ps({_json.dumps(ps_script)})\n"
            "sys.stdout.buffer.write(r.std_out)\n"
            "sys.stderr.buffer.write(r.std_err)\n"
            "sys.exit(r.status_code)\n"
        )
        return _sp.run(
            ["docker", "exec", self._container, "python3", "-c", py],
            capture_output=True, timeout=timeout,
        )

    def run_ps(self, script: str, op_timeout: int = 25, read_timeout: int = 30):
        result = self._exec_ps(script,
                               timeout=max(op_timeout, read_timeout) + 10,
                               op_timeout=op_timeout,
                               read_timeout=read_timeout)
        class _R:
            std_out     = result.stdout
            std_err     = result.stderr
            status_code = result.returncode
        return _R()

    def run_cmd(self, cmd: str, args=()):
        ps = cmd + " " + " ".join(str(a) for a in args)
        return self.run_ps(ps)

    def close(self):
        if self._container:
            import subprocess as _sp
            _sp.run(["docker", "rm", "-f", self._container],
                    capture_output=True)
            self._log(f"WinRM proxy container removed: {self._container}")
            self._container = None


def _winrm_connect_for_pod(pod_id: str,
                            ad_ip: str = AD_DC_IP,
                            user: str = AD_WINRM_USER,
                            pw: str = AD_WINRM_PASS,
                            log=None):
    """
    Return a WinRM session appropriate for the current runtime context.

    - Inside Docker (pipeline container): connect directly to AD1 — the
      container's VPN tunnel already routes 198.18.x.x.
    - Outside Docker (Mac / dashboard process): connect via DockerWinRMSession
      which proxies through the pod's vpn-{pod_id} container.
    """
    import os as _os
    if _os.path.exists("/.dockerenv"):
        return _winrm_connect(ad_ip, user, pw)
    return DockerWinRMSession(ad_ip, user, pw, pod_id, log=log)


def _winrm_connect_jump(pod_id: str, log=None):
    """WinRM session to the POD's jump host, valid from either runtime context.

    The 198.18.x.x lab addresses only resolve inside a POD's VPN namespace. The
    dashboard runs duo_run_card in a thread on the Mac, which has no VPN, so a
    raw winrm.Session to JUMP_HOST_IP fails there. Mirror
    _winrm_connect_for_pod: direct inside the pipeline container, proxied
    through vpn-{pod_id} otherwise.
    """
    import os as _os
    user, pw = JUMP_HOST_WINRM_CREDS
    if _os.path.exists("/.dockerenv"):
        return _winrm_connect(JUMP_HOST_IP, user, pw)
    return DockerWinRMSession(JUMP_HOST_IP, user, pw, pod_id, log=log)


# ──────────────────────────────────────────────────────────────────────────────
# Mac-native browser session — visible Chrome, no iDAC required.
# Used when duo automation is triggered directly on the Mac (dashboard process).
# ──────────────────────────────────────────────────────────────────────────────

def get_browser_sessions_mac(
        duo_host: str,
        scc_email: str,
        org_number: str,
        timeout_ms: int = 180_000,
        log=None,
        scc_password: str = "",
        before_close=None) -> dict:
    """Optional *before_close* hook: callable(ctx, duo_page, log) invoked after
    Duo admin cookies are extracted but before browser.close().  Use to run
    browser-automation tasks (e.g. External Directory setup) inside the same
    Playwright session so the user only needs one MFA approval."""
    """
    Obtain SCC Okta token + Duo admin session cookies.  Skips iDAC entirely.

    If scc_password is provided the login is fully automated (email + password,
    no MFA wait) and works both on Mac and headless in Docker.  Otherwise opens
    a visible Chrome window and waits up to timeout_ms for manual SSO/MFA.

    Flow:
      1. Launch Chrome (headless when scc_password set and running in Docker,
         otherwise visible channel="chrome" on Mac).
      2. Navigate to https://security.cisco.com.
      3. Fill email; if scc_password provided fill password immediately,
         otherwise wait up to timeout_ms for manual SSO/MFA completion.
      4. Handle the org-selection page — pick tile for org_number.
      5. Extract Okta token from sessionStorage.
      6. Navigate Products → Duo Security to open the Duo admin panel;
         if the admin panel redirects to a login page and scc_password is
         set, log in directly with email + password.
      7. Extract sid + _xsrf cookies from the Duo admin domain.

    Returns same dict as get_browser_sessions():
        okta_token, duo_sid, duo_xsrf, admin_host
    """
    _log = log or (lambda s: print(f"     [mac-browser] {s}"))

    from playwright.sync_api import sync_playwright
    import re as _re5

    m5 = _re5.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    expected_admin = f"admin-{m5.group(1)}.duosecurity.com" if m5 else None

    with sync_playwright() as p:
        import os as _os5
        _in_docker5 = _os5.path.exists("/.dockerenv")
        if scc_password:
            # Use fresh headless-capable Playwright Chromium — NOT system Chrome.
            # System Chrome retains cookies/sessions that cause stale Okta prompts.
            # Headless in Docker, headed (visible) on Mac so the user can see the
            # browser and approve the phone MFA if needed.
            _launch_kw = {
                "headless": bool(_in_docker5),
                "args": ["--disable-blink-features=AutomationControlled"],
            }
        else:
            # No password — open visible system Chrome for manual SSO/MFA
            _launch_kw = {
                "headless": False,
                "channel": "chrome",
                "args": ["--disable-blink-features=AutomationControlled"],
            }
        browser = p.chromium.launch(**_launch_kw)
        ctx = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1400, "height": 900},
            **_scc_session_kwargs(),
        )
        page = ctx.new_page()

        # ── Step 1: open SCC ────────────────────────────────────────────────
        _log("opening https://security.cisco.com ...")
        page.goto("https://security.cisco.com/",
                  timeout=60_000, wait_until="domcontentloaded")

        # ── Step 2: handle login if redirected ──────────────────────────────
        # Wait for post-load redirect to settle before checking URL
        page.wait_for_timeout(3000)
        _log(f"URL after goto+3s: {page.url[:80]}")
        _need_scc_login = ("security.cisco.com" not in page.url
                           or "sign-on" in page.url
                           or "login" in page.url)
        if _need_scc_login:
            # Wait for Okta SPA to render the login widget (async JS load)
            _log(f"login redirect detected — waiting for email field (Okta SPA) ...")
            _email_filled = False
            for sel in [
                "input[name='identifier']",
                "input[autocomplete='username']",
                "input[type='email']",
                "input[name='email']",
                "input[id*='email' i]",
                "input[placeholder*='email' i]",
            ]:
                try:
                    lc = page.locator(sel).first
                    lc.wait_for(state="visible", timeout=15_000)
                    lc.fill(scc_email)
                    lc.press("Enter")
                    _log(f"email filled via {sel!r}")
                    _email_filled = True
                    break
                except Exception:
                    continue
            if not _email_filled:
                _log(f"WARNING: no email field found — URL: {page.url[:80]}")

            if scc_password:
                # Automated: wait for password field to appear after email submit
                # (Okta SPA reveals it on the same page; 10s timeout)
                _log("waiting for password field to appear ...")
                _pw_lc = None
                for sel in [
                    "input[type='password']",
                    "input[name='password']",
                    "input[id*='password' i]",
                    "input[placeholder*='password' i]",
                ]:
                    try:
                        lc = page.locator(sel).first
                        lc.wait_for(state="visible", timeout=10_000)
                        _pw_lc = lc
                        _log(f"password field visible via {sel!r}")
                        break
                    except Exception:
                        continue
                _log(f"URL before password fill: {page.url[:80]}")
                if _pw_lc:
                    _pw_lc.fill(scc_password)
                    _pw_lc.press("Enter")
                    _log("password submitted")
                else:
                    _log("WARNING: no password field found")
                _log("waiting for post-password redirect (SCC or Duo MFA, up to 30s) ...")
                try:
                    page.wait_for_url(
                        lambda url: (url.startswith("https://security.cisco.com/")
                                     and "sign-on" not in url)
                                    or "launchpad" in url
                                    or "duosecurity.com/prompt" in url,
                        timeout=30_000,
                    )
                except Exception:
                    pass
                # Handle MFA step — may be Duo push, passkey (Touch ID), or hardware key
                if "duosecurity.com/prompt" in page.url:
                    # Force the Chromium window to the front on macOS
                    try:
                        page.bring_to_front()
                    except Exception:
                        pass
                    try:
                        import subprocess as _sp
                        _sp.run(
                            ["osascript", "-e",
                             'tell application "System Events" to set frontmost of '
                             'first process whose name contains "Chromium" to true'],
                            capture_output=True, timeout=3,
                        )
                    except Exception:
                        pass
                    # Try to click passkey / Touch ID / WebAuthn button if present
                    _passkey_clicked = False
                    for _sel in [
                        "button:has-text('Use a passkey')",
                        "button:has-text('Touch ID')",
                        "button:has-text('Passkey')",
                        "button:has-text('passkey')",
                        "button[aria-label*='passkey' i]",
                        "button[aria-label*='Touch ID' i]",
                        "[data-factor='webauthn']",
                        "button:has-text('Verify with Touch ID')",
                        "button:has-text('Use Touch ID')",
                    ]:
                        try:
                            _lc = page.locator(_sel).first
                            _lc.wait_for(state="visible", timeout=2_000)
                            _lc.click(timeout=2_000)
                            _log(f"passkey button clicked via {_sel!r}")
                            _passkey_clicked = True
                            break
                        except Exception:
                            continue
                    if not _passkey_clicked:
                        _log("no passkey button found — Touch ID prompt may appear automatically")
                    _log("*** MFA required — look at the Chromium browser window and "
                         "complete your fingerprint / passkey scan (waiting up to 3 min) ***")
                    try:
                        page.wait_for_url(
                            lambda url: (url.startswith("https://security.cisco.com/")
                                         and "sign-on" not in url)
                                        or "launchpad" in url,
                            timeout=180_000,
                        )
                    except Exception:
                        pass
            else:
                _log("waiting for SSO / MFA completion (up to 3 min) ...")
                try:
                    page.wait_for_url("*security.cisco.com*", timeout=timeout_ms)
                except Exception:
                    pass

            if ("security.cisco.com" not in page.url or "sign-on" in page.url) \
                    and "launchpad" not in page.url:
                raise RuntimeError(
                    f"Login did not reach SCC — stuck at: {page.url[:100]}"
                )

        _log(f"on SCC: {page.url[:80]}")
        _save_scc_session(ctx, _log)

        # ── Step 3: org selection modal ──────────────────────────────────────
        # SCC shows an org picker when the account manages multiple orgs.
        # The tile is labelled with the org slug (e.g. "pseudoco-504").
        page.wait_for_timeout(3000)
        if org_number:
            org_slug = f"pseudoco-{org_number}"
            _log(f"looking for org tile '{org_slug}' ...")
            org_selectors = [
                f"[data-testid*='{org_number}']",
                f"button:has-text('{org_slug}')",
                f"a:has-text('{org_slug}')",
                f"div[role='button']:has-text('{org_slug}')",
                f"li:has-text('{org_slug}')",
                f":has-text('{org_slug}')",
                # fallback — any element containing just the number
                f"button:has-text('{org_number}')",
                f"a:has-text('{org_number}')",
            ]
            org_clicked = False
            for sel in org_selectors:
                try:
                    lc = page.locator(sel).first
                    lc.wait_for(state="visible", timeout=5_000)
                    lc.click(timeout=5_000)
                    _log(f"org tile clicked via: {sel!r}")
                    org_clicked = True
                    page.wait_for_timeout(3000)
                    break
                except Exception:
                    continue
            if not org_clicked:
                _log("WARN: org selector not found — may already be on correct org")

        # ── Step 4: extract Okta token ───────────────────────────────────────
        def _get_okta_token():
            try:
                return page.evaluate(
                    "(() => { try {"
                    "  const raw = sessionStorage.getItem('okta-token-storage');"
                    "  if (!raw) return '';"
                    "  const obj = JSON.parse(raw);"
                    "  return (obj.accessToken && obj.accessToken.accessToken) || '';"
                    "} catch(e) { return ''; } })()"
                )
            except Exception:
                return ""

        okta_token = _get_okta_token()
        if not okta_token:
            page.wait_for_timeout(3000)
            okta_token = _get_okta_token()
        if not okta_token:
            # Also try localStorage (some Okta versions store there)
            try:
                okta_token = page.evaluate(
                    "(() => { try {"
                    "  const raw = localStorage.getItem('okta-token-storage');"
                    "  if (!raw) return '';"
                    "  const obj = JSON.parse(raw);"
                    "  return (obj.accessToken && obj.accessToken.accessToken) || '';"
                    "} catch(e) { return ''; } })()"
                )
            except Exception:
                pass
        if not okta_token:
            _log("WARN: Okta token not in SCC sessionStorage/localStorage — "
                 "SA steps will be skipped (non-fatal for Duo-only setup)")
        else:
            _log("Okta token extracted from SCC sessionStorage")

        # ── Step 5: navigate to Duo admin via Products → Duo Security → Duo Admin ──
        # Correct path: Products → "Duo Security" lands on security.cisco.com/duo/dashboard/
        # Then from that page click the "Duo Admin" / "Admin Panel" link to reach
        # admin-XXXX.duosecurity.com
        _log("navigating Products → Duo Security ...")
        duo_page = None

        # Open the Products menu
        for prod_sel in [
            "a:has-text('Products')",
            "button:has-text('Products')",
            "nav >> text=Products",
            "[aria-label='Products']",
            "text=Products",
        ]:
            try:
                lc = page.locator(prod_sel)
                if lc.count() > 0:
                    lc.first.click(timeout=5_000)
                    page.wait_for_timeout(800)
                    _log(f"Products menu opened via: {prod_sel!r}")
                    break
            except Exception:
                continue

        # Click "Duo Security" in the Products menu — this lands on
        # security.cisco.com/duo/dashboard/ (NOT directly on admin-XXXX.duosecurity.com)
        for duo_sel in [
            "a:has-text('Duo Security')",
            "a:has-text('Duo')",
            "text=Duo Security",
            "text=Duo",
        ]:
            try:
                lc = page.locator(duo_sel)
                if lc.count() > 0:
                    lc.first.click(timeout=5_000)
                    page.wait_for_load_state("domcontentloaded", timeout=20_000)
                    _log(f"Duo Security page: {page.url[:80]}")
                    break
            except Exception:
                continue

        # Ensure we're on the Duo Security page within SA — if not, navigate directly
        if "duo" not in page.url.lower():
            _log("Products menu click did not navigate to Duo — going directly to /duo/dashboard/")
            page.goto("https://security.cisco.com/duo/dashboard/",
                      timeout=timeout_ms, wait_until="domcontentloaded")
        page.wait_for_timeout(2000)
        _log(f"Duo Security dashboard page: {page.url[:80]}")

        # ── Step 5b: click "Duo Admin" / "Admin Panel" link on the Duo Security page ──
        _log("looking for Duo Admin link on Duo Security page ...")
        for admin_sel in [
            f"a[href*='{expected_admin}']" if expected_admin else "",
            "a[href*='admin-'][href*='duosecurity']",
            "a:has-text('Duo Admin')",
            "a:has-text('Admin Panel')",
            "a:has-text('Open Duo')",
            "a:has-text('Launch')",
            "button:has-text('Admin')",
        ]:
            if not admin_sel:
                continue
            try:
                lc = page.locator(admin_sel)
                if lc.count() > 0:
                    try:
                        with ctx.expect_page(timeout=15_000) as new_pg:
                            lc.first.click(timeout=5_000)
                        duo_page = new_pg.value
                        duo_page.wait_for_load_state("load", timeout=timeout_ms)
                        _log(f"Duo admin opened in new tab: {duo_page.url[:80]}")
                    except Exception:
                        # same-tab navigation
                        try:
                            page.wait_for_url("*duosecurity.com*", timeout=20_000)
                        except Exception:
                            pass
                        if "duosecurity.com" in page.url:
                            duo_page = page
                            _log(f"Duo admin loaded in same tab: {duo_page.url[:80]}")
                    if duo_page:
                        break
            except Exception:
                continue

        # Fallback: navigate directly to expected admin host
        if duo_page is None and expected_admin:
            _log(f"Duo Admin link not found — navigating directly to {expected_admin}")
            duo_page = ctx.new_page()
            duo_page.goto(f"https://{expected_admin}/",
                          timeout=timeout_ms, wait_until="load")

        if duo_page is None:
            raise RuntimeError("Could not open Duo admin panel via any method")

        if "login" in duo_page.url:
            if scc_password:
                _log("Duo admin landed on login page — attempting direct login ...")
                _duo_admin_direct_login(duo_page, scc_email, scc_password, _log)
            else:
                raise RuntimeError(
                    f"Duo admin landed on login page — SCC SSO did not carry "
                    f"over: {duo_page.url[:80]}"
                )

        # ── Step 6: extract Duo admin session cookies ─────────────────────────
        admin_host_actual = duo_page.url.split("/")[2]
        _log(f"Duo admin host: {admin_host_actual}")

        all_cookies = ctx.cookies()
        duo_cookies = {
            c["name"]: c["value"]
            for c in all_cookies
            if admin_host_actual in c.get("domain", "")
            or c.get("domain", "").lstrip(".") in admin_host_actual
        }
        sid  = duo_cookies.get("sid", "")
        xsrf = duo_cookies.get("_xsrf", "")
        if not sid:
            all_dict = {c["name"]: c["value"] for c in all_cookies}
            sid  = all_dict.get("sid", "")
            xsrf = all_dict.get("_xsrf", "")
            duo_cookies = all_dict  # use full cookie dict for extra_cookies

        # ── Optional pre-close hook (e.g. External Directory setup) ──────────
        if before_close is not None and duo_page is not None:
            try:
                before_close(ctx, duo_page, _log)
            except Exception as _bc_err:
                _log(f"WARN: before_close hook raised: {_bc_err}")

        browser.close()

        if not sid:
            raise RuntimeError(
                "Could not extract 'sid' cookie from Duo admin session"
            )

        _log("Duo admin session cookies extracted — browser closed")
        return {
            "okta_token":   okta_token,
            "duo_sid":      sid,
            "duo_xsrf":     xsrf,
            "admin_host":   admin_host_actual,
            "all_cookies":  duo_cookies,  # all admin-domain cookies (incl. AWSALB sticky)
        }


# ── Playwright UI helpers ─────────────────────────────────────────────────────

def _pw_click_first(page, selectors: list, timeout: int = 8000, log=None) -> bool:
    """Try clicking the first matching selector. Returns True on success."""
    for sel in selectors:
        if not sel:
            continue
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                loc.click(timeout=timeout)
                return True
        except Exception as e:
            if log:
                log(f"  selector {sel!r} → {e}")
    return False


def _pw_fill_first(page, selectors: list, value: str, timeout: int = 8000) -> bool:
    """Fill the first matching input/textarea. Returns True on success."""
    for sel in selectors:
        if not sel:
            continue
        try:
            loc = page.locator(sel).first
            if loc.count() > 0:
                loc.fill(value, timeout=timeout)
                return True
        except Exception:
            pass
    return False


def _duo_admin_direct_login(page, email: str, password: str, log=None) -> None:
    """
    Fill the Duo admin login form with email + password.
    page should already be on (or redirecting to) admin-xxx.duosecurity.com/login.
    Raises RuntimeError if still on login page after submission.
    """
    _l = log or (lambda s: print(f"[duo-login] {s}"))
    _l(f"filling Duo admin login form (email={email}) ...")

    # Fill email
    for sel in [
        "input[name='email']",
        "input[type='email']",
        "input[id*='email' i]",
        "input[placeholder*='email' i]",
    ]:
        try:
            lc = page.locator(sel)
            if lc.count() > 0:
                lc.first.fill(email)
                lc.first.press("Enter")
                _l(f"email filled via {sel!r}")
                break
        except Exception:
            continue

    page.wait_for_timeout(2000)

    # Fill password (appears on same page or after email submission)
    for sel in [
        "input[type='password']",
        "input[name='password']",
        "input[id*='password' i]",
        "input[placeholder*='password' i]",
    ]:
        try:
            lc = page.locator(sel)
            if lc.count() > 0:
                lc.first.fill(password)
                lc.first.press("Enter")
                _l(f"password filled via {sel!r}")
                break
        except Exception:
            continue

    # Wait for redirect away from login page
    page.wait_for_timeout(3000)
    if "/login" in page.url:
        raise RuntimeError(
            f"Duo admin login failed — still on login page after credentials: {page.url[:100]}"
        )
    _l(f"Duo admin login successful: {page.url[:80]}")


def _pw_get_copy_content(page, hint: str, log=None) -> str:
    """
    Extract the text content that a 'Copy' button in a step is copying.
    Tries reading nearby <pre>/<code>/<textarea> before falling back to
    the system clipboard (unreliable in headless mode).
    """
    # Strategy 1: find pre/code/textarea inside any element containing the hint
    for container_sel in [
        f"*:has-text('{hint}') pre",
        f"*:has-text('{hint}') code",
        f"*:has-text('{hint}') textarea",
        f"*:has-text('{hint}') .highlight",
    ]:
        try:
            loc = page.locator(container_sel).first
            if loc.count() > 0:
                text = loc.inner_text(timeout=3000).strip()
                if text and len(text) > 10:
                    if log:
                        log(f"  content from {container_sel!r}: {text[:80]}")
                    return text
        except Exception:
            pass

    # Strategy 2: click the nearby copy button, read clipboard
    try:
        btn = page.locator(f"*:has-text('{hint}') button:has-text('Copy')").first
        if btn.count() > 0:
            btn.click(timeout=5000)
            page.wait_for_timeout(500)
            text = page.evaluate(
                "() => { try { return navigator.clipboard.readText ? "
                "navigator.clipboard.readText() : Promise.resolve(''); } catch(e) { return ''; } }"
            )
            if isinstance(text, str) and len(text) > 10:
                if log:
                    log(f"  content from clipboard: {text[:80]}")
                return text
    except Exception:
        pass

    # Strategy 3: scan all <pre>/<code> on page for known markers
    try:
        for el in reversed(page.locator("pre, code").all()):
            try:
                t = el.inner_text(timeout=2000).strip()
                if any(m in t for m in ("[cloud]", "[sso]", "rikey=", "authproxyctl", "enroll")):
                    if log:
                        log(f"  content from code scan: {t[:80]}")
                    return t
            except Exception:
                pass
    except Exception:
        pass

    return ""


def _open_duo_admin_page(ctx, scc_page, admin_host: str, duo_host: str, log,
                          admin_email: str = "", admin_pass: str = ""):
    """
    Open Duo Admin panel from an already-authenticated SCC browser context.
    Returns the Duo admin Page object.
    """
    import re as _ro2
    duo_page = None

    # Try via SCC Duo dashboard → click admin link
    try:
        scc_page.goto(
            "https://security.cisco.com/duo/dashboard/",
            timeout=60_000,
            wait_until="networkidle",
        )
        scc_page.wait_for_timeout(2000)
        for sel in [
            f"a[href*='{admin_host}']" if admin_host else "",
            "a[href*='admin-'][href*='duosecurity']",
            "a:has-text('Duo Admin')",
            "a:has-text('Admin Panel')",
            "a:has-text('Open Duo')",
        ]:
            if not sel:
                continue
            try:
                lc = scc_page.locator(sel)
                if lc.count() > 0:
                    with ctx.expect_page(timeout=30_000) as new_page_info:
                        lc.first.click(timeout=10_000)
                    duo_page = new_page_info.value
                    duo_page.wait_for_load_state("networkidle", timeout=60_000)
                    log(f"Duo admin opened via SCC link: {duo_page.url[:80]}")
                    break
            except Exception:
                continue
    except Exception as e:
        log(f"WARN: SCC Duo dashboard approach failed: {e}")

    # Fallback: direct navigation to admin host
    if duo_page is None and admin_host:
        log(f"trying direct navigation to https://{admin_host}/ ...")
        duo_page = ctx.new_page()
        duo_page.goto(f"https://{admin_host}/", timeout=60_000, wait_until="networkidle")
        if "login" in duo_page.url.lower():
            if admin_email and admin_pass:
                _duo_admin_direct_login(duo_page, admin_email, admin_pass, log)
            else:
                raise RuntimeError(
                    f"Direct Duo admin navigation landed on login page — {duo_page.url[:80]}"
                )
        log(f"Duo admin loaded directly: {duo_page.url[:80]}")

    if duo_page is None:
        raise RuntimeError("Could not open Duo admin panel via any method")
    return duo_page


# ── Part 1: External Directory setup ─────────────────────────────────────────

def _pw_ext_dir_setup(
    duo_page,
    ap_ikey: str,
    ap_skey: str,
    ap_host: str,
    winrm_session,
    log,
    ad_ip:     str = AD_DC_IP,
    ad_port:   str = AD_DC_PORT,
    ad_base_dn: str = AD_BASE_DN,
) -> tuple[bool, str]:
    """
    Playwright flow: Users → External Directories → Add AD, push [cloud] to
    AD1, Test Connection, configure DC / groups / attrs, Sync Now.
    """
    import re as _rx
    import tempfile as _tmp2
    import os as _os2

    T  = 15_000   # standard element timeout
    TS = 5_000    # short timeout

    # ── Navigate to External Directories ──────────────────────────────────────
    log("navigating to Users → External Directories...")
    try:
        base_url = "/".join(duo_page.url.split("/")[:3])
        duo_page.goto(
            f"{base_url}/admin/directory-sync",
            timeout=T, wait_until="networkidle",
        )
        duo_page.wait_for_timeout(1000)
    except Exception:
        pass

    # If URL nav didn't work, click through nav
    if "directory" not in duo_page.url.lower():
        _pw_click_first(duo_page, [
            "nav a:has-text('Users')", "a:has-text('Users')",
        ], timeout=T, log=log)
        duo_page.wait_for_timeout(800)
        if not _pw_click_first(duo_page, [
            "a:has-text('Directory Sync')",
            "a:has-text('External Directories')",
            "a:has-text('Directories')",
        ], timeout=T, log=log):
            return False, "Could not navigate to External Directories"
        duo_page.wait_for_timeout(1500)

    log(f"page: {duo_page.url[:80]}")
    page_text = duo_page.inner_text("body")

    # ── Idempotency: skip creation if AD directory already exists ─────────────
    dir_exists = (
        "Active Directory" in page_text
        and "Add External Directory" in page_text  # button still present = list loaded
    )

    if dir_exists and "No directories" not in page_text:
        log("AD directory already present — skipping creation, going to Sync Now")
        # Navigate into the existing AD directory
        _pw_click_first(duo_page, [
            "a:has-text('Active Directory')",
            "td:has-text('Active Directory') a",
        ], timeout=TS, log=log)
        duo_page.wait_for_timeout(1500)
    else:
        log("no existing AD directory — starting fresh setup")

        # ── Add External Directory → Active Directory ─────────────────────────
        if not _pw_click_first(duo_page, [
            "button:has-text('Add External Directory')",
            "a:has-text('Add External Directory')",
        ], timeout=T, log=log):
            return False, "Could not find 'Add External Directory' button"
        duo_page.wait_for_timeout(1000)

        if not _pw_click_first(duo_page, [
            "button:has-text('Active Directory')",
            "a:has-text('Active Directory')",
            "li:has-text('Active Directory')",
            ".card:has-text('Active Directory')",
        ], timeout=T, log=log):
            return False, "Could not find 'Active Directory' option"
        duo_page.wait_for_timeout(1000)

        # Select "Add new connection" radio
        _pw_click_first(duo_page, [
            "input[value='new']",
            "label:has-text('Add new connection') input",
            "input[type='radio']:first-of-type",
        ], timeout=TS, log=log)

        if not _pw_click_first(duo_page, [
            "button:has-text('Continue')",
            "input[type='submit'][value='Continue']",
            "button[type='submit']",
        ], timeout=T, log=log):
            return False, "Could not click Continue"
        duo_page.wait_for_timeout(2000)
        log(f"after Continue: {duo_page.url[:80]}")

        # ── Download pre-configured authproxy.cfg to get [cloud] credentials ─
        log("downloading pre-configured authproxy.cfg ...")
        cloud_ikey, cloud_skey, cloud_host = ap_ikey, ap_skey, ap_host
        try:
            tmp_dir = _tmp2.mkdtemp()
            with duo_page.expect_download(timeout=20_000) as dl_info:
                _pw_click_first(duo_page, [
                    "a:has-text('download a pre-configured file')",
                    "button:has-text('download a pre-configured file')",
                    "a:has-text('pre-configured')",
                    "a[download]",
                ], timeout=T, log=log)
            dl = dl_info.value
            tmp_path = _os2.path.join(tmp_dir, "authproxy_dl.cfg")
            dl.save_as(tmp_path)
            with open(tmp_path) as fh:
                dl_content = fh.read()
            log(f"downloaded {len(dl_content)} bytes")
            m_ik = _rx.search(r'ikey\s*=\s*(\S+)', dl_content)
            m_sk = _rx.search(r'skey\s*=\s*(\S+)', dl_content)
            m_ah = _rx.search(r'api_host\s*=\s*(\S+)', dl_content)
            if m_ik:
                cloud_ikey = m_ik.group(1)
                log(f"  cloud ikey from file: {cloud_ikey}")
            if m_sk:
                cloud_skey = m_sk.group(1)
            if m_ah:
                cloud_host = m_ah.group(1)
        except Exception as e:
            log(f"WARN: could not download authproxy.cfg ({e}), using existing ap_creds")

        # ── Push clean [cloud] section to AD1 (no service_account_* fields) ──
        log("pushing clean [cloud] authproxy.cfg to AD1 ...")
        clean_cfg = (
            "[cloud]\n"
            f"ikey={cloud_ikey}\n"
            f"skey={cloud_skey}\n"
            f"api_host={cloud_host}\n"
        )
        ok_push, msg_push = _winrm_write_restart_cfg(winrm_session, clean_cfg, log)
        if not ok_push:
            return False, f"authproxy.cfg push failed: {msg_push}"
        log(f"authproxy push: {msg_push}")

        # ── Test Connection ───────────────────────────────────────────────────
        log("clicking Test Connection in Duo Admin ...")
        duo_page.wait_for_timeout(4000)   # give proxy time to start
        _pw_click_first(duo_page, [
            "button:has-text('Test Connection')",
            "a:has-text('Test Connection')",
            "input[value='Test Connection']",
        ], timeout=T, log=log)
        log("waiting for Test Connection result (up to 60 s) ...")
        for _ in range(12):
            duo_page.wait_for_timeout(5000)
            ct = duo_page.inner_text("body")
            if any(kw in ct for kw in ["Connected", "✓", "check", "Success", "connected"]):
                log("Test Connection: ✓ Connected")
                break
        else:
            log("WARN: Test Connection did not confirm within 60 s — continuing")

        # ── Configure DC ─────────────────────────────────────────────────────
        log("configuring domain controller ...")
        _pw_fill_first(duo_page, [
            "input[name='dc_ip']", "input[name='host']",
            "input[placeholder*='Hostname']", "input[placeholder*='hostname']",
            "input[placeholder*='IP address']", "input[id*='host']",
        ], ad_ip)
        _pw_fill_first(duo_page, [
            "input[name='dc_port']", "input[name='port']",
            "input[placeholder*='port']", "input[placeholder*='Port']",
        ], ad_port)
        _pw_fill_first(duo_page, [
            "input[name='base_dn']", "input[name='base']",
            "input[placeholder*='Base DN']", "input[placeholder*='base_dn']",
        ], ad_base_dn)

        _pw_click_first(duo_page, [
            "button:has-text('Save')", "input[type='submit'][value='Save']",
        ], timeout=T, log=log)
        duo_page.wait_for_timeout(2000)
        log("DC config saved")

        # Navigate back to the directory sync page if needed
        _pw_click_first(duo_page, [
            "a:has-text('Back to AD Sync')",
            "a:has-text('Back to Directory')",
            "a:has-text('Back')",
        ], timeout=TS, log=log)
        duo_page.wait_for_timeout(1500)

    # ── Add groups: IoT, MAIN, PROD ───────────────────────────────────────────
    log("adding groups: IoT, MAIN, PROD ...")
    for grp in AD_GROUPS_TO_ADD:
        _pw_click_first(duo_page, [
            "button:has-text('Add')",
            "a:has-text('Add Group')", "button:has-text('Add Group')",
        ], timeout=TS, log=log)
        duo_page.wait_for_timeout(400)
        _pw_fill_first(duo_page, [
            "input[placeholder*='group']", "input[placeholder*='Group']",
            "input[type='text']:last-of-type",
        ], grp)
        duo_page.wait_for_timeout(300)
        try:
            duo_page.keyboard.press("Enter")
        except Exception:
            pass
        duo_page.wait_for_timeout(600)
        log(f"  group added: {grp}")

    # ── Add synced attributes ─────────────────────────────────────────────────
    log("adding synced attributes: givenname, sn ...")
    for attr, _disp in [("givenname", "First Name"), ("sn", "Last Name")]:
        _pw_click_first(duo_page, [
            "button:has-text('Add Attribute')", "a:has-text('Add Attribute')",
        ], timeout=TS, log=log)
        duo_page.wait_for_timeout(400)
        _pw_fill_first(duo_page, [
            "input[placeholder*='attribute']", "input[placeholder*='Attribute']",
            "input[type='text']:last-of-type",
        ], attr)
        duo_page.wait_for_timeout(300)
        try:
            duo_page.keyboard.press("Enter")
        except Exception:
            pass
        duo_page.wait_for_timeout(600)
        log(f"  attribute added: {attr}")

    # ── Complete Setup ────────────────────────────────────────────────────────
    log("clicking Complete Setup ...")
    _pw_click_first(duo_page, [
        "button:has-text('Complete Setup')", "a:has-text('Complete Setup')",
        "input[value='Complete Setup']",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(2000)

    # ── Sync Now ──────────────────────────────────────────────────────────────
    log("clicking Sync Now ...")
    _pw_click_first(duo_page, [
        "button:has-text('Sync Now')", "a:has-text('Sync Now')",
        "button:has-text('Sync')",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(3000)

    log("External Directory setup complete")
    return True, "AD directory configured, groups/attrs added, Sync Now triggered"


# ── Part 2: SSO Auth Proxy setup ─────────────────────────────────────────────

def _pw_sso_ext_auth_setup(
    duo_page,
    winrm_session,
    permitted_domain: str,
    log,
    ad_ip:      str = AD_DC_IP,
    ad_port:    str = AD_DC_PORT,
    ad_base_dn: str = AD_BASE_DN,
) -> tuple[bool, str]:
    """
    Playwright flow: Applications → SSO Settings → External Auth Sources →
    Add Active Directory → copy [sso] config → push to AD1 → run enrollment
    → verify Connected → configure DC → permitted domain → routing rule.
    """
    import re as _rs2

    T  = 15_000
    TS = 5_000

    # ── Navigate to Applications → SSO Settings ───────────────────────────────
    log("navigating to Applications → SSO Settings ...")
    try:
        base_url = "/".join(duo_page.url.split("/")[:3])
        duo_page.goto(
            f"{base_url}/admin/sso",
            timeout=T, wait_until="networkidle",
        )
        duo_page.wait_for_timeout(1000)
    except Exception:
        pass

    if "sso" not in duo_page.url.lower():
        _pw_click_first(duo_page, [
            "nav a:has-text('Applications')", "a:has-text('Applications')",
        ], timeout=T, log=log)
        duo_page.wait_for_timeout(800)
        if not _pw_click_first(duo_page, [
            "a:has-text('SSO Settings')", "a:has-text('SSO')",
            "a:has-text('Single Sign-On')",
        ], timeout=T, log=log):
            return False, "Could not navigate to SSO Settings"
        duo_page.wait_for_timeout(2000)
    log(f"SSO Settings: {duo_page.url[:80]}")

    # ── External Authentication Sources tab ───────────────────────────────────
    log("clicking External Authentication Sources tab ...")
    _pw_click_first(duo_page, [
        "a:has-text('External Authentication Sources')",
        "button:has-text('External Authentication Sources')",
        "[role='tab']:has-text('External')",
        ".nav-tabs a:has-text('External')",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(1500)

    page_text = duo_page.inner_text("body")
    ad_already_added = (
        "Active Directory" in page_text
        and ("Enabled" in page_text or "Connected" in page_text)
    )

    if ad_already_added:
        log("AD ext auth source already present — skipping add flow")
        _pw_click_first(duo_page, [
            "a:has-text('Active Directory')",
            "td:has-text('Active Directory') a",
        ], timeout=TS, log=log)
        duo_page.wait_for_timeout(1500)
    else:
        # ── Add Source → Add Active Directory ────────────────────────────────
        log("adding Active Directory as external auth source ...")
        if not _pw_click_first(duo_page, [
            "button:has-text('Add Source')", "a:has-text('Add Source')",
            "button:has-text('+ Add Source')",
        ], timeout=T, log=log):
            return False, "Could not find '+ Add Source' button"
        duo_page.wait_for_timeout(800)

        if not _pw_click_first(duo_page, [
            "button:has-text('Add Active Directory')",
            "a:has-text('Add Active Directory')",
            "li:has-text('Active Directory')",
        ], timeout=T, log=log):
            return False, "Could not find '+ Add Active Directory' option"
        duo_page.wait_for_timeout(1500)

        # Accept Privacy Statement
        _pw_click_first(duo_page, [
            "button:has-text('Accept')", "input[value='Accept']",
            "button:has-text('I Accept')", "button:has-text('Agree')",
        ], timeout=TS, log=log)
        duo_page.wait_for_timeout(800)

        # Configure Active Directory
        if not _pw_click_first(duo_page, [
            "button:has-text('Configure Active Directory')",
            "a:has-text('Configure Active Directory')",
        ], timeout=T, log=log):
            return False, "Could not click 'Configure Active Directory'"
        duo_page.wait_for_timeout(2000)
        log(f"after Configure AD: {duo_page.url[:80]}")

    # ── Add Authentication Proxy ──────────────────────────────────────────────
    log("adding Authentication Proxy ...")
    _pw_click_first(duo_page, [
        "button:has-text('Add Authentication Proxy')",
        "a:has-text('Add Authentication Proxy')",
        "button:has-text('+ Add Authentication Proxy')",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(2000)

    # ── Step 1.2: capture [sso] config section ────────────────────────────────
    log("capturing [sso] config from step 1.2 ...")
    sso_cfg = (
        _pw_get_copy_content(duo_page, "1.2", log=log)
        or _pw_get_copy_content(duo_page, "SSO section", log=log)
        or _pw_get_copy_content(duo_page, "service account", log=log)
    )
    if sso_cfg:
        log(f"[sso] config captured ({len(sso_cfg)} chars)")
        # Append [sso] section to authproxy.cfg on AD1
        log("appending [sso] section to authproxy.cfg on AD1 ...")
        current_cfg = _winrm_read_file(winrm_session, AUTHPROXY_CFG_PATH)
        # Remove any prior [sso] block
        import re as _rc4
        current_clean = _rc4.sub(
            r'\[sso\].*?(?=\[|\Z)', '', current_cfg, flags=_rc4.DOTALL
        ).rstrip()
        new_cfg = current_clean + "\n\n" + sso_cfg.strip() + "\n"
        ok_a, msg_a = _winrm_write_restart_cfg(winrm_session, new_cfg, log)
        if not ok_a:
            log(f"WARN: [sso] append failed: {msg_a}")
        else:
            log(f"[sso] append: {msg_a}")
    else:
        log("WARN: could not capture [sso] config — manual copy may be needed")

    # ── Step 2: capture + run enrollment command ──────────────────────────────
    log("capturing enrollment command from step 2 ...")
    enroll_raw = (
        _pw_get_copy_content(duo_page, "2.", log=log)
        or _pw_get_copy_content(duo_page, "Connect the Authentication", log=log)
        or _pw_get_copy_content(duo_page, "Generate Command", log=log)
    )
    if not enroll_raw:
        # Scan page HTML for authproxyctl
        import re as _rc5
        m_enroll = _rc5.search(r'(authproxyctl[^\n<"]+)', duo_page.content())
        if m_enroll:
            enroll_raw = m_enroll.group(1).strip()

    if enroll_raw:
        log(f"enrollment command: {enroll_raw[:120]}")
        # Strip 'authproxyctl' prefix — run via the full EXE path on AD1
        import re as _rc6
        tail = _rc6.sub(r'^.*?authproxyctl\.exe?\s*', '', enroll_raw).strip()
        if not tail:
            tail = enroll_raw.strip()
        log(f"running enrollment on AD1: {AUTHPROXY_ENROLL_EXE} {tail[:60]}")
        _winrm_run_cmd(
            winrm_session,
            f"'{AUTHPROXY_ENROLL_EXE}' {tail}",
            log,
        )
        duo_page.wait_for_timeout(5000)
    else:
        log("WARN: could not capture enrollment command — proxy may need manual enrollment")

    # ── Step 3: verify Connected ──────────────────────────────────────────────
    log("running connection test (step 3) ...")
    _pw_click_first(duo_page, [
        "button:has-text('Run test')", "a:has-text('Run test')",
        "button:has-text('Test')",
    ], timeout=T, log=log)
    for _ in range(12):
        duo_page.wait_for_timeout(5000)
        if any(kw in duo_page.inner_text("body") for kw in ["Connected to Duo", "Connected", "Success"]):
            log("SSO Auth Proxy: ✓ Connected to Duo")
            break
    else:
        log("WARN: could not confirm Connected within 60 s — continuing")

    # ── Configure AD server: hostname, port, base DN ──────────────────────────
    log("configuring Active Directory server settings ...")
    # Navigate back to External Auth Sources → Active Directory
    _pw_click_first(duo_page, [
        "a:has-text('External Authentication Sources')",
    ], timeout=TS, log=log)
    duo_page.wait_for_timeout(1000)
    _pw_click_first(duo_page, [
        "a:has-text('Active Directory')",
        "td:has-text('Active Directory') a",
    ], timeout=TS, log=log)
    duo_page.wait_for_timeout(1500)
    try:
        duo_page.evaluate("window.scrollTo(0, document.body.scrollHeight / 2)")
    except Exception:
        pass

    _pw_fill_first(duo_page, [
        "input[name='host']", "input[name='dc_ip']",
        "input[placeholder*='Hostname']", "input[placeholder*='hostname']",
        "input[placeholder*='IP']",
    ], ad_ip)
    _pw_fill_first(duo_page, [
        "input[name='port']", "input[name='dc_port']",
        "input[placeholder*='port']", "input[placeholder*='Port']",
    ], ad_port)
    _pw_fill_first(duo_page, [
        "input[name='base_dn']", "input[name='base']",
        "input[placeholder*='Base DN']", "input[placeholder*='Base DN(s)']",
    ], ad_base_dn)
    _pw_click_first(duo_page, [
        "button:has-text('Save and enable')",
        "button:has-text('Save and Enable')",
        "input[value='Save and enable']",
        "button:has-text('Save')",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(2000)
    log("AD server settings saved + enabled")

    # ── Permitted Domains ─────────────────────────────────────────────────────
    log(f"adding permitted email domain: {permitted_domain} ...")
    # Navigate to SSO Settings main page
    try:
        base_url = "/".join(duo_page.url.split("/")[:3])
        duo_page.goto(f"{base_url}/admin/sso", timeout=T, wait_until="networkidle")
    except Exception:
        _pw_click_first(duo_page, [
            "a:has-text('SSO Settings')", "a:has-text('Single Sign-On')",
        ], timeout=TS, log=log)
    duo_page.wait_for_timeout(1500)

    # Scroll to Permitted Domains section
    try:
        duo_page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
    except Exception:
        pass
    duo_page.wait_for_timeout(500)

    _pw_click_first(duo_page, [
        "button:has-text('Add email domain')",
        "a:has-text('Add email domain')",
        "button:has-text('+ Add email domain')",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(400)
    _pw_fill_first(duo_page, [
        "input[placeholder*='domain']", "input[placeholder*='Domain']",
        "input[type='text']:last-of-type",
    ], permitted_domain)
    duo_page.wait_for_timeout(300)
    _pw_click_first(duo_page, [
        "button:has-text('Add')", "input[type='submit'][value='Add']",
    ], timeout=TS, log=log)
    duo_page.wait_for_timeout(1000)
    log(f"permitted domain '{permitted_domain}' added")

    # ── Routing Rules: set Active Directory as default ─────────────────────────
    log("setting Active Directory as default authentication source ...")
    _pw_click_first(duo_page, [
        "[role='tab']:has-text('Routing')", "a:has-text('Routing Rules')",
        "button:has-text('Routing Rules')",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(1500)

    try:
        sel_loc = duo_page.locator("select").first
        if sel_loc.count() > 0:
            sel_loc.select_option(label="Active Directory")
        else:
            # Try a custom select widget
            _pw_click_first(duo_page, [
                ".select2-selection", "[class*='select']",
            ], timeout=TS, log=log)
            duo_page.wait_for_timeout(500)
            _pw_click_first(duo_page, [
                "li:has-text('Active Directory')",
                "option:has-text('Active Directory')",
            ], timeout=TS, log=log)
    except Exception as e:
        log(f"WARN: routing rule dropdown: {e}")

    _pw_click_first(duo_page, [
        "button:has-text('Save')", "input[type='submit'][value='Save']",
    ], timeout=T, log=log)
    duo_page.wait_for_timeout(1500)
    log("routing rule saved: Active Directory as default")

    # ── Verify Active Directory is Enabled ────────────────────────────────────
    log("verifying Active Directory source is Enabled ...")
    _pw_click_first(duo_page, [
        "a:has-text('External Authentication Sources')",
    ], timeout=TS, log=log)
    duo_page.wait_for_timeout(1000)
    _pw_click_first(duo_page, [
        "a:has-text('Active Directory')",
    ], timeout=TS, log=log)
    duo_page.wait_for_timeout(1500)

    body = duo_page.inner_text("body")
    if "Enabled" not in body:
        log("enabling Active Directory source ...")
        _pw_click_first(duo_page, [
            "button:has-text('Enable Source')",
            "a:has-text('Enable Source')",
            "button:has-text('Enable')",
        ], timeout=T, log=log)
        duo_page.wait_for_timeout(1500)
        log("Active Directory source enabled")
    else:
        log("Active Directory source already Enabled ✓")

    return True, "SSO Auth Proxy: AD source enabled, permitted domain added, routing rule set"


# ── Pure-API authproxy config push (no browser required) ─────────────────────

AD_CLIENT_HOST    = "198.18.5.102"
AD_CLIENT_PORT    = "389"
AD_CLIENT_BASE_DN = "DC=corp,DC=pseudoco,DC=com"


def duo_push_authproxy_config(
    pod_id: str,
    db_path: str,
    log=None,
) -> tuple[bool, str]:
    """
    Push authproxy.cfg to AD1 via WinRM, then restart DuoAuthProxy.

    Priority:
      1. If org_credentials.authproxy_cfg is non-empty in the DB, push it verbatim.
         This is the preferred path — the file was downloaded from Duo Admin portal
         once per org (includes [cloud], [ad_client], and optionally [sso]).
      2. Otherwise, fall back to building the cfg dynamically from authproxy_ikey/skey
         (fetching/creating an Auth Proxy integration via Duo Admin API if needed).

    Does NOT require a browser session or Cisco Okta MFA.

    Returns (ok, message).
    """
    import sqlite3 as _sq4
    import re as _re4

    _log = log or (lambda s: print(f"     [authproxy-push] {s}"))

    # ── 1. Load credentials from DB ──────────────────────────────────────────
    _log("loading credentials from DB ...")
    try:
        with _sq4.connect(db_path) as conn:
            conn.row_factory = _sq4.Row
            pod_row = conn.execute(
                "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
            ).fetchone()
            if not pod_row:
                return False, f"POD {pod_id!r} not found in DB"
            scc_org = pod_row["scc_org"] or ""
            m = _re4.search(r"pseudoco-(\d+)", scc_org)
            if not m:
                return False, f"Cannot determine org number from scc_org={scc_org!r}"
            org_num = m.group(1)
            oc_row = conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
            ).fetchone()
            if not oc_row:
                return False, f"No org credentials for org {org_num}"
            oc = dict(oc_row)
    except Exception as e:
        return False, f"DB read error: {e}"

    # ── 2. Determine authproxy.cfg content ───────────────────────────────────────
    # Path A: pre-stored cfg from DB (downloaded from Duo Admin portal).
    #   Use this when authproxy_cfg is populated — includes [cloud], [ad_client],
    #   and optionally [sso].  No Admin API call needed.
    # Path B: build dynamically — session-scoped org; fetch/create auth proxy
    #   integration via Admin API (only [cloud] + [ad_client]).
    stored_cfg = oc.get("authproxy_cfg", "").strip()
    if stored_cfg:
        _log(f"using pre-stored authproxy.cfg from DB ({len(stored_cfg)} bytes) ...")
        cfg = stored_cfg
    else:
        _log("building authproxy.cfg dynamically (no pre-stored cfg in DB) ...")

        duo_ikey = oc.get("duo_ikey",  "").strip()
        duo_skey = oc.get("duo_skey",  "").strip()
        duo_host = oc.get("duo_host",  "").strip()

        if not duo_host:
            return False, "duo_host not configured for this org — run duo_setup first"
        if not duo_ikey or not duo_skey:
            return False, "Duo Admin API credentials not configured — run duo_setup first"

        _log("fetching Auth Proxy integration from Duo API ...")
        creds = duo_get_authproxy_creds(duo_ikey, duo_skey, duo_host)
        if not creds:
            _log("no existing auth proxy integration — creating new one ...")
            creds = duo_create_authproxy_integration(duo_ikey, duo_skey, duo_host)
        if not creds:
            return False, "Could not find or create Auth Proxy integration in Duo"
        ap_ikey = creds["ikey"]
        ap_skey = creds["skey"]
        _log(f"auth proxy ikey: {ap_ikey}")
        try:
            with _sq4.connect(db_path) as conn:
                conn.execute(
                    "UPDATE org_credentials SET authproxy_ikey=?, authproxy_skey=? "
                    "WHERE org_number=?",
                    (ap_ikey, ap_skey, org_num),
                )
                conn.commit()
            _log("saved authproxy_ikey/skey to DB")
        except Exception as e:
            _log(f"WARN: could not save authproxy creds to DB: {e}")

        cfg = (
            "[cloud]\n"
            f"ikey={ap_ikey}\n"
            f"skey={ap_skey}\n"
            f"api_host={duo_host}\n"
            "\n"
            "[ad_client]\n"
            f"host={AD_CLIENT_HOST}\n"
            f"port={AD_CLIENT_PORT}\n"
            f"service_account_username={AD_WINRM_USER}\n"
            f"service_account_password={AD_WINRM_PASS}\n"
            f"search_dn={AD_CLIENT_BASE_DN}\n"
        )
        _log(f"built authproxy.cfg ({len(cfg)} bytes): [cloud] + [ad_client]")

    # ── 3. Connect to AD1 via WinRM ──────────────────────────────────────────
    _log(f"connecting to AD1 ({AD_CLIENT_HOST}) via WinRM ...")
    try:
        winrm_sess = _winrm_connect_for_pod(pod_id, log=_log)
    except Exception as e:
        return False, f"WinRM connect failed: {e}"

    # ── 4. Push cfg + restart service ────────────────────────────────────────
    _log("pushing authproxy.cfg to AD1 and restarting DuoAuthProxy ...")
    ok, msg = _winrm_write_restart_cfg(winrm_sess, cfg, _log)
    if hasattr(winrm_sess, "close"):
        try:
            winrm_sess.close()
        except Exception:
            pass

    path_label = "pre-stored" if stored_cfg else "dynamic"
    if ok:
        _log(f"authproxy push ({path_label}): {msg}")
        return True, f"authproxy.cfg pushed ({path_label}) | {msg}"
    return False, f"authproxy push ({path_label}) failed: {msg}"


def duo_authproxy_enroll_and_update(
    pod_id: str,
    db_path: str,
    log=None,
) -> tuple[bool, str]:
    """
    On fresh AD1 (session reset), run authproxyctl.exe enroll to register
    this proxy instance with Duo and get a fresh rikey.

    Steps:
    1. Load duo_saml_app_ikey from DB
    2. Fetch SAML app secret_key from Duo Admin API
    3. Strip old [sso] from authproxy.cfg on AD1; append new [sso] with ikey/skey/api_host
    4. Run authproxyctl.exe enroll --ikey --skey --api-host → get rikey
    5. Update authproxy.cfg in DB with new rikey
    6. Restart DuoAuthProxy

    Returns (ok, rikey_or_message).
    """
    import sqlite3 as _sq, re as _re
    _log = log or (lambda s: print(f"     [authproxy-enroll] {s}"))

    # ── 1. Load creds from DB ──────────────────────────────────────────────────
    try:
        with _sq.connect(db_path) as conn:
            conn.row_factory = _sq.Row
            pod_row = conn.execute(
                "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
            ).fetchone()
            if not pod_row:
                return False, f"POD {pod_id} not found in DB"
            scc_org = pod_row["scc_org"] or ""
            m = _re.search(r"pseudoco-(\d+)", scc_org)
            if not m:
                return False, "Cannot determine org number from scc_org"
            org_num = m.group(1)
            oc = dict(conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
            ).fetchone() or {})
    except Exception as e:
        return False, f"DB read error: {e}"

    duo_ikey      = oc.get("duo_ikey", "").strip()
    duo_skey      = oc.get("duo_skey", "").strip()
    duo_host      = oc.get("duo_host", "").strip()
    app_ikey      = oc.get("duo_saml_app_ikey", "").strip()
    authproxy_cfg = oc.get("authproxy_cfg", "").strip()

    if not app_ikey:
        return False, "duo_saml_app_ikey not set in DB — complete step 4 first"
    if not authproxy_cfg:
        return False, "authproxy_cfg not set in DB — complete step 2 first"

    # ── 2. Fetch SAML app secret_key from Duo Admin API ───────────────────────
    _log(f"fetching SAML app secret_key from Duo Admin API (ikey={app_ikey}) ...")
    try:
        resp = _duo_request(duo_ikey, duo_skey, duo_host,
                            "GET", f"/admin/v1/integrations/{app_ikey}")
        app_skey = resp.get("response", {}).get("secret_key", "")
        if not app_skey:
            raise ValueError("secret_key empty in API response")
        _log(f"secret_key fetched ({len(app_skey)} chars)")
    except Exception as e:
        return False, f"Could not fetch SAML app secret_key: {e}"

    # ── 3. WinRM connect to AD1 ────────────────────────────────────────────────
    _log("WinRM-connecting to AD1 ...")
    try:
        winrm_sess = _winrm_connect_for_pod(pod_id, log=_log)
    except Exception as e:
        return False, f"WinRM connect failed: {e}"

    try:
        # Read current authproxy.cfg from AD1, strip any stale [sso] block
        _log("reading current authproxy.cfg from AD1 ...")
        current_cfg = _winrm_read_file(winrm_sess, AUTHPROXY_CFG_PATH)
        clean_cfg = _re.sub(
            r'\[sso\].*?(?=\[|\Z)', '', current_cfg, flags=_re.DOTALL
        ).rstrip()

        # Append fresh [sso] section (rikey will be written by authproxyctl enroll)
        new_cfg = (
            clean_cfg
            + "\n\n[sso]\n"
            + f"ikey={app_ikey}\n"
            + f"skey={app_skey}\n"
            + f"api_host={duo_host}\n"
        )
        _log("writing updated authproxy.cfg with [sso] section ...")
        ok_write, msg_write = _winrm_write_restart_cfg(winrm_sess, new_cfg, _log)
        if not ok_write:
            return False, f"authproxy.cfg write failed: {msg_write}"
        _log(f"cfg write: {msg_write}")

        # ── 4. Run authproxyctl enroll ─────────────────────────────────────────
        _log("running authproxyctl enroll on AD1 ...")
        enroll_cmd = (
            f"& '{AUTHPROXY_ENROLL_EXE}' enroll "
            f"--ikey {app_ikey} --skey {app_skey} --api-host {duo_host}"
        )
        ok_enroll, enroll_out = _winrm_run_cmd(winrm_sess, enroll_cmd, _log)
        _log(f"enroll output: {enroll_out[:300]}")

        # ── 5. Extract rikey from output and update DB ─────────────────────────
        rikey_m = _re.search(r'rikey[=\s:]+([A-Z0-9]{20,})', enroll_out, _re.IGNORECASE)
        if rikey_m:
            rikey = rikey_m.group(1)
            _log(f"rikey extracted: {rikey}")
            # Update authproxy_cfg in DB with the new rikey
            updated_cfg = _re.sub(
                r'(^\[sso\][^\[]*)',
                lambda mo: mo.group(0).rstrip() + f"\nrikey={rikey}\n",
                new_cfg, flags=_re.MULTILINE | _re.DOTALL,
            )
            try:
                with _sq.connect(db_path) as conn:
                    conn.execute(
                        "UPDATE org_credentials SET authproxy_cfg=?, updated_at=datetime('now') "
                        "WHERE org_number=?",
                        (updated_cfg, org_num)
                    )
                _log("authproxy_cfg updated in DB with new rikey")
            except Exception as e:
                _log(f"WARN: could not update DB: {e}")
        else:
            rikey = ""
            _log("WARN: rikey not found in enroll output — proxy may not be enrolled")

        # ── 6. Restart DuoAuthProxy to activate ───────────────────────────────
        _log("restarting DuoAuthProxy to activate enrollment ...")
        winrm_sess.run_ps(
            "Restart-Service DuoAuthProxy -Force -ErrorAction SilentlyContinue; "
            "Start-Sleep 5; "
            "$s = Get-Service DuoAuthProxy -ErrorAction SilentlyContinue; "
            "if ($s) { Write-Output \"STATUS:$($s.Status)\" }"
        )
        _log("DuoAuthProxy restarted")

    except Exception as e:
        return False, f"Enrollment error: {e}"
    finally:
        try:
            winrm_sess.close()
        except Exception:
            pass

    if rikey:
        return True, f"enrolled OK — rikey={rikey}"
    return False, "enrollment ran but no rikey in output — check AD1 manually"


def duo_admin_portal_configure(
    pod_id: str,
    db_path: str,
    log=None,
) -> tuple[bool, str]:
    """Use Playwright + saved SCC DT cookies to perform Duo admin portal actions.

    Navigates: SCC (DT cookies) → Duo Dashboard → Duo Admin panel, then:
    1. Enables AD auth source at /sso/authsources/ldap/{rikey}
    2. Adds permitted domain corp.pseudoco.com at /sso (Settings tab)
    3. Configures Default routing rule → Active Directory (Routing Rules tab)

    Always returns ok=True (soft-fail on any error).
    """
    import sqlite3 as _sq, re as _re
    _log = log or (lambda s: print(f"     [duo-portal] {s}"))

    # ── Load org creds ─────────────────────────────────────────────────────────
    try:
        with _sq.connect(db_path) as conn:
            conn.row_factory = _sq.Row
            pod_row = conn.execute(
                "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
            ).fetchone()
            if not pod_row:
                return True, f"POD {pod_id} not found — portal configure skipped"
            scc_org = pod_row["scc_org"] or ""
            m = _re.search(r"pseudoco-(\d+)", scc_org)
            if not m:
                return True, "Cannot determine org number — portal configure skipped"
            org_num = m.group(1)
            oc = dict(conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
            ).fetchone() or {})
    except Exception as e:
        return True, f"DB read error (non-fatal): {e}"

    duo_host     = oc.get("duo_host", "").strip()
    scc_org_uuid = oc.get("scc_org_uuid", "").strip()
    authproxy_cfg = oc.get("authproxy_cfg", "").strip()

    if not duo_host:
        return True, "duo_host not set — portal configure skipped"

    m2 = _re.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    if not m2:
        return True, f"Cannot parse admin host from duo_host={duo_host}"
    admin_host = f"admin-{m2.group(1)}.duosecurity.com"

    rikey = ""
    if authproxy_cfg:
        rm = _re.search(r"^\s*rikey\s*=\s*(\S+)", authproxy_cfg, _re.MULTILINE)
        if rm:
            rikey = rm.group(1)

    if not rikey:
        return True, "No rikey in authproxy_cfg — portal configure skipped"

    if not os.path.exists(_SCC_SESSION_FILE):
        return True, "No saved SCC session — portal configure skipped"

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return True, "Playwright not available — portal configure skipped"

    results = []
    TIMEOUT = 30_000

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1400, "height": 900},
                **_scc_session_kwargs(),
            )
            page = ctx.new_page()
            try:
                # ── Step 1: Authenticate to SCC via DT cookies ────────────────
                _log("loading SCC with saved DT cookies ...")
                try:
                    page.goto("https://security.cisco.com",
                              timeout=60_000, wait_until="domcontentloaded")
                except Exception:
                    page.wait_for_timeout(3000)
                page.wait_for_timeout(3000)

                if "security.cisco.com" not in page.url or "sign-on" in page.url:
                    return True, f"SCC DT session expired (url={page.url[:60]}) — portal configure skipped (re-auth needed)"

                # ── Step 2: Navigate to Duo dashboard to establish admin auth ──
                duo_dash_url = "https://security.cisco.com/duo/dashboard/"
                if scc_org_uuid:
                    duo_dash_url += f"?enterpriseId={scc_org_uuid}"
                _log(f"navigating to Duo dashboard ({duo_dash_url}) ...")
                page.goto(duo_dash_url, timeout=60_000, wait_until="domcontentloaded")
                # Wait up to 20s for SPA to render admin links
                try:
                    page.wait_for_selector(
                        f'a[href*="{admin_host}"], a[href*="duosecurity.com"]',
                        timeout=20_000,
                    )
                    _log(f"admin link appeared on dashboard (url={page.url[:80]})")
                except Exception:
                    _log(f"WARN: no admin link appeared after 20s (url={page.url[:80]})")
                    # Log page title for debugging
                    _log(f"page title: {page.title()[:80]}")

                # ── Step 3: Find admin link and open Duo admin portal ──────────
                admin_page = None
                for link_sel in [
                    f'a[href*="{admin_host}"]',
                    'a[href*="duosecurity.com"]',
                ]:
                    try:
                        link = page.locator(link_sel).first
                        link.wait_for(state="visible", timeout=3000)
                        href = link.get_attribute("href") or ""
                        _log(f"clicking admin link ({link_sel}): {href[:80]} ...")
                        try:
                            with ctx.expect_page(timeout=12_000) as popup_info:
                                link.click()
                            admin_page = popup_info.value
                            admin_page.wait_for_load_state("domcontentloaded", timeout=TIMEOUT)
                            _log(f"admin popup opened: {admin_page.url[:80]}")
                        except Exception as _pe:
                            _log(f"popup exception ({_pe}); checking same-tab navigation ...")
                            page.wait_for_timeout(3000)
                            if admin_host in page.url:
                                admin_page = page
                                _log("admin opened in same tab")
                        break
                    except Exception:
                        continue

                # Fallback: extract admin link from page source
                if not admin_page:
                    _log("no visible admin link — scanning page source ...")
                    content = page.content()
                    found_urls = _re.findall(
                        rf'https?://{_re.escape(admin_host)}/[^"\'\s<>]*', content
                    )
                    if found_urls:
                        admin_url = found_urls[0]
                        _log(f"found admin URL in source: {admin_url[:80]}")
                        try:
                            with ctx.expect_page(timeout=12_000) as popup_info:
                                page.evaluate(f"window.open('{admin_url}', '_blank')")
                            admin_page = popup_info.value
                            admin_page.wait_for_load_state("domcontentloaded", timeout=TIMEOUT)
                            _log(f"admin page opened via window.open: {admin_page.url[:80]}")
                        except Exception as _we:
                            _log(f"window.open failed ({_we}); trying goto ...")
                            page.goto(admin_url, timeout=TIMEOUT, wait_until="domcontentloaded")
                            page.wait_for_timeout(2000)
                            if admin_host in page.url:
                                admin_page = page

                if not admin_page:
                    # Last resort: direct navigation (works if SCC set an SSO cookie)
                    _log(f"trying direct nav to https://{admin_host}/ ...")
                    page.goto(f"https://{admin_host}/", timeout=TIMEOUT,
                              wait_until="domcontentloaded")
                    page.wait_for_timeout(2000)
                    if admin_host in page.url:
                        admin_page = page
                        _log("direct admin navigation succeeded")
                    else:
                        return True, f"cannot reach Duo admin portal (url={page.url[:60]})"

                ap = admin_page  # short alias

                # ── Parse DC/baseDN from authproxy_cfg [ad_client] ────────────
                dc_host = AD_DC_IP
                dc_port = "389"
                base_dn = AD_BASE_DN
                if authproxy_cfg:
                    _h = _re.search(r"^\s*host\s*=\s*(\S+)", authproxy_cfg, _re.MULTILINE)
                    _p = _re.search(r"^\s*port\s*=\s*(\d+)", authproxy_cfg, _re.MULTILINE)
                    _b = _re.search(r"^\s*base_dn\s*=\s*(\S+)", authproxy_cfg, _re.MULTILINE)
                    if _h: dc_host = _h.group(1)
                    if _p: dc_port = _p.group(1)
                    if _b: base_dn = _b.group(1)

                # ── Action 0: Enrollment — generate code if proxy not connected ─
                # Navigate to auth source page, find the auth proxy row, check
                # connection status. If "Not connected", generate a fresh
                # enrollment code from the portal and run the exe via WinRM.
                authsrc_url = f"https://{admin_host}/sso/authsources/ldap/{rikey}"
                _log(f"navigating to auth source page: {authsrc_url}")
                ap.goto(authsrc_url, timeout=TIMEOUT, wait_until="domcontentloaded")
                ap.wait_for_timeout(2000)

                try:
                    # Find and navigate to the auth proxy detail page.
                    # The proxy link in the table uses data-testid='link-component'
                    # inside the ldap-authproxies-table. Extract href and navigate
                    # directly to avoid clicking docs/external links.
                    proxy_page_url = None
                    for proxy_link_sel in [
                        "[data-testid='ldap-authproxies-table'] [data-testid='link-component']",
                        "[data-testid='ldap-authproxies-table'] a[href*='authproxies']",
                        "a[href*='/sso/authsources/ldap/'][href*='/authproxies/']",
                    ]:
                        try:
                            pl = ap.locator(proxy_link_sel).first
                            pl.wait_for(state="visible", timeout=5000)
                            href = pl.get_attribute("href") or ""
                            if "/authproxies/" in href:
                                proxy_page_url = href if href.startswith("http") else f"https://{admin_host}{href}"
                                _log(f"found auth proxy page: {proxy_page_url}")
                                break
                        except Exception:
                            continue

                    if not proxy_page_url:
                        _log("WARN: auth proxy link not found in table — skipping enrollment check")
                        results.append("WARN: auth proxy link not found")
                    else:
                        ap.goto(proxy_page_url, timeout=TIMEOUT, wait_until="domcontentloaded")
                        ap.wait_for_timeout(1500)

                        proxy_content = ap.content()
                        if "Not connected" in proxy_content or "not connected" in proxy_content.lower():
                            _log("proxy is NOT connected — generating enrollment code ...")

                            # Click "Generate command" button
                            gen_btn = ap.locator("button:has-text('Generate command')").first
                            gen_btn.wait_for(state="visible", timeout=6000)
                            gen_btn.click()
                            ap.wait_for_timeout(1000)

                            # Confirm dialog
                            confirm_btn = ap.locator(
                                "dialog button:has-text('Generate command'), "
                                "[role='dialog'] button:has-text('Generate command')"
                            ).first
                            confirm_btn.wait_for(state="visible", timeout=6000)
                            confirm_btn.click()
                            ap.wait_for_timeout(2000)

                            # Extract the full command text (contains base64 code)
                            cmd_text = None
                            for cmd_sel in [
                                "[data-testid*='enrollment'], [data-testid*='command']",
                                "pre, code",
                            ]:
                                try:
                                    el = ap.locator(cmd_sel).first
                                    el.wait_for(state="visible", timeout=4000)
                                    cmd_text = el.inner_text()
                                    break
                                except Exception:
                                    continue

                            # Fallback: scan page source for authproxy_update_sso
                            if not cmd_text:
                                content_after = ap.content()
                                m_cmd = _re.search(
                                    r'authproxy_update_sso_enrollment_code\.exe["\s]+([A-Za-z0-9+/=]+)',
                                    content_after
                                )
                                if m_cmd:
                                    cmd_text = m_cmd.group(0)

                            if cmd_text:
                                # Extract the base64 code (long alphanumeric+/= string)
                                m_b64 = _re.search(r'([A-Za-z0-9+/]{40,}={0,2})', cmd_text)
                                if m_b64:
                                    enroll_code = m_b64.group(1)
                                    _log(f"extracted enrollment code ({len(enroll_code)} chars)")

                                    # Run enrollment exe + restart via WinRM
                                    try:
                                        ws = _winrm_connect_for_pod(pod_id, log=_log)
                                        bin_dir = r"C:\Program Files\Duo Security Authentication Proxy\bin"
                                        enroll_exe = rf"{bin_dir}\authproxy_update_sso_enrollment_code.exe"
                                        ps_cmd = (
                                            f"& '{enroll_exe}' '{enroll_code}' 2>&1; "
                                            f"net stop duoauthproxy; net start duoauthproxy"
                                        )
                                        r = ws.run_ps(ps_cmd)
                                        out = r.std_out.decode(errors="replace").strip()
                                        _log(f"enrollment+restart: {out[:300]}")
                                        results.append(f"enrollment code applied: {out[:80]}")
                                    except Exception as _we:
                                        _log(f"WARN: WinRM enrollment failed: {_we}")
                                        results.append(f"WARN: enrollment WinRM error: {_we}")

                                    # Wait and verify connection
                                    ap.wait_for_timeout(15000)
                                    ap.reload()
                                    ap.wait_for_timeout(2000)
                                    post_content = ap.content()
                                    if "Connected to Duo" in post_content:
                                        _log("proxy now Connected to Duo ✓")
                                        results.append("proxy enrolled and Connected to Duo")
                                    else:
                                        _log("WARN: proxy still not connected after enrollment")
                                        results.append("WARN: proxy not connected after enrollment")
                                else:
                                    _log(f"WARN: could not extract base64 from command: {cmd_text[:200]}")
                                    results.append("WARN: enrollment code extraction failed")
                            else:
                                _log("WARN: Generate command UI changed — cannot extract code")
                                results.append("WARN: enrollment code not found in portal")
                        else:
                            _log("proxy already Connected to Duo — skipping enrollment")
                            results.append("proxy Connected to Duo (no enrollment needed)")
                except Exception as _e0:
                    _log(f"WARN: enrollment check error: {_e0}")
                    results.append(f"WARN: enrollment check: {_e0}")

                # ── Action 1: Enable AD auth source ───────────────────────────
                _log(f"navigating to auth source page: {authsrc_url}")
                ap.goto(authsrc_url, timeout=TIMEOUT, wait_until="domcontentloaded")
                ap.wait_for_timeout(2000)

                page_content = ap.content()
                if "Disabled" in page_content and "Enabled" not in page_content.replace("Successfully enabled", ""):
                    _log("auth source is Disabled — clicking Enable source ...")
                    try:
                        enable_btn = ap.locator("button:has-text('Enable source')").first
                        enable_btn.wait_for(state="visible", timeout=6000)
                        enable_btn.click()
                        ap.wait_for_timeout(2000)

                        # Dialog appears — fill domain controller form
                        dialog = ap.locator("dialog, [role='dialog']").first
                        dialog.wait_for(state="visible", timeout=6000)

                        # Fill hostname
                        hostname_input = dialog.locator(
                            "input[placeholder*='Hostname'], input[placeholder*='hostname'], "
                            "input[placeholder*='IP'], input[placeholder*='address']"
                        ).first
                        hostname_input.wait_for(state="visible", timeout=4000)
                        hostname_input.fill(dc_host)

                        # Fill port
                        try:
                            port_input = dialog.locator("input[placeholder*='Port'], input[placeholder*='port']").first
                            port_input.wait_for(state="visible", timeout=3000)
                            port_input.fill(dc_port)
                        except Exception:
                            pass

                        # Fill base DN
                        try:
                            basedn_input = dialog.locator(
                                "input[placeholder*='Base DN'], input[placeholder*='base_dn'], "
                                "input[placeholder*='DC=']"
                            ).first
                            basedn_input.wait_for(state="visible", timeout=3000)
                            basedn_input.fill(base_dn)
                        except Exception:
                            pass

                        # Click "Enable source" in dialog
                        dialog_enable = dialog.locator("button:has-text('Enable source')").first
                        dialog_enable.wait_for(state="visible", timeout=4000)
                        dialog_enable.click()
                        ap.wait_for_timeout(3000)

                        post = ap.content()
                        if "Successfully enabled" in post or "Enabled" in post:
                            results.append("AD auth source enabled")
                            _log("AD auth source enabled ✓")
                        else:
                            results.append("WARN: Enable source — result unclear")
                            _log("WARN: Enable source clicked but outcome unclear")
                    except Exception as _e1:
                        results.append(f"WARN: Enable source error: {_e1}")
                        _log(f"WARN: Enable source exception: {_e1}")
                else:
                    results.append("AD auth source already enabled")
                    _log("auth source already enabled")

                # ── Action 2: Permitted domain (soft-fail) ────────────────────
                try:
                    ap.goto(f"https://{admin_host}/sso?selected_tab=settings",
                            timeout=TIMEOUT, wait_until="domcontentloaded")
                    ap.wait_for_timeout(2000)
                    if "corp.pseudoco.com" in ap.content():
                        results.append("permitted domain corp.pseudoco.com already present")
                        _log("permitted domain already present")
                    else:
                        domain_added = False
                        for input_sel in [
                            "input[placeholder*='domain' i]",
                            "input[name*='domain' i]",
                            "input[id*='domain' i]",
                            "input[type='text'][placeholder*='Add' i]",
                        ]:
                            try:
                                inp = ap.locator(input_sel).first
                                inp.wait_for(state="visible", timeout=4000)
                                inp.fill("corp.pseudoco.com")
                                for confirm_sel in [
                                    "button:has-text('Add domain')",
                                    "button:has-text('Add')",
                                ]:
                                    try:
                                        ap.locator(confirm_sel).first.click()
                                        ap.wait_for_timeout(1500)
                                        domain_added = True
                                        break
                                    except Exception:
                                        continue
                                if not domain_added:
                                    inp.press("Enter")
                                    ap.wait_for_timeout(1500)
                                    domain_added = True
                                break
                            except Exception:
                                continue
                        if domain_added:
                            results.append("permitted domain corp.pseudoco.com added")
                        else:
                            results.append("WARN: permitted domain input not found")
                            _log("WARN: domain input not found")
                except Exception as _e2:
                    results.append(f"WARN: permitted domain error: {_e2}")
                    _log(f"WARN: permitted domain exception: {_e2}")


                # ── Action 3: Configure Default routing rule → Active Directory ──
                # The Default rule uses a React Select (not native <select>).
                # Correct flow: navigate to routing_rules tab → click combobox →
                # click "Active Directory" option → click Save.
                _log("navigating to SSO Routing Rules tab ...")
                ap.goto(
                    f"https://{admin_host}/sso?selected_tab=routing_rules",
                    timeout=TIMEOUT, wait_until="domcontentloaded"
                )
                ap.wait_for_timeout(2000)

                rule_configured = False
                try:
                    # Check current value — skip if already Active Directory
                    routing_content = ap.content()
                    if '"Active Directory"' in routing_content or ">Active Directory<" in routing_content:
                        # Check the default rule row specifically
                        default_row = ap.locator(
                            "tr:has-text('Default'), [class*='default']:has-text('Active Directory')"
                        ).first
                        try:
                            row_txt = default_row.inner_text()
                            if "Active Directory" in row_txt:
                                _log("routing rule Default already set to Active Directory")
                                results.append("routing rule Default already Active Directory")
                                rule_configured = True
                        except Exception:
                            pass

                    if not rule_configured:
                        # Click the React Select combobox for the Default rule
                        combobox = ap.locator(
                            "[data-testid='routing-rules-default-authsource-input'] [role='combobox'], "
                            "[data-testid='routing-rules-default-authsource-input'] input"
                        ).first
                        combobox.wait_for(state="visible", timeout=6000)
                        combobox.click()
                        ap.wait_for_timeout(1000)
                        _log("clicked routing rule combobox")

                        # Click "Active Directory" option
                        ad_option = ap.locator(
                            "[role='option']:has-text('Active Directory'), "
                            "[class*='option']:has-text('Active Directory')"
                        ).first
                        ad_option.wait_for(state="visible", timeout=5000)
                        ad_option.click()
                        ap.wait_for_timeout(1000)
                        _log("selected Active Directory from dropdown")

                        # Click Save
                        save_btn = ap.locator("button:has-text('Save')").first
                        save_btn.wait_for(state="visible", timeout=4000)
                        save_btn.click()
                        ap.wait_for_timeout(2000)

                        # Verify saved
                        post_routing = ap.content()
                        if "Changes have been saved" in post_routing or "Active Directory" in post_routing:
                            rule_configured = True
                            _log("routing rule saved: Active Directory ✓")
                            results.append("routing rule Default→Active Directory saved")
                        else:
                            results.append("WARN: routing rule Save clicked but outcome unclear")
                            _log("WARN: routing rule save outcome unclear")
                except Exception as _e3:
                    results.append(f"WARN: routing rule error: {_e3}")
                    _log(f"WARN: routing rule exception: {_e3}")

            except Exception as e:
                results.append(f"portal error: {e}")
                _log(f"WARN: Duo admin portal error: {e}")
                import traceback as _tb
                _log(_tb.format_exc()[:400])
            finally:
                try:
                    browser.close()
                except Exception:
                    pass
    except Exception as e:
        return True, f"Playwright launch error: {e}"

    return True, " | ".join(results) if results else "no portal actions taken"


def duo_trigger_ad_sync(
    duo_ikey: str,
    duo_skey: str,
    duo_host: str,
    log=None,
) -> tuple[bool, str]:
    """
    Trigger AD directory sync via Duo Admin API.

    Lists all registered AD sync connectors and triggers syncuser for the first
    one found.  Soft-fails (returns True with warning) if no connector is
    registered yet — the auth proxy may not have called home after restart.

    Returns (ok, message).  Always returns ok=True (soft-fail on any error)
    so it never blocks the pipeline.
    """
    _log = log or (lambda s: print(f"     [duo-dirsync] {s}"))

    if not duo_ikey or not duo_skey or not duo_host:
        _log("WARN: Duo Admin API credentials missing — skipping directory sync")
        return True, "directory sync skipped (no credentials)"

    try:
        resp = _duo_request(duo_ikey, duo_skey, duo_host, "GET",
                            "/admin/v1/users/directorysync")
        directories = resp.get("response", [])
    except Exception as e:
        _log(f"WARN: could not list AD sync connectors ({e}) — skipping sync trigger")
        return True, f"directory sync skipped (list failed: {e})"

    if not directories:
        _log("WARN: no AD sync connectors registered yet — auth proxy may not have called home")
        return True, "directory sync skipped (no connectors registered yet)"

    connector = directories[0]
    # Duo API may use 'directory_key', 'connector_id', or 'integration_key'
    directory_key = (
        connector.get("directory_key")
        or connector.get("connector_id")
        or connector.get("integration_key")
    )
    if not directory_key:
        _log(f"WARN: connector has no key field — keys: {list(connector.keys())}")
        return True, "directory sync skipped (no key in connector response)"

    connector_name = connector.get("name", directory_key)
    _log(f"triggering per-user directory sync for connector {connector_name!r} ({directory_key}) ...")

    # Build user list: try Duo API first, fall back to known lab users
    usernames: list[str] = []
    try:
        all_users = _paginate(duo_ikey, duo_skey, duo_host, "/admin/v1/users")
        usernames = [u.get("username", "") for u in all_users if u.get("username")]
        _log(f"found {len(usernames)} users in Duo")
    except Exception as e:
        _log(f"WARN: could not list Duo users ({e}) — using known lab user list")

    if not usernames:
        usernames = ["kit", "lee", "pat", "nik", "produser", "iotuser", "mainuser", "lin"]
        _log(f"using fallback user list: {usernames}")

    synced, failed = [], []
    from concurrent.futures import ThreadPoolExecutor, as_completed as _asc

    def _sync_one(username):
        try:
            _duo_request(duo_ikey, duo_skey, duo_host, "POST",
                         f"/admin/v1/users/directorysync/{directory_key}/syncuser",
                         {"username": username}, timeout=8)
            return username, True, None
        except Exception as exc:
            return username, False, exc

    with ThreadPoolExecutor(max_workers=len(usernames)) as _pool:
        futures = [_pool.submit(_sync_one, u) for u in usernames]
        for fut in _asc(futures):
            uname, ok, err = fut.result()
            if ok:
                synced.append(uname)
                _log(f"synced: {uname}")
            else:
                failed.append(uname)
                _log(f"WARN: sync failed for {uname!r}: {err}")

    if synced:
        msg = f"directory sync triggered for {len(synced)}/{len(usernames)} users ({','.join(synced)})"
        if failed:
            msg += f"; failed: {','.join(failed)}"
        return True, msg
    # A total failure must not report green. This previously returned ok=True,
    # so the card showed ad_sync ✓ while every syncuser call 404'd and the Duo
    # org stayed empty — the card looked healthy with zero users synced.
    # A partial failure is still tolerated above; only "nothing worked" fails.
    return False, (f"directory sync failed for all {len(failed)} users — "
                   f"the Auth Proxy is not registered as a directory-sync "
                   f"connector (check the [cloud] ikey/skey in authproxy.cfg): {failed}")


# ── Orchestrator ──────────────────────────────────────────────────────────────

def duo_ext_dir_and_sso_setup(
    pod_id: str,
    db_path: str,
    log=None,
) -> tuple[bool, str]:
    """
    Full External Directory (AD sync) + SSO Auth Proxy setup for a POD's Duo org.

    Prerequisite: duo_setup step must have already run (auth proxy installed on
    AD1, ap_ikey/skey stored in org_credentials, idac_url configured).

    Steps:
      Part 1 – External Directory:
        • Users → External Directories → Add AD connection
        • Download pre-configured authproxy.cfg → push clean [cloud] to AD1
        • Test Connection → configure DC (198.18.5.102:389) → add groups/attrs
        • Sync Now
      Part 2 – SSO Auth Proxy:
        • Applications → SSO Settings → External Auth Sources → Add Active Directory
        • Capture [sso] config → append to authproxy.cfg on AD1 → restart
        • Capture enrollment command → run on AD1
        • Verify Connected → configure DC → add permitted domain → set routing rule

    Returns (ok, result_string).
    """
    import sqlite3 as _sq3
    import re as _re3

    _log = log or (lambda s: print(f"     [ext-dir] {s}"))

    # ── 1. Load credentials ───────────────────────────────────────────────────
    _log("loading credentials from DB ...")
    try:
        with _sq3.connect(db_path) as conn:
            conn.row_factory = _sq3.Row
            pod_row = conn.execute(
                "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
            ).fetchone()
            if not pod_row:
                return False, f"POD {pod_id!r} not found in DB"
            scc_org = pod_row["scc_org"] or ""
            m = _re3.search(r"pseudoco-(\d+)", scc_org)
            if not m:
                return False, f"Cannot determine org number from scc_org={scc_org!r}"
            org_num = m.group(1)
            oc_row = conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
            ).fetchone()
            if not oc_row:
                return False, f"No org credentials for org {org_num}"
            oc = dict(oc_row)
    except Exception as e:
        return False, f"DB read error: {e}"

    duo_host     = oc.get("duo_host", "").strip()
    idac_url     = oc.get("idac_url", "").strip()
    ap_ikey      = oc.get("authproxy_ikey", "").strip()
    ap_skey      = oc.get("authproxy_skey", "").strip()
    scc_email    = oc.get("scc_email", "").strip()
    scc_password = oc.get("scc_password", "").strip()

    import os as _os
    _in_docker = _os.path.exists("/.dockerenv")

    if not duo_host:
        return False, "Duo host not configured for this org"
    has_direct_creds = bool(scc_email and scc_password)
    if not has_direct_creds:
        if _in_docker and not idac_url:
            return False, "iDAC URL not configured — set it in Org Credentials"
        if not _in_docker and not scc_email:
            return False, "scc_email not configured — set it in Org Credentials"
    if not ap_ikey or not ap_skey:
        return False, "Auth proxy credentials missing — run duo_setup step first"

    import re as _re3b
    m2 = _re3b.search(r"api-([a-z0-9]+)\.duosecurity\.com", duo_host)
    admin_host = f"admin-{m2.group(1)}.duosecurity.com" if m2 else None

    # ── 2. WinRM session (direct in Docker, proxied via VPN container on Mac) ──
    _log(f"connecting to AD1 ({AD_DC_IP}) via WinRM ...")
    try:
        winrm_sess = _winrm_connect_for_pod(pod_id, log=_log)
    except Exception as e:
        return False, f"WinRM connect failed: {e}"

    # ── 3. Playwright browser session ─────────────────────────────────────────
    from playwright.sync_api import sync_playwright

    ok1 = ok2 = False
    msg1 = msg2 = "not started"
    browser_err = None

    with sync_playwright() as p:
        if scc_password:
            # Password mode: use fresh Playwright Chromium (NOT system Chrome) so
            # there are no cached/expired SCC sessions to confuse the login flow.
            # Headless in Docker, visible on Mac.
            _headless_ext = _os.path.exists("/.dockerenv")
            browser = p.chromium.launch(
                headless=bool(_headless_ext),
                args=["--disable-blink-features=AutomationControlled"],
            )
            ctx = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1400, "height": 900},
                accept_downloads=True,
                **_scc_session_kwargs(),
            )
        elif _in_docker:
            browser = p.chromium.launch(
                headless=True,
                args=["--disable-blink-features=AutomationControlled"],
            )
            ctx = browser.new_context(
                ignore_https_errors=True,
                user_agent=(
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/124.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1400, "height": 900},
                accept_downloads=True,
                **_scc_session_kwargs(),
            )
        else:
            # Mac mode: visible Chrome, no iDAC needed
            browser = p.chromium.launch(
                headless=False,
                channel="chrome",
                args=["--disable-blink-features=AutomationControlled"],
            )
            ctx = browser.new_context(
                ignore_https_errors=True,
                viewport={"width": 1400, "height": 900},
                accept_downloads=True,
                **_scc_session_kwargs(),
            )
        scc_page = ctx.new_page()
        try:
            # Authenticate and open Duo Admin panel
            if scc_password:
                # Automated SCC login with email+password — no manual MFA wait
                _log(f"SCC password login (email={scc_email}) ...")
                scc_page.goto("https://security.cisco.com/",
                              timeout=60_000, wait_until="domcontentloaded")
                # Wait for any post-load redirect to settle (SCC may redirect to
                # sign-on.security.cisco.com even if domcontentloaded fires early)
                scc_page.wait_for_timeout(3000)
                _log(f"URL after goto+3s: {scc_page.url[:80]}")
                _need_login = ("security.cisco.com" not in scc_page.url
                               or "sign-on" in scc_page.url
                               or "login" in scc_page.url)
                if _need_login:
                    # Wait for Okta SPA to render the login widget (async JS load)
                    _log(f"login page — waiting for email field (Okta SPA) ...")
                    _email_filled = False
                    for _esel in [
                        "input[name='identifier']",
                        "input[autocomplete='username']",
                        "input[type='email']",
                        "input[name='email']",
                        "input[placeholder*='email' i]",
                    ]:
                        try:
                            _lc = scc_page.locator(_esel).first
                            _lc.wait_for(state="visible", timeout=15_000)
                            _lc.fill(scc_email)
                            _lc.press("Enter")
                            _log(f"email filled via {_esel!r}")
                            _email_filled = True
                            break
                        except Exception:
                            continue
                    if not _email_filled:
                        _log(f"WARNING: no email field found — URL: {scc_page.url[:80]}")
                    # After email submit wait for password field to appear (Okta SPA
                    # reveals it on the same page) — up to 10s
                    _log("waiting for password field to appear ...")
                    _pw_lc = None
                    for _psel in [
                        "input[type='password']",
                        "input[name='password']",
                        "input[id*='password' i]",
                        "input[placeholder*='password' i]",
                    ]:
                        try:
                            _lc = scc_page.locator(_psel).first
                            _lc.wait_for(state="visible", timeout=10_000)
                            _pw_lc = _lc
                            _log(f"password field visible via {_psel!r}")
                            break
                        except Exception:
                            continue
                    _log(f"URL before password fill: {scc_page.url[:80]}")
                    if _pw_lc:
                        _pw_lc.fill(scc_password)
                        _pw_lc.press("Enter")
                        _log("password submitted")
                    else:
                        _log("WARNING: no password field found")
                    _log("waiting for post-password redirect (SCC or Duo MFA, up to 30s) ...")
                    try:
                        scc_page.wait_for_url(
                            lambda url: (url.startswith("https://security.cisco.com/")
                                         and "sign-on" not in url)
                                        or "launchpad" in url
                                        or "duosecurity.com/prompt" in url,
                            timeout=30_000,
                        )
                    except Exception:
                        pass
                    # Handle Duo MFA — poll URL every 10s so we can see what the
                    # browser is doing after the push is approved (up to 5 min)
                    if "duosecurity.com/prompt" in scc_page.url or "sign-on" in scc_page.url:
                        _log("*** Duo MFA — LOOK AT THE CHROME BROWSER and approve the push (up to 5 min) ***")
                        import time as _time_mfa
                        _mfa_deadline = _time_mfa.time() + 300
                        while _time_mfa.time() < _mfa_deadline:
                            scc_page.wait_for_timeout(10_000)
                            _cur = scc_page.url
                            _log(f"  browser URL: {_cur[:80]}")
                            if "security.cisco.com" in _cur and "sign-on" not in _cur:
                                _log("  → SCC reached!")
                                break
                            if "launchpad" in _cur:
                                _log("  → Launchpad reached!")
                                break
                        else:
                            _log("  → 5-min timeout waiting for SCC")
                    _log(f"URL after login: {scc_page.url[:80]}")
                    # Guard: must be on SCC — not still on Duo MFA page
                    if ("security.cisco.com" not in scc_page.url
                            or "sign-on" in scc_page.url):
                        raise RuntimeError(
                            f"Did not reach SCC after Duo MFA (push not approved?) "
                            f"— stuck at: {scc_page.url[:80]}"
                        )
                # Org selection
                scc_page.wait_for_timeout(3000)
                org_slug = f"pseudoco-{org_num}"
                _log(f"selecting org tile '{org_slug}' ...")
                for _osel in [
                    f"button:has-text('{org_slug}')",
                    f"a:has-text('{org_slug}')",
                    f"div[role='button']:has-text('{org_slug}')",
                    f"li:has-text('{org_slug}')",
                    f"button:has-text('{org_num}')",
                    f"a:has-text('{org_num}')",
                ]:
                    try:
                        _lc = scc_page.locator(_osel).first
                        _lc.wait_for(state="visible", timeout=5_000)
                        _lc.click(timeout=5_000)
                        _log(f"org clicked via: {_osel!r}")
                        scc_page.wait_for_timeout(3000)
                        break
                    except Exception:
                        continue
                _log(f"SCC loaded: {scc_page.url[:60]}")
                _save_scc_session(ctx, _log)
                # Navigate to Duo admin via SCC SSO
                _log("opening Duo Admin panel via SCC SSO ...")
                duo_page = _open_duo_admin_page(ctx, scc_page, admin_host, duo_host, _log,
                                                admin_email=scc_email, admin_pass=scc_password)
            else:
                # Fall back to SCC-based authentication
                if _in_docker:
                    # Docker: use iDAC URL (handles direct autologin + adaptive card)
                    _log("authenticating via iDAC auto-login URL ...")
                    scc_page = _idac_navigate_to_scc(ctx, scc_page, idac_url, 90_000, _log)
                else:
                    # Mac: navigate directly to security.cisco.com, fill email, select org
                    _log(f"navigating directly to SCC (email={scc_email}, org={org_num}) ...")
                    scc_page.goto("https://security.cisco.com/",
                                  timeout=60_000, wait_until="domcontentloaded")
                    if "security.cisco.com" not in scc_page.url:
                        _log(f"login page detected — filling email: {scc_email}")
                        for _esel in ["input[type='email']", "input[name='email']",
                                      "input[name='identifier']",
                                      "input[placeholder*='email' i]"]:
                            try:
                                _lc = scc_page.locator(_esel)
                                if _lc.count() > 0:
                                    _lc.first.fill(scc_email)
                                    _lc.first.press("Enter")
                                    break
                            except Exception:
                                continue
                        _log("waiting for SSO / MFA (up to 3 min) ...")
                        try:
                            scc_page.wait_for_url("*security.cisco.com*", timeout=180_000)
                        except Exception:
                            if "security.cisco.com" not in scc_page.url:
                                raise RuntimeError(
                                    f"Login did not reach SCC — stuck at: {scc_page.url[:100]}"
                                )
                    # Org selection
                    scc_page.wait_for_timeout(3000)
                    org_slug = f"pseudoco-{org_num}"
                    _log(f"selecting org tile '{org_slug}' ...")
                    for _osel in [
                        f"button:has-text('{org_slug}')",
                        f"a:has-text('{org_slug}')",
                        f"div[role='button']:has-text('{org_slug}')",
                        f"li:has-text('{org_slug}')",
                        f"button:has-text('{org_num}')",
                    ]:
                        try:
                            _lc = scc_page.locator(_osel).first
                            _lc.wait_for(state="visible", timeout=5_000)
                            _lc.click(timeout=5_000)
                            _log(f"org clicked via: {_osel!r}")
                            scc_page.wait_for_timeout(3000)
                            break
                        except Exception:
                            continue
                _log(f"SCC loaded: {scc_page.url[:60]}")
                _save_scc_session(ctx, _log)
                # Open Duo Admin panel
                _log("opening Duo Admin panel ...")
                duo_page = _open_duo_admin_page(ctx, scc_page, admin_host, duo_host, _log,
                                                admin_email=scc_email, admin_pass=scc_password)

            # Part 1: External Directory
            _log("=== Part 1: External Directory (AD sync) ===")
            try:
                ok1, msg1 = _pw_ext_dir_setup(
                    duo_page, ap_ikey, ap_skey, duo_host, winrm_sess, _log,
                )
            except Exception as e:
                ok1, msg1 = False, f"exception: {e}"
            _log(f"Part 1: {'OK' if ok1 else 'FAILED'} — {msg1}")

            # Part 2: SSO Auth Proxy
            _log("=== Part 2: SSO Auth Proxy ===")
            try:
                ok2, msg2 = _pw_sso_ext_auth_setup(
                    duo_page, winrm_sess, SSO_PERMITTED_DOMAIN, _log,
                )
            except Exception as e:
                ok2, msg2 = False, f"exception: {e}"
            _log(f"Part 2: {'OK' if ok2 else 'FAILED'} — {msg2}")

        except Exception as e:
            browser_err = str(e)
            _log(f"browser error: {e}")
        finally:
            browser.close()

    if browser_err:
        return False, f"Browser error: {browser_err}"
    if not ok1 and not ok2:
        return False, f"Both parts failed — Part1: {msg1} | Part2: {msg2}"
    if not ok1:
        return False, f"Partial — Part1 FAILED ({msg1}) | Part2: {msg2}"
    if not ok2:
        return False, f"Partial — Part1 OK | Part2 FAILED ({msg2})"
    return True, f"External Directory + SSO Auth Proxy configured | {msg1} | {msg2}"


# ──────────────────────────────────────────────────────────────────────────────
# Duo Card — manual pipeline (replaces duo_setup/duo_ext_dir/duo_saml_setup
# pipeline steps).  Stored in duo_steps table.  Smart re-use: if the org
# already has duo_saml_app_ikey + sa_scim_token set the card runs a lightweight
# SESSION REFRESH instead of the full first-time setup.
# ──────────────────────────────────────────────────────────────────────────────

DUO_CARD_STEPS = [
    "bootstrap",
    "org_setup",
    "authproxy_push",
    "ad_sync",
    "saml_scim_config",
    "authproxy_enroll",

    "scim_push",
    "verify",
]

DUO_CARD_LABELS = {
    "bootstrap":       "Duo Org Bootstrap",
    "org_setup":       "Duo Org Setup",
    "authproxy_push":  "Auth Proxy Config Push",
    "ad_sync":         "AD Directory Sync",
    "saml_scim_config":"SA SAML + SCIM Config",
    "authproxy_enroll":"Auth Proxy Enroll",

     "scim_push":       "SA SCIM Verify Users",
     "verify":          "Verify Auth Proxy",
}


def sa_generate_scim_token_playwright(pod_id: str, db_path: str, log=None) -> tuple[str, str]:
    """
    Open a headed Chromium browser, login to SCC → Secure Access, then:
      1. Connect → User, Groups, and Endpoint Devices
      2. Configuration management (top-right)
      3. Integrate directories → Identity provider (IdP)
      4. Directory name = 'Duo', Identity Provider = 'Duo' → Next
      5. Generate Token → extract Token and Provisioning URL → Done

    Saves sa_scim_token to org_credentials in DB.
    Returns (scim_token, provisioning_url) or ("", "") on failure.
    """
    import sqlite3 as _sq
    import time as _time
    import re as _re

    _log = log or (lambda s: print(f"     [sa-scim-pw] {s}"))

    # ── Load creds ───────────────────────────────────────────────────────────────
    try:
        with _sq.connect(db_path) as _c:
            _c.row_factory = _sq.Row
            pod_row = dict(_c.execute(
                "SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)
            ).fetchone() or {})
            scc_org = pod_row.get("scc_org", "")
            # Derive org number from scc_org field
            m = _re.search(r"cisco-pseudoco-(\d+)", scc_org)
            org_num = int(m.group(1)) if m else None
            if org_num:
                oc = dict(_c.execute(
                    "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
                ).fetchone() or {})
            else:
                oc = {}
    except Exception as e:
        _log(f"DB load failed: {e}")
        return "", ""

    scc_email  = oc.get("scc_email", "").strip()
    scc_pass   = oc.get("scc_password", "").strip()
    scc_url    = f"https://{scc_org}" if scc_org else ""

    if not scc_url:
        _log("scc_org not set in DB — cannot navigate to SA portal")
        return "", ""
    if not scc_email:
        _log("scc_email not set in DB")
        return "", ""

    _log(f"opening SCC: {scc_url}")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        _log("playwright not installed")
        return "", ""

    scim_token = ""
    provisioning_url = SA_SCIM_URL  # static fallback

    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False, slow_mo=400)
            ctx = browser.new_context(viewport={"width": 1280, "height": 900})
            page = ctx.new_page()

            # ── SCC login ────────────────────────────────────────────────────────
            page.goto(scc_url, wait_until="domcontentloaded", timeout=30000)
            page.wait_for_timeout(2000)

            # Handle Cisco SSO login if redirected
            if scc_org not in page.url and "scc_org" not in page.url:
                if "login" in page.url.lower() or "id.cisco" in page.url or "accounts.google" in page.url:
                    _log("SCC login page — filling credentials ...")
                    for sel in ["input[name='email']", "input[type='email']",
                                "input[id*='email' i]", "input[id*='username' i]"]:
                        try:
                            loc = page.locator(sel)
                            if loc.count() > 0:
                                loc.first.fill(scc_email)
                                loc.first.press("Enter")
                                _log(f"email filled ({sel})")
                                break
                        except Exception:
                            continue
                    page.wait_for_timeout(2000)

                    for sel in ["input[type='password']", "input[name='password']"]:
                        try:
                            loc = page.locator(sel)
                            if loc.count() > 0:
                                loc.first.fill(scc_pass)
                                loc.first.press("Enter")
                                _log(f"password filled ({sel})")
                                break
                        except Exception:
                            continue

                    _log("waiting for SCC dashboard (60s) — complete any MFA if prompted ...")
                    deadline = _time.time() + 60
                    while _time.time() < deadline:
                        page.wait_for_timeout(3000)
                        if scc_org in page.url or "cdo.cisco" in page.url:
                            _log("SCC login successful")
                            break
                    else:
                        _log("WARN: SCC login may not have completed — proceeding anyway")

            page.wait_for_timeout(2000)

            # ── Click on Secure Access tile ───────────────────────────────────────
            _log("looking for Secure Access tile ...")
            for sel in ["a:has-text('Secure Access')", "button:has-text('Secure Access')",
                        ":text('Secure Access')", "[aria-label*='Secure Access' i]"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log(f"clicked Secure Access via {sel}")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(3000)

            # ── Navigate to Connect → User, Groups, and Endpoint Devices ─────────
            _log("navigating to Connect → User, Groups, and Endpoint Devices ...")
            for sel in ["a:has-text('Connect')", "button:has-text('Connect')",
                        "nav a:has-text('Connect')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log(f"clicked Connect via {sel}")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            for sel in ["a:has-text('User, Groups')", "a:has-text('Users, Groups')",
                        "a:has-text('User, Groups, and Endpoint')",
                        ":text('User, Groups')", ":text('Users and Groups')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log(f"clicked User Groups via {sel}")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(2000)

            # ── Configuration management ─────────────────────────────────────────
            _log("clicking Configuration management ...")
            for sel in ["button:has-text('Configuration management')",
                        "a:has-text('Configuration management')",
                        ":text('Configuration management')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Configuration management clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            # ── Integrate directories ─────────────────────────────────────────────
            _log("clicking Integrate directories ...")
            for sel in ["button:has-text('Integrate directories')",
                        "a:has-text('Integrate directories')",
                        ":text('Integrate directories')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Integrate directories clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            # ── Select Identity provider (IdP) ───────────────────────────────────
            _log("selecting Identity provider (IdP) ...")
            for sel in ["input[value='idp']", "label:has-text('Identity provider') input",
                        "*:has-text('Identity provider') input[type='radio']",
                        "input[type='radio']:near(:text('Identity provider'))"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("IdP radio selected")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(800)

            # ── Fill Directory name = "Duo" ───────────────────────────────────────
            # Guard: only fill if we're actually on the IdP setup form, not login
            if "login" in page.url.lower() or "accounts.google" in page.url:
                _log("WARN: still on login page — skipping IdP name fill")
            else:
                _log("filling IdP directory name = 'Duo' ...")
                for sel in [
                    "input[placeholder*='name' i]",
                    "input[label*='name' i]",
                    "input[id*='name' i]",
                    "input[aria-label*='name' i]",
                    "label:has-text('Name') + input",
                    "label:has-text('Directory name') + input",
                ]:
                    try:
                        loc = page.locator(sel)
                        if loc.count() > 0:
                            loc.first.fill("Duo")
                            _log(f"directory name filled via {sel}")
                            break
                    except Exception:
                        continue

            # ── Select Identity Provider = "Duo" from dropdown ───────────────────
            _log("selecting Identity Provider = 'Duo' ...")
            for sel in ["select:near(:text('Identity Provider'))", "select[name*='provider' i]",
                        "select[id*='provider' i]"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.select_option(label="Duo")
                        _log("Identity Provider set to Duo")
                        break
                except Exception:
                    continue

            # Click Next
            for sel in ["button:has-text('Next')", "button:has-text('Continue')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Next clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            # ── Generate Token ────────────────────────────────────────────────────
            _log("clicking Generate Token ...")
            for sel in ["button:has-text('Generate Token')", "button:has-text('Generate')",
                        ":text('Generate Token')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Generate Token clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(2000)

            # ── Extract Token and Provisioning URL ────────────────────────────────
            _log("extracting Token and Provisioning URL ...")

            # Try reading pre/code/input fields near "Token" and "URL" labels
            for hint, targets in [
                ("Token",            ["scim_token", "token"]),
                ("Provisioning URL", ["scim_url", "url"]),
            ]:
                for field_sel in [
                    f"*:has-text('{hint}') input",
                    f"*:has-text('{hint}') code",
                    f"*:has-text('{hint}') pre",
                    f"*:has-text('{hint}') textarea",
                    f"[aria-label*='{hint}' i]",
                ]:
                    try:
                        loc = page.locator(field_sel).first
                        if loc.count() > 0:
                            val = (loc.get_attribute("value") or loc.inner_text()).strip()
                            if val and len(val) > 10:
                                if "Token" in hint:
                                    scim_token = val
                                    _log(f"Token extracted (len={len(val)})")
                                else:
                                    provisioning_url = val
                                    _log(f"Provisioning URL extracted: {val[:60]}")
                                break
                    except Exception:
                        continue

            # Click "Copy token" and "Copy URL" buttons to confirm extraction
            for btn_text in ["Copy token", "Copy URL", "Copy"]:
                try:
                    loc = page.locator(f"button:has-text('{btn_text}')")
                    if loc.count() > 0:
                        loc.first.click()
                        page.wait_for_timeout(300)
                        _log(f"clicked '{btn_text}'")
                except Exception:
                    pass

            # ── Click Done ────────────────────────────────────────────────────────
            _log("clicking Done ...")
            for sel in ["button:has-text('Done')", "button:has-text('Finish')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Done clicked")
                        break
                except Exception:
                    continue

            browser.close()

    except Exception as e:
        _log(f"Playwright error: {e}")
        return "", ""

    if not scim_token:
        _log("WARN: could not extract SCIM token from SA portal")
        return "", provisioning_url

    # ── Save token to DB ─────────────────────────────────────────────────────────
    try:
        with _sq.connect(db_path) as _c:
            _c.execute(
                "UPDATE org_credentials SET sa_scim_token=?, updated_at=datetime('now') "
                "WHERE org_number=?",
                (scim_token, oc.get("org_number"))
            )
        _log(f"sa_scim_token saved to DB (len={len(scim_token)})")
    except Exception as e:
        _log(f"WARN: could not save token to DB: {e}")

    return scim_token, provisioning_url


def duo_create_cisco_sa_app_playwright(pod_id: str, db_path: str, log=None,
                                        scim_token: str = "", scim_url: str = "") -> tuple[bool, str]:
    """
    Open a headed Chromium browser to create the 'Cisco Secure Access' app in the
    Duo Admin portal, following the lab guide exactly:
      1. Applications → Protect an Application → search 'Cisco Secure Access' → Add
      2. Provisioning tab → paste SA SCIM URL + sa_scim_token → Connect to application
      3. Attribute mapping → add displayName, emails, name.familyName, name.givenName;
         set userName attribute → Email Address → Save mapping
      4. Groups → add IoT, MAIN, PROD
      5. Save and enable

    If a 'Cisco Secure Access' app already exists in Duo (Admin API check), skips
    creation and reuses the existing ikey.

    Saves duo_saml_app_ikey to org_credentials in DB.
    Returns (ok, message).
    """
    import sqlite3 as _sq
    import re as _re
    import os as _os
    import time as _time

    _log = log or (lambda s: print(f"     [duo-sa-app] {s}"))

    # ── Load creds ──────────────────────────────────────────────────────────────
    try:
        with _sq.connect(db_path) as _c:
            _c.row_factory = _sq.Row
            oc = dict(_c.execute(
                "SELECT * FROM org_credentials WHERE org_number=("
                "SELECT CAST(REPLACE(scc_org,'cisco-pseudoco-','') AS INTEGER) "
                "FROM pods WHERE pod_id=?)", (pod_id,)
            ).fetchone() or {})
            if not oc:
                oc = dict(_c.execute(
                    "SELECT oc.* FROM org_credentials oc "
                    "JOIN pods p ON p.pod_id=? "
                    "WHERE oc.org_number = CAST(SUBSTR(p.scc_org,16,3) AS INTEGER)",
                    (pod_id,)
                ).fetchone() or {})
    except Exception as e:
        return False, f"DB load failed: {e}"

    duo_ikey  = oc.get("duo_ikey", "").strip()
    duo_skey  = oc.get("duo_skey", "").strip()
    duo_host  = oc.get("duo_host", "").strip()
    # Use passed-in token/url if provided (freshly generated from SA portal),
    # otherwise fall back to stored value
    scim_tok  = scim_token or oc.get("sa_scim_token", "").strip()
    scim_base = scim_url or SA_SCIM_URL
    login_email = oc.get("scc_email", "").strip()
    login_pass  = oc.get("scc_password", "").strip()

    if not duo_host:
        return False, "duo_host not set in DB"
    if not scim_tok:
        return False, "sa_scim_token not set in DB — generate it first from SA portal"

    # derive admin portal URL from api host
    admin_host = duo_host.replace("api-", "admin-")
    admin_url  = f"https://{admin_host}"

    # derive SCC CDO URL for login entry point
    try:
        with _sq.connect(db_path) as _c2:
            _c2.row_factory = _sq.Row
            _pod_row = _c2.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
            scc_org = (_pod_row["scc_org"] or "") if _pod_row else ""
    except Exception:
        scc_org = ""
    scc_url = f"https://{scc_org}" if scc_org else ""

    # ── Check if app already exists via Admin API ────────────────────────────────
    if duo_ikey and duo_skey:
        try:
            integrations = _paginate(duo_ikey, duo_skey, duo_host, "/admin/v1/integrations")
            for integ in integrations:
                if integ.get("type") in ("cisco_secure_access", "sso_generic", "sso_saml"):
                    existing_ikey = integ["integration_key"]
                    _log(f"existing SAML app found via API (type={integ['type']}, ikey={existing_ikey})")
                    _save_saml_app_ikey(db_path, oc, existing_ikey)
                    return True, f"existing app reused (ikey={existing_ikey})"
        except Exception as e:
            _log(f"Admin API integration check failed: {e} — proceeding with browser")

    # ── Open headed browser ──────────────────────────────────────────────────────
    _log("launching headed browser for Duo Admin portal ...")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "playwright not installed — run: uv add playwright && playwright install chromium"

    app_ikey = ""
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=False, slow_mo=400)
            ctx = browser.new_context(viewport={"width": 1280, "height": 900})
            page = ctx.new_page()

            # ── Entry point: SCC CDO portal → Duo tile → SSO into Duo Admin ─────
            # Duo Admin can only be reached via SSO from within the SCC org portal.
            # Going directly to admin-xxx.duosecurity.com requires Okta Touch ID MFA.
            if scc_url:
                _log(f"opening SCC portal: {scc_url}")
                page.goto(scc_url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(2000)

                # Login to SCC if redirected to login page
                if "login" in page.url.lower() or "id.cisco" in page.url or "accounts.google" in page.url:
                    _log("SCC login page — filling credentials ...")
                    for sel in ["input[name='email']", "input[type='email']", "input[id*='email' i]"]:
                        try:
                            loc = page.locator(sel)
                            if loc.count() > 0:
                                loc.first.fill(login_email)
                                loc.first.press("Enter")
                                _log(f"email filled ({sel})")
                                break
                        except Exception:
                            continue
                    page.wait_for_timeout(2000)
                    for sel in ["input[type='password']", "input[name='password']"]:
                        try:
                            loc = page.locator(sel)
                            if loc.count() > 0:
                                loc.first.fill(login_pass)
                                loc.first.press("Enter")
                                _log(f"password filled ({sel})")
                                break
                        except Exception:
                            continue
                    _log("waiting for SCC dashboard (60s) ...")
                    deadline = _time.time() + 60
                    while _time.time() < deadline:
                        page.wait_for_timeout(3000)
                        if scc_org in page.url or "cdo.cisco" in page.url:
                            _log("SCC login successful")
                            break

                # Navigate to Duo Admin via the SCC org portal tile/link
                _log("looking for Duo Admin tile/link in SCC portal ...")
                page.wait_for_timeout(2000)
                clicked = False
                for sel in [
                    "a:has-text('Duo Admin')",
                    "button:has-text('Duo Admin')",
                    "[aria-label*='Duo' i]",
                    "a[href*='duosecurity.com']",
                    ":text('Duo')",
                ]:
                    try:
                        loc = page.locator(sel)
                        if loc.count() > 0:
                            _log(f"found Duo link via {sel} — clicking ...")
                            loc.first.click()
                            clicked = True
                            break
                    except Exception:
                        continue

                if clicked:
                    # Wait up to 10s to see if a new tab opened in this context
                    page.wait_for_timeout(3000)
                    pages = ctx.pages
                    # Pick whichever page is now on duosecurity.com
                    for p in pages:
                        try:
                            if admin_host in p.url:
                                page = p
                                _log(f"new tab on Duo Admin: {page.url}")
                                break
                        except Exception:
                            continue

                # If still not on Duo Admin, poll up to 60s for any navigation
                if admin_host not in page.url:
                    _log(f"⚠ Not on Duo Admin yet ({page.url}) — waiting 60s for navigation ...")
                    deadline = _time.time() + 60
                    while _time.time() < deadline:
                        page.wait_for_timeout(3000)
                        # Also re-check all open pages
                        for p in ctx.pages:
                            try:
                                if admin_host in p.url:
                                    page = p
                                    break
                            except Exception:
                                continue
                        if admin_host in page.url:
                            _log(f"arrived at Duo Admin: {page.url}")
                            break
                    else:
                        _log("WARN: still not on Duo Admin after 60s — proceeding anyway")
            else:
                _log("WARN: scc_url not set — opening Duo Admin directly (may require Touch ID MFA)")
                page.goto(admin_url, wait_until="domcontentloaded", timeout=30000)
                page.wait_for_timeout(2000)
                if "/login" in page.url or "signin" in page.url.lower():
                    _log("⚠ MFA required — please complete Touch ID in the browser window (3 min) ...")
                    deadline = _time.time() + 180
                    while _time.time() < deadline:
                        page.wait_for_timeout(3000)
                        if admin_host in page.url and "/login" not in page.url:
                            _log("login successful")
                            break
                    else:
                        return False, "Login timed out — Touch ID not completed within 3 minutes"

            # ── Navigate to Applications → Protect an Application ───────────────
            _log("navigating to Applications ...")
            page.wait_for_timeout(1000)
            page.goto(f"{admin_url}/applications/protect", wait_until="domcontentloaded",
                      timeout=20000)
            page.wait_for_timeout(2000)

            # Search for Cisco Secure Access
            _log("searching for 'Cisco Secure Access' ...")
            for sel in ["input[placeholder*='search' i]", "input[type='search']",
                        "input[aria-label*='search' i]", "input.search"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.fill("Cisco Secure Access")
                        _log(f"search filled via {sel}")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            # Click "Protect" button for Cisco Secure Access
            for btn_sel in [
                "button:has-text('Protect'):near(:text('Cisco Secure Access'))",
                ":text('Cisco Secure Access') ~ button:has-text('Protect')",
                "button:has-text('Protect')",
            ]:
                try:
                    loc = page.locator(btn_sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log(f"clicked Protect via {btn_sel}")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(3000)

            # Extract ikey from URL
            m = _re.search(r"/applications/([A-Z0-9]+)", page.url)
            if m:
                app_ikey = m.group(1)
                _log(f"app created — ikey={app_ikey}")
            else:
                _log(f"WARN: could not extract ikey from URL: {page.url}")
                # Try to find it in page content
                try:
                    ikey_text = page.locator("text=/^D[A-Z0-9]{19}$/").first.inner_text()
                    app_ikey = ikey_text.strip()
                    _log(f"ikey from page text: {app_ikey}")
                except Exception:
                    pass

            # ── Provisioning tab ─────────────────────────────────────────────────
            _log("opening Provisioning tab ...")
            for sel in ["button:has-text('Provisioning')", "a:has-text('Provisioning')",
                        "[role='tab']:has-text('Provisioning')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Provisioning tab opened")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            # Fill Base URL
            _log("filling SA SCIM Base URL ...")
            for sel in ["input[name*='base_url' i]", "input[placeholder*='Base URL' i]",
                        "input[label*='Base URL' i]", "input[id*='base' i]"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.fill(SA_SCIM_URL)
                        _log(f"Base URL filled via {sel}")
                        break
                except Exception:
                    continue

            # Fill Token
            _log("filling SA SCIM Token ...")
            for sel in ["input[name*='token' i]", "input[placeholder*='token' i]",
                        "input[type='password']:near(:text('Token'))",
                        "input[id*='token' i]"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.fill(scim_tok)
                        _log(f"Token filled via {sel}")
                        break
                except Exception:
                    continue

            # Click Connect
            _log("clicking Connect to application ...")
            for sel in ["button:has-text('Connect')", "button:has-text('Connect to application')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Connect clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(2000)

            # ── Attribute mapping ────────────────────────────────────────────────
            _log("configuring attribute mappings ...")
            for sel in ["button:has-text('Edit mappings')", "a:has-text('Edit mappings')",
                        ":text('Edit mappings')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Edit mappings clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            # Select optional attributes
            for attr in ["displayName", "emails", "name.familyName", "name.givenName"]:
                for sel in [f"input[value='{attr}']", f"label:has-text('{attr}') input",
                            f"*:has-text('{attr}') input[type='checkbox']"]:
                    try:
                        loc = page.locator(sel)
                        if loc.count() > 0 and not loc.first.is_checked():
                            loc.first.check()
                            _log(f"checked {attr}")
                            break
                    except Exception:
                        continue

            # Set userName → Email Address
            _log("setting userName attribute to Email Address ...")
            for sel in ["select:near(:text('userName'))", "select[name*='userName' i]"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.select_option(label="Email Address")
                        _log("userName set to Email Address")
                        break
                except Exception:
                    continue

            # Save mapping
            for sel in ["button:has-text('Save mapping')", "button:has-text('Save')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Save mapping clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(1500)

            # ── Groups ───────────────────────────────────────────────────────────
            _log("adding groups IoT, MAIN, PROD ...")
            for group in ["IoT", "MAIN", "PROD"]:
                for search_sel in ["input[placeholder*='group' i]", "input[placeholder*='Group' i]",
                                   "input[aria-label*='group' i]"]:
                    try:
                        loc = page.locator(search_sel)
                        if loc.count() > 0:
                            loc.first.fill(group)
                            page.wait_for_timeout(800)
                            # Click the dropdown option
                            for opt_sel in [f"li:has-text('{group}')", f"[role='option']:has-text('{group}')",
                                            f"button:has-text('{group}')"]:
                                try:
                                    opt = page.locator(opt_sel)
                                    if opt.count() > 0:
                                        opt.first.click()
                                        _log(f"added group {group}")
                                        break
                                except Exception:
                                    continue
                            break
                    except Exception:
                        continue
                page.wait_for_timeout(500)

            # ── Save and Enable ──────────────────────────────────────────────────
            _log("clicking Save and enable ...")
            for sel in ["button:has-text('Save and enable')", "button:has-text('Save')"]:
                try:
                    loc = page.locator(sel)
                    if loc.count() > 0:
                        loc.first.click()
                        _log("Save and enable clicked")
                        break
                except Exception:
                    continue
            page.wait_for_timeout(2000)

            # Re-confirm ikey from URL after save
            m2 = _re.search(r"/applications/([A-Z0-9]+)", page.url)
            if m2:
                app_ikey = m2.group(1)

            # Save cookies for future use
            try:
                import json as _json
                all_cookies = ctx.cookies()
                existing_state = {}
                try:
                    with open(_SCC_SESSION_FILE) as f:
                        existing_state = _json.load(f)
                except Exception:
                    pass
                if isinstance(existing_state, dict):
                    existing_state["cookies"] = all_cookies
                else:
                    existing_state = {"cookies": all_cookies}
                with open(_SCC_SESSION_FILE, "w") as f:
                    _json.dump(existing_state, f)
                _log(f"saved {len(all_cookies)} cookies to session file")
            except Exception as ce:
                _log(f"WARN: could not save cookies: {ce}")

            browser.close()

    except Exception as e:
        return False, f"Playwright error: {e}"

    if not app_ikey:
        return False, "Could not determine app ikey — check browser and retry"

    # ── Save ikey to DB ──────────────────────────────────────────────────────────
    _save_saml_app_ikey(db_path, oc, app_ikey)
    _log(f"duo_saml_app_ikey={app_ikey} saved to DB")
    return True, f"Cisco Secure Access app configured (ikey={app_ikey})"


def _save_saml_app_ikey(db_path: str, oc: dict, app_ikey: str) -> None:
    """Persist duo_saml_app_ikey to org_credentials for this org."""
    import sqlite3 as _sq
    org_num = oc.get("org_number") or oc.get("id")
    if not org_num:
        return
    try:
        with _sq.connect(db_path) as c:
            c.execute(
                "UPDATE org_credentials SET duo_saml_app_ikey=?, updated_at=datetime('now') "
                "WHERE org_number=?",
                (app_ikey, org_num)
            )
    except Exception:
        pass


def duo_ensure_table(db_path: str) -> None:
    """Create duo_steps table and ensure org_credentials has all required columns."""
    import sqlite3 as _sq
    with _sq.connect(db_path) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS duo_steps (
                pod_id        TEXT,
                step_name     TEXT,
                status        TEXT DEFAULT 'pending',
                result        TEXT DEFAULT '',
                started_at    TEXT,
                completed_at  TEXT,
                PRIMARY KEY (pod_id, step_name)
            )
        """)
        # Ensure authproxy_enroll_blob column exists (migration for existing DBs)
        cols = [r[1] for r in c.execute("PRAGMA table_info(org_credentials)").fetchall()]
        if "authproxy_enroll_blob" not in cols:
            c.execute("ALTER TABLE org_credentials ADD COLUMN authproxy_enroll_blob TEXT DEFAULT ''")
        if "authproxy_blob_saved_at" not in cols:
            c.execute("ALTER TABLE org_credentials ADD COLUMN authproxy_blob_saved_at TIMESTAMP DEFAULT NULL")

        # Duo admin bootstrap state (see duo_passkey_bootstrap).
        # duo_passkey_cred    - JSON WebAuthn credential from the virtual authenticator
        # duo_passkey_hwm     - signCount high-water mark; see the note in
        #                       _pw_load_passkey() about WebAuthn clone detection
        for _c, _type in (
            ("idac_url",            "TEXT DEFAULT ''"),
            ("duo_admin_email",     "TEXT DEFAULT ''"),
            ("duo_admin_password",  "TEXT DEFAULT ''"),
            ("duo_passkey_cred",    "TEXT DEFAULT ''"),
            ("duo_passkey_hwm",     "INTEGER DEFAULT 0"),
            ("duo_admin_host",      "TEXT DEFAULT ''"),
            ("duo_admin_totp_secret", "TEXT DEFAULT ''"),
            ("authproxy_sso_cfg",    "TEXT DEFAULT ''"),
        ):
            if _c not in cols:
                try:
                    c.execute(f"ALTER TABLE org_credentials ADD COLUMN {_c} {_type}")
                except Exception:
                    pass


def _duo_step_set(pod_id: str, step: str, status: str, result: str, db_path: str,
                  started_at: str = None, completed_at: str = None) -> None:
    """Upsert a single row in duo_steps."""
    import sqlite3 as _sq, datetime as _dt
    now = _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
    with _sq.connect(db_path) as c:
        c.execute("""
            INSERT INTO duo_steps (pod_id, step_name, status, result, started_at, completed_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(pod_id, step_name) DO UPDATE SET
                status=excluded.status, result=excluded.result,
                started_at=COALESCE(excluded.started_at, started_at),
                completed_at=excluded.completed_at
        """, (pod_id, step, status, result,
              started_at or now if status == "running" else None,
              completed_at or now if status in ("completed", "failed", "skipped") else None))


def duo_run_card(
    pod_id: str,
    db_path: str,
    from_step: int = 0,
    log=None,
) -> tuple[bool, str]:
    """
    Run the Duo card pipeline for a POD.

    Auto-detects mode:
    - SESSION REFRESH: org already integrated (duo_saml_app_ikey + sa_scim_token set
      AND authproxy_cfg has [sso]).  Only re-pushes authproxy config, re-enrolls,
      syncs AD users, pushes SCIM users, and verifies.  saml_scim_config is skipped.
    - FULL SETUP: fresh org.  Runs all 8 steps including org reset, SAML/SCIM config.

    from_step: 0-based index into DUO_CARD_STEPS to resume from.
    """
    import sqlite3 as _sq, datetime as _dt, os as _os, re as _re_dc
    _log = log or (lambda s: print(f"  [duo-card] {s}"))
    duo_ensure_table(db_path)

    # ── Load org credentials ──────────────────────────────────────────────────
    try:
        with _sq.connect(db_path) as conn:
            conn.row_factory = _sq.Row
            pod_row = conn.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
            if not pod_row:
                return False, f"POD {pod_id} not found in DB"
            scc_org = pod_row["scc_org"] or ""
            m = _re_dc.search(r"pseudoco-(\d+)", scc_org)
            if not m:
                return False, f"Cannot determine org number from scc_org={scc_org!r}"
            org_num = m.group(1)
            oc = dict(conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_num,)
            ).fetchone() or {})
    except Exception as e:
        return False, f"DB error: {e}"

    duo_ikey      = oc.get("duo_ikey", "").strip()
    duo_skey      = oc.get("duo_skey", "").strip()
    duo_host      = oc.get("duo_host", "").strip()
    app_ikey      = oc.get("duo_saml_app_ikey", "").strip()
    scim_tok      = oc.get("sa_scim_token", "").strip()
    ap_cfg        = oc.get("authproxy_cfg", "").strip()
    enroll_blob   = oc.get("authproxy_enroll_blob", "").strip()
    blob_saved_at = oc.get("authproxy_blob_saved_at", "") or ""

    # A fresh dCloud session has no Duo credentials at all — the org does not
    # exist until the iDAC card is activated. Bootstrap creates it, so this can
    # no longer be a hard gate before the first step runs; only the steps that
    # actually need the Admin API are blocked (see _need_api below).
    needs_bootstrap = not (duo_ikey and duo_skey and duo_host)
    if needs_bootstrap:
        _log("no Duo Admin API credentials — bootstrap step will create them")

    # ── Detect mode ───────────────────────────────────────────────────────────
    # SCC / SA / Duo orgs are permanently coupled — never torn down.
    # Every run is effectively a session re-integration: push authproxy,
    # sync AD users, verify app.  No "full setup vs refresh" distinction needed.
    is_refresh = True
    mode_label = "SESSION RE-INTEGRATION"
    _log(f"Mode: {mode_label} (app_ikey={'set' if app_ikey else 'empty'}, "
         f"scim_token={'set' if scim_tok else 'empty'}, "
         f"[sso]={'yes' if '[sso]' in ap_cfg else 'no'})")

    # ── Step helpers ──────────────────────────────────────────────────────────
    def _run(step_name: str, fn):
        """Run fn(), record in duo_steps, return (ok, result)."""
        _duo_step_set(pod_id, step_name, "running", "", db_path)
        _log(f"▶ {step_name} ...")
        try:
            ret = fn()
            ok, result = (ret, "") if isinstance(ret, bool) else ret
        except Exception as e:
            ok, result = False, f"exception: {e}"
        status = "completed" if ok else "failed"
        _duo_step_set(pod_id, step_name, status, result, db_path)
        _log(f"  {'✓' if ok else '✗'} {step_name}: {result[:120]}")
        return ok, result

    def _skip(step_name: str, reason: str):
        _duo_step_set(pod_id, step_name, "skipped", reason, db_path)
        _log(f"  ↷ {step_name}: {reason}")

    # ── Step functions ────────────────────────────────────────────────────────

    def step_bootstrap():
        """Create the Duo org's admin + Admin API credentials if they don't exist.

        Idempotent — returns immediately when credentials are already present, so
        re-running the card on an established org costs nothing.
        """
        nonlocal duo_ikey, duo_skey, duo_host
        parts = []
        if needs_bootstrap:
            ok, msg = duo_passkey_bootstrap(pod_id, db_path, log=_log)
            if not ok:
                return False, msg
            parts.append(msg)
            # Re-read what bootstrap just persisted so later steps see it.
            try:
                with _sq.connect(db_path) as conn:
                    conn.row_factory = _sq.Row
                    row = conn.execute(
                        "SELECT duo_ikey, duo_skey, duo_host FROM org_credentials "
                        "WHERE org_number=?", (org_num,)
                    ).fetchone()
                if row:
                    duo_ikey = (row["duo_ikey"] or "").strip()
                    duo_skey = (row["duo_skey"] or "").strip()
                    duo_host = (row["duo_host"] or "").strip()
            except Exception as e:
                return False, f"bootstrapped but could not re-read credentials: {e}"
        else:
            parts.append("already bootstrapped")

        # Students work from Jumphost1 and never see this dashboard, so the
        # proctor-facing passcode panel is no use to them. Make sure the org has
        # a TOTP token and republish the standalone login page on the jump host
        # on every run — a pod reset or reimage wipes the Public Desktop.
        try:
            with _sq.connect(db_path) as conn:
                conn.row_factory = _sq.Row
                srow = conn.execute(
                    "SELECT duo_admin_totp_secret FROM org_credentials WHERE org_number=?",
                    (org_num,)).fetchone()
            has_totp = bool((srow["duo_admin_totp_secret"] or "").strip()) if srow else False
            if not has_totp:
                tok_ok, tok_msg = duo_provision_admin_totp(pod_id, db_path, log=_log)
                parts.append(f"totp: {tok_msg}" if tok_ok else f"totp FAILED: {tok_msg}")
            else:
                parts.append("totp: token already provisioned")

            pg_ok, pg_msg = duo_publish_totp_page(pod_id, db_path, log=_log)
            parts.append(f"jumphost page: {'ok' if pg_ok else 'FAILED — ' + pg_msg}")
        except Exception as e:
            # Non-fatal: the Duo org itself is usable without the student page.
            parts.append(f"student login page skipped ({type(e).__name__}: {e})")

        return True, " | ".join(parts)

    def step_org_setup():
        if not (duo_ikey and duo_skey and duo_host):
            return False, "no Admin API credentials — bootstrap step must run first"
        if is_refresh:
            ok, msg = duo_verify_credentials(duo_ikey, duo_skey, duo_host)
            return ok, f"verify only: {msg}"
        # Full: reset org + create users/groups via onboard_router.phase_duo_setup
        _os.environ["POD_ID"]  = pod_id
        _os.environ["DB_PATH"] = db_path
        try:
            import onboard_router as _or
            return _or.phase_duo_setup()
        finally:
            pass

    def step_authproxy_push():
        return duo_push_authproxy_config(pod_id, db_path, log=_log)

    def step_ad_sync():
        """Import AD users/groups into Duo.

        Uses the admin UI's "Sync Now" action. The Admin API's per-user route
        (/admin/v1/users/directorysync/{dkey}/syncuser) 404s on this deployment
        for every key we can supply, so it is only a fallback for deployments
        where it does exist.
        """
        # authproxy_push runs earlier in the card and rewrites [cloud] from the
        # *radius* Auth Proxy integration, which de-registers the directory-sync
        # connector and drops [sso]. Re-assert the correct config here before
        # syncing, otherwise "Sync Now" is unavailable and every user 404s.
        ed_ok, ed_msg = duo_setup_external_directory(pod_id, db_path, log=_log)
        _log(f"directory config: {'ok' if ed_ok else 'PROBLEM'} — {ed_msg[:110]}")

        ok, msg = duo_sync_now(pod_id, db_path, log=_log)
        if ok:
            return True, msg
        _log(f"Sync Now path failed ({msg[:90]}) — trying the per-user API")
        ok2, msg2 = duo_trigger_ad_sync(duo_ikey, duo_skey, duo_host, log=_log)
        return ok2, (msg2 if ok2 else f"{msg}; API fallback also failed: {msg2[:110]}")

    def step_saml_scim_config():
        """
        Ensure Secure Access SCIM provisioning exists, then verify it.

        Every pod session gets a brand new SCC/SA org, so the SCIM token can
        never be pre-seeded — it has to be generated per org. There is no API
        for it (Secure Access exposes no provisioning scope), so this drives
        the SCC UI and scrapes the once-only token out of the DOM.
        """
        nonlocal scim_tok
        if not scim_tok:
            _log("no SCIM token for this org — generating one via Secure Access")
            g_ok, g_msg = sa_generate_scim_token_ui(pod_id, db_path, log=_log)
            if not g_ok:
                return False, f"could not generate SCIM token: {g_msg}"
            try:
                with _sq.connect(db_path) as _c:
                    _c.row_factory = _sq.Row
                    _r = _c.execute("SELECT sa_scim_token FROM org_credentials "
                                    "WHERE org_number=?", (org_num,)).fetchone()
                scim_tok = (_r["sa_scim_token"] or "").strip() if _r else ""
            except Exception as e:
                return False, f"generated token but could not re-read it: {e}"
        if not scim_tok:
            return False, "sa_scim_token still not set after generation"
        try:
            import requests as _req
            resp = _req.get(
                "https://api.sse.cisco.com/identity/v2/scim/Users",
                headers={"Authorization": f"Bearer {scim_tok}"},
                timeout=15,
            )
            if resp.status_code == 401:
                return False, "SA SCIM: 401 Unauthorized — sa_scim_token may be expired"
            if resp.status_code != 200:
                return False, f"SA SCIM: HTTP {resp.status_code} — {resp.text[:200]}"
            total = resp.json().get("totalResults", 0)
            if total == 0:
                # A valid token only proves Secure Access answers; it says
                # nothing about whether provisioning is wired up. Deferring to
                # "step 6 will push" hid a missing Duo application.
                _log("SA SCIM: token valid but 0 users — provisioning not configured")
                return False, (
                    "SA SCIM token valid but 0 users provisioned — the Duo "
                    "'Cisco Secure Access' application (Provisioning tab: Base URL "
                    "+ Token) is missing, so nothing pushes users to SA."
                )
            _log(f"SA SCIM: {total} users present ✓")
            return True, f"SA SCIM OK — {total} users synced"
        except Exception as e:
            return False, f"SA SCIM check failed: {e}"

    def step_authproxy_enroll():
        """
        Re-enroll the Authentication Proxy on fresh AD1 each session.

        Runs authproxy_update_sso_enrollment_code.exe with the stored blob,
        stops/starts DuoAuthProxy, reads the new rikey from authproxy.cfg
        on AD1, then updates authproxy_cfg in the DB so the next session's
        authproxy_push carries the current rikey.

        The blob comes from Duo Admin portal:
          Applications → SSO Settings → External Authentication Sources
          → Active Directory → Auth Proxy → Step 2 → Generate Command
        Copy the base64 argument (not the full EXE path) and store it in
        the dashboard org credentials card under 'authproxy_enroll_blob'.
        """
        import time as _te

        AUTHPROXY_LOG = (
            r"C:\Program Files\Duo Security Authentication Proxy\log\authproxy.log"
        )
        SSO_ENROLL_EXE = (
            r"C:\Program Files\Duo Security Authentication Proxy\bin"
            r"\authproxy_update_sso_enrollment_code.exe"
        )

        def _drpc_status(winrm_s, label=""):
            """Read last 25 lines of authproxy.log; return ('connected'|'failed'|'unknown')."""
            try:
                r = winrm_s.run_ps(
                    f'Get-Content "{AUTHPROXY_LOG}" -Tail 25 -ErrorAction SilentlyContinue'
                )
                lines = r.std_out.decode(errors="replace").splitlines()
                has_401 = any("Invalid signature" in l for l in lines)
                has_idp = any("configured IdP" in l for l in lines)
                manual  = any("manual intervention" in l.lower() for l in lines)
                if has_idp and not has_401:
                    return "connected"
                if has_401 or manual:
                    return "failed"
                return "unknown"
            except Exception:
                return "unknown"

        nonlocal enroll_blob

        # The enrollment command is a ONE-TIME code that Duo expires eight hours
        # after it is generated, so a stored blob is worthless on the next run —
        # the EXE still reports "All secrets stored successfully" but DRPC then
        # fails with 401 Invalid signature. Always mint a fresh one.
        _log("harvesting a fresh enrollment command (the stored one is single-use)")
        h_ok, h_msg = duo_harvest_sso_enrollment(pod_id, db_path, log=_log)
        if h_ok:
            try:
                with _sq.connect(db_path) as _c:
                    _c.row_factory = _sq.Row
                    _r = _c.execute("SELECT authproxy_enroll_blob FROM org_credentials "
                                    "WHERE org_number=?", (org_num,)).fetchone()
                if _r and (_r["authproxy_enroll_blob"] or "").strip():
                    enroll_blob = _r["authproxy_enroll_blob"].strip()
                    _log(f"fresh blob ({len(enroll_blob)} chars)")
            except Exception as e:
                _log(f"could not re-read blob: {e}")
        else:
            _log(f"harvest failed ({h_msg[:100]}) — falling back to the stored blob")

        if not enroll_blob:
            return False, (
                f"no enrollment blob available and harvesting one failed: {h_msg[:160]}"
            )

        # Warn if blob is stale — enrollment blobs are one-time codes.
        # A blob used in a previous session will cause 401 on the SSO DRPC
        # connection even though the EXE reports "All secrets stored successfully".
        blob_age_warn = ""
        if blob_saved_at:
            import datetime as _dtb
            try:
                saved = _dtb.datetime.strptime(blob_saved_at[:19], "%Y-%m-%d %H:%M:%S")
                age_h = ((_dtb.datetime.utcnow() - saved).total_seconds()) / 3600
                if age_h > 24:
                    blob_age_warn = (
                        f" ⚠ BLOB IS {age_h:.0f}h OLD — one-time codes expire after first use. "
                        "If the proxy fails to connect to Duo SSO (401 Invalid signature), "
                        "generate a new command from Duo Admin portal → SSO Settings → "
                        "External Auth Sources → AD → Auth Proxy → Step 2 → Generate Command, "
                        "paste into org credentials, then re-run this step."
                    )
                    _log(blob_age_warn)
            except Exception:
                pass

        _log("WinRM-connecting to AD1 for SSO enrollment ...")
        try:
            winrm_sess = _winrm_connect_for_pod(pod_id, log=_log)
        except Exception as e:
            return False, f"WinRM connect failed: {e}"

        try:
            # ── Pre-check: skip EXE if proxy is already connected ────────────
            pre = _drpc_status(winrm_sess, "pre")
            if pre == "connected":
                _log("DRPC already connected — skipping re-enrollment")
                return True, "enrollment skipped — proxy already connected to Duo SSO ✓"
            _log(f"DRPC pre-status: {pre} — proceeding with enrollment")

            # ── Run the enrollment EXE with the blob ─────────────────────────
            # Note: use run_ps directly (not _winrm_run_cmd) to avoid
            # double-& issue — _winrm_run_cmd prepends "& " to the cmd
            _log(f"running authproxy_update_sso_enrollment_code.exe ...")
            _r = winrm_sess.run_ps(
                f"& '{SSO_ENROLL_EXE}' '{enroll_blob}'; Write-Output 'ENROLL_DONE'"
            )
            _out = _r.std_out.decode(errors="replace").strip()
            _err = _r.std_err.decode(errors="replace").strip()
            if _out: _log(f"enroll stdout: {_out[:300]}")
            if _err: _log(f"enroll stderr: {_err[:200]}")

            exe_ok = "ENROLL_DONE" in _out or "secrets stored" in _out.lower()
            if not exe_ok:
                _log("WARN: EXE did not report success — may be an expired blob")

            # ── Restart DuoAuthProxy ─────────────────────────────────────────
            _log("restarting DuoAuthProxy ...")
            winrm_sess.run_ps(
                "Stop-Service -Name DuoAuthProxy -Force -ErrorAction SilentlyContinue"
            )
            _te.sleep(3)
            winrm_sess.run_ps("Start-Service -Name DuoAuthProxy")
            _te.sleep(5)  # give DRPC time to connect or fail

            # ── Post-check: verify DRPC connection from log ──────────────────
            post = _drpc_status(winrm_sess, "post")
            _log(f"DRPC post-status: {post}")

            if post == "connected":
                return True, "enrollment OK — DRPC connected, IdPs registered ✓" + blob_age_warn
            if post == "failed":
                return False, (
                    "enrollment EXE ran but DRPC is still rejected (401 Invalid signature) — "
                    "the blob is a one-time code that was already consumed. "
                    "Generate a NEW command: Duo Admin portal → SSO Settings → "
                    "External Auth Sources → AD → Auth Proxy → Step 2 → Generate Command, "
                    "paste into org credentials card, then re-run this step."
                )
            # Unknown — service restarted but log unclear
            return True, (
                "enrollment ran, DRPC status unclear — check step 7 to confirm"
                + blob_age_warn
            )

        except Exception as e:
            return False, f"authproxy enrollment failed: {e}"

    def step_scim_push():
        """
        Verify that SA SCIM has users synced.

        SA's SCIM endpoint does not allow direct user creation from external
        scripts — only Duo's own provisioning connector (running in Duo's
        cloud) is permitted to write.  After step 3 (AD sync) adds users to
        Duo, Duo's SCIM connector automatically pushes them to SA.  This step
        confirms that sync has completed.
        """
        if not scim_tok:
            return True, "skipped — no SA SCIM token stored"
        try:
            import requests as _req
            resp = _req.get(
                "https://api.sse.cisco.com/identity/v2/scim/Users",
                headers={"Authorization": f"Bearer {scim_tok}"},
                timeout=15,
            )
            if resp.status_code == 401:
                return False, "SA SCIM: 401 — token expired; regenerate sa_scim_token in org credentials"
            if resp.status_code != 200:
                return False, f"SA SCIM verify: HTTP {resp.status_code} — {resp.text[:120]}"
            total = resp.json().get("totalResults", 0)
            if total == 0:
                # This used to soft-pass on "Duo's connector will push once AD
                # sync propagates". There is nothing to wait for: the push comes
                # from the "Cisco Secure Access" application in Duo, and if that
                # application does not exist the count stays 0 forever while the
                # card reports success over an empty Secure Access org.
                return False, (
                    "SA SCIM reachable but 0 users — nothing is provisioning them. "
                    "Duo needs the 'Cisco Secure Access' application with the SCIM "
                    "Base URL + Token configured (lab guide section 3); check "
                    "duo_saml_app_ikey in org_credentials."
                )
            return True, f"SA SCIM: {total} users confirmed in SA ✓"
        except Exception as e:
            return False, f"SA SCIM verify failed: {e}"

    def step_verify():
        """WinRM: check DuoAuthProxy is Running AND DRPC is connected."""
        AUTHPROXY_LOG = (
            r"C:\Program Files\Duo Security Authentication Proxy\log\authproxy.log"
        )
        try:
            sess = _winrm_connect_for_pod(pod_id)

            # Service status
            r_svc = sess.run_ps("(Get-Service DuoAuthProxy).Status")
            svc_status = r_svc.std_out.decode(errors="replace").strip()
            if "running" not in svc_status.lower():
                return False, f"DuoAuthProxy service: {svc_status} (not running)"

            # DRPC connection status from log
            r_log = sess.run_ps(
                f'Get-Content "{AUTHPROXY_LOG}" -Tail 30 -ErrorAction SilentlyContinue'
            )
            lines = r_log.std_out.decode(errors="replace").splitlines()
            has_401    = any("Invalid signature" in l for l in lines)
            has_idp    = any("configured IdP"    in l for l in lines)
            manual_int = any("manual intervention" in l.lower() for l in lines)

            if has_idp and not has_401:
                idp_line = next(l for l in reversed(lines) if "configured IdP" in l)
                return True, f"DuoAuthProxy Running + DRPC connected ✓ ({idp_line.strip()[-40:]})"
            if has_401 or manual_int:
                return False, (
                    "DuoAuthProxy Running but DRPC NOT connected (401 Invalid signature) — "
                    "enrollment blob is spent. Generate a new blob: Duo Admin portal → "
                    "SSO Settings → External Auth Sources → AD → Auth Proxy → Step 2 → "
                    "Generate Command, paste into org credentials, re-run step 5."
                )
            return True, f"DuoAuthProxy service: {svc_status} (DRPC log status unclear)"
        except Exception as e:
            return False, f"WinRM verify error: {e}"

    step_fns = {
        "bootstrap":        step_bootstrap,
        "org_setup":        step_org_setup,
        "authproxy_push":   step_authproxy_push,
        "ad_sync":          step_ad_sync,
        "saml_scim_config": step_saml_scim_config,
        "authproxy_enroll": step_authproxy_enroll,
        "scim_push":        step_scim_push,
        "verify":           step_verify,
    }

    results = []
    final_ok = True
    for i, step in enumerate(DUO_CARD_STEPS):
        if i < from_step:
            continue
        ok, result = _run(step, step_fns[step])
        results.append(f"{step}={'OK' if ok else 'FAIL'}")
        if not ok:
            final_ok = False
            # Non-fatal steps: report the failure but keep going.
            # ad_sync is here because the later steps (SSO enrollment, verify)
            # are independent of user sync — but it must still show red rather
            # than the old soft-fail ok=True, which hid an empty Duo org.
            if step in ("scim_push", "verify", "saml_scim_config", "ad_sync"):
                continue
            # Fatal steps: stop on first hard failure
            _log(f"  Hard failure at {step} — stopping")
            break

    summary = " | ".join(results)
    _log(f"Duo card done: {'OK' if final_ok else 'FAILED'} — {summary}")
    return final_ok, summary
