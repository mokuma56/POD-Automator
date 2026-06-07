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
import requests


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

def duo_get_authproxy_creds(ikey: str, skey: str, host: str) -> dict | None:
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
        f"service_account_username={winrm_user}\n"
        f"service_account_password={winrm_pass}\n"
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

    # 1. Write authproxy.cfg using base64 to avoid quoting issues
    import base64 as _b64
    cfg_b64 = _b64.b64encode(cfg.encode("utf-8")).decode()
    write_ps = (
        f"$bytes = [Convert]::FromBase64String('{cfg_b64}'); "
        f"$text = [System.Text.Encoding]::UTF8.GetString($bytes); "
        f"$dir = Split-Path -Parent '{AUTHPROXY_CFG_PATH}'; "
        "if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }; "
        f"Set-Content -Path '{AUTHPROXY_CFG_PATH}' -Value $text -Encoding UTF8; "
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
        err2 = r2.std_err.decode(errors="replace")[:200]
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
