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

DUO_ADMIN_API_TYPE = "adminapi"  # integration type to keep

def duo_reset_org(ikey: str, skey: str, host: str,
                  log=None) -> tuple[bool, str]:
    """
    Delete all non-Admin-API integrations, all users, all groups,
    and all permitted domains from the Duo org.

    Returns (ok, message).
    log: optional callable(str) for progress messages.
    """
    _log = log or (lambda s: print(f"     [duo] {s}"))
    deleted = {"integrations": 0, "users": 0, "groups": 0, "domains": 0}

    try:
        # 1. Delete non-Admin-API integrations (v3 endpoint for SSO + v1 for classic)
        for api_path in ("/admin/v1/integrations", "/admin/v3/integrations"):
            try:
                integrations = _paginate(ikey, skey, host, api_path)
            except Exception:
                integrations = []
            for integ in integrations:
                itype = integ.get("type", "")
                ikey_val = integ.get("integration_key", "")
                if itype == DUO_ADMIN_API_TYPE or not ikey_val:
                    continue
                try:
                    _duo_request(ikey, skey, host, "DELETE",
                                 f"{api_path}/{ikey_val}")
                    deleted["integrations"] += 1
                    _log(f"Deleted integration {ikey_val} ({itype})")
                except Exception as e:
                    _log(f"WARN: could not delete integration {ikey_val}: {e}")

        # 2. Delete all users
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
