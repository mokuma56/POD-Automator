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


def duo_create_authproxy_integration(ikey: str, skey: str, host: str) -> dict | None:
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


# ──────────────────────────────────────────────────────────────────────────────
# Secure Access (SA) Management API helpers
# Requires management JWT obtained via Okta token exchange (browser session).
# ──────────────────────────────────────────────────────────────────────────────

SA_MGMT_BASE = "https://management.api.umbrella.com"
SA_SSE_BASE  = "https://api.sse.cisco.com"

# SA SP metadata (fixed for Cisco SSE — same across all orgs)
SA_SP_ENTITY_ID = "saml.fg.id.sse.cisco.com"
SA_SP_ACS_URL   = "https://fg.id.sse.cisco.com/gw/auth/acs/response"
SA_SCIM_URL     = "https://api.sse.cisco.com/identity/v2/scim"

# SP cert serial — confirmed from org 504 SP metadata; fallback if dynamic fetch fails
SA_SP_CERT_SERIAL_DEFAULT = "40019C6C7762BF3AB89A51B27222F88D"


def sa_get_mgmt_jwt(okta_token: str) -> str:
    """Exchange Okta access token (from SCC sessionStorage) for SA management JWT.

    The management JWT is required for management.api.umbrella.com endpoints.
    It has a ~5-minute TTL with scope=role:root-admin (covers all orgs).
    Client credentials tokens return 403 on management.api.umbrella.com.
    """
    r = requests.post(
        f"{SA_SSE_BASE}/auth/v2/jwt-bearer/token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": okta_token,
        },
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


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
                       xsrf_cookie: str) -> requests.Session:
    """Create a requests.Session pre-loaded with Duo admin cookies and XSRF header."""
    sess = requests.Session()
    sess.cookies.set("sid", sid, domain=admin_host)
    sess.cookies.set("_xsrf", xsrf_cookie, domain=admin_host)
    sess.headers.update({
        "x-xsrftoken": _duo_admin_xsrf_header(xsrf_cookie),
        "origin": f"https://{admin_host}",
        "referer": f"https://{admin_host}/",
    })
    return sess


def duo_admin_get_or_create_saml_app(
        admin_ikey: str, admin_skey: str, admin_host: str,
        sid: str, xsrf_cookie: str,
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
    sess = _duo_admin_session(admin_host, sid, xsrf_cookie)
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
        log=None) -> bool:
    """Configure Duo SAML SP app with SA entity ID and ACS URL (multipart form)."""
    _log = log or (lambda s: print(f"     [duo-admin] {s}"))
    sess = _duo_admin_session(admin_host, sid, xsrf_cookie)
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
        log=None) -> bool:
    """Configure (or reconfigure) Duo SCIM outbound integration with new SA SCIM token."""
    _log = log or (lambda s: print(f"     [duo-admin] {s}"))
    sess = _duo_admin_session(admin_host, sid, xsrf_cookie)
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
        # Wait until "Loading data..." placeholders are replaced with real content.
        try:
            page.wait_for_function(
                "() => !document.body.textContent.includes('Loading data...')",
                timeout=30_000,
            )
            page.wait_for_timeout(1000)  # let final render settle
            log("tiles loaded (Loading data... gone)")
        except Exception:
            log("WARN: tiles may still show 'Loading data...' — trying selectors anyway")
            page.wait_for_timeout(3000)

        scc_selectors = [
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

        # Final guard
        if "security.cisco.com" not in scc_page.url:
            try:
                scc_page.wait_for_url("*security.cisco.com*", timeout=30_000)
            except Exception:
                raise RuntimeError(
                    f"iDAC adaptive card SCC navigation failed — final URL: {scc_page.url[:100]}"
                )
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
            raise RuntimeError(
                "Could not extract Okta token from SCC sessionStorage — "
                "iDAC auto-login may have expired"
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


def fetch_idac_url_from_dcloud(log=None) -> str:
    """
    Connect to jump host via WinRM, run idac_sdk on it to generate a fresh
    iDAC auto-login URL.  Must be called from within a VPN container
    (host has no VPN; jump host 198.18.133.36 is only reachable via VPN).

    Returns the iDAC URL string, or raises RuntimeError on failure.
    """
    import base64
    import winrm

    _log = log or (lambda s: print(f"     [fetch-idac] {s}"))
    _log(f"WinRM → {JUMP_HOST_IP}: generating fresh iDAC URL via idac_sdk")

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

    duo_ikey   = oc.get("duo_ikey", "").strip()
    duo_skey   = oc.get("duo_skey", "").strip()
    duo_host   = oc.get("duo_host", "").strip()
    sa_api_key = oc.get("sa_api_key", "").strip()
    sa_api_sec = oc.get("sa_api_secret", "").strip()
    sa_org_id  = oc.get("sa_org_id", "").strip()
    idac_url   = oc.get("idac_url", "").strip()
    scc_email  = oc.get("scc_email", "").strip()

    import os as _os
    _in_docker = _os.path.exists("/.dockerenv")

    if not duo_ikey or not duo_skey or not duo_host:
        return False, "Duo Admin API credentials not configured for this org"
    if not sa_api_key or not sa_api_sec:
        return False, "SA API credentials not configured for this org"
    if not sa_org_id:
        return False, "SA org ID not configured for this org"
    if _in_docker and not idac_url:
        return False, (
            "iDAC auto-login URL not configured — "
            "paste the SCC auto-login URL in Org Credentials → iDAC URL field"
        )
    if not _in_docker and not scc_email:
        return False, (
            "scc_email not configured — set it in Org Credentials for this org"
        )

    # ── 2. Browser session: Okta token + Duo admin cookies ───────────────────
    _log("launching browser session (SCC + Duo admin authentication)...")
    try:
        if _in_docker:
            sessions = get_browser_sessions(idac_url, duo_host, log=_log)
        else:
            sessions = get_browser_sessions_mac(
                duo_host, scc_email, org_num, log=_log,
            )
    except Exception as e:
        return False, f"Browser authentication failed: {e}"

    okta_token = sessions["okta_token"]
    duo_sid    = sessions["duo_sid"]
    duo_xsrf   = sessions["duo_xsrf"]
    admin_host = sessions["admin_host"]

    # ── 3. SA management JWT ──────────────────────────────────────────────────
    _log("obtaining SA management JWT from Okta token...")
    try:
        mgmt_jwt = sa_get_mgmt_jwt(okta_token)
    except Exception as e:
        return False, f"SA management JWT exchange failed: {e}"
    _log("management JWT obtained")

    # ── 4. SA: ensure provisioning profile ───────────────────────────────────
    _log("verifying SA provisioning profile (source=/duo/scimv2)...")
    try:
        profile_id = sa_ensure_provisioning_profile(mgmt_jwt, sa_org_id, log=_log)
    except Exception as e:
        return False, f"SA provisioning profile error: {e}"
    if not profile_id:
        return False, "SA provisioning profile ID is empty after ensure"

    # ── 5. SA: generate SCIM token ────────────────────────────────────────────
    _log("generating new SA SCIM token...")
    try:
        scim_token = sa_generate_scim_token(mgmt_jwt, sa_org_id, log=_log)
        if not scim_token:
            return False, "SA SCIM token generation returned empty token"
    except Exception as e:
        return False, f"SA SCIM token generation failed: {e}"

    # ── 6. SA: clear existing SAML profiles ──────────────────────────────────
    _log("clearing existing SA SAML IdP profiles...")
    try:
        profiles = sa_list_saml_profiles(mgmt_jwt, sa_org_id)
        for prof in profiles:
            pid = str(prof.get("idpid") or prof.get("id") or "")
            if pid:
                sa_delete_saml_profile(mgmt_jwt, sa_org_id, pid, log=_log)
    except Exception as e:
        _log(f"WARN: could not clear SAML profiles: {e}")

    # ── 7. Duo admin: get or create SAML SP app ───────────────────────────────
    _log("checking/creating Duo SAML SP app...")
    try:
        app_ikey = duo_admin_get_or_create_saml_app(
            duo_ikey, duo_skey, duo_host,
            duo_sid, duo_xsrf, log=_log,
        )
    except Exception as e:
        return False, f"Duo SAML SP app error: {e}"

    # ── 8. Duo admin: configure SAML SP app ──────────────────────────────────
    _log(f"configuring Duo SAML SP app ({app_ikey}) with SA SP details...")
    try:
        ok8 = duo_admin_configure_saml_app(
            admin_host, app_ikey, duo_sid, duo_xsrf,
            entity_id=SA_SP_ENTITY_ID, acs_url=SA_SP_ACS_URL,
            log=_log,
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

    # ── 10. SA: create SAML profile ───────────────────────────────────────────
    _log("uploading Duo IdP metadata to SA as new SAML profile...")
    try:
        ok10 = sa_create_saml_profile(
            mgmt_jwt, sa_org_id, profile_id,
            idp_metadata_xml, cert_serial, log=_log,
        )
        if not ok10:
            return False, "SA SAML profile creation failed"
    except Exception as e:
        return False, f"SA SAML profile creation error: {e}"

    # ── 11. Duo admin: configure SCIM outbound ────────────────────────────────
    _log("configuring Duo SCIM outbound integration with new SA SCIM token...")
    try:
        ok11 = duo_admin_configure_scim(
            admin_host, app_ikey, duo_sid, duo_xsrf,
            scim_token=scim_token, log=_log,
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

    result = (
        f"SA+Duo SAML/SCIM setup complete | "
        f"org={sa_org_id} | profile={profile_id} | duo_app={app_ikey}"
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
        "} catch {} }; "
        "Start-Sleep 5; "
        "$s = Get-Service DuoAuthProxy -ErrorAction SilentlyContinue; "
        "if ($s) { Write-Output \"STATUS:$($s.Status)\" } "
        "else { Write-Output 'STATUS:NotFound' }"
    )
    r2 = session.run_ps(restart_ps)
    out2 = r2.std_out.decode(errors="replace").strip()
    import re as _rwr
    m = _rwr.search(r"STATUS:(\w+)", out2)
    status = m.group(1) if m else "Unknown"
    log(f"DuoAuthProxy service: {status}")
    if status.lower() == "running":
        return True, "cfg written | service Running"
    return False, f"cfg written but service={status}"


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
        self._container: str | None = None
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

    def _exec_ps(self, ps_script: str, timeout: int = 60):
        """Execute a PowerShell script inside the proxy container via WinRM."""
        import subprocess as _sp, json as _json
        py = (
            "import winrm, sys\n"
            f"s = winrm.Session("
            f"  'http://{self._ad_ip}:5985/wsman',"
            f"  auth=({_json.dumps(self._user)}, {_json.dumps(self._pw)}),"
            f"  transport='ntlm',"
            f"  read_timeout_sec=30, operation_timeout_sec=25)\n"
            f"r = s.run_ps({_json.dumps(ps_script)})\n"
            "sys.stdout.buffer.write(r.std_out)\n"
            "sys.stderr.buffer.write(r.std_err)\n"
            "sys.exit(r.status_code)\n"
        )
        return _sp.run(
            ["docker", "exec", self._container, "python3", "-c", py],
            capture_output=True, timeout=timeout,
        )

    def run_ps(self, script: str):
        result = self._exec_ps(script)
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


# ──────────────────────────────────────────────────────────────────────────────
# Mac-native browser session — visible Chrome, no iDAC required.
# Used when duo automation is triggered directly on the Mac (dashboard process).
# ──────────────────────────────────────────────────────────────────────────────

def get_browser_sessions_mac(
        duo_host: str,
        scc_email: str,
        org_number: str,
        timeout_ms: int = 180_000,
        log=None) -> dict:
    """
    Obtain SCC Okta token + Duo admin session cookies using a visible Chrome
    window on the Mac.  Skips iDAC entirely.

    Flow:
      1. Launch Chrome (visible, channel="chrome").
      2. Navigate to https://security.cisco.com.
      3. If login page appears, auto-fill scc_email and wait for SSO/MFA.
      4. Handle the org-selection modal — pick the tile for org_number.
      5. Extract Okta token from sessionStorage.
      6. Navigate Products → Duo Security to open the Duo admin panel.
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
        browser = p.chromium.launch(
            headless=False,
            channel="chrome",
            args=["--disable-blink-features=AutomationControlled"],
        )
        ctx = browser.new_context(
            ignore_https_errors=True,
            viewport={"width": 1400, "height": 900},
        )
        page = ctx.new_page()

        # ── Step 1: open SCC ────────────────────────────────────────────────
        _log("opening https://security.cisco.com ...")
        page.goto("https://security.cisco.com/",
                  timeout=60_000, wait_until="domcontentloaded")

        # ── Step 2: handle login if redirected ──────────────────────────────
        _log(f"current URL: {page.url[:80]}")
        if "security.cisco.com" not in page.url:
            _log(f"login redirect detected — filling email: {scc_email}")
            for sel in [
                "input[type='email']",
                "input[name='email']",
                "input[id*='email' i]",
                "input[placeholder*='email' i]",
                "input[name='identifier']",
            ]:
                try:
                    lc = page.locator(sel)
                    if lc.count() > 0:
                        lc.first.fill(scc_email)
                        lc.first.press("Enter")
                        _log(f"email filled via {sel!r}")
                        break
                except Exception:
                    continue

            _log("waiting for SSO / MFA completion (up to 3 min) ...")
            try:
                page.wait_for_url("*security.cisco.com*", timeout=timeout_ms)
            except Exception:
                if "security.cisco.com" not in page.url:
                    raise RuntimeError(
                        f"Login did not reach SCC — stuck at: {page.url[:100]}"
                    )

        _log(f"on SCC: {page.url[:80]}")

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
            raise RuntimeError(
                "Could not extract Okta token from SCC sessionStorage — "
                "login or org selection may not have completed"
            )
        _log("Okta token extracted from SCC sessionStorage")

        # ── Step 5: navigate to Duo admin via Products → Duo Security ────────
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

        # Click Duo Security in the menu
        for duo_sel in [
            "a:has-text('Duo Security')",
            "a:has-text('Duo')",
            f"a[href*='{expected_admin}']" if expected_admin else "",
            "a[href*='duosecurity.com']",
            "text=Duo Security",
            "text=Duo",
        ]:
            if not duo_sel:
                continue
            try:
                lc = page.locator(duo_sel)
                if lc.count() > 0:
                    try:
                        with ctx.expect_page(timeout=15_000) as new_pg:
                            lc.first.click(timeout=5_000)
                        duo_page = new_pg.value
                        duo_page.wait_for_load_state("load", timeout=timeout_ms)
                        _log(f"Duo admin opened in new tab: {duo_page.url[:80]}")
                    except Exception:
                        # same-tab navigation
                        page.wait_for_url("*duosecurity.com*", timeout=30_000)
                        duo_page = page
                        _log(f"Duo admin loaded in same tab: {duo_page.url[:80]}")
                    break
            except Exception:
                continue

        # Fallback: navigate directly
        if duo_page is None and expected_admin:
            _log(f"Products menu failed — navigating directly to {expected_admin}")
            duo_page = ctx.new_page()
            duo_page.goto(f"https://{expected_admin}/",
                          timeout=timeout_ms, wait_until="load")

        if duo_page is None:
            raise RuntimeError("Could not open Duo admin panel via any method")

        if "login" in duo_page.url:
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

        browser.close()

        if not sid:
            raise RuntimeError(
                "Could not extract 'sid' cookie from Duo admin session"
            )

        _log("Duo admin session cookies extracted — browser closed")
        return {
            "okta_token": okta_token,
            "duo_sid":    sid,
            "duo_xsrf":   xsrf,
            "admin_host": admin_host_actual,
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


def _open_duo_admin_page(ctx, scc_page, admin_host: str, duo_host: str, log):
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

    duo_host = oc.get("duo_host", "").strip()
    idac_url = oc.get("idac_url", "").strip()
    ap_ikey  = oc.get("authproxy_ikey", "").strip()
    ap_skey  = oc.get("authproxy_skey", "").strip()
    scc_email = oc.get("scc_email", "").strip()

    import os as _os
    _in_docker = _os.path.exists("/.dockerenv")

    if not duo_host:
        return False, "Duo host not configured for this org"
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
        if _in_docker:
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
            )
        scc_page = ctx.new_page()
        try:
            # Authenticate to SCC
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

            # Open Duo Admin panel
            _log("opening Duo Admin panel ...")
            duo_page = _open_duo_admin_page(ctx, scc_page, admin_host, duo_host, _log)

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
