"""A stored Admin API app must belong to the org whose admin was just activated.

POD-27, 2026-09-29: org 504's row carried Admin API credentials from a PREVIOUS
session's Duo org but no admin email, so the new-session check had nothing to
compare and passed. bootstrap then activated the new admin in the NEW org and
"kept existing Admin API app" — which still answered, for the OLD org. Every
API step went there: org_setup "admins=0, users=8" (June users from another
lab, kit@sjc02), TOTP "admin not found", and sso_test typed kit@sjc02 while
POD-27's AD has kit@rtp10.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sqlite3
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import duo_automation as da  # noqa: E402

SRC = (ROOT / "duo_automation.py").read_text()


# ── is this API app's org the one we just activated? ─────────────────────────

def test_admin_found_case_insensitively():
    admins = [{"email": "X-Arch-Duo-rtpf3131a@corp.pseudoco.com"}]
    assert da._admin_in_api_org(admins, "x-arch-duo-rtpf3131a@corp.pseudoco.com")


def test_old_org_with_no_admins_is_not_ours():
    """What POD-27's stale app returned."""
    assert not da._admin_in_api_org([], "x-arch-duo-rtpf3131a@corp.pseudoco.com")


def test_old_org_with_someone_elses_admin_is_not_ours():
    admins = [{"email": "x-arch-duo-sjc0a3aa1@corp.pseudoco.com"}]
    assert not da._admin_in_api_org(admins, "x-arch-duo-rtpf3131a@corp.pseudoco.com")


def test_no_email_never_matches():
    assert not da._admin_in_api_org([{"email": ""}], "")


def test_discarding_the_old_app_keeps_the_new_admin_and_clears_the_rest():
    """Activation is one-shot, so the new admin's login must survive; the old
    org's API app, auth-proxy config, SAML app and TOTP must not."""
    assert da._ADMIN_LOGIN_COLUMNS <= set(da.DUO_SESSION_SCOPED_COLUMNS)
    cleared = set(da.DUO_SESSION_SCOPED_COLUMNS) - da._ADMIN_LOGIN_COLUMNS
    for col in ("duo_ikey", "duo_skey", "duo_host", "authproxy_cfg",
                "authproxy_ikey", "duo_saml_app_ikey", "duo_admin_totp_secret"):
        assert col in cleared, col
    for col in ("duo_admin_email", "duo_passkey_cred", "duo_passkey_hwm"):
        assert col not in cleared, col


def test_bootstrap_checks_the_org_before_keeping_the_app():
    body = SRC[SRC.index("def duo_passkey_bootstrap("):]
    body = body[:body.index("\ndef ", 10)]
    keep = body.index("if _reuse_api_creds:")
    assert body.index("_admin_in_api_org(", keep) < body.index("kept existing", keep)
    # ...and a mismatch falls through to creating a new app in THIS org.
    assert body.index("belongs to a previous Duo org", keep) < \
        body.index("_pw_create_admin_api_app(page2", keep)


# ── the SSO test uses the POD's own AD address ────────────────────────────────

POD27_AD_VERIFY = ("All updated | Kit=kit@rtp10.corp.pseudoco.com [OK] | "
                   "Lee=lee@rtp10.corp.pseudoco.com [OK] | Pat=pat@rtp10.corp")


def test_kit_parsed_from_ad_verify():
    assert da._kit_email_from_ad_verify(POD27_AD_VERIFY) == "kit@rtp10.corp.pseudoco.com"
    assert da._kit_email_from_ad_verify("") == ""
    assert da._kit_email_from_ad_verify("AD not reachable") == ""


def test_ad_kit_comes_from_the_pipeline_result_without_winrm(tmp_path, monkeypatch):
    db = tmp_path / "pod_state.db"
    c = sqlite3.connect(db)
    c.execute("CREATE TABLE pipeline_steps (pod_id TEXT, step_name TEXT, status TEXT, result TEXT)")
    c.execute("INSERT INTO pipeline_steps VALUES ('POD-27','ad_verify','completed',?)",
              (POD27_AD_VERIFY,))
    c.commit(); c.close()
    monkeypatch.setattr(da, "_winrm_connect_for_pod",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no WinRM needed")))
    assert da._pod_ad_kit_email("POD-27", str(db)) == "kit@rtp10.corp.pseudoco.com"


def test_ad_kit_unknown_is_empty_not_an_error(tmp_path, monkeypatch):
    db = tmp_path / "pod_state.db"
    sqlite3.connect(db).execute(
        "CREATE TABLE pipeline_steps (pod_id TEXT, step_name TEXT, status TEXT, result TEXT)")

    def no_winrm(*a, **k):
        raise RuntimeError("jump host down")

    monkeypatch.setattr(da, "_winrm_connect_for_pod", no_winrm)
    assert da._pod_ad_kit_email("POD-99", str(db)) == ""


def test_sso_test_prefers_the_ad_address():
    body = SRC[SRC.index("def duo_test_sso_login("):]
    body = body[:body.index("\ndef ", 10)]
    assert body.index("_pick_sso_test_user(") < body.index("_pod_ad_kit_email(")
    assert "username = ad_kit" in body
