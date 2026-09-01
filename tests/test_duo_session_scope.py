"""Tests for new-session detection on the Duo card.

Regression cover for the bug that would have broken every POD on the first lab
session after rollout: a new session maps fresh PODs onto the SAME SCC orgs but
gives each pod a BRAND NEW Duo org. org_credentials is keyed by the SCC org
number, so the previous session's Duo credentials survive under a key that is
still valid — and duo_passkey_bootstrap's presence check read that as "already
has Admin API credentials — nothing to do". The card went green having
configured nothing, or worse configured the previous session's tenant.

The two directions both matter, so both are covered here:
  - a rotated session MUST clear the stale Duo credentials, and
  - an unreachable jump host MUST NOT, because wiping good credentials on a
    WinRM blip turns a transient outage into a full rebuild.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import duo_automation as da  # noqa: E402

OLD_URL = "https://idac.cat-dcloud.com/?id=SESSION-ONE&token=aaaaaaaaaaaaaaaa"
NEW_URL = "https://idac.cat-dcloud.com/?id=SESSION-TWO&token=bbbbbbbbbbbbbbbb"

# Populated by the previous session; every one describes that session's Duo org.
STALE_DUO = {
    "duo_ikey": "DIOLDOLDOLDOLDOLDOLD",
    "duo_skey": "oldsecret",
    "duo_host": "api-old1234.duosecurity.com",
    "duo_admin_email": "x-arch-duo-old@corp.pseudoco.com",
    "duo_admin_password": "oldpw",
    "duo_admin_host": "admin-old1234.duosecurity.com",
    "duo_passkey_cred": '[{"rpId": "admin-old1234.duosecurity.com"}]',
    "duo_passkey_hwm": "7",
    "duo_admin_totp_secret": "OLDTOTPSECRET",
    "duo_saml_app_ikey": "DIOLDSAMLAPPOLDSAMLA",
    "authproxy_ikey": "DIOLDPROXYOLDPROXYOL",
    "authproxy_skey": "oldproxysecret",
    "authproxy_cfg": "[cloud]\nikey=DIOLDPROXYOLDPROXYOL\n",
    "authproxy_enroll_blob": "b64oldblob",
    "authproxy_blob_saved_at": "2026-08-30T10:00:00Z",
    "authproxy_sso_cfg": "[sso]\nold\n",
}

# Stable across sessions — the SCC/SA orgs are reused, so these must SURVIVE.
STABLE = {
    "scc_api_key": "scc-key",
    "scc_api_secret": "scc-secret",
    "sa_org_id": "9999999",
    "sa_api_key": "sa-key",
    "sa_api_secret": "sa-secret",
    "cdfmc_host": "cisco-pseudoco-518.app.us.cdo.cisco.com",
    "cdfmc_api_token": "cdfmc-token",
    "pxgrid_cloud_email": "px@example.com",
    "meraki_org_id": "123456",
    # Secure Access owns these and its org is stable, so they are deliberately
    # NOT in DUO_SESSION_SCOPED_COLUMNS — the token has its own validity probe.
    "sa_scim_token": "sa-scim-token",
    "sa_scim_url": "https://api.sse.cisco.com/scim/v2",
}


def _make_db(tmp_path, *, stored_url):
    db = tmp_path / "pod_state.db"
    cols = sorted(set(STALE_DUO) | set(STABLE) | {"idac_url"})
    conn = sqlite3.connect(db)
    conn.execute(
        "CREATE TABLE org_credentials (org_number TEXT PRIMARY KEY, "
        "updated_at TEXT, " + ", ".join(f"{c} TEXT DEFAULT ''" for c in cols) + ")")
    conn.execute("CREATE TABLE pods (pod_id TEXT PRIMARY KEY, scc_org TEXT)")
    conn.execute("INSERT INTO pods VALUES ('POD-5', 'cisco-pseudoco-518--x.app.us.cdo.cisco.com')")
    values = {**STALE_DUO, **STABLE, "idac_url": stored_url}
    conn.execute(
        "INSERT INTO org_credentials (org_number, " + ", ".join(values) + ") "
        "VALUES (?" + ", ?" * len(values) + ")",
        ["518"] + list(values.values()))
    conn.commit()
    conn.close()
    return str(db)


def _row(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        return dict(conn.execute(
            "SELECT * FROM org_credentials WHERE org_number='518'").fetchone())
    finally:
        conn.close()


@pytest.fixture
def fake_session(monkeypatch):
    """Control what the jump host's session log appears to contain."""
    def _set(url):
        monkeypatch.setattr(da, "read_idac_url_from_session",
                            lambda pod_id, log=None: url)
    return _set


def test_new_session_clears_stale_duo_credentials(tmp_path, fake_session):
    """The whole point: a changed iDAC URL means a new Duo org."""
    db = _make_db(tmp_path, stored_url=OLD_URL)
    fake_session(NEW_URL)

    assert da.duo_refresh_session_scope("POD-5", db, "518", log=lambda m: None) == "rotated"

    row = _row(db)
    for col in STALE_DUO:
        assert row[col] == "", f"{col} still holds the previous session's value"
    assert row["idac_url"] == NEW_URL


def test_new_session_preserves_the_stable_orgs(tmp_path, fake_session):
    """Clearing must be surgical — SCC/SA/cdFMC/Meraki orgs are reused."""
    db = _make_db(tmp_path, stored_url=OLD_URL)
    fake_session(NEW_URL)

    da.duo_refresh_session_scope("POD-5", db, "518", log=lambda m: None)

    row = _row(db)
    for col, expected in STABLE.items():
        assert row[col] == expected, f"{col} was cleared but its org is stable"


def test_same_session_changes_nothing(tmp_path, fake_session):
    db = _make_db(tmp_path, stored_url=OLD_URL)
    fake_session(OLD_URL)

    assert da.duo_refresh_session_scope("POD-5", db, "518", log=lambda m: None) == "unchanged"

    row = _row(db)
    for col, expected in STALE_DUO.items():
        assert row[col] == expected


def test_unreachable_jump_host_never_wipes_credentials(tmp_path, fake_session):
    """A WinRM blip must not be mistaken for a rotated session.

    read_idac_url_from_session returns "" for every failure mode it has — no
    jump host, no log file, no match — so an empty result proves nothing about
    the session and must leave working credentials in place.
    """
    db = _make_db(tmp_path, stored_url=OLD_URL)
    fake_session("")

    assert da.duo_refresh_session_scope("POD-5", db, "518", log=lambda m: None) == "unavailable"

    row = _row(db)
    for col, expected in STALE_DUO.items():
        assert row[col] == expected
    assert row["idac_url"] == OLD_URL


def test_no_stored_url_also_clears(tmp_path, fake_session):
    """An empty stored URL is NOT a safe case — it must clear too.

    A new session remaps PODs onto different SCC orgs from the pool, so a POD can
    land on an org carrying duo_ikey/skey/host from some older run with no iDAC
    URL beside them. Org 507 was in exactly that state on 2026-09-01. Treating it
    as "rotation unproven" left the stale credentials in place, and if the old Duo
    org still answers /admin/v1/info/summary the card configures the WRONG tenant.

    Stored Duo credentials are trustworthy only when the stored URL EXACTLY
    matches the live one; absent counts as not matching.
    """
    db = _make_db(tmp_path, stored_url="")
    fake_session(NEW_URL)

    assert da.duo_refresh_session_scope("POD-5", db, "518", log=lambda m: None) == "rotated"

    row = _row(db)
    assert row["idac_url"] == NEW_URL
    for col in STALE_DUO:
        assert row[col] == "", f"{col} survived with no matching iDAC URL"
    for col, expected in STABLE.items():
        assert row[col] == expected, f"{col} was cleared but its org is stable"


def test_nothing_to_clear_reports_stored(tmp_path, fake_session):
    """A genuinely fresh org has no Duo state, so say so rather than crying
    rotation — the distinction is what makes the log line meaningful."""
    db = _make_db(tmp_path, stored_url="")
    conn = sqlite3.connect(db)
    conn.execute("UPDATE org_credentials SET "
                 + ", ".join(f"{c}=''" for c in STALE_DUO)
                 + " WHERE org_number='518'")
    conn.commit()
    conn.close()
    fake_session(NEW_URL)

    assert da.duo_refresh_session_scope("POD-5", db, "518", log=lambda m: None) == "stored"
    assert _row(db)["idac_url"] == NEW_URL


def test_scoped_columns_all_exist_in_the_real_schema():
    """A typo in DUO_SESSION_SCOPED_COLUMNS would silently narrow the clear —
    the UPDATE filters to columns that exist, so a misspelling is not an error.
    """
    db = Path(__file__).resolve().parent.parent / "data" / "pod_state.db"
    if not db.exists():
        pytest.skip("no local pod_state.db")
    conn = sqlite3.connect(db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(org_credentials)")}
    finally:
        conn.close()
    missing = [c for c in da.DUO_SESSION_SCOPED_COLUMNS if c not in cols]
    assert not missing, f"not real columns: {missing}"
