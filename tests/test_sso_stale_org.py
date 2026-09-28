"""Regression cover for POD-8 (2026-09-28): SSO kept pointing at a replaced Duo org.

Secure Access held an SSO configuration and SCIM users from a Duo org dCloud
had since replaced. sso_saml saw "configured" and skipped, so every login went
to the dead org's SSO host (sso-7f48f2cd) while the auth proxy served the
current one (sso-da7ee926) — "Invalid credentials", with no request ever
reaching the proxy. sso_test also typed the stale kit@rtp14 address because it
took the first kit@ in Secure Access's list.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from duo_automation import (  # noqa: E402
    SA_SP_ACS_URL,
    SA_SP_ENTITY_ID,
    _pick_sso_test_user,
    _sa_sp_metadata_xml,
    _saml_entity_host,
)

DUO_IDP_XML = (
    '<?xml version="1.0"?><md:EntityDescriptor '
    'xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" '
    'entityID="https://sso-da7ee926.demo.sso.duosecurity.com/saml2/sp/DIXXXX/metadata">'
    '</md:EntityDescriptor>'
)


def test_entity_host_names_the_duo_org():
    assert _saml_entity_host(DUO_IDP_XML) == "sso-da7ee926.demo.sso.duosecurity.com"


def test_entity_host_empty_when_absent():
    assert _saml_entity_host("") == ""
    assert _saml_entity_host("<html>not metadata</html>") == ""


def test_stale_and_current_orgs_differ():
    """The comparison sso_saml now makes: a different sso-<hash> is a different org."""
    stale = DUO_IDP_XML.replace("da7ee926", "7f48f2cd")
    assert _saml_entity_host(stale) != _saml_entity_host(DUO_IDP_XML)


def test_sp_metadata_carries_what_duo_upload_reads():
    """duo_upload_sp_metadata() regexes exactly these two values out of the file."""
    import re
    xml = _sa_sp_metadata_xml()
    assert re.search(r'entityID="([^"]+)"', xml).group(1) == SA_SP_ENTITY_ID
    assert re.search(r'AssertionConsumerService[^>]*Location="([^"]+)"',
                     xml).group(1) == SA_SP_ACS_URL


# Secure Access's list on POD-8, stale org first — the order that broke it.
POD8_SA = ["pat@rtp14.corp.pseudoco.com", "kit@rtp14.corp.pseudoco.com",
           "kit@sjc14.corp.pseudoco.com", "lin"]


def test_prefers_kit_as_the_current_duo_org_has_him():
    duo = [{"username": "lee", "email": "lee@sjc14.corp.pseudoco.com"},
           {"username": "kit", "email": "kit@sjc14.corp.pseudoco.com"}]
    assert _pick_sso_test_user(duo, POD8_SA) == "kit@sjc14.corp.pseudoco.com"


def test_falls_back_to_a_sa_kit_that_duo_knows():
    duo = [{"username": "kit.x", "email": "kit@sjc14.corp.pseudoco.com"}]
    assert _pick_sso_test_user(duo, POD8_SA) == "kit@sjc14.corp.pseudoco.com"


def test_old_behaviour_when_duo_list_unavailable():
    assert _pick_sso_test_user([], POD8_SA) == "kit@rtp14.corp.pseudoco.com"
    assert _pick_sso_test_user([], ["lin"]) == "lin"
    assert _pick_sso_test_user([], []) == ""


def test_kit_without_email_is_skipped():
    duo = [{"username": "kit", "email": ""}]
    assert _pick_sso_test_user(duo, POD8_SA) == "kit@rtp14.corp.pseudoco.com"
