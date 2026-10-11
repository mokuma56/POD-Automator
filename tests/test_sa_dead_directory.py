"""Tests for the dead Secure Access directory check.

Regression cover for POD-7 (org 529, 2026-10-11): a session reset deleted the
org's Duo directory, but the stored SCIM token still returned 200, so the card
reused it and provisioned users into a directory nothing can see. sso_saml then
found no Duo-NNNNN on the page, fell back to the literal "Duo", and failed as
"wizard step 1 incomplete — name or user directory not accepted".

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import duo_automation as da  # noqa: E402

# What a healthy org's Configuration management page carries (POD-15).
HEALTHY = ("Configuration management Directories Duo-32883 Identity provider "
           "Integrate directories SSO authentication Add SSO authentication")
# POD-7's page: the directories card is empty and SSO offers "Configure".
DEAD = ("Configuration management Directories Integrate directories "
        "SSO authentication Configure")


def test_finds_the_directory_on_a_healthy_page():
    assert da._sa_duo_directory_names(HEALTHY) == ["Duo-32883"]


def test_finds_nothing_on_pod7s_page():
    assert da._sa_duo_directory_names(DEAD) == []


def test_plain_word_duo_is_not_a_directory():
    # "Duo" appears all over these pages (Duo-Login.html, DuoSSO); only the
    # generated Duo-<digits> name is a directory.
    assert da._sa_duo_directory_names("DuoSSO Duo Duo-Login.html") == []


def test_orders_numerically():
    assert da._sa_duo_directory_names("Duo-9 Duo-32883 Duo-100") == \
        ["Duo-9", "Duo-100", "Duo-32883"]


def test_wizard_refuses_to_guess_a_directory(monkeypatch):
    """No directory must fail by naming the cause, never by trying "Duo"."""
    monkeypatch.setattr(da, "_sa_config_page", lambda t, o, e: True)
    monkeypatch.setattr(da, "_scc_text", lambda t, tries=3: DEAD)
    with pytest.raises(RuntimeError, match="no Duo-NNNNN directory"):
        da._sa_wizard_open(object(), "8383330", "ent")
