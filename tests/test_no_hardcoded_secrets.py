"""Credentials live in .env, never in the repo (GitGuardian STE0217780, 2026-11-21).

The lab password was hardcoded ~100 times and SCC API keys were committed under
data/scc_keys/. Everything now reads lab_secrets.py; these tests keep it that way.
"""
import os
import re
import subprocess
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

import lab_secrets  # noqa: E402

# Shapes of the old literals, not the literals themselves.
_FORBIDDEN = [
    re.compile(r"C1sco\d{3,}", re.I),             # dCloud lab password
    re.compile(r"Demo@C\W"),                       # Catalyst Center password
    re.compile(r"[a-z0-9.]+@gmail\.com", re.I),    # personal addresses
    re.compile(r'"scc_api_secret"\s*:\s*"[0-9a-f]{16,}"'),
]


def _tracked_text_files():
    out = subprocess.run(["git", "ls-files"], cwd=_ROOT, capture_output=True, text=True).stdout
    for rel in out.split():
        if rel.endswith((".docx", ".pdf", ".png", ".jpg", ".gz", ".bin", ".lock")):
            continue
        path = os.path.join(_ROOT, rel)
        try:
            with open(path, encoding="utf-8") as f:
                yield rel, f.read()
        except (OSError, UnicodeDecodeError):
            continue


def test_no_credential_literals_in_tracked_files():
    hits = [f"{rel}: {pat.pattern}"
            for rel, text in _tracked_text_files()
            for pat in _FORBIDDEN if pat.search(text)]
    assert not hits, "credential literal committed:\n" + "\n".join(hits)


def test_scc_key_files_are_not_tracked():
    out = subprocess.run(["git", "ls-files", "data/scc_keys"], cwd=_ROOT,
                         capture_output=True, text=True).stdout
    assert out.strip() == ""


def test_lab_secrets_reads_env_then_dotenv(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nLAB_PASS='from-dotenv'\nCATC_PASS=x\n")
    monkeypatch.setattr(lab_secrets, "_DOTENV", env)
    monkeypatch.delenv("LAB_PASS", raising=False)
    assert lab_secrets._read_dotenv(env)["LAB_PASS"] == "from-dotenv"
    monkeypatch.setenv("LAB_PASS", "from-env")
    assert lab_secrets.get("LAB_PASS") == "from-env"


def test_base_configs_use_the_placeholder():
    cfg_dir = os.path.join(_ROOT, "base_configs")
    for name in os.listdir(cfg_dir):
        text = open(os.path.join(cfg_dir, name)).read()
        if "password" in text:
            assert "{{LAB_PASS}}" in text, name
    src = open(os.path.join(_ROOT, "reset_switches.py")).read()
    assert '.replace("{{LAB_PASS}}", LAB_PASS)' in src


def test_dockerfile_ships_lab_secrets_and_no_passwords():
    src = open(os.path.join(_ROOT, "docker", "Dockerfile")).read()
    assert "lab_secrets.py" in src
    assert "COPY .env.example .env* ./" in src
    assert "_PASS=" not in src
