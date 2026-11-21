"""Lab credentials, read from the environment or the gitignored .env.

Nothing secret lives in the repo. Every module that needs a lab login imports
it from here:

    from lab_secrets import LAB_PASS, CATC_USER, CATC_PASS

Lookup order for each name:
  1. the process environment (launchd, `docker run -e NAME`, compose)
  2. .env next to this file -- the repo root on the host, /pipeline in the
     pod-automator image (the Dockerfile copies .env in at build time; the
     image is local-only and never pushed)

A missing value is an empty string, not an exception, so importing a module
never fails; `missing()` lists what is unset and the dashboard warns about it
at startup. See .env.example for the names.
"""
import os
from pathlib import Path

NAMES = (
    "LAB_PASS",        # standard dCloud lab password: routers, switches, ISE, AD, jump host, vManage
    "CATC_USER",       # Catalyst Center login
    "CATC_PASS",
)

_DOTENV = Path(__file__).resolve().parent / ".env"


def _read_dotenv(path=_DOTENV):
    vals = {}
    try:
        for line in path.read_text().splitlines():
            k, sep, v = line.strip().partition("=")
            if sep and not k.startswith("#"):
                vals[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return vals


def get(name, default=""):
    """One secret by name: environment first, then .env."""
    v = os.environ.get(name)
    if v:
        return v
    return _read_dotenv().get(name, default)


def missing(names=NAMES):
    return [n for n in names if not get(n)]


LAB_PASS = get("LAB_PASS")
CATC_USER = get("CATC_USER") or "admin"
CATC_PASS = get("CATC_PASS")
