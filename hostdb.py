"""Run a named database op — directly on the host, over HTTP from a container.

Containers must never open data/pod_state.db: WAL across the Docker Desktop
bind mount wedged the dashboard's connections (see db_ops.py for the full
story). Call sites use

    hostdb.call("pipeline_step_set", pod_id=..., step_name=..., status=...)

and this module decides how it runs:

  * inside a container (/.dockerenv exists): POST to the dashboard's
    /api/hostdb/<op>, which runs the op on the dashboard's own connection;
  * on the host (dashboard thread, CLI, tests): run it on db_path directly —
    the host is the one process allowed to open the file.

Same pattern, and the same host URL default, as the pre-existing
/api/scc/run-check-sync delegation in onboard_router.phase_scc_reset_check.
"""
import json
import os
import time
import urllib.error
import urllib.request

DEFAULT_DASHBOARD_URL = "http://192.168.65.254:5050"   # Docker Desktop's host gateway
HOST_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "data", "pod_state.db")

# The dashboard restarts in ~3s under launchd (KeepAlive), and a container's
# step write must survive that rather than leave a row stuck on 'running'.
RETRY_DELAYS = (0.5, 1, 2, 3, 5, 8)          # ~20s of retrying in total
REQUEST_TIMEOUT = 15


class HostDBError(RuntimeError):
    """The op could not be run — the host rejected it or was unreachable."""


def in_container() -> bool:
    return os.path.exists("/.dockerenv")


def call(op: str, db_path: str = "", **params):
    """Run *op* with *params*; return its result or raise HostDBError."""
    if in_container():
        return _call_http(op, params)
    return _call_local(op, db_path or HOST_DB_PATH, params)


def _call_local(op: str, db_path: str, params: dict):
    import sqlite3
    import db_ops
    conn = sqlite3.connect(db_path, timeout=30)
    try:
        conn.execute("PRAGMA busy_timeout=15000")
        return db_ops.run(op, conn, **params)
    except (sqlite3.Error, db_ops.UnknownOp, TypeError, ValueError) as e:
        raise HostDBError(f"{op}: {type(e).__name__}: {e}") from e
    finally:
        conn.close()


def _call_http(op: str, params: dict, _sleep=time.sleep, _urlopen=None):
    """POST the op to the host. Retries only while the host is unreachable or
    answering 5xx; a 4xx is a bug in the call and is raised immediately."""
    url = f"{os.environ.get('DASHBOARD_URL', DEFAULT_DASHBOARD_URL)}/api/hostdb/{op}"
    body = json.dumps(params).encode()
    opener = _urlopen or urllib.request.urlopen
    last = None
    for delay in (0,) + RETRY_DELAYS:
        if delay:
            _sleep(delay)
        req = urllib.request.Request(url, data=body, method="POST",
                                     headers={"Content-Type": "application/json"})
        try:
            with opener(req, timeout=REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            detail = _error_text(e)
            if e.code < 500:
                raise HostDBError(f"{op}: host rejected the call (HTTP {e.code}): {detail}") from e
            last = f"HTTP {e.code}: {detail}"
            continue
        except (urllib.error.URLError, OSError, ValueError) as e:
            last = f"{type(e).__name__}: {e}"
            continue
        if not data.get("ok"):
            raise HostDBError(f"{op}: {data.get('error', 'host returned ok=false')}")
        return data.get("result")
    raise HostDBError(f"{op}: host unreachable after {len(RETRY_DELAYS) + 1} tries ({last})")


def _error_text(e) -> str:
    try:
        return json.loads(e.read() or b"{}").get("error", "") or str(e)
    except (ValueError, OSError):
        return str(e)


# ── container tripwire ────────────────────────────────────────────────────────
# Converting every call site is not the same as guaranteeing none is left:
# duo_automation.py and onboard_router.py still open the file on host-only
# paths, and a future edit could reach one from a container. Inside a
# container, refuse outright — a loud failure at the call site instead of a
# wedge an hour later that nobody can trace back to it.

DB_FILENAME = "pod_state.db"


def _is_pod_state_path(database) -> bool:
    try:
        name = os.path.basename(os.fspath(database))
    except TypeError:
        return False
    return name == DB_FILENAME or name.startswith(DB_FILENAME + "-")


def install_container_guard(sqlite3_module=None) -> bool:
    """Make sqlite3.connect refuse pod_state.db. Idempotent; returns True if armed."""
    import sqlite3 as _default
    mod = sqlite3_module or _default
    if getattr(mod.connect, "_hostdb_guard", False):
        return True
    real = mod.connect

    def connect(database, *args, **kwargs):
        if _is_pod_state_path(database):
            raise mod.OperationalError(
                f"refusing to open {database!r} from a container — use "
                f"hostdb.call(<op>, ...) so the host dashboard does the access "
                f"(WAL across the bind mount wedges it; see db_ops.py)")
        return real(database, *args, **kwargs)

    connect._hostdb_guard = True
    connect._hostdb_real = real
    mod.connect = connect
    return True


if in_container():
    install_container_guard()
