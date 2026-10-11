"""Failed SD-WAN steps must say why.

POD-12's redeploy logged "Deploy task failed:" and POD-7's copy_bootstrap logged
"copy_bootstrap FAILED:" with nothing after the colon (2026-10-11); the real
cause was only in the docker logs.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import onboard_router as o  # noqa: E402


def test_details_wins_when_present():
    body = {"data": [{"details": "Template push failed", "currentActivity": "x"}]}
    assert o._vmanage_task_reason(body) == "Template push failed"


def test_empty_details_falls_back_to_current_activity():
    body = {"data": [{"details": "", "currentActivity": "Device is unreachable"}]}
    assert o._vmanage_task_reason(body) == "Device is unreachable"


def test_falls_back_to_last_activity_line():
    body = {"data": [{"activity": ["Started", "Config push timed out"]}]}
    assert o._vmanage_task_reason(body) == "Config push timed out"


def test_never_returns_empty():
    assert o._vmanage_task_reason({"data": [{}]})
    assert o._vmanage_task_reason({})
