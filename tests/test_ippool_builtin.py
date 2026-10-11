"""The Secure Access reset must leave the built-in IP pool alone.

Its delete control is disabled, and the reset used to land on it once the lab
pool was gone, spending 3 x 8s click timeouts and logging them as failures on
every POD (2026-10-11).

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dashboard as d  # noqa: E402


class FakeControl:
    def __init__(self, disabled=False, aria=None, cls=""):
        self._disabled, self._aria, self._cls = disabled, aria, cls

    def is_disabled(self, timeout=None):
        return self._disabled

    def evaluate(self, js):
        return self._aria == "true" or "disabled" in self._cls.lower()


def test_native_disabled_control_is_skipped():
    assert d._ippool_control_disabled(FakeControl(disabled=True)) is True


def test_aria_disabled_control_is_skipped():
    assert d._ippool_control_disabled(FakeControl(aria="true")) is True


def test_class_disabled_control_is_skipped():
    assert d._ippool_control_disabled(FakeControl(cls="btn btn--disabled")) is True


def test_live_control_is_used():
    assert d._ippool_control_disabled(FakeControl()) is False


def test_unreadable_control_is_treated_as_live():
    class Broken:
        def is_disabled(self, timeout=None):
            raise RuntimeError("detached")

        def evaluate(self, js):
            raise RuntimeError("detached")
    # Unknown must not hide a deletable pool: fall through to the click path.
    assert d._ippool_control_disabled(Broken()) is False
