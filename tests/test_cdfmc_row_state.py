"""cdFMC Application Instances: which row is the ACTIVE one.

The success icon alone was seen reporting active for a "Not Activated" row
(2026-09-23). cdFMC disables the delete control on the active row only, so that
decides when the row has one.

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dashboard as d  # noqa: E402


def sig(**kw):
    base = {"name": "ISE-FMC-POD-POD-4-3649", "text": "ISE-FMC-POD-POD-4-3649\nTenant ID: PseudoCo-510",
            "has_delete": True, "delete_disabled": False, "icon_success": True}
    base.update(kw)
    return base


def test_enabled_delete_is_not_active_even_with_success_icon():
    assert d._cdfmc_row_is_active(sig()) is False


def test_disabled_delete_is_active():
    assert d._cdfmc_row_is_active(sig(delete_disabled=True)) is True


def test_not_activated_text_wins():
    assert d._cdfmc_row_is_active(
        sig(delete_disabled=True, text="X\nNot Activated")) is False


def test_no_delete_control_falls_back_to_icon():
    assert d._cdfmc_row_is_active(sig(has_delete=False, icon_success=True)) is True
    assert d._cdfmc_row_is_active(sig(has_delete=False, icon_success=False)) is False


def test_signals_js_is_one_function_expression():
    # composed into "...map(" + JS + ")" and passed to locator.evaluate directly
    js = d._CDFMC_ROW_SIGNALS_JS.strip()
    assert js.startswith("(r) =>") and js.endswith("}")
