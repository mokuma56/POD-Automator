"""SGT verify must require the lab's full tag set, not "more than zero".

On 2026-10-11 PODs 3, 12 and 14 passed ise_sgt_verify with 2 tags while the
lab pushes 16 (counts above 16 are duplicates and fine).

Run: uv run --with pytest python3 -m pytest tests/ -q
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import dashboard as d  # noqa: E402


def test_two_tags_is_not_a_pass():
    assert d._sgt_count_ok(2) is False


def test_exactly_the_lab_set_passes():
    assert d._sgt_count_ok(16) is True


def test_duplicates_above_the_set_pass():
    assert d._sgt_count_ok(28) is True


def test_none_is_not_a_pass():
    assert d._sgt_count_ok(0) is False
