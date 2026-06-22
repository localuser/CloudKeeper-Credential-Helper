"""Tests for cli.ui.picker."""
from __future__ import annotations

from io import StringIO
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from cli.ui.picker import PickCancelled, pick_from_list


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _console_with_input(*responses: str) -> Console:
    """Return a Console whose .input() returns successive values."""
    con = MagicMock(spec=Console)
    con.input.side_effect = list(responses)
    return con


# ---------------------------------------------------------------------------
# Empty list
# ---------------------------------------------------------------------------


def test_raises_on_empty_list() -> None:
    with pytest.raises(ValueError, match="No items"):
        pick_from_list([], prompt="Pick")


# ---------------------------------------------------------------------------
# Auto-select
# ---------------------------------------------------------------------------


def test_auto_select_single_item_no_prompt() -> None:
    con = _console_with_input()  # no input needed
    result = pick_from_list(["only"], prompt="Pick", auto_select=True, console=con)
    assert result == "only"
    con.input.assert_not_called()


def test_auto_select_false_still_prompts_for_single_item() -> None:
    con = _console_with_input("1")
    result = pick_from_list(["only"], prompt="Pick", auto_select=False, console=con)
    assert result == "only"
    con.input.assert_called_once()


def test_auto_select_multiple_items_still_prompts() -> None:
    con = _console_with_input("2")
    result = pick_from_list(["a", "b"], prompt="Pick", auto_select=True, console=con)
    assert result == "b"


# ---------------------------------------------------------------------------
# Filter
# ---------------------------------------------------------------------------


def test_filter_narrows_list() -> None:
    con = _console_with_input("1")
    result = pick_from_list(
        ["Customer A - Admin", "Customer B - Dev", "Customer A - ReadOnly"],
        prompt="Pick",
        filter_name="Customer B",
        console=con,
    )
    assert result == "Customer B - Dev"


def test_filter_case_insensitive() -> None:
    con = _console_with_input("1")
    result = pick_from_list(
        ["PROD-account", "staging-account"],
        prompt="Pick",
        filter_name="prod",
        console=con,
    )
    assert result == "PROD-account"


def test_filter_no_match_falls_back_to_full_list() -> None:
    con = _console_with_input("2")
    result = pick_from_list(
        ["alpha", "beta"],
        prompt="Pick",
        filter_name="zzz-no-match",
        console=con,
    )
    assert result == "beta"


def test_filter_auto_select_single_match() -> None:
    con = _console_with_input()
    result = pick_from_list(
        ["Customer A - Admin", "Customer B - Dev", "Customer A - ReadOnly"],
        prompt="Pick",
        filter_name="Customer B",
        auto_select=True,
        console=con,
    )
    assert result == "Customer B - Dev"
    con.input.assert_not_called()


# ---------------------------------------------------------------------------
# Valid selection
# ---------------------------------------------------------------------------


def test_returns_correct_item_by_index() -> None:
    con = _console_with_input("3")
    result = pick_from_list(["x", "y", "z"], prompt="Pick", console=con)
    assert result == "z"


def test_display_fn_applied() -> None:
    items = [{"name": "Alpha"}, {"name": "Beta"}]
    con = _console_with_input("1")
    result = pick_from_list(
        items,
        prompt="Pick",
        display_fn=lambda i: i["name"],
        console=con,
    )
    assert result == {"name": "Alpha"}


# ---------------------------------------------------------------------------
# Invalid input → retry
# ---------------------------------------------------------------------------


def test_retries_on_non_numeric_input() -> None:
    con = _console_with_input("abc", "1")
    result = pick_from_list(["item"], prompt="Pick", console=con)
    assert result == "item"
    assert con.input.call_count == 2


def test_retries_on_out_of_range_input() -> None:
    con = _console_with_input("99", "0", "1")
    result = pick_from_list(["item"], prompt="Pick", console=con)
    assert result == "item"
    assert con.input.call_count == 3


# ---------------------------------------------------------------------------
# Cancellation
# ---------------------------------------------------------------------------


def test_keyboard_interrupt_raises_pick_cancelled() -> None:
    con = MagicMock(spec=Console)
    con.input.side_effect = KeyboardInterrupt
    with pytest.raises(PickCancelled):
        pick_from_list(["a"], prompt="Pick", console=con)


def test_eof_raises_pick_cancelled() -> None:
    con = MagicMock(spec=Console)
    con.input.side_effect = EOFError
    with pytest.raises(PickCancelled):
        pick_from_list(["a"], prompt="Pick", console=con)
