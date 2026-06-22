from __future__ import annotations

from typing import Callable, Optional, TypeVar

from rich.console import Console
from rich.table import Table

T = TypeVar("T")

_console = Console()


class PickCancelled(KeyboardInterrupt):
    """Raised when the user cancels a selection (Ctrl-C or EOF)."""


def pick_from_list(
    items: list[T],
    prompt: str,
    display_fn: Callable[[T], str] = str,
    filter_name: Optional[str] = None,
    auto_select: bool = False,
    console: Optional[Console] = None,
) -> T:
    """Display a numbered list and return the chosen item.

    Args:
        items: Objects to pick from.
        prompt: Heading shown above the list.
        display_fn: Converts an item to a display string (default: ``str``).
        filter_name: If provided, narrows *items* to those whose display
            string contains this substring (case-insensitive).  If no items
            match the filter, the full list is shown instead.
        auto_select: If ``True`` **and** exactly one item remains after
            filtering, return it immediately without prompting.
        console: Rich Console to use (defaults to the module-level instance —
            override in tests to capture output).

    Returns:
        The selected item.

    Raises:
        ValueError: If *items* is empty.
        PickCancelled: If the user interrupts (Ctrl-C / EOF).
    """
    if not items:
        raise ValueError("No items to pick from.")

    con = console or _console

    # ------------------------------------------------------------------ #
    # Filter
    # ------------------------------------------------------------------ #
    if filter_name:
        filtered = [i for i in items if filter_name.lower() in display_fn(i).lower()]
        working = filtered if filtered else items
    else:
        working = items

    # ------------------------------------------------------------------ #
    # Auto-select
    # ------------------------------------------------------------------ #
    if auto_select and len(working) == 1:
        return working[0]

    # ------------------------------------------------------------------ #
    # Render table
    # ------------------------------------------------------------------ #
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Index", style="cyan", width=4, no_wrap=True)
    table.add_column("Name")

    for idx, item in enumerate(working, start=1):
        table.add_row(str(idx), display_fn(item))

    con.print(f"\n[bold]{prompt}[/bold]")
    con.print(table)

    # ------------------------------------------------------------------ #
    # Input loop
    # ------------------------------------------------------------------ #
    while True:
        try:
            raw = con.input(f"  Enter number [1-{len(working)}]: ").strip()
        except (EOFError, KeyboardInterrupt):
            raise PickCancelled("Selection cancelled.")

        try:
            idx = int(raw)
        except ValueError:
            con.print(f"  [red]Please enter a number between 1 and {len(working)}[/red]")
            continue

        if 1 <= idx <= len(working):
            return working[idx - 1]

        con.print(f"  [red]Please enter a number between 1 and {len(working)}[/red]")
