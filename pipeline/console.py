from __future__ import annotations

from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn


def print_item(console: Console, label: str, value) -> None:
    console.print(f"  [dim]{label:<12}[/dim] {value}")


def print_step(console: Console, title: str) -> None:
    console.print()
    console.print(f"[bold]{title}[/bold]")


def make_progress(console: Console) -> Progress:
    return Progress(
        SpinnerColumn(),
        TextColumn("{task.description}"),
        BarColumn(bar_width=24),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    )
