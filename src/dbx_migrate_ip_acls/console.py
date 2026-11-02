"""Shared Rich console, theme, and rendering helpers.

Everything the CLI prints goes through here so the look stays consistent: a single themed
`console`, plus helpers for the recurring shapes — a decisions/config panel, a pandas DataFrame as a
Rich table (row-capped for terminal readability), a syntax-highlighted JSON preview, and the
severity banners (info / warn / danger / success) the notebooks emitted as emoji prints.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from typing import Any

import pandas as pd
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

# One theme, referenced everywhere by semantic name rather than raw colour.
THEME = Theme(
    {
        "brand": "bold #FF3621",  # Databricks red
        "info": "cyan",
        "muted": "dim",
        "ok": "bold green",
        "warn": "bold yellow",
        "danger": "bold red",
        "heading": "bold white",
        "key": "bold cyan",
        "value": "white",
        "enforce": "bold red",
        "dry_run": "bold green",
    }
)

console = Console(theme=THEME, highlight=False)

# Default cap on rows rendered to the terminal, so a very large IP access list stays readable.
MAX_TABLE_ROWS = 100

# ASCII splash (figlet "small") shown at startup so it's immediately clear which tool is running.
_APP_BANNER = r"""
 ____        _        _          _      _
|  _ \  __ _| |_ __ _| |__  _ __(_) ___| | _____
| | | |/ _` | __/ _` | '_ \| '__| |/ __| |/ / __|
| |_| | (_| | || (_| | |_) | |  | | (__|   <\__ \
|____/ \__,_|\__\__,_|_.__/|_|  |_|\___|_|\_\___/
 __  __ _                 _         ___ ____       _    ____ _
|  \/  (_) __ _ _ __ __ _| |_ ___  |_ _|  _ \     / \  / ___| |    ___
| |\/| | |/ _` | '__/ _` | __/ _ \  | || |_) |   / _ \| |   | |   / __|
| |  | | | (_| | | | (_| | ||  __/  | ||  __/   / ___ \ |___| |___\__ \
|_|  |_|_|\__, |_|  \__,_|\__\___| |___|_|     /_/   \_\____|_____|___/
          |___/
"""


def app_banner() -> None:
    """Print the tool's ASCII-art splash at startup, before anything else, so users can see at a
    glance what they're running."""
    console.print(Text(_APP_BANNER.strip("\n"), style="brand"))


def banner(kind: str, message: str) -> None:
    """Print a one-line severity banner. kind in {info, warn, danger, success}."""
    # Glyphs are stored bare; the single separating space is added here, so there's always exactly
    # one space between the emoji and the message (and no glyph ever ships without one).
    glyphs = {
        "info": ("ℹ️", "info"),
        "warn": ("⚠️", "warn"),
        "danger": ("⛔", "danger"),
        "success": ("✅", "ok"),
    }
    glyph, style = glyphs.get(kind, ("", "value"))
    text = f"{glyph} {message}" if glyph else message
    console.print(Text(text, style=style))


def rule(title: str) -> None:
    """A titled horizontal rule to separate sections."""
    console.rule(f"[heading]{title}[/heading]", style="brand")


def title_panel(title: str, subtitle: str | None = None) -> None:
    """The banner shown at the top of a command run."""
    body = Text(title, style="brand")
    if subtitle:
        body.append(f"\n{subtitle}", style="muted")
    console.print(Panel(body, border_style="brand", expand=False))


def workspace_panel(profile: str, host: str, workspace_id: Any) -> None:
    """A prominent panel naming the workspace this run will read from and act on (profile / URL /
    id), so the user is never in doubt about the target before analysis or any write."""
    body = Text()
    body.append("This run will analyse and (if you apply) modify:\n\n", style="heading")
    for label, value in (
        ("profile      ", profile),
        ("workspace URL", host),
        ("workspace id ", workspace_id),
    ):
        body.append(f"  {label}  ", style="key")
        body.append(f"{value}\n", style="value")
    console.print(Panel(body, title="[brand]Target workspace[/brand]", border_style="brand", expand=False))


def decisions_panel(title: str, rows: list[tuple[str, Any, str]]) -> None:
    """Render the run's configuration as a key / value / meaning table inside a panel — the CLI
    equivalent of the notebooks' `_decisions` DataFrame."""
    table = Table(show_header=True, header_style="heading", box=None, pad_edge=False, expand=True)
    table.add_column("Setting", style="key", no_wrap=True)
    table.add_column("Value", style="value")
    table.add_column("Meaning", style="muted")
    for name, value, meaning in rows:
        # Show the dash form (matching the actual CLI flags) so a copied name works as `--<name>`.
        table.add_row(name.replace("_", "-"), _fmt_value(value), meaning)
    console.print(Panel(table, title=f"[heading]{title}[/heading]", border_style="info"))


def _fmt_value(value: Any) -> str:
    if isinstance(value, bool):
        return "[ok]true[/ok]" if value else "[muted]false[/muted]"
    if value is None or value == "":
        return "[muted](unset)[/muted]"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value) if value else "[muted](none)[/muted]"
    return str(value)


def dataframe(
    df: pd.DataFrame, title: str, max_rows: int = MAX_TABLE_ROWS, highlight_col: str | None = None
) -> None:
    """Render a pandas DataFrame as a Rich table, capped to `max_rows`. If `highlight_col` is given
    and truthy for a row, that row is styled as a warning (used for the threat-match table)."""
    if df is None or df.empty:
        console.print(f"[muted]{title}: (no rows)[/muted]")
        return
    table = Table(
        title=f"[heading]{title}[/heading]",
        header_style="heading",
        title_style="heading",
        show_lines=False,
        expand=False,
    )
    for col in df.columns:
        table.add_column(str(col), overflow="fold")
    shown = df.head(max_rows)
    for _, row in shown.iterrows():
        style = "warn" if (highlight_col and row.get(highlight_col)) else None
        table.add_row(*[_cell(v) for v in row], style=style)
    console.print(table)
    if len(df) > max_rows:
        console.print(f"[muted]… showing {max_rows:,} of {len(df):,} rows.[/muted]")


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, float) and pd.isna(value):
        return ""
    if isinstance(value, (list, tuple)):
        return ", ".join(str(v) for v in value)
    if hasattr(value, "tolist"):  # numpy array
        return ", ".join(str(v) for v in value.tolist())
    return str(value)


def json_panel(title: str, obj: Any) -> None:
    """Syntax-highlighted JSON preview of a policy block (nothing is sent — preview only)."""
    console.print(
        Panel(JSON(json.dumps(obj)), title=f"[heading]{title}[/heading]", border_style="info", expand=False)
    )


@contextmanager
def status(message: str):
    """A spinner for a long step (an API write, re-enabling lists)."""
    with console.status(f"[info]{message}[/info]", spinner="dots"):
        yield


def responsibility_warning() -> None:
    """Shown after the policy JSON preview on every run — including propose-only, since the printed
    JSON can be copied and used to create a policy elsewhere."""
    body = Text()
    body.append("⚠️ THIS IS A SECURITY-ENFORCING NETWORK POLICY\n\n", style="warn")
    body.append(
        "You are solely responsible for reviewing every entry and confirming it is accurate and "
        "appropriate before using it in a policy — whether you create it here or copy this JSON to "
        "create it elsewhere. An incorrect or incomplete allow-list can block legitimate users or "
        "workloads (in enforce mode) or fail to block malicious ones.",
        style="value",
    )
    console.print(
        Panel(body, title="[danger]Your responsibility[/danger]", border_style="danger", expand=False)
    )
