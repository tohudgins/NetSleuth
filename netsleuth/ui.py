"""NetSleuth CLI presentation — ``rich`` rendering for the scanner.

Pure presentation: it reads scanner results and renders them. It holds no
scanning or capture logic. A live traffic dashboard arrives with the sniffer in
Phase 3; this module currently covers the privilege notice, the scan results
table, and a scan progress bar.
"""

from __future__ import annotations

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from .scanner import PortState, ScanReport

console = Console()

# Colour per port state so the table reads at a glance.
_STATE_STYLE = {
    PortState.OPEN: "bold green",
    PortState.OPEN_FILTERED: "yellow",
    PortState.FILTERED: "dim",
    PortState.CLOSED: "red",
}


def print_privilege_notice(notice: str) -> None:
    """Render the privilege line, styling the unprivileged warning."""
    if notice.startswith("Privileged"):
        console.print(notice, style="green")
    else:
        console.print(notice, style="bold yellow")


def render_scan_table(report: ScanReport) -> Table:
    """Build a rich Table of the scan results (returned so it's unit-testable)."""
    title = f"{report.scan_type} scan of {report.target}"
    table = Table(title=title, header_style="bold cyan", expand=False)
    table.add_column("Port", justify="right")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Banner", overflow="fold")

    for r in report.ports:
        style = _STATE_STYLE.get(r.state, "")
        table.add_row(
            str(r.port),
            r.proto.value,
            f"[{style}]{r.state.value}[/{style}]" if style else r.state.value,
            r.service_hint or "",
            r.banner or "",
        )
    return table


def make_scan_progress() -> Progress:
    """A Progress widget for the scan; caller adds a task and advances it."""
    return Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    )
