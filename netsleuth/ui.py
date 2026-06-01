"""NetSleuth CLI presentation — ``rich`` rendering for scanner and sniffer.

Pure presentation: it reads scanner/sniffer results and renders them. It holds
no scanning or capture logic. Covers the privilege notice, the scan results
table, a scan progress bar, live packet lines, and a traffic-stats table.
"""

from __future__ import annotations

import time

from rich.console import Console
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from .scanner import PortState, ScanReport
from .sniffer import PacketSummary, TrafficStats

console = Console()

# Colour per port state so the table reads at a glance.
_STATE_STYLE = {
    PortState.OPEN: "bold green",
    PortState.OPEN_FILTERED: "yellow",
    PortState.FILTERED: "dim",
    PortState.CLOSED: "red",
}

# Colour per protocol for live capture lines.
_PROTO_STYLE = {
    "TCP": "cyan",
    "UDP": "blue",
    "ICMP": "magenta",
    "ARP": "yellow",
    "DNS": "green",
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


def print_packet(summary: PacketSummary) -> None:
    """Print one live capture line, coloured by protocol."""
    clock = time.strftime("%H:%M:%S", time.localtime(summary.ts))
    style = _PROTO_STYLE.get(summary.proto, "white")
    console.print(
        f"[dim]{clock}[/dim] [{style}]{summary.proto:<5}[/{style}] "
        f"{summary.length:>5}B  {summary.info}"
    )


def render_traffic_table(stats: TrafficStats, top: int = 10) -> Table:
    """Build a rich Table of the top talkers by volume (returned for testing)."""
    title = f"Traffic — {stats.packets} pkts / {stats.bytes} bytes"
    table = Table(title=title, header_style="bold cyan", expand=False)
    table.add_column("Source IP")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    for ip, counter in stats.top(top):
        table.add_row(ip, str(counter.packets), str(counter.bytes))
    return table
