"""NetSleuth CLI presentation — ``rich`` rendering for scanner and sniffer.

Pure presentation: it reads scanner/sniffer/analyzer results and renders them.
It holds no scanning or capture logic. Covers the privilege notice, the scan
results table, a scan progress bar, live packet lines, a traffic-stats table,
and the integrated live dashboard.
"""

from __future__ import annotations

import time

from rich.console import Console, Group, RenderableType
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from .analyzer import AnomalyFlag
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
    protos = ", ".join(
        f"{proto}:{count}"
        for proto, count in sorted(stats.by_proto.items(), key=lambda kv: -kv[1])
    )
    title = f"Traffic — {stats.packets} pkts / {stats.bytes} bytes"
    if protos:
        title += f"  [{protos}]"
    table = Table(title=title, header_style="bold cyan", expand=False)
    table.add_column("Source IP")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    for ip, counter in stats.top(top):
        table.add_row(ip, str(counter.packets), str(counter.bytes))
    return table


def render_cve_table(cve_by_port: dict[int, list]) -> Table:
    """Build a rich Table of candidate CVEs per port (returned for testing)."""
    table = Table(title="Candidate CVEs (keyword match — verify before acting)",
                  header_style="bold red", expand=False)
    table.add_column("Port", justify="right")
    table.add_column("CVE")
    table.add_column("CVSS", justify="right")
    table.add_column("Summary", overflow="fold")
    for port in sorted(cve_by_port):
        for entry in cve_by_port[port]:
            table.add_row(str(port), entry.id, entry.cvss or "—", entry.summary)
    return table


def render_anomalies(anomalies: list[AnomalyFlag]) -> Panel:
    """Panel listing heuristic anomaly flags (or an all-clear)."""
    if not anomalies:
        body: RenderableType = "[green]no anomalies flagged[/green]"
    else:
        lines = [f"[bold red][{a.kind}][/bold red] {a.detail}" for a in anomalies]
        body = "\n".join(lines)
    return Panel(body, title="Anomaly flags (heuristic)", border_style="red")


def render_recent_packets(recent: list[PacketSummary]) -> Panel:
    """Panel of the most recent capture lines, newest last."""
    lines = []
    for s in recent:
        style = _PROTO_STYLE.get(s.proto, "white")
        lines.append(f"[{style}]{s.proto:<5}[/{style}] {s.length:>5}B  {s.info}")
    body: RenderableType = "\n".join(lines) if lines else "[dim]waiting…[/dim]"
    return Panel(body, title="Recent packets", border_style="blue")


def render_dashboard(
    scan_report: ScanReport,
    stats: TrafficStats,
    anomalies: list[AnomalyFlag],
    recent: list[PacketSummary],
) -> RenderableType:
    """Compose the integrated dashboard renderable (scan + live traffic)."""
    return Group(
        render_scan_table(scan_report),
        render_traffic_table(stats),
        render_recent_packets(recent),
        render_anomalies(anomalies),
    )
