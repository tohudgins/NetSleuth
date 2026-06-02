"""NetSleuth CLI presentation — ``rich`` rendering for scanner and sniffer.

Pure presentation: it reads scanner/sniffer/analyzer results and renders them.
It holds no scanning or capture logic. Covers the privilege notice, the scan
results table, a scan progress bar, live packet lines, a traffic-stats table,
and the integrated live dashboard.
"""

from __future__ import annotations

import time

from rich.console import Console, Group, RenderableType
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table

from .analyzer import AnomalyFlag
from .defense import DefenseAlert
from .discovery import DiscoveryReport
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

# Colour per protocol for live capture lines (mirrors the web palette).
_PROTO_STYLE = {
    "TCP": "cyan",
    "UDP": "blue",
    "ICMP": "magenta",
    "ICMPv6": "magenta",
    "ARP": "yellow",
    "DNS": "green",
    "IP": "white",
    "IPv6": "white",
    "OTHER": "white",
}


def print_privilege_notice(notice: str) -> None:
    """Render the privilege line, styling the unprivileged warning."""
    if notice.startswith("Privileged"):
        console.print(notice, style="green")
    else:
        console.print(notice, style="bold yellow")


# Port states worth listing row-by-row; everything else is summarised.
_SHOWN_STATES = {PortState.OPEN, PortState.OPEN_FILTERED}


def render_scan_table(report: ScanReport, *, show_closed: bool = False) -> Table:
    """Build a rich Table of the scan results (returned so it's unit-testable).

    By default only open / open|filtered ports get a row; the rest are collapsed
    into a one-line caption (like nmap's "Not shown: N closed ports"). Pass
    show_closed=True to list every port.
    """
    title = f"{report.scan_type} scan of {report.target}"
    table = Table(title=title, header_style="bold cyan", expand=False)
    table.add_column("Port", justify="right")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Banner", overflow="fold")

    hidden: dict[str, int] = {}
    for r in report.ports:
        if not show_closed and r.state not in _SHOWN_STATES:
            hidden[r.state.value] = hidden.get(r.state.value, 0) + 1
            continue
        style = _STATE_STYLE.get(r.state, "")
        table.add_row(
            str(r.port),
            r.proto.value,
            f"[{style}]{r.state.value}[/{style}]" if style else r.state.value,
            escape(r.service_hint or ""),
            escape(r.banner or ""),  # banner is remote-controlled — escape markup
        )

    if hidden:
        summary = ", ".join(f"{n} {state}" for state, n in sorted(hidden.items()))
        table.caption = f"Not shown: {summary}  (use --show-closed to list)"
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
    # escape() the info string: it contains literal brackets (e.g. TCP "[S]"
    # flags) that rich would otherwise swallow as markup tags.
    console.print(
        f"[dim]{clock}[/dim] [{style}]{summary.proto:<5}[/{style}] "
        f"{summary.length:>5}B  {escape(summary.info)}"
    )


def render_traffic_table(stats: TrafficStats, top: int = 10) -> Table:
    """Build a rich Table of the top talkers by volume (returned for testing)."""
    protos = ", ".join(
        f"{proto}:{count}"
        for proto, count in sorted(stats.by_proto.items(), key=lambda kv: -kv[1])
    )
    title = f"Traffic — {stats.packets} pkts / {stats.bytes} bytes"
    if protos:
        title += "  " + escape(f"[{protos}]")  # bracketed text, not rich markup
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
            table.add_row(str(port), escape(entry.id), entry.cvss or "—",
                          escape(entry.summary))  # NVD text — escape markup
    return table


def render_discovery_table(report: DiscoveryReport) -> Table:
    """Build a rich Table of discovered hosts (returned for testing)."""
    title = (f"Host discovery — {report.count} up on {report.network} "
             f"({report.method})")
    table = Table(title=title, header_style="bold cyan", expand=False)
    table.add_column("IP")
    table.add_column("MAC")
    table.add_column("Vendor (best guess)")
    table.add_column("Via")
    table.add_column("Open ports")
    for h in report.hosts:
        ports = ", ".join(str(p) for p in h.open_ports) if h.open_ports else "—"
        table.add_row(h.ip, h.mac or "—", h.vendor or "—", h.method, ports)
    return table


# Defense-alert severity colours, deepest red for the critical gateway case.
_SEVERITY_STYLE = {"info": "cyan", "warning": "yellow", "critical": "bold red"}


def render_defense(alerts: list[DefenseAlert]) -> Panel:
    """Panel listing ARP-spoofing / MITM alerts (or an all-clear)."""
    if not alerts:
        body: RenderableType = "[green]no spoofing signs detected[/green]"
    else:
        lines = []
        for a in alerts:
            style = _SEVERITY_STYLE.get(a.severity, "yellow")
            lines.append(
                f"[{style}]{escape(f'[{a.kind}]')}[/{style}] {escape(a.detail)}"
            )
        body = "\n".join(lines)
    return Panel(body, title="ARP-spoofing / MITM alerts (heuristic)",
                 border_style="red")


def render_anomalies(anomalies: list[AnomalyFlag]) -> Panel:
    """Panel listing heuristic anomaly flags (or an all-clear)."""
    if not anomalies:
        body: RenderableType = "[green]no anomalies flagged[/green]"
    else:
        lines = [
            f"[bold red]{escape(f'[{a.kind}]')}[/bold red] {escape(a.detail)}"
            for a in anomalies
        ]
        body = "\n".join(lines)
    return Panel(body, title="Anomaly flags (heuristic)", border_style="red")


def render_recent_packets(recent: list[PacketSummary]) -> Panel:
    """Panel of the most recent capture lines, newest last."""
    lines = []
    for s in recent:
        style = _PROTO_STYLE.get(s.proto, "white")
        lines.append(
            f"[{style}]{s.proto:<5}[/{style}] {s.length:>5}B  {escape(s.info)}"
        )
    body: RenderableType = "\n".join(lines) if lines else "[dim]waiting…[/dim]"
    return Panel(body, title="Recent packets", border_style="blue")


def render_dashboard(
    scan_report: ScanReport,
    stats: TrafficStats,
    anomalies: list[AnomalyFlag],
    recent: list[PacketSummary],
    *,
    defense: list[DefenseAlert] | None = None,
    show_closed: bool = False,
) -> RenderableType:
    """Compose the integrated dashboard renderable (scan + live traffic)."""
    sections: list[RenderableType] = [
        render_scan_table(scan_report, show_closed=show_closed),
        render_traffic_table(stats),
        render_recent_packets(recent),
    ]
    if defense is not None:
        sections.append(render_defense(defense))
    sections.append(render_anomalies(anomalies))
    return Group(*sections)
