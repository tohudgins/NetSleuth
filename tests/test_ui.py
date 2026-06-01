"""Smoke tests for the rich UI rendering — no live network."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from netsleuth.analyzer import AnomalyFlag
from netsleuth.scanner import PortResult, PortState, Protocol, ScanReport
from netsleuth.sniffer import PacketSummary, TrafficStats
from netsleuth.ui import render_dashboard, render_scan_table


def _sample_report() -> ScanReport:
    return ScanReport(
        target="127.0.0.1",
        scan_type="connect",
        proto=Protocol.TCP,
        ports=[
            PortResult(22, PortState.OPEN, Protocol.TCP, "SSH-2.0", "ssh"),
            PortResult(80, PortState.CLOSED, Protocol.TCP),
        ],
    )


def test_render_scan_table_shape():
    table = render_scan_table(_sample_report())
    assert isinstance(table, Table)
    assert table.row_count == 2
    assert [c.header for c in table.columns] == [
        "Port", "Proto", "State", "Service", "Banner",
    ]


def test_render_dashboard_renders_to_text():
    stats = TrafficStats()
    stats.record(PacketSummary(0.0, "10.0.0.1", "10.0.0.2", "TCP", 100, "TCP info"))
    recent = [PacketSummary(0.0, "10.0.0.1", "10.0.0.2", "TCP", 100, "TCP info")]
    anomalies = [AnomalyFlag("port-scan", "warning", "demo")]

    dashboard = render_dashboard(_sample_report(), stats, anomalies, recent)
    # Render to a string buffer to prove the renderable is well-formed.
    console = Console(file=None, width=100, record=True)
    console.print(dashboard)
    out = console.export_text()
    assert "connect scan of 127.0.0.1" in out
    assert "Traffic" in out
    assert "Recent packets" in out
    assert "Anomaly flags" in out
