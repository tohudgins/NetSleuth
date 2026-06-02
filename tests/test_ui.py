"""Smoke tests for the rich UI rendering — no live network."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

from netsleuth.analyzer import AnomalyFlag
from netsleuth.defense import DefenseAlert
from netsleuth.discovery import DiscoveryReport, Host
from netsleuth.scanner import PortResult, PortState, Protocol, ScanReport
from netsleuth.sniffer import PacketSummary, TrafficStats
from netsleuth.ui import (
    render_dashboard,
    render_defense,
    render_discovery_table,
    render_scan_table,
)


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
    # Sample has 1 open + 1 closed; by default only the open port is listed and
    # the closed one is summarised in the caption.
    table = render_scan_table(_sample_report())
    assert isinstance(table, Table)
    assert table.row_count == 1
    assert [c.header for c in table.columns] == [
        "Port", "Proto", "State", "Service", "Banner",
    ]
    assert table.caption is not None and "1 closed" in table.caption


def test_render_scan_table_show_closed():
    table = render_scan_table(_sample_report(), show_closed=True)
    assert table.row_count == 2
    assert table.caption is None


def test_render_dashboard_renders_to_text():
    stats = TrafficStats()
    stats.record(PacketSummary(0.0, "10.0.0.1", "10.0.0.2", "TCP", 100, "TCP info"))
    recent = [PacketSummary(0.0, "10.0.0.1", "10.0.0.2", "TCP", 100, "TCP info")]
    anomalies = [AnomalyFlag("port-scan", "warning", "demo")]
    defense = [DefenseAlert("duplicate-ip", "critical", "gateway dup")]

    dashboard = render_dashboard(_sample_report(), stats, anomalies, recent,
                                 defense=defense)
    # Render to a string buffer to prove the renderable is well-formed.
    console = Console(file=None, width=100, record=True)
    console.print(dashboard)
    out = console.export_text()
    assert "connect scan of 127.0.0.1" in out
    assert "Traffic" in out
    assert "Recent packets" in out
    assert "Anomaly flags" in out
    assert "MITM alerts" in out


def test_render_discovery_table_shape():
    report = DiscoveryReport(
        network="192.168.1.0/24", method="arp-sweep",
        hosts=[Host("192.168.1.1", "08:00:27:ab:cd:ef", "VirtualBox", "arp", [80])],
    )
    table = render_discovery_table(report)
    assert isinstance(table, Table)
    assert table.row_count == 1
    assert [c.header for c in table.columns][0] == "IP"


def test_render_defense_all_clear_and_alerts():
    console = Console(file=None, width=100, record=True)
    console.print(render_defense([]))
    assert "no spoofing signs" in console.export_text()

    console2 = Console(file=None, width=100, record=True)
    console2.print(render_defense([DefenseAlert("arp-mac-change", "critical", "x")]))
    assert "arp-mac-change" in console2.export_text()
