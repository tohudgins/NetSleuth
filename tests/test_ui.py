"""Smoke tests for the rich UI rendering — no live network."""

from __future__ import annotations

from rich.table import Table

from netsleuth.scanner import PortResult, PortState, Protocol, ScanReport
from netsleuth.ui import render_scan_table


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
