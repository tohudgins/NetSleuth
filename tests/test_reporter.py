"""Unit tests for the reporter (JSON + HTML) — Phase 3."""

from __future__ import annotations

import json

from netsleuth.analyzer import AnomalyFlag
from netsleuth.reporter import build_report, to_html, to_json, write_report
from netsleuth.scanner import PortResult, PortState, Protocol, ScanReport
from netsleuth.sniffer import PacketSummary, TrafficStats


def _scan_report() -> ScanReport:
    return ScanReport(
        target="127.0.0.1",
        scan_type="connect",
        proto=Protocol.TCP,
        ports=[PortResult(80, PortState.OPEN, Protocol.TCP, "nginx", "http")],
    )


def _stats() -> TrafficStats:
    s = TrafficStats()
    s.record(PacketSummary(0.0, "10.0.0.1", "10.0.0.2", "TCP", 100, "x"))
    return s


def test_build_report_scan_only():
    rep = build_report(scan=_scan_report())
    assert rep["scan"]["target"] == "127.0.0.1"
    assert rep["scan"]["open_ports"] == [80]
    assert "traffic" not in rep and "anomalies" not in rep
    assert rep["authorized_use_only"] is True


def test_to_json_roundtrips():
    rep = build_report(scan=_scan_report(), stats=_stats())
    parsed = json.loads(to_json(rep))
    assert parsed["scan"]["ports"][0]["state"] == "open"
    assert parsed["traffic"]["packets"] == 1


def test_to_html_contains_sections():
    rep = build_report(
        scan=_scan_report(),
        stats=_stats(),
        anomalies=[AnomalyFlag("port-scan", "warning", "demo detail")],
    )
    html = to_html(rep)
    assert "NetSleuth Report" in html
    assert "127.0.0.1" in html
    assert "demo detail" in html
    assert "Authorized use only" in html


def test_write_report_creates_files(tmp_path):
    rep = build_report(scan=_scan_report())
    paths = write_report(tmp_path, rep)
    assert paths["json"].exists() and paths["html"].exists()
    assert "127.0.0.1" in paths["json"].read_text()


def test_scan_only_html_omits_anomalies_section():
    # Without capture, the anomalies key is absent — the section must not render
    # a misleading "None detected" (regression: Undefined is not none -> True).
    html = to_html(build_report(scan=_scan_report()))
    assert "Anomaly flags" not in html


def test_empty_anomalies_shows_none_detected():
    html = to_html(build_report(scan=_scan_report(), stats=_stats(), anomalies=[]))
    assert "Anomaly flags" in html
    assert "None detected" in html


def test_open_filtered_state_css_class():
    report = ScanReport(
        target="127.0.0.1", scan_type="udp-connect", proto=Protocol.UDP,
        ports=[PortResult(53, PortState.OPEN_FILTERED, Protocol.UDP)],
    )
    html = to_html(build_report(scan=report))
    assert "state-open-filtered" in html
