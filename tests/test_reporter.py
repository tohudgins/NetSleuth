"""Unit tests for the reporter (JSON + HTML) — Phase 3."""

from __future__ import annotations

import json

from netsleuth.analyzer import AnomalyFlag
from netsleuth.defense import DefenseAlert
from netsleuth.discovery import DiscoveryReport, Host
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
    assert "none detected" in html.lower()


def _discovery() -> DiscoveryReport:
    return DiscoveryReport(
        network="192.168.1.0/24", method="arp-sweep",
        hosts=[Host(ip="192.168.1.1", mac="08:00:27:ab:cd:ef",
                    vendor="VirtualBox", method="arp", open_ports=[80])],
    )


def test_build_report_discovery_section():
    rep = build_report(discovery=_discovery())
    assert rep["discovery"]["count"] == 1
    assert rep["discovery"]["hosts"][0]["vendor"] == "VirtualBox"


def test_build_report_defense_section():
    rep = build_report(defense=[DefenseAlert("duplicate-ip", "critical", "demo")])
    assert rep["defense"][0]["severity"] == "critical"


def test_html_renders_discovery_and_defense():
    rep = build_report(
        discovery=_discovery(),
        defense=[DefenseAlert("arp-mac-change", "critical", "gateway MAC changed")],
    )
    html = to_html(rep)
    assert "192.168.1.1" in html
    assert "VirtualBox" in html
    assert "MITM alerts" in html
    assert "gateway MAC changed" in html
    assert "anom critical" in html  # severity-styled class


def test_html_omits_discovery_when_absent():
    html = to_html(build_report(scan=_scan_report()))
    assert "Host discovery" not in html
    assert "MITM alerts" not in html


def test_build_report_and_html_diff_section():
    diff = {"kind": "discovery", "empty": False, "network": "10.0.0.0/24",
            "hosts_added": [{"ip": "10.0.0.9", "mac": "aa:bb:cc:dd:ee:ff"}],
            "hosts_removed": [], "vendor_changed": [], "ports_changed": [],
            "mac_changed": [{"ip": "10.0.0.1", "from": "aa", "to": "bb"}]}
    rep = build_report(diff=diff)
    assert rep["diff"]["kind"] == "discovery"
    html = to_html(rep)
    assert "Changes since last run" in html
    assert "10.0.0.9" in html
    assert "MAC changed" in html  # the security-relevant delta


def test_html_omits_diff_when_absent():
    assert "Changes since last run" not in to_html(build_report(scan=_scan_report()))


def test_open_filtered_state_css_class():
    report = ScanReport(
        target="127.0.0.1", scan_type="udp-connect", proto=Protocol.UDP,
        ports=[PortResult(53, PortState.OPEN_FILTERED, Protocol.UDP)],
    )
    html = to_html(build_report(scan=report))
    assert "state-open-filtered" in html
