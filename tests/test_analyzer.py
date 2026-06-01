"""Unit tests for the analyzer anomaly heuristics — Phase 3.

Works off PacketSummary objects built in memory, so no scapy or capture needed.
"""

from __future__ import annotations

from netsleuth.analyzer import AnalysisConfig, analyze
from netsleuth.sniffer import PacketSummary


def _tcp(src, dst, dport, flags="S"):
    return PacketSummary(0.0, src, dst, "TCP", 60, "x", dport=dport, flags=flags)


def _arp(ip, mac):
    return PacketSummary(0.0, ip, "10.0.0.255", "ARP", 42, "x", mac=mac)


def test_port_scan_flagged():
    pkts = [_tcp("10.0.0.5", "10.0.0.1", port) for port in range(1, 21)]
    flags = analyze(pkts, AnalysisConfig(port_scan_ports=15))
    kinds = {f.kind for f in flags}
    assert "port-scan" in kinds
    assert any("10.0.0.5" in f.detail for f in flags)


def test_no_port_scan_below_threshold():
    pkts = [_tcp("10.0.0.5", "10.0.0.1", port) for port in range(1, 6)]
    flags = analyze(pkts, AnalysisConfig(port_scan_ports=15))
    assert all(f.kind != "port-scan" for f in flags)


def test_syn_flood_flagged():
    pkts = [_tcp("10.0.0.9", "10.0.0.1", 80, flags="S") for _ in range(120)]
    flags = analyze(pkts, AnalysisConfig(port_scan_ports=999, syn_flood_count=100))
    assert any(f.kind == "syn-flood" for f in flags)


def test_established_traffic_not_syn_flood():
    # SYN-ACK / ACK segments must not count as half-open SYNs.
    pkts = [_tcp("10.0.0.9", "10.0.0.1", 80, flags="SA") for _ in range(120)]
    flags = analyze(pkts, AnalysisConfig(port_scan_ports=999, syn_flood_count=100))
    assert all(f.kind != "syn-flood" for f in flags)


def test_arp_spoof_flagged():
    pkts = [
        _arp("10.0.0.1", "aa:aa:aa:aa:aa:aa"),
        _arp("10.0.0.1", "bb:bb:bb:bb:bb:bb"),
    ]
    flags = analyze(pkts)
    assert any(f.kind == "arp-spoof" for f in flags)


def test_single_mac_not_spoof():
    pkts = [_arp("10.0.0.1", "aa:aa:aa:aa:aa:aa") for _ in range(5)]
    flags = analyze(pkts)
    assert all(f.kind != "arp-spoof" for f in flags)


def test_clean_traffic_no_flags():
    assert analyze([]) == []
