"""Unit tests for the analyzer anomaly heuristics — Phase 3.

Works off PacketSummary objects built in memory, so no scapy or capture needed.
"""

from __future__ import annotations

from netsleuth.analyzer import AnalysisConfig, _classify_stealth_flags, analyze
from netsleuth.sniffer import PacketSummary


def _tcp(src, dst, dport, flags="S"):
    return PacketSummary(0.0, src, dst, "TCP", 60, "x", dport=dport, flags=flags)


def _arp(ip, mac):
    return PacketSummary(0.0, ip, "10.0.0.255", "ARP", 42, "x", mac=mac)


def _icmp(src, dst):
    return PacketSummary(0.0, src, dst, "ICMP", 64, "x")


def _dns(src, qname):
    return PacketSummary(0.0, src, "10.0.0.53", "DNS", 80, "x", qname=qname)


def _syn_at(src, dst, dport, ts):
    return PacketSummary(ts, src, dst, "TCP", 60, "x", dport=dport, flags="S")


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


def test_classify_stealth_flags():
    assert _classify_stealth_flags("") == "NULL"      # no flags
    assert _classify_stealth_flags("F") == "FIN"      # FIN alone
    assert _classify_stealth_flags("FPU") == "Xmas"   # FIN+PSH+URG
    assert _classify_stealth_flags("FA") is None      # normal close (FIN+ACK)
    assert _classify_stealth_flags("S") is None       # SYN
    assert _classify_stealth_flags("PA") is None      # data segment


def test_stealth_scan_flagged_by_flags_not_volume():
    # Only 8 ports, but all probed with Xmas flags — caught even under the
    # volume-based port_scan_ports threshold of 15.
    pkts = [_tcp("10.0.0.7", "10.0.0.1", port, flags="FPU") for port in range(1, 9)]
    flags = analyze(pkts, AnalysisConfig(port_scan_ports=15, stealth_scan_ports=6))
    stealth = [f for f in flags if f.kind == "stealth-scan"]
    assert stealth and "Xmas" in stealth[0].detail and "10.0.0.7" in stealth[0].detail


def test_normal_fin_close_not_stealth_scan():
    # Graceful closes (FIN+ACK) to many ports must not look like a NULL/FIN scan.
    pkts = [_tcp("10.0.0.7", "10.0.0.1", port, flags="FA") for port in range(1, 20)]
    flags = analyze(pkts, AnalysisConfig(stealth_scan_ports=6))
    assert all(f.kind != "stealth-scan" for f in flags)


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


def test_icmp_flood_flagged():
    pkts = [_icmp("10.0.0.5", "10.0.0.1") for _ in range(120)]
    flags = analyze(pkts, AnalysisConfig(icmp_flood_count=100))
    assert any(f.kind == "icmp-flood" for f in flags)


def test_dns_tunnel_flagged_on_volume_and_length():
    long_name = "x" * 50 + ".exfil.example.com"
    pkts = [_dns("10.0.0.5", long_name) for _ in range(60)]
    flags = analyze(pkts, AnalysisConfig(dns_query_count=50, dns_qname_min_len=40))
    assert any(f.kind == "dns-tunnel" for f in flags)


def test_normal_dns_not_tunnel():
    # Lots of queries but short, ordinary names should not trip the heuristic.
    pkts = [_dns("10.0.0.5", "www.example.com") for _ in range(60)]
    flags = analyze(pkts, AnalysisConfig(dns_query_count=50, dns_qname_min_len=40))
    assert all(f.kind != "dns-tunnel" for f in flags)


def test_beaconing_flagged_for_regular_interval():
    # Ten connections exactly 30s apart — metronomic, should flag.
    pkts = [_syn_at("10.0.0.5", "10.0.0.9", 443, ts=30.0 * i) for i in range(10)]
    flags = analyze(pkts, AnalysisConfig(port_scan_ports=999))
    assert any(f.kind == "beacon" for f in flags)


def test_irregular_connections_not_beacon():
    times = [0, 5, 60, 61, 200, 201, 999]
    pkts = [_syn_at("10.0.0.5", "10.0.0.9", 443, ts=float(t)) for t in times]
    flags = analyze(pkts, AnalysisConfig(port_scan_ports=999))
    assert all(f.kind != "beacon" for f in flags)


def test_new_host_flagged_against_baseline():
    pkts = [_tcp("10.0.0.250", "10.0.0.1", 80)]
    flags = analyze(pkts, known_hosts={"10.0.0.1", "10.0.0.5"})
    assert any(f.kind == "new-host" and "10.0.0.250" in f.detail for f in flags)


def test_known_host_not_flagged():
    pkts = [_tcp("10.0.0.5", "10.0.0.1", 80)]
    flags = analyze(pkts, known_hosts={"10.0.0.5"})
    assert all(f.kind != "new-host" for f in flags)


def test_clean_traffic_no_flags():
    assert analyze([]) == []
