"""Unit tests for the ARP-spoofing / MITM detector.

Pure: builds PacketSummary objects in memory, no scapy or capture needed.
"""

from __future__ import annotations

from netsleuth.defense import DefenseConfig, detect_spoofing
from netsleuth.sniffer import PacketSummary


def _arp(ip, mac, op="is-at"):
    return PacketSummary(0.0, ip, "10.0.0.255", "ARP", 42, "x", mac=mac, arp_op=op)


def test_baseline_mac_change_flagged():
    pkts = [_arp("10.0.0.1", "bb:bb:bb:bb:bb:bb")]
    alerts = detect_spoofing(pkts, baseline={"10.0.0.1": "aa:aa:aa:aa:aa:aa"})
    assert any(a.kind == "arp-mac-change" for a in alerts)


def test_baseline_match_is_clean():
    pkts = [_arp("10.0.0.1", "aa:aa:aa:aa:aa:aa")]
    alerts = detect_spoofing(pkts, baseline={"10.0.0.1": "AA:AA:AA:AA:AA:AA"})
    assert all(a.kind != "arp-mac-change" for a in alerts)  # case-insensitive


def test_gateway_change_escalates_to_critical():
    pkts = [_arp("10.0.0.1", "bb:bb:bb:bb:bb:bb")]
    cfg = DefenseConfig(critical_ips={"10.0.0.1"})
    alerts = detect_spoofing(
        pkts, baseline={"10.0.0.1": "aa:aa:aa:aa:aa:aa"}, config=cfg
    )
    change = next(a for a in alerts if a.kind == "arp-mac-change")
    assert change.severity == "critical"


def test_duplicate_ip_multiple_macs():
    pkts = [
        _arp("10.0.0.1", "aa:aa:aa:aa:aa:aa"),
        _arp("10.0.0.1", "bb:bb:bb:bb:bb:bb"),
    ]
    alerts = detect_spoofing(pkts)
    assert any(a.kind == "duplicate-ip" for a in alerts)


def test_one_mac_many_ips():
    pkts = [_arp(f"10.0.0.{i}", "bb:bb:bb:bb:bb:bb") for i in range(1, 7)]
    alerts = detect_spoofing(pkts, config=DefenseConfig(mac_many_ips=5))
    assert any(a.kind == "mac-many-ips" for a in alerts)


def test_gratuitous_arp_flood():
    pkts = [_arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", op="is-at") for _ in range(25)]
    alerts = detect_spoofing(pkts, config=DefenseConfig(gratuitous_replies=20))
    assert any(a.kind == "gratuitous-arp" for a in alerts)


def test_who_has_requests_are_not_gratuitous():
    pkts = [_arp("10.0.0.1", "aa:aa:aa:aa:aa:aa", op="who-has") for _ in range(25)]
    alerts = detect_spoofing(pkts, config=DefenseConfig(gratuitous_replies=20))
    assert all(a.kind != "gratuitous-arp" for a in alerts)


def test_clean_traffic_no_alerts():
    assert detect_spoofing([]) == []
    pkts = [_arp("10.0.0.1", "aa:aa:aa:aa:aa:aa")]
    assert detect_spoofing(pkts) == []
