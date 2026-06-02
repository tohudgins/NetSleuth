"""Unit tests for the sniffer — Phase 2.

Decoding is exercised against packets crafted in memory, so these need neither
privileges nor a live network. The whole module skips if scapy is unavailable.
"""

from __future__ import annotations

import pytest

from netsleuth.sniffer import (
    PacketSummary,
    TrafficStats,
    _SCAPY_AVAILABLE,
    hexdump,
    summarize,
)

if not _SCAPY_AVAILABLE:  # pragma: no cover - environment dependent
    pytest.skip("scapy not installed", allow_module_level=True)

from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP  # noqa: E402


def test_summarize_tcp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S")
    s = summarize(pkt)
    assert s.proto == "TCP"
    assert s.src == "10.0.0.1" and s.dst == "10.0.0.2"
    assert "1234" in s.info and "80" in s.info


def test_summarize_udp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=5000, dport=53)
    s = summarize(pkt)
    assert s.proto == "UDP"
    assert "5000" in s.info and "53" in s.info


def test_summarize_icmp():
    pkt = IP(src="10.0.0.1", dst="10.0.0.2") / ICMP()
    s = summarize(pkt)
    assert s.proto == "ICMP"
    assert "type=" in s.info


def test_summarize_arp():
    pkt = ARP(op=1, psrc="10.0.0.1", pdst="10.0.0.2")
    s = summarize(pkt)
    assert s.proto == "ARP"
    assert "who-has" in s.info


def test_summarize_dns_query():
    pkt = (IP(src="10.0.0.1", dst="8.8.8.8")
           / UDP(sport=5353, dport=53)
           / DNS(rd=1, qd=DNSQR(qname="example.com")))
    s = summarize(pkt)
    assert s.proto == "DNS"
    assert "example.com" in s.info


def test_traffic_stats_accounting():
    stats = TrafficStats()
    stats.record(PacketSummary(0.0, "10.0.0.1", "10.0.0.2", "TCP", 100, "x"))
    stats.record(PacketSummary(0.0, "10.0.0.1", "10.0.0.2", "TCP", 40, "x"))
    stats.record(PacketSummary(0.0, "10.0.0.9", "10.0.0.2", "UDP", 200, "x"))
    assert stats.packets == 3
    assert stats.bytes == 340
    top_ip, top_counter = stats.top()[0]
    assert top_ip == "10.0.0.9" and top_counter.bytes == 200
    assert stats.by_ip["10.0.0.1"].packets == 2


def test_hexdump_format():
    out = hexdump(b"AB\x00\xff")
    assert out.startswith("0000  ")
    assert "41 42 00 ff" in out
    assert out.rstrip().endswith("AB..")


def test_sniffer_thread_lifecycle(monkeypatch):
    """Drive the worker thread + stop Event without root by stubbing sniff()."""
    import netsleuth.sniffer as snf

    monkeypatch.setattr(snf, "_SCAPY_AVAILABLE", True)
    monkeypatch.setattr(snf, "can_raw_socket", lambda: True)

    pkt = IP(src="10.0.0.5", dst="10.0.0.6") / UDP(sport=1, dport=2)

    def fake_sniff(prn=None, stop_filter=None, **_kw):
        if prn is not None:
            prn(pkt)

    monkeypatch.setattr(snf, "sniff", fake_sniff)

    seen: list = []
    sniffer = snf.Sniffer(count=1, on_packet=lambda s, _raw: seen.append(s))
    sniffer.start()
    sniffer.stop(timeout=2.0)

    assert not sniffer.running
    assert sniffer.stats.packets >= 1
    assert len(seen) >= 1
    assert sniffer.packets[0].proto == "UDP"


def test_sniffer_captures_thread_error(monkeypatch):
    """A capture-startup failure is recorded, not raised from the worker."""
    import netsleuth.sniffer as snf

    monkeypatch.setattr(snf, "_SCAPY_AVAILABLE", True)
    monkeypatch.setattr(snf, "can_raw_socket", lambda: True)

    def boom_sniff(**_kw):
        raise snf.Scapy_Exception("Cannot set promiscuous mode on interface (en0)!")

    monkeypatch.setattr(snf, "sniff", boom_sniff)

    sniffer = snf.Sniffer()
    sniffer.start()
    sniffer.stop(timeout=2.0)

    assert not sniffer.running
    assert sniffer.error is not None
    assert "promiscuous" in str(sniffer.error)
