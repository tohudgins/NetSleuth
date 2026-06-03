"""End-to-end tests for PCAP import + attack samples — Phase 4.

Generates the sample captures, reads them back, and asserts the analyzer fires
on each attack and stays quiet on benign traffic. Skips if scapy is absent.
"""

from __future__ import annotations

import pytest

from netsleuth.pcap import _SCAPY_AVAILABLE, analyze_pcap, read_pcap
from netsleuth.samples import write_samples

if not _SCAPY_AVAILABLE:  # pragma: no cover - environment dependent
    pytest.skip("scapy not installed", allow_module_level=True)


@pytest.fixture
def samples(tmp_path):
    return write_samples(tmp_path)


def test_port_scan_detected(samples):
    result = analyze_pcap(samples["port_scan"])
    assert any(a.kind == "port-scan" for a in result.anomalies)


def test_syn_flood_detected(samples):
    result = analyze_pcap(samples["syn_flood"])
    assert any(a.kind == "syn-flood" for a in result.anomalies)


def test_arp_spoof_detected(samples):
    result = analyze_pcap(samples["arp_spoof"])
    assert any(a.kind == "arp-spoof" for a in result.anomalies)


def test_icmp_flood_detected(samples):
    result = analyze_pcap(samples["icmp_flood"])
    assert any(a.kind == "icmp-flood" for a in result.anomalies)


def test_dns_tunnel_detected(samples):
    result = analyze_pcap(samples["dns_tunnel"])
    assert any(a.kind == "dns-tunnel" for a in result.anomalies)


def test_beacon_detected(samples):
    result = analyze_pcap(samples["beacon"])
    assert any(a.kind == "beacon" for a in result.anomalies)


def test_slow_scan_batch_vs_stream(samples):
    # Batch (count) sees a plain port-scan; windowed mode recognises it as the
    # low-and-slow variant a fixed-count threshold can't time.
    batch = analyze_pcap(samples["slow_scan"])
    assert any(a.kind == "port-scan" for a in batch.anomalies)
    stream = analyze_pcap(samples["slow_scan"], stream=True)
    kinds = {a.kind for a in stream.anomalies}
    assert "slow-scan" in kinds
    assert "port-scan" not in kinds  # too slow to be a "fast" scan in window mode


def test_arp_spoof_sample_triggers_defense(samples):
    # The same ARP-spoof fixture the analyzer flags should also raise a
    # defense-side duplicate-IP alert from detect_spoofing.
    from netsleuth.defense import detect_spoofing
    result = analyze_pcap(samples["arp_spoof"])
    alerts = detect_spoofing(result.packets)
    assert any(a.kind == "duplicate-ip" for a in alerts)


def test_benign_traffic_clean(samples):
    result = analyze_pcap(samples["benign"])
    assert result.anomalies == []
    assert result.stats.packets > 0


def test_read_pcap_roundtrip_and_proto_breakdown(samples):
    summaries = read_pcap(samples["port_scan"])
    assert len(summaries) > 0
    assert all(s.proto == "TCP" for s in summaries)
    # protocol breakdown is populated by TrafficStats during analysis
    result = analyze_pcap(samples["port_scan"])
    assert result.stats.by_proto.get("TCP", 0) == len(summaries)


def test_read_pcap_missing_file_raises_filenotfound(tmp_path):
    with pytest.raises(FileNotFoundError):
        read_pcap(tmp_path / "nope.pcap")


def test_read_pcap_invalid_file_raises_valueerror(tmp_path):
    bogus = tmp_path / "not.pcap"
    bogus.write_text("this is not a capture file")
    with pytest.raises(ValueError):
        read_pcap(bogus)
