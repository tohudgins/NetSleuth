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
