"""Unit tests for the windowed/streaming analyzer (window mode).

Builds synthetic timestamped PacketSummary objects, so detection is deterministic
and needs no scapy/capture. The recurring theme: window mode reacts to *rate* and
*time*, where whole/batch mode only counts.
"""

from __future__ import annotations

from netsleuth.analyzer import AnalysisConfig, WindowAnalyzer, analyze, analyze_stream
from netsleuth.sniffer import PacketSummary


def _syn(src, dst, dport, ts):
    return PacketSummary(ts, src, dst, "TCP", 60, "x", dport=dport, flags="S")


def _icmp(src, dst, ts):
    return PacketSummary(ts, src, dst, "ICMP", 64, "x")


def _dns(src, qname, ts):
    return PacketSummary(ts, src, "10.0.0.53", "DNS", 80, "x", qname=qname)


# --- rate vs count: the core distinction ----------------------------------- #

def test_fast_flood_fires_on_rate():
    # 600 SYN spread across a 10s window → 60/s ≥ 50/s threshold.
    cfg = AnalysisConfig(window=10.0, syn_rate=50.0)
    pkts = [_syn("10.0.0.9", "10.0.0.1", 80, ts=i * (10.0 / 600)) for i in range(600)]
    flags = analyze_stream(pkts, cfg)
    assert any(f.kind == "syn-flood" for f in flags)


def test_stealth_scan_fires_in_window_mode():
    # 8 distinct ports probed with NULL flags inside one 10s window.
    cfg = AnalysisConfig(window=10.0, stealth_scan_ports=6)
    pkts = [PacketSummary(i * 0.1, "10.0.0.7", "10.0.0.1", "TCP", 60, "x",
                          dport=1000 + i, flags="") for i in range(8)]
    flags = analyze_stream(pkts, cfg)
    assert any(f.kind == "stealth-scan" and "NULL" in f.detail for f in flags)


def test_slow_trickle_does_not_fire_on_rate():
    # Same 600 SYN, but spread over 6000s → 0.1/s. Window mode stays quiet…
    cfg = AnalysisConfig(window=10.0, syn_rate=50.0)
    pkts = [_syn("10.0.0.9", "10.0.0.1", 80, ts=i * 10.0) for i in range(600)]
    assert all(f.kind != "syn-flood" for f in analyze_stream(pkts, cfg))
    # …yet whole/batch mode still flags it by sheer count (the contrast).
    assert any(f.kind == "syn-flood" for f in analyze(pkts, AnalysisConfig(syn_flood_count=100)))


# --- low-and-slow scan: window mode catches what batch labels differently --- #

def test_low_and_slow_scan_flagged_as_slow():
    # 25 distinct ports from one src, ~8s apart → never 15 ports inside a 10s
    # window (so not "fast"), but 25 over the 300s slow window → slow-scan.
    cfg = AnalysisConfig(window=10.0, scan_ports=15,
                         slow_scan_window=300.0, slow_scan_ports=20)
    pkts = [_syn("10.0.0.5", "10.0.0.1", 1000 + i, ts=i * 8.0) for i in range(25)]
    kinds = {f.kind for f in analyze_stream(pkts, cfg)}
    assert "slow-scan" in kinds
    assert "port-scan" not in kinds  # it was deliberately too slow to be "fast"


def test_fast_scan_is_port_scan_not_slow():
    cfg = AnalysisConfig(window=10.0, scan_ports=15, slow_scan_ports=20)
    pkts = [_syn("10.0.0.5", "10.0.0.1", 1000 + i, ts=i * 0.01) for i in range(25)]
    kinds = {f.kind for f in analyze_stream(pkts, cfg)}
    assert "port-scan" in kinds


# --- cooldown + eviction --------------------------------------------------- #

def test_cooldown_suppresses_repeat():
    # A sustained flood must not emit on every packet — once per cooldown.
    cfg = AnalysisConfig(window=10.0, syn_rate=10.0, cooldown=30.0)
    pkts = [_syn("10.0.0.9", "10.0.0.1", 80, ts=i * 0.1) for i in range(300)]  # 30s
    floods = [f for f in analyze_stream(pkts, cfg) if f.kind == "syn-flood"]
    assert 1 <= len(floods) <= 2  # ~once per 30s cooldown, not hundreds


def test_eviction_clears_after_silence():
    # A brief burst then a long gap: the window empties, so a later trickle
    # below the rate must not re-trigger.
    cfg = AnalysisConfig(window=10.0, syn_rate=50.0, cooldown=1.0)
    burst = [_syn("10.0.0.9", "10.0.0.1", 80, ts=i * 0.01) for i in range(100)]
    later = [_syn("10.0.0.9", "10.0.0.1", 80, ts=1000.0 + i * 5) for i in range(3)]
    flags = analyze_stream(burst + later, cfg)
    # The burst fires once; the trickle 1000s later (evicted window) does not add more.
    assert sum(f.kind == "syn-flood" for f in flags) == 1


# --- other detectors in window mode ---------------------------------------- #

def test_icmp_flood_rate():
    cfg = AnalysisConfig(window=10.0, icmp_rate=50.0)
    pkts = [_icmp("10.0.0.5", "10.0.0.1", ts=i * (10.0 / 600)) for i in range(600)]
    assert any(f.kind == "icmp-flood" for f in analyze_stream(pkts, cfg))


def test_dns_tunnel_needs_rate_and_length():
    cfg = AnalysisConfig(window=10.0, dns_qps=20.0, dns_qname_min_len=40)
    long_name = "x" * 55 + ".exfil.example.com"
    fast = [_dns("10.0.0.5", long_name, ts=i * (10.0 / 300)) for i in range(300)]
    assert any(f.kind == "dns-tunnel" for f in analyze_stream(fast, cfg))
    # Same rate but short names → no tunnel.
    short = [_dns("10.0.0.5", "www.example.com", ts=i * (10.0 / 300)) for i in range(300)]
    assert all(f.kind != "dns-tunnel" for f in analyze_stream(short, cfg))


def test_beacon_window_mode():
    cfg = AnalysisConfig(beacon_min_events=6, beacon_max_cv=0.15, beacon_window=600.0)
    pkts = [_syn("10.0.0.5", "10.0.0.9", 443, ts=30.0 * i) for i in range(10)]
    assert any(f.kind == "beacon" for f in analyze_stream(pkts, cfg))


def test_new_host_in_window_mode():
    pkts = [_syn("10.0.0.250", "10.0.0.1", 80, ts=1.0)]
    flags = analyze_stream(pkts, known_hosts={"10.0.0.1"})
    assert any(f.kind == "new-host" and "10.0.0.250" in f.detail for f in flags)


def test_window_update_is_incremental():
    # Feeding packets one-at-a-time vs all-at-once yields the same flags.
    cfg = AnalysisConfig(window=10.0, syn_rate=50.0)
    pkts = [_syn("10.0.0.9", "10.0.0.1", 80, ts=i * (10.0 / 600)) for i in range(600)]
    wa = WindowAnalyzer(mode="window", config=cfg)
    incremental = []
    for p in pkts:
        incremental += wa.update([p])
    assert [f.kind for f in incremental] == [f.kind for f in analyze_stream(pkts, cfg)]


def test_empty_stream_clean():
    assert analyze_stream([]) == []
