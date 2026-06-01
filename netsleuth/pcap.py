"""NetSleuth PCAP import — Phase 4.

Analyze *saved* capture files (.pcap/.pcapng) offline. This is the legal,
unprivileged way to run NetSleuth's detection over real-world adversarial
traffic: point it at a capture from a public dataset (Wireshark sample
captures, malware-traffic-analysis.net, CTF pcaps) or one of the lab's
generated samples, and the analyzer flags the same patterns it would on a live
wire.

Pure composition of existing building blocks — no new decode/analysis logic:
``sniffer.summarize`` decodes each packet, ``sniffer.TrafficStats`` accumulates
volume, and ``analyzer.analyze`` produces the anomaly flags.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .analyzer import AnalysisConfig, AnomalyFlag, analyze
from .sniffer import PacketSummary, TrafficStats, summarize

try:
    from scapy.all import PcapReader

    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _SCAPY_AVAILABLE = False


@dataclass
class PcapAnalysis:
    path: str
    packets: list[PacketSummary] = field(default_factory=list)
    stats: TrafficStats = field(default_factory=TrafficStats)
    anomalies: list[AnomalyFlag] = field(default_factory=list)


def read_pcap(path: str | Path) -> list[PacketSummary]:
    """Decode every packet in a capture file into PacketSummary objects.

    Streams with scapy's PcapReader so large files don't load fully into memory.
    Reading a file needs no privileges.
    """
    if not _SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required to read pcap files")
    summaries: list[PacketSummary] = []
    with PcapReader(str(path)) as reader:
        for pkt in reader:
            summaries.append(summarize(pkt))
    return summaries


def analyze_pcap(
    path: str | Path,
    config: AnalysisConfig | None = None,
) -> PcapAnalysis:
    """Read a capture file and run the full traffic + anomaly analysis."""
    packets = read_pcap(path)
    stats = TrafficStats()
    for s in packets:
        stats.record(s)
    return PcapAnalysis(
        path=str(path),
        packets=packets,
        stats=stats,
        anomalies=analyze(packets, config),
    )
