"""NetSleuth traffic analyzer — Phase 3.

Consumes the sniffer's decoded ``PacketSummary`` stream and produces *simple,
clearly-labeled* anomaly flags. These are coarse heuristics, NOT an IDS — they
exist to surface obvious patterns, and we say so in every flag.

  * port-scan pattern  — one source hitting many distinct destination ports.
  * SYN flood          — many SYN-only segments toward one destination.
  * ARP spoof signs    — one IP advertising multiple MAC addresses.

Works purely off PacketSummary fields (no scapy), so it is fully unit-testable.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .sniffer import PacketSummary


@dataclass
class AnomalyFlag:
    kind: str  # "port-scan" | "syn-flood" | "arp-spoof"
    severity: str  # "info" | "warning"
    detail: str  # human-readable, names the heuristic


@dataclass
class AnalysisConfig:
    # Thresholds are deliberately conservative; tune per environment.
    port_scan_ports: int = 15  # distinct dst ports from one src
    syn_flood_count: int = 100  # SYN-only segments toward one dst


def _is_syn_only(flags: str | None) -> bool:
    """True for a bare SYN (handshake start) — SYN set, ACK not."""
    return flags is not None and "S" in flags and "A" not in flags


def analyze(
    packets: list[PacketSummary],
    config: AnalysisConfig | None = None,
) -> list[AnomalyFlag]:
    """Scan a batch of packet summaries for coarse anomaly patterns."""
    cfg = config or AnalysisConfig()

    ports_by_src: dict[str, set[int]] = defaultdict(set)
    syn_by_dst: dict[str, int] = defaultdict(int)
    macs_by_ip: dict[str, set[str]] = defaultdict(set)

    for p in packets:
        if p.proto == "TCP":
            if p.dport is not None:
                ports_by_src[p.src].add(p.dport)
            if _is_syn_only(p.flags):
                syn_by_dst[p.dst] += 1
        elif p.proto == "ARP" and p.mac:
            macs_by_ip[p.src].add(p.mac)

    flags: list[AnomalyFlag] = []

    for src, ports in ports_by_src.items():
        if len(ports) >= cfg.port_scan_ports:
            flags.append(AnomalyFlag(
                "port-scan", "warning",
                f"{src} touched {len(ports)} distinct TCP ports "
                f"(>= {cfg.port_scan_ports}) — possible port scan (heuristic)",
            ))

    for dst, count in syn_by_dst.items():
        if count >= cfg.syn_flood_count:
            flags.append(AnomalyFlag(
                "syn-flood", "warning",
                f"{count} SYN-only segments toward {dst} "
                f"(>= {cfg.syn_flood_count}) — possible SYN flood (heuristic)",
            ))

    for ip, macs in macs_by_ip.items():
        if len(macs) > 1:
            flags.append(AnomalyFlag(
                "arp-spoof", "warning",
                f"{ip} advertised {len(macs)} MACs ({', '.join(sorted(macs))}) "
                "— possible ARP spoofing (heuristic)",
            ))

    return flags
