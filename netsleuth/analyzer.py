"""NetSleuth traffic analyzer — Phase 3 (+ deeper heuristics).

Consumes the sniffer's decoded ``PacketSummary`` stream and produces *simple,
clearly-labeled* anomaly flags. These are coarse heuristics, NOT an IDS — they
exist to surface obvious patterns, and we say so in every flag.

  * port-scan pattern  — one source hitting many distinct destination ports.
  * SYN flood          — many SYN-only segments toward one destination.
  * ARP spoof signs    — one IP advertising multiple MAC addresses.
  * ICMP flood         — many ICMP/ICMPv6 packets toward one destination.
  * DNS tunneling/exfil — one source making many DNS queries with long names.
  * C2 beaconing       — one source connecting to a dst:port at a regular cadence.
  * new host           — a source not in a supplied baseline of known hosts.

Works purely off PacketSummary fields (no scapy), so it is fully unit-testable.
"""

from __future__ import annotations

import statistics
from collections import defaultdict
from collections.abc import Iterable
from dataclasses import dataclass

from .sniffer import PacketSummary


@dataclass
class AnomalyFlag:
    kind: str  # "port-scan" | "syn-flood" | "arp-spoof" | "icmp-flood" | ...
    severity: str  # "info" | "warning"
    detail: str  # human-readable, names the heuristic


@dataclass
class AnalysisConfig:
    # Thresholds are deliberately conservative; tune per environment.
    port_scan_ports: int = 15  # distinct dst ports from one src
    syn_flood_count: int = 100  # SYN-only segments toward one dst
    icmp_flood_count: int = 100  # ICMP(v6) packets toward one dst
    dns_query_count: int = 50  # DNS packets from one src
    dns_qname_min_len: int = 40  # avg query-name length suggesting encoding
    beacon_min_events: int = 6  # connection starts needed to judge a cadence
    beacon_max_cv: float = 0.15  # interval coeff. of variation below = regular


def _is_syn_only(flags: str | None) -> bool:
    """True for a bare SYN (handshake start) — SYN set, ACK not."""
    return flags is not None and "S" in flags and "A" not in flags


# --- individual heuristics (each returns its own flags) -------------------- #

def _detect_port_scan(packets: list[PacketSummary], cfg: AnalysisConfig) -> list[AnomalyFlag]:
    ports_by_src: dict[str, set[int]] = defaultdict(set)
    for p in packets:
        if p.proto == "TCP" and p.dport is not None:
            ports_by_src[p.src].add(p.dport)
    flags = []
    for src, ports in ports_by_src.items():
        if len(ports) >= cfg.port_scan_ports:
            flags.append(AnomalyFlag(
                "port-scan", "warning",
                f"{src} touched {len(ports)} distinct TCP ports "
                f"(>= {cfg.port_scan_ports}) — possible port scan (heuristic)",
            ))
    return flags


def _detect_syn_flood(packets: list[PacketSummary], cfg: AnalysisConfig) -> list[AnomalyFlag]:
    syn_by_dst: dict[str, int] = defaultdict(int)
    for p in packets:
        if p.proto == "TCP" and _is_syn_only(p.flags):
            syn_by_dst[p.dst] += 1
    flags = []
    for dst, count in syn_by_dst.items():
        if count >= cfg.syn_flood_count:
            flags.append(AnomalyFlag(
                "syn-flood", "warning",
                f"{count} SYN-only segments toward {dst} "
                f"(>= {cfg.syn_flood_count}) — possible SYN flood (heuristic)",
            ))
    return flags


def _detect_arp_spoof(packets: list[PacketSummary], cfg: AnalysisConfig) -> list[AnomalyFlag]:
    macs_by_ip: dict[str, set[str]] = defaultdict(set)
    for p in packets:
        if p.proto == "ARP" and p.mac:
            macs_by_ip[p.src].add(p.mac)
    flags = []
    for ip, macs in macs_by_ip.items():
        if len(macs) > 1:
            flags.append(AnomalyFlag(
                "arp-spoof", "warning",
                f"{ip} advertised {len(macs)} MACs ({', '.join(sorted(macs))}) "
                "— possible ARP spoofing (heuristic)",
            ))
    return flags


def _detect_icmp_flood(packets: list[PacketSummary], cfg: AnalysisConfig) -> list[AnomalyFlag]:
    icmp_by_dst: dict[str, int] = defaultdict(int)
    for p in packets:
        if p.proto in ("ICMP", "ICMPv6"):
            icmp_by_dst[p.dst] += 1
    flags = []
    for dst, count in icmp_by_dst.items():
        if count >= cfg.icmp_flood_count:
            flags.append(AnomalyFlag(
                "icmp-flood", "warning",
                f"{count} ICMP packets toward {dst} "
                f"(>= {cfg.icmp_flood_count}) — possible ICMP flood / ping "
                "sweep (heuristic)",
            ))
    return flags


def _detect_dns_tunnel(packets: list[PacketSummary], cfg: AnalysisConfig) -> list[AnomalyFlag]:
    """High volume of DNS queries with long names from one source.

    Encoding data into DNS labels makes the names both numerous and unusually
    long, so we flag on the combination rather than either signal alone.
    """
    names_by_src: dict[str, list[int]] = defaultdict(list)
    for p in packets:
        if p.proto == "DNS" and p.qname:
            names_by_src[p.src].append(len(p.qname))
    flags = []
    for src, lengths in names_by_src.items():
        if len(lengths) >= cfg.dns_query_count:
            avg = statistics.mean(lengths)
            if avg >= cfg.dns_qname_min_len:
                flags.append(AnomalyFlag(
                    "dns-tunnel", "warning",
                    f"{src} made {len(lengths)} DNS queries averaging "
                    f"{avg:.0f}-char names (>= {cfg.dns_qname_min_len}) — "
                    "possible DNS tunneling / exfiltration (heuristic)",
                ))
    return flags


def _detect_beaconing(packets: list[PacketSummary], cfg: AnalysisConfig) -> list[AnomalyFlag]:
    """Regular-interval connection starts to one dst:port (C2 beacon signature).

    Groups SYN-only timestamps per (src, dst, dport) and flags a group whose
    inter-arrival gaps are tightly clustered (low coefficient of variation) —
    automation tends to be metronomic where human traffic is bursty.
    """
    starts: dict[tuple[str, str, int], list[float]] = defaultdict(list)
    for p in packets:
        if p.proto == "TCP" and p.dport is not None and _is_syn_only(p.flags):
            starts[(p.src, p.dst, p.dport)].append(p.ts)
    flags = []
    for (src, dst, dport), times in starts.items():
        if len(times) < cfg.beacon_min_events:
            continue
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean_gap = statistics.mean(gaps)
        if mean_gap <= 0:
            continue
        cv = statistics.pstdev(gaps) / mean_gap
        if cv <= cfg.beacon_max_cv:
            flags.append(AnomalyFlag(
                "beacon", "warning",
                f"{src} → {dst}:{dport} connected {len(times)} times every "
                f"~{mean_gap:.1f}s (jitter {cv:.0%}) — possible C2 beaconing "
                "(heuristic)",
            ))
    return flags


def _detect_new_hosts(
    packets: list[PacketSummary], known_hosts: Iterable[str]
) -> list[AnomalyFlag]:
    """Sources not present in a supplied baseline of known-good hosts."""
    known = set(known_hosts)
    seen: set[str] = set()
    flags = []
    for p in packets:
        if p.src in known or p.src in seen or p.src in ("?", ""):
            continue
        seen.add(p.src)
        flags.append(AnomalyFlag(
            "new-host", "info",
            f"{p.src} is not in the known-host baseline — new device on the "
            "network (heuristic)",
        ))
    return flags


def analyze(
    packets: list[PacketSummary],
    config: AnalysisConfig | None = None,
    *,
    known_hosts: Iterable[str] | None = None,
) -> list[AnomalyFlag]:
    """Scan a batch of packet summaries for coarse anomaly patterns.

    Pass ``known_hosts`` (e.g. from a trusted discovery sweep) to additionally
    flag sources absent from that baseline as new devices.
    """
    cfg = config or AnalysisConfig()
    flags: list[AnomalyFlag] = []
    flags += _detect_port_scan(packets, cfg)
    flags += _detect_syn_flood(packets, cfg)
    flags += _detect_arp_spoof(packets, cfg)
    flags += _detect_icmp_flood(packets, cfg)
    flags += _detect_dns_tunnel(packets, cfg)
    flags += _detect_beaconing(packets, cfg)
    if known_hosts is not None:
        flags += _detect_new_hosts(packets, known_hosts)
    return flags
