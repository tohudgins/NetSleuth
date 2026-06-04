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

import json
import logging
import statistics
from collections import defaultdict, deque
from collections.abc import Iterable
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from .sniffer import PacketSummary

logger = logging.getLogger(__name__)


@dataclass
class AnomalyFlag:
    kind: str  # "port-scan" | "syn-flood" | "arp-spoof" | "icmp-flood" | ...
    severity: str  # "info" | "warning"
    detail: str  # human-readable, names the heuristic


@dataclass
class AnalysisConfig:
    # Thresholds are deliberately conservative; tune per environment.
    # --- whole/batch mode: absolute counts over the entire capture ---------- #
    port_scan_ports: int = 15  # distinct dst ports from one src
    syn_flood_count: int = 100  # SYN-only segments toward one dst
    icmp_flood_count: int = 100  # ICMP(v6) packets toward one dst
    dns_query_count: int = 50  # DNS packets from one src
    dns_qname_min_len: int = 40  # avg query-name length suggesting encoding
    beacon_min_events: int = 6  # connection starts needed to judge a cadence
    beacon_max_cv: float = 0.15  # interval coeff. of variation below = regular
    # --- window/streaming mode: rates over a sliding time window ------------ #
    window: float = 10.0  # sliding window (seconds) for rate detectors
    syn_rate: float = 50.0  # SYN-only/sec toward one dst
    icmp_rate: float = 50.0  # ICMP/sec toward one dst
    dns_qps: float = 20.0  # DNS queries/sec from one src
    scan_ports: int = 15  # distinct dst ports/src within `window` (fast scan)
    slow_scan_window: float = 300.0  # long window for low-and-slow scans
    slow_scan_ports: int = 20  # distinct ports/src over the long window
    beacon_window: float = 600.0  # window over which to judge a beacon cadence
    cooldown: float = 30.0  # min seconds between repeats of one (kind, key)


def load_config(path: str | Path) -> AnalysisConfig:
    """Load analyzer thresholds from a JSON object file.

    Only keys matching real ``AnalysisConfig`` fields are applied; unknown keys
    are warned-and-ignored. Raises on a missing file or non-object JSON.
    """
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"config must be a JSON object: {path}")
    known = {f.name for f in fields(AnalysisConfig)}
    kwargs = {}
    for key, value in data.items():
        if key in known:
            kwargs[key] = value
        else:
            logger.warning("config: ignoring unknown key %r", key)
    return AnalysisConfig(**kwargs)


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


def _run_batch(
    packets: list[PacketSummary], cfg: AnalysisConfig, known: set[str] | None
) -> list[AnomalyFlag]:
    """The whole-capture, count-based verdict (the original batch detectors)."""
    flags: list[AnomalyFlag] = []
    flags += _detect_port_scan(packets, cfg)
    flags += _detect_syn_flood(packets, cfg)
    flags += _detect_arp_spoof(packets, cfg)
    flags += _detect_icmp_flood(packets, cfg)
    flags += _detect_dns_tunnel(packets, cfg)
    flags += _detect_beaconing(packets, cfg)
    if known is not None:
        flags += _detect_new_hosts(packets, known)
    return flags


# --- one engine, two modes ------------------------------------------------- #

def _first_ts(item: Any) -> float:
    """Timestamp accessor for the eviction helper (float or (ts, …) tuple)."""
    return item[0] if isinstance(item, tuple) else item


def _evict(dq: deque, horizon: float) -> None:
    """Drop events older than `horizon` from the left of a time-ordered deque."""
    while dq and _first_ts(dq[0]) < horizon:
        dq.popleft()


class WindowAnalyzer:
    """Stateful anomaly engine with two modes (CLAUDE.md: threads, no asyncio).

    * ``whole``  — buffer every packet and, on ``flush()``, run the count-based
      batch detectors over the lot. Reproduces ``analyze()`` exactly; used for a
      finished capture / pcap.
    * ``window`` — ingest packets incrementally; ``update()`` evicts events older
      than the sliding window, evaluates *rate* thresholds, and returns only the
      newly-raised flags (rising edge, deduped by a per-(kind, key) cooldown).
      O(new packets) per call — this is what the live paths use, killing the old
      re-scan-the-whole-buffer-every-tick O(n²).

    Time is driven off ``PacketSummary.ts`` (captured packet time), so window
    mode is deterministic and works identically on a live wire and a saved pcap.
    """

    def __init__(
        self,
        *,
        mode: str = "whole",
        config: AnalysisConfig | None = None,
        known_hosts: Iterable[str] | None = None,
    ) -> None:
        self.mode = mode
        self.cfg = config or AnalysisConfig()
        self.known: set[str] | None = (
            set(known_hosts) if known_hosts is not None else None
        )
        self._buffer: list[PacketSummary] = []  # whole mode
        # window-mode per-key event stores
        self._ports: dict[str, deque] = defaultdict(deque)       # (ts, port) fast
        self._slow: dict[str, deque] = defaultdict(deque)        # (ts, port) slow
        self._syn: dict[str, deque] = defaultdict(deque)         # ts per dst
        self._icmp: dict[str, deque] = defaultdict(deque)        # ts per dst
        self._dns: dict[str, deque] = defaultdict(deque)         # (ts, len) src
        self._beacon: dict[tuple, deque] = defaultdict(deque)    # ts per flow
        self._macs: dict[str, set[str]] = defaultdict(set)
        self._seen: set[str] = set()
        self._last_fired: dict[tuple[str, str], float] = {}
        self._now = 0.0

    # -- public ------------------------------------------------------------- #

    def update(self, packets: list[PacketSummary]) -> list[AnomalyFlag]:
        if self.mode != "window":
            self._buffer.extend(packets)
            return []
        flags: list[AnomalyFlag] = []
        for p in packets:
            if p.ts > self._now:
                self._now = p.ts
            flags += self._ingest(p)
        return flags

    def flush(self) -> list[AnomalyFlag]:
        if self.mode != "window":
            return _run_batch(self._buffer, self.cfg, self.known)
        return []

    # -- window-mode internals --------------------------------------------- #

    def _fire(self, kind: str, key: str, detail: str,
              severity: str = "warning") -> AnomalyFlag | None:
        """Emit a flag unless this (kind, key) fired within the cooldown."""
        last = self._last_fired.get((kind, key))
        if last is not None and self._now - last < self.cfg.cooldown:
            return None
        self._last_fired[(kind, key)] = self._now
        return AnomalyFlag(kind, severity, detail)

    def _rate(self, dq: deque) -> float:
        """Events/sec over the events currently in `dq` (1s floor avoids spikes)."""
        span = max(self._now - _first_ts(dq[0]), 1.0)
        return len(dq) / span

    def _ingest(self, p: PacketSummary) -> list[AnomalyFlag]:
        cfg, now = self.cfg, self._now
        out: list[AnomalyFlag] = []

        if p.proto == "TCP" and p.dport is not None:
            if _is_syn_only(p.flags):
                syn = self._syn[p.dst]
                syn.append(p.ts)
                _evict(syn, now - cfg.window)
                if self._rate(syn) >= cfg.syn_rate:
                    self._emit(out, "syn-flood", p.dst,
                               f"~{self._rate(syn):.0f} SYN/s toward {p.dst} "
                               f"(>= {cfg.syn_rate:.0f}/s) — possible SYN flood (heuristic)")
                bq = self._beacon[(p.src, p.dst, p.dport)]
                bq.append(p.ts)
                _evict(bq, now - cfg.beacon_window)
                self._maybe_beacon(out, p, bq)

            fast = self._ports[p.src]
            fast.append((p.ts, p.dport))
            _evict(fast, now - cfg.window)
            fast_distinct = len({port for _, port in fast})
            if fast_distinct >= cfg.scan_ports:
                self._emit(out, "port-scan", p.src,
                           f"{p.src} hit {fast_distinct} distinct TCP ports in "
                           f"{cfg.window:.0f}s (>= {cfg.scan_ports}) — possible "
                           "fast port scan (heuristic)")

            slow = self._slow[p.src]
            slow.append((p.ts, p.dport))
            _evict(slow, now - cfg.slow_scan_window)
            slow_distinct = len({port for _, port in slow})
            # Only "slow" when it is NOT also a burst (otherwise port-scan covers it).
            if slow_distinct >= cfg.slow_scan_ports and fast_distinct < cfg.scan_ports:
                self._emit(out, "slow-scan", p.src,
                           f"{p.src} touched {slow_distinct} distinct ports over "
                           f"{cfg.slow_scan_window:.0f}s (>= {cfg.slow_scan_ports}) "
                           "— possible low-and-slow port scan (heuristic)")

        elif p.proto in ("ICMP", "ICMPv6"):
            icmp = self._icmp[p.dst]
            icmp.append(p.ts)
            _evict(icmp, now - cfg.window)
            if self._rate(icmp) >= cfg.icmp_rate:
                self._emit(out, "icmp-flood", p.dst,
                           f"~{self._rate(icmp):.0f} ICMP/s toward {p.dst} "
                           f"(>= {cfg.icmp_rate:.0f}/s) — possible ICMP flood (heuristic)")

        elif p.proto == "DNS" and p.qname:
            dns = self._dns[p.src]
            dns.append((p.ts, len(p.qname)))
            _evict(dns, now - cfg.window)
            if self._rate(dns) >= cfg.dns_qps:
                avg = statistics.mean([n for _, n in dns])
                if avg >= cfg.dns_qname_min_len:
                    self._emit(out, "dns-tunnel", p.src,
                               f"{p.src} ~{self._rate(dns):.0f} DNS q/s averaging "
                               f"{avg:.0f}-char names — possible DNS tunneling / "
                               "exfiltration (heuristic)")

        elif p.proto == "ARP" and p.mac:
            macs = self._macs[p.src]
            macs.add(p.mac)
            if len(macs) > 1:
                self._emit(out, "arp-spoof", p.src,
                           f"{p.src} advertised {len(macs)} MACs "
                           f"({', '.join(sorted(macs))}) — possible ARP spoofing "
                           "(heuristic)")

        if (self.known is not None and p.src not in ("?", "")
                and p.src not in self.known and p.src not in self._seen):
            self._seen.add(p.src)
            out.append(AnomalyFlag(
                "new-host", "info",
                f"{p.src} is not in the known-host baseline — new device on the "
                "network (heuristic)"))
        return out

    def _emit(self, out: list[AnomalyFlag], kind: str, key: str, detail: str) -> None:
        flag = self._fire(kind, key, detail)
        if flag is not None:
            out.append(flag)

    def _maybe_beacon(self, out: list[AnomalyFlag], p: PacketSummary,
                      bq: deque) -> None:
        if len(bq) < self.cfg.beacon_min_events:
            return
        times = list(bq)
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean_gap = statistics.mean(gaps)
        if mean_gap <= 0:
            return
        cv = statistics.pstdev(gaps) / mean_gap
        if cv <= self.cfg.beacon_max_cv:
            self._emit(out, "beacon", f"{p.src}->{p.dst}:{p.dport}",
                       f"{p.src} → {p.dst}:{p.dport} connected {len(times)} times "
                       f"every ~{mean_gap:.1f}s (jitter {cv:.0%}) — possible C2 "
                       "beaconing (heuristic)")


# --- public entry points --------------------------------------------------- #

def analyze(
    packets: list[PacketSummary],
    config: AnalysisConfig | None = None,
    *,
    known_hosts: Iterable[str] | None = None,
) -> list[AnomalyFlag]:
    """Whole-capture, count-based anomaly scan (the batch verdict).

    Pass ``known_hosts`` (e.g. from a trusted discovery sweep) to additionally
    flag sources absent from that baseline as new devices. Thin wrapper over the
    engine's ``whole`` mode.
    """
    wa = WindowAnalyzer(mode="whole", config=config, known_hosts=known_hosts)
    wa.update(packets)
    return wa.flush()


def analyze_stream(
    packets: list[PacketSummary],
    config: AnalysisConfig | None = None,
    *,
    known_hosts: Iterable[str] | None = None,
) -> list[AnomalyFlag]:
    """Windowed, rate-based scan over a capture (replays packets in time order).

    Catches what the batch verdict can't: low-and-slow scans, and real flood
    *rates* (so a long quiet capture doesn't accumulate into a false positive).
    Used by ``--pcap --stream``; the live paths drive a ``WindowAnalyzer``
    directly so they only pay for new packets.
    """
    wa = WindowAnalyzer(mode="window", config=config, known_hosts=known_hosts)
    flags: list[AnomalyFlag] = []
    for p in sorted(packets, key=lambda x: x.ts):
        flags += wa.update([p])
    return flags
