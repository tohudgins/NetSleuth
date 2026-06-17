"""NetSleuth packet sniffer — Phase 2.

Wireshark-style live capture built on scapy. Per CLAUDE.md rule #3, scapy's
blocking ``sniff()`` runs in its own dedicated thread controlled by a
``threading.Event`` stop flag — no asyncio anywhere. Decoding is ours: we read
scapy's parsed layers and build our own per-packet summaries and hex dump
(rule #1 — no tshark).

Capture needs raw-socket privileges; callers gate on ``capture_available()``
and degrade gracefully rather than crashing (rule #4).
"""

from __future__ import annotations

import logging
import threading
import time
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .privileges import can_raw_socket

logger = logging.getLogger(__name__)

try:
    from scapy.all import ARP, DNS, ICMP, IP, IPv6, TCP, UDP, sniff, wrpcap
    from scapy.all import conf as scapy_conf
    from scapy.error import Scapy_Exception

    scapy_conf.verb = 0
    # We only inspect our own host's traffic, never other devices' frames, so we
    # do NOT need promiscuous mode. Disabling it also avoids a hard failure on
    # macOS interfaces (e.g. en0) that reject BIOCPROMISC ("Cannot set
    # promiscuous mode"). This keeps capture working and is the right default for
    # a defensive tool.
    scapy_conf.sniff_promisc = 0
    # scapy 2.7 deprecated direct DNS qd/an/ns/ar access; the API still works and
    # _dns_info() handles both shapes. Silence only that one third-party warning
    # so a live DNS capture doesn't print noise.
    warnings.filterwarnings(
        "ignore", message="The DNS fields.*",
        category=DeprecationWarning, module="scapy",
    )
    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _SCAPY_AVAILABLE = False
    Scapy_Exception = Exception


def capture_available() -> bool:
    """True when live capture is actually possible (scapy + privileges)."""
    return _SCAPY_AVAILABLE and can_raw_socket()


# --- Per-packet summary ---------------------------------------------------- #

@dataclass
class PacketSummary:
    ts: float
    src: str
    dst: str
    proto: str
    length: int
    info: str
    # Structured fields the analyzer reads (kept off the display string so it
    # never has to re-parse `info`).
    sport: int | None = None
    dport: int | None = None
    flags: str | None = None  # TCP flags, e.g. "S", "SA"
    mac: str | None = None  # L2 source (ARP hwsrc) — for spoof detection
    arp_op: str | None = None  # "who-has" | "is-at" — for spoof detection
    qname: str | None = None  # DNS question name — for tunneling/exfil heuristics


def _dns_qname(dns: Any) -> str:
    """First question name, tolerant of scapy returning a list or single record."""
    qd = dns.qd
    if not qd:
        return ""
    first = qd[0] if isinstance(qd, list) else qd
    return bytes(first.qname).decode(errors="replace").rstrip(".")


def _dns_info(pkt: Any) -> str:
    dns = pkt[DNS]
    qname = _dns_qname(dns)
    if int(dns.qr) == 0:  # query
        return f"DNS query {qname}".rstrip()
    return f"DNS response {qname} ({int(dns.ancount)} answer(s))"


def _l4_summary(
    pkt: Any, ts: float, src: str, dst: str, length: int
) -> PacketSummary | None:
    """TCP/UDP/DNS summary shared by IPv4 and IPv6; None if not one of those."""
    if pkt.haslayer(DNS):
        return PacketSummary(ts, src, dst, "DNS", length, _dns_info(pkt),
                             qname=_dns_qname(pkt[DNS]) or None)
    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        info = f"TCP {src}:{tcp.sport} -> {dst}:{tcp.dport} [{tcp.flags}]"
        return PacketSummary(ts, src, dst, "TCP", length, info,
                             sport=int(tcp.sport), dport=int(tcp.dport),
                             flags=str(tcp.flags))
    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        info = f"UDP {src}:{udp.sport} -> {dst}:{udp.dport}"
        return PacketSummary(ts, src, dst, "UDP", length, info,
                             sport=int(udp.sport), dport=int(udp.dport))
    return None


def summarize(pkt: Any) -> PacketSummary:
    """Decode one scapy packet into a protocol-aware summary.

    Covers ARP, plus DNS / TCP / UDP / ICMP(v6) over both IPv4 and IPv6; anything
    else falls back to scapy's own one-line summary so capture never drops a
    packet silently.
    """
    ts = float(getattr(pkt, "time", None) or time.time())
    length = len(pkt)

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        op = {1: "who-has", 2: "is-at"}.get(int(arp.op), f"op{arp.op}")
        info = (f"ARP {op} {arp.pdst} tell {arp.psrc}" if int(arp.op) == 1
                else f"ARP {arp.psrc} is-at {arp.hwsrc}")
        return PacketSummary(ts, arp.psrc, arp.pdst, "ARP", length, info,
                             mac=str(arp.hwsrc), arp_op=op)

    if pkt.haslayer(IP):
        ip = pkt[IP]
        src, dst = ip.src, ip.dst
        l4 = _l4_summary(pkt, ts, src, dst, length)
        if l4 is not None:
            return l4
        if pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            info = f"ICMP {src} -> {dst} type={icmp.type} code={icmp.code}"
            return PacketSummary(ts, src, dst, "ICMP", length, info)
        return PacketSummary(ts, src, dst, "IP", length, pkt.summary())

    if pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        src, dst = ip6.src, ip6.dst
        l4 = _l4_summary(pkt, ts, src, dst, length)
        if l4 is not None:
            return l4
        if int(ip6.nh) == 58:  # Next Header 58 = ICMPv6 (NDP, echo, etc.)
            return PacketSummary(ts, src, dst, "ICMPv6", length,
                                 f"ICMPv6 {src} -> {dst}")
        return PacketSummary(ts, src, dst, "IPv6", length, pkt.summary())

    return PacketSummary(ts, "?", "?", "OTHER", length, pkt.summary())


# --- Our own hex dump (no external tooling) -------------------------------- #

def hexdump(data: bytes, width: int = 16) -> str:
    """Classic offset / hex / ASCII dump, implemented ourselves."""
    lines = []
    for off in range(0, len(data), width):
        chunk = data[off:off + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:04x}  {hex_part:<{width * 3}}  {ascii_part}")
    return "\n".join(lines)


# --- Per-IP traffic volume ------------------------------------------------- #

@dataclass
class _IPCounter:
    packets: int = 0
    bytes: int = 0


@dataclass
class TrafficStats:
    """Running per-source-IP volume counters plus a per-protocol breakdown."""

    packets: int = 0
    bytes: int = 0
    by_ip: dict[str, _IPCounter] = field(default_factory=dict)
    by_proto: dict[str, int] = field(default_factory=dict)

    def record(self, s: PacketSummary) -> None:
        self.packets += 1
        self.bytes += s.length
        c = self.by_ip.setdefault(s.src, _IPCounter())
        c.packets += 1
        c.bytes += s.length
        self.by_proto[s.proto] = self.by_proto.get(s.proto, 0) + 1

    def top(self, n: int = 10) -> list[tuple[str, _IPCounter]]:
        return sorted(self.by_ip.items(), key=lambda kv: kv[1].bytes, reverse=True)[:n]


# --- The sniffer ----------------------------------------------------------- #

class Sniffer:
    """Run scapy's blocking ``sniff()`` in a dedicated thread.

    The worker re-enters ``sniff()`` with a short timeout so the stop Event is
    honoured promptly even when no traffic is arriving.
    """

    def __init__(
        self,
        *,
        iface: str | None = None,
        bpf_filter: str | None = None,
        count: int = 0,
        collect: bool = True,
        keep_raw: bool = False,
        on_packet: Callable[[PacketSummary, Any], None] | None = None,
    ) -> None:
        self.iface = iface
        self.bpf_filter = bpf_filter
        self.max_count = count  # 0 = unlimited
        self.collect = collect
        # Retain raw scapy packets too (memory cost) so the capture can be saved
        # to a .pcap for Wireshark / re-analysis via `--pcap`.
        self.keep_raw = keep_raw
        self.on_packet = on_packet
        self.packets: list[PacketSummary] = []
        self.raw_packets: list[Any] = []
        self.stats = TrafficStats()
        self.error: Exception | None = None  # set if the capture thread fails
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def _handle(self, pkt: Any) -> None:
        summary = summarize(pkt)
        self.stats.record(summary)
        if self.collect:
            self.packets.append(summary)
        if self.keep_raw:
            self.raw_packets.append(pkt)
        if self.on_packet is not None:
            self.on_packet(summary, pkt)
        if self.max_count and self.stats.packets >= self.max_count:
            self._stop.set()

    def _run(self) -> None:
        # Loop so a quiet network still lets us notice the stop flag quickly.
        # A capture-startup failure (bad interface, missing privileges, an
        # unsupported BPF feature) is recorded and stops the thread cleanly
        # instead of dumping a traceback from the worker.
        try:
            while not self._stop.is_set():
                sniff(
                    prn=self._handle,
                    store=False,
                    filter=self.bpf_filter,
                    iface=self.iface,
                    timeout=0.5,
                    stop_filter=lambda _p: self._stop.is_set(),
                )
        except (Scapy_Exception, OSError, PermissionError) as exc:
            self.error = exc
            self._stop.set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if not capture_available():
            raise PermissionError(
                "packet capture requires root/Administrator privileges and scapy"
            )
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run, name="netsleuth-sniffer", daemon=True
        )
        self._thread.start()
        logger.info("capture started: iface=%s filter=%s", self.iface, self.bpf_filter)

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
        logger.info("capture stopped: %d packets", self.stats.packets)

    def write_pcap(self, path: str) -> int:
        """Save the captured raw packets to a .pcap file; returns the count.

        Requires ``keep_raw=True`` at construction. Raises ``RuntimeError`` if no
        raw packets were retained, so a caller never writes a silently-empty file.
        """
        if not self.keep_raw:
            raise RuntimeError("sniffer was not built with keep_raw=True")
        if not self.raw_packets:
            raise RuntimeError("no packets captured — nothing to write")
        wrpcap(path, self.raw_packets)
        logger.info("wrote %d packets to %s", len(self.raw_packets), path)
        return len(self.raw_packets)
