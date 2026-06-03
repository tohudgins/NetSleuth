"""Attack-sample generator — Phase 4 (blue-team detection fixtures).

Builds small, deterministic capture samples that contain the exact patterns the
analyzer detects, then writes them to .pcap files. These are *detection test
fixtures*: packets are crafted and written to disk only — nothing is ever sent
on the wire, so this stays squarely on the defensive side of CLAUDE.md.

Used by the lab demo (`lab/generate_samples.py`) and by the test suite to prove
the analyzer fires on realistic adversarial traffic.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    from scapy.all import ARP, DNS, DNSQR, ICMP, IP, TCP, UDP, Ether, wrpcap

    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _SCAPY_AVAILABLE = False

ATTACKER = "10.0.0.66"
VICTIM = "10.0.0.10"
GATEWAY = "10.0.0.1"

# Explicit MACs so scapy never tries to resolve them at write time (which would
# need root and emit warnings) — these are fixtures, not real hosts.
ATTACKER_MAC = "02:00:00:00:00:66"
VICTIM_MAC = "02:00:00:00:00:10"
CLIENT_MAC = "02:00:00:00:00:20"
SERVER_MAC = "02:00:00:00:00:30"


def build_port_scan(ports: int = 25) -> list[Any]:
    """One source probing many distinct TCP ports with bare SYNs."""
    eth = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
    return [
        eth / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=40000 + p, dport=p, flags="S")
        for p in range(1, ports + 1)
    ]


def build_syn_flood(count: int = 150) -> list[Any]:
    """Many SYN-only segments hammering one destination port."""
    eth = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
    return [
        eth / IP(src=ATTACKER, dst=VICTIM) / TCP(sport=50000 + i, dport=80, flags="S")
        for i in range(count)
    ]


def build_arp_spoof() -> list[Any]:
    """One IP (the gateway) advertised with two different MAC addresses."""
    eth = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
    return [
        eth / ARP(op=2, psrc=GATEWAY, hwsrc="aa:aa:aa:aa:aa:aa",
                  pdst=VICTIM, hwdst=VICTIM_MAC),
        eth / ARP(op=2, psrc=GATEWAY, hwsrc="bb:bb:bb:bb:bb:bb",
                  pdst=VICTIM, hwdst=VICTIM_MAC),
        eth / ARP(op=2, psrc=GATEWAY, hwsrc="aa:aa:aa:aa:aa:aa",
                  pdst=VICTIM, hwdst=VICTIM_MAC),
    ]


def build_icmp_flood(count: int = 120) -> list[Any]:
    """Many ICMP echo packets toward one destination (ping flood / sweep)."""
    eth = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
    return [
        eth / IP(src=ATTACKER, dst=VICTIM) / ICMP()
        for _ in range(count)
    ]


def build_dns_tunnel(count: int = 60) -> list[Any]:
    """One source making many DNS queries with long, encoded-looking names."""
    eth = Ether(src=ATTACKER_MAC, dst=SERVER_MAC)
    resolver = "10.0.0.53"
    pkts: list[Any] = []
    for i in range(count):
        label = ("d3adbeef" * 6) + f"{i:04d}"  # ~52-char encoded-looking label
        qname = f"{label}.exfil.example.com"
        pkts.append(eth / IP(src=ATTACKER, dst=resolver)
                    / UDP(sport=40000 + i, dport=53)
                    / DNS(rd=1, qd=DNSQR(qname=qname)))
    return pkts


def build_beacon(count: int = 12, interval: float = 30.0) -> list[Any]:
    """Metronomic connections to one dst:port — a C2 beacon signature.

    Timestamps are stamped on each frame at a fixed interval so the analyzer's
    inter-arrival cadence check (low jitter) fires when the capture is read back.
    """
    eth = Ether(src=ATTACKER_MAC, dst=SERVER_MAC)
    c2 = "10.0.0.99"
    pkts: list[Any] = []
    for i in range(count):
        pkt = (eth / IP(src=ATTACKER, dst=c2)
               / TCP(sport=40000 + i, dport=443, flags="S"))
        pkt.time = 1_000_000.0 + i * interval
        pkts.append(pkt)
    return pkts


def build_slow_scan(ports: int = 25, interval: float = 8.0) -> list[Any]:
    """A low-and-slow port scan: distinct ports, spaced out over minutes.

    Each SYN lands ~`interval` seconds apart, so no 10-second window ever holds
    enough ports to look like a *fast* scan — only the windowed analyzer's long
    slow-scan window catches it. (Batch mode flags it as a plain port-scan by
    count, which is the point of the side-by-side demo.)
    """
    eth = Ether(src=ATTACKER_MAC, dst=VICTIM_MAC)
    pkts: list[Any] = []
    for i in range(ports):
        pkt = (eth / IP(src=ATTACKER, dst=VICTIM)
               / TCP(sport=40000 + i, dport=1000 + i, flags="S"))
        pkt.time = 1_000_000.0 + i * interval
        pkts.append(pkt)
    return pkts


def build_benign() -> list[Any]:
    """Normal established traffic — a few sessions, no half-open SYN floods.

    Stays well under the port-scan threshold (only a handful of distinct ports)
    and uses established flags so no heuristic fires.
    """
    pkts: list[Any] = []
    client, server = "10.0.0.20", "10.0.0.30"
    to_server = Ether(src=CLIENT_MAC, dst=SERVER_MAC)
    to_client = Ether(src=SERVER_MAC, dst=CLIENT_MAC)
    for dport in (443, 443, 80):  # repeated, only two distinct ports
        for i in range(6):
            flags = "PA" if i % 2 == 0 else "A"
            pkts.append(to_server / IP(src=client, dst=server)
                        / TCP(sport=52000 + dport, dport=dport, flags=flags))
            pkts.append(to_client / IP(src=server, dst=client)
                        / TCP(sport=dport, dport=52000 + dport, flags="A"))
    pkts.append(to_server / IP(src=client, dst="8.8.8.8") / UDP(sport=5353, dport=53))
    return pkts


_BUILDERS = {
    "port_scan": build_port_scan,
    "syn_flood": build_syn_flood,
    "arp_spoof": build_arp_spoof,
    "icmp_flood": build_icmp_flood,
    "dns_tunnel": build_dns_tunnel,
    "beacon": build_beacon,
    "slow_scan": build_slow_scan,
    "benign": build_benign,
}


def write_samples(out_dir: str | Path) -> dict[str, Path]:
    """Write every sample capture into out_dir; returns {name: path}."""
    if not _SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required to write pcap samples")
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for name, builder in _BUILDERS.items():
        path = out / f"{name}.pcap"
        wrpcap(str(path), builder())
        written[name] = path
    return written
