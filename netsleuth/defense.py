"""NetSleuth ARP-spoofing / MITM detector — active defense.

This is the *defensive* counterpart to a man-in-the-middle attack: instead of
performing ARP poisoning, NetSleuth watches the ARP traffic the sniffer already
captures and flags the tell-tale signs that someone *else* is doing it. It is
the natural extension of the analyzer's coarse "one IP, many MACs" check, made
stateful and gateway-aware.

Like the analyzer, this works purely off ``PacketSummary`` fields (the ``mac``
and ``arp_op`` the sniffer fills in), so it needs no scapy and is fully
unit-testable. Detections are clearly-labeled heuristics, not proof:

  * arp-mac-change   — an IP's MAC changed from a known-good baseline. For the
                       gateway this is the classic poisoning signature → critical.
  * duplicate-ip     — one IP currently claimed by multiple MACs (a poisoner and
                       the real host both answering).
  * mac-many-ips     — one MAC claiming many IPs (a poisoner impersonating the
                       whole subnet).
  * gratuitous-arp   — a host sending an unusual volume of unsolicited is-at
                       replies (how poisoners keep a victim's cache poisoned).

Build a ``baseline`` (IP → real MAC) from a trusted discovery sweep or your
known gateway; pass it in to turn the first check on. Without a baseline the
last three still work off the captured traffic alone.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from .sniffer import PacketSummary


@dataclass
class DefenseAlert:
    kind: str  # "arp-mac-change" | "duplicate-ip" | "mac-many-ips" | "gratuitous-arp"
    severity: str  # "info" | "warning" | "critical"
    detail: str  # human-readable, names the heuristic


@dataclass
class DefenseConfig:
    # Conservative defaults; tune per environment.
    mac_many_ips: int = 5  # one MAC claiming >= this many IPs is suspicious
    gratuitous_replies: int = 20  # unsolicited is-at replies from one MAC
    # IPs whose MAC change should be escalated to "critical" (e.g. the gateway).
    # Empty == treat every baseline MAC change as a warning.
    critical_ips: set[str] = field(default_factory=set)


def _normalize(mac: str) -> str:
    return mac.lower().replace("-", ":")


def detect_spoofing(
    packets: list[PacketSummary],
    *,
    baseline: dict[str, str] | None = None,
    config: DefenseConfig | None = None,
) -> list[DefenseAlert]:
    """Inspect a batch of packet summaries for ARP-spoofing signatures.

    ``baseline`` maps an IP to its known-good MAC (from a trusted sweep). When
    supplied, any observed MAC for that IP that differs raises an
    ``arp-mac-change`` alert — escalated to critical for ``config.critical_ips``.
    """
    cfg = config or DefenseConfig()
    base = {ip: _normalize(mac) for ip, mac in (baseline or {}).items()}
    critical = cfg.critical_ips

    macs_by_ip: dict[str, set[str]] = defaultdict(set)
    ips_by_mac: dict[str, set[str]] = defaultdict(set)
    replies_by_mac: dict[str, int] = defaultdict(int)

    for p in packets:
        if p.proto != "ARP" or not p.mac:
            continue
        mac = _normalize(p.mac)
        macs_by_ip[p.src].add(mac)
        ips_by_mac[mac].add(p.src)
        if p.arp_op == "is-at":
            replies_by_mac[mac] += 1

    alerts: list[DefenseAlert] = []

    # 1. MAC changed vs. a trusted baseline — strongest single signal.
    for ip, observed in sorted(macs_by_ip.items()):
        known = base.get(ip)
        if known is None:
            continue
        rogue = sorted(observed - {known})
        if rogue:
            sev = "critical" if ip in critical else "warning"
            alerts.append(DefenseAlert(
                "arp-mac-change", sev,
                f"{ip} baseline MAC is {known} but ARP advertised "
                f"{', '.join(rogue)} — possible ARP poisoning (heuristic)",
            ))

    # 2. One IP currently claimed by multiple MACs.
    for ip, observed in sorted(macs_by_ip.items()):
        if len(observed) > 1:
            sev = "critical" if ip in critical else "warning"
            alerts.append(DefenseAlert(
                "duplicate-ip", sev,
                f"{ip} is claimed by {len(observed)} MACs "
                f"({', '.join(sorted(observed))}) — possible ARP spoofing (heuristic)",
            ))

    # 3. One MAC impersonating many IPs (subnet-wide poisoning).
    for mac, ips in sorted(ips_by_mac.items()):
        if len(ips) >= cfg.mac_many_ips:
            alerts.append(DefenseAlert(
                "mac-many-ips", "warning",
                f"{mac} answered for {len(ips)} distinct IPs "
                f"(>= {cfg.mac_many_ips}) — one host impersonating many "
                "(heuristic)",
            ))

    # 4. A flood of unsolicited is-at replies (keeps a poisoned cache fresh).
    for mac, count in sorted(replies_by_mac.items()):
        if count >= cfg.gratuitous_replies:
            alerts.append(DefenseAlert(
                "gratuitous-arp", "warning",
                f"{mac} sent {count} ARP is-at replies "
                f"(>= {cfg.gratuitous_replies}) — possible gratuitous-ARP "
                "flooding (heuristic)",
            ))

    return alerts
