"""NetSleuth traffic analyzer — Phase 3 (stub).

Consumes the sniffer's decoded packets and produces traffic statistics plus
*simple, clearly-labeled* anomaly flags. These are heuristics, not an IDS:

  * port-scan pattern  — one source touching many ports in a short window.
  * SYN flood          — high rate of SYNs without completed handshakes.
  * ARP spoof signs    — one IP claiming multiple MACs (or vice versa).

Planned surface:
  * TrafficStats dataclass: per-IP counts, byte volumes, protocol breakdown.
  * analyze(packets) -> list[AnomalyFlag] with a short human-readable reason.
"""

from __future__ import annotations

# Implementation lands in Phase 3.
