"""NetSleuth packet sniffer — Phase 2 (stub).

Wireshark-style live capture built on scapy. Per CLAUDE.md rule #3, scapy's
blocking ``sniff()`` runs in its own dedicated thread controlled by a
``threading.Event`` stop flag — no asyncio anywhere.

Planned surface:
  * Sniffer class: start()/stop() driving a worker thread around sniff().
  * Decoders for TCP / UDP / ICMP / ARP / DNS into per-packet summaries.
  * Optional hex dump of payloads.
  * Per-IP traffic volume counters feeding analyzer.py.

Requires raw-socket privileges; callers must gate on privileges.can_raw_socket()
and degrade gracefully (rule #4).
"""

from __future__ import annotations

# Implementation lands in Phase 2.
