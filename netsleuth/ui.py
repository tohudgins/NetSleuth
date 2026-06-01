"""NetSleuth CLI dashboard — Phase 3 (stub).

A ``rich``-based terminal UI: scan progress bars, a results table, and a live
dashboard that updates as the sniffer reports traffic. Pure presentation — it
reads from scanner/sniffer/analyzer and renders; it holds no capture logic.

Planned surface:
  * print_privilege_notice(notice: str)
  * render_scan_table(report)
  * live_dashboard(...)  — rich.live.Live loop over scan + traffic state.
"""

from __future__ import annotations

# Implementation lands in Phase 3.
