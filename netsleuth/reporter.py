"""NetSleuth reporter — Phase 3 (stub).

Exports a unified report (scan results + traffic stats + anomaly flags) in two
formats:

  * JSON  — machine-readable, via the stdlib ``json`` module.
  * HTML  — human-readable, rendered from templates/report.html with jinja2.

Planned surface:
  * to_json(report) -> str
  * to_html(report) -> str   (loads templates/report.html)
  * write_report(report, out_dir, formats=("json", "html"))
"""

from __future__ import annotations

# Implementation lands in Phase 3.
