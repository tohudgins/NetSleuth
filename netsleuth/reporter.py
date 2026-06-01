"""NetSleuth reporter — Phase 3.

Builds a single unified report (scan results + traffic stats + anomaly flags)
and exports it as:

  * JSON  — machine-readable, via the stdlib ``json`` module.
  * HTML  — human-readable, rendered from templates/report.html with jinja2.

The intermediate ``build_report()`` dict is the stable schema both formats share.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .analyzer import AnomalyFlag
from .scanner import ScanReport
from .sniffer import TrafficStats

_TEMPLATE_DIR = Path(__file__).resolve().parent.parent / "templates"


def build_report(
    scan: ScanReport | None = None,
    stats: TrafficStats | None = None,
    anomalies: list[AnomalyFlag] | None = None,
) -> dict[str, Any]:
    """Assemble the unified, JSON-serialisable report structure."""
    report: dict[str, Any] = {
        "tool": "NetSleuth",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "authorized_use_only": True,
    }

    if scan is not None:
        report["scan"] = {
            "target": scan.target,
            "scan_type": scan.scan_type,
            "proto": scan.proto.value,
            "os_family_guess": scan.os_family_guess,
            "open_ports": scan.open_ports,
            "ports": [
                {
                    "port": p.port,
                    "proto": p.proto.value,
                    "state": p.state.value,
                    "service_hint": p.service_hint,
                    "banner": p.banner,
                }
                for p in scan.ports
            ],
        }

    if stats is not None:
        report["traffic"] = {
            "packets": stats.packets,
            "bytes": stats.bytes,
            "by_ip": [
                {"ip": ip, "packets": c.packets, "bytes": c.bytes}
                for ip, c in stats.top(50)
            ],
        }

    if anomalies is not None:
        report["anomalies"] = [
            {"kind": a.kind, "severity": a.severity, "detail": a.detail}
            for a in anomalies
        ]

    return report


def to_json(report: dict[str, Any]) -> str:
    return json.dumps(report, indent=2, sort_keys=False)


def to_html(report: dict[str, Any]) -> str:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    template = env.get_template("report.html")
    return template.render(**report)


def write_report(
    out_dir: str | Path,
    report: dict[str, Any],
    *,
    basename: str = "netsleuth-report",
) -> dict[str, Path]:
    """Write JSON + HTML into out_dir; returns the paths written."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    json_path = out / f"{basename}.json"
    html_path = out / f"{basename}.html"
    json_path.write_text(to_json(report), encoding="utf-8")
    html_path.write_text(to_html(report), encoding="utf-8")
    return {"json": json_path, "html": html_path}
