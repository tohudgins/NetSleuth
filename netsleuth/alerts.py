"""Alert forwarding — Phase 4.

Generalizes the old "--honeypot-mode" idea into standard blue-team integration:
emit detected anomaly flags to whatever your alerting pipeline ingests. A
honeypot, a SIEM, or a log shipper are all just sinks for the same JSON.

Three sinks, all stdlib (no new dependencies):
  * JSON-lines — append one JSON object per flag to a file (the universal,
    SIEM-friendly format).
  * webhook    — HTTP POST the flags as a JSON array (Slack-style, SOAR, etc.).
  * syslog     — send each flag as a syslog message (RFC 3164 via SysLogHandler).

Network sinks fail soft: a webhook/syslog error is reported, never fatal.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path

from .analyzer import AnomalyFlag


def _as_dicts(anomalies: list[AnomalyFlag]) -> list[dict[str, str]]:
    return [asdict(a) for a in anomalies]


def to_jsonl(anomalies: list[AnomalyFlag]) -> str:
    """Render flags as JSON-lines (one compact JSON object per line)."""
    return "\n".join(json.dumps(d, sort_keys=True) for d in _as_dicts(anomalies))


def write_jsonl(path: str | Path, anomalies: list[AnomalyFlag]) -> Path:
    """Append flags as JSON-lines to a file (created if absent)."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    if anomalies:
        with out.open("a", encoding="utf-8") as fh:
            fh.write(to_jsonl(anomalies) + "\n")
    return out


def post_webhook(url: str, anomalies: list[AnomalyFlag], *, timeout: float = 5.0) -> int:
    """POST flags as a JSON array; returns the HTTP status code."""
    payload = json.dumps({"tool": "NetSleuth", "anomalies": _as_dicts(anomalies)})
    req = urllib.request.Request(
        url, data=payload.encode(), method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (user-supplied URL)
        return int(resp.status)


def send_syslog(
    anomalies: list[AnomalyFlag],
    *,
    address: tuple[str, int] = ("localhost", 514),
) -> None:
    """Send each flag as a syslog WARNING via SysLogHandler (UDP)."""
    logger = logging.getLogger("netsleuth.alerts.syslog")
    logger.setLevel(logging.WARNING)
    handler = logging.handlers.SysLogHandler(address=address)
    handler.setFormatter(logging.Formatter("netsleuth[%(process)d]: %(message)s"))
    logger.addHandler(handler)
    try:
        for a in anomalies:
            logger.warning("[%s/%s] %s", a.kind, a.severity, a.detail)
    finally:
        handler.close()
        logger.removeHandler(handler)


def emit_alerts(
    anomalies: list[AnomalyFlag],
    *,
    jsonl_path: str | Path | None = None,
    webhook: str | None = None,
    syslog: tuple[str, int] | None = None,
) -> list[str]:
    """Dispatch flags to the configured sinks; returns human-readable results.

    Network sinks fail soft so a down collector never aborts the run.
    """
    results: list[str] = []
    if not anomalies:
        return results

    if jsonl_path is not None:
        path = write_jsonl(jsonl_path, anomalies)
        results.append(f"wrote {len(anomalies)} alert(s) to {path}")

    if webhook is not None:
        try:
            status = post_webhook(webhook, anomalies)
            results.append(f"posted {len(anomalies)} alert(s) to webhook (HTTP {status})")
        except (urllib.error.URLError, OSError, ValueError) as exc:
            results.append(f"webhook failed: {exc}")

    if syslog is not None:
        try:
            send_syslog(anomalies, address=syslog)
            results.append(f"sent {len(anomalies)} alert(s) to syslog {syslog[0]}:{syslog[1]}")
        except OSError as exc:
            results.append(f"syslog failed: {exc}")

    return results
