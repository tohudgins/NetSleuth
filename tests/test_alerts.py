"""Unit tests for alert forwarding — Phase 4. No real network used."""

from __future__ import annotations

import json

from netsleuth import alerts
from netsleuth.alerts import emit_alerts, to_jsonl, write_jsonl
from netsleuth.analyzer import AnomalyFlag

_FLAGS = [
    AnomalyFlag("port-scan", "warning", "10.0.0.5 touched 20 ports"),
    AnomalyFlag("arp-spoof", "warning", "10.0.0.1 advertised 2 MACs"),
]


def test_to_jsonl_one_object_per_line():
    lines = to_jsonl(_FLAGS).splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["kind"] == "port-scan" and first["severity"] == "warning"


def test_write_jsonl_appends(tmp_path):
    path = tmp_path / "alerts.jsonl"
    write_jsonl(path, _FLAGS)
    write_jsonl(path, _FLAGS)
    lines = path.read_text().splitlines()
    assert len(lines) == 4  # appended, not overwritten


def test_emit_alerts_noop_when_empty(tmp_path):
    path = tmp_path / "alerts.jsonl"
    assert emit_alerts([], jsonl_path=path) == []
    assert not path.exists()


def test_emit_alerts_webhook_failsoft(monkeypatch):
    def _boom(url, anomalies, **kw):
        raise OSError("connection refused")

    monkeypatch.setattr(alerts, "post_webhook", _boom)
    results = emit_alerts(_FLAGS, webhook="http://localhost:9/none")
    assert any("webhook failed" in r for r in results)


def test_emit_alerts_webhook_success(monkeypatch):
    captured = {}

    def _ok(url, anomalies, **kw):
        captured["url"] = url
        captured["n"] = len(anomalies)
        return 200

    monkeypatch.setattr(alerts, "post_webhook", _ok)
    results = emit_alerts(_FLAGS, webhook="http://example/hook")
    assert captured["n"] == 2
    assert any("HTTP 200" in r for r in results)
