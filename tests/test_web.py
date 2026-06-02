"""Tests for the Flask web dashboard via the test client (no real network/root)."""

from __future__ import annotations

import pytest

import netsleuth.web as web
from netsleuth.sniffer import TrafficStats
from netsleuth.web import create_app


@pytest.fixture
def client():
    app = create_app()
    app.config.update(TESTING=True)
    return app.test_client()


def test_index_serves_dashboard(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"NetSleuth" in resp.data


def test_api_scan_localhost(client):
    resp = client.post("/api/scan", json={
        "target": "127.0.0.1", "ports": "22,80", "connect": True, "timeout": 0.3,
    })
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["scan"]["target"] == "127.0.0.1"
    assert body["scan"]["scan_type"] == "connect"


def test_api_pcap_detects_attack(client, tmp_path):
    samples = pytest.importorskip("netsleuth.samples")
    if not samples._SCAPY_AVAILABLE:  # pragma: no cover
        pytest.skip("scapy not installed")
    paths = samples.write_samples(tmp_path)
    with paths["port_scan"].open("rb") as fh:
        resp = client.post("/api/pcap", data={"file": (fh, "port_scan.pcap")},
                           content_type="multipart/form-data")
    assert resp.status_code == 200
    body = resp.get_json()
    assert any(a["kind"] == "port-scan" for a in body["anomalies"])


def test_api_pcap_missing_file(client):
    resp = client.post("/api/pcap", data={}, content_type="multipart/form-data")
    assert resp.status_code == 400


def test_capture_start_requires_privilege(client, monkeypatch):
    monkeypatch.setattr(web, "capture_available", lambda: False)
    resp = client.post("/api/capture/start", json={})
    assert resp.status_code == 403
    assert "privileges" in resp.get_json()["error"]


class _FakeSniffer:
    def __init__(self, *, iface=None, bpf_filter=None, on_packet=None):
        self.packets: list = []
        self.stats = TrafficStats()
        self.error = None
        self.running = False
        self.on_packet = on_packet

    def start(self):
        self.running = True

    def stop(self, timeout=2.0):
        self.running = False


def test_capture_start_stop_roundtrip(client, monkeypatch):
    monkeypatch.setattr(web, "capture_available", lambda: True)
    monkeypatch.setattr(web, "Sniffer", _FakeSniffer)
    monkeypatch.setattr(web, "_sniffer", None)

    assert client.post("/api/capture/start", json={"iface": "lo0"}).status_code == 200
    stop = client.post("/api/capture/stop")
    assert stop.status_code == 200
    body = stop.get_json()
    assert "traffic" in body
    assert "defense" in body  # spoofing alerts attached to live-capture report


def test_api_discover_force_tcp_localhost(client):
    resp = client.post("/api/discover", json={"network": "127.0.0.1"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["discovery"]["network"] == "127.0.0.1"
    assert "hosts" in body["discovery"]


def test_capture_frame_hexdump(client):
    # Seed the bounded raw-frame store directly, then drill into it.
    monkey_idx = 7
    with web._frames_lock:
        web._raw_frames.clear()
        web._raw_frames[monkey_idx] = b"GET / HTTP/1.0\r\n\r\n"
    resp = client.get(f"/api/capture/frame/{monkey_idx}")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["index"] == monkey_idx
    assert "GET" in body["hex"]  # ASCII column of our own hexdump
    assert client.get("/api/capture/frame/999999").status_code == 404
