"""Tests for the Flask web dashboard via the test client (no real network/root)."""

from __future__ import annotations

import pytest

import netsleuth.web as web
from netsleuth.sniffer import TrafficStats
from netsleuth.web import create_app


@pytest.fixture
def client(tmp_path):
    # Isolated history DB per test so nothing touches the real ~/.netsleuth.
    app = create_app(db_path=tmp_path / "history.db")
    app.config.update(TESTING=True)
    return app.test_client()


def test_index_serves_dashboard(client):
    resp = client.get("/")
    assert resp.status_code == 200
    assert b"NetSleuth" in resp.data


def test_rejects_non_loopback_host(client):
    # DNS-rebinding: the browser would send the attacker's domain as Host.
    resp = client.post("/api/scan", json={"target": "127.0.0.1"},
                       base_url="http://evil.example.com")
    assert resp.status_code == 403
    assert "Host" in resp.get_json()["error"]


def test_rejects_cross_origin(client):
    resp = client.post("/api/scan", json={"target": "127.0.0.1", "ports": "22",
                                          "connect": True, "timeout": 0.2},
                       headers={"Origin": "http://evil.example.com"})
    assert resp.status_code == 403
    assert "cross-origin" in resp.get_json()["error"]


def test_allows_loopback_origin(client):
    resp = client.post("/api/scan", json={"target": "127.0.0.1", "ports": "22",
                                          "connect": True, "timeout": 0.2},
                       headers={"Origin": "http://127.0.0.1:8765"})
    assert resp.status_code == 200


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


def test_api_pcap_windowed_stream(client, tmp_path):
    samples = pytest.importorskip("netsleuth.samples")
    if not samples._SCAPY_AVAILABLE:  # pragma: no cover
        pytest.skip("scapy not installed")
    paths = samples.write_samples(tmp_path)
    with paths["slow_scan"].open("rb") as fh:
        resp = client.post(
            "/api/pcap",
            data={"file": (fh, "slow_scan.pcap"), "stream": "on"},
            content_type="multipart/form-data")
    assert resp.status_code == 200
    assert any(a["kind"] == "slow-scan" for a in resp.get_json()["anomalies"])


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


def test_history_empty_then_save_then_list(client):
    assert client.get("/api/history").get_json() == {"runs": []}
    # Save a scan run, then it should appear in history.
    client.post("/api/scan", json={"target": "127.0.0.1", "ports": "22",
                                   "connect": True, "timeout": 0.2, "save": True})
    runs = client.get("/api/history").get_json()["runs"]
    assert len(runs) == 1
    assert runs[0]["kind"] == "scan" and runs[0]["target"] == "127.0.0.1"


def test_history_diff_endpoint(client):
    # Two scans of the same target → the second run's /diff compares to the first.
    client.post("/api/scan", json={"target": "127.0.0.1", "ports": "22",
                                   "connect": True, "timeout": 0.2, "save": True})
    r2 = client.post("/api/scan", json={"target": "127.0.0.1", "ports": "22",
                                        "connect": True, "timeout": 0.2, "save": True})
    assert "diff" not in r2.get_json()  # save-only, no diff requested
    runs = client.get("/api/history").get_json()["runs"]
    latest_id = runs[0]["id"]
    diff = client.get(f"/api/history/{latest_id}/diff").get_json()["diff"]
    assert diff is not None and diff["kind"] == "scan" and diff["empty"] is True


def test_scan_with_diff_attaches_delta(client):
    client.post("/api/scan", json={"target": "127.0.0.1", "ports": "22",
                                   "connect": True, "timeout": 0.2, "save": True})
    r2 = client.post("/api/scan", json={"target": "127.0.0.1", "ports": "22",
                                        "connect": True, "timeout": 0.2, "diff": True})
    assert r2.get_json().get("diff", {}).get("kind") == "scan"


def test_history_run_not_found(client):
    assert client.get("/api/history/9999").status_code == 404


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
