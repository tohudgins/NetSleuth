"""Unit tests for the scanner — Phase 1.

These exercise the pure/helper logic that doesn't require privileges or a live
network. Probe-level tests use a loopback listener so they stay hermetic.
"""

from __future__ import annotations

import socket
import threading

from netsleuth.cli import _parse_ports
from netsleuth.scanner import (
    TIMING_TEMPLATES,
    PortState,
    Protocol,
    _connect_probe,
    _family_from_ttl,
    _grab_banner,
    _service_hint,
    _udp_connect_probe,
    scan,
)


def test_timing_templates_shape():
    assert set(TIMING_TEMPLATES) == {0, 1, 2, 3, 4, 5}
    assert TIMING_TEMPLATES[3] == (100, 1.0, 0.0)  # T3 == built-in defaults
    # paranoid is slower/serial than insane
    assert TIMING_TEMPLATES[0][0] < TIMING_TEMPLATES[5][0]    # fewer workers
    assert TIMING_TEMPLATES[0][2] > TIMING_TEMPLATES[5][2]    # longer delay


def test_scan_with_delay_still_sorted():
    report = scan("127.0.0.1", [80, 22, 443], force_connect=True, timeout=0.2,
                  delay=0.001, max_workers=1)
    assert [p.port for p in report.ports] == [22, 80, 443]


def test_service_hint_well_known_port():
    assert _service_hint(22, None) == "ssh"
    assert _service_hint(443, None) == "https"
    assert _service_hint(161, None) == "snmp"  # UDP service hint


def test_service_hint_from_banner_overrides():
    assert _service_hint(9999, "SSH-2.0-OpenSSH_9.0") == "ssh"


def test_family_from_ttl_buckets():
    assert "Linux/Unix" in _family_from_ttl(64)
    assert "Windows" in _family_from_ttl(128)
    assert "Network device" in _family_from_ttl(255)


def test_parse_ports_specs():
    assert _parse_ports("22,80,443") == [22, 80, 443]
    assert _parse_ports("1-5") == [1, 2, 3, 4, 5]
    assert _parse_ports("80, 22, 22") == [22, 80]          # dedupe + sort
    assert _parse_ports("0,70000,443") == [443]            # out-of-range dropped


def test_connect_probe_open_then_closed():
    # Stand up a throwaway loopback listener on an ephemeral port.
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _accept_loop():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                conn.close()
            except OSError:
                break

    t = threading.Thread(target=_accept_loop, daemon=True)
    t.start()
    try:
        opened = _connect_probe("127.0.0.1", port, timeout=1.0)
        assert opened.state is PortState.OPEN
        assert opened.proto is Protocol.TCP
    finally:
        stop.set()
        srv.close()
        t.join(timeout=1)


def test_grab_banner_reads_server_greeting():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def _serve_once():
        srv.settimeout(1.0)
        try:
            conn, _ = srv.accept()
            with conn:
                conn.sendall(b"220 test-banner ready\r\n")
        except OSError:
            pass

    t = threading.Thread(target=_serve_once, daemon=True)
    t.start()
    try:
        banner = _grab_banner("127.0.0.1", port, timeout=1.0)
        assert banner == "220 test-banner ready"
    finally:
        srv.close()
        t.join(timeout=1)


def test_udp_connect_probe_open_against_echo():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    stop = threading.Event()

    def _echo_loop():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(256)
                srv.sendto(b"pong:" + data, addr)
            except OSError:
                break

    t = threading.Thread(target=_echo_loop, daemon=True)
    t.start()
    try:
        result = _udp_connect_probe("127.0.0.1", port, timeout=1.0)
        assert result.state is PortState.OPEN
        assert result.proto is Protocol.UDP
    finally:
        stop.set()
        srv.close()
        t.join(timeout=1)


def test_scan_returns_sorted_ports():
    report = scan("127.0.0.1", [80, 22, 443], force_connect=True, timeout=0.2)
    assert [p.port for p in report.ports] == [22, 80, 443]
    assert report.scan_type == "connect"
    assert report.proto is Protocol.TCP


def test_scan_invokes_on_result_callback():
    seen: list[int] = []
    scan("127.0.0.1", [22, 80], force_connect=True, timeout=0.2,
         on_result=lambda r: seen.append(r.port))
    assert sorted(seen) == [22, 80]
