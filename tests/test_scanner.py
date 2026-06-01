"""Unit tests for the scanner — Phase 1.

These exercise the pure/helper logic that doesn't require privileges or a live
network. Probe-level tests use a loopback listener so they stay hermetic.
"""

from __future__ import annotations

import socket
import threading

from netsleuth.scanner import (
    PortState,
    _connect_probe,
    _service_hint,
    scan,
)


def test_service_hint_well_known_port():
    assert _service_hint(22, None) == "ssh"
    assert _service_hint(443, None) == "https"


def test_service_hint_from_banner_overrides():
    assert _service_hint(9999, "SSH-2.0-OpenSSH_9.0") == "ssh"


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
    finally:
        stop.set()
        srv.close()
        t.join(timeout=1)


def test_scan_returns_sorted_ports():
    report = scan("127.0.0.1", [80, 22, 443], force_connect=True, timeout=0.2)
    assert [p.port for p in report.ports] == [22, 80, 443]
    assert report.scan_type == "connect"
