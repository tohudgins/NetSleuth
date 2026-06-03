"""Unit tests for host & network discovery.

The pure helpers (CIDR expansion, OUI lookup) and the unprivileged TCP-ping
path are exercised without privileges; TCP ping uses a loopback listener so it
stays hermetic, like the scanner tests.
"""

from __future__ import annotations

import socket
import threading

from netsleuth.discovery import (
    _expand,
    _tcp_ping,
    discover,
    lookup_vendor,
    subnet_of,
    tcp_ping_sweep,
)


def test_subnet_of():
    assert subnet_of("192.168.1.50") == "192.168.1.0/24"
    assert subnet_of("10.0.0.1") == "10.0.0.0/24"
    assert subnet_of("172.16.5.9", prefix=16) == "172.16.0.0/16"


def test_expand_cidr():
    hosts = _expand("192.168.1.0/30")
    assert hosts == ["192.168.1.1", "192.168.1.2"]  # .hosts() drops net/bcast


def test_expand_single_host():
    assert _expand("10.0.0.5") == ["10.0.0.5"]
    assert _expand("10.0.0.5/32") == ["10.0.0.5"]


def test_lookup_vendor_known_and_unknown():
    assert lookup_vendor("08:00:27:ab:cd:ef") == "VirtualBox"
    assert lookup_vendor("52:54:00:11:22:33") == "QEMU/KVM"
    assert lookup_vendor("DC-A6-32-11-22-33") == "Raspberry Pi"  # dashes + case
    assert lookup_vendor("de:ad:be:ef:00:01") is None
    assert lookup_vendor(None) is None
    assert lookup_vendor("nonsense") is None


def test_tcp_ping_detects_listener_as_up():
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
        host = _tcp_ping("127.0.0.1", (port,), timeout=1.0)
        assert host is not None
        assert host.ip == "127.0.0.1"
        assert host.method == "tcp-ping"
        assert port in host.open_ports
    finally:
        stop.set()
        srv.close()
        t.join(timeout=1)


def test_tcp_ping_refused_port_still_counts_as_up():
    # An ephemeral port with nothing listening on loopback is actively refused,
    # which still proves the host is alive.
    host = _tcp_ping("127.0.0.1", (1,), timeout=0.5)
    assert host is not None
    assert host.open_ports == []  # refused, so up but no open port


def test_tcp_ping_sweep_reports_loopback():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        report = tcp_ping_sweep("127.0.0.1", ports=(port,), timeout=0.5)
        assert report and report[0].ip == "127.0.0.1"
    finally:
        srv.close()


def test_discover_force_tcp_uses_tcp_ping():
    report = discover("127.0.0.1", force_tcp=True, timeout=0.3)
    assert report.method == "tcp-ping"
    assert report.network == "127.0.0.1"
