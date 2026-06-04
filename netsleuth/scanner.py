"""NetSleuth port scanner — Phase 1.

Implements scanning logic ourselves (CLAUDE.md rule #1): no python-nmap, no
shelling out to the nmap binary. Strategies:

  * TCP connect scan — uses socket.connect_ex; works unprivileged.
  * TCP SYN scan      — crafts a TCP SYN with scapy and inspects the reply;
                        needs raw-socket privileges.
  * UDP scan          — unprivileged best-effort via a connected datagram
                        socket, or a scapy probe (UDP reply / ICMP
                        port-unreachable) when privileged.

Concurrency is a single ThreadPoolExecutor over ports (CLAUDE.md rule #3 — no
asyncio). The OS guess is a *family heuristic* only, never called "detection"
(rule #2).
"""

from __future__ import annotations

import logging
import socket
import ssl
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .privileges import can_raw_socket

logger = logging.getLogger(__name__)

# nmap-style timing templates: T -> (max_workers, per-port timeout, inter-probe
# delay). Lower = stealthier/politer (fewer workers, longer waits, spaced
# probes); higher = faster. T3 reproduces the built-in defaults.
TIMING_TEMPLATES: dict[int, tuple[int, float, float]] = {
    0: (1, 5.0, 1.0),     # paranoid — serial, one probe/second
    1: (1, 3.0, 0.4),     # sneaky
    2: (10, 2.0, 0.1),    # polite
    3: (100, 1.0, 0.0),   # normal (default)
    4: (200, 0.5, 0.0),   # aggressive
    5: (400, 0.25, 0.0),  # insane
}

# scapy is a building block we compose, not a finished tool we orchestrate, so
# using it still counts as "doing it ourselves". Imported lazily-friendly at the
# top; SYN/UDP raw probes are only invoked when privileged.
try:
    from scapy.all import ICMP, IP, TCP, UDP, conf as scapy_conf, sr1

    scapy_conf.verb = 0  # silence scapy's own logging
    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _SCAPY_AVAILABLE = False


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    # UDP frequently can't separate "open" from "filtered" — be honest about it.
    OPEN_FILTERED = "open|filtered"


@dataclass
class PortResult:
    port: int
    state: PortState
    proto: Protocol = Protocol.TCP
    banner: str | None = None
    service_hint: str | None = None


@dataclass
class ScanReport:
    target: str
    scan_type: str  # "syn" | "connect" | "udp" | "udp-connect"
    proto: Protocol = Protocol.TCP
    ports: list[PortResult] = field(default_factory=list)
    os_family_guess: str | None = None  # heuristic only — see note in code

    @property
    def open_ports(self) -> list[int]:
        open_states = {PortState.OPEN, PortState.OPEN_FILTERED}
        return [p.port for p in self.ports if p.state in open_states]


# --- Banner grabbing ------------------------------------------------------- #

# Ports where we must speak first (send a request) vs. read-first services that
# greet us on connect (FTP/SSH/SMTP/POP3/IMAP/Telnet/MySQL just need a read).
_HTTP_PORTS = {80, 8080, 8000}
_HTTPS_PORTS = {443, 8443}


def _http_head(target: str) -> bytes:
    return f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n".encode()


def _grab_tls_banner(target: str, port: int, timeout: float) -> str | None:
    """HTTPS banner grab over TLS.

    We scan by IP and lab targets use self-signed certs, so verification is
    disabled deliberately — we want the server's response, not a trust decision.
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((target, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=target) as s:
            s.settimeout(timeout)
            s.sendall(_http_head(target))
            data = s.recv(256)
    return data.decode(errors="replace").strip() or None


def _grab_banner(target: str, port: int, timeout: float = 1.5) -> str | None:
    """Best-effort banner grab for HTTP(S) / FTP / SSH / mail-style services."""
    try:
        if port in _HTTPS_PORTS:
            return _grab_tls_banner(target, port, timeout)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            if port in _HTTP_PORTS:
                s.sendall(_http_head(target))
            data = s.recv(256)
            return data.decode(errors="replace").strip() or None
    except (OSError, ssl.SSLError):
        return None


def _service_hint(port: int, banner: str | None) -> str | None:
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        67: "dhcp", 68: "dhcp", 80: "http", 110: "pop3", 123: "ntp",
        143: "imap", 161: "snmp", 443: "https", 500: "isakmp",
        3306: "mysql", 3389: "rdp", 5432: "postgres",
        8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
    }
    if banner and "SSH" in banner:
        return "ssh"
    if banner and banner.startswith("220"):
        return "ftp/smtp"
    return common.get(port)


# --- TCP connect scan (unprivileged) --------------------------------------- #

def _connect_probe(target: str, port: int, timeout: float) -> PortResult:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
    if result == 0:
        banner = _grab_banner(target, port)
        return PortResult(port, PortState.OPEN, Protocol.TCP, banner,
                          _service_hint(port, banner))
    return PortResult(port, PortState.CLOSED, Protocol.TCP)


# --- TCP SYN scan (privileged, scapy) -------------------------------------- #

def _syn_probe(target: str, port: int, timeout: float) -> PortResult:
    """Send a lone SYN and classify the reply.

    SYN-ACK (flags 0x12) -> open; RST (0x14) -> closed; no reply -> filtered.
    We send a RST after a SYN-ACK to avoid completing the handshake (a polite
    half-open scan), mirroring how nmap's SYN scan behaves.
    """
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        return PortResult(port, PortState.FILTERED, Protocol.TCP)
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:  # SYN-ACK
            # tear down without finishing the handshake
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=timeout)
            banner = _grab_banner(target, port)
            return PortResult(port, PortState.OPEN, Protocol.TCP, banner,
                              _service_hint(port, banner))
        if flags == 0x14:  # RST-ACK
            return PortResult(port, PortState.CLOSED, Protocol.TCP)
    return PortResult(port, PortState.FILTERED, Protocol.TCP)


# --- UDP scan -------------------------------------------------------------- #

def _udp_connect_probe(target: str, port: int, timeout: float) -> PortResult:
    """Unprivileged UDP probe via a connected datagram socket.

    A datagram back -> open. A ConnectionRefusedError means the kernel saw an
    ICMP port-unreachable -> closed. Silence -> open|filtered (we genuinely
    can't tell without raw sockets, so we say so).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            s.send(b"\x00")
            try:
                data = s.recv(256)
            except socket.timeout:
                return PortResult(port, PortState.OPEN_FILTERED, Protocol.UDP)
            banner = data.decode(errors="replace").strip() or None
            return PortResult(port, PortState.OPEN, Protocol.UDP, banner,
                              _service_hint(port, banner))
    except ConnectionRefusedError:
        return PortResult(port, PortState.CLOSED, Protocol.UDP)
    except OSError:
        return PortResult(port, PortState.OPEN_FILTERED, Protocol.UDP)


def _udp_scapy_probe(target: str, port: int, timeout: float) -> PortResult:
    """Privileged UDP probe: UDP reply -> open; ICMP 3/3 -> closed.

    Other ICMP unreachable codes mean the port is administratively filtered;
    no reply at all is the ambiguous open|filtered case.
    """
    resp = sr1(IP(dst=target) / UDP(dport=port), timeout=timeout)
    if resp is None:
        return PortResult(port, PortState.OPEN_FILTERED, Protocol.UDP)
    if resp.haslayer(UDP):
        return PortResult(port, PortState.OPEN, Protocol.UDP)
    if resp.haslayer(ICMP):
        icmp = resp[ICMP]
        if int(icmp.type) == 3 and int(icmp.code) == 3:  # port unreachable
            return PortResult(port, PortState.CLOSED, Protocol.UDP)
        return PortResult(port, PortState.FILTERED, Protocol.UDP)
    return PortResult(port, PortState.OPEN_FILTERED, Protocol.UDP)


# --- OS family heuristic (NOT detection) ----------------------------------- #

def _family_from_ttl(ttl: int) -> str:
    """Map an observed TTL to a coarse OS *family* guess.

    Pure function so it can be unit-tested without scapy or a live network.
    Typical initial TTLs: ~64 Linux/Unix, ~128 Windows, ~255 network devices.
    This is a heuristic, NOT OS fingerprinting.
    """
    if ttl <= 64:
        return "Linux/Unix family (TTL≈64 heuristic — best guess)"
    if ttl <= 128:
        return "Windows family (TTL≈128 heuristic — best guess)"
    return "Network device / other (high TTL heuristic — best guess)"


def _os_family_guess(target: str, timeout: float = 1.5) -> str | None:
    """Rough OS *family* guess from the TTL of one reply.

    This is a coarse heuristic, NOT OS fingerprinting. Real fingerprinting needs
    dozens of probes and a signature database. We label it as a guess everywhere
    it surfaces.
    """
    if not (_SCAPY_AVAILABLE and can_raw_socket()):
        return None
    resp = sr1(IP(dst=target) / TCP(dport=80, flags="S"), timeout=timeout)
    if resp is None or not resp.haslayer(IP):
        return None
    return _family_from_ttl(int(resp[IP].ttl))


# --- Public entry point ---------------------------------------------------- #

def scan(
    target: str,
    ports: list[int],
    *,
    proto: Protocol = Protocol.TCP,
    timeout: float = 1.0,
    max_workers: int = 100,
    delay: float = 0.0,
    force_connect: bool = False,
    on_result: Callable[[PortResult], None] | None = None,
) -> ScanReport:
    """Scan `ports` on `target`, picking the probe by protocol and privilege.

    Set force_connect=True to use the TCP connect scan even when privileged
    (useful for the optional nmap-parity test). `on_result` is invoked on the
    calling thread as each port finishes — used by the UI for a progress bar.
    `delay` spaces out probe submissions (timing templates) — with max_workers=1
    that yields a serial, paced scan for stealth/politeness.
    """
    privileged = can_raw_socket() and _SCAPY_AVAILABLE
    if proto is Protocol.UDP:
        use_raw = privileged
        probe = _udp_scapy_probe if use_raw else _udp_connect_probe
        scan_type = "udp" if use_raw else "udp-connect"
    else:
        use_raw = privileged and not force_connect
        probe = _syn_probe if use_raw else _connect_probe
        scan_type = "syn" if use_raw else "connect"

    logger.debug("scan %s: %d ports, type=%s, workers=%d, timeout=%.2fs, delay=%.2fs",
                 target, len(ports), scan_type, max_workers, timeout, delay)
    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures: dict[Any, int] = {}
        for p in ports:
            futures[pool.submit(probe, target, p, timeout)] = p
            if delay:
                time.sleep(delay)  # pace probe submission for stealthy templates
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except (OSError, PermissionError):
                # Degrade quietly per-port rather than aborting the whole scan.
                result = PortResult(futures[fut], PortState.FILTERED, proto)
            results.append(result)
            if on_result is not None:
                on_result(result)

    results.sort(key=lambda r: r.port)
    report = ScanReport(target=target, scan_type=scan_type, proto=proto, ports=results)
    if proto is Protocol.TCP and use_raw:
        report.os_family_guess = _os_family_guess(target)
    return report
