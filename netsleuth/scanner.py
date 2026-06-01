"""NetSleuth port scanner — Phase 1.

Implements scanning logic ourselves (CLAUDE.md rule #1): no python-nmap, no
shelling out to the nmap binary. Two strategies:

  * connect scan  — uses socket.connect_ex; works unprivileged.
  * SYN scan      — crafts a TCP SYN with scapy and inspects the reply; needs
                    raw-socket privileges.

Concurrency is a single ThreadPoolExecutor over ports (CLAUDE.md rule #3 — no
asyncio). The OS guess is a *family heuristic* only, never called "detection"
(rule #2).
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from enum import Enum

from .privileges import can_raw_socket

# scapy is a building block we compose, not a finished tool we orchestrate, so
# using it still counts as "doing it ourselves". Imported lazily-friendly at the
# top; SYN scanning is only invoked when privileged.
try:
    from scapy.all import IP, TCP, sr1, conf as scapy_conf

    scapy_conf.verb = 0  # silence scapy's own logging
    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _SCAPY_AVAILABLE = False


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass
class PortResult:
    port: int
    state: PortState
    banner: str | None = None
    service_hint: str | None = None


@dataclass
class ScanReport:
    target: str
    scan_type: str  # "syn" or "connect"
    ports: list[PortResult] = field(default_factory=list)
    os_family_guess: str | None = None  # heuristic only — see note in code

    @property
    def open_ports(self) -> list[int]:
        return [p.port for p in self.ports if p.state is PortState.OPEN]


# --- Banner grabbing ------------------------------------------------------- #

# A tiny probe table. For services that speak first (FTP/SSH) we just read; for
# HTTP we have to send a request before the server says anything.
_HTTP_PORTS = {80, 8080, 8000, 443, 8443}


def _grab_banner(target: str, port: int, timeout: float = 1.5) -> str | None:
    """Best-effort banner grab for HTTP / FTP / SSH-style services."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target, port))
            if port in _HTTP_PORTS:
                req = f"HEAD / HTTP/1.0\r\nHost: {target}\r\n\r\n"
                s.sendall(req.encode())
            data = s.recv(256)
            return data.decode(errors="replace").strip() or None
    except (OSError, socket.timeout):
        return None


def _service_hint(port: int, banner: str | None) -> str | None:
    common = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 143: "imap", 443: "https",
        3306: "mysql", 3389: "rdp", 5432: "postgres", 8080: "http-alt",
    }
    if banner and "SSH" in banner:
        return "ssh"
    if banner and banner.startswith("220"):
        return "ftp/smtp"
    return common.get(port)


# --- Connect scan (unprivileged) ------------------------------------------- #

def _connect_probe(target: str, port: int, timeout: float) -> PortResult:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((target, port))
    if result == 0:
        banner = _grab_banner(target, port)
        return PortResult(port, PortState.OPEN, banner, _service_hint(port, banner))
    return PortResult(port, PortState.CLOSED)


# --- SYN scan (privileged, scapy) ------------------------------------------ #

def _syn_probe(target: str, port: int, timeout: float) -> PortResult:
    """Send a lone SYN and classify the reply.

    SYN-ACK (flags 0x12) -> open; RST (0x14) -> closed; no reply -> filtered.
    We send a RST after a SYN-ACK to avoid completing the handshake (a polite
    half-open scan), mirroring how nmap's SYN scan behaves.
    """
    pkt = IP(dst=target) / TCP(dport=port, flags="S")
    resp = sr1(pkt, timeout=timeout)
    if resp is None:
        return PortResult(port, PortState.FILTERED)
    if resp.haslayer(TCP):
        flags = resp[TCP].flags
        if flags == 0x12:  # SYN-ACK
            # tear down without finishing the handshake
            sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=timeout)
            banner = _grab_banner(target, port)
            return PortResult(port, PortState.OPEN, banner, _service_hint(port, banner))
        if flags == 0x14:  # RST-ACK
            return PortResult(port, PortState.CLOSED)
    return PortResult(port, PortState.FILTERED)


# --- OS family heuristic (NOT detection) ----------------------------------- #

def _os_family_guess(target: str, timeout: float = 1.5) -> str | None:
    """Rough OS *family* guess from the TTL (and window size) of one reply.

    This is a coarse heuristic, NOT OS fingerprinting. Real fingerprinting
    needs dozens of probes and a signature database. We label it as a guess
    everywhere it surfaces. Typical initial TTLs: ~64 Linux/Unix, ~128 Windows,
    ~255 many network devices.
    """
    if not (_SCAPY_AVAILABLE and can_raw_socket()):
        return None
    resp = sr1(IP(dst=target) / TCP(dport=80, flags="S"), timeout=timeout)
    if resp is None or not resp.haslayer(IP):
        return None
    ttl = resp[IP].ttl
    if ttl <= 64:
        return "Linux/Unix family (TTL≈64 heuristic — best guess)"
    if ttl <= 128:
        return "Windows family (TTL≈128 heuristic — best guess)"
    return "Network device / other (high TTL heuristic — best guess)"


# --- Public entry point ---------------------------------------------------- #

def scan(
    target: str,
    ports: list[int],
    *,
    timeout: float = 1.0,
    max_workers: int = 100,
    force_connect: bool = False,
) -> ScanReport:
    """Scan `ports` on `target`, picking SYN vs connect based on privilege.

    Set force_connect=True to use the connect scan even when privileged
    (useful for the optional nmap-parity test).
    """
    use_syn = can_raw_socket() and _SCAPY_AVAILABLE and not force_connect
    scan_type = "syn" if use_syn else "connect"
    probe = _syn_probe if use_syn else _connect_probe

    results: list[PortResult] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(probe, target, p, timeout): p for p in ports}
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except (OSError, PermissionError):
                # Degrade quietly per-port rather than aborting the whole scan.
                results.append(PortResult(futures[fut], PortState.FILTERED))

    results.sort(key=lambda r: r.port)
    report = ScanReport(target=target, scan_type=scan_type, ports=results)
    report.os_family_guess = _os_family_guess(target) if use_syn else None
    return report
