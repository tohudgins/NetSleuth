"""NetSleuth host & network discovery — defensive asset mapping.

Builds an inventory of live hosts on a *local* subnet you own — the first step
of any defensive network audit ("what is actually on my wire?"). Two strategies,
chosen by privilege the same way the scanner picks SYN vs connect (CLAUDE.md
rule #4):

  * ARP sweep    — privileged. We craft ARP who-has frames with scapy across the
                   subnet and collect responders (IP + MAC). This is the most
                   reliable local-network discovery: every host must answer ARP.
  * TCP ping     — unprivileged fallback. We can't send raw ICMP without root, so
                   we "ping" each host by attempting a TCP connection to a few
                   common ports; a connect *or* a refusal both prove the host is
                   up. A ``ThreadPoolExecutor`` fans out the probes (rule #3 — no
                   asyncio).

Discovery logic is ours (rule #1): no nmap ``-sn``, no arp-scan binary. The MAC
vendor lookup uses a small, clearly-labeled built-in OUI table — it is a *best
effort* partial map, not the full IEEE registry, and we say so.

Scope is deliberately local: ARP only works on your own broadcast domain, and a
discovery sweep is something you run on a network you own or are authorized to
audit (rule #5).
"""

from __future__ import annotations

import errno
import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from .privileges import can_raw_socket

try:
    from scapy.all import ARP, Ether, conf as scapy_conf, srp

    scapy_conf.verb = 0
    _SCAPY_AVAILABLE = True
except Exception:  # pragma: no cover - environment dependent
    _SCAPY_AVAILABLE = False


# A small, hand-picked OUI → vendor table. This is intentionally partial: the
# full IEEE registry is ~30k entries and we don't ship it. Treated as a *best
# guess* hint, never authoritative — labeled as such wherever it surfaces.
_OUI_VENDORS: dict[str, str] = {
    "00:00:0c": "Cisco",
    "00:1a:11": "Google",
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "52:54:00": "QEMU/KVM",
    "00:16:3e": "Xen",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "ac:de:48": "Apple",
    "f0:18:98": "Apple",
    "a4:83:e7": "Apple",
    "3c:22:fb": "Apple",
    "00:1c:b3": "Apple",
    "fc:fb:fb": "Apple",
    "00:d8:61": "Micro-Star (MSI)",
    "00:e0:4c": "Realtek",
    "00:1d:0f": "TP-Link",
    "50:c7:bf": "TP-Link",
    "ec:08:6b": "TP-Link",
    "00:14:bf": "Cisco-Linksys",
    "00:18:4d": "Netgear",
    "00:26:f2": "Netgear",
    "00:1f:33": "Netgear",
    "ff:ff:ff": "broadcast",
}

# Ports used by the unprivileged TCP-ping fallback. A response of *any* kind
# (open or actively refused) proves the host is alive; only silence is "down".
_TCP_PING_PORTS = (80, 443, 22, 445, 3389)


@dataclass
class Host:
    """One discovered host on the local network."""

    ip: str
    mac: str | None = None
    vendor: str | None = None  # best-guess from the partial OUI table
    method: str = "arp"  # "arp" | "tcp-ping"
    open_ports: list[int] = field(default_factory=list)  # only from tcp-ping


@dataclass
class DiscoveryReport:
    network: str
    method: str  # "arp-sweep" | "tcp-ping"
    hosts: list[Host] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.hosts)


def discovery_available() -> bool:
    """True when the reliable ARP sweep is possible (scapy + privileges)."""
    return _SCAPY_AVAILABLE and can_raw_socket()


def lookup_vendor(mac: str | None) -> str | None:
    """Best-guess vendor from a MAC's OUI prefix (partial built-in table).

    Returns None for unknown prefixes; this is a hint, not authoritative.
    """
    if not mac:
        return None
    parts = mac.lower().replace("-", ":").split(":")
    if len(parts) < 3:
        return None
    return _OUI_VENDORS.get(":".join(parts[:3]))


def _expand(network: str) -> list[str]:
    """Expand a CIDR ('192.168.1.0/24') or single host into addresses to probe.

    A bare host string with no prefix is treated as a single /32 target so the
    same entry point handles 'scan one host' and 'sweep a subnet'.
    """
    net = ipaddress.ip_network(network, strict=False)
    if net.num_addresses <= 2:  # /31, /32 or a single host
        return [str(h) for h in net]
    return [str(h) for h in net.hosts()]


# --- ARP sweep (privileged) ------------------------------------------------ #

def arp_sweep(
    network: str,
    *,
    timeout: float = 2.0,
    iface: str | None = None,
) -> list[Host]:
    """Discover hosts by broadcasting ARP who-has across the subnet.

    Sends one ARP request per address in a single scapy ``srp`` call (scapy
    handles the concurrency) and collects every responder's IP + MAC. Needs
    raw-socket privileges; callers gate on ``discovery_available()``.
    """
    if not _SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for an ARP sweep")
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=_expand(network))
    answered, _ = srp(request, timeout=timeout, iface=iface, verbose=0)
    hosts: list[Host] = []
    seen: set[str] = set()
    for _sent, received in answered:
        ip = str(received.psrc)
        mac = str(received.hwsrc)
        if ip in seen:
            continue
        seen.add(ip)
        hosts.append(Host(ip=ip, mac=mac, vendor=lookup_vendor(mac), method="arp"))
    hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return hosts


# --- TCP ping sweep (unprivileged) ----------------------------------------- #

def _tcp_ping(ip: str, ports: tuple[int, ...], timeout: float) -> Host | None:
    """Probe one host: a connect or an active refusal both mean 'up'.

    Returns a Host (with any open ports we happened to find) when the host
    answers on at least one probe, else None. Silence on every port is treated
    as down/filtered.
    """
    alive = False
    open_ports: list[int] = []
    for port in ports:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((ip, port))
            if result == 0:
                alive = True
                open_ports.append(port)
            elif result == errno.ECONNREFUSED:
                alive = True  # refused = host is up, port just closed
        except OSError:
            continue
    if not alive:
        return None
    return Host(ip=ip, method="tcp-ping", open_ports=sorted(open_ports))


def tcp_ping_sweep(
    network: str,
    *,
    ports: tuple[int, ...] = _TCP_PING_PORTS,
    timeout: float = 0.5,
    max_workers: int = 100,
) -> list[Host]:
    """Unprivileged host discovery via parallel TCP connection probes."""
    targets = _expand(network)
    hosts: list[Host] = []
    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_tcp_ping, ip, ports, timeout): ip for ip in targets
        }
        for fut in as_completed(futures):
            host = fut.result()
            if host is not None:
                hosts.append(host)
    hosts.sort(key=lambda h: ipaddress.ip_address(h.ip))
    return hosts


# --- Public entry point ---------------------------------------------------- #

def discover(
    network: str,
    *,
    timeout: float | None = None,
    iface: str | None = None,
    force_tcp: bool = False,
    max_workers: int = 100,
) -> DiscoveryReport:
    """Discover live hosts on ``network``, picking the method by privilege.

    Uses the reliable ARP sweep when privileged; otherwise degrades to the
    unprivileged TCP-ping sweep (rule #4). Set ``force_tcp=True`` to use the
    connect-based sweep even when privileged (useful for tests / comparison).
    """
    if discovery_available() and not force_tcp:
        hosts = arp_sweep(network, timeout=timeout or 2.0, iface=iface)
        return DiscoveryReport(network=network, method="arp-sweep", hosts=hosts)
    hosts = tcp_ping_sweep(
        network, timeout=timeout or 0.5, max_workers=max_workers
    )
    return DiscoveryReport(network=network, method="tcp-ping", hosts=hosts)
