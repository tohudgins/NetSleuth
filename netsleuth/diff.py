"""NetSleuth run diffing — "what changed since last time?".

Compares two ``reporter.build_report()`` dicts (typically the latest two stored
runs for the same target, from ``store.py``) and reports the meaningful deltas:
newly-open / newly-closed ports, hosts that appeared or vanished, and — most
security-relevant — an IP whose MAC moved between sweeps, which is exactly the
ARP-poisoning signal the live defense module hunts for.

Pure functions over plain dicts: no DB, no scapy, fully unit-testable. Diffs are
serialisable with ``to_dict`` for the JSON/HTML report and the web History tab.

Caveat (surfaced in --help/README): a scan diff is only meaningful when the two
runs covered the *same ports* — a port absent from one run can't be told apart
from a closed one, so re-run the same target + port spec to compare like-for-like.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

_OPEN_STATES = {"open", "open|filtered"}


@dataclass
class ScanDiff:
    target: str
    ports_opened: list[int] = field(default_factory=list)
    ports_closed: list[int] = field(default_factory=list)
    service_changed: list[dict[str, Any]] = field(default_factory=list)
    banner_changed: list[int] = field(default_factory=list)
    os_changed: dict[str, Any] | None = None

    @property
    def empty(self) -> bool:
        return not (self.ports_opened or self.ports_closed or self.service_changed
                    or self.banner_changed or self.os_changed)


@dataclass
class DiscoveryDiff:
    network: str
    hosts_added: list[dict[str, Any]] = field(default_factory=list)
    hosts_removed: list[dict[str, Any]] = field(default_factory=list)
    mac_changed: list[dict[str, Any]] = field(default_factory=list)
    vendor_changed: list[dict[str, Any]] = field(default_factory=list)
    ports_changed: list[dict[str, Any]] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.hosts_added or self.hosts_removed or self.mac_changed
                    or self.vendor_changed or self.ports_changed)


def _ports_by_num(report: dict[str, Any]) -> dict[int, dict[str, Any]]:
    scan = report.get("scan") or {}
    return {int(p["port"]): p for p in scan.get("ports", [])}


def diff_scan(old: dict[str, Any], new: dict[str, Any]) -> ScanDiff:
    """Delta between two scans of the same target."""
    target = str((new.get("scan") or {}).get("target", ""))
    old_ports = _ports_by_num(old)
    new_ports = _ports_by_num(new)

    def is_open(p: dict[str, Any] | None) -> bool:
        return p is not None and p.get("state") in _OPEN_STATES

    diff = ScanDiff(target=target)
    for num in sorted(set(old_ports) | set(new_ports)):
        o, n = old_ports.get(num), new_ports.get(num)
        if is_open(n) and not is_open(o):
            diff.ports_opened.append(num)
        elif is_open(o) and not is_open(n):
            diff.ports_closed.append(num)
        if is_open(o) and is_open(n):  # compare details only for still-open ports
            assert o is not None and n is not None
            if o.get("service_hint") != n.get("service_hint"):
                diff.service_changed.append(
                    {"port": num, "from": o.get("service_hint"),
                     "to": n.get("service_hint")})
            if (o.get("banner") or "") != (n.get("banner") or ""):
                diff.banner_changed.append(num)

    old_os = (old.get("scan") or {}).get("os_family_guess")
    new_os = (new.get("scan") or {}).get("os_family_guess")
    if old_os != new_os:
        diff.os_changed = {"from": old_os, "to": new_os}
    return diff


def _hosts_by_ip(report: dict[str, Any]) -> dict[str, dict[str, Any]]:
    disc = report.get("discovery") or {}
    return {str(h["ip"]): h for h in disc.get("hosts", [])}


def diff_discovery(old: dict[str, Any], new: dict[str, Any]) -> DiscoveryDiff:
    """Delta between two discovery sweeps of the same network."""
    network = str((new.get("discovery") or {}).get("network", ""))
    old_hosts = _hosts_by_ip(old)
    new_hosts = _hosts_by_ip(new)

    diff = DiscoveryDiff(network=network)
    for ip in sorted(set(new_hosts) - set(old_hosts)):
        diff.hosts_added.append(new_hosts[ip])
    for ip in sorted(set(old_hosts) - set(new_hosts)):
        diff.hosts_removed.append(old_hosts[ip])

    for ip in sorted(set(old_hosts) & set(new_hosts)):
        o, n = old_hosts[ip], new_hosts[ip]
        if o.get("mac") and n.get("mac") and o["mac"] != n["mac"]:
            diff.mac_changed.append(
                {"ip": ip, "from": o["mac"], "to": n["mac"]})
        if o.get("vendor") != n.get("vendor"):
            diff.vendor_changed.append(
                {"ip": ip, "from": o.get("vendor"), "to": n.get("vendor")})
        if sorted(o.get("open_ports") or []) != sorted(n.get("open_ports") or []):
            diff.ports_changed.append(
                {"ip": ip, "from": o.get("open_ports") or [],
                 "to": n.get("open_ports") or []})
    return diff


def diff_run(
    kind: str, old: dict[str, Any], new: dict[str, Any]
) -> ScanDiff | DiscoveryDiff | None:
    """Dispatch to the right diff for ``kind`` ('scan' | 'discovery')."""
    if kind == "scan":
        return diff_scan(old, new)
    if kind == "discovery":
        return diff_discovery(old, new)
    return None


def to_dict(diff: ScanDiff | DiscoveryDiff) -> dict[str, Any]:
    """Serialise a diff for JSON / the web History tab, tagging its kind."""
    payload = asdict(diff)
    payload["kind"] = "scan" if isinstance(diff, ScanDiff) else "discovery"
    payload["empty"] = diff.empty
    return payload
