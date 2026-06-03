"""Unit tests for the run-diff engine. Pure dicts, no DB/scapy."""

from __future__ import annotations

from netsleuth.diff import diff_discovery, diff_run, diff_scan, to_dict


def _scan(target, ports):
    """ports: list of (num, state, service, banner)."""
    return {"scan": {"target": target, "os_family_guess": None,
                     "ports": [{"port": n, "state": s, "service_hint": sv, "banner": b}
                               for n, s, sv, b in ports]}}


def _disc(network, hosts):
    """hosts: list of (ip, mac, vendor, open_ports)."""
    return {"discovery": {"network": network,
                          "hosts": [{"ip": ip, "mac": m, "vendor": v, "open_ports": op}
                                    for ip, m, v, op in hosts]}}


# --- scan diffs ------------------------------------------------------------ #

def test_scan_port_opened_and_closed():
    old = _scan("h", [(22, "open", "ssh", None), (80, "closed", None, None)])
    new = _scan("h", [(22, "closed", None, None), (80, "open", "http", None)])
    d = diff_scan(old, new)
    assert d.ports_opened == [80]
    assert d.ports_closed == [22]
    assert not d.empty


def test_scan_service_and_banner_change():
    old = _scan("h", [(80, "open", "http", "nginx/1.0")])
    new = _scan("h", [(80, "open", "http-alt", "nginx/1.2")])
    d = diff_scan(old, new)
    assert d.ports_opened == [] and d.ports_closed == []
    assert d.service_changed == [{"port": 80, "from": "http", "to": "http-alt"}]
    assert d.banner_changed == [80]


def test_scan_os_change():
    old = {"scan": {"target": "h", "os_family_guess": "Linux", "ports": []}}
    new = {"scan": {"target": "h", "os_family_guess": "Windows", "ports": []}}
    d = diff_scan(old, new)
    assert d.os_changed == {"from": "Linux", "to": "Windows"}


def test_identical_scan_is_empty():
    rep = _scan("h", [(22, "open", "ssh", "x")])
    assert diff_scan(rep, rep).empty


# --- discovery diffs ------------------------------------------------------- #

def test_discovery_host_added_and_removed():
    old = _disc("n", [("10.0.0.1", "aa:aa:aa:aa:aa:aa", None, [])])
    new = _disc("n", [("10.0.0.2", "bb:bb:bb:bb:bb:bb", None, [])])
    d = diff_discovery(old, new)
    assert [h["ip"] for h in d.hosts_added] == ["10.0.0.2"]
    assert [h["ip"] for h in d.hosts_removed] == ["10.0.0.1"]


def test_discovery_mac_change_is_flagged():
    old = _disc("n", [("10.0.0.1", "aa:aa:aa:aa:aa:aa", "Cisco", [])])
    new = _disc("n", [("10.0.0.1", "bb:bb:bb:bb:bb:bb", "Cisco", [])])
    d = diff_discovery(old, new)
    assert d.mac_changed == [{"ip": "10.0.0.1", "from": "aa:aa:aa:aa:aa:aa",
                              "to": "bb:bb:bb:bb:bb:bb"}]
    assert d.hosts_added == [] and d.hosts_removed == []


def test_discovery_vendor_and_ports_change():
    old = _disc("n", [("10.0.0.1", "aa:aa:aa:aa:aa:aa", "Cisco", [80])])
    new = _disc("n", [("10.0.0.1", "aa:aa:aa:aa:aa:aa", "Netgear", [80, 443])])
    d = diff_discovery(old, new)
    assert d.vendor_changed[0]["to"] == "Netgear"
    assert d.ports_changed[0]["to"] == [80, 443]


def test_identical_discovery_is_empty():
    rep = _disc("n", [("10.0.0.1", "aa:aa:aa:aa:aa:aa", "Cisco", [80])])
    assert diff_discovery(rep, rep).empty


# --- dispatcher + serialisation -------------------------------------------- #

def test_diff_run_dispatch_and_to_dict():
    old = _scan("h", [(22, "open", "ssh", None)])
    new = _scan("h", [(22, "open", "ssh", None), (80, "open", "http", None)])
    d = diff_run("scan", old, new)
    payload = to_dict(d)
    assert payload["kind"] == "scan"
    assert payload["ports_opened"] == [80]
    assert payload["empty"] is False
    assert diff_run("capture", old, new) is None
