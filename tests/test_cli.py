"""Unit tests for CLI integration helpers — discovery↔defense wiring.

The network-touching pieces (ARP resolve, default route, subnet sweep) are
monkeypatched, so these stay hermetic.
"""

from __future__ import annotations

import argparse

from netsleuth import cli
from netsleuth.discovery import DiscoveryReport, Host


def _args(**kw) -> argparse.Namespace:
    base = {"gateway": None, "iface": None, "known_hosts": None}
    base.update(kw)
    return argparse.Namespace(**base)


# --- _known_hosts ---------------------------------------------------------- #

def test_known_hosts_explicit_list():
    assert cli._known_hosts(_args(known_hosts="10.0.0.1, 10.0.0.2 ,")) == {
        "10.0.0.1", "10.0.0.2",
    }


def test_known_hosts_none_when_unset():
    assert cli._known_hosts(_args()) is None


def test_known_hosts_auto_uses_discovery(monkeypatch):
    report = DiscoveryReport(network="10.0.0.0/24", method="arp-sweep",
                             hosts=[Host("10.0.0.1"), Host("10.0.0.2")])
    monkeypatch.setattr(cli, "default_gateway", lambda iface: "10.0.0.1")
    monkeypatch.setattr(cli, "discover", lambda network, iface=None: report)
    assert cli._known_hosts(_args(known_hosts="auto")) == {"10.0.0.1", "10.0.0.2"}


def test_known_hosts_auto_ignored_for_pcap(monkeypatch):
    # allow_auto=False (offline pcap) must not trigger a live sweep.
    called = {"n": 0}
    monkeypatch.setattr(cli, "_autodiscover_known_hosts",
                        lambda args: called.__setitem__("n", called["n"] + 1))
    assert cli._known_hosts(_args(known_hosts="auto"), allow_auto=False) is None
    assert called["n"] == 0


def test_known_hosts_auto_no_gateway_returns_none(monkeypatch):
    monkeypatch.setattr(cli, "default_gateway", lambda iface: None)
    assert cli._known_hosts(_args(known_hosts="auto")) is None


# --- _defense_setup -------------------------------------------------------- #

def test_defense_setup_pcap_marks_gateway_critical_without_baseline():
    baseline, config = cli._defense_setup(_args(gateway="10.0.0.1"), live=False)
    assert baseline is None  # offline: never ARP-resolve
    assert config.critical_ips == {"10.0.0.1"}


def test_defense_setup_live_learns_gateway_mac(monkeypatch):
    monkeypatch.setattr(cli, "discovery_available", lambda: True)
    monkeypatch.setattr(cli, "default_gateway", lambda iface: "10.0.0.1")
    monkeypatch.setattr(cli, "resolve_mac", lambda ip, iface=None: "aa:bb:cc:dd:ee:ff")
    baseline, config = cli._defense_setup(_args(), live=True)
    assert baseline == {"10.0.0.1": "aa:bb:cc:dd:ee:ff"}
    assert config.critical_ips == {"10.0.0.1"}


def test_defense_setup_live_unprivileged_no_baseline(monkeypatch):
    # Gateway still tagged critical, but no MAC learned without raw sockets.
    monkeypatch.setattr(cli, "discovery_available", lambda: False)
    monkeypatch.setattr(cli, "default_gateway", lambda iface: "10.0.0.1")
    baseline, config = cli._defense_setup(_args(), live=True)
    assert baseline is None
    assert config.critical_ips == {"10.0.0.1"}


def test_defense_setup_live_no_gateway(monkeypatch):
    monkeypatch.setattr(cli, "discovery_available", lambda: True)
    monkeypatch.setattr(cli, "default_gateway", lambda iface: None)
    baseline, config = cli._defense_setup(_args(), live=True)
    assert baseline is None
    assert config.critical_ips == set()


# --- parser smoke ---------------------------------------------------------- #

def test_parser_accepts_new_flags():
    args = cli.build_parser().parse_args(
        ["10.0.0.0/24", "--discover", "--gateway", "10.0.0.1",
         "--known-hosts", "auto"])
    assert args.gateway == "10.0.0.1"
    assert args.known_hosts == "auto"
    assert args.discover is True
