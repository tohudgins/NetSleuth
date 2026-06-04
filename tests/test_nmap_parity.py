"""OPTIONAL validation: diff NetSleuth's scan against the real nmap binary.

This is the *encouraged exception* in CLAUDE.md rule #1 — we never use nmap for
core functionality, but comparing against it proves our handshake logic is
correct. The whole module skips cleanly if nmap isn't installed, so it never
becomes a hidden dependency.

It's also a learning harness: it shells out to ``nmap -sT -oX`` (an unprivileged
connect scan, machine-readable XML output), parses the result, and asserts the
*real* tool and our raw-socket scanner agree on which ports are open. Reading
nmap's XML schema and `--reason` codes here is itself good nmap practice — see
docs/learning-with-netsleuth.md.
"""

from __future__ import annotations

import shutil
import socket
import subprocess
import xml.etree.ElementTree as ET

import pytest

from netsleuth.scanner import scan

if shutil.which("nmap") is None:
    pytest.skip("nmap binary not installed — parity check skipped",
                allow_module_level=True)


def _free_loopback_port() -> int:
    """Grab an ephemeral port, then release it so it's (almost certainly) closed."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _nmap_open_ports(target: str, ports: list[int]) -> set[int]:
    """Run an unprivileged nmap connect scan and parse open ports from its XML.

    ``-sT`` connect scan (no root), ``-oX -`` writes XML to stdout, ``-Pn`` skips
    host discovery (loopback is always up). Each open port appears as
    ``<port portid="N"><state state="open"/></port>``.
    """
    spec = ",".join(str(p) for p in ports)
    proc = subprocess.run(
        ["nmap", "-sT", "-Pn", "-oX", "-", "-p", spec, target],
        capture_output=True, text=True, timeout=60, check=True,
    )
    root = ET.fromstring(proc.stdout)
    open_ports: set[int] = set()
    for port_el in root.iterfind(".//port"):
        state = port_el.find("state")
        if state is not None and state.get("state") == "open":
            open_ports.add(int(port_el.get("portid", "0")))
    return open_ports


def test_nmap_parity_open_and_closed():
    """nmap and NetSleuth must agree on the open set for a known target."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    open_port = srv.getsockname()[1]
    closed_port = _free_loopback_port()
    ports = sorted({open_port, closed_port})
    try:
        nmap_open = _nmap_open_ports("127.0.0.1", ports)
        ours = scan("127.0.0.1", ports, force_connect=True, timeout=1.0)
        ours_open = set(ours.open_ports)

        # Both must see the listener as open…
        assert open_port in nmap_open
        assert open_port in ours_open
        # …and agree on the whole open set (so the closed one is closed in both).
        assert nmap_open == ours_open
    finally:
        srv.close()
