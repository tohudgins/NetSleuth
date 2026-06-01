"""OPTIONAL validation: diff NetSleuth's scan against the real nmap binary.

This is the *encouraged exception* in CLAUDE.md rule #1 — we never use nmap for
core functionality, but comparing against it proves our handshake logic is
correct. The whole module skips cleanly if nmap isn't installed, so it never
becomes a hidden dependency.
"""

from __future__ import annotations

import shutil

import pytest

if shutil.which("nmap") is None:
    pytest.skip("nmap binary not installed — parity check skipped",
                allow_module_level=True)

# Parity comparison lands alongside a richer scanner; placeholder for now.
