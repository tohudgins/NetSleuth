"""Privilege detection and graceful degradation.

Raw sockets, SYN scans, and packet capture require root (Linux/macOS) or
Administrator (Windows). This module lets the rest of the tool detect that
*once*, warn clearly, and fall back to unprivileged techniques instead of
crashing with a bare PermissionError.
"""

from __future__ import annotations

import ctypes
import os
import sys


def is_privileged() -> bool:
    """Return True if the process can open raw sockets.

    On POSIX this means effective UID 0. On Windows it means the process is
    running with an elevated (Administrator) token.
    """
    if sys.platform == "win32":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    # POSIX: geteuid() == 0 means root.
    return hasattr(os, "geteuid") and os.geteuid() == 0


def can_raw_socket() -> bool:
    """Alias kept for readability at call sites that gate raw-socket features."""
    return is_privileged()


def privilege_notice() -> str:
    """Human-readable line describing the current capability level.

    Used by the CLI/UI so the user always knows which scan mode is active.
    """
    if is_privileged():
        return "Privileged: SYN scan and raw packet capture available."
    return (
        "Unprivileged: falling back to TCP connect scan; raw capture disabled. "
        "Re-run with sudo (Linux/macOS) or as Administrator (Windows) for full features."
    )
