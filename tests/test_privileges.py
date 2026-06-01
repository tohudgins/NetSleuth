"""Unit tests for privilege detection messaging."""

from __future__ import annotations

import netsleuth.privileges as priv


def test_privilege_notice_privileged(monkeypatch):
    monkeypatch.setattr(priv, "is_privileged", lambda: True)
    notice = priv.privilege_notice()
    assert notice.startswith("Privileged")
    # Mode-neutral: must not claim a specific scan fallback.
    assert "connect scan" not in notice


def test_privilege_notice_unprivileged(monkeypatch):
    monkeypatch.setattr(priv, "is_privileged", lambda: False)
    notice = priv.privilege_notice()
    assert notice.startswith("Unprivileged")
    assert "sudo" in notice and "Administrator" in notice
