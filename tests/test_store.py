"""Unit tests for the SQLite run history. Uses a temp-file DB, no network."""

from __future__ import annotations

from netsleuth.store import (
    connect,
    get_run,
    list_runs,
    previous_run,
    save_run,
)


def _report(target: str, ts: str, open_ports=None) -> dict:
    return {
        "tool": "NetSleuth", "generated_at": ts, "authorized_use_only": True,
        "scan": {"target": target, "scan_type": "connect", "proto": "tcp",
                 "os_family_guess": None, "open_ports": open_ports or [],
                 "ports": [{"port": p, "proto": "tcp", "state": "open",
                            "service_hint": None, "banner": None, "cves": []}
                           for p in (open_ports or [])]},
    }


def test_save_and_get_roundtrip(tmp_path):
    conn = connect(tmp_path / "h.db")
    rid = save_run(conn, "scan", "127.0.0.1", _report("127.0.0.1", "2026-01-01T00:00:00+00:00", [80]))
    assert rid > 0
    got = get_run(conn, rid)
    assert got is not None
    assert got["scan"]["open_ports"] == [80]
    assert got["_run_id"] == rid
    assert got["_created_at"] == "2026-01-01T00:00:00+00:00"


def test_previous_run_returns_prior_not_self(tmp_path):
    conn = connect(tmp_path / "h.db")
    r1 = save_run(conn, "scan", "127.0.0.1", _report("127.0.0.1", "2026-01-01T00:00:00+00:00", [80]))
    r2 = save_run(conn, "scan", "127.0.0.1", _report("127.0.0.1", "2026-01-02T00:00:00+00:00", [80, 443]))
    # The run before r2 is r1, not r2 itself.
    prev = previous_run(conn, "scan", "127.0.0.1", before_id=r2)
    assert prev is not None
    assert prev["_run_id"] == r1
    assert prev["scan"]["open_ports"] == [80]


def test_previous_run_none_when_no_history(tmp_path):
    conn = connect(tmp_path / "h.db")
    assert previous_run(conn, "scan", "10.0.0.1") is None


def test_previous_run_scoped_by_kind_and_target(tmp_path):
    conn = connect(tmp_path / "h.db")
    save_run(conn, "scan", "127.0.0.1", _report("127.0.0.1", "2026-01-01T00:00:00+00:00", [80]))
    # Different target → no prior run for this one.
    assert previous_run(conn, "scan", "10.0.0.9") is None
    # Different kind → no prior run either.
    assert previous_run(conn, "discovery", "127.0.0.1") is None


def test_list_runs_newest_first_and_filtered(tmp_path):
    conn = connect(tmp_path / "h.db")
    save_run(conn, "scan", "a", _report("a", "2026-01-01T00:00:00+00:00"))
    save_run(conn, "scan", "b", _report("b", "2026-01-03T00:00:00+00:00"))
    save_run(conn, "discovery", "net", {"generated_at": "2026-01-02T00:00:00+00:00",
                                        "discovery": {"network": "net", "method": "arp-sweep",
                                                      "count": 0, "hosts": []}})
    rows = list_runs(conn)
    assert [r["target"] for r in rows] == ["b", "net", "a"]  # by created_at desc
    scans = list_runs(conn, kind="scan")
    assert {r["kind"] for r in scans} == {"scan"}


def test_connect_creates_parent_dir(tmp_path):
    nested = tmp_path / "deep" / "nested" / "h.db"
    conn = connect(nested)
    assert nested.exists()
    conn.close()
