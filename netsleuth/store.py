"""NetSleuth run history — local SQLite persistence.

Makes the tool *stateful*: scans and discoveries are point-in-time inventories,
so storing them lets NetSleuth answer "what changed on my network since last
time?" (see ``diff.py``). Persistence is explicit — only ``--save`` / ``--diff``
write here — and there are no new dependencies: stdlib ``sqlite3`` + ``json``.

We store the whole ``reporter.build_report()`` dict as JSON per run rather than
normalising it. That dict is already the stable schema shared by the CLI, web,
and report files, so the diff engine just deserialises two runs and compares —
no migrations, no schema drift between a run and its stored form.

A run is identified by ``(kind, target)``: kind is "scan" or "discovery", target
is the host or CIDR. The diff compares the latest two runs for that identity.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

DEFAULT_DB = Path.home() / ".netsleuth" / "history.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    kind         TEXT NOT NULL,          -- 'scan' | 'discovery'
    target       TEXT NOT NULL,          -- host or CIDR
    created_at   TEXT NOT NULL,          -- ISO-8601 UTC (sorts lexically)
    tool_version TEXT NOT NULL,
    report       TEXT NOT NULL           -- build_report() JSON
);
CREATE INDEX IF NOT EXISTS idx_runs_kind_target
    ON runs (kind, target, created_at);
"""


def connect(db_path: str | Path = DEFAULT_DB) -> sqlite3.Connection:
    """Open (creating if needed) the history DB and ensure the schema exists.

    Open a *fresh* connection per CLI invocation / web request — sqlite
    connection objects are not safe to share across threads.
    """
    path = Path(db_path)
    if path.parent and not path.parent.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    return conn


def save_run(
    conn: sqlite3.Connection, kind: str, target: str, report: dict[str, Any]
) -> int:
    """Persist one run's report; returns the new row id.

    ``created_at`` comes from the report's own ``generated_at`` when present so
    the stored timestamp matches the report, falling back to now().
    """
    created_at = str(report.get("generated_at") or _now_iso())
    cur = conn.execute(
        "INSERT INTO runs (kind, target, created_at, tool_version, report) "
        "VALUES (?, ?, ?, ?, ?)",
        (kind, target, created_at, __version__, json.dumps(report)),
    )
    conn.commit()
    return int(cur.lastrowid or 0)


def previous_run(
    conn: sqlite3.Connection,
    kind: str,
    target: str,
    *,
    before_id: int | None = None,
) -> dict[str, Any] | None:
    """Most recent stored run for ``(kind, target)``, parsed back to a report dict.

    Pass ``before_id`` to exclude a run you just saved (so ``--diff`` compares
    against the prior run, not itself). Returns None when there is no history.
    """
    sql = "SELECT * FROM runs WHERE kind = ? AND target = ?"
    params: list[Any] = [kind, target]
    if before_id is not None:
        sql += " AND id < ?"
        params.append(before_id)
    sql += " ORDER BY created_at DESC, id DESC LIMIT 1"
    row = conn.execute(sql, params).fetchone()
    return _row_to_report(row) if row is not None else None


def list_runs(
    conn: sqlite3.Connection,
    *,
    kind: str | None = None,
    target: str | None = None,
    limit: int = 50,
) -> list[sqlite3.Row]:
    """List stored runs (newest first), optionally filtered by kind/target."""
    sql = "SELECT id, kind, target, created_at, tool_version FROM runs"
    clauses: list[str] = []
    params: list[Any] = []
    if kind:
        clauses.append("kind = ?")
        params.append(kind)
    if target:
        clauses.append("target = ?")
        params.append(target)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY created_at DESC, id DESC LIMIT ?"
    params.append(limit)
    return list(conn.execute(sql, params).fetchall())


def get_run(conn: sqlite3.Connection, run_id: int) -> dict[str, Any] | None:
    """Fetch one run's full report by id (parsed), or None if absent."""
    row = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
    return _row_to_report(row) if row is not None else None


def _row_to_report(row: sqlite3.Row) -> dict[str, Any]:
    report: dict[str, Any] = json.loads(row["report"])
    # Attach the storage metadata under reserved keys the rest of the app reads.
    report["_run_id"] = row["id"]
    report["_created_at"] = row["created_at"]
    return report


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
