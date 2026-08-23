import json
import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path(__file__).resolve().parent.parent / "scanner.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                target_type TEXT NOT NULL,
                status TEXT NOT NULL,
                findings TEXT NOT NULL,
                error TEXT,
                authorized INTEGER NOT NULL DEFAULT 0,
                scope TEXT,
                tools TEXT NOT NULL DEFAULT '[]',
                evidence TEXT NOT NULL DEFAULT '{}',
                metadata TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        columns = {row[1] for row in connection.execute("PRAGMA table_info(scans)").fetchall()}
        migrations = {
            "authorized": "ALTER TABLE scans ADD COLUMN authorized INTEGER NOT NULL DEFAULT 0",
            "scope": "ALTER TABLE scans ADD COLUMN scope TEXT",
            "tools": "ALTER TABLE scans ADD COLUMN tools TEXT NOT NULL DEFAULT '[]'",
            "evidence": "ALTER TABLE scans ADD COLUMN evidence TEXT NOT NULL DEFAULT '{}'",
            "metadata": "ALTER TABLE scans ADD COLUMN metadata TEXT NOT NULL DEFAULT '{}'",
        }
        for name, statement in migrations.items():
            if name not in columns:
                connection.execute(statement)
        connection.commit()


def _metadata(scan: dict[str, Any]) -> dict[str, Any]:
    keys = (
        "category",
        "state",
        "state_history",
        "scope_version",
        "user_confirmation",
        "project_id",
        "user_id",
        "policy_profile",
        "authorization_gate",
    )
    return {key: scan[key] for key in keys if key in scan}


def save_scan(scan: dict[str, Any]) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id, target, target_type, status, findings, error,
                authorized, scope, tools, evidence, metadata
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan["scan_id"],
                scan["target"],
                scan.get("target_type", "web"),
                scan["status"],
                json.dumps(scan.get("findings", [])),
                scan.get("error"),
                1 if scan.get("authorized") else 0,
                scan.get("scope"),
                json.dumps(scan.get("tools", [])),
                json.dumps(scan.get("evidence", {})),
                json.dumps(_metadata(scan)),
            ),
        )
        connection.commit()


def load_scans() -> dict[str, dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT scan_id, target, target_type, status, findings, error,
                   authorized, scope, tools, evidence, metadata
            FROM scans ORDER BY rowid ASC
            """
        ).fetchall()

    scans: dict[str, dict[str, Any]] = {}
    for row in rows:
        metadata = json.loads(row["metadata"] or "{}")
        scans[row["scan_id"]] = {
            "scan_id": row["scan_id"],
            "target": row["target"],
            "target_type": row["target_type"],
            "status": row["status"],
            "findings": json.loads(row["findings"] or "[]"),
            "authorized": bool(row["authorized"]),
            "scope": row["scope"],
            "tools": json.loads(row["tools"] or "[]"),
            "evidence": json.loads(row["evidence"] or "{}"),
            **metadata,
        }
        if row["error"]:
            scans[row["scan_id"]]["error"] = row["error"]
    return scans


def delete_all_scans() -> None:
    with get_connection() as connection:
        connection.execute("DELETE FROM scans")
        connection.commit()
