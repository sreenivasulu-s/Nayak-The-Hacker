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
                error TEXT
            )
            """
        )
        connection.commit()


def save_scan(scan: dict[str, Any]) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id,
                target,
                target_type,
                status,
                findings,
                error
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan["scan_id"],
                scan["target"],
                scan.get("target_type", "web"),
                scan["status"],
                json.dumps(scan.get("findings", [])),
                scan.get("error"),
            ),
        )
        connection.commit()


def load_scans() -> dict[str, dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT
                scan_id,
                target,
                target_type,
                status,
                findings,
                error
            FROM scans
            ORDER BY rowid ASC
            """
        ).fetchall()

    scans: dict[str, dict[str, Any]] = {}

    for row in rows:
        scans[row["scan_id"]] = {
            "scan_id": row["scan_id"],
            "target": row["target"],
            "target_type": row["target_type"],
            "status": row["status"],
            "findings": json.loads(row["findings"] or "[]"),
        }

        if row["error"]:
            scans[row["scan_id"]]["error"] = row["error"]

    return scans


def delete_all_scans() -> None:
    with get_connection() as connection:
        connection.execute("DELETE FROM scans")
        connection.commit()
