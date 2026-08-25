from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def write_report(run_summary: dict[str, Any], jobs: list[dict[str, Any]], path: str | None = None) -> str:
    """Write a self-contained JSON lab report with status and evidence."""
    output = path or f"lab-{run_summary['run_id']}.json"
    payload = {"report": "Nayak PortSwigger Lab Assessment", "run": run_summary, "jobs": jobs}
    Path(output).write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return output
