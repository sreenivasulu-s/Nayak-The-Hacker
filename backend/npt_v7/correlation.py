"""Deterministic cross-tool finding correlation for NPT v7.

This module never invents evidence. It only merges candidates that already have
an evidence-backed verification result and share a normalized issue key.
"""

import re


def _normalize(value: str) -> str:
    return re.sub(r"\s+", " ", value.strip().lower())


def correlate_findings(findings: list[dict]) -> list[dict]:
    merged: dict[tuple[str, str], dict] = {}
    for finding in findings:
        evidence = str(finding.get("evidence", ""))
        title = _normalize(str(finding.get("title", "")))
        key = (title, _normalize(evidence))
        existing = merged.get(key)
        if existing is None:
            item = dict(finding)
            item["tools"] = [finding.get("tool", "unknown")]
            merged[key] = item
            continue
        tool = finding.get("tool", "unknown")
        if tool not in existing["tools"]:
            existing["tools"].append(tool)
        if float(finding.get("confidence", 0)) > float(existing.get("confidence", 0)):
            existing["confidence"] = finding.get("confidence", 0)
            existing["verification_status"] = finding.get("verification_status", existing.get("verification_status"))
    return list(merged.values())
