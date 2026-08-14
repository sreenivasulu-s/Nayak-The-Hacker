from __future__ import annotations

import json
import os


def analyze_findings(target: str, findings: list[dict]) -> dict:
    """Use OpenAI Responses API when configured; otherwise return a deterministic local summary."""
    if not findings:
        return {
            "status": "completed",
            "provider": "local",
            "summary": "No normalized findings were produced by the configured scanners.",
            "priorities": [],
        }

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return _local_summary(findings)

    try:
        from openai import OpenAI

        client = OpenAI(api_key=api_key)
        model = os.getenv("OPENAI_MODEL", "gpt-5")
        payload = json.dumps({"target": target, "findings": findings}, ensure_ascii=False)
        response = client.responses.create(
            model=model,
            input=(
                "You are a defensive VAPT analyst. Analyze only the supplied scan evidence. "
                "Do not invent vulnerabilities. Correlate duplicates, identify likely false positives, "
                "rank remediation priorities, and explain evidence. Target authorization is assumed "
                "to have been confirmed by the scanner before execution. Return concise technical findings.\n\n"
                + payload
            ),
        )
        return {
            "status": "completed",
            "provider": "openai",
            "model": model,
            "summary": response.output_text,
        }
    except Exception as exc:
        fallback = _local_summary(findings)
        fallback["openai_error"] = str(exc)
        return fallback


def _local_summary(findings: list[dict]) -> dict:
    rank = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
    ordered = sorted(findings, key=lambda item: rank.get(item.get("severity", "info"), 1), reverse=True)
    priorities = [
        {
            "title": item.get("title"),
            "severity": item.get("severity"),
            "tool": item.get("tool"),
            "evidence": item.get("evidence"),
        }
        for item in ordered[:10]
    ]
    return {
        "status": "completed",
        "provider": "local",
        "summary": f"{len(findings)} normalized finding(s) were collected. Review the highest-severity evidence first.",
        "priorities": priorities,
    }
