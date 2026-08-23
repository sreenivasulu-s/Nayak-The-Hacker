"""Evidence-first records with content hashing and provenance."""

import hashlib
from datetime import datetime, timezone
from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    tool_run_id: str
    tool_name: str
    tool_version: str
    target: str
    timestamp: str
    sha256: str
    artifact_reference: str
    scope_version: str
    policy_version: str
    parser_version: str
    content: str


def make_evidence(evidence_id: str, tool_run_id: str, tool_name: str, tool_version: str, target: str, content: str, artifact_reference: str, scope_version: str = "1", policy_version: str = "1", parser_version: str = "1") -> dict:
    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    item = Evidence(
        evidence_id=evidence_id,
        tool_run_id=tool_run_id,
        tool_name=tool_name,
        tool_version=tool_version,
        target=target,
        timestamp=datetime.now(timezone.utc).isoformat(),
        sha256=digest,
        artifact_reference=artifact_reference,
        scope_version=scope_version,
        policy_version=policy_version,
        parser_version=parser_version,
        content=content,
    )
    return asdict(item)


def evidence_sufficient(evidence: list[dict]) -> bool:
    return bool(evidence) and all(item.get("sha256") and item.get("artifact_reference") for item in evidence)
