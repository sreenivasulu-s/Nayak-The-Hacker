"""Deterministic verification gate. Scanner output alone is never a finding."""

from backend.npt_v7.evidence import evidence_sufficient


def verify_candidate(candidate: dict, evidence: list[dict], corroborating: list[dict] | None = None) -> dict:
    if not evidence_sufficient(evidence):
        return {"status": "REJECTED", "confidence": 0.0, "reason": "No sufficient evidence"}
    corroborating = corroborating or []
    confidence = 0.70 if corroborating else 0.55
    if candidate.get("severity") in {"critical", "high"} and not corroborating:
        return {"status": "UNCERTAIN", "confidence": confidence, "reason": "High-impact candidate requires corroboration or human review"}
    return {"status": "VERIFIED", "confidence": confidence, "reason": "Evidence is present and verification rules passed"}
