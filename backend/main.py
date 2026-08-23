import os
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, model_validator

from backend.db import init_db, load_scans, save_scan
from backend.npt_v7.catalog import TOOLS, assessment_catalog
from backend.npt_v7.control_plane import Authorization, PolicyProfile, authorize
from backend.npt_v7.correlation import correlate_findings
from backend.npt_v7.evidence import make_evidence
from backend.npt_v7.state_machine import State, transition
from backend.npt_v7.verification import verify_candidate
from backend.scanner.tool_runner import execute_tools

app = FastAPI(title="Nayak Pen Testing Tool", version="7.0.0")


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ORIGINS", "").strip()
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
)


class ScanRequest(BaseModel):
    category: str = "network"
    target: str
    scope: str
    tools: list[str] | None = None
    authorized: bool = False
    user_confirmation: bool = False
    project_id: str | None = None
    user_id: str | None = None
    policy_profile: str = "default-read-only"

    @field_validator("target", "scope")
    @classmethod
    def clean_text(cls, value: str) -> str:
        value = value.strip().strip("`").strip()
        if not value:
            raise ValueError("Target and scope are required")
        return value

    @field_validator("category")
    @classmethod
    def clean_category(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("tools")
    @classmethod
    def clean_tools(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return list(dict.fromkeys(item.strip().lower() for item in value if item.strip()))

    @model_validator(mode="after")
    def validate_confirmation(self):
        if not self.authorized:
            raise ValueError("Explicit authorization is required before a scan can start")
        if not self.user_confirmation:
            raise ValueError("User confirmation is required before tool execution")
        return self


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: str
    tool: str
    verification_status: str = "UNCERTAIN"
    confidence: float = 0.0


init_db()
scans: dict[str, dict] = load_scans()


def _set_state(scan: dict, next_state: State, *, status: str | None = None) -> None:
    current = State(scan["state"])
    if current != next_state:
        scan["state"] = transition(current, next_state)
    if status is not None:
        scan["status"] = status
    scan.setdefault("state_history", []).append(scan["state"])
    save_scan(scan)


async def run_scan(scan_id: str):
    scan = scans[scan_id]
    try:
        _set_state(scan, State.AUTHORIZATION_CHECK)
        gate = authorize(
            scan["category"],
            scan["target"],
            Authorization(scan["authorized"], scan["scope"], scan.get("project_id"), scan.get("user_id")),
            scan["tools"],
            PolicyProfile(name=scan.get("policy_profile", "default-read-only")),
        )
        scan["authorization_gate"] = gate
        _set_state(scan, State.SCOPE_VALIDATION)
        _set_state(scan, State.POLICY_VALIDATION)
        _set_state(scan, State.PLANNING)
        _set_state(scan, State.QUEUED, status="queued")
        _set_state(scan, State.RUNNING, status="running")

        findings, evidence_summary = await execute_tools(scan["target"], scan["scope"], scan["tools"])

        scan["evidence"] = {}
        scan["findings"] = []
        _set_state(scan, State.EVIDENCE_COLLECTION)
        for tool, summary in evidence_summary.items():
            evidence_id = f"evidence_{uuid4().hex}"
            tool_run_id = f"toolrun_{uuid4().hex}"
            raw = summary.get("raw_output", "")
            scan["evidence"][tool] = make_evidence(
                evidence_id,
                tool_run_id,
                tool,
                summary.get("tool_version", "detected-at-worker-runtime"),
                scan["target"],
                raw,
                f"memory://{tool_run_id}",
                scope_version=scan.get("scope_version", "1"),
                policy_version=scan.get("policy_profile", "default-read-only"),
            )
        save_scan(scan)

        _set_state(scan, State.VERIFICATION)
        verified_candidates = []
        for candidate in findings:
            tool = candidate.get("tool", "unknown")
            evidence = [scan["evidence"][tool]] if tool in scan["evidence"] else []
            result = verify_candidate(candidate, evidence)
            candidate["verification_status"] = result["status"]
            candidate["confidence"] = result["confidence"]
            if result["status"] != "REJECTED":
                verified_candidates.append(Finding(**candidate).model_dump())

        scan["findings"] = correlate_findings(verified_candidates)
        if any(item.get("verification_status") == "VERIFIED" for item in scan["findings"]):
            _set_state(scan, State.VERIFIED)
            _set_state(scan, State.FALSE_POSITIVE_GATE)
        else:
            _set_state(scan, State.UNCERTAIN)
        _set_state(scan, State.AI_ANALYSIS)
        _set_state(scan, State.CORRELATION)
        _set_state(scan, State.FINDING)
        _set_state(scan, State.REPORT)
        _set_state(scan, State.COMPLETE, status="completed")
        scan.pop("error", None)
    except PermissionError as exc:
        scan["error"] = str(exc)
        if scan.get("state") in {State.AUTHORIZATION_CHECK, State.SCOPE_VALIDATION, State.POLICY_VALIDATION, State.PLANNING}:
            try:
                _set_state(scan, State.REJECTED, status="rejected")
            except ValueError:
                scan["status"] = "rejected"
                scan["state"] = State.REJECTED
                save_scan(scan)
        else:
            scan["status"] = "failed"
            scan["state"] = State.ERROR
            save_scan(scan)
    except Exception as exc:
        scan["status"] = "failed"
        scan["state"] = State.ERROR
        scan["error"] = str(exc)
        save_scan(scan)


@app.get("/")
def home():
    return {
        "status": "ok",
        "message": "Nayak Pen Testing Tool API is running",
        "version": "7.0.0",
        "execution_mode": "real-bounded",
        "architecture": "NPT v7.0",
        "assessment_categories": 13,
    }


@app.get("/assessment-categories")
def get_assessment_categories():
    return {"version": "7.0.0", "categories": assessment_catalog()}


@app.get("/tools")
def get_tools():
    return {
        "tools": [
            {
                "name": spec.name,
                "capability": spec.capability,
                "execution_class": spec.execution_class,
                "enabled": spec.enabled,
            }
            for spec in TOOLS.values()
        ],
        "note": "Only enabled read-only tools permitted by category and policy can execute.",
    }


@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        gate = authorize(
            request.category,
            request.target,
            Authorization(request.authorized, request.scope, request.project_id, request.user_id),
            request.tools or [],
            PolicyProfile(name=request.policy_profile),
        )
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc

    scan_id = str(uuid4())
    scans[scan_id] = {
        "scan_id": scan_id,
        "category": request.category,
        "target": request.target,
        "scope": request.scope,
        "authorized": request.authorized,
        "user_confirmation": request.user_confirmation,
        "project_id": request.project_id,
        "user_id": request.user_id,
        "policy_profile": request.policy_profile,
        "scope_version": "1",
        "tools": gate["plan"]["planned_tools"],
        "target_type": "web" if request.target.startswith(("http://", "https://")) else "network",
        "status": "created",
        "state": State.CREATED,
        "state_history": [State.CREATED],
        "findings": [],
        "evidence": {},
        "authorization_gate": gate,
    }
    save_scan(scans[scan_id])
    background_tasks.add_task(run_scan, scan_id)
    return scans[scan_id]


@app.get("/scans")
def get_scans():
    return [
        {
            "scan_id": s["scan_id"],
            "category": s.get("category"),
            "target": s["target"],
            "scope": s.get("scope"),
            "tools": s.get("tools", []),
            "status": s["status"],
            "state": s.get("state"),
            "findings_count": len(s["findings"]),
        }
        for s in reversed(list(scans.values()))
    ]


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@app.get("/scan/{scan_id}/findings")
def get_findings(scan_id: str, severity: str | None = Query(default=None)):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = scan["findings"] if not severity else [f for f in scan["findings"] if f["severity"] == severity]
    return {"scan_id": scan_id, "count": len(findings), "findings": findings}


@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    counts = {
        level: sum(1 for f in scan["findings"] if f.get("severity") == level)
        for level in ("critical", "high", "medium", "low", "info")
    }
    report = {
        "report": "Nayak Pen Testing Tool Assessment Report",
        "architecture": "NPT v7.0",
        "scan_id": scan["scan_id"],
        "category": scan.get("category"),
        "target": scan["target"],
        "scope": scan["scope"],
        "authorized": scan["authorized"],
        "policy": scan.get("authorization_gate", {}).get("policy"),
        "tools": scan["tools"],
        "status": scan["status"],
        "state": scan.get("state"),
        "state_history": scan.get("state_history", []),
        "summary": {"total_findings": len(scan["findings"]), **counts},
        "findings": scan["findings"],
        "evidence": scan.get("evidence", {}),
    }
    return JSONResponse(
        content=report,
        headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'},
    )
