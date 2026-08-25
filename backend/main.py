import os
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator

from backend.db import init_db, load_scans, save_scan
from backend.npt_v7.catalog import assessment_catalog
from backend.npt_v7.control_plane import Authorization, PolicyProfile, authorize
from backend.npt_v7.evidence import make_evidence
from backend.npt_v7.state_machine import State
from backend.npt_v7.verification import verify_candidate
from backend.scanner.tool_runner import execute_tools
from backend.npt_v7.lab_solver.models import LabJob, LabState
from backend.npt_v7.lab_solver.orchestrator import build_lab_plan, validate_lab_url

app = FastAPI(title="Nayak Pen Testing Tool", version="7.1.0")


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ORIGINS", "").strip()
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"]


app.add_middleware(CORSMiddleware, allow_origins=_cors_origins(), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


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
        if not value: raise ValueError("Target and scope are required")
        return value

    @field_validator("category")
    @classmethod
    def clean_category(cls, value: str) -> str: return value.strip().lower()

    @model_validator(mode="after")
    def validate_confirmation(self):
        if not self.authorized: raise ValueError("Explicit authorization is required before a scan can start")
        if not self.user_confirmation: raise ValueError("User confirmation is required before tool execution")
        return self


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: str
    tool: str
    verification_status: str = "UNCERTAIN"
    confidence: float = 0.0


class LabRequest(BaseModel):
    url: str
    authorized: bool = True
    user_confirmation: bool = True

    @field_validator("url")
    @classmethod
    def clean_url(cls, value: str) -> str:
        value = value.strip().strip("`").strip()
        validate_lab_url(value)
        return value

    @model_validator(mode="after")
    def validate_confirmation(self):
        if not self.authorized or not self.user_confirmation:
            raise ValueError("PortSwigger lab authorization and confirmation are required")
        return self


init_db()
scans: dict[str, dict] = load_scans()
lab_jobs: dict[str, LabJob] = {}


async def run_scan(scan_id: str):
    scan = scans[scan_id]
    try:
        scan["state"] = State.AUTHORIZATION_CHECK; save_scan(scan)
        gate = authorize(scan["category"], scan["target"], Authorization(scan["authorized"], scan["scope"], scan.get("project_id"), scan.get("user_id")), scan["tools"], PolicyProfile(name=scan.get("policy_profile", "default-read-only")))
        scan["authorization_gate"] = gate; scan["state"] = State.QUEUED; scan["status"] = "queued"; save_scan(scan)
        scan["state"] = State.RUNNING; scan["status"] = "running"; save_scan(scan)
        findings, evidence_summary = await execute_tools(scan["target"], scan["scope"], scan["tools"])
        scan["state"] = State.EVIDENCE_COLLECTION; scan["evidence"] = {}; scan["findings"] = []
        for tool, summary in evidence_summary.items():
            evidence_id, tool_run_id = f"evidence_{uuid4().hex}", f"toolrun_{uuid4().hex}"
            raw = summary.get("raw_output", "")
            scan["evidence"][tool] = make_evidence(evidence_id, tool_run_id, tool, "detected-at-worker-runtime", scan["target"], raw, f"memory://{tool_run_id}")
        scan["state"] = State.VERIFICATION
        for candidate in findings:
            tool = candidate.get("tool", "unknown")
            result = verify_candidate(candidate, [scan["evidence"][tool]] if tool in scan["evidence"] else [])
            candidate["verification_status"], candidate["confidence"] = result["status"], result["confidence"]
            if result["status"] != "REJECTED": scan["findings"].append(Finding(**candidate).model_dump())
        scan["state"] = State.CORRELATION; scan["state"] = State.FINDING; scan["status"] = "completed"; scan["state"] = State.REPORT; scan["state"] = State.COMPLETE
    except Exception as exc:
        scan["status"] = "failed"; scan["state"] = State.ERROR; scan["error"] = str(exc)
    save_scan(scan)


def lab_report(job: LabJob) -> dict:
    return {
        "report": "Nayak Pen Testing Tool — PortSwigger Lab Report",
        "job_id": job.job_id,
        "lab_url": job.lab_url,
        "lab_host": job.lab_host,
        "lab_name": job.lab_name,
        "status": job.result,
        "state": job.state,
        "hypothesis": job.hypothesis,
        "events": job.events,
        "evidence": job.evidence,
        "error": job.error,
    }


@app.get("/")
def home(): return {"status": "ok", "message": "Nayak Pen Testing Tool API is running", "version": "7.1.0", "execution_mode": "real", "architecture": "NPT v7.1", "assessment_categories": 13, "portswigger_lab_solver": True}

@app.get("/assessment-categories")
def get_assessment_categories(): return {"version": "7.1.0", "categories": assessment_catalog()}

@app.get("/tools")
def get_tools(): return {"tools": ["nmap", "gobuster", "nikto", "nuclei"], "note": "Only tools enabled by category and policy can execute"}

@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        gate = authorize(request.category, request.target, Authorization(request.authorized, request.scope, request.project_id, request.user_id), request.tools or [], PolicyProfile(name=request.policy_profile))
    except (ValueError, PermissionError) as exc: raise HTTPException(status_code=403, detail=str(exc)) from exc
    scan_id = str(uuid4())
    scans[scan_id] = {"scan_id": scan_id, "category": request.category, "target": request.target, "scope": request.scope, "authorized": request.authorized, "user_confirmation": request.user_confirmation, "project_id": request.project_id, "user_id": request.user_id, "policy_profile": request.policy_profile, "tools": gate["plan"]["planned_tools"], "target_type": "web" if request.target.startswith(("http://", "https://")) else "network", "status": "created", "state": State.CREATED, "findings": [], "evidence": {}, "authorization_gate": gate}
    save_scan(scans[scan_id]); background_tasks.add_task(run_scan, scan_id); return scans[scan_id]

@app.post("/lab")
def start_lab(request: LabRequest):
    job_id = str(uuid4())
    job = LabJob(job_id=job_id, lab_url=request.url, state=LabState.VALIDATING)
    try:
        plan = build_lab_plan(job)
        job.state = LabState.DISCOVERING
        job.event("job_created", job_id=job_id)
        job.event("plan_created", plan=plan)
        job.state = LabState.PLANNING
        lab_jobs[job_id] = job
        return lab_report(job)
    except (ValueError, PermissionError) as exc:
        job.state = LabState.FAILED; job.result = "rejected"; job.error = str(exc); lab_jobs[job_id] = job
        raise HTTPException(status_code=403, detail=str(exc)) from exc

@app.get("/labs")
def get_labs():
    return [lab_report(job) for job in reversed(list(lab_jobs.values()))]

@app.get("/lab/{job_id}")
def get_lab(job_id: str):
    job = lab_jobs.get(job_id)
    if job is None: raise HTTPException(status_code=404, detail="Lab job not found")
    return lab_report(job)

@app.get("/lab/{job_id}/report")
def get_lab_report(job_id: str):
    job = lab_jobs.get(job_id)
    if job is None: raise HTTPException(status_code=404, detail="Lab job not found")
    return JSONResponse(content=lab_report(job), headers={"Content-Disposition": f'attachment; filename="lab-{job_id}.json"'})

@app.get("/scans")
def get_scans(): return [{"scan_id": s["scan_id"], "category": s.get("category"), "target": s["target"], "scope": s.get("scope"), "tools": s.get("tools", []), "status": s["status"], "state": s.get("state"), "findings_count": len(s["findings"])} for s in reversed(list(scans.values()))]

@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = scans.get(scan_id)
    if scan is None: raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scan/{scan_id}/findings")
def get_findings(scan_id: str, severity: str | None = Query(default=None)):
    scan = scans.get(scan_id)
    if scan is None: raise HTTPException(status_code=404, detail="Scan not found")
    findings = scan["findings"] if not severity else [f for f in scan["findings"] if f["severity"] == severity]
    return {"scan_id": scan_id, "count": len(findings), "findings": findings}

@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str):
    scan = scans.get(scan_id)
    if scan is None: raise HTTPException(status_code=404, detail="Scan not found")
    counts = {level: sum(1 for f in scan["findings"] if f.get("severity") == level) for level in ("critical", "high", "medium", "low", "info")}
    report = {"report": "Nayak Pen Testing Tool Assessment Report", "architecture": "NPT v7.0", "scan_id": scan["scan_id"], "category": scan.get("category"), "target": scan["target"], "scope": scan["scope"], "authorized": scan["authorized"], "tools": scan["tools"], "status": scan["status"], "state": scan.get("state"), "summary": {"total_findings": len(scan["findings"]), **counts}, "findings": scan["findings"], "evidence": scan.get("evidence", {})}
    return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'})
