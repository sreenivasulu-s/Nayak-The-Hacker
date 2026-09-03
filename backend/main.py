import os
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, field_validator, model_validator

from backend.db import init_db, load_scans, save_scan
from backend.npt_v7.catalog import assessment_catalog
from backend.npt_v7.control_plane import Authorization, PolicyProfile, authorize
from backend.npt_v7.evidence import make_evidence
from backend.npt_v7.events import bus
from backend.npt_v7.state_machine import State, transition
from backend.npt_v7.verification import verify_candidate
from backend.scanner.tool_runner import execute_tools

app = FastAPI(title="Nayak Pen Testing Tool", version="8.0.0")


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ORIGINS", "").strip()
    if configured:
        return [x.strip() for x in configured.split(",") if x.strip()]
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
        if not value:
            raise ValueError("Target and scope are required")
        return value

    @field_validator("category")
    @classmethod
    def clean_category(cls, value: str) -> str:
        return value.strip().lower()

    @model_validator(mode="after")
    def validate_confirmation(self):
        if not self.authorized:
            raise ValueError("Explicit authorization is required before a scan can start")
        if not self.user_confirmation:
            raise ValueError("User confirmation is required before tool execution")
        return self


class ApprovalRequest(BaseModel):
    approved: bool
    note: str = ""


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


async def _event(scan_id: str, event: str, **data) -> None:
    await bus.publish(scan_id, {"event": event, "scan_id": scan_id, **data})


async def _set_state(scan: dict, state: State, status: str | None = None) -> None:
    current = State(scan["state"])
    scan["state"] = transition(current, state)
    if status:
        scan["status"] = status
    save_scan(scan)
    await _event(scan["scan_id"], "state_changed", state=state.value, status=scan.get("status"))


async def run_scan(scan_id: str):
    scan = scans[scan_id]
    try:
        await _set_state(scan, State.AUTHORIZATION_CHECK)
        gate = authorize(scan["category"], scan["target"], Authorization(scan["authorized"], scan["scope"], scan.get("project_id"), scan.get("user_id")), scan["tools"], PolicyProfile(name=scan.get("policy_profile", "default-read-only")))
        scan["authorization_gate"] = gate
        await _event(scan_id, "scope_verified", scope=scan["scope"])
        await _set_state(scan, State.SCOPE_VALIDATION)
        await _set_state(scan, State.POLICY_VALIDATION)
        await _set_state(scan, State.PLANNING)
        await _event(scan_id, "plan_ready", tools=gate["plan"]["planned_tools"])
        await _set_state(scan, State.QUEUED, "queued")
        await _set_state(scan, State.RUNNING, "running")
        await _event(scan_id, "execution_started", tools=scan["tools"])

        findings, evidence_summary = await execute_tools(scan["target"], scan["scope"], scan["tools"])
        await _set_state(scan, State.EVIDENCE_COLLECTION)
        scan["evidence"], scan["findings"] = {}, []
        for tool, summary in evidence_summary.items():
            evidence_id, tool_run_id = f"evidence_{uuid4().hex}", f"toolrun_{uuid4().hex}"
            raw = summary.get("raw_output", "")
            scan["evidence"][tool] = make_evidence(evidence_id, tool_run_id, tool, "detected-at-worker-runtime", scan["target"], raw, f"memory://{tool_run_id}")
            await _event(scan_id, "evidence_collected", tool=tool, evidence_id=evidence_id)

        await _set_state(scan, State.VERIFICATION)
        for candidate in findings:
            tool = candidate.get("tool", "unknown")
            result = verify_candidate(candidate, [scan["evidence"][tool]] if tool in scan["evidence"] else [])
            candidate["verification_status"], candidate["confidence"] = result["status"], result["confidence"]
            await _event(scan_id, "finding_verified", title=candidate.get("title"), tool=tool, verification_status=result["status"], confidence=result["confidence"])
            if result["status"] == "VERIFIED":
                scan["findings"].append(Finding(**candidate).model_dump())
            elif result["status"] == "UNCERTAIN":
                scan["findings"].append(Finding(**candidate).model_dump())

        await _set_state(scan, State.FALSE_POSITIVE_GATE)
        await _set_state(scan, State.AI_ANALYSIS)
        await _event(scan_id, "ai_review_ready", findings_count=len(scan["findings"]))
        await _set_state(scan, State.CORRELATION)
        await _set_state(scan, State.FINDING)
        await _set_state(scan, State.REPORT)
        await _set_state(scan, State.COMPLETE, "completed")
        await _event(scan_id, "scan_completed", findings_count=len(scan["findings"]))
    except Exception as exc:
        scan["status"] = "failed"
        scan["state"] = State.ERROR
        scan["error"] = str(exc)
        save_scan(scan)
        await _event(scan_id, "scan_failed", error=str(exc))


@app.get("/")
def home():
    return {"status": "ok", "message": "Nayak Pen Testing Tool API is running", "version": "8.0.0", "execution_mode": "real", "architecture": "Nayak Final Architecture", "docker": False}


@app.get("/assessment-categories")
def get_assessment_categories():
    return {"version": "8.0.0", "categories": assessment_catalog()}


@app.get("/tools")
def get_tools():
    return {"tools": ["burp-pro", "nmap", "gobuster", "nikto", "nuclei"], "primary_engine": "burp-pro", "note": "Only tools enabled by category and policy can execute"}


@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    try:
        gate = authorize(request.category, request.target, Authorization(request.authorized, request.scope, request.project_id, request.user_id), request.tools or [], PolicyProfile(name=request.policy_profile))
    except (ValueError, PermissionError) as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc
    scan_id = str(uuid4())
    scans[scan_id] = {"scan_id": scan_id, "category": request.category, "target": request.target, "scope": request.scope, "authorized": request.authorized, "user_confirmation": request.user_confirmation, "project_id": request.project_id, "user_id": request.user_id, "policy_profile": request.policy_profile, "tools": gate["plan"]["planned_tools"], "target_type": "web" if request.target.startswith(("http://", "https://")) else "network", "status": "created", "state": State.CREATED, "findings": [], "evidence": {}, "authorization_gate": gate, "approval": None}
    save_scan(scans[scan_id])
    background_tasks.add_task(run_scan, scan_id)
    return scans[scan_id]


@app.post("/scan/{scan_id}/approval")
async def set_approval(scan_id: str, request: ApprovalRequest):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    scan["approval"] = {"approved": request.approved, "note": request.note}
    save_scan(scan)
    await _event(scan_id, "human_approval", approved=request.approved, note=request.note)
    return scan["approval"]


@app.get("/scans")
def get_scans():
    return [{"scan_id": s["scan_id"], "category": s.get("category"), "target": s["target"], "scope": s.get("scope"), "tools": s.get("tools", []), "status": s["status"], "state": s.get("state"), "findings_count": len(s["findings"]), "approval": s.get("approval")} for s in reversed(list(scans.values()))]


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
    counts = {level: sum(1 for f in scan["findings"] if f.get("severity") == level) for level in ("critical", "high", "medium", "low", "info")}
    report = {"report": "Nayak Pen Testing Tool Assessment Report", "architecture": "Nayak Final Architecture", "scan_id": scan["scan_id"], "category": scan.get("category"), "target": scan["target"], "scope": scan["scope"], "authorized": scan["authorized"], "tools": scan["tools"], "status": scan["status"], "state": scan.get("state"), "summary": {"total_findings": len(scan["findings"]), **counts}, "findings": scan["findings"], "evidence": scan.get("evidence", {})}
    return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'})


@app.websocket("/ws/scans/{scan_id}")
async def scan_events(websocket: WebSocket, scan_id: str):
    if scan_id not in scans:
        await websocket.close(code=1008, reason="Scan not found")
        return
    await websocket.accept()
    queue = bus.subscribe(scan_id)
    try:
        await websocket.send_json({"event": "snapshot", "scan": scans[scan_id]})
        while True:
            await websocket.send_json(await queue.get())
    except WebSocketDisconnect:
        pass
    finally:
        bus.unsubscribe(scan_id, queue)
