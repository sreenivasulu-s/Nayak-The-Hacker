import os
from uuid import uuid4
from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator
from backend.ai_analysis import analyze_findings
from backend.scanner.dispatcher import TargetTypeAdapter
from backend.scanner.vapt_orchestrator import ScopeError, run_vapt
from backend.db import init_db, load_scans, save_scan

app = FastAPI(title="Nayak The Hacker", version="0.9.0")

def _cors_origins():
    configured = os.getenv("CORS_ORIGINS", "").strip()
    return [x.strip() for x in configured.split(",") if x.strip()] if configured else ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174", "http://localhost:5175", "http://127.0.0.1:5175"]

app.add_middleware(CORSMiddleware, allow_origins=_cors_origins(), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

class ScanRequest(BaseModel):
    url: str
    target_type: str = "web"
    authorized: bool = False
    active_approved: bool = False
    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, value):
        value = value.strip().lower()
        if value not in {"web", "api", "network", "mobile", "cloud", "wireless"}:
            raise ValueError("target_type must be one of: web, api, network, mobile, cloud, wireless")
        return value
    @field_validator("url")
    @classmethod
    def normalize_target(cls, value):
        value = value.strip().strip("`").strip()
        if not value:
            raise ValueError("Target must not be empty")
        return value
    @model_validator(mode="after")
    def validate_target_for_type(self):
        if self.target_type in {"web", "api"} and not (self.url.startswith("http://") or self.url.startswith("https://")):
            raise ValueError("Web and API targets must start with http:// or https://")
        if self.active_approved and not self.authorized:
            raise ValueError("active_approved requires authorized=true")
        return self

class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: str
    tool: str

init_db()
scans = load_scans()

def add_finding(scan_id, finding):
    scans[scan_id]["findings"].append(Finding(**finding).model_dump())
    save_scan(scans[scan_id])

async def run_passive_scan(scan_id):
    scan = scans[scan_id]
    try:
        if scan["target_type"] in {"web", "api"}:
            findings, raw_tools = await run_vapt(scan["target"], authorized=True, active_approved=False)
            scan["tool_runs"] = raw_tools
            for finding in findings:
                add_finding(scan_id, finding)
            scan["status"] = "manual_action_required"
            scan["manual_action"] = {"type": "active_scan_approval", "message": "Passive reconnaissance is complete. Review the findings and approve the next active stage only if the target is authorized and in scope.", "next_tools": ["ffuf", "Gobuster", "Nuclei", "Nikto"], "how_to_proceed": "Review the passive findings, then use Approve Active Checks in the dashboard."}
        else:
            scanner = TargetTypeAdapter()
            findings = await scanner.scan(scan["target"], scan["target_type"])
            for finding in findings:
                add_finding(scan_id, finding)
            scan["status"] = "completed"
            scan["ai_analysis"] = analyze_findings(scan["target"], scan["findings"])
    except ScopeError as exc:
        scan["status"] = "blocked"
        scan["error"] = str(exc)
    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
    save_scan(scan)

async def run_active_stage(scan_id):
    scan = scans[scan_id]
    try:
        findings, raw_tools = await run_vapt(scan["target"], authorized=True, active_approved=True)
        scan["tool_runs"] = scan.get("tool_runs", []) + raw_tools
        existing = {(f.get("title"), f.get("severity"), f.get("evidence")) for f in scan["findings"]}
        for finding in findings:
            key = (finding.get("title"), finding.get("severity"), finding.get("evidence"))
            if key not in existing:
                add_finding(scan_id, finding)
                existing.add(key)
        scan["status"] = "completed"
        scan["manual_action"] = None
        scan["ai_analysis"] = analyze_findings(scan["target"], scan["findings"])
    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
    save_scan(scan)

@app.get("/")
def home():
    return {"status": "ok", "message": "Nayak The Hacker Security Scanner API is running"}

@app.get("/capabilities")
def capabilities():
    return {"url_first_pipeline": ["httpx", "WhatWeb", "Nmap", "Subfinder", "Amass", "ffuf", "Gobuster", "Nuclei", "Nikto"], "manual_gate": "passive stage pauses before active checks", "active_checks": "require authorization and separate manual approval", "analysis": "OpenAI Responses API when OPENAI_API_KEY is configured, otherwise local prioritization", "mcp": "mcp/kali_vapt_server.py", "non_url_inputs": "mobile/cloud/social-engineering require separate evidence/workflows and are not inferred from a URL"}

@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    if not request.authorized:
        raise HTTPException(status_code=400, detail="Explicit authorization is required before a scan can run")
    scan_id = str(uuid4())
    scans[scan_id] = {"scan_id": scan_id, "target": request.url, "target_type": request.target_type, "authorized": True, "active_approved": False, "status": "queued", "findings": [], "tool_runs": [], "ai_analysis": None, "manual_action": None}
    save_scan(scans[scan_id])
    background_tasks.add_task(run_passive_scan, scan_id)
    return scans[scan_id]

@app.post("/scan/{scan_id}/approve-active")
def approve_active(scan_id: str, background_tasks: BackgroundTasks):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    if not scan.get("authorized"):
        raise HTTPException(status_code=403, detail="Authorization is required")
    if scan.get("status") != "manual_action_required":
        raise HTTPException(status_code=409, detail="Scan is not waiting for manual active-stage approval")
    scan["active_approved"] = True
    scan["status"] = "queued_active"
    scan["manual_action"] = None
    save_scan(scan)
    background_tasks.add_task(run_active_stage, scan_id)
    return scan

@app.get("/scans")
def get_scans():
    return [{"scan_id": s["scan_id"], "target": s["target"], "target_type": s.get("target_type", "web"), "status": s["status"], "findings_count": len(s["findings"])} for s in reversed(list(scans.values()))]

@app.get("/scan/{scan_id}")
def get_scan(scan_id):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in scan["findings"]:
        severity = finding.get("severity", "info")
        if severity in severity_counts:
            severity_counts[severity] += 1
    report = {"report": "Nayak The Hacker Security Assessment Report", "scan_id": scan["scan_id"], "target": scan["target"], "target_type": scan.get("target_type", "web"), "status": scan["status"], "authorized": scan.get("authorized", False), "active_approved": scan.get("active_approved", False), "summary": {"total_findings": len(scan["findings"]), **severity_counts}, "findings": scan["findings"], "ai_analysis": scan.get("ai_analysis"), "manual_action": scan.get("manual_action")}
    return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'})

@app.get("/scan/{scan_id}/findings")
def get_findings(scan_id, severity: str | None = Query(default=None)):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = scan["findings"]
    if severity:
        findings = [f for f in findings if f["severity"] == severity]
    return {"scan_id": scan_id, "count": len(findings), "findings": findings}
