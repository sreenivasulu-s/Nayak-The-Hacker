import os
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator

from backend.db import init_db, load_scans, save_scan
from backend.scanner.tool_runner import execute_tools

app = FastAPI(title="Nayak Enterprise Penetration Testing Platform", version="7.0.0")


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ORIGINS", "").strip()
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]
    return ["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:5174", "http://127.0.0.1:5174"]


app.add_middleware(CORSMiddleware, allow_origins=_cors_origins(), allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


TOOLS = {"nmap", "gobuster", "nikto", "nuclei"}


class ScanRequest(BaseModel):
    target: str
    scope: str
    tools: list[str]
    authorized: bool = False

    @field_validator("target", "scope")
    @classmethod
    def clean_text(cls, value: str) -> str:
        value = value.strip().strip("`").strip()
        if not value:
            raise ValueError("Target and scope are required")
        return value

    @field_validator("tools")
    @classmethod
    def validate_tools(cls, value: list[str]) -> list[str]:
        normalized = list(dict.fromkeys(tool.strip().lower() for tool in value if tool.strip()))
        if not normalized:
            raise ValueError("Select at least one scanner tool")
        unknown = [tool for tool in normalized if tool not in TOOLS]
        if unknown:
            raise ValueError(f"Unsupported tools: {', '.join(unknown)}")
        return normalized

    @model_validator(mode="after")
    def validate_authorization(self):
        if not self.authorized:
            raise ValueError("Explicit authorization is required before a scan can start")
        return self


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: str
    tool: str


init_db()
scans: dict[str, dict] = load_scans()


async def run_scan(scan_id: str):
    scan = scans[scan_id]
    scan["status"] = "running"
    save_scan(scan)
    try:
        findings, evidence = await execute_tools(scan["target"], scan["scope"], scan["tools"])
        scan["findings"] = [Finding(**finding).model_dump() for finding in findings]
        scan["evidence"] = evidence
        scan["status"] = "completed"
    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
    save_scan(scan)


@app.get("/")
def home():
    return {"status": "ok", "message": "Nayak Enterprise Penetration Testing Platform API is running", "version": "7.0.0", "execution_mode": "real", "tools": sorted(TOOLS)}


@app.get("/tools")
def get_tools():
    return {"tools": sorted(TOOLS)}


@app.post("/scan")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    scan_id = str(uuid4())
    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.target,
        "scope": request.scope,
        "authorized": request.authorized,
        "tools": request.tools,
        "target_type": "web" if request.target.startswith(("http://", "https://")) else "network",
        "status": "queued",
        "findings": [],
        "evidence": {},
    }
    save_scan(scans[scan_id])
    background_tasks.add_task(run_scan, scan_id)
    return scans[scan_id]


@app.get("/scans")
def get_scans():
    return [{"scan_id": s["scan_id"], "target": s["target"], "scope": s.get("scope"), "tools": s.get("tools", []), "status": s["status"], "findings_count": len(s["findings"])} for s in reversed(list(scans.values()))]


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
    findings = scan["findings"]
    if severity:
        findings = [finding for finding in findings if finding["severity"] == severity]
    return {"scan_id": scan_id, "count": len(findings), "findings": findings}


@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str):
    scan = scans.get(scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    counts = {level: 0 for level in ("critical", "high", "medium", "low", "info")}
    for finding in scan["findings"]:
        level = finding.get("severity", "info")
        if level in counts:
            counts[level] += 1
    report = {
        "report": "Nayak Enterprise Penetration Testing Platform Assessment Report",
        "scan_id": scan["scan_id"],
        "target": scan["target"],
        "scope": scan["scope"],
        "authorized": scan["authorized"],
        "tools": scan["tools"],
        "status": scan["status"],
        "summary": {"total_findings": len(scan["findings"]), **counts},
        "findings": scan["findings"],
        "evidence": scan.get("evidence", {}),
    }
    return JSONResponse(content=report, headers={"Content-Disposition": f'attachment; filename="scan-{scan_id}.json"'})
