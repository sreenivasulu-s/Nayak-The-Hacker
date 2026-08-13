import os
from uuid import uuid4

from fastapi import BackgroundTasks, FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator, model_validator

from backend.scanner.dispatcher import TargetTypeAdapter
from backend.db import init_db, load_scans, save_scan


app = FastAPI(
    title="Nayak The Hacker",
    version="0.7.0",
)


def _cors_origins() -> list[str]:
    configured = os.getenv("CORS_ORIGINS", "").strip()
    if configured:
        return [origin.strip() for origin in configured.split(",") if origin.strip()]

    return [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:5174",
        "http://127.0.0.1:5174",
        "http://localhost:5175",
        "http://127.0.0.1:5175",
    ]


app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins(),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    url: str
    target_type: str = "web"

    @field_validator("target_type")
    @classmethod
    def validate_target_type(cls, value: str) -> str:
        value = value.strip().lower()

        allowed = {
            "web",
            "api",
            "network",
            "mobile",
            "cloud",
            "wireless",
        }

        if value not in allowed:
            raise ValueError(
                "target_type must be one of: "
                "web, api, network, mobile, cloud, wireless"
            )

        return value

    @field_validator("url")
    @classmethod
    def normalize_target(cls, value: str) -> str:
        value = value.strip().strip("`").strip()

        if "](" in value and value.endswith(")"):
            value = value.split("](", 1)[1][:-1].strip()

        if not value:
            raise ValueError("Target must not be empty")

        return value

    @model_validator(mode="after")
    def validate_target_for_type(self):
        if self.target_type in {"web", "api"} and not (
            self.url.startswith("http://") or self.url.startswith("https://")
        ):
            raise ValueError("Web and API targets must start with http:// or https://")

        return self


class Finding(BaseModel):
    title: str
    severity: str
    description: str
    evidence: str
    tool: str


init_db()
scans: dict[str, dict] = load_scans()


def add_finding(
    scan_id: str,
    finding: dict,
) -> None:
    scans[scan_id]["findings"].append(
        Finding(**finding).model_dump()
    )
    save_scan(scans[scan_id])


async def run_scan(scan_id: str):
    scan = scans[scan_id]

    try:
        scanner = TargetTypeAdapter()
        findings = await scanner.scan(
            scan["target"],
            scan.get("target_type", "web"),
        )

        for finding in findings:
            add_finding(scan_id, finding)

        scan["status"] = "completed"

    except Exception as exc:
        scan["status"] = "failed"
        scan["error"] = str(exc)
    save_scan(scan)


@app.get("/")
def home():
    return {
        "status": "ok",
        "message": "Nayak The Hacker Security Scanner API is running",
    }


@app.post("/scan")
def start_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks,
):
    scan_id = str(uuid4())

    scans[scan_id] = {
        "scan_id": scan_id,
        "target": request.url,
        "target_type": request.target_type,
        "status": "queued",
        "findings": [],
    }

    save_scan(scans[scan_id])
    background_tasks.add_task(run_scan, scan_id)

    return scans[scan_id]


@app.get("/scans")
def get_scans():
    return [
        {
            "scan_id": scan["scan_id"],
            "target": scan["target"],
            "target_type": scan.get("target_type", "web"),
            "status": scan["status"],
            "findings_count": len(scan["findings"]),
        }
        for scan in reversed(list(scans.values()))
    ]


@app.get("/scan/{scan_id}")
def get_scan(scan_id: str):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return scan


@app.get("/scan/{scan_id}/report")
def get_scan_report(scan_id: str):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = scan["findings"]

    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = finding.get("severity", "info")
        if severity in severity_counts:
            severity_counts[severity] += 1

    report = {
        "report": "Nayak The Hacker Security Assessment Report",
        "scan_id": scan["scan_id"],
        "target": scan["target"],
        "target_type": scan.get("target_type", "web"),
        "status": scan["status"],
        "summary": {
            "total_findings": len(findings),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
        },
        "findings": findings,
    }

    return JSONResponse(
        content=report,
        headers={
            "Content-Disposition": (
                f'attachment; filename="scan-{scan_id}.json"'
            )
        },
    )


@app.get("/scan/{scan_id}/findings")
def get_findings(
    scan_id: str,
    severity: str | None = Query(default=None),
):
    scan = scans.get(scan_id)

    if scan is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    findings = scan["findings"]

    if severity:
        findings = [
            finding
            for finding in findings
            if finding["severity"] == severity
        ]

    return {
        "scan_id": scan_id,
        "count": len(findings),
        "findings": findings,
    }
