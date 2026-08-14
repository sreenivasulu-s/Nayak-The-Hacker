from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from urllib.parse import urlparse


SAFE_TOOLS = {
    "httpx": "httpx",
    "whatweb": "whatweb",
    "nmap": "nmap",
    "subfinder": "subfinder",
    "amass": "amass",
}

ACTIVE_TOOLS = {
    "ffuf": "ffuf",
    "gobuster": "gobuster",
    "nuclei": "nuclei",
    "nikto": "nikto",
}

DEFAULT_WORDLIST = os.getenv(
    "VAPT_WORDLIST",
    "/usr/share/wordlists/dirb/common.txt",
)


@dataclass
class ToolResult:
    tool: str
    status: str
    stdout: str = ""
    stderr: str = ""
    returncode: int = 0


class ScopeError(ValueError):
    pass


def validate_scope(target: str, authorized: bool) -> str:
    if not authorized:
        raise ScopeError("Explicit authorization is required before a scan can run")

    parsed = urlparse(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("Only http:// or https:// targets with a hostname are supported")

    if parsed.username or parsed.password:
        raise ScopeError("Credentials embedded in the target URL are not allowed")

    return parsed.hostname


def _tool_available(binary: str) -> bool:
    return shutil.which(binary) is not None


def _run(binary: str, args: list[str], timeout: int = 180) -> ToolResult:
    if not _tool_available(binary):
        return ToolResult(binary, "unavailable", stderr=f"{binary} is not installed")

    try:
        completed = subprocess.run(
            [binary, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
        return ToolResult(
            binary,
            "completed" if completed.returncode == 0 else "error",
            completed.stdout[-200_000:],
            completed.stderr[-50_000:],
            completed.returncode,
        )
    except subprocess.TimeoutExpired as exc:
        return ToolResult(binary, "timeout", (exc.stdout or "")[-50_000:], (exc.stderr or "")[-10_000:], 124)


def _severity(value: str) -> str:
    value = value.lower()
    for level in ("critical", "high", "medium", "low", "info"):
        if level in value:
            return level
    return "info"


def _finding(title: str, severity: str, description: str, evidence: str, tool: str) -> dict:
    return {
        "title": title[:240],
        "severity": _severity(severity),
        "description": description[:2000],
        "evidence": evidence[:5000],
        "tool": tool,
    }


def parse_result(result: ToolResult) -> list[dict]:
    findings: list[dict] = []
    out = result.stdout.strip()

    if result.status == "unavailable":
        return [_finding(f"{result.tool} unavailable", "info", "The Kali tool is not installed or not on PATH.", result.stderr, result.tool)]
    if result.status == "timeout":
        return [_finding(f"{result.tool} timed out", "low", "The tool exceeded the configured scan timeout.", result.stderr, result.tool)]
    if result.status == "error" and result.stderr:
        findings.append(_finding(f"{result.tool} returned an error", "info", "The tool did not complete successfully.", result.stderr, result.tool))

    if result.tool == "nuclei":
        for line in out.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = item.get("info") or {}
            severity = info.get("severity", "info")
            name = info.get("name") or item.get("template-id") or "Nuclei finding"
            matched = item.get("matched-at") or item.get("host") or ""
            findings.append(_finding(name, severity, info.get("description") or "Nuclei template matched the target.", matched, "nuclei"))
        return findings

    if result.tool == "ffuf":
        for line in out.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            for hit in item.get("results", []):
                url = hit.get("url", "")
                status = hit.get("status")
                findings.append(_finding("Discovered web content", "info", f"ffuf discovered a response with HTTP status {status}.", url, "ffuf"))
        return findings

    if result.tool == "gobuster":
        for line in out.splitlines():
            if "] " in line and "Status:" in line:
                findings.append(_finding("Discovered web content", "info", "Gobuster discovered a content path.", line, "gobuster"))
        return findings

    if result.tool == "nmap":
        for line in out.splitlines():
            stripped = line.strip()
            if "/tcp" in stripped and " open " in stripped:
                findings.append(_finding("Open network service", "info", "Nmap identified an open TCP service.", stripped, "nmap"))
        return findings

    if out:
        findings.append(_finding(f"{result.tool} completed", "info", f"{result.tool} produced scan output for correlation.", out[:5000], result.tool))
    return findings


async def run_vapt(
    target: str,
    *,
    authorized: bool,
    active_approved: bool = False,
    timeout: int = 180,
) -> tuple[list[dict], list[dict]]:
    hostname = validate_scope(target, authorized)
    parsed = urlparse(target)
    root = f"{parsed.scheme}://{parsed.netloc}"

    commands: list[tuple[str, list[str], int]] = [
        ("httpx", ["-silent", "-json", "-u", root], timeout),
        ("whatweb", ["--log-json=-", root], timeout),
        ("nmap", ["-Pn", "-sV", "--top-ports", "1000", hostname], timeout),
        ("subfinder", ["-silent", "-d", hostname], timeout),
        ("amass", ["enum", "-passive", "-d", hostname], timeout),
    ]

    if active_approved:
        commands.extend([
            ("ffuf", ["-u", root.rstrip("/") + "/FUZZ", "-w", DEFAULT_WORDLIST, "-of", "json", "-o", "-", "-noninteractive"], timeout),
            ("gobuster", ["dir", "-u", root, "-w", DEFAULT_WORDLIST, "-q"], timeout),
            ("nuclei", ["-u", root, "-silent", "-jsonl"], timeout),
            ("nikto", ["-h", root, "-Format", "txt", "-output", "-"], timeout),
        ])

    results: list[ToolResult] = []
    for binary, args, tool_timeout in commands:
        results.append(await asyncio.to_thread(_run, binary, args, tool_timeout))

    findings: list[dict] = []
    for result in results:
        findings.extend(parse_result(result))

    # Preserve raw tool metadata for auditability while keeping findings normalized.
    raw = [
        {
            "tool": item.tool,
            "status": item.status,
            "returncode": item.returncode,
            "stdout": item.stdout,
            "stderr": item.stderr,
        }
        for item in results
    ]
    return deduplicate(findings), raw


def deduplicate(findings: list[dict]) -> list[dict]:
    unique: dict[tuple[str, str, str], dict] = {}
    for finding in findings:
        key = (
            finding.get("title", "").strip().lower(),
            finding.get("severity", "info"),
            finding.get("evidence", "").strip().lower()[:500],
        )
        unique.setdefault(key, finding)
    return list(unique.values())
