import asyncio
import json
import os
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

TOOL_TIMEOUT_SECONDS = int(os.getenv("SCAN_TOOL_TIMEOUT_SECONDS", "300"))
MAX_OUTPUT_BYTES = int(os.getenv("SCAN_MAX_OUTPUT_BYTES", "2000000"))


def _wordlist() -> str:
    candidates = [os.getenv("GOBUSTER_WORDLIST", ""), "/usr/share/seclists/Discovery/Web-Content/common.txt", "/usr/share/wordlists/dirb/common.txt"]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    raise RuntimeError("Gobuster wordlist not found. Set GOBUSTER_WORDLIST or install a standard wordlist.")


def _host(target: str) -> str:
    parsed = urlparse(target if "://" in target else f"//{target}")
    if not parsed.hostname:
        raise ValueError("Target host could not be determined")
    return parsed.hostname


def _validate_scope(target: str, scope: str) -> None:
    if _host(target).lower().rstrip(".") != _host(scope).lower().rstrip("."):
        raise ValueError("Target is outside the authorized scope")


def _base_url(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else f"http://{target}"


async def _run(command: list[str]) -> tuple[int, str, str]:
    executable = shutil.which(command[0])
    if not executable:
        raise RuntimeError(f"Required tool is not installed: {command[0]}")
    process = await asyncio.create_subprocess_exec(executable, *command[1:], stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=TOOL_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        process.kill(); await process.communicate()
        raise RuntimeError(f"{command[0]} timed out after {TOOL_TIMEOUT_SECONDS} seconds")
    return process.returncode or 0, stdout[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"), stderr[:MAX_OUTPUT_BYTES].decode("utf-8", errors="replace")


def _finding(title: str, severity: str, description: str, evidence: str, tool: str) -> dict:
    return {"title": title, "severity": severity, "description": description, "evidence": evidence[:12000], "tool": tool}


def _parse_nmap(xml_text: str) -> list[dict]:
    findings = []
    try: root = ET.fromstring(xml_text)
    except ET.ParseError: return findings
    for host in root.findall("host"):
        address = host.find("address")
        host_value = address.attrib.get("addr", "target") if address is not None else "target"
        for port in host.findall("./ports/port"):
            state = port.find("state")
            if state is None or state.attrib.get("state") != "open": continue
            service = port.find("service")
            service_name = service.attrib.get("name", "unknown") if service is not None else "unknown"
            product = service.attrib.get("product", "") if service is not None else ""
            version = service.attrib.get("version", "") if service is not None else ""
            details = " ".join(x for x in [product, version] if x).strip()
            evidence = f"{host_value}:{port.attrib.get('portid')} / {port.attrib.get('protocol')} / {service_name}"
            if details: evidence += f" / {details}"
            findings.append(_finding(f"Open {port.attrib.get('portid')}/{port.attrib.get('protocol')} service", "info", "Nmap identified an open service on the authorized target.", evidence, "nmap"))
    return findings


def _parse_gobuster(output: str) -> list[dict]:
    return [_finding("Web path discovered", "info", "Gobuster discovered a web path responding on the authorized target.", line.strip(), "gobuster") for line in output.splitlines() if line.strip() and "Status:" in line]


def _parse_nikto(output: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("+") and any(token in stripped.lower() for token in ("osvdb", "x-frame-options", "cookie", "server", "allowed", "outdated", "interesting")):
            severity = "medium" if any(x in stripped.lower() for x in ("outdated", "vulnerab")) else "low"
            findings.append(_finding("Nikto web-server observation", severity, "Nikto reported an observation for the authorized web target.", stripped, "nikto"))
    return findings


def _parse_nuclei(output: str) -> list[dict]:
    findings = []
    for line in output.splitlines():
        try: item = json.loads(line)
        except json.JSONDecodeError: continue
        info = item.get("info", {})
        severity = str(info.get("severity", "info")).lower()
        if severity not in {"critical", "high", "medium", "low", "info"}: severity = "info"
        findings.append(_finding(str(info.get("name") or item.get("template-id") or "Nuclei finding"), severity, str(info.get("description") or "Nuclei matched a template on the authorized target."), str(item.get("matched-at") or item.get("host") or line), "nuclei"))
    return findings


async def execute_tools(target: str, scope: str, tools: list[str]) -> tuple[list[dict], dict]:
    _validate_scope(target, scope)
    allowed = {"nmap", "gobuster", "nikto", "nuclei"}
    selected = [tool.lower().strip() for tool in tools]
    unknown = [tool for tool in selected if tool not in allowed]
    if unknown: raise ValueError(f"Unsupported tools: {', '.join(unknown)}")
    if not selected: raise ValueError("Select at least one scanner tool")
    host, web_target = _host(target), _base_url(target)
    results, evidence = [], {}
    for tool in dict.fromkeys(selected):
        if tool == "nmap": code, out, err = await _run(["nmap", "-sV", "--version-light", "-oX", "-", host])
        elif tool == "gobuster": code, out, err = await _run(["gobuster", "dir", "-u", web_target, "-w", _wordlist(), "--no-error", "-q"])
        elif tool == "nikto": code, out, err = await _run(["nikto", "-h", web_target, "-Format", "txt"])
        else: code, out, err = await _run(["nuclei", "-u", web_target, "-jsonl", "-silent"])
        parser = {"nmap": _parse_nmap, "gobuster": _parse_gobuster, "nikto": _parse_nikto, "nuclei": _parse_nuclei}[tool]
        results.extend(parser(out))
        evidence[tool] = {"return_code": code, "stderr": err[-4000:], "raw_size": len(out), "raw_output": out}
    if not results:
        results.append(_finding("No findings returned", "info", "The selected tools completed without producing a parsed security finding.", json.dumps({k: {x: v for x, v in value.items() if x != "raw_output"} for k, value in evidence.items()}), "scanner-pipeline"))
    return results, evidence
