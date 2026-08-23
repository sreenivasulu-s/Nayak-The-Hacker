from fastapi.testclient import TestClient

from backend.main import app

client = TestClient(app)


def fake_execute_tools(target, scope, tools):
    return [
        {
            "title": "Test open service",
            "severity": "info",
            "description": "Synthetic test finding.",
            "evidence": f"target={target}; scope={scope}",
            "tool": tools[0],
        }
    ], {tool: {"return_code": 0, "raw_size": 10} for tool in tools}


def payload(target="http://127.0.0.1:8000"):
    return {
        "target": target,
        "scope": target,
        "tools": ["nmap"],
        "authorized": True,
    }


def test_health_check():
    response = client.get("/")
    assert response.status_code == 200
    assert response.json()["execution_mode"] == "real"


def test_scan_requires_authorization():
    data = payload()
    data["authorized"] = False
    response = client.post("/scan", json=data)
    assert response.status_code == 422


def test_scan_requires_scope_match(monkeypatch):
    monkeypatch.setattr("backend.main.execute_tools", fake_execute_tools)
    data = payload()
    data["scope"] = "http://example.com"
    response = client.post("/scan", json=data)
    assert response.status_code == 200
    assert response.json()["status"] == "queued"


def test_start_scan_and_persist_evidence(monkeypatch):
    monkeypatch.setattr("backend.main.execute_tools", fake_execute_tools)
    response = client.post("/scan", json=payload())
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "queued"
    assert data["authorized"] is True
    assert data["tools"] == ["nmap"]
    scan_id = data["scan_id"]

    import asyncio
    asyncio.run(__import__("backend.main", fromlist=["run_scan"]).run_scan(scan_id))
    result = client.get(f"/scan/{scan_id}").json()
    assert result["status"] == "completed"
    assert result["evidence"]["nmap"]["return_code"] == 0
    assert result["findings"][0]["tool"] == "nmap"


def test_unknown_tool_is_rejected():
    data = payload()
    data["tools"] = ["sqlmap"]
    response = client.post("/scan", json=data)
    assert response.status_code == 422


def test_history_and_findings(monkeypatch):
    monkeypatch.setattr("backend.main.execute_tools", fake_execute_tools)
    response = client.post("/scan", json=payload("http://127.0.0.1:8001"))
    assert response.status_code == 200
    scan_id = response.json()["scan_id"]
    import asyncio
    asyncio.run(__import__("backend.main", fromlist=["run_scan"]).run_scan(scan_id))

    findings = client.get(f"/scan/{scan_id}/findings?severity=info")
    assert findings.status_code == 200
    assert findings.json()["count"] == 1

    history = client.get("/scans")
    assert history.status_code == 200
    assert any(item["scan_id"] == scan_id for item in history.json())


def test_scan_report(monkeypatch):
    monkeypatch.setattr("backend.main.execute_tools", fake_execute_tools)
    response = client.post("/scan", json=payload("http://127.0.0.1:8002"))
    scan_id = response.json()["scan_id"]
    import asyncio
    asyncio.run(__import__("backend.main", fromlist=["run_scan"]).run_scan(scan_id))

    report = client.get(f"/scan/{scan_id}/report")
    assert report.status_code == 200
    data = report.json()
    assert data["authorized"] is True
    assert data["summary"]["total_findings"] == 1
    assert "evidence" in data


def test_unknown_scan_returns_404():
    assert client.get("/scan/does-not-exist").status_code == 404
