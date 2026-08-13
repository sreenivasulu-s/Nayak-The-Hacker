from fastapi.testclient import TestClient

import os

os.environ["APP_USERNAME"] = "sreenivasulu-s"
os.environ["APP_PASSWORD"] = "test-password-for-pytest"


from backend.main import app


import base64

_TEST_AUTH = base64.b64encode(
    b"sreenivasulu-s:test-password-for-pytest"
).decode()

client = TestClient(
    app,
    headers={"Authorization": f"Basic {_TEST_AUTH}"},
)


def test_health_check():
    response = client.get("/")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_start_scan():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    data = response.json()

    assert data["status"] == "queued"
    assert data["target"] == "http://127.0.0.1:8000"
    assert "scan_id" in data
    assert data["findings"] == []


def test_get_scan_findings():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    scan_id = response.json()["scan_id"]

    status_response = client.get(
        f"/scan/{scan_id}"
    )

    assert status_response.status_code == 200

    data = status_response.json()

    assert data["scan_id"] == scan_id
    assert data["status"] in {"queued", "completed"}


def test_scan_produces_httpx_finding():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    scan_id = response.json()["scan_id"]

    findings_response = client.get(
        f"/scan/{scan_id}/findings"
    )

    assert findings_response.status_code == 200

    data = findings_response.json()

    assert data["scan_id"] == scan_id
    assert data["count"] == 7

    finding = data["findings"][0]

    assert finding["title"] == "HTTP service reachable"
    assert finding["severity"] == "info"
    assert finding["tool"] == "httpx"


def test_scan_normalizes_markdown_url():
    response = client.post(
        "/scan",
        json={
            "url": "[http://127.0.0.1:8000](http://127.0.0.1:8000)",
        },
    )

    assert response.status_code == 200

    data = response.json()

    assert data["target"] == "http://127.0.0.1:8000"


def test_scan_rejects_invalid_scheme():
    response = client.post(
        "/scan",
        json={"url": "ftp://127.0.0.1:8000"},
    )

    assert response.status_code == 422


def test_findings_severity_filter():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    scan_id = response.json()["scan_id"]

    findings_response = client.get(
        f"/scan/{scan_id}/findings?severity=info"
    )

    assert findings_response.status_code == 200

    data = findings_response.json()

    assert data["scan_id"] == scan_id
    assert data["count"] == 2
    assert data["findings"][0]["severity"] == "info"

def test_scan_history_returns_scans_newest_first():
    first_response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )
    second_response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8001"},
    )

    assert first_response.status_code == 200
    assert second_response.status_code == 200

    first_scan_id = first_response.json()["scan_id"]
    second_scan_id = second_response.json()["scan_id"]

    response = client.get("/scans")

    assert response.status_code == 200

    data = response.json()

    scan_ids = [scan["scan_id"] for scan in data]

    assert second_scan_id in scan_ids
    assert first_scan_id in scan_ids
    assert scan_ids.index(second_scan_id) < scan_ids.index(first_scan_id)

    history_entry = next(
        scan for scan in data if scan["scan_id"] == second_scan_id
    )

    assert history_entry["target"] == "http://127.0.0.1:8001"
    assert history_entry["status"] in {"queued", "completed"}
    assert history_entry["findings_count"] >= 0


def test_scan_history_is_empty_when_no_scans_exist():
    from backend.main import scans

    scans.clear()

    response = client.get("/scans")

    assert response.status_code == 200
    assert response.json() == []

def test_scan_report_returns_json_download():
    response = client.post(
        "/scan",
        json={"url": "http://127.0.0.1:8000"},
    )

    assert response.status_code == 200

    scan_id = response.json()["scan_id"]

    report_response = client.get(
        f"/scan/{scan_id}/report"
    )

    assert report_response.status_code == 200
    assert report_response.headers["content-type"].startswith(
        "application/json"
    )
    assert "attachment" in report_response.headers["content-disposition"]

    data = report_response.json()

    assert data["scan_id"] == scan_id
    assert data["target"] == "http://127.0.0.1:8000"
    assert data["summary"]["total_findings"] == 7
    assert data["summary"]["info"] == 2
    assert data["summary"]["low"] == 5
    assert len(data["findings"]) == 7


def test_scan_report_returns_404_for_unknown_scan():
    response = client.get(
        "/scan/does-not-exist/report"
    )

    assert response.status_code == 404

