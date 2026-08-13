import json

import httpx

from backend.scanner.api_scanner import ApiScanner


def test_openapi_inventory_counts_paths():
    response = httpx.Response(
        200,
        json={
            "openapi": "3.0.0",
            "paths": {
                "/users": {
                    "get": {},
                    "post": {},
                },
                "/health": {
                    "get": {},
                },
            },
        },
    )

    findings = ApiScanner._inventory_openapi(response)

    assert len(findings) == 1
    assert findings[0]["title"] == "OpenAPI endpoint inventory generated"
    assert "2 documented path(s)" in findings[0]["evidence"]
    assert "GET" in findings[0]["evidence"]
    assert "POST" in findings[0]["evidence"]


def test_openapi_invalid_json():
    response = httpx.Response(
        200,
        content=b"not-json",
        headers={"content-type": "application/json"},
    )

    findings = ApiScanner._inventory_openapi(response)

    assert findings[0]["title"] == "OpenAPI document is not valid JSON"


def test_openapi_missing_paths():
    response = httpx.Response(
        200,
        content=json.dumps({"openapi": "3.0.0"}).encode(),
        headers={"content-type": "application/json"},
    )

    findings = ApiScanner._inventory_openapi(response)

    assert findings[0]["title"] == "OpenAPI paths section missing"

def test_api_normalizes_markdown_target():
    url = "http://127.0.0.1:8000/docs"
    markdown_target = "[" + url + "](" + url + ")"

    assert ApiScanner._normalize_target(markdown_target) == url
