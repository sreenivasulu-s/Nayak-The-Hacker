import asyncio
import json

from backend.scanner.cloud_scanner import CloudScanner


def test_cloud_detects_aws():
    findings = asyncio.run(
        CloudScanner().scan("authorized-aws-config")
    )
    assert findings[0]["title"] == "Cloud provider detected"


def test_cloud_detects_service_endpoint():
    findings = asyncio.run(
        CloudScanner().scan("https://example.amazonaws.com")
    )
    assert any(
        f["title"] == "Cloud service endpoint reference detected"
        for f in findings
    )


def test_cloud_parses_json_config(tmp_path):
    config = tmp_path / "cloud.json"
    config.write_text(
        json.dumps({"provider": "aws", "region": "test-region"})
    )

    findings = asyncio.run(
        CloudScanner().scan(str(config))
    )

    assert any(
        f["title"] == "Cloud configuration JSON parsed"
        for f in findings
    )
    assert any(
        f["title"] == "Cloud provider detected"
        for f in findings
    )


def test_cloud_requires_context():
    findings = asyncio.run(
        CloudScanner().scan("unknown-cloud-target")
    )
    assert findings[0]["title"] == "Cloud assessment context required"
