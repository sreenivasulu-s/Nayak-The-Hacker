from backend.npt_v7.correlation import correlate_findings


def test_same_evidence_key_is_correlated():
    findings = [
        {
            "title": "Open service",
            "severity": "info",
            "description": "service",
            "evidence": "127.0.0.1:80 / tcp / http",
            "tool": "nmap",
            "verification_status": "VERIFIED",
            "confidence": 0.8,
        },
        {
            "title": "  Open service ",
            "severity": "info",
            "description": "same service",
            "evidence": "127.0.0.1:80 / tcp / http",
            "tool": "nikto",
            "verification_status": "VERIFIED",
            "confidence": 0.9,
        },
    ]
    result = correlate_findings(findings)
    assert len(result) == 1
    assert result[0]["tools"] == ["nmap", "nikto"]
    assert result[0]["confidence"] == 0.9
