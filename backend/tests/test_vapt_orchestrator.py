import pytest

from backend.scanner.vapt_orchestrator import ScopeError, deduplicate, validate_scope


def test_authorization_is_required():
    with pytest.raises(ScopeError):
        validate_scope("https://example.com", False)


def test_only_http_urls_are_accepted():
    with pytest.raises(ScopeError):
        validate_scope("ftp://example.com", True)


def test_credentials_in_url_are_rejected():
    with pytest.raises(ScopeError):
        validate_scope("https://user:pass@example.com", True)


def test_duplicate_findings_are_removed():
    finding = {
        "title": "Example finding",
        "severity": "high",
        "description": "same",
        "evidence": "https://example.com/a",
        "tool": "nuclei",
    }
    result = deduplicate([finding, dict(finding)])
    assert len(result) == 1
