import asyncio

from backend.scanner.network_scanner import NetworkScanner


def test_network_normalizes_url_host():
    assert (
        NetworkScanner._normalize_host("http://localhost:8000/docs")
        == "localhost"
    )


def test_network_normalizes_hostname():
    assert NetworkScanner._normalize_host("localhost") == "localhost"


def test_network_returns_resolution_finding():
    findings = asyncio.run(NetworkScanner().scan("localhost"))

    assert findings
    assert findings[0]["title"] == "Authorized network target resolved"
    assert findings[0]["tool"] == "socket"


def test_network_invalid_host_returns_info_finding():
    findings = asyncio.run(
        NetworkScanner().scan("definitely-not-a-real-authorized-host.invalid")
    )

    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert findings[0]["tool"] == "socket"
