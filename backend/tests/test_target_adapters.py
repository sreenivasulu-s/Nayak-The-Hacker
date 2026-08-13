import asyncio

from backend.scanner.cloud_scanner import CloudScanner
from backend.scanner.mobile_scanner import MobileScanner
from backend.scanner.network_scanner import NetworkScanner
from backend.scanner.wireless_scanner import WirelessScanner


def test_mobile_accepts_apk_reference():
    findings = asyncio.run(MobileScanner().scan("sample.apk"))
    assert findings[0]["title"] == "Mobile artifact not found"


def test_cloud_detects_provider():
    findings = asyncio.run(
        CloudScanner().scan("authorized-aws-config")
    )
    assert findings[0]["title"] == "Cloud provider detected"


def test_wireless_accepts_scope():
    findings = asyncio.run(
        WirelessScanner().scan("wlan0:authorized-lab")
    )
    assert findings[0]["title"] == "Wireless assessment scope received"


def test_network_returns_resolution_finding():
    findings = asyncio.run(
        NetworkScanner().scan("localhost")
    )
    assert findings
    assert findings[0]["tool"] == "socket"
