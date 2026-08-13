import asyncio

from backend.scanner.wireless_scanner import WirelessScanner


def test_wireless_requires_scope():
    findings = asyncio.run(WirelessScanner().scan(""))
    assert findings[0]["title"] == "Wireless assessment scope required"


def test_wireless_accepts_unknown_scope():
    findings = asyncio.run(
        WirelessScanner().scan("definitely-not-a-real-interface")
    )
    assert findings[0]["title"] == "Wireless assessment scope received"


def test_wireless_detects_existing_interface():
    findings = asyncio.run(WirelessScanner().scan("lo"))
    assert findings[0]["title"] == "Wireless interface found"
    assert findings[0]["tool"] == "sysfs"


def test_wireless_scope_with_suffix_is_normalized():
    findings = asyncio.run(WirelessScanner().scan("lo:authorized-lab"))
    assert findings[0]["title"] == "Wireless interface found"
