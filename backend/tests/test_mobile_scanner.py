import asyncio
import zipfile

from backend.scanner.mobile_scanner import MobileScanner


def test_mobile_requires_artifact():
    findings = asyncio.run(
        MobileScanner().scan("sample.txt")
    )
    assert findings[0]["title"] == "Mobile artifact required"


def test_mobile_reports_missing_artifact():
    findings = asyncio.run(
        MobileScanner().scan("missing.apk")
    )
    assert findings[0]["title"] == "Mobile artifact not found"


def test_mobile_detects_apk_manifest(tmp_path):
    apk = tmp_path / "sample.apk"

    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"test")

    findings = asyncio.run(
        MobileScanner().scan(str(apk))
    )

    assert findings[0]["title"] == "Mobile artifact found"
    assert any(
        finding["title"] == "Android manifest detected"
        for finding in findings
    )


def test_mobile_detects_ipa_payload(tmp_path):
    ipa = tmp_path / "sample.ipa"

    with zipfile.ZipFile(ipa, "w") as archive:
        archive.writestr("Payload/Test.app/Info.plist", b"test")

    findings = asyncio.run(
        MobileScanner().scan(str(ipa))
    )

    assert findings[0]["title"] == "Mobile artifact found"
    assert any(
        finding["title"] == "iOS payload detected"
        for finding in findings
    )
