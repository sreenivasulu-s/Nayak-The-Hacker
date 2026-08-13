from pathlib import Path
import zipfile

from backend.scanner.base import ScannerBase


class MobileScanner(ScannerBase):
    async def scan(self, target: str) -> list[dict]:
        value = target.strip()
        path = Path(value)
        suffix = path.suffix.lower()

        if suffix not in {".apk", ".ipa"}:
            return [
                {
                    "title": "Mobile artifact required",
                    "severity": "info",
                    "description": (
                        "Provide an authorized APK or IPA artifact reference "
                        "for static mobile assessment."
                    ),
                    "evidence": f"Received target: {value}",
                    "tool": "mobile-adapter",
                }
            ]

        if not path.exists():
            return [
                {
                    "title": "Mobile artifact not found",
                    "severity": "info",
                    "description": (
                        "The supplied APK/IPA reference does not exist "
                        "at the provided path."
                    ),
                    "evidence": str(path),
                    "tool": "mobile-adapter",
                }
            ]

        findings: list[dict] = [
            {
                "title": "Mobile artifact found",
                "severity": "info",
                "description": "The authorized mobile artifact exists and is ready for static inspection.",
                "evidence": f"{path} ({path.stat().st_size} bytes)",
                "tool": "mobile-adapter",
            }
        ]

        if suffix == ".apk":
            try:
                with zipfile.ZipFile(path) as archive:
                    names = set(archive.namelist())

                if "AndroidManifest.xml" in names:
                    findings.append(
                        {
                            "title": "Android manifest detected",
                            "severity": "info",
                            "description": "The APK contains an Android manifest.",
                            "evidence": "AndroidManifest.xml",
                            "tool": "apk-static",
                        }
                    )
                else:
                    findings.append(
                        {
                            "title": "Android manifest missing",
                            "severity": "low",
                            "description": "The APK archive does not contain the expected Android manifest.",
                            "evidence": "AndroidManifest.xml not found",
                            "tool": "apk-static",
                        }
                    )
            except zipfile.BadZipFile:
                findings.append(
                    {
                        "title": "Invalid APK archive",
                        "severity": "low",
                        "description": "The supplied APK does not appear to be a valid ZIP-based APK archive.",
                        "evidence": str(path),
                        "tool": "apk-static",
                    }
                )

        else:
            try:
                with zipfile.ZipFile(path) as archive:
                    names = set(archive.namelist())

                if any(name.startswith("Payload/") for name in names):
                    findings.append(
                        {
                            "title": "iOS payload detected",
                            "severity": "info",
                            "description": "The IPA contains the expected iOS Payload directory.",
                            "evidence": "Payload/ detected",
                            "tool": "ipa-static",
                        }
                    )
                else:
                    findings.append(
                        {
                            "title": "iOS payload missing",
                            "severity": "low",
                            "description": "The IPA archive does not contain the expected Payload directory.",
                            "evidence": "Payload/ not found",
                            "tool": "ipa-static",
                        }
                    )
            except zipfile.BadZipFile:
                findings.append(
                    {
                        "title": "Invalid IPA archive",
                        "severity": "low",
                        "description": "The supplied IPA does not appear to be a valid ZIP archive.",
                        "evidence": str(path),
                        "tool": "ipa-static",
                    }
                )

        return findings
