from pathlib import Path
import json

from backend.scanner.base import ScannerBase


PROVIDERS = {
    "aws": "AWS",
    "amazonaws": "AWS",
    "azure": "Azure",
    "microsoft": "Azure",
    "gcp": "Google Cloud",
    "googleapis": "Google Cloud",
}


class CloudScanner(ScannerBase):
    async def scan(self, target: str) -> list[dict]:
        value = target.strip()
        lowered = value.lower()
        findings: list[dict] = []

        provider = next(
            (name for marker, name in PROVIDERS.items() if marker in lowered),
            None,
        )

        path = Path(value)

        if path.is_file():
            findings.append(
                {
                    "title": "Cloud configuration file found",
                    "severity": "info",
                    "description": (
                        "An authorized cloud configuration/reference file "
                        "was found for static inspection."
                    ),
                    "evidence": f"{path} ({path.stat().st_size} bytes)",
                    "tool": "cloud-static",
                }
            )

            if path.suffix.lower() == ".json":
                try:
                    data = json.loads(path.read_text())
                    text = json.dumps(data).lower()

                    provider_from_file = next(
                        (
                            name
                            for marker, name in PROVIDERS.items()
                            if marker in text
                        ),
                        None,
                    )

                    if provider_from_file:
                        provider = provider_from_file

                    findings.append(
                        {
                            "title": "Cloud configuration JSON parsed",
                            "severity": "info",
                            "description": (
                                "The configuration file is valid JSON and "
                                "can be inspected without contacting the cloud provider."
                            ),
                            "evidence": f"JSON keys: {len(data) if isinstance(data, dict) else 'non-object'}",
                            "tool": "cloud-static",
                        }
                    )
                except (OSError, json.JSONDecodeError) as exc:
                    findings.append(
                        {
                            "title": "Cloud configuration JSON invalid",
                            "severity": "low",
                            "description": (
                                "The supplied JSON configuration could not be parsed."
                            ),
                            "evidence": str(exc),
                            "tool": "cloud-static",
                        }
                    )

        if provider:
            findings.append(
                {
                    "title": "Cloud provider detected",
                    "severity": "info",
                    "description": (
                        "The authorized cloud assessment reference contains "
                        "a recognized cloud provider."
                    ),
                    "evidence": f"Provider: {provider}",
                    "tool": "cloud-adapter",
                }
            )

        if any(
            marker in lowered
            for marker in (
                "amazonaws.com",
                "azure.com",
                "googleapis.com",
            )
        ):
            findings.append(
                {
                    "title": "Cloud service endpoint reference detected",
                    "severity": "info",
                    "description": (
                        "The supplied authorized target contains a known "
                        "cloud service endpoint reference."
                    ),
                    "evidence": value,
                    "tool": "cloud-adapter",
                }
            )

        if not findings:
            findings.append(
                {
                    "title": "Cloud assessment context required",
                    "severity": "info",
                    "description": (
                        "Provide an authorized cloud provider reference, "
                        "configuration file, or service endpoint."
                    ),
                    "evidence": f"Received target: {value}",
                    "tool": "cloud-adapter",
                }
            )

        return findings
