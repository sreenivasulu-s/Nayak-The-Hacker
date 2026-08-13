from pathlib import Path

from backend.scanner.base import ScannerBase


class WirelessScanner(ScannerBase):
    async def scan(self, target: str) -> list[dict]:
        value = target.strip()

        if not value:
            return [
                {
                    "title": "Wireless assessment scope required",
                    "severity": "info",
                    "description": (
                        "Provide an authorized wireless interface or network scope."
                    ),
                    "evidence": "No wireless scope supplied.",
                    "tool": "wireless-adapter",
                }
            ]

        interface = value.split(":", 1)[0].strip()
        interface_path = Path("/sys/class/net") / interface

        if interface_path.exists():
            findings = [
                {
                    "title": "Wireless interface found",
                    "severity": "info",
                    "description": (
                        "The supplied interface exists on the local system "
                        "and is available for authorized assessment."
                    ),
                    "evidence": f"Interface: {interface}",
                    "tool": "sysfs",
                }
            ]

            wireless_path = interface_path / "wireless"

            if wireless_path.exists():
                findings.append(
                    {
                        "title": "Wireless interface confirmed",
                        "severity": "info",
                        "description": (
                            "The interface exposes the Linux wireless sysfs marker."
                        ),
                        "evidence": f"{interface}/wireless",
                        "tool": "sysfs",
                    }
                )

            address_path = interface_path / "address"

            if address_path.exists():
                try:
                    mac = address_path.read_text().strip()
                    findings.append(
                        {
                            "title": "Interface hardware address detected",
                            "severity": "info",
                            "description": (
                                "The local interface hardware address was read "
                                "without transmitting network traffic."
                            ),
                            "evidence": mac,
                            "tool": "sysfs",
                        }
                    )
                except OSError:
                    pass

            return findings

        return [
            {
                "title": "Wireless assessment scope received",
                "severity": "info",
                "description": (
                    "The requested wireless interface was not found locally, "
                    "but the supplied scope reference was retained."
                ),
                "evidence": f"Scope: {value}",
                "tool": "wireless-adapter",
            }
        ]
