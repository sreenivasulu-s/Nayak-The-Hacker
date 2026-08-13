from backend.scanner.api_scanner import ApiScanner
from backend.scanner.cloud_scanner import CloudScanner
from backend.scanner.lab_scanner import LabScanner
from backend.scanner.mobile_scanner import MobileScanner
from backend.scanner.network_scanner import NetworkScanner
from backend.scanner.wireless_scanner import WirelessScanner


class TargetTypeAdapter:
    async def scan(self, target: str, target_type: str) -> list[dict]:
        scanners = {
            "web": LabScanner(),
            "api": ApiScanner(),
            "network": NetworkScanner(),
            "mobile": MobileScanner(),
            "cloud": CloudScanner(),
            "wireless": WirelessScanner(),
        }

        scanner = scanners.get(target_type)
        if scanner is None:
            return [
                {
                    "title": "Unsupported target type",
                    "severity": "info",
                    "description": "The requested target type is not supported.",
                    "evidence": f"Target type: {target_type}",
                    "tool": "dispatcher",
                }
            ]

        return await scanner.scan(target)
