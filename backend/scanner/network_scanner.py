import asyncio
import socket
from urllib.parse import urlparse

from backend.scanner.base import ScannerBase


COMMON_PORTS = {
    22: "SSH",
    80: "HTTP",
    443: "HTTPS",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}


class NetworkScanner(ScannerBase):
    async def scan(self, target: str) -> list[dict]:
        host = self._normalize_host(target)
        findings: list[dict] = []

        try:
            resolved = await asyncio.to_thread(socket.gethostbyname, host)
        except (socket.gaierror, OSError) as exc:
            return [
                {
                    "title": "Network target could not be resolved",
                    "severity": "info",
                    "description": (
                        "The supplied authorized network host could not be resolved."
                    ),
                    "evidence": str(exc),
                    "tool": "socket",
                }
            ]

        findings.append(
            {
                "title": "Authorized network target resolved",
                "severity": "info",
                "description": (
                    "The supplied authorized network host resolved successfully."
                ),
                "evidence": f"{host} -> {resolved}",
                "tool": "socket",
            }
        )

        for port, service in COMMON_PORTS.items():
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(resolved, port),
                    timeout=0.75,
                )
                writer.close()
                await writer.wait_closed()

                findings.append(
                    {
                        "title": f"{service} service reachable",
                        "severity": "info",
                        "description": (
                            "A TCP connection to a common service port succeeded."
                        ),
                        "evidence": f"{host}:{port}",
                        "tool": "tcp-connect",
                    }
                )
            except (asyncio.TimeoutError, OSError):
                continue

        return findings

    @staticmethod
    def _normalize_host(target: str) -> str:
        value = target.strip()

        if value.startswith(("http://", "https://")):
            parsed = urlparse(value)
            if parsed.hostname:
                return parsed.hostname

        return value.split("/", 1)[0].split(":", 1)[0]
