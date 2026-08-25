from __future__ import annotations

import os
from dataclasses import dataclass
from urllib.parse import urlparse

import httpx


@dataclass(frozen=True)
class BrowserObservation:
    url: str
    status: int | None
    title: str
    body_excerpt: str


class BrowserGateway:
    """Optional local browser/proxy adapter.

    A browser worker can be attached through BROWSER_GATEWAY_URL. The gateway
    receives only an allowlisted Academy target and returns observations. This
    keeps browser automation separate from the reasoning engine and avoids
    treating a Burp proxy port as an MCP endpoint.
    """

    def __init__(self, endpoint: str | None = None):
        self.endpoint = (endpoint or os.getenv("BROWSER_GATEWAY_URL", "")).strip().rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self.endpoint)

    async def navigate(self, target: str) -> dict:
        if not self.configured:
            raise RuntimeError("BROWSER_GATEWAY_URL is not configured")
        parsed = urlparse(target)
        if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".web-security-academy.net"):
            raise PermissionError("Browser gateway accepts PortSwigger Academy lab hosts only")
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
            response = await client.post(f"{self.endpoint}/navigate", json={"url": target})
            response.raise_for_status()
            return response.json()
