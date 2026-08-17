from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Protocol

import httpx


@dataclass(frozen=True, slots=True)
class AgentDecision:
    action: str
    summary: str
    tool: str | None = None
    arguments: dict | None = None


class LabAgent(Protocol):
    async def decide(self, *, target: str, category: str, evidence: list[dict]) -> AgentDecision: ...


class BurpMcpGateway:
    """Thin MCP bridge; it does not expose shell execution to the model."""

    def __init__(self, endpoint: str | None = None):
        self.endpoint = (endpoint or os.getenv("BURP_MCP_URL", "")).strip().rstrip("/")

    @property
    def configured(self) -> bool:
        return bool(self.endpoint)

    async def call(self, tool: str, arguments: dict) -> dict:
        if not self.endpoint:
            raise RuntimeError("BURP_MCP_URL is not configured")
        async with httpx.AsyncClient(timeout=20.0) as client:
            response = await client.post(
                self.endpoint,
                json={"tool": tool, "arguments": arguments},
            )
            response.raise_for_status()
            return response.json()


class OllamaLabAgent:
    """Local LLM adapter using an Ollama-compatible HTTP API."""

    def __init__(self, base_url: str | None = None, model: str | None = None):
        self.base_url = (base_url or os.getenv("OLLAMA_URL", "http://127.0.0.1:11434")).rstrip("/")
        self.model = model or os.getenv("OLLAMA_MODEL", "qwen2.5:14b")

    async def decide(self, *, target: str, category: str, evidence: list[dict]) -> AgentDecision:
        prompt = (
            "You are an agent for authorized PortSwigger Web Security Academy labs only. "
            "Choose the next safe assessment action from the available MCP tools. "
            "Do not request shell access, credentials, persistence, or destructive actions.\n"
            f"Target: {target}\nCategory: {category}\nEvidence: {evidence[-8:]}\n"
            "Return JSON with action, summary, tool, arguments."
        )
        payload = {
            "model": self.model,
            "stream": False,
            "format": "json",
            "prompt": prompt,
        }
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(f"{self.base_url}/api/generate", json=payload)
            response.raise_for_status()
            data = response.json()
        import json
        parsed = json.loads(data.get("response", "{}"))
        return AgentDecision(
            action=str(parsed.get("action", "stop")),
            summary=str(parsed.get("summary", "")),
            tool=parsed.get("tool"),
            arguments=parsed.get("arguments") or {},
        )
