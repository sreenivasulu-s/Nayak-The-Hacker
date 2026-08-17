# PortSwigger Lab Orchestrator

This package is the first stage of the all-labs automation path for PortSwigger Web Security Academy training targets.

## Current stage

- Accepts only `portswigger.net` and `*.web-security-academy.net` targets.
- Models one global run with a 3600-second deadline.
- Runs multiple lab jobs concurrently with a worker semaphore.
- Keeps per-lab attempts, evidence, worker IDs, and status.
- Uses an allowlist for Burp MCP tools; shell execution is not exposed to the model.
- Provides an Ollama-compatible local LLM adapter.
- Detects common Academy completion text before marking a job `solved`.
- Emits structured events for a future live dashboard/WebSocket layer.

## Environment

```text
BURP_MCP_URL=http://127.0.0.1:<burp-mcp-port>/mcp
OLLAMA_URL=http://127.0.0.1:11434
OLLAMA_MODEL=qwen2.5:14b
```

The exact Burp MCP endpoint and tool protocol must be configured from the installed Burp MCP bridge. The adapter intentionally does not guess a port or protocol.

## Next integration stage

1. Mount the orchestrator in the FastAPI application.
2. Add run creation/status/event endpoints and WebSocket streaming.
3. Replace the generic Burp adapter with the confirmed Burp MCP protocol.
4. Add browser/session state handling for Academy lab instances.
5. Add persistent run/event storage and resumable workers.
6. Add LLM strategy memory and category-specific solver policies.
