from __future__ import annotations

from mcp.server import MCPServer

from backend.scanner.vapt_orchestrator import run_vapt

mcp = MCPServer("Nayak-The-Hacker-Kali-VAPT")


@mcp.tool()
async def scan_authorized_url(
    target: str,
    authorized: bool,
    active_approved: bool = False,
) -> dict:
    """Run the configured Kali VAPT pipeline against an explicitly authorized URL.

    active_approved=False keeps fuzzing/Nuclei/Nikto disabled. The caller must
    explicitly opt into active checks for an authorized assessment.
    """
    findings, raw_tools = await run_vapt(
        target,
        authorized=authorized,
        active_approved=active_approved,
    )
    return {
        "target": target,
        "authorized": authorized,
        "active_approved": active_approved,
        "findings": findings,
        "tools": raw_tools,
    }


if __name__ == "__main__":
    # Stdio is convenient for local MCP hosts. The same server can be exposed
    # over Streamable HTTP by the MCP SDK when needed.
    mcp.run()
