"""Mandatory NPT v7 control-plane gates.

No worker is allowed to execute a tool unless the request has passed
authorization, scope, policy, category routing, capability and resource gates.
"""

from dataclasses import dataclass, asdict
from urllib.parse import urlparse

from backend.npt_v7.catalog import TOOLS, plan_for


@dataclass(frozen=True)
class PolicyProfile:
    name: str = "default-read-only"
    max_runtime_seconds: int = 300
    max_output_bytes: int = 2_000_000
    max_tools_per_assessment: int = 4
    allow_network: bool = True
    allow_filesystem_write: bool = False


@dataclass(frozen=True)
class Authorization:
    confirmed: bool
    scope: str
    project_id: str | None = None
    user_id: str | None = None


def _host(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"//{value}")
    if not parsed.hostname:
        raise ValueError("Invalid target/scope host")
    return parsed.hostname.lower().rstrip(".")


def validate_scope(target: str, scope: str) -> None:
    target_host = _host(target)
    scope_host = _host(scope)
    if target_host != scope_host:
        raise PermissionError("Target is outside the authorized scope")


def validate_policy(policy: PolicyProfile) -> None:
    if policy.max_runtime_seconds <= 0 or policy.max_runtime_seconds > 3600:
        raise PermissionError("Policy runtime limit must be between 1 and 3600 seconds")
    if policy.max_output_bytes <= 0 or policy.max_output_bytes > 10_000_000:
        raise PermissionError("Policy output limit must be between 1 byte and 10 MB")
    if policy.max_tools_per_assessment <= 0 or policy.max_tools_per_assessment > 10:
        raise PermissionError("Policy tool-count limit is invalid")
    if policy.allow_filesystem_write:
        raise PermissionError("The default NPT execution boundary does not permit worker filesystem writes")


def validate_capabilities(tools: list[str], policy: PolicyProfile) -> None:
    if len(tools) > policy.max_tools_per_assessment:
        raise PermissionError("Assessment exceeds the policy tool-count limit")
    for tool in tools:
        spec = TOOLS.get(tool)
        if spec is None or not spec.enabled:
            raise PermissionError(f"Tool capability is not enabled: {tool}")
        if spec.execution_class not in {"read-only-discovery", "read-only-review"}:
            raise PermissionError(f"Tool execution class is not permitted by the active policy: {tool}")


def authorize(category: str, target: str, auth: Authorization, tools: list[str], policy: PolicyProfile | None = None) -> dict:
    if not auth.confirmed:
        raise PermissionError("Explicit authorization is required")
    validate_scope(target, auth.scope)
    policy = policy or PolicyProfile()
    validate_policy(policy)
    plan = plan_for(category, tools)
    validate_capabilities(plan["planned_tools"], policy)
    if not policy.allow_network:
        raise PermissionError("Policy profile denies network execution")
    return {
        "authorized": True,
        "scope": auth.scope,
        "project_id": auth.project_id,
        "user_id": auth.user_id,
        "policy": asdict(policy),
        "plan": plan,
        "capabilities": [asdict(TOOLS[tool]) for tool in plan["planned_tools"]],
    }
