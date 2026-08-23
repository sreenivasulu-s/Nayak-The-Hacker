"""Mandatory control-plane gates. Every execution request passes here first."""

from dataclasses import dataclass
from urllib.parse import urlparse

from backend.npt_v7.catalog import plan_for


@dataclass(frozen=True)
class PolicyProfile:
    name: str = "default-read-only"
    max_runtime_seconds: int = 300
    max_output_bytes: int = 2_000_000
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


def authorize(category: str, target: str, auth: Authorization, tools: list[str], policy: PolicyProfile | None = None) -> dict:
    if not auth.confirmed:
        raise PermissionError("Explicit authorization is required")
    validate_scope(target, auth.scope)
    plan = plan_for(category, tools)
    policy = policy or PolicyProfile()
    if not policy.allow_network:
        raise PermissionError("Policy profile denies network execution")
    return {
        "authorized": True,
        "scope": auth.scope,
        "project_id": auth.project_id,
        "user_id": auth.user_id,
        "policy": policy.name,
        "plan": plan,
    }
