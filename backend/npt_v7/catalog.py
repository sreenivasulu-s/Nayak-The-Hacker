"""Assessment categories and policy-aware tool routing for NPT v7."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ToolSpec:
    name: str
    capability: str
    execution_class: str
    enabled: bool = False


CATEGORIES = {
    "network": {"name": "Network Pentesting", "tools": ("nmap",)},
    "web": {"name": "Web Application Pentesting", "tools": ("gobuster", "nikto", "nuclei")},
    "api": {"name": "API Pentesting", "tools": ("nuclei",)},
    "mobile": {"name": "Mobile App Pentesting", "tools": ()},
    "cloud": {"name": "Cloud Pentesting", "tools": ()},
    "wireless": {"name": "Wireless Pentesting", "tools": ()},
    "active-directory": {"name": "Active Directory Pentesting", "tools": ()},
    "social-engineering": {"name": "Social Engineering", "tools": ()},
    "physical": {"name": "Physical Security Testing", "tools": ()},
    "iot": {"name": "IoT / Embedded Pentesting", "tools": ("nmap",)},
    "red-team": {"name": "Red Teaming", "tools": ()},
    "external": {"name": "External Pentesting", "tools": ("nmap", "gobuster", "nikto", "nuclei")},
    "internal": {"name": "Internal Pentesting", "tools": ("nmap",)},
}

TOOLS = {
    "nmap": ToolSpec("nmap", "network-discovery", "read-only-discovery", True),
    "gobuster": ToolSpec("gobuster", "web-content-discovery", "read-only-discovery", True),
    "nikto": ToolSpec("nikto", "web-review", "read-only-review", True),
    "nuclei": ToolSpec("nuclei", "template-review", "read-only-review", True),
    "wireshark": ToolSpec("wireshark", "packet-analysis", "analysis", False),
    "netcat": ToolSpec("netcat", "network-connectivity", "controlled-network", False),
    "burp": ToolSpec("burp", "http-analysis", "controlled-web", False),
    "ffuf": ToolSpec("ffuf", "web-content-discovery", "controlled-web", False),
    "sqlmap": ToolSpec("sqlmap", "database-validation", "active-validation", False),
    "aircrack": ToolSpec("aircrack", "wireless-analysis", "wireless", False),
    "ghidra": ToolSpec("ghidra", "binary-analysis", "analysis", False),
    "yara": ToolSpec("yara", "artifact-analysis", "analysis", False),
}


def assessment_catalog() -> list[dict]:
    return [{"id": key, **value} for key, value in CATEGORIES.items()]


def plan_for(category: str, requested_tools: list[str] | None = None) -> dict:
    if category not in CATEGORIES:
        raise ValueError(f"Unknown assessment category: {category}")
    allowed = set(CATEGORIES[category]["tools"])
    requested = requested_tools if requested_tools is not None else list(allowed)
    requested = list(dict.fromkeys(x.lower().strip() for x in requested))
    unsupported = [x for x in requested if x not in TOOLS or x not in allowed or not TOOLS[x].enabled]
    if unsupported:
        raise ValueError(f"Tools not permitted for category/policy: {', '.join(unsupported)}")
    return {
        "category": category,
        "category_name": CATEGORIES[category]["name"],
        "requested_tools": requested,
        "planned_tools": requested,
        "gates": ["authorization", "scope", "policy", "capability", "resource_limits", "user_confirmation"],
    }
