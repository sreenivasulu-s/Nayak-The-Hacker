"""PortSwigger Web Security Academy lab orchestration primitives.

This package is intentionally scoped to PortSwigger lab hosts and provides
planning/state/evidence primitives. Exploit execution is delegated to a
controlled worker runtime and must pass the existing authorization gate.
"""

from .models import LabJob, LabState
from .orchestrator import build_lab_plan, validate_lab_url

__all__ = ["LabJob", "LabState", "build_lab_plan", "validate_lab_url"]
