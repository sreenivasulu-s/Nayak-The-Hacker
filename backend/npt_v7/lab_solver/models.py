from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class LabState(StrEnum):
    CREATED = "created"
    VALIDATING = "validating"
    DISCOVERING = "discovering"
    PLANNING = "planning"
    TESTING = "testing"
    VERIFYING = "verifying"
    REPORTING = "reporting"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass
class LabJob:
    job_id: str
    lab_url: str
    state: LabState = LabState.CREATED
    lab_host: str | None = None
    lab_name: str | None = None
    hypothesis: list[str] = field(default_factory=list)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    events: list[dict[str, Any]] = field(default_factory=list)
    result: str = "pending"
    error: str | None = None

    def event(self, name: str, **data: Any) -> None:
        self.events.append({"name": name, **data})
