from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import StrEnum
from time import time


class LabStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    SOLVED = "solved"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"


@dataclass(slots=True)
class LabJob:
    lab_id: str
    target: str
    category: str = "unknown"
    status: LabStatus = LabStatus.QUEUED
    attempts: int = 0
    worker_id: str | None = None
    started_at: float | None = None
    finished_at: float | None = None
    last_event: str = ""
    error: str | None = None
    evidence: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass(slots=True)
class LabRun:
    run_id: str
    jobs: dict[str, LabJob]
    started_at: float = field(default_factory=time)
    deadline_seconds: int = 3600
    status: str = "running"

    @property
    def deadline_at(self) -> float:
        return self.started_at + self.deadline_seconds

    def summary(self) -> dict:
        counts = {status.value: 0 for status in LabStatus}
        for job in self.jobs.values():
            counts[job.status.value] += 1
        return {
            "run_id": self.run_id,
            "status": self.status,
            "deadline_seconds": self.deadline_seconds,
            "elapsed_seconds": max(0.0, time() - self.started_at),
            "remaining_seconds": max(0.0, self.deadline_at - time()),
            "total": len(self.jobs),
            "counts": counts,
        }
