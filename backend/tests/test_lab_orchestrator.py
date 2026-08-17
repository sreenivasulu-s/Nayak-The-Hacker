import asyncio

import pytest

from backend.labs.models import LabStatus
from backend.labs.orchestrator import LabOrchestrator
from backend.labs.providers import AgentDecision
from backend.labs.target import is_authorized_training_target, normalize_lab_target


class FakeAgent:
    async def decide(self, *, target, category, evidence):
        return AgentDecision(
            action="request",
            summary="inspect lab response",
            tool="send_request",
            arguments={"url": target},
        )


class FakeBurp:
    def __init__(self):
        self.calls = []

    async def call(self, tool, arguments):
        self.calls.append((tool, arguments))
        return {"body": "Congratulations, you solved the lab"}


@pytest.mark.asyncio
async def test_training_target_boundary():
    assert is_authorized_training_target("https://portswigger.net/web-security/sql-injection")
    assert is_authorized_training_target("https://0a1b2c3d.web-security-academy.net/")
    assert not is_authorized_training_target("https://example.com/")


def test_normalize_training_lab():
    target = normalize_lab_target("https://0a1b2c3d.web-security-academy.net/login")
    assert target.lab_id == "0a1b2c3d"
    assert target.category == "unknown"


@pytest.mark.asyncio
async def test_orchestrator_solves_in_parallel():
    burp = FakeBurp()
    orchestrator = LabOrchestrator(
        max_workers=2,
        deadline_seconds=60,
        max_attempts=2,
        agent=FakeAgent(),
        burp=burp,
    )
    run = await orchestrator.run([
        "https://a1.web-security-academy.net/",
        "https://a2.web-security-academy.net/",
    ])

    assert all(job.status == LabStatus.SOLVED for job in run.jobs.values())
    assert len(burp.calls) == 2


@pytest.mark.asyncio
async def test_global_timeout_marks_active_jobs():
    class SlowAgent:
        async def decide(self, *, target, category, evidence):
            await asyncio.sleep(1)
            return AgentDecision(action="stop", summary="slow")

    orchestrator = LabOrchestrator(
        max_workers=2,
        deadline_seconds=60,
        max_attempts=1,
        agent=SlowAgent(),
        burp=FakeBurp(),
    )
    orchestrator.deadline_seconds = 60
    run = await orchestrator.run(["https://a3.web-security-academy.net/"])
    assert run.jobs["a3"].status == LabStatus.BLOCKED
