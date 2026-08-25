import asyncio

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


def test_training_target_boundary():
    assert is_authorized_training_target("https://portswigger.net/web-security/sql-injection")
    assert is_authorized_training_target("https://0a1b2c3d.web-security-academy.net/")
    assert not is_authorized_training_target("https://example.com/")


def test_normalize_training_lab():
    target = normalize_lab_target("https://0a1b2c3d.web-security-academy.net/login")
    assert target.lab_id == "0a1b2c3d"
    assert target.category == "unknown"


def test_orchestrator_solves_in_parallel():
    async def run_test():
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

    asyncio.run(run_test())


def test_agent_stop_marks_job_blocked():
    class StoppingAgent:
        async def decide(self, *, target, category, evidence):
            return AgentDecision(action="stop", summary="needs human review")

    async def run_test():
        orchestrator = LabOrchestrator(
            max_workers=1,
            deadline_seconds=60,
            max_attempts=1,
            agent=StoppingAgent(),
            burp=FakeBurp(),
        )
        run = await orchestrator.run(["https://a3.web-security-academy.net/"])
        assert run.jobs["a3"].status == LabStatus.BLOCKED

    asyncio.run(run_test())


def test_orchestrator_browser_navigate_uses_browser_gateway():
    class BrowserAgent:
        async def decide(self, *, target, category, evidence):
            return AgentDecision(
                action="request",
                summary="inspect lab in browser",
                tool="browser_navigate",
                arguments={},
            )

    class FakeBrowser:
        def __init__(self):
            self.calls = []

        async def navigate(self, target):
            self.calls.append(target)
            return {
                "url": target,
                "status": 200,
                "title": "Academy lab",
                "body_excerpt": "lab page",
            }

    async def run_test():
        browser = FakeBrowser()
        orchestrator = LabOrchestrator(
            max_workers=1,
            deadline_seconds=60,
            max_attempts=1,
            agent=BrowserAgent(),
            browser=browser,
        )

        target = "https://browser-test.web-security-academy.net/"
        run = await orchestrator.run([target])
        job = run.jobs["browser-test"]

        assert job.status == LabStatus.FAILED
        assert browser.calls == [target]
        assert job.evidence[0]["tool"] == "browser_navigate"
        assert job.evidence[0]["result"]["status"] == 200

    asyncio.run(run_test())
