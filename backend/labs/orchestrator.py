from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import asdict
from time import time
from uuid import uuid4

from .models import LabJob, LabRun, LabStatus
from .providers import AgentDecision, BurpMcpGateway, LabAgent, OllamaLabAgent
from .target import normalize_lab_target

EventSink = Callable[[dict], Awaitable[None]]


class LabOrchestrator:
    """Run many authorized Academy labs concurrently under one global deadline."""

    def __init__(
        self,
        *,
        max_workers: int = 32,
        deadline_seconds: int = 3600,
        max_attempts: int = 12,
        agent: LabAgent | None = None,
        burp: BurpMcpGateway | None = None,
        event_sink: EventSink | None = None,
    ):
        self.max_workers = max(1, max_workers)
        self.deadline_seconds = max(60, deadline_seconds)
        self.max_attempts = max(1, max_attempts)
        self.agent = agent or OllamaLabAgent()
        self.burp = burp or BurpMcpGateway()
        self.event_sink = event_sink

    async def _emit(self, event: dict) -> None:
        if self.event_sink:
            await self.event_sink(event)

    @staticmethod
    def _completion_signal(response: object) -> bool:
        text = str(response).lower()
        return any(
            marker in text
            for marker in (
                "congratulations, you solved the lab",
                "you solved the lab",
                "lab solved",
            )
        )

    async def _solve_job(self, job: LabJob, deadline_at: float, semaphore: asyncio.Semaphore) -> None:
        async with semaphore:
            job.status = LabStatus.RUNNING
            job.worker_id = f"worker-{uuid4().hex[:8]}"
            job.started_at = time()
            await self._emit({"type": "lab.started", "job": job.to_dict()})

            try:
                while job.attempts < self.max_attempts and time() < deadline_at:
                    job.attempts += 1
                    decision: AgentDecision = await asyncio.wait_for(
                        self.agent.decide(
                            target=job.target,
                            category=job.category,
                            evidence=job.evidence,
                        ),
                        timeout=min(60.0, max(5.0, deadline_at - time())),
                    )
                    job.last_event = decision.summary
                    await self._emit({
                        "type": "agent.decision",
                        "job": job.to_dict(),
                        "decision": asdict(decision),
                    })

                    if decision.action.lower() in {"stop", "blocked"}:
                        job.status = LabStatus.BLOCKED
                        job.error = decision.summary or "Agent stopped without completion."
                        break

                    if not decision.tool:
                        job.status = LabStatus.FAILED
                        job.error = "Agent returned no MCP tool."
                        break

                    allowed_tools = {
                        "proxy_history",
                        "send_request",
                        "repeat_request",
                        "get_response",
                        "browser_navigate",
                    }
                    if decision.tool not in allowed_tools:
                        job.status = LabStatus.BLOCKED
                        job.error = f"Tool not allowlisted: {decision.tool}"
                        break

                    result = await self.burp.call(decision.tool, decision.arguments or {})
                    job.evidence.append({
                        "attempt": job.attempts,
                        "tool": decision.tool,
                        "summary": decision.summary,
                        "result": result,
                    })
                    await self._emit({"type": "mcp.result", "job": job.to_dict()})

                    if self._completion_signal(result):
                        job.status = LabStatus.SOLVED
                        break

                if job.status == LabStatus.RUNNING:
                    job.status = LabStatus.TIMEOUT if time() >= deadline_at else LabStatus.FAILED
            except asyncio.TimeoutError:
                job.status = LabStatus.TIMEOUT
                job.error = "Agent action exceeded its time budget."
            except Exception as exc:
                job.status = LabStatus.FAILED
                job.error = str(exc)
            finally:
                job.finished_at = time()
                await self._emit({"type": "lab.finished", "job": job.to_dict()})

    async def run(self, targets: list[str]) -> LabRun:
        jobs: dict[str, LabJob] = {}
        for raw in targets:
            target = normalize_lab_target(raw)
            jobs[target.lab_id] = LabJob(
                lab_id=target.lab_id,
                target=target.url,
                category=target.category,
            )

        run = LabRun(
            run_id=str(uuid4()),
            jobs=jobs,
            deadline_seconds=self.deadline_seconds,
        )
        semaphore = asyncio.Semaphore(self.max_workers)
        tasks = [
            asyncio.create_task(self._solve_job(job, run.deadline_at, semaphore))
            for job in run.jobs.values()
        ]

        try:
            await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.deadline_seconds,
            )
        except asyncio.TimeoutError:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            for job in run.jobs.values():
                if job.status in {LabStatus.QUEUED, LabStatus.RUNNING}:
                    job.status = LabStatus.TIMEOUT
        finally:
            run.status = "completed"
            await self._emit({"type": "run.finished", "run": run.summary()})

        return run
