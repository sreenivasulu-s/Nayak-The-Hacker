"""In-memory event bus for live Nayak observer updates."""
from __future__ import annotations

import asyncio
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any


class EventBus:
    def __init__(self) -> None:
        self._subscribers: dict[str, set[asyncio.Queue]] = defaultdict(set)

    async def publish(self, scan_id: str, event: dict[str, Any]) -> None:
        event = {"ts": datetime.now(timezone.utc).isoformat(), **event}
        for queue in tuple(self._subscribers.get(scan_id, ())):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                pass

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._subscribers[scan_id].add(queue)
        return queue

    def unsubscribe(self, scan_id: str, queue: asyncio.Queue) -> None:
        self._subscribers[scan_id].discard(queue)
        if not self._subscribers[scan_id]:
            self._subscribers.pop(scan_id, None)


bus = EventBus()
