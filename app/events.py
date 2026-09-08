"""Structured application events shared by headless and interactive frontends."""

from dataclasses import dataclass, field
from enum import Enum
import asyncio
import logging
from typing import Any, Mapping, Protocol

logger = logging.getLogger(__name__)


class EventKind(str, Enum):
    """Lifecycle categories emitted by application phases."""

    MESSAGE = "message"
    PHASE_STARTED = "phase_started"
    PHASE_UPDATED = "phase_updated"
    TARGET_STARTED = "target_started"
    TARGET_FINISHED = "target_finished"
    FINDING = "finding"
    ERROR = "error"
    COMPLETE = "complete"
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class AppEvent:
    """Immutable state change suitable for logs, state stores, or UI widgets."""

    phase: str
    target: str = ""
    message: str = ""
    kind: EventKind = EventKind.MESSAGE
    status: str | None = None
    completed: int | None = None
    total: int | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)


class EventSink(Protocol):
    """Synchronous event consumer contract used by application phases."""

    def emit(self, event: AppEvent) -> None:
        ...


class EventQueue:
    """Bridge synchronous phase callbacks to an async UI consumer."""

    def __init__(self, maxsize: int = 0) -> None:
        self._events: asyncio.Queue[AppEvent] = asyncio.Queue(maxsize=maxsize)

    def emit(self, event: AppEvent) -> None:
        """Enqueue without blocking the producer event loop."""
        try:
            self._events.put_nowait(event)
        except asyncio.QueueFull:
            logger.warning("Event queue full; dropping oldest application event")
            self._events.get_nowait()
            self._events.put_nowait(event)

    async def get(self) -> AppEvent:
        """Wait for the next application event."""
        return await self._events.get()

    def task_done(self) -> None:
        """Mark the most recently consumed event as processed."""
        self._events.task_done()

    async def join(self) -> None:
        """Wait until all queued events have been consumed."""
        await self._events.join()
