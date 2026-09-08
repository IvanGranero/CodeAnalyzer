"""Observable scan state and cooperative cancellation primitives."""

import asyncio
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from app.events import AppEvent, EventKind
from app.progress import ProgressEvent


class TargetStatus(str, Enum):
    """Lifecycle state for one prioritized scan target."""

    QUEUED = "queued"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class TargetState:
    """Current UI-friendly state for one target function."""

    name: str
    status: TargetStatus = TargetStatus.QUEUED
    phase: str = ""
    message: str = ""
    report: dict[str, Any] | None = None
    error: str | None = None


@dataclass
class ScanState:
    """Mutable projection of application events for dashboards and summaries."""

    targets: dict[str, TargetState] = field(default_factory=dict)
    phase: str = ""
    completed: int = 0
    total: int = 0
    started_at: float | None = None
    finished_at: float | None = None
    cancelled: bool = False
    error_count: int = 0
    llm_tokens: int = 0
    llm_cost: float = 0.0

    @property
    def active_workers(self) -> int:
        """Count targets currently being processed."""
        return sum(target.status is TargetStatus.RUNNING for target in self.targets.values())

    def apply(self, event: AppEvent) -> None:
        """Apply one event without requiring consumers to parse log text."""
        if self.started_at is None:
            self.started_at = time.monotonic()
        self.phase = event.phase or self.phase
        if event.total is not None:
            self.total = event.total
        if event.completed is not None:
            self.completed = event.completed
        if event.kind == EventKind.ERROR:
            self.error_count += 1
        usage = event.payload.get("usage", {})
        if isinstance(usage, dict):
            self.llm_tokens += int(usage.get("total_tokens", 0) or 0)
            self.llm_cost += float(usage.get("cost_usd", 0.0) or 0.0)

        if event.target:
            target = self.targets.setdefault(event.target, TargetState(event.target))
            target.phase = event.phase
            target.message = event.message
            if event.kind == EventKind.TARGET_STARTED:
                target.status = TargetStatus.RUNNING
            elif event.kind == EventKind.TARGET_FINISHED:
                target.status = (
                    TargetStatus.FAILED
                    if event.status == "error"
                    else TargetStatus.COMPLETE
                )
                report = event.payload.get("report")
                if isinstance(report, dict):
                    target.report = report
            elif event.kind == EventKind.ERROR:
                target.status = TargetStatus.FAILED
                target.error = event.message
            elif event.kind == EventKind.CANCELLED:
                target.status = TargetStatus.CANCELLED

        if event.kind == EventKind.CANCELLED:
            self.cancelled = True
            for target in self.targets.values():
                if target.status in {TargetStatus.QUEUED, TargetStatus.RUNNING}:
                    target.status = TargetStatus.CANCELLED
        if event.kind in {EventKind.COMPLETE, EventKind.CANCELLED}:
            self.finished_at = time.monotonic()


class ScanStateSink:
    """Adapt legacy progress events into a live ``ScanState`` projection."""

    def __init__(self, state: ScanState | None = None) -> None:
        self.state = state or ScanState()

    def emit(self, event: ProgressEvent) -> None:
        self.state.apply(event.to_app_event())


class ScanSession:
    """Own a running application task and expose cooperative cancellation."""

    def __init__(self) -> None:
        self.cancel_event = asyncio.Event()
        self.task: asyncio.Task[Any] | None = None

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def cancel(self) -> None:
        """Request cancellation and interrupt the active task if one exists."""
        self.cancel_event.set()
        if self.task is not None and not self.task.done():
            self.task.cancel()
