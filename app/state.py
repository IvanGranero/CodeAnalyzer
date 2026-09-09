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
class ExploitState:
    """Current UI-friendly state for one exploit validation target."""

    name: str
    status: str = "queued"
    message: str = ""
    report: dict[str, Any] | None = None
    result: dict[str, Any] | None = None


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
    exploits: dict[str, ExploitState] = field(default_factory=dict)
    exploit_total: int = 0
    exploit_completed: int = 0
    exploit_successful: int = 0
    exploit_failed: int = 0
    exploit_current: str = ""
    exploit_message: str = ""

    @property
    def exploit_percent(self) -> float:
        """Return completed exploit validations as a percentage."""
        return (self.exploit_completed / self.exploit_total * 100) if self.exploit_total else 0.0

    @property
    def exploit_success_percent(self) -> float:
        """Return successful validations among completed validations."""
        return (
            self.exploit_successful / self.exploit_completed * 100
            if self.exploit_completed
            else 0.0
        )

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

        if event.phase == "exploit":
            self._apply_exploit_event(event)
            return

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

    def _apply_exploit_event(self, event: AppEvent) -> None:
        """Project exploit lifecycle events separately from scan targets."""
        exploit = event.payload.get("exploit", {})
        if not isinstance(exploit, dict):
            exploit = {}
        event_name = event.target or str(exploit.get("target", ""))
        if event.kind == EventKind.PHASE_STARTED:
            self.exploit_total = event.total or int(exploit.get("total", 0) or 0)
        if exploit.get("queued") and exploit.get("count_total", True):
            self.exploit_total += 1
            if event_name:
                self.exploits.setdefault(event_name, ExploitState(event_name))
        if not event_name:
            return
        target = self.exploits.setdefault(event_name, ExploitState(event_name))
        target.message = event.message
        report = event.payload.get("report")
        if isinstance(report, dict) and report:
            target.report = report
        self.exploit_current = event_name
        self.exploit_message = event.message
        if event.kind == EventKind.TARGET_STARTED:
            target.status = "running"
        elif event.kind == EventKind.TARGET_FINISHED:
            result = event.payload.get("result")
            target.status = event.status or (result or {}).get("status", "failed")
            target.result = result if isinstance(result, dict) else None
            self.exploit_completed += 1
            if target.status == "success":
                self.exploit_successful += 1
            else:
                self.exploit_failed += 1


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
        self.resume_event = asyncio.Event()
        self.resume_event.set()
        self.task: asyncio.Task[Any] | None = None

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    def cancel(self) -> None:
        """Request cancellation and interrupt the active task if one exists."""
        self.cancel_event.set()
        if self.task is not None and not self.task.done():
            self.task.cancel()

    def pause(self) -> None:
        """Stop workers from starting another target."""
        self.resume_event.clear()

    def resume(self) -> None:
        """Allow paused workers to continue with queued targets."""
        self.resume_event.set()

    async def wait_if_paused(self) -> None:
        """Wait until the session is resumed without blocking the event loop."""
        await self.resume_event.wait()
