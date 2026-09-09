"""Concise, user-facing progress reporting for long-running scans."""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from app.events import AppEvent, EventKind, EventSink


@dataclass(frozen=True)
class ProgressEvent:
    phase: str
    target: str
    message: str
    completed: int | None = None
    total: int | None = None
    kind: EventKind = EventKind.MESSAGE
    status: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)

    def to_app_event(self) -> AppEvent:
        """Convert the legacy progress shape to the shared event contract."""
        return AppEvent(
            phase=self.phase,
            target=self.target,
            message=self.message,
            kind=self.kind,
            status=self.status,
            completed=self.completed,
            total=self.total,
            payload=self.payload,
        )


class ProgressSink(Protocol):
    def emit(self, event: ProgressEvent) -> None: ...


class ConsoleProgressSink:
    def __init__(self, writer: Callable[[str], None] | None = None):
        self.writer = writer or (lambda message: print(message, flush=True))

    def emit(self, event: ProgressEvent) -> None:
        self.writer(f"[{event.phase}] {event.target} | {event.message}")


class _SilentProgressSink:
    """Discard console progress when a structured event sink owns presentation."""

    def emit(self, event: ProgressEvent) -> None:
        return None


class ScanProgress:
    def __init__(
        self,
        sink: ProgressSink | None = None,
        event_sink: EventSink | None = None,
    ) -> None:
        self.total = 0
        self.completed = 0
        self.started = 0
        self.started_at = 0.0
        self._lock = asyncio.Lock()
        self.sink = sink or (ConsoleProgressSink() if event_sink is None else _SilentProgressSink())
        self.event_sink = event_sink

    async def start(self, total: int) -> None:
        async with self._lock:
            self.total = total
            self.completed = 0
            self.started = 0
            self.started_at = time.monotonic()
            self._write(
                f"Scan started: {total} targets",
                kind=EventKind.PHASE_STARTED,
                total=total,
            )

    async def target_started(self, target: str) -> None:
        async with self._lock:
            self.started += 1
            self._write(
                f"[{self._status()}] Analyzing {target} | graph -> triage",
                target=target,
                kind=EventKind.TARGET_STARTED,
            )

    async def phase(self, target: str, message: str) -> None:
        await self._write_locked(
            f"[{self._status()}] {target} | {message}",
            target=target,
            kind=EventKind.PHASE_UPDATED,
        )

    async def tool(self, tool_name: str) -> None:
        await self._write_locked(
            f"[{self._status()}] triage | tool: {tool_name}",
            kind=EventKind.PHASE_UPDATED,
        )

    async def target_finished(self, target: str, report: dict) -> None:
        async with self._lock:
            self.completed += 1
            elapsed = time.monotonic() - self.started_at
            if report.get("vulnerability_found"):
                result = f"finding: {report.get('severity', 'unknown')}"
            elif report.get("scan_status") == "error":
                result = "error"
            else:
                result = "clean"
            rate = self.completed / elapsed if elapsed else 0
            eta = (self.total - self.completed) / rate if rate else 0
            eta_text = f", ETA {self._duration(eta)}" if self.completed < self.total else ""
            self._write(
                f"[{self._status()}] Completed {target} | {result} | "
                f"{self.completed}/{self.total}{eta_text}",
                target=target,
                kind=EventKind.TARGET_FINISHED,
                status="error" if result == "error" else "complete",
                completed=self.completed,
                payload={"report": report},
            )

    def _percent(self) -> str:
        percent = (self.completed / self.total * 100) if self.total else 0
        return f"{percent:5.1f}%"

    def _status(self) -> str:
        active = max(0, self.started - self.completed)
        return f"{self._percent()} | {self.completed}/{self.total} done | {active} active"

    @staticmethod
    def _duration(seconds: float) -> str:
        seconds = max(0, int(seconds))
        minutes, remainder = divmod(seconds, 60)
        return f"{minutes}m {remainder:02d}s" if minutes else f"{remainder}s"

    async def _write_locked(self, message: str, **event_data: object) -> None:
        async with self._lock:
            self._write(message, **event_data)

    def _write(self, message: str, **event_data: object) -> None:
        event = ProgressEvent(
            phase="scan",
            target=str(event_data.get("target", "")),
            message=message,
            completed=event_data.get("completed"),
            total=event_data.get("total"),
            kind=event_data.get("kind", EventKind.MESSAGE),
            status=event_data.get("status"),
            payload=event_data.get("payload", {}),
        )
        self.sink.emit(event)
        if self.event_sink is not None:
            self.event_sink.emit(event.to_app_event())