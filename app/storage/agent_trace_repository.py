"""Durable append-only traces for resumable agent workflows."""

from datetime import datetime, timezone
from typing import Any

from app.storage.json_file_store import JsonFileStore


class AgentTraceRepository:
    """Persist ordered agent turns without coupling storage to an agent implementation."""

    def __init__(self, directory: str):
        self.store = JsonFileStore(directory)

    def load(self, trace_id: str) -> dict[str, Any]:
        try:
            value = self.store.load(self._name(trace_id))
        except FileNotFoundError:
            return self._empty(trace_id)
        if value.get("schema_version") != "1.0":
            return self._empty(trace_id)
        value.setdefault("turns", [])
        return value

    def append(
        self,
        trace_id: str,
        *,
        phase: str,
        target: str,
        turn_id: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        trace = self.load(trace_id)
        trace["turns"].append({
            "turn_id": turn_id,
            "phase": phase,
            "target": target,
            "record": record,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        })
        self.store.save(self._name(trace_id), trace)
        return trace

    @staticmethod
    def _empty(trace_id: str) -> dict[str, Any]:
        return {"schema_version": "1.0", "trace_id": trace_id, "turns": []}

    @staticmethod
    def _name(trace_id: str) -> str:
        safe = "".join(character if character.isalnum() or character in "._-" else "_" for character in trace_id)
        return f"agent-trace-{safe}"
