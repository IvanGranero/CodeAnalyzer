"""Small, deterministic runtime primitives for tool-calling agents."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger(__name__)

ToolHandler = Callable[[str, Mapping[str, Any]], str]


@dataclass(frozen=True)
class BoundCall:
    """Validated provider tool-call data."""

    call_id: str
    name: str
    arguments: dict[str, Any]


class CallBinder:
    """Validate tool names, call IDs, arguments, and result binding."""

    def __init__(self, definitions: Sequence[Mapping[str, Any]]) -> None:
        self._schemas: dict[str, Mapping[str, Any]] = {}
        for definition in definitions:
            function = definition.get("function", definition)
            name = function.get("name")
            if name:
                self._schemas[str(name)] = function.get("parameters", {})
        self._seen_ids: set[str] = set()

    def bind(self, call_id: Any, name: Any, raw_arguments: Any) -> BoundCall:
        if not isinstance(call_id, str) or not call_id.strip():
            raise ValueError("tool call is missing a call ID")
        if call_id in self._seen_ids:
            raise ValueError(f"duplicate tool call ID: {call_id}")
        if not isinstance(name, str) or name not in self._schemas:
            raise ValueError(f"tool is not allow-listed: {name!r}")
        try:
            arguments = json.loads(raw_arguments or "{}") if isinstance(raw_arguments, str) else raw_arguments
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid arguments for tool '{name}': {exc}") from exc
        if not isinstance(arguments, dict):
            raise ValueError(f"arguments for tool '{name}' must be an object")
        self._validate_schema(name, arguments)
        self._seen_ids.add(call_id)
        return BoundCall(call_id, name, arguments)

    def result(self, call: BoundCall, output: str) -> dict[str, str]:
        return {
            "type": "function_call_output",
            "call_id": call.call_id,
            "output": output,
        }

    def legacy_result(self, call: BoundCall, output: str) -> dict[str, str]:
        return {
            "role": "tool",
            "tool_call_id": call.call_id,
            "content": output,
        }

    def _validate_schema(self, name: str, arguments: Mapping[str, Any]) -> None:
        schema = self._schemas[name]
        if not schema:
            return
        properties = schema.get("properties", {})
        required = schema.get("required", [])
        missing = [key for key in required if key not in arguments]
        if missing:
            raise ValueError(f"tool '{name}' is missing required arguments: {missing}")
        unknown = [key for key in arguments if key not in properties]
        if unknown and schema.get("additionalProperties", False) is False:
            raise ValueError(f"tool '{name}' received unknown arguments: {unknown}")
        for key, value in arguments.items():
            property_schema = properties.get(key, {})
            expected = property_schema.get("type")
            if expected == "string" and not isinstance(value, str):
                raise ValueError(f"tool '{name}' argument '{key}' must be a string")
            if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
                raise ValueError(f"tool '{name}' argument '{key}' must be an integer")
            allowed = property_schema.get("enum")
            if allowed is not None and value not in allowed:
                raise ValueError(f"tool '{name}' argument '{key}' must be one of {allowed}")
            if expected == "integer":
                minimum = property_schema.get("minimum")
                maximum = property_schema.get("maximum")
                if minimum is not None and value < minimum:
                    raise ValueError(f"tool '{name}' argument '{key}' must be >= {minimum}")
                if maximum is not None and value > maximum:
                    raise ValueError(f"tool '{name}' argument '{key}' must be <= {maximum}")


class AgentRuntime:
    """Execute agent tasks with tools and invocation-local metadata."""

    def __init__(self, llm: Any, tool_registry: Any = None) -> None:
        self.llm = llm
        self.tool_registry = tool_registry

    @property
    def tracker(self) -> Any:
        return self.llm.tracker

    async def execute(
        self,
        task_name: str,
        kwargs: Mapping[str, Any],
        context_id: str,
        settings_override: Mapping[str, Any] | None = None,
        enable_tools: bool = True,
        tool_registry: Any = None,
        preloaded_messages=None,
    ) -> str:
        registry = tool_registry if tool_registry is not None else self.tool_registry

        async def operation() -> str:
            use_tools = enable_tools and registry is not None
            request = {
                "task_name": task_name,
                "context_id": context_id,
                "kwargs": kwargs,
            }
            if settings_override is not None:
                request["settings_override"] = settings_override
            if use_tools:
                request["tools"] = registry.definitions()
                request["tool_handler"] = registry.call
            if preloaded_messages is not None:
                request["preloaded_messages"] = preloaded_messages

            return await self.llm.execute_task(
                **request,
            )

        return await operation()
