"""Small, deterministic runtime primitives for tool-calling agents."""

from __future__ import annotations

import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

logger = logging.getLogger(__name__)

OperationResult = TypeVar("OperationResult")
ToolHandler = Callable[[str, Mapping[str, Any]], str]


@dataclass
class MessageRouter:
    """Own provider message ordering for one model invocation."""

    messages: list[Any] = field(default_factory=list)

    def append_assistant(self, items: Sequence[Any]) -> None:
        self.messages.extend(items)

    def append_tool_results(self, items: Sequence[Any]) -> None:
        self.messages.extend(items)


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
            expected = properties.get(key, {}).get("type")
            if expected == "string" and not isinstance(value, str):
                raise ValueError(f"tool '{name}' argument '{key}' must be a string")
            if expected == "integer" and (not isinstance(value, int) or isinstance(value, bool)):
                raise ValueError(f"tool '{name}' argument '{key}' must be an integer")


class ToolInvoker:
    """Invoke only validated, allow-listed tools."""

    def __init__(self, handler: ToolHandler) -> None:
        self._handler = handler

    def invoke(self, call: BoundCall) -> str:
        try:
            output = self._handler(call.name, call.arguments)
            return output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
        except Exception as exc:
            logger.exception("Tool '%s' failed", call.name)
            return json.dumps({"error": f"Tool '{call.name}' failed: {exc}"})


class RetryController:
    """Retry transient operations with bounded exponential backoff."""

    def __init__(
        self,
        retryable: Callable[[Exception], bool],
        max_attempts: int = 3,
        base_delay: float = 2.0,
    ) -> None:
        self.retryable = retryable
        self.max_attempts = max(1, max_attempts)
        self.base_delay = max(0.0, base_delay)

    async def run(
        self,
        operation: Callable[[], Awaitable[OperationResult]],
        on_retry: Callable[[int, Exception, float], None] | None = None,
    ) -> OperationResult:
        import asyncio

        for attempt in range(1, self.max_attempts + 1):
            try:
                return await operation()
            except Exception as exc:
                if attempt == self.max_attempts or not self.retryable(exc):
                    raise
                delay = self.base_delay * (2 ** (attempt - 1))
                if on_retry:
                    on_retry(attempt, exc, delay)
                await asyncio.sleep(delay)
        raise AssertionError("retry controller exited without a result")


@dataclass
class InvocationLog:
    """Invocation-local records, safe to use for concurrent agent calls."""

    records: list[dict[str, Any]] = field(default_factory=list)

    def record(self, **values: Any) -> None:
        self.records.append(dict(values))


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

            return await self.llm.execute_task(
                **request,
            )

        return await operation()
