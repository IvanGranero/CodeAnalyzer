from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import random
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from openai import AsyncOpenAI

from app.errors import is_retryable

logger = logging.getLogger(__name__)

ToolDefinition = Mapping[str, Any]
ToolHandler = Callable[[str, Mapping[str, Any]], str]
UsageCallback = Callable[[Mapping[str, Any], float], None | Awaitable[None]]
ChatMessage = Mapping[str, Any]

_TOOL_LIMIT_NOTICE = (
    "The bounded evidence budget of {limit} tool calls is exhausted. "
    "Do not call tools. Return the complete final JSON decision now using the evidence already supplied."
)


class EmptyLLMResponseError(RuntimeError):
    """The provider returned no assistant content after a successful request."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


def _jsonable(value: Any) -> Any:
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if hasattr(value, "__dict__"):
        return {str(key): _jsonable(item) for key, item in vars(value).items() if not key.startswith("_")}
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value if value is None or isinstance(value, (str, int, float, bool)) else str(value)


class LLMClient:
    """Raw-SDK LLM client retaining the application's stable contract."""

    def __init__(
        self,
        api_key: str,
        model_name: str,
        deployment: str,
        base_url: str,
        default_headers: str = "",
        api_version: str = "",
        api_style: str = "chat_completions",
        audit_log_dir: str = "logs/llm_audit",
    ) -> None:
        self.api_keys = [key.strip() for key in api_key.split(",") if key.strip()]
        if not self.api_keys:
            raise ValueError("At least one non-empty LLM API key is required")
        self.model_name = model_name
        self.deployment = deployment
        self.base_url = base_url.rstrip("/")
        self.default_headers = self._parse_pairs(default_headers)
        self.api_version = api_version
        self.api_style = api_style
        self.audit_log_dir = audit_log_dir
        os.makedirs(self.audit_log_dir, exist_ok=True)
        self._current_index = 0

        stripped_name = model_name.split("/", 1)[1] if "/" in model_name else model_name
        self._request_model_name = deployment or stripped_name
        self._request_base_url = f"{self.base_url}/{deployment}" if deployment else self.base_url
        default_query = {"api-version": api_version} if api_version else None

        # Built once and reused across calls: a fresh AsyncOpenAI (and its
        # underlying httpx connection pool) no longer gets constructed per request.
        self._clients: dict[str, AsyncOpenAI] = {
            key: AsyncOpenAI(
                api_key=key,
                base_url=self._request_base_url,
                default_headers=self.default_headers or None,
                default_query=default_query,
                timeout=300.0,
                max_retries=0,
            )
            for key in self.api_keys
        }
        logger.info(
            "Initialized %s LLM client (api_style=%s, %d key(s)) -> %s",
            model_name,
            api_style,
            len(self.api_keys),
            self._request_base_url,
        )

    async def aclose(self) -> None:
        """Release pooled HTTP connections. Call once during app shutdown."""
        for client in self._clients.values():
            await client.close()

    @staticmethod
    def _parse_pairs(value: str) -> dict[str, str]:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if len(parts) % 2:
            raise ValueError("Configuration pairs must contain comma-separated key/value pairs")
        return dict(zip(parts[::2], parts[1::2]))

    def _next_client(self) -> AsyncOpenAI:
        api_key = self.api_keys[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.api_keys)
        return self._clients[api_key]

    def _build_request_kwargs(self, settings: Mapping[str, Any]) -> dict[str, Any]:
        kwargs: dict[str, Any] = {"model": self._request_model_name}

        max_tokens = settings.get("max_completion_tokens", settings.get("max_tokens"))
        if max_tokens is not None:
            key = "max_output_tokens" if self.api_style == "responses" else "max_completion_tokens"
            kwargs[key] = max_tokens

        reasoning_effort = settings.get("reasoning_effort")
        if reasoning_effort is not None:
            if self.api_style == "responses":
                kwargs["reasoning"] = {"effort": reasoning_effort}
            else:
                kwargs["reasoning_effort"] = reasoning_effort

        is_deepseek = "deepseek" in self._request_model_name.lower() or "deepseek" in self.model_name.lower()
        if settings.get("response_format") == "json_object" and not is_deepseek:
            if self.api_style == "responses":
                kwargs["text"] = {"format": {"type": "json_object"}}
            else:
                kwargs["response_format"] = {"type": "json_object"}

        return kwargs

    @staticmethod
    def _tool_schema(definition: ToolDefinition) -> tuple[str, str, Mapping[str, Any]]:
        function = definition.get("function", definition)
        return (
            str(function["name"]),
            str(function.get("description", "")),
            function.get("parameters", {}) or {},
        )

    @staticmethod
    def _make_strict(schema: Mapping[str, Any]) -> dict[str, Any]:
        """Best-effort adaptation of a JSON schema to OpenAI strict function-calling
        rules: every property must be listed as required, and optional fields are
        made nullable so omission is still expressible (mirrors the old
        Optional[..., default=None] pydantic behavior)."""
        schema = dict(schema)
        properties = dict(schema.get("properties", {}) or {})
        required = set(schema.get("required", []) or [])
        for key, prop_schema in list(properties.items()):
            prop_schema = dict(prop_schema)
            if key not in required:
                existing_type = prop_schema.get("type")
                if isinstance(existing_type, str) and existing_type != "null":
                    prop_schema["type"] = [existing_type, "null"]
                elif isinstance(existing_type, list) and "null" not in existing_type:
                    prop_schema["type"] = [*existing_type, "null"]
            properties[key] = prop_schema
        schema["type"] = schema.get("type", "object")
        schema["properties"] = properties
        schema["required"] = list(properties.keys())
        schema["additionalProperties"] = False
        return schema

    def _tool_specs(self, definitions: Sequence[ToolDefinition], *, strict: bool) -> list[dict[str, Any]]:
        specs = []
        for definition in definitions:
            name, description, schema = self._tool_schema(definition)
            schema = dict(schema or {"type": "object", "properties": {}})
            if strict:
                schema = self._make_strict(schema)
            if self.api_style == "responses":
                spec: dict[str, Any] = {
                    "type": "function",
                    "name": name,
                    "description": description or name,
                    "parameters": schema,
                }
                if strict:
                    spec["strict"] = True
            else:
                spec = {
                    "type": "function",
                    "function": {
                        "name": name,
                        "description": description or name,
                        "parameters": schema,
                    },
                }
                if strict:
                    spec["function"]["strict"] = True
            specs.append(spec)
        return specs

    @staticmethod
    def _safe_json_loads(raw: str | None) -> dict[str, Any]:
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except (TypeError, json.JSONDecodeError):
            logger.warning("Tool call arguments were not valid JSON: %r", raw)
            return {}

    @staticmethod
    def _invoke_tool_handler(handler: ToolHandler, name: str, arguments: Mapping[str, Any]) -> str:
        try:
            output = handler(name, arguments)
            return output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
        except Exception as exc:
            logger.exception("Tool '%s' failed", name)
            return json.dumps({"error": f"Tool '{name}' failed: {exc}"})

    async def _with_retries(
        self,
        coro_factory: Callable[[], Awaitable[Any]],
        *,
        attempts: int = 3,
        base_delay: float = 1.0,
    ) -> Any:
        delay = base_delay
        for attempt in range(1, attempts + 1):
            try:
                return await coro_factory()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if attempt >= attempts or not is_retryable(exc):
                    raise
                jittered = delay * (1 + random.random())
                logger.warning(
                    "Transient provider error on attempt %d/%d (%s); retrying in %.1fs: %s",
                    attempt,
                    attempts,
                    type(exc).__name__,
                    jittered,
                    exc,
                )
                await asyncio.sleep(jittered)
                delay *= 2

    # ---- Chat Completions style tool loop ----------------------------------

    async def _run_tool_loop_chat(
        self,
        client: AsyncOpenAI,
        messages: list[ChatMessage],
        tool_specs: list[dict[str, Any]],
        tool_handler: ToolHandler,
        request_kwargs: Mapping[str, Any],
        max_tool_calls: int,
    ) -> tuple[str, Any, list[dict[str, Any]]]:
        conversation = list(messages)
        tool_actions: list[dict[str, Any]] = []
        calls_used = 0

        while True:
            response = await self._with_retries(
                lambda: client.chat.completions.create(messages=conversation, tools=tool_specs, **request_kwargs)
            )
            message = response.choices[0].message
            if not message.tool_calls:
                return message.content or "", response, tool_actions
            if calls_used + len(message.tool_calls) > max_tool_calls:
                return await self._finalize_chat(client, conversation, tool_actions, request_kwargs, max_tool_calls)

            conversation.append({
                "role": "assistant",
                "content": message.content,
                "tool_calls": [
                    {
                        "id": call.id,
                        "type": "function",
                        "function": {"name": call.function.name, "arguments": call.function.arguments},
                    }
                    for call in message.tool_calls
                ],
            })
            for call in message.tool_calls:
                args = self._safe_json_loads(call.function.arguments)
                output = self._invoke_tool_handler(tool_handler, call.function.name, args)
                conversation.append({"role": "tool", "tool_call_id": call.id, "content": output})
                tool_actions.append({
                    "name": call.function.name,
                    "arguments": args,
                    "output": output,
                    "tool_call_id": call.id,
                })
                calls_used += 1

            if calls_used >= max_tool_calls:
                return await self._finalize_chat(client, conversation, tool_actions, request_kwargs, max_tool_calls)

    async def _finalize_chat(
        self,
        client: AsyncOpenAI,
        conversation: list[ChatMessage],
        tool_actions: list[dict[str, Any]],
        request_kwargs: Mapping[str, Any],
        max_tool_calls: int,
    ) -> tuple[str, Any, list[dict[str, Any]]]:
        final_prompt = {"role": "user", "content": _TOOL_LIMIT_NOTICE.format(limit=max_tool_calls)}
        response = await self._with_retries(
            lambda: client.chat.completions.create(messages=[*conversation, final_prompt], **request_kwargs)
        )
        return response.choices[0].message.content or "", response, tool_actions

    async def _single_tool_call_chat(
        self,
        client: AsyncOpenAI,
        messages: list[ChatMessage],
        tool_specs: list[dict[str, Any]],
        tool_handler: ToolHandler,
        request_kwargs: Mapping[str, Any],
    ) -> tuple[str, Any, list[dict[str, Any]]]:
        response = await self._with_retries(
            lambda: client.chat.completions.create(messages=messages, tools=tool_specs, **request_kwargs)
        )
        message = response.choices[0].message
        tool_actions: list[dict[str, Any]] = []
        for call in message.tool_calls or []:
            args = self._safe_json_loads(call.function.arguments)
            tool_actions.append({"name": call.function.name, "arguments": args, "tool_call_id": call.id})
            tool_handler(call.function.name, args)  # fire-and-forget, matches prior behavior
        return message.content or "", response, tool_actions

    # ---- Responses API style tool loop --------------------------------------
    # Uses `previous_response_id` for multi-turn continuation instead of
    # manually replaying the whole output array back as input.

    async def _run_tool_loop_responses(
        self,
        client: AsyncOpenAI,
        messages: list[ChatMessage],
        tool_specs: list[dict[str, Any]],
        tool_handler: ToolHandler,
        request_kwargs: Mapping[str, Any],
        max_tool_calls: int,
    ) -> tuple[str, Any, list[dict[str, Any]]]:
        current_input: list[Any] = list(messages)
        previous_response_id: str | None = None
        tool_actions: list[dict[str, Any]] = []
        calls_used = 0

        while True:
            call_kwargs = dict(request_kwargs)
            if previous_response_id:
                call_kwargs["previous_response_id"] = previous_response_id
            response = await self._with_retries(
                lambda: client.responses.create(input=current_input, tools=tool_specs, **call_kwargs)
            )
            previous_response_id = response.id
            function_calls = [item for item in response.output if getattr(item, "type", None) == "function_call"]
            if not function_calls:
                return response.output_text or "", response, tool_actions
            if calls_used + len(function_calls) > max_tool_calls:
                return await self._finalize_responses(
                    client, previous_response_id, tool_actions, request_kwargs, max_tool_calls
                )

            current_input = []
            for call in function_calls:
                args = self._safe_json_loads(call.arguments)
                output = self._invoke_tool_handler(tool_handler, call.name, args)
                current_input.append({"type": "function_call_output", "call_id": call.call_id, "output": output})
                tool_actions.append({
                    "name": call.name,
                    "arguments": args,
                    "output": output,
                    "call_id": call.call_id,
                })
                calls_used += 1

            if calls_used >= max_tool_calls:
                return await self._finalize_responses(
                    client, previous_response_id, tool_actions, request_kwargs, max_tool_calls
                )

    async def _finalize_responses(
        self,
        client: AsyncOpenAI,
        previous_response_id: str | None,
        tool_actions: list[dict[str, Any]],
        request_kwargs: Mapping[str, Any],
        max_tool_calls: int,
    ) -> tuple[str, Any, list[dict[str, Any]]]:
        final_text = _TOOL_LIMIT_NOTICE.format(limit=max_tool_calls)
        response = await self._with_retries(
            lambda: client.responses.create(
                input=[{"role": "user", "content": final_text}],
                previous_response_id=previous_response_id,
                **request_kwargs,
            )
        )
        return response.output_text or "", response, tool_actions

    async def _single_tool_call_responses(
        self,
        client: AsyncOpenAI,
        messages: list[ChatMessage],
        tool_specs: list[dict[str, Any]],
        tool_handler: ToolHandler,
        request_kwargs: Mapping[str, Any],
    ) -> tuple[str, Any, list[dict[str, Any]]]:
        response = await self._with_retries(
            lambda: client.responses.create(input=messages, tools=tool_specs, **request_kwargs)
        )
        tool_actions: list[dict[str, Any]] = []
        for item in response.output:
            if getattr(item, "type", None) != "function_call":
                continue
            args = self._safe_json_loads(item.arguments)
            tool_actions.append({"name": item.name, "arguments": args, "call_id": item.call_id})
            tool_handler(item.name, args)  # fire-and-forget, matches prior behavior
        return response.output_text or "", response, tool_actions

    # ---- Usage normalization -------------------------------------------------

    @staticmethod
    def _normalize_usage(usage: Any) -> dict[str, Any]:
        """Map a Chat Completions or Responses API usage object onto the same
        shape LangChain's UsageMetadata used, so TokenTracker keeps working
        unmodified. Verify this against llm/tracker.py's expectations."""
        if usage is None:
            return {}
        data = usage.model_dump() if hasattr(usage, "model_dump") else dict(usage)

        input_tokens = data.get("input_tokens", data.get("prompt_tokens", 0)) or 0
        output_tokens = data.get("output_tokens", data.get("completion_tokens", 0)) or 0
        total_tokens = data.get("total_tokens", input_tokens + output_tokens) or 0

        input_details = data.get("input_tokens_details") or data.get("prompt_tokens_details") or {}
        output_details = data.get("output_tokens_details") or data.get("completion_tokens_details") or {}
        cached = input_details.get("cached_tokens", 0) or 0
        reasoning = output_details.get("reasoning_tokens", 0) or 0

        return {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "input_token_details": {"cache_read": cached},
            "output_token_details": {"reasoning": reasoning},
        }

    # ---- Public entrypoint ----------------------------------------------------

    async def generate_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model_settings: Mapping[str, Any] | None = None,
        context_id: str | None = None,
        tools: Sequence[ToolDefinition] | None = None,
        tool_handler: ToolHandler | None = None,
        audit_metadata: Mapping[str, Any] | None = None,
        preloaded_messages: Sequence[ChatMessage] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        settings = model_settings or {}
        client = self._next_client()
        request_kwargs = self._build_request_kwargs(settings)
        max_tool_calls = int(settings.get("max_tool_calls", 6))

        messages: list[ChatMessage] = [
            {"role": "system", "content": system_prompt},
            *(preloaded_messages or []),
            {"role": "user", "content": user_prompt},
        ]

        tool_actions: list[dict[str, Any]] = []
        response_obj: Any = None

        if tools and tool_handler:
            single = bool(settings.get("single_tool_call"))
            tool_specs = self._tool_specs(tools, strict=not single)
            if self.api_style == "responses":
                if single:
                    text, response_obj, tool_actions = await self._single_tool_call_responses(
                        client, messages, tool_specs, tool_handler, request_kwargs
                    )
                else:
                    text, response_obj, tool_actions = await self._run_tool_loop_responses(
                        client, messages, tool_specs, tool_handler, request_kwargs, max_tool_calls
                    )
            else:
                if single:
                    text, response_obj, tool_actions = await self._single_tool_call_chat(
                        client, messages, tool_specs, tool_handler, request_kwargs
                    )
                else:
                    text, response_obj, tool_actions = await self._run_tool_loop_chat(
                        client, messages, tool_specs, tool_handler, request_kwargs, max_tool_calls
                    )
        else:
            if self.api_style == "responses":
                response_obj = await self._with_retries(
                    lambda: client.responses.create(input=messages, **request_kwargs)
                )
                text = response_obj.output_text or ""
            else:
                response_obj = await self._with_retries(
                    lambda: client.chat.completions.create(messages=messages, **request_kwargs)
                )
                text = response_obj.choices[0].message.content or ""

        if (not isinstance(text, str) or not text.strip()) and tool_actions:
            # Some models finish after a function call with no prose turn.
            # The tool result is the useful output.
            text = "{}"
        if not isinstance(text, str) or not text.strip():
            self._audit_log(messages, "", context_id, tool_actions, audit_metadata, response_obj=response_obj)
            raise EmptyLLMResponseError(f"empty_response: {self.model_name} returned no assistant content")

        usage = self._normalize_usage(getattr(response_obj, "usage", None))
        self._audit_log(messages, text, context_id, tool_actions, audit_metadata, response_obj=response_obj)
        return text, usage

    def _audit_log(
        self,
        messages: Sequence[ChatMessage],
        response_text: str,
        context_id: str | None,
        tool_actions: Sequence[Any],
        audit_metadata: Mapping[str, Any] | None,
        response_obj: Any = None,
    ) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        context = context_id or "unknown_target"
        safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in context)
        digest = hashlib.sha256(context.encode("utf-8")).hexdigest()[:12]
        filename = os.path.join(self.audit_log_dir, f"{safe_name}-{digest}.txt")
        endpoint = "/responses" if self.api_style == "responses" else "/chat/completions"
        log_content = (
            "==================================================\n"
            f"TIMESTAMP: {timestamp}\n"
            f"MODEL: {self.model_name} (request model: {self._request_model_name})\n"
            f"ENDPOINT USED: {endpoint} @ {self._request_base_url}\n"
            "==================================================\n"
            "=== RAW INPUT (MESSAGES) ===\n"
            f"{json.dumps(_jsonable(list(messages)), indent=2, ensure_ascii=False)}\n\n"
            "=== RAW OUTPUT (ASSISTANT TEXT) ===\n"
            f"{response_text}\n\n"
        )
        if response_obj is not None:
            log_content += (
                "=== RAW RESPONSE OBJECT ===\n"
                f"{json.dumps(_jsonable(response_obj), indent=2, ensure_ascii=False)}\n\n"
            )
        if audit_metadata:
            log_content += f"=== INVOCATION METADATA ===\n{json.dumps(dict(audit_metadata), indent=2, ensure_ascii=False)}\n\n"
        if tool_actions:
            log_content += f"=== TOOL CALLS ===\n{json.dumps(_jsonable(list(tool_actions)), indent=2, ensure_ascii=False)}\n\n"
        try:
            with open(filename, "a", encoding="utf-8") as file:
                file.write(log_content)
        except OSError as exc:
            logger.error("Failed to write LLM audit log: %s", exc)
