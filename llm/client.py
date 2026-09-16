from email.mime import message
import os
import json
import logging
import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from typing import Any, TypeVar
import openai
from openai import AsyncOpenAI, APIConnectionError
from llm.runtime import CallBinder, InvocationLog, MessageRouter, RetryController, ToolInvoker

logger = logging.getLogger(__name__)
ResponseT = TypeVar("ResponseT")
ToolDefinition = Mapping[str, Any]
ToolHandler = Callable[[str, Mapping[str, Any]], str]
UsageCallback = Callable[[Mapping[str, Any], float], None | Awaitable[None]]


class EmptyLLMResponseError(RuntimeError):
    """The provider returned no assistant content after a successful request."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable

class LLMClient:
    def __init__(
        self,
        api_key: str,
        model_name: str,
        base_url: str,
        default_headers: str = "",
        extra_query: str = "",
        audit_log_dir: str = "logs/llm_audit",
    ):
        self.api_keys = [k.strip() for k in api_key.split(",") if k.strip()]
        if not self.api_keys:
            raise ValueError("At least one non-empty LLM API key is required")
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.default_headers = self._parse_pairs(default_headers)
        self.extra_query = self._parse_pairs(extra_query)
        self.audit_log_dir = audit_log_dir
        os.makedirs(self.audit_log_dir, exist_ok=True)

        self._use_legacy_endpoint = False
        self._endpoint_probe_complete = False
        self._endpoint_probe_lock = asyncio.Lock()
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_audit_file = os.path.join(self.audit_log_dir, f"llm_session_{timestamp}.txt")

        self.clients = []
        for key in self.api_keys:
            headers = self.default_headers.copy()
            query_params = self.extra_query.copy()

            self.clients.append(
                AsyncOpenAI(
                    base_url=self.base_url,
                    api_key=key,
                    default_headers=headers,
                    default_query=query_params if query_params else None,
                    timeout=300.0
                )
            )

        self._current_index = 0
        logger.info(f"Initialized {self.model_name} LLMClient with {len(self.clients)} keys.")

    @staticmethod
    def _parse_pairs(value: str) -> dict[str, str]:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if len(parts) % 2:
            raise ValueError("Configuration pairs must contain comma-separated key/value pairs")
        return dict(zip(parts[::2], parts[1::2]))

    def _audit_log(
        self,
        kwargs: Mapping[str, Any],
        response_content: str,
        endpoint_used: str,
        context_id: str | None = None,
        tool_calls: Sequence[Mapping[str, Any]] | None = None,
        audit_metadata: Mapping[str, Any] | None = None,
    ) -> None:
        """Saves the exact API payload and response to disk for debugging/auditing."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        context = context_id or "unknown_target"
        safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in context)
        digest = hashlib.sha256(context.encode("utf-8")).hexdigest()[:12]
        filename = os.path.join(self.audit_log_dir, f"{safe_name}-{digest}.txt")

        log_content = (
            f"==================================================\n"
            f"TIMESTAMP: {timestamp}\n"
            f"MODEL: {self.model_name}\n"
            f"ENDPOINT USED: {endpoint_used}\n"
            f"==================================================\n"
            f"=== RAW INPUT (API PAYLOAD) ===\n"
            f"{json.dumps(kwargs, indent=2)}\n\n"
            f"=== RAW OUTPUT (LLM RESPONSE) ===\n"
            f"{response_content}\n\n\n"
        )
        if audit_metadata:
            log_content += (
                "=== INVOCATION METADATA ===\n"
                f"{json.dumps(dict(audit_metadata), indent=2, ensure_ascii=False)}\n\n\n"
            )
        if tool_calls:
            log_content += (
                "=== TOOL CALLS (RUNTIME) ===\n"
                f"{json.dumps(list(tool_calls), indent=2, ensure_ascii=False)}\n\n\n"
            )
        try:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(log_content)
        except Exception as e:
            logger.error(f"Failed to write LLM audit log: {e}")

    async def generate_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model_settings: Mapping[str, Any] | None = None,
        context_id: str | None = None,
        tools: Sequence[ToolDefinition] | None = None,
        tool_handler: ToolHandler | None = None,
        audit_metadata: Mapping[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Generate a response using the configured endpoint and tool handler."""
        model_settings = model_settings or {}

        client = self.clients[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.clients)

        if self._use_legacy_endpoint:
            return await self._execute_legacy_chat(
                client, system_prompt, user_prompt, model_settings,
                context_id, tools, tool_handler, audit_metadata=audit_metadata,
            )

        kwargs_responses = {
            "model": self.model_name,
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }
        if tools:
            kwargs_responses["tools"] = tools
        # NOTE: the /responses API uses `max_output_tokens`, not `max_tokens`/
        # `max_completion_tokens`. Callers (see llm/prompts.json's model_settings) set
        # `max_completion_tokens` and `reasoning_effort`; previously only `max_tokens` was
        # forwarded here, so both were silently dropped on every call and every deep-scan
        # ran at whatever the provider's default reasoning effort happens to be.
        if "max_completion_tokens" in model_settings:
            kwargs_responses["max_output_tokens"] = model_settings["max_completion_tokens"]
        elif "max_tokens" in model_settings:
            kwargs_responses["max_output_tokens"] = model_settings["max_tokens"]
        if model_settings.get("reasoning_effort") is not None:
            kwargs_responses["reasoning"] = {"effort": model_settings["reasoning_effort"]}
        if model_settings.get("response_format") == "json_object":
            kwargs_responses["text"] = {"format": {"type": "json_object"}}

        if self._use_legacy_endpoint:
            return await self._execute_legacy_chat(
                client, system_prompt, user_prompt, model_settings,
                context_id, tools, tool_handler, audit_metadata=audit_metadata,
            )

        async def request_response_text() -> tuple[str, dict[str, Any], list[dict[str, Any]]]:
            response, tool_calls = await self._request_responses(
                client, kwargs_responses, tool_handler
            )
            return self._response_text(response, "Frontier"), self._usage_dict(response), tool_calls

        if not self._endpoint_probe_complete:
            async with self._endpoint_probe_lock:
                if self._use_legacy_endpoint:
                    return await self._execute_legacy_chat(
                        client, system_prompt, user_prompt, model_settings,
                        context_id, tools, tool_handler, audit_metadata=audit_metadata,
                    )
                if not self._endpoint_probe_complete:
                    try:
                        final_text, usage_dict, tool_calls = await self._retry_request(
                            request_response_text,
                            endpoint="/responses",
                        )
                        self._endpoint_probe_complete = True
                    except openai.NotFoundError:
                        logger.warning("[LLM] /responses returned 404; using /chat/completions for this client")
                        self._use_legacy_endpoint = True
                        self._endpoint_probe_complete = True
                        try:
                            return await self._execute_legacy_chat(
                                client, system_prompt, user_prompt, model_settings,
                                context_id, tools, tool_handler, audit_metadata=audit_metadata,
                            )
                        except openai.NotFoundError as exc:
                            raise RuntimeError(
                                f"LLM endpoint not found at '{self.base_url}'. "
                                "Both /responses and /chat/completions returned 404; "
                                "check the configured base URL and model endpoint."
                            ) from exc

        if self._use_legacy_endpoint:
            return await self._execute_legacy_chat(
                client, system_prompt, user_prompt, model_settings,
                context_id, tools, tool_handler, audit_metadata=audit_metadata,
            )
        if not self._endpoint_probe_complete:
            raise RuntimeError("LLM endpoint probe completed without selecting an endpoint")
        try:
            final_text, usage_dict, tool_calls = await self._retry_request(
                request_response_text,
                endpoint="/responses",
            )
        except openai.NotFoundError:
            logger.warning("[LLM] /responses became unavailable; using /chat/completions for this client")
            self._use_legacy_endpoint = True
            self._endpoint_probe_complete = True
            return await self._execute_legacy_chat(
                client, system_prompt, user_prompt, model_settings,
                context_id, tools, tool_handler, audit_metadata=audit_metadata,
            )

        self._audit_log(
            kwargs_responses, final_text, "/responses", context_id, tool_calls,
            audit_metadata,
        )
        return final_text, usage_dict

    async def _retry_request(
        self,
        operation: Callable[[], Awaitable[ResponseT]],
        *,
        endpoint: str,
        max_retries: int = 3,
    ) -> ResponseT:
        """Retry transient provider failures using exponential backoff."""
        controller = RetryController(self._is_retryable, max_attempts=max_retries)

        def on_retry(attempt: int, exc: Exception, delay: float) -> None:
            logger.warning(
                "[LLM] %s %s (attempt %d/%d); retrying in %.1fs",
                endpoint, exc, attempt, max_retries, delay,
            )

        return await controller.run(operation, on_retry=on_retry)

    @staticmethod
    def _is_retryable(exc: Exception) -> bool:
        if isinstance(exc, EmptyLLMResponseError):
            return exc.retryable
        if isinstance(exc, openai.NotFoundError):
            return False
        if isinstance(exc, (APIConnectionError, openai.RateLimitError)):
            return True
        if isinstance(exc, openai.APIStatusError):
            return exc.status_code in (500, 502, 503, 504)
        message = str(exc).lower()
        return any(marker in message for marker in ("getaddrinfo failed", "connection", "timeout"))

    async def _request_responses(
        self,
        client: Any,
        request_kwargs: dict[str, Any],
        tool_handler: ToolHandler | None,
    ) -> Any:
        router = MessageRouter(list(request_kwargs["input"]))
        binder = CallBinder(request_kwargs.get("tools", []))
        invoker = ToolInvoker(tool_handler) if tool_handler else None
        invocation_log = InvocationLog()
        for _ in range(4):
            response = await client.responses.create(
                **{**request_kwargs, "input": router.messages}
            )
            function_calls = [
                item for item in response.output
                if getattr(item, "type", None) == "function_call"
            ]
            if not function_calls:
                return response, invocation_log.records
            if invoker is None:
                raise RuntimeError("model returned tool calls but no tool handler is configured")
            router.append_assistant(response.output)
            tool_outputs = []
            for call in function_calls:
                bound = binder.bind(call.call_id, call.name, call.arguments)
                output = invoker.invoke(bound)
                invocation_log.record(call_id=bound.call_id, name=bound.name, output_length=len(output))
                tool_outputs.append(binder.result(bound, output))
            router.append_tool_results(tool_outputs)
        raise RuntimeError("Model exceeded the maximum tool-call rounds")

    @staticmethod
    def _usage_dict(response: Any) -> dict[str, Any]:
        usage = getattr(response, "usage", None)
        if not usage:
            return {}
        return usage.model_dump() if hasattr(usage, "model_dump") else vars(usage)

    @staticmethod
    def _response_text(response: Any, model_name: str) -> str:
        for block in response.output:
            if getattr(block, "type", None) == "message":
                content = getattr(block, "content", None) or []
                text = getattr(content[0], "text", "") if content else ""
                if isinstance(text, str) and text.strip():
                    return text
                break
        raise EmptyLLMResponseError(f"empty_response: {model_name} returned no assistant content")

    async def _execute_legacy_chat(
        self,
        client: Any,
        system_prompt: str,
        user_prompt: str,
        model_settings: Mapping[str, Any],
        context_id: str | None = None,
        tools: Sequence[ToolDefinition] | None = None,
        tool_handler: ToolHandler | None = None,
        tool_calls: Sequence[Mapping[str, Any]] | None = None,
        audit_metadata: Mapping[str, Any] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        kwargs_chat = {
            "model": self.model_name,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }

        if "max_completion_tokens" in model_settings:
            kwargs_chat["max_completion_tokens"] = model_settings["max_completion_tokens"]
        elif "max_tokens" in model_settings:
            kwargs_chat["max_tokens"] = model_settings["max_tokens"]
        if model_settings.get("reasoning_effort") is not None:
            kwargs_chat["reasoning_effort"] = model_settings["reasoning_effort"]
        if model_settings.get("response_format") == "json_object":
            kwargs_chat["response_format"] = {"type": "json_object"}
        if tools:
            kwargs_chat["tools"] = [
                {"type": "function", "function": {
                    "name": tool["name"],
                    "description": tool.get("description", ""),
                    "parameters": tool.get("parameters", {}),
                }}
                for tool in tools
            ]

        async def request_legacy_response() -> tuple[Any, dict[str, Any], list[dict[str, Any]]]:
            response, tool_calls = await self._request_legacy_chat(
                client, kwargs_chat, tool_handler
            )
            return response, self._usage_dict(response), tool_calls
        response, usage_dict, tool_calls = await self._retry_request(
            request_legacy_response,
            endpoint="/chat/completions",
        )
        message = response.choices[0].message
        final_text = getattr(message, "content", None)
        if not isinstance(final_text, str) or not final_text.strip():
            finish_reason = getattr(response.choices[0], "finish_reason", None)
            refusal = getattr(message, "refusal", None)
            returned_tool_calls = getattr(message, "tool_calls", None) or []
            details = [f"finish_reason={finish_reason!r}"]
            if refusal:
                details.append(f"refusal={refusal!r}")
            if returned_tool_calls:
                details.append(f"tool_calls={len(returned_tool_calls)}")
            raise EmptyLLMResponseError(
                "empty_response: model returned no assistant content (" + ", ".join(details) + ")",
                retryable=finish_reason not in {"length", "content_filter"},
            )
        self._audit_log(
            kwargs_chat, final_text, "/chat/completions", context_id, tool_calls,
            audit_metadata,
        )
        return final_text, usage_dict

    async def _request_legacy_chat(
        self,
        client: Any,
        request_kwargs: dict[str, Any],
        tool_handler: ToolHandler | None,
    ) -> Any:
        router = MessageRouter(list(request_kwargs["messages"]))
        binder = CallBinder(request_kwargs.get("tools", []))
        invoker = ToolInvoker(tool_handler) if tool_handler else None
        invocation_log = InvocationLog()
        for _ in range(4):
            response = await client.chat.completions.create(
                **{**request_kwargs, "messages": router.messages}
            )
            message = response.choices[0].message
            tool_calls = getattr(message, "tool_calls", None) or []
            if not tool_calls:
                return response, invocation_log.records
            if invoker is None:
                raise RuntimeError("model returned tool calls but no tool handler is configured")
            router.append_assistant([self._legacy_assistant_payload(message)])
            tool_results = []
            for tool_call in tool_calls:
                bound = binder.bind(
                    tool_call.id,
                    tool_call.function.name,
                    tool_call.function.arguments,
                )
                output = invoker.invoke(bound)
                invocation_log.record(
                    call_id=bound.call_id,
                    name=bound.name,
                    output_length=len(output),
                )
                tool_results.append(binder.legacy_result(bound, output))
            router.append_tool_results(tool_results)
        raise RuntimeError("Model exceeded the maximum tool-call rounds")

    @staticmethod
    def _legacy_assistant_payload(message: Any) -> dict[str, Any]:
        """Convert an SDK assistant message into JSON-safe request data."""
        payload: dict[str, Any] = {
            "role": getattr(message, "role", None) or "assistant",
            "content": getattr(message, "content", None),
        }
        tool_calls = []
        for call in getattr(message, "tool_calls", None) or []:
            function = getattr(call, "function", None)
            tool_calls.append(
                {
                    "id": getattr(call, "id", ""),
                    "type": getattr(call, "type", None) or "function",
                    "function": {
                        "name": getattr(function, "name", ""),
                        "arguments": getattr(function, "arguments", ""),
                    },
                }
            )
        if tool_calls:
            payload["tool_calls"] = tool_calls
        return payload
