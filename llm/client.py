import os
import json
import logging
import asyncio
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from typing import Any, TypeVar
import openai
from openai import AsyncOpenAI, APIConnectionError

logger = logging.getLogger(__name__)
ResponseT = TypeVar("ResponseT")
ToolDefinition = Mapping[str, Any]
ToolHandler = Callable[[str, Mapping[str, Any]], str]
UsageCallback = Callable[[Mapping[str, Any], float], None | Awaitable[None]]

class LLMClient:
    def __init__(
        self, 
        api_key: str, 
        model_name: str, 
        base_url: str, 
        api_version: str = "",
        api_key_header: str = "",
        audit_log_dir: str = "logs/llm_audit"
    ):
        self.api_keys = [k.strip() for k in api_key.split(",") if k.strip()]
        if not self.api_keys:
            raise ValueError("At least one non-empty LLM API key is required")
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.api_version = api_version
        
        self.api_key_header = api_key_header.strip() if api_key_header.strip() else "api-key"
        self.audit_log_dir = audit_log_dir
        os.makedirs(self.audit_log_dir, exist_ok=True)
        
        self._use_legacy_endpoint = False
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_audit_file = os.path.join(self.audit_log_dir, f"llm_session_{timestamp}.txt")
                
        self.clients = []
        for key in self.api_keys:
            headers = {self.api_key_header: key}
            query_params = {}
            
            if self.api_version:
                query_params["api-version"] = self.api_version
                
            self.clients.append(
                AsyncOpenAI(
                    base_url=self.base_url,
                    api_key=key,
                    default_headers=headers,
                    default_query=query_params if query_params else None,
                    # 60s was too short for deep_scan_agent's reasoning_effort="high" +
                    # max_completion_tokens=16000 calls -- confirmed against a real run:
                    # every deep_scan call for a "gpt-5.6-luna" reasoning model timed out
                    # at exactly 60.06s (openai SDK's own "Retrying request in Ns" log,
                    # httpx read timeout), then kept re-timing-out through both the SDK's
                    # internal retry and this client's own retry loop below, since the
                    # ceiling itself -- not a transient blip -- was the bottleneck. Cheap
                    # tasks (triage_agent: reasoning_effort="low", 4096 tokens) finish in
                    # ~15-18s regardless, so a generous shared ceiling costs them nothing.
                    timeout=300.0
                )
            )
            
        self._current_index = 0
        logger.info(f"Initialized LLMClient with {len(self.clients)} keys. Auth Header: '{self.api_key_header}'")

    def _audit_log(
        self,
        kwargs: Mapping[str, Any],
        response_content: str,
        endpoint_used: str,
        context_id: str | None = None,
    ) -> None:
        """Saves the exact API payload and response to disk for debugging/auditing."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c for c in (context_id or "unknown_target") if c.isalnum() or c in "_-")
        filename = os.path.join(self.audit_log_dir, f"llm_audit_{safe_name}.txt")
        
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
    ) -> tuple[str, dict[str, Any]]:
        """Generate a response using the configured endpoint and tool handler."""
        model_settings = model_settings or {}
            
        client = self.clients[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.clients)
        
        if self._use_legacy_endpoint:
            return await self._execute_legacy_chat(client, system_prompt, user_prompt, model_settings, context_id, tools, tool_handler)

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
        if "reasoning_effort" in model_settings:
            kwargs_responses["reasoning"] = {"effort": model_settings["reasoning_effort"]}
        if model_settings.get("response_format") == "json_object":
            kwargs_responses["text"] = {"format": {"type": "json_object"}}

        try:
            response = await self._retry_request(
                lambda: self._request_responses(client, kwargs_responses, tool_handler),
                endpoint="/responses",
            )
        except openai.NotFoundError:
            logger.warning("[LLM] /responses returned 404; using /chat/completions.")
            self._use_legacy_endpoint = True
            return await self._execute_legacy_chat(
                client, system_prompt, user_prompt, model_settings,
                context_id, tools, tool_handler,
            )

        final_text = self._response_text(response, "Frontier")
        usage_dict = self._usage_dict(response)
        self._audit_log(kwargs_responses, final_text, "/responses", context_id)
        return final_text, usage_dict

    async def _retry_request(
        self,
        operation: Callable[[], Awaitable[ResponseT]],
        *,
        endpoint: str,
        max_retries: int = 3,
    ) -> ResponseT:
        """Retry transient provider failures using exponential backoff."""
        for attempt in range(max_retries):
            try:
                return await operation()
            except openai.NotFoundError:
                raise
            except APIConnectionError as exc:
                retryable = True
                message = f"connection failed: {exc}"
            except openai.RateLimitError as exc:
                retryable = True
                message = f"rate limited: {exc}"
            except openai.APIStatusError as exc:
                retryable = exc.status_code in (500, 502, 503, 504)
                message = f"HTTP {exc.status_code}: {exc}"
            except Exception as exc:
                message_text = str(exc).lower()
                retryable = any(
                    marker in message_text
                    for marker in ("getaddrinfo failed", "connection", "timeout")
                )
                if not retryable:
                    logger.exception("[LLM] %s failed on model %s", endpoint, self.model_name)
                    raise
                message = f"network failure: {exc}"

            if attempt == max_retries - 1 or not retryable:
                raise
            delay = 2.0 * (2 ** attempt)
            logger.warning(
                "[LLM] %s %s (attempt %d/%d); retrying in %.1fs",
                endpoint, message, attempt + 1, max_retries, delay,
            )
            await asyncio.sleep(delay)

        raise AssertionError("retry loop completed without returning or raising")

    async def _request_responses(
        self,
        client: Any,
        request_kwargs: dict[str, Any],
        tool_handler: ToolHandler | None,
    ) -> Any:
        response_input = request_kwargs["input"]
        for _ in range(4):
            response = await client.responses.create(
                **{**request_kwargs, "input": response_input}
            )
            function_calls = [
                item for item in response.output
                if getattr(item, "type", None) == "function_call"
            ]
            if not function_calls or not tool_handler:
                return response
            tool_outputs = [
                {
                    "type": "function_call_output",
                    "call_id": call.call_id,
                    "output": self._call_tool(tool_handler, call.name, call.arguments),
                }
                for call in function_calls
            ]
            response_input = response_input + list(response.output) + tool_outputs
        raise RuntimeError("Model exceeded the maximum tool-call rounds")

    @staticmethod
    def _call_tool(tool_handler: ToolHandler, name: str, arguments: str | None) -> str:
        try:
            return tool_handler(name, json.loads(arguments or "{}"))
        except Exception as exc:
            return json.dumps({"error": str(exc)})

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
                return block.content[0].text
        raise RuntimeError(f"{model_name} model returned no assistant message.")

    async def _execute_legacy_chat(
        self,
        client: Any,
        system_prompt: str,
        user_prompt: str,
        model_settings: Mapping[str, Any],
        context_id: str | None = None,
        tools: Sequence[ToolDefinition] | None = None,
        tool_handler: ToolHandler | None = None,
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
        if "reasoning_effort" in model_settings:
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
            
        response = await self._retry_request(
            lambda: self._request_legacy_chat(client, kwargs_chat, tool_handler),
            endpoint="/chat/completions",
        )
        final_text = response.choices[0].message.content
        if final_text is None:
            raise RuntimeError("Legacy model returned no assistant message.")
        self._audit_log(kwargs_chat, final_text, "/chat/completions", context_id)
        return final_text, self._usage_dict(response)

    async def _request_legacy_chat(
        self,
        client: Any,
        request_kwargs: dict[str, Any],
        tool_handler: ToolHandler | None,
    ) -> Any:
        messages = list(request_kwargs["messages"])
        for _ in range(4):
            response = await client.chat.completions.create(
                **{**request_kwargs, "messages": messages}
            )
            message = response.choices[0].message
            tool_calls = getattr(message, "tool_calls", None) or []
            if not tool_calls or not tool_handler:
                return response
            messages.append(message)
            for tool_call in tool_calls:
                messages.append({
                    "role": "tool",
                    "tool_call_id": tool_call.id,
                    "content": self._call_tool(
                        tool_handler,
                        tool_call.function.name,
                        tool_call.function.arguments,
                    ),
                })
        raise RuntimeError("Model exceeded the maximum tool-call rounds")
