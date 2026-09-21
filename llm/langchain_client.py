from __future__ import annotations
import hashlib
import json
import logging
import os
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import datetime
from typing import Any

from langchain_core.callbacks import BaseCallbackHandler
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.tools import StructuredTool
from langchain_google_vertexai.model_garden import ChatAnthropicVertex
from openai import AsyncOpenAI
from pydantic import BaseModel, ConfigDict, Field, create_model

from llm.native_chat_model import NativeOpenAIChatModel

logger = logging.getLogger(__name__)
ToolDefinition = Mapping[str, Any]
ToolHandler = Callable[[str, Mapping[str, Any]], str]
UsageCallback = Callable[[Mapping[str, Any], float], None | Awaitable[None]]


class EmptyLLMResponseError(RuntimeError):
    """The provider returned no assistant content after a successful request."""

    def __init__(self, message: str, *, retryable: bool = True) -> None:
        super().__init__(message)
        self.retryable = retryable


class _UsageCapture(BaseCallbackHandler):
    """Collect usage from LangChain callbacks when an agent executes tools."""

    def __init__(self) -> None:
        self.usage: dict[str, Any] = {}

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        generations = getattr(response, "generations", [])
        if not generations or not generations[0]:
            return
        message = getattr(generations[0][0], "message", None)
        self.usage = _usage_dict(message)


def _usage_dict(message: Any) -> dict[str, Any]:
    usage = getattr(message, "usage_metadata", None)
    if isinstance(usage, Mapping):
        return dict(usage)
    metadata = getattr(message, "response_metadata", {}) or {}
    token_usage = metadata.get("token_usage", {})
    if isinstance(token_usage, Mapping):
        return dict(token_usage)
    return {}


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


def _message_payload(message: BaseMessage) -> dict[str, Any]:
    return {
        "type": message.type,
        "content": _jsonable(message.content),
        **({"tool_calls": _jsonable(message.tool_calls)} if getattr(message, "tool_calls", None) else {}),
        **({"additional_kwargs": _jsonable(message.additional_kwargs)} if message.additional_kwargs else {}),
    }


class LLMClient:
    """LangChain-backed LLM client retaining the application's stable contract."""

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
        self.base_url = base_url.rstrip('/')
        self.default_headers = self._parse_pairs(default_headers)
        self.api_version = api_version
        self.api_style = api_style
        self.audit_log_dir = audit_log_dir
        os.makedirs(self.audit_log_dir, exist_ok=True)
        self._current_index = 0
        logger.info("Initialized %s LangChain LLM client with %d keys.", model_name, len(self.api_keys))

    @staticmethod
    def _parse_pairs(value: str) -> dict[str, str]:
        parts = [part.strip() for part in value.split(",") if part.strip()]
        if len(parts) % 2:
            raise ValueError("Configuration pairs must contain comma-separated key/value pairs")
        return dict(zip(parts[::2], parts[1::2]))

    def _build_model(self, api_key: str, settings: Mapping[str, Any]) -> BaseChatModel:
        if self.model_name.startswith("anthropic/"):
            return ChatAnthropicVertex(
                access_token=api_key,
                project="_",
                location="_",
                model=self.deployment,
                base_url=self.base_url,
                timeout=300.0,
                max_retries=0,
            )

        deployment_base_url = f"{self.base_url.rstrip('/')}/{self.deployment}"
        is_azure = self.model_name.startswith("azure/")
        api_style = self.api_style
        model_name = self.model_name.split("/", 1)[1] if "/" in self.model_name else self.model_name
        if is_azure:
            model_name = self.deployment or model_name
        base_url = deployment_base_url if self.deployment else self.base_url
        default_query = {"api-version": self.api_version} if is_azure and self.api_version else None
        async_client = AsyncOpenAI(
            api_key=api_key,
            base_url=base_url,
            default_headers=self.default_headers or None,
            default_query=default_query,
            timeout=300.0,
            max_retries=0,
        )
        return NativeOpenAIChatModel(
            model=model_name,
            api_style=api_style,
            max_completion_tokens=settings.get("max_completion_tokens", settings.get("max_tokens")),
            max_tool_calls=int(settings.get("max_tool_calls", 6)),
            reasoning_effort=settings.get("reasoning_effort"),
            response_format={"type": "json_object"} if settings.get("response_format") == "json_object" else None,
            async_client=async_client,
        )

    @staticmethod
    def _tool_schema(definition: ToolDefinition) -> tuple[str, str, Mapping[str, Any]]:
        function = definition.get("function", definition)
        return (
            str(function["name"]),
            str(function.get("description", "")),
            function.get("parameters", {}) or {},
        )

    @staticmethod
    def _args_model(name: str, schema: Mapping[str, Any]) -> type[BaseModel]:
        properties = schema.get("properties", {}) or {}
        required = set(schema.get("required", []) or [])
        fields: dict[str, tuple[Any, Any]] = {}
        type_map = {"string": str, "integer": int, "number": float, "boolean": bool}
        for field_name, field_schema in properties.items():
            annotation = type_map.get(field_schema.get("type"), Any)
            default = ... if field_name in required else None
            fields[field_name] = (annotation, Field(default=default, description=field_schema.get("description")))
        config = ConfigDict(extra="forbid") if schema.get("additionalProperties", False) is False else ConfigDict()
        return create_model(f"{name.title().replace('_', '')}Arguments", __config__=config, **fields)

    def _tools(self, definitions: Sequence[ToolDefinition], handler: ToolHandler) -> list[StructuredTool]:
        result = []
        for definition in definitions:
            name, description, schema = self._tool_schema(definition)
            args_model = self._args_model(name, schema)

            def invoke(_name: str = name, **arguments: Any) -> str:
                try:
                    output = handler(_name, arguments)
                    return output if isinstance(output, str) else json.dumps(output, ensure_ascii=False)
                except Exception as exc:
                    logger.exception("Tool '%s' failed", _name)
                    return json.dumps({"error": f"Tool '{_name}' failed: {exc}"})

            result.append(StructuredTool.from_function(
                func=invoke,
                name=name,
                description=description or name,
                args_schema=args_model,
            ))
        return result

    @staticmethod
    def _text_content(content: Any) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(
                str(block.get("text", ""))
                for block in content
                if isinstance(block, Mapping) and block.get("type") == "text"
            )
        return ""

    async def generate_chat(
        self,
        system_prompt: str,
        user_prompt: str,
        model_settings: Mapping[str, Any] | None = None,
        context_id: str | None = None,
        tools: Sequence[ToolDefinition] | None = None,
        tool_handler: ToolHandler | None = None,
        audit_metadata: Mapping[str, Any] | None = None,
        preloaded_messages: Sequence[BaseMessage] | None = None,
    ) -> tuple[str, dict[str, Any]]:
        settings = model_settings or {}
        api_key = self.api_keys[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.api_keys)
        model = self._build_model(api_key, settings)
        messages = [
            SystemMessage(content=system_prompt),
            *(preloaded_messages or []),
            HumanMessage(content=user_prompt),
        ]
        usage_capture = _UsageCapture()
        tool_actions: list[Any] = []

        if tools and tool_handler:
            from langchain.agents import create_agent

            lc_tools = self._tools(tools, tool_handler)
            agent = create_agent(
                model,
                tools=lc_tools,
                system_prompt=system_prompt,
            )
            result = await agent.ainvoke(
                {"messages": messages},
                config={
                    "callbacks": [usage_capture],
                    "recursion_limit": int(settings.get("agent_recursion_limit", 16)),
                },
            )
            result_messages = result.get("messages", [])
            final_message = next(
                (message for message in reversed(result_messages) if isinstance(message, AIMessage)),
                None,
            )
            text = self._text_content(final_message.content) if final_message is not None else ""
            tool_actions = [
                message
                for message in result_messages
                if getattr(message, "type", None) == "tool"
            ]
        else:
            runnable = model.with_retry(stop_after_attempt=3, wait_exponential_jitter=True)
            response = await runnable.ainvoke(messages, config={"callbacks": [usage_capture]})
            text = self._text_content(response.content) if isinstance(response, AIMessage) else str(response)
            usage_capture.usage = _usage_dict(response) or usage_capture.usage

        if (not isinstance(text, str) or not text.strip()) and tool_actions:
            # Some Responses API models finish after a function call and do not
            # emit a prose assistant turn. The tool result is the useful output.
            text = "{}"
        if not isinstance(text, str) or not text.strip():
            raise EmptyLLMResponseError(f"empty_response: {self.model_name} returned no assistant content")

        usage = usage_capture.usage
        self._audit_log(
            messages,
            text,
            context_id,
            [_jsonable(action) for action in tool_actions],
            audit_metadata,
        )
        return text, usage

    def _audit_log(
        self,
        messages: Sequence[BaseMessage],
        response_content: str,
        context_id: str | None,
        tool_calls: Sequence[Any],
        audit_metadata: Mapping[str, Any] | None,
    ) -> None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        context = context_id or "unknown_target"
        safe_name = "".join(char if char.isalnum() or char in "._-" else "_" for char in context)
        digest = hashlib.sha256(context.encode("utf-8")).hexdigest()[:12]
        filename = os.path.join(self.audit_log_dir, f"{safe_name}-{digest}.txt")
        log_content = (
            "==================================================\n"
            f"TIMESTAMP: {timestamp}\n"
            f"MODEL: {self.model_name}\n"
            "ENDPOINT USED: /chat/completions via LiteLLM\n"
            "==================================================\n"
            "=== RAW INPUT (LANGCHAIN MESSAGES) ===\n"
            f"{json.dumps([_message_payload(message) for message in messages], indent=2)}\n\n"
            "=== RAW OUTPUT (LLM RESPONSE) ===\n"
            f"{response_content}\n\n"
        )
        if audit_metadata:
            log_content += f"=== INVOCATION METADATA ===\n{json.dumps(dict(audit_metadata), indent=2, ensure_ascii=False)}\n\n"
        if tool_calls:
            log_content += f"=== TOOL CALLS (LANGCHAIN) ===\n{json.dumps(list(tool_calls), indent=2, ensure_ascii=False)}\n\n"
        try:
            with open(filename, "a", encoding="utf-8") as file:
                file.write(log_content)
        except OSError as exc:
            logger.error("Failed to write LLM audit log: %s", exc)
