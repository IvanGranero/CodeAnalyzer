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
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import StructuredTool
from langchain_google_vertexai.model_garden import ChatAnthropicVertex
from langchain_litellm import ChatLiteLLM
from pydantic import BaseModel, ConfigDict, Field, create_model

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
            )

        
        deployment_base_url = f"{self.base_url.rstrip('/')}/{self.deployment}"
        os.environ["OPENAI_API_KEY"] = api_key
        if self.model_name.startswith("openai/"):
            os.environ["OPENAI_API_BASE"] = deployment_base_url
        else:
            os.environ["AZURE_API_BASE"] = deployment_base_url
            os.environ["AZURE_API_KEY"] = api_key
        if self.api_version:
            os.environ["AZURE_API_VERSION"] = self.api_version

        model_kwargs: dict[str, Any] = {"headers": self.default_headers} if self.default_headers else {}
        if settings.get("reasoning_effort") is not None:
            model_kwargs["reasoning_effort"] = settings["reasoning_effort"]
        if settings.get("response_format") == "json_object":
            model_kwargs["response_format"] = {"type": "json_object"}
        constructor_args: dict[str, Any] = {
            "model": self.model_name,
            "request_timeout": 300.0,
            "max_retries": 0,
            "model_kwargs": model_kwargs,
        }
        token_limit = settings.get("max_completion_tokens", settings.get("max_tokens"))
        if token_limit is not None:
            constructor_args["max_tokens"] = token_limit
        return ChatLiteLLM(**constructor_args)

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
        settings = model_settings or {}
        api_key = self.api_keys[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.api_keys)
        model = self._build_model(api_key, settings)
        messages = [SystemMessage(content=system_prompt), HumanMessage(content=user_prompt)]
        usage_capture = _UsageCapture()
        tool_actions: list[Any] = []

        if tools and tool_handler:
            from langchain.agents import AgentExecutor, create_tool_calling_agent
            from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

            lc_tools = self._tools(tools, tool_handler)
            prompt = ChatPromptTemplate.from_messages([
                ("system", system_prompt),
                ("human", "{input}"),
                MessagesPlaceholder("agent_scratchpad"),
            ])
            agent = create_tool_calling_agent(model, lc_tools, prompt)
            executor = AgentExecutor(
                agent=agent,
                tools=lc_tools,
                max_iterations=4,
                return_intermediate_steps=True,
                verbose=False,
            ).with_retry(stop_after_attempt=3, wait_exponential_jitter=True)
            result = await executor.ainvoke(
                {"input": user_prompt},
                config={"callbacks": [usage_capture]},
            )
            text = result.get("output", "")
            tool_actions = result.get("intermediate_steps", [])
        else:
            runnable = model.with_retry(stop_after_attempt=3, wait_exponential_jitter=True)
            response = await runnable.ainvoke(messages, config={"callbacks": [usage_capture]})
            text = response.content if isinstance(response, AIMessage) else str(response)
            usage_capture.usage = _usage_dict(response) or usage_capture.usage

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
