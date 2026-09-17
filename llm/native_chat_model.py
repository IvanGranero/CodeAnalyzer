from __future__ import annotations

import asyncio
import logging
from typing import Any, Literal, Sequence

from langchain_core.callbacks import AsyncCallbackManagerForLLMRun, CallbackManagerForLLMRun
from langchain_core.language_models.chat_models import BaseChatModel
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage, ToolMessage
from langchain_core.outputs import ChatGeneration, ChatResult
from openai import AsyncOpenAI
from pydantic import ConfigDict, Field

logger = logging.getLogger(__name__)


class NativeOpenAIChatModel(BaseChatModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    model: str
    api_style: Literal["chat_completions", "responses"] = "chat_completions"
    max_completion_tokens: int | None = None
    max_tool_calls: int = 6
    reasoning_effort: str | None = None
    response_format: dict[str, Any] | None = None
    bound_tools: list[dict[str, Any]] = Field(default_factory=list)
    async_client: AsyncOpenAI = Field(exclude=True)

    @property
    def _llm_type(self) -> str:
        return "native_openai"

    def bind_tools(
        self,
        tools: Sequence[dict[str, Any] | type | Any],
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> NativeOpenAIChatModel:
        normalized = []
        for tool in tools:
            if isinstance(tool, dict):
                normalized.append(tool)
            elif hasattr(tool, "args_schema"):
                normalized.append({
                    "type": "function",
                    "function": {
                        "name": tool.name,
                        "description": tool.description or "",
                        "parameters": tool.args_schema.model_json_schema(),
                    },
                })
            else:
                raise TypeError(f"Unsupported tool type: {type(tool).__name__}")
        return self.model_copy(update={"bound_tools": normalized})

    @staticmethod
    def _message_payload(message: BaseMessage) -> dict[str, Any]:
        if isinstance(message, SystemMessage):
            role = "system"
        elif isinstance(message, HumanMessage):
            role = "user"
        elif isinstance(message, ToolMessage):
            return {
                "role": "tool",
                "tool_call_id": message.tool_call_id,
                "content": message.content,
            }
        else:
            role = "assistant"
        payload: dict[str, Any] = {"role": role, "content": message.content}
        if isinstance(message, AIMessage) and message.tool_calls:
            payload["tool_calls"] = [
                {
                    "id": call["id"],
                    "type": "function",
                    "function": {
                        "name": call["name"],
                        "arguments": _json_arguments(call["args"]),
                    },
                }
                for call in message.tool_calls
            ]
        return payload

    def _request_kwargs(self, tool_calls_used: int = 0) -> dict[str, Any]:
        kwargs: dict[str, Any] = {}
        if self.max_completion_tokens is not None:
            kwargs["max_completion_tokens"] = self.max_completion_tokens
        if self.reasoning_effort is not None:
            kwargs["reasoning_effort"] = self.reasoning_effort
        if self.response_format is not None and not self.bound_tools and self.api_style == "chat_completions":
            kwargs["response_format"] = self.response_format
        if self.response_format is not None and not self.bound_tools and self.api_style == "responses":
            kwargs["text"] = {"format": self.response_format}
        tools_allowed = self.bound_tools and tool_calls_used < self.max_tool_calls
        if tools_allowed and self.api_style == "chat_completions":
            kwargs["tools"] = self.bound_tools
        if tools_allowed and self.api_style == "responses":
            kwargs["tools"] = [
                {
                    "type": "function",
                    "name": tool["function"]["name"],
                    "description": tool["function"].get("description", ""),
                    "parameters": tool["function"].get("parameters", {}),
                }
                for tool in self.bound_tools
            ]
        return kwargs

    async def _agenerate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: AsyncCallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        request = {
            "model": self.model,
            "messages": [self._message_payload(message) for message in messages],
            **self._request_kwargs(sum(message.type == "tool" for message in messages)),
            **kwargs,
        }
        if stop is not None:
            request["stop"] = stop
        if self.api_style == "responses":
            response = await self.async_client.responses.create(
                model=request.pop("model"),
                input=request.pop("messages"),
                max_output_tokens=request.pop("max_completion_tokens", None),
                **request,
            )
            message = _responses_message(response)
        else:
            response = await self.async_client.chat.completions.create(**request)
            message = _chat_message(response)
        return ChatResult(
            generations=[ChatGeneration(message=message)],
            llm_output={"token_usage": _usage_metadata(response) or {}},
        )

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        return asyncio.run(self._agenerate(messages, stop, None, **kwargs))


def _json_arguments(arguments: Any) -> str:
    import json
    return json.dumps(arguments, separators=(",", ":"), ensure_ascii=False)


def _chat_message(response: Any) -> AIMessage:
    choice = response.choices[0]
    message = choice.message
    tool_calls = []
    for call in message.tool_calls or []:
        import json
        try:
            arguments = json.loads(call.function.arguments or "{}")
        except json.JSONDecodeError:
            arguments = {}
        tool_calls.append({
            "name": call.function.name,
            "args": arguments,
            "id": call.id,
            "type": "tool_call",
        })
    content = _message_content(message)
    if not content and not tool_calls:
        logger.warning(
            "Native chat response contained no assistant text: finish_reason=%s refusal=%s "
            "message_fields=%s usage=%s",
            getattr(choice, "finish_reason", None),
            bool(getattr(message, "refusal", None)),
            sorted(_object_fields(message)),
            _usage_metadata(response),
        )
    return AIMessage(
        content=content,
        tool_calls=tool_calls,
        response_metadata={"finish_reason": choice.finish_reason},
        usage_metadata=_usage_metadata(response),
    )


def _responses_message(response: Any) -> AIMessage:
    tool_calls = []
    content = getattr(response, "output_text", "") or ""
    for item in getattr(response, "output", []) or []:
        if getattr(item, "type", None) == "function_call":
            import json
            try:
                arguments = json.loads(item.arguments or "{}")
            except json.JSONDecodeError:
                arguments = {}
            tool_calls.append({
                "name": item.name,
                "args": arguments,
                "id": item.call_id,
                "type": "tool_call",
            })
    if not content:
        logger.warning(
            "Native Responses API response contained no output text: status=%s output_items=%s usage=%s",
            getattr(response, "status", None),
            len(getattr(response, "output", []) or []),
            _usage_metadata(response),
        )
    return AIMessage(content=content, tool_calls=tool_calls, usage_metadata=_usage_metadata(response))


def _message_content(message: Any) -> str:
    content = getattr(message, "content", "")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(block.get("text", ""))
            for block in content
            if isinstance(block, dict) and block.get("type") in {"text", "output_text"}
        )
    refusal = getattr(message, "refusal", None)
    if refusal:
        return str(refusal)
    reasoning = getattr(message, "reasoning_content", None)
    return str(reasoning) if reasoning else ""


def _object_fields(value: Any) -> set[str]:
    if hasattr(value, "model_fields_set"):
        return set(value.model_fields_set)
    if hasattr(value, "__dict__"):
        return {key for key in vars(value) if not key.startswith("_")}
    return set()


def _usage_metadata(response: Any) -> dict[str, int] | None:
    usage = getattr(response, "usage", None)
    if usage is None:
        return None
    input_tokens = getattr(usage, "input_tokens", getattr(usage, "prompt_tokens", 0)) or 0
    output_tokens = getattr(usage, "output_tokens", getattr(usage, "completion_tokens", 0)) or 0
    return {
        "input_tokens": int(input_tokens),
        "output_tokens": int(output_tokens),
        "total_tokens": int(input_tokens) + int(output_tokens),
    }
