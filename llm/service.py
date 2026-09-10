"""Task-oriented LLM execution and usage tracking."""

import inspect
import json
import logging
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Awaitable, Callable

from llm.client import LLMClient, ToolDefinition, ToolHandler, UsageCallback
from llm.tracker import TokenTracker
from config import TokenPricing

logger = logging.getLogger(__name__)


class LLMService:
    """Execute named prompt tasks and track their token usage and cost."""

    def __init__(
        self,
        api_key: str,
        model_name: str,
        base_url: str,
        pricing: TokenPricing,
        default_headers: str = "",
        extra_query: str = "",
        usage_listener: UsageCallback | None = None,
        tracker: TokenTracker | None = None,
    ) -> None:
        self.client = LLMClient(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            default_headers=default_headers,
            extra_query=extra_query,
        )
        self.prompts = self._load_prompts()
        self.tracker = tracker or TokenTracker()
        self.tracker.register_model(model_name, pricing)
        self.model_name = model_name
        self.usage_listener = usage_listener
        self.pause_waiter: Callable[[], Awaitable[None]] | None = None
        self.audit_context_id: str | None = None

    def _load_prompts(self) -> dict[str, dict[str, Any]]:
        """Load task templates and model defaults from ``prompts.json``."""
        try:
            prompts_path = Path(__file__).with_name("prompts.json")
            with prompts_path.open("r", encoding="utf-8") as file:
                return json.load(file)
        except Exception as exc:
            logger.error("Failed to load prompts.json: %s", exc)
            return {}

    async def execute_task(
        self,
        task_name: str,
        kwargs: Mapping[str, Any],
        context_id: str | None = None,
        settings_override: Mapping[str, Any] | None = None,
        usage_callback: UsageCallback | None = None,
        tools: Sequence[ToolDefinition] | None = None,
        tool_handler: ToolHandler | None = None,
    ) -> str:
        """Render and execute one configured prompt task."""
        if self.pause_waiter is not None:
            await self.pause_waiter()
        if task_name not in self.prompts:
            raise ValueError(f"Task '{task_name}' not found in prompts.json")

        task_config = self.prompts[task_name]
        system_prompt = (
            "\n".join(task_config["system"])
            if isinstance(task_config["system"], list)
            else task_config["system"]
        )
        template = (
            "\n".join(task_config["template"])
            if isinstance(task_config["template"], list)
            else task_config["template"]
        )
        user_prompt = template.format(**kwargs)
        settings = task_config.get("model_settings", {})
        if settings_override:
            settings = {**settings, **settings_override}

        start_time = time.time()
        logger.debug(
            "LLM Service (%s): Executing async task '%s'",
            self.client.model_name,
            task_name,
        )
        result_text, usage_dict = await self.client.generate_chat(
            system_prompt,
            user_prompt,
            settings,
            self.audit_context_id or context_id,
            tools=tools,
            tool_handler=tool_handler,
            audit_metadata={"task_name": task_name, "task_context_id": context_id},
        )

        if usage_dict:
            self.tracker.add_usage(usage_dict, task_name=task_name, model_name=self.model_name)
            if usage_callback:
                callback_result = usage_callback(
                    usage_dict,
                    self.tracker.estimate_usage_cost(usage_dict, model_name=self.model_name),
                )
                if inspect.isawaitable(callback_result):
                    await callback_result
            if self.usage_listener:
                listener_result = self.usage_listener(
                    usage_dict,
                    self.tracker.estimate_usage_cost(usage_dict, model_name=self.model_name),
                )
                if inspect.isawaitable(listener_result):
                    await listener_result

        elapsed = time.time() - start_time
        logger.debug(
            "LLM Service (%s): Task '%s' completed in %.2fs",
            self.client.model_name,
            task_name,
            elapsed,
        )
        preview = (
            result_text[:75].replace("\n", " ") + "..."
            if len(result_text) > 75
            else result_text
        )
        logger.debug("[LLM Response Preview] %s", preview)
        return result_text

    def set_audit_context(self, context_id: str | None) -> None:
        """Override per-task audit filenames for one application run."""
        self.audit_context_id = context_id

    def set_usage_listener(self, listener: UsageCallback | None) -> None:
        """Set a process-local observer for completed LLM usage records."""
        self.usage_listener = listener

    def set_pause_waiter(
        self, waiter: Callable[[], Awaitable[None]] | None
    ) -> None:
        """Pause before starting the next remote model request when configured."""
        self.pause_waiter = waiter
