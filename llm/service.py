"""Task-oriented LLM execution and usage tracking."""

import inspect
import json
import logging
import time
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from llm.client import LLMClient, ToolDefinition, ToolHandler, UsageCallback
from llm.tracker import TokenTracker

logger = logging.getLogger(__name__)


class LLMService:
    """Execute named prompt tasks and track their token usage and cost."""

    def __init__(
        self,
        api_key: str,
        model_name: str,
        base_url: str,
        api_version: str,
        api_key_header: str = "",
        usd_per_1m_input: float | None = None,
        usd_per_1m_output: float | None = None,
        usage_listener: UsageCallback | None = None,
    ) -> None:
        self.client = LLMClient(
            api_key=api_key,
            model_name=model_name,
            base_url=base_url,
            api_version=api_version,
            api_key_header=api_key_header,
        )
        self.prompts = self._load_prompts()
        self.tracker = TokenTracker(
            model_name=model_name,
            usd_per_1m_input=usd_per_1m_input,
            usd_per_1m_output=usd_per_1m_output,
        )
        self.usage_listener = usage_listener

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
            context_id,
            tools=tools,
            tool_handler=tool_handler,
        )

        if usage_dict:
            self.tracker.add_usage(usage_dict)
            if usage_callback:
                callback_result = usage_callback(
                    usage_dict,
                    self.tracker.estimate_usage_cost(usage_dict),
                )
                if inspect.isawaitable(callback_result):
                    await callback_result
            if self.usage_listener:
                listener_result = self.usage_listener(
                    usage_dict,
                    self.tracker.estimate_usage_cost(usage_dict),
                )
                if inspect.isawaitable(listener_result):
                    await listener_result

    def set_usage_listener(self, listener: UsageCallback | None) -> None:
        """Set a process-local observer for completed LLM usage records."""
        self.usage_listener = listener

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
