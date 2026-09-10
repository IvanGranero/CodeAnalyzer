"""Task-aware routing between cheap and strong LLM services."""

from collections.abc import Mapping, Sequence
from enum import Enum
from typing import Any

from llm.client import ToolDefinition, ToolHandler, UsageCallback


class ModelTier(str, Enum):
    CHEAP = "cheap"
    STRONG = "strong"


class TieredLLMService:
    """Route prompt tasks to cheap or strong services by investigation cost."""

    _CHEAP_TASKS = frozenset({
        "discovery",
        "nl2cypher",
        "triage_agent",
        "exploit_analyzer",
    })

    def __init__(self, cheap_service: Any, strong_service: Any):
        self.services = {
            ModelTier.CHEAP: cheap_service,
            ModelTier.STRONG: strong_service,
        }

    def _tier_for(
        self,
        task_name: str,
        kwargs: Mapping[str, Any],
        settings_override: Mapping[str, Any] | None = None,
    ) -> ModelTier:
        """Choose a model tier according to the task's reasoning requirements."""
        if task_name in self._CHEAP_TASKS:
            return ModelTier.CHEAP
        if task_name == "deep_scan_agent":
            return ModelTier.STRONG
        return ModelTier.STRONG

    def tier_for(
        self,
        task_name: str,
        kwargs: Mapping[str, Any],
        settings_override: Mapping[str, Any] | None = None,
    ) -> ModelTier:
        """Expose deterministic routing for model selection."""
        return self._tier_for(task_name, kwargs, settings_override)

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
        tier = self._tier_for(task_name, kwargs, settings_override)
        return await self.services[tier].execute_task(
            task_name, kwargs, context_id, settings_override, usage_callback, tools, tool_handler
        )

    @property
    def tracker(self):
        return self.services[ModelTier.STRONG].tracker

    def log_summary(self) -> None:
        if hasattr(self.tracker, "log_summary"):
            self.tracker.log_summary()

    def set_usage_listener(self, listener: UsageCallback | None) -> None:
        """Forward usage events from both model tiers to one observer."""
        for service in self.services.values():
            if hasattr(service, "set_usage_listener"):
                service.set_usage_listener(listener)

    def set_audit_context(self, context_id: str | None) -> None:
        """Route one application-run audit context to both model services."""
        for service in self.services.values():
            if hasattr(service, "set_audit_context"):
                service.set_audit_context(context_id)