import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Mapping

from config import TokenPricing

logger = logging.getLogger(__name__)


@dataclass
class UsageSnapshot:
    calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    reasoning_tokens: int = 0
    cost: float = 0.0
    phases: dict[str, "UsageSnapshot"] = field(default_factory=dict)

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens

    @property
    def actual_tokens(self) -> int:
        return self.total_tokens

    @property
    def actual_cost(self) -> float:
        return self.cost


class TokenTracker:
    """Centralized token and cost ledger for all LLM workflows."""

    def __init__(
        self,
        model_name: str = "",
        pricing: TokenPricing = TokenPricing(),
    ):
        self.lock = threading.Lock()
        self.model_name = model_name
        self.pricing = pricing
        self._pricing_by_model: dict[str, TokenPricing] = {}
        if model_name:
            self._pricing_by_model[model_name] = pricing
        self._total = UsageSnapshot()
        self._by_phase: dict[str, UsageSnapshot] = {}

    @property
    def total_calls(self) -> int:
        return self._total.calls

    @property
    def prompt_tokens(self) -> int:
        return self._total.input_tokens

    @property
    def completion_tokens(self) -> int:
        return self._total.output_tokens

    @property
    def reasoning_tokens(self) -> int:
        return self._total.reasoning_tokens

    @property
    def cached_tokens(self) -> int:
        return self._total.cached_tokens

    def register_model(self, model_name: str, pricing: TokenPricing) -> None:
        with self.lock:
            self._pricing_by_model[model_name] = pricing

    def add_usage(
        self,
        usage: Mapping[str, Any] | None,
        task_name: str | None = None,
        model_name: str | None = None,
    ) -> None:
        """Record one provider response, optionally attributed to a workflow phase."""
        if not usage:
            return

        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0
        output_details = usage.get("output_tokens_details") or usage.get("completion_tokens_details") or {}
        input_details = usage.get("input_tokens_details") or usage.get("prompt_tokens_details") or {}
        reasoning_tokens = (
            output_details.get("reasoning_tokens", 0) or 0
            if isinstance(output_details, dict)
            else 0
        )
        cached_tokens = (
            input_details.get("cached_tokens", 0) or 0
            if isinstance(input_details, dict)
            else 0
        )
        pricing = self._pricing_by_model.get(model_name or "", self.pricing)
        uncached_input_tokens = max(input_tokens - cached_tokens, 0)
        cost = (
            uncached_input_tokens / 1_000_000 * pricing.input
            + cached_tokens / 1_000_000 * pricing.cached
            + output_tokens / 1_000_000 * pricing.output
        )

        with self.lock:
            self._add_to_snapshot(
                self._total,
                input_tokens,
                output_tokens,
                cached_tokens,
                reasoning_tokens,
                cost,
            )
            phase = self.phase_for_task(task_name)
            if phase:
                phase_snapshot = self._by_phase.setdefault(phase, UsageSnapshot())
                self._add_to_snapshot(
                    phase_snapshot,
                    input_tokens,
                    output_tokens,
                    cached_tokens,
                    reasoning_tokens,
                    cost,
                )

    @staticmethod
    def phase_for_task(task_name: str | None) -> str | None:
        """Map prompt task names to the report's workflow phases."""
        if not task_name:
            return None
        if task_name in {"discovery", "triage_agent"}:
            return "triage"
        if task_name.startswith("exploit_"):
            return "exploit"
        return "scan"

    @staticmethod
    def _add_to_snapshot(
        snapshot: UsageSnapshot,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int,
        reasoning_tokens: int,
        cost: float,
    ) -> None:
        snapshot.calls += 1
        snapshot.input_tokens += input_tokens
        snapshot.output_tokens += output_tokens
        snapshot.cached_tokens += cached_tokens
        snapshot.reasoning_tokens += reasoning_tokens
        snapshot.cost += cost

    def snapshot(self) -> UsageSnapshot:
        with self.lock:
            return UsageSnapshot(
                calls=self._total.calls,
                input_tokens=self._total.input_tokens,
                output_tokens=self._total.output_tokens,
                cached_tokens=self._total.cached_tokens,
                reasoning_tokens=self._total.reasoning_tokens,
                cost=self._total.cost,
                phases={phase: self._copy_snapshot(snapshot) for phase, snapshot in self._by_phase.items()},
            )

    def phase_snapshot(self, phase: str) -> UsageSnapshot:
        return self.snapshot().phases.get(phase, UsageSnapshot())

    @staticmethod
    def _copy_snapshot(snapshot: UsageSnapshot) -> UsageSnapshot:
        return UsageSnapshot(
            calls=snapshot.calls,
            input_tokens=snapshot.input_tokens,
            output_tokens=snapshot.output_tokens,
            cached_tokens=snapshot.cached_tokens,
            reasoning_tokens=snapshot.reasoning_tokens,
            cost=snapshot.cost,
        )

    def get_estimated_cost(self) -> float:
        return self.snapshot().cost

    def estimate_usage_cost(
        self,
        usage: Mapping[str, Any],
        model_name: str | None = None,
    ) -> float:
        input_tokens = usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0
        output_tokens = usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0
        input_details = usage.get("input_tokens_details") or usage.get("prompt_tokens_details") or {}
        cached_tokens = input_details.get("cached_tokens", 0) if isinstance(input_details, dict) else 0
        pricing = self._pricing_by_model.get(model_name or "", self.pricing)
        return (
            max(input_tokens - cached_tokens, 0) / 1_000_000 * pricing.input
            + cached_tokens / 1_000_000 * pricing.cached
            + output_tokens / 1_000_000 * pricing.output
        )

    def log_summary(self) -> None:
        snapshot = self.snapshot()
        report = (
            f"\n{'=' * 60}\n"
            " LLM TOKEN USAGE & COST SUMMARY\n"
            f"{'=' * 60}\n"
            f"  Total API Calls   : {snapshot.calls}\n"
            f"  Input Tokens      : {snapshot.input_tokens:,}\n"
            f"  Cached Input      : {snapshot.cached_tokens:,}\n"
            f"  Output Tokens     : {snapshot.output_tokens:,}\n"
            f"  Reasoning Tokens  : {snapshot.reasoning_tokens:,}\n"
            f"  Total Tokens      : {snapshot.total_tokens:,}\n"
            f"  Estimated Cost    : ${snapshot.cost:.4f} USD\n"
        )
        for phase, phase_snapshot in snapshot.phases.items():
            report += (
                f"  {phase.title():<17}: {phase_snapshot.total_tokens:,} tokens, "
                f"${phase_snapshot.cost:.4f}\n"
            )
        report += f"{'=' * 60}\n"
        logger.info(report)
        print(report)
