"""Shared budgets for asynchronous scan work."""

import asyncio
from dataclasses import dataclass
from typing import Optional


@dataclass
class BudgetSnapshot:
    calls: int
    estimated_tokens: int
    estimated_cost: float
    actual_tokens: int = 0
    actual_cost: float = 0.0


class ScanBudget:
    """A shared admission controller for target, candidate, and follow-up calls."""

    def __init__(
        self,
        max_concurrent: int = 5,
        max_calls: int = 0,
        max_tokens: int = 0,
        max_cost_usd: float = 0.0,
    ):
        self._semaphore = asyncio.Semaphore(max(1, max_concurrent))
        self.max_calls = max_calls
        self.max_tokens = max_tokens
        self.max_cost_usd = max_cost_usd
        self._calls = 0
        self._estimated_tokens = 0
        self._estimated_cost = 0.0
        self._actual_tokens = 0
        self._actual_cost = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self, estimated_tokens: int = 0, estimated_cost: float = 0.0) -> None:
        async with self._lock:
            if self.max_calls and self._calls >= self.max_calls:
                raise RuntimeError("scan LLM call budget exhausted")
            if self.max_tokens and self._estimated_tokens + estimated_tokens > self.max_tokens:
                raise RuntimeError("scan token budget exhausted")
            if self.max_cost_usd and self._estimated_cost + estimated_cost > self.max_cost_usd:
                raise RuntimeError("scan cost budget exhausted")
            self._calls += 1
            self._estimated_tokens += max(0, estimated_tokens)
            self._estimated_cost += max(0.0, estimated_cost)
        await self._semaphore.acquire()

    def release(self) -> None:
        self._semaphore.release()

    def snapshot(self) -> BudgetSnapshot:
        return BudgetSnapshot(
            self._calls,
            self._estimated_tokens,
            self._estimated_cost,
            self._actual_tokens,
            self._actual_cost,
        )

    async def record_actual_usage(self, tokens: int = 0, cost_usd: float = 0.0) -> None:
        """Record provider-reported usage without reserving another call."""
        async with self._lock:
            self._actual_tokens += max(0, tokens)
            self._actual_cost += max(0.0, cost_usd)

    async def run(self, operation, estimated_tokens: int = 0, estimated_cost: float = 0.0):
        await self.acquire(estimated_tokens, estimated_cost)
        try:
            return await operation()
        finally:
            self.release()


class CandidateScheduler:
    """Bound candidate fan-out while preserving result order."""

    def __init__(self, budget: ScanBudget, max_candidates_per_target: int = 12):
        self.budget = budget
        self.max_candidates_per_target = max(1, max_candidates_per_target)

    async def gather(self, operations):
        operations = list(operations)[: self.max_candidates_per_target]
        return await asyncio.gather(*operations)