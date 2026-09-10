"""Bounded scheduling for scan candidates."""

import asyncio


class CandidateScheduler:
    """Bound candidate fan-out while preserving result order."""

    def __init__(self, max_candidates_per_target: int = 12):
        self.max_candidates_per_target = max(1, max_candidates_per_target)

    async def gather(self, operations):
        operations = list(operations)[: self.max_candidates_per_target]
        return await asyncio.gather(*operations)