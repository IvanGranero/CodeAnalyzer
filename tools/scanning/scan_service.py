"""Application service for prioritized vulnerability scanning."""

from typing import Any

from tools.scanning.orchestrator import ScanOrchestrator


class ScanService:
    """Stable application boundary around the scan workflow."""

    def __init__(self, orchestrator: ScanOrchestrator):
        self.orchestrator = orchestrator

    async def prioritize_targets(self, **filters: Any) -> list[str]:
        return await self.orchestrator.prioritize_targets(**filters)

    async def scan_function(self, target_function: str) -> dict[str, Any]:
        return await self.orchestrator.scan_function(target_function)

    def set_progress_callback(self, progress: Any) -> None:
        """Forward user-facing progress events to the owning orchestrator."""
        self.orchestrator.set_progress_callback(progress)
