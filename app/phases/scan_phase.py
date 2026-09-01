import asyncio
import json
import logging
import os
from typing import Dict, Optional

from exploit.config import exploit_settings
from exploit.domain_mapping import DEFAULT_DOMAIN, infer_domain
from scan.orchestrator import ScanOrchestrator

from app.phases.exploit_phase import ExploitPhase

logger = logging.getLogger(__name__)

MAX_CONCURRENT_SCANS = 5

# Applied only when no domain was selected and no --target-file was given (an
# unscoped, whole-repository scan) and the user did not pass --limit explicitly.
# Keeps the historical safety default for that one case; a domain-scoped scan
# defaults to exhaustive instead (see resolve_scan_limit).
DEFAULT_GLOBAL_SCAN_LIMIT = 50


def resolve_scan_limit(limit: Optional[int], scan_all: bool, target_file: Optional[str], selected_domain: Optional[str]) -> int:
    """
    Determines the max-targets cap actually applied to a scan.

    Previously this was computed as `0 if (scan_all or target_file) else args.limit`
    BEFORE domain selection ran, with --limit defaulting to 50 -- so choosing a
    domain interactively still silently capped the scan at 50 functions with no
    way to tell that from an explicit `--limit 50`. Returns 0 for "uncapped".
    """
    if scan_all or target_file:
        return 0
    if limit is not None:
        return limit
    if selected_domain:
        return 0
    return DEFAULT_GLOBAL_SCAN_LIMIT


class ScanPhase:
    """Phase 3: prioritize targets, scan them concurrently, and hand any UDS-reachable
    findings off to the ExploitPhase."""

    def __init__(
        self,
        orchestrator: ScanOrchestrator,
        exploit_phase: ExploitPhase,
        cache_dir: str,
        max_concurrent: int = MAX_CONCURRENT_SCANS,
    ):
        self.orchestrator = orchestrator
        self.exploit_phase = exploit_phase
        self.cache_dir = cache_dir
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.max_concurrent = max_concurrent

    async def prioritize(self, max_targets: int, domain_filter: Optional[str], file_filter: Optional[str]) -> list:
        return await self.orchestrator.prioritize_targets(
            max_targets=max_targets, domain_filter=domain_filter, file_filter=file_filter
        )

    async def run(self, targets: list, selected_domain: Optional[str], all_reports: Dict[str, dict]) -> Dict[str, dict]:
        if not targets:
            return all_reports

        queue: asyncio.Queue = asyncio.Queue()
        for t in targets:
            queue.put_nowait(t)

        async def worker():
            while True:
                try:
                    target_func = queue.get_nowait()
                except asyncio.QueueEmpty:
                    return
                try:
                    await self._scan_one(target_func, selected_domain, all_reports)
                except Exception as e:
                    logger.error(f"Worker failed on {target_func}: {e}")
                finally:
                    queue.task_done()

        workers = [asyncio.create_task(worker()) for _ in range(self.max_concurrent)]
        try:
            await queue.join()
        except asyncio.CancelledError:
            logger.warning("\nExecution was cancelled. Shutting down gracefully...")
            for w in workers:
                w.cancel()
            raise
        return all_reports

    async def _scan_one(self, target_func: str, selected_domain: Optional[str], all_reports: Dict[str, dict]) -> None:
        async with self.semaphore:
            try:
                report = await self.orchestrator.scan_function(target_func)
            except asyncio.CancelledError:
                logger.warning(f"Scan task for {target_func} was cancelled.")
                raise
            except Exception as exc:
                logger.error(f"Scan for {target_func} crashed: {exc}")
                return

            all_reports[target_func] = report
            with open(os.path.join(self.cache_dir, f"{target_func}.json"), 'w') as f:
                json.dump(report, f)

            if not report.get("vulnerability_found"):
                logger.info(f"✔ [CLEAN] -> {target_func}")
                return

            logger.warning(f"⚠️ [VULNERABILITY FOUND] -> {target_func} ({report.get('severity')})")

            taint_val = report.get("metadata", {}).get("TaintedByUDS", False)
            is_uds = taint_val is True or str(taint_val).lower() == "true"
            if not is_uds:
                logger.info(f"⏭️ [SKIPPED EXPLOIT] -> {target_func} is not reachable via UDS/DoIP.")
                return

            domain_to_use = selected_domain
            if not domain_to_use:
                file_path = report.get("metadata", {}).get("FilePath", "")
                domain_to_use = infer_domain(file_path, exploit_settings.target_map)

            await self.exploit_phase.enqueue(report, target_func, domain_to_use)

    @staticmethod
    def resume_pending_exploits(all_reports: Dict[str, dict], selected_domain: Optional[str]) -> list:
        """Returns (func_name, report, domain) tuples for cached vulnerable/UDS reports
        that don't yet have exploit_validation, for use with --resume."""
        pending = []
        for func_name, report in all_reports.items():
            is_uds = report.get("metadata", {}).get("TaintedByUDS") is True
            if report.get("vulnerability_found") and "exploit_validation" not in report and is_uds:
                domain_to_use = selected_domain if selected_domain else report.get("domain", DEFAULT_DOMAIN)
                pending.append((func_name, report, domain_to_use))
        return pending
