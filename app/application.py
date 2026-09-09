"""UI-neutral application service for running scan workflows."""

import asyncio
import inspect
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable

from app.context import AppContext
from app.events import AppEvent, EventKind, EventSink
from app.phases.discovery_phase import DiscoveryPhase
from app.phases.domain_selection import select_domain
from app.phases.exploit_phase import ExploitPhase
from app.phases.ingestion_phase import IngestionPhase
from app.phases.reporting_phase import generate_final_report
from app.phases.scan_phase import ScanPhase, resolve_scan_limit
from app.state import ScanSession
from app.storage.repositories import ScanCacheRepository
from tools.scanning import ScanService
from tools.scanning.orchestrator import ScanOrchestrator
from tools.scanning.reporter import ScanReporter
from tools.scanning.contracts import ScanReport

logger = logging.getLogger(__name__)

DomainSelector = Callable[
    [list, bool, str | None],
    str | None | Awaitable[str | None],
]
Confirmation = Callable[[str], bool | Awaitable[bool]]


@dataclass(frozen=True)
class ScanRequest:
    """Inputs required to run a scan without depending on argparse."""

    source_directory: Path
    limit: int | None = None
    scan_all: bool = False
    target_file: str | None = None
    resume: bool = False
    skip_ingest: bool = False
    skip_exploit: bool = False
    exploit_only: Path | None = None


@dataclass
class ScanResult:
    """Stable result returned to CLI, TUI, or another frontend."""

    reports: dict[str, dict[str, Any]]
    cancelled: bool = False
    exploit_results: dict[str, dict[str, Any]] | None = None

    @property
    def validated_reports(self) -> dict[str, ScanReport]:
        """Return report envelopes validated at the application boundary."""
        return {name: ScanReport.model_validate(report) for name, report in self.reports.items()}


class ScanApplication:
    """Coordinate scan phases while keeping UI and terminal concerns outside."""

    def __init__(
        self,
        context: AppContext,
        *,
        reporter: ScanReporter | None = None,
        cache_dir: str = "scan_cache",
        report_dir: str = "reports",
        event_sink: EventSink | None = None,
        output: Callable[[str], None] | None = print,
        domain_selector: DomainSelector = select_domain,
        confirm: Confirmation | None = None,
        max_candidates_per_target: int = 12,
    ) -> None:
        self.context = context
        self.reporter = reporter or ScanReporter(output_dir=report_dir)
        self.cache_dir = cache_dir
        self.report_dir = report_dir
        self.event_sink = event_sink
        self.output = output
        self.domain_selector = domain_selector
        self.confirm = confirm or (lambda _message: True)
        self.max_candidates_per_target = max_candidates_per_target
        self.session = ScanSession()
        self._active_exploit_phase: ExploitPhase | None = None
        self._current_reports: dict[str, dict[str, Any]] = {}
        if hasattr(self.context.llm, "set_usage_listener"):
            self.context.llm.set_usage_listener(self._on_usage)
        if hasattr(self.context.llm, "set_pause_waiter"):
            self.context.llm.set_pause_waiter(self.session.wait_if_paused)

    async def run(self, request: ScanRequest) -> ScanResult:
        """Run either the normal pipeline or direct exploit validation."""
        self.session.task = asyncio.current_task()
        try:
            source_directory = request.source_directory.resolve()
            if not source_directory.is_dir():
                raise NotADirectoryError(str(source_directory))
            if request.exploit_only:
                result = await self._run_exploit_only(request.exploit_only)
            else:
                result = await self._run_full_pipeline(
                    ScanRequest(
                        source_directory=source_directory,
                        limit=request.limit,
                        scan_all=request.scan_all,
                        target_file=request.target_file,
                        resume=request.resume,
                        skip_ingest=request.skip_ingest,
                        skip_exploit=request.skip_exploit,
                        exploit_only=request.exploit_only,
                    )
                )
            self._emit(AppEvent(phase="application", kind=EventKind.COMPLETE))
            return result
        except asyncio.CancelledError:
            if self._active_exploit_phase is not None:
                await self._active_exploit_phase.cancel_and_wait()
            self._emit(
                AppEvent(phase="application", kind=EventKind.CANCELLED)
            )
            return ScanResult(reports=self._current_reports, cancelled=True)

    def _emit(self, event: AppEvent) -> None:
        if self.event_sink is not None:
            self.event_sink.emit(event)

    def _on_usage(self, usage: dict[str, Any], cost_usd: float) -> None:
        input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
        output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
        self._emit(
            AppEvent(
                phase="llm",
                kind=EventKind.PHASE_UPDATED,
                message="LLM usage updated",
                payload={
                    "usage": {
                        "total_tokens": input_tokens + output_tokens,
                        "cost_usd": cost_usd,
                    }
                },
            )
        )

    @staticmethod
    async def _resolve_interaction(value: Any) -> Any:
        if inspect.isawaitable(value):
            return await value
        return value

    async def _run_exploit_only(self, report_path: Path) -> ScanResult:
        exploit_phase = ExploitPhase(
            self.context.llm,
            cache_dir=self.report_dir,
            event_sink=self.event_sink,
            graph_manager=self.context.graph,
        )
        self._active_exploit_phase = exploit_phase
        results = await exploit_phase.run_standalone(str(report_path))
        await asyncio.to_thread(
            generate_final_report,
            exploit_phase.standalone_reports,
            self.reporter,
            self.output,
        )
        return ScanResult(
            reports=exploit_phase.standalone_reports,
            exploit_results=results,
        )

    async def _run_full_pipeline(self, request: ScanRequest) -> ScanResult:
        os.makedirs(self.cache_dir, exist_ok=True)
        self._emit(AppEvent(phase="discovery", kind=EventKind.PHASE_STARTED))
        discovery = DiscoveryPhase(self.context.llm, self.cache_dir)
        used_cache = discovery.used_cache(request.skip_ingest)
        config_json = await discovery.run(
            str(request.source_directory),
            skip_ingest=request.skip_ingest,
        )
        if used_cache:
            logger.info("--- PHASE 2: Skipped (using cached graph) ---")
        else:
            self._emit(AppEvent(phase="ingestion", kind=EventKind.PHASE_STARTED))
            await asyncio.to_thread(
                IngestionPhase().run,
                str(request.source_directory),
                self.context.graph,
                config_json,
            )

        mcu = config_json.get("mcu_guess", "Unknown MCU")
        vendor = config_json.get("stack_vendor", "Generic AutoSAR")
        platform_info = f"Hardware: {mcu}, Stack: {vendor}"
        orchestrator = ScanOrchestrator(
            self.context.llm,
            self.context.graph,
            platform_info=platform_info,
            scan_budget=self.context.scan_budget,
            max_candidates_per_target=self.max_candidates_per_target,
        )
        scan_service = ScanService(orchestrator)
        selected_domain = await self._resolve_interaction(
            self.domain_selector(
                config_json.get("app_domains", []),
                request.scan_all,
                request.target_file,
            )
        )
        scan_limit = resolve_scan_limit(
            request.limit,
            request.scan_all,
            request.target_file,
            selected_domain,
        )

        all_reports: dict[str, dict[str, Any]] = {}
        self._current_reports = all_reports
        if request.resume:
            cached_reports = ScanCacheRepository(self.cache_dir).load_all(
                exclude={"discovery_config.json"}
            )
            for cached_name, report in cached_reports.items():
                func_name = report.get("_target_function", cached_name)
                all_reports[func_name] = report
                self._emit(
                    AppEvent(
                        phase="resume",
                        target=func_name,
                        kind=EventKind.TARGET_FINISHED,
                        status="complete",
                        message="Loaded cached report",
                        payload={"report": report},
                    )
                )

        exploit_phase = ExploitPhase(
            self.context.llm,
            self.cache_dir,
            skip=request.skip_exploit,
            event_sink=self.event_sink,
            graph_manager=self.context.graph,
        )
        self._active_exploit_phase = exploit_phase
        scan_phase = ScanPhase(
            scan_service,
            exploit_phase,
            self.cache_dir,
            event_sink=self.event_sink,
        )
        top_targets = await scan_phase.prioritize(
            max_targets=scan_limit,
            domain_filter=selected_domain,
            file_filter=request.target_file,
        )
        targets_to_scan = [
            target
            for target in top_targets
            if target not in all_reports or all_reports[target].get("scan_status") == "error"
        ]
        if targets_to_scan and scan_limit == 0 and not request.target_file:
            scope = "global scan-all" if request.scan_all else "uncapped scan"
            confirmed = await self._resolve_interaction(
                self.confirm(
                    f"An uncapped {scope} selected {len(targets_to_scan)} targets. Continue?"
                )
            )
            if not confirmed:
                return ScanResult(reports=all_reports)

        if targets_to_scan:
            exploit_phase.start()
            if request.resume:
                for func_name, report, domain in scan_phase.resume_pending_exploits(
                    all_reports, selected_domain
                ):
                    await exploit_phase.enqueue(report, func_name, domain)
            await scan_phase.run(
                targets_to_scan,
                selected_domain,
                all_reports,
                pause_waiter=self.session.wait_if_paused,
            )
            await exploit_phase.drain()

        await asyncio.to_thread(
            generate_final_report,
            all_reports,
            self.reporter,
            self.output,
        )
        return ScanResult(reports=all_reports)

    def cancel(self) -> None:
        """Cancel the currently running application task, if one exists."""
        self.session.cancel()
        if self._active_exploit_phase is not None:
            self._active_exploit_phase.cancel()

    def pause(self) -> None:
        """Pause target scheduling after any active target work completes."""
        self.session.pause()

    def resume(self) -> None:
        """Resume target scheduling for queued work."""
        self.session.resume()
