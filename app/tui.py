"""Textual adapter for the UI-neutral scan application."""

from __future__ import annotations

import logging
import traceback
from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    DataTable,
    Footer,
    Header,
    Label,
    ProgressBar,
    RichLog,
    Select,
    Static,
)

from app.application import ScanApplication, ScanRequest
from app.context import build_app_context, shutdown
from app.events import AppEvent, EventKind, EventQueue
from app.state import ScanState

logger = logging.getLogger(__name__)


class DomainSelectionScreen(ModalScreen[str | None]):
    """Ask for a scan domain without blocking the Textual event loop."""

    CSS = """
    DomainSelectionScreen, ConfirmationScreen {
        align: center middle;
    }
    #dialog {
        width: 64;
        height: auto;
        padding: 2;
        background: $surface;
        border: round $accent;
    }
    #actions {
        height: auto;
        margin-top: 1;
        align-horizontal: right;
    }
    #actions Button {
        margin-left: 1;
    }
    """

    def __init__(self, domains: list[str]) -> None:
        super().__init__()
        self.domains = domains

    def compose(self) -> ComposeResult:
        options = [(domain, domain) for domain in self.domains]
        options.append(("All domains", ""))
        with Vertical(id="dialog"):
            yield Label("Choose the application domain to scan")
            yield Select(options, prompt="Domain", id="domain")
            with Horizontal(id="actions"):
                yield Button("Scan", variant="primary", id="accept")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "cancel":
            self.dismiss(None)
            return
        if event.button.id == "accept":
            value = self.query_one("#domain", Select).value
            self.dismiss(value or None)

    def on_select_changed(self, event: Select.Changed) -> None:
        """Continue as soon as the operator chooses a domain."""
        if event.value is not Select.BLANK:
            self.dismiss(event.value or None)


class ConfirmationScreen(ModalScreen[bool]):
    """Confirm an expensive uncapped scan in the TUI."""

    def __init__(self, message: str) -> None:
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        with Vertical(id="dialog"):
            yield Label(self.message)
            with Horizontal(id="actions"):
                yield Button("Continue", variant="primary", id="accept")
                yield Button("Cancel", id="cancel")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "accept")


class ScanTUI(App[None]):
    """Render scan state while keeping orchestration in ``ScanApplication``."""

    CSS = """
    Screen {
        layout: vertical;
    }
    #summary {
        height: 4;
        padding: 0 1;
        background: $surface;
        border-bottom: solid $accent;
    }
    #summary Label {
        width: 1fr;
        padding: 1 1;
    }
    #progress {
        margin: 1 2;
    }
    #workspace {
        height: 1fr;
    }
    #findings {
        width: 62%;
        margin: 1 0 0 1;
        border: round $accent;
    }
    #evidence {
        width: 38%;
        margin: 1 1 0 1;
        padding: 1;
        border: round $accent;
        overflow-y: auto;
    }
    #activity {
        height: 8;
        margin: 1;
        border: round $accent;
    }
    #evidence-title {
        text-style: bold;
        color: $accent;
    }
    #progress {
        margin: 0 1;
    }
    """

    BINDINGS = [
        ("c", "cancel_scan", "Cancel"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, request: ScanRequest, context) -> None:
        super().__init__()
        self.request = request
        self.context = context
        self.events = EventQueue()
        self.state = ScanState()
        self.application: ScanApplication | None = None
        self._finding_rows: dict[str, dict] = {}

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Horizontal(id="summary"):
            yield Label("Stage: waiting", id="phase")
            yield Label("Targets: 0/0", id="count")
            yield Label("Active: 0 | Errors: 0", id="workers")
            yield Label("LLM: 0 tokens | $0.00", id="usage")
            yield Label("Status: ready", id="status")
        yield ProgressBar(total=1, show_eta=False, id="progress")
        with Horizontal(id="workspace"):
            yield DataTable(id="findings", cursor_type="row", zebra_stripes=True)
            with Vertical(id="evidence"):
                yield Label("Select a finding", id="evidence-title")
                yield Static("Finding evidence will appear here.", id="evidence-body")
        yield RichLog(id="activity", wrap=True, highlight=True)
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#findings", DataTable)
        table.add_columns("Target", "Severity", "Confidence", "Class", "File", "Review")
        self.run_worker(
            self._run_scan(),
            name="scan",
            exclusive=True,
        )
        self.run_worker(self._consume_events(), exclusive=False)

    async def _run_scan(self) -> None:
        self.application = ScanApplication(
            self.context,
            event_sink=self.events,
            output=None,
            confirm=self._confirm,
            domain_selector=self._select_domain,
        )
        try:
            await self.application.run(self.request)
        except Exception as exc:
            logger.exception("Textual scan failed")
            self.events.emit(
                AppEvent(
                    phase="application",
                    kind=EventKind.ERROR,
                    message=f"{type(exc).__name__}: {exc}",
                    payload={"traceback": traceback.format_exc()},
                )
            )

    async def _select_domain(
        self,
        domains: list,
        scan_all: bool,
        target_file: str | None,
    ) -> str | None:
        if scan_all or target_file or not domains:
            return None
        return await self.push_screen_wait(DomainSelectionScreen([str(domain) for domain in domains]))

    async def _confirm(self, message: str) -> bool:
        return await self.push_screen_wait(ConfirmationScreen(message))

    async def _consume_events(self) -> None:
        while True:
            event = await self.events.get()
            try:
                self.state.apply(event)
                self._render_event(event)
                if event.kind in {
                    EventKind.COMPLETE,
                    EventKind.CANCELLED,
                    EventKind.ERROR,
                }:
                    return
            finally:
                self.events.task_done()

    def _render_event(self, event: AppEvent) -> None:
        self.query_one("#phase", Label).update(f"Stage: {self.state.phase or 'waiting'}")
        self.query_one("#count", Label).update(
            f"Targets: {self.state.completed}/{self.state.total}"
        )
        self.query_one("#workers", Label).update(
            f"Active: {self.state.active_workers} | Errors: {self.state.error_count}"
        )
        self.query_one("#usage", Label).update(
            f"LLM: {self.state.llm_tokens:,} tokens | ${self.state.llm_cost:.2f}"
        )
        if self.state.cancelled:
            status = "cancelled"
        elif event.kind == EventKind.ERROR:
            status = f"error: {event.message}"
        else:
            status = event.kind.value
        self.query_one("#status", Label).update(f"Status: {status}")

        progress = self.query_one("#progress", ProgressBar)
        progress.total = max(self.state.total, 1)
        progress.update(progress=self.state.completed)

        if event.target:
            target = self.state.targets[event.target]
            self._update_finding(event.target, target.report)
            self.query_one("#activity", RichLog).write(
                f"{target.status.value:9} {event.target} | {event.message}"
            )
        elif event.message:
            self.query_one("#activity", RichLog).write(event.message)
            if event.kind == EventKind.ERROR:
                traceback_text = event.payload.get("traceback")
                if traceback_text:
                    self.query_one("#activity", RichLog).write(str(traceback_text))

    def _update_finding(self, target: str, report: dict | None) -> None:
        if not report or not report.get("vulnerability_found"):
            return
        self._finding_rows[target] = report
        metadata = report.get("metadata", {}) or {}
        file_path = metadata.get("FilePath", metadata.get("file_path", "-"))
        findings = report.get("findings", []) or [{}]
        finding = findings[0] if isinstance(findings[0], dict) else {}
        classification = finding.get(
            "vulnerability_type",
            report.get("vulnerability_type", "unknown"),
        )
        review = "review" if finding.get("needs_human_review") else "ready"
        table = self.query_one("#findings", DataTable)
        row_key = target
        if row_key in table.rows:
            table.remove_row(row_key)
        table.add_row(
            target,
            str(report.get("severity", "-")),
            str(report.get("confidence", "-")),
            str(classification),
            str(file_path),
            review,
            key=row_key,
        )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        report = self._finding_rows.get(str(event.row_key.value))
        if report is not None:
            self._show_evidence(str(event.row_key.value), report)

    def _show_evidence(self, target: str, report: dict) -> None:
        metadata = report.get("metadata", {}) or {}
        finding = (report.get("findings") or [{}])[0]
        finding = finding if isinstance(finding, dict) else {}
        context = report.get("exploit_context", {}) or {}
        references = finding.get("evidence_references", []) or []
        lines = [
            f"Target: {target}",
            f"Severity: {report.get('severity', '-')}",
            f"Confidence: {report.get('confidence', '-')}",
            f"File: {metadata.get('FilePath', metadata.get('file_path', '-'))}",
            f"Byte span: {metadata.get('ByteSpan', metadata.get('byte_span', '-'))}",
            "",
            "Classification",
            str(finding.get("vulnerability_type", report.get("vulnerability_type", "-"))),
            "",
            "Agent rationale",
            str(finding.get("details") or finding.get("evidence") or report.get("details", "-")),
            "",
            "Taint / call / CFG evidence",
            str(context.get("evidence") or report.get("evidence", "-")),
            "",
            "Concurrency / unresolved references",
            str(context.get("limitations") or report.get("limitations", "-")),
            "",
            "Source references",
        ]
        lines.extend(str(reference) for reference in references or ["-"])
        self.query_one("#evidence-title", Label).update(f"Evidence: {target}")
        self.query_one("#evidence-body", Static).update("\n".join(lines))

    def action_cancel_scan(self) -> None:
        if self.application is not None:
            self.application.cancel()
            self.query_one("#status", Label).update("Status: cancelling")

    async def on_unmount(self) -> None:
        if self.application is not None:
            self.application.cancel()


def run_tui(args) -> None:
    """Build core services, run Textual, and release shared resources."""
    from config import settings

    source_directory = Path(args.source_dir).resolve()
    if not source_directory.is_dir():
        raise NotADirectoryError(str(source_directory))

    context = build_app_context(settings)
    request = ScanRequest(
        source_directory=source_directory,
        limit=args.limit,
        scan_all=args.scan_all,
        target_file=args.target_file,
        resume=args.resume,
        skip_ingest=args.skip_ingest,
        skip_exploit=args.skip_exploit,
        exploit_only=Path(args.exploit_only) if args.exploit_only else None,
    )
    try:
        ScanTUI(request, context).run()
    finally:
        shutdown(context)