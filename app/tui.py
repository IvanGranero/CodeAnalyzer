"""Textual adapter for the UI-neutral scan application."""

from __future__ import annotations

import json
import logging
import traceback
from pathlib import Path
from typing import Any, Callable

from textual import events, on
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


class FindingTable(DataTable):
    """Make the first click on a different row an explicit selection."""

    def __init__(
        self,
        *args,
        on_finding_selected: Callable[[str], None] | None = None,
        **kwargs,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.on_finding_selected = on_finding_selected

    def _select_row(self, row_index: int) -> None:
        if not 0 <= row_index < self.row_count:
            return
        key = self._row_locations.get_key(row_index)
        row_key = str(getattr(key, "value", None) or key)
        if self.on_finding_selected is not None:
            self.on_finding_selected(row_key)
        self.post_message(DataTable.RowSelected(self, row_index, row_key))

    def watch_cursor_coordinate(self, old_coordinate, new_coordinate) -> None:
        super().watch_cursor_coordinate(old_coordinate, new_coordinate)
        self._select_row(new_coordinate.row)

    def on_mouse_down(self, event: events.MouseDown) -> None:
        meta = event.style.meta
        row_index = meta.get("row")
        if isinstance(row_index, int):
            self._select_row(row_index)

    async def _on_click(self, event) -> None:
        meta = event.style.meta
        if isinstance(meta.get("row"), int):
            self._select_row(meta["row"])
        await super()._on_click(event)
        if self.cursor_type != "row" or "row" not in meta:
            return
        row_index = meta["row"]
        self._select_row(row_index)

    def action_cursor_up(self) -> None:
        super().action_cursor_up()
        self._select_row(self.cursor_row)

    def action_cursor_down(self) -> None:
        super().action_cursor_down()
        self._select_row(self.cursor_row)

    def action_select_cursor(self) -> None:
        super().action_select_cursor()
        self._select_row(self.cursor_row)


class ScanTUI(App[None]):
    """Render scan state while keeping orchestration in ``ScanApplication``."""

    CSS = """
    Screen {
        layout: vertical;
        background: $background;
    }
    Header {
        background: $primary;
    }
    #overview {
        height: 7;
        padding: 1 2;
        background: $panel;
        border-bottom: solid $accent;
    }
    #overview-title {
        height: 1;
        text-style: bold;
        color: $accent;
    }
    #scan-controls {
        height: 1;
        align: right middle;
    }
    #pause-scan {
        min-width: 16;
    }
    #metrics {
        height: 1;
    }
    #exploit-metrics {
        height: 1;
    }
    #exploit-metrics Label {
        width: 1fr;
        padding-right: 2;
        color: $text-muted;
    }
    #metrics Label {
        width: 1fr;
        padding-right: 2;
        color: $text-muted;
    }
    #progress {
        margin: 0 2;
        color: $accent;
    }
    #exploit-progress {
        margin: 0 2;
        color: $success;
    }
    #workspace {
        height: 1fr;
        padding: 1 2 0 2;
    }
    #findings-pane, #evidence-pane {
        height: 1fr;
        border: round $accent;
        background: $surface;
    }
    #findings-pane {
        width: 60%;
        margin-right: 1;
    }
    #evidence-pane {
        width: 40%;
        padding: 1;
        overflow-y: auto;
    }
    #findings-heading {
        height: 2;
        padding: 1 1 0 1;
        text-style: bold;
        color: $accent;
    }
    #findings {
        height: 1fr;
        min-height: 5;
    }
    #evidence-title {
        height: auto;
        text-style: bold;
        color: $accent;
        padding-bottom: 1;
    }
    #evidence-body {
        height: 1fr;
        overflow-y: auto;
        color: $text;
        border-top: solid $panel;
        padding: 1;
    }
    #activity {
        height: 9;
        margin: 1 2;
        border: round $panel;
        background: $surface;
    }
    """

    BINDINGS = [
        ("p", "pause_scan", "Pause"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, request: ScanRequest, context) -> None:
        super().__init__()
        self.request = request
        self.context = context
        self.events = EventQueue()
        self.state = ScanState()
        self.application: ScanApplication | None = None
        self._finding_rows: dict[str, tuple[str, dict, dict]] = {}
        self._selected_row_key: str | None = None
        self._scan_paused = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        with Vertical(id="overview"):
            yield Label("SCAN OVERVIEW  /  LIVE ANALYSIS", id="overview-title")
            with Horizontal(id="metrics"):
                yield Label("Stage: waiting", id="phase")
                yield Label("Targets: 0 done / 0 remaining", id="count")
                yield Label("Workers: 0  |  Errors: 0", id="workers")
                yield Label("LLM: 0 tokens  |  $0.00", id="usage")
                yield Label("Status: ready", id="status")
            with Horizontal(id="exploit-metrics"):
                yield Label("Exploits: 0/0 (0%)", id="exploit-count")
                yield Label("Validated: 0  |  Failed: 0", id="exploit-results")
                yield Label("Current exploit: idle", id="exploit-current")
            with Horizontal(id="scan-controls"):
                yield Button("Pause", id="pause-scan")
        yield ProgressBar(total=1, show_eta=False, id="progress")
        yield ProgressBar(total=1, show_eta=False, id="exploit-progress")
        with Horizontal(id="workspace"):
            with Vertical(id="findings-pane"):
                yield Label("FINDINGS  /  focus a row, press Enter to inspect", id="findings-heading")
                yield FindingTable(
                    id="findings",
                    cursor_type="row",
                    zebra_stripes=True,
                    on_finding_selected=self._select_finding,
                )
            with Vertical(id="evidence-pane"):
                yield Label("Select a finding", id="evidence-title")
                yield RichLog(id="evidence-body", wrap=True, highlight=True, markup=False)
        yield RichLog(id="activity", wrap=True, highlight=True)
        yield Footer()

    async def on_mount(self) -> None:
        self._set_pause_binding(False)
        table = self.query_one("#findings", FindingTable)
        table.on_finding_selected = self._select_finding
        self.query_one("#evidence-body", RichLog).write(
            "Finding evidence will appear here."
        )
        table.add_columns(
            "Severity", "Confidence", "Rule / classification", "File:line",
            "Target function", "Exploit status", "Review",
        )
        self.run_worker(
            self._run_scan(),
            name="scan",
            exclusive=True,
        )
        self.run_worker(self._consume_events(), exclusive=False)

    async def _run_scan(self) -> None:
        try:
            self.application = ScanApplication(
                self.context,
                event_sink=self.events,
                output=None,
                confirm=self._confirm,
                domain_selector=self._select_domain,
            )
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
            f"Targets: {self.state.completed} done / {max(self.state.total - self.state.completed, 0)} remaining"
        )
        self.query_one("#workers", Label).update(
            f"Workers: {self.state.active_workers}  |  Errors: {self.state.error_count}"
        )
        self.query_one("#exploit-count", Label).update(
            f"Exploits: {self.state.exploit_completed}/{self.state.exploit_total} "
            f"({self.state.exploit_percent:.0f}%)"
        )
        self.query_one("#exploit-results", Label).update(
            f"Validated: {self.state.exploit_successful} "
            f"({self.state.exploit_success_percent:.0f}%)  |  Failed: {self.state.exploit_failed}"
        )
        current = self.state.exploit_current or "idle"
        if self.state.exploit_message:
            current = f"{current} | {self.state.exploit_message}"
        self.query_one("#exploit-current", Label).update(f"Current exploit: {current}")
        self.query_one("#usage", Label).update(
            f"LLM: {self.state.llm_tokens:,} tokens | ${self.state.llm_cost:.2f}"
        )
        if self._scan_paused:
            status = "paused"
        elif self.state.cancelled:
            status = "cancelled"
        elif event.kind == EventKind.ERROR:
            status = f"error: {event.message}"
        else:
            status = event.kind.value
        self.query_one("#status", Label).update(f"Status: {status}")
        self._update_pause_control()

        if self._scan_paused and event.kind not in {
            EventKind.COMPLETE,
            EventKind.CANCELLED,
            EventKind.ERROR,
        }:
            return

        progress = self.query_one("#progress", ProgressBar)
        progress.total = max(self.state.total, 1)
        progress.update(progress=self.state.completed)
        exploit_progress = self.query_one("#exploit-progress", ProgressBar)
        exploit_progress.total = max(self.state.exploit_total, 1)
        exploit_progress.update(progress=self.state.exploit_completed)

        if event.phase == "exploit":
            exploit = self.state.exploits.get(event.target)
            if exploit is not None:
                selected_row_key = self._selected_row_key
                self._update_finding(event.target, exploit.report)
                if selected_row_key and selected_row_key.startswith(f"{event.target}:"):
                    self._select_finding(selected_row_key)
                self.query_one("#activity", RichLog).write(
                    f"{exploit.status:9} {event.target} | {event.message}"
                )
            elif event.message:
                self.query_one("#activity", RichLog).write(event.message)
            return

        if event.target:
            target = self.state.targets[event.target]
            self._update_finding(event.target, target.report)
            self.query_one("#activity", RichLog).write(
                f"{target.status.value:9} {event.target} | {event.message}"
            )
        elif event.message and event.message != "LLM usage updated":
            self.query_one("#activity", RichLog).write(event.message)
            if event.kind == EventKind.ERROR:
                traceback_text = event.payload.get("traceback")
                if traceback_text:
                    self.query_one("#activity", RichLog).write(str(traceback_text))

    def _update_finding(self, target: str, report: dict | None) -> None:
        if not report:
            return
        metadata = report.get("metadata", {}) or {}
        findings = [item for item in (report.get("findings") or []) if isinstance(item, dict)]
        supported_findings = [
            finding for finding in findings
            if finding.get("status") in {"supported", "confirmed"}
            or finding.get("vulnerability_found") is True
        ]
        if supported_findings:
            findings = supported_findings
        if not findings:
            if not report.get("vulnerability_found"):
                return
            findings = [report]
        table = self.query_one("#findings", DataTable)
        stale_rows = [row_key for row_key in self._finding_rows if row_key.startswith(f"{target}:")]
        for row_key in stale_rows:
            self._finding_rows.pop(row_key, None)
            if row_key in table.rows:
                table.remove_row(row_key)
        if self._selected_row_key in stale_rows:
            self._selected_row_key = None
            self.query_one("#findings-heading", Label).update(
                "FINDINGS  /  focus a row, press Enter to inspect"
            )
        for index, finding in enumerate(findings):
            row_key = f"{target}:{index}"
            self._finding_rows[row_key] = (target, report, finding)
            classification = finding.get("vulnerability_type", report.get("vulnerability_type", "unknown"))
            severity = finding.get("severity", report.get("severity", "-"))
            confidence = finding.get("confidence", report.get("confidence", "-"))
            file_path = metadata.get("FilePath", metadata.get("file_path", "-"))
            line = self._first_value(finding, "line", "line_number")
            line = line or self._first_value(metadata, "Line", "line", "line_number")
            location = f"{file_path}:{line}" if line else str(file_path)
            function = self._first_value(
                finding, "target_function", "function_name"
            ) or report.get("_target_function") or target
            exploitability = self._exploit_status(report, finding)
            review = "REVIEW" if finding.get("needs_human_review", report.get("needs_human_review")) else "READY"
            if row_key in table.rows:
                table.remove_row(row_key)
            table.add_row(
                str(severity), str(confidence), str(classification), location,
                str(function), exploitability, review, key=row_key,
            )

    @on(DataTable.RowSelected)
    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        self._select_finding(self._row_key_text(event.row_key))

    @on(DataTable.RowHighlighted)
    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        row_key = self._row_key_text(event.row_key)
        self._select_finding(row_key)

    @staticmethod
    def _row_key_text(row_key: object) -> str:
        return str(getattr(row_key, "value", None) or row_key)

    def _select_finding(self, row_key: str) -> None:
        row = self._finding_rows.get(row_key)
        if row is None:
            normalized_key = next(
                (
                    key
                    for key in self._finding_rows
                    if str(key) == str(row_key) or str(key) in str(row_key)
                ),
                None,
            )
            if normalized_key is not None:
                row_key = normalized_key
                row = self._finding_rows[row_key]
        if row is not None:
            self._selected_row_key = row_key
            target, report, finding = row
            self.query_one("#findings-heading", Label).update(
                f"FINDINGS  /  selected: {target}"
            )
            self._show_evidence(target, report, finding)

    @staticmethod
    def _first_value(data: dict[str, Any], *keys: str) -> Any:
        for key in keys:
            value = data.get(key)
            if value not in (None, "", [], {}):
                return value
        return None

    @staticmethod
    def _exploitability(report: dict, finding: dict) -> str:
        value = ScanTUI._first_value(
            finding, "exploitability", "exploit_status", "validated"
        )
        context = report.get("exploit_context", {}) or {}
        if value is None and isinstance(context, dict):
            value = ScanTUI._first_value(context, "exploitability", "status")
        return str(value if value is not None else "unassessed")

    @staticmethod
    def _exploit_status(report: dict, finding: dict) -> str:
        validation = report.get("exploit_validation", {}) or {}
        if isinstance(validation, dict) and validation.get("status"):
            return str(validation["status"]).upper()
        return ScanTUI._exploitability(report, finding)

    @staticmethod
    def _format_value(value: Any) -> str:
        if value in (None, "", [], {}):
            return "-"
        if isinstance(value, (dict, list)):
            return json.dumps(value, indent=2, ensure_ascii=False, default=str)
        return str(value)

    def _show_evidence(self, target: str, report: dict, finding: dict) -> None:
        metadata = report.get("metadata", {}) or {}
        context = report.get("exploit_context", {}) or {}
        entry_point = context.get("entry_point", {}) if isinstance(context, dict) else {}
        triage = context.get("triage", {}) if isinstance(context, dict) else {}
        context_evidence = context.get("evidence", {}) if isinstance(context, dict) else {}
        if not isinstance(entry_point, dict):
            entry_point = {}
        if not isinstance(triage, dict):
            triage = {}
        if not isinstance(context_evidence, dict):
            context_evidence = {}
        source = self._first_value(
            finding, "source_snippet", "source_code", "snippet"
        ) or self._first_value(report, "source_snippet", "source_code")
        spans = self._first_value(
            finding, "highlighted_byte_spans", "byte_spans", "byte_span"
        ) or self._first_value(metadata, "ByteSpan", "byte_span")
        taint = self._first_value(
            finding, "taint_path", "taint_paths"
        ) or self._first_value(context_evidence, "taint_path", "taint_paths")
        call_path = self._first_value(
            finding, "call_path", "call_paths"
        ) or self._first_value(context_evidence, "call_path", "call_paths") or self._first_value(entry_point, "call_path", "callers")
        cfg = self._first_value(finding, "cfg", "cfg_blocks") or self._first_value(context_evidence, "cfg", "cfg_blocks")
        concurrency = self._first_value(finding, "concurrency", "concurrency_relationships") or self._first_value(context, "concurrency") or self._first_value(report, "concurrency") or self._first_value(triage, "concurrency")
        unresolved = self._first_value(finding, "unresolved_references", "unresolved") or self._first_value(context, "limitations") or self._first_value(triage, "graph_contradictions") or self._first_value(report, "limitations")
        rationale = self._first_value(finding, "details", "evidence") or report.get("details")
        references = finding.get("evidence_references", []) or []
        source = source or "Source snippet was not persisted in this report."
        taint = taint or {
            "uds_reachable": entry_point.get("uds_reachable", metadata.get("TaintedByUDS")),
            "uds_triggers": entry_point.get("uds_triggers", metadata.get("DIDs", [])),
        }
        cfg = cfg or "CFG blocks were not persisted in this report."
        concurrency = concurrency or "Concurrency relationships were not persisted in this report."
        lines = [
            f"TARGET  {target}",
            f"{finding.get('vulnerability_type', report.get('vulnerability_type', '-'))}  |  severity {finding.get('severity', report.get('severity', '-'))}  |  confidence {finding.get('confidence', report.get('confidence', '-'))}",
            f"FILE  {metadata.get('FilePath', metadata.get('file_path', '-'))}  |  BYTE SPAN  {metadata.get('ByteSpan', metadata.get('byte_span', '-'))}",
            f"REVIEW  {'required' if finding.get('needs_human_review', report.get('needs_human_review')) else 'ready'}  |  EXPLOITABILITY  {self._exploitability(report, finding)}",
            "",
            "EXPLOIT VALIDATION",
            self._format_value(report.get("exploit_validation") or "Not started."),
            "",
            "SOURCE SNIPPET",
            self._format_value(source),
            "",
            "HIGHLIGHTED BYTE SPANS",
            self._format_value(spans),
            "",
            "TAINT PATH",
            self._format_value(taint),
            "",
            "CALL PATH",
            self._format_value(call_path),
            "",
            "CFG BLOCKS",
            self._format_value(cfg),
            "",
            "CONCURRENCY RELATIONSHIPS",
            self._format_value(concurrency),
            "",
            "UNRESOLVED REFERENCES",
            self._format_value(unresolved),
            "",
            "TRIAGE COVERAGE",
            self._format_value(report.get("triage_coverage") or triage.get("coverage")),
            "",
            "GRAPH EVIDENCE SUMMARY",
            self._format_value(context_evidence),
            "",
            "AGENT RATIONALE",
            self._format_value(rationale),
            "",
            "EVIDENCE REFERENCES",
        ]
        lines.extend(self._format_value(reference) for reference in references or ["-"])
        self.query_one("#evidence-title", Label).update(f"Evidence: {target}")
        evidence = self.query_one("#evidence-body", RichLog)
        evidence.clear()
        evidence.write("\n".join(lines))
        evidence.scroll_home(animate=False)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "pause-scan":
            if self._scan_paused:
                self.action_resume_scan()
            else:
                self.action_pause_scan()

    def _update_pause_control(self) -> None:
        button = self.query_one("#pause-scan", Button)
        button.label = "Resume" if self._scan_paused else "Pause"

    def _set_pause_binding(self, paused: bool) -> None:
        bindings = self._bindings.key_to_bindings
        for key in ("p", "r"):
            bindings[key] = [
                binding
                for binding in bindings.get(key, [])
                if binding.action not in {"pause_scan", "resume_scan"}
            ]
            if not bindings[key]:
                bindings.pop(key, None)
        self.bind(
            "r" if paused else "p",
            "resume_scan" if paused else "pause_scan",
            description="Resume" if paused else "Pause",
        )
        self.screen.refresh_bindings()

    def action_pause_scan(self) -> None:
        if self.application is not None and not self._scan_paused:
            self.application.pause()
            self._scan_paused = True
            self.query_one("#status", Label).update("Status: paused")
            self._set_pause_binding(True)
            self._update_pause_control()

    def action_resume_scan(self) -> None:
        if self.application is not None and self._scan_paused:
            self.application.resume()
            self._scan_paused = False
            self.query_one("#status", Label).update("Status: resuming")
            self._set_pause_binding(False)
            self._update_pause_control()

    async def on_unmount(self) -> None:
        if self.application is not None:
            self.application.cancel()


def run_tui(args) -> None:
    """Build core services, run Textual, and release shared resources."""

    source_directory = Path(args.source_dir).resolve()
    if not source_directory.is_dir():
        raise NotADirectoryError(str(source_directory))

    context = build_app_context()
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
        # Console logging writes directly into the terminal surface Textual is
        # composing, which causes redraw artifacts while a scan is active.
        previous_disable = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        ScanTUI(request, context).run()
    finally:
        logging.disable(previous_disable)
        shutdown(context)