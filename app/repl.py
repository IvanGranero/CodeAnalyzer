from __future__ import annotations

import asyncio
import io
import json
import logging
import readline
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from app.context import AppContext
from app.errors import format_repl_error, log_error_quietly
from app.phases.exploit_phase import ExploitPhase
from app.progress import CallbackProgressSink, ScanProgress
from llm.router import ModelTier
from tools.graph.graph_service import GraphService
from tools.graph.nl2cypher import NL2CypherEngine
from tools.scanning.orchestrator import ScanOrchestrator
from tools.scanning.response_parser import extract_json_object
from tools.scanning.reporter import ScanReporter
from tools.scanning.tool_registry import ReadOnlyToolRegistry
from tools.scanning.tools import AnalyzerTools

logger = logging.getLogger(__name__)


REPL_ACTION_TOOLS = [
    {
        "type": "function",
        "name": "query_graph",
        "description": "Answer a natural-language question about the indexed code graph. Use this for reachability, callers, callees, UDS/DID/RID relationships, counts, domains, and other graph facts. Set use_previous_results=true when the question filters or refers to functions from the immediately previous graph result; otherwise set it to false. This reads the graph and does not scan or exploit code.",
        "parameters": {"type": "object", "properties": {"question": {"type": "string"}, "use_previous_results": {"type": "boolean"}}, "required": ["question", "use_previous_results"], "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "show_graph_nodes",
        "description": "Print the nodes from the most recent graph query when the user asks to show, list, or display those results. Use only when a previous graph query returned a graph result.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "select_target",
        "description": "Set one explicitly named function as the current scan target. Use when the user asks to select, focus on, or choose a function; do not scan it as part of this action.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"], "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "scan_function",
        "description": "Run the static vulnerability scan for exactly one explicitly named function. Use only when the user names the function or supplies an unambiguous function name; do not use for a general graph question.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "required": ["function_name"], "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "scan_previous_results",
        "description": "Run the static vulnerability scan for every function returned by the most recent graph query. Use when the user says scan these, scan the results, scan them, or otherwise refers to the previous query's functions.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "scan_uds_targets",
        "description": "Scan every function reachable through indexed UDS, DID, or RID evidence and queue exploit validation for vulnerable results. Use only when the user explicitly requests scanning, auditing, analyzing, assessing, or exploiting all UDS/DID/RID-reachable functions. Do not use to answer which functions are reachable.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "validate_finding",
        "description": "Run dynamic exploit validation for one scanned vulnerable function. Use function_name when the user names a specific function after a multi-target scan; omit it only when there is exactly one current vulnerable result.",
        "parameters": {"type": "object", "properties": {"function_name": {"type": "string"}}, "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "show_last_result",
        "description": "Print the most recent graph query and scan result summary. Use when the user asks to show the last result, last query, scan output, or current findings.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "show_status",
        "description": "Print current analyzer usage counters and REPL session status. Use for status, usage, progress, or session-state requests.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "show_help",
        "description": "Show context-aware next actions available in the current REPL session. Use when the user asks for help, guidance, commands, or what to do next.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "type": "function",
        "name": "end_session",
        "description": "End the interactive REPL session. Use only when the user explicitly asks to quit, exit, or end the session.",
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
    },
]


class _LiteCypherGenerator:
    """Synchronous bridge for the existing NL2CypherEngine inside the REPL loop."""

    def __init__(self, llm, loop: asyncio.AbstractEventLoop) -> None:
        self.llm = llm
        self.loop = loop

    def generate(self, prompt: str) -> str:
        service = self.llm.services[ModelTier.LITE]
        result, _ = self.loop.run_until_complete(
            service.client.generate_chat(
                "Return only valid Neo4j Cypher.",
                prompt,
                {"reasoning_effort": "low", "max_completion_tokens": 4096},
                context_id="repl-nl2cypher",
            )
        )
        return result


class ApplicationRepl:
    """Text session for graph exploration, static scans, and exploit validation."""

    _READLINE_HISTORY_LIMIT = 100
    _MESSAGE_HISTORY_TURNS = 8

    def __init__(
        self,
        context: AppContext,
        source_directory: Path,
        status_callback=None,
        progress_callback=None,
    ) -> None:
        self.context = context
        self.source_directory = source_directory
        self.status_callback = status_callback
        self.progress_callback = progress_callback
        self.graph = GraphService(context.graph)
        self.tool_registry = ReadOnlyToolRegistry(AnalyzerTools(context.graph))
        self.last_query: dict[str, Any] | None = None
        self.last_scan: dict[str, Any] | None = None
        self.last_scan_function: str | None = None
        self.last_scan_results: dict[str, dict[str, Any]] = {}
        self.last_query_functions: list[str] = []
        self.selected_function: str | None = None
        self.last_command: str = "session_started"
        self._conversation_history: list[dict[str, str]] = []
        self._message_history: list[Any] = []
        self._suggestion_history: list[str] = []
        self._orchestrator: ScanOrchestrator | None = None
        self._pending_action: dict[str, Any] | None = None
        self._pending_tool_call: dict[str, Any] | None = None
        self._last_router_output = ""
        self._loop = asyncio.new_event_loop()
        self._progress_sink = CallbackProgressSink(self._emit_progress)
        self.reporter = ScanReporter(output_dir="reports")
        self.graph.query_service.nl_engine = NL2CypherEngine(
            context.graph.db,
            _LiteCypherGenerator(context.llm, self._loop),
        )

    def run(self) -> None:
        print("CodeAnalyzer REPL. Ask a question or type :quit to exit.")
        readline.set_history_length(self._READLINE_HISTORY_LIMIT)
        asyncio.set_event_loop(self._loop)
        try:
            # initial_suggestions = self.get_initial_suggestions()
            # if initial_suggestions:
            #     print(initial_suggestions)
            while True:
                try:
                    line = input("codeanalyzer> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
                if not line:
                    continue
                try:
                    should_continue = self._natural_command(line)
                    # if should_continue:
                    #     suggestions = self.get_suggestions()
                    #     if suggestions:
                    #         print(suggestions)
                    if not should_continue:
                        return
                except KeyboardInterrupt:
                    print("Interrupted.")
                except Exception as exc:
                    log_error_quietly(exc, "command")
                    print(f"error: {format_repl_error(exc, 'command')}")
        finally:
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.close()

    def execute(self, line: str) -> str:
        """Execute one REPL command and return the output printed by it."""
        output = io.StringIO()
        try:
            with redirect_stdout(output):
                if not self._natural_command(line):
                    print("Session exit requested.")
        except Exception as exc:
            log_error_quietly(exc, "command")
            print(f"error: {format_repl_error(exc, 'command')}", file=output)
        return output.getvalue().strip()

    def get_suggestions(self) -> str:
        """Return useful next commands for the current session state."""
        suggestions = self._run(self._get_suggestions())
        lines = [suggestions.get("message", "Possible next commands:")]
        lines.extend(f"- {suggestion}" for suggestion in suggestions.get("suggestions", []))
        return "\n".join(lines)

    def get_initial_suggestions(self) -> str:
        """Return startup guidance from cached discovery data without using the LLM."""
        config_path = Path("scan_cache") / "discovery_config.json"
        config: dict[str, Any] = {}
        try:
            with config_path.open("r", encoding="utf-8") as stream:
                loaded = json.load(stream)
            if isinstance(loaded, dict):
                config = loaded
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Initial discovery context unavailable: %s", exc)

        mcu = config.get("mcu_guess", "Unknown MCU")
        vendor = config.get(
            "stack_vendor_guess",
            config.get("stack_vendor", "Unknown stack vendor"),
        )
        domains = config.get(
            "app_domain_guesses",
            config.get("app_domains", []),
        )
        if not isinstance(domains, list):
            domains = []
        domain_text = ", ".join(str(domain) for domain in domains) or "No application domains detected"
        example_domain = str(domains[0]) if domains else None
        suggestions = [
            "how many functions, tasks, and interrupts are in the graph?",
            "which functions have the most callers?",
            "which functions have the most callees?",
            "show the main application components and domains",
            "scan <function name>",
        ]
        if example_domain:
            suggestions.insert(
                3,
                f"what functions are associated with the {example_domain} domain?",
            )

        context_line = (
            f"Repository context: MCU={mcu}; Stack vendor={vendor}; "
            f"Domains={domain_text}"
        )
        self._suggestion_history.extend(suggestions)
        self._suggestion_history = self._suggestion_history[-20:]
        return "\n".join([
            context_line,
            "Suggestions: " + ", ".join(suggestions),
        ])

    def _natural_command(self, text: str) -> bool:
        if self._is_exit_command(text):
            return False
        action = self._run(self._translate_command(text))
        if action is None:
            raise ValueError("The REPL router did not select an action tool")
        if self._last_router_output.strip() and self._last_router_output.strip() != "{}":
            print(self._last_router_output.strip())
        self._execute_action(action)            
        return action["name"] != "end_session"

    @staticmethod
    def _is_exit_command(text: str) -> bool:
        return text.strip().lower() in {":quit", ":exit", "quit", "exit"}

    @staticmethod
    def _refers_to_previous_results(text: str) -> bool:
        normalized = " ".join(text.lower().split())
        return any(phrase in normalized for phrase in (
            "from this list",
            "from the list",
            "these functions",
            "those functions",
            "previous result",
            "previous results",
            "these results",
            "those results",
        ))

    def _repl_tool_call(self, name: str, arguments: dict[str, Any]) -> str:
        """Queue one semantic REPL action; execute it after the LLM loop returns."""
        action_names = {tool["name"] for tool in REPL_ACTION_TOOLS}
        if name in action_names:
            if self._pending_action is not None:
                return json.dumps({
                    "queued": self._pending_action["name"],
                    "ignored_duplicate_action": name,
                })
            self._pending_tool_call = {
                "name": name,
                "args": arguments,
                "id": f"repl-action-{len(self._message_history) + 1}",
            }
            self._pending_action = {"name": name, "arguments": arguments}
            return json.dumps({"queued": name})
        return self.tool_registry.call(name, arguments)

    def _execute_action(self, action: dict[str, Any]) -> None:
        handlers = {
            "query_graph": lambda args: self._query(
                str(args["question"]),
                bool(args.get("use_previous_results", False)),
            ),
            "show_graph_nodes": lambda args: self._show_nodes(),
            "select_target": lambda args: self._select(str(args["function_name"])),
            "scan_function": lambda args: self._scan(str(args["function_name"])),
            "scan_previous_results": lambda args: self._scan_last_query(),
            "scan_uds_targets": lambda args: self._scan_uds(),
            "validate_finding": lambda args: self._exploit(args.get("function_name")),
            "show_last_result": lambda args: self._show_last(),
            "show_status": lambda args: self._status(),
            "show_help": lambda args: self._suggestions(),
            "end_session": lambda args: None,
        }
        handler = handlers.get(action["name"])
        if handler is None:
            raise ValueError(f"Unsupported REPL action: {action['name']}")
        handler(action.get("arguments", {}))
        if action["name"] != "query_graph":
            self._message_history.append(
                AIMessage(content=f"Completed REPL action: {action['name']}.")
            )
        self._trim_message_history()

    async def _translate_command(self, text: str) -> dict[str, Any]:
        self._set_status("Thinking...")
        try:
            self._pending_action = None
            self._pending_tool_call = None
            self._last_router_output = ""
            self._message_history.append(HumanMessage(content=text))
            response = await self.context.llm.execute_task(
                "repl_action",
                {
                    "user_input": text,
                    "conversation_context": self._conversation_context(),
                },
                context_id="repl",
                tools=REPL_ACTION_TOOLS + self.tool_registry.definitions(),
                tool_handler=self._repl_tool_call,
                preloaded_messages=self._message_history[:-1],
            )
        finally:
            self._set_status("Analyzing...")
        self._last_router_output = response
        if self._pending_action is None:
            raise ValueError(f"REPL router returned no action: {response[:200]}")
        if self._pending_tool_call is not None:
            call = self._pending_tool_call
            self._message_history.append(
                AIMessage(
                    content="",
                    tool_calls=[{
                        "name": call["name"],
                        "args": call["args"],
                        "id": call["id"],
                        "type": "tool_call",
                    }],
                )
            )
            self._message_history.append(
                ToolMessage(
                    content=json.dumps({"queued": call["name"]}),
                    tool_call_id=call["id"],
                    name=call["name"],
                )
            )
        if (
            self._pending_action["name"] == "query_graph"
            and self.last_query_functions
            and self._refers_to_previous_results(text)
        ):
            self._pending_action.setdefault("arguments", {})["use_previous_results"] = True
        self._trim_message_history()
        self.last_command = self._pending_action["name"]
        return self._pending_action

    def _suggestions(self) -> None:
        print(self.get_suggestions())

    async def _get_suggestions(self) -> dict[str, Any]:
        state = {
            "last_command": self.last_command,
            "has_query": self.last_query is not None,
            "query_function_count": len(self.last_query_functions),
            "selected_function": self.selected_function,
            "has_scan": self.last_scan is not None,
            "last_scan_function": self.last_scan_function,
            "batch_scan_count": len(self.last_scan_results),
            "last_query_question": (self.last_query or {}).get("question"),
            "previous_suggestions": self._suggestion_history[-20:],
        }
        self._set_status("Thinking...")
        try:
            try:
                response = await self.context.llm.execute_task(
                    "repl_suggestions",
                    {"session_state": json.dumps(state, ensure_ascii=False)},
                    context_id="repl",
                )
            except Exception as exc:
                logger.debug("REPL suggestions unavailable: %s", exc)
                return self._default_suggestions(state)
        finally:
            self._set_status("Analyzing...")
        result = extract_json_object(response)
        if not isinstance(result.get("suggestions"), list):
            result = self._default_suggestions(state)
        suggestions = [
            str(suggestion).strip()
            for suggestion in result.get("suggestions", [])
            if str(suggestion).strip()
        ]
        previous = {self._suggestion_key(item) for item in self._suggestion_history}
        suggestions = [
            suggestion
            for suggestion in suggestions
            if self._suggestion_key(suggestion) not in previous
            and not self._suggestion_already_answered(suggestion, state)
        ]
        self._suggestion_history.extend(suggestions)
        self._suggestion_history = self._suggestion_history[-20:]
        result["suggestions"] = suggestions
        return result

    @staticmethod
    def _suggestion_key(suggestion: str) -> str:
        return " ".join(suggestion.lower().split())

    @staticmethod
    def _suggestion_already_answered(suggestion: str, state: dict[str, Any]) -> bool:
        previous_question = " ".join(
            str(state.get("last_query_question") or "").lower().split()
        )
        current_suggestion = ApplicationRepl._suggestion_key(suggestion)
        return (
            "uds" in previous_question
            and ("reachable" in previous_question or "accessible" in previous_question)
            and "uds" in current_suggestion
            and ("reachable" in current_suggestion or "accessible" in current_suggestion)
        )

    @staticmethod
    def _default_suggestions(state: dict[str, Any]) -> dict[str, Any]:
        suggestions = ["what functions are reachable via UDS?"]
        if state["has_query"]:
            suggestions.insert(0, "scan these")
        if state["has_scan"]:
            suggestions.insert(0, "show the last results")
        return {
            "message": "Possible next commands:",
            "suggestions": suggestions,
        }

    def _query(self, question: str, use_previous_results: bool = False) -> None:
        if not question:
            print("usage: :query <question>")
            return
        prior_functions = self.last_query_functions if use_previous_results else None
        result = self.graph.ask(question, function_names=prior_functions)
        self.last_query = result
        answer = result.get("answer") or result.get("message", "No answer.")
        print(answer)
        self._conversation_history.append({"user": question, "assistant": answer})
        self._conversation_history = self._conversation_history[-6:]
        self._message_history.append(AIMessage(content=answer))
        self._trim_message_history()
        if result.get("status") == "success":
            graph = result.get("graph", {})
            functions = [
                node.get("name")
                for node in graph.get("nodes", [])
                if "Function" in node.get("labels", []) and node.get("name")
            ]
            if not functions:
                functions = self._functions_from_rows(result.get("rows", []))
            self.last_query_functions = list(dict.fromkeys(functions))
            if functions:
                self.selected_function = functions[0]

    def _conversation_context(self) -> str:
        context = {
            "recent_exchange": [
                {
                    "user": self._context_text(exchange["user"], 500),
                    "assistant": self._context_text(exchange["assistant"], 1000),
                }
                for exchange in self._conversation_history[-3:]
            ],
            "last_query": self._query_context(),
            "selected_function": self.selected_function,
        }
        return json.dumps(context, ensure_ascii=False)

    def _trim_message_history(self) -> None:
        """Keep complete recent REPL turns without splitting tool-call pairs."""
        human_indexes = [
            index
            for index, message in enumerate(self._message_history)
            if isinstance(message, HumanMessage)
        ]
        if len(human_indexes) <= self._MESSAGE_HISTORY_TURNS:
            return
        self._message_history = self._message_history[human_indexes[-self._MESSAGE_HISTORY_TURNS]:]

    def _query_context(self) -> dict[str, Any] | None:
        if not self.last_query:
            return None
        rows = self.last_query.get("rows", [])
        graph = self.last_query.get("graph", {})
        return {
            "question": self.last_query.get("question"),
            "answer": self._context_text(str(self.last_query.get("answer", "")), 1500),
            "function_names": self.last_query_functions,
            "cypher": self.last_query.get("cypher"),
            "status": self.last_query.get("status"),
            "row_count": len(rows),
            "columns": list(rows[0].keys()) if rows else [],
            "graph_node_count": len(graph.get("nodes", [])),
            "graph_edge_count": len(graph.get("edges", [])),
        }

    @staticmethod
    def _context_text(text: str, limit: int) -> str:
        if len(text) <= limit:
            return text
        return text[:limit].rstrip() + f" ... ({len(text)} chars total)"

    @staticmethod
    def _functions_from_rows(rows: list[dict[str, Any]]) -> list[str]:
        function_fields = {
            "function", "function_name", "f", "f.name", "caller", "callee",
            "source", "target", "originfunction", "reachablefunction",
        }
        names: list[str] = []
        for row in rows:
            for field, value in row.items():
                normalized_field = str(field).lower()
                dotted_prefix = normalized_field.rsplit(".", 1)[0] if "." in normalized_field else ""
                function_name_field = normalized_field.endswith(".name") and dotted_prefix in {
                    "f", "function", "caller", "callee", "source", "target",
                    "start", "originfunction", "reachablefunction",
                }
                if normalized_field not in function_fields and not function_name_field:
                    continue
                if isinstance(value, dict):
                    name = value.get("name")
                elif hasattr(value, "get"):
                    name = value.get("name")
                else:
                    name = value if isinstance(value, str) else None
                if not name:
                    continue
                names.append(str(name))
        return list(dict.fromkeys(names))

    def _show_nodes(self) -> None:
        if not self.last_query:
            print("No query result.")
            return
        nodes = self.last_query.get("graph", {}).get("nodes", [])
        if not nodes:
            rows = self.last_query.get("rows", [])
            if rows:
                print("The last query returned scalar records; there are no graph nodes to show.")
            else:
                print("The last query returned no records.")
            return
        for node in nodes:
            labels = ",".join(node.get("labels", []))
            print(f"{node.get('id')}: {labels} {node.get('name', '')}".strip())

    def _select(self, function_name: str) -> None:
        if not function_name:
            print(f"selected={self.selected_function or 'none'}")
            return
        self.selected_function = function_name
        print(f"selected={function_name}")

    def _scan(self, function_name: str | None) -> None:
        normalized = " ".join((function_name or "").lower().split())
        if normalized in {
            "these", "them", "those", "all",
            "the results", "the result", "these results", "those results",
            "the functions", "these functions", "those functions",
        }:
            self._scan_last_query()
            return
        if not function_name:
            print("Select a function first with :select <function> or query the graph.")
            return
        self.last_scan_function = function_name
        self.last_scan = self._run(self._scan_one(function_name))
        self._persist_scan_reports({function_name: self.last_scan})
        print(self.reporter.render_individual_report(function_name, self.last_scan))

    def _scan_last_query(self) -> None:
        if not self.last_query_functions:
            print("The last query did not return any functions.")
            return
        self._run(self._scan_functions(self.last_query_functions))

    async def _scan_functions(self, functions: list[str]) -> None:
        orchestrator = self._get_orchestrator()
        progress = ScanProgress(sink=self._progress_sink)
        await progress.start(len(functions))
        orchestrator.set_progress_callback(progress)
        results: dict[str, dict[str, Any]] = {}
        for index, function_name in enumerate(functions, 1):
            results[function_name] = await self._scan_one_with_progress(
                orchestrator, progress, function_name
            )
        self.last_scan_results = results
        self.last_scan_function = None
        self.last_scan = {
            "scan_status": "batch",
            "results": results,
            "count": len(results),
        }
        self._persist_scan_reports(results)
        for function_name, report in results.items():
            print(self.reporter.render_individual_report(function_name, report))

    def _persist_scan_reports(self, reports: dict[str, dict[str, Any]]) -> None:
        """Write the same report artifacts as the non-REPL scan workflow."""
        for function_name, report in reports.items():
            if report.get("vulnerability_found"):
                self.reporter.generate_individual_report(function_name, report)
        self.reporter.generate_consolidated_reports(reports)

    def _scan_uds(self) -> None:
        self._run(self._scan_uds_and_exploit())

    async def _scan_uds_and_exploit(self) -> None:
        orchestrator = self._get_orchestrator()
        targets = await orchestrator.prioritize_targets(max_targets=0, uds_only=True)
        self._emit_progress(f"UDS-accessible functions: {len(targets)}")
        progress = ScanProgress(sink=self._progress_sink)
        await progress.start(len(targets))
        orchestrator.set_progress_callback(progress)
        results: dict[str, dict[str, Any]] = {}
        for function_name in targets:
            report = await self._scan_one_with_progress(
                orchestrator, progress, function_name
            )
            results[function_name] = report
        self.last_scan_results = results
        self.last_scan_function = None
        self.last_scan = {
            "scan_status": "batch",
            "results": results,
            "count": len(results),
        }
        self._persist_scan_reports(results)
        self._emit_progress(
            f"UDS scan complete: {len(results)} functions; use 'run an exploit for <function>' "
            "to validate one finding."
        )

    def _exploit(self, function_name: str | None = None) -> None:
        report, selected_name = self._select_exploit_target(function_name)
        if report is None:
            print("No scanned vulnerable result matched that function.")
            return
        if not report.get("vulnerability_found"):
            print(f"'{selected_name}' did not produce a vulnerability to exploit.")
            return
        self.last_scan = report
        self.last_scan_function = selected_name
        self._run(self._run_exploit())
        print(f"Exploit validation completed for {selected_name}.")

    def _select_exploit_target(
        self, function_name: str | None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        results = self.last_scan_results
        if function_name:
            report = results.get(function_name)
            if report is None and self.last_scan_function == function_name and self.last_scan:
                report = self.last_scan
            return report, function_name if report is not None else None
        if self.last_scan_function and self.last_scan:
            return self.last_scan, self.last_scan_function
        vulnerable = [
            (name, report) for name, report in results.items()
            if report.get("vulnerability_found")
        ]
        if len(vulnerable) == 1:
            return vulnerable[0][1], vulnerable[0][0]
        if len(vulnerable) > 1:
            print("Multiple vulnerable scan results exist; specify the function name.")
        return None, None

    async def _run_exploit(self) -> None:
        exploit = ExploitPhase(
            self.context.llm,
            cache_dir="reports",
            graph_manager=self.context.graph,
            progress_sink=self._progress_sink,
        )
        exploit.start()
        await exploit.enqueue(self.last_scan, self.last_scan_function or "unknown", "")
        await exploit.drain()

    async def _scan_one(self, function_name: str) -> dict[str, Any]:
        orchestrator = self._get_orchestrator()
        progress = ScanProgress(sink=self._progress_sink)
        await progress.start(1)
        return await self._scan_one_with_progress(orchestrator, progress, function_name)

    async def _scan_one_with_progress(
        self,
        orchestrator: ScanOrchestrator,
        progress: ScanProgress,
        function_name: str,
    ) -> dict[str, Any]:
        orchestrator.set_progress_callback(progress)
        await progress.target_started(function_name)
        report = await orchestrator.scan_function(function_name)
        await progress.target_finished(function_name, report)
        return report

    def _show_last(self) -> None:
        print(json.dumps({"query": self.last_query, "scan": self.last_scan}, indent=2, ensure_ascii=False))

    def _status(self) -> None:
        print(json.dumps(self.context.llm.tracker.snapshot(), indent=2, ensure_ascii=False))

    def _get_orchestrator(self) -> ScanOrchestrator:
        if self._orchestrator is None:
            self._orchestrator = ScanOrchestrator(self.context.llm, self.context.graph)
        return self._orchestrator

    def _run(self, coroutine):
        return self._loop.run_until_complete(coroutine)

    def _set_status(self, status: str) -> None:
        if self.status_callback is not None:
            self.status_callback(status)

    def _emit_progress(self, message: str) -> None:
        callback = self.progress_callback or self.status_callback
        if callback is not None:
            callback(message)
        else:
            print(message, flush=True)
