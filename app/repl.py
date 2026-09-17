from __future__ import annotations

import asyncio
import json
import logging
from pathlib import Path
from typing import Any

from app.context import AppContext
from app.phases.exploit_phase import ExploitPhase
from llm.router import ModelTier
from tools.graph.graph_service import GraphService
from tools.graph.nl2cypher import NL2CypherEngine
from tools.scanning.orchestrator import ScanOrchestrator
from tools.scanning.response_parser import extract_json_object

logger = logging.getLogger(__name__)


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

    def __init__(self, context: AppContext, source_directory: Path) -> None:
        self.context = context
        self.source_directory = source_directory
        self.graph = GraphService(context.graph)
        self.last_query: dict[str, Any] | None = None
        self.last_scan: dict[str, Any] | None = None
        self.last_scan_function: str | None = None
        self.last_scan_results: dict[str, dict[str, Any]] = {}
        self.last_query_functions: list[str] = []
        self.selected_function: str | None = None
        self.last_command: str = "session_started"
        self._orchestrator: ScanOrchestrator | None = None
        self._loop = asyncio.new_event_loop()
        self.graph.query_service.nl_engine = NL2CypherEngine(
            context.graph.db,
            _LiteCypherGenerator(context.llm, self._loop),
        )

    def run(self) -> None:
        print("CodeAnalyzer REPL. Ask a question or type :quit to exit.")
        asyncio.set_event_loop(self._loop)
        try:
            while True:
                try:
                    line = input("codeanalyzer> ").strip()
                except (EOFError, KeyboardInterrupt):
                    print()
                    return
                if not line:
                    continue
                if line.lower() in {"quit", "exit", "q", ":quit", ":exit", ":q"}:
                    return
                try:
                    if self._command(line):
                        continue
                    if not self._natural_command(line):
                        return
                except KeyboardInterrupt:
                    print("Interrupted.")
                except Exception as exc:
                    logger.exception("REPL command failed")
                    print(f"error: {exc}")
        finally:
            self._loop.run_until_complete(self._loop.shutdown_asyncgens())
            self._loop.close()

    def _command(self, line: str) -> bool:
        if not line.startswith(":"):
            return False
        command, _, argument = line.partition(" ")
        argument = argument.strip()
        self.last_command = command.lstrip(":")
        if command in {":help", ":h"}:
            self._suggestions()
        elif command == ":query":
            self._query(argument)
        elif command == ":nodes":
            self._show_nodes()
        elif command in {":use", ":select"}:
            self._select(argument)
        elif command == ":scan":
            self._scan(argument or self.selected_function)
        elif command in {":scan-uds", ":scan-uds-only"}:
            self._scan_uds()
        elif command == ":exploit":
            self._exploit()
        elif command == ":last":
            self._show_last()
        elif command == ":status":
            self._status()
        else:
            print(f"unknown command: {command}")
            self._suggestions()
        return True

    def _natural_command(self, text: str) -> bool:
        translated = self._run(self._translate_command(text))
        command = translated.get("command")
        argument = str(translated.get("argument", "")).strip()
        self.last_command = command
        if command == "query":
            self._query(argument)
        elif command == "nodes":
            self._show_nodes()
        elif command in {"select", "scan"}:
            if command == "select":
                self._select(argument)
            else:
                self._scan(argument or self.selected_function)
        elif command == "scan_uds":
            self._scan_uds()
        elif command == "exploit":
            self._exploit()
        elif command == "last":
            self._show_last()
        elif command == "status":
            self._status()
        elif command in {"help", "quit"}:
            if command == "help":
                self._suggestions()
            else:
                return False
        else:
            print(f"I could not map that to a REPL command: {command!r}")
        return True

    async def _translate_command(self, text: str) -> dict[str, Any]:
        response = await self.context.llm.execute_task(
            "repl_command",
            {"user_input": text},
            context_id="repl",
        )
        command = extract_json_object(response)
        allowed = {"query", "nodes", "select", "scan", "scan_uds", "exploit", "last", "status", "help", "quit"}
        if command.get("command") not in allowed:
            raise ValueError(f"Unsupported REPL command: {command.get('command')!r}")
        return command

    def _suggestions(self) -> None:
        suggestions = self._run(self._get_suggestions())
        print(suggestions.get("message", "Possible next commands:"))
        for suggestion in suggestions.get("suggestions", []):
            print(f"- {suggestion}")

    async def _get_suggestions(self) -> dict[str, Any]:
        state = {
            "last_command": self.last_command,
            "has_query": self.last_query is not None,
            "query_function_count": len(self.last_query_functions),
            "selected_function": self.selected_function,
            "has_scan": self.last_scan is not None,
            "last_scan_function": self.last_scan_function,
            "batch_scan_count": len(self.last_scan_results),
        }
        response = await self.context.llm.execute_task(
            "repl_suggestions",
            {"session_state": json.dumps(state, ensure_ascii=False)},
            context_id="repl",
        )
        result = extract_json_object(response)
        if not isinstance(result.get("suggestions"), list):
            raise ValueError("REPL suggestions must be a list")
        return result

    def _query(self, question: str) -> None:
        if not question:
            print("usage: :query <question>")
            return
        result = self.graph.ask(question)
        self.last_query = result
        print(result.get("answer") or result.get("message", "No answer."))
        if result.get("status") == "success":
            graph = result.get("graph", {})
            print(f"nodes={len(graph.get('nodes', []))} edges={len(graph.get('edges', []))}")
            functions = [
                node.get("name")
                for node in graph.get("nodes", [])
                if "Function" in node.get("labels", []) and node.get("name")
            ]
            self.last_query_functions = list(dict.fromkeys(functions))
            if functions:
                self.selected_function = functions[0]
                print(f"selected={self.selected_function}; {len(functions)} function(s) available for 'scan these'")

    def _show_nodes(self) -> None:
        if not self.last_query:
            print("No query result.")
            return
        for node in self.last_query.get("graph", {}).get("nodes", []):
            labels = ",".join(node.get("labels", []))
            print(f"{node.get('id')}: {labels} {node.get('name', '')}".strip())

    def _select(self, function_name: str) -> None:
        if not function_name:
            print(f"selected={self.selected_function or 'none'}")
            return
        self.selected_function = function_name
        print(f"selected={function_name}")

    def _scan(self, function_name: str | None) -> None:
        if function_name and function_name.lower() in {"these", "them", "those", "all"}:
            self._scan_last_query()
            return
        if not function_name:
            print("Select a function first with :select <function> or query the graph.")
            return
        orchestrator = self._get_orchestrator()
        self.last_scan_function = function_name
        self.last_scan = self._run(orchestrator.scan_function(function_name))
        print(json.dumps(self.last_scan, indent=2, ensure_ascii=False))

    def _scan_last_query(self) -> None:
        if not self.last_query_functions:
            print("The last query did not return any functions.")
            return
        self._run(self._scan_functions(self.last_query_functions))

    async def _scan_functions(self, functions: list[str]) -> None:
        orchestrator = self._get_orchestrator()
        results: dict[str, dict[str, Any]] = {}
        for index, function_name in enumerate(functions, 1):
            print(f"[{index}/{len(functions)}] scanning {function_name}")
            results[function_name] = await orchestrator.scan_function(function_name)
        self.last_scan_results = results
        self.last_scan_function = None
        self.last_scan = {
            "scan_status": "batch",
            "results": results,
            "count": len(results),
        }
        print(json.dumps(self.last_scan, indent=2, ensure_ascii=False))

    def _scan_uds(self) -> None:
        self._run(self._scan_uds_and_exploit())

    async def _scan_uds_and_exploit(self) -> None:
        orchestrator = self._get_orchestrator()
        targets = await orchestrator.prioritize_targets(max_targets=0, uds_only=True)
        print(f"UDS-accessible functions: {len(targets)}")
        exploit = ExploitPhase(
            self.context.llm,
            cache_dir="reports",
            graph_manager=self.context.graph,
        )
        exploit.start()
        try:
            for index, function_name in enumerate(targets, 1):
                print(f"[{index}/{len(targets)}] scanning {function_name}")
                report = await orchestrator.scan_function(function_name)
                self.last_scan_function = function_name
                self.last_scan = report
                if report.get("vulnerability_found"):
                    print(f"  vulnerability found: {report.get('severity', 'unknown')}")
                    await exploit.enqueue(report, function_name, "")
                elif report.get("scan_status") == "error":
                    print(f"  scan error: {report.get('error', report.get('details', 'unknown'))}")
                else:
                    print("  no supported vulnerability")
        finally:
            await exploit.drain()

    def _exploit(self) -> None:
        if not self.last_scan:
            print("No scan result to exploit.")
            return
        if not self.last_scan.get("vulnerability_found"):
            print("The last scan did not produce a vulnerability to exploit.")
            return
        self._run(self._run_exploit())
        print("Exploit validation completed.")

    async def _run_exploit(self) -> None:
        exploit = ExploitPhase(
            self.context.llm,
            cache_dir="reports",
            graph_manager=self.context.graph,
        )
        exploit.start()
        await exploit.enqueue(self.last_scan, self.last_scan_function or "unknown", "")
        await exploit.drain()

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
