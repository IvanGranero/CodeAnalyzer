import json
import logging
import ast
from dataclasses import dataclass
from typing import Dict, Any

from llm.service import LLMService
from tools.scanning.tools import AnalyzerTools
from tools.graph.manager import GraphManager
from tools.scanning.contracts import Candidate, ExploitContext, Finding, VulnerabilityClass
from tools.scanning.agents import AgentRuntime, DeepScanAgent, TriageAgent, run_triage
from tools.scanning.scheduler import CandidateScheduler, ScanBudget
from tools.scanning.tool_registry import ReadOnlyToolRegistry
from tools.scanning.response_parser import extract_json_object
from tools.scanning.reconciliation import reconcile_finding
from tools.scanning.target_prioritizer import prioritize_targets

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ScanContext:
    """Source and graph evidence collected for one target function."""

    target_function_name: str
    metadata: Dict[str, Any]
    source_code: str
    graph_json: str
    graph_summary: str


class ScanOrchestrator:
    _MAX_TRIAGE_ATTEMPTS = 3

    def __init__(self, llm_service: LLMService, graph_manager: GraphManager, platform_info: str = "Unknown Platform", scan_budget: ScanBudget = None, max_candidates_per_target: int = 12):
        self.llm = llm_service
        self.graph_resolver = graph_manager.resolver
        self.tools_engine = AnalyzerTools(graph_manager)
        self.tool_registry = ReadOnlyToolRegistry(self.tools_engine)
        self.platform_info = platform_info
        self.scan_budget = scan_budget or ScanBudget()
        self.max_candidates_per_target = max(1, max_candidates_per_target)
        self.candidate_scheduler = CandidateScheduler(self.scan_budget, self.max_candidates_per_target)
        runtime = AgentRuntime(self.llm, self.scan_budget, self.tool_registry)
        self.triage_agent = TriageAgent(runtime, self._extract_json_object)
        self.deep_scan_agent = DeepScanAgent(runtime, self._extract_json_object)
        
    def _extract_json_object(self, response_text: str) -> Dict[str, Any]:
        return extract_json_object(response_text)

    def set_progress_callback(self, progress) -> None:
        self.progress = progress
        self.tool_registry.set_activity_callback(progress)

    async def _progress(self, target: str, message: str) -> None:
        if getattr(self, "progress", None):
            await self.progress.phase(target, message)

    @staticmethod
    def _validated_candidates(values) -> list:
        candidates = []
        for value in values or []:
            try:
                candidates.append(Candidate.model_validate(value).model_dump(mode="json"))
            except ValueError:
                logger.warning("Ignoring malformed triage candidate: %r", value)
        return candidates
    
    async def _triage_target(self, graph_json: str, graph_summary: str, source_code: str, directive: str, follow_up_context: str = "", target_func: str = "") -> Dict[str, Any]:
        return await run_triage(
            self.triage_agent,
            graph_json,
            graph_summary,
            source_code,
            directive,
            follow_up_context,
            target_func,
            self._MAX_TRIAGE_ATTEMPTS,
        )

    _SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    def _reconcile_single_finding(self, finding: Dict[str, Any], graph_json: str) -> Dict[str, Any]:
        return reconcile_finding(finding, graph_json)

    async def _deep_scan_candidate(self, candidate: Dict[str, Any], graph_json: str, graph_summary: str, source_code: str, directive: str, follow_up_context: str = "", target_func: str = "") -> Dict[str, Any]:
        """
        Single-tasked deep scan: proves/disproves exactly ONE Triage-decomposed
        candidate per call (prompt decomposition), at a reasoning_effort/token budget
        picked from that candidate's own effort_estimate (adaptive reasoning
        selection) -- instead of one call batching a whole checklist at a single
        fixed reasoning_effort sized for the hardest item in it.
        """
        vuln_class = candidate.get("vulnerability_class", "unknown")
        try:
            finding = await self.deep_scan_agent.run(
                candidate,
                graph_json,
                graph_summary,
                source_code,
                directive,
                follow_up_context,
                target_func,
            )
            return self._reconcile_single_finding(finding, graph_json)
        except (ValueError, json.JSONDecodeError, RuntimeError) as exc:
            logger.warning(f"Deep scan for candidate '{vuln_class}' did not return JSON. Error: {exc}")
            return Finding(
                vulnerability_type=vuln_class if vuln_class in {member.value for member in VulnerabilityClass} else "other",
                status="unknown",
                vulnerability_found=False,
                severity="Informational",
                details=f"Deep scan failed to return valid JSON for candidate '{vuln_class}'; partial analysis only.",
                confidence="low",
                needs_human_review=True,
            ).model_dump(mode="json")

    async def _run_candidate(self, candidate: Dict[str, Any], graph_json: str, graph_summary: str, source_code: str, directive: str, follow_up_context: str, target_func: str) -> Dict[str, Any]:
        """Run one focused deep scan using evidence collected by triage."""
        return await self._deep_scan_candidate(
            candidate, graph_json, graph_summary, source_code, directive, follow_up_context, target_func
        )

    def _get_target_source(self, func_name: str) -> str:
        query = """
        MATCH (f:Function {name: $func_name}) 
        WHERE NOT f.storage_uri ENDS WITH '.h'
        RETURN f.storage_uri AS uri, f.byte_span AS span LIMIT 1
        """
        try:
            with self.tools_engine.db.driver.session() as session:
                result = session.run(query, func_name=func_name).single()
                if not result:
                    return f"// Source code not found for {func_name}"
            return self.tools_engine.read_file_span(result["uri"], result["span"])
        except Exception as e:
            return f"// Error retrieving source code: {e}"

    async def _build_scan_context(self, target_function_name: str) -> ScanContext:
        """Load metadata, source, and graph evidence for a scan target."""
        await self._progress(target_function_name, "reading graph metadata and source")
        metadata_value = self.tools_engine.get_function_metadata(target_function_name)
        if isinstance(metadata_value, str):
            try:
                metadata_list = json.loads(metadata_value)
            except json.JSONDecodeError:
                metadata_list = ast.literal_eval(metadata_value)
        else:
            metadata_list = metadata_value
        metadata = metadata_list[0] if isinstance(metadata_list, list) and metadata_list else {}
        source_code = self._get_target_source(target_function_name)
        graph_json, graph_summary = self.graph_resolver.serialize_function_neighborhood(
            target_function_name
        )
        return ScanContext(
            target_function_name=target_function_name,
            metadata=metadata,
            source_code=source_code,
            graph_json=graph_json,
            graph_summary=graph_summary,
        )

    async def _run_triage_phase(
        self,
        context: ScanContext,
    ) -> tuple[Dict[str, Any], str, list[Dict[str, Any]], bool]:
        """Run triage and normalize its directive, candidates, and coverage."""
        target = context.target_function_name
        await self._progress(target, "triage: exploring graph evidence")
        directive = (
            f"Platform Context: [{self.platform_info}]. "
            "Formulate an investigation directive based on the graph context."
        )
        triage = await self._triage_target(
            context.graph_json,
            context.graph_summary,
            context.source_code,
            directive,
            target_func=target,
        )
        if triage.get("decision") != "escalate":
            return triage, "", [], True

        deep_scan_directive = triage.get(
            "investigation_directive",
            "Perform a standard check for logic flaws.",
        )
        candidates = self._validated_candidates(triage.get("vulnerability_candidates"))
        coverage = triage.get("coverage", {})
        incomplete = any(
            coverage.get(category, "unknown") in {"unknown", "insufficient_evidence"}
            for category in (
                "memory_safety",
                "integer_arithmetic",
                "taint_validation",
                "concurrency",
                "state_management",
            )
        )
        preview = deep_scan_directive[:60].replace("\n", " ")
        if len(deep_scan_directive) > 60:
            preview += "..."
        logger.debug("Triage Escalated -> Threat Model: '%s'", preview)
        await self._progress(target, f"triage complete: {len(candidates)} candidates")
        logger.debug("Full Threat Model Directive:\n%s", deep_scan_directive)
        return triage, deep_scan_directive, candidates, incomplete

    async def _run_deep_scans(
        self,
        context: ScanContext,
        candidates: list[Dict[str, Any]],
        directive: str,
    ) -> list[Dict[str, Any]]:
        """Run one bounded deep scan for each validated triage candidate."""
        operations = [
            self._run_candidate(
                candidate,
                context.graph_json,
                context.graph_summary,
                context.source_code,
                directive,
                "",
                context.target_function_name,
            )
            for candidate in candidates
        ]
        await self._progress(
            context.target_function_name,
            f"deep scan: analyzing {len(operations)} candidates",
        )
        scheduler = getattr(self, "candidate_scheduler", None)
        if scheduler is None:
            scheduler = CandidateScheduler(
                getattr(self, "scan_budget", ScanBudget()),
                getattr(self, "max_candidates_per_target", 12),
            )
        return await scheduler.gather(operations)

    def _build_scan_report(
        self,
        context: ScanContext,
        triage: Dict[str, Any],
        directive: str,
        candidates: list[Dict[str, Any]],
        results: list[Dict[str, Any]],
        coverage_incomplete: bool,
    ) -> Dict[str, Any]:
        """Select the primary finding and build the persisted scan envelope."""
        triage_degraded = not directive or not candidates
        supported = [
            finding for finding in results
            if isinstance(finding, dict) and finding.get("status") == "supported"
        ]
        graph_contradictions = [
            contradiction
            for finding in results
            if isinstance(finding, dict)
            for contradiction in (finding.get("graph_contradictions") or [])
        ]
        needs_human_review = triage_degraded or coverage_incomplete or any(
            isinstance(finding, dict) and finding.get("needs_human_review")
            for finding in results
        )

        if supported:
            confidence_rank = {"low": 0, "medium": 1, "high": 2}

            def finding_rank(finding: Dict[str, Any]) -> tuple[int, int, int]:
                evidence_score = 0 if finding.get("needs_human_review") else 1
                return (
                    evidence_score,
                    confidence_rank.get(str(finding.get("confidence", "low")).lower(), 0),
                    self._SEVERITY_RANK.get(str(finding.get("severity", "")).lower(), -1),
                )

            primary = max(supported, key=finding_rank)
            report = {
                "vulnerability_found": True,
                "vulnerability_type": primary.get("vulnerability_type"),
                "severity": primary.get("severity", "Informational"),
                "details": primary.get("details") or primary.get("evidence", ""),
                "mitigation": primary.get("mitigation"),
                "confidence": primary.get("confidence", "low"),
                "decision": "final",
                "findings": results,
            }
        else:
            report = {
                "vulnerability_found": False,
                "severity": "Informational",
                "details": f"No supported findings across {len(results)} decomposed candidate(s).",
                "confidence": "low",
                "decision": "final",
                "findings": results,
            }

        if graph_contradictions:
            report["graph_contradictions"] = graph_contradictions
        if needs_human_review:
            report["needs_human_review"] = True
        report["metadata"] = context.metadata
        report["triage_directive"] = directive
        report["triage_degraded"] = triage_degraded
        report["triage_coverage"] = triage.get("coverage", {})
        report["exploit_context"] = self._build_exploit_context(
            context.target_function_name,
            report,
            context.metadata,
            directive,
            triage,
            source_code=context.source_code,
            graph_summary=context.graph_summary,
            candidates=candidates,
        )
        return report

    async def scan_function(self, target_function_name: str) -> Dict[str, Any]:
        """Run metadata, triage, deep-scan, and report phases for one target."""
        logger.info("=== Starting Scan for '%s' ===", target_function_name)
        try:
            context = await self._build_scan_context(target_function_name)
        except Exception as exc:
            logger.error("Could not build context for %s: %s", target_function_name, exc)
            return {
                "vulnerability_found": False,
                "details": "Failed during graph context creation.",
                "metadata": {},
            }

        logger.info("Running triage for '%s' with callable graph tools", target_function_name)
        triage, directive, candidates, coverage_incomplete = await self._run_triage_phase(context)
        decision = triage.get("decision", "escalate")
        if decision == "ignore":
            return {
                "vulnerability_found": False,
                "severity": "Informational",
                "details": f"Triage dismissed. Reason: {triage.get('reason')}",
                "confidence": triage.get("confidence", 0.9),
                "metadata": context.metadata,
            }

        triage_error = None
        if decision == "error":
            triage_error = triage.get("error") or triage.get("reason") or "unknown triage failure"
        elif decision != "escalate":
            triage_error = triage.get("reason") or "Triage requested unsupported follow-up evidence."
        if triage_error:
            logger.error(
                "Triage failed for '%s' after %d attempts; no deep scan will run: %s",
                target_function_name,
                self._MAX_TRIAGE_ATTEMPTS,
                triage_error,
            )
            return {
                "vulnerability_found": False,
                "scan_status": "error",
                "severity": "Informational",
                "details": "Static vulnerability analysis did not complete because triage failed.",
                "error": triage_error,
                "confidence": "none",
                "decision": "error",
                "findings": [],
                "metadata": context.metadata,
                "triage_degraded": True,
                "needs_human_review": True,
            }
        if not candidates:
            logger.error("Triage escalated without usable candidates for '%s'", target_function_name)
            return {
                "vulnerability_found": False,
                "scan_status": "error",
                "severity": "Informational",
                "details": "Static vulnerability analysis did not complete because triage returned no candidates.",
                "error": "triage_escalated_without_candidates",
                "confidence": "none",
                "decision": "error",
                "findings": [],
                "metadata": context.metadata,
                "triage_degraded": True,
                "needs_human_review": True,
            }

        results = await self._run_deep_scans(context, candidates, directive)
        return self._build_scan_report(
            context,
            triage,
            directive,
            candidates,
            results,
            coverage_incomplete,
        )

    @staticmethod
    def _build_exploit_context(
        target_function_name: str,
        report: Dict[str, Any],
        metadata: Dict[str, Any],
        triage_directive: str,
        triage: Dict[str, Any],
        source_code: str = "",
        graph_summary: str = "",
        candidates: list[Dict[str, Any]] | None = None,
    ) -> Dict[str, Any]:
        """Build the durable handoff used by later exploit-only runs."""
        candidates = candidates or []
        findings = [
            {
                key: finding.get(key)
                for key in (
                    "vulnerability_type", "status", "vulnerability_found",
                    "severity", "confidence", "evidence",
                    "details", "mitigation", "evidence_references",
                    "graph_flag_agreement", "needs_human_review", "decision",
                )
                if finding.get(key) is not None
            }
            for finding in report.get("findings", [])
            if isinstance(finding, dict)
        ]
        did_details = metadata.get("DidDetails") or []
        uds_triggers = [
            {
                key: item.get(key)
                for key in ("did", "func_class_hex", "source")
                if item.get(key) is not None
            }
            for item in did_details
            if isinstance(item, dict) and item.get("did") is not None
        ]
        if not uds_triggers:
            uds_triggers = [{"did": did} for did in metadata.get("DIDs", []) if isinstance(did, str)]

        return ExploitContext.model_validate({
            "schema_version": "1.0",
            "target_function": target_function_name,
            "entry_point": {
                "uds_reachable": bool(metadata.get("TaintedByUDS")),
                "uds_triggers": uds_triggers,
                "file_path": metadata.get("FilePath"),
                "byte_span": metadata.get("ByteSpan"),
                "is_vendor_library": metadata.get("IsVendorLibrary"),
                "is_stub": metadata.get("IsStubNode"),
            },
            "findings": findings,
            "primary_finding": {
                key: report.get(key)
                for key in ("vulnerability_type", "severity", "confidence", "details", "mitigation")
                if report.get(key) is not None
            },
            "triage": {
                "directive": triage_directive,
                "coverage": report.get("triage_coverage", {}),
                "degraded": bool(report.get("triage_degraded")),
                "graph_contradictions": report.get("graph_contradictions", []),
                "reason": triage.get("reason") if isinstance(triage, dict) else None,
                "candidates": candidates,
            },
            "evidence": {
                "tainted_by_uds": bool(metadata.get("TaintedByUDS")),
                "all_findings_count": len(findings),
                "supported_findings_count": sum(
                    finding.get("status") == "supported" for finding in findings
                ),
                "source_code": source_code,
                "graph_summary": graph_summary,
            },
            "limitations": [
                "Exploit context contains persisted scan evidence; live graph lookup is available only through read-only tools.",
                "UDS request layout, session requirements, and type layout are unknown unless explicitly stated in findings.",
            ],
        }).model_dump(mode="json")

    async def prioritize_targets(self, max_targets: int, domain_filter: str = None, file_filter: str = None) -> list:
        return await prioritize_targets(
            self.graph_resolver,
            max_targets,
            domain_filter,
            file_filter,
        )
