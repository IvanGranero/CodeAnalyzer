import json
import logging
import asyncio
from typing import Dict, Any

from llm.service import LLMService
from scan.tools import AnalyzerTools
from graph.manager import GraphManager

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    def __init__(self, llm_service: LLMService, graph_manager: GraphManager, platform_info: str = "Unknown Platform"):
        self.llm = llm_service
        self.graph_resolver = graph_manager.resolver
        self.tools_engine = AnalyzerTools(graph_manager)
        self.platform_info = platform_info
        
    def _extract_json_object(self, response_text: str) -> Dict[str, Any]:
        if not response_text:
            raise ValueError("Empty response from LLM")

        try:
            # 1. Fast happy path
            return json.loads(response_text)
        except json.JSONDecodeError:
            pass

        # 2. Strip Markdown
        cleaned = response_text.strip()
        if cleaned.startswith("```json"): cleaned = cleaned[7:]
        elif cleaned.startswith("```"): cleaned = cleaned[3:]
        if cleaned.endswith("```"): cleaned = cleaned[:-3]
        cleaned = cleaned.strip()

        try:
            return json.loads(cleaned)
        except json.JSONDecodeError:
            pass

        # 3. Bracket Counting (Bulletproof for trailing garbage/bad cuts)
        logger.warning("Standard JSON parse failed. Attempting bracket-counting extraction...")
        start_idx = cleaned.find('{')
        if start_idx == -1:
            raise ValueError("No '{' found in response.")
            
        brace_count = 0
        in_string = False
        escape_next = False
        
        for i in range(start_idx, len(cleaned)):
            char = cleaned[i]
            
            if escape_next:
                escape_next = False
                continue
                
            if char == '\\':
                escape_next = True
                continue
                
            if char == '"':
                in_string = not in_string
                continue
                
            if not in_string:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    
                # We found the matching closing brace for the first opening brace!
                if brace_count == 0:
                    try:
                        return json.loads(cleaned[start_idx:i+1])
                    except json.JSONDecodeError as e:
                        raise ValueError(f"Extracted JSON block is invalid: {e}")
                        
        raise ValueError("Could not find balanced JSON brackets in response.")

    def _fetch_follow_up_artifact(self, request: Dict[str, Any]) -> str:
        kind = request.get("kind", "unknown")
        func_name = request.get("function")
        symbol = request.get("symbol")
        file_name = request.get("file")
        macro = request.get("macro")
        span = request.get("span") or {}

        logger.info(f"[Follow-up] Requesting artifact kind='{kind}' function='{func_name}' symbol='{symbol}' file='{file_name}' macro='{macro}'")

        if kind in {"caller_impl", "callee_impl", "full_function_body"} and func_name:
            snippet = self._get_target_source(func_name)
            return f"FOLLOW-UP ARTIFACT ({kind}):\nFunction: {func_name}\n\n{snippet}"

        if kind == "global_initializer" and symbol:
            query = """
            MATCH (n) WHERE n.name = $symbol
            RETURN n.name AS name, labels(n) AS labels, n.storage_uri AS file, n.byte_span AS span
            ORDER BY CASE WHEN n.storage_uri ENDS WITH '.h' THEN 1 ELSE 0 END ASC
            LIMIT 5
            """
            try:
                with self.tools_engine.db.driver.session() as session:
                    rows = session.run(query, symbol=symbol).data()
                if rows:
                    return "FOLLOW-UP ARTIFACT (global_initializer):\n" + json.dumps(rows, ensure_ascii=False, separators=(",", ":"))
            except Exception as exc:
                logger.warning(f"Failed to resolve global initializer '{symbol}': {exc}")
            return f"FOLLOW-UP ARTIFACT (global_initializer):\nSymbol {symbol} not found in graph."

        if kind == "header_macro" and macro:
            return f"FOLLOW-UP ARTIFACT (header_macro):\nMacro requested: {macro}\nFile: {file_name or 'unknown'}\nRelevant span: {json.dumps(span, ensure_ascii=False)}"

        if kind == "related_taint_path":
            return f"FOLLOW-UP ARTIFACT (related_taint_path):\nRequested path context: {json.dumps(request, ensure_ascii=False)}"

        return f"FOLLOW-UP ARTIFACT ({kind}):\nNo retriever implemented; request requires manual review."
    
    async def _triage_target(self, graph_json: str, graph_summary: str, source_code: str, directive: str, follow_up_context: str = "", target_func: str = "") -> Dict[str, Any]:
        """Triage acts as Hypothesis Generator."""
        try:
            response_text = await self.llm.execute_task(
                task_name="triage_agent",
                context_id=target_func,
                kwargs={
                    "graph_json": graph_json,
                    "graph_summary": graph_summary,
                    "source_code": source_code,
                    "directive": directive,
                    "follow_up_context": follow_up_context,
                },
            )
            return self._extract_json_object(response_text)
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning(f"Triage did not return JSON. Error: {exc}")
            return {"decision": "request_more", "confidence": 0.2, "reason": "Triage output was not valid JSON.", "follow_up_requests": []}

    _SEVERITY_RANK = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
    _RACE_KEYWORDS = ("race", "concurrency")
    # Used only when Triage fails to produce a usable candidate list (see
    # scan_function's "if not deep_scan_directive" fallback) -- deliberately generic
    # since there is no tailored threat model to decompose. effort_estimate is fixed
    # at "medium" for all of them: there's no per-candidate graph evidence to justify
    # scaling any of them up or down.
    _FALLBACK_CANDIDATES = [
        {"vulnerability_class": "buffer_overflow", "priority": 1, "rationale": "Fallback: triage output was unavailable.", "effort_estimate": "medium"},
        {"vulnerability_class": "missing_validation", "priority": 2, "rationale": "Fallback: triage output was unavailable.", "effort_estimate": "medium"},
        {"vulnerability_class": "data_race", "priority": 3, "rationale": "Fallback: triage output was unavailable.", "effort_estimate": "medium"},
        {"vulnerability_class": "other", "priority": 4, "rationale": "Fallback: triage output was unavailable.", "effort_estimate": "medium"},
    ]
    # "access_control" is one of the canonical vulnerability_class/vulnerability_type
    # slugs (see llm/prompts.json) for the same unreachability-premised false-positive
    # class as missing_validation/injection -- must be included here or the substring
    # check below silently never fires for it.
    _VALIDATION_KEYWORDS = ("validation", "injection", "access_control")
    _UNREACHABLE_EVIDENCE_KEYWORDS = ("unreachable", "never called", "dead code", "no caller", "internal-only", "internal only")

    # Maps Triage's per-candidate effort_estimate to the actual model_settings used
    # for that candidate's deep_scan_agent call -- this is the "adaptive reasoning
    # selection" half of prompt decomposition: a candidate Triage flagged as a quick
    # mechanical check no longer pays for the same reasoning_effort="high" budget as
    # a candidate needing multi-hop taint/concurrency reasoning.
    _EFFORT_MODEL_SETTINGS = {
        "low": {"reasoning_effort": "low", "max_completion_tokens": 3000},
        "medium": {"reasoning_effort": "medium", "max_completion_tokens": 6000},
        "high": {"reasoning_effort": "high", "max_completion_tokens": 10000},
    }
    _DEFAULT_EFFORT = "medium"

    def _reconcile_single_finding(self, finding: Dict[str, Any], graph_json: str) -> Dict[str, Any]:
        """
        Per-candidate equivalent of the old array-based reconciliation, adapted for
        single-tasked deep_scan output (one self-contained finding per call instead of
        a 'findings' array covering a whole checklist):
          1. Recomputes vulnerability_found from 'status' so a report can never
             silently claim a vulnerability while status != 'supported'.
          2. Cross-checks a 'data_race'/'concurrency' finding against the graph's own
             has_data_race_risk flag. Previously the model could freely assert a data
             race that the graph explicitly marks false, with no flag raised (observed
             in production: "The graph JSON note (has_data_race_risk: false) is
             superseded by the explicit snippet"). Any disagreement now forces
             needs_human_review.
          3. Cross-checks a validation/injection finding whose evidence claims the
             function is unreachable/internal-only against the graph's authoritative
             UDS-entry-point signal (is_dead_code + sources.uds[].source ==
             'dcm_did_table'). Same false-positive class investigated this session
             (e.g. Dcm DID dispatch-table callbacks with no direct caller in the source
             tree, which the resolver now correctly marks reachable).
        """
        if not isinstance(finding, dict):
            return finding

        try:
            graph_data = json.loads(graph_json)
            graph_function = graph_data.get("function", {}) or {}
            # NOTE: graph/resolver's serialize_function_neighborhood re-nests UDS
            # trigger evidence under top-level "sources.uds" (not "upstream.uds_triggers"
            # -- that key only exists in the raw Cypher payload before reassembly).
            graph_uds_sources = graph_data.get("sources", {}).get("uds", []) or []
        except (ValueError, json.JSONDecodeError, AttributeError):
            graph_function, graph_uds_sources = {}, []

        graph_has_data_race_risk = bool(graph_function.get("has_data_race_risk", False))
        graph_is_dead_code = bool(graph_function.get("is_dead_code", False))
        graph_has_authoritative_uds_trigger = any(
            isinstance(t, dict) and t.get("source") == "dcm_did_table"
            for t in graph_uds_sources
        )
        graph_is_reachable = (not graph_is_dead_code) or graph_has_authoritative_uds_trigger

        finding["vulnerability_found"] = finding.get("status") == "supported"
        if not finding["vulnerability_found"]:
            return finding

        vuln_type = str(finding.get("vulnerability_type", "")).lower()
        contradiction = None

        if any(kw in vuln_type for kw in self._RACE_KEYWORDS):
            claimed_agreement = finding.get("graph_flag_agreement")
            actual_agreement = graph_has_data_race_risk
            if claimed_agreement is not True and claimed_agreement is not False:
                # Model omitted the required field entirely.
                finding["graph_flag_agreement"] = actual_agreement
                contradiction = f"{finding.get('vulnerability_type')}: graph_flag_agreement missing (graph has_data_race_risk={graph_has_data_race_risk})"
            elif bool(claimed_agreement) != actual_agreement:
                contradiction = f"{finding.get('vulnerability_type')}: model claimed graph_flag_agreement={claimed_agreement} but graph has_data_race_risk={graph_has_data_race_risk}"

        elif any(kw in vuln_type for kw in self._VALIDATION_KEYWORDS):
            evidence = str(finding.get("evidence", "")).lower()
            premised_on_unreachability = any(kw in evidence for kw in self._UNREACHABLE_EVIDENCE_KEYWORDS)
            if premised_on_unreachability:
                claimed_agreement = finding.get("graph_flag_agreement")
                actual_agreement = not graph_is_reachable
                if claimed_agreement is not True and claimed_agreement is not False:
                    finding["graph_flag_agreement"] = actual_agreement
                    contradiction = (
                        f"{finding.get('vulnerability_type')}: graph_flag_agreement missing (graph is_dead_code="
                        f"{graph_is_dead_code}, authoritative_uds_trigger={graph_has_authoritative_uds_trigger})"
                    )
                elif bool(claimed_agreement) != actual_agreement:
                    contradiction = (
                        f"{finding.get('vulnerability_type')}: model claimed unreachability (graph_flag_agreement="
                        f"{claimed_agreement}) but graph is_dead_code={graph_is_dead_code} with "
                        f"authoritative_uds_trigger={graph_has_authoritative_uds_trigger}"
                    )

        if contradiction:
            finding["needs_human_review"] = True
            finding["graph_contradictions"] = [contradiction]
            logger.warning(f"Deep-scan/graph disagreement: {contradiction}")

        return finding

    async def _deep_scan_candidate(self, candidate: Dict[str, Any], graph_json: str, graph_summary: str, source_code: str, directive: str, follow_up_context: str = "", target_func: str = "") -> Dict[str, Any]:
        """
        Single-tasked deep scan: proves/disproves exactly ONE Triage-decomposed
        candidate per call (prompt decomposition), at a reasoning_effort/token budget
        picked from that candidate's own effort_estimate (adaptive reasoning
        selection) -- instead of one call batching a whole checklist at a single
        fixed reasoning_effort sized for the hardest item in it.
        """
        vuln_class = candidate.get("vulnerability_class", "unknown")
        settings_override = self._EFFORT_MODEL_SETTINGS.get(
            candidate.get("effort_estimate"), self._EFFORT_MODEL_SETTINGS[self._DEFAULT_EFFORT]
        )
        try:
            response_text = await self.llm.execute_task(
                task_name="deep_scan_agent",
                context_id=f"{target_func}-{vuln_class}",
                kwargs={
                    "graph_json": graph_json,
                    "graph_summary": graph_summary,
                    "source_code": source_code,
                    "directive": directive,
                    "candidate": json.dumps(candidate, ensure_ascii=False),
                    "follow_up_context": follow_up_context,
                },
                settings_override=settings_override,
            )
            finding = self._extract_json_object(response_text)
            return self._reconcile_single_finding(finding, graph_json)
        except (ValueError, json.JSONDecodeError) as exc:
            logger.warning(f"Deep scan for candidate '{vuln_class}' did not return JSON. Error: {exc}")
            return {
                "vulnerability_type": vuln_class,
                "status": "unknown",
                "vulnerability_found": False,
                "severity": "Informational",
                "details": f"Deep scan failed to return valid JSON for candidate '{vuln_class}'; partial analysis only.",
                "confidence": "low",
                "needs_human_review": True,
                "follow_up_requests": [],
            }

    async def _run_candidate_with_follow_up(self, candidate: Dict[str, Any], graph_json: str, graph_summary: str, source_code: str, directive: str, follow_up_context: str, target_func: str, seen_artifacts: set) -> Dict[str, Any]:
        """Runs one candidate's deep_scan call, with its own tiny (budget=1)
        follow-up-artifact loop so a candidate needing one more piece of evidence
        doesn't block or share budget with the other candidates running concurrently."""
        deep_budget = 1
        local_follow_up_context = follow_up_context
        while True:
            finding = await self._deep_scan_candidate(
                candidate, graph_json, graph_summary, source_code, directive, local_follow_up_context, target_func
            )
            follow_up_requests = finding.get("follow_up_requests") or []
            if not follow_up_requests or deep_budget <= 0:
                return finding

            request = follow_up_requests[0]
            artifact_key = (request.get("kind"), request.get("file"), request.get("function"), request.get("symbol"), request.get("macro"), json.dumps(request.get("span", {}), sort_keys=True))
            if artifact_key in seen_artifacts:
                return finding

            deep_budget -= 1
            seen_artifacts.add(artifact_key)
            local_follow_up_context = self._fetch_follow_up_artifact(request)

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

    async def scan_function(self, target_function_name: str) -> Dict[str, Any]:
        """Runs the scan pipeline with bounded follow-up loops for targeted missing evidence."""
        logger.info(f"=== Starting Scan for '{target_function_name}' ===")

        try:
            def safe_eval(tool_output: str):
                tool_output = tool_output.strip()
                if tool_output.startswith('[') or tool_output.startswith('{'):
                    try: return eval(tool_output)
                    except: return None
                return None

            metadata_str = self.tools_engine.get_function_metadata(target_function_name)
            metadata_list = safe_eval(metadata_str)
            metadata = metadata_list[0] if isinstance(metadata_list, list) and metadata_list else {}
        except Exception as e:
            logger.error(f"Could not retrieve metadata for {target_function_name}: {e}")
            metadata = {}

        try:
            source_code = self._get_target_source(target_function_name)
            graph_json, graph_summary = self.graph_resolver.serialize_function_neighborhood(target_function_name)
        except Exception as e:
            logger.error(f"Failed to build graph context for {target_function_name}: {e}")
            return {"vulnerability_found": False, "details": "Failed during graph context creation.", "metadata": metadata}

        triage_budget = 3
        seen_artifacts = set()
        follow_up_context = ""

        # Initial minimal directive to kick off Triage
        base_directive = f"Platform Context: [{self.platform_info}]. Formulate an investigation directive based on the graph context."

        # This will hold the dynamic threat model generated by the Triage Agent
        deep_scan_directive = ""
        deep_scan_candidates = []

        while triage_budget >= 0:
            logger.info(f"Running triage for '{target_function_name}' (remaining budget: {triage_budget})")
            triage = await self._triage_target(graph_json, graph_summary, source_code, base_directive, follow_up_context, target_func=target_function_name)
            decision = triage.get("decision", "escalate")
            requests = triage.get("follow_up_requests") or []

            # If Triage decides to escalate, it MUST provide the dynamic threat model
            # If Triage decides to escalate, it MUST provide the dynamic threat model
            if decision == "escalate":
                deep_scan_directive = triage.get("investigation_directive", "Perform a standard check for logic flaws.")
                deep_scan_candidates = triage.get("vulnerability_candidates") or []
                preview = deep_scan_directive[:60].replace('\n', ' ') + "..." if len(deep_scan_directive) > 60 else deep_scan_directive
                logger.info(f"Triage Escalated -> Threat Model: '{preview}'")
                logger.debug(f"Full Threat Model Directive:\n{deep_scan_directive}")
                break

            if decision == "ignore":
                logger.info(f"Triage dismissed '{target_function_name}'. Reason: {triage.get('reason')}")
                return {
                    "vulnerability_found": False,
                    "severity": "Informational",
                    "details": f"Triage dismissed. Reason: {triage.get('reason')}",
                    "confidence": triage.get("confidence", 0.9),
                    "metadata": metadata
                }

            if decision == "request_more" and requests and triage_budget > 0:
                triage_budget -= 1
                request = requests[0]
                artifact_key = (request.get("kind"), request.get("file"), request.get("function"), request.get("symbol"), request.get("macro"), json.dumps(request.get("span", {}), sort_keys=True))
                if artifact_key not in seen_artifacts:
                    seen_artifacts.add(artifact_key)
                    follow_up_context = self._fetch_follow_up_artifact(request)
                    base_directive = triage.get("reason") or base_directive
                    continue
                break

            break

        triage_degraded = not deep_scan_directive or not deep_scan_candidates
        if triage_degraded:
            # Triage never reached its "escalate" branch (JSON parsing failed and
            # _triage_target's fallback returned an empty follow_up_requests list, or
            # the follow-up budget ran out), or escalated without a usable candidate
            # list -- deep_scan_directive/deep_scan_candidates are still at (or reduced
            # to) their initial empty values. Previously this silently ran deep_scan
            # with nothing to check, which correctly-but-uselessly reports zero
            # findings; confirmed in a real run where 45/50 triage calls hit this path
            # after their JSON response was truncated by too small a
            # max_completion_tokens budget. Use a generic conservative candidate list
            # instead of leaving the target completely unchecked, and flag it for
            # review since triage's tailored threat model was lost.
            logger.warning(
                f"Triage for '{target_function_name}' never reached a clean escalate decision "
                "with a usable candidate list (likely a JSON parse failure) -- falling back to "
                "a generic candidate list instead of an empty/degraded deep-scan directive."
            )
            deep_scan_directive = (
                f"Platform Context: [{self.platform_info}]. Triage failed to produce a tailored "
                "threat model for this function (its response could not be parsed as valid JSON, "
                "or omitted a usable candidate list). Perform a generic multi-class review using "
                "only the graph JSON and source snippet."
            )
            deep_scan_candidates = self._FALLBACK_CANDIDATES

        # Prompt decomposition: one single-tasked deep_scan call per candidate,
        # run concurrently, each at a reasoning effort/token budget scaled to that
        # candidate's own effort_estimate (adaptive reasoning selection) instead of
        # one batched call sized for the hardest item in the whole checklist.
        results = await asyncio.gather(*[
            self._run_candidate_with_follow_up(
                candidate, graph_json, graph_summary, source_code, deep_scan_directive,
                follow_up_context, target_function_name, seen_artifacts,
            )
            for candidate in deep_scan_candidates
        ])

        supported = [f for f in results if isinstance(f, dict) and f.get("status") == "supported"]
        graph_contradictions = [
            c for f in results if isinstance(f, dict) for c in (f.get("graph_contradictions") or [])
        ]
        needs_human_review = triage_degraded or any(
            isinstance(f, dict) and f.get("needs_human_review") for f in results
        )

        if supported:
            primary = max(supported, key=lambda f: self._SEVERITY_RANK.get(str(f.get("severity", "")).lower(), -1))
            last_report = {
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
            last_report = {
                "vulnerability_found": False,
                "severity": "Informational",
                "details": f"No supported findings across {len(results)} decomposed candidate(s).",
                "confidence": "low",
                "decision": "final",
                "findings": results,
            }

        if graph_contradictions:
            last_report["graph_contradictions"] = graph_contradictions
        if needs_human_review:
            last_report["needs_human_review"] = True

        last_report["metadata"] = metadata
        last_report["triage_directive"] = deep_scan_directive
        last_report["triage_degraded"] = triage_degraded
        return last_report

    async def prioritize_targets(self, max_targets: int, domain_filter: str = None, file_filter: str = None) -> list:
        """
        DETERMINISTIC TARGET SELECTION: 
        Replaces the LLM 'prioritization_agent' with pure Cypher queries to eliminate hallucinated rankings.
        """
        logger.info(f"=== Starting Target Prioritization Phase (Max Targets: {max_targets}, Domain Filter: {domain_filter}, File Filter: {file_filter}) ===")

        if domain_filter:
            logger.info(f"Applying domain filter: Scanning functions within '{domain_filter}'...")
        else:
            logger.info("Extracting targets for ALL active candidates from Neo4j...")

        try:
            # Delegate entirely to the Graph Module to maintain strict modularity
            targets = self.graph_resolver.get_prioritized_targets(
                max_targets=max_targets,
                domain_filter=domain_filter,
                file_filter=file_filter
            )
            
            logger.info(f"Target Selection Complete! Identified {len(targets)} deterministically mapped targets.")
            return targets
            
        except asyncio.CancelledError:
            logger.warning("Prioritization was cancelled.")
            raise
        except Exception as e:
            logger.error(f"Target Selection failed: {e}")
            return []
