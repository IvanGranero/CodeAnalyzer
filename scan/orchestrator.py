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

    async def _deep_scan_target(self, graph_json: str, graph_summary: str, source_code: str, directive: str, follow_up_context: str = "", target_func: str = "") -> Dict[str, Any]:
        """Deep scan evaluates the hypothesis with full context."""
        try:
            response_text = await self.llm.execute_task(
                task_name="deep_scan_agent",
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
            logger.warning(f"Deep scan did not return JSON. Error: {exc}")
            return {
                "vulnerability_found": False,
                "severity": "Informational",
                "details": "Deep scan failed to return valid JSON; partial analysis only.",
                "confidence": "low",
                "needs_human_review": True,
                "follow_up_requests": [],
            }

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
        deep_budget = 1
        seen_artifacts = set()
        follow_up_context = ""
        
        # Initial minimal directive to kick off Triage
        base_directive = f"Platform Context: [{self.platform_info}]. Formulate an investigation directive based on the graph context."
        
        # This will hold the dynamic threat model generated by the Triage Agent
        deep_scan_directive = ""

        while triage_budget >= 0:
            logger.info(f"Running triage for '{target_function_name}' (remaining budget: {triage_budget})")
            triage = await self._triage_target(graph_json, graph_summary, source_code, base_directive, follow_up_context, target_func=target_function_name)
            decision = triage.get("decision", "escalate")
            requests = triage.get("follow_up_requests") or []

            # If Triage decides to escalate, it MUST provide the dynamic threat model
            # If Triage decides to escalate, it MUST provide the dynamic threat model
            if decision == "escalate":
                deep_scan_directive = triage.get("investigation_directive", "Perform a standard check for logic flaws.")
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

        last_report = None
        while deep_budget >= 0:
            logger.info(f"Running deep scan for '{target_function_name}' (remaining budget: {deep_budget})")
            # Pass the dynamically generated directive from the Triage Agent!
            deep_response = await self._deep_scan_target(graph_json, graph_summary, source_code, deep_scan_directive, follow_up_context, target_func=target_function_name)
            last_report = deep_response

            follow_up_requests = deep_response.get("follow_up_requests") or []
            if follow_up_requests and deep_budget > 0:
                deep_budget -= 1
                request = follow_up_requests[0]
                artifact_key = (request.get("kind"), request.get("file"), request.get("function"), request.get("symbol"), request.get("macro"), json.dumps(request.get("span", {}), sort_keys=True))
                if artifact_key not in seen_artifacts:
                    seen_artifacts.add(artifact_key)
                    follow_up_context = self._fetch_follow_up_artifact(request)
                    continue

            if deep_response.get("needs_human_review") or deep_response.get("decision") == "needs_more_context":
                if deep_budget <= 0:
                    break

            if not follow_up_requests:
                break

            if deep_budget <= 0:
                break

        if last_report is None:
            last_report = {
                "vulnerability_found": False,
                "severity": "Informational",
                "details": "Scan completed without a final deep-scan verdict.",
                "confidence": "low",
                "needs_human_review": True,
            }

        if isinstance(last_report, dict):
            last_report["metadata"] = metadata
            last_report["triage_directive"] = deep_scan_directive 
            return last_report

        logger.error(f"Deep Scan output for {target_function_name} was not a dictionary: {last_report}")
        return {"vulnerability_found": False, "details": "Scan failed: invalid final result.", "metadata": metadata}

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
