import json
import logging
import asyncio
from typing import Dict, Any

from llm.service import LLMService
from scan.tools import AnalyzerTools
from graph.manager import GraphManager

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    def __init__(self, llm_service: LLMService, graph_manager: GraphManager):
        self.llm = llm_service
        self.graph_resolver = graph_manager.resolver
        # Tools remain synchronous!
        self.tools_engine = AnalyzerTools(graph_manager)

    # --- REMAINS SYNCHRONOUS ---
    def _get_target_source(self, func_name: str) -> str:
        query = "MATCH (f:Function {name: $func_name}) RETURN f.storage_uri AS uri, f.byte_span AS span LIMIT 1"
        try:
            with self.tools_engine.db.driver.session() as session:
                result = session.run(query, func_name=func_name).single()
                if not result:
                    return f"// Source code not found for {func_name}"
            return self.tools_engine.read_file_span(result["uri"], result["span"])
        except Exception as e:
            return f"// Error retrieving source code: {e}"

    # --- CHANGED: ASYNC (Calls LLM) ---
    async def scan_function(self, target_function_name: str) -> Dict[str, Any]:
        """Runs the scan pipeline. Awaits the LLM calls to free the event loop."""
        logger.info(f"=== Starting Scan for '{target_function_name}' ===")
        
        try:
            def safe_eval(tool_output: str):
                tool_output = tool_output.strip()
                if tool_output.startswith('[') or tool_output.startswith('{'):
                    try: return eval(tool_output)
                    except: return None
                return None
            
            # Sync DB calls
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

        logger.info(f"Generating directive for '{target_function_name}'...")
        # --- AWAIT LLM CALL ---
        directive = await self._generate_analysis_directive(graph_json, graph_summary)
        
        logger.info(f"Passing compact Neo4j JSON + summary to Deep-Scan Agent for '{target_function_name}'...")
        try:
            # --- AWAIT LLM CALL ---
            response_text = await self.llm.execute_task(
                task_name="deep_scan_agent",
                kwargs={
                    "graph_json": graph_json,
                    "graph_summary": graph_summary,
                    "source_code": source_code,
                    "directive": directive,
                }
            )
            
            start_idx = response_text.find('{')
            end_idx = response_text.rfind('}')
            
            if start_idx != -1 and end_idx != -1:
                json_string = response_text[start_idx:end_idx + 1]
                report = json.loads(json_string)
                report['metadata'] = metadata
                return report
            else:
                logger.error(f"Deep Scan output for {target_function_name} did not contain JSON.\nRAW RESPONSE:\n{response_text}")
                return {"vulnerability_found": False, "details": "Scan failed: No JSON object found in response.", "metadata": metadata}
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse JSON for {target_function_name}: {e}")
            return {"vulnerability_found": False, "details": "Scan failed due to invalid JSON format.", "metadata": metadata}
        except asyncio.CancelledError:
            # Handle graceful cancellation!
            logger.warning(f"Scan for {target_function_name} was cancelled.")
            raise
        except Exception as e:
            return {"vulnerability_found": False, "details": f"Scan failed for {target_function_name}: {e}", "metadata": metadata}

    # --- CHANGED: ASYNC (Calls LLM) ---
    async def _generate_analysis_directive(self, graph_json: str, graph_summary: str) -> str:
        try:
            directive = await self.llm.execute_task(
                task_name="triage_agent",
                kwargs={
                    "graph_json": graph_json,
                    "graph_summary": graph_summary,
                },
            )
            return directive if directive.strip() else "Perform a standard check for logic flaws."
        except asyncio.CancelledError:
            raise
        except Exception:
            return "Perform a standard check for logic flaws."

    # --- ASYNC (Calls LLM) ---
    async def prioritize_targets(self, scan_depth: str, max_targets: int, domain_filter: str = None) -> list:
        logger.info(f"=== Starting Target Prioritization Phase (Depth: {scan_depth.upper()}) ===")

        if domain_filter:
            logger.info(f"Applying domain filter: Scanning functions within '{domain_filter}'...")
        else:
            logger.info("Extracting metrics for ALL active candidates from Neo4j...")

        try:
            metrics_list = self.graph_resolver.get_candidate_metrics(domain_filter=domain_filter)

            if not metrics_list:
                logger.warning("No dangerous candidate functions found in the graph for the selected domain.")
                return []
                
            logger.info(f"Extracted metrics for {len(metrics_list)} total high-risk candidate functions.")
            
            if scan_depth == "full":
                logger.info(f"Full scan requested. Returning all {len(metrics_list)} candidates.")
                return [m["FunctionName"] for m in metrics_list]

            logger.info(f"Asking Prioritization Agent to rank the Top {max_targets} targets...")
            
            metrics_for_llm = metrics_list[:500]
            metrics_json_str = json.dumps(metrics_for_llm)
            
            # --- AWAIT LLM CALL ---
            response_text = await self.llm.execute_task(
                task_name="prioritization_agent",
                kwargs={"metrics_data": metrics_json_str}
            )
            
            cleaned = response_text.strip()
            if cleaned.startswith("```json"): cleaned = cleaned[7:]
            elif cleaned.startswith("```"): cleaned = cleaned[3:]
            if cleaned.endswith("```"): cleaned = cleaned[:-3]
            
            report = json.loads(cleaned.strip())
            ranked_list = report.get("ranked_targets", [])
            
            ranked_list = ranked_list[:max_targets]
            
            logger.info(f"Target Prioritization Complete! Identified {len(ranked_list)} critical targets for '{scan_depth}' scan.")
            return ranked_list
            
        except asyncio.CancelledError:
            logger.warning("Prioritization was cancelled.")
            raise
        except Exception as e:
            logger.error(f"Target Prioritization failed: {e}")
            return []
