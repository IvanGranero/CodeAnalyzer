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
        # Tools remain synchronous!
        self.tools_engine = AnalyzerTools(graph_manager)

    # --- REMAINS SYNCHRONOUS (Fast DB/File I/O) ---
    def _build_markdown_dossier(self, func_name: str) -> str:
        """Deterministically builds a highly-structured Markdown Dossier in milliseconds."""
        logger.info(f"Gathering Graph Neighborhood Context for '{func_name}'...")
        
        def safe_eval(tool_output: str):
            tool_output = tool_output.strip()
            if tool_output.startswith('[') or tool_output.startswith('{'):
                try: return eval(tool_output)
                except: return None
            return None

        # Synchronous calls to the DB
        source_code = self._get_target_source(func_name)
        metadata = safe_eval(self.tools_engine.get_function_metadata(func_name))
        callers = safe_eval(self.tools_engine.get_callers_and_entry_points(func_name))
        callees = safe_eval(self.tools_engine.get_callees(func_name))
        vars_access = safe_eval(self.tools_engine.get_variable_access(func_name))
        
        md = []
        md.append(f"# VULNERABILITY DOSSIER: `{func_name}`\n")
        
        md.append("## 1. SOURCE CODE")
        md.append("```c\n" + source_code.strip() + "\n```\n")
        
        md.append("## 2. ATTACK SURFACE & METADATA")
        if isinstance(metadata, list) and metadata:
            meta = metadata[0]
            md.append(f"- **Tainted by UDS:** {meta.get('TaintedByUDS', False)}")
            dids = meta.get('DIDs')
            if dids: md.append(f"- **Reachable DIDs:** {', '.join(dids)}")
            md.append(f"- **Is Vendor Library:** {meta.get('IsVendorLibrary', False)}\n")
        else:
            md.append("- No metadata found.\n")
            
        md.append("## 3. UPSTREAM TRIGGERS (Who calls this?)")
        if isinstance(callers, dict):
            md.append(f"- **UDS Triggers:** {', '.join(callers.get('UdsTriggers', [])) or 'None'}")
            md.append(f"- **Network Triggers:** {', '.join(callers.get('NetworkTriggers', [])) or 'None'}")
            md.append(f"- **Standard C Callers:** {', '.join(callers.get('StandardCallers', [])) or 'None'}")
            md.append(f"- **Is OS/Hardware Task:** {callers.get('IsHardwareTask', False)}\n")
        else:
            md.append("- No upstream context found.\n")
            
        md.append("## 4. DOWNSTREAM CALLS (What does this call?)")
        if isinstance(callees, list) and callees:
            for c in callees:
                warn = " (WARNING: Unparsed Stub)" if c.get('IsStubNode') else ""
                danger = " ⚠️ [DANGEROUS SINK]" if c.get('IsDangerousSink') else ""
                md.append(f"- `{c.get('CalledFunction')}`{danger}{warn}")
        else:
            md.append("- No downstream calls found.")
        md.append("\n")
            
        md.append("## 5. GLOBAL VARIABLE ACCESS")
        if isinstance(vars_access, list) and vars_access:
            reads = [v['VariableName'] for v in vars_access if v['AccessType'] == 'READS_VAR']
            writes = [v['VariableName'] for v in vars_access if v['AccessType'] == 'WRITES_VAR']
            md.append(f"- **Reads:** {', '.join(reads) or 'None'}")
            md.append(f"- **Writes:** {', '.join(writes) or 'None'}")
        else:
            md.append("- No global variable access found.")
            
        return "\n".join(md)

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
            # Sync Dossier build
            full_dossier = self._build_markdown_dossier(target_function_name)
        except Exception as e:
            logger.error(f"Failed to build dossier for {target_function_name}: {e}")
            return {"vulnerability_found": False, "details": "Failed during dossier creation.", "metadata": metadata}

        logger.info(f"Generating directive for '{target_function_name}'...")
        # --- AWAIT LLM CALL ---
        directive = await self._generate_analysis_directive(full_dossier)
        
        logger.info(f"Passing Dossier to Deep-Scan Agent for '{target_function_name}'...")
        try:
            # --- AWAIT LLM CALL ---
            response_text = await self.llm.execute_task(
                task_name="deep_scan_agent",
                kwargs={"dossier": full_dossier, "directive": directive}
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
    async def _generate_analysis_directive(self, dossier: str) -> str:
        try:
            directive = await self.llm.execute_task(task_name="triage_agent", kwargs={"dossier": dossier})
            return directive if directive.strip() else "Perform a standard check for logic flaws."
        except asyncio.CancelledError:
            raise
        except Exception:
            return "Perform a standard check for logic flaws."

    # --- CHANGED: ASYNC (Calls LLM) ---
    async def prioritize_targets(self, scan_depth: str, max_targets: int, domain_filter: str = None) -> list:
        logger.info(f"=== Starting Target Prioritization Phase (Depth: {scan_depth.upper()}) ===")
        
        cypher_filter = ""
        if domain_filter:
            cypher_filter = f"AND (f.storage_uri CONTAINS '/{domain_filter}/' OR f.storage_uri CONTAINS '\\\\{domain_filter}\\\\')"
            logger.info(f"Applying domain filter: Scanning functions within '{domain_filter}'...")
        else:
            logger.info("Extracting metrics for ALL active candidates from Neo4j...")
        
        query = f"""
        MATCH (f:Function)
        WHERE coalesce(f.is_vendor_code, false) = false 
          AND coalesce(f.is_dead_code, false) = false
          AND NOT f:Stub
          {cypher_filter}
          
        OPTIONAL MATCH (f)-[:CALLS*1..3]->(sink:Function {{is_dangerous_sink: true}})
        OPTIONAL MATCH (f)-[w:WRITES_VAR]->(v:GlobalVariable)
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        OPTIONAL MATCH (f)-[:RECEIVES_SIGNAL]->(net:NetworkSignal)
        
        WITH f, 
             count(DISTINCT sink) AS DangerousSinksReached,
             count(DISTINCT w) AS GlobalVariableWrites,
             count(DISTINCT uds) > 0 AS IsDirectUdsHandler,
             count(DISTINCT net) > 0 AS IsDirectNetworkHandler
             
        WHERE coalesce(f.tainted_by_uds, false) = true OR DangerousSinksReached > 0 OR GlobalVariableWrites > 0
        
        RETURN {{
            FunctionName: f.name,
            TaintedByUDS: coalesce(f.tainted_by_uds, false),
            IsUdsHandler: IsDirectUdsHandler,
            IsNetworkHandler: IsDirectNetworkHandler,
            DangerousSinksReached: DangerousSinksReached,
            GlobalVariableWrites: GlobalVariableWrites
        }} AS Metrics
        ORDER BY DangerousSinksReached DESC, GlobalVariableWrites DESC, coalesce(f.tainted_by_uds, false) DESC
        """
        
        try:
            # Synchronous DB query
            with self.tools_engine.db.driver.session() as session:
                results = session.run(query).data()
                metrics_list = [r["Metrics"] for r in results]
                
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
