import logging
from typing import Dict, Any, List
from graph.db import GraphDB

logger = logging.getLogger(__name__)

class GraphRetriever:
    def __init__(self, db: GraphDB):
        self.db = db

    def get_function_cpg_context(self, function_name: str) -> Dict[str, Any]:
        """
        Retrieves the immediate CPG context for a specific function.
        Gets callers, callees, variables, and checks if it implements an AutoSAR Runnable.
        """
        query = """
        MATCH (target:Function {name: $func_name})
        
        // 1. Get callers
        OPTIONAL MATCH (caller:Function)-[:CALLS]->(target)
        
        // 2. Get callees
        OPTIONAL MATCH (target)-[:CALLS]->(callee:Function)
        
        // 3. Get variables accessed/modified
        OPTIONAL MATCH (target)-[use_rel:USES]->(var:Variable)
        
        // 4. Bridge to AutoSAR Layer: Does this implement a runnable?
        OPTIONAL MATCH (target)-[:IMPLEMENTS]->(runnable:RunnableEntity)
        
        RETURN 
            target.name AS target_function,
            target.storage_uri AS uri,
            target.byte_span AS byte_span,
            collect(DISTINCT caller.name) AS callers,
            collect(DISTINCT callee.name) AS callees,
            collect(DISTINCT {name: var.name, type: use_rel.type}) AS variables,
            collect(DISTINCT runnable.name) AS autosar_runnables
        """
        
        results = self.db.retrieve(query, {"func_name": function_name})
        if not results:
            logger.warning(f"Function {function_name} not found in CPG.")
            return {}
            
        return results[0]

    def get_autosar_domain_context(self, runnable_name: str) -> Dict[str, Any]:
        """
        Retrieves the AutoSAR architectural context for a RunnableEntity.
        Useful for understanding the vehicle-level meaning of a function.
        """
        query = """
        MATCH (r:RunnableEntity {name: $runnable_name})
        
        // RTE ports accessed by this runnable
        OPTIONAL MATCH (r)-[:ACCESSES]->(port:RtePort)
        
        // Events that trigger this runnable (e.g., TimingEvent, DataReceivedEvent)
        OPTIONAL MATCH (event:RteEvent)-[:TRIGGERS]->(r)
        
        RETURN 
            r.name AS runnable,
            collect(DISTINCT port.name) AS accessed_ports,
            collect(DISTINCT event.name) AS triggering_events
        """
        results = self.db.retrieve(query, {"runnable_name": runnable_name})
        return results[0] if results else {}

    def build_scan_prompt_context(self, function_name: str) -> str:
        """
        Utility method for the /scan module. 
        Aggregates graph data and formats it directly into a Markdown string for the LLM.
        """
        cpg_data = self.get_function_cpg_context(function_name)
        if not cpg_data:
            return f"No graph context available for {function_name}."

        context_blocks = [f"### Graph Context for Function: `{function_name}`\n"]
        
        if cpg_data.get('callers'):
            context_blocks.append(f"**Called By (Incoming):** {', '.join(cpg_data['callers'])}")
        
        if cpg_data.get('callees'):
            context_blocks.append(f"**Calls (Outgoing):** {', '.join(cpg_data['callees'])}")
            
        if cpg_data.get('variables'):
            vars_str = ", ".join([f"{v['name']} ({v['type']})" for v in cpg_data['variables']])
            context_blocks.append(f"**Variables Accessed:** {vars_str}")

        # Check for AutoSAR architectural mapping
        runnables = cpg_data.get('autosar_runnables', [])
        for runnable in runnables:
            autosar_data = self.get_autosar_domain_context(runnable)
            if autosar_data:
                context_blocks.append(f"\n#### AutoSAR Architectural Mapping (Runnable: `{runnable}`)")
                context_blocks.append(f"**Triggered By:** {', '.join(autosar_data.get('triggering_events', []))}")
                context_blocks.append(f"**Accesses RTE Ports:** {', '.join(autosar_data.get('accessed_ports', []))}")

        return "\n".join(context_blocks)
