import os
import json
import logging
from tools.graph.manager import GraphManager

logger = logging.getLogger(__name__)

class AnalyzerTools:
    """Deterministic tools exposed to the AnalyzerAgent for exploring the codebase."""
    
    def __init__(self, graph_manager: GraphManager):
        self.db = graph_manager.db
        self.graph_resolver = graph_manager.resolver
        self._cache = set()

    def _check_cache(self, tool_name: str, cache_key: str) -> bool:
        """Checks if the agent already ran this exact tool with these exact arguments."""
        full_key = f"{tool_name}::{cache_key}"
        if full_key in self._cache:
            return True
        self._cache.add(full_key)
        return False

    def get_function_metadata(self, func_name: str) -> str:
        # NOTE: fields are returned as separate top-level aliases, NOT as a single
        # map aliased "metadata" -- `RETURN {...} AS metadata` used to make every row
        # come back as {"metadata": {FilePath: ..., ...}}, one nesting level deeper
        # than every consumer expects (scan_function's `metadata_list[0]`,
        # scan/reporter.py, app/phases/scan_phase.py's TaintedByUDS exploit-routing
        # check, exploit/orchestrator.py's DID context builder). Confirmed against a
        # real run: 100% of cached reports had this double-nested shape, so
        # metadata.get("TaintedByUDS") always silently returned the False default --
        # meaning every found vulnerability was skipped for exploit regardless of
        # actual UDS reachability -- and the DIDs-truncation/stub-warning
        # post-processing two lines below never fired either.
        query = """
        MATCH (f:Function {name: $func_name})
        WHERE NOT f.storage_uri ENDS WITH '.h'  // <--- NEW: Force .c file
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        WITH f, collect(DISTINCT {did: uds.did, func_class_hex: uds.func_class_hex, source: coalesce(uds.source, 'heuristic')}) AS did_details
        RETURN f.storage_uri AS FilePath,
               f.byte_span AS ByteSpan,
               coalesce(f.tainted_by_uds, false) AS TaintedByUDS,
               coalesce(f.reachable_from_dids, []) AS DIDs,
               did_details AS DidDetails,
               coalesce(f.is_vendor_code, false) AS IsVendorLibrary,
               f:Stub AS IsStubNode
        LIMIT 1
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).data()
                if not result: return f"Function {func_name} not found in graph."
                for r in result:
                    dids = r.get("DIDs")
                    if dids and len(dids) > 10: r["DIDs"] = dids[:10] + [f"... and {len(dids) - 10} more"]
                    if r.get("IsStubNode"): r["WARNING"] = "This is a Stub node. It has no source code available."
                return str(result)
        except Exception as e:
            return f"Error executing tool: {e}"

    def get_type_definition(self, type_name: str) -> str:
        """Returns the source code snippet for a struct, enum, or typedef definition."""
        if self._check_cache("get_type_definition", type_name):
            return f"System Note: You have already requested the definition for type '{type_name}'."
        
        query = "MATCH (t:TypeDefinition {name: $type_name}) RETURN t.storage_uri AS uri, t.byte_span AS span LIMIT 1"
        try:
            with self.db.driver.session() as session:
                result = session.run(query, type_name=type_name).single()
                if not result:
                    return f"Type '{type_name}' not found in the graph."
            return self.read_file_span(result["uri"], result["span"])
        except Exception as e:
            return f"Error executing tool: {e}"

    # --- NEW: Tool to get the definition of a preprocessor macro ---
    def get_macro_definition(self, macro_name: str) -> str:
        """Returns the '#define' value of a macro."""
        if self._check_cache("get_macro_definition", macro_name):
            return f"System Note: You have already requested the definition for macro '{macro_name}'."

        query = "MATCH (m:MacroDefinition {name: $macro_name}) RETURN m.value AS value LIMIT 1"
        try:
            with self.db.driver.session() as session:
                result = session.run(query, macro_name=macro_name).single()
                if not result:
                    return f"Macro '{macro_name}' not found in the graph."
            return f"#define {macro_name} {result['value']}"
        except Exception as e:
            return f"Error executing tool: {e}"

    def get_callees(self, func_name: str) -> str:
        # (This function remains the same)
        if self._check_cache("get_callees", func_name):
            return f"System Note: Callees for '{func_name}' are already in your conversation history."
        query = """
        MATCH (f:Function {name: $func_name})-[:CALLS]->(callee:Function)
        RETURN callee.name AS CalledFunction, callee.is_vendor_code AS IsVendorLibrary, 
               callee.is_dangerous_sink AS IsDangerousSink, callee:Stub AS IsStubNode
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).data()
                if not result: return "No callees found."
                for r in result:
                    if r.get("IsStubNode"): r["WARNING"] = "Stub node. No source code available."
                return str(result)
        except Exception as e:
            return f"Error executing tool: {e}"

    def read_file_span(self, storage_uri: str, byte_span: str) -> str:
        # (This function remains the same)
        if not storage_uri or not byte_span:
            return "Error: Must provide both storage_uri and byte_span."
        if self._check_cache("read_file_span", f"{storage_uri}_{byte_span}"):
            return "System Note: You have already read this exact file span."
        file_path = storage_uri
        if file_path.startswith("file://"): file_path = file_path[7:]
        if os.name == 'nt' and file_path.startswith('/') and ':' in file_path: file_path = file_path[1:]
        try:
            start_byte, end_byte = map(int, byte_span.split('-'))
            with open(file_path, 'rb') as f:
                f.seek(start_byte)
                snippet = f.read(end_byte - start_byte)
                return snippet.decode('utf-8', errors='ignore')
        except FileNotFoundError:
            return f"Error: The file {file_path} was not found on disk."
        except Exception as e:
            return f"Error reading file from disk: {e}"

    def get_callers_and_entry_points(self, func_name: str) -> str:
        # (This function remains the same)
        if self._check_cache("get_callers", func_name):
            return f"System Note: Callers for '{func_name}' are already in your conversation history."
        query = """
        MATCH (f:Function {name: $func_name})
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        OPTIONAL MATCH (f)-[:RECEIVES_SIGNAL]->(net:NetworkSignal)
        OPTIONAL MATCH (caller:Function)-[:CALLS]->(f)
        RETURN collect(DISTINCT uds.did) AS UdsTriggers, collect(DISTINCT net.name) AS NetworkTriggers,
               collect(DISTINCT caller.name) AS StandardCallers, f.is_hardware_entry AS IsHardwareTask
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).single()
                return str(result.data()) if result else "No upstream context found."
        except Exception as e:
            return f"Error executing tool: {e}"

    def get_variable_access(self, func_name: str) -> str:
        # (This function remains the same)
        if self._check_cache("get_vars", func_name):
            return f"System Note: Variable access for '{func_name}' is already in your conversation history."
        query = """
        MATCH (f:Function {name: $func_name})-[r:READS_VAR|WRITES_VAR]->(v:GlobalVariable)
        RETURN v.name AS VariableName, type(r) AS AccessType
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).data()
                return str(result) if result else "No global variable access found."
        except Exception as e:
            return f"Error executing tool: {e}"

    def get_related_global_accesses(self, func_name: str, symbol: str = None) -> str:
        """Return all graph-resolved reads and writes for globals used by a function."""
        query = """
        MATCH (f:Function {name: $func_name})-[:READS_VAR|WRITES_VAR]->(v:GlobalVariable)
        WITH collect(DISTINCT v) AS variables
        UNWIND variables AS v
        MATCH (accessor:Function)-[r:READS_VAR|WRITES_VAR]->(v)
        WHERE $symbol IS NULL OR v.name = $symbol
        RETURN v.name AS VariableName,
               v.storage_uri AS FilePath,
               v.byte_span AS ByteSpan,
               accessor.name AS FunctionName,
               type(r) AS AccessType,
               coalesce(r.resolution, 'unknown') AS Resolution
        ORDER BY VariableName, FunctionName, AccessType
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name, symbol=symbol).data()
            return json.dumps(result, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"Error executing tool: {e}"})

    def get_concurrency_metadata(self, func_name: str) -> str:
        """Return task/ISR bindings, locks, exclusive areas, and race flags."""
        query = """
        MATCH (f:Function {name: $func_name})
        OPTIONAL MATCH (f)-[:IMPLEMENTS_TASK]->(task:OsTask)
        OPTIONAL MATCH (f)-[:IMPLEMENTS_TASK]->(isr:OsIsr)
        OPTIONAL MATCH (f)-[lock:OS_LOCK_ACTION]->(resource:OsResource)
        OPTIONAL MATCH (f)-[area:CALLS {call_type: 'exclusive_area'}]->(exclusive:OsResource)
        RETURN collect(DISTINCT {name: task.name, priority: task.priority,
                                 max_activations: task.max_activations}) AS Tasks,
               collect(DISTINCT {name: isr.name, category: isr.isr_category}) AS ISRs,
               collect(DISTINCT {name: resource.name, action: lock.action,
                                 mechanism: resource.mechanism,
                                 property: resource.resource_property}) AS Locks,
               collect(DISTINCT {name: exclusive.name, mechanism: area.mechanism}) AS ExclusiveAreas,
               coalesce(f.has_data_race_risk, false) AS HasDataRaceRisk,
               coalesce(f.is_hardware_entry, false) AS IsHardwareEntry
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).single()
            return json.dumps(result.data() if result else {}, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"Error executing tool: {e}"})

    def get_preprocessed_source(self, func_name: str, build_variant: str = "default") -> str:
        """Return the indexed implementation source and state whether preprocessing exists."""
        query = """
        MATCH (f:Function {name: $func_name})
        WHERE NOT f.storage_uri ENDS WITH '.h'
        RETURN f.storage_uri AS FilePath, f.byte_span AS ByteSpan,
               coalesce(f.build_variant, 'source') AS IndexedVariant
        LIMIT 1
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, func_name=func_name).single()
            if not result:
                return json.dumps({"status": "not_found", "function": func_name})
            source = self.read_file_span(result["FilePath"], result["ByteSpan"])
            return json.dumps({
                "status": "source_only",
                "requested_variant": build_variant,
                "indexed_variant": result["IndexedVariant"],
                "file": result["FilePath"],
                "span": result["ByteSpan"],
                "content": source,
                "note": "No compiler-preprocessed build variant is indexed; this is the parsed source span.",
            }, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"Error executing tool: {e}"})

    def get_type_layout(self, type_name: str) -> str:
        """Return indexed type properties and its bounded definition when available."""
        query = """
        MATCH (t:TypeDefinition {name: $type_name})
        RETURN t.name AS TypeName, t.storage_uri AS FilePath, t.byte_span AS ByteSpan,
               properties(t) AS Properties
        LIMIT 1
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query, type_name=type_name).single()
            if not result:
                return json.dumps({"status": "not_found", "type": type_name})
            data = result.data()
            data["definition"] = self.read_file_span(data["FilePath"], data["ByteSpan"])
            data["layout_status"] = "indexed_properties_only"
            data["note"] = "Compiler sizeof/alignment/layout is unavailable because no build record is indexed."
            return json.dumps(data, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"Error executing tool: {e}"})

    def get_related_taint_paths(self, func_name: str, max_hops: int = 8) -> str:
        """Return verified UDS-to-function graph paths."""
        try:
            paths = self.graph_resolver.get_verified_taint_paths(func_name, max_hops)
            return json.dumps(paths, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"Error executing tool: {e}"})
