import os
import json
import logging
from collections import OrderedDict
from typing import Any
from tools.graph.manager import GraphManager

logger = logging.getLogger(__name__)

class AnalyzerTools:
    """Deterministic tools exposed to the AnalyzerAgent for exploring the codebase."""

    def __init__(self, graph_manager: GraphManager):
        self.db = graph_manager.db
        self.graph_resolver = graph_manager.resolver
        self._cache = set()
        self._file_cache: OrderedDict[tuple[str, str], str] = OrderedDict()
        self._location_cache: OrderedDict[tuple[str | None, str | None], dict] = OrderedDict()
        self._cache_limit = 256

    def _remember(self, cache: OrderedDict, key, value):
        cache[key] = value
        cache.move_to_end(key)
        while len(cache) > self._cache_limit:
            cache.popitem(last=False)
        return value

    def _check_cache(self, tool_name: str, cache_key: str) -> bool:
        """Checks if the agent already ran this exact tool with these exact arguments."""
        full_key = f"{tool_name}::{cache_key}"
        if full_key in self._cache:
            return True
        self._cache.add(full_key)
        return False

    def _query_data(self, query: str, **parameters: Any) -> list[dict[str, Any]]:
        with self.db.driver.session() as session:
            return session.run(query, **parameters).data()

    def _query_single(self, query: str, **parameters: Any) -> Any:
        with self.db.driver.session() as session:
            return session.run(query, **parameters).single()

    @staticmethod
    def _json(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def _error(exc: Exception) -> str:
        return json.dumps({"error": f"Error executing tool: {exc}"}, ensure_ascii=False)

    def _location(self, storage_uri: str | None, byte_span: str | None) -> dict:
        """Add line coordinates to graph byte spans when the source is available."""
        cache_key = (storage_uri, byte_span)
        cached = self._location_cache.get(cache_key)
        if cached is not None:
            return dict(cached)
        location = {"file": storage_uri, "byte_span": byte_span}
        if not storage_uri or not byte_span:
            return location
        path = storage_uri[7:] if storage_uri.startswith("file://") else storage_uri
        try:
            start, end = (int(value) for value in byte_span.split("-", 1))
            with open(path, "rb") as source:
                prefix = source.read(start)
                source.seek(start)
                snippet = source.read(max(0, end - start)).decode("utf-8", errors="replace")
            location.update({
                "line_start": prefix.count(b"\n") + 1,
                "line_end": prefix.count(b"\n") + snippet.count("\n") + 1,
                "snippet": snippet,
            })
        except (OSError, ValueError):
            pass
        return self._remember(self._location_cache, cache_key, location.copy())

    def get_function_metadata(self, func_name: str) -> str:
        
        
        
        
        
        
        
        
        
        
        
        query = """
        MATCH (f:Function {name: $func_name})
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        WITH f, collect(DISTINCT {
            did: uds.did,
            func_class_hex: uds.func_class_hex,
            source: coalesce(uds.source, 'heuristic'),
            required_seed_subfunctions: uds.required_seed_subfunctions,
            required_key_subfunctions: uds.required_key_subfunctions,
            required_session_subfunctions: uds.required_session_subfunctions,
            dcm_security_bitmask: uds.dcm_security_bitmask,
            dcm_requirements_source: uds.dcm_requirements_source
        }) AS did_details
        RETURN f.storage_uri AS FilePath,
               f.byte_span AS ByteSpan,
               coalesce(f.tainted_by_uds, false) AS TaintedByUDS,
             coalesce(f.taint_depth, f.taint_hops, null) AS TaintDepth,
             coalesce(f.memory_region, f.memory_class, null) AS MemoryRegion,
               coalesce(f.reachable_from_dids, []) AS DIDs,
               did_details AS DidDetails,
               coalesce(f.is_vendor_code, false) AS IsVendorLibrary,
               f:Stub AS IsStubNode
        ORDER BY coalesce(f.is_vendor_code, false),
             CASE WHEN f.storage_uri ENDS WITH '.c' OR f.storage_uri ENDS WITH '.cpp' THEN 0 ELSE 1 END,
             f.storage_uri
        LIMIT 1
        """
        try:
            result = self._query_data(query, func_name=func_name)
            if not result:
                return self._json({"status": "not_found", "function": func_name})
            for row in result:
                dids = row.get("DIDs")
                if dids and len(dids) > 10: row["DIDs"] = dids[:10] + [f"... and {len(dids) - 10} more"]
                if row.get("IsStubNode"): row["WARNING"] = "This is a Stub node. It has no source code available."
                row["Location"] = self._location(row.get("FilePath"), row.get("ByteSpan"))
            return self._json({"status": "found", "function": func_name, "metadata": result[0]})
        except Exception as e:
            return self._error(e)

    def get_uds_contract(self, func_name: str) -> str:
        """Return one deterministic protocol handoff for an analyzed function."""
        try:
            graph_json, _ = self.graph_resolver.serialize_function_neighborhood(
                func_name, verbosity="compact"
            )
            payload = json.loads(graph_json)
            return json.dumps({
                "function": func_name,
                "protocol_contract": payload.get("protocol_contract", {}),
                "entry_points": payload.get("sources", {}).get("uds", []),
                "source": payload.get("function", {}).get("file"),
            })
        except Exception as exc:
            return json.dumps({"function": func_name, "error": str(exc)})

    def get_type_definition(self, type_name: str) -> str:
        """Returns the source code snippet for a struct, enum, or typedef definition."""
        if self._check_cache("get_type_definition", type_name):
            return f"System Note: You have already requested the definition for type '{type_name}'."

        query = "MATCH (t:TypeDefinition {name: $type_name}) RETURN t.storage_uri AS uri, t.byte_span AS span LIMIT 1"
        try:
            result = self._query_single(query, type_name=type_name)
            if not result:
                return f"Type '{type_name}' not found in the graph."
            return self.read_file_span(result["uri"], result["span"])
        except Exception as e:
            return f"Error executing tool: {e}"

    
    def get_macro_definition(self, macro_name: str) -> str:
        """Returns the '#define' value of a macro."""
        if self._check_cache("get_macro_definition", macro_name):
            return f"System Note: You have already requested the definition for macro '{macro_name}'."

        query = "MATCH (m:MacroDefinition {name: $macro_name}) RETURN m.value AS value LIMIT 1"
        try:
            result = self._query_single(query, macro_name=macro_name)
            if not result:
                return f"Macro '{macro_name}' not found in the graph."
            return f"#define {macro_name} {result['value']}"
        except Exception as e:
            return f"Error executing tool: {e}"

    def get_callees(self, func_name: str) -> str:
        
        if self._check_cache("get_callees", func_name):
            return f"System Note: Callees for '{func_name}' are already in your conversation history."
        query = """
         MATCH (f:Function {name: $func_name})-[call:CALLS]->(callee:Function)
         RETURN callee.name AS CalledFunction, callee.storage_uri AS FilePath,
             callee.byte_span AS ByteSpan, callee.is_vendor_code AS IsVendorLibrary,
             callee.is_dangerous_sink AS IsDangerousSink, callee:Stub AS IsStubNode,
             coalesce(call.resolution, 'unknown') AS Resolution
        """
        try:
            result = self._query_data(query, func_name=func_name)
            if not result:
                return self._json({"status": "not_found", "function": func_name, "callees": []})
            for row in result:
                if row.get("IsStubNode"): row["WARNING"] = "Stub node. No source code available."
                row["Location"] = self._location(row.pop("FilePath", None), row.pop("ByteSpan", None))
            return self._json({"status": "found", "function": func_name, "callees": result})
        except Exception as e:
            return self._error(e)

    def get_graph_evidence(self, func_name: str, verbosity: str = "medium") -> str:
        """Return the canonical structured graph payload used by scan agents."""
        if verbosity not in {"compact", "medium", "full"}:
            return self._json({
                "status": "error",
                "function": func_name,
                "error": "verbosity must be compact, medium, or full",
            })
        try:
            graph_json, graph_summary = self.graph_resolver.serialize_function_neighborhood(
                func_name,
                verbosity=verbosity,
            )
            payload = json.loads(graph_json)
            return self._json({
                "status": "found" if payload.get("function", {}).get("file") else "not_found",
                "function": func_name,
                "payload": payload,
                "summary": graph_summary,
                "provenance": payload.get("provenance", {}),
            })
        except Exception as exc:
            return self._error(exc)

    def read_file_span(self, storage_uri: str, byte_span: str) -> str:
        
        if not storage_uri or not byte_span:
            return "Error: Must provide both storage_uri and byte_span."
        cache_key = (storage_uri, byte_span)
        cached = self._file_cache.get(cache_key)
        if cached is not None:
            self._file_cache.move_to_end(cache_key)
            return cached
        file_path = storage_uri
        if file_path.startswith("file://"): file_path = file_path[7:]
        if os.name == 'nt' and file_path.startswith('/') and ':' in file_path: file_path = file_path[1:]
        try:
            start_byte, end_byte = map(int, byte_span.split('-'))
            with open(file_path, 'rb') as f:
                f.seek(start_byte)
                snippet = f.read(end_byte - start_byte)
                return self._remember(
                    self._file_cache,
                    cache_key,
                    snippet.decode('utf-8', errors='ignore'),
                )
        except FileNotFoundError:
            return f"Error: The file {file_path} was not found on disk."
        except Exception as e:
            return f"Error reading file from disk: {e}"

    def get_callers_and_entry_points(self, func_name: str) -> str:
        if self._check_cache("get_callers", func_name):
            return f"System Note: Callers for '{func_name}' are already in your conversation history."
        query = """
        MATCH (f:Function {name: $func_name})
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        OPTIONAL MATCH (f)-[:RECEIVES_SIGNAL]->(net:NetworkSignal)
        OPTIONAL MATCH (caller:Function)-[:CALLS]->(f)
        RETURN collect(DISTINCT uds.did) AS UdsTriggers,
               collect(DISTINCT net.name) AS NetworkTriggers,
               collect(DISTINCT {
                   name: caller.name,
                   file: caller.storage_uri,
                   byte_span: caller.byte_span
               }) AS StandardCallers,
               coalesce(f.is_hardware_entry, false) AS IsHardwareTask
        """
        try:
            result = self._query_single(query, func_name=func_name)
            if not result:
                return self._json({"status": "not_found", "function": func_name})
            data = result.data()
            for caller in data.get("StandardCallers", []):
                if caller.get("name"):
                    caller["location"] = self._location(caller.pop("file", None), caller.pop("byte_span", None))
            return self._json({"status": "found", "function": func_name, **data})
        except Exception as e:
            return self._error(e)

    def get_variable_access(self, func_name: str) -> str:
        if self._check_cache("get_vars", func_name):
            return f"System Note: Variable access for '{func_name}' is already in your conversation history."
        query = """
        MATCH (f:Function {name: $func_name})-[r:READS_VAR|WRITES_VAR]->(v:GlobalVariable)
        RETURN v.name AS VariableName, v.storage_uri AS FilePath, v.byte_span AS ByteSpan,
               type(r) AS AccessType, coalesce(r.resolution, 'unknown') AS Resolution
        """
        try:
            result = self._query_data(query, func_name=func_name)
            for row in result:
                row["Location"] = self._location(row.pop("FilePath", None), row.pop("ByteSpan", None))
            return self._json({
                "status": "found" if result else "not_found",
                "function": func_name,
                "accesses": result,
            })
        except Exception as e:
            return self._error(e)

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
            result = self._query_data(query, func_name=func_name, symbol=symbol)
            for row in result:
                row["Location"] = self._location(row.pop("FilePath", None), row.pop("ByteSpan", None))
            return self._json(result)
        except Exception as e:
            return self._error(e)

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
            result = self._query_single(query, func_name=func_name)
            return self._json(result.data() if result else {})
        except Exception as e:
            return self._error(e)

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
            result = self._query_single(query, func_name=func_name)
            if not result:
                return self._json({"status": "not_found", "function": func_name})
            source = self.read_file_span(result["FilePath"], result["ByteSpan"])
            return self._json({
                "status": "source_only",
                "requested_variant": build_variant,
                "indexed_variant": result["IndexedVariant"],
                "file": result["FilePath"],
                "span": result["ByteSpan"],
                "content": source,
                "note": "No compiler-preprocessed build variant is indexed; this is the parsed source span.",
            })
        except Exception as e:
            return self._error(e)

    def get_type_layout(self, type_name: str) -> str:
        """Return indexed type properties and its bounded definition when available."""
        query = """
        MATCH (t:TypeDefinition {name: $type_name})
        RETURN t.name AS TypeName, t.storage_uri AS FilePath, t.byte_span AS ByteSpan,
               properties(t) AS Properties
        LIMIT 1
        """
        try:
            result = self._query_single(query, type_name=type_name)
            if not result:
                return self._json({"status": "not_found", "type": type_name})
            data = result.data()
            data["definition"] = self.read_file_span(data["FilePath"], data["ByteSpan"])
            data["layout_status"] = "indexed_properties_only"
            data["note"] = "Compiler sizeof/alignment/layout is unavailable because no build record is indexed."
            return self._json(data)
        except Exception as e:
            return self._error(e)

    def get_related_taint_paths(self, func_name: str, max_hops: int = 8) -> str:
        """Return verified UDS-to-function graph paths."""
        try:
            paths = self.graph_resolver.get_verified_taint_paths(func_name, max_hops)
            return json.dumps(paths, ensure_ascii=False)
        except Exception as e:
            return json.dumps({"error": f"Error executing tool: {e}"})

    def get_resolution_metadata(self, func_name: str) -> str:
        """Return resolver flags and provenance attached to a function neighborhood."""
        query = """
        MATCH (f:Function {name: $func_name})
        OPTIONAL MATCH (f)-[:IMPLEMENTS_TASK]->(task:OsTask)
        OPTIONAL MATCH (f)-[:IMPLEMENTS_TASK]->(isr:OsIsr)
        OPTIONAL MATCH (f)-[:USES_MACRO]->(macro:MacroDefinition)
        OPTIONAL MATCH (f)-[call:CALLS]->(callee:Function)
        RETURN f.name AS function,
               coalesce(f.is_dead_code, false) AS is_dead_code,
               coalesce(f.is_dangerous_sink, false) AS is_dangerous_sink,
               coalesce(f.has_data_race_risk, false) AS has_data_race_risk,
               coalesce(f.tainted_by_uds, false) AS tainted_by_uds,
               coalesce(f.reachable_from_dids, []) AS reachable_from_dids,
               collect(DISTINCT {name: task.name, priority: task.priority}) AS tasks,
               collect(DISTINCT {name: isr.name, category: isr.isr_category}) AS isrs,
               collect(DISTINCT {name: macro.name, value: macro.value,
                                 file: macro.storage_uri, byte_span: macro.byte_span}) AS macros,
               collect(DISTINCT {name: callee.name, resolution: coalesce(call.resolution, 'unknown'),
                                 file: callee.storage_uri, byte_span: callee.byte_span}) AS callees
        LIMIT 1
        """
        try:
            result = self._query_single(query, func_name=func_name)
            if not result:
                return self._json({"status": "not_found", "function": func_name})
            data = result.data()
            for item in data.get("macros", []):
                item["location"] = self._location(item.pop("file", None), item.pop("byte_span", None))
            for item in data.get("callees", []):
                item["location"] = self._location(item.pop("file", None), item.pop("byte_span", None))
            data["status"] = "found"
            data["provenance"] = "neo4j:resolver_annotations"
            return self._json(data)
        except Exception as exc:
            return self._error(exc)

    def get_rte_data_flows(self, func_name: str) -> str:
        """Return authoritative RTE sender/receiver relationships and locations."""
        query = """
        MATCH (f:Function {name: $func_name})-[r]-(peer:Function)
        WHERE type(r) = 'RTE_DATA_FLOW'
        RETURN CASE WHEN startNode(r) = f THEN 'outgoing' ELSE 'incoming' END AS direction,
               peer.name AS peer_function,
               peer.storage_uri AS peer_file,
               peer.byte_span AS peer_byte_span,
               properties(r)['port'] AS port,
               properties(r)['data_type'] AS data_type,
               coalesce(properties(r)['source'], 'unknown') AS source,
               coalesce(properties(r)['resolution'], 'exact') AS resolution
        ORDER BY direction, peer_function, port
        """
        try:
            rows = self._query_data(query, func_name=func_name)
            for row in rows:
                row["location"] = self._location(row.pop("peer_file", None), row.pop("peer_byte_span", None))
            return self._json({
                "status": "found" if rows else "not_found",
                "function": func_name,
                "flows": rows,
                "provenance": "neo4j:RTE_DATA_FLOW",
            })
        except Exception as exc:
            return self._error(exc)

    def get_memory_sinks(self, func_name: str, max_hops: int = 4) -> str:
        """Return resolved dangerous-sink paths with sink source locations."""
        max_hops = max(0, min(max_hops, 8))
        query = f"""
        MATCH path = (f:Function {{name: $func_name}})-[:CALLS*0..{max_hops}]->(sink:Function)
        WHERE coalesce(sink.is_dangerous_sink, false) = true
        RETURN sink.name AS sink_function,
               sink.storage_uri AS sink_file,
               sink.byte_span AS sink_byte_span,
             coalesce(sink.memory_region, sink.memory_class, null) AS memory_region,
               [node IN nodes(path) | node.name] AS path,
               'neo4j:CALLS+is_dangerous_sink' AS provenance
        ORDER BY sink_function
        LIMIT 50
        """
        try:
            rows = self._query_data(query, func_name=func_name)
            for row in rows:
                row["location"] = self._location(row.pop("sink_file", None), row.pop("sink_byte_span", None))
            return self._json({
                "status": "found" if rows else "not_found",
                "function": func_name,
                "paths": rows,
            })
        except Exception as exc:
            return self._error(exc)
