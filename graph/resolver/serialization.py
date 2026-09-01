import json
import logging
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)


class SerializationMixin:
    """Serializes a function's graph neighborhood into the structured JSON payload
    consumed by the triage/deep-scan LLM agents."""

    def serialize_function_neighborhood(
        self,
        func_name: str,
        verbosity: str = "medium",
        retrieval_pointer: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Query a function neighborhood from Neo4j and serialize it as structured graph JSON."""

        # --- FIXED FOR NEO4J 5 GQL COMPLIANCE AND EDGE PROPERTIES ---
        query = """
        MATCH (f:Function {name: $func_name})
        WHERE NOT f.storage_uri ENDS WITH '.h'  // <--- Force it to grab the .c implementation!

        // 1. Gather Concurrency Context
        OPTIONAL MATCH (f)-[:IMPLEMENTS_TASK]->(task:OsTask)
        WITH f, task
        OPTIONAL MATCH (f)-[lock_edge:OS_LOCK_ACTION]->(lock:OsResource)
        WITH f, task, collect(DISTINCT {name: lock.name, action: lock_edge.action}) AS locks_held

        // 2. Gather Dependencies
        // NOTE: DEPENDS_ON_TYPE is retired (99.99% of its edges were unresolved
        // stubs, invisible to this query anyway since it's scoped to :TypeDefinition
        // -- pure ingestion cost with no observed consumer). `types` stays in the
        // output shape as an always-empty list for downstream schema stability.
        WITH f, task, locks_held, [] AS types
        OPTIONAL MATCH (f)-[:USES_MACRO]->(m:MacroDefinition)
        WITH f, task, locks_held, types, collect(DISTINCT m.name) AS macros

        // 3. Gather Upstream Context
        OPTIONAL MATCH (caller:Function)-[:CALLS]->(f)
        WITH f, task, locks_held, types, macros, collect(DISTINCT {id: elementId(caller), type: labels(caller)[0], name: caller.name}) AS callers
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        WITH f, task, locks_held, types, macros, callers, collect(DISTINCT {id: elementId(uds), type: labels(uds)[0], name: coalesce(uds.name, 'UDS_' + uds.did), did: uds.did, source: coalesce(uds.source, 'heuristic'), func_class_hex: uds.func_class_hex}) AS uds_triggers
        OPTIONAL MATCH (f)-[:RECEIVES_SIGNAL]->(net:NetworkSignal)
        WITH f, task, locks_held, types, macros, callers, uds_triggers, collect(DISTINCT {id: elementId(net), type: labels(net)[0], name: net.name}) AS network_triggers

        // 4. Gather Downstream Context
        OPTIONAL MATCH (f)-[:CALLS]->(callee:Function)
        WITH f, task, locks_held, types, macros, callers, uds_triggers, network_triggers, collect(DISTINCT {id: elementId(callee), type: labels(callee)[0], called_function: callee.name, is_dangerous_sink: coalesce(callee.is_dangerous_sink, false), is_stub_node: CASE WHEN callee:Stub THEN true ELSE false END}) AS callees

        // 5. Gather Variables & Sanitizers
        OPTIONAL MATCH (f)-[r:READS_VAR|WRITES_VAR]->(v:GlobalVariable)
        WITH f, task, locks_held, types, macros, callers, uds_triggers, network_triggers, callees, collect(DISTINCT {id: elementId(v), type: labels(v)[0], variable_name: v.name, access_type: type(r), resolution: coalesce(r.resolution, 'unknown')}) AS var_access
        OPTIONAL MATCH (san:Function)-[:CALLS]->(f) WHERE san.name =~ '.*(sanitize|validate|check|clean|strip|guard).*'
        WITH f, task, locks_held, types, macros, callers, uds_triggers, network_triggers, callees, var_access, collect(DISTINCT {id: elementId(san), type: labels(san)[0], name: san.name}) AS sanitizers

        // Final Assembly
        RETURN {
            function: {
                id: elementId(f),
                name: f.name,
                file: f.storage_uri,
                tainted_by_uds: coalesce(f.tainted_by_uds, false),
                reachable_dids: coalesce(f.reachable_from_dids, []),
                is_vendor_library: coalesce(f.is_vendor_code, false),
                is_hardware_entry: coalesce(f.is_hardware_entry, false),
                has_data_race_risk: coalesce(f.has_data_race_risk, false),
                is_dead_code: coalesce(f.is_dead_code, false),
                is_stub_node: f:Stub
            },
            concurrency: {
                hosting_task: task.name,
                task_priority: task.priority,
                locks_held: locks_held
            },
            dependencies: {
                types: types,
                macros: macros
            },
            upstream: {
                uds_triggers: uds_triggers,
                network_triggers: network_triggers,
                standard_callers: callers
            },
            downstream: callees,
            variable_access: var_access,
            sanitizers: sanitizers
        } AS payload
        LIMIT 1
        """

        def _node_record(name: str, kind: str, node_id: Any = None, **props) -> Dict[str, Any]:
            record = {"id": node_id, "type": kind, "name": name}
            record.update(props)
            return record

        def _path_excerpt(source_name: str, sink_name: str) -> str:
            if source_name and sink_name:
                return f"{source_name} -> {func_name} -> {sink_name}"
            if source_name:
                return f"{source_name} -> {func_name}"
            if sink_name:
                return f"{func_name} -> {sink_name}"
            return func_name

        try:
            with self.db.driver.session() as session:
                records = session.run(query, func_name=func_name).data()

            if not records:
                payload = {
                    "function": {
                        "id": None,
                        "name": func_name,
                        "file": None,
                        "tainted_by_uds": False,
                        "reachable_dids": [],
                        "is_vendor_library": False,
                        "is_hardware_entry": False,
                        "has_data_race_risk": False,
                        "is_dead_code": False,
                        "is_stub_node": False
                    },
                    "concurrency": {
                        "hosting_task": None,
                        "task_priority": None,
                        "locks_held": []
                    },
                    "dependencies": {
                        "types": [],
                        "macros": []
                    },
                    "upstream": {"uds_triggers": [], "network_triggers": [], "standard_callers": []},
                    "downstream": [],
                    "variable_access": [],
                    "sanitizers": []
                }
            else:
                payload = records[0].get("payload", {})

            if payload.get("function") is None:
                payload["function"] = {
                    "id": None,
                    "name": func_name,
                    "file": None,
                    "tainted_by_uds": False,
                    "reachable_dids": [],
                    "is_vendor_library": False,
                    "is_hardware_entry": False,
                    "has_data_race_risk": False,
                    "is_dead_code": False,
                    "is_stub_node": False
                }

            nodes = []
            edges = []
            target = payload["function"]
            nodes.append(_node_record(
                target.get("name"),
                "Function",
                target.get("id"),
                file=target.get("file"),
                tainted_by_uds=target.get("tainted_by_uds", False),
                reachable_dids=target.get("reachable_dids", []),
                is_vendor_library=target.get("is_vendor_library", False),
                is_hardware_entry=target.get("is_hardware_entry", False),
                has_data_race_risk=target.get("has_data_race_risk", False),
                is_dead_code=target.get("is_dead_code", False)
            ))

            for caller in payload.get("upstream", {}).get("standard_callers", []) or []:
                caller_name = caller.get("name")
                if caller_name:
                    nodes.append(_node_record(caller_name, caller.get("type", "Function"), caller.get("id"), source_kind="caller"))
                    edges.append({
                        "id": f"edge:{caller_name}->{func_name}",
                        "type": "CALLS",
                        "from": caller.get("id"),
                        "to": target.get("id"),
                        "properties": {"direction": "inbound"}
                    })

            for uds in payload.get("upstream", {}).get("uds_triggers", []) or []:
                uds_name = uds.get("name") or f"UDS_{uds.get('did', 'unknown')}"
                nodes.append(_node_record(uds_name, uds.get("type", "UdsService"), uds.get("id"), did=uds.get("did"), source_kind="uds"))
                edges.append({
                    "id": f"edge:{uds_name}->{func_name}",
                    "type": "HANDLES_UDS",
                    "from": uds.get("id"),
                    "to": target.get("id"),
                    "properties": {"did": uds.get("did")}
                })

            for net in payload.get("upstream", {}).get("network_triggers", []) or []:
                net_name = net.get("name")
                if net_name:
                    nodes.append(_node_record(net_name, net.get("type", "NetworkSignal"), net.get("id"), source_kind="signal"))
                    edges.append({
                        "id": f"edge:{net_name}->{func_name}",
                        "type": "RECEIVES_SIGNAL",
                        "from": net.get("id"),
                        "to": target.get("id"),
                        "properties": {"source": "network"}
                    })

            for callee in payload.get("downstream", []) or []:
                callee_name = callee.get("called_function")
                if callee_name:
                    nodes.append(_node_record(
                        callee_name,
                        callee.get("type", "Function"),
                        callee.get("id"),
                        is_dangerous_sink=callee.get("is_dangerous_sink", False),
                        is_stub_node=callee.get("is_stub_node", False)
                    ))
                    edges.append({
                        "id": f"edge:{func_name}->{callee_name}",
                        "type": "CALLS",
                        "from": target.get("id"),
                        "to": callee.get("id"),
                        "properties": {"is_dangerous_sink": callee.get("is_dangerous_sink", False)}
                    })

            for var in payload.get("variable_access", []) or []:
                var_name = var.get("variable_name")
                if var_name:
                    nodes.append(_node_record(
                        var_name,
                        var.get("type", "GlobalVariable"),
                        var.get("id"),
                        access_type=var.get("access_type"),
                        resolution=var.get("resolution", "unknown")
                    ))
                    edges.append({
                        "id": f"edge:{func_name}->{var_name}",
                        "type": var.get("access_type", "READS_VAR"),
                        "from": target.get("id"),
                        "to": var.get("id"),
                        # "resolution" tells the LLM/report whether this edge was matched
                        # exactly (declared in the same file as the accessing function) or
                        # fuzzily (name+label matched elsewhere) -- fuzzy evidence should be
                        # treated with lower confidence than exact evidence.
                        "properties": {"access_type": var.get("access_type"), "resolution": var.get("resolution", "unknown")}
                    })

            for sanitizer in payload.get("sanitizers", []) or []:
                sanitizer_name = sanitizer.get("name")
                if sanitizer_name:
                    nodes.append(_node_record(
                        sanitizer_name,
                        sanitizer.get("type", "Function"),
                        sanitizer.get("id"),
                        sanitizer_kind="sanitizer"
                    ))
                    edges.append({
                        "id": f"edge:{sanitizer_name}->{func_name}",
                        "type": "CALLS",
                        "from": sanitizer.get("id"),
                        "to": target.get("id"),
                        "properties": {"role": "sanitizer"}
                    })

            source_names = [
                item.get("name") or item.get("did")
                for item in (payload.get("upstream", {}).get("uds_triggers", []) or [])
            ] + [
                item.get("name")
                for item in (payload.get("upstream", {}).get("network_triggers", []) or [])
                if item.get("name")
            ] + [
                item.get("name")
                for item in (payload.get("upstream", {}).get("standard_callers", []) or [])
                if item.get("name")
            ]
            uds_dids = [
                item.get("did")
                for item in (payload.get("upstream", {}).get("uds_triggers", []) or [])
                if item.get("did") is not None
            ]
            sink_names = [
                item.get("called_function")
                for item in (payload.get("downstream", []) or [])
                if item.get("is_dangerous_sink")
            ]

            path_candidates = []
            for source_name in source_names[:5]:
                for sink_name in sink_names[:5]:
                    path_candidates.append({
                        "type": "source_to_sink",
                        "path": _path_excerpt(source_name, sink_name),
                        "source": source_name,
                        "sink": sink_name,
                        "confidence": "medium" if source_name and sink_name else "low",
                    })
            if not path_candidates:
                for sink_name in sink_names[:5]:
                    path_candidates.append({
                        "type": "internal_sink",
                        "path": _path_excerpt(None, sink_name),
                        "source": None,
                        "sink": sink_name,
                        "confidence": "low"
                    })

            seen_paths = set()
            top_paths = []
            for item in path_candidates:
                if item["path"] not in seen_paths:
                    seen_paths.add(item["path"])
                    top_paths.append(item)
                if len(top_paths) >= 5:
                    break

            provenance = {
                "retrieval_pointer": retrieval_pointer or f"neo4j:function_neighborhood:{func_name}",
                "query": "MATCH (f:Function {name: $func_name}) ... neighborhood",
                "evidence": {
                    "node_count": len(nodes),
                    "edge_count": len(edges),
                    "source_count": len(source_names),
                    "sink_count": len(sink_names),
                    "sanitizer_count": len(payload.get("sanitizers", []) or [])
                },
                "confidence": "high" if payload.get("function", {}).get("tainted_by_uds") or sink_names else "medium",
            }

            payload = {
                "schema_version": "1.2",
                "verbosity": verbosity,
                "function": target,
                "graph": {
                    "nodes": nodes,
                    "edges": edges,
                    "paths": top_paths,
                },
                "sources": {
                    "uds": [item for item in (payload.get("upstream", {}).get("uds_triggers", []) or [])],
                    "network": [item for item in (payload.get("upstream", {}).get("network_triggers", []) or [])],
                    "callers": [item for item in (payload.get("upstream", {}).get("standard_callers", []) or [])],
                },
                "sinks": [item for item in (payload.get("downstream", []) or []) if item.get("is_dangerous_sink")],
                "sanitizers": payload.get("sanitizers", []) or [],
                "variable_access": payload.get("variable_access", []) or [],
                "concurrency": payload.get("concurrency", {}),
                "dependencies": payload.get("dependencies", {}),
                "provenance": provenance,
                "confidence": provenance["confidence"],
            }

            if verbosity == "full":
                payload["graph"]["all_paths"] = top_paths
                payload["graph"]["node_types"] = sorted({node["type"] for node in nodes})
                payload["graph"]["edge_types"] = sorted({edge["type"] for edge in edges})
            elif verbosity == "compact":
                payload["graph"] = {"nodes": nodes[:10], "edges": edges[:20], "paths": top_paths}

            json_data = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
            summary_lines = [
                f"Function: {func_name}",
                f"- tainted_by_uds: {str(target.get('tainted_by_uds', False)).lower()}",
                f"- reachable_dids: {', '.join(str(did) for did in (target.get('reachable_dids', []) or [])) if target.get('reachable_dids') else 'none'}",
                f"- hosting_task: {payload.get('concurrency', {}).get('hosting_task', 'none')} (priority: {payload.get('concurrency', {}).get('task_priority', 'none')})",
                f"- has_data_race_risk: {str(target.get('has_data_race_risk', False)).lower()}",
                f"- uds_sources: {', '.join(str(did) for did in uds_dids) if uds_dids else 'none'}",
                f"- sources: {', '.join(source_names) if source_names else 'none'}",
                f"- sinks: {', '.join(sink_names) if sink_names else 'none'}",
                f"- sanitizers: {', '.join(item.get('name', '') for item in (payload.get('sanitizers', []) or []) if item.get('name')) or 'none'}",
                f"- dependencies: {', '.join(payload.get('dependencies', {}).get('types', [])) or 'none'}",
                f"- top_paths: {', '.join(item['path'] for item in top_paths) if top_paths else 'none'}",
                f"- confidence: {provenance['confidence']}",
                f"- retrieval_pointer: {provenance['retrieval_pointer']}",
            ]

            return json_data, "\n".join(summary_lines)
        except Exception as e:
            logger.warning(f"Failed to serialize graph neighborhood for {func_name}: {e}")
            fallback = {
                "schema_version": "1.2",
                "verbosity": verbosity,
                "function": {
                    "id": None,
                    "name": func_name,
                    "file": None,
                    "tainted_by_uds": False,
                    "reachable_dids": [],
                    "is_vendor_library": False,
                    "is_hardware_entry": False,
                    "has_data_race_risk": False,
                    "is_dead_code": False,
                    "is_stub_node": False
                },
                "graph": {"nodes": [], "edges": [], "paths": []},
                "sources": {"uds": [], "network": [], "callers": []},
                "sinks": [],
                "sanitizers": [],
                "variable_access": [],
                "concurrency": {},
                "dependencies": {},
                "provenance": {
                    "retrieval_pointer": retrieval_pointer or f"neo4j:function_neighborhood:{func_name}",
                    "query": "MATCH ...",
                    "evidence": {"node_count": 0, "edge_count": 0, "source_count": 0, "sink_count": 0, "sanitizer_count": 0},
                    "confidence": "low"
                },
                "confidence": "low",
            }
            return json.dumps(fallback, separators=(",", ":"), ensure_ascii=False), f"Function {func_name} has no serializable graph neighborhood."
