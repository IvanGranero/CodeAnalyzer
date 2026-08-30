import json
import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class GraphResolver:
    """
    Executes Post-Ingestion graph completion passes.
    Bakes semantic meaning (taint, data flow, dead code, concurrency) directly into Neo4j.
    """
    
    def __init__(self, db: Any):
        self.db = db

    def serialize_function_neighborhood(
        self,
        func_name: str,
        verbosity: str = "medium",
        retrieval_pointer: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Query a function neighborhood from Neo4j and serialize it as structured graph JSON."""
        query = """
        MATCH (f:Function {name: $func_name})
        OPTIONAL MATCH (caller:Function)-[:CALLS]->(f)
        OPTIONAL MATCH (f)-[:CALLS]->(callee:Function)
        OPTIONAL MATCH (f)-[r:READS_VAR|WRITES_VAR]->(v:GlobalVariable)
        OPTIONAL MATCH (f)-[:HANDLES_UDS]->(uds:UdsService)
        OPTIONAL MATCH (f)-[:RECEIVES_SIGNAL]->(net:NetworkSignal)
        OPTIONAL MATCH (f)-[:IMPLEMENTS_TASK]->(task:OsTask)
        OPTIONAL MATCH (f)-[:OS_LOCK_ACTION]->(lock:OsResource)
        OPTIONAL MATCH (f)-[:DEPENDS_ON_TYPE]->(t:TypeDefinition)
        OPTIONAL MATCH (f)-[:USES_MACRO]->(m:MacroDefinition)
        OPTIONAL MATCH (san:Function)-[:CALLS]->(f)
        WHERE san.name =~ '.*(sanitize|validate|check|clean|strip|guard).*'
        
        RETURN {
            function: {
                id: id(f),
                name: f.name,
                file: f.storage_uri,
                tainted_by_uds: coalesce(f.tainted_by_uds, false),
                reachable_dids: coalesce(f.reachable_from_dids, []),
                is_vendor_library: coalesce(f.is_vendor_code, false),
                is_hardware_entry: coalesce(f.is_hardware_entry, false),
                has_data_race_risk: coalesce(f.has_data_race_risk, false),
                is_stub_node: f:Stub
            },
            concurrency: {
                hosting_task: task.name,
                task_priority: task.priority,
                locks_held: collect(DISTINCT {name: lock.name, action: lock.action})
            },
            dependencies: {
                types: collect(DISTINCT t.name),
                macros: collect(DISTINCT m.name)
            },
            upstream: {
                uds_triggers: collect(DISTINCT {
                    id: id(uds),
                    type: labels(uds)[0],
                    name: coalesce(uds.name, 'UDS_' + uds.did),
                    did: uds.did
                }),
                network_triggers: collect(DISTINCT {
                    id: id(net),
                    type: labels(net)[0],
                    name: net.name
                }),
                standard_callers: collect(DISTINCT {
                    id: id(caller),
                    type: labels(caller)[0],
                    name: caller.name
                })
            },
            downstream: collect(DISTINCT {
                id: id(callee),
                type: labels(callee)[0],
                called_function: callee.name,
                is_dangerous_sink: coalesce(callee.is_dangerous_sink, false),
                is_stub_node: CASE WHEN callee:Stub THEN true ELSE false END
            }),
            variable_access: collect(DISTINCT {
                id: id(v),
                type: labels(v)[0],
                variable_name: v.name,
                access_type: type(r)
            }),
            sanitizers: collect(DISTINCT {
                id: id(san),
                type: labels(san)[0],
                name: san.name
            })
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
                has_data_race_risk=target.get("has_data_race_risk", False)
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
                        access_type=var.get("access_type")
                    ))
                    edges.append({
                        "id": f"edge:{func_name}->{var_name}",
                        "type": var.get("access_type", "READS_VAR"),
                        "from": target.get("id"),
                        "to": var.get("id"),
                        "properties": {"access_type": var.get("access_type")}
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

    def get_prioritized_targets(self, max_targets: int, domain_filter: Optional[str] = None, file_filter: Optional[str] = None) -> List[str]:
        cypher_filter = ""
        if domain_filter:
            cypher_filter += f" AND (f.storage_uri CONTAINS '/{domain_filter}/' OR f.storage_uri CONTAINS '\\\\{domain_filter}\\\\')"
        if file_filter:
            safe_file = file_filter.replace('\\', '/')
            cypher_filter += f" AND f.storage_uri CONTAINS '{safe_file}'"
            
        query = f"""
        MATCH (f:Function)
        WHERE coalesce(f.is_vendor_code, false) = false 
          AND coalesce(f.is_dead_code, false) = false 
          AND NOT f:Stub
          {cypher_filter}
        OPTIONAL MATCH (f)-[:CALLS*1..3]->(sink:Function {{is_dangerous_sink: true}})
        OPTIONAL MATCH (f)-[:WRITES_VAR]->(w:GlobalVariable)
        WITH f,
             (CASE WHEN coalesce(f.tainted_by_uds, false) THEN 100 ELSE 0 END) +
             (CASE WHEN coalesce(f.is_hardware_entry, false) THEN 80 ELSE 0 END) +
             (CASE WHEN coalesce(f.has_data_race_risk, false) THEN 200 ELSE 0 END) +
             (count(DISTINCT sink) * 50) +
             (count(DISTINCT w) * 10) AS RiskScore
        WHERE RiskScore > 0
        RETURN f.name AS FunctionName, RiskScore
        ORDER BY RiskScore DESC, f.name ASC
        """
        if max_targets > 0:
            query += f"\nLIMIT {max_targets}"
            
        try:
            with self.db.driver.session() as session:
                results = session.run(query).data()
            return [r["FunctionName"] for r in results]
        except Exception as e:
            logger.error(f"Failed to extract prioritized targets from Neo4j: {e}")
            return []

    def run_all_passes(self):
        """Executes the full suite of resolution passes in the correct order."""
        logger.info("=== Starting Graph Resolution & Completion Passes ===")
        self._prune_local_variable_stubs()
        self._bind_runnables_to_tasks()
        self._resolve_os_concurrency()
        self._resolve_uds_taint()
        self._flag_dead_code()
        self._resolve_rte_data_flow()
        self._flag_dangerous_sinks()
        self._resolve_data_races()
        logger.info("=== Graph Resolution Complete ===")

    def _prune_local_variable_stubs(self):
        """
        Runs after ingestion. Any 'Stub' node that only has READS/WRITES edges 
        and never got upgraded to a GlobalVariable is a local variable.
        We delete them to keep the graph lean.
        """
        logger.info("Pruning local variable stubs to optimize graph size...")
        query = """
        MATCH (n:Stub)
        WHERE NOT ()-[:CALLS]->(n) AND NOT ()-[:DEPENDS_ON_TYPE]->(n)
        DETACH DELETE n
        RETURN count(n) as deleted_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["deleted_count"] if result else 0
                logger.info(f"Deleted {count} useless local variable stubs.")
        except Exception as e:
            logger.error(f"Failed to prune local variables: {e}")

    def _bind_runnables_to_tasks(self):
        """Binds RTE runnable placeholder stubs directly to concrete Function nodes."""
        logger.info("Binding RTE Runnables to Functions...")
        query = """
        MATCH (s:Stub)-[r:IMPLEMENTS_TASK]->(t)
        WHERE s.name STARTS WITH 'Rte_' OR s.name STARTS WITH 'Runnable_'
        MATCH (f:Function {name: s.name})
        MERGE (f)-[rel:IMPLEMENTS_TASK]->(t)
        SET rel = properties(r)
        DELETE r, s
        """
        try:
            with self.db.driver.session() as session:
                session.run(query)
        except Exception as e:
            logger.error(f"Failed to bind Runnables to Tasks: {e}")

    def _resolve_os_concurrency(self):
        """
        Converts CALLS to GetResource/ReleaseResource and interrupt locks into explicit
        OS_LOCK_ACTION edges targeting shared OsResource nodes.
        """
        logger.info("Resolving AutoSAR OS Concurrency Primitives...")
        query = """
        MATCH (f:Function)-[c:CALLS]->(api:Function)
        WHERE api.name IN [
            'GetResource', 'SuspendAllInterrupts', 'DisableAllInterrupts',
            'ReleaseResource', 'ResumeAllInterrupts', 'EnableAllInterrupts'
        ]
        WITH f, c, api,
             CASE WHEN size(c.arguments) > 0 THEN c.arguments[0] ELSE 'GLOBAL_INTERRUPT' END AS resource_name,
             CASE WHEN api.name STARTS WITH 'Get' OR api.name STARTS WITH 'Suspend' OR api.name STARTS WITH 'Disable'
                  THEN 'ACQUIRES_LOCK' ELSE 'RELEASES_LOCK' END AS lock_action
        MERGE (res:OsResource {name: resource_name}) ON CREATE SET res:GraphNode
        MERGE (f)-[l:OS_LOCK_ACTION {action: lock_action}]->(res)
        RETURN count(f) AS locks_resolved
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["locks_resolved"] if result else 0
                logger.info(f"Successfully resolved {count} OS locking mechanisms.")
        except Exception as e:
            logger.error(f"Failed to resolve OS concurrency: {e}")

    def _resolve_uds_taint(self):
        """
        Dynamically finds DIDs and RIDs, links them to the UDS Attack Surface, 
        and traces the taint down the call stack.
        """
        logger.info("Resolving UDS Attack Surface Entry Points...")
        map_uds_query = """
        MATCH (f:Function)
        WHERE f.name CONTAINS "_DID_" OR f.name CONTAINS "_RID_"
        WITH f, 
             CASE 
                WHEN f.name CONTAINS "_DID_" THEN substring(split(f.name, "_DID_")[1], 0, 4)
                ELSE substring(split(f.name, "_RID_")[1], 0, 4)
             END AS uds_hex
        WHERE uds_hex <> ""
        MERGE (u:UdsService {did: uds_hex})
        ON CREATE SET u:GraphNode, u.name = "UDS_" + uds_hex
        MERGE (f)-[:HANDLES_UDS]->(u)
        RETURN count(f) AS linked_uds
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(map_uds_query).single()
                count = result["linked_uds"] if result else 0
                logger.info(f"Successfully mapped {count} AutoSAR UDS Entry Points.")
        except Exception as e:
            logger.error(f"Failed to map UDS entry points: {e}")

        logger.info("Propagating Taint Downstream...")
        taint_query = """
        MATCH path = (u:UdsService)<-[:HANDLES_UDS]-(entry:Function)-[:CALLS*0..10]->(downstream:Function)
        WITH DISTINCT downstream, u.did AS source_did
        SET downstream.tainted_by_uds = true
        WITH downstream, collect(DISTINCT source_did) AS uds_sources
        SET downstream.reachable_from_dids = uds_sources
        RETURN count(downstream) AS tainted_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(taint_query).single()
                count = result["tainted_count"] if result else 0
                logger.info(f"Successfully traced UDS taint to {count} downstream functions.")
        except Exception as e:
            logger.error(f"Failed to propagate UDS Taint: {e}")

    def _flag_dead_code(self):
        """Finds isolated functions (no callers, no UDS links, no Network links, no Hardware entries)."""
        logger.info("Flagging Unreachable / Dead Code...")
        query = """
        MATCH (f:Function)
        WHERE NOT ()-[:CALLS]->(f)
          AND NOT (f)-[:HANDLES_UDS]->()
          AND NOT (f)-[:RECEIVES_SIGNAL]->()
          AND NOT (f)-[:SENDS_SIGNAL]->()
          AND coalesce(f.is_hardware_entry, false) = false
        SET f.is_dead_code = true
        RETURN count(f) AS dead_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["dead_count"] if result else 0
                logger.warning(f"Flagged {count} isolated functions as Dead Code.")
        except Exception as e:
            logger.error(f"Failed to flag Dead Code: {e}")

    def _resolve_rte_data_flow(self):
        """Connects Runnables via RTE port data flow."""
        logger.info("Resolving RTE Port Data Flows...")
        query = """
        MATCH (writer:Function)-[:CALLS]->(w_api:Function)
        WHERE w_api.name STARTS WITH "Rte_Write_"
        MATCH (reader:Function)-[:CALLS]->(r_api:Function)
        WHERE r_api.name STARTS WITH "Rte_Read_"
        WITH writer, reader, w_api, r_api,
             substring(w_api.name, 10) AS write_port,
             substring(r_api.name, 9) AS read_port
        WHERE write_port = read_port
        MERGE (writer)-[r:RTE_DATA_FLOW {port: write_port}]->(reader)
        RETURN count(r) AS rte_flows
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["rte_flows"] if result else 0
                logger.info(f"Resolved {count} RTE data flow connections.")
        except Exception as e:
            logger.error(f"Failed to resolve RTE data flow: {e}")

    def _flag_dangerous_sinks(self):
        """Flags functions that are known vulnerability sinks."""
        logger.info("Flagging Dangerous Memory and NVM Sinks...")
        query = """
        MATCH (f:Function)
        WHERE toLower(f.name) CONTAINS 'memcpy'
           OR toLower(f.name) CONTAINS 'memcopy'
           OR toLower(f.name) CONTAINS 'memset'
           OR toLower(f.name) CONTAINS 'memmove'
           OR toLower(f.name) CONTAINS 'strcpy'
           OR toLower(f.name) CONTAINS 'sprintf'
           OR f.name STARTS WITH 'NvM_Write' 
           OR f.name STARTS WITH 'Fls_Write'
        SET f.is_dangerous_sink = true
        RETURN count(f) AS sink_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["sink_count"] if result else 0
                logger.info(f"Flagged {count} functions as dangerous memory sinks.")
        except Exception as e:
            logger.error(f"Failed to flag dangerous sinks: {e}")

    def _resolve_data_races(self):
        """
        Flags functions that write to a global variable concurrently with another
        function across different task/ISR contexts without an exclusive lock.
        Uses COUNT {...} for modern Neo4j GQL compliance and sets a boolean property
        to avoid relationship explosion.
        """
        logger.info("Flagging functions with potential data races...")
        query = """
        MATCH (v:GlobalVariable)
        WHERE COUNT { (v)<-[:WRITES_VAR]-(:Function) } > 1
        MATCH (f:Function)-[:WRITES_VAR]->(v)
        WHERE EXISTS {
            MATCH (other_f:Function)-[:WRITES_VAR]->(v)
            WHERE f <> other_f
            OPTIONAL MATCH (f)-[:IMPLEMENTS_TASK]->(t1:OsTask)
            OPTIONAL MATCH (other_f)-[:IMPLEMENTS_TASK]->(t2:OsTask)
            WHERE (t1 IS NULL OR t2 IS NULL OR t1 <> t2)
              AND NOT EXISTS {
                (f)-[:OS_LOCK_ACTION]->(:OsResource)<-[:OS_LOCK_ACTION]-(other_f)
            }
        }
        SET f.has_data_race_risk = true
        """
        try:
            with self.db.driver.session() as session:
                session.run(query)
                logger.info("Successfully completed linear data-race detection pass.")
        except Exception as e:
            logger.error(f"Failed to detect Data Races: {e}")
