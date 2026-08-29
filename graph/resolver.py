import json
import logging
from typing import Any, Dict, List, Optional, Tuple
from graph.manager import GraphManager

logger = logging.getLogger(__name__)

class GraphResolver:
    """
    Executes Post-Ingestion graph completion passes.
    Bakes semantic meaning (taint, data flow, dead code) directly into Neo4j.
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
        OPTIONAL MATCH (san:Function)-[:CALLS]->(f)
        WHERE san.name =~ '.*(sanitize|validate|check|clean|strip|guard).*'
        RETURN {
            function: {
                id: id(f),
                name: f.name,
                file: f.storage_uri,
                tainted_by_uds: coalesce(f.tainted_by_uds, false),
                reachable_dids: coalesce(f.reachable_from_dids, []),
                is_vendor_library: coalesce(f.is_vendor_code, false)
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
                    "function": {"id": None, "name": func_name, "file": None, "tainted_by_uds": False, "reachable_dids": [], "is_vendor_library": False},
                    "upstream": {"uds_triggers": [], "network_triggers": [], "standard_callers": []},
                    "downstream": [],
                    "variable_access": [],
                    "sanitizers": []
                }
            else:
                payload = records[0].get("payload", {})

            if payload.get("function") is None:
                payload["function"] = {"id": None, "name": func_name, "file": None, "tainted_by_uds": False, "reachable_dids": [], "is_vendor_library": False}

            nodes = []
            edges = []
            target = payload["function"]
            nodes.append(_node_record(target.get("name"), "Function", target.get("id"), file=target.get("file"), tainted_by_uds=target.get("tainted_by_uds", False), reachable_dids=target.get("reachable_dids", []), is_vendor_library=target.get("is_vendor_library", False)))

            for caller in payload.get("upstream", {}).get("standard_callers", []) or []:
                caller_name = caller.get("name")
                if caller_name:
                    nodes.append(_node_record(caller_name, caller.get("type", "Function"), caller.get("id"), source_kind="caller"))
                    edges.append({"id": f"edge:{caller_name}->{func_name}", "type": "CALLS", "from": caller.get("id"), "to": target.get("id"), "properties": {"direction": "inbound"}})

            for uds in payload.get("upstream", {}).get("uds_triggers", []) or []:
                uds_name = uds.get("name") or f"UDS_{uds.get('did', 'unknown')}"
                nodes.append(_node_record(uds_name, uds.get("type", "UdsService"), uds.get("id"), did=uds.get("did"), source_kind="uds"))
                edges.append({"id": f"edge:{uds_name}->{func_name}", "type": "HANDLES_UDS", "from": uds.get("id"), "to": target.get("id"), "properties": {"did": uds.get("did")}})

            for net in payload.get("upstream", {}).get("network_triggers", []) or []:
                net_name = net.get("name")
                if net_name:
                    nodes.append(_node_record(net_name, net.get("type", "NetworkSignal"), net.get("id"), source_kind="signal"))
                    edges.append({"id": f"edge:{net_name}->{func_name}", "type": "RECEIVES_SIGNAL", "from": net.get("id"), "to": target.get("id"), "properties": {"source": "network"}})

            for callee in payload.get("downstream", []) or []:
                callee_name = callee.get("called_function")
                if callee_name:
                    nodes.append(_node_record(callee_name, callee.get("type", "Function"), callee.get("id"), is_dangerous_sink=callee.get("is_dangerous_sink", False), is_stub_node=callee.get("is_stub_node", False)))
                    edges.append({"id": f"edge:{func_name}->{callee_name}", "type": "CALLS", "from": target.get("id"), "to": callee.get("id"), "properties": {"is_dangerous_sink": callee.get("is_dangerous_sink", False)}})

            for var in payload.get("variable_access", []) or []:
                var_name = var.get("variable_name")
                if var_name:
                    nodes.append(_node_record(var_name, var.get("type", "GlobalVariable"), var.get("id"), access_type=var.get("access_type")))
                    edges.append({"id": f"edge:{func_name}->{var_name}", "type": var.get("access_type", "READS_VAR"), "from": target.get("id"), "to": var.get("id"), "properties": {"access_type": var.get("access_type")}})

            for sanitizer in payload.get("sanitizers", []) or []:
                sanitizer_name = sanitizer.get("name")
                if sanitizer_name:
                    nodes.append(_node_record(sanitizer_name, sanitizer.get("type", "Function"), sanitizer.get("id"), sanitizer_kind="sanitizer"))
                    edges.append({"id": f"edge:{sanitizer_name}->{func_name}", "type": "CALLS", "from": sanitizer.get("id"), "to": target.get("id"), "properties": {"role": "sanitizer"}})

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

            # Canonicalized path excerpts for downstream taint/source -> sink investigations.
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
                    path_candidates.append({"type": "internal_sink", "path": _path_excerpt(None, sink_name), "source": None, "sink": sink_name, "confidence": "low"})

            # Deduplicate and keep a compact top-k path list.
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
                "schema_version": "1.1",
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
                f"- uds_sources: {', '.join(str(did) for did in uds_dids) if uds_dids else 'none'}",
                f"- sources: {', '.join(source_names) if source_names else 'none'}",
                f"- sinks: {', '.join(sink_names) if sink_names else 'none'}",
                f"- sanitizers: {', '.join(item.get('name', '') for item in (payload.get('sanitizers', []) or []) if item.get('name')) or 'none'}",
                f"- top_paths: {', '.join(item['path'] for item in top_paths) if top_paths else 'none'}",
                f"- confidence: {provenance['confidence']}",
                f"- retrieval_pointer: {provenance['retrieval_pointer']}",
            ]
            return json_data, "\n".join(summary_lines)
        except Exception as e:
            logger.warning(f"Failed to serialize graph neighborhood for {func_name}: {e}")
            fallback = {
                "schema_version": "1.1",
                "verbosity": verbosity,
                "function": {"id": None, "name": func_name, "file": None, "tainted_by_uds": False, "reachable_dids": [], "is_vendor_library": False},
                "graph": {"nodes": [], "edges": [], "paths": []},
                "sources": {"uds": [], "network": [], "callers": []},
                "sinks": [],
                "sanitizers": [],
                "variable_access": [],
                "provenance": {"retrieval_pointer": retrieval_pointer or f"neo4j:function_neighborhood:{func_name}", "query": "MATCH ...", "evidence": {"node_count": 0, "edge_count": 0, "source_count": 0, "sink_count": 0, "sanitizer_count": 0}, "confidence": "low"},
                "confidence": "low",
            }
            return json.dumps(fallback, separators=(",", ":"), ensure_ascii=False), f"Function {func_name} has no serializable graph neighborhood."

    def get_candidate_metrics(self, domain_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Query the graph for high-risk candidate metrics without any LLM orchestration."""
        cypher_filter = ""
        if domain_filter:
            cypher_filter = f"AND (f.storage_uri CONTAINS '/{domain_filter}/' OR f.storage_uri CONTAINS '\\{domain_filter}\\')"

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
            with self.db.driver.session() as session:
                results = session.run(query).data()
            return [r["Metrics"] for r in results]
        except Exception as e:
            logger.error(f"Failed to extract candidate metrics from Neo4j: {e}")
            return []

    def run_all_passes(self):
        """Executes the full suite of resolution passes."""
        logger.info("=== Starting Graph Resolution & Completion Passes ===")
        self._resolve_uds_taint()
        self._flag_dead_code()
        self._resolve_rte_data_flow()
        self._flag_dangerous_sinks()
        logger.info("=== Graph Resolution Complete ===")

    def _resolve_uds_taint(self):
        """
        Dynamically finds DIDs and RIDs, links them to the UDS Attack Surface, 
        and traces the taint down the call stack.
        """
        logger.info("Resolving UDS Attack Surface Entry Points...")
        
        # Step 1: Find functions with _DID_ or _RID_ in their name and wire them up
        map_uds_query = """
        MATCH (f:Function)
        WHERE f.name CONTAINS "_DID_" OR f.name CONTAINS "_RID_"
        
        // Extract the 4-character Hex code (e.g., F081)
        WITH f, 
             CASE 
                WHEN f.name CONTAINS "_DID_" THEN substring(split(f.name, "_DID_")[1], 0, 4)
                ELSE substring(split(f.name, "_RID_")[1], 0, 4)
             END AS uds_hex
        WHERE uds_hex <> ""
        
        // Create the External UDS Node and link it
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
        
        # Step 2: Propagate the Taint down the newly connected call trees
        taint_query = """
        // Start the path at length 0 so the Entry Point itself gets tagged
        MATCH path = (u:UdsService)<-[:HANDLES_UDS]-(entry:Function)-[:CALLS*0..10]->(downstream:Function)
        WITH DISTINCT downstream, u.did AS source_did
        SET downstream.tainted_by_uds = true
        // Use DISTINCT to prevent massive duplicate arrays if multiple paths exist
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
        """
        Finds isolated functions (no callers, no UDS links, no Network links, no Hardware entries).
        """
        logger.info("Flagging Unreachable / Dead Code...")
        query = """
        // 1. Match all functions
        MATCH (f:Function)
        
        // 2. Ensure NO incoming CALLS, NO UDS links, NO Network links, and NOT an OS/Hardware entry
        WHERE NOT ()-[:CALLS]->(f)
          AND NOT (f)-[:HANDLES_UDS]->()
          AND NOT (f)-[:RECEIVES_SIGNAL]->()
          AND NOT (f)-[:SENDS_SIGNAL]->()
          AND coalesce(f.is_hardware_entry, false) = false
          
        // 3. Mark them!
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
        """
        Connects Runnables via RTE. If Func A writes to 'PortX', and Func B reads from 'PortX',
        this creates a direct semantic data flow edge between them.
        """
        logger.info("Resolving RTE Port Data Flows...")
        query = """
        // Find functions calling Rte_Write and Rte_Read for the same port/element
        MATCH (writer:Function)-[:CALLS]->(w_api:Function)
        WHERE w_api.name STARTS WITH "Rte_Write_"
        
        MATCH (reader:Function)-[:CALLS]->(r_api:Function)
        WHERE r_api.name STARTS WITH "Rte_Read_"
        
        // Extract the Port_Element part of the name (e.g., Rte_Write_BatteryPort_Voltage)
        WITH writer, reader, w_api, r_api,
             substring(w_api.name, 10) AS write_port,
             substring(r_api.name, 9) AS read_port
        WHERE write_port = read_port
        
        // Connect the writer directly to the reader
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
        """Flags functions that are known vulnerability sinks (libc + AutoSAR variants)."""
        logger.info("Flagging Dangerous Memory and NVM Sinks...")
        query = """
        MATCH (f:Function)
        // Catch standard libc AND AutoSAR wrappers like VStdLib_MemCpy, TRNmemcpy, etc.
        WHERE toLower(f.name) CONTAINS 'memcpy'
           OR toLower(f.name) CONTAINS 'memcopy'
           OR toLower(f.name) CONTAINS 'memset'
           OR toLower(f.name) CONTAINS 'memmove'
           OR toLower(f.name) CONTAINS 'strcpy'
           OR toLower(f.name) CONTAINS 'sprintf'
           // Catch AutoSAR NVM / Flash operations
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
