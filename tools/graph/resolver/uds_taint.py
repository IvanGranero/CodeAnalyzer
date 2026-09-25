import logging

logger = logging.getLogger(__name__)


class UdsTaintMixin:
    """Detects UDS DID/RID entry points, propagates taint, and flags dead code."""

    def _resolve_uds_taint(self):
        """
        Dynamically finds DIDs and RIDs, links them to the UDS Attack Surface,
        and traces the taint down the call stack.
        """
        logger.info("Resolving UDS Attack Surface Entry Points...")
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        
        map_uds_query = """
        MATCH (f:Function)
                WHERE NOT (f)-[:HANDLES_UDS {source: "dispatch_table"}]->()
                    AND (f.name CONTAINS "_DID_" OR f.name CONTAINS "_RID_"
           OR (
                (f.name CONTAINS "DID" OR f.name CONTAINS "RID")
                AND (
                     f.name ENDS WITH "_ReadData" OR f.name ENDS WITH "_WriteData" OR
                     f.name ENDS WITH "_ReadDataLength" OR f.name ENDS WITH "_ConditionCheckRead" OR
                     f.name ENDS WITH "_ConditionCheckWrite" OR f.name ENDS WITH "_Start" OR
                     f.name ENDS WITH "_Stop" OR f.name ENDS WITH "_RequestResults"
                )
              ))
          WITH f,
                 CASE
                WHEN f.name CONTAINS "_DID_" THEN substring(split(f.name, "_DID_")[1], 0, 4)
                WHEN f.name CONTAINS "_RID_" THEN substring(split(f.name, "_RID_")[1], 0, 4)
                WHEN f.name CONTAINS "DID" THEN "NAMED_" + split(f.name, "DID")[0]
                ELSE "NAMED_" + split(f.name, "RID")[0]
                 END AS uds_hex,
                 CASE WHEN f.name CONTAINS "RID" THEN "rid" ELSE "did" END AS protocol_kind,
                 CASE
                     WHEN f.name ENDS WITH "_ReadData" OR f.name ENDS WITH "_ReadDataLength" OR f.name ENDS WITH "_ConditionCheckRead" THEN "Read"
                     WHEN f.name ENDS WITH "_WriteData" OR f.name ENDS WITH "_ConditionCheckWrite" THEN "Write"
                     ELSE NULL
                 END AS protocol_operation
        WHERE uds_hex <> ""
        MERGE (u:UdsService {did: uds_hex})
        ON CREATE SET u:GraphNode, u.name = "UDS_" + uds_hex
        SET u.protocol_kind = coalesce(u.protocol_kind, protocol_kind),
            u.protocol_identifier = coalesce(u.protocol_identifier, "0x" + uds_hex),
            u.operation = coalesce(u.operation, protocol_operation),
            u.protocol_source = coalesce(u.protocol_source, "name_heuristic"),
            u.protocol_confidence = coalesce(u.protocol_confidence, "partial"),
            u.protocol_missing_facts = coalesce(
                u.protocol_missing_facts,
                CASE
                    WHEN protocol_kind = "rid" THEN ["routine subfunction", "request layout", "request length"]
                    WHEN protocol_operation = "Read" THEN ["response data length"]
                    ELSE ["service direction", "request layout", "request length"]
                END
            )
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
            raise

        logger.info("Propagating Taint Downstream...")
        taint_query = """
        MATCH path = (u:UdsService)<-[:HANDLES_UDS]-(entry:Function)-[:CALLS*0..10]->(downstream:Function)
        WITH downstream, u.did AS source_did, min(length(path)) AS taint_depth
        SET downstream.tainted_by_uds = true
        SET downstream.reachable_from_dids = coalesce(downstream.reachable_from_dids, []) + source_did,
            downstream.uds_taint_depth = coalesce(downstream.uds_taint_depth, taint_depth),
            downstream.uds_taint_source = CASE WHEN taint_depth = 0 THEN 'direct_entry' ELSE 'call_graph' END
        RETURN count(DISTINCT downstream) AS tainted_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(taint_query).single()
                count = result["tainted_count"] if result else 0
                logger.info(f"Successfully traced UDS taint to {count} downstream functions.")
        except Exception as e:
            logger.error(f"Failed to propagate UDS Taint: {e}")
            raise

    def _flag_dead_code(self):
        """Finds isolated functions (no callers, no UDS links, no Network links, no Hardware entries)."""
        logger.info("Flagging Unreachable / Dead Code...")
        
        
        
        
        
        
        vendor_folders = [str(folder).strip().strip('/\\').lower() for folder in self.discovery_context.get("vendor_folders", [])]
        application_roots = [str(folder).strip().strip('/\\').lower() for folder in self.discovery_context.get("application_roots", [])]
        scope_predicate = "true"
        if vendor_folders:
            scope_predicate += " AND NOT any(folder IN $vendor_folders WHERE toLower(f.storage_uri) CONTAINS '/' + folder + '/')"
        if application_roots:
            scope_predicate += " AND any(folder IN $application_roots WHERE toLower(f.storage_uri) CONTAINS '/' + folder + '/')"
        query = f"""
        MATCH (f:Function)
        WITH f, (
            {scope_predicate} AND
            NOT ()-[:CALLS]->(f)
            AND NOT (f)-[:HANDLES_UDS]->()
            AND NOT (f)-[:RECEIVES_SIGNAL]->()
            AND NOT (f)-[:SENDS_SIGNAL]->()
            AND coalesce(f.is_hardware_entry, false) = false
        ) AS is_isolated
        SET f.is_dead_code = is_isolated
        RETURN count(CASE WHEN is_isolated THEN 1 END) AS dead_count
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(
                    query,
                    vendor_folders=vendor_folders,
                    application_roots=application_roots,
                ).single()
                count = result["dead_count"] if result else 0
                logger.warning(f"Flagged {count} isolated functions as Dead Code.")
        except Exception as e:
            logger.error(f"Failed to flag Dead Code: {e}")
            raise
