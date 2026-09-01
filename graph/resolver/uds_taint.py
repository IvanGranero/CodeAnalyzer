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
        # Two detection tiers:
        #  1. "_DID_"/"_RID_" (underscore-flanked) -- the DID/RID hex code is literally
        #     embedded in the name (e.g. DataServices_DID_F129_..._ReadData). Extract
        #     the real hex code as the UdsService key.
        #  2. Broader: the name contains "DID"/"RID" ANYWHERE and ends with one of the
        #     well-known Dcm/RTE-generated diagnostic-callback suffixes. This catches
        #     the very common convention <SignalName>DID_ReadData /
        #     <SignalName>DID_ConditionCheckRead / RID_..._Start etc., where there is no
        #     underscore before "DID"/"RID" and often no hex code in the name at all
        #     (the DID is symbolic, defined only in ARXML config). Confirmed against a
        #     real ingested codebase: tier 1 alone missed 2,193 real, non-vendor DID
        #     callback functions, which were then incorrectly flagged as dead code and
        #     silently excluded from scanning entirely.
        #  When no hex code is extractable, a synthetic per-signal key (everything
        #  before "DID"/"RID" in the name) is used instead, so ReadData/WriteData/
        #  ConditionCheckRead variants of the SAME signal still merge onto one
        #  UdsService node instead of each getting an unrelated stand-in id.
        map_uds_query = """
        MATCH (f:Function)
        WHERE f.name CONTAINS "_DID_" OR f.name CONTAINS "_RID_"
           OR (
                (f.name CONTAINS "DID" OR f.name CONTAINS "RID")
                AND (
                     f.name ENDS WITH "_ReadData" OR f.name ENDS WITH "_WriteData" OR
                     f.name ENDS WITH "_ReadDataLength" OR f.name ENDS WITH "_ConditionCheckRead" OR
                     f.name ENDS WITH "_ConditionCheckWrite" OR f.name ENDS WITH "_Start" OR
                     f.name ENDS WITH "_Stop" OR f.name ENDS WITH "_RequestResults"
                )
              )
        WITH f,
             CASE
                WHEN f.name CONTAINS "_DID_" THEN substring(split(f.name, "_DID_")[1], 0, 4)
                WHEN f.name CONTAINS "_RID_" THEN substring(split(f.name, "_RID_")[1], 0, 4)
                WHEN f.name CONTAINS "DID" THEN "NAMED_" + split(f.name, "DID")[0]
                ELSE "NAMED_" + split(f.name, "RID")[0]
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
            raise

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
            raise

    def _flag_dead_code(self):
        """Finds isolated functions (no callers, no UDS links, no Network links, no Hardware entries)."""
        logger.info("Flagging Unreachable / Dead Code...")
        # NOTE: this SETs is_dead_code = false for non-isolated functions too, not just
        # true for isolated ones. Previously it only ever set the flag to true and never
        # cleared it, so re-running resolution after improving upstream detection (e.g.
        # UDS entry-point detection in _resolve_uds_taint) would NOT retroactively
        # un-flag functions that are now correctly known to be reachable -- the pass
        # wasn't idempotent.
        query = """
        MATCH (f:Function)
        WITH f, (
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
                result = session.run(query).single()
                count = result["dead_count"] if result else 0
                logger.warning(f"Flagged {count} isolated functions as Dead Code.")
        except Exception as e:
            logger.error(f"Failed to flag Dead Code: {e}")
            raise
