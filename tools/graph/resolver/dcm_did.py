import logging

logger = logging.getLogger(__name__)


class DcmDidMixin:
    """Resolves the generated Dcm DID dispatch table into HANDLES_UDS edges."""

    def _resolve_dcm_did_table_entries(self):
        """
        Resolves the (function_name, did_hex) facts scraped from a generated Dcm DID
        dispatch table (ingest/parser.py's _extract_dcm_did_table_entries) into real
        HANDLES_UDS edges.

        This is a name-convention-independent, generator-authoritative alternative to
        _resolve_uds_taint's regex heuristic below: it's the module's own dispatch
        table, so it correctly tags callback functions whose C symbol name has no
        "DID"/"RID" token at all (confirmed against a real codebase: 608 such functions
        were still being false-positive-flagged as dead code after every naming-based
        heuristic improvement). Runs before _resolve_uds_taint so taint propagation
        and dead-code exclusion both see the complete HANDLES_UDS picture.
        """
        logger.info("Resolving Dcm DID dispatch table entries...")
        
        
        
        
        
        
        query = """
        MATCH (entry:DcmDidTableEntry)
        OPTIONAL MATCH (alias_stub:GraphNode {id: "stub::" + entry.function_name})
        WITH entry, coalesce(alias_stub.alias_target, entry.function_name) AS resolved_name
        CALL (resolved_name) {
            MATCH (f:Function {name: resolved_name})
            RETURN f
            ORDER BY f.storage_uri
            LIMIT 1
        }
        MERGE (u:UdsService {did: entry.did_hex})
        ON CREATE SET u:GraphNode, u.name = "DID_" + entry.did_hex
        SET u.protocol_kind = "did",
            u.protocol_identifier = "0x" + entry.did_hex,
            u.protocol_source = "dispatch_table",
            u.protocol_confidence = "exact",
            u.protocol_missing_facts = ["request layout", "request length"],
            u.source = "dispatch_table"
        MERGE (f)-[handles:HANDLES_UDS]->(u)
        SET handles.kind = "did", handles.source = "dispatch_table"
        SET u.source = "dcm_did_table", u.func_class_hex = entry.func_class_hex
        RETURN count(f) AS linked
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["linked"] if result else 0
                logger.info(f"Resolved {count} Dcm DID dispatch table entries to HANDLES_UDS edges.")
        except Exception as e:
            logger.error(f"Failed to resolve Dcm DID dispatch table entries: {e}")
            raise

    def _resolve_dcm_security_requirements(self):
        """Merge decoded Dcm security/session requirements onto UdsService nodes.

        The ingestion parser stores the resolved requirements as :DcmSecurityRequirement
        nodes keyed by (kind, identifier_hex). This pass attaches those facts to the
        matching :UdsService (matched by did/rid) so graph serialization can surface
        concrete session_requirements / security_requirements instead of 'unknown'.
        """
        logger.info("Resolving Dcm security/session requirements...")
        query = """
        MATCH (req:DcmSecurityRequirement)
        OPTIONAL MATCH (u:UdsService)
        WHERE (
            (req.kind = "rid" AND (u.rid = req.identifier_hex OR u.did = req.identifier_hex))
            OR (req.kind = "did" AND u.did = req.identifier_hex)
        )
        WITH req, u
        WHERE u IS NOT NULL
        SET u.required_session_subfunctions = req.required_session_subfunctions,
            u.required_seed_subfunctions = req.required_seed_subfunctions,
            u.required_key_subfunctions = req.required_key_subfunctions,
            u.dcm_session_bitmask = req.session_bitmask,
            u.dcm_security_bitmask = req.security_bitmask,
            u.dcm_requirements_source = "dcm_config_table",
            u.rid = CASE WHEN req.kind = "rid" AND u.rid IS NULL THEN req.identifier_hex ELSE u.rid END
        RETURN count(DISTINCT u) AS linked
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["linked"] if result else 0
                logger.info(
                    f"Attached Dcm security/session requirements to {count} UdsService nodes."
                )
        except Exception as e:
            logger.error(f"Failed to resolve Dcm security requirements: {e}")
            raise
