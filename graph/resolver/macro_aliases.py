import logging

logger = logging.getLogger(__name__)


class MacroAliasMixin:
    """Redirects RTE macro-alias CALLS edges onto their real function targets."""

    def _resolve_macro_call_aliases(self):
        """
        Redirects CALLS edges that landed on a macro-alias stub onto the real target
        function, then removes the stub.

        Vector MICROSAR RTE-generated code universally uses
        `#define Rte_IrvRead_SHORT(...) Rte_IrvRead_LONG(...)`-style pass-through
        macros for Rte_Read_/Rte_Write_/Rte_Call_/Rte_IrvRead_/Rte_IrvWrite_ port
        accessors: call sites use the SHORT name, but the actual Function node only
        exists under the LONG name. ingest/parser.py's _process_macro_alias records
        this mapping as an `alias_target` property on the deterministic
        "stub::<short_name>" node (the same id manager.py's fuzzy CALLS resolution
        already falls back to for an unresolved call target), so this works
        regardless of whether the macro's header or the caller's .c file was parsed
        first. Without this, real, frequently-used functions look never-called and get
        incorrectly flagged as dead code by _flag_dead_code.
        """
        logger.info("Resolving RTE macro-alias call targets (Rte_Read_/Rte_IrvRead_/etc.)...")
        query = """
        MATCH (stub:GraphNode)
        WHERE stub.alias_target IS NOT NULL
        CALL (stub) {
            MATCH (real:Function {name: stub.alias_target})
            RETURN real
            ORDER BY real.storage_uri
            LIMIT 1
        }
        MATCH (caller)-[:CALLS]->(stub)
        MERGE (caller)-[:CALLS]->(real)
        WITH DISTINCT stub
        DETACH DELETE stub
        RETURN count(stub) AS aliases_resolved
        """
        try:
            with self.db.driver.session() as session:
                result = session.run(query).single()
                count = result["aliases_resolved"] if result else 0
                logger.info(f"Redirected {count} macro-aliased call targets to their real functions.")
        except Exception as e:
            logger.error(f"Failed to resolve macro-alias call targets: {e}")
            raise
