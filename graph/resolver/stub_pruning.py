import logging

logger = logging.getLogger(__name__)


class StubPruningMixin:
    """Removes local-variable stubs that never carry any real evidence."""

    def _prune_local_variable_stubs(self):
        """
        Runs after ingestion. Any 'Stub' node that only has READS/WRITES edges
        and never got upgraded to a GlobalVariable is a local variable.
        We delete them to keep the graph lean.
        """
        logger.info("Pruning local variable stubs to optimize graph size...")
        # NOTE: stubs with an incoming READS_VAR/WRITES_VAR edge are NOT pruned here.
        # Those edges are exactly the evidence a vulnerability finding relies on ("this
        # function writes to X") -- deleting the stub silently destroys that evidence.
        # Only truly orphaned stubs (created but never actually referenced) are cleaned up.
        query = """
        MATCH (n:Stub)
        WHERE NOT ()-[:CALLS]->(n)
          AND NOT ()-[:READS_VAR]->(n)
          AND NOT ()-[:WRITES_VAR]->(n)
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
            raise
