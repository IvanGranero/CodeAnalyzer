import logging

logger = logging.getLogger(__name__)


class RunnableBindingMixin:
    """Binds RTE Runnables/Functions to their hosting OS Tasks."""

    def _bind_runnables_to_tasks(self):
        """
        Binds Functions to their hosting OS Tasks.
        Phase 1: Uses explicit RTE JSON stubs.
        Phase 2: Uses Call Graph propagation as a fallback.
        """
        logger.info("Binding RTE Runnables to Functions...")

        # Phase 1: Merge the explicit JSON Stubs
        json_bind_query = """
        MATCH (s:Stub)-[r:IMPLEMENTS_TASK]->(t)
        WHERE s.name STARTS WITH 'Rte_' OR s.name STARTS WITH 'Runnable_'
        MATCH (f:Function {name: s.name})
        MERGE (f)-[rel:IMPLEMENTS_TASK]->(t)
        SET rel = properties(r)
        DELETE r, s
        RETURN count(rel) AS explicit_bindings
        """

        # Phase 2: Propagate bindings down the call tree (The Fallback)
        propagate_query = """
        MATCH (entry:Function)-[:IMPLEMENTS_TASK]->(t:OsTask)
        MATCH (entry)-[:CALLS*1..5]->(f:Function)
        WHERE coalesce(f.is_vendor_code, false) = false
        MERGE (f)-[:IMPLEMENTS_TASK]->(t)
        RETURN count(DISTINCT f) AS propagated_bindings
        """

        try:
            with self.db.driver.session() as session:
                res1 = session.run(json_bind_query).single()
                explicit = res1["explicit_bindings"] if res1 else 0
                logger.info(f"Bound {explicit} Runnables to Tasks using explicit RTE JSON data.")

                res2 = session.run(propagate_query).single()
                propagated = res2["propagated_bindings"] if res2 else 0
                logger.info(f"Propagated OS Task bindings to {propagated} downstream application functions.")
        except Exception as e:
            logger.error(f"Failed to bind Runnables to Tasks: {e}")
            raise
