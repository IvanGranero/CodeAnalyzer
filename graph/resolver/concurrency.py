import logging

logger = logging.getLogger(__name__)


class ConcurrencyMixin:
    """Resolves AUTOSAR OS locking primitives and flags data-race risk."""

    def _resolve_os_concurrency(self):
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
        """
        try:
            with self.db.driver.session() as session:
                session.run(query)
        except Exception as e:
            logger.error(f"Failed to resolve OS concurrency: {e}")
            raise

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
            raise
