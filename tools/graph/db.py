import logging
import time
from typing import List, Dict, Any
from neo4j import GraphDatabase, exceptions

logger = logging.getLogger(__name__)

class GraphDB:
    def __init__(self, uri: str, user: str, password: str, max_pool_size: int = 50):
        """
        Initializes the Neo4j driver with connection pooling.
        """
        
        
        self.driver = GraphDatabase.driver(
            uri, 
            auth=(user, password),
            max_connection_pool_size=max_pool_size
        )
        self._closed = False

    def close(self):
        """Ensure the driver connection is closed upon exit."""
        if self.driver is None or self._closed:
            return
        self._closed = True
        try:
            self.driver.close()
        except BufferError as exc:
            logger.warning("Neo4j driver closed with an active buffer: %s", exc)

    def initialize_schema(self):
        """
        Sets up necessary constraints and native vector indexes. 
        Run this once upon database initialization.
        """
        logger.info("Initializing GraphDB schema and indexes...")
        with self.driver.session() as session:
            session.execute_write(self._create_constraints_and_indexes)

    @staticmethod
    def _create_constraints_and_indexes(tx):
        
        tx.run("CREATE CONSTRAINT graphnode_id IF NOT EXISTS FOR (n:GraphNode) REQUIRE n.id IS UNIQUE")
        
        
        tx.run("CREATE INDEX graphnode_name IF NOT EXISTS FOR (n:GraphNode) ON (n.name)")

        
        
        
        
        
        tx.run("CREATE INDEX function_name IF NOT EXISTS FOR (n:Function) ON (n.name)")
        tx.run("CREATE INDEX globalvariable_name IF NOT EXISTS FOR (n:GlobalVariable) ON (n.name)")
        tx.run("CREATE INDEX udsservice_did IF NOT EXISTS FOR (n:UdsService) ON (n.did)")
        tx.run("CREATE INDEX typedefinition_name IF NOT EXISTS FOR (n:TypeDefinition) ON (n.name)")
        tx.run("CREATE INDEX macrodefinition_name IF NOT EXISTS FOR (n:MacroDefinition) ON (n.name)")
        tx.run("CREATE INDEX osresource_name IF NOT EXISTS FOR (n:OsResource) ON (n.name)")

    def ingest_batched(self, query: str, records: List[Dict[str, Any]], batch_size: int = 5000, max_retries: int = 5, base_delay: float = 2.0):
        total_records = len(records)
        
        logger.debug(f"Starting batched ingestion of {total_records} records in chunks of {batch_size}.")

        
        
        with self.driver.session() as session:
            for i in range(0, total_records, batch_size):
                batch = records[i : i + batch_size]
                batch_num = i // batch_size + 1

                for attempt in range(1, max_retries + 1):
                    try:
                        session.execute_write(self._run_unwind_batch, query, batch)
                        logger.debug(f"Successfully ingested batch {batch_num}")
                        break
                    except exceptions.TransientError as e:
                        
                        if attempt == max_retries:
                            logger.error(f"Transient error on batch {batch_num} after {max_retries} attempts, giving up on this batch: {e}")
                            raise
                        delay = base_delay * (2 ** (attempt - 1))
                        logger.warning(f"Transient error on batch {batch_num} (attempt {attempt}/{max_retries}): {e}. Retrying in {delay:.1f}s...")
                        time.sleep(delay)
                    except Exception as e:
                        logger.error(f"Failed to ingest batch {batch_num}: {e}")
                        raise

    @staticmethod
    def _run_unwind_batch(tx, query: str, batch: List[Dict[str, Any]]):
        """Helper method executed within the transaction."""
        tx.run(query, batch=batch)

    def retrieve(self, query: str, parameters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Generic read method for retrieving data or context for the LLM.
        """
        if parameters is None:
            parameters = {}
        with self.driver.session() as session:
            result = session.run(query, parameters)
            return [record.data() for record in result]
