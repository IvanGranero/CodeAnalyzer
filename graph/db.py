import logging
from typing import List, Dict, Any
from neo4j import GraphDatabase, exceptions

logger = logging.getLogger(__name__)

class GraphDB:
    def __init__(self, uri: str, user: str, password: str, max_pool_size: int = 50):
        """
        Initializes the Neo4j driver with connection pooling.
        """
        # The Neo4j driver inherently manages a connection pool. 
        # Tuning max_connection_pool_size is helpful for highly concurrent ingestion.
        self.driver = GraphDatabase.driver(
            uri, 
            auth=(user, password),
            max_connection_pool_size=max_pool_size
        )

    def close(self):
        """Ensure the driver connection is closed upon exit."""
        if self.driver:
            self.driver.close()

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
        # 1. Unique ID constraint (Guarantees local scoping doesn't merge incorrectly)
        tx.run("CREATE CONSTRAINT graphnode_id IF NOT EXISTS FOR (n:GraphNode) REQUIRE n.id IS UNIQUE")
        
        # 2. Name index (Drastically speeds up Late-Binding edge queries!)
        tx.run("CREATE INDEX graphnode_name IF NOT EXISTS FOR (n:GraphNode) ON (n.name)")
        
    def ingest_batched(self, query: str, records: List[Dict[str, Any]], batch_size: int = 5000):
        total_records = len(records)
        # Downgrade from INFO to DEBUG
        logger.debug(f"Starting batched ingestion of {total_records} records in chunks of {batch_size}.")

        for i in range(0, total_records, batch_size):
            batch = records[i : i + batch_size]
            try:
                with self.driver.session() as session:
                    session.execute_write(self._run_unwind_batch, query, batch)
                # Downgrade from INFO to DEBUG
                logger.debug(f"Successfully ingested batch {i // batch_size + 1}")
            except exceptions.TransientError as e:
                logger.error(f"Transient error on batch {i // batch_size + 1}: {e}")
            except Exception as e:
                logger.error(f"Failed to ingest batch {i // batch_size + 1}: {e}")
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
