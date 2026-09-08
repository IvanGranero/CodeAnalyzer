import logging

logger = logging.getLogger(__name__)


class RteDataFlowMixin:
    """Connects RTE Runnables via Rte_Write_/Rte_Read_ port data flow."""

    def _resolve_rte_data_flow(self):
        """Connects Runnables via RTE port data flow."""
        logger.info("Resolving RTE Port Data Flows...")
        query = """
        MATCH (writer:Function)-[:CALLS]->(w_api:Function)
        WHERE w_api.name STARTS WITH "Rte_Write_"
        MATCH (reader:Function)-[:CALLS]->(r_api:Function)
        WHERE r_api.name STARTS WITH "Rte_Read_"
        WITH writer, reader, w_api, r_api,
             substring(w_api.name, 10) AS write_port,
             substring(r_api.name, 9) AS read_port
        WHERE write_port = read_port
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
            raise
