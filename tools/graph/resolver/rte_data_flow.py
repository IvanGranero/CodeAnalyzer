import logging

logger = logging.getLogger(__name__)


class RteDataFlowMixin:
    """Connects RTE Runnables via Rte_Write_/Rte_Read_ port data flow."""

    def _resolve_rte_data_flow(self):
        """Connects Runnables via RTE port data flow."""
        logger.info("Resolving RTE Port Data Flows...")
        config_query = """
        MATCH (writer_stub:GraphNode)-[e:DEPENDS_ON_TYPE]->(reader_stub:GraphNode)
        WHERE e.context = "RTE_DATA_FLOW"
        MATCH (writer:Function {name: writer_stub.name})
        MATCH (reader:Function {name: reader_stub.name})
        MERGE (writer)-[r:RTE_DATA_FLOW {port: e.port}]->(reader)
        SET r.data_type = e.data_type,
            r.source = "rte_configuration",
            r.resolution = "exact"
        RETURN count(r) AS rte_flows
        """
        heuristic_query = """
        MATCH (writer:Function)-[:CALLS]->(w_api:GraphNode)
        WHERE w_api.name STARTS WITH "Rte_Write_"
        MATCH (reader:Function)-[:CALLS]->(r_api:GraphNode)
        WHERE r_api.name STARTS WITH "Rte_Read_"
        WITH writer, reader, w_api, r_api,
             substring(w_api.name, 10) AS write_port,
             substring(r_api.name, 9) AS read_port
        WHERE write_port = read_port
        MERGE (writer)-[r:RTE_DATA_FLOW {port: write_port}]->(reader)
        SET r.source = coalesce(r.source, "rte_heuristic"),
            r.resolution = coalesce(r.resolution, "fuzzy"),
            r.data_type = coalesce(r.data_type, "unknown")
        RETURN count(r) AS rte_flows
        """
        try:
            with self.db.driver.session() as session:
                config_result = session.run(config_query).single()
                config_count = config_result["rte_flows"] if config_result else 0
                heuristic_result = session.run(heuristic_query).single()
                heuristic_count = heuristic_result["rte_flows"] if heuristic_result else 0
                count = config_count + heuristic_count
                logger.info(
                    "Resolved %s RTE data flow connections (%s authoritative, %s source-level exact accessor matches).",
                    count,
                    config_count,
                    heuristic_count,
                )
                if count == 0:
                    evidence = session.run(
                        """
                        MATCH (f:Function)-[:CALLS]->(api:GraphNode)
                        WHERE api.name STARTS WITH 'Rte_Read_' OR api.name STARTS WITH 'Rte_Write_'
                        RETURN count(DISTINCT f) AS callers, count(DISTINCT api) AS accessors
                        """
                    ).single()
                    logger.warning(
                        "No RTE data flows resolved. Accessor evidence present: %s callers across %s APIs; "
                        "authoritative sender/receiver configuration is required to establish cross-runnable edges.",
                        evidence.get("callers", 0) if evidence else 0,
                        evidence.get("accessors", 0) if evidence else 0,
                    )
        except Exception as e:
            logger.error(f"Failed to resolve RTE data flow: {e}")
            raise
