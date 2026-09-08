import logging

from tools.graph.manager import GraphManager
from tools.ingestion import IngestionService

logger = logging.getLogger(__name__)


class IngestionPhase:
    """Phase 2: parse the source tree into the graph, then run resolver passes."""

    def run(self, target_directory: str, graph: GraphManager, config_json: dict) -> None:
        logger.info("\n--- PHASE 2: Starting Graph Ingestion & Resolution ---")
        IngestionService().run(target_directory, graph, config_json)
