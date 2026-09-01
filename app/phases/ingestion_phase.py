import logging

from graph.manager import GraphManager
from ingest.pipeline import IngestionPipeline

logger = logging.getLogger(__name__)


class IngestionPhase:
    """Phase 2: parse the source tree into the graph, then run resolver passes."""

    def run(self, target_directory: str, graph: GraphManager, config_json: dict) -> None:
        logger.info("\n--- PHASE 2: Starting Graph Ingestion & Resolution ---")
        IngestionPipeline(target_directory, graph).run(
            vendor_folders=config_json.get('vendor_folders', []),
            config_files=config_json.get('config_files', []),
        )
        graph.resolver.run_all_passes()
