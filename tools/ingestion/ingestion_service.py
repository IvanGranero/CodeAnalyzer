"""Application service for source-to-graph ingestion."""

from threading import Event
from typing import Any

from tools.graph.manager import GraphManager
from tools.ingestion.pipeline import IngestionPipeline


class IngestionService:
    """Run parsers and graph resolution as one application operation."""

    def run(
        self,
        target_directory: str,
        graph: GraphManager,
        config: dict[str, Any],
        cancel_event: Event | None = None,
    ) -> dict[str, Any]:
        report = IngestionPipeline(target_directory, graph).run(
            vendor_folders=config.get("vendor_folders", []),
            config_files=config.get("config_files", []),
            vendor_parse_mode=config.get("vendor_parse_mode", "full"),
            cancel_event=cancel_event,
        )
        graph.resolver.run_all_passes()
        return report
