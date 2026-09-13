"""Application service for source-to-graph ingestion."""

from typing import Any

from tools.graph.manager import GraphManager
from tools.ingestion.pipeline import IngestionPipeline


class IngestionService:
    """Run parsers and graph resolution as one application operation."""

    def run(self, target_directory: str, graph: GraphManager, config: dict[str, Any]) -> dict[str, Any]:
        report = IngestionPipeline(target_directory, graph).run(
            vendor_folders=config.get("vendor_folders", []),
            config_files=config.get("config_files", []),
        )
        joern_export = config.get("joern_export")
        if joern_export:
            report["joern"] = graph.ingest_joern_export(joern_export)
        graph.resolver.run_all_passes()
        return report
