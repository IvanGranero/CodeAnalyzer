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
        discovery_context = {
            "mcu": config.get("mcu_guess"),
            "device": config.get("device_guess"),
            "vendor": config.get("stack_vendor_guess"),
            "modules": config.get("modules", []),
            "config_structures": config.get("config_structures", []),
            "application_roots": config.get("application_roots", []),
            "mcu_candidates": config.get("mcu_candidates", []),
        }
        graph.ingest_discovery_context(discovery_context)
        graph.resolver.set_discovery_context(discovery_context)
        report = IngestionPipeline(target_directory, graph).run(
            vendor_folders=config.get("vendor_folders", []),
            config_files=config.get("config_files", []),
            vendor_parse_mode=config.get("vendor_parse_mode", "full"),
            discovery_context=discovery_context,
            cancel_event=cancel_event,
        )
        graph.resolver.run_all_passes()
        return report
