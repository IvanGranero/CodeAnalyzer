import json
import logging
import os

from tools.ingestion.discovery import RepoDiscoverer
from llm.service import LLMService
from tools.scanning.response_parser import extract_json_object

logger = logging.getLogger(__name__)


class DiscoveryPhase:
    """Phase 1: infer platform architecture and locate config files from the directory tree."""

    def __init__(self, llm_service: LLMService, cache_dir: str):
        self.llm = llm_service
        self.cache_file = os.path.join(cache_dir, "discovery_config.json")

    def used_cache(self, skip_ingest: bool) -> bool:
        return skip_ingest and os.path.exists(self.cache_file)

    async def run(self, target_directory: str, skip_ingest: bool) -> dict:
        if self.used_cache(skip_ingest):
            logger.info("--- PHASE 1: Skipped (using cached discovery config) ---")
            with open(self.cache_file, 'r') as f:
                return json.load(f)

        logger.info("--- PHASE 1: Starting Architectural Discovery ---")
        dir_tree = RepoDiscoverer.generate_directory_tree(target_directory)
        llm_response = await self.llm.execute_task(
            task_name="discovery",
            kwargs={"directory_tree": dir_tree},
            context_id="discovery",
        )
        try:
            config_json = extract_json_object(llm_response)
        except ValueError as exc:
            logger.error(
                "Discovery LLM did not return a JSON object (response length=%d): %s",
                len(llm_response),
                exc,
            )
            raise ValueError("Discovery LLM did not return valid JSON") from exc

        config_json.setdefault("mcu_guess", "Unknown MCU")
        config_json.setdefault("stack_vendor_guess", config_json.get("stack_vendor", "Unknown vendor"))
        config_json.setdefault("likely_vendor_folders", config_json.get("vendor_folders", []))
        config_json.setdefault("app_domain_guesses", config_json.get("app_domains", []))
        config_json.setdefault("config_file_extensions", [])
        config_json.setdefault("config_filename_patterns", [])
        config_json["config_files"] = RepoDiscoverer.search_config_files(
            target_directory,
            config_json["config_file_extensions"],
            config_json["config_filename_patterns"],
        )
        config_json["vendor_folders"] = config_json["likely_vendor_folders"]
        config_json["app_domains"] = config_json["app_domain_guesses"]
        config_json["stack_vendor"] = config_json["stack_vendor_guess"]

        with open(self.cache_file, 'w') as f:
            json.dump(config_json, f)

        found_configs = config_json.get('config_files', [])
        if found_configs:
            logger.info(f"Discovery found {len(found_configs)} system configuration files.")
        return config_json
