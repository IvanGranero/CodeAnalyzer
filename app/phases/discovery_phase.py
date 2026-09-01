import json
import logging
import os
import sys

from ingest.discovery import RepoDiscoverer
from llm.service import LLMService

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
        llm_response = await self.llm.execute_task(task_name="discovery", kwargs={"directory_tree": dir_tree})
        try:
            config_json = json.loads(llm_response)
        except json.JSONDecodeError:
            logger.error("Discovery LLM did not return valid JSON. Cannot proceed.")
            sys.exit(1)

        with open(self.cache_file, 'w') as f:
            json.dump(config_json, f)

        found_configs = config_json.get('config_files', [])
        if found_configs:
            logger.info(f"Discovery found {len(found_configs)} system configuration files.")
        return config_json
