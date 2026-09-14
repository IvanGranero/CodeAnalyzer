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
                config_json = json.load(f)
            return self._normalize_scope(config_json, target_directory)

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
        config_json.setdefault("application_root_guesses", config_json.get("application_roots", []))
        config_json["config_file_extensions"] = self._merge_discovery_rules(
            config_json.get("config_file_extensions"),
            RepoDiscoverer.DEFAULT_CONFIG_EXTENSIONS,
        )
        config_json["config_filename_patterns"] = self._merge_discovery_rules(
            config_json.get("config_filename_patterns"),
            RepoDiscoverer.DEFAULT_CONFIG_PATTERNS,
        )
        discovered_config_files = RepoDiscoverer.search_config_files(
            target_directory,
            config_json["config_file_extensions"],
            config_json["config_filename_patterns"],
        )
        config_json["config_files"] = [
            path for path in discovered_config_files
            if os.path.splitext(path)[1].lower() in RepoDiscoverer.SUPPORTED_CONFIG_EXTENSIONS
        ]
        config_json["ignored_config_candidates"] = len(discovered_config_files) - len(config_json["config_files"])
        config_json = self._normalize_scope(config_json, target_directory)
        config_json["app_domains"] = config_json["app_domain_guesses"]
        config_json["stack_vendor"] = config_json["stack_vendor_guess"]

        with open(self.cache_file, 'w') as f:
            json.dump(config_json, f)

        found_configs = config_json.get('config_files', [])
        if found_configs:
            logger.info(f"Discovery found {len(found_configs)} system configuration files.")
        return config_json

    @staticmethod
    def _normalize_scope(config_json: dict, target_directory: str) -> dict:
        """Make the vendor boundary deterministic even when the model under-infers it."""
        vendor_folders = config_json.get("likely_vendor_folders", config_json.get("vendor_folders", []))
        if not isinstance(vendor_folders, list):
            vendor_folders = []
        normalized = [str(folder).strip().strip('/\\') for folder in vendor_folders if str(folder).strip()]
        stack_vendor = str(config_json.get("stack_vendor_guess", config_json.get("stack_vendor", ""))).strip()
        target_names = set()
        if os.path.isdir(target_directory):
            target_names = {
                entry.name.lower()
                for entry in os.scandir(target_directory)
                if entry.is_dir()
            }
        if stack_vendor and stack_vendor.lower() in target_names:
            normalized.append(stack_vendor)
        seen = set()
        config_json["vendor_folders"] = [
            folder for folder in normalized
            if not (folder.lower() in seen or seen.add(folder.lower()))
        ]
        config_json["likely_vendor_folders"] = config_json["vendor_folders"]
        app_roots = config_json.get("application_root_guesses", config_json.get("application_roots", []))
        if not isinstance(app_roots, list):
            app_roots = []
        config_json["application_roots"] = [
            str(folder).strip().strip('/\\')
            for folder in app_roots
            if (
                str(folder).strip()
                and str(folder).strip().strip('/\\').lower() in target_names
                and str(folder).strip().strip('/\\').lower() not in {
                    vendor.lower() for vendor in config_json["vendor_folders"]
                }
            )
        ]
        if not config_json["application_roots"] and "app" in target_names:
            config_json["application_roots"] = ["app"]
        config_json["application_root_guesses"] = config_json["application_roots"]
        return config_json

    @staticmethod
    def _merge_discovery_rules(value, defaults) -> list[str]:
        """Keep deterministic repository coverage when the model under-infers rules."""
        candidates = value if isinstance(value, list) else []
        merged = []
        seen = set()
        for item in [*candidates, *defaults]:
            rule = str(item).strip()
            key = rule.lower()
            if rule and key not in seen:
                merged.append(rule)
                seen.add(key)
        return merged
