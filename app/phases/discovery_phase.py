import json
import logging
import os
import hashlib
import sys

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

        logger.info("--- PHASE 1: Starting tiered architectural discovery ---")
        self._write_progress("Tiered discovery: building repository manifest")
        manifest = RepoDiscoverer.build_repo_manifest(target_directory)
        self._write_progress("Tiered discovery: Tier 1 scanning files")
        tier1_artifacts = RepoDiscoverer.build_tier1_artifacts(target_directory)
        self._write_progress(
            "Tiered discovery: Tier 1 LLM analysis "
            f"({len(tier1_artifacts['top_paths_sample'])} paths, "
            f"{len(tier1_artifacts['top_keyword_hits'])} hits)"
        )
        coarse = await self._execute_json(
            "discovery_coarse",
            {"artifacts": json.dumps(tier1_artifacts, sort_keys=True)},
            "discovery-coarse",
        )
        focused_folders = self._list_values(
            coarse.get("interesting_folders"), coarse.get("next_dirs"),
            coarse.get("app_folders"), coarse.get("vendor_folders"),
        )
        self._write_progress(
            "Tiered discovery: Tier 2 scanning selected folders "
            f"({len(focused_folders)} folders)"
        )
        tier2_artifacts = RepoDiscoverer.build_tier2_artifacts(target_directory, focused_folders)
        self._write_progress(
            "Tiered discovery: Tier 2 LLM analysis "
            f"({len(tier2_artifacts['hits'])} hits, {len(tier2_artifacts['snippets'])} snippets)"
        )
        focused = await self._execute_json(
            "discovery_focused",
            {
                "artifacts": json.dumps(tier2_artifacts, sort_keys=True),
                "previous_guesses": json.dumps(coarse, sort_keys=True),
            },
            "discovery-focused",
        )
        application_folders = self._list_values(focused.get("app_folders"))
        if not application_folders:
            application_folders = self._list_values(focused.get("application_folders"))
        if not application_folders:
            application_folders = focused_folders
        application_folders = self._filter_application_folders(
            application_folders,
            self._list_values(coarse.get("vendor_folders")),
            target_directory,
            self._list_values(coarse.get("app_folders")) or ["app"],
        )
        self._write_progress(
            "Tiered discovery: Tier 3 scanning application folders "
            f"({len(application_folders)} folders)"
        )
        tier3_artifacts = RepoDiscoverer.build_tier3_artifacts(target_directory, application_folders)
        self._write_progress(
            "Tiered discovery: Tier 3 LLM confirmation "
            f"({len(tier3_artifacts['hits'])} hits, {len(tier3_artifacts['snippets'])} snippets)"
        )
        confirmed = await self._execute_json(
            "discovery_confirm",
            {
                "artifacts": json.dumps(tier3_artifacts, sort_keys=True),
                "previous_guesses": json.dumps({**coarse, **focused}, sort_keys=True),
            },
            "discovery-confirm",
        )
        config_json = {**coarse, **focused, **confirmed}
        for field in ("modules", "config_structures", "diagnostics", "hsm", "comms", "swc"):
            config_json[field] = self._merge_evidence_lists(
                coarse.get(field), focused.get(field), confirmed.get(field)
            )
        config_json["modules"] = self._filter_module_names(config_json["modules"])
        if not config_json["modules"]:
            config_json["modules"] = self._filter_module_names(tier2_artifacts.get("matched_terms", []))
        if not config_json["config_structures"]:
            config_json["config_structures"] = tier2_artifacts.get("config_terms", [])
        config_json["mcu"] = next(
            (value for result in (confirmed, focused, coarse)
             for value in (result.get("mcu"), result.get("mcu_candidates"))
             if self._first_named_value(value)),
            config_json.get("mcu"),
        )
        manifest_json = json.dumps(manifest, ensure_ascii=False, sort_keys=True)

        config_json["mcu_guess"] = self._first_named_value(
            config_json.get("mcu"), config_json.get("mcu_guess"), default="Unknown MCU"
        )
        config_json["silicon_vendor"] = self._first_named_value(
            config_json.get("silicon_vendor"), config_json.get("vendors"), default="Unknown"
        )
        config_json["autosar_stack_vendor"] = self._first_named_value(
            config_json.get("autosar_stack_vendor"), default="Unknown"
        )
        config_json["autosar_stack_product"] = self._first_named_value(
            config_json.get("autosar_stack_product"), default="Unknown"
        )
        config_json["ecu_role"] = self._first_named_value(
            config_json.get("ecu_role"), default="Unknown"
        )
        config_json["device_guess"] = config_json["ecu_role"]
        config_json["stack_vendor_guess"] = self._first_named_value(
            config_json.get("autosar_stack_vendor"), config_json.get("stack_vendor_guess"),
            config_json.get("stack_vendor"), default="Unknown vendor"
        )
        config_json["vendor_folders"] = self._list_values(
            config_json.get("skip_folders"), config_json.get("vendor_folders"), config_json.get("vendors"),
        )
        config_json.setdefault("likely_vendor_folders", config_json.get("vendor_folders", []))
        config_json.setdefault("app_domain_guesses", config_json.get("app_domains", []))
        config_json["application_roots"] = self._list_values(
            config_json.get("application_folders"), config_json.get("application_roots"),
        )
        config_json.setdefault("application_root_guesses", config_json.get("application_roots", []))
        config_json["app_folders"] = self._filter_application_folders(
            config_json.get("app_folders"), config_json.get("vendor_folders", []), target_directory,
            config_json.get("application_roots", ["app"]),
        )
        config_json["application_folders"] = self._filter_application_folders(
            config_json.get("application_folders"), config_json.get("vendor_folders", []), target_directory,
            config_json.get("application_roots", ["app"]),
        )
        config_json["app_domain_guesses"] = self._derive_app_domains(config_json)
        config_candidates = config_json.get("configs")
        config_extensions = config_candidates.get("extensions", []) if isinstance(config_candidates, dict) else config_candidates
        config_json["config_file_extensions"] = self._merge_discovery_rules(
            config_json.get("config_file_extensions") or config_extensions,
            RepoDiscoverer.DEFAULT_CONFIG_EXTENSIONS,
        )
        config_patterns = config_json.get("config_filename_patterns")
        if isinstance(config_candidates, dict):
            config_patterns = config_candidates.get("patterns", config_patterns)
        config_json["config_filename_patterns"] = self._merge_discovery_rules(
            config_patterns,
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
        config_json["repository_manifest"] = manifest
        config_json["repository_manifest_hash"] = hashlib.sha256(
            manifest_json.encode("utf-8")
        ).hexdigest()
        config_json = self._normalize_scope(config_json, target_directory, manifest)
        config_json["app_domains"] = config_json["app_domain_guesses"]
        config_json["stack_vendor"] = config_json["stack_vendor_guess"]

        with open(self.cache_file, 'w') as f:
            json.dump(config_json, f)

        found_configs = config_json.get('config_files', [])
        self._finish_progress()
        logger.info(
            "Discovery confirmed: MCU=%s | device=%s | vendor=%s | modules=%s | "
            "application=%s | vendor_skip=%s | config_extensions=%s | configs=%d",
            config_json.get("mcu_guess", "Unknown MCU"),
            config_json.get("ecu_role", "Unknown"),
            config_json.get("autosar_stack_vendor", "Unknown"),
            self._format_values(config_json.get("modules")),
            self._format_values(config_json.get("application_roots")),
            self._format_values(config_json.get("vendor_folders")),
            self._format_values(config_json.get("config_file_extensions")),
            len(found_configs),
        )
        if found_configs:
            logger.info(f"Discovery found {len(found_configs)} system configuration files.")
        return config_json

    async def _execute_json(self, task_name: str, kwargs: dict, context_id: str) -> dict:
        self._write_progress(f"Tiered discovery: waiting for {task_name} response")
        response = await self.llm.execute_task(
            task_name=task_name,
            kwargs=kwargs,
            context_id=context_id,
        )
        try:
            return extract_json_object(response)
        except ValueError as exc:
            logger.error("Discovery task %s did not return valid JSON", task_name)
            raise ValueError(f"Discovery task {task_name} did not return valid JSON") from exc

    @staticmethod
    def _write_progress(message: str) -> None:
        """Keep long discovery work visible without adding one log line per update."""
        sys.stdout.write(f"\r{message}...                                  ")
        sys.stdout.flush()

    @staticmethod
    def _finish_progress() -> None:
        sys.stdout.write("\n")
        sys.stdout.flush()

    @staticmethod
    def _format_values(value, limit: int = 8) -> str:
        if isinstance(value, dict):
            value = value.get("items", value.get("names", []))
        if not isinstance(value, list):
            return str(value or "unknown")
        values = [DiscoveryPhase._first_named_value(item) for item in value]
        values = [item for item in values if item]
        if len(values) > limit:
            return ", ".join(values[:limit]) + f", +{len(values) - limit} more"
        return ", ".join(values) or "none"

    @staticmethod
    def _list_values(*values) -> list[str]:
        result = []
        seen = set()
        for value in values:
            items = value if isinstance(value, list) else []
            for item in items:
                if isinstance(item, dict):
                    item = item.get("path", item.get("name", item.get("domain", "")))
                text = str(item).strip().strip('/\\')
                if text and text.casefold() not in seen:
                    result.append(text)
                    seen.add(text.casefold())
        return result

    @staticmethod
    def _merge_evidence_lists(*values) -> list:
        merged = []
        seen = set()
        for value in values:
            if not isinstance(value, list):
                continue
            for item in value:
                key = json.dumps(item, sort_keys=True) if isinstance(item, dict) else str(item)
                name = item.get("name", item.get("path", "")) if isinstance(item, dict) else item
                name_key = str(name).casefold()
                if key not in seen and name_key not in seen:
                    merged.append(item)
                    seen.add(key)
                    seen.add(name_key)
        return merged

    @staticmethod
    def _filter_module_names(values) -> list[str]:
        excluded = {
            "app", "application", "microsar", "rta-os", "mcal", "cdd",
            "bsw", "vendor", "gendata", "output", "selftest", "avb",
        }
        return [
            value for value in DiscoveryPhase._list_values(values)
            if value.casefold() not in excluded
        ]

    @classmethod
    def _filter_application_folders(
        cls,
        folders,
        vendor_folders,
        target_directory: str | None = None,
        application_roots: list[str] | None = None,
    ) -> list[str]:
        candidates = cls._list_values(folders)
        vendors = {item.casefold() for item in cls._list_values(vendor_folders)}
        vendors.update({"vendor", "third_party", "third-party", "mcal", "bsw", "microsar", "rta-os", "cdd"})
        roots = cls._list_values(application_roots) or ["app"]
        resolved = []
        for folder in candidates:
            if folder.casefold().split("/", 1)[0] in vendors:
                continue
            candidate_paths = [folder]
            if "/" not in folder and folder.casefold() not in {root.casefold() for root in roots}:
                candidate_paths = [f"{root.rstrip('/\\')}/{folder}" for root in roots]
            for candidate in candidate_paths:
                if target_directory is None or os.path.isdir(
                    os.path.join(target_directory, candidate.replace("/", os.sep))
                ):
                    if candidate.casefold() not in {item.casefold() for item in resolved}:
                        resolved.append(candidate)
                    break
        return resolved

    @staticmethod
    def _first_named_value(*values, default: str = "") -> str:
        for value in values:
            items = value if isinstance(value, list) else [value]
            for item in items:
                if isinstance(item, dict):
                    item = item.get("name", item.get("path", item.get("value", "")))
                text = str(item).strip()
                if text and text.casefold() not in {
                    "unknown", "unknown mcu", "unknown vendor", "none", "null",
                }:
                    return text
        return default

    @classmethod
    def _derive_app_domains(cls, config_json: dict) -> list[str]:
        """Build selectable domains when tiered output omits an explicit list."""
        explicit = cls._list_values(
            config_json.get("app_domain_guesses"), config_json.get("app_domains"),
        )
        if explicit:
            return explicit
        roots = cls._list_values(config_json.get("application_roots"))
        folders = cls._list_values(
            config_json.get("app_folders"), config_json.get("application_folders"),
        )
        dir_map = config_json.get("dir_map", [])
        if isinstance(dir_map, list):
            folders.extend(
                entry.get("path", entry.get("name", ""))
                for entry in dir_map
                if isinstance(entry, dict)
                and str(entry.get("category", "")).casefold() in {"app", "application"}
            )
        domains = []
        for folder in cls._list_values(folders):
            domain = folder
            for root in roots:
                prefix = root.rstrip("/\\") + "/"
                if folder.casefold() == root.casefold():
                    domain = folder
                    break
                if folder.casefold().startswith(prefix.casefold()):
                    domain = folder[len(prefix):].split("/", 1)[0]
                    break
            if domain.casefold() in {root.casefold() for root in roots} and any(
                candidate.casefold().startswith(domain.casefold().rstrip("/\\") + "/")
                for candidate in cls._list_values(folders)
            ):
                continue
            if domain and domain.casefold() not in {item.casefold() for item in domains}:
                domains.append(domain)
        return domains

    @staticmethod
    def _normalize_scope(config_json: dict, target_directory: str, manifest: dict | None = None) -> dict:
        """Make the vendor boundary deterministic even when the model under-infers it."""
        manifest = manifest or config_json.get("repository_manifest") or {}
        vendor_folders = config_json.get("likely_vendor_folders", config_json.get("vendor_folders", []))
        model_vendor_folders = config_json.get("vendor_folder_candidates", vendor_folders)
        if isinstance(model_vendor_folders, list):
            vendor_folders = model_vendor_folders
        if not isinstance(vendor_folders, list):
            vendor_folders = []
        normalized = DiscoveryPhase._list_values(vendor_folders)
        stack_vendor = DiscoveryPhase._first_named_value(
            config_json.get("stack_vendor_guess"), config_json.get("stack_vendor"),
        )
        target_names = set()
        if os.path.isdir(target_directory):
            target_names = {
                entry.name.lower()
                for entry in os.scandir(target_directory)
                if entry.is_dir()
            }
        manifest_components = {
            str(value).casefold()
            for value in manifest.get("directory_components", [])
            if str(value).strip()
        }
        if manifest_components:
            normalized = [
                folder for folder in normalized
                if folder.casefold() in manifest_components
            ]
        deterministic_vendor_folders = {
            "vendor", "third_party", "third-party", "mcal", "bsw",
            "basicsoftware", "generated", "gen",
        }
        deterministic_vendor_folders.update(
            str(value).casefold()
            for value in manifest.get("deterministic_vendor_folders", [])
            if str(value).strip()
        )
        normalized.extend(
            component for component in sorted(deterministic_vendor_folders)
            if component in manifest_components
        )
        if stack_vendor and stack_vendor.lower() in target_names:
            normalized.append(stack_vendor)
        seen = set()
        config_json["vendor_folders"] = [
            folder for folder in normalized
            if not (folder.lower() in seen or seen.add(folder.lower()))
        ]
        config_json["likely_vendor_folders"] = config_json["vendor_folders"]
        app_roots = config_json.get("application_root_guesses", config_json.get("application_roots", []))
        model_app_roots = config_json.get("application_root_candidates", app_roots)
        app_roots = DiscoveryPhase._list_values(model_app_roots)
        config_json["application_roots"] = [
            folder for folder in app_roots
            if folder.lower() in target_names
            and folder.lower() not in {vendor.lower() for vendor in config_json["vendor_folders"]}
        ]
        if not config_json["application_roots"] and "app" in target_names:
            config_json["application_roots"] = ["app"]
        config_json["application_root_guesses"] = config_json["application_roots"]
        config_json["app_folders"] = DiscoveryPhase._filter_application_folders(
            config_json.get("app_folders", []), config_json["vendor_folders"], target_directory,
            config_json["application_roots"],
        )
        config_json["application_folders"] = DiscoveryPhase._filter_application_folders(
            config_json.get("application_folders", []), config_json["vendor_folders"], target_directory,
            config_json["application_roots"],
        )
        config_json["modules"] = DiscoveryPhase._filter_module_names(config_json.get("modules", []))
        config_json["app_domain_guesses"] = DiscoveryPhase._derive_app_domains(config_json)
        vendor_parse_mode = str(config_json.get("vendor_parse_mode", "full")).strip().lower()
        if vendor_parse_mode not in {"full", "structure", "application_only"}:
            vendor_parse_mode = "full"
        config_json["vendor_parse_mode"] = vendor_parse_mode
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
