import json
import logging
import os
import hashlib
import sys

from tools.ingestion.discovery import RepoDiscoverer, DiscoveryToolRegistry
from llm.service import LLMService
from tools.agent_loop import agent_loop
from tools.scanning.response_parser import extract_json_object

logger = logging.getLogger(__name__)


class DiscoveryPhase:
    """Phase 1: infer platform architecture and locate config files from the directory tree."""

    CACHE_SCHEMA_VERSION = 1
    CACHE_FIELDS = (
        "mcu_guess", "silicon_vendor", "autosar_stack_vendor", "autosar_stack_product",
        "ecu_role", "device_guess", "stack_vendor", "stack_vendor_guess",
        "modules", "config_structures", "diagnostics", "hsm", "comms", "swc", "rte",
        "vendor_folders", "likely_vendor_folders", "application_roots",
        "application_root_guesses", "application_domains", "app_domains", "app_domain_guesses",
        "confidence", "confidence_scores",
    )

    def __init__(self, llm_service: LLMService, cache_dir: str):
        self.llm = llm_service
        self.cache_file = os.path.join(cache_dir, "discovery_config.json")

    def used_cache(self, skip_ingest: bool) -> bool:
        return skip_ingest and os.path.exists(self.cache_file)

    @classmethod
    def _cache_payload(cls, config_json: dict) -> dict:
        """Keep only fields needed to scope scans and seed downstream agents."""
        payload = {
            key: config_json[key]
            for key in cls.CACHE_FIELDS
            if key in config_json
        }
        manifest = config_json.get("repository_manifest")
        payload["repository_name"] = manifest.get("root", "") if isinstance(manifest, dict) else config_json.get("repository_name", "")
        payload["configuration_file_count"] = len(config_json.get("config_files") or [])
        payload["application_folder_count"] = len(config_json.get("app_folders") or [])
        payload["cache_schema_version"] = cls.CACHE_SCHEMA_VERSION
        return payload

    async def run(self, target_directory: str, skip_ingest: bool) -> dict:
        if self.used_cache(skip_ingest):
            logger.info("--- PHASE 1: Skipped (using cached discovery config) ---")
            with open(self.cache_file, 'r', encoding="utf-8") as f:
                config_json = json.load(f)
            config_json = self._normalize_scope(config_json, target_directory)
            if config_json.get("cache_schema_version") != self.CACHE_SCHEMA_VERSION:
                with open(self.cache_file, "w", encoding="utf-8") as f:
                    json.dump(self._cache_payload(config_json), f)
            return config_json

        logger.info("--- PHASE 1: Starting architectural discovery ---")
        self._write_progress("Discovery: building repository manifest")
        manifest = RepoDiscoverer.build_repo_manifest(target_directory)
        self._write_progress("Discovery: LLM agent exploring repository")
        initial_tree = RepoDiscoverer.generate_directory_tree(target_directory, max_depth=2)
        discovered = await self._run_discovery_agent(
            target_directory, manifest, initial_tree,
        )
        config_json = dict(discovered)
        config_json["modules"] = self._filter_module_names(config_json.get("modules", []))
        config_json["mcu"] = next(
            (value for value in (config_json.get("mcu"), config_json.get("mcu_candidates"))
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
        inferred_roots = self._discover_application_roots(
            target_directory, manifest, config_json["vendor_folders"]
        )
        model_roots = self._list_values(
            config_json.get("application_roots"), config_json.get("application_root_guesses"),
        )
        if not model_roots:
            model_roots = self._list_values(config_json.get("application_folders"))
        conventional_roots = [
            root for root in inferred_roots
            if root.casefold() in {"app", "application", "src", "source", "swc", "swcs"}
        ]
        root_guesses = self._merge_folder_values(
            model_roots,
            conventional_roots if model_roots else inferred_roots,
        )
        config_json["application_roots"] = self._filter_application_roots(
            root_guesses, config_json["vendor_folders"], target_directory
        )
        config_json["application_root_guesses"] = config_json["application_roots"]
        config_json["app_folders"] = self._filter_application_folders(
            config_json.get("app_folders"), config_json.get("vendor_folders", []), target_directory,
            config_json.get("application_roots", ["app"]),
        )
        config_json["app_folders"] = self._merge_folder_values(
            config_json["app_folders"],
            self._discover_application_folders(
                target_directory, config_json.get("application_roots", ["app"]), config_json["vendor_folders"]
            ),
        )
        config_json["application_folders"] = self._filter_application_folders(
            config_json.get("application_folders"), config_json.get("vendor_folders", []), target_directory,
            config_json.get("application_roots", ["app"]),
        )
        domain_roots = config_json.get("application_roots", [])
        model_domain_groups = self._extract_domain_groups(
            config_json.get("application_domains"),
            config_json.get("app_domain_guesses"),
            config_json.get("app_domains"),
        )
        validated_domain_groups = self._validate_domain_groups(
            model_domain_groups, domain_roots, config_json["vendor_folders"], target_directory,
        )
        if validated_domain_groups:
            config_json["application_domains"] = validated_domain_groups
            config_json["app_domain_guesses"] = self._merge_folder_values(
                *[group["folders"] for group in validated_domain_groups]
            )
        else:
            derived_domains = self._derive_app_domains(
                {**config_json, "application_domains": [], "app_domain_guesses": [], "app_domains": []}
            )
            config_json["app_domain_guesses"] = self._merge_folder_values(derived_domains)
            config_json["application_domains"] = [
                {"name": domain, "folders": [domain], "evidence": [], "confidence": 0.0}
                for domain in config_json["app_domain_guesses"]
            ]
        if not self._has_conventional_application_root(domain_roots):
            config_json["app_domain_guesses"] = self._merge_folder_values(
                config_json["app_domain_guesses"], domain_roots
            )
        config_json["app_domain_guesses"] = self._merge_folder_values(
            config_json["app_domain_guesses"],
            self._discover_application_domains(target_directory, config_json["application_roots"], config_json["vendor_folders"])
            if self._has_conventional_application_root(config_json["application_roots"])
            else [],
        )
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

        with open(self.cache_file, "w", encoding="utf-8") as f:
            json.dump(self._cache_payload(config_json), f)

        found_configs = config_json.get('config_files', [])
        self._finish_progress()
        logger.info(
            "Discovery confirmed: MCU=%s | silicon=%s | device=%s | stack_vendor=%s | "
            "stack_product=%s | modules=%s | structures=%s | application_roots=%s | "
            "domains=%s | vendor_skip=%s | config_extensions=%s | configs=%d | "
            "mcu_candidates=%d | app_folders=%d | confidence=%s",
            config_json.get("mcu_guess", "Unknown MCU"),
            config_json.get("silicon_vendor", "Unknown"),
            config_json.get("ecu_role", "Unknown"),
            config_json.get("autosar_stack_vendor", "Unknown"),
            config_json.get("autosar_stack_product", "Unknown"),
            self._format_values(config_json.get("modules")),
            self._format_values(config_json.get("config_structures")),
            self._format_values(config_json.get("application_roots")),
            self._format_values(config_json.get("app_domain_guesses")),
            self._format_values(config_json.get("vendor_folders")),
            self._format_values(config_json.get("config_file_extensions")),
            len(found_configs),
            len(config_json.get("mcu_candidates", [])),
            len(config_json.get("app_folders", [])),
            config_json.get("confidence", config_json.get("confidence_scores", "unknown")),
        )
        if found_configs:
            logger.info(f"Discovery found {len(found_configs)} system configuration files.")
        return config_json

    async def _run_discovery_agent(
        self, target_directory: str, manifest: dict, initial_tree: str,
    ) -> dict:
        """Run one tool-calling agent loop that explores the repository itself
        (list_directory / read_file / grep_repository / search_config_files)
        starting from a 2-level tree, replacing the old fixed coarse -> focused
        -> confirm regex sweeps. Bounded contract-validation retries are
        provided by agent_loop, exactly like tools/scanning/agents.py's
        triage/deep-scan agents.
        """
        registry = DiscoveryToolRegistry(target_directory)

        async def step(attempt: int, directive: str) -> dict:
            response = await self.llm.execute_task(
                task_name="discovery_agent",
                kwargs={
                    "repo_root_name": manifest.get("root", ""),
                    "initial_tree": initial_tree,
                    "directive": directive,
                },
                context_id="discovery-agent",
                tools=registry.definitions(),
                tool_handler=registry.call,
            )
            return extract_json_object(response)

        def build_retry_directive(prev_directive: str, attempt: int, error: str) -> str:
            return (
                f"RETRY {attempt}: Your previous response failed contract validation ({error}). "
                "Return one complete, final JSON object (no markdown fences, no prose) with every "
                "required discovery field. Do not describe further tool calls in the response text "
                "-- either call a tool, or return the final JSON."
            )

        def build_fallback(error: str) -> dict:
            logger.error("Discovery agent failed after bounded retries: %s", error)
            return {
                "mcu": "Unknown", "silicon_vendor": "Unknown", "autosar_stack_vendor": "Unknown",
                "autosar_stack_product": "Unknown", "ecu_role": "Unknown", "modules": [],
                "application_roots": [], "application_domains": [], "vendor_folders": [],
                "app_folders": [], "configs": {}, "confidence": 0.0, "error": error,
            }

        result: dict | None = None
        async for event in agent_loop(
            context_id="discovery-agent",
            max_attempts=3,
            step=step,
            build_retry_directive=build_retry_directive,
            build_fallback=build_fallback,
        ):
            if event.kind != "final":
                self._write_progress(f"[{event.kind}] {event.data}")
            else:
                return event.data

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

    @classmethod
    def _merge_named_field(cls, *values, default_value: str = "Unknown") -> dict:
        """Pick the first tier's {value, evidence, confidence}-style object that isn't an
        empty Unknown placeholder, preferring the most-confirmed tier; used for fields like
        diagnostics/hsm/comms/swc that are single classifications, not evidence lists."""
        candidates = [value for value in values if isinstance(value, dict)]
        for value in candidates:
            if cls._first_named_value(value.get("value"), value.get("name")):
                return value
        if candidates:
            return candidates[0]
        return {"value": default_value, "evidence": [], "confidence": 0.0}

    @staticmethod
    def _filter_module_names(values) -> list[str]:
        excluded = {
            "app", "application", "microsar", "rta-os", "cdd",
            "bsw", "vendor", "gendata", "output", "selftest", "avb",
        }
        return [
            value for value in DiscoveryPhase._list_values(values)
            if value.casefold() not in excluded
        ]

    @classmethod
    def _discover_application_roots(cls, target_directory: str, manifest: dict, vendor_folders) -> list[str]:
        """Infer source-bearing application roots when the model returns none."""
        known_names = {"app", "application", "src", "source", "swc", "swcs"}
        vendor_names = {item.casefold() for item in cls._list_values(vendor_folders)}
        vendor_names.update({"vendor", "bsw", "mcal", "microsar", "rta-os", "cdd", "gendata"})
        directories = manifest.get("directories", []) if isinstance(manifest, dict) else []
        roots = []
        for directory in directories:
            if not isinstance(directory, dict) or directory.get("depth") != 1:
                continue
            path = str(directory.get("path", "")).strip().strip("/\\")
            if not path or path.startswith((".", "_")) or path.casefold() in vendor_names:
                continue
            if path.casefold() in known_names or int(directory.get("source_file_count", 0) or 0) > 0:
                roots.append(path)
        return sorted(set(roots), key=str.casefold)

    @classmethod
    def _filter_application_roots(cls, roots, vendor_folders, target_directory: str) -> list[str]:
        """Keep only real in-repository roots outside known vendor/generated paths."""
        repository_root = os.path.realpath(target_directory)
        vendors = {item.casefold() for item in cls._list_values(vendor_folders)}
        vendors.update({"vendor", "third_party", "third-party", "mcal", "bsw", "microsar", "rta-os", "cdd"})
        resolved = []
        seen = set()
        for root in cls._list_values(roots):
            normalized = root.replace("\\", "/")
            parts = normalized.split("/")
            if not normalized or any(part.startswith((".", "_")) for part in parts):
                continue
            if any(part.casefold() in vendors for part in parts):
                continue
            candidate = os.path.realpath(os.path.join(repository_root, normalized.replace("/", os.sep)))
            try:
                inside_repository = os.path.commonpath((repository_root, candidate)) == repository_root
            except ValueError:
                inside_repository = False
            key = normalized.casefold()
            if (
                inside_repository
                and candidate != repository_root
                and os.path.isdir(candidate)
                and key not in seen
            ):
                resolved.append(normalized)
                seen.add(key)
        return resolved

    @staticmethod
    def _has_conventional_application_root(roots) -> bool:
        return bool({item.replace("\\", "/").rstrip("/").split("/")[-1].casefold() for item in DiscoveryPhase._list_values(roots)} & {
            "app", "application", "src", "source", "swc", "swcs"
        })

    @staticmethod
    def _merge_folder_values(*values) -> list[str]:
        merged = []
        seen = set()
        for value in values:
            for folder in DiscoveryPhase._list_values(value):
                key = folder.casefold()
                if key not in seen:
                    merged.append(folder)
                    seen.add(key)
        return merged

    @classmethod
    def _discover_application_folders(
        cls, target_directory: str, roots, vendor_folders
    ) -> list[str]:
        """Return real application subdirectories for focused scanning."""
        result = []
        for root in cls._list_values(roots):
            root_path = os.path.join(target_directory, root.replace("/", os.sep))
            if not os.path.isdir(root_path):
                continue
            for entry in sorted(os.scandir(root_path), key=lambda item: item.name.casefold()):
                if not entry.is_dir() or entry.name.startswith("_"):
                    continue
                relative = f"{root.rstrip('/\\')}/{entry.name}"
                result.append(relative)
        return cls._filter_application_folders(result, vendor_folders, target_directory, roots)

    @classmethod
    def _discover_application_domains(cls, target_directory: str, roots, vendor_folders) -> list[str]:
        """Return selectable domain names from immediate application subdirectories."""
        domains = []
        for folder in cls._discover_application_folders(target_directory, roots, vendor_folders):
            parts = folder.replace("\\", "/").split("/")
            if len(parts) >= 2 and parts[-1].casefold() not in {item.casefold() for item in domains}:
                domains.append(parts[-1])
        return domains

    @classmethod
    def _validate_application_domains(
        cls, candidates, target_directory: str, roots, vendor_folders
    ) -> list[str]:
        """Accept LLM domain names only when they match real scoped directories."""
        roots = cls._filter_application_roots(roots, vendor_folders, target_directory)
        if cls._has_conventional_application_root(roots):
            actual_domains = cls._discover_application_domains(
                target_directory, roots, vendor_folders
            )
        else:
            actual_domains = [root.replace("\\", "/").rstrip("/").split("/")[-1] for root in roots]
        actual_by_name = {domain.casefold(): domain for domain in actual_domains}
        validated = []
        for candidate in cls._list_values(candidates):
            name = candidate.replace("\\", "/").rstrip("/").split("/")[-1]
            match = actual_by_name.get(name.casefold())
            if match is not None:
                validated.append(match)
        return cls._merge_folder_values(validated)

    @classmethod
    def _extract_domain_groups(cls, *sources) -> list[dict]:
        """Normalize application_domains-shaped inputs into {name, folders, evidence, confidence}
        groups without collapsing a domain to its title string the way _list_values would
        (item.get("name") on a domain object returns the domain's title, not its member
        folders -- that is what previously caused every model-proposed domain to be dropped).

        Sources are processed in order and a folder already claimed by an earlier group is
        never re-added as its own standalone domain -- this matters because callers pass the
        rich `application_domains` groups *and* the already-flattened `app_domain_guesses`/
        `app_domains` lists together (the flat lists are derived FROM the groups), and without
        this check every grouped folder would reappear a second time as a one-folder domain."""
        groups = []
        seen_names = set()
        seen_folders = set()
        for source in sources:
            if not isinstance(source, list):
                continue
            for item in source:
                if isinstance(item, dict) and isinstance(item.get("folders"), list):
                    folders = [f for f in cls._list_values(item.get("folders")) if f.casefold() not in seen_folders]
                    if not folders:
                        continue
                    name = str(item.get("name") or item.get("domain") or "").strip() or folders[0]
                    key = name.casefold()
                    if key in seen_names:
                        continue
                    seen_names.add(key)
                    seen_folders.update(f.casefold() for f in folders)
                    evidence = item.get("evidence")
                    confidence = item.get("confidence")
                    groups.append({
                        "name": name,
                        "folders": folders,
                        "evidence": evidence if isinstance(evidence, list) else [],
                        "confidence": confidence if isinstance(confidence, (int, float)) else 0.0,
                    })
                else:
                    # Legacy shape: a bare folder name/path with no explicit grouping.
                    folder = next(iter(cls._list_values([item])), "")
                    if not folder:
                        continue
                    key = folder.casefold()
                    if key in seen_names or key in seen_folders:
                        continue
                    seen_names.add(key)
                    seen_folders.add(key)
                    groups.append({"name": folder, "folders": [folder], "evidence": [], "confidence": 0.0})
        return groups

    @classmethod
    def _validate_domain_groups(
        cls, groups: list[dict], roots, vendor_folders, target_directory: str
    ) -> list[dict]:
        """Keep a model-proposed domain only if its member folders are real, filtered
        application roots -- validated by the group's *folders*, not by whether the domain's
        display name happens to match a folder name (a multi-root domain like "Fuel supply
        and injection" is never itself a folder, so name-matching rejected every valid
        grouped domain the model produced)."""
        valid_roots = {
            root.casefold() for root in cls._filter_application_roots(roots, vendor_folders, target_directory)
        }
        validated = []
        for group in groups:
            kept = [folder for folder in group.get("folders", []) if folder.casefold() in valid_roots]
            if not kept:
                continue
            validated.append({**group, "folders": kept})
        return validated

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
        app_roots = DiscoveryPhase._list_values(
            config_json.get("application_roots"),
            config_json.get("application_root_guesses"),
            config_json.get("application_root_candidates"),
        )
        inferred_roots = DiscoveryPhase._discover_application_roots(
            target_directory, manifest, vendor_folders
        )
        conventional_roots = [
            root for root in inferred_roots
            if root.casefold() in {"app", "application", "src", "source", "swc", "swcs"}
        ]
        app_roots = DiscoveryPhase._merge_folder_values(
            app_roots,
            conventional_roots if app_roots else inferred_roots,
        )
        config_json["application_roots"] = DiscoveryPhase._filter_application_roots(
            app_roots, config_json["vendor_folders"], target_directory
        )
        if not config_json["application_roots"] and "app" in target_names:
            config_json["application_roots"] = ["app"]
        config_json["application_root_guesses"] = config_json["application_roots"]
        config_json["app_folders"] = DiscoveryPhase._filter_application_folders(
            config_json.get("app_folders", []), config_json["vendor_folders"], target_directory,
            config_json["application_roots"],
        )
        config_json["app_folders"] = DiscoveryPhase._merge_folder_values(
            config_json["app_folders"],
            DiscoveryPhase._discover_application_folders(
                target_directory, config_json["application_roots"], config_json["vendor_folders"]
            ) if DiscoveryPhase._has_conventional_application_root(config_json["application_roots"]) else [],
        )
        config_json["application_folders"] = DiscoveryPhase._filter_application_folders(
            config_json.get("application_folders", []), config_json["vendor_folders"], target_directory,
            config_json["application_roots"],
        )
        config_json["modules"] = DiscoveryPhase._filter_module_names(config_json.get("modules", []))
        model_domain_groups = DiscoveryPhase._extract_domain_groups(
            config_json.get("application_domains"),
            config_json.get("app_domain_guesses"),
            config_json.get("app_domains"),
        )
        validated_domain_groups = DiscoveryPhase._validate_domain_groups(
            model_domain_groups, config_json["application_roots"], config_json["vendor_folders"], target_directory,
        )
        if validated_domain_groups:
            config_json["application_domains"] = validated_domain_groups
            config_json["app_domain_guesses"] = DiscoveryPhase._merge_folder_values(
                *[group["folders"] for group in validated_domain_groups]
            )
        else:
            derived_domains = DiscoveryPhase._derive_app_domains(
                {**config_json, "application_domains": [], "app_domain_guesses": [], "app_domains": []}
            )
            config_json["app_domain_guesses"] = DiscoveryPhase._merge_folder_values(derived_domains)
            config_json["application_domains"] = [
                {"name": domain, "folders": [domain], "evidence": [], "confidence": 0.0}
                for domain in config_json["app_domain_guesses"]
            ]
        if not DiscoveryPhase._has_conventional_application_root(config_json["application_roots"]):
            config_json["app_domain_guesses"] = DiscoveryPhase._merge_folder_values(
                config_json["app_domain_guesses"],
                [root.replace("\\", "/").rstrip("/").split("/")[-1] for root in config_json["application_roots"]],
            )
        config_json["app_domain_guesses"] = DiscoveryPhase._merge_folder_values(
            config_json["app_domain_guesses"],
            DiscoveryPhase._discover_application_domains(
                target_directory, config_json["application_roots"], config_json["vendor_folders"]
            ) if DiscoveryPhase._has_conventional_application_root(config_json["application_roots"]) else [],
        )
        config_json["app_domains"] = config_json["app_domain_guesses"]
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