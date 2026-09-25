import os
import logging
import fnmatch
import re
from collections import Counter, defaultdict
from pathlib import Path

logger = logging.getLogger(__name__)

class RepoDiscoverer:
    SUPPORTED_CONFIG_EXTENSIONS = frozenset({".arxml", ".xml", ".json"})
    DEFAULT_CONFIG_EXTENSIONS = (
        ".arxml", ".oil", ".cdd", ".rte.json", ".rte", ".xml", ".json",
        ".ini", ".cfg", ".mk", ".ld", ".sct",
    )
    DEFAULT_CONFIG_PATTERNS = (
        "*.arxml", "*.oil", "CMakeLists.txt", "Makefile", "*.ld",
    )
    TIER1_PATTERN = re.compile(
        r"arxml|Ecuc|ContainerDef|Rte_|Swc|CanIf|CanTp|Com|PduR|Dcm|Dem|Det|"
        r"BswM|EcuM|NvM|FiM|Wdgm|Os|Hsm|Diag|stm32|nxp|s32k|rh850|tricore|"
        r"renesas|infineon",
        re.IGNORECASE,
    )
    TIER2_PATTERN = re.compile(
        r"\b(CanIf|CanDrv|CanTp|Com|PduR|Dcm|Dem|Det|NvM|FiM|Wdgm|Os|BswM|"
        r"EcuM|Rte|Xcp|SoAd|TcpIp|IpduM|LinIf|EthIf)\b|"
        r"\b(EcucContainerDef|EcucPartition|EcucForeignReference|ContainerDef|"
        r"LinkerSymbolDef|PublishedInformation|postBuildVariantsUsed)\b|"
        r"(?:\.ld|\.map|\.elf|\.hex|LinkerSymbol)|"
        r"\b(stm32f[0-9]+|stm32|s32k|s32z|rh850|tricore|tms570|pic32|"
        r"cortex[-_ ]?m[0-9]+)\b",
        re.IGNORECASE,
    )
    TIER3_PATTERN = re.compile(
        r"\b[A-Z][A-Za-z0-9]+_(?:Init|Runnable|MainFunction|Periodic|10msTask|20msTask)\b|"
        r"Rte_(?:Type|Cfg|Swc|Application|Call|Read|Write)|"
        r"(?:Diag_Init|Dcm_Init|Dem_Init|Hsm_Init|Hsm_Process|Crypto_)|"
        r"(?:CanIf_Init|CanTp_Init|Com_Init|PduR_Init|SoAd_Init|TcpIp_Init)|"
        r"\b(?:FLASH|RAM|SECTIONS|MEMORY|REGION|ENTRY|PROVIDE)\b",
        re.IGNORECASE,
    )
    MCU_PATTERN = re.compile(
        r"\b(stm32[fgh][0-9a-z]+|s32k[0-9a-z]*|s32z[0-9a-z]*|rh850[a-z0-9_-]*|"
        r"tricore|aurix|tc[0-9]+[a-z0-9_-]*|tms570[a-z0-9_-]*|pic32[a-z0-9_-]*|"
        r"cortex[-_ ]?m[0-9]+|renesas|infineon|nxp)\b",
        re.IGNORECASE,
    )

    @classmethod
    def build_repo_manifest(cls, target_dir: str) -> dict:
        """Return deterministic aggregates for embedded source and configuration files."""
        root = Path(target_dir).resolve()
        records = defaultdict(lambda: {
            "file_count": 0,
            "source_file_count": 0,
            "extensions": Counter(),
            "sample_files": [],
            "generator_markers": [],
        })
        source_suffixes = {".c", ".cc", ".cpp", ".h", ".hh", ".hpp"}
        relevant_suffixes = source_suffixes | {
            ".arxml", ".cdd", ".cfg", ".ini", ".json", ".ld", ".mk", ".oil",
            ".rte", ".sct", ".xml",
        }
        relevant_names = {"CMakeLists.txt", "Makefile"}
        generator_patterns = (
            re.compile(r"^rte_.*\.(c|h|cpp|hpp|arxml|xml)$", re.IGNORECASE),
            re.compile(r"^dcm_.*\.(c|h|cpp|hpp|arxml|xml)$", re.IGNORECASE),
            re.compile(r"_cfg\.(c|h|cpp|hpp)$", re.IGNORECASE),
            re.compile(r"(generated|autosar|autosar).*\.(c|h|cpp|hpp|arxml|xml)$", re.IGNORECASE),
        )

        paths = (
            item for item in root.rglob("*")
            if item.is_file()
            and (item.suffix.casefold() in relevant_suffixes or item.name in relevant_names)
        )
        for path in sorted(paths, key=lambda item: item.relative_to(root).as_posix().casefold()):
            relative = path.relative_to(root).as_posix()
            parent_parts = Path(relative).parts[:-1]
            for depth in range(1, len(parent_parts) + 1):
                directory = "/".join(parent_parts[:depth])
                record = records[directory]
                record["file_count"] += 1
                suffix = path.suffix.lower() or "[no_extension]"
                record["extensions"][suffix] += 1
                if suffix in source_suffixes:
                    record["source_file_count"] += 1
                if depth <= 2 and len(record["sample_files"]) < 6:
                    record["sample_files"].append(relative)
                if depth <= 2 and any(pattern.search(path.name) for pattern in generator_patterns):
                    marker = path.name
                    if marker not in record["generator_markers"] and len(record["generator_markers"]) < 6:
                        record["generator_markers"].append(marker)

        directories = []
        for directory in sorted(records, key=str.casefold):
            record = records[directory]
            directories.append({
                "path": directory,
                "depth": directory.count("/") + 1,
                "file_count": record["file_count"],
                "source_file_count": record["source_file_count"],
                "extensions": dict(sorted(record["extensions"].items())),
                "sample_files": record["sample_files"],
                "generator_markers": record["generator_markers"],
            })

        components = sorted(
            {part.casefold() for directory in directories for part in Path(directory["path"]).parts},
        )
        application_names = {
            "app", "application", "src", "source", "tools", "lib", "include",
        }
        deterministic_vendor_folders = sorted({
            Path(directory["path"]).name.casefold()
            for directory in directories
            if len(directory["generator_markers"]) >= 2
            and Path(directory["path"]).name.casefold() not in application_names
        })
        return {
            "root": root.name,
            "directory_count": len(directories),
            "file_count": sum(item["file_count"] for item in directories if item["depth"] == 1),
            "top_level_directories": sorted(
                {directory["path"].split("/", 1)[0] for directory in directories},
                key=str.casefold,
            ),
            "directory_components": components,
            "deterministic_vendor_folders": deterministic_vendor_folders,
            "directories": directories,
        }

    @classmethod
    def build_tier1_artifacts(cls, target_dir: str) -> dict:
        """Return small, high-signal metadata for the coarse discovery loop."""
        root = Path(target_dir).resolve()
        extension_histogram = Counter()
        path_hits = []
        line_hits = []
        hardware_hits = []
        hardware_paths = []
        directory_counts = Counter()
        for path in cls._iter_files(root):
            suffix = path.suffix.casefold() or "[no_extension]"
            extension_histogram[suffix] += 1
            relative = path.relative_to(root).as_posix()
            directory = relative.rsplit("/", 1)[0] if "/" in relative else "."
            directory_counts[directory.split("/", 1)[0]] += 1
            matched = False
            for line_number, line in cls._read_lines(path):
                if cls.TIER1_PATTERN.search(line):
                    matched = True
                    entry = f'{relative}:{line_number}:{line.strip()[:240]}'
                    if len(line_hits) < 20:
                        line_hits.append(entry)
                if cls.MCU_PATTERN.search(f"{relative} {line}"):
                    entry = f'{relative}:{line_number}:{line.strip()[:240]}'
                    if len(hardware_hits) < 20:
                        hardware_hits.append(entry)
                    if relative not in hardware_paths and len(hardware_paths) < 20:
                        hardware_paths.append(relative)
            if matched and len(path_hits) < 50:
                path_hits.append(relative)
            if cls.MCU_PATTERN.search(relative) and relative not in hardware_paths and len(hardware_paths) < 20:
                hardware_paths.append(relative)
        return {
            "ext_histogram": dict(sorted(extension_histogram.items())),
            "top_paths_sample": sorted(path_hits, key=str.casefold)[:50],
            "top_keyword_hits": line_hits,
            "hardware_evidence": {
                "mcu_hits": hardware_hits,
                "matching_paths": sorted(hardware_paths, key=str.casefold),
            },
            "top_dirs": [
                {"path": path, "file_count": count}
                for path, count in sorted(
                    directory_counts.items(), key=lambda item: (-item[1], item[0].casefold())
                )[:10]
            ],
        }

    @classmethod
    def build_tier2_artifacts(cls, target_dir: str, folders: list[str]) -> dict:
        """Scan only model-selected folders for module and structure evidence."""
        return cls._build_focused_artifacts(target_dir, folders, cls.TIER2_PATTERN, 40, 10)

    @classmethod
    def build_tier3_artifacts(cls, target_dir: str, folders: list[str]) -> dict:
        """Scan only model-selected application folders for confirmatory evidence."""
        return cls._build_focused_artifacts(target_dir, folders, cls.TIER3_PATTERN, 20, 5)

    @staticmethod
    def _iter_files(root: Path, folders: list[str] | None = None):
        allowed = None if folders is None else []
        if folders is not None:
            for folder in folders:
                if isinstance(folder, dict):
                    folder = folder.get("path", folder.get("name", ""))
                candidate = (root / str(folder).strip().strip("/\\")).resolve()
                if candidate == root or root in candidate.parents:
                    allowed.append(candidate)
        for path in sorted(
            (item for item in root.rglob("*") if item.is_file()),
            key=lambda item: item.relative_to(root).as_posix().casefold(),
        ):
            if allowed is None or any(path == folder or folder in path.parents for folder in allowed):
                yield path

    @staticmethod
    def _read_lines(path: Path):
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as stream:
                characters_read = 0
                for line_number, line in enumerate(stream, 1):
                    characters_read += len(line)
                    if characters_read > 1_000_000:
                        break
                    yield line_number, line
        except (OSError, UnicodeError):
            return

    @classmethod
    def _build_focused_artifacts(
        cls, target_dir: str, folders: list[str], pattern: re.Pattern, max_hits: int, max_snippets: int,
    ) -> dict:
        root = Path(target_dir).resolve()
        hits = []
        snippets = []
        matched_terms = []
        config_terms = []
        for path in cls._iter_files(root, folders if isinstance(folders, list) else []):
            relative = path.relative_to(root).as_posix()
            file_hits = []
            for line_number, line in cls._read_lines(path):
                if pattern.search(line):
                    entry = f'{relative}:{line_number}:{line.strip()[:240]}'
                    file_hits.append(entry)
                    for match in pattern.finditer(line):
                        groups = match.groups()
                        term = groups[0] if groups else ""
                        structure = groups[1] if len(groups) > 1 else ""
                        if term and term.casefold() not in {item.casefold() for item in matched_terms}:
                            matched_terms.append(term)
                        if structure and structure.casefold() not in {item.casefold() for item in config_terms}:
                            config_terms.append(structure)
                    if len(hits) < max_hits:
                        hits.append(entry)
            if file_hits and len(snippets) < max_snippets:
                snippets.append({"file": relative, "text": " ".join(file_hits[:3])[:600]})
        normalized_folders = []
        for folder in folders if isinstance(folders, list) else []:
            if isinstance(folder, dict):
                folder = folder.get("path", folder.get("name", ""))
            folder = str(folder).strip().strip("/\\")
            if folder and folder not in normalized_folders:
                normalized_folders.append(folder)
        return {
            "hits": hits,
            "snippets": snippets,
            "matched_terms": sorted(matched_terms, key=str.casefold),
            "config_terms": sorted(config_terms, key=str.casefold),
            "folders": sorted(normalized_folders, key=str.casefold),
        }

    @staticmethod
    def generate_directory_tree(target_dir: str, max_depth: int = 4) -> str:
        """Generates a lightweight text representation of the folder structure."""
        tree = []
        base_depth = target_dir.rstrip(os.sep).count(os.sep)
        
        for root, dirs, files in os.walk(target_dir):
            dirs.sort(key=str.casefold)
            files.sort(key=str.casefold)
            current_depth = root.count(os.sep) - base_depth
            if current_depth > max_depth:
                del dirs[:]
                continue
                
            indent = "  " * current_depth
            folder_name = os.path.basename(root)
            tree.append(f"{indent}[DIR] {folder_name}/")
            
            important_exts = ('.arxml', '.oil', '.xml', 'CMakeLists.txt', '.mk')
            important_files = [
                f for f in files 
                if f.endswith(important_exts) 
                or f.startswith('Makefile')
                or ('rte' in f.lower() and f.endswith('.json'))
            ]
            other_files = [f for f in files if f not in important_files]
            display_files = (important_files + other_files)[:5] 
            
            for f in display_files: 
                
                relative_path = os.path.relpath(os.path.join(root, f), target_dir)
                normalized_path = Path(relative_path).as_posix() 
                tree.append(f"{indent}  - {normalized_path}")
            
            if len(files) > 5:
                tree.append(f"{indent}  - ... ({len(files) - 5} more files)")
                
        return "\n".join(tree)

    @classmethod
    def search_config_files(
        cls,
        target_dir: str,
        extensions: list[str] | None = None,
        filename_patterns: list[str] | None = None,
    ) -> list[str]:
        """Find configuration candidates deterministically from search rules."""
        root = Path(target_dir).resolve()
        extensions = tuple(
            str(value).strip().lower()
            for value in (extensions or cls.DEFAULT_CONFIG_EXTENSIONS)
            if str(value).strip()
        )
        filename_patterns = tuple(
            str(value).strip()
            for value in (filename_patterns or cls.DEFAULT_CONFIG_PATTERNS)
            if str(value).strip()
        )

        def matches(path: Path) -> bool:
            name = path.name
            name_lower = name.lower()
            extension_match = any(
                name_lower.endswith(value) if value.startswith(".") else name_lower == value
                for value in extensions
            )
            for pattern in filename_patterns:
                if fnmatch.fnmatch(name, pattern) or fnmatch.fnmatch(name_lower, pattern.lower()):
                    return True
                try:
                    if re.search(pattern, name, re.IGNORECASE):
                        return True
                except re.error:
                    if pattern.lower() in name_lower:
                        return True
            return extension_match

        return sorted(
            (
                path.relative_to(root).as_posix()
                for path in root.rglob("*")
                if path.is_file() and matches(path)
            ),
            key=str.casefold,
        )
