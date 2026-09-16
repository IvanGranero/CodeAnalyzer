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
                # Create a relative path from the root and normalize separators
                relative_path = os.path.relpath(os.path.join(root, f), target_dir)
                normalized_path = Path(relative_path).as_posix() # <-- POSIX uses '/'
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
