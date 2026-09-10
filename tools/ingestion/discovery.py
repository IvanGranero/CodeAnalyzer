import os
import logging
import fnmatch
import re
from pathlib import Path

logger = logging.getLogger(__name__)

class RepoDiscoverer:
    DEFAULT_CONFIG_EXTENSIONS = (
        ".arxml", ".oil", ".cdd", ".rte.json", ".rte", ".xml",
        ".ini", ".cfg", ".mk", ".ld", ".sct",
    )
    DEFAULT_CONFIG_PATTERNS = (
        "Rte*", "*.arxml", "*.oil", "CMakeLists.txt", "Makefile", "*.ld",
    )

    @staticmethod
    def generate_directory_tree(target_dir: str, max_depth: int = 4) -> str:
        """Generates a lightweight text representation of the folder structure."""
        tree = []
        base_depth = target_dir.rstrip(os.sep).count(os.sep)
        
        for root, dirs, files in os.walk(target_dir):
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
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and matches(path)
        )
