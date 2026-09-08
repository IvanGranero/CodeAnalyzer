"""Source-file discovery for C/C++ ingestion."""

from pathlib import Path

SOURCE_SUFFIXES = frozenset({".c", ".cpp", ".h", ".hpp"})


def discover_source_files(root: str | Path) -> list[Path]:
    return sorted(
        path for path in Path(root).rglob("*")
        if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
    )


def is_vendor_file(path: Path, vendor_folders: set[str]) -> bool:
    return any(part.lower() in vendor_folders for part in path.parts)
