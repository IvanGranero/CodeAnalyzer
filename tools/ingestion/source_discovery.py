from pathlib import Path

SOURCE_SUFFIXES = frozenset({".c", ".cpp", ".h", ".hpp"})

def discover_source_files(root: str | Path) -> list[Path]:
    root = Path(root).resolve()
    return sorted(
        (
            path for path in root.rglob("*")
            if path.is_file() and path.suffix.lower() in SOURCE_SUFFIXES
        ),
        key=lambda path: path.relative_to(root).as_posix().casefold(),
    )

def is_vendor_file(path: Path, vendor_folders: set[str], root: str | Path | None = None) -> bool:
    """Return whether a source file is below a configured vendor directory.

    Compare normalized relative path components so the result is independent of
    Windows drive prefixes and path separators.
    """
    path = Path(path).resolve()
    if root is not None:
        root = Path(root).resolve()
        try:
            parts = path.relative_to(root).parts
        except ValueError:
            parts = path.parts
    else:
        parts = path.parts
    normalized_folders = {str(folder).strip().strip("/\\").casefold() for folder in vendor_folders}
    return any(part.casefold() in normalized_folders for part in parts)
