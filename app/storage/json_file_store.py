"""Atomic JSON file persistence used by domain-specific repositories."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any


class JsonFileStore:
    def __init__(self, directory: str | os.PathLike[str]):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, name: str, value: dict[str, Any]) -> Path:
        path = self.directory / self.filename(name)
        temporary_path: Path | None = None
        try:
            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{path.stem}.", suffix=".tmp", dir=self.directory
            )
            temporary_path = Path(temporary_name)
            with os.fdopen(fd, "w", encoding="utf-8") as file:
                json.dump(value, file)
                file.flush()
                os.fsync(file.fileno())
            os.replace(temporary_path, path)
            return path
        finally:
            if temporary_path is not None:
                temporary_path.unlink(missing_ok=True)

    def load(self, name: str) -> dict[str, Any]:
        with (self.directory / self.filename(name)).open(encoding="utf-8") as file:
            value = json.load(file)
        if not isinstance(value, dict):
            raise ValueError(f"Stored JSON object expected for {name}")
        return value

    def load_all(self, *, exclude: set[str] | None = None) -> dict[str, dict[str, Any]]:
        excluded = exclude or set()
        values = {}
        for path in sorted(self.directory.glob("*.json")):
            if path.name in excluded:
                continue
            with path.open(encoding="utf-8") as file:
                value = json.load(file)
            if isinstance(value, dict):
                values[path.stem] = value
        return values

    @staticmethod
    def filename(name: str) -> str:
        return name if name.endswith(".json") else f"{name}.json"