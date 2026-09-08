"""Backward-compatible facade for the domain-specific storage adapters."""

import os
from pathlib import Path
from typing import Any

from app.storage.json_file_store import JsonFileStore


class ReportStore:
    """Persist report dictionaries with one consistent atomic-write policy."""

    def __init__(self, directory: str | os.PathLike[str]):
        self._store = JsonFileStore(directory)
        self.directory = Path(directory)

    def save(self, name: str, report: dict[str, Any]) -> Path:
        return self._store.save(name, report)

    def load(self, name: str) -> dict[str, Any]:
        return self._store.load(name)

    def load_all(self, *, exclude: set[str] | None = None) -> dict[str, dict[str, Any]]:
        return self._store.load_all(exclude=exclude)

    @staticmethod
    def _filename(name: str) -> str:
        return JsonFileStore.filename(name)