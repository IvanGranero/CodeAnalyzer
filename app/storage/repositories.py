"""Domain-specific persistence boundaries over the JSON file store."""

from typing import Any

from app.storage.json_file_store import JsonFileStore
from tools.scanning.contracts import ScanReport


class ScanCacheRepository:
    def __init__(self, directory: str):
        self.store = JsonFileStore(directory)

    def save(self, name: str, report: dict[str, Any]) -> None:
        validated = ScanReport.model_validate(report)
        self.store.save(name, validated.as_report_dict())

    def load_all(self, *, exclude: set[str] | None = None) -> dict[str, dict[str, Any]]:
        return self.store.load_all(exclude=exclude)


class ExploitReportRepository:
    def __init__(self, directory: str):
        self.store = JsonFileStore(directory)

    def save(self, name: str, report: dict[str, Any]) -> None:
        self.store.save(name, report)

    def load(self, name: str) -> dict[str, Any]:
        return self.store.load(name)