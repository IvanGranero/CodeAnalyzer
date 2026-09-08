"""Configuration parser dispatch for ingestion."""

from pathlib import Path
from typing import Any


class ConfigParserDispatcher:
    def __init__(self, parsers: dict[str, Any]):
        self.parsers = {suffix.lower(): parser for suffix, parser in parsers.items()}

    def parse(self, path: Path) -> bool:
        parser = self.parsers.get(path.suffix.lower())
        if parser is None:
            return False
        parser.parse(str(path))
        return True
