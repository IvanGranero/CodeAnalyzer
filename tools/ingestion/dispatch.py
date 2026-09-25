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

    def classify(self, path: Path) -> str:
        """Return a schema-oriented parser category for coverage reporting."""
        parser = self.parsers.get(path.suffix.lower())
        if parser is None:
            return "unsupported"
        if parser.__class__.__name__ == "RteJsonParser":
            name = path.name.casefold()
            if "usedtemplate" in name:
                return "rte_template_metadata"
            if "rteanalyzer" in name:
                return "rte_analyzer_config"
            return "rte_json"
        if parser.__class__.__name__ == "ARXMLParser":
            return "arxml_ecuc"
        return parser.__class__.__name__

    def result(self, path: Path) -> dict:
        parser = self.parsers.get(path.suffix.lower())
        result = getattr(parser, "last_result", None)
        return dict(result) if isinstance(result, dict) else {"status": "parsed", "flow_count": None}
