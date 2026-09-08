"""Source URI and byte-span normalization for security reports."""

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceLocation:
    path: str
    line: int
    file_uri: str


class SourceLocationResolver:
    def parse_path(self, uri: str | None) -> str:
        if not uri or uri == "Unknown":
            return "Unknown"
        path = uri[7:] if uri.startswith("file://") else uri
        if os.name == "nt" and path.startswith("/") and ":" in path:
            path = path[1:]
        return os.path.normpath(path)

    def line_from_span(self, path: str, byte_span: str | None) -> int:
        if not path or path == "Unknown" or not isinstance(byte_span, str):
            return 1
        try:
            start = int(byte_span.split("-", 1)[0])
        except (ValueError, IndexError):
            return 1
        try:
            return Path(path).read_bytes()[:max(0, start)].count(b"\n") + 1
        except (OSError, ValueError):
            return 1

    def resolve(self, uri: str | None, byte_span: str | None) -> SourceLocation:
        path = self.parse_path(uri)
        line = self.line_from_span(path, byte_span)
        relative = os.path.relpath(path, os.getcwd()).replace("\\", "/")
        file_uri = f"file:///{relative}" if os.name == "nt" else f"file://{relative}"
        return SourceLocation(path=path, line=line, file_uri=file_uri)
