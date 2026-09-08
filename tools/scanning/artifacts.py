"""Safe retrieval of evidence requested during a scan."""

import json
import logging
from typing import Any, Callable

from tools.scanning.contracts import ArtifactRequest, ArtifactResult, EvidenceStatus

logger = logging.getLogger(__name__)


class ArtifactRetriever:
    def __init__(self, tools_engine: Any, graph_resolver: Any, source_getter: Callable[[str], str]):
        self.tools_engine = tools_engine
        self.graph_resolver = graph_resolver
        self.source_getter = source_getter

    def fetch(self, request: dict[str, Any]) -> str:
        result = self.retrieve(request)
        return f"FOLLOW-UP ARTIFACT ({result.kind}) [{result.status.value}]:\n{result.content}"

    def retrieve(self, request: dict[str, Any]) -> ArtifactResult:
        request = ArtifactRequest.model_validate(request)
        logger.info(
            "[Follow-up] Requesting artifact kind='%s' function='%s' symbol='%s' file='%s' macro='%s'",
            request.kind,
            request.function,
            request.symbol,
            request.file,
            request.macro,
        )

        if request.kind in {"caller_impl", "callee_impl", "full_function_body"} and request.function:
            snippet = self.source_getter(request.function)
            if snippet.startswith("// Error") or snippet.startswith("// Source code not found"):
                return ArtifactResult(status=EvidenceStatus.NOT_FOUND, kind=request.kind, content=snippet)
            return ArtifactResult(
                status=EvidenceStatus.FOUND,
                kind=request.kind,
                content=f"Function: {request.function}\n\n{snippet}",
            )

        if request.kind == "global_initializer" and request.symbol:
            query = """
            MATCH (n) WHERE n.name = $symbol
            RETURN n.name AS name, labels(n) AS labels, n.storage_uri AS file, n.byte_span AS span
            ORDER BY CASE WHEN n.storage_uri ENDS WITH '.h' THEN 1 ELSE 0 END ASC
            LIMIT 5
            """
            try:
                with self.tools_engine.db.driver.session() as session:
                    rows = session.run(query, symbol=request.symbol).data()
                if rows:
                    return ArtifactResult(
                        status=EvidenceStatus.FOUND,
                        kind=request.kind,
                        content=json.dumps(rows, ensure_ascii=False, separators=(",", ":")),
                    )
            except Exception as exc:
                logger.warning("Failed to resolve global initializer '%s': %s", request.symbol, exc)
            return ArtifactResult(
                status=EvidenceStatus.NOT_FOUND,
                kind=request.kind,
                content=f"Symbol {request.symbol} not found in graph.",
            )

        if request.kind == "header_macro" and request.macro:
            content = self.tools_engine.get_macro_definition(request.macro)
            status = EvidenceStatus.FOUND if not content.startswith(("Error", "System Note")) else EvidenceStatus.NOT_FOUND
            return ArtifactResult(status=status, kind=request.kind, content=content)

        if request.kind == "related_taint_path":
            getter = getattr(self.graph_resolver, "get_verified_taint_paths", None)
            if getter and request.function:
                paths = getter(request.function)
                if paths:
                    return ArtifactResult(
                        status=EvidenceStatus.FOUND,
                        kind=request.kind,
                        content=json.dumps(paths, ensure_ascii=False),
                    )
            return ArtifactResult(
                status=EvidenceStatus.NOT_FOUND,
                kind=request.kind,
                content="No verified related taint path was found.",
            )

        return ArtifactResult(
            status=EvidenceStatus.UNSUPPORTED,
            kind=request.kind,
            content="No safe retriever is implemented for this artifact kind.",
        )

    @staticmethod
    def key(request: dict[str, Any]) -> tuple:
        request = ArtifactRequest.model_validate(request)
        return (
            request.kind,
            request.file,
            request.function,
            request.symbol,
            request.macro,
            json.dumps(request.span, sort_keys=True),
        )