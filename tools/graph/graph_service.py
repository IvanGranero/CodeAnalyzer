"""Application service for graph ingestion and resolution."""

from typing import Any

from tools.graph.manager import GraphManager
from tools.graph.query_service import GraphQueryService


class GraphService:
    """Own graph lifecycle operations without exposing database details."""

    def __init__(self, graph: GraphManager):
        self.graph = graph
        self.query_service = GraphQueryService(graph.db, graph.nl_engine)

    @property
    def resolver(self):
        return self.graph.resolver

    def ingest_batch(self, batch: Any) -> None:
        self.graph.ingest_batch(batch)

    def resolve(self) -> None:
        self.graph.resolver.run_all_passes()

    def close(self) -> None:
        self.graph.close()

    def ask(self, question: str) -> dict[str, Any]:
        return self.query_service.ask(question)
