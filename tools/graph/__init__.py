"""Graph services exposed to application workflows."""

__all__ = ["GraphService", "GraphQueryService", "GraphProjection"]


def __getattr__(name: str):
	if name == "GraphService":
		from tools.graph.graph_service import GraphService

		return GraphService
	if name == "GraphQueryService":
		from tools.graph.query_service import GraphQueryService

		return GraphQueryService
	if name == "GraphProjection":
		from tools.graph.graph_projection import GraphProjection

		return GraphProjection
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
