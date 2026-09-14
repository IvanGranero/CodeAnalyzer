"""Graph services exposed to application workflows."""

__all__ = ["GraphService"]


def __getattr__(name: str):
	if name == "GraphService":
		from tools.graph.graph_service import GraphService

		return GraphService
	raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
