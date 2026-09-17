from __future__ import annotations

from typing import Any, Iterable, Mapping

import networkx as nx


class GraphProjection:
    """NetworkX projection and serializable result for one graph query."""

    def __init__(self, nodes: Iterable[Mapping[str, Any]], edges: Iterable[Mapping[str, Any]]) -> None:
        self.graph = nx.MultiDiGraph()
        for node in nodes:
            node_id = str(node["id"])
            attributes = dict(node)
            attributes.pop("id", None)
            self.graph.add_node(node_id, **attributes)
        for edge in edges:
            source = str(edge["source"])
            target = str(edge["target"])
            attributes = dict(edge)
            attributes.pop("source", None)
            attributes.pop("target", None)
            self.graph.add_edge(source, target, **attributes)

    def to_dict(self) -> dict[str, list[dict[str, Any]]]:
        return {
            "nodes": [
                {"id": node_id, **dict(attributes)}
                for node_id, attributes in self.graph.nodes(data=True)
            ],
            "edges": [
                {"source": source, "target": target, **dict(attributes)}
                for source, target, attributes in self.graph.edges(data=True)
            ],
        }

    def to_networkx(self) -> nx.MultiDiGraph:
        return self.graph


def project_records(records: Iterable[Mapping[str, Any]]) -> GraphProjection:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for record in records:
        for value in record.values():
            if _is_node(value):
                node = _node_dict(value)
                nodes[node["id"]] = node
            elif _is_relationship(value):
                edge = _edge_dict(value)
                edges.append(edge)
                for endpoint in (value.start_node, value.end_node):
                    if _is_node(endpoint):
                        node = _node_dict(endpoint)
                        nodes[node["id"]] = node
    return GraphProjection(nodes.values(), edges)


def _is_node(value: Any) -> bool:
    return hasattr(value, "element_id") and hasattr(value, "labels") and hasattr(value, "items")


def _is_relationship(value: Any) -> bool:
    return hasattr(value, "start_node") and hasattr(value, "end_node") and hasattr(value, "type")


def _node_dict(node: Any) -> dict[str, Any]:
    properties = dict(node.items())
    return {
        "id": str(node.element_id),
        "labels": sorted(str(label) for label in node.labels),
        **properties,
    }


def _edge_dict(edge: Any) -> dict[str, Any]:
    return {
        "source": str(edge.start_node.element_id),
        "target": str(edge.end_node.element_id),
        "relationship": str(edge.type),
        **dict(edge.items()),
    }
