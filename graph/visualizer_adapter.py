import logging
from neo4j.graph import Node, Relationship, Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class GraphVisualizerAdapter:
    @staticmethod
    def format_for_ui(neo4j_records: List[Dict[str, Any]]) -> Dict[str, List[Dict]]:
        """
        Parses raw Neo4j driver records into a deduplicated nodes/edges dictionary 
        suitable for JavaScript graph visualizers.
        """
        nodes_dict = {}
        edges_dict = {}

        def process_node(node: Node):
            # Use element_id (Neo4j 5+) or id (older versions) as the unique identifier
            node_id = str(getattr(node, 'element_id', getattr(node, 'id', '')))
            if node_id and node_id not in nodes_dict:
                nodes_dict[node_id] = {
                    "id": node_id,
                    "labels": list(node.labels),
                    "properties": dict(node)
                }

        def process_relationship(rel: Relationship):
            rel_id = str(getattr(rel, 'element_id', getattr(rel, 'id', '')))
            if rel_id and rel_id not in edges_dict:
                # Safely extract start and end node IDs
                source_id = str(getattr(rel.start_node, 'element_id', getattr(rel.start_node, 'id', '')))
                target_id = str(getattr(rel.end_node, 'element_id', getattr(rel.end_node, 'id', '')))
                
                edges_dict[rel_id] = {
                    "id": rel_id,
                    "source": source_id,
                    "target": target_id,
                    "type": rel.type,
                    "properties": dict(rel)
                }

        # Iterate through the rows returned by the query
        for record in neo4j_records:
            # record is a dictionary representing a row returned by Neo4j
            for key, value in record.items():
                if isinstance(value, Node):
                    process_node(value)
                elif isinstance(value, Relationship):
                    process_relationship(value)
                elif isinstance(value, Path):
                    # Paths contain multiple nodes and relationships sequentially
                    for node in value.nodes:
                        process_node(node)
                    for rel in value.relationships:
                        process_relationship(rel)
                elif isinstance(value, list):
                    # Queries that use collect() return lists of nodes/edges
                    for item in value:
                        if isinstance(item, Node):
                            process_node(item)
                        elif isinstance(item, Relationship):
                            process_relationship(item)
                else:
                    # Scalar values (strings, ints) returned by queries are ignored 
                    # in the visual graph representation unless explicitly mapped.
                    pass

        logger.debug(f"Visualizer adapter processed {len(nodes_dict)} nodes and {len(edges_dict)} edges.")
        
        return {
            "nodes": list(nodes_dict.values()),
            "edges": list(edges_dict.values())
        }
