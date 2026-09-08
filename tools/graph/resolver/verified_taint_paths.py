"""Verified UDS-to-function path retrieval."""

import logging
from typing import Any

logger = logging.getLogger(__name__)


def get_verified_taint_paths(db: Any, func_name: str, max_hops: int = 8) -> list[dict[str, Any]]:
    """Return only UDS-to-function paths backed by graph relationships."""
    max_hops = max(0, min(max_hops, 12))
    query = f"""
    MATCH (entry:Function)-[:HANDLES_UDS]->(uds:UdsService)
    WHERE entry.name = $func_name
    RETURN [entry.name, uds.did] AS nodes,
           ['HANDLES_UDS'] AS relationships,
           uds.did AS did,
           coalesce(uds.source, 'heuristic') AS source
    UNION
    MATCH (entry:Function)-[:HANDLES_UDS]->(uds:UdsService),
          path=(entry)-[:CALLS*1..{max_hops}]->(target:Function {{name: $func_name}})
    RETURN [entry.name] + [node IN nodes(path) | node.name] AS nodes,
           ['HANDLES_UDS'] + [rel IN relationships(path) | type(rel)] AS relationships,
           uds.did AS did,
           coalesce(uds.source, 'heuristic') AS source
    LIMIT 25
    """
    try:
        with db.driver.session() as session:
            rows = session.run(query, func_name=func_name).data()
        return [
            {
                "status": "verified",
                "resolution": "exact_graph_path",
                "provenance": "neo4j:HANDLES_UDS+CALLS",
                "function": func_name,
                "did": row.get("did"),
                "source": row.get("source"),
                "nodes": row.get("nodes", []),
                "relationships": row.get("relationships", []),
            }
            for row in rows
        ]
    except Exception as exc:
        logger.warning("Failed to retrieve verified taint paths for %s: %s", func_name, exc)
        return []
