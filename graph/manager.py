import logging
from typing import List, Dict, Any, Optional

from graph.db import GraphDB
# from graph.resolver import GraphResolver # Removed to fix circular import
from graph.nl2cypher import NL2CypherEngine
from graph.models import GraphNode, GraphEdge, IngestBatch

logger = logging.getLogger(__name__)

class GraphManager:
    def __init__(self, uri: str, user: str, password: str, llm_client: Any = None):
        logger.info("Initializing GraphManager...")
        self.db = GraphDB(uri, user, password)
        # NOTE: LLM context-building goes exclusively through
        # GraphResolver.serialize_function_neighborhood (see scan/orchestrator.py) -- the
        # previous GraphRetriever/graph/retrieve.py path queried a schema vocabulary
        # (USES, Variable, RunnableEntity, RtePort) that didn't match what's actually
        # ingested (READS_VAR/WRITES_VAR, GlobalVariable, HANDLES_UDS), was unreachable
        # from the real scan path, and has been removed rather than left as dead code.
        # Resolver initialization is done outside or lazily to avoid circular imports.
        self.nl_engine = NL2CypherEngine(self.db, llm_client) if llm_client else None
        self.db.initialize_schema()

    def close(self):
        self.db.close()

    def ingest_batch(self, batch: IngestBatch):
        node_dicts, edge_dicts = batch.to_neo4j_dicts()
        if node_dicts:
            self._ingest_nodes(node_dicts)
        if edge_dicts:
            self._ingest_edges(edge_dicts)

    def _ingest_nodes(self, node_dicts: List[Dict[str, Any]]):
        grouped_nodes = {}
        for nd in node_dicts:
            labels = set(nd.get('labels', []))
            labels.add("GraphNode") 
            label_str = ":" + ":".join(sorted(labels))
            if label_str not in grouped_nodes:
                grouped_nodes[label_str] = []
            grouped_nodes[label_str].append(nd)

        for label_str, batch in grouped_nodes.items():
            query = f"""
            UNWIND $batch AS record
            MERGE (n{label_str} {{id: record.id}})
            SET n += record.properties
            """
            self.db.ingest_batched(query, batch)

    # Which label a fuzzy (name-only) edge target should be scoped to, keyed by
    # relationship type. Scoping by label prevents e.g. a WRITES_VAR edge from
    # fuzzily landing on an unrelated Function/Macro/Stub node that happens to
    # share the same name (a real collision seen in production: a call target's
    # identifier was previously eligible to match a GlobalVariable-typed search).
    _FUZZY_TARGET_LABEL = {
        "CALLS": "Function",
        "READS_VAR": "GlobalVariable",
        "WRITES_VAR": "GlobalVariable",
        "DEPENDS_ON_TYPE": "TypeDefinition",
        "USES_MACRO": "MacroDefinition",
        "RECEIVES_SIGNAL": "NetworkSignal",
        "SENDS_SIGNAL": "NetworkSignal",
    }

    def _ingest_edges(self, edge_dicts: List[Dict[str, Any]]):
        grouped_edges = {}
        for ed in edge_dicts:
            rel_type = ed['type']
            if rel_type not in grouped_edges:
                grouped_edges[rel_type] = []
            grouped_edges[rel_type].append(ed)

        for rel_type, batch in grouped_edges.items():
            exact_batch = [b for b in batch if b.get('target_id')]
            fuzzy_batch = [b for b in batch if not b.get('target_id') and b.get('target_name')]

            if exact_batch:
                query_exact = f"""
                UNWIND $batch AS record
                MATCH (source:GraphNode {{id: record.source_id}})
                MATCH (target:GraphNode {{id: record.target_id}})
                MERGE (source)-[rel:{rel_type}]->(target)
                SET rel += record.properties, rel.resolution = 'exact'
                """
                self.db.ingest_batched(query_exact, exact_batch)

            if fuzzy_batch:
                # Creates stubs. We will garbage collect local var stubs later in resolver.py
                #
                # Two correctness fixes vs. the original query:
                #  1. The OPTIONAL MATCH is scoped by label (via _FUZZY_TARGET_LABEL), so a
                #     name can only match a node of the semantically correct type.
                #  2. The subquery returns at most ONE candidate (ORDER BY + LIMIT 1). The
                #     previous unbounded OPTIONAL MATCH fanned out to every node sharing that
                #     name anywhere in the graph, silently creating one edge per match -- this
                #     is what produced identical WRITES_VAR target ids across unrelated
                #     functions in different files/domains.
                target_label = self._FUZZY_TARGET_LABEL.get(rel_type, "GraphNode")
                query_fuzzy = f"""
                UNWIND $batch AS record
                MATCH (source:GraphNode {{id: record.source_id}})
                CALL (record) {{
                    OPTIONAL MATCH (target:{target_label} {{name: record.target_name}})
                    RETURN target
                    ORDER BY target.storage_uri
                    LIMIT 1
                }}
                WITH source, record, target,
                     COALESCE(target.id, "stub::" + record.target_name) AS final_id
                MERGE (final_target:GraphNode {{id: final_id}})
                ON CREATE SET final_target:Stub, final_target.name = record.target_name
                MERGE (source)-[rel:{rel_type}]->(final_target)
                SET rel += record.properties, rel.resolution = CASE WHEN target IS NULL THEN 'stub' ELSE 'fuzzy' END
                """
                self.db.ingest_batched(query_fuzzy, fuzzy_batch)

    def process_natural_language_query(self, user_query: str, allow_write: bool = False) -> Dict[str, Any]:
        if not self.nl_engine:
            raise ValueError("GraphManager was initialized without an LLM client.")
        return self.nl_engine.query_and_execute(user_query, allow_write=allow_write)
