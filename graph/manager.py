import logging
from typing import List, Dict, Any, Optional

from graph.db import GraphDB
from graph.retriever import GraphRetriever
# from graph.resolver import GraphResolver # Removed to fix circular import
from graph.nl2cypher import NL2CypherEngine
from graph.models import GraphNode, GraphEdge, IngestBatch

logger = logging.getLogger(__name__)

class GraphManager:
    def __init__(self, uri: str, user: str, password: str, llm_client: Any = None):
        logger.info("Initializing GraphManager...")
        self.db = GraphDB(uri, user, password)
        self.retriever = GraphRetriever(self.db)
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
                SET rel += record.properties
                """
                self.db.ingest_batched(query_exact, exact_batch)

            if fuzzy_batch:
                # Creates stubs. We will garbage collect local var stubs later in resolver.py
                query_fuzzy = f"""
                UNWIND $batch AS record
                MATCH (source:GraphNode {{id: record.source_id}})
                OPTIONAL MATCH (target:GraphNode {{name: record.target_name}})
                WITH source, record, target, 
                     COALESCE(target.id, "stub::" + record.target_name) AS final_id
                MERGE (final_target:GraphNode {{id: final_id}})
                ON CREATE SET final_target:Stub, final_target.name = record.target_name
                MERGE (source)-[rel:{rel_type}]->(final_target)
                SET rel += record.properties
                """
                self.db.ingest_batched(query_fuzzy, fuzzy_batch)

    def get_context_for_llm(self, function_name: str) -> str:
        return self.retriever.build_scan_prompt_context(function_name)

    def process_natural_language_query(self, user_query: str) -> Dict[str, Any]:
        if not self.nl_engine:
            raise ValueError("GraphManager was initialized without an LLM client.")
        return self.nl_engine.query_and_execute(user_query)
