import logging
from typing import List, Dict, Any, Optional

from graph.db import GraphDB
from graph.retriever import GraphRetriever
from graph.nl2cypher import NL2CypherEngine
from graph.models import GraphNode, GraphEdge, IngestBatch

logger = logging.getLogger(__name__)

class GraphManager:
    def __init__(self, uri: str, user: str, password: str, llm_client: Any = None):
        """
        Initializes the Graph subsystem, establishing DB connections and 
        wiring up the sub-components.
        """
        logger.info("Initializing GraphManager...")
        
        # 1. Initialize the Core Database Connection
        self.db = GraphDB(uri, user, password)
        
        # 2. Initialize Sub-modules
        self.retriever = GraphRetriever(self.db)
        self.nl_engine = NL2CypherEngine(self.db, llm_client) if llm_client else None
        
        # Ensure schema/indexes exist (runs idempotently)
        self.db.initialize_schema()

    def close(self):
        """Cleanly shutdown the database driver."""
        self.db.close()

    # ==========================================
    # WRITE: Ingestion API (Used by your Parsers)
    # ==========================================

    def ingest_batch(self, batch: IngestBatch):
        """
        Takes a validated Pydantic IngestBatch and safely writes it to Neo4j.
        Handles nodes and edges in separate optimized UNWIND transactions.
        """
        node_dicts, edge_dicts = batch.to_neo4j_dicts()
        
        if node_dicts:
            self._ingest_nodes(node_dicts)
        if edge_dicts:
            self._ingest_edges(edge_dicts)

    def _ingest_nodes(self, node_dicts: List[Dict[str, Any]]):
        """Groups nodes by their labels and ingests them using standard Cypher."""
        grouped_nodes = {}
        for nd in node_dicts:
            # --- FIX: Ensure every node gets the base GraphNode label ---
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
        """Groups edges by relationship type and applies memory-safe Late-Binding logic."""
        grouped_edges = {}
        for ed in edge_dicts:
            rel_type = ed['type']
            if rel_type not in grouped_edges:
                grouped_edges[rel_type] = []
            grouped_edges[rel_type].append(ed)

        for rel_type, batch in grouped_edges.items():
            
            # Split the batch: Edges with exact IDs vs Edges with fuzzy names
            exact_batch = [b for b in batch if b.get('target_id')]
            fuzzy_batch = [b for b in batch if not b.get('target_id') and b.get('target_name')]

            # 1. Exact ID Match (Blazing fast, used for UDS/Network/Resolved nodes)
            if exact_batch:
                query_exact = f"""
                UNWIND $batch AS record
                MATCH (source:GraphNode {{id: record.source_id}})
                MATCH (target:GraphNode {{id: record.target_id}})
                MERGE (source)-[rel:{rel_type}]->(target)
                SET rel += record.properties
                """
                self.db.ingest_batched(query_exact, exact_batch)

            # 2. Fuzzy Name Match (With automatic memory-safe Stub generation)
            if fuzzy_batch:
                query_fuzzy = f"""
                UNWIND $batch AS record
                MATCH (source:GraphNode {{id: record.source_id}})
                
                // Try to find the real node globally by name
                OPTIONAL MATCH (target:GraphNode {{name: record.target_name}})
                
                // If it wasn't found, fallback to creating a stub deterministically
                WITH source, record, target, 
                     COALESCE(target.id, "stub::" + record.target_name) AS final_id
                     
                // Merge the final target (this will either match the real node or create a stub)
                MERGE (final_target:GraphNode {{id: final_id}})
                ON CREATE SET final_target:Function, final_target:Stub, final_target.name = record.target_name
                
                // Connect them
                MERGE (source)-[rel:{rel_type}]->(final_target)
                SET rel += record.properties
                """
                self.db.ingest_batched(query_fuzzy, fuzzy_batch)

    # ==========================================
    # READ: Retrieval API (Used by /scan module)
    # ==========================================

    def get_context_for_llm(self, function_name: str) -> str:
        """
        Directly used by the /scan module to inject graph context into the LLM prompt.
        """
        return self.retriever.build_scan_prompt_context(function_name)

    # ==========================================
    # READ/WRITE: HMI / UI API (Used by /hmi module)
    # ==========================================

    def process_natural_language_query(self, user_query: str) -> Dict[str, Any]:
        """
        Used by the UI/CLI to allow the user to talk to the graph.
        Returns visualizer-ready JSON.
        """
        if not self.nl_engine:
            raise ValueError("GraphManager was initialized without an LLM client. NL2Cypher is disabled.")
            
        return self.nl_engine.query_and_execute(user_query)
