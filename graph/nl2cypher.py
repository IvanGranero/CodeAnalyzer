import logging
import re
from typing import Dict, Any, List, Optional
# Assuming you have access to your GraphDB instance from db.py
from graph.db import GraphDB
from graph.models import EdgeType, NodeLabel

logger = logging.getLogger(__name__)

# Clauses that mutate the graph. An LLM-generated query containing any of these is
# rejected unless the caller explicitly opts in via allow_write=True. Without this,
# an NL query (which can itself be influenced by untrusted content flowing through the
# discovery/ingest LLM prompts) could run e.g. "MATCH (n) DETACH DELETE n" with full
# write privileges against the production graph.
_WRITE_CLAUSE_RE = re.compile(r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV)\b", re.IGNORECASE)

class NL2CypherEngine:
    def __init__(self, db: GraphDB, llm_client: Any):
        """
        Args:
            db: Instance of your GraphDB.
            llm_client: A callable/interface to your /llm module to generate text.
        """
        self.db = db
        self.llm_client = llm_client
        
        # Domain-specific examples for the prompt (Few-Shot), kept in sync with the
        # actual node/edge vocabulary in graph/models.py -- previously these referenced
        # a "USES"/"Variable" schema that was never ingested (the real relationships are
        # READS_VAR/WRITES_VAR against GlobalVariable), which could steer the LLM into
        # generating cypher against a vocabulary that doesn't exist in this graph.
        self.few_shot_examples = [
            {
                "question": "Find all functions that call Rte_Write_PortA.",
                "cypher": "MATCH (f:Function)-[:CALLS]->(target:Function {name: 'Rte_Write_PortA'}) RETURN f"
            },
            {
                "question": "Show me the global variables read or written by the function 'EcuM_Init'.",
                "cypher": "MATCH (f:Function {name: 'EcuM_Init'})-[r:READS_VAR|WRITES_VAR]->(v:GlobalVariable) RETURN v.name, type(r)"
            },
            {
                "question": "Which functions handle UDS DID 0xF190?",
                "cypher": "MATCH (f:Function)-[:HANDLES_UDS]->(u:UdsService {did: 'F190'}) RETURN f.name, u.source"
            },
            {
                "question": "Tag function 'Vulnerable_Func' as reviewed.",
                "cypher": "MATCH (f:Function {name: 'Vulnerable_Func'}) SET f.status = 'reviewed' RETURN f"
            }
        ]

    @staticmethod
    def _static_schema_summary() -> str:
        """
        Builds the fallback schema description directly from graph/models.py's
        NodeLabel/EdgeType enums, so it can never drift out of sync with what's
        actually ingested the way a hand-typed schema string could.
        """
        labels = ", ".join(label.value for label in NodeLabel)
        edge_types = ", ".join(edge.value for edge in EdgeType)
        return (
            f"Node labels: {labels}\n"
            f"Relationship types: {edge_types}\n"
            "Every node also carries the generic label GraphNode. "
            "Common properties: Function.name, Function.storage_uri, Function.is_dead_code; "
            "GlobalVariable.name; UdsService.did, UdsService.source ('dcm_did_table'|'heuristic'); "
            "edges carry a 'resolution' property ('exact'|'fuzzy'|'stub')."
        )

    def _get_live_schema(self) -> str:
        """Retrieves the current schema directly from Neo4j, falling back to the static
        enum-derived summary (always in sync with graph/models.py) if APOC is unavailable."""
        query = "CALL apoc.meta.schema() YIELD value RETURN value"
        try:
            # Requires APOC plugin installed in Neo4j
            result = self.db.retrieve(query)
            if result:
                return str(result[0]['value'])
        except Exception as e:
            logger.warning(f"Could not retrieve schema via APOC: {e}")
        return self._static_schema_summary()

    def _build_prompt(self, user_query: str, schema: str) -> str:
        """Constructs the prompt with schema and examples."""
        prompt = f"""
You are an expert Neo4j Cypher developer working on an AutoSAR Code Property Graph.
Convert the user's natural language question into a valid Cypher query.

DATABASE SCHEMA:
{schema}

EXAMPLES:
"""
        for ex in self.few_shot_examples:
            prompt += f"Q: {ex['question']}\nA: {ex['cypher']}\n\n"

        prompt += f"USER QUESTION: {user_query}\n"
        prompt += "Return ONLY the raw Cypher query text, without markdown formatting or explanation."
        return prompt

    def query_and_execute(self, user_query: str, max_retries: int = 2, allow_write: bool = False) -> Dict[str, Any]:
        """
        Translates NL to Cypher, executes it, and includes a retry loop for syntax errors.

        By default this only ever executes read queries: if the generated Cypher contains
        a mutating clause (CREATE/MERGE/DELETE/DETACH/SET/REMOVE/DROP/LOAD CSV) it is
        rejected instead of run. Pass allow_write=True only for an explicit, reviewed
        admin action -- never for an ordinary user-facing NL query.
        """
        schema = self._get_live_schema()
        prompt = self._build_prompt(user_query, schema)

        attempt = 0
        last_error = ""
        cypher_query = ""

        while attempt <= max_retries:
            if attempt > 0:
                # Append the error to the prompt for correction
                correction_prompt = prompt + f"\n\nYour last query failed with this error:\n{last_error}\nPlease fix the syntax and try again."
                cypher_query = self.llm_client.generate(correction_prompt)
            else:
                cypher_query = self.llm_client.generate(prompt)

            # Clean up the output in case the LLM ignored instructions and used markdown
            cypher_query = cypher_query.replace("```cypher", "").replace("```", "").strip()

            if _WRITE_CLAUSE_RE.search(cypher_query) and not allow_write:
                logger.warning(f"Rejected LLM-generated Cypher containing a write clause: {cypher_query}")
                return {
                    "status": "rejected",
                    "message": "Generated query contains a write clause (CREATE/MERGE/DELETE/DETACH/SET/REMOVE/DROP). "
                                "Re-run with allow_write=True only after explicit review.",
                    "cypher": cypher_query,
                }

            logger.info(f"Attempt {attempt + 1}: Executing generated Cypher: {cypher_query}")

            try:
                with self.db.driver.session() as session:
                    exec_fn = session.execute_write if allow_write else session.execute_read
                    result = exec_fn(lambda tx: list(tx.run(cypher_query)))

                return {
                    "status": "success",
                    "cypher": cypher_query,
                    "data": [record.data() for record in result]
                }
            except Exception as e:
                logger.error(f"Cypher execution failed: {e}")
                last_error = str(e)
                attempt += 1

        return {
            "status": "error",
            "message": f"Failed after {max_retries} retries. Last error: {last_error}",
            "failed_cypher": cypher_query
        }
