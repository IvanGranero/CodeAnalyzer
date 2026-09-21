import logging
import re
from typing import Dict, Any, List, Optional

from neo4j import Query
from tools.graph.db import GraphDB
from tools.graph.models import EdgeType, NodeLabel

logger = logging.getLogger(__name__)

QUERY_TIMEOUT_SECONDS = 15
MAX_RESULT_ROWS = 200





_WRITE_CLAUSE_RE = re.compile(
    r"\b(CREATE|MERGE|DELETE|DETACH|SET|REMOVE|DROP|LOAD\s+CSV|FOREACH)\b"
    r"|\bCALL\s*\{",
    re.IGNORECASE,
)

class NL2CypherEngine:
    def __init__(self, db: GraphDB, llm_client: Any):
        """
        Args:
            db: Instance of your GraphDB.
            llm_client: A callable/interface to your /llm module to generate text.
        """
        self.db = db
        self.llm_client = llm_client
        
        
        
        
        
        
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
            with self.db.driver.session() as session:
                result = session.run(
                    Query(query, timeout=QUERY_TIMEOUT_SECONDS)
                ).fetch(1)
            if result:
                return str(result[0]['value'])
        except Exception as e:
            logger.debug("APOC schema procedure unavailable; using static graph schema: %s", e)
        return self._static_schema_summary()

    def _build_prompt(self, user_query: str, schema: str) -> str:
        """Constructs the prompt with schema and examples."""
        prompt = f"""
You are an expert Neo4j Cypher developer working on an AutoSAR Code Property Graph.
Convert the user's natural language question into a valid, read-only Cypher query.

DATABASE SCHEMA:
{schema}

QUERY RULES:
- Available node labels include Function, GlobalVariable, UdsService, NetworkSignal, TypeDefinition, MacroDefinition, OsTask, OsIsr, and OsResource.
- Available relationships include CALLS, HANDLES_UDS, READS_VAR, WRITES_VAR, RECEIVES_SIGNAL, SENDS_SIGNAL, IMPLEMENTS_TASK, USES_MACRO, OS_LOCK_ACTION, RTE_DATA_FLOW, and LOCATED_IN.
- UDS identifiers are stored on UdsService.did or UdsService.rid as four-character uppercase hexadecimal strings without the 0x prefix.
- For caller/callee or UDS questions, return the relevant nodes and relationships when possible, not only scalar names.
- Every query must be bounded. Include a LIMIT clause for row-producing queries; never scan or return an unbounded collection.
- Never invent a function named 'did' or 'dids' when the question contains a DID/RID identifier.
- When the user question contains PREVIOUS_RESULT_SCOPE (mandatory), preserve that scope in the Cypher. Restrict every Function variable relevant to the answer with an exact name-membership predicate such as `f.name IN [...]`; never broaden the query beyond the listed names.

EXAMPLES:
"""
        for ex in self.few_shot_examples:
            prompt += f"Q: {ex['question']}\nA: {ex['cypher']}\n\n"

        prompt += f"USER QUESTION: {user_query}\n"
        prompt += "Return ONLY the raw Cypher query text, without markdown formatting or explanation."
        return prompt

    def query_and_execute(self, user_query: str, max_retries: int = 2, allow_write: bool = False) -> Dict[str, Any]:
        """
        Translates NL to Cypher, executes it, and retries failed or empty queries.

        By default this only ever executes read queries: if the generated Cypher contains
        a mutating clause (including CREATE/MERGE/DELETE/DETACH/SET/REMOVE/DROP,
        LOAD CSV, FOREACH, or write-capable subqueries) it is
        rejected instead of run.
        """
        schema = self._get_live_schema()
        prompt = self._build_prompt(user_query, schema)

        attempt = 0
        last_error = ""
        cypher_query = ""
        empty_result_retry = False

        while attempt <= max_retries:
            if attempt > 0:
                if empty_result_retry:
                    correction_prompt = prompt + (
                        "\n\nYour last read-only query executed successfully but returned no records. "
                        "Reformulate the query to test a plausible alternative interpretation of "
                        "the user's question. Prefer case-insensitive matching with toLower() and "
                        "CONTAINS when an exact name match may be too strict, or use a relevant "
                        "alternate relationship/property supported by the schema. Keep the query "
                        "bounded and read-only. Do not broaden unrelated filters or invent entities. "
                        "Return the alternative Cypher query only."
                    )
                else:
                    correction_prompt = prompt + f"\n\nYour last query failed with this error:\n{last_error}\nPlease fix the syntax and try again."
                cypher_query = self.llm_client.generate(correction_prompt)
            else:
                cypher_query = self.llm_client.generate(prompt)

            
            cypher_query = cypher_query.replace("```cypher", "").replace("```", "").strip()

            if not cypher_query:
                last_error = "The generated Cypher query was empty."
                attempt += 1
                continue

            if cypher_query.rstrip().endswith(";"):
                cypher_query = cypher_query.rstrip()[:-1].rstrip()
            if ";" in cypher_query:
                return {
                    "status": "rejected",
                    "message": "Multiple Cypher statements are not allowed.",
                    "cypher": cypher_query,
                }

            if _WRITE_CLAUSE_RE.search(cypher_query) and not allow_write:
                logger.warning(f"Rejected LLM-generated Cypher containing a write clause: {cypher_query}")
                return {
                    "status": "rejected",
                    "message": "Generated query contains a write clause or write-capable subquery. "
                                "Re-run with allow_write=True only after explicit review.",
                    "cypher": cypher_query,
                }

            logger.info(f"Attempt {attempt + 1}: Executing generated Cypher: {cypher_query}")

            try:
                with self.db.driver.session() as session:
                    result = session.run(
                        Query(cypher_query, timeout=QUERY_TIMEOUT_SECONDS)
                    ).fetch(MAX_RESULT_ROWS)

                data = [record.data() for record in result]
                if not data and attempt < max_retries:
                    last_error = "The query executed successfully but returned no records."
                    empty_result_retry = True
                    attempt += 1
                    continue

                return {
                    "status": "success",
                    "cypher": cypher_query,
                    "data": data,
                }
            except Exception as e:
                logger.debug("Cypher execution attempt failed; retrying if available: %s", e)
                last_error = str(e)
                empty_result_retry = False
                attempt += 1

        return {
            "status": "error",
            "message": f"Failed after {max_retries} retries. Last error: {last_error}",
            "failed_cypher": cypher_query
        }
