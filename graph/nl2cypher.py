import logging
from typing import Dict, Any, List, Optional
# Assuming you have access to your GraphDB instance from db.py
from graph.db import GraphDB 

logger = logging.getLogger(__name__)

class NL2CypherEngine:
    def __init__(self, db: GraphDB, llm_client: Any):
        """
        Args:
            db: Instance of your GraphDB.
            llm_client: A callable/interface to your /llm module to generate text.
        """
        self.db = db
        self.llm_client = llm_client
        
        # Hardcode some domain-specific examples for the prompt (Few-Shot)
        self.few_shot_examples = [
            {
                "question": "Find all functions that call Rte_Write_PortA.",
                "cypher": "MATCH (f:Function)-[:CALLS]->(target:Function {name: 'Rte_Write_PortA'}) RETURN f"
            },
            {
                "question": "Show me the variables used in the function 'EcuM_Init'.",
                "cypher": "MATCH (f:Function {name: 'EcuM_Init'})-[:USES]->(v:Variable) RETURN f, v"
            },
            {
                "question": "Tag function 'Vulnerable_Func' as reviewed.",
                "cypher": "MATCH (f:Function {name: 'Vulnerable_Func'}) SET f.status = 'reviewed' RETURN f"
            }
        ]

    def _get_live_schema(self) -> str:
        """Retrieves the current schema directly from Neo4j."""
        query = "CALL apoc.meta.schema() YIELD value RETURN value"
        try:
            # Requires APOC plugin installed in Neo4j
            result = self.db.retrieve(query)
            if result:
                return str(result[0]['value'])
            return "Schema unavailable."
        except Exception as e:
            logger.warning(f"Could not retrieve schema via APOC: {e}")
            return "Fallback to manual schema definition..."

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

    def query_and_execute(self, user_query: str, max_retries: int = 2) -> Dict[str, Any]:
        """
        Translates NL to Cypher, executes it, and includes a retry loop for syntax errors.
        """
        schema = self._get_live_schema()
        prompt = self._build_prompt(user_query, schema)
        
        attempt = 0
        last_error = ""

        while attempt <= max_retries:
            if attempt > 0:
                # Append the error to the prompt for correction
                correction_prompt = prompt + f"\n\nYour last query failed with this error:\n{last_error}\nPlease fix the syntax and try again."
                cypher_query = self.llm_client.generate(correction_prompt)
            else:
                cypher_query = self.llm_client.generate(prompt)
                
            # Clean up the output in case the LLM ignored instructions and used markdown
            cypher_query = cypher_query.replace("```cypher", "").replace("```", "").strip()
            
            logger.info(f"Attempt {attempt + 1}: Executing generated Cypher: {cypher_query}")
            
            try:
                # For safety, you might want to enforce read-only transactions if the query 
                # shouldn't mutate data, but since you want to update visually, we use a standard session.
                with self.db.driver.session() as session:
                    # Using write_transaction to allow both reads and updates based on the LLM output
                    result = session.execute_write(lambda tx: list(tx.run(cypher_query)))
                    
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
