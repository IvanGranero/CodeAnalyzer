import os
import json
import uuid
import logging
from datetime import datetime
from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

class LLMClient:
    def __init__(
        self, 
        api_key: str,  # We will parse this as a comma-separated string
        model_name: str, 
        base_url: str, 
        api_version: str,
        audit_log_dir: str = "logs/llm_audit"
    ):
        # 1. Split the string into a list of keys, stripping any whitespace
        self.api_keys = [k.strip() for k in api_key.split(",") if k.strip()]
        self.model_name = model_name
        self.base_url = base_url
        self.api_version = api_version
        self.audit_log_dir = audit_log_dir
        os.makedirs(self.audit_log_dir, exist_ok=True)
        
        # 2. Create a pool of AsyncOpenAI clients, one for each key
        self.clients = [
            AsyncOpenAI(api_key=key, base_url=self.base_url)
            for key in self.api_keys
        ]
        self._current_index = 0
        
        logger.info(f"Initialized LLMClient with a pool of {len(self.clients)} API keys for round-robin routing.")

    def _audit_log(self, kwargs: dict, response_content: str):
        """Saves the exact API payload and response to disk for debugging/auditing."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = str(uuid.uuid4())[:8]
        filename = os.path.join(self.audit_log_dir, f"llm_audit_{timestamp}_{run_id}.txt")
        
        log_content = (
            f"==================================================\n"
            f"TIMESTAMP: {timestamp}\n"
            f"MODEL: {self.model_name}\n"
            f"==================================================\n"
            f"=== RAW INPUT (API PAYLOAD) ===\n"
            f"{json.dumps(kwargs, indent=2)}\n\n"
            f"=== RAW OUTPUT (LLM RESPONSE) ===\n"
            f"{response_content}\n"
        )
        
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(log_content)
        except Exception as e:
            logger.error(f"Failed to write LLM audit log: {e}")

    async def generate_chat(self, system_prompt: str, user_prompt: str, model_settings: dict = None) -> str:
        if model_settings is None:
            model_settings = {}
            
        # 3. Round-Robin Selection: Pick the client and advance the index
        client = self.clients[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.clients)
        
        try:
            kwargs = {
                "model": self.model_name,
                "input": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                #"extra_query": {"api-version": self.api_version}
            }
            
            if "max_tokens" in model_settings: 
                kwargs["max_tokens"] = model_settings["max_tokens"]
                
            # if model_settings.get("response_format") == "json_object": 
            #     kwargs["response_format"] = {"type": "json_object"}

            #logger.debug(f"[LLM] Sending request with kwargs:\n{json.dumps(kwargs, indent=2)}")

            # 4. Use the dynamically selected client for this specific request
            response = await client.responses.create(**kwargs)

            reasoning_text = None
            final_text = None

            for block in response.output:
                if block.type == "reasoning":
                    # Frontier reasoning is encrypted; you only get a summary if enabled
                    # But you CAN log the encrypted blob or summary metadata
                    reasoning_text = (
                        block.encrypted_content
                        or "No reasoning summary available."
                    )
                    #logger.info(f"[LLM Reasoning] {reasoning_text}")

                elif block.type == "message":
                    # This is the actual assistant output
                    final_text = block.content[0].text

            if final_text is None:
                raise RuntimeError("Frontier model returned no assistant message.")

            self._audit_log(kwargs, final_text)
            logger.info(f"[LLM response] {final_text}")
            return final_text

        except Exception as e:
            logger.exception(f"[LLM] API call failed on model {self.model_name}")
            raise
