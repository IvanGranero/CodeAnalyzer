import os
import json
import uuid
import logging
from datetime import datetime
import openai
from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

class LLMClient:
    def __init__(
        self, 
        api_key: str, 
        model_name: str, 
        base_url: str, 
        api_version: str = "",
        api_key_header: str = "",
        audit_log_dir: str = "logs/llm_audit"
    ):
        self.api_keys = [k.strip() for k in api_key.split(",") if k.strip()]
        self.model_name = model_name
        self.base_url = base_url.rstrip("/")
        self.api_version = api_version
        
        self.api_key_header = api_key_header.strip() if api_key_header.strip() else "api-key"
        self.audit_log_dir = audit_log_dir
        os.makedirs(self.audit_log_dir, exist_ok=True)
        
        # --- NEW: Flag to cache the preferred endpoint ---
        self._use_legacy_endpoint = False
        
        self.clients = []
        for key in self.api_keys:
            headers = {self.api_key_header: key}
            query_params = {}
            
            if self.api_version:
                query_params["api-version"] = self.api_version
                
            self.clients.append(
                AsyncOpenAI(
                    base_url=self.base_url,
                    api_key=key,
                    default_headers=headers,
                    default_query=query_params if query_params else None
                )
            )
            
        self._current_index = 0
        logger.info(f"Initialized LLMClient with {len(self.clients)} keys. Auth Header: '{self.api_key_header}'")

    def _audit_log(self, kwargs: dict, response_content: str, endpoint_used: str):
        """Saves the exact API payload and response to disk for debugging/auditing."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_id = str(uuid.uuid4())[:8]
        filename = os.path.join(self.audit_log_dir, f"llm_audit_{timestamp}_{run_id}.txt")
        
        log_content = (
            f"==================================================\n"
            f"TIMESTAMP: {timestamp}\n"
            f"MODEL: {self.model_name}\n"
            f"ENDPOINT USED: {endpoint_used}\n"
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
            
        client = self.clients[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.clients)
        
        reasoning_text = None
        final_text = None
        used_endpoint = ""
        final_kwargs = None
        
        # --- NEW: Fast Path for Legacy API ---
        if self._use_legacy_endpoint:
            return await self._execute_legacy_chat(client, system_prompt, user_prompt, model_settings)

        # Standard Modern Path
        kwargs_responses = {
            "model": self.model_name,
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }
        if "max_tokens" in model_settings: 
            kwargs_responses["max_tokens"] = model_settings["max_tokens"]

        try:
            # 1. Attempt the new 'Responses' API
            response = await client.responses.create(**kwargs_responses)
            
            for block in response.output:
                if block.type == "reasoning":
                    reasoning_text = block.encrypted_content or "No reasoning summary available."
                elif block.type == "message":
                    final_text = block.content[0].text
                    
            used_endpoint = "/responses"
            final_kwargs = kwargs_responses
            
        except openai.NotFoundError:
            # 2. Graceful Fallback if Gateway throws 404
            logger.warning(f"[LLM] Endpoint /responses returned 404. Falling back to /chat/completions globally.")
            self._use_legacy_endpoint = True  # <--- Cache the failure so we never try /responses again
            
            return await self._execute_legacy_chat(client, system_prompt, user_prompt, model_settings)
                
        except Exception as e:
            logger.exception(f"[LLM] Primary API call failed with unknown error on model {self.model_name}")
            raise

        if final_text is None:
            raise RuntimeError("Frontier model returned no assistant message.")

        self._audit_log(final_kwargs, final_text, used_endpoint)
        logger.info(f"[LLM response via {used_endpoint}] {final_text[:100]}...")
        return final_text
        
    async def _execute_legacy_chat(self, client, system_prompt, user_prompt, model_settings):
        """Helper method to isolate the legacy /chat/completions logic"""
        kwargs_chat = {
            "model": self.model_name,
            "messages": [ 
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }
        
        if "max_tokens" in model_settings: 
            kwargs_chat["max_tokens"] = model_settings["max_tokens"]
        if model_settings.get("response_format") == "json_object": 
            kwargs_chat["response_format"] = {"type": "json_object"}
            
        try:
            response = await client.chat.completions.create(**kwargs_chat)
            final_text = response.choices[0].message.content
            used_endpoint = "/chat/completions"
            
            if final_text is None:
                raise RuntimeError("Legacy model returned no assistant message.")
                
            self._audit_log(kwargs_chat, final_text, used_endpoint)
            logger.info(f"[LLM response via {used_endpoint}] {final_text[:100]}...")
            return final_text
            
        except Exception as e:
            logger.exception(f"[LLM] Fallback API call failed on model {self.model_name}")
            raise
