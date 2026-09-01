import os
import json
import uuid
import logging
import asyncio
from datetime import datetime
import openai
from openai import AsyncOpenAI, APIConnectionError

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
        
        self._use_legacy_endpoint = False
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_audit_file = os.path.join(self.audit_log_dir, f"llm_session_{timestamp}.txt")
                
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
                    default_query=query_params if query_params else None,
                    timeout=60.0 # Added explicit timeout
                )
            )
            
        self._current_index = 0
        logger.info(f"Initialized LLMClient with {len(self.clients)} keys. Auth Header: '{self.api_key_header}'")

    def _audit_log(self, kwargs: dict, response_content: str, endpoint_used: str, context_id: str = None):
        """Saves the exact API payload and response to disk for debugging/auditing."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = "".join(c for c in (context_id or "unknown_target") if c.isalnum() or c in "_-")
        filename = os.path.join(self.audit_log_dir, f"llm_audit_{safe_name}.txt")
        
        log_content = (
            f"==================================================\n"
            f"TIMESTAMP: {timestamp}\n"
            f"MODEL: {self.model_name}\n"
            f"ENDPOINT USED: {endpoint_used}\n"
            f"==================================================\n"
            f"=== RAW INPUT (API PAYLOAD) ===\n"
            f"{json.dumps(kwargs, indent=2)}\n\n"
            f"=== RAW OUTPUT (LLM RESPONSE) ===\n"
            f"{response_content}\n\n\n"
        )
        try:
            with open(filename, "a", encoding="utf-8") as f:
                f.write(log_content)
        except Exception as e:
            logger.error(f"Failed to write LLM audit log: {e}")

    async def generate_chat(self, system_prompt: str, user_prompt: str, model_settings: dict = None, context_id: str = None) -> tuple[str, dict]:

        """Returns a tuple of (response_text, usage_dict)"""
        if model_settings is None:
            model_settings = {}
            
        client = self.clients[self._current_index]
        self._current_index = (self._current_index + 1) % len(self.clients)
        
        if self._use_legacy_endpoint:
            return await self._execute_legacy_chat(client, system_prompt, user_prompt, model_settings, context_id)

        kwargs_responses = {
            "model": self.model_name,
            "input": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }
        # NOTE: the /responses API uses `max_output_tokens`, not `max_tokens`/
        # `max_completion_tokens`. Callers (see llm/prompts.json's model_settings) set
        # `max_completion_tokens` and `reasoning_effort`; previously only `max_tokens` was
        # forwarded here, so both were silently dropped on every call and every deep-scan
        # ran at whatever the provider's default reasoning effort happens to be.
        if "max_completion_tokens" in model_settings:
            kwargs_responses["max_output_tokens"] = model_settings["max_completion_tokens"]
        elif "max_tokens" in model_settings:
            kwargs_responses["max_output_tokens"] = model_settings["max_tokens"]
        if "reasoning_effort" in model_settings:
            kwargs_responses["reasoning"] = {"effort": model_settings["reasoning_effort"]}
        if model_settings.get("response_format") == "json_object":
            kwargs_responses["text"] = {"format": {"type": "json_object"}}

        max_retries = 3
        base_delay = 2.0

        for attempt in range(max_retries):
            try:
                response = await client.responses.create(**kwargs_responses)
                
                final_text = None
                usage_dict = {}
                
                # Extract tokens
                if hasattr(response, 'usage') and response.usage:
                    usage_dict = response.usage.model_dump() if hasattr(response.usage, 'model_dump') else vars(response.usage)
                    
                # Extract text
                for block in response.output:
                    if block.type == "message":
                        final_text = block.content[0].text
                
                if final_text is None:
                    raise RuntimeError("Frontier model returned no assistant message.")

                self._audit_log(kwargs_responses, final_text, "/responses", context_id)
                return final_text, usage_dict

            except openai.NotFoundError:
                logger.warning(f"[LLM] Endpoint /responses returned 404. Falling back to /chat/completions globally.")
                self._use_legacy_endpoint = True
                return await self._execute_legacy_chat(client, system_prompt, user_prompt, model_settings, context_id)

            except APIConnectionError as e:
                logger.warning(f"[LLM Network Error] Connection failed (Attempt {attempt+1}/{max_retries}): {e}")
                if attempt == max_retries - 1: raise
                await asyncio.sleep(base_delay * (2 ** attempt))

            except openai.RateLimitError as e:
                logger.warning(f"[LLM Rate Limit] 429 (Attempt {attempt+1}/{max_retries}): {e}")
                if attempt == max_retries - 1: raise
                await asyncio.sleep(base_delay * (2 ** attempt))

            except openai.APIStatusError as e:
                # 5xx are transient/retryable; other 4xx (bad request, auth, etc.) are not.
                if e.status_code in (500, 502, 503, 504) and attempt < max_retries - 1:
                    logger.warning(f"[LLM Server Error] {e.status_code} (Attempt {attempt+1}/{max_retries}): {e}")
                    await asyncio.sleep(base_delay * (2 ** attempt))
                else:
                    raise

            except Exception as e:
                err_str = str(e).lower()
                if "getaddrinfo failed" in err_str or "connection" in err_str or "timeout" in err_str:
                    logger.warning(f"[LLM Network Error] Socket/Timeout (Attempt {attempt+1}/{max_retries}): {e}")
                    if attempt == max_retries - 1: raise
                    await asyncio.sleep(base_delay * (2 ** attempt))
                else:
                    logger.exception(f"[LLM] Primary API call failed with unknown error on model {self.model_name}")
                    raise

    async def _execute_legacy_chat(self, client, system_prompt, user_prompt, model_settings, context_id: str = None) -> tuple[str, dict]:
        kwargs_chat = {
            "model": self.model_name,
            "messages": [ 
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ]
        }
        
        if "max_completion_tokens" in model_settings:
            kwargs_chat["max_completion_tokens"] = model_settings["max_completion_tokens"]
        elif "max_tokens" in model_settings:
            kwargs_chat["max_tokens"] = model_settings["max_tokens"]
        if "reasoning_effort" in model_settings:
            kwargs_chat["reasoning_effort"] = model_settings["reasoning_effort"]
        if model_settings.get("response_format") == "json_object":
            kwargs_chat["response_format"] = {"type": "json_object"}
            
        max_retries = 3
        base_delay = 2.0

        for attempt in range(max_retries):
            try:
                response = await client.chat.completions.create(**kwargs_chat)
                final_text = response.choices[0].message.content
                used_endpoint = "/chat/completions"
                
                usage_dict = {}
                if hasattr(response, 'usage') and response.usage:
                    usage_dict = response.usage.model_dump() if hasattr(response.usage, 'model_dump') else vars(response.usage)
                
                if final_text is None:
                    raise RuntimeError("Legacy model returned no assistant message.")
                    
                self._audit_log(kwargs_chat, final_text, used_endpoint, context_id)
                return final_text, usage_dict
                
            except APIConnectionError as e:
                logger.warning(f"[LLM Network Error] Connection failed (Attempt {attempt+1}/{max_retries}): {e}")
                if attempt == max_retries - 1: raise
                await asyncio.sleep(base_delay * (2 ** attempt))

            except openai.RateLimitError as e:
                logger.warning(f"[LLM Rate Limit] 429 (Attempt {attempt+1}/{max_retries}): {e}")
                if attempt == max_retries - 1: raise
                await asyncio.sleep(base_delay * (2 ** attempt))

            except openai.APIStatusError as e:
                if e.status_code in (500, 502, 503, 504) and attempt < max_retries - 1:
                    logger.warning(f"[LLM Server Error] {e.status_code} (Attempt {attempt+1}/{max_retries}): {e}")
                    await asyncio.sleep(base_delay * (2 ** attempt))
                else:
                    raise

            except Exception as e:
                err_str = str(e).lower()
                if "getaddrinfo failed" in err_str or "connection" in err_str or "timeout" in err_str:
                    logger.warning(f"[LLM Network Error] Socket/Timeout (Attempt {attempt+1}/{max_retries}): {e}")
                    if attempt == max_retries - 1: raise
                    await asyncio.sleep(base_delay * (2 ** attempt))
                else:
                    logger.exception(f"[LLM] Fallback API call failed on model {self.model_name}")
                    raise
