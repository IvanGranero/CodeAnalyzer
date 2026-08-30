import json
import logging
import time
from llm.client import LLMClient

logger = logging.getLogger(__name__)

class LLMService:
    def __init__(
        self, 
        api_key: str, 
        model_name: str, 
        base_url: str, 
        api_version: str, 
        api_key_header: str = ""
    ):
        self.client = LLMClient(
            api_key=api_key, 
            model_name=model_name, 
            base_url=base_url, 
            api_version=api_version,
            api_key_header=api_key_header
        )
        self.prompts = self._load_prompts()

    def _load_prompts(self) -> dict:
        try:
            with open("llm/prompts.json", "r") as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load prompts.json: {e}")
            return {}

    async def execute_task(self, task_name: str, kwargs: dict) -> str:
        if task_name not in self.prompts:
            raise ValueError(f"Task '{task_name}' not found in prompts.json")
            
        task_config = self.prompts[task_name]
        
        system_prompt = "\n".join(task_config["system"]) if isinstance(task_config["system"], list) else task_config["system"]
        template = "\n".join(task_config["template"]) if isinstance(task_config["template"], list) else task_config["template"]
        
        user_prompt = template.format(**kwargs)
        settings = task_config.get("model_settings", {})
        
        start_time = time.time()
        logger.info(f"LLM Service ({self.client.model_name}): Executing async task '{task_name}'")
        
        # --- CHANGED: Added 'await' ---
        result = await self.client.generate_chat(system_prompt, user_prompt, settings)
        
        elapsed = time.time() - start_time
        logger.info(f"LLM Service ({self.client.model_name}): Task '{task_name}' completed in {elapsed:.2f}s")
        
        return result
