import logging
import threading
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class TokenTracker:
    def __init__(self, model_name: str, usd_per_1m_input: Optional[float] = None, usd_per_1m_output: Optional[float] = None):
        self.lock = threading.Lock()
        self.model_name = model_name
        self.total_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.reasoning_tokens = 0

        # Extract pricing or fallback to 0 if not provided in .env
        self.input_rate = usd_per_1m_input if usd_per_1m_input is not None else 0.0
        self.output_rate = usd_per_1m_output if usd_per_1m_output is not None else 0.0

    def add_usage(self, usage: Dict[str, Any]):
        """
        Safely aggregates token usage from the raw API response.

        The primary LLM call path is the OpenAI /responses API (see
        llm/client.py's generate_chat), whose usage schema uses
        input_tokens/output_tokens/output_tokens_details.reasoning_tokens --
        NOT prompt_tokens/completion_tokens/completion_tokens_details, which is
        the legacy /chat/completions schema. Reading only the legacy keys here
        meant every /responses call (the default, always-used path unless the
        API 404s and falls back to legacy) silently added 0 tokens on every
        field while total_calls still incremented -- confirmed against a real
        run's audit log: 129 calls, all via /responses, token summary all
        zeros. Both key sets are checked so either endpoint accounts correctly.
        """
        if not usage:
            return

        with self.lock:
            self.total_calls += 1
            self.prompt_tokens += usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0
            self.completion_tokens += usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0

            details = usage.get("output_tokens_details") or usage.get("completion_tokens_details") or {}
            if isinstance(details, dict):
                self.reasoning_tokens += details.get("reasoning_tokens", 0) or 0

    def get_estimated_cost(self) -> float:
        """Calculates cost based on the 1M token pricing from config."""
        input_cost = (self.prompt_tokens / 1_000_000) * self.input_rate
        output_cost = (self.completion_tokens / 1_000_000) * self.output_rate
        return input_cost + output_cost

    def log_summary(self):
        """Prints a highly formatted financial/usage report."""
        cost = self.get_estimated_cost()
        total_tokens = self.prompt_tokens + self.completion_tokens
        
        report = (
            f"\n{'='*60}\n"
            f" 📊 LLM TOKEN USAGE & COST SUMMARY\n"
            f"{'='*60}\n"
            f"  Model Used        : {self.model_name}\n"
            f"  Total API Calls   : {self.total_calls}\n"
            f"  Input Tokens      : {self.prompt_tokens:,}\n"
            f"  Output Tokens     : {self.completion_tokens:,} (Includes {self.reasoning_tokens:,} Reasoning Tokens)\n"
            f"  Total Tokens      : {total_tokens:,}\n"
            f"  Estimated Cost    : ${cost:.4f} USD\n"
            f"{'='*60}\n"
        )
        logger.info(report)
        print(report)
