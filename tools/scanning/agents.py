"""LLM-facing triage and deep-scan agents.

These classes own prompt invocation and response validation. Workflow decisions,
follow-up decisions, evidence retrieval, and finding aggregation remain in the
orchestrator.
"""

import json
import logging
from collections.abc import Callable, Mapping
from typing import Any

from llm.runtime import AgentRuntime
from tools.scanning.contracts import Finding, TriageResponse, parse_object

logger = logging.getLogger(__name__)


class ScanAgent:
    def __init__(
        self,
        runtime: AgentRuntime,
        extract_json: Callable[[str], Mapping[str, Any]],
    ) -> None:
        self._runtime = runtime
        self._extract_json = extract_json


class TriageAgent(ScanAgent):
    """Request and validate a structured triage decision."""

    async def run(
        self,
        graph_json: str,
        graph_summary: str,
        source_code: str,
        directive: str,
        follow_up_context: str = "",
        target_func: str = "",
    ) -> dict[str, Any]:
        response_text = await self._runtime.execute(
            task_name="triage_agent",
            context_id=target_func,
            kwargs={
                "graph_json": graph_json,
                "graph_summary": graph_summary,
                "source_code": source_code,
                "directive": directive,
                "follow_up_context": follow_up_context,
            },
            settings_override=(
                {"reasoning_effort": "medium", "max_completion_tokens": 6000}
                if follow_up_context.strip()
                else None
            ),
        )
        return parse_object(self._extract_json(response_text), TriageResponse).model_dump(mode="json")

    async def run_with_retries(
        self,
        graph_json: str,
        graph_summary: str,
        source_code: str,
        directive: str,
        follow_up_context: str = "",
        target_func: str = "",
        max_attempts: int = 3,
    ) -> dict[str, Any]:
        return await run_triage(
            self,
            graph_json,
            graph_summary,
            source_code,
            directive,
            follow_up_context,
            target_func,
            max_attempts,
        )


async def run_triage(
    triage_agent: TriageAgent,
    graph_json: str,
    graph_summary: str,
    source_code: str,
    directive: str,
    follow_up_context: str = "",
    target_func: str = "",
    max_attempts: int = 3,
) -> dict[str, Any]:
    """Run a triage agent with bounded contract-validation retries."""
    last_error = "unknown triage failure"
    retry_directive = directive
    for attempt in range(1, max_attempts + 1):
        try:
            return await triage_agent.run(
                graph_json,
                graph_summary,
                source_code,
                retry_directive,
                follow_up_context,
                target_func,
            )
        except (ValueError, json.JSONDecodeError, RuntimeError) as exc:
            last_error = str(exc)
            logger.warning(
                "Triage attempt %d/%d failed for '%s': %s",
                attempt,
                max_attempts,
                target_func,
                exc,
            )
            retry_directive = (
                f"{directive}\n\nRETRY {attempt}: Your previous response failed contract validation. "
                "Return one valid JSON object matching every required triage field. "
                "Do not omit vulnerability_candidates or investigation_directive when escalating."
            )

    return {
        "decision": "error",
        "confidence": 0.0,
        "reason": "Triage failed after bounded retries.",
        "error": last_error,
        "vulnerability_candidates": [],
        "coverage": {},
    }


class DeepScanAgent(ScanAgent):
    """Request and validate one focused finding for a triage candidate."""

    async def run(
        self,
        candidate: Mapping[str, Any],
        graph_json: str,
        graph_summary: str,
        source_code: str,
        directive: str,
        follow_up_context: str = "",
        target_func: str = "",
    ) -> dict[str, Any]:
        effort = candidate.get("effort_estimate", "medium")
        settings = {
            "low": {"reasoning_effort": "low", "max_completion_tokens": 3000},
            "medium": {"reasoning_effort": "medium", "max_completion_tokens": 6000},
            "high": {"reasoning_effort": "high", "max_completion_tokens": 10000},
        }.get(effort, {"reasoning_effort": "medium", "max_completion_tokens": 6000})
        response_text = await self._runtime.execute(
            task_name="deep_scan_agent",
            context_id=f"{target_func}-{candidate.get('vulnerability_class', 'unknown')}",
            kwargs={
                "graph_json": graph_json,
                "graph_summary": graph_summary,
                "source_code": source_code,
                "directive": directive,
                "candidate": json.dumps(candidate, ensure_ascii=False),
                "target_function": target_func,
                "follow_up_context": follow_up_context,
            },
            settings_override=settings,
        )
        return parse_object(self._extract_json(response_text), Finding).model_dump(mode="json")
