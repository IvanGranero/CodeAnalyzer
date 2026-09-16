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
from tools.scanning.contracts import Finding, TriageResponse, VulnerabilityClass, parse_object

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
        enable_tools: bool = True,
    ) -> dict[str, Any]:
        response_text = await self._runtime.execute(
            task_name="triage_agent",
            context_id=target_func,
            kwargs={
                "target_function": target_func,
                "graph_json": graph_json,
                "graph_summary": graph_summary,
                "source_code": source_code,
                "directive": directive,
                "follow_up_context": follow_up_context,
            },
            settings_override=(
                {
                    "max_completion_tokens": 6000,
                }
                if follow_up_context.strip()
                else None
            ),
            enable_tools=enable_tools,
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
                enable_tools=attempt == 1,
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
                "The previous turn returned incomplete or non-final JSON. "
                "Return the complete final decision envelope through the response text. "
                "Do not call tools, do not return ran_tools/tool_calls metadata, and return one valid JSON object matching every required triage field. "
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
        enable_tools: bool = True,
    ) -> dict[str, Any]:
        effort = candidate.get("effort_estimate", "medium")
        settings = {
            "low": {"reasoning_effort": "low", "max_completion_tokens": 4096},
            "medium": {"reasoning_effort": "medium", "max_completion_tokens": 6144},
            "high": {"reasoning_effort": "medium", "max_completion_tokens": 6144},
        }.get(effort, {"reasoning_effort": "medium", "max_completion_tokens": 6144})
        if not enable_tools:
            settings = {
                **settings,
                "reasoning_effort": "low",
                "max_completion_tokens": max(6000, settings["max_completion_tokens"]),
            }
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
            enable_tools=enable_tools,
        )
        return parse_object(self._extract_json(response_text), Finding).model_dump(mode="json")

    async def run_with_retries(
        self,
        candidate: Mapping[str, Any],
        graph_json: str,
        graph_summary: str,
        source_code: str,
        directive: str,
        follow_up_context: str = "",
        target_func: str = "",
        max_attempts: int = 2,
    ) -> dict[str, Any]:
        """Retry only contract failures, preserving the same evidence scope."""
        last_error = "unknown deep-scan failure"
        for attempt in range(1, max(1, max_attempts) + 1):
            try:
                return await self.run(
                    candidate, graph_json, graph_summary, source_code,
                    directive, follow_up_context, target_func,
                    enable_tools=attempt == 1,
                )
            except (ValueError, json.JSONDecodeError, RuntimeError) as exc:
                last_error = str(exc)
                logger.warning(
                    "Deep-scan attempt %d/%d failed for '%s': %s",
                    attempt, max_attempts, target_func, exc,
                )
                follow_up_context = (
                    f"{follow_up_context}\nRETRY {attempt}: Return one JSON object matching the Finding contract. "
                    "Your previous response was incomplete or non-final. "
                    "Return the complete final Finding JSON through the response text. "
                    "Do not call tools or return tool-call metadata. Use status='unknown' and needs_human_review=true "
                    "when graph evidence is insufficient."
                )
        vulnerability_type = candidate.get("vulnerability_class", "other")
        if vulnerability_type not in {member.value for member in VulnerabilityClass}:
            vulnerability_type = "other"
        return Finding(
            vulnerability_type=vulnerability_type,
            status="unknown",
            vulnerability_found=False,
            details=f"Deep scan returned no valid final response after bounded retries: {last_error}",
            evidence="No contract-valid model verdict was returned.",
            needs_human_review=True,
        ).model_dump(mode="json")
