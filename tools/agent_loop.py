from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from app.errors import is_retryable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Streamed event envelope
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AgentEvent:
    """One granular unit of the agent stream.

    kind is one of:
      "thought"     -- a step log / status line (was: logger.debug / _progress calls)
      "tool_call"    -- a tool the agent invoked, with its arguments
      "tool_result"  -- the output of a tool call
      "retry"        -- a contract-validation or transient-provider retry
      "sub_agent"    -- a nested/recursive agent loop is starting (e.g. one
                        deep-scan candidate spawned by a triage escalation)
      "final"        -- the loop's terminal result (success OR the bounded
                        fallback error object -- both are "final", exactly
                        like the original functions always returned
                        *something* rather than raising after exhausting
                        retries)
    """

    kind: str
    context_id: str
    data: Any = None
    attempt: int | None = None


# ---------------------------------------------------------------------------
# 1. Unified bounded-retry agent step
#    Replaces: run_triage, DeepScanAgent.run_with_retries, and the
#    craft/send/analyze while-loop in ExploitOrchestrator.
# ---------------------------------------------------------------------------

RetryDirectiveBuilder = Callable[[str, int, str], str]
FallbackBuilder = Callable[[str], Mapping[str, Any]]


async def agent_loop(
    *,
    context_id: str,
    max_attempts: int,
    step: Callable[[int, str], Awaitable[Mapping[str, Any]]],
    initial_directive: str = "",
    retryable_contract_errors: tuple[type[BaseException], ...] = (
        ValueError,
        json.JSONDecodeError,
        RuntimeError,
    ),
    build_retry_directive: RetryDirectiveBuilder | None = None,
    build_fallback: FallbackBuilder | None = None,
    on_attempt_start: str | None = "attempt {attempt}/{max_attempts}",
) -> AsyncIterator[AgentEvent]:
    """Run ``step`` up to ``max_attempts`` times, streaming progress.

    ``step(attempt, directive)`` performs exactly one unit of agent work
    (one LLM call + parse + validate, or one full craft/send/analyze turn)
    and either returns the successful result dict or raises. This
    preserves the *exact* three-tier exception handling every original
    call site used:

      * ``retryable_contract_errors`` (default: ValueError, JSONDecodeError,
        RuntimeError) -> the model's response failed contract validation.
        Logged as a warning, ``build_retry_directive`` (if given) rebuilds
        the directive/context text for the next attempt, exactly as
        ``run_triage`` and ``DeepScanAgent.run_with_retries`` did with
        their bespoke "RETRY N: ..." strings.
      * any other ``Exception`` -> checked against ``is_retryable``. Not
        retryable -> re-raised immediately (unchanged from every original
        call site). Retryable -> logged and retried unchanged.
      * attempts exhausted -> ``build_fallback(last_error)`` produces the
        same kind of degraded-but-well-formed result object the originals
        returned (e.g. ``{"decision": "error", ...}`` /
        ``Finding(status="unknown", needs_human_review=True, ...)``).

    Nothing here decides *what* a step does -- that keeps this generic
    enough to host triage, deep-scan, or the exploit crafter/analyzer turn
    without losing any of their distinct side effects (tracing, JSON
    parsing, contract models), which stay in the caller-supplied ``step``.
    """
    last_error = "unknown agent failure"
    directive = initial_directive

    for attempt in range(1, max_attempts + 1):
        if on_attempt_start:
            yield AgentEvent(
                "thought", context_id,
                on_attempt_start.format(attempt=attempt, max_attempts=max_attempts),
                attempt=attempt,
            )
        try:
            result = await step(attempt, directive)
        except retryable_contract_errors as exc:
            last_error = str(exc)
            logger.warning(
                "Agent attempt %d/%d failed contract validation for '%s': %s",
                attempt, max_attempts, context_id, exc,
            )
            yield AgentEvent("retry", context_id, {"reason": "contract_validation", "error": last_error}, attempt=attempt)
            if build_retry_directive is not None:
                directive = build_retry_directive(directive, attempt, last_error)
            continue
        except Exception as exc:  # noqa: BLE001 - deliberate: mirrors original catch-all
            if not is_retryable(exc):
                raise
            last_error = str(exc)
            logger.warning(
                "Agent attempt %d/%d failed for '%s' (transient provider error): %s",
                attempt, max_attempts, context_id, exc,
            )
            yield AgentEvent("retry", context_id, {"reason": "transient_provider_error", "error": last_error}, attempt=attempt)
            continue
        else:
            yield AgentEvent("final", context_id, result, attempt=attempt)
            return

    fallback = build_fallback(last_error) if build_fallback is not None else {
        "decision": "error",
        "error": last_error,
    }
    yield AgentEvent("final", context_id, fallback, attempt=max_attempts)


# ---------------------------------------------------------------------------
# 2. Unified "preload completed tool calls" builder
#    Replaces: agents.py::_build_initial_tool_history and
#    orchestrator.py (exploitation)::_build_exploit_tool_history
# ---------------------------------------------------------------------------

ToolCallSpec = tuple[str, Mapping[str, Any], Mapping[str, Any]]


def build_tool_history(
    calls: Sequence[ToolCallSpec],
    *,
    id_prefix: str,
    already_supplied_flag: str = "already_supplied_in_initial_bundle",
    extra_result_fields: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build a fake completed-tool-call turn: one assistant message with
    ``tool_calls`` plus one ``role: "tool"`` message per call, in the
    OpenAI chat-completions message shape ``client.py`` expects for
    ``preloaded_messages``.

    ``calls`` is the same ``[(name, arguments, result), ...]`` shape both
    original builders used. ``extra_result_fields`` covers the bits that
    differed between the two (``agents.py`` merged in a
    ``retrieval_manifest``; the exploit builder didn't), without
    duplicating the surrounding loop.
    """
    tool_calls: list[dict[str, Any]] = []
    tool_messages: list[dict[str, Any]] = []
    for index, (name, arguments, result) in enumerate(calls, 1):
        call_id = f"{id_prefix}-{index}-{name}"
        tool_calls.append({
            "id": call_id,
            "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments, ensure_ascii=False)},
        })
        payload = {**result, already_supplied_flag: True}
        if extra_result_fields:
            payload.update(extra_result_fields)
        tool_messages.append({
            "role": "tool",
            "tool_call_id": call_id,
            "content": json.dumps(payload, ensure_ascii=False),
        })
    return [{"role": "assistant", "content": None, "tool_calls": tool_calls}, *tool_messages]


# ---------------------------------------------------------------------------
# 3. Concurrent fan-out that still yields one flattened, ordered-by-arrival
#    stream. Replaces ScanOrchestrator._run_deep_scans's
#    "N candidates -> CandidateScheduler.gather -> flat results list", while
#    additionally exposing each candidate's own agent_loop() events instead
#    of only the final list (which the original silently discarded).
# ---------------------------------------------------------------------------

async def fan_out(
    context_id: str,
    branches: Sequence[AsyncIterator[AgentEvent]],
    *,
    max_branches: int | None = None,
) -> AsyncIterator[AgentEvent]:
    """Run each branch (itself typically an ``agent_loop`` call, one per
    candidate/sub-agent) concurrently and yield every event from every
    branch as soon as it's produced, preserving the original code's
    concurrency (``CandidateScheduler.gather`` ran candidates in
    parallel, not sequentially) instead of silently serializing it -- a
    plain ``for branch in branches: async for event in branch: yield
    event`` would be correct but would run branches one at a time and
    change latency/behavior.

    Two behaviors of the original ``CandidateScheduler`` are preserved
    exactly, not just approximated:

    * ``max_branches`` bounds fan-out the same way
      ``CandidateScheduler(max_candidates_per_target=12).gather`` sliced
      ``operations[:12]`` -- extra branches beyond the bound are simply
      never started, not queued or cancelled later.
    * Final results are still available *in submission order*, matching
      ``asyncio.gather``'s order-preserving-regardless-of-completion-order
      guarantee, which ``ScanOrchestrator._build_scan_report`` relies on
      when it zips ``results`` back up against ``candidates``. Live
      "thought"/"retry"/"tool_*" events still stream in true arrival
      order (that's the whole point of streaming); only the ``"final"``
      events are additionally replayed a second time, in order, as
      ``"final_ordered"`` once every branch has completed, so a caller
      that needs the ordered list doesn't have to reconstruct it itself.

    This is the recursive delegation point: each branch is usually
    itself built from ``agent_loop`` (e.g. one deep-scan candidate's
    bounded-retry loop), so this function is what turns N independent
    recursive sub-agent streams into the single cohesive stream the
    outer ``scan_function``-style caller consumes.
    """
    branches = list(branches)
    if max_branches is not None:
        branches = branches[:max_branches]

    yield AgentEvent("thought", context_id, f"fanning out {len(branches)} sub-agent(s)")
    queue: asyncio.Queue[tuple[int, AgentEvent | None, BaseException | None]] = asyncio.Queue()
    remaining = len(branches)
    finals: list[Any] = [None] * len(branches)

    async def _drain(index: int, branch: AsyncIterator[AgentEvent]) -> None:
        try:
            async for event in branch:
                if event.kind == "final":
                    finals[index] = event.data
                await queue.put((index, event, None))
        except BaseException as exc:  # noqa: BLE001 - propagated to the consumer, not swallowed
            await queue.put((index, None, exc))
        finally:
            await queue.put((index, None, None))

    tasks = [asyncio.ensure_future(_drain(i, branch)) for i, branch in enumerate(branches)]
    try:
        while remaining:
            _, event, error = await queue.get()
            if error is not None:
                raise error
            if event is None:
                remaining -= 1
                continue
            yield event
        # Replayed once, in original submission order -- the piece
        # asyncio.gather gave callers "for free" that arrival-ordered
        # streaming otherwise loses.
        yield AgentEvent("final_ordered", context_id, finals)
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


# ---------------------------------------------------------------------------
# Sketch: how each original call site becomes a thin wrapper.
# (Illustrative -- shows exactly what moves where; not itself imported.)
# ---------------------------------------------------------------------------

async def _example_triage_as_agent_loop(triage_agent, graph_json, graph_summary, source_code,
                                         directive, follow_up_context, target_func, max_attempts,
                                         discovery_context=None) -> AsyncIterator[AgentEvent]:
    """Drop-in replacement for ``run_triage`` in agents.py."""

    def build_retry_directive(prev_directive: str, attempt: int, error: str) -> str:
        # Verbatim text from the original run_triage retry_directive.
        return (
            f"{prev_directive}\n\nRETRY {attempt}: Your previous response failed contract validation. "
            "The previous turn returned incomplete or non-final JSON. "
            "Return the complete final decision envelope through the response text. "
            "Do not call tools, do not return ran_tools/tool_calls metadata, and return one valid JSON object matching every required triage field. "
            "Do not omit vulnerability_candidates or investigation_directive when escalating."
        )

    def build_fallback(error: str) -> Mapping[str, Any]:
        # Verbatim shape from the original run_triage exhausted-retries return.
        return {
            "decision": "error",
            "confidence": 0.0,
            "reason": "Triage failed after bounded retries.",
            "error": error,
            "vulnerability_candidates": [],
            "coverage": {},
        }

    async def step(attempt: int, current_directive: str) -> Mapping[str, Any]:
        return await triage_agent.run(
            graph_json, graph_summary, source_code, current_directive, follow_up_context,
            target_func, enable_tools=attempt == 1, discovery_context=discovery_context,
        )

    async for evt in agent_loop(
        context_id=target_func,
        max_attempts=max_attempts,
        step=step,
        initial_directive=directive,
        build_retry_directive=build_retry_directive,
        build_fallback=build_fallback,
    ):
        yield evt


async def _example_scan_function_as_stream(orchestrator, target_function_name: str) -> AsyncIterator[AgentEvent]:
    """Sketch of ScanOrchestrator.scan_function rebuilt to stream and to
    recursively delegate into per-candidate agent_loop()s via fan_out(),
    instead of returning one opaque dict at the end. Every branch point
    (ignore / error / escalate) from the original is preserved."""
    context = await orchestrator._build_scan_context(target_function_name)
    triage_stream = _example_triage_as_agent_loop(
        orchestrator.triage_agent, context.graph_json, context.graph_summary,
        context.source_code, "investigate", "", target_function_name,
        orchestrator._MAX_TRIAGE_ATTEMPTS, context.discovery_context,
    )

    triage_result: Mapping[str, Any] | None = None
    async for event in triage_stream:  # `yield from` is invalid here -- see module docstring
        yield event
        if event.kind == "final":
            triage_result = event.data

    if triage_result is None or triage_result.get("decision") != "escalate":
        yield AgentEvent("final", target_function_name, {"vulnerability_found": False})
        return

    candidates = triage_result.get("vulnerability_candidates", [])
    branches = [
        agent_loop(
            context_id=f"{target_function_name}-{c.get('vulnerability_class')}",
            max_attempts=2,
            step=lambda attempt, directive, c=c: orchestrator.deep_scan_agent.run(
                c, context.graph_json, context.graph_summary, context.source_code,
                directive, "", target_function_name, enable_tools=attempt == 1,
            ),
            initial_directive=triage_result.get("investigation_directive", ""),
        )
        for c in candidates
    ]
    results: list[Any] | None = None
    # max_branches=12 matches CandidateScheduler's default max_candidates_per_target.
    async for event in fan_out(target_function_name, branches, max_branches=12):
        if event.kind == "final_ordered":
            results = event.data  # in candidate order, like asyncio.gather gave the original
            continue
        yield event
    # `results` now feeds orchestrator._build_scan_report exactly as the
    # original CandidateScheduler.gather(...) return value did.