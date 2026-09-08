"""Delegate -- scoped sub-agent spawning for complex subtask decomposition.

Gives solve_engine ability to delegate focused subtasks to scoped sub-agents.
Safety constraints:
  - Depth limit: 1 (sub-agents cannot spawn further sub-agents)
  - Token budget: 4K context per sub-agent
  - Time budget: 30s per sub-agent
  - Read-only: sub-agents return strings, don't modify state
"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any

from kraken.config import ModelConfig, EvolutionConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)

# Maximum tokens for sub-agent context
_MAX_CONTEXT_TOKENS = 4096
# Maximum time per sub-agent
_MAX_TIME_SECONDS = 30
# Maximum concurrent sub-agents
_MAX_CONCURRENT = 3


@dataclass
class SubAgentTask:
    """A scoped subtask for a sub-agent."""
    task_id: str
    prompt: str
    context: str = ""  # Scoped context (truncated to _MAX_CONTEXT_TOKENS chars)
    timeout: float = _MAX_TIME_SECONDS


@dataclass
class SubAgentResult:
    """Result from a sub-agent execution."""
    task_id: str
    output: str
    success: bool
    duration_seconds: float
    error: str = ""


async def delegate_subtask(task: SubAgentTask, config: ModelConfig) -> SubAgentResult:
    """Execute a scoped sub-agent for a focused subtask.

    The sub-agent receives a focused prompt with scoped context and returns
    its findings as a string. It cannot modify state or spawn further agents.

    Args:
        task: SubAgentTask with prompt and scoped context.
        config: Model config for LLM call.

    Returns:
        SubAgentResult with the sub-agent's output.
    """
    from kraken.models import direct_generate

    start = time.monotonic()

    # Truncate context to budget
    context = task.context[:_MAX_CONTEXT_TOKENS * 4]  # ~4 chars per token estimate

    full_prompt = (
        f"You are a focused analysis sub-agent. Your task:\n\n"
        f"{task.prompt}\n\n"
    )
    if context:
        full_prompt += f"## Context\n{context}\n\n"
    full_prompt += (
        "Respond with a concise analysis (max 500 words). "
        "Focus on actionable findings only."
    )

    try:
        result = await asyncio.wait_for(
            direct_generate(full_prompt, "low", config),
            timeout=task.timeout,
        )
        duration = time.monotonic() - start
        log.info("delegate_success", task_id=task.task_id, duration=round(duration, 1))
        return SubAgentResult(
            task_id=task.task_id,
            output=result.strip(),
            success=True,
            duration_seconds=round(duration, 1),
        )
    except asyncio.TimeoutError:
        duration = time.monotonic() - start
        log.warning("delegate_timeout", task_id=task.task_id, timeout=task.timeout)
        return SubAgentResult(
            task_id=task.task_id,
            output="",
            success=False,
            duration_seconds=round(duration, 1),
            error=f"Timeout after {task.timeout}s",
        )
    except Exception as exc:
        duration = time.monotonic() - start
        log.warning("delegate_error", task_id=task.task_id, error=str(exc))
        return SubAgentResult(
            task_id=task.task_id,
            output="",
            success=False,
            duration_seconds=round(duration, 1),
            error=str(exc),
        )


async def delegate_parallel(tasks: list[SubAgentTask], config: ModelConfig) -> list[SubAgentResult]:
    """Run multiple sub-agents in parallel with concurrency limit.

    Args:
        tasks: List of subtasks to delegate.
        config: Model config for LLM calls.

    Returns:
        List of SubAgentResults, one per task.
    """
    if not EvolutionConfig().enable_delegation:
        return []

    # Limit concurrency
    limited_tasks = tasks[:_MAX_CONCURRENT]

    log.info("delegate_parallel_start", tasks=len(limited_tasks))

    coros = [delegate_subtask(task, config) for task in limited_tasks]
    results = await asyncio.gather(*coros, return_exceptions=True)

    # Convert exceptions to failed results
    final: list[SubAgentResult] = []
    for task, result in zip(limited_tasks, results):
        if isinstance(result, SubAgentResult):
            final.append(result)
        else:
            final.append(SubAgentResult(
                task_id=task.task_id,
                output="",
                success=False,
                duration_seconds=0,
                error=str(result),
            ))

    log.info("delegate_parallel_complete",
             total=len(final),
             successful=sum(1 for r in final if r.success))

    return final


def plan_decomposition(state: dict, functions: dict) -> list[SubAgentTask]:
    """Plan subtask decomposition for a complex challenge.

    Heuristic: decompose when challenge has >10 functions or multiple secondary types.
    Creates focused sub-agent tasks for different aspects of the challenge.

    Args:
        state: KrakenState dict.
        functions: Decompiled functions dict.

    Returns:
        List of SubAgentTask instances, or empty if decomposition not warranted.
    """
    secondary_types = state.get("secondary_types", [])

    # Only decompose complex challenges
    if len(functions) <= 10 and len(secondary_types) <= 1:
        return []

    tasks: list[SubAgentTask] = []
    func_items = list(functions.items())

    # Task 1: Analyze main control flow
    main_funcs = {k: v[:2000] for k, v in func_items[:5]}
    tasks.append(SubAgentTask(
        task_id="control_flow",
        prompt=(
            "Analyze the main control flow of this binary. "
            "Identify the validation logic, key comparisons, and execution paths. "
            "What is the high-level algorithm?"
        ),
        context="\n\n".join(f"### {k}\n{v}" for k, v in main_funcs.items()),
    ))

    # Task 2: Identify crypto/encoding patterns
    if any(t in str(secondary_types) for t in ["crypto", "dynamic"]):
        crypto_funcs = {k: v[:2000] for k, v in func_items[5:10]}
        if crypto_funcs:
            tasks.append(SubAgentTask(
                task_id="crypto_patterns",
                prompt=(
                    "Look for cryptographic or encoding patterns in these functions. "
                    "Identify XOR operations, lookup tables, key schedules, or encoding chains."
                ),
                context="\n\n".join(f"### {k}\n{v}" for k, v in crypto_funcs.items()),
            ))

    # Task 3: Extract constants and magic values
    all_code = "\n".join(v[:1000] for _, v in func_items[:15])
    tasks.append(SubAgentTask(
        task_id="constants",
        prompt=(
            "Extract all significant constants, magic values, key bytes, and comparison targets "
            "from this code. List them with their locations and likely purpose."
        ),
        context=all_code[:_MAX_CONTEXT_TOKENS * 4],
    ))

    return tasks[:_MAX_CONCURRENT]
