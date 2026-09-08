"""Specialist fan-out -- parallel specialist execution for ambiguous challenges.

When enabled (enable_parallel_specialists), runs the primary specialist plus
up to 2 secondary-type specialists in parallel using asyncio.gather.

Each specialist runs with its own checkpoint namespace to avoid conflicts.
Results are merged: best strategy_hypothesis wins, angr_results are combined.
"""
from __future__ import annotations

import asyncio

from kraken.state import KrakenState
from kraken.config import EvolutionConfig
from kraken.logging.structured import get_logger

log = get_logger(__name__)

# Map challenge types to specialist functions
_SPECIALIST_MAP = {
    "constraint": "constraint_solver",
    "crypto": "crypto_decode",
    "dotnet": "dotnet_specialist",
    "dynamic": "dynamic_analysis",
    "keygen": "keygen",
    "pwn": "pwn_specialist",
    "fuzzing": "fuzzing_specialist",
    "scripting": "constraint_solver",
    "web": "web_specialist",
    "firmware": "firmware_specialist",
}


async def _run_specialist(specialist_name: str, state: dict) -> dict:
    """Run a single specialist node by name."""
    import importlib
    module = importlib.import_module(f"kraken.nodes.{specialist_name}")
    func = getattr(module, specialist_name)
    try:
        result = await func(state)
        return result if isinstance(result, dict) else {}
    except Exception as exc:
        log.warning("fanout_specialist_failed", specialist=specialist_name, error=str(exc))
        return {}


def _merge_results(results: list[dict]) -> dict:
    """Merge results from multiple specialists.

    Strategy: pick the longest strategy_hypothesis, merge angr_results,
    combine recent_actions.
    """
    merged: dict = {
        "strategy_hypothesis": "",
        "angr_results": {},
        "recent_actions": [],
    }

    best_hypothesis = ""
    for r in results:
        hyp = r.get("strategy_hypothesis", "")
        if len(hyp) > len(best_hypothesis):
            best_hypothesis = hyp

        # Merge angr_results (later results override, but preserve satisfiable flag)
        angr = r.get("angr_results", {})
        if angr:
            if angr.get("satisfiable") and not merged["angr_results"].get("satisfiable"):
                merged["angr_results"] = angr
            elif not merged["angr_results"]:
                merged["angr_results"] = angr

        # Collect actions
        actions = r.get("recent_actions", [])
        if isinstance(actions, list):
            merged["recent_actions"].extend(actions)

    merged["strategy_hypothesis"] = best_hypothesis
    return merged


async def specialist_fanout(state: KrakenState) -> dict:
    """Fan out multiple specialists in parallel for ambiguous challenges.

    If enable_parallel_specialists is False, routes to single primary specialist.
    """
    evo_cfg = EvolutionConfig()
    challenge_type = state.get("challenge_type", "constraint")
    secondary_types = state.get("secondary_types", [])[:2]

    primary_name = _SPECIALIST_MAP.get(challenge_type, "constraint_solver")

    if not evo_cfg.enable_parallel_specialists or not secondary_types:
        # Single specialist mode
        return await _run_specialist(primary_name, state)

    # Parallel mode: run primary + secondary specialists
    types_to_run = [challenge_type] + [t for t in secondary_types if t != challenge_type]
    specialist_names = []
    seen = set()
    for t in types_to_run:
        name = _SPECIALIST_MAP.get(t, "constraint_solver")
        if name not in seen:
            specialist_names.append(name)
            seen.add(name)

    log.info("specialist_fanout_start", specialists=specialist_names)

    tasks = [_run_specialist(name, state) for name in specialist_names]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions
    valid_results = [r for r in results if isinstance(r, dict)]

    if not valid_results:
        log.warning("specialist_fanout_all_failed")
        return {
            "strategy_hypothesis": f"All {len(specialist_names)} specialists failed",
            "recent_actions": [{"action": "specialist_fanout", "reasoning": "parallel execution", "result_summary": "All specialists failed"}],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    merged = _merge_results(valid_results)
    merged["iteration_count"] = state.get("iteration_count", 0) + 1

    log.info("specialist_fanout_complete",
             specialists_run=len(specialist_names),
             results=len(valid_results))

    return merged
