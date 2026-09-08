"""LangGraph assembly -- the KRAKEN processing graph.

Graph topology (20 nodes):
  START → triage → unpack → decompile → normalize → classify
                                                       ↓ (conditional)
                                  ┌────────┬─────────┬────────┬────────┐
                                  ↓        ↓         ↓        ↓        ↓
                              constraint crypto  dotnet  dynamic  keygen  pwn ...
                                  └────────┼─────────┴────────┴────────┘
                                           ↓
                                    param_extraction  (deterministic: regex/heuristics)
                                           ↓
                                      tool_router     (deterministic: cascade helper tools)
                                      ↓           ↓
                               flag_validator  solve_engine  (LLM only if tools fail)
                                   ↓       ↓        ↓
                                [END]   manager   flag_validator
                              (success)    ↓          ...
                                       [END] (give up)

Happy path uses 0 Opus tokens. Manager only fires on failure.
Tool router can short-circuit to flag_validator without any LLM call.
"""

from __future__ import annotations

import functools

from langgraph.graph import END, StateGraph
from langgraph.checkpoint.memory import MemorySaver

from kraken.state import KrakenState
from kraken.storage.artifact_store import get_artifact
from kraken.logging.structured import get_logger

_log = get_logger(__name__)

# ── Node imports ────────────────────────────────────────────────
from kraken.nodes.triage import triage
from kraken.nodes.unpack import unpack
from kraken.nodes.decompile import decompile
from kraken.nodes.normalize import normalize
from kraken.nodes.classify import classify, route_from_classify
from kraken.nodes.specialists.constraint_subgraph import constraint_solver_wrapper
from kraken.nodes.specialists.crypto_subgraph import crypto_decode_wrapper
from kraken.nodes.dynamic_analysis import dynamic_analysis
from kraken.nodes.keygen import keygen
from kraken.nodes.pwn_specialist import pwn_specialist
from kraken.nodes.fuzzing_specialist import fuzzing_specialist
from kraken.nodes.web_specialist import web_specialist
from kraken.nodes.dotnet_specialist import dotnet_specialist
from kraken.nodes.firmware_specialist import firmware_specialist
from kraken.nodes.solve_engine import solve_engine
from kraken.nodes.tool_router import tool_router
from kraken.nodes.flag_validator import flag_validator, route_from_validator
from kraken.nodes.manager import manager, route_from_manager
from kraken.nodes.context_compressor import context_compressor
from kraken.nodes.specialist_fanout import specialist_fanout
from kraken.config import EvolutionConfig
from kraken.tools.param_extractor import extract_solve_params


async def param_extraction(state):
    """Deterministic parameter extraction from decompiled code."""
    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    params = extract_solve_params(
        functions,
        state.get("strings_of_interest", []),
        state.get("binary_info", {}),
    )
    return {"extracted_params": params}


def route_after_tools(state):
    """Route based on whether the tool cascade found a flag."""
    if state.get("tool_flag_candidate"):
        return "flag_validator"
    return "solve_engine"


def _safe_node(func):
    """Wrap an async node so unhandled exceptions degrade gracefully."""
    @functools.wraps(func)
    async def wrapper(state):
        try:
            return await func(state)
        except Exception as exc:
            _log.error("node_crash", node=func.__name__, error=str(exc))
            crash_count = int(state.get("framework_crash_count", 0) or 0) + 1
            updates = {
                "error_log": [{"node": func.__name__, "error": f"Unhandled: {exc}"}],
                "recent_actions": [{
                    "action": func.__name__,
                    "reasoning": "Crashed",
                    "result_summary": f"ERROR: {str(exc)[:200]}",
                }],
                "iteration_count": state.get("iteration_count", 0) + 1,
                "framework_crash_count": crash_count,
                # Safety: routing nodes (flag_validator) read next_node from state.
                # Without this, a crash leaves stale next_node (e.g. "fuzzing_specialist")
                # which causes a routing KeyError in the validator's conditional edges.
                "next_node": "manager",
            }
            # Prevent solve_engine crash-spin by giving validator/manager concrete failure IO.
            if func.__name__ == "solve_engine":
                latest_attempt = len(state.get("solve_scripts", []) or []) + 1
                crash_msg = f"Framework node crash in solve_engine: {exc}"
                updates["current_attempt"] = {
                    "attempt_num": latest_attempt,
                    "strategy": state.get("current_strategy", ""),
                    "code": "",
                    "stdout": "",
                    "stderr": crash_msg,
                    "exit_code": 1,
                }
                updates["solve_scripts"] = [{
                    "attempt_num": latest_attempt,
                    "strategy": state.get("current_strategy", ""),
                    "code": "",
                    "stdout": "",
                    "stderr": crash_msg,
                    "exit_code": 1,
                }]

            # Hard brake for repeated framework crashes.
            if crash_count >= 8:
                updates["next_node"] = "__end__"
                updates["recent_actions"][0]["result_summary"] = (
                    f"ERROR: repeated framework crashes ({crash_count}); forcing termination"
                )

            return updates
    return wrapper


# ── Deterministic node caching wrapper (#13) ──────────────────────

def _cached_node(func, cache_fields: list[str]):
    """Wrap a deterministic node so it skips re-execution if results exist.

    If all ``cache_fields`` are non-empty in state, returns a no-op update.
    This prevents re-running expensive tools (Ghidra, strings, pwntools)
    when the manager routes back to triage/decompile.
    """
    @functools.wraps(func)
    async def wrapper(state):
        # Check if cached results exist
        if all(state.get(f) for f in cache_fields):
            _log.info("node_cached", node=func.__name__, fields=cache_fields)
            return {
                "recent_actions": [{
                    "action": func.__name__,
                    "reasoning": "Skipped -- cached results already available",
                    "result_summary": f"Cached: {', '.join(cache_fields)}",
                }],
                "iteration_count": state.get("iteration_count", 0) + 1,
            }
        return await func(state)
    return wrapper


def build_graph(checkpointer=None) -> StateGraph:
    """Assemble and compile the KRAKEN LangGraph.

    Args:
        checkpointer: LangGraph checkpointer (MemorySaver, SqliteSaver, etc.).
                      Defaults to MemorySaver for dev.

    Returns:
        Compiled StateGraph ready for `.ainvoke()`.
    """
    graph = StateGraph(KrakenState)

    # ── Register all nodes (wrapped for crash resilience) ──────
    # Triage and decompile get caching wrapper (#13)
    graph.add_node("triage", _safe_node(
        _cached_node(triage, ["binary_info", "strings_of_interest"])
    ))
    graph.add_node("unpack", _safe_node(unpack))
    graph.add_node("decompile", _safe_node(
        _cached_node(decompile, ["decompiled_functions"])
    ))
    graph.add_node("normalize", _safe_node(normalize))
    graph.add_node("classify", _safe_node(classify))
    graph.add_node("constraint_solver", _safe_node(constraint_solver_wrapper))
    graph.add_node("crypto_decode", _safe_node(crypto_decode_wrapper))
    graph.add_node("dynamic_analysis", _safe_node(dynamic_analysis))
    graph.add_node("keygen", _safe_node(keygen))
    graph.add_node("pwn_specialist", _safe_node(pwn_specialist))
    graph.add_node("fuzzing_specialist", _safe_node(fuzzing_specialist))
    graph.add_node("web_specialist", _safe_node(web_specialist))
    graph.add_node("dotnet_specialist", _safe_node(dotnet_specialist))
    graph.add_node("firmware_specialist", _safe_node(firmware_specialist))
    graph.add_node("param_extraction", _safe_node(param_extraction))
    graph.add_node("tool_router", _safe_node(tool_router))
    graph.add_node("solve_engine", _safe_node(solve_engine))
    graph.add_node("flag_validator", _safe_node(flag_validator))
    graph.add_node("manager", _safe_node(manager))
    graph.add_node("context_compressor", _safe_node(context_compressor))

    # ── Happy path (linear with conditional unpack) ───────────
    graph.set_entry_point("triage")
    graph.add_edge("triage", "unpack")
    graph.add_edge("unpack", "decompile")
    graph.add_edge("decompile", "normalize")
    graph.add_edge("normalize", "classify")

    # ── Classify → specialist (conditional or fanout) ──────────
    evo = EvolutionConfig()

    if evo.enable_parallel_specialists:
        # Phase 6: classify → fanout → param_extraction
        graph.add_node("specialist_fanout", _safe_node(specialist_fanout))
        graph.add_edge("classify", "specialist_fanout")
        graph.add_edge("specialist_fanout", "param_extraction")
    else:
        # Original: classify → conditional specialist routing
        graph.add_conditional_edges(
            "classify",
            route_from_classify,
            {
                "constraint_solver": "constraint_solver",
                "crypto_decode": "crypto_decode",
                "dynamic_analysis": "dynamic_analysis",
                "keygen": "keygen",
                "pwn_specialist": "pwn_specialist",
                "fuzzing_specialist": "fuzzing_specialist",
                "web_specialist": "web_specialist",
                "dotnet_specialist": "dotnet_specialist",
                "firmware_specialist": "firmware_specialist",
            },
        )

    # ── All specialists → param_extraction (always present for manager routing) ─
    for specialist in [
        "constraint_solver", "crypto_decode", "dotnet_specialist",
        "dynamic_analysis", "keygen", "pwn_specialist",
        "fuzzing_specialist", "web_specialist", "firmware_specialist",
    ]:
        graph.add_edge(specialist, "param_extraction")

    graph.add_edge("param_extraction", "tool_router")

    # ── Tool router → flag_validator (flag found) or solve_engine ─
    graph.add_conditional_edges(
        "tool_router",
        route_after_tools,
        {
            "flag_validator": "flag_validator",
            "solve_engine": "solve_engine",
        },
    )

    # ── Solve → validate ───────────────────────────────────────
    graph.add_edge("solve_engine", "flag_validator")

    # ── Validator → END (success) or retry/manager ─────────────
    graph.add_conditional_edges(
        "flag_validator",
        route_from_validator,
        {
            "__end__": END,
            "solve_engine": "solve_engine",  # self-correction
            "manager": "manager",  # escalate
        },
    )

    # ── Manager → route to any node or END ─────────────────────
    graph.add_conditional_edges(
        "manager",
        route_from_manager,
        {
            "triage": "triage",
            "decompile": "decompile",
            "normalize": "normalize",
            "classify": "classify",
            "constraint_solver": "constraint_solver",
            "crypto_decode": "crypto_decode",
            "dynamic_analysis": "dynamic_analysis",
            "keygen": "keygen",
            "pwn_specialist": "pwn_specialist",
            "fuzzing_specialist": "fuzzing_specialist",
            "web_specialist": "web_specialist",
            "dotnet_specialist": "dotnet_specialist",
            "firmware_specialist": "firmware_specialist",
            "param_extraction": "param_extraction",
            "tool_router": "tool_router",
            "solve_engine": "solve_engine",
            "context_compressor": "context_compressor",
            "__end__": END,
        },
    )

    # ── Context compressor → manager ───────────────────────────
    graph.add_edge("context_compressor", "manager")

    # ── Compile ────────────────────────────────────────────────
    if checkpointer is None:
        checkpointer = MemorySaver()

    return graph.compile(checkpointer=checkpointer)
