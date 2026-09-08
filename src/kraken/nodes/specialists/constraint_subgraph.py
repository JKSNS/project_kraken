"""Constraint solver specialist as an isolated LangGraph subgraph.

Private internal state allows multi-step analysis (symbolics -> fallback -> result)
without polluting the parent graph state.
"""
from __future__ import annotations

from typing import TypedDict
from langgraph.graph import END, StateGraph
from langgraph.checkpoint.memory import MemorySaver

from kraken.nodes.specialists.base import SpecialistInput, SpecialistOutput, build_specialist_input
from kraken.logging.structured import get_logger

log = get_logger(__name__)


class ConstraintState(TypedDict, total=False):
    """Private internal state for constraint solver subgraph."""
    # Input (from parent)
    challenge_path: str
    binary_info: dict
    decompiled_functions: dict
    strings_of_interest: list[str]
    symbols: dict
    # Internal working state
    angr_result: dict
    z3_result: dict
    plt_addresses: dict
    exploration_strategies_tried: list[str]
    # Output
    strategy_hypothesis: str
    angr_results: dict


async def _symbolic_analysis(state: ConstraintState) -> dict:
    """Step 1: Run angr symbolic execution with multiple strategies."""
    from kraken.nodes.constraint_solver import constraint_solver as _legacy_solver
    # Delegate to existing logic for now, wrapping state
    parent_state = dict(state)
    result = await _legacy_solver(parent_state)
    return {
        "angr_results": result.get("angr_results", {}),
        "strategy_hypothesis": result.get("strategy_hypothesis", ""),
    }


async def _fallback_analysis(state: ConstraintState) -> dict:
    """Step 2: If symbolic failed, try z3 direct constraint solving."""
    if state.get("angr_results", {}).get("satisfiable"):
        return {}  # Already solved, skip
    # The existing constraint_solver handles fallbacks internally
    return {}


def _route_after_symbolic(state: ConstraintState) -> str:
    """Route based on symbolic analysis results."""
    angr = state.get("angr_results", {})
    if angr.get("satisfiable") or angr.get("solution"):
        return "__end__"
    return "fallback_analysis"


def build_constraint_subgraph():
    """Build the constraint solver subgraph."""
    graph = StateGraph(ConstraintState)

    graph.add_node("symbolic_analysis", _symbolic_analysis)
    graph.add_node("fallback_analysis", _fallback_analysis)

    graph.set_entry_point("symbolic_analysis")
    graph.add_conditional_edges(
        "symbolic_analysis",
        _route_after_symbolic,
        {"__end__": END, "fallback_analysis": "fallback_analysis"},
    )
    graph.add_edge("fallback_analysis", END)

    return graph.compile(checkpointer=MemorySaver())


async def constraint_solver_wrapper(state: dict) -> dict:
    """Wrapper to run constraint solver as subgraph from parent graph."""
    from kraken.config import EvolutionConfig

    if not EvolutionConfig().enable_subgraphs:
        # Legacy path: direct call
        from kraken.nodes.constraint_solver import constraint_solver
        return await constraint_solver(state)

    sub_input = build_specialist_input(state)
    subgraph = build_constraint_subgraph()

    config = {"configurable": {"thread_id": "constraint-sub"}}
    result = await subgraph.ainvoke(dict(sub_input), config=config)

    return {
        "angr_results": result.get("angr_results", {}),
        "strategy_hypothesis": result.get("strategy_hypothesis", ""),
        "recent_actions": result.get("recent_actions", [{"action": "constraint_solver", "reasoning": "subgraph", "result_summary": "Constraint analysis via subgraph"}]),
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
