"""Crypto decode specialist as an isolated LangGraph subgraph."""
from __future__ import annotations

from typing import TypedDict
from langgraph.graph import END, StateGraph
from langgraph.checkpoint.memory import MemorySaver

from kraken.nodes.specialists.base import SpecialistInput, SpecialistOutput, build_specialist_input
from kraken.logging.structured import get_logger

log = get_logger(__name__)


class CryptoState(TypedDict, total=False):
    """Private internal state for crypto decode subgraph."""
    challenge_path: str
    binary_info: dict
    decompiled_functions: dict
    function_annotations: dict
    strings_of_interest: list[str]
    angr_results: dict
    # Internal
    crypto_constants: dict
    encoding_chains: list[dict]
    # Output
    strategy_hypothesis: str


async def _crypto_analysis(state: CryptoState) -> dict:
    """Run crypto analysis via existing crypto_decode logic."""
    from kraken.nodes.crypto_decode import crypto_decode as _legacy_crypto
    parent_state = dict(state)
    result = await _legacy_crypto(parent_state)
    return {
        "strategy_hypothesis": result.get("strategy_hypothesis", ""),
        "angr_results": result.get("angr_results", {}),
    }


def build_crypto_subgraph():
    """Build the crypto decode subgraph."""
    graph = StateGraph(CryptoState)
    graph.add_node("crypto_analysis", _crypto_analysis)
    graph.set_entry_point("crypto_analysis")
    graph.add_edge("crypto_analysis", END)
    return graph.compile(checkpointer=MemorySaver())


async def crypto_decode_wrapper(state: dict) -> dict:
    """Wrapper to run crypto decode as subgraph from parent graph."""
    from kraken.config import EvolutionConfig

    if not EvolutionConfig().enable_subgraphs:
        from kraken.nodes.crypto_decode import crypto_decode
        return await crypto_decode(state)

    sub_input = build_specialist_input(state)
    subgraph = build_crypto_subgraph()

    config = {"configurable": {"thread_id": "crypto-sub"}}
    result = await subgraph.ainvoke(dict(sub_input), config=config)

    return {
        "angr_results": result.get("angr_results", {}),
        "strategy_hypothesis": result.get("strategy_hypothesis", ""),
        "recent_actions": [{"action": "crypto_decode", "reasoning": "subgraph", "result_summary": "Crypto analysis via subgraph"}],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
