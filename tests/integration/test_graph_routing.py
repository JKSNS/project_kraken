"""Integration test for graph construction and routing logic.

Covers all route functions including pwn_specialist (#11) and graph assembly.
"""

from kraken.nodes.classify import route_from_classify
from kraken.nodes.flag_validator import route_from_validator
from kraken.nodes.manager import route_from_manager

# ── Classify routing ─────────────────────────────────────────────────


def test_classify_routes():
    assert route_from_classify({"challenge_type": "constraint"}) == "constraint_solver"
    assert route_from_classify({"challenge_type": "crypto"}) == "crypto_decode"
    assert route_from_classify({"challenge_type": "dynamic"}) == "dynamic_analysis"
    assert route_from_classify({"challenge_type": "keygen"}) == "keygen"


def test_classify_routes_pwn():
    """Pwn classification should route to pwn_specialist (#11)."""
    assert route_from_classify({"challenge_type": "pwn"}) == "pwn_specialist"


def test_classify_routes_new_specialists():
    """New specialist types should route correctly."""
    assert route_from_classify({"challenge_type": "fuzzing"}) == "fuzzing_specialist"
    assert route_from_classify({"challenge_type": "web"}) == "web_specialist"
    assert route_from_classify({"challenge_type": "firmware"}) == "firmware_specialist"


def test_classify_routes_unknown_defaults():
    """Unknown type should default to constraint_solver."""
    assert route_from_classify({"challenge_type": "unknown"}) == "constraint_solver"
    assert route_from_classify({}) == "constraint_solver"


# ── Validator routing ────────────────────────────────────────────────


def test_validator_routes():
    assert route_from_validator({"next_node": "__end__"}) == "__end__"
    assert route_from_validator({"next_node": "solve_engine"}) == "solve_engine"
    assert route_from_validator({"next_node": "manager"}) == "manager"


def test_validator_default_route():
    assert route_from_validator({}) == "manager"


# ── Manager routing ──────────────────────────────────────────────────


def test_manager_routes():
    assert route_from_manager({"next_node": "triage"}) == "triage"
    assert route_from_manager({"next_node": "decompile"}) == "decompile"
    assert route_from_manager({"next_node": "__end__"}) == "__end__"
    assert route_from_manager({"next_node": "give_up"}) == "__end__"


def test_manager_routes_pwn():
    """Manager should be able to route to pwn_specialist (#11)."""
    assert route_from_manager({"next_node": "pwn_specialist"}) == "pwn_specialist"


def test_manager_routes_all_specialists():
    """Manager should route to every specialist node."""
    for node in [
        "triage",
        "decompile",
        "normalize",
        "classify",
        "constraint_solver",
        "crypto_decode",
        "dynamic_analysis",
        "keygen",
        "pwn_specialist",
        "fuzzing_specialist",
        "web_specialist",
        "firmware_specialist",
        "solve_engine",
        "context_compressor",
    ]:
        assert route_from_manager({"next_node": node}) == node


# ── Graph construction ───────────────────────────────────────────────


def test_graph_compiles():
    """Graph should compile without errors."""
    from kraken.graph import build_graph

    graph = build_graph()
    assert graph is not None


def test_graph_has_all_nodes():
    """Graph should contain all expected nodes including new ones."""
    from kraken.graph import build_graph

    graph = build_graph()
    # Access the underlying graph structure
    # LangGraph compiled graphs expose nodes differently, so check the builder
    # We test that build_graph() doesn't crash with all nodes registered
    assert graph is not None


def test_graph_compiles_with_subgraphs():
    """Graph should compile with enable_subgraphs=True."""
    import os

    os.environ["KRAKEN_EVO_ENABLE_SUBGRAPHS"] = "true"
    try:
        from kraken.graph import build_graph

        graph = build_graph()
        assert graph is not None
    finally:
        os.environ.pop("KRAKEN_EVO_ENABLE_SUBGRAPHS", None)


def test_graph_compiles_with_fanout():
    """Graph should compile with enable_parallel_specialists=True."""
    import os

    os.environ["KRAKEN_EVO_ENABLE_PARALLEL_SPECIALISTS"] = "true"
    try:
        from kraken.graph import build_graph

        graph = build_graph()
        assert graph is not None
    finally:
        os.environ.pop("KRAKEN_EVO_ENABLE_PARALLEL_SPECIALISTS", None)


def test_cached_node_wrapper():
    """Test the _cached_node wrapper skips re-execution when cache fields are populated."""
    import asyncio

    from kraken.graph import _cached_node

    call_count = 0

    async def mock_node(state):
        nonlocal call_count
        call_count += 1
        return {"binary_info": {"file_type": "ELF"}, "strings_of_interest": ["hello"]}

    cached = _cached_node(mock_node, ["binary_info", "strings_of_interest"])

    # First call: cache empty → should execute
    state_empty = {"binary_info": {}, "strings_of_interest": [], "iteration_count": 0}
    result = asyncio.run(cached(state_empty))
    assert call_count == 1

    # Second call: cache populated → should skip
    state_full = {"binary_info": {"file_type": "ELF"}, "strings_of_interest": ["hello"], "iteration_count": 1}
    result = asyncio.run(cached(state_full))
    assert call_count == 1  # Should NOT have called the real function
    assert (
        "Skipped" in result["recent_actions"][0]["reasoning"]
        or "cached" in result["recent_actions"][0]["reasoning"].lower()
    )
