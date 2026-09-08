"""Unit tests for Phase 5 -- specialist subgraph wrappers."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest


@pytest.mark.asyncio
async def test_constraint_wrapper_legacy_path():
    """When enable_subgraphs=False, wrapper calls original constraint_solver."""
    from kraken.nodes.specialists.constraint_subgraph import constraint_solver_wrapper

    mock_result = {"strategy_hypothesis": "test", "iteration_count": 1}
    with patch("kraken.config.EvolutionConfig") as mock_cfg, \
         patch("kraken.nodes.constraint_solver.constraint_solver", new_callable=AsyncMock, return_value=mock_result) as mock_solver:
        mock_cfg.return_value.enable_subgraphs = False
        result = await constraint_solver_wrapper({"iteration_count": 0})
        mock_solver.assert_awaited_once()
        assert result == mock_result


@pytest.mark.asyncio
async def test_crypto_wrapper_legacy_path():
    """When enable_subgraphs=False, wrapper calls original crypto_decode."""
    from kraken.nodes.specialists.crypto_subgraph import crypto_decode_wrapper

    mock_result = {"strategy_hypothesis": "crypto_test", "iteration_count": 1}
    with patch("kraken.config.EvolutionConfig") as mock_cfg, \
         patch("kraken.nodes.crypto_decode.crypto_decode", new_callable=AsyncMock, return_value=mock_result) as mock_decoder:
        mock_cfg.return_value.enable_subgraphs = False
        result = await crypto_decode_wrapper({"iteration_count": 0})
        mock_decoder.assert_awaited_once()
        assert result == mock_result


@pytest.mark.asyncio
async def test_constraint_wrapper_subgraph_path():
    """When enable_subgraphs=True, wrapper builds and invokes subgraph."""
    from kraken.nodes.specialists.constraint_subgraph import constraint_solver_wrapper

    subgraph_result = {
        "angr_results": {"satisfiable": True},
        "strategy_hypothesis": "symbolic",
        "recent_actions": [{"action": "constraint_solver", "reasoning": "subgraph", "result_summary": "ok"}],
    }

    mock_subgraph = AsyncMock(return_value=subgraph_result)

    with patch("kraken.config.EvolutionConfig") as mock_cfg, \
         patch("kraken.nodes.specialists.constraint_subgraph.build_constraint_subgraph") as mock_build:
        mock_cfg.return_value.enable_subgraphs = True
        mock_build.return_value.ainvoke = mock_subgraph

        state = {
            "challenge_path": "/tmp/test",
            "binary_info": {},
            "decompiled_functions": {},
            "strings_of_interest": [],
            "symbols": {},
            "iteration_count": 0,
        }
        result = await constraint_solver_wrapper(state)

        assert result["angr_results"]["satisfiable"] is True
        assert result["strategy_hypothesis"] == "symbolic"
        assert result["iteration_count"] == 1
