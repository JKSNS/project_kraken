"""Unit tests for Phase 6 -- specialist fanout."""
from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from kraken.nodes.specialist_fanout import (
    _SPECIALIST_MAP,
    _merge_results,
    specialist_fanout,
)


@pytest.mark.asyncio
async def test_fanout_single_specialist_when_disabled():
    """When enable_parallel_specialists=False, runs single specialist."""
    state = {"challenge_type": "constraint", "secondary_types": [], "iteration_count": 0}
    mock_result = {"strategy_hypothesis": "angr solve", "iteration_count": 1}

    with patch("kraken.nodes.specialist_fanout.EvolutionConfig") as mock_cfg, \
         patch("kraken.nodes.specialist_fanout._run_specialist", new_callable=AsyncMock, return_value=mock_result):
        mock_cfg.return_value.enable_parallel_specialists = False
        result = await specialist_fanout(state)
        assert result["strategy_hypothesis"] == "angr solve"


@pytest.mark.asyncio
async def test_fanout_single_specialist_no_secondary():
    """Even when enabled, runs single specialist if no secondary types."""
    state = {"challenge_type": "crypto", "secondary_types": [], "iteration_count": 0}
    mock_result = {"strategy_hypothesis": "xor decode", "iteration_count": 1}

    with patch("kraken.nodes.specialist_fanout.EvolutionConfig") as mock_cfg, \
         patch("kraken.nodes.specialist_fanout._run_specialist", new_callable=AsyncMock, return_value=mock_result):
        mock_cfg.return_value.enable_parallel_specialists = True
        result = await specialist_fanout(state)
        assert result["strategy_hypothesis"] == "xor decode"


@pytest.mark.asyncio
async def test_fanout_parallel_execution():
    """When enabled with secondary types, runs multiple specialists."""
    state = {
        "challenge_type": "constraint",
        "secondary_types": ["crypto"],
        "iteration_count": 0,
    }

    async def mock_run(name, st):
        if name == "constraint_solver":
            return {"strategy_hypothesis": "angr", "recent_actions": [{"action": "constraint_solver"}]}
        return {"strategy_hypothesis": "xor", "recent_actions": [{"action": "crypto_decode"}]}

    with patch("kraken.nodes.specialist_fanout.EvolutionConfig") as mock_cfg, \
         patch("kraken.nodes.specialist_fanout._run_specialist", side_effect=mock_run):
        mock_cfg.return_value.enable_parallel_specialists = True
        result = await specialist_fanout(state)
        # Should have merged results from both
        assert len(result.get("recent_actions", [])) == 2
        assert result["iteration_count"] == 1


def test_merge_results_picks_longest_hypothesis():
    """Merge should select the longest strategy_hypothesis."""
    results = [
        {"strategy_hypothesis": "short", "recent_actions": []},
        {"strategy_hypothesis": "a much longer hypothesis wins", "recent_actions": []},
    ]
    merged = _merge_results(results)
    assert merged["strategy_hypothesis"] == "a much longer hypothesis wins"


def test_specialist_map_completeness():
    """All expected challenge types should be in the specialist map."""
    expected_types = [
        "constraint", "crypto", "dotnet", "dynamic",
        "keygen", "pwn", "fuzzing", "web", "firmware",
    ]
    for t in expected_types:
        assert t in _SPECIALIST_MAP, f"Missing type: {t}"
