"""Unit tests for Phase 7 -- recursive delegation."""
from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest

from kraken.agents.delegate import (
    SubAgentTask,
    delegate_parallel,
    plan_decomposition,
)


def test_decomposition_empty_for_simple_challenge():
    """Simple challenges (<= 10 functions, <= 1 secondary type) should not decompose."""
    state = {"secondary_types": []}
    functions = {f"func_{i}": f"code_{i}" for i in range(5)}
    tasks = plan_decomposition(state, functions)
    assert tasks == []


def test_decomposition_creates_tasks_for_complex():
    """Complex challenges (>10 functions) should produce subtasks."""
    state = {"secondary_types": ["crypto", "dynamic"]}
    functions = {f"func_{i}": f"code_{i}" * 100 for i in range(15)}
    tasks = plan_decomposition(state, functions)
    assert len(tasks) >= 2
    task_ids = [t.task_id for t in tasks]
    assert "control_flow" in task_ids
    assert "crypto_patterns" in task_ids


@pytest.mark.asyncio
async def test_delegate_parallel_noop_when_disabled():
    """When enable_delegation=False, delegate_parallel returns empty list."""
    tasks = [SubAgentTask(task_id="test", prompt="analyze")]
    with patch("kraken.agents.delegate.EvolutionConfig") as mock_cfg:
        mock_cfg.return_value.enable_delegation = False
        from kraken.config import ModelConfig
        results = await delegate_parallel(tasks, ModelConfig())
        assert results == []


@pytest.mark.asyncio
async def test_delegate_subtask_timeout_handling():
    """Timed-out sub-agents should return failed results."""
    from kraken.agents.delegate import delegate_subtask
    from kraken.config import ModelConfig

    task = SubAgentTask(task_id="slow", prompt="analyze", timeout=0.01)

    async def slow_generate(*args, **kwargs):
        await asyncio.sleep(10)
        return "never"

    with patch("kraken.models.direct_generate", side_effect=slow_generate):
        result = await delegate_subtask(task, ModelConfig())
        assert result.success is False
        assert "Timeout" in result.error
