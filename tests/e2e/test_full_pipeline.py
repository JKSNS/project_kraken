"""E2E test -- requires compiled challenge binaries and a running Ollama instance."""
import json
import asyncio
from pathlib import Path

import pytest

from kraken.orchestrator import Orchestrator
from kraken.config import KrakenConfig


CHALLENGES_DIR = Path(__file__).parent / "challenges"


@pytest.fixture
def orchestrator():
    config = KrakenConfig()
    config.budget.timeout_minutes = 5
    return Orchestrator(config=config)


@pytest.mark.skipif(
    not (CHALLENGES_DIR / "simple_xor" / "simple_xor").exists(),
    reason="Challenge binary not compiled",
)
@pytest.mark.asyncio
async def test_simple_xor(orchestrator):
    config = json.loads((CHALLENGES_DIR / "simple_xor" / "challenge.json").read_text())
    result = await orchestrator.solve(config)
    assert result["solved"] is True
    assert "flag{" in result["flag"]
