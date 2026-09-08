"""Tests for kraken.nodes.unpack -- conditional binary unpacking."""
import pytest
from unittest.mock import patch, AsyncMock

from kraken.nodes.unpack import unpack


@pytest.mark.asyncio
async def test_skip_not_packed():
    """Non-packed binary should skip unpacking."""
    state = {
        "binary_info": {"entropy": {"likely_packed": False}},
        "challenge_path": "/tmp/binary",
        "strings_of_interest": ["hello", "world"],
        "iteration_count": 0,
    }
    result = await unpack(state)
    assert "challenge_path" not in result
    assert result["recent_actions"][0]["reasoning"].startswith("Skipped")


@pytest.mark.asyncio
async def test_skip_no_entropy_info():
    """Missing entropy info should skip unpacking."""
    state = {
        "binary_info": {},
        "challenge_path": "/tmp/binary",
        "strings_of_interest": [],
        "iteration_count": 0,
    }
    result = await unpack(state)
    assert "challenge_path" not in result


@pytest.mark.asyncio
async def test_upx_detected_in_strings():
    """UPX string in binary strings should trigger unpacking attempt."""
    state = {
        "binary_info": {"entropy": {"likely_packed": False}},
        "challenge_path": "/tmp/binary",
        "strings_of_interest": ["UPX!", "other string"],
        "iteration_count": 0,
    }
    with patch("kraken.nodes.unpack._try_upx_unpack", new_callable=AsyncMock, return_value=None), \
         patch("kraken.nodes.unpack._try_dynamic_dump", new_callable=AsyncMock, return_value=None):
        result = await unpack(state)
    # Should have attempted unpacking (not skipped)
    action = result["recent_actions"][0]
    assert "packed" in action["reasoning"].lower() or "failed" in action["result_summary"].lower()


@pytest.mark.asyncio
async def test_upx_unpack_success():
    """Successful UPX unpack should update challenge_path."""
    state = {
        "binary_info": {"entropy": {"likely_packed": True}},
        "challenge_path": "/tmp/binary",
        "strings_of_interest": [],
        "iteration_count": 0,
    }
    with patch("kraken.nodes.unpack._try_upx_unpack", new_callable=AsyncMock, return_value="/tmp/binary_unpacked"):
        result = await unpack(state)
    assert result["challenge_path"] == "/tmp/binary_unpacked"


@pytest.mark.asyncio
async def test_all_unpack_fail():
    """When all unpack methods fail, original path should be preserved."""
    state = {
        "binary_info": {"entropy": {"likely_packed": True}},
        "challenge_path": "/tmp/binary",
        "strings_of_interest": [],
        "iteration_count": 0,
    }
    with patch("kraken.nodes.unpack._try_upx_unpack", new_callable=AsyncMock, return_value=None), \
         patch("kraken.nodes.unpack._try_dynamic_dump", new_callable=AsyncMock, return_value=None):
        result = await unpack(state)
    assert "challenge_path" not in result  # Don't overwrite with None
    assert len(result["error_log"]) > 0


@pytest.mark.asyncio
async def test_iteration_count_incremented():
    """Iteration count should always increment."""
    state = {
        "binary_info": {"entropy": {"likely_packed": False}},
        "challenge_path": "/tmp/binary",
        "strings_of_interest": [],
        "iteration_count": 5,
    }
    result = await unpack(state)
    assert result["iteration_count"] == 6
