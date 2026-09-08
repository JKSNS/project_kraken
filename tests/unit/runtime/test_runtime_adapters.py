import pytest

from kraken.runtime.factory import create_runtime
from kraken.runtime.local_runtime import LocalRuntime
from kraken.runtime.claude_code_runtime import ClaudeCodeRuntime


def test_factory_defaults_to_claude_code():
    rt = create_runtime("")
    assert isinstance(rt, ClaudeCodeRuntime)


def test_factory_local():
    rt = create_runtime("local")
    assert isinstance(rt, LocalRuntime)


def test_factory_invalid():
    with pytest.raises(ValueError):
        create_runtime("unknown")


@pytest.mark.asyncio
async def test_local_runtime_run_command_success():
    rt = LocalRuntime()
    res = await rt.run_command(["python3", "-c", "print('ok')"])
    assert res.exit_code == 0
    assert res.stdout.strip() == "ok"


@pytest.mark.asyncio
async def test_local_runtime_timeout():
    rt = LocalRuntime()
    res = await rt.run_command(["python3", "-c", "import time; time.sleep(2)"], timeout_seconds=1)
    assert res.exit_code == 124
