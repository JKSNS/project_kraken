from __future__ import annotations

from pathlib import Path

import pytest

from kraken.state import initial_state
from kraken.tools.script_executor import execute_script


def test_initial_state_includes_solve_workspace():
    st = initial_state("Basic", "/tmp/binary", solve_workspace="/tmp/Basic_solve")
    assert st["solve_workspace"] == "/tmp/Basic_solve"


@pytest.mark.asyncio
async def test_execute_script_persists_artifacts_in_cwd(tmp_path: Path):
    code = "print('hello')\n"
    res = await execute_script(code, timeout=5, cwd=str(tmp_path))

    assert res.success is True
    assert res.stdout.strip() == "hello"
    assert isinstance(res.data, dict)

    script_path = Path(res.data["script_path"])
    stdout_path = Path(res.data["stdout_path"])
    stderr_path = Path(res.data["stderr_path"])

    assert script_path.parent == tmp_path
    assert stdout_path.parent == tmp_path
    assert stderr_path.parent == tmp_path

    assert script_path.exists()
    assert stdout_path.exists()
    assert stderr_path.exists()

    assert "print('hello')" in script_path.read_text()
    assert stdout_path.read_text().strip() == "hello"
