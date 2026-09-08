"""Script executor -- runs Python solve scripts, returns stdout/stderr/exit_code."""
from __future__ import annotations

import asyncio
import time
from pathlib import Path

from kraken.tools.base import ToolResult


async def execute_script(
    code: str,
    timeout: int = 30,
    cwd: str | None = None,
    artifact_dir: str | None = None,
) -> ToolResult:
    """Execute a Python solve script and capture output.

    Args:
        code: Python source code to execute.
        timeout: Maximum execution time in seconds.
        cwd: Working directory for execution (so scripts can access binaries).
        artifact_dir: Directory for storing script/stdout/stderr files.
                      Falls back to ``cwd`` if not provided.
    """
    exec_dir = Path(cwd).resolve() if cwd else Path.cwd().resolve()
    store_dir = Path(artifact_dir).resolve() if artifact_dir else exec_dir
    store_dir.mkdir(parents=True, exist_ok=True)

    stem = f"solve_attempt_{int(time.time() * 1000)}"
    script_path = store_dir / f"{stem}.py"
    stdout_path = store_dir / f"{stem}.stdout"
    stderr_path = store_dir / f"{stem}.stderr"
    script_path.write_text(code)

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            "python3", str(script_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=str(exec_dir),
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        stdout_text = stdout.decode(errors="replace")
        stderr_text = stderr.decode(errors="replace")
        stdout_path.write_text(stdout_text)
        stderr_path.write_text(stderr_text)
        return ToolResult(
            tool="script_executor",
            success=proc.returncode == 0,
            stdout=stdout_text,
            stderr=stderr_text,
            exit_code=proc.returncode or 0,
            data={
                "script_path": str(script_path),
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            },
        )
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await proc.communicate()
            except Exception:
                pass
        stderr_path.write_text(f"Script timed out after {timeout}s")
        return ToolResult(
            tool="script_executor",
            success=False,
            error=f"Script timed out after {timeout}s",
            exit_code=124,
            data={
                "script_path": str(script_path),
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            },
        )
    except Exception as e:
        stderr_path.write_text(str(e))
        return ToolResult(
            tool="script_executor",
            success=False,
            error=str(e),
            exit_code=1,
            data={
                "script_path": str(script_path),
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
            },
        )
