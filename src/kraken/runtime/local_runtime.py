"""Local process runtime adapter (default implementation)."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path

from kraken.runtime.base import CommandResult


class LocalRuntime:
    """Runs commands directly on the host machine."""

    name = "local"

    async def run_command(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        timeout_seconds: int = 60,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            cwd=cwd,
            env={**os.environ, **(env or {})},
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout_seconds)
        except asyncio.TimeoutError:
            proc.kill()
            stdout, stderr = await proc.communicate()
            return CommandResult(exit_code=124, stdout=stdout.decode(errors="replace"), stderr=stderr.decode(errors="replace"))
        return CommandResult(
            exit_code=proc.returncode or 0,
            stdout=stdout.decode(errors="replace"),
            stderr=stderr.decode(errors="replace"),
        )

    def read_text(self, path: str) -> str:
        return Path(path).read_text()

    def write_text(self, path: str, content: str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
