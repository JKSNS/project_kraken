"""Runtime adapter contract for KRAKEN execution environments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass
class CommandResult:
    """Normalized command execution result across runtime adapters."""

    exit_code: int
    stdout: str
    stderr: str


class RuntimeAdapter(Protocol):
    """Capability contract for execution runtimes."""

    name: str

    async def run_command(
        self,
        cmd: list[str],
        *,
        cwd: str | None = None,
        timeout_seconds: int = 60,
        env: dict[str, str] | None = None,
    ) -> CommandResult:
        """Execute a command and capture stdout/stderr/exit code."""

    def read_text(self, path: str) -> str:
        """Read a UTF-8 text file from runtime workspace."""

    def write_text(self, path: str, content: str) -> None:
        """Write UTF-8 text content into runtime workspace."""
