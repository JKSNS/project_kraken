"""Base types for tool results."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ToolResult:
    tool: str
    success: bool = True
    data: Any = None
    stdout: str = ""
    stderr: str = ""
    error: str = ""
    exit_code: int = 0
