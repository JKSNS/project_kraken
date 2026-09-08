"""Factory for runtime adapters."""

from __future__ import annotations

from kraken.runtime.base import RuntimeAdapter
from kraken.runtime.local_runtime import LocalRuntime
from kraken.runtime.claude_code_runtime import ClaudeCodeRuntime


def create_runtime(runtime_name: str) -> RuntimeAdapter:
    name = (runtime_name or "claude_code").strip().lower()
    if name == "claude_code":
        return ClaudeCodeRuntime()
    if name == "local":
        return LocalRuntime()
    if name == "kraken":
        from kraken.runtime.kraken_runtime import KrakenRuntime
        return KrakenRuntime()
    raise ValueError(f"Unknown runtime '{runtime_name}'. Expected one of: claude_code, local, kraken")
