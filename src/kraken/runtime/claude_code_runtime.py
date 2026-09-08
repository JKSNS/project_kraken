"""Claude Code runtime adapter.

This adapter intentionally shares the same local execution mechanics as LocalRuntime.
The distinction is semantic/configurational: this runtime is expected to run inside a
Claude Code-managed workspace/session with richer orchestration workflows.
"""

from __future__ import annotations

from kraken.runtime.local_runtime import LocalRuntime


class ClaudeCodeRuntime(LocalRuntime):
    """Runtime profile for Claude Code-centric execution."""

    name = "claude_code"
