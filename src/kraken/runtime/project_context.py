"""Project context -- persistent project-level knowledge (KRAKEN.md).

Like Claude Code's CLAUDE.md, maintains a project-level knowledge file
that accumulates learnings across solve sessions. Content is injected
into solve_engine prompts via template variables.
"""
from __future__ import annotations

import time
from pathlib import Path

from kraken.logging.structured import get_logger

log = get_logger(__name__)

_DEFAULT_KRAKEN_MD = """\
# KRAKEN Project Context

This file accumulates learnings from solve sessions.
It is automatically updated after each solve attempt.

## Patterns

## Anti-Patterns

## Model Notes
"""


class ProjectContext:
    """Manage KRAKEN.md project context file."""

    def __init__(self, workspace: str | Path = "."):
        self.workspace = Path(workspace)
        self.context_path = self.workspace / "KRAKEN.md"

    def load(self) -> str:
        """Load project context. Creates default if missing."""
        if not self.context_path.exists():
            return _DEFAULT_KRAKEN_MD
        try:
            return self.context_path.read_text()
        except Exception as exc:
            log.warning("project_context_load_error", error=str(exc)[:200])
            return _DEFAULT_KRAKEN_MD

    def save(self, content: str) -> None:
        """Save project context."""
        try:
            self.context_path.parent.mkdir(parents=True, exist_ok=True)
            self.context_path.write_text(content)
        except Exception as exc:
            log.warning("project_context_save_error", error=str(exc)[:200])

    def append_learning(
        self,
        challenge_id: str,
        challenge_type: str,
        outcome: str,
        strategy: str,
        notes: str = "",
    ) -> None:
        """Append a learning entry after a solve attempt."""
        content = self.load()

        timestamp = time.strftime("%Y-%m-%d %H:%M")
        entry = (
            f"\n### {challenge_id} ({challenge_type}) -- {outcome}\n"
            f"- **Date**: {timestamp}\n"
            f"- **Strategy**: {strategy}\n"
        )
        if notes:
            entry += f"- **Notes**: {notes}\n"

        # Append to appropriate section
        if outcome == "solved":
            marker = "## Patterns"
        else:
            marker = "## Anti-Patterns"

        if marker in content:
            idx = content.index(marker) + len(marker)
            content = content[:idx] + "\n" + entry + content[idx:]
        else:
            content += "\n" + entry

        self.save(content)
        log.info("project_context_updated", challenge=challenge_id, outcome=outcome)

    def get_context_for_prompt(self, max_chars: int = 4000) -> str:
        """Get project context suitable for injection into prompts."""
        content = self.load()
        if len(content) > max_chars:
            content = content[:max_chars] + "\n... [truncated]"
        return content
