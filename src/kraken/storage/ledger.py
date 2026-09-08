"""Helpers for the per-challenge solve ledger scratchpad."""

from __future__ import annotations

import re
from pathlib import Path


_FLAG_LIKE_TOKEN = re.compile(r"\b[A-Za-z0-9_\-]{1,32}\{[^\n\r}]{1,220}\}")


def _sanitize_ledger_entry(entry: str) -> str:
    """Redact flag-like tokens before persisting ledger entries."""
    return _FLAG_LIKE_TOKEN.sub("<redacted_flag_like_token>", entry or "")


def ledger_path_for_workspace(solve_workspace: str) -> Path:
    return Path(solve_workspace) / "solve_ledger.md"


def initialize_ledger(solve_workspace: str, challenge_name: str) -> str:
    path = ledger_path_for_workspace(solve_workspace)
    header = f"# Solve Ledger for {challenge_name}\n\n## Initial Triage\n"
    path.write_text(header, encoding="utf-8")
    return str(path)


def append_ledger_entry(ledger_path: str | None, entry: str) -> None:
    if not ledger_path or not entry:
        return
    entry = _sanitize_ledger_entry(entry)
    p = Path(ledger_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        if not entry.endswith("\n"):
            entry += "\n"
        f.write(entry)


def read_ledger_tail(ledger_path: str | None, max_chars: int = 2000) -> str:
    if not ledger_path:
        return ""
    p = Path(ledger_path)
    if not p.exists():
        return ""
    text = p.read_text(encoding="utf-8", errors="replace")
    return text[-max_chars:]


def read_ledger_all(ledger_path: str | None) -> str:
    if not ledger_path:
        return ""
    p = Path(ledger_path)
    if not p.exists():
        return ""
    return p.read_text(encoding="utf-8", errors="replace")
