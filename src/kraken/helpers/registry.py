"""Tool auto-registration registry for KRAKEN helpers.

Single source of truth for tool metadata.  Adding a new tool requires
editing ONLY ``tool_meta.json`` in this directory.  The tool_router,
optimizer, and MCP server all read from this registry.

The JSON file stores:
  - ``tools``  -- per-tool metadata (description, timeout, command_style, ...)
  - ``universal_order``  -- ordered list of universal tool names
  - ``type_specific``  -- per-challenge-type ordered tool lists
  - ``default_type_specific``  -- fallback list for unknown challenge types
  - ``remote_tools``  -- tools injected when remote_info has a host

The registry is loaded lazily on first access and cached.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolMeta:
    """Metadata for a registered helper tool."""

    name: str
    description: str = ""
    universal: bool = False
    timeout: int = 120
    needs_binary: bool = True
    needs_challenge_dir: bool = False
    # "custom"       -- uses the existing _build_*_command() in tool_router
    # "dir_flag"     -- python3 {helpers}/{name}.py "{challenge_dir}" [--flag-format ...]
    # "binary_flag"  -- python3 {helpers}/{name}.py "{binary}" [--flag-format ...]
    command_style: str = "custom"


# ── Internal state ───────────────────────────────────────────────────────

_META_JSON_PATH = Path(__file__).resolve().parent / "tool_meta.json"

_TOOLS: dict[str, ToolMeta] = {}
_UNIVERSAL_ORDER: list[str] = []
_TYPE_SPECIFIC: dict[str, list[str]] = {}
_DEFAULT_TYPE_SPECIFIC: list[str] = []
_REMOTE_TOOLS: list[str] = []
_LOADED = False


def _ensure_loaded() -> None:
    """Load tool metadata from tool_meta.json on first access."""
    global _LOADED
    if _LOADED:
        return
    _LOADED = True

    if not _META_JSON_PATH.exists():
        return

    try:
        data = json.loads(_META_JSON_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return

    # Parse per-tool metadata
    tools_dict = data.get("tools", {})
    for tool_name, meta_dict in tools_dict.items():
        _TOOLS[tool_name] = ToolMeta(
            name=tool_name,
            description=meta_dict.get("description", ""),
            universal=meta_dict.get("universal", False),
            timeout=meta_dict.get("timeout", 120),
            needs_binary=meta_dict.get("needs_binary", True),
            needs_challenge_dir=meta_dict.get("needs_challenge_dir", False),
            command_style=meta_dict.get("command_style", "custom"),
        )

    # Parse explicit ordering lists
    _UNIVERSAL_ORDER.extend(data.get("universal_order", []))
    for ctype, tools in data.get("type_specific", {}).items():
        _TYPE_SPECIFIC[ctype] = list(tools)
    _DEFAULT_TYPE_SPECIFIC.extend(data.get("default_type_specific", []))
    _REMOTE_TOOLS.extend(data.get("remote_tools", []))


def reload() -> None:
    """Force reload of registry from disk (useful for testing)."""
    global _LOADED
    _TOOLS.clear()
    _UNIVERSAL_ORDER.clear()
    _TYPE_SPECIFIC.clear()
    _DEFAULT_TYPE_SPECIFIC.clear()
    _REMOTE_TOOLS.clear()
    _LOADED = False
    _ensure_loaded()


# ── Public API ───────────────────────────────────────────────────────────

def is_loaded() -> bool:
    """Return True if the registry has been loaded from tool_meta.json."""
    _ensure_loaded()
    return bool(_TOOLS)


def get_registry() -> dict[str, ToolMeta]:
    """Return a copy of the full tool registry."""
    _ensure_loaded()
    return dict(_TOOLS)


def get_tool(name: str) -> ToolMeta | None:
    """Look up metadata for a single tool by name."""
    _ensure_loaded()
    return _TOOLS.get(name)


def get_universal_tools() -> list[str]:
    """Return the ordered list of universal tool names."""
    _ensure_loaded()
    return list(_UNIVERSAL_ORDER)


def get_type_tools(challenge_type: str) -> list[str]:
    """Return the ordered list of type-specific tools for *challenge_type*."""
    _ensure_loaded()
    return list(_TYPE_SPECIFIC.get(challenge_type, []))


def get_all_type_specific() -> dict[str, list[str]]:
    """Return a dict mapping each challenge type to its type-specific tools.

    This mirrors the shape of the old ``_TYPE_SPECIFIC`` dict so callers can
    use it as a drop-in replacement.
    """
    _ensure_loaded()
    return {k: list(v) for k, v in _TYPE_SPECIFIC.items()}


def get_default_type_specific() -> list[str]:
    """Return the default fallback type-specific tools."""
    _ensure_loaded()
    return list(_DEFAULT_TYPE_SPECIFIC)


def get_remote_tools() -> list[str]:
    """Return the list of remote-interaction tools."""
    _ensure_loaded()
    return list(_REMOTE_TOOLS)
