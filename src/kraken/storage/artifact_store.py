"""Artifact Store -- decouple large binary data from KrakenState.

Implements the Handle Pattern: large artifacts (decompiled functions,
angr results, dynamic traces) are stored on disk and referenced by
handle keys in state. This reduces checkpoint serialization size
from 50-200KB to a few hundred bytes per artifact.

Usage:
    store = ArtifactStore(workspace_dir + "/.artifacts")
    handle = store.put("decompiled_functions", big_dict)
    # ... later ...
    data = store.get(handle)
    preview = store.summary(handle, max_chars=2000)
"""

from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any


class ArtifactStore:
    """File-backed store for large binary analysis artifacts.

    Each artifact is serialized as JSON and stored in a flat directory
    keyed by content hash. Reads are O(1) file lookups.
    """

    def __init__(self, base_dir: str) -> None:
        self._base = Path(base_dir)
        self._base.mkdir(parents=True, exist_ok=True)

    @property
    def base_dir(self) -> str:
        return str(self._base)

    def put(self, artifact_type: str, data: Any) -> str:
        """Store an artifact and return its handle key.

        Args:
            artifact_type: Category tag (e.g. "decompiled_functions", "angr_results").
            data: Any JSON-serializable data.

        Returns:
            Handle key string like "decompiled_functions:abc123".
        """
        payload = json.dumps(data, ensure_ascii=False, default=str)
        content_hash = hashlib.sha256(payload.encode()).hexdigest()[:16]
        handle = f"{artifact_type}:{content_hash}"

        artifact_path = self._base / f"{handle.replace(':', '_')}.json"
        artifact_path.write_text(payload, encoding="utf-8")

        # Write a small metadata sidecar for debugging
        meta_path = self._base / f"{handle.replace(':', '_')}.meta"
        meta = {
            "artifact_type": artifact_type,
            "handle": handle,
            "size_bytes": len(payload),
            "timestamp": time.time(),
        }
        meta_path.write_text(json.dumps(meta), encoding="utf-8")

        return handle

    def get(self, handle: str) -> Any:
        """Fetch artifact data by handle key.

        Args:
            handle: Handle key returned by put().

        Returns:
            Deserialized artifact data.

        Raises:
            FileNotFoundError: If the handle does not exist.
        """
        artifact_path = self._base / f"{handle.replace(':', '_')}.json"
        if not artifact_path.exists():
            raise FileNotFoundError(f"Artifact not found: {handle}")
        payload = artifact_path.read_text(encoding="utf-8")
        return json.loads(payload)

    def summary(self, handle: str, max_chars: int = 2000) -> str:
        """Return a truncated text preview of the artifact.

        For dicts: shows keys and truncated values.
        For lists: shows first few items.
        For strings: shows first max_chars characters.
        """
        data = self.get(handle)

        if isinstance(data, dict):
            parts = []
            budget = max_chars
            for key, value in data.items():
                val_str = str(value)
                if len(val_str) > 200:
                    val_str = val_str[:200] + "..."
                entry = f"{key}: {val_str}"
                if budget - len(entry) < 0:
                    parts.append(f"... ({len(data) - len(parts)} more keys)")
                    break
                parts.append(entry)
                budget -= len(entry)
            return "\n".join(parts)

        if isinstance(data, list):
            parts = []
            budget = max_chars
            for i, item in enumerate(data):
                item_str = str(item)
                if len(item_str) > 200:
                    item_str = item_str[:200] + "..."
                if budget - len(item_str) < 0:
                    parts.append(f"... ({len(data) - i} more items)")
                    break
                parts.append(item_str)
                budget -= len(item_str)
            return "\n".join(parts)

        return str(data)[:max_chars]

    def exists(self, handle: str) -> bool:
        """Check if a handle exists in the store."""
        artifact_path = self._base / f"{handle.replace(':', '_')}.json"
        return artifact_path.exists()


def get_artifact(state: dict, field: str, handle_field: str) -> Any:
    """Try to load artifact via handle; fall back to inline state field.

    This is the primary read interface for nodes. It transparently handles
    both the new handle-based path and the legacy inline path.

    Args:
        state: KrakenState dict.
        field: The original inline field name (e.g. "decompiled_functions").
        handle_field: The handle field name (e.g. "decompiled_functions_handle").

    Returns:
        The artifact data, or the inline state value, or an empty default.
    """
    handle = state.get(handle_field, "")
    if handle:
        store_path = state.get("artifact_store_path", "")
        if store_path:
            try:
                store = ArtifactStore(store_path)
                return store.get(handle)
            except (FileNotFoundError, json.JSONDecodeError):
                pass  # Fall through to inline

    # Fall back to inline state field
    inline = state.get(field)
    if inline is not None:
        return inline

    # Return sensible default based on field name conventions
    if "functions" in field or "results" in field or "info" in field:
        return {}
    if "traces" in field:
        return []
    return {}
