"""Tests for the artifact store (Phase 1 -- Handle Pattern)."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from kraken.storage.artifact_store import ArtifactStore, get_artifact


@pytest.fixture
def tmp_store(tmp_path):
    """Create an ArtifactStore in a temp directory."""
    return ArtifactStore(str(tmp_path / ".artifacts"))


class TestArtifactStore:
    def test_put_get_roundtrip_dict(self, tmp_store):
        data = {"main@0x401000": "int main() { return 0; }", "check@0x401100": "void check(char *s) {}"}
        handle = tmp_store.put("decompiled_functions", data)
        assert handle.startswith("decompiled_functions:")
        recovered = tmp_store.get(handle)
        assert recovered == data

    def test_put_get_roundtrip_list(self, tmp_store):
        data = [{"type": "strace", "stdout": "write(1, ..."}, {"type": "ltrace"}]
        handle = tmp_store.put("dynamic_traces", data)
        assert handle.startswith("dynamic_traces:")
        assert tmp_store.get(handle) == data

    def test_put_get_roundtrip_string(self, tmp_store):
        data = "large text blob" * 1000
        handle = tmp_store.put("raw_output", data)
        assert tmp_store.get(handle) == data

    def test_get_missing_handle_raises(self, tmp_store):
        with pytest.raises(FileNotFoundError):
            tmp_store.get("nonexistent:abc123")

    def test_exists(self, tmp_store):
        handle = tmp_store.put("test", {"a": 1})
        assert tmp_store.exists(handle)
        assert not tmp_store.exists("missing:xyz")

    def test_summary_dict(self, tmp_store):
        data = {"func_a": "x" * 500, "func_b": "y" * 500}
        handle = tmp_store.put("test", data)
        summary = tmp_store.summary(handle, max_chars=300)
        assert "func_a" in summary
        assert len(summary) <= 500  # some overhead for key: format

    def test_summary_list(self, tmp_store):
        data = list(range(100))
        handle = tmp_store.put("test", data)
        summary = tmp_store.summary(handle, max_chars=200)
        assert "0" in summary

    def test_summary_string(self, tmp_store):
        data = "hello world" * 100
        handle = tmp_store.put("test", data)
        summary = tmp_store.summary(handle, max_chars=50)
        assert len(summary) <= 50

    def test_same_data_same_handle(self, tmp_store):
        """Same data should produce same content hash → same handle."""
        data = {"key": "value"}
        h1 = tmp_store.put("test", data)
        h2 = tmp_store.put("test", data)
        assert h1 == h2

    def test_different_data_different_handle(self, tmp_store):
        h1 = tmp_store.put("test", {"a": 1})
        h2 = tmp_store.put("test", {"b": 2})
        assert h1 != h2

    def test_metadata_sidecar_created(self, tmp_store):
        handle = tmp_store.put("test", {"data": True})
        meta_path = Path(tmp_store.base_dir) / f"{handle.replace(':', '_')}.meta"
        assert meta_path.exists()
        meta = json.loads(meta_path.read_text())
        assert meta["artifact_type"] == "test"
        assert meta["handle"] == handle


class TestGetArtifact:
    def test_handle_path(self, tmp_path):
        """get_artifact() uses handle when available."""
        store = ArtifactStore(str(tmp_path / ".artifacts"))
        data = {"func": "code"}
        handle = store.put("decompiled_functions", data)

        state = {
            "artifact_store_path": str(tmp_path / ".artifacts"),
            "decompiled_functions_handle": handle,
            "decompiled_functions": {},  # inline is empty
        }
        result = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
        assert result == data

    def test_fallback_to_inline(self):
        """get_artifact() falls back to inline state when no handle."""
        inline_data = {"func": "inline code"}
        state = {
            "artifact_store_path": "",
            "decompiled_functions_handle": "",
            "decompiled_functions": inline_data,
        }
        result = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
        assert result == inline_data

    def test_fallback_to_inline_when_handle_missing(self, tmp_path):
        """get_artifact() falls back to inline when handle file is missing."""
        inline_data = {"func": "code"}
        state = {
            "artifact_store_path": str(tmp_path / ".artifacts"),
            "decompiled_functions_handle": "decompiled_functions:nonexistent",
            "decompiled_functions": inline_data,
        }
        result = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
        assert result == inline_data

    def test_default_dict_for_functions(self):
        """get_artifact() returns {} for missing 'functions' fields."""
        state = {}
        result = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
        assert result == {}

    def test_default_list_for_traces(self):
        """get_artifact() returns [] for missing 'traces' fields."""
        state = {}
        result = get_artifact(state, "dynamic_traces", "dynamic_traces_handle")
        assert result == []

    def test_all_449_tests_compatible(self):
        """Smoke test: get_artifact with empty state returns sensible defaults."""
        empty_state: dict = {}
        assert get_artifact(empty_state, "decompiled_functions", "decompiled_functions_handle") == {}
        assert get_artifact(empty_state, "angr_results", "angr_results_handle") == {}
        assert get_artifact(empty_state, "dynamic_traces", "dynamic_traces_handle") == []
