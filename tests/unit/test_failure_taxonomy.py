"""Tests for failure taxonomy classification in the optimizer.

Covers:
- FailureType enum values
- FailureDB.record_failure persistence
- FailureDB.failure_stats aggregation
- classify_failure auto-classification logic
- FailureDB.suggest_improvements output
"""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from kraken.execution.optimizer import (
    FailureDB,
    FailureType,
    classify_failure,
)


# ── FailureType enum ────────────────────────────────────────────────────────


class TestFailureType:
    """FailureType enum has all expected members and string values."""

    def test_all_members_present(self):
        expected = {
            "NO_TOOL_MATCH",
            "TOOL_PARTIAL",
            "CLASSIFY_WRONG",
            "LLM_FLAKY",
            "TIMEOUT",
            "TOOL_CRASH",
            "FLAG_REJECTED",
            "UNKNOWN",
        }
        assert set(FailureType.__members__.keys()) == expected

    def test_string_values(self):
        assert FailureType.NO_TOOL_MATCH == "no_tool_match"
        assert FailureType.TOOL_PARTIAL == "tool_partial"
        assert FailureType.CLASSIFY_WRONG == "classify_wrong"
        assert FailureType.LLM_FLAKY == "llm_flaky"
        assert FailureType.TIMEOUT == "timeout"
        assert FailureType.TOOL_CRASH == "tool_crash"
        assert FailureType.FLAG_REJECTED == "flag_rejected"
        assert FailureType.UNKNOWN == "unknown"

    def test_is_str_enum(self):
        """FailureType values can be used as plain strings."""
        assert isinstance(FailureType.TIMEOUT, str)
        assert FailureType.TIMEOUT.value == "timeout"
        # Can compare directly with string
        assert FailureType.TIMEOUT == "timeout"

    def test_from_value(self):
        assert FailureType("no_tool_match") is FailureType.NO_TOOL_MATCH
        assert FailureType("flag_rejected") is FailureType.FLAG_REJECTED

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            FailureType("not_a_real_type")


# ── FailureDB.record_failure ────────────────────────────────────────────────


class TestRecordFailure:
    """record_failure writes entries to failures.json correctly."""

    def _make_db(self, tmp_path: Path) -> FailureDB:
        return FailureDB(db_path=tmp_path / "failures.json")

    def test_creates_file(self, tmp_path):
        db = self._make_db(tmp_path)
        db.record_failure("chall_a", "crypto", FailureType.NO_TOOL_MATCH)
        assert (tmp_path / "failures.json").exists()

    def test_writes_valid_json(self, tmp_path):
        db = self._make_db(tmp_path)
        db.record_failure("chall_a", "crypto", "no_tool_match", "no tools matched")
        data = json.loads((tmp_path / "failures.json").read_text())
        assert "failures" in data
        assert "summary" in data

    def test_entry_fields(self, tmp_path):
        db = self._make_db(tmp_path)
        entry = db.record_failure(
            challenge_id="PackedAway",
            challenge_type="forensics",
            failure_type=FailureType.TOOL_PARTIAL,
            details="file_carve found nested archive but didn't recurse",
            tools_tried=["auto_file_carve", "auto_archive_search"],
        )
        assert entry["challenge_id"] == "PackedAway"
        assert entry["challenge_type"] == "forensics"
        assert entry["failure_type"] == "tool_partial"
        assert "didn't recurse" in entry["details"]
        assert entry["tools_tried"] == ["auto_file_carve", "auto_archive_search"]
        assert "timestamp" in entry

    def test_multiple_failures_accumulate(self, tmp_path):
        db = self._make_db(tmp_path)
        db.record_failure("c1", "crypto", "no_tool_match")
        db.record_failure("c2", "rev", "tool_crash")
        db.record_failure("c3", "crypto", "no_tool_match")

        data = json.loads((tmp_path / "failures.json").read_text())
        assert len(data["failures"]) == 3
        assert data["summary"]["total"] == 3
        assert data["summary"]["no_tool_match"] == 2
        assert data["summary"]["tool_crash"] == 1

    def test_invalid_failure_type_defaults_to_unknown(self, tmp_path):
        db = self._make_db(tmp_path)
        entry = db.record_failure("c1", "misc", "bogus_type")
        assert entry["failure_type"] == "unknown"

    def test_enum_and_string_both_work(self, tmp_path):
        db = self._make_db(tmp_path)
        e1 = db.record_failure("c1", "crypto", FailureType.TIMEOUT)
        e2 = db.record_failure("c2", "crypto", "timeout")
        assert e1["failure_type"] == e2["failure_type"] == "timeout"

    def test_persists_across_instances(self, tmp_path):
        db_path = tmp_path / "failures.json"
        db1 = FailureDB(db_path=db_path)
        db1.record_failure("c1", "crypto", "no_tool_match")

        db2 = FailureDB(db_path=db_path)
        assert len(db2.to_dict()["failures"]) == 1

    def test_cap_at_max_failures(self, tmp_path):
        db = self._make_db(tmp_path)
        # Record more than _MAX_FAILURES
        for i in range(db._MAX_FAILURES + 50):
            db.record_failure(f"chall_{i}", "misc", "unknown")
        data = db.to_dict()
        assert len(data["failures"]) <= db._MAX_FAILURES

    def test_empty_tools_tried_defaults(self, tmp_path):
        db = self._make_db(tmp_path)
        entry = db.record_failure("c1", "crypto", "timeout")
        assert entry["tools_tried"] == []


# ── FailureDB.failure_stats ─────────────────────────────────────────────────


class TestFailureStats:
    """failure_stats returns correct aggregation."""

    def _make_db_with_data(self, tmp_path: Path) -> FailureDB:
        db = FailureDB(db_path=tmp_path / "failures.json")
        db.record_failure("c1", "crypto", "no_tool_match", tools_tried=["auto_xor_brute"])
        db.record_failure("c2", "crypto", "no_tool_match", tools_tried=["auto_c_brute"])
        db.record_failure("c3", "forensics", "tool_partial", details="found data no flag")
        db.record_failure("c4", "forensics", "tool_partial", details="incomplete extraction")
        db.record_failure("c5", "forensics", "tool_partial", details="nested archive")
        db.record_failure("c6", "rev", "tool_crash", tools_tried=["auto_angr"])
        db.record_failure("c7", "rev", "flag_rejected", details="candidate rejected")
        return db

    def test_by_failure_type(self, tmp_path):
        db = self._make_db_with_data(tmp_path)
        stats = db.failure_stats()
        by_ft = stats["by_failure_type"]
        assert by_ft["no_tool_match"] == 2
        assert by_ft["tool_partial"] == 3
        assert by_ft["tool_crash"] == 1
        assert by_ft["flag_rejected"] == 1

    def test_by_challenge_type(self, tmp_path):
        db = self._make_db_with_data(tmp_path)
        stats = db.failure_stats()
        by_ct = stats["by_challenge_type"]
        assert by_ct["crypto"]["total"] == 2
        assert by_ct["crypto"]["no_tool_match"] == 2
        assert by_ct["forensics"]["total"] == 3
        assert by_ct["forensics"]["tool_partial"] == 3
        assert by_ct["rev"]["total"] == 2

    def test_total(self, tmp_path):
        db = self._make_db_with_data(tmp_path)
        stats = db.failure_stats()
        assert stats["total"] == 7

    def test_top_failures_sorted(self, tmp_path):
        db = self._make_db_with_data(tmp_path)
        stats = db.failure_stats()
        top = stats["top_failures"]
        # tool_partial has 3, no_tool_match has 2
        assert top[0] == ("tool_partial", 3)
        assert top[1] == ("no_tool_match", 2)

    def test_empty_db(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        stats = db.failure_stats()
        assert stats["total"] == 0
        assert stats["by_failure_type"] == {}
        assert stats["by_challenge_type"] == {}
        assert stats["top_failures"] == []


# ── classify_failure ────────────────────────────────────────────────────────


class TestClassifyFailure:
    """Auto-classification logic from cascade results."""

    def test_empty_results_gives_no_tool_match(self):
        assert classify_failure([]) == "no_tool_match"

    def test_timeout_detection(self):
        results = [{"tool": "auto_angr", "stdout": "running...", "exit_code": 0}]
        # elapsed >= 95% of timeout
        assert classify_failure(results, elapsed=95.0, timeout=100.0) == "timeout"

    def test_timeout_not_triggered_below_threshold(self):
        results = [{"tool": "auto_angr", "stdout": "running...", "exit_code": 0}]
        result = classify_failure(results, elapsed=50.0, timeout=100.0)
        # Should be tool_partial since there's output
        assert result != "timeout"

    def test_flag_rejected_detection(self):
        results = [
            {
                "tool": "auto_source_decode",
                "stdout": "found something",
                "exit_code": 0,
                "flag": "flag{maybe_this}",
            }
        ]
        assert classify_failure(results) == "flag_rejected"

    def test_flag_candidate_key(self):
        results = [
            {
                "tool": "auto_angr",
                "stdout": "output",
                "exit_code": 0,
                "flag_candidate": "flag{test}",
            }
        ]
        assert classify_failure(results) == "flag_rejected"

    def test_tool_crash_detection(self):
        results = [
            {
                "tool": "auto_angr",
                "stdout": "",
                "stderr": "Traceback (most recent call last):\n  File ...\nValueError: bad",
                "exit_code": 1,
            }
        ]
        assert classify_failure(results) == "tool_crash"

    def test_tool_crash_with_error_keyword(self):
        results = [
            {
                "tool": "auto_gdb_cmp",
                "stdout": "",
                "stderr": "Error: binary not found",
                "exit_code": 2,
            }
        ]
        assert classify_failure(results) == "tool_crash"

    def test_tool_partial_with_output(self):
        results = [
            {
                "tool": "auto_source_decode",
                "stdout": "Decoded base64: some meaningful data that was found in the binary",
                "exit_code": 0,
            }
        ]
        assert classify_failure(results) == "tool_partial"

    def test_no_tool_match_with_empty_output(self):
        results = [
            {"tool": "auto_angr", "stdout": "", "exit_code": 0},
            {"tool": "auto_gdb_cmp", "stdout": "  \n", "exit_code": 0},
        ]
        assert classify_failure(results) == "no_tool_match"

    def test_multiple_results_flag_takes_priority(self):
        """If any result has a flag candidate, that takes priority."""
        results = [
            {"tool": "auto_angr", "stdout": "", "stderr": "Traceback\nError", "exit_code": 1},
            {"tool": "auto_source_decode", "stdout": "data", "exit_code": 0, "flag": "flag{x}"},
        ]
        assert classify_failure(results) == "flag_rejected"

    def test_crash_takes_priority_over_partial(self):
        """Crash + partial output = crash wins (if no flag candidate)."""
        results = [
            {"tool": "auto_angr", "stdout": "", "stderr": "Traceback\nError", "exit_code": 1},
            {"tool": "auto_source_decode", "stdout": "some data found here in the output", "exit_code": 0},
        ]
        # Flag rejected > crash > partial > no_tool_match
        # No flag candidate here, so crash wins over partial
        assert classify_failure(results) == "tool_crash"

    def test_no_timeout_when_timeout_is_zero(self):
        """When timeout is 0 (unset), never classify as timeout."""
        results = [{"tool": "auto_angr", "stdout": "data output here", "exit_code": 0}]
        assert classify_failure(results, elapsed=9999.0, timeout=0) != "timeout"


# ── FailureDB.suggest_improvements ──────────────────────────────────────────


class TestSuggestImprovements:
    """suggest_improvements returns actionable, sorted suggestions."""

    def test_empty_db_returns_empty(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        assert db.suggest_improvements() == []

    def test_returns_suggestions_sorted_by_impact(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        # 3 forensics tool_partial failures
        db.record_failure("c1", "forensics", "tool_partial", "no recurse")
        db.record_failure("c2", "forensics", "tool_partial", "no recurse")
        db.record_failure("c3", "forensics", "tool_partial", "no recurse")
        # 1 crypto no_tool_match
        db.record_failure("c4", "crypto", "no_tool_match")

        suggestions = db.suggest_improvements()
        assert len(suggestions) >= 2
        # Highest impact first
        assert suggestions[0]["impact"] >= suggestions[1]["impact"]
        assert suggestions[0]["failure_type"] == "tool_partial"
        assert suggestions[0]["challenge_type"] == "forensics"

    def test_suggestion_has_required_fields(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        db.record_failure("c1", "crypto", "no_tool_match", tools_tried=["auto_xor_brute"])

        suggestions = db.suggest_improvements()
        assert len(suggestions) == 1
        s = suggestions[0]
        assert "suggestion" in s
        assert "impact" in s
        assert "failure_type" in s
        assert "challenge_type" in s
        assert "affected_challenges" in s
        assert s["impact"] == 1
        assert "c1" in s["affected_challenges"]

    def test_no_tool_match_suggestion_text(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        db.record_failure("c1", "crypto", "no_tool_match", tools_tried=["auto_xor_brute"])
        db.record_failure("c2", "crypto", "no_tool_match", tools_tried=["auto_c_brute"])

        suggestions = db.suggest_improvements()
        s = suggestions[0]
        assert "Add new tool" in s["suggestion"]
        assert "crypto" in s["suggestion"]

    def test_tool_crash_suggestion_text(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        db.record_failure("c1", "rev", "tool_crash", tools_tried=["auto_angr"])

        suggestions = db.suggest_improvements()
        s = suggestions[0]
        assert "Fix crashing" in s["suggestion"]
        assert "auto_angr" in s["suggestion"]

    def test_flag_rejected_suggestion_text(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        db.record_failure("c1", "misc", "flag_rejected", details="low diversity")

        suggestions = db.suggest_improvements()
        s = suggestions[0]
        assert "validation" in s["suggestion"].lower() or "Loosen" in s["suggestion"]

    def test_timeout_suggestion_text(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        db.record_failure("c1", "rev", "timeout", tools_tried=["auto_angr"])

        suggestions = db.suggest_improvements()
        s = suggestions[0]
        assert "timeout" in s["suggestion"].lower() or "performance" in s["suggestion"].lower()

    def test_deduplication_by_challenge_id(self, tmp_path):
        """Same challenge failing twice should count as 1 in impact."""
        db = FailureDB(db_path=tmp_path / "failures.json")
        db.record_failure("c1", "crypto", "no_tool_match")
        db.record_failure("c1", "crypto", "no_tool_match")  # duplicate

        suggestions = db.suggest_improvements()
        # Impact should be 1 (unique challenges), not 2
        assert suggestions[0]["impact"] == 1
        assert suggestions[0]["affected_challenges"] == ["c1"]

    def test_all_failure_types_produce_suggestions(self, tmp_path):
        db = FailureDB(db_path=tmp_path / "failures.json")
        for ft in FailureType:
            db.record_failure(f"chall_{ft.value}", "misc", ft)

        suggestions = db.suggest_improvements()
        suggestion_types = {s["failure_type"] for s in suggestions}
        # Every failure type should generate a suggestion
        assert suggestion_types == {ft.value for ft in FailureType}
