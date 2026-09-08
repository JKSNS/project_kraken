"""Tests for kraken.execution.solve_session -- SolveSession lifecycle."""
import json
import time

import pytest

from kraken.execution.solve_session import SolveSession, StepRecord, _safe_snapshot


# ── StepRecord ───────────────────────────────────────────────────────────────


class TestStepRecord:
    def test_to_dict(self):
        step = StepRecord(
            name="triage",
            started_at=100.0,
            elapsed_seconds=1.2345,
            input_summary="challenge_path=/tmp/test",
            output_keys=["binary_info", "strings_of_interest"],
            output_snapshot={"binary_info": {"file_type": "ELF"}},
        )
        d = step.to_dict()
        assert d["name"] == "triage"
        assert d["elapsed_seconds"] == 1.2345
        assert "binary_info" in d["output_keys"]
        assert d["output_snapshot"]["binary_info"]["file_type"] == "ELF"
        assert d["error"] == ""

    def test_error_field(self):
        step = StepRecord(
            name="decompile",
            started_at=0,
            elapsed_seconds=0.5,
            error="Ghidra not found",
        )
        d = step.to_dict()
        assert d["error"] == "Ghidra not found"


# ── SolveSession creation ────────────────────────────────────────────────────


class TestSolveSessionCreation:
    def test_defaults(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        assert session.challenge_id == "test"
        assert session.challenge_path == "/tmp/test"
        assert len(session.session_id) == 12
        assert session.steps == []
        assert session.flag == ""
        assert session.solved is False
        assert session.total_elapsed == 0.0

    def test_session_id_unique(self):
        s1 = SolveSession(challenge_id="a", challenge_path="/a")
        s2 = SolveSession(challenge_id="a", challenge_path="/a")
        assert s1.session_id != s2.session_id


# ── add_step ─────────────────────────────────────────────────────────────────


class TestAddStep:
    def test_add_step_basic(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        step = session.add_step(
            "triage",
            "challenge_path=/tmp/test",
            {"binary_info": {"file_type": "ELF"}, "strings_of_interest": ["hello"]},
            1.5,
        )
        assert len(session.steps) == 1
        assert step.name == "triage"
        assert step.elapsed_seconds == 1.5
        assert "binary_info" in step.output_keys
        assert step.error == ""

    def test_add_step_with_error(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        step = session.add_step("decompile", "binary=/tmp/x", {}, 0.1, error="failed")
        assert step.error == "failed"
        assert step.output_keys == []

    def test_input_summary_truncated(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        long_input = "x" * 1000
        step = session.add_step("triage", long_input, {}, 0.1)
        assert len(step.input_summary) == 500

    def test_multiple_steps(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        session.add_step("triage", "", {"a": 1}, 1.0)
        session.add_step("decompile", "", {"b": 2}, 2.0)
        session.add_step("extract_params", "", {"c": 3}, 0.5)
        assert len(session.steps) == 3
        assert [s.name for s in session.steps] == ["triage", "decompile", "extract_params"]


# ── finalize ─────────────────────────────────────────────────────────────────


class TestFinalize:
    def test_finalize_sets_elapsed(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        time.sleep(0.01)
        session.finalize()
        assert session.total_elapsed > 0

    def test_finalize_after_steps(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        session.add_step("triage", "", {}, 1.0)
        session.flag = "flag{test}"
        session.solved = True
        session.finalize()
        assert session.total_elapsed > 0
        assert session.solved is True


# ── to_dict ──────────────────────────────────────────────────────────────────


class TestToDict:
    def test_serializable(self):
        session = SolveSession(challenge_id="test", challenge_path="/tmp/test")
        session.add_step("triage", "input", {"key": "value"}, 1.0)
        session.triage_result = {"binary_info": {"file_type": "ELF"}}
        session.flag = "flag{abc}"
        session.solved = True
        session.solving_tool = "auto_c_source_eval"
        session.finalize()

        d = session.to_dict()
        # Must be JSON-serializable
        serialized = json.dumps(d)
        assert isinstance(serialized, str)

        # Check fields
        assert d["session_id"] == session.session_id
        assert d["challenge_id"] == "test"
        assert d["solved"] is True
        assert d["flag"] == "flag{abc}"
        assert d["solving_tool"] == "auto_c_source_eval"
        assert d["total_elapsed"] >= 0  # monotonic clock -- may be 0 on fast machines
        assert len(d["steps"]) == 1
        assert d["triage_result"]["binary_info"]["file_type"] == "ELF"

    def test_empty_session_serializable(self):
        session = SolveSession(challenge_id="x", challenge_path="/x")
        d = session.to_dict()
        json.dumps(d)  # should not raise
        assert d["steps"] == []
        assert d["cascade_results"] == []


# ── save / load roundtrip ────────────────────────────────────────────────────


class TestSaveLoad:
    def test_save_creates_structure(self, tmp_path):
        session = SolveSession(challenge_id="test_chall", challenge_path="/tmp/test")
        session.add_step("triage", "input", {"binary_info": {}}, 0.5)
        session.triage_result = {"binary_info": {"file_type": "ELF"}}
        session.decompile_result = {"decompiled_functions": {"main": "int main(){}"}}
        session.extracted_params = {"input_mode": "stdin", "input_length": 32}
        session.cascade_results = [
            {"tool": "auto_source_decode", "flag": "", "exit_code": 0},
            {"tool": "auto_c_source_eval", "flag": "flag{test}", "exit_code": 0},
        ]
        session.flag = "flag{test}"
        session.solved = True
        session.solving_tool = "auto_c_source_eval"
        session.finalize()

        out = tmp_path / "test_chall"
        session.save(out)

        assert (out / "session.json").exists()
        assert (out / "flag.txt").exists()
        assert (out / "flag.txt").read_text().strip() == "flag{test}"
        assert (out / "artifacts" / "triage.json").exists()
        assert (out / "artifacts" / "decompile.json").exists()
        assert (out / "artifacts" / "params.json").exists()
        assert (out / "artifacts" / "cascade.json").exists()
        assert (out / "artifacts" / "timeline.jsonl").exists()
        assert (out / "scripts").is_dir()

    def test_no_flag_file_when_unsolved(self, tmp_path):
        session = SolveSession(challenge_id="x", challenge_path="/tmp/x")
        session.finalize()
        session.save(tmp_path / "x")
        assert not (tmp_path / "x" / "flag.txt").exists()

    def test_roundtrip(self, tmp_path):
        session = SolveSession(challenge_id="rt", challenge_path="/tmp/rt")
        session.add_step("triage", "input", {"binary_info": {"file_type": "ELF"}}, 1.5)
        session.add_step("decompile", "binary", {"decompiled_functions": {}}, 3.0)
        session.triage_result = {"binary_info": {"file_type": "ELF"}, "strings_of_interest": ["x"]}
        session.extracted_params = {"input_mode": "stdin"}
        session.cascade_results = [{"tool": "auto_angr", "flag": "", "exit_code": 1}]
        session.flag = "flag{roundtrip}"
        session.solved = True
        session.solving_tool = "auto_angr"
        session.total_elapsed = 4.5
        session.finalize()

        out = tmp_path / "rt"
        session.save(out)

        loaded = SolveSession.load(out / "session.json")
        assert loaded.session_id == session.session_id
        assert loaded.challenge_id == "rt"
        assert loaded.flag == "flag{roundtrip}"
        assert loaded.solved is True
        assert loaded.solving_tool == "auto_angr"
        assert len(loaded.steps) == 2
        assert loaded.steps[0].name == "triage"
        assert loaded.steps[0].elapsed_seconds == 1.5
        assert loaded.steps[1].name == "decompile"
        assert loaded.triage_result["binary_info"]["file_type"] == "ELF"
        assert loaded.extracted_params["input_mode"] == "stdin"
        assert len(loaded.cascade_results) == 1

    def test_timeline_jsonl(self, tmp_path):
        session = SolveSession(challenge_id="tl", challenge_path="/tmp/tl")
        session.add_step("triage", "", {}, 1.0)
        session.add_step("decompile", "", {}, 2.0)
        session.finalize()
        session.save(tmp_path / "tl")

        lines = (tmp_path / "tl" / "artifacts" / "timeline.jsonl").read_text().strip().split("\n")
        assert len(lines) == 2
        first = json.loads(lines[0])
        assert first["name"] == "triage"
        second = json.loads(lines[1])
        assert second["name"] == "decompile"

    def test_scripts_extracted(self, tmp_path):
        session = SolveSession(challenge_id="sc", challenge_path="/tmp/sc")
        session.cascade_results = [
            {"tool": "auto_angr", "script": "import angr\nangr.Project('x')"},
            {"tool": "auto_z3", "code": "from z3 import *"},
            {"tool": "auto_gdb", "flag": ""},  # no script
        ]
        session.finalize()
        session.save(tmp_path / "sc")

        assert (tmp_path / "sc" / "scripts" / "attempt_1.py").read_text() == "import angr\nangr.Project('x')"
        assert (tmp_path / "sc" / "scripts" / "attempt_2.py").read_text() == "from z3 import *"
        assert not (tmp_path / "sc" / "scripts" / "attempt_3.py").exists()


# ── _safe_snapshot ───────────────────────────────────────────────────────────


class TestSafeSnapshot:
    def test_basic_types(self):
        assert _safe_snapshot(42) == 42
        assert _safe_snapshot(3.14) == 3.14
        assert _safe_snapshot(True) is True
        assert _safe_snapshot(None) is None
        assert _safe_snapshot("hello") == "hello"

    def test_truncates_long_strings(self):
        long = "x" * 10000
        result = _safe_snapshot(long, max_str_len=100)
        assert len(result) < 200
        assert "truncated" in result

    def test_dict(self):
        d = {"a": 1, "b": "hello", "c": [1, 2]}
        assert _safe_snapshot(d) == d

    def test_bytes_converted(self):
        result = _safe_snapshot(b"\x7fELF")
        assert isinstance(result, str)
        assert "7f454c46" in result

    def test_nested(self):
        d = {"a": {"b": {"c": "x" * 10000}}}
        result = _safe_snapshot(d, max_str_len=50)
        assert "truncated" in result["a"]["b"]["c"]

    def test_non_serializable_type(self):
        result = _safe_snapshot(object())
        assert isinstance(result, str)


# ── Report generation from session ───────────────────────────────────────────


class TestReportFromSession:
    @pytest.fixture()
    def sample_session_dict(self):
        return {
            "session_id": "abc123",
            "challenge_id": "test_challenge",
            "challenge_path": "/tmp/test",
            "solved": True,
            "flag": "flag{test_flag}",
            "solving_tool": "auto_c_source_eval",
            "total_elapsed": 16.5,
            "steps": [
                {
                    "name": "triage",
                    "started_at": 0,
                    "elapsed_seconds": 0.3,
                    "input_summary": "challenge_path=/tmp/test",
                    "output_keys": ["binary_info", "strings_of_interest"],
                    "output_snapshot": {},
                    "artifacts_created": [],
                    "error": "",
                },
                {
                    "name": "decompile",
                    "started_at": 0,
                    "elapsed_seconds": 12.1,
                    "input_summary": "binary=/tmp/test/binary",
                    "output_keys": ["decompiled_functions"],
                    "output_snapshot": {"decompiled_functions": {"main": "int main(){}", "check": "void check(){}"}},
                    "artifacts_created": [],
                    "error": "",
                },
                {
                    "name": "extract_params",
                    "started_at": 0,
                    "elapsed_seconds": 0.1,
                    "input_summary": "functions=2",
                    "output_keys": ["input_mode", "input_length"],
                    "output_snapshot": {"input_mode": "stdin", "input_length": 32, "success_string": "Correct"},
                    "artifacts_created": [],
                    "error": "",
                },
                {
                    "name": "tool_cascade",
                    "started_at": 0,
                    "elapsed_seconds": 4.0,
                    "input_summary": "type=auto",
                    "output_keys": ["tool_cascade_results", "tool_flag_candidate"],
                    "output_snapshot": {},
                    "artifacts_created": [],
                    "error": "",
                },
            ],
            "triage_result": {
                "binary_info": {"file_type": "ELF x86-64", "corruption_detected": False},
                "strings_of_interest": ["Correct!", "Wrong!", "Enter flag:"],
            },
            "decompile_result": {"decompiled_functions": {"main": "int main(){}", "check": "void check(){}"}},
            "extracted_params": {"input_mode": "stdin", "input_length": 32},
            "cascade_results": [
                {"tool": "auto_source_decode", "flag": "", "exit_code": 0},
                {"tool": "auto_constraint_extract", "flag": "", "exit_code": 0},
                {"tool": "auto_c_source_eval", "flag": "flag{test_flag}", "exit_code": 0},
            ],
        }

    def test_mindmap_output(self, sample_session_dict):
        from kraken.reporting.generator import generate_report

        report = generate_report(sample_session_dict, mode="mindmap")
        assert "test_challenge" in report
        assert "SOLVED" in report
        assert "flag{test_flag}" in report
        assert "auto_source_decode" in report
        assert "auto_c_source_eval" in report
        assert "FLAG FOUND" in report

    def test_mindmap_unsolved(self, sample_session_dict):
        from kraken.reporting.generator import generate_report

        sample_session_dict["solved"] = False
        sample_session_dict["flag"] = ""
        report = generate_report(sample_session_dict, mode="mindmap")
        assert "UNSOLVED" in report

    def test_timeline_output(self, sample_session_dict):
        from kraken.reporting.generator import generate_report

        report = generate_report(sample_session_dict, mode="timeline")
        assert "test_challenge" in report
        assert "abc123" in report
        assert "Triage" in report
        assert "Decompile" in report
        assert "Extract Params" in report
        assert "Tool Cascade" in report
        assert "SOLVED" in report
        assert "auto_source_decode" in report

    def test_timeline_tool_table(self, sample_session_dict):
        from kraken.reporting.generator import generate_report

        report = generate_report(sample_session_dict, mode="timeline")
        assert "| # | Tool |" in report
        assert "auto_c_source_eval" in report

    def test_mindmap_with_error_step(self, sample_session_dict):
        from kraken.reporting.generator import generate_report

        sample_session_dict["steps"][1]["error"] = "Ghidra timeout"
        report = generate_report(sample_session_dict, mode="mindmap")
        assert "ERROR" in report
        assert "Ghidra timeout" in report

    def test_report_to_file(self, tmp_path, sample_session_dict):
        from kraken.reporting.generator import generate_report

        output = str(tmp_path / "report.md")
        report = generate_report(sample_session_dict, mode="mindmap", output_path=output)
        assert (tmp_path / "report.md").exists()
        assert (tmp_path / "report.md").read_text() == report

    def test_session_writeup_mode(self, sample_session_dict):
        from kraken.reporting.generator import generate_report

        report = generate_report(sample_session_dict, mode="session_writeup")
        assert "test_challenge" in report
        assert "SOLVED" in report
        assert "flag{test_flag}" in report
        assert "auto_c_source_eval" in report
        assert "## Binary Analysis" in report
        assert "ELF x86-64" in report
        assert "## Extracted Parameters" in report
        assert "## Solve Pipeline" in report
        assert "## Tool Cascade" in report
        assert "## Decision Tree" in report

    def test_writeup_auto_detects_session(self, sample_session_dict):
        """writeup mode with session_id in data should auto-use session_writeup."""
        from kraken.reporting.generator import generate_report

        report = generate_report(sample_session_dict, mode="writeup")
        # Should contain session-writeup-specific sections
        assert "## Solve Pipeline" in report
        assert "## Decision Tree" in report

    def test_mindmap_solving_tool_marked(self, sample_session_dict):
        """Solving tool should show FLAG FOUND even when individual result has no flag."""
        from kraken.reporting.generator import generate_report

        # Clear flag from individual cascade result but keep session-level flag
        for r in sample_session_dict["cascade_results"]:
            r["flag"] = ""
        report = generate_report(sample_session_dict, mode="mindmap")
        assert "auto_c_source_eval" in report
        assert "FLAG FOUND" in report

    def test_session_writeup_cascade_table_shows_flag(self, sample_session_dict):
        """Solving tool row in cascade table should show flag even if not in individual result."""
        from kraken.reporting.generator import generate_report

        # Clear individual flags
        for r in sample_session_dict["cascade_results"]:
            r["flag"] = ""
        report = generate_report(sample_session_dict, mode="session_writeup")
        assert "flag{test_flag}" in report


# ── Auto-README in save() ────────────────────────────────────────────────────


class TestAutoReadme:
    def test_save_generates_readme(self, tmp_path):
        session = SolveSession(challenge_id="readme_test", challenge_path="/tmp/test")
        session.add_step("triage", "input", {"binary_info": {"file_type": "ELF"}}, 0.5)
        session.triage_result = {"binary_info": {"file_type": "ELF x86-64"}}
        session.flag = "flag{readme_works}"
        session.solved = True
        session.solving_tool = "auto_angr"
        session.finalize()
        session.save(tmp_path / "readme_test")

        readme_path = tmp_path / "readme_test" / "README.md"
        assert readme_path.exists()
        content = readme_path.read_text()
        assert "readme_test" in content
        assert "SOLVED" in content
        assert "flag{readme_works}" in content
        assert "auto_angr" in content

    def test_save_no_readme_crash_on_error(self, tmp_path):
        """README generation failure should not prevent save from completing."""
        session = SolveSession(challenge_id="x", challenge_path="/tmp/x")
        session.finalize()
        session.save(tmp_path / "x")
        # session.json should still exist even if README generation had issues
        assert (tmp_path / "x" / "session.json").exists()
