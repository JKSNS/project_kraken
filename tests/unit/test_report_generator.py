"""Tests for kraken.reporting.generator -- report generation."""
import pytest

from kraken.reporting.generator import generate_report, _format_duration


class TestFormatDuration:
    def test_seconds(self):
        assert _format_duration(5.3) == "5.3s"

    def test_minutes(self):
        assert _format_duration(125) == "2m05s"

    def test_hours(self):
        assert _format_duration(3661) == "1h01m01s"

    def test_zero(self):
        assert _format_duration(0) == "0.0s"


class TestGenerateWriteup:
    def test_basic_writeup(self):
        result = {
            "solved": True,
            "flag": "flag{test_flag}",
            "duration_seconds": 42.5,
            "strategies_tried": ["XOR decode"],
            "solve_path": ["triage", "decompile", "classify", "solve_engine"],
            "node_timings": [
                {"node": "triage", "duration_s": 5.0},
                {"node": "decompile", "duration_s": 10.0},
                {"node": "classify", "duration_s": 2.0},
                {"node": "solve_engine", "duration_s": 25.5},
            ],
            "challenge_id": "test_challenge",
            "challenge_type": "crypto",
        }
        report = generate_report(result, mode="writeup")
        assert "test_challenge" in report
        assert "flag{test_flag}" in report
        assert "Solved" in report
        assert "crypto" in report

    def test_unsolved_writeup(self):
        result = {
            "solved": False,
            "flag": "",
            "duration_seconds": 300,
            "strategies_tried": ["angr", "z3"],
            "challenge_id": "hard_challenge",
            "challenge_type": "constraint",
        }
        report = generate_report(result, mode="writeup")
        assert "Unsolved" in report
        assert "hard_challenge" in report

    def test_writeup_with_state(self):
        result = {"solved": True, "flag": "flag{x}", "duration_seconds": 10}
        state = {
            "challenge_id": "my_challenge",
            "challenge_type": "pwn",
            "challenge_description": "Exploit the buffer overflow",
            "binary_info": {"file_type": "ELF 64-bit", "architecture": "x86_64"},
            "solve_scripts": [{"code": "from pwn import *", "exit_code": 0, "stdout": "flag{x}"}],
        }
        report = generate_report(result, state=state, mode="writeup")
        assert "Exploit the buffer overflow" in report
        assert "ELF 64-bit" in report
        assert "from pwn import" in report


class TestGenerateAnalysis:
    def test_basic_analysis(self):
        state = {
            "challenge_id": "binary_analysis",
            "challenge_path": "/tmp/binary",
            "binary_info": {"file_type": "ELF 64-bit", "architecture": "x86_64"},
            "decompiled_functions": {"main": "int main() { return 0; }"},
            "strings_of_interest": ["Hello", "flag{"],
        }
        report = generate_report({}, state=state, mode="analysis")
        assert "Binary Analysis Report" in report
        assert "binary_analysis" in report
        assert "ELF 64-bit" in report
        assert "main" in report


class TestGenerateBenchmark:
    def test_benchmark_report(self):
        results = [
            {"challenge_id": "c1", "solved": True, "challenge_type": "crypto", "duration_seconds": 30, "strategies_tried": []},
            {"challenge_id": "c2", "solved": False, "challenge_type": "pwn", "duration_seconds": 300, "strategies_tried": ["rop"]},
            {"challenge_id": "c3", "solved": True, "challenge_type": "crypto", "duration_seconds": 15, "strategies_tried": []},
        ]
        report = generate_report(results, mode="benchmark")
        assert "Benchmark Report" in report
        assert "2/3" in report or "66" in report  # 2 out of 3 solved
        assert "crypto" in report
        assert "pwn" in report

    def test_empty_benchmark(self):
        report = generate_report([], mode="benchmark")
        assert "Benchmark Report" in report
        assert "0" in report


class TestGenerateToFile:
    def test_output_path(self, tmp_path):
        result = {"solved": True, "flag": "flag{x}", "challenge_id": "test", "duration_seconds": 1}
        output = str(tmp_path / "report.md")
        report = generate_report(result, mode="writeup", output_path=output)
        assert (tmp_path / "report.md").exists()
        contents = (tmp_path / "report.md").read_text()
        assert contents == report
