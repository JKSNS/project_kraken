"""Tests for kraken.nodes.failure_analysis -- diagnose_failure and extract_script_findings."""
import pytest

from kraken.nodes.failure_analysis import diagnose_failure, extract_script_findings


# ── diagnose_failure ─────────────────────────────────────────────────


class TestDiagnoseFailure:
    """Test deterministic failure pattern matching."""

    def test_module_not_found(self):
        diag = diagnose_failure("", "ModuleNotFoundError: No module named 'pwntools'", 1)
        assert "[missing_module]" in diag
        assert "pwntools" in diag

    def test_import_error(self):
        diag = diagnose_failure("", "ImportError: cannot import name 'foo'", 1)
        assert "[import_error]" in diag
        assert "foo" in diag

    def test_file_not_found(self):
        diag = diagnose_failure("", "FileNotFoundError: [Errno 2] No such file or directory: '/tmp/bin'", 1)
        assert "[file_not_found]" in diag
        assert "/tmp/bin" in diag

    def test_permission_denied(self):
        diag = diagnose_failure("", "PermissionError: [Errno 13] Permission denied: '/opt/x'", 1)
        assert "[permission_denied]" in diag

    def test_timeout(self):
        diag = diagnose_failure("", "Script timed out after 120s", 1)
        assert "[timeout]" in diag
        assert "120" in diag

    def test_memory_error(self):
        diag = diagnose_failure("", "MemoryError", 1)
        assert "[memory_error]" in diag

    def test_killed_oom(self):
        diag = diagnose_failure("", "Killed", 137)
        assert "[memory_error]" in diag

    def test_angr_timeout(self):
        diag = diagnose_failure("angr exploration timed out", "", 1)
        assert "[angr_timeout]" in diag
        assert "veritesting" in diag

    def test_angr_unsat(self):
        diag = diagnose_failure("UNSAT", "", 1)
        assert "[angr_unsat]" in diag

    def test_segfault(self):
        diag = diagnose_failure("", "Segmentation fault", 139)
        assert "[segfault]" in diag

    def test_syntax_error(self):
        # Pattern: r"Traceback.*SyntaxError" -- .* doesn't cross newlines,
        # so Traceback and SyntaxError must be on the same line
        diag = diagnose_failure("some output", "Traceback ...SyntaxError: invalid syntax", 1)
        assert "[syntax_error]" in diag

    def test_z3_timeout(self):
        diag = diagnose_failure("z3 solver timeout", "", 1)
        assert "[z3_timeout]" in diag

    def test_index_error(self):
        diag = diagnose_failure("", "IndexError: list index out of range", 1)
        assert "[index_error]" in diag

    def test_key_error(self):
        diag = diagnose_failure("", "KeyError: '.text'", 1)
        assert "[key_error]" in diag
        assert ".text" in diag

    def test_value_error(self):
        diag = diagnose_failure("", "ValueError: invalid literal for int()", 1)
        assert "[value_error]" in diag

    def test_missing_section(self):
        diag = diagnose_failure("No section named .rodata", "", 1)
        assert "[missing_section]" in diag

    def test_lief_error(self):
        diag = diagnose_failure("lief.parse failed with error", "", 1)
        assert "[lief_error]" in diag

    def test_no_output_success_exit(self):
        """Script exits 0 but produces nothing."""
        diag = diagnose_failure("", "", 0)
        assert "[no_output]" in diag

    def test_unknown_failure(self):
        """Non-zero exit with no recognized pattern (but has some output to avoid empty_output match)."""
        diag = diagnose_failure("something weird happened", "some stderr", 42)
        assert "[unknown_failure]" in diag
        assert "42" in diag

    def test_no_failure(self):
        """Successful script with output should return empty string."""
        # Need non-empty stdout to avoid empty_output pattern
        diag = diagnose_failure("flag{test}", "no errors", 0)
        assert diag == ""

    def test_multiple_patterns(self):
        """Multiple patterns can fire at once."""
        stderr = "ModuleNotFoundError: No module named 'z3'\nScript timed out after 30s"
        diag = diagnose_failure("", stderr, 1)
        assert "[missing_module]" in diag
        assert "[timeout]" in diag

    def test_case_insensitivity(self):
        """Patterns should match case-insensitively."""
        diag = diagnose_failure("", "segmentation fault (core dumped)", 139)
        assert "[segfault]" in diag


# ── extract_script_findings ──────────────────────────────────────────


class TestExtractScriptFindings:
    """Test intermediate result extraction from script output."""

    def test_key_extraction(self):
        findings = extract_script_findings("Key: 0xdeadbeef\n", "")
        assert any("key:" in f.lower() for f in findings)
        assert any("deadbeef" in f for f in findings)

    def test_partial_flag(self):
        findings = extract_script_findings("Flag: partial_result_here\n", "")
        assert any("partial_flag:" in f.lower() for f in findings)

    def test_decrypted_data(self):
        findings = extract_script_findings("Decrypted: hello_world_flag\n", "")
        assert any("decrypted:" in f.lower() for f in findings)

    def test_password(self):
        findings = extract_script_findings("Password: s3cr3t_p4ss\n", "")
        assert any("password:" in f.lower() for f in findings)

    def test_offset(self):
        # Offset pattern: (?:offset|Offset|OFFSET)[:\s=]+(?:0x)?...
        findings = extract_script_findings("Offset=0x4041\n", "")
        assert any("offset:" in f.lower() for f in findings)

    def test_address(self):
        findings = extract_script_findings("Address: 0x401000\n", "")
        assert any("address:" in f.lower() for f in findings)

    def test_xor_result(self):
        findings = extract_script_findings("XOR key result: decoded_string\n", "")
        assert any("xor_result:" in f.lower() for f in findings)

    def test_b64_decoded(self):
        # The "decoded" keyword also matches the "decrypted" pattern earlier,
        # so deduplicate may cause "b64_decoded" to appear OR "decrypted" depending on order.
        # The important thing is the value is captured.
        findings = extract_script_findings("b64 decoded=secretvalue123\n", "")
        assert any("secretvalue123" in f for f in findings)

    def test_flag_like(self):
        # The flag_like pattern captures prefix before {}, group(1) is the prefix.
        # "Flag:" pattern may match first. Test with a clear flag-like string.
        findings = extract_script_findings("Flag: ABCD{test_value}\n", "")
        assert len(findings) > 0
        assert any("ABCD" in f or "test_value" in f for f in findings)

    def test_empty_output(self):
        findings = extract_script_findings("", "")
        assert findings == []

    def test_deduplication(self):
        """Same value shouldn't appear twice."""
        findings = extract_script_findings("Key: deadbeef\nKey: deadbeef\n", "")
        values = [f.split(": ", 1)[1] for f in findings]
        assert len(values) == len(set(values))

    def test_cap_at_20(self):
        """Should return at most 20 findings."""
        # Generate many findings
        output = "\n".join(f"Key: {hex(i * 0x1111)}" for i in range(1, 50))
        findings = extract_script_findings(output, "")
        assert len(findings) <= 20

    def test_stderr_also_checked(self):
        """Findings from stderr should be extracted too."""
        findings = extract_script_findings("", "Key: 0xaabb\n")
        assert len(findings) > 0

    def test_short_values_filtered(self):
        """Values shorter than 3 chars should be filtered."""
        findings = extract_script_findings("Key: ab\n", "")
        # "ab" is too short (< 3 chars)
        assert not any("ab" == f.split(": ", 1)[1] for f in findings if ": " in f)
