"""Unit tests for flag_validator node -- including enhanced features (#1, #2, #8)."""
import re
import pytest
from unittest.mock import patch

from kraken.nodes.flag_validator import (
    flag_validator,
    route_from_validator,
    _check_output_files,
    _detect_hallucinated_flag,
    _extract_flag_candidate,
    _is_likely_printable_flag,
    _normalized_flag_pattern,
    _is_likely_ctf_body,
    _looks_like_binary_success,
    _is_suspicious_low_diversity_flag,
    _is_runtime_noise_flag,
)


# ── Core flag finding ────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_flag_found_in_stdout():
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{"stdout": "The flag is flag{test_123}\n", "stderr": "", "exit_code": 0, "attempt_num": 1}],
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    assert result["flag"] == "flag{test_123}"
    assert result["next_node"] == "__end__"


@pytest.mark.asyncio
async def test_flag_rejected_when_binary_rejects_candidate():
    """Even regex-matching candidate should be rejected if binary says wrong."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "binary_path": "/tmp/fake_bin",
        "solve_scripts": [{"stdout": "flag{almost_right}\n", "stderr": "", "exit_code": 0, "attempt_num": 1, "strategy": "crypto"}],
        "current_strategy": "crypto",
        "iteration_count": 5,
    }
    with patch("kraken.nodes.flag_validator._verify_flag_with_binary", return_value=False):
        result = await flag_validator(state)
    assert "flag" not in result
    assert result["next_node"] in ("solve_engine", "manager")


@pytest.mark.asyncio
async def test_flag_rejected_when_non_printable_candidate():
    state = {
        "flag_format": r"vere\{[^\}]+\}",
        "solve_scripts": [{"stdout": "vere{l\u00e4`Q0Yg\u00a2}\n", "stderr": "", "exit_code": 0, "attempt_num": 1, "strategy": "crypto"}],
        "current_strategy": "crypto",
        "iteration_count": 5,
    }
    with patch("kraken.nodes.flag_validator._check_output_files", return_value=None):
        result = await flag_validator(state)
    assert "flag" not in result
    assert result["next_node"] in ("solve_engine", "manager")


@pytest.mark.asyncio
async def test_flag_rejected_when_nested_braces_in_body():
    state = {
        "flag_format": "vere{}",
        "solve_scripts": [{"stdout": "vere{vere{tphts/:/brasdra.loc#8m/2c4a}\n", "stderr": "", "exit_code": 0, "attempt_num": 1, "strategy": "crypto"}],
        "current_strategy": "crypto",
        "iteration_count": 5,
    }
    with patch("kraken.nodes.flag_validator._check_output_files", return_value=None):
        result = await flag_validator(state)
    assert "flag" not in result
    assert result["next_node"] in ("solve_engine", "manager")




@pytest.mark.asyncio
async def test_malformed_candidate_sets_diagnosis_and_finding():
    state = {
        "flag_format": "vere{}",
        "solve_scripts": [{
            "stdout": "Flag: vere{vere{tphts/:/brasdra.loc#8m/2c4a}\n",
            "stderr": "",
            "exit_code": 0,
            "attempt_num": 1,
            "strategy": "constraint",
        }],
        "current_strategy": "constraint",
        "iteration_count": 2,
    }
    with patch("kraken.nodes.flag_validator._check_output_files", return_value=None):
        result = await flag_validator(state)
    assert "flag" not in result
    assert "failure_diagnosis" in result
    assert "malformed_flag_candidate" in result["failure_diagnosis"]
    assert any("malformed" in f.lower() for f in result.get("script_findings", []))

@pytest.mark.asyncio
async def test_flag_found_in_stderr():
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{"stdout": "no flag", "stderr": "flag{in_stderr}", "exit_code": 0, "attempt_num": 1}],
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    assert result["flag"] == "flag{in_stderr}"
    assert result["next_node"] == "__end__"


@pytest.mark.asyncio
async def test_flag_not_found():
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{"stdout": "no flag here", "stderr": "", "exit_code": 1, "attempt_num": 1, "strategy": "xor"}],
        "current_strategy": "xor",
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    assert "flag" not in result
    assert result["next_node"] in ("solve_engine", "manager")


@pytest.mark.asyncio
async def test_no_scripts():
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [],
        "iteration_count": 0,
    }
    result = await flag_validator(state)
    assert result["next_node"] == "manager"


def test_route_from_validator():
    assert route_from_validator({"next_node": "__end__"}) == "__end__"
    assert route_from_validator({"next_node": "manager"}) == "manager"
    assert route_from_validator({"next_node": "solve_engine"}) == "solve_engine"
    assert route_from_validator({}) == "manager"


# ── Failure diagnosis integration (#1) ───────────────────────────────


@pytest.mark.asyncio
async def test_failure_diagnosis_injected():
    """When flag not found and stderr has patterns, failure_diagnosis should be set."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{
            "stdout": "", "stderr": "ModuleNotFoundError: No module named 'z3'",
            "exit_code": 1, "attempt_num": 1, "strategy": "constraint",
        }],
        "current_strategy": "constraint",
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    assert "failure_diagnosis" in result
    assert "missing_module" in result["failure_diagnosis"]


@pytest.mark.asyncio
async def test_no_diagnosis_on_clean_failure():
    """No diagnosis for generic failures with non-empty output and stderr."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{
            "stdout": "wrong answer: 42", "stderr": "some log line",
            "exit_code": 0, "attempt_num": 1, "strategy": "crypto",
        }],
        "current_strategy": "crypto",
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    # No recognized error patterns (output isn't empty), so no diagnosis
    assert result.get("failure_diagnosis", "") == "" or "failure_diagnosis" not in result


# ── Script findings integration (#2) ────────────────────────────────


@pytest.mark.asyncio
async def test_script_findings_extracted():
    """Intermediate results should be extracted and stored."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{
            "stdout": "Key: 0xdeadbeef\nDecrypted: partial_result\n", "stderr": "",
            "exit_code": 1, "attempt_num": 1, "strategy": "crypto",
        }],
        "current_strategy": "crypto",
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    assert "script_findings" in result
    assert len(result["script_findings"]) > 0


# ── Self-correction routing ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_self_correction_within_budget():
    """First failure should route to solve_engine for self-correction."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{
            "stdout": "nope", "stderr": "",
            "exit_code": 1, "attempt_num": 1, "strategy": "xor_decode",
        }],
        "current_strategy": "xor_decode",
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    assert result["next_node"] == "solve_engine"


@pytest.mark.asyncio
async def test_escalation_after_max_corrections():
    """After max_self_corrections, should escalate to manager."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [
            {"stdout": "", "stderr": "err", "exit_code": 1, "strategy": "xor_decode", "attempt_num": i}
            for i in range(1, 5)  # 4 attempts with same strategy
        ],
        "current_strategy": "xor_decode",
        "iteration_count": 20,
    }
    result = await flag_validator(state)
    assert result["next_node"] == "manager"


# ── Hallucination detection (#8) ─────────────────────────────────────


class TestDetectHallucinatedFlag:

    def test_hardcoded_flag_detected(self):
        code = 'print("flag{hardcoded_value}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is True

    def test_computed_flag_not_detected(self):
        """Flag from computation (not in string literal) should not trigger."""
        code = "result = decode(data)\nprint(result)"
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_flag_in_comment_skipped(self):
        code = '# Example: flag{test_example}\nresult = solve()'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_flag_in_regex_skipped(self):
        code = 're.search(r"flag{test}", output)'
        # "re." appears before the flag on the same line
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_flag_in_format_string_skipped(self):
        code = 'format("flag{placeholder}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_no_flag_in_code(self):
        code = "x = 42\nprint(x)"
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_flag_in_bytes_literal(self):
        code = 'data = b"flag{bytes_literal}"'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is True


# ── Output file checking (#8) ───────────────────────────────────────


class TestCheckOutputFiles:

    def test_no_files_returns_none(self):
        """When no flag files exist, should return None."""
        with patch("glob.glob", return_value=[]):
            result = _check_output_files(r"flag\{[a-zA-Z0-9_]+\}")
        assert result is None

    def test_flag_found_in_file(self, tmp_path):
        """Flag in output file should be found."""
        flag_file = tmp_path / "flag.txt"
        flag_file.write_text("flag{from_file}")

        with patch("glob.glob", side_effect=lambda p: [str(flag_file)] if "flag" in p else []):
            result = _check_output_files(r"flag\{[a-zA-Z0-9_]+\}")
        assert result == "flag{from_file}"

    def test_no_match_in_file(self, tmp_path):
        """File without flag should return None."""
        out_file = tmp_path / "output.txt"
        out_file.write_text("no flag here\n")

        with patch("glob.glob", side_effect=lambda p: [str(out_file)] if "output" in p else []):
            result = _check_output_files(r"flag\{[a-zA-Z0-9_]+\}")
        assert result is None


def test_common_pattern_extraction_picoctf():
    flag, source = _extract_flag_candidate("", "picoCTF{abc123}", r"flag\{[a-z]+\}")
    assert flag == "picoCTF{abc123}"
    assert source.startswith("common:")


def test_brace_heuristic_extraction():
    flag, source = _extract_flag_candidate("candidate token: custom{alpha_beta_123}", "", r"flag\{x+\}")
    assert flag == "custom{alpha_beta_123}"
    assert source == "brace_heuristic"


def test_printable_flag_heuristic():
    assert _is_likely_printable_flag("vere{b4s1c_r3v_pr0gr4m_lol}") is True
    assert _is_likely_printable_flag("vere{l\u00e4`Q0Yg\u00a2}") is False


def test_normalized_flag_pattern_for_placeholder_format():
    pat = _normalized_flag_pattern("vere{}")
    assert re.search(pat, "vere{b4s1c_r3v_pr0gr4m_lol}")
    # Widened regex now accepts special chars in flag body (!, @, %, etc.)
    assert re.search(pat, "vere{ce>J]ogr%mn3GG}")
    # But closing brace still terminates the match
    assert not re.search(pat, "vere{ab}")


def test_ctf_body_heuristic():
    assert _is_likely_ctf_body("vere{b4s1c_r3v_pr0gr4m_lol}") is True
    assert _is_likely_ctf_body("vere{ce>J]ogr%mn3GG}") is True
    assert _is_likely_ctf_body("vere{vere{tphts/:/brasdra.loc#8m/2c4a}") is False


def test_binary_success_heuristic():
    assert _looks_like_binary_success(b"Correct!\n") is True
    assert _looks_like_binary_success(b"wrong input\n") is False
    assert _looks_like_binary_success(b"") is None


def test_low_diversity_flag_heuristic():
    assert _is_suspicious_low_diversity_flag("vere{thpsaaaaaaaaaaaaaaaaaaaaa}") is True
    assert _is_suspicious_low_diversity_flag("vere{b4s1c_r3v_pr0gr4m_lol}") is False


class TestComputationWhitelistExpanded:
    """Expanded computation whitelist should not flag scripts using CTF libraries."""

    def test_pycryptodome_not_hallucination(self):
        code = 'from Crypto.Cipher import AES\nkey = b"secret"\nprint("flag{decrypted_value}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_pwntools_not_hallucination(self):
        code = 'from pwn import *\nresult = xor(data, key)\nprint("flag{pwned}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_sympy_not_hallucination(self):
        code = 'import sympy\nresult = sympy.solve(eq)\nprint("flag{solved}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_numpy_not_hallucination(self):
        code = 'import numpy as np\narr = numpy.array([1,2])\nprint("flag{computed}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_decrypt_keyword_not_hallucination(self):
        code = 'plaintext = decrypt(ciphertext, key)\nprint("flag{decrypted}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_xor_keyword_not_hallucination(self):
        code = 'result = xor(data, 0x42)\nprint("flag{xored}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is False

    def test_plain_print_still_hallucination(self):
        """Script with no computation indicators should still be flagged."""
        code = 'print("flag{totally_made_up}")'
        assert _detect_hallucinated_flag(code, r"flag\{[a-zA-Z0-9_]+\}") is True


# ── Runtime noise flag rejection ─────────────────────────────────────


class TestRuntimeNoiseFlag:
    """Reject candidates whose prefix is a runtime/compiler internal namespace."""

    def test_rspunycode_rejected(self):
        """rspunycode{-} from Rust punycode internals must be rejected."""
        assert _is_runtime_noise_flag("rspunycode{-}") is True

    def test_rspunycode_with_longer_body_rejected(self):
        assert _is_runtime_noise_flag("rspunycode{some_thing}") is True

    def test_rustc_rejected(self):
        assert _is_runtime_noise_flag("rustc{1.75.0}") is True

    def test_llvm_rejected(self):
        assert _is_runtime_noise_flag("llvm{metadata_string}") is True

    def test_cargo_rejected(self):
        assert _is_runtime_noise_flag("cargo{build_info}") is True

    def test_gimli_rejected(self):
        assert _is_runtime_noise_flag("gimli{dwarf_section}") is True

    def test_libcore_rejected(self):
        assert _is_runtime_noise_flag("libcore{panic_impl}") is True

    def test_glibc_rejected(self):
        assert _is_runtime_noise_flag("glibc{version_info}") is True

    def test_runtime_rejected(self):
        assert _is_runtime_noise_flag("runtime{goroutine_stack}") is True

    def test_valid_flag_prefix_not_rejected(self):
        """Normal CTF flag prefixes must NOT be rejected."""
        assert _is_runtime_noise_flag("flag{real_flag_value}") is False

    def test_picoctf_not_rejected(self):
        assert _is_runtime_noise_flag("picoCTF{some_flag}") is False

    def test_htb_not_rejected(self):
        assert _is_runtime_noise_flag("HTB{hackthebox}") is False

    def test_vere_not_rejected(self):
        assert _is_runtime_noise_flag("vere{challenge_flag}") is False

    def test_custom_prefix_not_rejected(self):
        assert _is_runtime_noise_flag("myctf{custom_flag}") is False

    def test_case_insensitive_rejection(self):
        """Rejection should be case-insensitive."""
        assert _is_runtime_noise_flag("RUSTC{version}") is True
        assert _is_runtime_noise_flag("Llvm{info}") is True

    def test_no_braces_returns_false(self):
        assert _is_runtime_noise_flag("just_a_string") is False

    def test_empty_returns_false(self):
        assert _is_runtime_noise_flag("") is False
        assert _is_runtime_noise_flag(None) is False


@pytest.mark.asyncio
async def test_runtime_noise_rejected_from_tool_candidate():
    """tool_flag_candidate with runtime noise prefix should be rejected."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "tool_flag_candidate": "rspunycode{-}",
        "solve_scripts": [],
        "iteration_count": 0,
    }
    result = await flag_validator(state)
    assert "flag" not in result
    assert result["next_node"] == "manager"


@pytest.mark.asyncio
async def test_runtime_noise_rejected_from_stdout():
    """Runtime noise in stdout should not be accepted as a flag."""
    state = {
        "flag_format": r"flag\{[a-zA-Z0-9_]+\}",
        "solve_scripts": [{
            "stdout": "Found: rspunycode{-}\n",
            "stderr": "",
            "exit_code": 0,
            "attempt_num": 1,
            "strategy": "rev",
        }],
        "current_strategy": "rev",
        "iteration_count": 5,
    }
    result = await flag_validator(state)
    assert "flag" not in result
    assert result["next_node"] in ("solve_engine", "manager")
