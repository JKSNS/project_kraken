"""Tests for the auto_patcher flag-gate scanner and patcher.

Tests cover:
  - Flag gate pattern scanning (mov byte, mov dword, conditional jumps)
  - Confidence boosting near interesting strings
  - Patching operations (offset, NOP, value)
  - Flag extraction from patched binary output
  - Tool router integration (_build_patcher_command)
"""
from __future__ import annotations

import os
import struct
import tempfile
from unittest.mock import patch

import pytest

from kraken.helpers.auto_patcher import (
    FlagGate,
    _find_flags,
    _scan_mov_byte_gates,
    _scan_mov_byte_short_gates,
    _scan_mov_dword_gates,
    _scan_conditional_jump_gates,
    _scan_near_conditional_jump_gates,
    _boost_gates_near_strings,
    _boost_gates_near_test_cmp,
    scan_flag_gates,
    scan_all_gates,
    patch_at_offset,
    nop_at_offset,
    apply_gates,
)
from kraken.nodes.tool_router import _build_tool_command


# ── Helper to create a minimal ELF binary in memory ──────────────────────

def _make_elf_header() -> bytes:
    """Return a minimal 64-bit ELF header (enough for our scanner)."""
    # ELF magic + class(64) + endian(LE) + version + OS/ABI + padding
    return (
        b"\x7fELF"           # magic
        + b"\x02"            # 64-bit
        + b"\x01"            # little-endian
        + b"\x01"            # ELF version
        + b"\x00" * 9        # OS/ABI + padding
        + b"\x02\x00"        # type = EXEC
        + b"\x3e\x00"        # machine = x86-64
        + b"\x01\x00\x00\x00"  # version
        + b"\x00" * 40       # rest of header (entry, phoff, shoff, etc.)
    )


def _make_binary_with_data(data: bytes) -> bytes:
    """Return ELF header + data."""
    return _make_elf_header() + data


# ── _scan_mov_byte_gates tests ───────────────────────────────────────────


class TestScanMovByteGates:
    def test_finds_c685_pattern(self):
        """C6 85 xx xx xx xx 00 should be detected as a mov_byte_long gate."""
        # mov byte [rbp-0xd29], 0x0
        # C6 85 D7 F2 FF FF 00
        data = b"\x90" * 16 + b"\xc6\x85\xd7\xf2\xff\xff\x00" + b"\x90" * 16
        gates = _scan_mov_byte_gates(data)
        assert len(gates) >= 1
        gate = gates[0]
        assert gate.offset == 16 + 6  # immediate byte offset
        assert gate.original == b"\x00"
        assert gate.patched == b"\x01"
        assert gate.pattern_type == "mov_byte_long"

    def test_ignores_nonzero_immediate(self):
        """C6 85 xx xx xx xx 01 should NOT match (immediate is already 0x01)."""
        data = b"\x90" * 16 + b"\xc6\x85\xd7\xf2\xff\xff\x01" + b"\x90" * 16
        gates = _scan_mov_byte_gates(data)
        assert len(gates) == 0

    def test_multiple_gates(self):
        """Multiple C6 85 patterns should all be detected."""
        pattern = b"\xc6\x85\x00\x00\x00\x00\x00"
        data = pattern + b"\x90" * 4 + pattern + b"\x90" * 8
        gates = _scan_mov_byte_gates(data)
        assert len(gates) == 2

    def test_empty_data(self):
        gates = _scan_mov_byte_gates(b"")
        assert gates == []


class TestScanMovByteShortGates:
    def test_finds_c645_pattern(self):
        """C6 45 xx 00 should be detected as a mov_byte_short gate."""
        # mov byte [rbp+0xb], 0x0
        data = b"\x90" * 8 + b"\xc6\x45\x0b\x00" + b"\x90" * 8
        gates = _scan_mov_byte_short_gates(data)
        assert len(gates) >= 1
        gate = gates[0]
        assert gate.offset == 8 + 3
        assert gate.original == b"\x00"
        assert gate.patched == b"\x01"
        assert gate.pattern_type == "mov_byte_short"

    def test_ignores_nonzero(self):
        data = b"\xc6\x45\x0b\x01"
        gates = _scan_mov_byte_short_gates(data)
        assert len(gates) == 0


class TestScanMovDwordGates:
    def test_finds_c785_pattern(self):
        """C7 85 xx xx xx xx 00 00 00 00 should be detected."""
        data = b"\x90" * 4 + b"\xc7\x85\x00\x00\x00\x00\x00\x00\x00\x00" + b"\x90" * 4
        gates = _scan_mov_dword_gates(data)
        assert len(gates) >= 1
        gate = gates[0]
        assert gate.offset == 4 + 6
        assert gate.original == b"\x00\x00\x00\x00"
        assert gate.patched == b"\x01\x00\x00\x00"
        assert gate.pattern_type == "mov_dword"


class TestScanConditionalJumpGates:
    def test_finds_je_short(self):
        """74 xx should be detected as je short."""
        data = b"\x90" * 4 + b"\x74\x10" + b"\x90" * 4
        gates = _scan_conditional_jump_gates(data)
        je_gates = [g for g in gates if g.pattern_type == "je_to_jne"]
        assert len(je_gates) >= 1
        gate = je_gates[0]
        assert gate.offset == 4
        assert gate.original == b"\x74"
        assert gate.patched == b"\x75"

    def test_finds_jne_short(self):
        """75 xx should be detected as jne short."""
        data = b"\x90" * 4 + b"\x75\x08" + b"\x90" * 4
        gates = _scan_conditional_jump_gates(data)
        jne_gates = [g for g in gates if g.pattern_type == "jne_to_je"]
        assert len(jne_gates) >= 1


class TestScanNearConditionalJumpGates:
    def test_finds_je_near(self):
        """0F 84 xx xx xx xx should be detected as je near."""
        data = b"\x90" * 4 + b"\x0f\x84\x10\x00\x00\x00" + b"\x90" * 4
        gates = _scan_near_conditional_jump_gates(data)
        assert len(gates) >= 1
        gate = gates[0]
        assert gate.pattern_type == "je_near_to_jne"
        assert gate.original == b"\x84"
        assert gate.patched == b"\x85"

    def test_finds_jne_near(self):
        """0F 85 xx xx xx xx should be detected as jne near."""
        data = b"\x90" * 4 + b"\x0f\x85\x10\x00\x00\x00" + b"\x90" * 4
        gates = _scan_near_conditional_jump_gates(data)
        assert len(gates) >= 1
        gate = gates[0]
        assert gate.pattern_type == "jne_near_to_je"


# ── Confidence boosting tests ────────────────────────────────────────────


class TestConfidenceBoosting:
    def test_boost_near_flag_string(self):
        """Gates near 'flag' string should get boosted confidence."""
        # Put a gate and a "flag" string within 4KB of each other
        gate_data = b"\xc6\x85\x00\x00\x00\x00\x00"
        padding = b"\x90" * 100
        string_data = b"flag"
        data = gate_data + padding + string_data + b"\x90" * 100

        gates = _scan_mov_byte_gates(data)
        assert len(gates) == 1
        original_conf = gates[0].confidence

        _boost_gates_near_strings(data, gates)
        assert gates[0].confidence > original_conf

    def test_no_boost_far_from_strings(self):
        """Gates far from interesting strings should not be boosted."""
        gate_data = b"\xc6\x85\x00\x00\x00\x00\x00"
        # Put 5KB of padding (beyond the 4KB threshold)
        padding = b"\x90" * 5000
        string_data = b"flag"
        data = gate_data + padding + string_data

        gates = _scan_mov_byte_gates(data)
        assert len(gates) == 1
        original_conf = gates[0].confidence

        _boost_gates_near_strings(data, gates)
        assert gates[0].confidence == original_conf

    def test_boost_near_htb_prefix(self):
        """Gates near 'HTB{' should get boosted."""
        gate_data = b"\xc6\x85\x00\x00\x00\x00\x00"
        data = gate_data + b"\x90" * 50 + b"HTB{" + b"\x90" * 50

        gates = _scan_mov_byte_gates(data)
        _boost_gates_near_strings(data, gates)
        assert gates[0].confidence > 0.6  # boosted above default 0.6

    def test_boost_test_cmp_before_je(self):
        """je gate preceded by test eax,eax should get boosted."""
        # test eax,eax = 85 C0, then je short = 74 10
        data = b"\x90" * 4 + b"\x85\xc0\x74\x10" + b"\x90" * 4
        gates = _scan_conditional_jump_gates(data)
        je_gates = [g for g in gates if g.pattern_type == "je_to_jne"]
        assert len(je_gates) >= 1
        original_conf = je_gates[0].confidence
        _boost_gates_near_test_cmp(data, je_gates)
        assert je_gates[0].confidence > original_conf


# ── Full scan tests ──────────────────────────────────────────────────────


class TestScanFlagGates:
    def test_scan_elf_binary(self, tmp_path):
        """scan_flag_gates should work on a valid ELF with mov byte gates."""
        # Build a fake ELF with a mov byte gate
        gate_bytes = b"\xc6\x85\xd7\xf2\xff\xff\x00"
        data = _make_binary_with_data(b"\x90" * 100 + gate_bytes + b"\x90" * 100)
        binary = tmp_path / "test_binary"
        binary.write_bytes(data)

        gates = scan_flag_gates(str(binary))
        mov_gates = [g for g in gates if g.pattern_type.startswith("mov_")]
        assert len(mov_gates) >= 1

    def test_scan_all_includes_jumps(self, tmp_path):
        """scan_all_gates should also find conditional jump gates."""
        gate_bytes = b"\x74\x10"  # je short
        data = _make_binary_with_data(b"\x90" * 100 + gate_bytes + b"\x90" * 100)
        binary = tmp_path / "test_binary"
        binary.write_bytes(data)

        # scan_flag_gates should NOT find jump gates
        gates = scan_flag_gates(str(binary))
        je_gates = [g for g in gates if "je" in g.pattern_type]
        assert len(je_gates) == 0

        # scan_all_gates SHOULD find them
        gates = scan_all_gates(str(binary))
        je_gates = [g for g in gates if "je" in g.pattern_type]
        assert len(je_gates) >= 1

    def test_sorted_by_confidence(self, tmp_path):
        """Results should be sorted highest confidence first."""
        # Two gates: one near a "flag" string, one far away
        gate1 = b"\xc6\x85\x00\x00\x00\x00\x00"
        gate2 = b"\xc6\x85\x01\x00\x00\x00\x00"
        # gate1 near "flag", gate2 far away
        data = _make_binary_with_data(
            gate1 + b"flag" + b"\x90" * 100
            + b"\x90" * 5000
            + gate2 + b"\x90" * 100
        )
        binary = tmp_path / "test_binary"
        binary.write_bytes(data)

        gates = scan_flag_gates(str(binary))
        if len(gates) >= 2:
            assert gates[0].confidence >= gates[1].confidence


# ── Patching tests ───────────────────────────────────────────────────────


class TestPatchAtOffset:
    def test_basic_patch(self, tmp_path):
        """patch_at_offset should write bytes at the given offset."""
        binary = tmp_path / "original"
        binary.write_bytes(b"\x00" * 16)
        out = tmp_path / "patched"

        patch_at_offset(str(binary), str(out), 4, b"\x01")

        data = out.read_bytes()
        assert data[4] == 0x01
        assert data[3] == 0x00  # untouched
        assert data[5] == 0x00  # untouched

    def test_multi_byte_patch(self, tmp_path):
        binary = tmp_path / "original"
        binary.write_bytes(b"\x00" * 16)
        out = tmp_path / "patched"

        patch_at_offset(str(binary), str(out), 8, b"\xDE\xAD\xBE\xEF")

        data = out.read_bytes()
        assert data[8:12] == b"\xDE\xAD\xBE\xEF"

    def test_preserves_other_bytes(self, tmp_path):
        original_data = bytes(range(32))
        binary = tmp_path / "original"
        binary.write_bytes(original_data)
        out = tmp_path / "patched"

        patch_at_offset(str(binary), str(out), 10, b"\xFF")

        data = out.read_bytes()
        assert data[10] == 0xFF
        assert data[:10] == original_data[:10]
        assert data[11:] == original_data[11:]

    def test_output_is_executable(self, tmp_path):
        binary = tmp_path / "original"
        binary.write_bytes(b"\x00" * 16)
        out = tmp_path / "patched"

        patch_at_offset(str(binary), str(out), 0, b"\x01")
        assert os.access(str(out), os.X_OK)


class TestNopAtOffset:
    def test_nop_single_byte(self, tmp_path):
        binary = tmp_path / "original"
        binary.write_bytes(b"\xCC" * 16)
        out = tmp_path / "patched"

        nop_at_offset(str(binary), str(out), 4, 1)

        data = out.read_bytes()
        assert data[4] == 0x90

    def test_nop_multiple_bytes(self, tmp_path):
        binary = tmp_path / "original"
        binary.write_bytes(b"\xCC" * 16)
        out = tmp_path / "patched"

        nop_at_offset(str(binary), str(out), 2, 5)

        data = out.read_bytes()
        assert data[2:7] == b"\x90" * 5
        assert data[0] == 0xCC  # untouched
        assert data[7] == 0xCC  # untouched


class TestApplyGates:
    def test_apply_multiple_gates(self, tmp_path):
        binary = tmp_path / "original"
        binary.write_bytes(b"\x00" * 32)
        out = tmp_path / "patched"

        gates = [
            FlagGate(4, b"\x00", b"\x01", "mov_byte_long", "gate1"),
            FlagGate(12, b"\x00", b"\x01", "mov_byte_short", "gate2"),
        ]

        apply_gates(str(binary), str(out), gates)
        data = out.read_bytes()
        assert data[4] == 0x01
        assert data[12] == 0x01
        assert data[0] == 0x00  # untouched


# ── Flag finding tests ───────────────────────────────────────────────────


class TestFindFlags:
    def test_htb_flag(self):
        flags = _find_flags("Output: HTB{br1ng_th3_p4rt5_t0g3th3r}", r"HTB\{[^}]+\}")
        assert "HTB{br1ng_th3_p4rt5_t0g3th3r}" in flags

    def test_generic_flag(self):
        flags = _find_flags("The flag is flag{test_value_123}", "")
        assert "flag{test_value_123}" in flags

    def test_no_flag(self):
        flags = _find_flags("Nothing to see here", r"HTB\{[^}]+\}")
        assert len(flags) == 0

    def test_multiple_flags(self):
        text = "flag{one} and also flag{two_more}"
        flags = _find_flags(text, "")
        assert len(flags) >= 2

    def test_low_diversity_rejected(self):
        """Flags with single-char bodies (e.g. flag{aaaa}) should be rejected."""
        flags = _find_flags("flag{aa}", "")
        # body "aa" has only 1 unique char -> should be filtered
        # But body needs len >= 3 for generic pattern, so "aa" won't match anyway
        assert len(flags) == 0


# ── Tool router integration tests ────────────────────────────────────────


class TestBuildPatcherCommand:
    def test_builds_command_with_flag_gate(self):
        """When has_flag_gate is True, auto_patcher should build a command."""
        params = {"has_flag_gate": True, "input_mode": "stdin"}
        state = {
            "challenge_path": "/tmp/test_binary",
            "flag_format": r"HTB\{[^}]+\}",
        }
        # Mock os.path.isfile to return True
        with patch("os.path.isfile", return_value=True):
            cmd = _build_tool_command("auto_patcher", params, state)
        assert cmd is not None
        assert "auto_patcher.py" in cmd
        assert "--auto" in cmd
        assert "--flag-format" in cmd
        assert "HTB" in cmd

    def test_builds_command_with_no_input(self):
        """When no_user_input is True, auto_patcher should build a command."""
        params = {"no_user_input": True, "input_mode": "unknown"}
        state = {"challenge_path": "/tmp/test_binary"}
        with patch("os.path.isfile", return_value=True):
            cmd = _build_tool_command("auto_patcher", params, state)
        assert cmd is not None
        assert "--auto" in cmd

    def test_builds_command_with_unknown_input_mode(self):
        """When input_mode is 'unknown', auto_patcher should try."""
        params = {"input_mode": "unknown"}
        state = {"challenge_path": "/tmp/test_binary"}
        with patch("os.path.isfile", return_value=True):
            cmd = _build_tool_command("auto_patcher", params, state)
        assert cmd is not None

    def test_skips_when_stdin_input(self):
        """When input_mode is 'stdin' and no gate detected, skip."""
        params = {"input_mode": "stdin", "has_flag_gate": False, "no_user_input": False}
        state = {"challenge_path": "/tmp/test_binary"}
        with patch("os.path.isfile", return_value=True):
            cmd = _build_tool_command("auto_patcher", params, state)
        assert cmd is None

    def test_skips_when_no_binary(self):
        """No binary path -> should skip."""
        params = {"has_flag_gate": True}
        state = {"challenge_path": ""}
        cmd = _build_tool_command("auto_patcher", params, state)
        assert cmd is None

    def test_skips_when_directory(self):
        """Directory path -> should skip."""
        params = {"has_flag_gate": True}
        state = {"challenge_path": "/tmp"}
        cmd = _build_tool_command("auto_patcher", params, state)
        assert cmd is None


# ── Param extractor integration tests ────────────────────────────────────


class TestParamExtractorFlagGate:
    def test_detects_found_false_gate(self):
        from kraken.tools.param_extractor import extract_solve_params

        code = """
        int main(void) {
            bool found = false;
            // ... processing ...
            if (found) {
                puts("flag{secret}");
            }
            return 0;
        }
        """
        result = extract_solve_params(
            decompiled_functions={"main": code},
            strings=[],
            binary_info={},
        )
        assert result["has_flag_gate"] is True

    def test_detects_success_zero_gate(self):
        from kraken.tools.param_extractor import extract_solve_params

        code = """
        void check(void) {
            int success = 0;
            // ... validation ...
            if (success != 0) {
                printf("You won!");
            }
        }
        """
        result = extract_solve_params(
            decompiled_functions={"check": code},
            strings=[],
            binary_info={},
        )
        assert result["has_flag_gate"] is True

    def test_detects_local_var_gate(self):
        from kraken.tools.param_extractor import extract_solve_params

        code = """
        void run(void) {
            local_a8 = 0;
            // ECS tick processing
            if (local_a8 == 1) {
                print_flag();
            }
        }
        """
        result = extract_solve_params(
            decompiled_functions={"run": code},
            strings=[],
            binary_info={},
        )
        assert result["has_flag_gate"] is True

    def test_no_gate_in_normal_code(self):
        from kraken.tools.param_extractor import extract_solve_params

        code = """
        int main(int argc, char **argv) {
            if (argc != 2) return 1;
            char *input = argv[1];
            if (strcmp(input, "password") == 0) {
                puts("Correct!");
            }
            return 0;
        }
        """
        result = extract_solve_params(
            decompiled_functions={"main": code},
            strings=["Correct!"],
            binary_info={},
        )
        # This code has strcmp-based validation, not a boolean gate
        # However, local_xx patterns aren't present, so has_flag_gate should be False
        assert result["has_flag_gate"] is False

    def test_no_user_input_detected(self):
        from kraken.tools.param_extractor import extract_solve_params

        code = """
        int main(void) {
            srand(42);
            // ECS simulation, no user input
            run_simulation();
            return 0;
        }
        """
        result = extract_solve_params(
            decompiled_functions={"main": code},
            strings=[],
            binary_info={},
        )
        assert result["no_user_input"] is True

    def test_has_user_input_stdin(self):
        from kraken.tools.param_extractor import extract_solve_params

        code = """
        int main(void) {
            char buf[64];
            fgets(buf, 64, stdin);
            return 0;
        }
        """
        result = extract_solve_params(
            decompiled_functions={"main": code},
            strings=[],
            binary_info={},
        )
        assert result["no_user_input"] is False

    def test_has_user_input_argv(self):
        from kraken.tools.param_extractor import extract_solve_params

        code = """
        int main(int argc, char **argv) {
            if (argc != 2) return 1;
            char *input = argv[1];
            return 0;
        }
        """
        result = extract_solve_params(
            decompiled_functions={"main": code},
            strings=[],
            binary_info={},
        )
        assert result["no_user_input"] is False


# ── FlecksOfGold-like pattern test ───────────────────────────────────────


class TestFlecksOfGoldPattern:
    """Test that the scanner detects the exact pattern from FlecksOfGold."""

    def test_detects_flecks_gate_pattern(self, tmp_path):
        """The exact byte sequence from FlecksOfGold should be detected."""
        # From the real binary: C6 85 D7 F2 FF FF 00
        # This is: mov byte [rbp-0xd29], 0x0
        gate_bytes = b"\xc6\x85\xd7\xf2\xff\xff\x00"

        # Build a minimal "binary" with ELF header + padding + gate
        data = _make_binary_with_data(
            b"\x90" * 0x100 + gate_bytes + b"\x90" * 0x100
        )
        binary = tmp_path / "flecks"
        binary.write_bytes(data)

        gates = scan_flag_gates(str(binary))
        # Should find at least the gate we planted
        mov_long_gates = [g for g in gates if g.pattern_type == "mov_byte_long"]
        assert len(mov_long_gates) >= 1

        # Find the gate at the expected offset
        expected_offset = len(_make_elf_header()) + 0x100 + 6  # imm byte offset
        matching = [g for g in mov_long_gates if g.offset == expected_offset]
        assert len(matching) == 1
        gate = matching[0]
        assert gate.original == b"\x00"
        assert gate.patched == b"\x01"

    def test_patch_flips_byte(self, tmp_path):
        """Patching the detected gate should flip 0x00 -> 0x01."""
        gate_bytes = b"\xc6\x85\xd7\xf2\xff\xff\x00"
        data = _make_binary_with_data(
            b"\x90" * 0x100 + gate_bytes + b"\x90" * 0x100
        )
        binary = tmp_path / "flecks"
        binary.write_bytes(data)
        out = tmp_path / "flecks_patched"

        gates = scan_flag_gates(str(binary))
        mov_gates = [g for g in gates if g.pattern_type == "mov_byte_long"]
        apply_gates(str(binary), str(out), mov_gates)

        patched_data = out.read_bytes()
        # The immediate byte should now be 0x01
        imm_offset = len(_make_elf_header()) + 0x100 + 6
        assert patched_data[imm_offset] == 0x01
        # The rest of the instruction should be unchanged
        assert patched_data[imm_offset - 6:imm_offset] == b"\xc6\x85\xd7\xf2\xff\xff"
