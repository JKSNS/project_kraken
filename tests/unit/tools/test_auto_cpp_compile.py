"""Tests for the auto_cpp_compile helper tool.

Tests cover:
  - Detection of compilable source files (.c, .cpp, Makefile, etc.)
  - Compilation of a simple C file
  - Flag extraction from binary output
  - Graceful failure when no source files found
  - Tool router integration (_build_cpp_compile_command)
"""
from __future__ import annotations

import os
import stat
import subprocess
import tempfile

import pytest

from kraken.helpers.auto_cpp_compile import (
    _find_sources,
    _scan_for_flag,
    compile_sources,
    run_binary,
)
from kraken.nodes.tool_router import _build_tool_command


# ── Source detection tests ───────────────────────────────────────────────


class TestFindSources:
    def test_detects_c_file(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() { return 0; }")
        result = _find_sources(str(tmp_path))
        assert len(result["c_files"]) == 1
        assert result["c_files"][0].endswith("main.c")

    def test_detects_cpp_file(self, tmp_path):
        (tmp_path / "solver.cpp").write_text("int main() { return 0; }")
        result = _find_sources(str(tmp_path))
        assert len(result["cpp_files"]) == 1

    def test_detects_cc_file(self, tmp_path):
        (tmp_path / "prog.cc").write_text("int main() {}")
        result = _find_sources(str(tmp_path))
        assert len(result["cpp_files"]) == 1

    def test_detects_asm_file(self, tmp_path):
        (tmp_path / "entry.s").write_text(".globl _start")
        result = _find_sources(str(tmp_path))
        assert len(result["asm_files"]) == 1

    def test_detects_makefile(self, tmp_path):
        (tmp_path / "Makefile").write_text("all: main\nmain: main.c\n\tgcc -o main main.c")
        result = _find_sources(str(tmp_path))
        assert result["makefile"] is not None

    def test_detects_cmake(self, tmp_path):
        (tmp_path / "CMakeLists.txt").write_text("cmake_minimum_required(VERSION 3.10)")
        result = _find_sources(str(tmp_path))
        assert result["cmake"] is not None

    def test_detects_build_sh(self, tmp_path):
        (tmp_path / "build.sh").write_text("#!/bin/bash\ngcc -o main main.c")
        result = _find_sources(str(tmp_path))
        assert result["build_sh"] is not None

    def test_empty_directory(self, tmp_path):
        result = _find_sources(str(tmp_path))
        assert result["makefile"] is None
        assert result["cmake"] is None
        assert result["c_files"] == []
        assert result["cpp_files"] == []
        assert result["asm_files"] == []

    def test_ignores_directories(self, tmp_path):
        (tmp_path / "src.c").mkdir()  # directory named src.c
        result = _find_sources(str(tmp_path))
        assert result["c_files"] == []

    def test_multiple_c_files(self, tmp_path):
        (tmp_path / "main.c").write_text("int main() {}")
        (tmp_path / "utils.c").write_text("void util() {}")
        (tmp_path / "helper.c").write_text("void help() {}")
        result = _find_sources(str(tmp_path))
        assert len(result["c_files"]) == 3


# ── Flag scanning tests ─────────────────────────────────────────────────


class TestScanForFlag:
    def test_finds_standard_flag(self):
        flag = _scan_for_flag("Output: flag{test_value_123}", "flag")
        assert flag == "flag{test_value_123}"

    def test_finds_custom_prefix(self):
        flag = _scan_for_flag("Result: HTB{s3cr3t_fl4g}", "HTB")
        assert flag == "HTB{s3cr3t_fl4g}"

    def test_no_flag_returns_none(self):
        flag = _scan_for_flag("Nothing here to find", "flag")
        assert flag is None

    def test_flag_in_stderr_text(self):
        flag = _scan_for_flag("Error occurred\nflag{hidden_in_error}", "flag")
        assert flag == "flag{hidden_in_error}"

    def test_generic_fallback(self):
        flag = _scan_for_flag("CTF{some_flag_value}", "")
        assert flag == "CTF{some_flag_value}"


# ── Compilation tests ────────────────────────────────────────────────────


class TestCompileSources:
    def test_compile_single_c_file(self, tmp_path):
        """A simple C file should compile and produce an executable."""
        src = tmp_path / "main.c"
        src.write_text('#include <stdio.h>\nint main() { printf("hello\\n"); return 0; }\n')
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, msg = compile_sources(str(tmp_path), str(workspace))
        assert binary is not None, f"Compilation failed: {msg}"
        assert os.path.isfile(binary)
        assert os.access(binary, os.X_OK)

    def test_compile_single_cpp_file(self, tmp_path):
        """A simple C++ file should compile."""
        src = tmp_path / "main.cpp"
        src.write_text('#include <iostream>\nint main() { std::cout << "hi" << std::endl; return 0; }\n')
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, msg = compile_sources(str(tmp_path), str(workspace))
        assert binary is not None, f"Compilation failed: {msg}"
        assert os.access(binary, os.X_OK)

    def test_compile_with_makefile(self, tmp_path):
        """A directory with a Makefile should use make."""
        src = tmp_path / "main.c"
        src.write_text('#include <stdio.h>\nint main() { printf("built\\n"); return 0; }\n')
        makefile = tmp_path / "Makefile"
        makefile.write_text(f"all:\n\tgcc -o {tmp_path}/out/binary {tmp_path}/main.c\n")
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, msg = compile_sources(str(tmp_path), str(workspace))
        assert binary is not None, f"Compilation failed: {msg}"

    def test_no_sources_fails(self, tmp_path):
        """Directory with no compilable sources should fail."""
        (tmp_path / "readme.txt").write_text("nothing to compile")
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, msg = compile_sources(str(tmp_path), str(workspace))
        assert binary is None
        assert "no compilable source" in msg

    def test_compile_error_returns_none(self, tmp_path):
        """A C file with syntax errors should fail gracefully."""
        src = tmp_path / "broken.c"
        src.write_text("this is not valid C code at all !!!\n")
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, msg = compile_sources(str(tmp_path), str(workspace))
        assert binary is None
        assert "failed" in msg.lower()


# ── Binary execution + flag extraction tests ─────────────────────────────


class TestRunBinary:
    def test_extracts_flag_from_output(self, tmp_path):
        """If binary prints a flag, run_binary should find it."""
        src = tmp_path / "flag_printer.c"
        src.write_text(
            '#include <stdio.h>\n'
            'int main() { printf("flag{compile_test_123}\\n"); return 0; }\n'
        )
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, _ = compile_sources(str(tmp_path), str(workspace))
        assert binary is not None

        flag = run_binary(binary, "flag")
        assert flag == "flag{compile_test_123}"

    def test_no_flag_returns_none(self, tmp_path):
        """If binary prints no flag, return None."""
        src = tmp_path / "noflag.c"
        src.write_text(
            '#include <stdio.h>\n'
            'int main() { printf("no flag here\\n"); return 0; }\n'
        )
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, _ = compile_sources(str(tmp_path), str(workspace))
        assert binary is not None

        flag = run_binary(binary, "flag")
        assert flag is None

    def test_handles_timeout(self, tmp_path):
        """Binary that hangs should not block forever."""
        src = tmp_path / "hang.c"
        src.write_text(
            '#include <unistd.h>\n'
            'int main() { while(1) sleep(1); return 0; }\n'
        )
        workspace = tmp_path / "out"
        workspace.mkdir()

        binary, _ = compile_sources(str(tmp_path), str(workspace))
        if binary is not None:
            flag = run_binary(binary, "flag", timeout=2)
            assert flag is None  # should not hang, just return None


# ── Tool router integration tests ────────────────────────────────────────


class TestBuildCppCompileCommand:
    def test_builds_command_when_c_file_present(self):
        """With a .c file in challenge_files, should build a command."""
        state = {
            "challenge_dir": "/tmp/test_challenge",
            "challenge_files": {"main.c": {"path": "/tmp/test_challenge/main.c"}},
        }
        cmd = _build_tool_command("auto_cpp_compile", {}, state)
        assert cmd is not None
        assert "auto_cpp_compile.py" in cmd
        assert "--dir" in cmd
        assert "/tmp/test_challenge" in cmd

    def test_builds_command_when_makefile_present(self):
        """With a Makefile in challenge_files, should build a command."""
        state = {
            "challenge_dir": "/tmp/test_challenge",
            "challenge_files": {"Makefile": {"path": "/tmp/test_challenge/Makefile"}},
        }
        cmd = _build_tool_command("auto_cpp_compile", {}, state)
        assert cmd is not None
        assert "auto_cpp_compile.py" in cmd

    def test_skips_when_no_sources(self):
        """With no compilable files, should skip."""
        state = {
            "challenge_dir": "/tmp/test_challenge",
            "challenge_files": {"readme.txt": {"path": "/tmp/test_challenge/readme.txt"}},
        }
        cmd = _build_tool_command("auto_cpp_compile", {}, state)
        assert cmd is None

    def test_skips_when_no_challenge_dir(self):
        """No challenge_dir -> should skip."""
        state = {"challenge_dir": "", "challenge_files": {}}
        cmd = _build_tool_command("auto_cpp_compile", {}, state)
        assert cmd is None

    def test_includes_prefix_from_flag_format(self):
        """Flag format should be parsed into --prefix."""
        state = {
            "challenge_dir": "/tmp/test_challenge",
            "challenge_files": {"main.cpp": {"path": "/tmp/test_challenge/main.cpp"}},
            "flag_format": r"HTB\{[^}]+\}",
        }
        cmd = _build_tool_command("auto_cpp_compile", {}, state)
        assert cmd is not None
        assert '--prefix "HTB"' in cmd


# ── End-to-end compilation + flag test ───────────────────────────────────


class TestEndToEnd:
    def test_full_pipeline_extracts_flag(self, tmp_path):
        """End-to-end: compile C source, run binary, extract flag."""
        src = tmp_path / "challenge.c"
        src.write_text(
            '#include <stdio.h>\n'
            'int main() {\n'
            '    printf("The answer is flag{e2e_compile_works}\\n");\n'
            '    return 0;\n'
            '}\n'
        )
        workspace = tmp_path / "workspace"
        workspace.mkdir()

        binary, msg = compile_sources(str(tmp_path), str(workspace))
        assert binary is not None, f"Failed: {msg}"

        flag = run_binary(binary, "flag")
        assert flag == "flag{e2e_compile_works}"
