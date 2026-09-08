#!/usr/bin/env python3
"""auto_fuzz_harness -- Automatic fuzzing harness generator for binaries.

Analyzes a target binary to determine its input method, expected formats,
and interesting constants, then generates ready-to-run AFL and libFuzzer
harnesses with seed corpus and dictionary.

Output structure:
    fuzz_output/
    ├── run_afl.sh          # AFL command to start fuzzing
    ├── run_libfuzzer.sh    # libFuzzer command
    ├── harness.c           # libFuzzer harness source
    ├── corpus/             # Initial seed inputs
    │   ├── seed_000.bin
    │   └── ...
    └── dict.txt            # Fuzzing dictionary

Usage:
    python3 auto_fuzz_harness.py --binary /path/to/target
    python3 auto_fuzz_harness.py --binary /path/to/target --output-dir /tmp/fuzz
    python3 auto_fuzz_harness.py --binary /path/to/target --type afl --timeout 1000
"""
from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import struct
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Literal


# ── Data structures ──────────────────────────────────────────────────────

@dataclass
class BinaryAnalysis:
    """Results from analyzing a target binary."""

    path: str
    basename: str
    arch: str = "unknown"
    bits: int = 64
    is_pie: bool = False
    is_stripped: bool = False
    has_canary: bool = False
    input_methods: list[str] = field(default_factory=list)
    file_format_hints: list[str] = field(default_factory=list)
    magic_bytes: list[bytes] = field(default_factory=list)
    comparison_constants: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    imported_functions: list[str] = field(default_factory=list)
    linked_libraries: list[str] = field(default_factory=list)
    has_main: bool = False
    reads_files: bool = False
    uses_network: bool = False
    uses_stdin: bool = False
    uses_argv: bool = False
    uses_environ: bool = False
    file_extensions: list[str] = field(default_factory=list)


# ── Subprocess helpers ───────────────────────────────────────────────────

def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
    """Run a command and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"command not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return -1, "", f"command timed out after {timeout}s"
    except Exception as exc:
        return -1, "", str(exc)


def _run_bytes(cmd: list[str], timeout: int = 30) -> tuple[int, bytes, bytes]:
    """Run a command and return raw bytes output."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, timeout=timeout,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, b"", b"command not found"
    except subprocess.TimeoutExpired:
        return -1, b"", b"timeout"
    except Exception as exc:
        return -1, b"", str(exc).encode()


def _tool_available(name: str) -> bool:
    """Check if a command-line tool is available."""
    return shutil.which(name) is not None


# ── Binary analysis ──────────────────────────────────────────────────────

def _analyze_elf_header(binary: str, analysis: BinaryAnalysis) -> None:
    """Parse ELF header via readelf for architecture and security info."""
    rc, out, _ = _run(["readelf", "-h", binary])
    if rc != 0:
        return

    for line in out.splitlines():
        line_stripped = line.strip()
        if "Class:" in line_stripped:
            if "ELF64" in line_stripped:
                analysis.bits = 64
            elif "ELF32" in line_stripped:
                analysis.bits = 32
        if "Machine:" in line_stripped:
            if "X86-64" in line_stripped or "x86-64" in line_stripped:
                analysis.arch = "x86_64"
            elif "80386" in line_stripped or "Intel 80386" in line_stripped:
                analysis.arch = "i386"
            elif "ARM" in line_stripped:
                analysis.arch = "arm"
            elif "AArch64" in line_stripped:
                analysis.arch = "aarch64"
            elif "MIPS" in line_stripped:
                analysis.arch = "mips"
        if "Type:" in line_stripped:
            if "DYN" in line_stripped:
                analysis.is_pie = True

    # Check for stack canary and stripped status
    rc, out, _ = _run(["readelf", "-s", binary])
    if rc == 0:
        if "__stack_chk_fail" in out:
            analysis.has_canary = True
        if "Symbol table '.symtab'" not in out:
            analysis.is_stripped = True
        if " main" in out or " main\n" in out:
            analysis.has_main = True


def _analyze_imports(binary: str, analysis: BinaryAnalysis) -> None:
    """Extract imported functions and linked libraries."""
    # Dynamic symbols
    rc, out, _ = _run(["readelf", "-d", binary])
    if rc == 0:
        for line in out.splitlines():
            m = re.search(r"NEEDED\].*\[(.+)\]", line)
            if m:
                analysis.linked_libraries.append(m.group(1))

    # Imported function names from PLT/GOT
    rc, out, _ = _run(["objdump", "-T", binary])
    if rc != 0:
        rc, out, _ = _run(["objdump", "-t", binary])
    if rc == 0:
        for line in out.splitlines():
            # Match symbol names (last column)
            parts = line.split()
            if parts:
                sym = parts[-1]
                if sym.startswith("_") and sym.count("@") == 0:
                    continue
                # Strip version info like @GLIBC_2.17
                sym_clean = sym.split("@")[0]
                if sym_clean and len(sym_clean) > 1:
                    analysis.imported_functions.append(sym_clean)

    # Also grab from nm if available
    rc, out, _ = _run(["nm", "-D", binary])
    if rc == 0:
        for line in out.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3 and parts[1] == "U":
                analysis.imported_functions.append(parts[2].split("@")[0])

    # Deduplicate
    analysis.imported_functions = sorted(set(analysis.imported_functions))


def _detect_input_methods(analysis: BinaryAnalysis) -> None:
    """Determine how the binary reads input based on imported functions."""
    funcs = set(analysis.imported_functions)

    # stdin-reading functions
    stdin_funcs = {
        "read", "fread", "fgets", "gets", "getchar", "getline",
        "scanf", "fscanf", "sscanf", "__isoc99_scanf",
        "fgetc", "getc", "getchar_unlocked", "fread_unlocked",
    }
    if funcs & stdin_funcs:
        analysis.uses_stdin = True
        analysis.input_methods.append("stdin")

    # File-reading functions
    file_funcs = {
        "fopen", "fopen64", "open", "open64", "openat",
        "freopen", "fdopen", "mmap", "mmap64",
    }
    if funcs & file_funcs:
        analysis.reads_files = True
        analysis.input_methods.append("file")

    # argv access indicators
    argv_funcs = {
        "getopt", "getopt_long", "strtol", "strtoul", "atoi", "atol",
        "strtod", "strtof", "strtoimax",
    }
    if funcs & argv_funcs:
        analysis.uses_argv = True
        analysis.input_methods.append("argv")

    # Network functions
    net_funcs = {
        "socket", "bind", "listen", "accept", "connect",
        "recv", "recvfrom", "recvmsg", "send", "sendto", "sendmsg",
        "getaddrinfo", "gethostbyname", "inet_pton", "inet_ntop",
        "htons", "htonl", "ntohs", "ntohl",
    }
    if funcs & net_funcs:
        analysis.uses_network = True
        analysis.input_methods.append("network")

    # Environment variable access
    env_funcs = {"getenv", "secure_getenv", "setenv", "putenv"}
    if funcs & env_funcs:
        analysis.uses_environ = True
        analysis.input_methods.append("environ")

    # If we found nothing specific, assume stdin
    if not analysis.input_methods:
        analysis.input_methods.append("stdin")
        analysis.uses_stdin = True


def _extract_strings(binary: str, analysis: BinaryAnalysis) -> None:
    """Extract interesting strings from the binary for corpus and dict."""
    rc, out, _ = _run(["strings", "-a", "-n", "4", binary])
    if rc != 0:
        return

    seen: set[str] = set()
    for line in out.splitlines():
        s = line.strip()
        if not s or s in seen:
            continue
        seen.add(s)

        # File extension hints
        ext_match = re.search(r"\.\w{1,6}$", s)
        if ext_match and len(s) <= 20:
            analysis.file_extensions.append(ext_match.group(0))

        # Format string / magic hints
        if s.startswith("%") or s.startswith("\\x"):
            analysis.file_format_hints.append(s)
        elif re.match(r"^[A-Z]{2,8}$", s):
            # Short uppercase tokens (potential magic/format identifiers)
            analysis.interesting_strings.append(s)
        elif re.match(r"^(ELF|PNG|JFIF|GIF8|PDF-|%PDF|PK|BM|RIFF|WAVE|OggS)", s):
            analysis.file_format_hints.append(s)
        elif len(s) >= 4 and len(s) <= 200:
            # General interesting string
            # Skip common noise
            if not re.match(
                r"^(lib|GLIBC|GCC|GNU|\.gnu|\.note|\.text|\.data"
                r"|\.rodata|\.bss|\.plt|\.got|__)", s,
            ):
                analysis.interesting_strings.append(s)

    # Cap to avoid excessive output
    analysis.interesting_strings = analysis.interesting_strings[:500]
    analysis.file_extensions = sorted(set(analysis.file_extensions))[:20]


def _extract_comparison_constants(binary: str, analysis: BinaryAnalysis) -> None:
    """Extract comparison constants from objdump disassembly."""
    rc, out, _ = _run(["objdump", "-d", "-M", "intel", binary], timeout=60)
    if rc != 0:
        # Try without intel syntax
        rc, out, _ = _run(["objdump", "-d", binary], timeout=60)
    if rc != 0:
        return

    constants: set[str] = set()
    for line in out.splitlines():
        # Match immediate comparison values: cmp reg, 0xNN
        for m in re.finditer(r"cmp\s+\w+,\s*(0x[0-9a-fA-F]+)", line):
            val_str = m.group(1)
            try:
                val = int(val_str, 16)
            except ValueError:
                continue
            # Only include printable-range or interesting constants
            if 0x20 <= val <= 0x7e:
                constants.add(chr(val))
            elif val > 0xff:
                constants.add(val_str)

        # Match test/and with immediate values
        for m in re.finditer(r"(?:test|and)\s+\w+,\s*(0x[0-9a-fA-F]+)", line):
            constants.add(m.group(1))

        # Match mov of immediate values that look like magic bytes
        for m in re.finditer(r"mov\s+\w+,\s*(0x[0-9a-fA-F]{4,16})", line):
            val_str = m.group(1)
            try:
                val = int(val_str, 16)
            except ValueError:
                continue
            # Check if this could be ASCII text packed into an int
            try:
                if analysis.bits == 64 and val > 0xffff:
                    raw = struct.pack("<Q", val & 0xffffffffffffffff)
                elif val > 0xff:
                    raw = struct.pack("<I", val & 0xffffffff)
                else:
                    continue
                decoded = raw.rstrip(b"\x00")
                if decoded and all(0x20 <= b <= 0x7e for b in decoded):
                    constants.add(decoded.decode("ascii"))
                else:
                    constants.add(val_str)
            except (struct.error, OverflowError):
                constants.add(val_str)

    analysis.comparison_constants = sorted(constants)[:200]


def _detect_magic_bytes(binary: str, analysis: BinaryAnalysis) -> None:
    """Try to detect expected magic bytes from string references."""
    # Known magic byte patterns
    magic_patterns = {
        b"\x89PNG": "PNG image",
        b"GIF8": "GIF image",
        b"\xff\xd8\xff": "JPEG image",
        b"%PDF": "PDF document",
        b"PK\x03\x04": "ZIP archive",
        b"\x7fELF": "ELF binary",
        b"BM": "BMP image",
        b"RIFF": "RIFF container (WAV/AVI)",
        b"OggS": "Ogg container",
        b"\x1f\x8b": "gzip compressed",
        b"BZh": "bzip2 compressed",
        b"\xfd7zXZ": "xz compressed",
    }

    # Check strings for references to file format keywords
    format_keywords = {
        "png": b"\x89PNG\r\n\x1a\n",
        "jpeg": b"\xff\xd8\xff\xe0",
        "jpg": b"\xff\xd8\xff\xe0",
        "gif": b"GIF89a",
        "pdf": b"%PDF-1.4",
        "zip": b"PK\x03\x04",
        "elf": b"\x7fELF",
        "bmp": b"BM",
        "wav": b"RIFF",
        "xml": b"<?xml version=",
        "html": b"<html",
        "json": b'{"',
    }

    strings_lower = " ".join(s.lower() for s in analysis.interesting_strings)
    strings_lower += " ".join(s.lower() for s in analysis.file_format_hints)
    strings_lower += " ".join(s.lower() for s in analysis.file_extensions)

    for keyword, magic in format_keywords.items():
        if keyword in strings_lower:
            analysis.magic_bytes.append(magic)
            analysis.file_format_hints.append(f"possible {keyword} format")


def analyze_binary(binary: str) -> BinaryAnalysis:
    """Perform full analysis of a binary."""
    analysis = BinaryAnalysis(
        path=os.path.abspath(binary),
        basename=os.path.basename(binary),
    )

    print(f"[*] Analyzing binary: {analysis.path}")

    # Phase 1: ELF header
    print("[*] Phase 1: ELF header and security properties")
    _analyze_elf_header(binary, analysis)
    print(f"    arch={analysis.arch}, bits={analysis.bits}, "
          f"pie={analysis.is_pie}, canary={analysis.has_canary}, "
          f"stripped={analysis.is_stripped}")

    # Phase 2: Imports and libraries
    print("[*] Phase 2: Imported functions and libraries")
    _analyze_imports(binary, analysis)
    print(f"    {len(analysis.imported_functions)} imports, "
          f"{len(analysis.linked_libraries)} libraries")

    # Phase 3: Input method detection
    print("[*] Phase 3: Input method detection")
    _detect_input_methods(analysis)
    print(f"    input methods: {', '.join(analysis.input_methods)}")

    # Phase 4: String extraction
    print("[*] Phase 4: String extraction")
    _extract_strings(binary, analysis)
    print(f"    {len(analysis.interesting_strings)} interesting strings, "
          f"{len(analysis.file_extensions)} file extensions")

    # Phase 5: Comparison constants
    print("[*] Phase 5: Disassembly constant extraction")
    _extract_comparison_constants(binary, analysis)
    print(f"    {len(analysis.comparison_constants)} comparison constants")

    # Phase 6: Magic byte detection
    print("[*] Phase 6: Magic byte / format detection")
    _detect_magic_bytes(binary, analysis)
    if analysis.magic_bytes:
        print(f"    {len(analysis.magic_bytes)} magic byte pattern(s) detected")
    else:
        print("    no specific format expectations detected")

    return analysis


# ── Harness generation ───────────────────────────────────────────────────

def _generate_libfuzzer_harness(analysis: BinaryAnalysis) -> str:
    """Generate a libFuzzer harness C source file."""
    binary_abs = analysis.path

    # Determine the primary input method and generate appropriate harness
    uses_file = "file" in analysis.input_methods
    uses_stdin = "stdin" in analysis.input_methods
    uses_argv = "argv" in analysis.input_methods

    lines: list[str] = []
    lines.append("/*")
    lines.append(f" * libFuzzer harness for: {analysis.basename}")
    lines.append(f" * Generated by kraken auto_fuzz_harness")
    lines.append(f" * Architecture: {analysis.arch} ({analysis.bits}-bit)")
    lines.append(f" * Input methods detected: {', '.join(analysis.input_methods)}")
    lines.append(" *")
    lines.append(" * Compilation:")
    lines.append(" *   clang -g -O1 -fsanitize=fuzzer,address -o harness harness.c")
    lines.append(" *")
    lines.append(" * If the target is a shared library:")
    lines.append(f" *   clang -g -O1 -fsanitize=fuzzer,address -o harness harness.c -L. -l:{analysis.basename}")
    lines.append(" */")
    lines.append("")
    lines.append("#include <stddef.h>")
    lines.append("#include <stdint.h>")
    lines.append("#include <stdio.h>")
    lines.append("#include <stdlib.h>")
    lines.append("#include <string.h>")
    lines.append("#include <unistd.h>")
    lines.append("#include <signal.h>")
    lines.append("#include <sys/wait.h>")
    lines.append("")

    if uses_file:
        lines.append("/*")
        lines.append(" * Strategy: Write fuzz data to a temp file, invoke the target")
        lines.append(" * with the file path as an argument.")
        lines.append(" */")
        lines.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")
        lines.append("    /* Limit input size to avoid excessive resource use */")
        lines.append("    if (size > 1024 * 1024) return 0;")
        lines.append("")
        lines.append("    /* Write fuzz data to temp file */")
        lines.append('    char tmpfile[] = "/tmp/fuzz_input_XXXXXX";')
        lines.append("    int fd = mkstemp(tmpfile);")
        lines.append("    if (fd < 0) return 0;")
        lines.append("    write(fd, data, size);")
        lines.append("    close(fd);")
        lines.append("")
        lines.append("    /* Fork and exec the target */")
        lines.append("    pid_t pid = fork();")
        lines.append("    if (pid == 0) {")
        lines.append("        /* Child: redirect stderr to /dev/null */")
        lines.append('        freopen("/dev/null", "w", stderr);')
        lines.append("        alarm(5);  /* Timeout */")
        lines.append(f'        execl("{binary_abs}", "{analysis.basename}", tmpfile, NULL);')
        lines.append("        _exit(1);")
        lines.append("    } else if (pid > 0) {")
        lines.append("        int status;")
        lines.append("        waitpid(pid, &status, 0);")
        lines.append("    }")
        lines.append("")
        lines.append("    unlink(tmpfile);")
        lines.append("    return 0;")
        lines.append("}")
    elif uses_argv:
        lines.append("/*")
        lines.append(" * Strategy: Pass fuzz data as a command-line argument.")
        lines.append(" */")
        lines.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")
        lines.append("    if (size > 4096) return 0;")
        lines.append("    if (size == 0) return 0;")
        lines.append("")
        lines.append("    /* Null-terminate the input for use as argv */")
        lines.append("    char *arg = (char *)malloc(size + 1);")
        lines.append("    if (!arg) return 0;")
        lines.append("    memcpy(arg, data, size);")
        lines.append("    arg[size] = '\\0';")
        lines.append("")
        lines.append("    pid_t pid = fork();")
        lines.append("    if (pid == 0) {")
        lines.append('        freopen("/dev/null", "w", stdout);')
        lines.append('        freopen("/dev/null", "w", stderr);')
        lines.append("        alarm(5);")
        lines.append(f'        execl("{binary_abs}", "{analysis.basename}", arg, NULL);')
        lines.append("        _exit(1);")
        lines.append("    } else if (pid > 0) {")
        lines.append("        int status;")
        lines.append("        waitpid(pid, &status, 0);")
        lines.append("    }")
        lines.append("")
        lines.append("    free(arg);")
        lines.append("    return 0;")
        lines.append("}")
    else:
        # Default: stdin-based fuzzing
        lines.append("/*")
        lines.append(" * Strategy: Feed fuzz data to target via stdin using a pipe.")
        lines.append(" */")
        lines.append("int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {")
        lines.append("    if (size > 1024 * 1024) return 0;")
        lines.append("")
        lines.append("    /* Create a pipe for stdin */")
        lines.append("    int pipefd[2];")
        lines.append("    if (pipe(pipefd) != 0) return 0;")
        lines.append("")
        lines.append("    pid_t pid = fork();")
        lines.append("    if (pid == 0) {")
        lines.append("        /* Child: replace stdin with pipe read end */")
        lines.append("        close(pipefd[1]);")
        lines.append("        dup2(pipefd[0], STDIN_FILENO);")
        lines.append("        close(pipefd[0]);")
        lines.append('        freopen("/dev/null", "w", stdout);')
        lines.append('        freopen("/dev/null", "w", stderr);')
        lines.append("        alarm(5);  /* Timeout */")
        lines.append(f'        execl("{binary_abs}", "{analysis.basename}", NULL);')
        lines.append("        _exit(1);")
        lines.append("    } else if (pid > 0) {")
        lines.append("        /* Parent: write fuzz data to pipe, then close */")
        lines.append("        close(pipefd[0]);")
        lines.append("        write(pipefd[1], data, size);")
        lines.append("        close(pipefd[1]);")
        lines.append("        int status;")
        lines.append("        waitpid(pid, &status, 0);")
        lines.append("    } else {")
        lines.append("        close(pipefd[0]);")
        lines.append("        close(pipefd[1]);")
        lines.append("    }")
        lines.append("")
        lines.append("    return 0;")
        lines.append("}")

    lines.append("")
    return "\n".join(lines)


def _generate_afl_script(
    analysis: BinaryAnalysis,
    output_dir: str,
    timeout: int,
) -> str:
    """Generate a shell script to run AFL on the target."""
    binary_abs = analysis.path
    corpus_dir = os.path.join(output_dir, "corpus")
    findings_dir = os.path.join(output_dir, "findings")
    dict_path = os.path.join(output_dir, "dict.txt")

    uses_file = "file" in analysis.input_methods

    lines: list[str] = []
    lines.append("#!/bin/bash")
    lines.append(f"# AFL fuzzing script for: {analysis.basename}")
    lines.append("# Generated by kraken auto_fuzz_harness")
    lines.append("#")
    lines.append(f"# Architecture: {analysis.arch} ({analysis.bits}-bit)")
    lines.append(f"# Input methods: {', '.join(analysis.input_methods)}")
    lines.append("")
    lines.append("set -e")
    lines.append("")
    lines.append("# ── Configuration ──")
    lines.append(f'BINARY="{binary_abs}"')
    lines.append(f'CORPUS="{corpus_dir}"')
    lines.append(f'FINDINGS="{findings_dir}"')
    lines.append(f'DICT="{dict_path}"')
    lines.append(f"TIMEOUT={timeout}")
    lines.append("")
    lines.append("# ── Pre-flight checks ──")
    lines.append("if ! command -v afl-fuzz &>/dev/null; then")
    lines.append('    echo "[-] afl-fuzz not found. Install AFL++:"')
    lines.append('    echo "    apt install afl++"')
    lines.append('    echo "    # or: git clone https://github.com/AFLplusplus/AFLplusplus && cd AFLplusplus && make && sudo make install"')
    lines.append("    exit 1")
    lines.append("fi")
    lines.append("")
    lines.append('if [ ! -f "$BINARY" ]; then')
    lines.append('    echo "[-] Binary not found: $BINARY"')
    lines.append("    exit 1")
    lines.append("fi")
    lines.append("")
    lines.append('if [ ! -d "$CORPUS" ] || [ -z "$(ls -A $CORPUS 2>/dev/null)" ]; then')
    lines.append('    echo "[-] Corpus directory empty or missing: $CORPUS"')
    lines.append("    exit 1")
    lines.append("fi")
    lines.append("")
    lines.append('mkdir -p "$FINDINGS"')
    lines.append("")
    lines.append("# ── AFL options ──")
    lines.append('AFL_OPTS="-i $CORPUS -o $FINDINGS -t $TIMEOUT"')
    lines.append("")
    lines.append("# Add dictionary if it exists and is non-empty")
    lines.append('if [ -s "$DICT" ]; then')
    lines.append('    AFL_OPTS="$AFL_OPTS -x $DICT"')
    lines.append("fi")
    lines.append("")

    # Recommend disabling core pattern if needed
    lines.append("# ── System tuning (may need sudo) ──")
    lines.append('CORE_PATTERN=$(cat /proc/sys/kernel/core_pattern 2>/dev/null)')
    lines.append('if [ "$CORE_PATTERN" != "core" ]; then')
    lines.append('    echo "[*] Consider running: echo core | sudo tee /proc/sys/kernel/core_pattern"')
    lines.append("fi")
    lines.append("")

    if uses_file:
        lines.append("# ── Run AFL (file input mode) ──")
        lines.append(f'echo "[*] Starting AFL with file input mode"')
        lines.append('echo "[*] Binary: $BINARY"')
        lines.append('echo "[*] Corpus: $CORPUS"')
        lines.append('echo "[*] Findings: $FINDINGS"')
        lines.append("echo")
        lines.append("")
        lines.append("# AFL replaces @@ with the path to the test input file")
        lines.append('afl-fuzz $AFL_OPTS -- "$BINARY" @@')
    else:
        lines.append("# ── Run AFL (stdin mode) ──")
        lines.append(f'echo "[*] Starting AFL with stdin mode"')
        lines.append('echo "[*] Binary: $BINARY"')
        lines.append('echo "[*] Corpus: $CORPUS"')
        lines.append('echo "[*] Findings: $FINDINGS"')
        lines.append("echo")
        lines.append("")
        lines.append('afl-fuzz $AFL_OPTS -- "$BINARY"')

    lines.append("")
    return "\n".join(lines)


def _generate_libfuzzer_script(
    analysis: BinaryAnalysis,
    output_dir: str,
) -> str:
    """Generate a shell script to compile and run the libFuzzer harness."""
    corpus_dir = os.path.join(output_dir, "corpus")
    harness_src = os.path.join(output_dir, "harness.c")
    harness_bin = os.path.join(output_dir, "harness")
    dict_path = os.path.join(output_dir, "dict.txt")

    lines: list[str] = []
    lines.append("#!/bin/bash")
    lines.append(f"# libFuzzer script for: {analysis.basename}")
    lines.append("# Generated by kraken auto_fuzz_harness")
    lines.append("")
    lines.append("set -e")
    lines.append("")
    lines.append(f'HARNESS_SRC="{harness_src}"')
    lines.append(f'HARNESS_BIN="{harness_bin}"')
    lines.append(f'CORPUS="{corpus_dir}"')
    lines.append(f'DICT="{dict_path}"')
    lines.append("")
    lines.append("# ── Pre-flight checks ──")
    lines.append("if ! command -v clang &>/dev/null; then")
    lines.append('    echo "[-] clang not found. Install:"')
    lines.append('    echo "    apt install clang"')
    lines.append("    exit 1")
    lines.append("fi")
    lines.append("")
    lines.append("# ── Compile harness ──")
    lines.append('echo "[*] Compiling libFuzzer harness..."')
    lines.append('clang -g -O1 -fsanitize=fuzzer,address \\')
    lines.append('    -o "$HARNESS_BIN" "$HARNESS_SRC"')
    lines.append("")
    lines.append('if [ ! -f "$HARNESS_BIN" ]; then')
    lines.append('    echo "[-] Compilation failed"')
    lines.append("    exit 1")
    lines.append("fi")
    lines.append("")
    lines.append('echo "[+] Harness compiled: $HARNESS_BIN"')
    lines.append("")
    lines.append("# ── Run libFuzzer ──")
    lines.append('FUZZ_OPTS=""')
    lines.append('if [ -s "$DICT" ]; then')
    lines.append('    FUZZ_OPTS="$FUZZ_OPTS -dict=$DICT"')
    lines.append("fi")
    lines.append("")
    lines.append('echo "[*] Starting libFuzzer..."')
    lines.append('echo "[*] Corpus: $CORPUS"')
    lines.append("echo")
    lines.append("")
    lines.append('"$HARNESS_BIN" $FUZZ_OPTS "$CORPUS"')
    lines.append("")
    return "\n".join(lines)


def _generate_dictionary(analysis: BinaryAnalysis) -> str:
    """Generate an AFL/libFuzzer dictionary from analysis results."""
    entries: list[str] = []
    seen: set[str] = set()
    idx = 0

    def _add_entry(label: str, value: str) -> None:
        nonlocal idx
        if value in seen:
            return
        seen.add(value)
        # Escape for AFL dict format
        escaped = ""
        for ch in value:
            if 0x20 <= ord(ch) <= 0x7e and ch not in ('"', "\\"):
                escaped += ch
            else:
                escaped += f"\\x{ord(ch):02x}"
        entries.append(f'{label}_{idx}="{escaped}"')
        idx += 1

    # Add magic bytes
    for magic in analysis.magic_bytes:
        label = "magic"
        escaped_bytes = ""
        for b in magic:
            if 0x20 <= b <= 0x7e and b not in (ord('"'), ord("\\")):
                escaped_bytes += chr(b)
            else:
                escaped_bytes += f"\\x{b:02x}"
        if escaped_bytes not in seen:
            seen.add(escaped_bytes)
            entries.append(f'{label}_{idx}="{escaped_bytes}"')
            idx += 1

    # Add comparison constants
    for const in analysis.comparison_constants[:50]:
        if const.startswith("0x"):
            try:
                val = int(const, 16)
                if val <= 0xff:
                    _add_entry("cmp_byte", chr(val) if 0x20 <= val <= 0x7e else f"\\x{val:02x}")
                elif val <= 0xffff:
                    # 2-byte constant
                    b = struct.pack("<H", val)
                    esc = "".join(f"\\x{x:02x}" for x in b)
                    if esc not in seen:
                        seen.add(esc)
                        entries.append(f'cmp_word_{idx}="{esc}"')
                        idx += 1
                elif val <= 0xffffffff:
                    b = struct.pack("<I", val)
                    esc = "".join(f"\\x{x:02x}" for x in b)
                    if esc not in seen:
                        seen.add(esc)
                        entries.append(f'cmp_dword_{idx}="{esc}"')
                        idx += 1
            except (ValueError, struct.error):
                pass
        else:
            _add_entry("const", const)

    # Add interesting short strings (error messages, keywords, etc.)
    for s in analysis.interesting_strings[:100]:
        if 2 <= len(s) <= 64:
            _add_entry("str", s)

    # Add file extension strings
    for ext in analysis.file_extensions:
        _add_entry("ext", ext)

    # Standard useful tokens
    standard_tokens = [
        "\x00", "\xff", "\n", "\r\n", "\t",
        "true", "false", "null", "none",
        "{}", "[]", '""', "''",
        "-1", "0", "1", "4294967295", "2147483647",
        "../", "../../", "%s", "%d", "%n", "%x",
    ]
    for tok in standard_tokens:
        _add_entry("std", tok)

    return "\n".join(entries) + "\n" if entries else ""


def _generate_seed_corpus(
    analysis: BinaryAnalysis,
    corpus_dir: str,
) -> int:
    """Generate initial seed corpus files. Returns number of seeds created."""
    os.makedirs(corpus_dir, exist_ok=True)
    seed_idx = 0

    def _write_seed(data: bytes, label: str = "") -> None:
        nonlocal seed_idx
        path = os.path.join(corpus_dir, f"seed_{seed_idx:03d}.bin")
        with open(path, "wb") as f:
            f.write(data)
        seed_idx += 1

    # Seed 0: empty input
    _write_seed(b"", "empty")

    # Seed 1: single newline
    _write_seed(b"\n", "newline")

    # Seed 2: simple ASCII
    _write_seed(b"AAAA", "simple_ascii")

    # Seed 3: longer pattern
    _write_seed(b"A" * 256, "long_pattern")

    # Seed 4: numeric
    _write_seed(b"12345678", "numeric")

    # Seed 5: format-string style
    _write_seed(b"%s%s%s%s%s", "format_string")

    # Seed 6: null bytes
    _write_seed(b"\x00" * 16, "null_bytes")

    # Seed 7: boundary values
    _write_seed(b"\xff" * 16, "max_bytes")

    # Add magic-byte-based seeds
    for magic in analysis.magic_bytes:
        # Create a minimal file with magic bytes + padding
        _write_seed(magic + b"\x00" * 64, "magic")

    # Add seeds from interesting comparison constants
    for const in analysis.comparison_constants[:20]:
        if const.startswith("0x"):
            try:
                val = int(const, 16)
                if val <= 0xff:
                    _write_seed(struct.pack("B", val), "const_byte")
                elif val <= 0xffff:
                    _write_seed(struct.pack("<H", val), "const_word")
                elif val <= 0xffffffff:
                    _write_seed(struct.pack("<I", val), "const_dword")
            except (ValueError, struct.error):
                pass
        elif len(const) <= 256:
            _write_seed(const.encode("utf-8", errors="replace"), "const_str")

    # Add seeds from short interesting strings that look like valid inputs
    input_like_strings = [
        s for s in analysis.interesting_strings
        if 2 <= len(s) <= 128
        and not any(kw in s.lower() for kw in [
            "usage", "error", "warning", "copyright", "version",
            "license", "help", "invalid",
        ])
    ]
    for s in input_like_strings[:15]:
        _write_seed(s.encode("utf-8", errors="replace"), "string")

    # File extension hint seeds
    for ext in analysis.file_extensions[:5]:
        # Create a seed that starts with a plausible filename-like string
        _write_seed(f"input{ext}\x00".encode(), "ext_hint")

    return seed_idx


# ── Output assembly ──────────────────────────────────────────────────────

def generate_harness(
    analysis: BinaryAnalysis,
    output_dir: str,
    timeout: int,
    fuzz_type: Literal["afl", "libfuzzer", "both"],
) -> None:
    """Generate the complete fuzzing directory structure."""
    os.makedirs(output_dir, exist_ok=True)
    corpus_dir = os.path.join(output_dir, "corpus")

    # Summary
    print()
    print("=" * 60)
    print(f"  Fuzzing Harness Generation: {analysis.basename}")
    print("=" * 60)
    print(f"  Architecture:    {analysis.arch} ({analysis.bits}-bit)")
    print(f"  PIE:             {analysis.is_pie}")
    print(f"  Stack canary:    {analysis.has_canary}")
    print(f"  Stripped:        {analysis.is_stripped}")
    print(f"  Input methods:   {', '.join(analysis.input_methods)}")
    print(f"  Libraries:       {', '.join(analysis.linked_libraries) or 'none detected'}")
    print(f"  Constants found: {len(analysis.comparison_constants)}")
    print(f"  Strings found:   {len(analysis.interesting_strings)}")
    print(f"  Output:          {output_dir}")
    print(f"  Type:            {fuzz_type}")
    print("=" * 60)
    print()

    # 1. Seed corpus
    print("[*] Generating seed corpus...")
    num_seeds = _generate_seed_corpus(analysis, corpus_dir)
    print(f"[+] Created {num_seeds} seed files in {corpus_dir}")

    # 2. Dictionary
    print("[*] Generating fuzzing dictionary...")
    dict_content = _generate_dictionary(analysis)
    dict_path = os.path.join(output_dir, "dict.txt")
    with open(dict_path, "w") as f:
        f.write(dict_content)
    num_entries = dict_content.count("=") if dict_content else 0
    print(f"[+] Dictionary: {num_entries} entries written to {dict_path}")

    # 3. AFL harness
    if fuzz_type in ("afl", "both"):
        print("[*] Generating AFL run script...")
        afl_script = _generate_afl_script(analysis, output_dir, timeout)
        afl_path = os.path.join(output_dir, "run_afl.sh")
        with open(afl_path, "w") as f:
            f.write(afl_script)
        os.chmod(afl_path, os.stat(afl_path).st_mode | stat.S_IXUSR | stat.S_IXGRP)
        print(f"[+] AFL script: {afl_path}")

    # 4. libFuzzer harness
    if fuzz_type in ("libfuzzer", "both"):
        print("[*] Generating libFuzzer harness...")
        harness_src = _generate_libfuzzer_harness(analysis)
        harness_path = os.path.join(output_dir, "harness.c")
        with open(harness_path, "w") as f:
            f.write(harness_src)
        print(f"[+] libFuzzer harness source: {harness_path}")

        libfuzzer_script = _generate_libfuzzer_script(analysis, output_dir)
        libfuzzer_path = os.path.join(output_dir, "run_libfuzzer.sh")
        with open(libfuzzer_path, "w") as f:
            f.write(libfuzzer_script)
        os.chmod(
            libfuzzer_path,
            os.stat(libfuzzer_path).st_mode | stat.S_IXUSR | stat.S_IXGRP,
        )
        print(f"[+] libFuzzer script: {libfuzzer_path}")

    # Final summary
    print()
    print("[+] Harness generation complete. Directory structure:")
    for root, dirs, files in os.walk(output_dir):
        level = root.replace(output_dir, "").count(os.sep)
        indent = "    " * level
        basename = os.path.basename(root)
        if level == 0:
            print(f"  {output_dir}/")
        else:
            print(f"  {indent}{basename}/")
        sub_indent = "    " * (level + 1)
        for f in sorted(files):
            filepath = os.path.join(root, f)
            size = os.path.getsize(filepath)
            print(f"  {sub_indent}{f} ({size} bytes)")


# ── CLI entry point ──────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Fuzz Harness Generator -- automatically generate "
                    "AFL and libFuzzer harnesses for target binaries",
    )
    parser.add_argument(
        "--binary", required=True,
        help="Path to the target binary to fuzz",
    )
    parser.add_argument(
        "--output-dir", default="./fuzz_output",
        help="Output directory for generated harness files (default: ./fuzz_output)",
    )
    parser.add_argument(
        "--timeout", type=int, default=1000,
        help="AFL timeout per execution in milliseconds (default: 1000)",
    )
    parser.add_argument(
        "--type", dest="fuzz_type", choices=["afl", "libfuzzer", "both"],
        default="both",
        help="Which fuzzer harness(es) to generate (default: both)",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)
    output_dir = os.path.abspath(args.output_dir)

    # ── Validate binary ──
    if not os.path.isfile(binary):
        print(f"[-] File not found: {binary}")
        sys.exit(1)

    # Check if ELF
    try:
        with open(binary, "rb") as f:
            magic = f.read(4)
        if magic != b"\x7fELF":
            print(f"[!] Warning: {binary} does not appear to be an ELF binary")
            print(f"    Magic bytes: {magic.hex()}")
            print("[*] Proceeding anyway (may be a script or other executable)")
    except OSError as e:
        print(f"[-] Cannot read binary: {e}")
        sys.exit(1)

    # Ensure executable
    if not os.access(binary, os.X_OK):
        print(f"[*] Setting executable permission on {binary}")
        try:
            os.chmod(binary, os.stat(binary).st_mode | 0o111)
        except OSError as e:
            print(f"[!] Warning: cannot set executable bit: {e}")

    # ── Analyze ──
    analysis = analyze_binary(binary)

    # ── Generate ──
    generate_harness(analysis, output_dir, args.timeout, args.fuzz_type)

    print()
    if args.fuzz_type in ("afl", "both"):
        print(f"[*] To start AFL:       bash {os.path.join(output_dir, 'run_afl.sh')}")
    if args.fuzz_type in ("libfuzzer", "both"):
        print(f"[*] To start libFuzzer: bash {os.path.join(output_dir, 'run_libfuzzer.sh')}")
    print()


if __name__ == "__main__":
    main()
