#!/usr/bin/env python3
"""Compile C/C++/assembly source files from challenge directories into executables.

Detects compilable source code (Makefiles, .c, .cpp, .s, .asm) and attempts
compilation using appropriate strategies.  After a successful build the binary
is optionally executed with common inputs to extract a flag.

Usage:
    python3 auto_cpp_compile.py --dir /path/to/challenge [--workspace /tmp/out] \
                                [--prefix flag] [--no-run]
"""
from __future__ import annotations

import argparse
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile


# ── Detection helpers ────────────────────────────────────────────────────

def _find_sources(directory: str) -> dict:
    """Scan *directory* for compilable artefacts.

    Returns a dict with keys:
        makefile, cmake, build_sh, compile_sh, setup_sh,
        c_files, cpp_files, asm_files
    """
    result: dict = {
        "makefile": None,
        "cmake": None,
        "build_sh": None,
        "compile_sh": None,
        "setup_sh": None,
        "c_files": [],
        "cpp_files": [],
        "asm_files": [],
    }
    for entry in os.listdir(directory):
        lower = entry.lower()
        full = os.path.join(directory, entry)
        if not os.path.isfile(full):
            continue
        if lower == "makefile" or lower == "gnumakefile":
            result["makefile"] = full
        elif lower == "cmakelists.txt":
            result["cmake"] = full
        elif lower == "build.sh":
            result["build_sh"] = full
        elif lower == "compile.sh":
            result["compile_sh"] = full
        elif lower == "setup.sh":
            result["setup_sh"] = full
        elif entry.endswith(".c"):
            result["c_files"].append(full)
        elif entry.endswith((".cpp", ".cc", ".cxx")):
            result["cpp_files"].append(full)
        elif entry.endswith((".s", ".asm", ".S")):
            result["asm_files"].append(full)
    return result


# ── Compilation strategies ───────────────────────────────────────────────

def _run_cmd(cmd: list[str] | str, cwd: str, timeout: int = 120,
             shell: bool = False) -> tuple[int, str, str]:
    """Run a command, return (exit_code, stdout, stderr)."""
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, timeout=timeout, shell=shell,
            capture_output=True, text=True,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "compilation timed out"
    except Exception as exc:
        return -1, "", str(exc)


def _find_output_binary(workspace: str, before: set[str]) -> str | None:
    """Find the newly created executable in *workspace*."""
    for entry in os.listdir(workspace):
        full = os.path.join(workspace, entry)
        if full in before:
            continue
        if os.path.isfile(full) and os.access(full, os.X_OK):
            return full
    # Also check common names
    for name in ("binary", "a.out", "main", "challenge", "program"):
        p = os.path.join(workspace, name)
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return None


def compile_sources(directory: str, workspace: str) -> tuple[str | None, str]:
    """Try compilation strategies in priority order.

    Returns (path_to_binary | None, log_message).
    """
    sources = _find_sources(directory)
    os.makedirs(workspace, exist_ok=True)

    # Snapshot existing executables so we can detect new ones
    before = set()
    for e in os.listdir(workspace):
        fp = os.path.join(workspace, e)
        if os.path.isfile(fp) and os.access(fp, os.X_OK):
            before.add(fp)
    for e in os.listdir(directory):
        fp = os.path.join(directory, e)
        if os.path.isfile(fp) and os.access(fp, os.X_OK):
            before.add(fp)

    strategies: list[tuple[str, list[str] | str, str, bool]] = []
    # (label, cmd, cwd, shell)

    # 1. Makefile
    if sources["makefile"]:
        strategies.append(("Makefile", ["make", "-C", directory], directory, False))

    # 2. build.sh
    if sources["build_sh"]:
        strategies.append(("build.sh", f'bash "{sources["build_sh"]}"', directory, True))

    # 3. compile.sh
    if sources["compile_sh"]:
        strategies.append(("compile.sh", f'bash "{sources["compile_sh"]}"', directory, True))

    # 4. setup.sh
    if sources["setup_sh"]:
        strategies.append(("setup.sh", f'bash "{sources["setup_sh"]}"', directory, True))

    # 5. CMakeLists.txt
    if sources["cmake"]:
        cmake_cmd = f'cd "{workspace}" && cmake "{directory}" && make'
        strategies.append(("CMake", cmake_cmd, workspace, True))

    out_bin = os.path.join(workspace, "binary")

    # 6. Single .c file
    if len(sources["c_files"]) == 1 and not sources["cpp_files"]:
        cf = sources["c_files"][0]
        strategies.append((
            f"gcc {os.path.basename(cf)}",
            ["gcc", "-o", out_bin, cf, "-lm", "-lpthread"],
            workspace, False,
        ))

    # 7. Single .cpp file
    if len(sources["cpp_files"]) == 1 and not sources["c_files"]:
        cf = sources["cpp_files"][0]
        strategies.append((
            f"g++ {os.path.basename(cf)}",
            ["g++", "-o", out_bin, cf, "-lm", "-lpthread", "-std=c++17"],
            workspace, False,
        ))

    # 8. Multiple .c files
    if len(sources["c_files"]) > 1:
        strategies.append((
            f"gcc {len(sources['c_files'])} .c files",
            ["gcc", "-o", out_bin] + sources["c_files"] + ["-lm", "-lpthread"],
            workspace, False,
        ))

    # 9. .c + .s mixed
    if sources["c_files"] and sources["asm_files"]:
        all_srcs = sources["c_files"] + sources["asm_files"]
        strategies.append((
            "gcc .c + .s",
            ["gcc", "-o", out_bin] + all_srcs + ["-lm", "-lpthread"],
            workspace, False,
        ))

    # 10. Multiple .cpp files
    if len(sources["cpp_files"]) > 1:
        strategies.append((
            f"g++ {len(sources['cpp_files'])} .cpp files",
            ["g++", "-o", out_bin] + sources["cpp_files"]
            + ["-lm", "-lpthread", "-std=c++17"],
            workspace, False,
        ))

    # 11. .cpp + .s mixed
    if sources["cpp_files"] and sources["asm_files"]:
        all_srcs = sources["cpp_files"] + sources["asm_files"]
        strategies.append((
            "g++ .cpp + .s",
            ["g++", "-o", out_bin] + all_srcs + ["-lm", "-lpthread", "-std=c++17"],
            workspace, False,
        ))

    # 12. Assembly only
    if sources["asm_files"] and not sources["c_files"] and not sources["cpp_files"]:
        af = sources["asm_files"][0]
        strategies.append((
            f"gcc {os.path.basename(af)}",
            ["gcc", "-o", out_bin, af, "-lm", "-lpthread", "-no-pie"],
            workspace, False,
        ))

    if not strategies:
        return None, "no compilable source files found"

    logs: list[str] = []
    for label, cmd, cwd, shell in strategies:
        print(f"[*] Trying strategy: {label}")
        rc, stdout, stderr = _run_cmd(cmd, cwd, shell=shell)
        if rc == 0:
            # Check for output binary
            binary = _find_output_binary(workspace, before)
            if binary is None:
                binary = _find_output_binary(directory, before)
            if binary is not None:
                print(f"[+] Compiled successfully via {label}")
                return binary, f"compiled via {label}"
            logs.append(f"{label}: compiled (rc=0) but no executable found")
        else:
            detail = (stderr or stdout or "unknown error")[:200]
            logs.append(f"{label}: failed (rc={rc}) -- {detail}")
            print(f"[-] {label}: failed (rc={rc})")

    return None, "; ".join(logs)


# ── Post-compilation execution ───────────────────────────────────────────

def _scan_for_flag(text: str, prefix: str) -> str | None:
    """Scan text for a flag matching prefix{...}."""
    if not prefix:
        prefix = "flag"
    # Try exact prefix first
    pat = re.escape(prefix) + r"\{[A-Za-z0-9_\-. ]+\}"
    m = re.search(pat, text)
    if m:
        return m.group(0)
    # Generic fallback
    m = re.search(r"[A-Za-z0-9_]+\{[A-Za-z0-9_\-. ]{3,}\}", text)
    if m:
        return m.group(0)
    return None


def run_binary(binary_path: str, prefix: str, timeout: int = 10) -> str | None:
    """Run the compiled binary with various inputs, return flag if found."""
    inputs_to_try = [
        "",           # no input
        "flag\n",
        "password\n",
        "test\n",
        "A" * 32 + "\n",
    ]

    for inp in inputs_to_try:
        try:
            proc = subprocess.run(
                [binary_path],
                input=inp, capture_output=True, text=True,
                timeout=timeout,
            )
            combined = proc.stdout + proc.stderr
            flag = _scan_for_flag(combined, prefix)
            if flag:
                return flag
        except subprocess.TimeoutExpired:
            continue
        except PermissionError:
            # Try making executable
            try:
                os.chmod(binary_path, 0o755)
                proc = subprocess.run(
                    [binary_path],
                    input=inp, capture_output=True, text=True,
                    timeout=timeout,
                )
                combined = proc.stdout + proc.stderr
                flag = _scan_for_flag(combined, prefix)
                if flag:
                    return flag
            except Exception:
                break
        except Exception:
            continue
    return None


# ── Main entry point ─────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken C/C++/ASM Compiler -- compile challenge sources and extract flags",
    )
    parser.add_argument("--dir", "--binary", dest="directory",
                        help="Challenge directory containing source files")
    parser.add_argument("--workspace", default=None,
                        help="Output directory for compiled binary (default: tempdir)")
    parser.add_argument("--prefix", default="flag",
                        help="Flag prefix for detection (default: flag)")
    parser.add_argument("--run", default=True, action=argparse.BooleanOptionalAction,
                        help="Run the binary after compilation (default: True)")
    args = parser.parse_args()

    directory = args.directory
    if not directory:
        print("[-] COMPILE FAILED: no --dir specified")
        sys.exit(1)

    if not os.path.isdir(directory):
        print(f"[-] COMPILE FAILED: {directory} is not a directory")
        sys.exit(1)

    # Set up workspace
    workspace = args.workspace
    cleanup_workspace = False
    if not workspace:
        workspace = tempfile.mkdtemp(prefix="kraken_compile_")
        cleanup_workspace = True
    os.makedirs(workspace, exist_ok=True)

    print(f"[*] Scanning {directory} for compilable sources...")

    # Check if there's anything to compile
    sources = _find_sources(directory)
    has_sources = (
        sources["makefile"] or sources["cmake"]
        or sources["build_sh"] or sources["compile_sh"] or sources["setup_sh"]
        or sources["c_files"] or sources["cpp_files"] or sources["asm_files"]
    )
    if not has_sources:
        print("[-] COMPILE FAILED: no compilable source files found")
        if cleanup_workspace:
            shutil.rmtree(workspace, ignore_errors=True)
        sys.exit(1)

    # Report what we found
    for key, val in sources.items():
        if isinstance(val, list) and val:
            print(f"[*] Found {len(val)} {key}: {', '.join(os.path.basename(f) for f in val)}")
        elif isinstance(val, str) and val:
            print(f"[*] Found {key}: {os.path.basename(val)}")

    # Compile
    binary_path, log_msg = compile_sources(directory, workspace)

    if binary_path is None:
        print(f"[-] COMPILE FAILED: {log_msg}")
        if cleanup_workspace:
            shutil.rmtree(workspace, ignore_errors=True)
        sys.exit(1)

    print(f"[+] COMPILED: {binary_path}")

    # Optionally run the binary
    if args.run:
        print(f"[*] Running {binary_path} to check for flags...")
        flag = run_binary(binary_path, args.prefix)
        if flag:
            print(f"[+] EXTRACTED FLAG: {flag}")
            sys.exit(0)
        else:
            print("[*] No flag found in binary output")

    # Even without a flag, report the compiled binary
    print(f"[+] COMPILED: {binary_path}")
    sys.exit(0)


if __name__ == "__main__":
    main()
