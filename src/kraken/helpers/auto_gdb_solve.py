#!/usr/bin/env python3
"""auto_gdb_solve -- GDB Python scripting engine for runtime analysis.

Full-featured GDB automation for CTF binary challenges:
  1. strcmp/memcmp/strncmp hook -- extract comparison arguments at runtime
  2. Anti-debug bypass -- patch ptrace, LD_PRELOAD fake ptrace
  3. Decrypt-and-dump -- let binary decrypt, then dump strings/memory
  4. Watchpoint monitoring -- track memory writes to flag storage
  5. Register inspection -- read regs at key points after decryption
  6. Runtime patching -- NOP out checks, force branches
  7. Function hooking -- log arguments and return values for arbitrary funcs

Usage:
    python3 auto_gdb_solve.py --binary ./challenge --prefix flag
    python3 auto_gdb_solve.py --binary ./challenge --prefix flag --strategy strcmp
    python3 auto_gdb_solve.py --binary ./challenge --args arg1 arg2 --input "password"
    python3 auto_gdb_solve.py --binary ./challenge --hook-funcs check_password,verify

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
TECHNIQUE_TIMEOUT = 30
DEFAULT_FLAG_PATTERN = re.compile(r"[A-Za-z_]{2,}\{[^\}]{3,}\}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _is_elf(path: str) -> bool:
    """Check if file is an ELF binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except (OSError, IOError):
        return False


def _find_flags(text: str, prefix: str) -> list[str]:
    """Return all flag-pattern matches found in text."""
    flags: list[str] = []
    if prefix:
        escaped = re.escape(prefix.rstrip("{"))
        pattern = escaped + r"\{[^\}]{3,}\}"
    else:
        pattern = r"[A-Za-z_]{2,}\{[^\}]{3,}\}"

    for m in re.finditer(pattern, text):
        candidate = m.group(0)
        body_match = re.search(r"\{(.+)\}", candidate)
        if body_match:
            body = body_match.group(1)
            if len(body) >= 3 and len(set(body)) >= 2:
                flags.append(candidate)
    return flags


def _deduplicate(flags: list[str]) -> list[str]:
    """Deduplicate while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            result.append(f)
    return result


def _score_flag(flag: str, prefix: str) -> int:
    """Score a flag candidate: higher is better."""
    score = 0
    pfx = prefix.rstrip("{")
    if flag.startswith(pfx + "{"):
        score += 100
    if flag.endswith("}"):
        score += 50
    body_match = re.search(r"\{(.+)\}", flag)
    if body_match:
        body = body_match.group(1)
        score += len(body)
        score += len(set(body)) * 2
    return score


def _extract_printable_strings(text: str, min_len: int = 4) -> list[str]:
    """Extract printable ASCII strings of at least min_len from text."""
    return re.findall(r"[\x20-\x7e]{" + str(min_len) + r",}", text)


# ---------------------------------------------------------------------------
# GDB Script Runner
# ---------------------------------------------------------------------------
class GDBSolver:
    """Generate and execute GDB Python scripts for runtime binary analysis."""

    def __init__(
        self,
        binary_path: str,
        prefix: str = "flag",
        args: list[str] | None = None,
        input_data: str | None = None,
        timeout: int = TECHNIQUE_TIMEOUT,
        hook_funcs: list[str] | None = None,
        patch_addrs: list[str] | None = None,
    ):
        self.binary = os.path.abspath(binary_path)
        self.prefix = prefix
        self.args = args or []
        self.input_data = input_data
        self.timeout = timeout
        self.hook_funcs = hook_funcs or []
        self.patch_addrs = patch_addrs or []
        self.all_candidates: list[str] = []

    # ----- Strategy: strcmp/memcmp/strncmp hook -----
    def strategy_strcmp_hook(self) -> str:
        """Hook string comparison functions to extract comparison values."""
        prefix_escaped = self.prefix.replace("'", "\\'")
        return f'''
import gdb
import re
import sys

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set print elements 0")
gdb.execute("set print repeats 0")

found_values = []

class CmpBreakpoint(gdb.Breakpoint):
    """Breakpoint on comparison functions to extract arguments."""

    def __init__(self, func_name):
        try:
            super().__init__(func_name, internal=True)
            self.silent = True
            self.func_name = func_name
        except Exception:
            pass

    def stop(self):
        try:
            # x86-64: rdi = arg1, rsi = arg2
            # x86-32: stack-based
            try:
                arg1 = gdb.parse_and_eval("(char*)$rdi").string(length=512)
            except Exception:
                arg1 = ""
            try:
                arg2 = gdb.parse_and_eval("(char*)$rsi").string(length=512)
            except Exception:
                arg2 = ""

            if arg1:
                print(f"GDB_CMP_ARG1: {{arg1}}")
                found_values.append(arg1)
            if arg2:
                print(f"GDB_CMP_ARG2: {{arg2}}")
                found_values.append(arg2)

            # For memcmp, also try to get the length (rdx)
            if self.func_name == "memcmp":
                try:
                    length = int(gdb.parse_and_eval("$rdx"))
                    if length > 0 and length < 1024:
                        try:
                            raw1 = gdb.execute(f"x/{{length}}c $rdi", to_string=True)
                            raw2 = gdb.execute(f"x/{{length}}c $rsi", to_string=True)
                            print(f"GDB_MEMCMP_RAW1: {{raw1}}")
                            print(f"GDB_MEMCMP_RAW2: {{raw2}}")
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception as e:
            pass
        return False  # Continue execution

# Set breakpoints on all comparison functions
for func in ["strcmp", "strncmp", "memcmp", "strcasecmp", "strstr"]:
    try:
        CmpBreakpoint(func)
    except Exception:
        pass

# Run the binary
try:
    gdb.execute("run")
except gdb.error:
    pass

# Print summary
print("GDB_STRATEGY_DONE: strcmp_hook")
for val in found_values:
    print(f"GDB_FOUND_VALUE: {{val}}")
'''

    # ----- Strategy: anti-debug bypass -----
    def strategy_anti_debug_bypass(self) -> str:
        """Bypass ptrace-based anti-debugging and other anti-debug checks."""
        return '''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("set follow-fork-mode child")

class PtraceBypass(gdb.Breakpoint):
    """Make ptrace always return 0 (success)."""

    def __init__(self):
        try:
            super().__init__("ptrace", internal=True)
            self.silent = True
        except Exception:
            pass

    def stop(self):
        try:
            # Check if this is PTRACE_TRACEME (request == 0)
            request = int(gdb.parse_and_eval("$rdi"))
            if request == 0:
                # Skip the actual ptrace call and return 0
                gdb.execute("set $rax = 0")
                gdb.execute("return 0")
                print("GDB_ANTIDEBUG: Bypassed ptrace(PTRACE_TRACEME)")
        except Exception:
            try:
                gdb.execute("set $rax = 0")
                gdb.execute("return 0")
                print("GDB_ANTIDEBUG: Bypassed ptrace call")
            except Exception:
                pass
        return False

class IsDebuggerPresentBypass(gdb.Breakpoint):
    """Bypass checks that read /proc/self/status for TracerPid."""

    def __init__(self):
        try:
            super().__init__("fopen", internal=True)
            self.silent = True
        except Exception:
            pass

    def stop(self):
        try:
            filename = gdb.parse_and_eval("(char*)$rdi").string()
            if "status" in filename or "TracerPid" in filename:
                print(f"GDB_ANTIDEBUG: Intercepted fopen({filename})")
        except Exception:
            pass
        return False

try:
    PtraceBypass()
except Exception:
    pass

try:
    IsDebuggerPresentBypass()
except Exception:
    pass

# Also try to catch alarm/signal-based anti-debug
try:
    gdb.execute("handle SIGALRM ignore")
    gdb.execute("handle SIGTRAP ignore")
    print("GDB_ANTIDEBUG: Ignoring SIGALRM and SIGTRAP")
except Exception:
    pass

try:
    gdb.execute("run")
except gdb.error:
    pass

print("GDB_STRATEGY_DONE: anti_debug_bypass")
'''

    # ----- Strategy: decrypt and dump -----
    def strategy_decrypt_dump(self) -> str:
        """Let binary run to completion, then dump all strings from memory."""
        return '''
import gdb
import re

gdb.execute("set pagination off")
gdb.execute("set confirm off")

# Set a breakpoint at common "done with decryption" points
decrypt_done_funcs = [
    "puts", "printf", "write", "fputs",
    "fwrite", "fprintf", "__printf_chk",
]

class OutputCapture(gdb.Breakpoint):
    """Capture output function arguments to find decrypted data."""

    def __init__(self, func_name):
        try:
            super().__init__(func_name, internal=True)
            self.silent = True
            self.func_name = func_name
        except Exception:
            pass

    def stop(self):
        try:
            if self.func_name in ("puts", "fputs"):
                val = gdb.parse_and_eval("(char*)$rdi").string(length=1024)
                if val and len(val) > 2:
                    print(f"GDB_OUTPUT_{self.func_name.upper()}: {val}")
            elif self.func_name in ("printf", "__printf_chk", "fprintf"):
                # Try to get format string
                try:
                    fmt = gdb.parse_and_eval("(char*)$rdi").string(length=256)
                    print(f"GDB_OUTPUT_FMT: {fmt}")
                except Exception:
                    pass
                # Try second arg (often the actual string)
                try:
                    val = gdb.parse_and_eval("(char*)$rsi").string(length=1024)
                    if val and len(val) > 2:
                        print(f"GDB_OUTPUT_ARG: {val}")
                except Exception:
                    pass
            elif self.func_name == "write":
                try:
                    fd = int(gdb.parse_and_eval("$rdi"))
                    length = int(gdb.parse_and_eval("$rdx"))
                    if fd in (1, 2) and 0 < length < 4096:
                        buf = gdb.parse_and_eval("(char*)$rsi").string(length=length)
                        print(f"GDB_OUTPUT_WRITE: {buf}")
                except Exception:
                    pass
        except Exception:
            pass
        return False

for func in decrypt_done_funcs:
    try:
        OutputCapture(func)
    except Exception:
        pass

# Also set breakpoint at exit to dump stack/heap strings
class ExitDump(gdb.Breakpoint):
    """At program exit, dump strings from stack and nearby memory."""

    def __init__(self):
        try:
            super().__init__("exit", internal=True)
            self.silent = True
        except Exception:
            pass

    def stop(self):
        try:
            # Dump stack strings
            sp = int(gdb.parse_and_eval("$rsp"))
            for offset in range(0, 2048, 8):
                try:
                    addr = sp + offset
                    val = gdb.execute(f"x/s {addr}", to_string=True)
                    if val and len(val.strip()) > 10:
                        print(f"GDB_STACK_STR: {val.strip()}")
                except Exception:
                    pass
        except Exception:
            pass
        return True  # Stop here so we can examine

try:
    ExitDump()
except Exception:
    pass

try:
    gdb.execute("run")
except gdb.error:
    pass

print("GDB_STRATEGY_DONE: decrypt_dump")
'''

    # ----- Strategy: watchpoint on BSS/data for flag writes -----
    def strategy_watchpoint_scan(self) -> str:
        """Set hardware watchpoints on potential flag storage locations."""
        prefix_escaped = self.prefix.replace("'", "\\'")
        return f'''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")

# Start the binary, stop at main
try:
    gdb.execute("break main")
    gdb.execute("run")
except Exception:
    pass

# Find BSS and data segments to watch
# Scan for the flag prefix character in memory after running a bit
try:
    gdb.execute("continue")
except Exception:
    pass

# Try to find strings in the process
try:
    info = gdb.execute("info proc mappings", to_string=True)
    print(f"GDB_MAPPINGS: {{info}}")
except Exception:
    pass

# Search memory for common strings
search_terms = ["{prefix_escaped}", "flag", "password", "key", "secret"]
for term in search_terms:
    try:
        result = gdb.execute(f'find /b 0x400000, 0x500000, "{{term}}"', to_string=True)
        if "found" in result.lower() or "0x" in result:
            print(f"GDB_MEMORY_SEARCH {{term}}: {{result.strip()}}")
    except Exception:
        pass

# Also search heap region if available
try:
    result = gdb.execute("info proc mappings", to_string=True)
    for line in result.splitlines():
        if "[heap]" in line:
            parts = line.split()
            start = parts[0]
            end = parts[1]
            for term in search_terms:
                try:
                    found = gdb.execute(
                        f'find /b {{start}}, {{end}}, "{{term}}"',
                        to_string=True,
                    )
                    if "found" in found.lower() or "0x" in found:
                        print(f"GDB_HEAP_SEARCH {{term}}: {{found.strip()}}")
                        # Read string at found address
                        for addr_line in found.splitlines():
                            addr_line = addr_line.strip()
                            if addr_line.startswith("0x"):
                                addr = addr_line.split()[0]
                                try:
                                    s = gdb.execute(f"x/s {{addr}}", to_string=True)
                                    print(f"GDB_HEAP_STR: {{s.strip()}}")
                                except Exception:
                                    pass
                except Exception:
                    pass
except Exception:
    pass

print("GDB_STRATEGY_DONE: watchpoint_scan")
'''

    # ----- Strategy: function hooking (user-specified) -----
    def strategy_function_hook(self, func_names: list[str]) -> str:
        """Hook user-specified functions to log arguments and return values."""
        funcs_list = repr(func_names)
        return f'''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")

class FuncHook(gdb.Breakpoint):
    """Generic function hook that logs arguments."""

    def __init__(self, func_name):
        try:
            super().__init__(func_name, internal=True)
            self.silent = True
            self.func_name = func_name
        except Exception:
            pass

    def stop(self):
        try:
            # Log register state (x86-64 calling convention)
            regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            print(f"GDB_HOOK {{self.func_name}} called:")
            for i, reg in enumerate(regs):
                try:
                    val = int(gdb.parse_and_eval(f"${{reg}}"))
                    # Try to read as string
                    try:
                        s = gdb.parse_and_eval(f"(char*)${{reg}}").string(length=256)
                        print(f"  arg{{i}} (${{reg}}): 0x{{val:x}} = \\"{{s}}\\"")
                    except Exception:
                        print(f"  arg{{i}} (${{reg}}): 0x{{val:x}} ({{val}})")
                except Exception:
                    pass
        except Exception:
            pass
        return False

for func in {funcs_list}:
    try:
        FuncHook(func)
    except Exception:
        print(f"GDB_HOOK_FAIL: Could not hook {{func}}")

try:
    gdb.execute("run")
except gdb.error:
    pass

print("GDB_STRATEGY_DONE: function_hook")
'''

    # ----- Strategy: runtime patching (NOP out instructions) -----
    def strategy_runtime_patch(self, addresses: list[str]) -> str:
        """NOP out instructions at given addresses to bypass checks."""
        addrs_list = repr(addresses)
        return f'''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")

# Break at main to patch before execution
try:
    gdb.execute("break main")
    gdb.execute("run")
except Exception:
    pass

# Patch specified addresses with NOPs
for addr_str in {addrs_list}:
    try:
        addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
        # Write NOP (0x90) at the address - patch 6 bytes (typical call instruction)
        for i in range(6):
            gdb.execute(f"set *(unsigned char*)({addr} + {{i}}) = 0x90")
        print(f"GDB_PATCH: NOPed 6 bytes at 0x{{addr:x}}")
    except Exception as e:
        print(f"GDB_PATCH_FAIL: {{addr_str}}: {{e}}")

# Continue execution
try:
    gdb.execute("continue")
except gdb.error:
    pass

print("GDB_STRATEGY_DONE: runtime_patch")
'''

    # ----- Strategy: register dump at main exit -----
    def strategy_register_dump(self) -> str:
        """Dump all registers at key points (after main returns)."""
        return '''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")

class RegisterDumper(gdb.Breakpoint):
    """Dump registers when hitting common exit/check points."""

    def __init__(self, location):
        try:
            super().__init__(location, internal=True)
            self.silent = True
            self.location = location
        except Exception:
            pass

    def stop(self):
        try:
            print(f"GDB_REGDUMP at {self.location}:")
            regs = gdb.execute("info registers", to_string=True)
            print(regs)

            # Dump stack top
            try:
                sp_dump = gdb.execute("x/32xb $rsp", to_string=True)
                print(f"GDB_STACK_TOP: {sp_dump}")
            except Exception:
                pass

            # Try to read strings near common registers
            for reg in ["rax", "rbx", "rcx", "rdx", "rdi", "rsi"]:
                try:
                    s = gdb.parse_and_eval(f"(char*)${reg}").string(length=256)
                    if s and len(s) >= 3:
                        print(f"GDB_REG_STR ${reg}: {s}")
                except Exception:
                    pass
        except Exception:
            pass
        return False

# Hook at various interesting points
for loc in ["exit", "puts", "printf", "main"]:
    try:
        RegisterDumper(loc)
    except Exception:
        pass

try:
    gdb.execute("run")
except gdb.error:
    pass

print("GDB_STRATEGY_DONE: register_dump")
'''

    # ----- GDB execution engine -----
    def run_gdb(self, script_content: str, timeout: int | None = None) -> tuple[str, list[str]]:
        """Execute GDB with the given Python script, return (output, flags)."""
        timeout = timeout or self.timeout

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, dir="/tmp"
        ) as f:
            # Wrap script to handle input if provided
            if self.input_data:
                # Create input file
                input_file = f.name + ".input"
                with open(input_file, "w") as inf:
                    inf.write(self.input_data)
                    if not self.input_data.endswith("\n"):
                        inf.write("\n")
                # Redirect stdin in GDB
                f.write(f'import gdb\ngdb.execute("set args {" ".join(self.args)}")\n')
                f.write(f'gdb.execute("run < {input_file}")\n')
                # Actually, use the script as-is but set the run command
                f.truncate(0)
                f.seek(0)

            f.write(script_content)
            script_path = f.name

        try:
            # Build GDB command
            cmd = [
                "gdb", "-batch", "-nx", "-q",
                "-x", script_path,
            ]

            if self.args:
                cmd.extend(["--args", self.binary] + self.args)
            else:
                cmd.append(self.binary)

            # Prepare stdin
            stdin_data = None
            if self.input_data:
                stdin_data = self.input_data.encode()

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                input=self.input_data if self.input_data else None,
                env={**os.environ, "TERM": "dumb"},
                preexec_fn=os.setsid,
            )
            output = result.stdout + "\n" + result.stderr
        except subprocess.TimeoutExpired:
            output = "[!] GDB timed out"
        except FileNotFoundError:
            output = "[!] GDB not found - install with: apt install gdb"
        except Exception as e:
            output = f"[!] GDB error: {e}"
        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass
            # Clean up input file if created
            try:
                os.unlink(script_path + ".input")
            except OSError:
                pass

        # Extract flags from output
        flags = _find_flags(output, self.prefix)

        # Also scan GDB output lines for flag-like strings
        for line in output.splitlines():
            # Parse GDB_CMP_ARG, GDB_OUTPUT, GDB_FOUND_VALUE lines
            for marker in [
                "GDB_CMP_ARG1:", "GDB_CMP_ARG2:",
                "GDB_OUTPUT_PUTS:", "GDB_OUTPUT_ARG:",
                "GDB_OUTPUT_WRITE:", "GDB_OUTPUT_FMT:",
                "GDB_FOUND_VALUE:", "GDB_HEAP_STR:",
                "GDB_STACK_STR:", "GDB_REG_STR",
            ]:
                if marker in line:
                    val = line.split(marker, 1)[-1].strip()
                    found = _find_flags(val, self.prefix)
                    flags.extend(found)
                    # Also try the raw value as a potential flag
                    val_clean = val.strip('"').strip()
                    if re.match(r"[A-Za-z_]{2,}\{.+\}", val_clean):
                        flags.append(val_clean)

        return output, _deduplicate(flags)

    # ----- Main solve orchestrator -----
    def solve(self) -> list[str]:
        """Try all GDB strategies in order, return found flags."""
        print(f"[*] GDB Solver: {self.binary}")
        print(f"[*] Flag prefix: {self.prefix}")
        if self.args:
            print(f"[*] Arguments: {self.args}")
        if self.input_data:
            print(f"[*] Input data: {self.input_data[:50]}...")
        print()

        all_flags: list[str] = []

        # Build strategy list
        strategies: list[tuple[str, callable]] = [
            ("strcmp/memcmp hook", self.strategy_strcmp_hook),
            ("anti-debug bypass + strcmp", self._strategy_combined_antidebug_strcmp),
            ("decrypt and dump", self.strategy_decrypt_dump),
            ("register dump", self.strategy_register_dump),
            ("watchpoint memory scan", self.strategy_watchpoint_scan),
        ]

        # Add function hooks if specified
        if self.hook_funcs:
            strategies.append((
                f"function hook ({', '.join(self.hook_funcs)})",
                lambda: self.strategy_function_hook(self.hook_funcs),
            ))

        # Add runtime patches if specified
        if self.patch_addrs:
            strategies.append((
                f"runtime patch ({', '.join(self.patch_addrs)})",
                lambda: self.strategy_runtime_patch(self.patch_addrs),
            ))

        for name, strategy_fn in strategies:
            print(f"[*] Trying GDB strategy: {name}")
            try:
                script = strategy_fn()
                output, flags = self.run_gdb(script)

                if flags:
                    print(f"[+] Strategy '{name}' found {len(flags)} flag(s)")
                    all_flags.extend(flags)
                    # Return immediately on first success
                    break

                # Also scan raw output for any printable flag-like strings
                raw_flags = _find_flags(output, self.prefix)
                if raw_flags:
                    print(f"[+] Strategy '{name}' found {len(raw_flags)} flag(s) in raw output")
                    all_flags.extend(raw_flags)
                    break

                print(f"[-] Strategy '{name}': no flags found")

            except Exception as e:
                print(f"[!] Strategy '{name}' failed: {e}")

            print()

        all_flags = _deduplicate(all_flags)

        if all_flags:
            # Score and sort
            all_flags.sort(
                key=lambda f: _score_flag(f, self.prefix), reverse=True,
            )
            best = all_flags[0]
            print(f"\nEXTRACTED FLAG: {best}")
            if len(all_flags) > 1:
                print(f"[*] Also found: {all_flags[1:]}")
        else:
            print("\n[-] No flags found via GDB analysis.")

        return all_flags

    def _strategy_combined_antidebug_strcmp(self) -> str:
        """Combined anti-debug bypass with strcmp hooking."""
        return '''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")
gdb.execute("handle SIGALRM ignore")
gdb.execute("handle SIGTRAP ignore")

# --- Anti-debug bypass ---
class PtraceBypass(gdb.Breakpoint):
    def __init__(self):
        try:
            super().__init__("ptrace", internal=True)
            self.silent = True
        except Exception:
            pass

    def stop(self):
        try:
            gdb.execute("set $rax = 0")
            gdb.execute("return 0")
            print("GDB_ANTIDEBUG: Bypassed ptrace")
        except Exception:
            pass
        return False

try:
    PtraceBypass()
except Exception:
    pass

# --- Comparison hooks ---
class CmpHook(gdb.Breakpoint):
    def __init__(self, func):
        try:
            super().__init__(func, internal=True)
            self.silent = True
            self.func = func
        except Exception:
            pass

    def stop(self):
        try:
            try:
                a1 = gdb.parse_and_eval("(char*)$rdi").string(length=512)
                print(f"GDB_CMP_ARG1: {a1}")
            except Exception:
                pass
            try:
                a2 = gdb.parse_and_eval("(char*)$rsi").string(length=512)
                print(f"GDB_CMP_ARG2: {a2}")
            except Exception:
                pass
        except Exception:
            pass
        return False

for func in ["strcmp", "strncmp", "memcmp", "strcasecmp"]:
    try:
        CmpHook(func)
    except Exception:
        pass

# --- Output hooks ---
class OutputHook(gdb.Breakpoint):
    def __init__(self, func):
        try:
            super().__init__(func, internal=True)
            self.silent = True
            self.func = func
        except Exception:
            pass

    def stop(self):
        try:
            val = gdb.parse_and_eval("(char*)$rdi").string(length=1024)
            if val and len(val) > 2:
                print(f"GDB_OUTPUT_{self.func.upper()}: {val}")
        except Exception:
            pass
        return False

for func in ["puts", "printf"]:
    try:
        OutputHook(func)
    except Exception:
        pass

try:
    gdb.execute("run")
except gdb.error:
    pass

print("GDB_STRATEGY_DONE: combined_antidebug_strcmp")
'''


# ---------------------------------------------------------------------------
# LD_PRELOAD anti-debug bypass (supplementary)
# ---------------------------------------------------------------------------
def _create_ld_preload_bypass(binary: str, prefix: str, timeout: int = 15) -> list[str]:
    """Create an LD_PRELOAD library that fakes ptrace to bypass anti-debug."""
    print("[*] Trying LD_PRELOAD ptrace bypass")

    c_source = '''
#include <sys/types.h>
long ptrace(int request, ...) {
    return 0;
}
int _ptrace(int request, ...) {
    return 0;
}
'''
    flags: list[str] = []
    tmpdir = tempfile.mkdtemp(prefix="gdb_solve_")

    try:
        src_path = os.path.join(tmpdir, "fakeptrace.c")
        lib_path = os.path.join(tmpdir, "fakeptrace.so")

        with open(src_path, "w") as f:
            f.write(c_source)

        # Compile shared library
        compile_cmd = [
            "gcc", "-shared", "-fPIC", "-o", lib_path, src_path,
            "-nostdlib",
        ]
        result = subprocess.run(
            compile_cmd, capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            print(f"[-] LD_PRELOAD: gcc compilation failed: {result.stderr}")
            return []

        # Run binary with LD_PRELOAD
        env = {**os.environ, "LD_PRELOAD": lib_path}
        try:
            result = subprocess.run(
                [binary], capture_output=True, text=True,
                timeout=timeout, env=env,
                preexec_fn=os.setsid,
            )
            output = result.stdout + "\n" + result.stderr
            flags = _find_flags(output, prefix)
            if flags:
                print(f"[+] LD_PRELOAD bypass found {len(flags)} flag(s)")
        except subprocess.TimeoutExpired:
            print("[-] LD_PRELOAD: binary timed out")
        except Exception as e:
            print(f"[-] LD_PRELOAD: error: {e}")

    finally:
        # Cleanup
        for f in [src_path, lib_path]:
            try:
                os.unlink(f)
            except OSError:
                pass
        try:
            os.rmdir(tmpdir)
        except OSError:
            pass

    return flags


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken GDB Solver -- runtime analysis via GDB Python scripting",
    )
    parser.add_argument("--binary", required=True, help="Path to the ELF binary")
    parser.add_argument(
        "--prefix", default="flag",
        help="Flag prefix (default: 'flag')",
    )
    parser.add_argument(
        "--args", nargs="*", default=[],
        help="Arguments to pass to the binary",
    )
    parser.add_argument(
        "--input", default=None,
        help="Input to feed to the binary via stdin",
    )
    parser.add_argument(
        "--timeout", type=int, default=TECHNIQUE_TIMEOUT,
        help="Timeout per GDB strategy in seconds (default: 30)",
    )
    parser.add_argument(
        "--strategy", default=None,
        choices=["strcmp", "antidebug", "decrypt", "register", "watchpoint", "all"],
        help="Run a specific strategy instead of all",
    )
    parser.add_argument(
        "--hook-funcs", nargs="*", default=[],
        help="Additional function names to hook (e.g., check_password verify)",
    )
    parser.add_argument(
        "--patch-addrs", nargs="*", default=[],
        help="Addresses to NOP out at runtime (e.g., 0x401234)",
    )
    parser.add_argument(
        "--ld-preload", action="store_true",
        help="Also try LD_PRELOAD ptrace bypass",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)

    # Validate binary
    if not os.path.isfile(binary):
        print(f"[-] File not found: {binary}")
        sys.exit(1)

    if not _is_elf(binary):
        print(f"[-] Not an ELF binary: {binary}")
        sys.exit(1)

    # Ensure executable
    if not os.access(binary, os.X_OK):
        try:
            os.chmod(binary, os.stat(binary).st_mode | 0o111)
        except OSError as e:
            print(f"[-] Cannot make executable: {e}")
            sys.exit(1)

    solver = GDBSolver(
        binary_path=binary,
        prefix=args.prefix,
        args=args.args,
        input_data=args.input,
        timeout=args.timeout,
        hook_funcs=args.hook_funcs,
        patch_addrs=args.patch_addrs,
    )

    found_flags = solver.solve()

    # Also try LD_PRELOAD if requested or if GDB found nothing
    if (args.ld_preload or not found_flags) and not found_flags:
        ld_flags = _create_ld_preload_bypass(binary, args.prefix, args.timeout)
        if ld_flags:
            found_flags.extend(ld_flags)
            best = max(ld_flags, key=lambda f: _score_flag(f, args.prefix))
            print(f"EXTRACTED FLAG: {best}")

    sys.exit(0 if found_flags else 1)


if __name__ == "__main__":
    main()
