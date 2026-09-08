#!/usr/bin/env python3
"""auto_memory_dump -- Runtime memory extraction and analysis.

Analyzes process memory at runtime to extract flags, keys, and secrets:
  1. Process memory dump -- read /proc/pid/maps + /proc/pid/mem
  2. Run-and-dump -- start binary, let it initialize/decrypt, dump memory
  3. Heap analysis -- parse heap chunks, find strings and pointers
  4. Stack analysis -- extract local variables and return addresses
  5. String extraction -- find all printable strings in memory regions
  6. Pattern search -- search memory for flag pattern, known prefixes
  7. Core dump analysis -- parse core files for embedded flags/keys
  8. Crypto key detection -- find AES/RSA keys in memory by entropy/pattern

Usage:
    python3 auto_memory_dump.py --binary ./challenge --prefix flag
    python3 auto_memory_dump.py --pid 12345 --prefix flag
    python3 auto_memory_dump.py --core ./core.dump --prefix flag
    python3 auto_memory_dump.py --binary ./challenge --delay 2 --input "password"

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import math
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_FLAG_PATTERN = re.compile(r"[A-Za-z_]{2,}\{[^\}]{3,}\}")
MAX_REGION_SIZE = 50 * 1024 * 1024  # 50 MB per region
TECHNIQUE_TIMEOUT = 15


# ---------------------------------------------------------------------------
# Flag helpers
# ---------------------------------------------------------------------------
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


def _deduplicate(items: list[str]) -> list[str]:
    """Deduplicate while preserving order."""
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
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


def _is_elf(path: str) -> bool:
    """Check if file is an ELF binary."""
    try:
        with open(path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except (OSError, IOError):
        return False


def _extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    """Extract printable ASCII strings from binary data."""
    pattern = rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"
    return [m.group(0).decode("ascii") for m in re.finditer(pattern, data)]


def _entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence (0.0-8.0)."""
    if not data:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    total = len(data)
    ent = 0.0
    for count in freq:
        if count > 0:
            p = count / total
            ent -= p * math.log2(p)
    return ent


# ---------------------------------------------------------------------------
# Memory map parser
# ---------------------------------------------------------------------------
def _parse_maps(pid: int) -> list[dict]:
    """Parse /proc/pid/maps and return list of memory regions."""
    maps_path = f"/proc/{pid}/maps"
    regions = []
    try:
        with open(maps_path, "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 2:
                    continue

                addr_range = parts[0]
                perms = parts[1]
                name = parts[-1] if len(parts) >= 6 else ""

                try:
                    start_s, end_s = addr_range.split("-")
                    start = int(start_s, 16)
                    end = int(end_s, 16)
                except ValueError:
                    continue

                regions.append({
                    "start": start,
                    "end": end,
                    "size": end - start,
                    "perms": perms,
                    "name": name,
                    "readable": "r" in perms,
                    "writable": "w" in perms,
                    "executable": "x" in perms,
                })
    except (OSError, PermissionError) as e:
        print(f"[-] Cannot read {maps_path}: {e}")

    return regions


def _read_memory_region(pid: int, start: int, size: int) -> bytes:
    """Read a memory region from /proc/pid/mem."""
    mem_path = f"/proc/{pid}/mem"
    try:
        with open(mem_path, "rb") as f:
            f.seek(start)
            return f.read(size)
    except (OSError, PermissionError, OverflowError, ValueError):
        return b""


# ---------------------------------------------------------------------------
# Memory Dumper
# ---------------------------------------------------------------------------
class MemoryDumper:
    """Runtime memory analysis and extraction."""

    def __init__(
        self,
        binary: str | None = None,
        pid: int | None = None,
        core: str | None = None,
        prefix: str = "flag",
        delay: float = 0.5,
        input_data: str | None = None,
        binary_args: list[str] | None = None,
        timeout: int = TECHNIQUE_TIMEOUT,
    ):
        self.binary = os.path.abspath(binary) if binary else None
        self.pid = pid
        self.core = os.path.abspath(core) if core else None
        self.prefix = prefix
        self.delay = delay
        self.input_data = input_data
        self.binary_args = binary_args or []
        self.timeout = timeout
        self.all_flags: list[str] = []
        self._started_proc: subprocess.Popen | None = None

    def _cleanup_proc(self) -> None:
        """Kill any started process."""
        if self._started_proc:
            try:
                os.killpg(os.getpgid(self._started_proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            try:
                self._started_proc.kill()
            except Exception:
                pass
            try:
                self._started_proc.wait(timeout=2)
            except Exception:
                pass
            self._started_proc = None

    # ----- Technique 1: Run binary and dump memory -----
    def technique_run_and_dump(self) -> list[str]:
        """Start binary, wait for initialization, dump all readable memory."""
        print("[*] Technique 1: run binary and dump memory")

        if not self.binary:
            print("[-] No binary specified")
            return []

        flags: list[str] = []

        try:
            cmd = [self.binary] + self.binary_args
            self._started_proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                preexec_fn=os.setsid,
            )

            # Send input if provided
            if self.input_data:
                try:
                    self._started_proc.stdin.write(self.input_data.encode())
                    self._started_proc.stdin.flush()
                except (BrokenPipeError, OSError):
                    pass

            # Wait for binary to initialize/decrypt
            time.sleep(self.delay)

            if self._started_proc.poll() is not None:
                # Process already exited - check output
                stdout = self._started_proc.stdout.read().decode("utf-8", errors="replace")
                stderr = self._started_proc.stderr.read().decode("utf-8", errors="replace")
                flags.extend(_find_flags(stdout + stderr, self.prefix))
                if flags:
                    print(f"[+] Found {len(flags)} flag(s) in process output")
                else:
                    print("[-] Process exited immediately, no flags in output")
                return flags

            pid = self._started_proc.pid
            print(f"    Process PID: {pid}")

            # Dump memory
            dump_flags = self._dump_pid_memory(pid)
            flags.extend(dump_flags)

        except FileNotFoundError:
            print(f"[-] Binary not found: {self.binary}")
        except PermissionError:
            # Try making executable
            try:
                os.chmod(self.binary, os.stat(self.binary).st_mode | 0o111)
                return self.technique_run_and_dump()
            except OSError:
                print(f"[-] Cannot execute: {self.binary}")
        except Exception as e:
            print(f"[-] Run-and-dump error: {e}")
        finally:
            self._cleanup_proc()

        return flags

    # ----- Technique 2: Dump existing process -----
    def technique_dump_pid(self) -> list[str]:
        """Dump memory of an already-running process by PID."""
        print(f"[*] Technique 2: dump existing process (PID {self.pid})")

        if not self.pid:
            print("[-] No PID specified")
            return []

        return self._dump_pid_memory(self.pid)

    # ----- Core memory dump implementation -----
    def _dump_pid_memory(self, pid: int) -> list[str]:
        """Dump all readable memory of a process and search for flags."""
        flags: list[str] = []

        regions = _parse_maps(pid)
        if not regions:
            print(f"[-] No memory regions found for PID {pid}")
            return flags

        readable = [r for r in regions if r["readable"]]
        print(f"    Found {len(readable)} readable memory regions")

        total_scanned = 0
        interesting_strings: list[str] = []

        for region in readable:
            size = region["size"]
            if size > MAX_REGION_SIZE:
                continue
            if size < 4:
                continue

            data = _read_memory_region(pid, region["start"], size)
            if not data:
                continue

            total_scanned += len(data)

            # Search for flags in raw bytes
            text = data.decode("utf-8", errors="replace")
            found = _find_flags(text, self.prefix)
            if found:
                flags.extend(found)
                print(f"    [+] Flag found in region 0x{region['start']:x}-0x{region['end']:x} ({region['name']})")

            # Also extract interesting strings
            strings = _extract_strings(data, min_len=6)
            for s in strings:
                # Check for flag-like patterns
                if _find_flags(s, self.prefix):
                    flags.extend(_find_flags(s, self.prefix))
                # Collect potentially interesting strings
                elif any(kw in s.lower() for kw in ["flag", "key", "secret", "pass", "token", "hash"]):
                    interesting_strings.append(s)

            # Search for the flag prefix directly in bytes
            prefix_bytes = self.prefix.encode()
            idx = 0
            while True:
                idx = data.find(prefix_bytes, idx)
                if idx == -1:
                    break
                # Extract surrounding context
                context_start = max(0, idx - 10)
                context_end = min(len(data), idx + 200)
                context = data[context_start:context_end].decode("utf-8", errors="replace")
                found = _find_flags(context, self.prefix)
                flags.extend(found)
                idx += 1

        print(f"    Scanned {total_scanned / 1024:.0f} KB of process memory")

        if interesting_strings:
            print(f"    Found {len(interesting_strings)} interesting strings:")
            for s in interesting_strings[:10]:
                print(f"      {s[:100]}")

        return flags

    # ----- Technique 3: Analyze core dump -----
    def technique_core_dump(self) -> list[str]:
        """Analyze a core dump file for flags and keys."""
        print(f"[*] Technique 3: core dump analysis ({self.core})")

        if not self.core:
            print("[-] No core file specified")
            return []

        if not os.path.isfile(self.core):
            print(f"[-] Core file not found: {self.core}")
            return []

        flags: list[str] = []

        # Method 1: Direct binary scan
        print("    Scanning core dump for flag patterns...")
        try:
            with open(self.core, "rb") as f:
                # Read in chunks to handle large core files
                chunk_size = 10 * 1024 * 1024  # 10 MB chunks
                overlap = 1024  # Overlap to catch strings spanning chunks
                offset = 0
                prev_tail = b""

                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break

                    # Combine with tail of previous chunk for overlap
                    search_data = prev_tail + chunk
                    text = search_data.decode("utf-8", errors="replace")
                    found = _find_flags(text, self.prefix)
                    flags.extend(found)

                    # Extract all strings
                    strings = _extract_strings(search_data, min_len=6)
                    for s in strings:
                        f_found = _find_flags(s, self.prefix)
                        flags.extend(f_found)

                    prev_tail = chunk[-overlap:] if len(chunk) > overlap else chunk
                    offset += len(chunk)

            print(f"    Scanned {offset / 1024 / 1024:.1f} MB of core dump")
        except (OSError, PermissionError) as e:
            print(f"[-] Cannot read core file: {e}")

        # Method 2: Use GDB to analyze core dump
        if not flags and self.binary:
            print("    Using GDB to analyze core dump...")
            gdb_flags = self._gdb_core_analyze()
            flags.extend(gdb_flags)

        # Method 3: Use strings command
        if not flags:
            print("    Running strings on core dump...")
            try:
                result = subprocess.run(
                    ["strings", "-a", "-n", "6", self.core],
                    capture_output=True, text=True, timeout=30,
                )
                found = _find_flags(result.stdout, self.prefix)
                flags.extend(found)

                # Also check for interesting strings
                for line in result.stdout.splitlines():
                    if any(kw in line.lower() for kw in ["flag", "key", "secret"]):
                        f_found = _find_flags(line, self.prefix)
                        if f_found:
                            flags.extend(f_found)
                        elif len(line) > 3:
                            print(f"    Interesting: {line[:100]}")
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return flags

    def _gdb_core_analyze(self) -> list[str]:
        """Use GDB to analyze core dump with the original binary."""
        flags: list[str] = []

        gdb_commands = f"""
set pagination off
set print elements 0

# Print all strings on stack
info locals
info args

# Dump registers
info registers

# Print stack backtrace
bt full

# Search for flag prefix in memory
find /b 0x0, 0xffffffffffffffff, "{self.prefix}"

quit
"""
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                f.write(gdb_commands)
                gdb_script = f.name

            result = subprocess.run(
                ["gdb", "-batch", "-nx", "-q", "-x", gdb_script,
                 self.binary, self.core],
                capture_output=True, text=True, timeout=30,
            )
            output = result.stdout + "\n" + result.stderr
            flags.extend(_find_flags(output, self.prefix))

            os.unlink(gdb_script)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

        return flags

    # ----- Technique 4: Crypto key detection -----
    def technique_crypto_keys(self) -> list[str]:
        """Search process memory for cryptographic keys by entropy and patterns."""
        print("[*] Technique 4: cryptographic key detection in memory")

        pid = self.pid
        if not pid and self._started_proc:
            pid = self._started_proc.pid

        if not pid and self.binary:
            # Start the binary briefly to scan
            try:
                proc = subprocess.Popen(
                    [self.binary] + self.binary_args,
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    preexec_fn=os.setsid,
                )
                if self.input_data:
                    try:
                        proc.stdin.write(self.input_data.encode())
                        proc.stdin.flush()
                    except (BrokenPipeError, OSError):
                        pass
                time.sleep(self.delay)
                if proc.poll() is None:
                    pid = proc.pid
                else:
                    return []
                self._started_proc = proc
            except Exception as e:
                print(f"[-] Cannot start binary: {e}")
                return []

        if not pid:
            print("[-] No PID available for crypto key scan")
            return []

        flags: list[str] = []
        keys_found: list[dict] = []

        regions = _parse_maps(pid)
        readable = [r for r in regions if r["readable"] and r["size"] < MAX_REGION_SIZE]

        for region in readable:
            data = _read_memory_region(pid, region["start"], region["size"])
            if not data:
                continue

            # Look for high-entropy blocks (potential keys)
            block_size = 32  # AES-256 key size
            for offset in range(0, len(data) - block_size, 16):
                block = data[offset:offset + block_size]
                ent = _entropy(block)

                # High entropy block (> 7.0 is suspicious for crypto keys)
                if ent > 7.0:
                    # Check if it's surrounded by lower entropy (not just random data)
                    pre = data[max(0, offset - 32):offset]
                    post = data[offset + block_size:offset + block_size + 32]
                    if pre and post:
                        pre_ent = _entropy(pre)
                        post_ent = _entropy(post)
                        if pre_ent < 6.0 or post_ent < 6.0:
                            keys_found.append({
                                "offset": region["start"] + offset,
                                "entropy": ent,
                                "hex": block.hex(),
                                "size": block_size,
                                "region": region["name"],
                            })

            # Search for RSA key markers
            rsa_markers = [
                b"-----BEGIN RSA PRIVATE KEY-----",
                b"-----BEGIN PRIVATE KEY-----",
                b"-----BEGIN EC PRIVATE KEY-----",
            ]
            for marker in rsa_markers:
                idx = data.find(marker)
                if idx != -1:
                    # Extract the full key
                    end_marker = marker.replace(b"BEGIN", b"END")
                    end_idx = data.find(end_marker, idx)
                    if end_idx != -1:
                        key_data = data[idx:end_idx + len(end_marker)]
                        key_str = key_data.decode("ascii", errors="replace")
                        print(f"    [+] Found RSA/EC key at 0x{region['start'] + idx:x}")
                        print(f"        {key_str[:80]}...")

            # Also check for flag patterns in the data
            text = data.decode("utf-8", errors="replace")
            flags.extend(_find_flags(text, self.prefix))

        if keys_found:
            print(f"    Found {len(keys_found)} high-entropy blocks (potential keys):")
            for key in keys_found[:5]:
                print(f"      Addr: 0x{key['offset']:x}, Entropy: {key['entropy']:.2f}, "
                      f"Hex: {key['hex'][:32]}...")

        self._cleanup_proc()
        return flags

    # ----- Technique 5: GDB-assisted memory analysis -----
    def technique_gdb_memory(self) -> list[str]:
        """Use GDB to set breakpoints and dump memory at key moments."""
        print("[*] Technique 5: GDB-assisted memory analysis")

        if not self.binary:
            print("[-] No binary specified for GDB analysis")
            return []

        flags: list[str] = []

        gdb_script = f'''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")

class MemDumper(gdb.Breakpoint):
    """Dump memory at interesting function calls."""

    def __init__(self, func):
        try:
            super().__init__(func, internal=True)
            self.silent = True
            self.func = func
            self.hit_count = 0
        except Exception:
            pass

    def stop(self):
        self.hit_count += 1
        if self.hit_count > 20:
            return False  # Don't dump too many times

        try:
            # Dump string arguments
            for reg in ["rdi", "rsi", "rdx"]:
                try:
                    val = gdb.parse_and_eval(f"(char*)${{reg}}").string(length=512)
                    if val and len(val) >= 3:
                        print(f"MEMDUMP_STR ${{reg}}: {{val}}")
                except Exception:
                    pass

            # For memcpy/memmove, dump the destination after
            if self.func in ("memcpy", "memmove"):
                try:
                    dst = int(gdb.parse_and_eval("$rdi"))
                    size = int(gdb.parse_and_eval("$rdx"))
                    if 0 < size < 1024:
                        gdb.execute("finish")
                        raw = gdb.execute(f"x/{{size}}c {{dst}}", to_string=True)
                        print(f"MEMDUMP_COPY: {{raw}}")
                except Exception:
                    pass
        except Exception:
            pass
        return False

# Hook memory and string functions
for func in ["strcmp", "strncmp", "memcmp", "memcpy", "memmove",
             "strcpy", "strncpy", "puts", "printf"]:
    try:
        MemDumper(func)
    except Exception:
        pass

try:
    gdb.execute("run")
except gdb.error:
    pass

print("MEMDUMP_DONE")
'''

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, dir="/tmp",
            ) as f:
                f.write(gdb_script)
                script_path = f.name

            cmd = ["gdb", "-batch", "-nx", "-q", "-x", script_path, self.binary]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
                input=self.input_data,
                env={**os.environ, "TERM": "dumb"},
            )
            output = result.stdout + "\n" + result.stderr

            # Extract flags from GDB output
            flags.extend(_find_flags(output, self.prefix))

            # Parse MEMDUMP_STR lines for additional flag candidates
            for line in output.splitlines():
                if "MEMDUMP_STR" in line or "MEMDUMP_COPY" in line:
                    found = _find_flags(line, self.prefix)
                    flags.extend(found)

            os.unlink(script_path)
        except subprocess.TimeoutExpired:
            print("[-] GDB memory analysis timed out")
        except FileNotFoundError:
            print("[-] GDB not found")
        except Exception as e:
            print(f"[-] GDB memory analysis error: {e}")

        return flags

    # ----- Technique 6: Strings from binary sections -----
    def technique_binary_strings(self) -> list[str]:
        """Extract strings from binary .data/.rodata sections and search."""
        print("[*] Technique 6: binary section string extraction")

        if not self.binary:
            print("[-] No binary specified")
            return []

        flags: list[str] = []

        # Use objdump to get section contents
        try:
            result = subprocess.run(
                ["objdump", "-s", "-j", ".rodata", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            flags.extend(_find_flags(result.stdout, self.prefix))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        try:
            result = subprocess.run(
                ["objdump", "-s", "-j", ".data", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            flags.extend(_find_flags(result.stdout, self.prefix))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Use strings as fallback
        try:
            result = subprocess.run(
                ["strings", "-a", "-n", "6", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            flags.extend(_find_flags(result.stdout, self.prefix))
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        # Read raw binary and search
        try:
            with open(self.binary, "rb") as f:
                data = f.read()
            text = data.decode("utf-8", errors="replace")
            flags.extend(_find_flags(text, self.prefix))

            # Search for XOR-encoded flags (common in CTF)
            prefix_bytes = self.prefix.encode()
            for xor_key in range(1, 256):
                decoded = bytes(b ^ xor_key for b in data[:len(data)])
                # Only check first 1MB for XOR to avoid slow scan
                check = decoded[:1024 * 1024].decode("utf-8", errors="replace")
                found = _find_flags(check, self.prefix)
                if found:
                    print(f"    [+] XOR key 0x{xor_key:02x} reveals flag")
                    flags.extend(found)
                    break
        except (OSError, PermissionError):
            pass

        if flags:
            print(f"[+] Found {len(flags)} flag(s) in binary sections")
        else:
            print("[-] No flags in binary sections")
        return flags

    # ----- Main solve orchestrator -----
    def solve(self) -> list[str]:
        """Run all memory dump techniques, return found flags."""
        target = self.binary or f"PID {self.pid}" or self.core
        print(f"[*] Memory Dumper: {target}")
        print(f"[*] Flag prefix: {self.prefix}")
        print()

        all_flags: list[str] = []

        if self.core:
            # Core dump analysis
            flags = self.technique_core_dump()
            all_flags.extend(flags)

        if self.pid:
            # Live process dump
            flags = self.technique_dump_pid()
            all_flags.extend(flags)

        if self.binary:
            strategies: list[tuple[str, callable]] = [
                ("run and dump", self.technique_run_and_dump),
                ("binary strings", self.technique_binary_strings),
                ("GDB memory", self.technique_gdb_memory),
                ("crypto keys", self.technique_crypto_keys),
            ]

            for name, strategy_fn in strategies:
                try:
                    flags = strategy_fn()
                    all_flags.extend(flags)
                    if all_flags:
                        break
                except Exception as e:
                    print(f"[!] Technique '{name}' failed: {e}")
                print()

        all_flags = _deduplicate(all_flags)

        if all_flags:
            all_flags.sort(
                key=lambda f: _score_flag(f, self.prefix), reverse=True,
            )
            best = all_flags[0]
            print(f"\nEXTRACTED FLAG: {best}")
            if len(all_flags) > 1:
                print(f"[*] Also found: {all_flags[1:]}")
        else:
            print("\n[-] No flags found via memory analysis.")

        return all_flags


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Memory Dump -- runtime memory extraction and analysis",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--binary", help="Path to ELF binary to analyze")
    group.add_argument("--pid", type=int, help="PID of running process to dump")
    group.add_argument("--core", help="Path to core dump file")
    parser.add_argument(
        "--prefix", default="flag",
        help="Flag prefix (default: 'flag')",
    )
    parser.add_argument(
        "--delay", type=float, default=0.5,
        help="Seconds to wait after starting binary before dumping (default: 0.5)",
    )
    parser.add_argument(
        "--input", default=None,
        help="Input to feed to the binary via stdin",
    )
    parser.add_argument(
        "--args", nargs="*", default=[],
        help="Arguments to pass to the binary",
    )
    parser.add_argument(
        "--timeout", type=int, default=TECHNIQUE_TIMEOUT,
        help="Timeout per technique in seconds (default: 15)",
    )
    args = parser.parse_args()

    # Validate binary
    if args.binary:
        binary = os.path.abspath(args.binary)
        if not os.path.isfile(binary):
            print(f"[-] File not found: {binary}")
            sys.exit(1)
        if not _is_elf(binary):
            print(f"[-] Not an ELF binary: {binary}")
            sys.exit(1)
        if not os.access(binary, os.X_OK):
            try:
                os.chmod(binary, os.stat(binary).st_mode | 0o111)
            except OSError as e:
                print(f"[-] Cannot make executable: {e}")
                sys.exit(1)
    else:
        binary = None

    dumper = MemoryDumper(
        binary=binary,
        pid=args.pid,
        core=args.core,
        prefix=args.prefix,
        delay=args.delay,
        input_data=args.input,
        binary_args=args.args,
        timeout=args.timeout,
    )

    found = dumper.solve()
    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
