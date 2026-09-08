#!/usr/bin/env python3
"""auto_patcher -- ELF binary flag-gate scanner and patcher.

Scans ELF binaries for "flag gate" patterns -- boolean assignments and
conditional jumps that control whether flag/success output is reached --
then patches them and runs the result to extract the flag.

Flag gate patterns detected:
  1. mov byte [rbp+off], 0x0  (C6 85 xx xx xx xx 00) -- boolean gate set to false
     Patch: change immediate 0x00 -> 0x01
  2. mov byte [rbp+off], 0x0  (C6 45 xx 00) -- short-form boolean gate
     Patch: change immediate 0x00 -> 0x01
  3. mov dword [rbp+off], 0x0 (C7 85 xx xx xx xx 00 00 00 00) -- 32-bit gate
     Patch: change first immediate byte 0x00 -> 0x01
  4. je/jz -> jne/jnz  (74 xx -> 75 xx, 0F 84 -> 0F 85) -- conditional jump flip
  5. jne/jnz -> je/jz  (75 xx -> 74 xx, 0F 85 -> 0F 84) -- reverse conditional flip
  6. test reg,reg / cmp reg,0 followed by je/jne -- conditional check + jump pattern

Modes:
  --scan           Scan-only: report flag gate candidates (no patching)
  --auto           Scan, patch ALL gates, run binary, extract flag
  --offset 0xABC   Explicit patch at given file offset
  --patch-value 01 Byte(s) to write (default: flip 0x00<->0x01 or je<->jne)
  --nop            NOP out bytes instead of value-patching (legacy mode)

Usage:
  python3 auto_patcher.py binary --scan
  python3 auto_patcher.py binary --auto --flag-format "HTB{.*}"
  python3 auto_patcher.py binary --offset 0x48bc --patch-value 01
  python3 auto_patcher.py binary --offset 0x11ab --nop --bytes 2
"""
import argparse
import os
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile

DEFAULT_FLAG_PATTERN = r"[A-Za-z0-9_]{2,}\{[^\}]{3,}\}"
SCAN_TIMEOUT = 10  # seconds for running patched binary (per attempt)
AUTO_TIMEOUT = 15   # seconds for auto-mode per-attempt runs
EXTENDED_TIMEOUT = 30  # seconds for extended retry attempts


# ---------------------------------------------------------------------------
# ELF helpers
# ---------------------------------------------------------------------------

def _is_elf(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except (OSError, IOError):
        return False


def _read_binary(path: str) -> bytes:
    with open(path, "rb") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Flag gate pattern scanners
# ---------------------------------------------------------------------------

class FlagGate:
    """A detected flag-gate candidate in the binary."""
    __slots__ = ("offset", "original", "patched", "pattern_type", "description", "confidence")

    def __init__(self, offset: int, original: bytes, patched: bytes,
                 pattern_type: str, description: str, confidence: float = 0.5):
        self.offset = offset
        self.original = original
        self.patched = patched
        self.pattern_type = pattern_type
        self.description = description
        self.confidence = confidence  # 0.0-1.0: higher = more likely a real gate

    def __repr__(self) -> str:
        return (f"FlagGate(0x{self.offset:x}, {self.pattern_type}, "
                f"conf={self.confidence:.2f}, {self.description})")


def _scan_mov_byte_gates(data: bytes) -> list[FlagGate]:
    """Scan for mov byte [rbp+off], 0x0 patterns (long form: C6 85 xx xx xx xx 00)."""
    gates: list[FlagGate] = []
    # C6 85 = mov byte [rbp + disp32], imm8
    # Pattern: C6 85 [4 bytes disp32] 00
    i = 0
    while i < len(data) - 7:
        if data[i] == 0xC6 and data[i + 1] == 0x85 and data[i + 6] == 0x00:
            disp = struct.unpack_from("<i", data, i + 2)[0]
            desc = f"mov byte [rbp{disp:+#x}], 0x0 -> 0x1"
            gate = FlagGate(
                offset=i + 6,
                original=b'\x00',
                patched=b'\x01',
                pattern_type="mov_byte_long",
                description=desc,
                confidence=0.6,
            )
            gates.append(gate)
            i += 7
        else:
            i += 1
    return gates


def _scan_mov_byte_short_gates(data: bytes) -> list[FlagGate]:
    """Scan for mov byte [rbp+off], 0x0 patterns (short form: C6 45 xx 00)."""
    gates: list[FlagGate] = []
    # C6 45 = mov byte [rbp + disp8], imm8
    i = 0
    while i < len(data) - 4:
        if data[i] == 0xC6 and data[i + 1] == 0x45 and data[i + 3] == 0x00:
            disp = struct.unpack_from("<b", data, i + 2)[0]
            desc = f"mov byte [rbp{disp:+#x}], 0x0 -> 0x1"
            gate = FlagGate(
                offset=i + 3,
                original=b'\x00',
                patched=b'\x01',
                pattern_type="mov_byte_short",
                description=desc,
                confidence=0.5,
            )
            gates.append(gate)
            i += 4
        else:
            i += 1
    return gates


def _scan_mov_dword_gates(data: bytes) -> list[FlagGate]:
    """Scan for mov dword [rbp+off], 0x0 (C7 85 xx xx xx xx 00 00 00 00)."""
    gates: list[FlagGate] = []
    i = 0
    while i < len(data) - 10:
        if (data[i] == 0xC7 and data[i + 1] == 0x85
                and data[i + 6:i + 10] == b'\x00\x00\x00\x00'):
            disp = struct.unpack_from("<i", data, i + 2)[0]
            desc = f"mov dword [rbp{disp:+#x}], 0x0 -> 0x1"
            gate = FlagGate(
                offset=i + 6,
                original=b'\x00\x00\x00\x00',
                patched=b'\x01\x00\x00\x00',
                pattern_type="mov_dword",
                description=desc,
                confidence=0.4,
            )
            gates.append(gate)
            i += 10
        else:
            i += 1
    return gates


def _scan_conditional_jump_gates(data: bytes) -> list[FlagGate]:
    """Scan for je/jne short jumps (74 xx / 75 xx) that could gate flag output."""
    gates: list[FlagGate] = []
    i = 0
    while i < len(data) - 2:
        if data[i] == 0x74:  # je short
            rel = struct.unpack_from("<b", data, i + 1)[0]
            desc = f"je +{rel:#x} -> jne (flip conditional)"
            gate = FlagGate(
                offset=i,
                original=b'\x74',
                patched=b'\x75',
                pattern_type="je_to_jne",
                description=desc,
                confidence=0.3,
            )
            gates.append(gate)
            i += 2
        elif data[i] == 0x75:  # jne short
            rel = struct.unpack_from("<b", data, i + 1)[0]
            desc = f"jne +{rel:#x} -> je (flip conditional)"
            gate = FlagGate(
                offset=i,
                original=b'\x75',
                patched=b'\x74',
                pattern_type="jne_to_je",
                description=desc,
                confidence=0.3,
            )
            gates.append(gate)
            i += 2
        else:
            i += 1
    return gates


def _scan_near_conditional_jump_gates(data: bytes) -> list[FlagGate]:
    """Scan for je/jne near jumps (0F 84 xx xx xx xx / 0F 85 xx xx xx xx)."""
    gates: list[FlagGate] = []
    i = 0
    while i < len(data) - 6:
        if data[i] == 0x0F and data[i + 1] == 0x84:  # je near
            rel = struct.unpack_from("<i", data, i + 2)[0]
            desc = f"je near +{rel:#x} -> jne (flip conditional)"
            gate = FlagGate(
                offset=i + 1,
                original=b'\x84',
                patched=b'\x85',
                pattern_type="je_near_to_jne",
                description=desc,
                confidence=0.3,
            )
            gates.append(gate)
            i += 6
        elif data[i] == 0x0F and data[i + 1] == 0x85:  # jne near
            rel = struct.unpack_from("<i", data, i + 2)[0]
            desc = f"jne near +{rel:#x} -> je (flip conditional)"
            gate = FlagGate(
                offset=i + 1,
                original=b'\x85',
                patched=b'\x84',
                pattern_type="jne_near_to_je",
                description=desc,
                confidence=0.3,
            )
            gates.append(gate)
            i += 6
        else:
            i += 1
    return gates


def _boost_gates_near_strings(data: bytes, gates: list[FlagGate]) -> None:
    """Boost confidence of gates near flag/success/print-related strings."""
    # Find offsets of interesting strings in the binary
    interesting_patterns = [
        rb"flag", rb"FLAG", rb"HTB{", rb"CTF{", rb"correct", rb"Correct",
        rb"success", rb"Success", rb"congrat", rb"Congrat", rb"print",
        rb"puts", rb"printf", rb"You win", rb"you win", rb"Well done",
        rb"right", rb"YES", rb"good",
    ]

    string_offsets: list[int] = []
    for pat in interesting_patterns:
        start = 0
        while True:
            idx = data.find(pat, start)
            if idx == -1:
                break
            string_offsets.append(idx)
            start = idx + 1

    if not string_offsets:
        return

    # Boost gates that are within 4KB of an interesting string
    PROXIMITY = 4096
    for gate in gates:
        for soff in string_offsets:
            if abs(gate.offset - soff) < PROXIMITY:
                gate.confidence = min(gate.confidence + 0.25, 1.0)
                break


def _boost_gates_near_test_cmp(data: bytes, gates: list[FlagGate]) -> None:
    """Boost conditional jump gates that are preceded by test/cmp instructions."""
    for gate in gates:
        if gate.pattern_type not in ("je_to_jne", "jne_to_je",
                                      "je_near_to_jne", "jne_near_to_je"):
            continue
        # Check bytes before the gate for test/cmp patterns
        start = max(0, gate.offset - 10)
        preceding = data[start:gate.offset]
        # test reg, reg: 85 C0 (test eax,eax), 84 C0 (test al,al)
        # cmp reg, 0:   83 F8 00 (cmp eax, 0), 80 F8 00 (cmp al, 0)
        # cmp byte [...], 0: 80 7D xx 00, 80 BD xx xx xx xx 00
        if (b'\x85\xc0' in preceding or b'\x84\xc0' in preceding
                or b'\x83\xf8\x00' in preceding or b'\x80\xf8\x00' in preceding
                or b'\x3c\x00' in preceding):  # cmp al, 0
            gate.confidence = min(gate.confidence + 0.15, 1.0)


def scan_flag_gates(binary_path: str) -> list[FlagGate]:
    """Scan a binary for all flag gate candidates.

    Returns gates sorted by confidence (highest first).
    """
    data = _read_binary(binary_path)

    # Only scan mov-byte gates (most promising for flag gates)
    # Conditional jump gates generate too many false positives to scan blindly
    gates: list[FlagGate] = []
    gates.extend(_scan_mov_byte_gates(data))
    gates.extend(_scan_mov_byte_short_gates(data))
    gates.extend(_scan_mov_dword_gates(data))

    # Boost confidence based on proximity to interesting strings
    _boost_gates_near_strings(data, gates)

    # Sort by confidence (descending), then by offset
    gates.sort(key=lambda g: (-g.confidence, g.offset))

    return gates


def scan_all_gates(binary_path: str) -> list[FlagGate]:
    """Scan including conditional jumps (used when --scan-jumps is set)."""
    data = _read_binary(binary_path)

    gates: list[FlagGate] = []
    gates.extend(_scan_mov_byte_gates(data))
    gates.extend(_scan_mov_byte_short_gates(data))
    gates.extend(_scan_mov_dword_gates(data))
    gates.extend(_scan_conditional_jump_gates(data))
    gates.extend(_scan_near_conditional_jump_gates(data))

    _boost_gates_near_strings(data, gates)
    _boost_gates_near_test_cmp(data, gates)

    gates.sort(key=lambda g: (-g.confidence, g.offset))
    return gates


# ---------------------------------------------------------------------------
# Patching
# ---------------------------------------------------------------------------

def patch_at_offset(binary_path: str, out_path: str,
                    offset: int, patch_bytes: bytes) -> str:
    """Apply a patch at a specific offset and return the output path."""
    shutil.copy2(binary_path, out_path)
    with open(out_path, "r+b") as f:
        f.seek(offset)
        f.write(patch_bytes)
    os.chmod(out_path, os.stat(out_path).st_mode | 0o111)
    return out_path


def nop_at_offset(binary_path: str, out_path: str,
                  offset: int, num_bytes: int) -> str:
    """NOP out bytes at a specific offset (legacy mode)."""
    return patch_at_offset(binary_path, out_path, offset, b'\x90' * num_bytes)


def apply_gates(binary_path: str, out_path: str,
                gates: list[FlagGate]) -> str:
    """Apply all gate patches to a copy of the binary."""
    shutil.copy2(binary_path, out_path)
    with open(out_path, "r+b") as f:
        for gate in gates:
            f.seek(gate.offset)
            f.write(gate.patched)
    os.chmod(out_path, os.stat(out_path).st_mode | 0o111)
    return out_path


# ---------------------------------------------------------------------------
# Run + extract
# ---------------------------------------------------------------------------

def _find_flags(text: str, flag_format: str) -> list[str]:
    """Find flag candidates in text."""
    flags: list[str] = []

    # Try specific flag format pattern
    if flag_format:
        try:
            for m in re.finditer(flag_format, text):
                flags.append(m.group(0))
        except re.error:
            pass
        # Try prefix-based pattern
        prefix_match = re.match(r"([A-Za-z0-9_]+)\{", flag_format.replace("\\", ""))
        if prefix_match:
            prefix = re.escape(prefix_match.group(0).rstrip("{"))
            pattern = prefix + r"\{[^}]{3,}\}"
            for m in re.finditer(pattern, text):
                if m.group(0) not in flags:
                    flags.append(m.group(0))

    # Generic flag pattern
    for m in re.finditer(DEFAULT_FLAG_PATTERN, text):
        candidate = m.group(0)
        if candidate not in flags:
            # Body diversity check
            body_m = re.search(r"\{(.+)\}", candidate)
            if body_m and len(set(body_m.group(1))) >= 2:
                flags.append(candidate)

    return flags


def run_and_extract(binary_path: str, flag_format: str,
                    timeout: int = SCAN_TIMEOUT) -> list[str]:
    """Run a binary and extract any flags from its output."""
    if not os.access(binary_path, os.X_OK):
        try:
            os.chmod(binary_path, os.stat(binary_path).st_mode | 0o111)
        except OSError:
            pass

    try:
        proc = subprocess.Popen(
            [binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )
        try:
            stdout, stderr = proc.communicate(input=b"\n", timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
            proc.kill()
            try:
                stdout, stderr = proc.communicate(timeout=2)
            except Exception:
                stdout, stderr = b"", b""

        combined = stdout.decode("utf-8", errors="replace") + "\n" + stderr.decode("utf-8", errors="replace")
        return _find_flags(combined, flag_format)

    except Exception as e:
        print(f"[-] Run failed: {e}")
        return []


# ---------------------------------------------------------------------------
# Auto mode: scan -> patch -> run -> extract
# ---------------------------------------------------------------------------

def auto_solve(binary_path: str, flag_format: str,
               max_attempts: int = 20, include_jumps: bool = False,
               run_timeout: int = AUTO_TIMEOUT) -> str | None:
    """Attempt automatic flag-gate patching.

    Scans for flag gates, tries patching the highest-confidence gates
    individually and in combination, runs each patched binary, and
    returns the first flag found.
    """
    if include_jumps:
        gates = scan_all_gates(binary_path)
    else:
        gates = scan_flag_gates(binary_path)

    if not gates:
        print("[-] No flag gate candidates found")
        return None

    # Filter to high-confidence gates
    high_conf = [g for g in gates if g.confidence >= 0.5]
    if not high_conf:
        high_conf = gates[:max_attempts]

    print(f"[*] Found {len(gates)} gate candidates, {len(high_conf)} high-confidence")

    attempts = 0

    with tempfile.TemporaryDirectory() as tmpdir:
        # Strategy 1: Try each high-confidence gate individually
        for gate in high_conf:
            if attempts >= max_attempts:
                break
            attempts += 1
            out_path = os.path.join(tmpdir, f"patched_{attempts}")
            print(f"[*] Attempt {attempts}: patching {gate}")
            try:
                patch_at_offset(binary_path, out_path, gate.offset, gate.patched)
                flags = run_and_extract(out_path, flag_format, timeout=run_timeout)
                if flags:
                    print(f"[+] Flag found with single gate patch!")
                    return flags[0]
            except Exception as e:
                print(f"[-] Attempt {attempts} failed: {e}")

        # Strategy 2: Try patching ALL mov-byte gates at once
        mov_gates = [g for g in gates if g.pattern_type.startswith("mov_")]
        if mov_gates and attempts < max_attempts:
            attempts += 1
            out_path = os.path.join(tmpdir, f"patched_all_mov")
            print(f"[*] Attempt {attempts}: patching ALL {len(mov_gates)} mov-byte gates")
            try:
                apply_gates(binary_path, out_path, mov_gates)
                flags = run_and_extract(out_path, flag_format, timeout=run_timeout)
                if flags:
                    print(f"[+] Flag found with all-gates patch!")
                    return flags[0]
            except Exception as e:
                print(f"[-] All-gates attempt failed: {e}")

        # Strategy 3: Try top gates with extended timeout (2x)
        extended = max(run_timeout * 2, EXTENDED_TIMEOUT)
        for gate in high_conf[:5]:
            if attempts >= max_attempts:
                break
            attempts += 1
            out_path = os.path.join(tmpdir, f"patched_long_{attempts}")
            print(f"[*] Attempt {attempts}: patching {gate} (extended timeout {extended}s)")
            try:
                patch_at_offset(binary_path, out_path, gate.offset, gate.patched)
                flags = run_and_extract(out_path, flag_format, timeout=extended)
                if flags:
                    print(f"[+] Flag found with extended run!")
                    return flags[0]
            except Exception as e:
                print(f"[-] Extended attempt failed: {e}")

    print(f"[-] No flag found after {attempts} patching attempts")
    return None


# ---------------------------------------------------------------------------
# Main CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Binary Flag-Gate Scanner & Patcher",
    )
    parser.add_argument("binary", help="Path to ELF binary")
    parser.add_argument("--scan", action="store_true",
                        help="Scan-only: report flag gate candidates")
    parser.add_argument("--scan-jumps", action="store_true",
                        help="Include conditional jump gates in scan (noisy)")
    parser.add_argument("--auto", action="store_true",
                        help="Auto-solve: scan + patch + run + extract flag")
    parser.add_argument("--offset", type=str, default=None,
                        help="Explicit file offset to patch (hex, e.g. 0x48bc)")
    parser.add_argument("--patch-value", type=str, default=None,
                        help="Hex byte(s) to write at offset (e.g. '01' or '9090')")
    parser.add_argument("--nop", action="store_true",
                        help="NOP out bytes (legacy mode, requires --bytes)")
    parser.add_argument("--bytes", type=int, default=1,
                        help="Number of bytes to NOP (with --nop, default: 1)")
    parser.add_argument("--out", default=None,
                        help="Output filename for patched binary")
    parser.add_argument("--flag-format", default="",
                        help="Expected flag format regex (e.g. 'HTB\\{.*\\}')")
    parser.add_argument("--run", action="store_true",
                        help="Run the patched binary after patching")
    parser.add_argument("--max-attempts", type=int, default=20,
                        help="Max patching attempts in --auto mode (default: 20)")
    parser.add_argument("--timeout", type=int, default=AUTO_TIMEOUT,
                        help=f"Seconds to wait per patched-binary run (default: {AUTO_TIMEOUT})")

    args = parser.parse_args()
    binary = os.path.abspath(args.binary)

    if not os.path.isfile(binary):
        print(f"[-] File not found: {binary}")
        sys.exit(1)

    if not _is_elf(binary):
        print(f"[-] Not an ELF binary: {binary}")
        sys.exit(1)

    print(f"[*] Binary: {binary}")

    # ── Scan mode ────────────────────────────────────────────────────
    if args.scan or args.scan_jumps:
        if args.scan_jumps:
            gates = scan_all_gates(binary)
        else:
            gates = scan_flag_gates(binary)

        if not gates:
            print("[-] No flag gate candidates found")
            sys.exit(1)

        print(f"\n[+] Found {len(gates)} flag gate candidate(s):\n")
        for i, gate in enumerate(gates[:50], 1):
            print(f"  {i:3d}. offset={gate.offset:#x}  conf={gate.confidence:.2f}"
                  f"  type={gate.pattern_type}")
            print(f"       {gate.description}")
            print(f"       orig={gate.original.hex()} -> patch={gate.patched.hex()}")
        if len(gates) > 50:
            print(f"  ... and {len(gates) - 50} more")
        return

    # ── Auto mode ────────────────────────────────────────────────────
    if args.auto:
        flag = auto_solve(binary, args.flag_format,
                          max_attempts=args.max_attempts,
                          include_jumps=args.scan_jumps,
                          run_timeout=args.timeout)
        if flag:
            print(f"\nEXTRACTED FLAG: {flag}")
        else:
            print("\n[-] Auto-solve failed: no flag extracted")
            sys.exit(1)
        return

    # ── Explicit offset mode ─────────────────────────────────────────
    if args.offset:
        try:
            offset = int(args.offset, 16)
        except ValueError:
            print(f"[-] Invalid offset: {args.offset}")
            sys.exit(1)

        out_path = args.out or os.path.join(
            os.path.dirname(binary),
            os.path.basename(binary) + "_patched",
        )

        if args.nop:
            print(f"[*] NOP-patching {args.bytes} bytes at offset {offset:#x}")
            nop_at_offset(binary, out_path, offset, args.bytes)
        elif args.patch_value:
            patch_bytes = bytes.fromhex(args.patch_value)
            print(f"[*] Patching {len(patch_bytes)} byte(s) at offset {offset:#x}"
                  f" with {args.patch_value}")
            patch_at_offset(binary, out_path, offset, patch_bytes)
        else:
            # Default: read current byte and flip 0x00<->0x01
            data = _read_binary(binary)
            if offset >= len(data):
                print(f"[-] Offset {offset:#x} beyond file size {len(data):#x}")
                sys.exit(1)
            current = data[offset]
            if current == 0x00:
                patch_bytes = b'\x01'
            elif current == 0x01:
                patch_bytes = b'\x00'
            else:
                print(f"[-] Byte at {offset:#x} is {current:#04x}, not 0x00 or 0x01."
                      " Use --patch-value to specify replacement.")
                sys.exit(1)
            print(f"[*] Flipping byte at {offset:#x}: {current:#04x} -> {patch_bytes[0]:#04x}")
            patch_at_offset(binary, out_path, offset, patch_bytes)

        print(f"[+] Patched binary written to: {out_path}")

        # Optionally run the patched binary
        if args.run:
            print(f"\n[*] Running patched binary (timeout={args.timeout}s)...")
            flags = run_and_extract(out_path, args.flag_format, timeout=args.timeout)
            if flags:
                print(f"\nEXTRACTED FLAG: {flags[0]}")
            else:
                print("[-] No flag found in patched binary output")
        return

    # ── No mode specified -- show usage ───────────────────────────────
    parser.print_help()
    print("\nExamples:")
    print("  python3 auto_patcher.py ./binary --scan")
    print("  python3 auto_patcher.py ./binary --auto --flag-format 'HTB\\{.*\\}'")
    print("  python3 auto_patcher.py ./binary --offset 0x48bc --run")
    sys.exit(1)


if __name__ == "__main__":
    main()
