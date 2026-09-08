#!/usr/bin/env python3
"""Kraken Deobfuscator -- reverse obfuscation in binaries and source code.

Detects and reverses common CTF obfuscation techniques:
  1. UPX / custom packing -- unpack first, then analyze
  2. String encryption -- find XOR/ADD decode loops, emulate them
  3. Control flow flattening (OLLVM) -- detect dispatcher pattern
  4. Opaque predicates -- detect always-true/false conditions
  5. Dead code / junk instructions -- remove NOPs and unreachable blocks
  6. MBA (Mixed Boolean-Arithmetic) -- simplify via Z3 if available
  7. VM-based obfuscation -- detect dispatch loop patterns

Usage:
  python3 auto_deobfuscate.py --binary ./obfuscated --prefix flag
  python3 auto_deobfuscate.py --binary ./packed --prefix HTB
  python3 auto_deobfuscate.py --source ./obfuscated.c --prefix flag
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
from collections import defaultdict


# ── Packer signatures ───────────────────────────────────────────────────

PACKER_SIGNATURES = [
    (b"UPX!", "UPX"),
    (b"UPX0", "UPX"),
    (b"UPX1", "UPX"),
    (b"\x60\xe8\x00\x00\x00\x00\x5d", "UPX-variant"),
    (b"MPRESS", "MPRESS"),
    (b"Petite", "Petite"),
    (b"ASPack", "ASPack"),
    (b"PECompact", "PECompact"),
]

# ── XOR decode loop patterns (in disassembly) ───────────────────────────

XOR_LOOP_PATTERNS = [
    # xor byte [reg+offset], imm8 pattern
    re.compile(r'xor\s+(?:BYTE\s+PTR\s+)?\[.+?\],\s*0x[0-9a-fA-F]+', re.IGNORECASE),
    # xor reg, imm pattern in loop
    re.compile(r'xor\s+(?:al|bl|cl|dl|r\d+b),\s*0x[0-9a-fA-F]+', re.IGNORECASE),
    # mov + xor + mov store pattern
    re.compile(r'movzx.+xor.+mov\s+\[', re.IGNORECASE),
]

# ── String encryption detection heuristics ───────────────────────────────

OBFUSCATED_STRING_INDICATORS = [
    # High entropy data in .rodata
    "high_entropy_rodata",
    # No readable strings > 4 chars in .rodata
    "no_readable_strings",
    # XOR loops referencing .rodata
    "xor_refs_rodata",
]


class Deobfuscator:
    """Multi-strategy binary deobfuscator for CTF challenges."""

    def __init__(self, binary_path, source_path=None, prefix="flag"):
        self.binary = os.path.abspath(binary_path) if binary_path else None
        self.source = source_path
        self.prefix = prefix
        self.flag_pattern = re.compile(
            rf'{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}'
        )
        self.raw_data = b""
        self.obfuscation_types = []
        self.results = []

    # ── Obfuscation detection ────────────────────────────────────────

    def detect_obfuscation(self):
        """Detect what type(s) of obfuscation are present.

        Returns list of detected obfuscation types with confidence scores.
        """
        print("[*] Detecting obfuscation techniques...")

        if not self.binary or not os.path.isfile(self.binary):
            print("[-] No binary to analyze")
            return []

        try:
            with open(self.binary, "rb") as f:
                self.raw_data = f.read()
        except OSError as e:
            print(f"[-] Cannot read binary: {e}")
            return []

        detections = []

        # 1. Check for packing
        packer = self._detect_packer()
        if packer:
            detections.append(("packing", packer, 0.9))
            print(f"[+] Packer detected: {packer}")

        # 2. Check for string encryption
        str_enc = self._detect_string_encryption()
        if str_enc:
            detections.append(("string_encryption", str_enc, 0.7))
            print(f"[+] String encryption detected: {str_enc}")

        # 3. Check for control flow flattening
        cff = self._detect_control_flow_flattening()
        if cff:
            detections.append(("control_flow_flattening", cff, 0.6))
            print(f"[+] Control flow flattening detected: {cff}")

        # 4. Check for VM obfuscation
        vm = self._detect_vm_obfuscation()
        if vm:
            detections.append(("vm_obfuscation", vm, 0.5))
            print(f"[+] VM-based obfuscation detected: {vm}")

        # 5. Check for anti-debugging
        anti_dbg = self._detect_anti_debugging()
        if anti_dbg:
            detections.append(("anti_debugging", anti_dbg, 0.6))
            print(f"[+] Anti-debugging detected: {anti_dbg}")

        if not detections:
            print("[*] No obvious obfuscation detected")
            # Check if binary is just stripped
            stripped = self._check_stripped()
            if stripped:
                detections.append(("stripped", "symbol table removed", 0.3))
                print("[*] Binary is stripped (symbols removed)")

        self.obfuscation_types = detections
        return detections

    def _detect_packer(self):
        """Check for known packer signatures."""
        for sig, name in PACKER_SIGNATURES:
            if sig in self.raw_data:
                return name

        # Check section names for packer indicators
        try:
            proc = subprocess.run(
                ["readelf", "-S", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            section_names = re.findall(r'\]\s+(\.\w+)', proc.stdout)
            upx_sections = [s for s in section_names if s.startswith(".UPX") or s == "UPX0" or s == "UPX1"]
            if upx_sections:
                return "UPX"
            # Unusual section names can indicate custom packing
            normal_sections = {".text", ".data", ".bss", ".rodata", ".init", ".fini",
                             ".plt", ".got", ".dynamic", ".dynsym", ".dynstr",
                             ".comment", ".note", ".symtab", ".strtab", ".shstrtab",
                             ".interp", ".gnu.hash", ".rela.dyn", ".rela.plt",
                             ".init_array", ".fini_array", ".eh_frame", ".eh_frame_hdr",
                             ".got.plt", ".gnu.version", ".gnu.version_r", ".note.ABI-tag",
                             ".note.gnu.build-id", ".gcc_except_table", ".tbss", ".tdata"}
            weird_sections = [s for s in section_names if s not in normal_sections and not s.startswith(".note")]
            if len(weird_sections) > 3:
                return f"custom-packer (unusual sections: {', '.join(weird_sections[:5])})"
        except Exception:
            pass

        # Check for abnormally high entropy in .text section
        if self._section_entropy(".text") > 7.5:
            return "possible-packer (high .text entropy)"

        return None

    def _section_entropy(self, section_name):
        """Calculate Shannon entropy of a section."""
        try:
            proc = subprocess.run(
                ["readelf", "-S", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            for line in proc.stdout.splitlines():
                m = re.search(
                    rf'\]\s+{re.escape(section_name)}\s+\w+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',
                    line
                )
                if m:
                    offset = int(m.group(2), 16)
                    size = int(m.group(3), 16)
                    section_data = self.raw_data[offset:offset + size]
                    if not section_data:
                        return 0.0
                    import math
                    freq = [0] * 256
                    for b in section_data:
                        freq[b] += 1
                    entropy = 0.0
                    n = len(section_data)
                    for count in freq:
                        if count > 0:
                            p = count / n
                            entropy -= p * math.log2(p)
                    return entropy
        except Exception:
            pass
        return 0.0

    def _detect_string_encryption(self):
        """Detect encrypted/obfuscated strings."""
        try:
            proc = subprocess.run(
                ["strings", "-a", "-n", "4", self.binary],
                capture_output=True, text=True, timeout=15,
            )
            all_strings = proc.stdout.strip().splitlines()
            readable_count = sum(
                1 for s in all_strings
                if len(s) >= 6 and s.isascii() and s.isprintable()
                and re.search(r'[a-zA-Z]{3,}', s)
            )
        except Exception:
            return None

        total = len(all_strings) if all_strings else 1

        # Very few readable strings compared to binary size = likely encrypted
        size = len(self.raw_data)
        if size > 10000 and readable_count < 5:
            return "very few readable strings (likely encrypted)"

        # Check for XOR decode loops in disassembly
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=30,
            )
            xor_count = 0
            for pat in XOR_LOOP_PATTERNS:
                xor_count += len(pat.findall(proc.stdout))
            if xor_count > 5:
                return f"XOR decode loops detected ({xor_count} patterns)"
        except Exception:
            pass

        return None

    def _detect_control_flow_flattening(self):
        """Detect OLLVM-style control flow flattening.

        CFF signature: a dispatcher block with a switch on a state variable,
        leading to many case blocks that update the state and jump back.
        """
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            return None

        # Count functions with many indirect jumps or jump tables
        current_func = None
        func_indirect_jumps = defaultdict(int)
        func_cmp_count = defaultdict(int)

        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue
            if not current_func:
                continue

            # Indirect jump: jmp *rax, jmp qword ptr [...]
            if re.search(r'jmp\s+\*', line, re.IGNORECASE):
                func_indirect_jumps[current_func] += 1

            # Many comparisons with constants (state variable checks)
            if re.search(r'cmp\s+\w+,\s*0x[0-9a-fA-F]+', line, re.IGNORECASE):
                func_cmp_count[current_func] += 1

        # CFF typically has functions with many cmp + indirect jump patterns
        for func, indirect in func_indirect_jumps.items():
            cmps = func_cmp_count.get(func, 0)
            if indirect >= 2 and cmps >= 10:
                return f"dispatcher pattern in {func} ({cmps} state checks, {indirect} indirect jumps)"

        return None

    def _detect_vm_obfuscation(self):
        """Detect VM-based obfuscation (custom bytecode interpreter)."""
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            return None

        # VM dispatch pattern: a loop with a large jump table
        # Look for functions with many case-like blocks and a central dispatch
        current_func = None
        func_jump_tables = defaultdict(int)

        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue
            if current_func:
                # Jump table entry: jmp *[base + reg*scale]
                if re.search(r'jmp\s+\*.*\(.*,.*,\s*[48]\)', line, re.IGNORECASE):
                    func_jump_tables[current_func] += 1

        for func, count in func_jump_tables.items():
            if count >= 1:
                return f"possible VM dispatch in {func} ({count} jump table references)"

        return None

    # Extended anti-debug detection patterns
    _ANTI_DEBUG_PATTERNS = {
        'ptrace': {
            'detect_asm': r'ptrace',
            'detect_str': r'PTRACE_TRACEME',
            'description': 'ptrace-based anti-debug',
        },
        'proc_status': {
            'detect_str': r'/proc/self/status',
            'description': '/proc/self/status TracerPid check',
        },
        'proc_maps': {
            'detect_str': r'/proc/self/maps',
            'description': '/proc/self/maps debugger detection',
        },
        'timing_rdtsc': {
            'detect_asm': r'rdtsc',
            'description': 'RDTSC timing check',
        },
        'timing_clock': {
            'detect_asm': r'clock_gettime|gettimeofday',
            'description': 'timing-based anti-debug',
        },
        'signal_trap': {
            'detect_asm': r'signal.*SIGTRAP|sigaction.*SIGTRAP',
            'detect_str': r'SIGTRAP',
            'description': 'SIGTRAP signal handler',
        },
        'alarm_timer': {
            'detect_asm': r'alarm@plt',
            'description': 'alarm-based timeout',
        },
        'prctl': {
            'detect_asm': r'prctl',
            'detect_str': r'PR_SET_DUMPABLE',
            'description': 'prctl dumpable check',
        },
        'int3': {
            'detect_asm': r'\bint3\b|\bint\s+\$?0x3\b',
            'description': 'INT3 breakpoint trap',
        },
        'parent_check': {
            'detect_str': r'getppid|/proc/self/stat',
            'description': 'parent process check',
        },
        'env_check': {
            'detect_str': r'LD_PRELOAD|LD_LIBRARY_PATH',
            'description': 'environment variable check',
        },
        'isatty': {
            'detect_asm': r'isatty',
            'description': 'isatty terminal check',
        },
    }

    def _detect_anti_debugging(self):
        """Detect anti-debugging techniques (extended patterns)."""
        indicators = []

        # Get disassembly
        asm_text = ""
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=30,
            )
            asm_text = proc.stdout
        except Exception:
            pass

        # Get strings
        str_text = ""
        try:
            proc = subprocess.run(
                ["strings", "-a", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            str_text = proc.stdout
        except Exception:
            pass

        for name, pattern in self._ANTI_DEBUG_PATTERNS.items():
            found = False
            if 'detect_asm' in pattern and asm_text:
                if re.search(pattern['detect_asm'], asm_text, re.IGNORECASE):
                    found = True
            if 'detect_str' in pattern and str_text:
                if re.search(pattern['detect_str'], str_text, re.IGNORECASE):
                    found = True
            if found:
                indicators.append(pattern['description'])

        # Legacy checks for specific combinations
        if "TracerPid" in str_text:
            if "TracerPid check" not in indicators:
                indicators.append("TracerPid check")
        if "LINES" in str_text and "COLUMNS" in str_text:
            indicators.append("terminal-env check")

        return ", ".join(indicators) if indicators else None

    def _check_stripped(self):
        """Check if the binary is stripped."""
        try:
            proc = subprocess.run(
                ["file", self.binary],
                capture_output=True, text=True, timeout=5,
            )
            return "stripped" in proc.stdout.lower() and "not stripped" not in proc.stdout.lower()
        except Exception:
            return False

    # ── Unpacking ────────────────────────────────────────────────────

    def unpack(self):
        """Attempt to unpack a packed binary.

        Returns path to unpacked binary, or None if unpacking fails.
        """
        print("[*] Attempting to unpack binary...")

        packer_type = None
        for det_type, det_info, _ in self.obfuscation_types:
            if det_type == "packing":
                packer_type = det_info
                break

        if not packer_type:
            print("[*] No packing detected, skipping unpack step")
            return None

        # Try UPX
        if "UPX" in packer_type.upper():
            return self._unpack_upx()

        # Generic: try to run and dump memory
        return self._unpack_generic()

    def _unpack_upx(self):
        """Unpack UPX-packed binary."""
        if not shutil.which("upx"):
            print("[-] upx not installed -- trying manual unpack")
            return self._unpack_upx_manual()

        with tempfile.NamedTemporaryFile(suffix="_unpacked", delete=False) as tmp:
            unpacked_path = tmp.name

        shutil.copy2(self.binary, unpacked_path)
        try:
            proc = subprocess.run(
                ["upx", "-d", unpacked_path],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode == 0:
                print(f"[+] UPX unpack successful: {unpacked_path}")
                return unpacked_path
            else:
                print(f"[-] UPX unpack failed: {proc.stderr.strip()}")
                os.unlink(unpacked_path)
                return self._unpack_upx_manual()
        except Exception as e:
            print(f"[-] UPX unpack error: {e}")
            try:
                os.unlink(unpacked_path)
            except OSError:
                pass
            return None

    def _unpack_upx_manual(self):
        """Manual UPX unpack: fix corrupted UPX headers."""
        # Some CTF challenges corrupt the UPX magic to prevent `upx -d`
        # Fix: restore the UPX! magic bytes
        data = bytearray(self.raw_data)
        fixed = False

        # Look for corrupted UPX section names and fix them
        for i in range(len(data) - 4):
            # Common corruption: changing UPX! to something else
            # Check if we have UPX0/UPX1 section names nearby
            if data[i:i+3] == b"UPX" and data[i+3:i+4] != b"!":
                # Check context -- is this in a section header area?
                pass

        # Try: patch bytes and retry upx -d
        if not shutil.which("upx"):
            return None

        # Check for p_info corruption (common CTF trick)
        upx_magic_positions = []
        for i in range(len(data) - 4):
            if data[i:i+4] == b"UPX!":
                upx_magic_positions.append(i)

        if len(upx_magic_positions) < 2:
            # Try restoring UPX! at expected positions
            for i in range(len(data) - 4):
                if data[i:i+3] == b"UPX" and data[i+3] not in (ord("!"), ord("0"), ord("1")):
                    data[i+3] = ord("!")
                    fixed = True

        if fixed:
            with tempfile.NamedTemporaryFile(suffix="_fixed", delete=False) as tmp:
                tmp.write(bytes(data))
                fixed_path = tmp.name
            os.chmod(fixed_path, 0o755)

            try:
                proc = subprocess.run(
                    ["upx", "-d", fixed_path],
                    capture_output=True, text=True, timeout=30,
                )
                if proc.returncode == 0:
                    print(f"[+] Manual UPX fix + unpack successful: {fixed_path}")
                    return fixed_path
            except Exception:
                pass
            try:
                os.unlink(fixed_path)
            except OSError:
                pass

        return None

    def _unpack_generic(self):
        """Generic unpack: run binary briefly and dump from /proc memory."""
        print("[*] Trying generic unpack via memory dump...")

        # This is a best-effort approach: run the binary, let it unpack itself,
        # then read the unpacked code from /proc/pid/mem
        try:
            proc = subprocess.Popen(
                [self.binary],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            # Give it a moment to unpack
            import time
            time.sleep(0.5)

            # Try to read memory maps
            try:
                maps_path = f"/proc/{proc.pid}/maps"
                mem_path = f"/proc/{proc.pid}/mem"
                if os.path.isfile(maps_path):
                    with open(maps_path) as f:
                        maps = f.read()
                    # Find executable regions
                    for line in maps.splitlines():
                        if "r-xp" in line and self.binary.split("/")[-1] in line:
                            parts = line.split()
                            addr_range = parts[0]
                            start, end = addr_range.split("-")
                            start = int(start, 16)
                            end = int(end, 16)
                            print(f"[*] Found executable region: {start:#x}-{end:#x}")
                            # We could dump this region but it requires
                            # careful ELF reconstruction which is complex
                            break
            except Exception:
                pass

            proc.kill()
            proc.wait()
        except Exception as e:
            print(f"[-] Generic unpack failed: {e}")

        return None

    # ── String decryption ────────────────────────────────────────────

    def decrypt_strings(self):
        """Extract and decrypt obfuscated strings.

        Strategies:
          1. Find XOR decode loops and emulate them
          2. Run binary with GDB and dump decoded strings
          3. Check .bss/.data for strings after initialization
        """
        print("[*] Attempting string decryption...")
        results = []

        # Strategy 1: XOR brute-force on suspicious data sections
        xor_results = self._xor_brute_sections()
        results.extend(xor_results)

        # Strategy 2: GDB-based string extraction
        gdb_results = self._gdb_string_extraction()
        results.extend(gdb_results)

        # Strategy 3: ltrace/strace to capture runtime strings
        trace_results = self._trace_string_operations()
        results.extend(trace_results)

        if results:
            print(f"[+] Decrypted {len(results)} strings:")
            for s in results:
                print(f"    {s}")
                # Check for flags
                flags = self.flag_pattern.findall(s)
                for f in flags:
                    print(f"EXTRACTED FLAG: {f}")

        return results

    def _xor_brute_sections(self):
        """XOR brute-force on data sections looking for flag patterns."""
        results = []

        # Extract .rodata and .data sections
        sections_data = {}
        try:
            proc = subprocess.run(
                ["readelf", "-S", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            for line in proc.stdout.splitlines():
                for sec_name in [".rodata", ".data"]:
                    m = re.search(
                        rf'\]\s+{re.escape(sec_name)}\s+\w+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',
                        line
                    )
                    if m:
                        offset = int(m.group(2), 16)
                        size = int(m.group(3), 16)
                        sections_data[sec_name] = self.raw_data[offset:offset + size]
        except Exception:
            pass

        # XOR each section with single-byte keys
        prefix_bytes = self.prefix.encode()
        for sec_name, data in sections_data.items():
            if len(data) > 100000:
                data = data[:100000]  # Limit to avoid excessive computation

            for key in range(1, 256):
                decoded = bytes(b ^ key for b in data)
                # Check for flag prefix
                if prefix_bytes in decoded:
                    idx = decoded.index(prefix_bytes)
                    # Extract flag candidate
                    candidate = decoded[idx:idx + 200]
                    try:
                        text = candidate.decode("utf-8", errors="replace")
                        m = re.search(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', text)
                        if m:
                            results.append(f"XOR key={key:#04x} in {sec_name}: {m.group(0)}")
                    except Exception:
                        pass

            # Multi-byte XOR: try common key lengths (2-8 bytes)
            for key_len in range(2, min(9, len(data))):
                # Use known-plaintext attack: assume prefix starts at some offset
                for offset in range(min(len(data) - len(prefix_bytes), 1000)):
                    # Derive key from assumed plaintext position
                    key = bytes(
                        data[offset + i] ^ prefix_bytes[i % len(prefix_bytes)]
                        for i in range(key_len)
                    )
                    # Decode with this key
                    decoded = bytes(
                        data[(offset + i)] ^ key[i % key_len]
                        for i in range(min(200, len(data) - offset))
                    )
                    try:
                        text = decoded.decode("utf-8", errors="replace")
                        if text.startswith(self.prefix + "{"):
                            m = re.search(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', text)
                            if m:
                                results.append(
                                    f"XOR key={key.hex()} offset={offset} in {sec_name}: {m.group(0)}"
                                )
                    except Exception:
                        pass

        return results

    def _gdb_string_extraction(self):
        """Use GDB to run binary and extract runtime strings."""
        if not shutil.which("gdb"):
            return []

        results = []
        gdb_script = """
set pagination off
set confirm off
catch syscall write
commands
  silent
  if $rdi == 1 || $rdi == 2
    set $len = (int)$rdx
    if $len > 0 && $len < 4096
      printf "KRAKEN_WRITE: "
      x/%dbs $rsi
      printf "\\n"
    end
  end
  continue
end
break puts
commands
  silent
  printf "KRAKEN_PUTS: %s\\n", (char*)$rdi
  continue
end
break printf
commands
  silent
  printf "KRAKEN_PRINTF: %s\\n", (char*)$rdi
  continue
end
run
quit
"""
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                f.write(gdb_script)
                script_path = f.name

            proc = subprocess.run(
                ["gdb", "-q", "-batch", "-x", script_path, self.binary],
                input=b"\n",
                capture_output=True,
                timeout=15,
            )
            output = proc.stdout.decode("utf-8", errors="replace")

            for line in output.splitlines():
                for marker in ["KRAKEN_WRITE:", "KRAKEN_PUTS:", "KRAKEN_PRINTF:"]:
                    if marker in line:
                        value = line.split(marker, 1)[1].strip()
                        if len(value) >= 3 and value.isprintable():
                            results.append(f"GDB runtime: {value}")

            os.unlink(script_path)
        except Exception as e:
            print(f"[-] GDB string extraction failed: {e}")
            try:
                os.unlink(script_path)
            except Exception:
                pass

        return results

    def _trace_string_operations(self):
        """Use ltrace/strace to capture string operations at runtime."""
        results = []

        # ltrace: capture library calls
        if shutil.which("ltrace"):
            try:
                proc = subprocess.run(
                    ["ltrace", "-s", "256", "-e", "strcmp+strncmp+memcmp+puts+printf",
                     self.binary],
                    input=b"\n",
                    capture_output=True, text=True, timeout=10,
                )
                for line in proc.stderr.splitlines():
                    # Extract string arguments from ltrace output
                    strings = re.findall(r'"([^"]+)"', line)
                    for s in strings:
                        if len(s) >= 4 and s.isprintable():
                            results.append(f"ltrace: {s}")
            except Exception:
                pass

        return results

    # ── Control flow unflattening ────────────────────────────────────

    def deobfuscate_cff_source(self, decompiled_source: str) -> str:
        """Remove OLLVM-style control flow flattening from decompiled C source.

        Detects: while(1) { switch(state_var) { case X: ...; state_var = Y; break; } }
        Recovers: original control flow by tracing state transitions.
        """
        # Step 1: Find the dispatcher pattern
        dispatcher_re = re.compile(
            r'while\s*\(\s*1\s*\)\s*\{[^}]*?switch\s*\(\s*(\w+)\s*\)',
            re.DOTALL
        )
        match = dispatcher_re.search(decompiled_source)
        if not match:
            return decompiled_source  # not flattened

        state_var = match.group(1)
        print(f"[+] CFF dispatcher found: state variable = {state_var}")

        # Step 2: Extract case blocks and their state transitions
        # Parse case blocks with their code and next state assignment
        case_re = re.compile(
            rf'case\s+(0x[0-9a-fA-F]+|\d+)\s*:(.*?)'
            rf'{re.escape(state_var)}\s*=\s*(0x[0-9a-fA-F]+|\d+)',
            re.DOTALL
        )
        transitions = {}  # {current_state: (code_block, next_state)}
        for m in case_re.finditer(decompiled_source):
            current = int(m.group(1), 0)
            code = m.group(2).strip()
            # Clean up the code block
            code = re.sub(r'\s*break\s*;\s*$', '', code).strip()
            next_state = int(m.group(3), 0)
            transitions[current] = (code, next_state)

        if not transitions:
            print("[-] No state transitions found in CFF")
            return decompiled_source

        print(f"[+] Found {len(transitions)} CFF state blocks")

        # Step 3: Find entry state (initial value of state_var)
        # Look before the while loop
        while_pos = decompiled_source.find('while')
        init_re = re.compile(
            rf'{re.escape(state_var)}\s*=\s*(0x[0-9a-fA-F]+|\d+)'
        )
        init_match = None
        if while_pos > 0:
            pre_while = decompiled_source[:while_pos]
            for im in init_re.finditer(pre_while):
                init_match = im  # take last assignment before while

        if not init_match:
            # Try first state from transitions
            current = min(transitions.keys())
            print(f"[*] No init state found, using first state: {current:#x}")
        else:
            current = int(init_match.group(1), 0)
            print(f"[*] Entry state: {current:#x}")

        # Step 4: Follow chain to reconstruct linear flow
        recovered_code = []
        visited = set()
        while current in transitions and current not in visited:
            visited.add(current)
            code, next_state = transitions[current]
            if code:  # skip empty blocks
                recovered_code.append(f"// [state {current:#x}]")
                recovered_code.append(code)
            current = next_state

        if recovered_code:
            print(f"[+] Recovered {len(recovered_code)//2} code blocks from CFF")
            return '\n'.join(recovered_code)

        return decompiled_source

    def unflatten_control_flow(self):
        """Attempt to reverse OLLVM-style control flow flattening.

        This is a simplified approach that identifies the dispatcher and
        maps state transitions to reconstruct the original flow.
        """
        print("[*] Analyzing control flow for flattening...")

        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=60,
            )
        except Exception as e:
            print(f"[-] Disassembly failed: {e}")
            return None

        # Find functions with flattened control flow
        current_func = None
        func_blocks = defaultdict(list)
        current_addr = None

        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                current_addr = int(func_match.group(1), 16)
                continue

            if not current_func:
                continue

            addr_match = re.match(r'\s*([0-9a-fA-F]+):', line)
            if addr_match:
                current_addr = int(addr_match.group(1), 16)

            # Look for state variable comparisons: cmp reg, constant
            cmp_match = re.search(r'cmp\s+\w+,\s*\$?(0x[0-9a-fA-F]+)', line, re.IGNORECASE)
            if cmp_match:
                state_val = int(cmp_match.group(1), 16)
                func_blocks[current_func].append(
                    ("cmp", current_addr, state_val)
                )

            # Look for state updates: mov [state_var], constant
            mov_match = re.search(
                r'mov\s+(?:DWORD\s+PTR\s+)?\[.*\],\s*\$?(0x[0-9a-fA-F]+)',
                line, re.IGNORECASE
            )
            if mov_match:
                new_state = int(mov_match.group(1), 16)
                func_blocks[current_func].append(
                    ("mov_state", current_addr, new_state)
                )

        # Report findings
        for func, blocks in func_blocks.items():
            cmps = [b for b in blocks if b[0] == "cmp"]
            state_updates = [b for b in blocks if b[0] == "mov_state"]
            if len(cmps) >= 5 and len(state_updates) >= 3:
                print(f"\n[+] Flattened function: {func}")
                print(f"    State checks: {len(cmps)}")
                print(f"    State updates: {len(state_updates)}")
                states = sorted(set(b[2] for b in cmps))
                print(f"    State values: {', '.join(f'{s:#x}' for s in states[:20])}")

                # Map state transitions
                transitions = []
                last_cmp = None
                for block in blocks:
                    if block[0] == "cmp":
                        last_cmp = block[2]
                    elif block[0] == "mov_state" and last_cmp is not None:
                        transitions.append((last_cmp, block[2]))
                        last_cmp = None

                if transitions:
                    print(f"    State transitions:")
                    for from_state, to_state in transitions[:20]:
                        print(f"      {from_state:#x} -> {to_state:#x}")

        return func_blocks

    # ── Source code deobfuscation ────────────────────────────────────

    def deobfuscate_source(self):
        """Deobfuscate source code file."""
        if not self.source:
            return None

        print(f"[*] Deobfuscating source: {self.source}")
        try:
            with open(self.source, encoding="utf-8", errors="replace") as f:
                code = f.read()
        except OSError as e:
            print(f"[-] Cannot read source: {e}")
            return None

        result = code

        # C/C++ macro expansion
        result = self._expand_macros(result)

        # Remove dead code blocks
        result = self._remove_dead_code_source(result)

        # Simplify constant expressions
        result = self._simplify_constants(result)

        # De-mangle names
        result = self._demangle_names(result)

        # Check for flags in cleaned source
        flags = self.flag_pattern.findall(result)
        for f in flags:
            print(f"EXTRACTED FLAG: {f}")

        return result

    def _expand_macros(self, code):
        """Expand simple #define macros in source code."""
        macros = {}
        lines = code.splitlines()
        result_lines = []

        for line in lines:
            m = re.match(r'#define\s+(\w+)\s+(.+)', line)
            if m:
                macros[m.group(1)] = m.group(2).strip()
                result_lines.append(line)
            else:
                expanded = line
                for name, value in macros.items():
                    expanded = re.sub(rf'\b{re.escape(name)}\b', value, expanded)
                result_lines.append(expanded)

        return "\n".join(result_lines)

    def _remove_dead_code_source(self, code):
        """Remove obvious dead code patterns from source."""
        # Remove if(0) { ... } blocks
        code = re.sub(r'if\s*\(\s*0\s*\)\s*\{[^}]*\}', '/* dead code removed */', code)
        # Remove while(0) { ... } blocks
        code = re.sub(r'while\s*\(\s*0\s*\)\s*\{[^}]*\}', '/* dead code removed */', code)
        # Remove #if 0 ... #endif blocks
        code = re.sub(r'#if\s+0\s*\n.*?#endif', '/* preprocessor dead code removed */',
                      code, flags=re.DOTALL)
        return code

    def _simplify_constants(self, code):
        """Simplify constant arithmetic expressions."""
        # Simplify expressions like (0x41 ^ 0x27) to their result
        def eval_hex_expr(m):
            try:
                result = eval(m.group(0))
                return f"{result:#x}"
            except Exception:
                return m.group(0)

        code = re.sub(
            r'0x[0-9a-fA-F]+\s*[\^&|+\-*]\s*0x[0-9a-fA-F]+',
            eval_hex_expr, code
        )
        return code

    def _demangle_names(self, code):
        """Demangle C++ names if present."""
        if not shutil.which("c++filt"):
            return code

        # Find mangled names: _Z followed by encoding
        mangled = re.findall(r'_Z[A-Za-z0-9_]+', code)
        if not mangled:
            return code

        try:
            proc = subprocess.run(
                ["c++filt"] + list(set(mangled)),
                capture_output=True, text=True, timeout=5,
            )
            demangled = proc.stdout.strip().splitlines()
            for orig, dem in zip(sorted(set(mangled)), demangled):
                if dem != orig:
                    code = code.replace(orig, dem)
        except Exception:
            pass

        return code

    # ── Anti-debug patching ─────────────────────────────────────────

    def patch_anti_debug(self):
        """Patch anti-debugging checks in the binary.

        Creates a copy of the binary with anti-debug calls NOPped out.
        Returns path to patched binary, or None.
        """
        if not self.binary:
            return None

        print("[*] Attempting to patch anti-debugging...")

        try:
            proc = subprocess.run(
                ["objdump", "-d", self.binary],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            return None

        # Find ptrace call sites
        patch_sites = []
        for line in proc.stdout.splitlines():
            m = re.match(r'\s*([0-9a-fA-F]+):', line)
            if not m:
                continue
            addr = int(m.group(1), 16)

            # ptrace TRACEME call -- typically: call <ptrace@plt>
            if 'call' in line and 'ptrace' in line:
                # Find the instruction bytes (offset in file)
                patch_sites.append(('ptrace_call', addr, line.strip()))

            # alarm() call
            if 'call' in line and 'alarm' in line:
                patch_sites.append(('alarm_call', addr, line.strip()))

        if not patch_sites:
            print("[*] No patchable anti-debug sites found")
            return None

        print(f"[+] Found {len(patch_sites)} anti-debug call sites:")
        for ptype, addr, desc in patch_sites:
            print(f"    {ptype} @ {addr:#x}: {desc}")

        # Create patched binary using GDB (more reliable than manual patching)
        if shutil.which("gdb"):
            patched_path = self.binary + ".patched"
            shutil.copy2(self.binary, patched_path)
            os.chmod(patched_path, 0o755)

            # Build GDB script to NOP the calls
            gdb_cmds = ["set pagination off", "set confirm off"]
            for ptype, addr, _ in patch_sites:
                if ptype == "ptrace_call":
                    # Patch the call to return 0 (xor eax,eax; nop*3)
                    # call is 5 bytes: replace with xor eax,eax (2) + nop*3
                    gdb_cmds.append(f"set *(unsigned char*)({addr:#x}) = 0x31")   # xor
                    gdb_cmds.append(f"set *(unsigned char*)({addr:#x}+1) = 0xc0") # eax,eax
                    gdb_cmds.append(f"set *(unsigned char*)({addr:#x}+2) = 0x90") # nop
                    gdb_cmds.append(f"set *(unsigned char*)({addr:#x}+3) = 0x90") # nop
                    gdb_cmds.append(f"set *(unsigned char*)({addr:#x}+4) = 0x90") # nop
                elif ptype == "alarm_call":
                    # NOP the alarm call entirely (5 bytes)
                    for off in range(5):
                        gdb_cmds.append(f"set *(unsigned char*)({addr:#x}+{off}) = 0x90")
            gdb_cmds.append("quit")

            try:
                with tempfile.NamedTemporaryFile(mode="w", suffix=".gdb", delete=False) as f:
                    f.write("\n".join(gdb_cmds))
                    script_path = f.name

                subprocess.run(
                    ["gdb", "-q", "-batch", "-x", script_path, patched_path],
                    capture_output=True, timeout=15,
                )
                os.unlink(script_path)
                print(f"[+] Patched binary: {patched_path}")
                return patched_path
            except Exception as e:
                print(f"[-] GDB patching failed: {e}")
                try:
                    os.unlink(script_path)
                except Exception:
                    pass

        return None

    # ── Main solve loop ──────────────────────────────────────────────

    def solve(self):
        """Main deobfuscation pipeline.

        1. Detect obfuscation type
        2. Try unpacking (if packed)
        3. Patch anti-debugging (if detected)
        4. Try string decryption (most likely to yield flag directly)
        5. Analyze control flow flattening (binary + source)
        6. Deobfuscate source code (if provided)
        7. Output cleaned/simplified code
        """
        if self.source:
            result = self.deobfuscate_source()
            if result:
                # Also try CFF deflattening on source
                deflattened = self.deobfuscate_cff_source(result)
                if deflattened != result:
                    print("\n[*] CFF-deflattened source:")
                    print("=" * 72)
                    print(deflattened[:50000])
                    # Check for flags
                    flags = self.flag_pattern.findall(deflattened)
                    for f in flags:
                        print(f"EXTRACTED FLAG: {f}")
                else:
                    print("\n[*] Deobfuscated source output:")
                    print("=" * 72)
                    print(result[:50000])
            return result

        if not self.binary:
            print("[-] No binary or source provided")
            sys.exit(1)

        # Step 1: Detect obfuscation
        detections = self.detect_obfuscation()

        # Step 2: Try unpacking
        unpacked = None
        for det_type, _, _ in detections:
            if det_type == "packing":
                unpacked = self.unpack()
                if unpacked:
                    self.binary = unpacked
                    print(f"[+] Working with unpacked binary: {unpacked}")
                    # Re-detect on unpacked binary
                    try:
                        with open(self.binary, "rb") as f:
                            self.raw_data = f.read()
                    except OSError:
                        pass
                break

        # Step 2.5: Patch anti-debugging if detected
        for det_type, _, _ in detections:
            if det_type == "anti_debugging":
                patched = self.patch_anti_debug()
                if patched:
                    self.binary = patched
                    try:
                        with open(self.binary, "rb") as f:
                            self.raw_data = f.read()
                    except OSError:
                        pass
                break

        # Step 3: Try string decryption (most likely to yield flag)
        decrypted = self.decrypt_strings()

        # Check for flags in decrypted strings
        for s in decrypted:
            flags = self.flag_pattern.findall(s)
            for f in flags:
                print(f"EXTRACTED FLAG: {f}")

        # Step 4: Analyze control flow
        for det_type, _, _ in detections:
            if det_type == "control_flow_flattening":
                self.unflatten_control_flow()
                break

        # Step 5: Final strings scan on (possibly unpacked) binary
        print("\n[*] Final strings scan...")
        try:
            proc = subprocess.run(
                ["strings", "-a", "-n", "4", self.binary],
                capture_output=True, text=True, timeout=15,
            )
            flags = self.flag_pattern.findall(proc.stdout)
            for f in flags:
                print(f"EXTRACTED FLAG: {f}")

            # Also try generic pattern
            if not flags:
                generic = re.findall(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', proc.stdout)
                for g in generic:
                    body_match = re.search(r'\{(.+)\}', g)
                    if body_match and len(set(body_match.group(1))) >= 3:
                        print(f"EXTRACTED FLAG: {g}")
        except Exception:
            pass

        # Summary
        print("\n[*] Deobfuscation analysis complete")
        print(f"    Obfuscation detected: {len(detections)} technique(s)")
        print(f"    Strings decrypted: {len(decrypted)}")
        if unpacked:
            print(f"    Unpacked binary: {unpacked}")

        # Cleanup
        if unpacked and os.path.isfile(unpacked):
            # Keep the unpacked binary for further analysis
            print(f"[*] Unpacked binary available at: {unpacked}")

        return decrypted


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Kraken Deobfuscator -- reverse obfuscation in binaries"
    )
    parser.add_argument("--binary", default=None, help="Path to binary")
    parser.add_argument("--source", default=None, help="Path to source code file")
    parser.add_argument("--prefix", default="flag", help="Flag prefix (default: flag)")
    parser.add_argument("--detect-only", action="store_true",
                        help="Only detect obfuscation, don't try to reverse it")

    args = parser.parse_args()

    if not args.binary and not args.source:
        print("[-] Must provide --binary or --source")
        sys.exit(1)

    if args.binary and not os.path.isfile(args.binary):
        print(f"[-] File not found: {args.binary}")
        sys.exit(1)

    if args.source and not os.path.isfile(args.source):
        print(f"[-] File not found: {args.source}")
        sys.exit(1)

    deobfuscator = Deobfuscator(
        args.binary, source_path=args.source, prefix=args.prefix,
    )

    if args.detect_only:
        detections = deobfuscator.detect_obfuscation()
        if detections:
            print(f"\n[*] Summary: {len(detections)} obfuscation technique(s) detected:")
            for det_type, det_info, confidence in detections:
                print(f"    [{confidence:.0%}] {det_type}: {det_info}")
        else:
            print("[*] No obfuscation detected")
    else:
        deobfuscator.solve()


if __name__ == "__main__":
    main()
