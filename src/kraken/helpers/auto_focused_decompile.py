#!/usr/bin/env python3
"""Kraken Focused Decompile -- smart function triage for large binaries.

Instead of decompiling every function in a 1MB+ binary (which can take
minutes with Ghidra and produce tens of thousands of lines of noise),
this tool triages functions by "interestingness" and only decompiles
the top N most promising candidates.

Scoring heuristics:
  +10  references flag-like / success / password strings
  +8   calls crypto functions (AES, SHA, MD5, RC4, etc.)
  +5   calls comparison functions (strcmp, memcmp, bcmp)
  +5   has XOR operations (common in CTF crypto/obfuscation)
  +4   takes user input (scanf, fgets, read, recv)
  +3   complex control flow (many conditional branches)
  +3   called from main() chain (within 3 hops)
  -5   known library / compiler function (deregister_tm_clones, etc.)

Usage:
  python3 auto_focused_decompile.py --binary ./large_binary --max-functions 30 --prefix flag
  python3 auto_focused_decompile.py --binary ./challenge --ghidra /opt/ghidra
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


# ── Scoring constants ───────────────────────────────────────────────────

# Strings that suggest a function is "interesting" for CTF purposes
INTERESTING_STRINGS = [
    b"flag", b"FLAG", b"correct", b"Correct", b"CORRECT",
    b"success", b"Success", b"password", b"Password",
    b"wrong", b"Wrong", b"WRONG", b"incorrect", b"Incorrect",
    b"congratul", b"Congratul", b"You win", b"you win",
    b"Well done", b"Access granted", b"access granted",
    b"secret", b"Secret", b"key{", b"KEY{", b"CTF{", b"HTB{",
    b"picoCTF{", b"vere{", b"VERE{",
]

# Crypto-related imported function names
CRYPTO_FUNCTIONS = {
    "AES_encrypt", "AES_decrypt", "AES_set_encrypt_key", "AES_set_decrypt_key",
    "SHA1", "SHA256", "SHA256_Init", "SHA256_Update", "SHA256_Final",
    "MD5", "MD5_Init", "MD5_Update", "MD5_Final",
    "EVP_EncryptInit", "EVP_DecryptInit", "EVP_CipherInit",
    "EVP_EncryptUpdate", "EVP_DecryptUpdate",
    "EVP_DigestInit", "EVP_DigestUpdate", "EVP_DigestFinal",
    "RC4", "RC4_set_key", "DES_ecb_encrypt", "DES_set_key",
    "BF_encrypt", "BF_decrypt", "BF_set_key",
    "RAND_bytes", "RAND_pseudo_bytes",
    "RSA_public_encrypt", "RSA_private_decrypt",
}

# Comparison functions
COMPARISON_FUNCTIONS = {
    "strcmp", "strncmp", "memcmp", "bcmp", "strcasecmp", "strncasecmp",
    "wmemcmp", "wcscmp",
}

# Input functions
INPUT_FUNCTIONS = {
    "scanf", "fscanf", "sscanf", "__isoc99_scanf",
    "fgets", "gets", "getline", "getchar", "fgetc", "fread",
    "read", "recv", "recvfrom", "recvmsg",
}

# Known library / compiler boilerplate functions to de-prioritize
LIBRARY_FUNCTIONS = {
    "deregister_tm_clones", "register_tm_clones",
    "__do_global_dtors_aux", "frame_dummy",
    "_start", "__libc_csu_init", "__libc_csu_fini", "__libc_start_main",
    "_init", "_fini", "_dl_relocate_static_pie",
    "__cxa_finalize", "__cxa_atexit", "__stack_chk_fail",
    "__gmon_start__", "__x86.get_pc_thunk.ax", "__x86.get_pc_thunk.bx",
    "_ITM_deregisterTMCloneTable", "_ITM_registerTMCloneTable",
}


class FocusedDecompiler:
    """Smart decompilation: triage functions, decompile only the interesting ones."""

    def __init__(self, binary_path, prefix="flag", max_functions=20, ghidra_path=None):
        self.binary = os.path.abspath(binary_path)
        self.prefix = prefix
        self.max_functions = max_functions
        self.ghidra = ghidra_path or self._find_ghidra()
        self.flag_pattern = re.compile(
            rf'{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}'
        )

        # Populated during analysis
        self.functions = {}        # name -> {addr, size, section}
        self.call_graph = defaultdict(set)    # caller -> {callees}
        self.reverse_graph = defaultdict(set)  # callee -> {callers}
        self.string_refs = defaultdict(list)   # func_name -> [string_bytes]
        self.import_calls = defaultdict(set)   # func_name -> {imported_func_names}
        self.raw_data = b""

    def _find_ghidra(self):
        """Find Ghidra installation."""
        env_dir = os.environ.get("GHIDRA_INSTALL_DIR", "")
        if env_dir and os.path.isdir(env_dir):
            return env_dir
        for path in [
            "/opt/ghidra",
            "/opt/ghidra_12.0.3_PUBLIC",
            "/opt/ghidra",
            "/usr/local/ghidra",
        ]:
            if os.path.isdir(path):
                return path
        # Glob search
        for parent in ["/opt", "/opt", "/usr/local"]:
            if not os.path.isdir(parent):
                continue
            for entry in sorted(os.listdir(parent), reverse=True):
                if entry.startswith("ghidra") and os.path.isdir(os.path.join(parent, entry)):
                    return os.path.join(parent, entry)
        return None

    # ── Binary info ──────────────────────────────────────────────────

    def get_binary_info(self):
        """Get basic binary info: size, architecture, sections, function count."""
        info = {}
        try:
            info["size"] = os.path.getsize(self.binary)
        except OSError:
            info["size"] = 0

        # file command
        try:
            proc = subprocess.run(
                ["file", self.binary], capture_output=True, text=True, timeout=10
            )
            info["type"] = proc.stdout.strip()
        except Exception:
            info["type"] = "unknown"

        # Read raw binary data
        try:
            with open(self.binary, "rb") as f:
                self.raw_data = f.read()
        except OSError:
            self.raw_data = b""

        return info

    # ── String extraction with cross-references ──────────────────────

    def extract_strings_with_refs(self):
        """Extract interesting strings and map them to referencing functions.

        Uses `strings` for extraction and `objdump -d` to find which functions
        reference them via their addresses.
        """
        print("[*] Extracting strings and cross-references...")

        # Step 1: Find all strings with offsets using strings -t d
        string_map = {}  # offset -> string_bytes
        try:
            proc = subprocess.run(
                ["strings", "-a", "-t", "d", "-n", "4", self.binary],
                capture_output=True, text=True, timeout=30,
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    try:
                        offset = int(parts[0])
                        string_val = parts[1]
                        string_map[offset] = string_val.encode("utf-8", errors="replace")
                    except ValueError:
                        pass
        except Exception as e:
            print(f"[-] strings extraction failed: {e}")
            return {}

        # Filter to interesting strings only
        interesting = {}
        for offset, s in string_map.items():
            s_lower = s.lower()
            for marker in INTERESTING_STRINGS:
                if marker.lower() in s_lower:
                    interesting[offset] = s
                    break

        if not interesting:
            print("[*] No interesting strings found in binary")
            return {}

        print(f"[*] Found {len(interesting)} interesting strings")

        # Step 2: Map string references to functions using readelf + objdump
        # Get section headers to translate file offsets to virtual addresses
        vaddr_map = self._file_offset_to_vaddr(interesting)

        # Step 3: Search disassembly for references to these addresses
        self._map_string_refs_via_disasm(vaddr_map)

        return interesting

    def _file_offset_to_vaddr(self, string_offsets):
        """Convert file offsets of strings to virtual addresses using section info."""
        vaddr_map = {}  # vaddr -> string_bytes

        # Parse section headers with readelf
        sections = []
        try:
            proc = subprocess.run(
                ["readelf", "-S", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            for line in proc.stdout.splitlines():
                # Parse section entries: look for .rodata, .data, etc.
                m = re.search(
                    r'\[\s*\d+\]\s+(\.\w+)\s+\w+\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)\s+([0-9a-fA-F]+)',
                    line
                )
                if m:
                    name = m.group(1)
                    vaddr = int(m.group(2), 16)
                    file_off = int(m.group(3), 16)
                    size = int(m.group(4), 16)
                    sections.append((name, vaddr, file_off, size))
        except Exception:
            pass

        if not sections:
            # Fallback: assume 1:1 mapping (non-PIE or stripped)
            for off, s in string_offsets.items():
                vaddr_map[off] = s
            return vaddr_map

        for off, s in string_offsets.items():
            for name, vaddr, file_off, size in sections:
                if file_off <= off < file_off + size:
                    va = vaddr + (off - file_off)
                    vaddr_map[va] = s
                    break

        return vaddr_map

    def _map_string_refs_via_disasm(self, vaddr_map):
        """Search disassembly for instructions that reference string addresses."""
        if not vaddr_map:
            return

        # Build a set of hex address patterns to search for
        addr_patterns = {}
        for va in vaddr_map:
            # Format as both full hex and lea/mov patterns
            addr_hex = f"{va:#x}"
            addr_patterns[addr_hex] = va

        # Partial disassembly -- only get text section
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            return

        current_func = None
        for line in proc.stdout.splitlines():
            # Function header: 0000000000401000 <main>:
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue

            if not current_func:
                continue

            # Check if this instruction references any interesting address
            for addr_hex, va in addr_patterns.items():
                if addr_hex in line:
                    self.string_refs[current_func].append(vaddr_map[va])
                    break

    # ── Function extraction ──────────────────────────────────────────

    def extract_functions(self):
        """Extract function list with addresses and sizes."""
        print("[*] Extracting functions...")

        # Try nm first (works for non-stripped binaries)
        try:
            proc = subprocess.run(
                ["nm", "-S", "--defined-only", self.binary],
                capture_output=True, text=True, timeout=15,
            )
            for line in proc.stdout.splitlines():
                # Format: addr size type name
                parts = line.strip().split()
                if len(parts) >= 4 and parts[2].lower() in ("t", "T"):
                    addr = int(parts[0], 16)
                    size = int(parts[1], 16) if len(parts[1]) > 1 else 0
                    name = parts[3]
                    self.functions[name] = {"addr": addr, "size": size}
        except Exception:
            pass

        # Fallback: extract from objdump
        if not self.functions:
            try:
                proc = subprocess.run(
                    ["objdump", "-t", self.binary],
                    capture_output=True, text=True, timeout=15,
                )
                for line in proc.stdout.splitlines():
                    # Format: addr flags section alignment name
                    m = re.match(
                        r'^([0-9a-fA-F]+)\s+.*\s+\.text\s+([0-9a-fA-F]+)\s+(\S+)',
                        line
                    )
                    if m:
                        addr = int(m.group(1), 16)
                        size = int(m.group(2), 16)
                        name = m.group(3)
                        self.functions[name] = {"addr": addr, "size": size}
            except Exception:
                pass

        # Also detect functions from disassembly headers (for stripped binaries)
        if not self.functions or len(self.functions) < 5:
            try:
                proc = subprocess.run(
                    ["objdump", "-d", "--no-show-raw-insn", self.binary],
                    capture_output=True, text=True, timeout=60,
                )
                for line in proc.stdout.splitlines():
                    m = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
                    if m:
                        addr = int(m.group(1), 16)
                        name = m.group(2)
                        if name not in self.functions:
                            self.functions[name] = {"addr": addr, "size": 0}
            except Exception:
                pass

        print(f"[*] Found {len(self.functions)} functions")
        return self.functions

    # ── Call graph ───────────────────────────────────────────────────

    def build_call_graph(self):
        """Build call graph from disassembly: caller -> callees."""
        print("[*] Building call graph...")
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=60,
            )
        except Exception as e:
            print(f"[-] Failed to build call graph: {e}")
            return

        current_func = None
        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue

            if not current_func:
                continue

            # Look for call instructions: call <addr> <name>
            call_match = re.search(r'\bcall\s+[0-9a-fA-F]+\s+<([^>]+)>', line)
            if call_match:
                callee = call_match.group(1)
                # Strip @plt suffix for import tracking
                callee_base = callee.replace("@plt", "")
                self.call_graph[current_func].add(callee)
                self.reverse_graph[callee].add(current_func)

                # Track imported function calls
                if callee.endswith("@plt") or callee_base in CRYPTO_FUNCTIONS | COMPARISON_FUNCTIONS | INPUT_FUNCTIONS:
                    self.import_calls[current_func].add(callee_base)

        print(f"[*] Call graph: {len(self.call_graph)} callers, "
              f"{sum(len(v) for v in self.call_graph.values())} edges")

    # ── Main chain detection ─────────────────────────────────────────

    def _find_main_chain(self, max_depth=3):
        """Find functions reachable from main() within max_depth hops."""
        main_chain = set()
        if "main" not in self.call_graph:
            return main_chain

        frontier = {"main"}
        for _ in range(max_depth):
            next_frontier = set()
            for func in frontier:
                main_chain.add(func)
                for callee in self.call_graph.get(func, set()):
                    clean = callee.replace("@plt", "")
                    if clean not in main_chain:
                        next_frontier.add(clean)
            frontier = next_frontier

        return main_chain

    # ── XOR instruction detection ────────────────────────────────────

    def _detect_xor_functions(self):
        """Find functions that contain XOR operations (common in CTF crypto)."""
        xor_funcs = set()
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            return xor_funcs

        current_func = None
        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue
            if current_func and re.search(r'\bxor\b', line, re.IGNORECASE):
                # Skip xor reg, reg (register zeroing idiom)
                parts = line.split()
                if len(parts) >= 2:
                    operands = parts[-1] if "," in parts[-1] else ""
                    ops = [o.strip() for o in operands.split(",")]
                    if len(ops) == 2 and ops[0] == ops[1]:
                        continue  # xor eax, eax -- just zeroing
                xor_funcs.add(current_func)

        return xor_funcs

    # ── Branch complexity detection ──────────────────────────────────

    def _count_branches(self):
        """Count conditional branch instructions per function."""
        branch_counts = defaultdict(int)
        branch_mnemonics = {"je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                           "ja", "jae", "jb", "jbe", "jnb", "jna",
                           "js", "jns", "jo", "jno", "jp", "jnp"}
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            return branch_counts

        current_func = None
        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                continue
            if current_func:
                parts = line.strip().split()
                if len(parts) >= 2:
                    mnemonic = parts[1] if parts[0].endswith(":") else parts[0]
                    if mnemonic in branch_mnemonics:
                        branch_counts[current_func] += 1

        return branch_counts

    # ── Function ranking ─────────────────────────────────────────────

    def rank_functions(self):
        """Rank all functions by interestingness score.

        Returns list of (name, score, reasons) sorted by score descending.
        """
        print("[*] Ranking functions by interestingness...")

        main_chain = self._find_main_chain()
        xor_funcs = self._detect_xor_functions()
        branch_counts = self._count_branches()

        ranked = []
        for name in self.functions:
            score = 0
            reasons = []

            # String references
            if name in self.string_refs:
                for s in self.string_refs[name]:
                    s_lower = s.lower()
                    if any(m.lower() in s_lower for m in
                           [b"flag", b"correct", b"password", b"secret", b"key{",
                            b"congrat", b"you win", b"access granted"]):
                        score += 10
                        reasons.append(f"refs interesting string: {s[:40]}")
                        break

            # Crypto function calls
            crypto_calls = self.import_calls.get(name, set()) & CRYPTO_FUNCTIONS
            if crypto_calls:
                score += 8
                reasons.append(f"calls crypto: {', '.join(list(crypto_calls)[:3])}")

            # Comparison function calls
            cmp_calls = self.import_calls.get(name, set()) & COMPARISON_FUNCTIONS
            if cmp_calls:
                score += 5
                reasons.append(f"calls comparison: {', '.join(cmp_calls)}")

            # XOR operations
            if name in xor_funcs:
                score += 5
                reasons.append("uses XOR (crypto/obfuscation)")

            # Input function calls
            input_calls = self.import_calls.get(name, set()) & INPUT_FUNCTIONS
            if input_calls:
                score += 4
                reasons.append(f"reads input: {', '.join(input_calls)}")

            # Complex control flow
            branches = branch_counts.get(name, 0)
            if branches >= 10:
                score += 3
                reasons.append(f"complex control flow ({branches} branches)")

            # Main chain proximity
            if name in main_chain:
                score += 3
                reasons.append("in main() call chain")

            # Penalty: known library function
            clean_name = name.replace("@plt", "")
            if clean_name in LIBRARY_FUNCTIONS:
                score -= 5
                reasons.append("library/compiler function (deprioritized)")

            # Penalty: PLT stubs are just trampolines
            if name.endswith("@plt"):
                score -= 10
                reasons.append("PLT stub (skip)")

            # Small bonus for "main" itself
            if name == "main":
                score += 2
                reasons.append("entry point")

            # Bonus: has callers AND callees (non-leaf, non-root)
            if name in self.call_graph and name in self.reverse_graph:
                score += 1
                reasons.append("intermediate function")

            ranked.append((name, score, reasons))

        ranked.sort(key=lambda x: -x[1])
        return ranked

    # ── Ghidra selective decompilation ───────────────────────────────

    def decompile_with_ghidra(self, function_addrs):
        """Decompile specific functions using Ghidra headless mode.

        Generates a temporary Ghidra script that decompiles only the
        specified function addresses, then runs it headless.
        """
        if not self.ghidra:
            print("[-] Ghidra not found -- cannot decompile")
            return None

        headless = os.path.join(self.ghidra, "support", "analyzeHeadless")
        if not os.path.isfile(headless):
            print(f"[-] analyzeHeadless not found at {headless}")
            return None

        print(f"[*] Decompiling {len(function_addrs)} functions with Ghidra...")

        with tempfile.TemporaryDirectory(prefix="kraken_focused_") as tmpdir:
            # Build address list for the script
            addr_list = ",".join(f"0x{a:x}" for a in function_addrs)

            # Write Ghidra script that decompiles only specified addresses
            script_path = os.path.join(tmpdir, "FocusedDecompile.java")
            output_path = os.path.join(tmpdir, "decompiled.txt")

            with open(script_path, "w") as f:
                f.write(self._ghidra_script(addr_list, output_path))

            # JAVA_HOME for Ghidra
            env = os.environ.copy()
            java_home = env.get("JAVA_HOME", "/usr/lib/jvm/java-21")
            if os.path.isdir(java_home):
                env["JAVA_HOME"] = java_home
                env["PATH"] = f"{java_home}/bin:{env.get('PATH', '')}"

            proj_dir = os.path.join(tmpdir, "proj")
            os.makedirs(proj_dir)

            cmd = [
                headless, proj_dir, "kraken_focused",
                "-import", self.binary,
                "-postScript", "FocusedDecompile.java",
                "-scriptPath", tmpdir,
                "-deleteProject",
            ]

            try:
                proc = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=300, env=env,
                )
            except subprocess.TimeoutExpired:
                print("[-] Ghidra timed out (300s)")
                return None
            except FileNotFoundError:
                print(f"[-] Cannot execute {headless}")
                return None

            if os.path.isfile(output_path):
                with open(output_path) as f:
                    return f.read()
            else:
                # Try extracting from stdout
                return proc.stdout if proc.stdout else None

    def _ghidra_script(self, addr_csv, output_path):
        """Generate a Ghidra Java script for focused decompilation."""
        # Escape backslashes in path for Java string literal
        escaped_output = output_path.replace("\\", "\\\\")
        return f"""//Focused Decompile Script for Kraken
//@category Analysis
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import java.io.*;

public class FocusedDecompile extends GhidraScript {{
    @Override
    public void run() throws Exception {{
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String[] addrs = "{addr_csv}".split(",");
        StringBuilder sb = new StringBuilder();
        FunctionManager fm = currentProgram.getFunctionManager();

        // First decompile functions at specified addresses
        for (String addrStr : addrs) {{
            addrStr = addrStr.trim();
            if (addrStr.isEmpty()) continue;
            try {{
                Address addr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(addrStr);
                Function func = fm.getFunctionContaining(addr);
                if (func == null) {{
                    func = fm.getFunctionAt(addr);
                }}
                if (func != null) {{
                    DecompileResults result = decomp.decompileFunction(func, 60, monitor);
                    if (result.decompileCompleted()) {{
                        sb.append("// === Function: " + func.getName()
                            + " @ " + func.getEntryPoint() + " ===\\n");
                        sb.append(result.getDecompiledFunction().getC());
                        sb.append("\\n\\n");
                    }}
                }}
            }} catch (Exception e) {{
                sb.append("// Failed to decompile at " + addrStr + ": " + e.getMessage() + "\\n");
            }}
        }}

        // If no specific addresses found functions, decompile ALL functions
        // but limit to first 50
        if (sb.length() < 100) {{
            int count = 0;
            FunctionIterator iter = fm.getFunctions(true);
            while (iter.hasNext() && count < 50) {{
                Function func = iter.next();
                if (func.isThunk()) continue;
                try {{
                    DecompileResults result = decomp.decompileFunction(func, 30, monitor);
                    if (result.decompileCompleted()) {{
                        sb.append("// === Function: " + func.getName()
                            + " @ " + func.getEntryPoint() + " ===\\n");
                        sb.append(result.getDecompiledFunction().getC());
                        sb.append("\\n\\n");
                        count++;
                    }}
                }} catch (Exception e) {{
                    // skip
                }}
            }}
        }}

        // Write output
        PrintWriter pw = new PrintWriter(new File("{escaped_output}"));
        pw.write(sb.toString());
        pw.close();

        decomp.dispose();
    }}
}}
"""

    # ── Objdump fallback decompilation ───────────────────────────────

    def decompile_with_objdump(self, function_names):
        """Fallback: extract disassembly for specific functions using objdump.

        When Ghidra is not available, objdump gives us the raw assembly
        which is still useful for pattern analysis.
        """
        print(f"[*] Extracting disassembly for {len(function_names)} functions (objdump fallback)...")

        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=60,
            )
        except Exception as e:
            print(f"[-] objdump failed: {e}")
            return None

        # Extract sections for target functions
        result_parts = []
        current_func = None
        current_lines = []
        target_set = set(function_names)

        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                # Save previous function if it was a target
                if current_func and current_func in target_set:
                    result_parts.append(f"// === Function: {current_func} ===")
                    result_parts.extend(current_lines)
                    result_parts.append("")
                current_func = func_match.group(2)
                current_lines = [line]
            elif current_func:
                current_lines.append(line)

        # Don't forget last function
        if current_func and current_func in target_set:
            result_parts.append(f"// === Function: {current_func} ===")
            result_parts.extend(current_lines)

        return "\n".join(result_parts) if result_parts else None

    # ── Vulnerability path detection ─────────────────────────────────

    def find_vuln_path(self):
        """Find paths from input functions to comparison/output functions.

        Returns list of (input_func, comparison_func, path) tuples.
        """
        paths = []
        input_funcs = set()
        target_funcs = set()

        for func, imports in self.import_calls.items():
            if imports & INPUT_FUNCTIONS:
                input_funcs.add(func)
            if imports & (COMPARISON_FUNCTIONS | {"puts", "printf", "exit"}):
                target_funcs.add(func)

        # BFS from each input function to find paths to targets
        for start in input_funcs:
            visited = {start}
            queue = [(start, [start])]
            while queue:
                current, path = queue.pop(0)
                if current in target_funcs and current != start:
                    paths.append((start, current, path))
                    continue
                for callee in self.call_graph.get(current, set()):
                    clean = callee.replace("@plt", "")
                    if clean not in visited and clean in self.functions:
                        visited.add(clean)
                        queue.append((clean, path + [clean]))

        return paths

    # ── Main solve loop ──────────────────────────────────────────────

    def solve(self):
        """Main analysis pipeline: triage -> rank -> decompile -> scan for flags."""
        info = self.get_binary_info()
        size_kb = info.get("size", 0) // 1024
        print(f"[*] Binary: {self.binary} ({size_kb} KB)")
        print(f"[*] Type: {info.get('type', 'unknown')}")

        # Extract functions
        self.extract_functions()
        if not self.functions:
            print("[-] No functions found -- binary may be packed or non-standard")
            # Try strings-only approach
            return self._strings_only_analysis()

        # Build call graph
        self.build_call_graph()

        # Extract string cross-references
        self.extract_strings_with_refs()

        # Rank functions
        ranked = self.rank_functions()

        # Determine how many to decompile
        func_count = len(self.functions)
        if func_count <= self.max_functions:
            print(f"[*] Small binary ({func_count} functions) -- analyzing all")
            top_functions = ranked
        else:
            # Only take functions with positive score, up to max
            top_functions = [(n, s, r) for n, s, r in ranked if s > 0][:self.max_functions]
            if len(top_functions) < 5:
                # If too few interesting functions, take top N by score anyway
                top_functions = ranked[:self.max_functions]

        print(f"\n[*] Top {len(top_functions)} functions to analyze:")
        for name, score, reasons in top_functions[:20]:
            reason_str = "; ".join(reasons) if reasons else "baseline"
            print(f"    {name:40s} score={score:3d}  ({reason_str})")

        # Show vulnerability paths
        vuln_paths = self.find_vuln_path()
        if vuln_paths:
            print(f"\n[*] Found {len(vuln_paths)} input-to-check paths:")
            for inp, target, path in vuln_paths[:5]:
                print(f"    {inp} -> {'->'.join(path[1:])} -> {target}")

        # Decompile
        function_addrs = [
            self.functions[name]["addr"]
            for name, _, _ in top_functions
            if name in self.functions
        ]
        function_names = [name for name, _, _ in top_functions if name in self.functions]

        decompiled = None
        if self.ghidra:
            decompiled = self.decompile_with_ghidra(function_addrs)

        if not decompiled:
            decompiled = self.decompile_with_objdump(function_names)

        if not decompiled:
            print("[-] No decompilation output produced")
            return None

        # Scan for flags in decompiled output
        print(f"\n[*] Scanning {len(decompiled)} chars of decompiled output for flags...")
        flags = self.flag_pattern.findall(decompiled)
        for f in flags:
            print(f"EXTRACTED FLAG: {f}")

        if not flags:
            # Try generic flag pattern
            generic = re.findall(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', decompiled)
            for g in generic:
                body_match = re.search(r'\{(.+)\}', g)
                if body_match and len(set(body_match.group(1))) >= 3:
                    print(f"EXTRACTED FLAG: {g}")
                    flags.append(g)

        # Also look for hardcoded comparisons
        self._extract_hardcoded_comparisons(decompiled)

        # Print decompilation summary
        print(f"\n[*] Decompiled output ({len(decompiled)} chars) written to stdout")
        print("=" * 72)
        # Truncate very long output
        if len(decompiled) > 50000:
            print(decompiled[:50000])
            print(f"\n[... truncated {len(decompiled) - 50000} chars ...]")
        else:
            print(decompiled)

        return decompiled

    def _strings_only_analysis(self):
        """Last-resort analysis: just scan strings for flags."""
        print("[*] Falling back to strings-only analysis...")
        try:
            proc = subprocess.run(
                ["strings", "-a", "-n", "4", self.binary],
                capture_output=True, text=True, timeout=30,
            )
            flags = self.flag_pattern.findall(proc.stdout)
            for f in flags:
                print(f"EXTRACTED FLAG: {f}")
            if not flags:
                # Try generic
                generic = re.findall(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', proc.stdout)
                for g in generic:
                    body_match = re.search(r'\{(.+)\}', g)
                    if body_match and len(set(body_match.group(1))) >= 3:
                        print(f"EXTRACTED FLAG: {g}")
            return proc.stdout
        except Exception as e:
            print(f"[-] strings failed: {e}")
            return None

    def _extract_hardcoded_comparisons(self, decompiled):
        """Look for hardcoded string comparisons in decompiled code.

        Patterns like:
          if (strcmp(input, "s3cr3t_p4ss") == 0)
          if (memcmp(buf, "\\x41\\x42\\x43", 3) == 0)
        """
        # strcmp/strncmp with literal strings
        for m in re.finditer(
            r'(?:strcmp|strncmp|memcmp)\s*\([^,]+,\s*"([^"]+)"', decompiled
        ):
            value = m.group(1)
            if len(value) >= 3 and value.isprintable():
                print(f"[+] Hardcoded comparison value: \"{value}\"")

        # Direct character comparisons: input[0] == 'f'
        char_cmps = re.findall(
            r"\[\s*(\d+)\s*\]\s*==\s*'(.)'", decompiled
        )
        if len(char_cmps) >= 4:
            chars = [""] * (max(int(idx) for idx, _ in char_cmps) + 1)
            for idx, ch in char_cmps:
                chars[int(idx)] = ch
            assembled = "".join(chars)
            if assembled:
                print(f"[+] Assembled from char comparisons: \"{assembled}\"")

        # Hex byte comparisons: if (buf[i] == 0x66)
        hex_cmps = re.findall(
            r"\[\s*(\d+)\s*\]\s*==\s*0x([0-9a-fA-F]{2})", decompiled
        )
        if len(hex_cmps) >= 4:
            chars = {}
            for idx, hx in hex_cmps:
                try:
                    chars[int(idx)] = chr(int(hx, 16))
                except (ValueError, OverflowError):
                    pass
            if chars:
                max_idx = max(chars.keys())
                assembled = "".join(chars.get(i, "?") for i in range(max_idx + 1))
                print(f"[+] Assembled from hex comparisons: \"{assembled}\"")


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Kraken Focused Decompile -- smart function triage for large binaries"
    )
    parser.add_argument("--binary", required=True, help="Path to binary")
    parser.add_argument("--max-functions", type=int, default=20,
                        help="Max functions to decompile (default: 20)")
    parser.add_argument("--prefix", default="flag",
                        help="Flag prefix (default: flag)")
    parser.add_argument("--ghidra", default=None,
                        help="Path to Ghidra install directory")
    parser.add_argument("--no-ghidra", action="store_true",
                        help="Skip Ghidra, use objdump only")

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"[-] File not found: {args.binary}")
        sys.exit(1)

    ghidra = None if args.no_ghidra else args.ghidra
    decompiler = FocusedDecompiler(
        args.binary,
        prefix=args.prefix,
        max_functions=args.max_functions,
        ghidra_path=ghidra,
    )
    decompiler.solve()


if __name__ == "__main__":
    main()
