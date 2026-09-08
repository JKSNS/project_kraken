#!/usr/bin/env python3
"""Kraken Binary Diff -- find changes between binary versions.

Compares two binaries (original vs patched) to identify:
  1. Added / removed / changed functions
  2. Byte-level differences with context
  3. Patch type classification (NOP, branch flip, bounds check, etc.)
  4. Vulnerability suggestions based on patch patterns
  5. Decompilation of changed functions (via Ghidra or objdump)

Useful for Attack/Defense CTF, binary patch analysis, and understanding
what changed in a firmware update.

Usage:
  python3 auto_binary_diff.py --original ./vuln --patched ./vuln_patched
  python3 auto_binary_diff.py --original ./v1.bin --patched ./v2.bin --decompile
  python3 auto_binary_diff.py --original ./before --patched ./after --prefix flag
"""
import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict


class BinaryDiffer:
    """Compare two binaries and identify meaningful differences."""

    def __init__(self, binary_a, binary_b, prefix="flag", ghidra_path=None):
        self.binary_a = os.path.abspath(binary_a)  # Original
        self.binary_b = os.path.abspath(binary_b)  # Patched
        self.prefix = prefix
        self.ghidra = ghidra_path or self._find_ghidra()
        self.flag_pattern = re.compile(
            rf'{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}'
        )

        # Populated during analysis
        self.funcs_a = {}  # name -> {addr, size, hash}
        self.funcs_b = {}
        self.byte_diffs = []
        self.data_a = b""
        self.data_b = b""

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
        return None

    # ── Binary info ──────────────────────────────────────────────────

    def get_binary_info(self, binary_path):
        """Get basic info about a binary."""
        info = {}
        try:
            info["size"] = os.path.getsize(binary_path)
        except OSError:
            info["size"] = 0

        try:
            proc = subprocess.run(
                ["file", binary_path], capture_output=True, text=True, timeout=5,
            )
            info["type"] = proc.stdout.strip()
        except Exception:
            info["type"] = "unknown"

        try:
            with open(binary_path, "rb") as f:
                data = f.read()
            info["md5"] = hashlib.md5(data).hexdigest()
            info["sha256"] = hashlib.sha256(data).hexdigest()[:16] + "..."
        except OSError:
            info["md5"] = "unknown"
            info["sha256"] = "unknown"

        return info

    # ── Function extraction ──────────────────────────────────────────

    def get_functions(self, binary_path):
        """Extract function list with addresses, sizes, and content hashes.

        For stripped binaries, uses objdump heuristic function detection.
        Returns dict: name -> {addr, size, hash}
        """
        functions = {}

        # Try nm first
        try:
            proc = subprocess.run(
                ["nm", "-S", "--defined-only", binary_path],
                capture_output=True, text=True, timeout=15,
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split()
                if len(parts) >= 4 and parts[2].lower() in ("t", "T"):
                    addr = int(parts[0], 16)
                    size = int(parts[1], 16)
                    name = parts[3]
                    functions[name] = {"addr": addr, "size": size}
        except Exception:
            pass

        # Fallback: objdump disassembly headers
        if not functions or len(functions) < 3:
            try:
                proc = subprocess.run(
                    ["objdump", "-d", "--no-show-raw-insn", binary_path],
                    capture_output=True, text=True, timeout=60,
                )
                current_func = None
                current_addr = None
                current_lines = []

                for line in proc.stdout.splitlines():
                    func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
                    if func_match:
                        # Save previous function
                        if current_func and current_lines:
                            content = "\n".join(current_lines)
                            func_hash = hashlib.md5(content.encode()).hexdigest()
                            if current_func in functions:
                                functions[current_func]["hash"] = func_hash
                                functions[current_func]["content"] = content
                            else:
                                functions[current_func] = {
                                    "addr": current_addr,
                                    "size": 0,
                                    "hash": func_hash,
                                    "content": content,
                                }
                        current_func = func_match.group(2)
                        current_addr = int(func_match.group(1), 16)
                        current_lines = [line]
                    elif current_func and line.strip():
                        current_lines.append(line)

                # Last function
                if current_func and current_lines:
                    content = "\n".join(current_lines)
                    func_hash = hashlib.md5(content.encode()).hexdigest()
                    if current_func in functions:
                        functions[current_func]["hash"] = func_hash
                        functions[current_func]["content"] = content
                    else:
                        functions[current_func] = {
                            "addr": current_addr,
                            "size": 0,
                            "hash": func_hash,
                            "content": content,
                        }
            except Exception:
                pass

        # Compute hashes for functions from nm that don't have one yet
        if functions:
            try:
                with open(binary_path, "rb") as f:
                    data = f.read()
                for name, info in functions.items():
                    if "hash" not in info and info.get("size", 0) > 0:
                        addr = info["addr"]
                        size = info["size"]
                        # Convert virtual address to file offset (approximate)
                        func_bytes = data[addr:addr + size] if addr + size <= len(data) else b""
                        info["hash"] = hashlib.md5(func_bytes).hexdigest()
            except OSError:
                pass

        return functions

    # ── Function-level diff ──────────────────────────────────────────

    def diff_functions(self):
        """Compare functions between two binaries.

        Returns dict with added, removed, and changed function names.
        """
        print("[*] Comparing functions...")

        self.funcs_a = self.get_functions(self.binary_a)
        self.funcs_b = self.get_functions(self.binary_b)

        names_a = set(self.funcs_a.keys())
        names_b = set(self.funcs_b.keys())

        added = names_b - names_a
        removed = names_a - names_b

        changed = []
        for name in names_a & names_b:
            hash_a = self.funcs_a[name].get("hash", "")
            hash_b = self.funcs_b[name].get("hash", "")
            if hash_a and hash_b and hash_a != hash_b:
                changed.append(name)
            elif not hash_a or not hash_b:
                # Can't compare hashes; check by size
                size_a = self.funcs_a[name].get("size", 0)
                size_b = self.funcs_b[name].get("size", 0)
                if size_a != size_b:
                    changed.append(name)

        result = {
            "added": sorted(added),
            "removed": sorted(removed),
            "changed": sorted(changed),
            "unchanged": len(names_a & names_b) - len(changed),
        }

        print(f"[*] Functions: {len(names_a)} (A) vs {len(names_b)} (B)")
        print(f"    Added:     {len(added)}")
        print(f"    Removed:   {len(removed)}")
        print(f"    Changed:   {len(changed)}")
        print(f"    Unchanged: {result['unchanged']}")

        return result

    # ── Byte-level diff ──────────────────────────────────────────────

    def byte_diff(self, max_diffs=10000):
        """Find byte-level differences between the two binaries.

        Returns list of (offset, byte_a, byte_b) tuples.
        """
        print("[*] Computing byte-level diff...")

        try:
            with open(self.binary_a, "rb") as f:
                self.data_a = f.read()
            with open(self.binary_b, "rb") as f:
                self.data_b = f.read()
        except OSError as e:
            print(f"[-] Cannot read binaries: {e}")
            return []

        diffs = []
        min_len = min(len(self.data_a), len(self.data_b))

        for i in range(min_len):
            if self.data_a[i] != self.data_b[i]:
                diffs.append((i, self.data_a[i], self.data_b[i]))
                if len(diffs) >= max_diffs:
                    print(f"[!] Stopped at {max_diffs} diffs (binary likely very different)")
                    break

        # Track size difference
        if len(self.data_a) != len(self.data_b):
            diffs.append((-1, len(self.data_a), len(self.data_b)))  # sentinel

        self.byte_diffs = diffs
        diff_count = len([d for d in diffs if d[0] >= 0])
        print(f"[*] Found {diff_count} byte differences")

        if len(self.data_a) != len(self.data_b):
            print(f"[*] Size difference: {len(self.data_a)} (A) vs {len(self.data_b)} (B)"
                  f" ({len(self.data_b) - len(self.data_a):+d} bytes)")

        return diffs

    # ── Diff grouping ────────────────────────────────────────────────

    def group_diffs(self, max_gap=16):
        """Group adjacent byte diffs into contiguous regions.

        Returns list of (start_offset, bytes_a, bytes_b) tuples.
        """
        if not self.byte_diffs:
            return []

        # Filter out sentinel entries
        real_diffs = [(off, ba, bb) for off, ba, bb in self.byte_diffs if off >= 0]
        if not real_diffs:
            return []

        groups = []
        group_start = real_diffs[0][0]
        group_bytes_a = bytearray()
        group_bytes_b = bytearray()
        prev_off = group_start - 1

        for off, ba, bb in real_diffs:
            if off > prev_off + max_gap:
                # Start new group
                if group_bytes_a:
                    groups.append((group_start, bytes(group_bytes_a), bytes(group_bytes_b)))
                group_start = off
                group_bytes_a = bytearray()
                group_bytes_b = bytearray()

            # Fill gaps with actual bytes
            while prev_off + 1 < off and prev_off >= group_start - 1:
                prev_off += 1
                if prev_off < len(self.data_a):
                    group_bytes_a.append(self.data_a[prev_off])
                if prev_off < len(self.data_b):
                    group_bytes_b.append(self.data_b[prev_off])

            group_bytes_a.append(ba)
            group_bytes_b.append(bb)
            prev_off = off

        if group_bytes_a:
            groups.append((group_start, bytes(group_bytes_a), bytes(group_bytes_b)))

        return groups

    # ── Patch type identification ────────────────────────────────────

    def identify_patch_type(self, groups=None):
        """Categorize what kind of patch was applied.

        Returns list of (offset, patch_type, description) tuples.
        """
        if groups is None:
            groups = self.group_diffs()

        print("[*] Analyzing patch types...")
        patches = []

        for start, bytes_a, bytes_b in groups:
            desc = self._classify_patch(start, bytes_a, bytes_b)
            patches.append(desc)

        # Print results
        for offset, ptype, description in patches:
            print(f"    [{offset:#08x}] {ptype}: {description}")

        return patches

    def _classify_patch(self, offset, bytes_a, bytes_b):
        """Classify a single patch region."""
        n = len(bytes_a)

        # NOP insertion: bytes changed to 0x90
        if all(b == 0x90 for b in bytes_b):
            return (offset, "NOP_OUT", f"{n} byte(s) NOP'd out (was: {bytes_a.hex()})")

        # NOP removal: 0x90 replaced with actual code
        if all(b == 0x90 for b in bytes_a):
            return (offset, "CODE_INSERT", f"{n} byte(s) of code inserted (was NOPs)")

        # Conditional branch flip
        branch_flips = {
            (0x74, 0x75): "JE -> JNE",
            (0x75, 0x74): "JNE -> JE",
            (0x74, 0xEB): "JE -> JMP (unconditional)",
            (0x75, 0xEB): "JNE -> JMP (unconditional)",
            (0x7C, 0x7D): "JL -> JGE",
            (0x7D, 0x7C): "JGE -> JL",
            (0x7E, 0x7F): "JLE -> JG",
            (0x7F, 0x7E): "JG -> JLE",
            (0x72, 0x73): "JB -> JAE",
            (0x73, 0x72): "JAE -> JB",
            (0x76, 0x77): "JBE -> JA",
            (0x77, 0x76): "JA -> JBE",
        }
        if n == 1 and (bytes_a[0], bytes_b[0]) in branch_flips:
            return (offset, "BRANCH_FLIP", branch_flips[(bytes_a[0], bytes_b[0])])

        # Near conditional branch flip (0F 84 -> 0F 85, etc.)
        near_flips = {
            (0x84, 0x85): "JE near -> JNE near",
            (0x85, 0x84): "JNE near -> JE near",
            (0x8C, 0x8D): "JL near -> JGE near",
            (0x8D, 0x8C): "JGE near -> JL near",
            (0x8E, 0x8F): "JLE near -> JG near",
            (0x8F, 0x8E): "JG near -> JLE near",
        }
        if n == 1 and offset > 0:
            # Check if previous byte is 0x0F (two-byte opcode prefix)
            if offset < len(self.data_a) and self.data_a[offset - 1] == 0x0F:
                if (bytes_a[0], bytes_b[0]) in near_flips:
                    return (offset - 1, "BRANCH_FLIP_NEAR", near_flips[(bytes_a[0], bytes_b[0])])

        # Boolean gate: 0x00 -> 0x01 or vice versa
        if n == 1 and bytes_a == b'\x00' and bytes_b == b'\x01':
            return (offset, "GATE_SET", "Boolean gate: 0 -> 1 (enable flag)")
        if n == 1 and bytes_a == b'\x01' and bytes_b == b'\x00':
            return (offset, "GATE_CLEAR", "Boolean gate: 1 -> 0 (disable flag)")

        # Constant change
        if n <= 4:
            try:
                if n == 1:
                    val_a, val_b = bytes_a[0], bytes_b[0]
                elif n == 2:
                    val_a = int.from_bytes(bytes_a, "little")
                    val_b = int.from_bytes(bytes_b, "little")
                elif n == 4:
                    val_a = int.from_bytes(bytes_a, "little")
                    val_b = int.from_bytes(bytes_b, "little")
                else:
                    val_a = int.from_bytes(bytes_a, "little")
                    val_b = int.from_bytes(bytes_b, "little")
                return (offset, "CONST_CHANGE",
                        f"Constant changed: {val_a:#x} -> {val_b:#x} "
                        f"(bytes: {bytes_a.hex()} -> {bytes_b.hex()})")
            except Exception:
                pass

        # Call target change
        if n == 4 and offset > 0:
            # Check if previous byte is 0xE8 (call near)
            if offset - 1 < len(self.data_a) and self.data_a[offset - 1] == 0xE8:
                old_target = int.from_bytes(bytes_a, "little", signed=True) + offset + 4
                new_target = int.from_bytes(bytes_b, "little", signed=True) + offset + 4
                return (offset - 1, "CALL_RETARGET",
                        f"Call target changed: {old_target:#x} -> {new_target:#x}")

        # String change
        if all(32 <= b <= 126 for b in bytes_a) and all(32 <= b <= 126 for b in bytes_b):
            try:
                str_a = bytes_a.decode("ascii")
                str_b = bytes_b.decode("ascii")
                return (offset, "STRING_CHANGE", f'"{str_a}" -> "{str_b}"')
            except Exception:
                pass

        # Generic: unknown patch type
        return (offset, "UNKNOWN",
                f"{n} byte(s) changed: {bytes_a[:16].hex()} -> {bytes_b[:16].hex()}")

    # ── Vulnerability suggestions ────────────────────────────────────

    def suggest_exploit(self, patches=None):
        """Based on patches, suggest what vulnerability was fixed."""
        if patches is None:
            groups = self.group_diffs()
            patches = self.identify_patch_type(groups)

        print("\n[*] Vulnerability analysis:")
        suggestions = []

        for offset, ptype, desc in patches:
            if ptype == "BRANCH_FLIP" or ptype == "BRANCH_FLIP_NEAR":
                suggestions.append(
                    f"  [{offset:#08x}] Conditional check was flipped -- "
                    f"original path may bypass authentication or input validation. "
                    f"Try: flip the condition back to reach the original 'success' path."
                )
            elif ptype == "NOP_OUT":
                suggestions.append(
                    f"  [{offset:#08x}] Code was removed (NOP'd) -- "
                    f"the original code may have been a vulnerability check, "
                    f"bounds validation, or authentication bypass."
                )
            elif ptype == "GATE_SET":
                suggestions.append(
                    f"  [{offset:#08x}] Boolean flag enabled -- "
                    f"a gate condition was activated. The vulnerability may be "
                    f"accessible when this gate is disabled (set to 0)."
                )
            elif ptype == "GATE_CLEAR":
                suggestions.append(
                    f"  [{offset:#08x}] Boolean flag disabled -- "
                    f"a security check was deactivated. Exploit may work "
                    f"when this check is bypassed."
                )
            elif ptype == "CALL_RETARGET":
                suggestions.append(
                    f"  [{offset:#08x}] Function call target changed -- "
                    f"the original function may have a vulnerability (e.g., "
                    f"replaced `gets` with `fgets`, `strcpy` with `strncpy`)."
                )
            elif ptype == "CONST_CHANGE":
                suggestions.append(
                    f"  [{offset:#08x}] Constant value changed -- "
                    f"may be a buffer size increase (fixing overflow), "
                    f"loop bound change, or comparison threshold."
                )

        if suggestions:
            for s in suggestions:
                print(s)
        else:
            print("    No clear vulnerability pattern identified")

        return suggestions

    # ── Decompilation of changed functions ───────────────────────────

    def decompile_changed(self, changed_funcs=None):
        """Decompile only the changed functions from both binaries.

        Shows side-by-side comparison of the changed function code.
        """
        if changed_funcs is None:
            diff = self.diff_functions()
            changed_funcs = diff.get("changed", [])

        if not changed_funcs:
            print("[*] No changed functions to decompile")
            return None

        print(f"\n[*] Decompiling {len(changed_funcs)} changed functions...")

        # Get disassembly for changed functions from both binaries
        disasm_a = self._get_function_disasm(self.binary_a, changed_funcs)
        disasm_b = self._get_function_disasm(self.binary_b, changed_funcs)

        # Show side-by-side diff
        for func_name in changed_funcs:
            code_a = disasm_a.get(func_name, "[not found]")
            code_b = disasm_b.get(func_name, "[not found]")

            print(f"\n{'=' * 72}")
            print(f"  Function: {func_name}")
            print(f"{'=' * 72}")

            # Simple line-by-line diff
            lines_a = code_a.splitlines()
            lines_b = code_b.splitlines()

            # Find differing lines
            max_lines = max(len(lines_a), len(lines_b))
            has_diff = False
            for i in range(max_lines):
                line_a = lines_a[i] if i < len(lines_a) else ""
                line_b = lines_b[i] if i < len(lines_b) else ""
                if line_a != line_b:
                    if not has_diff:
                        print("  --- Original (A)")
                        print("  +++ Patched (B)")
                        has_diff = True
                    print(f"  - {line_a}")
                    print(f"  + {line_b}")

            if not has_diff:
                print("  [identical disassembly -- difference may be in data references]")

        return {"a": disasm_a, "b": disasm_b}

    def _get_function_disasm(self, binary_path, function_names):
        """Extract disassembly for specific functions."""
        result = {}
        target_set = set(function_names)

        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", binary_path],
                capture_output=True, text=True, timeout=60,
            )
        except Exception:
            return result

        current_func = None
        current_lines = []

        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                if current_func and current_func in target_set:
                    result[current_func] = "\n".join(current_lines)
                current_func = func_match.group(2)
                current_lines = [line]
            elif current_func:
                current_lines.append(line)

        if current_func and current_func in target_set:
            result[current_func] = "\n".join(current_lines)

        return result

    # ── String diff ──────────────────────────────────────────────────

    def diff_strings(self):
        """Compare strings between the two binaries."""
        print("[*] Comparing strings...")

        def get_strings(binary_path):
            try:
                proc = subprocess.run(
                    ["strings", "-a", "-n", "4", binary_path],
                    capture_output=True, text=True, timeout=15,
                )
                return set(proc.stdout.strip().splitlines())
            except Exception:
                return set()

        strings_a = get_strings(self.binary_a)
        strings_b = get_strings(self.binary_b)

        added = strings_b - strings_a
        removed = strings_a - strings_b

        print(f"    Strings in A: {len(strings_a)}")
        print(f"    Strings in B: {len(strings_b)}")
        print(f"    Added:   {len(added)}")
        print(f"    Removed: {len(removed)}")

        # Show interesting added/removed strings
        if added:
            print("\n    Added strings (first 20):")
            for s in sorted(added)[:20]:
                if len(s) >= 4:
                    print(f"      + {s}")
        if removed:
            print("\n    Removed strings (first 20):")
            for s in sorted(removed)[:20]:
                if len(s) >= 4:
                    print(f"      - {s}")

        # Check for flags in added strings
        for s in added:
            flags = self.flag_pattern.findall(s)
            for f in flags:
                print(f"EXTRACTED FLAG: {f}")

        return {"added": added, "removed": removed}

    # ── Main solve ───────────────────────────────────────────────────

    def solve(self, decompile=False):
        """Full binary diff analysis pipeline."""
        # Binary info
        print("[*] Binary A (original):")
        info_a = self.get_binary_info(self.binary_a)
        print(f"    Path: {self.binary_a}")
        print(f"    Size: {info_a['size']} bytes")
        print(f"    MD5:  {info_a['md5']}")

        print("[*] Binary B (patched):")
        info_b = self.get_binary_info(self.binary_b)
        print(f"    Path: {self.binary_b}")
        print(f"    Size: {info_b['size']} bytes")
        print(f"    MD5:  {info_b['md5']}")

        if info_a["md5"] == info_b["md5"]:
            print("\n[*] Binaries are identical (same MD5)")
            return

        # Function-level diff
        func_diff = self.diff_functions()

        # Byte-level diff
        self.byte_diff()

        # Group and classify patches
        groups = self.group_diffs()
        if groups:
            print(f"\n[*] {len(groups)} patch region(s) found:")
            patches = self.identify_patch_type(groups)

            # Vulnerability suggestions
            self.suggest_exploit(patches)

        # String diff
        self.diff_strings()

        # Decompile changed functions
        if decompile and func_diff.get("changed"):
            self.decompile_changed(func_diff["changed"])

        # Summary
        print(f"\n{'=' * 72}")
        print("[*] DIFF SUMMARY")
        print(f"    Byte differences:    {len([d for d in self.byte_diffs if d[0] >= 0])}")
        print(f"    Patch regions:       {len(groups)}")
        print(f"    Changed functions:   {len(func_diff.get('changed', []))}")
        print(f"    Added functions:     {len(func_diff.get('added', []))}")
        print(f"    Removed functions:   {len(func_diff.get('removed', []))}")

        if func_diff.get("changed"):
            print(f"\n    Changed: {', '.join(func_diff['changed'][:10])}")
        if func_diff.get("added"):
            print(f"    Added:   {', '.join(func_diff['added'][:10])}")
        if func_diff.get("removed"):
            print(f"    Removed: {', '.join(func_diff['removed'][:10])}")


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Kraken Binary Diff -- find changes between binary versions"
    )
    parser.add_argument("--original", required=True, help="Path to original binary")
    parser.add_argument("--patched", required=True, help="Path to patched binary")
    parser.add_argument("--prefix", default="flag", help="Flag prefix (default: flag)")
    parser.add_argument("--decompile", action="store_true",
                        help="Decompile changed functions")
    parser.add_argument("--ghidra", default=None,
                        help="Path to Ghidra install directory")

    args = parser.parse_args()

    for path in [args.original, args.patched]:
        if not os.path.isfile(path):
            print(f"[-] File not found: {path}")
            sys.exit(1)

    differ = BinaryDiffer(
        args.original, args.patched,
        prefix=args.prefix,
        ghidra_path=args.ghidra,
    )
    differ.solve(decompile=args.decompile)


if __name__ == "__main__":
    main()
