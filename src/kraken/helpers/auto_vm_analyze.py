#!/usr/bin/env python3
"""auto_vm_analyze -- Custom VM / bytecode interpreter analysis.

Analyzes binaries that implement custom virtual machines:
  1. VM detection -- identify dispatch tables, opcode handlers, switch statements
  2. Opcode extraction -- map opcode numbers to operations from source/decompiled
  3. Bytecode extraction -- pull embedded bytecode from .rodata/.data sections
  4. VM trace -- run with GDB instrumentation, log all operations
  5. Symbolic VM execution -- use Z3 to solve VM programs symbolically
  6. Pattern matching -- recognize stack/register machines, common VM patterns
  7. Bytecode disassembly -- disassemble extracted bytecode with opcode map

Usage:
    python3 auto_vm_analyze.py --binary ./vm_challenge --prefix flag
    python3 auto_vm_analyze.py --binary ./vm --source decompiled.c --prefix flag
    python3 auto_vm_analyze.py --binary ./vm --bytecode program.bin --prefix flag

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import os
import re
import signal
import struct
import subprocess
import sys
import tempfile
import time

# ---------------------------------------------------------------------------
# Optional Z3 import
# ---------------------------------------------------------------------------
try:
    from z3 import (
        BitVec, BitVecVal, Solver, sat, If, And, Or, Not,
        Extract, Concat, ZeroExt, SignExt, URem, UDiv,
        LShR, RotateLeft, RotateRight,
    )
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DEFAULT_FLAG_PATTERN = re.compile(r"[A-Za-z_]{2,}\{[^\}]{3,}\}")
TECHNIQUE_TIMEOUT = 30

# Common VM opcode names
VM_OP_NAMES = {
    "push", "pop", "add", "sub", "mul", "div", "mod", "xor", "and", "or",
    "not", "shl", "shr", "cmp", "jmp", "jz", "jnz", "je", "jne", "jl",
    "jg", "jle", "jge", "call", "ret", "nop", "halt", "stop", "exit",
    "load", "store", "mov", "inc", "dec", "dup", "swap", "rot",
    "print", "read", "input", "output", "putc", "getc",
}


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


# ---------------------------------------------------------------------------
# VM Detector
# ---------------------------------------------------------------------------
class VMDetector:
    """Detect VM/interpreter patterns in source code or binary."""

    # Keywords that indicate a VM implementation
    VM_KEYWORDS = re.compile(
        r"\b(opcode|bytecode|dispatch|interpret|vm_run|execute|"
        r"instruction|program_counter|stack_pointer|vm_stack|"
        r"fetch|decode|ip\b|pc\b|sp\b)\b",
        re.I,
    )

    # Switch/case dispatch pattern
    SWITCH_PATTERN = re.compile(
        r"switch\s*\(\s*\w+\s*\)\s*\{(.*?)\}",
        re.DOTALL,
    )

    # Case label pattern
    CASE_PATTERN = re.compile(
        r"case\s+(0x[0-9a-fA-F]+|\d+)\s*:\s*(.*?)(?=case\s|default\s*:|break\s*;|\})",
        re.DOTALL,
    )

    # Function pointer table pattern
    FPTR_PATTERN = re.compile(
        r"(?:void|int|uint\d+_t)\s*\(\s*\*\s*\w+\s*\[\s*\]\s*\)\s*\(",
    )

    @classmethod
    def detect_in_source(cls, source: str) -> dict:
        """Analyze source code for VM patterns.

        Returns dict with: is_vm, confidence, opcodes, dispatch_type
        """
        result = {
            "is_vm": False,
            "confidence": 0.0,
            "opcodes": {},
            "dispatch_type": "unknown",
            "bytecode_vars": [],
        }

        # Count VM keyword hits
        keyword_hits = len(cls.VM_KEYWORDS.findall(source))
        result["confidence"] += min(keyword_hits * 5, 30)

        # Look for switch dispatch
        switch_matches = cls.SWITCH_PATTERN.findall(source)
        if switch_matches:
            for switch_body in switch_matches:
                cases = cls.CASE_PATTERN.findall(switch_body)
                if len(cases) >= 3:
                    result["dispatch_type"] = "switch"
                    result["confidence"] += 30
                    # Extract opcode mappings
                    for case_val, case_body in cases:
                        try:
                            opval = int(case_val, 0)
                        except ValueError:
                            continue
                        # Guess operation name from body
                        op_name = cls._guess_op_name(case_body)
                        result["opcodes"][opval] = op_name

        # Look for function pointer dispatch
        if cls.FPTR_PATTERN.search(source):
            result["dispatch_type"] = "function_pointer"
            result["confidence"] += 25

        # Look for while/for loop with fetch-decode-execute
        if re.search(r"while\s*\(.+\)\s*\{.*(?:switch|table|handler)", source, re.DOTALL):
            result["confidence"] += 20

        # Look for bytecode arrays
        bc_vars = re.findall(
            r"(?:unsigned\s+)?(?:char|uint8_t|byte)\s+(\w+)\s*\[\s*\]\s*=\s*\{([^}]+)\}",
            source,
        )
        if bc_vars:
            result["bytecode_vars"] = [(name, body) for name, body in bc_vars]
            result["confidence"] += 15

        # Look for stack operations
        stack_ops = len(re.findall(r"\b(?:push|pop|stack\[)", source, re.I))
        if stack_ops >= 2:
            result["confidence"] += 10

        result["is_vm"] = result["confidence"] >= 30
        return result

    @staticmethod
    def _guess_op_name(case_body: str) -> str:
        """Guess opcode operation name from switch case body."""
        body_lower = case_body.lower().strip()

        # Direct operation detection
        for op in VM_OP_NAMES:
            if op in body_lower:
                return op

        # Pattern-based detection
        if re.search(r"\+\+|inc|add.*1", body_lower):
            return "inc"
        if re.search(r"--|dec|sub.*1", body_lower):
            return "dec"
        if re.search(r"stack\[.*\+\+\]|push", body_lower):
            return "push"
        if re.search(r"stack\[.*--\]|pop", body_lower):
            return "pop"
        if re.search(r"\+|add", body_lower):
            return "add"
        if re.search(r"-|sub", body_lower):
            return "sub"
        if re.search(r"\*|mul", body_lower):
            return "mul"
        if re.search(r"/|div", body_lower):
            return "div"
        if re.search(r"%|mod", body_lower):
            return "mod"
        if re.search(r"\^|xor", body_lower):
            return "xor"
        if re.search(r"&|and", body_lower):
            return "and"
        if re.search(r"\||or_", body_lower):
            return "or"
        if re.search(r"<<|shl|shift.*left", body_lower):
            return "shl"
        if re.search(r">>|shr|shift.*right", body_lower):
            return "shr"
        if re.search(r"==|cmp|compar", body_lower):
            return "cmp"
        if re.search(r"jmp|goto|ip\s*=|pc\s*=", body_lower):
            return "jmp"
        if re.search(r"print|put|output|write", body_lower):
            return "output"
        if re.search(r"read|get|input|scan", body_lower):
            return "input"
        if re.search(r"mov|load|store", body_lower):
            return "mov"
        if re.search(r"halt|stop|exit|return|break", body_lower):
            return "halt"
        if re.search(r"nop|no.?op", body_lower):
            return "nop"

        return f"op_{hash(case_body) & 0xFF:02x}"


# ---------------------------------------------------------------------------
# Bytecode Extractor
# ---------------------------------------------------------------------------
class BytecodeExtractor:
    """Extract bytecode from binaries and source."""

    @staticmethod
    def from_source(source: str) -> list[tuple[str, bytes]]:
        """Extract byte arrays from source code."""
        results = []

        # C-style byte arrays: uint8_t bytecode[] = { 0x01, 0x02, ... };
        arrays = re.findall(
            r"(?:unsigned\s+)?(?:char|uint8_t|byte)\s+(\w+)\s*\[\s*(?:\d+)?\s*\]\s*=\s*\{([^}]+)\}",
            source,
        )
        for name, body in arrays:
            values = re.findall(r"0x([0-9a-fA-F]+)|\b(\d+)\b", body)
            bytecode = []
            for hex_val, dec_val in values:
                if hex_val:
                    bytecode.append(int(hex_val, 16) & 0xFF)
                elif dec_val:
                    val = int(dec_val)
                    if 0 <= val <= 255:
                        bytecode.append(val)
            if bytecode:
                results.append((name, bytes(bytecode)))

        return results

    @staticmethod
    def from_binary(binary_path: str) -> list[tuple[str, bytes]]:
        """Extract potential bytecode from binary sections."""
        results = []

        # Use objdump to get .rodata and .data sections
        for section in [".rodata", ".data"]:
            try:
                result = subprocess.run(
                    ["objdump", "-s", "-j", section, binary_path],
                    capture_output=True, text=True, timeout=10,
                )
                if result.returncode == 0:
                    # Parse hex dump
                    raw_bytes = b""
                    for line in result.stdout.splitlines():
                        # objdump hex format: "  401000 01020304 05060708 ..."
                        match = re.match(r"\s*[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{8}\s*)+)", line)
                        if match:
                            hex_str = match.group(1).replace(" ", "")
                            raw_bytes += bytes.fromhex(hex_str)

                    if raw_bytes:
                        results.append((section, raw_bytes))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return results

    @staticmethod
    def from_file(filepath: str) -> bytes:
        """Read raw bytecode from a file."""
        with open(filepath, "rb") as f:
            return f.read()


# ---------------------------------------------------------------------------
# VM Disassembler
# ---------------------------------------------------------------------------
class VMDisassembler:
    """Disassemble bytecode using an opcode map."""

    def __init__(self, opcodes: dict[int, str]):
        self.opcodes = opcodes

    def disassemble(self, bytecode: bytes, has_operands: bool = True) -> list[str]:
        """Disassemble bytecode into instruction strings."""
        instructions = []
        ip = 0

        while ip < len(bytecode):
            opval = bytecode[ip]
            op_name = self.opcodes.get(opval, f"unk_{opval:02x}")

            if has_operands and ip + 1 < len(bytecode):
                # Peek at next byte as potential operand
                operand = bytecode[ip + 1]

                # Heuristic: if this opcode typically has an operand
                if op_name in ("push", "jmp", "jz", "jnz", "je", "jne", "jl", "jg",
                               "jle", "jge", "call", "load", "store", "mov"):
                    # Try 1-byte and 2-byte operands
                    if ip + 2 < len(bytecode):
                        operand_16 = struct.unpack_from("<H", bytecode, ip + 1)[0]
                        instructions.append(f"  {ip:04x}: {op_name} {operand} (0x{operand:02x}) [16bit: {operand_16}]")
                    else:
                        instructions.append(f"  {ip:04x}: {op_name} {operand} (0x{operand:02x})")
                    ip += 2
                    continue

            instructions.append(f"  {ip:04x}: {op_name}")
            ip += 1

        return instructions


# ---------------------------------------------------------------------------
# Symbolic VM Solver (Z3)
# ---------------------------------------------------------------------------
class SymbolicVMSolver:
    """Symbolically execute a VM program to find valid inputs."""

    def __init__(self, opcodes: dict[int, str], prefix: str = "flag"):
        self.opcodes = opcodes
        self.prefix = prefix

    def solve_bytecode(
        self,
        bytecode: bytes,
        input_length: int = 32,
        expected_output: bytes | None = None,
    ) -> str | None:
        """Symbolically execute bytecode and solve for input."""
        if not Z3_AVAILABLE:
            print("[-] Z3 not available for symbolic execution")
            return None

        print(f"[*] Symbolic VM execution (input_length={input_length})")

        solver = Solver()
        solver.set("timeout", 30000)  # 30 second timeout

        # Symbolic input
        sym_input = [BitVec(f"input_{i}", 8) for i in range(input_length)]

        # Constrain to printable ASCII
        for i in range(input_length):
            solver.add(sym_input[i] >= 32)
            solver.add(sym_input[i] <= 126)

        # If we know the prefix, constrain it
        if self.prefix:
            pfx = self.prefix.rstrip("{") + "{"
            for i, ch in enumerate(pfx):
                if i < input_length:
                    solver.add(sym_input[i] == ord(ch))

            # Closing brace at the end
            solver.add(sym_input[input_length - 1] == ord("}"))

        # Simulate VM execution symbolically
        stack: list = []
        regs = [BitVecVal(0, 8) for _ in range(16)]
        memory = {}
        ip = 0
        max_steps = 10000
        steps = 0
        input_idx = 0

        while ip < len(bytecode) and steps < max_steps:
            steps += 1
            opval = bytecode[ip]
            op_name = self.opcodes.get(opval, "unknown")

            try:
                if op_name == "push":
                    if ip + 1 < len(bytecode):
                        stack.append(BitVecVal(bytecode[ip + 1], 8))
                        ip += 2
                    else:
                        ip += 1
                elif op_name == "pop":
                    if stack:
                        stack.pop()
                    ip += 1
                elif op_name == "input" or op_name == "read" or op_name == "getc":
                    if input_idx < len(sym_input):
                        stack.append(sym_input[input_idx])
                        input_idx += 1
                    ip += 1
                elif op_name == "add":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(a + b)
                    ip += 1
                elif op_name == "sub":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(a - b)
                    ip += 1
                elif op_name == "mul":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(a * b)
                    ip += 1
                elif op_name == "xor":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(a ^ b)
                    ip += 1
                elif op_name == "and":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(a & b)
                    ip += 1
                elif op_name == "or":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(a | b)
                    ip += 1
                elif op_name == "not":
                    if stack:
                        a = stack.pop()
                        stack.append(~a)
                    ip += 1
                elif op_name == "shl":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(a << b)
                    ip += 1
                elif op_name == "shr":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(LShR(a, b))
                    ip += 1
                elif op_name == "mod":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(URem(a, b))
                    ip += 1
                elif op_name == "div":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        stack.append(UDiv(a, b))
                    ip += 1
                elif op_name == "cmp":
                    if len(stack) >= 2:
                        b = stack.pop()
                        a = stack.pop()
                        # Add constraint: a must equal b
                        solver.add(a == b)
                    ip += 1
                elif op_name in ("jmp", "goto"):
                    if ip + 1 < len(bytecode):
                        ip = bytecode[ip + 1]
                    else:
                        ip += 1
                elif op_name in ("jz", "je"):
                    if ip + 1 < len(bytecode) and stack:
                        val = stack.pop()
                        # Cannot branch symbolically easily; skip
                        ip += 2
                    else:
                        ip += 1
                elif op_name in ("jnz", "jne"):
                    if ip + 1 < len(bytecode) and stack:
                        val = stack.pop()
                        ip += 2
                    else:
                        ip += 1
                elif op_name == "dup":
                    if stack:
                        stack.append(stack[-1])
                    ip += 1
                elif op_name == "swap":
                    if len(stack) >= 2:
                        stack[-1], stack[-2] = stack[-2], stack[-1]
                    ip += 1
                elif op_name == "load":
                    if ip + 1 < len(bytecode):
                        addr = bytecode[ip + 1]
                        stack.append(memory.get(addr, BitVecVal(0, 8)))
                        ip += 2
                    else:
                        ip += 1
                elif op_name == "store":
                    if ip + 1 < len(bytecode) and stack:
                        addr = bytecode[ip + 1]
                        memory[addr] = stack.pop()
                        ip += 2
                    else:
                        ip += 1
                elif op_name in ("halt", "stop", "exit", "ret"):
                    break
                elif op_name == "mov":
                    if ip + 2 < len(bytecode):
                        dst = bytecode[ip + 1]
                        src = bytecode[ip + 2]
                        if src < len(regs):
                            regs[dst] = regs[src]
                        ip += 3
                    else:
                        ip += 1
                elif op_name in ("output", "print", "putc"):
                    ip += 1
                elif op_name in ("inc",):
                    if stack:
                        a = stack.pop()
                        stack.append(a + 1)
                    ip += 1
                elif op_name in ("dec",):
                    if stack:
                        a = stack.pop()
                        stack.append(a - 1)
                    ip += 1
                elif op_name == "nop":
                    ip += 1
                else:
                    # Unknown opcode, skip
                    ip += 1
            except Exception:
                ip += 1

        # If expected output is provided, add constraints
        if expected_output:
            for i, expected_byte in enumerate(expected_output):
                if i < len(stack):
                    solver.add(stack[i] == expected_byte)

        # Solve
        if solver.check() == sat:
            model = solver.model()
            result_chars = []
            for i in range(input_length):
                val = model.evaluate(sym_input[i], model_completion=True)
                try:
                    result_chars.append(chr(int(str(val))))
                except (ValueError, TypeError):
                    result_chars.append("?")
            solution = "".join(result_chars)
            print(f"[+] Z3 solution: {solution}")
            return solution
        else:
            print("[-] Z3: no solution found (UNSAT or timeout)")
            return None


# ---------------------------------------------------------------------------
# VM Analyzer
# ---------------------------------------------------------------------------
class VMAnalyzer:
    """Main VM analysis engine."""

    def __init__(
        self,
        binary_path: str,
        source_path: str | None = None,
        bytecode_path: str | None = None,
        prefix: str = "flag",
        input_length: int = 32,
        timeout: int = TECHNIQUE_TIMEOUT,
    ):
        self.binary = os.path.abspath(binary_path)
        self.source_path = source_path
        self.bytecode_path = bytecode_path
        self.prefix = prefix
        self.input_length = input_length
        self.timeout = timeout
        self.source: str | None = None
        self.opcodes: dict[int, str] = {}
        self.bytecode_segments: list[tuple[str, bytes]] = []
        self.all_flags: list[str] = []

    def _load_source(self) -> str | None:
        """Load source code from file."""
        if self.source_path and os.path.isfile(self.source_path):
            with open(self.source_path, "r", errors="replace") as f:
                self.source = f.read()
            return self.source
        return None

    # ----- Technique 1: VM Detection -----
    def technique_detect_vm(self) -> dict:
        """Detect if the binary contains a custom VM."""
        print("[*] Technique 1: VM detection")

        result = {"is_vm": False, "confidence": 0}

        # Check source code if available
        if self.source:
            result = VMDetector.detect_in_source(self.source)
            if result["is_vm"]:
                print(f"    [+] VM detected in source (confidence: {result['confidence']}%)")
                print(f"    [+] Dispatch type: {result['dispatch_type']}")
                print(f"    [+] Found {len(result['opcodes'])} opcodes")
                self.opcodes = result["opcodes"]
            else:
                print(f"    [-] No clear VM pattern in source (confidence: {result['confidence']}%)")

        # Also try to detect from binary strings
        try:
            strings_result = subprocess.run(
                ["strings", "-a", "-n", "4", self.binary],
                capture_output=True, text=True, timeout=10,
            )
            for s in strings_result.stdout.splitlines():
                s_lower = s.lower()
                if any(kw in s_lower for kw in ["opcode", "bytecode", "vm", "interpret", "dispatch"]):
                    result["confidence"] += 5
                    print(f"    [*] VM-related string: {s[:80]}")
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass

        return result

    # ----- Technique 2: Opcode Extraction -----
    def technique_extract_opcodes(self) -> dict[int, str]:
        """Extract opcode definitions from source or decompiled code."""
        print("[*] Technique 2: opcode extraction")

        if not self.source:
            # Try to decompile with objdump
            try:
                result = subprocess.run(
                    ["objdump", "-d", self.binary],
                    capture_output=True, text=True, timeout=30,
                )
                # Look for large switch-like jump table patterns
                disasm = result.stdout

                # Find indirect jump (dispatch table indicator)
                if re.search(r"jmp\s+\*", disasm):
                    print("    [*] Found indirect jump (potential dispatch table)")

                # Look for sequential comparison patterns (case labels)
                cmp_vals = re.findall(r"cmp\w*\s+.*\$0x([0-9a-fA-F]+)", disasm)
                if len(cmp_vals) >= 5:
                    print(f"    [*] Found {len(cmp_vals)} comparison values (potential opcodes)")
                    for i, val in enumerate(cmp_vals[:20]):
                        self.opcodes[int(val, 16)] = f"op_{int(val, 16):02x}"
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        elif self.opcodes:
            print(f"    [+] Using {len(self.opcodes)} opcodes from VM detection")
        else:
            # Try to extract from source
            detection = VMDetector.detect_in_source(self.source)
            self.opcodes = detection["opcodes"]

        if self.opcodes:
            print(f"    [+] Extracted {len(self.opcodes)} opcodes:")
            for opval, opname in sorted(self.opcodes.items()):
                print(f"      0x{opval:02x} -> {opname}")
        else:
            print("    [-] No opcodes extracted")

        return self.opcodes

    # ----- Technique 3: Bytecode Extraction -----
    def technique_extract_bytecode(self) -> list[tuple[str, bytes]]:
        """Extract bytecode from binary or source."""
        print("[*] Technique 3: bytecode extraction")

        if self.bytecode_path:
            data = BytecodeExtractor.from_file(self.bytecode_path)
            self.bytecode_segments = [("file", data)]
            print(f"    [+] Loaded {len(data)} bytes from {self.bytecode_path}")
        elif self.source:
            self.bytecode_segments = BytecodeExtractor.from_source(self.source)
            if self.bytecode_segments:
                for name, data in self.bytecode_segments:
                    print(f"    [+] Array '{name}': {len(data)} bytes")
        else:
            self.bytecode_segments = BytecodeExtractor.from_binary(self.binary)
            if self.bytecode_segments:
                for name, data in self.bytecode_segments:
                    print(f"    [+] Section '{name}': {len(data)} bytes")

        if not self.bytecode_segments:
            print("    [-] No bytecode extracted")

        return self.bytecode_segments

    # ----- Technique 4: Bytecode Disassembly -----
    def technique_disassemble(self) -> list[str]:
        """Disassemble extracted bytecode."""
        print("[*] Technique 4: bytecode disassembly")

        if not self.opcodes:
            print("    [-] No opcodes available for disassembly")
            return []

        if not self.bytecode_segments:
            print("    [-] No bytecode to disassemble")
            return []

        all_instructions: list[str] = []

        for name, bytecode in self.bytecode_segments:
            print(f"\n    Disassembly of '{name}' ({len(bytecode)} bytes):")
            disasm = VMDisassembler(self.opcodes)
            instructions = disasm.disassemble(bytecode)
            all_instructions.extend(instructions)

            for inst in instructions[:50]:
                print(f"    {inst}")
            if len(instructions) > 50:
                print(f"    ... ({len(instructions) - 50} more instructions)")

        return all_instructions

    # ----- Technique 5: GDB VM Trace -----
    def technique_gdb_trace(self) -> list[str]:
        """Use GDB to trace VM execution."""
        print("[*] Technique 5: GDB VM trace")

        flags: list[str] = []

        gdb_script = '''
import gdb

gdb.execute("set pagination off")
gdb.execute("set confirm off")

# Hook comparison functions for flag extraction
class CmpHook(gdb.Breakpoint):
    def __init__(self, func):
        try:
            super().__init__(func, internal=True)
            self.silent = True
        except Exception:
            pass

    def stop(self):
        try:
            try:
                a1 = gdb.parse_and_eval("(char*)$rdi").string(length=512)
                print(f"VM_TRACE_CMP1: {a1}")
            except Exception:
                pass
            try:
                a2 = gdb.parse_and_eval("(char*)$rsi").string(length=512)
                print(f"VM_TRACE_CMP2: {a2}")
            except Exception:
                pass
        except Exception:
            pass
        return False

class OutputHook(gdb.Breakpoint):
    def __init__(self, func):
        try:
            super().__init__(func, internal=True)
            self.silent = True
        except Exception:
            pass

    def stop(self):
        try:
            val = gdb.parse_and_eval("(char*)$rdi").string(length=1024)
            if val and len(val) > 1:
                print(f"VM_TRACE_OUT: {val}")
        except Exception:
            pass
        return False

for func in ["strcmp", "strncmp", "memcmp"]:
    try:
        CmpHook(func)
    except Exception:
        pass

for func in ["puts", "printf", "write"]:
    try:
        OutputHook(func)
    except Exception:
        pass

try:
    gdb.execute("run")
except gdb.error:
    pass

print("VM_TRACE_DONE")
'''

        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, dir="/tmp",
            ) as f:
                f.write(gdb_script)
                script_path = f.name

            cmd = ["gdb", "-batch", "-nx", "-q", "-x", script_path, self.binary]

            # Try with various inputs
            test_inputs = [
                "AAAA\n",
                f"{self.prefix}{{test}}\n",
                "A" * 32 + "\n",
            ]

            for test_input in test_inputs:
                result = subprocess.run(
                    cmd, capture_output=True, text=True,
                    timeout=self.timeout, input=test_input,
                    env={**os.environ, "TERM": "dumb"},
                )
                output = result.stdout + "\n" + result.stderr

                # Extract flags from trace output
                flags.extend(_find_flags(output, self.prefix))

                for line in output.splitlines():
                    for marker in ["VM_TRACE_CMP1:", "VM_TRACE_CMP2:", "VM_TRACE_OUT:"]:
                        if marker in line:
                            val = line.split(marker, 1)[-1].strip()
                            flags.extend(_find_flags(val, self.prefix))

                if flags:
                    break

            os.unlink(script_path)
        except subprocess.TimeoutExpired:
            print("[-] GDB VM trace timed out")
        except FileNotFoundError:
            print("[-] GDB not found")
        except Exception as e:
            print(f"[-] GDB VM trace error: {e}")

        if flags:
            print(f"[+] GDB trace found {len(flags)} flag(s)")
        else:
            print("[-] GDB trace: no flags")
        return flags

    # ----- Technique 6: Symbolic Execution -----
    def technique_symbolic(self) -> list[str]:
        """Use Z3 to solve VM program symbolically."""
        print("[*] Technique 6: symbolic VM execution")

        if not Z3_AVAILABLE:
            print("    [-] Z3 not available (pip install z3-solver)")
            return []

        if not self.opcodes:
            print("    [-] No opcodes available for symbolic execution")
            return []

        flags: list[str] = []

        for name, bytecode in self.bytecode_segments:
            print(f"    Solving bytecode '{name}' ({len(bytecode)} bytes)")
            solver = SymbolicVMSolver(self.opcodes, self.prefix)
            solution = solver.solve_bytecode(bytecode, self.input_length)
            if solution:
                found = _find_flags(solution, self.prefix)
                if found:
                    flags.extend(found)
                else:
                    # The solution itself might be the flag
                    print(f"    [*] Z3 solution (not flag pattern): {solution}")

        return flags

    # ----- Technique 7: Direct execution with various inputs -----
    def technique_brute_execute(self) -> list[str]:
        """Run the VM binary with various inputs to extract flag."""
        print("[*] Technique 7: direct execution with test inputs")

        flags: list[str] = []
        test_inputs = [
            "\n",
            "test\n",
            f"{self.prefix}{{test}}\n",
            "A" * 32 + "\n",
            "admin\n",
            "password\n",
            "flag\n",
        ]

        for test_input in test_inputs:
            try:
                result = subprocess.run(
                    [self.binary],
                    capture_output=True, text=True,
                    timeout=10, input=test_input,
                    preexec_fn=os.setsid,
                )
                output = result.stdout + "\n" + result.stderr
                found = _find_flags(output, self.prefix)
                if found:
                    flags.extend(found)
                    break

                # Check for hints about expected input format
                if re.search(r"(?:correct|right|success|win|congrat)", output, re.I):
                    print(f"    [+] Positive response to: {test_input.strip()}")
                    flags.extend(_find_flags(output, self.prefix))
                    break
            except subprocess.TimeoutExpired:
                continue
            except Exception:
                continue

        if flags:
            print(f"[+] Direct execution found {len(flags)} flag(s)")
        else:
            print("[-] Direct execution: no flags")
        return flags

    # ----- Main solve orchestrator -----
    def solve(self) -> list[str]:
        """Run all VM analysis techniques, return found flags."""
        print(f"[*] VM Analyzer: {self.binary}")
        if self.source_path:
            print(f"[*] Source: {self.source_path}")
        print(f"[*] Flag prefix: {self.prefix}")
        print()

        # Load source if available
        self._load_source()

        # Analysis pipeline
        strategies: list[tuple[str, callable]] = [
            ("VM detection", self.technique_detect_vm),
            ("opcode extraction", self.technique_extract_opcodes),
            ("bytecode extraction", self.technique_extract_bytecode),
            ("bytecode disassembly", self.technique_disassemble),
            ("GDB VM trace", self.technique_gdb_trace),
            ("direct execution", self.technique_brute_execute),
        ]

        # Run analysis techniques (non-flag-producing)
        for name, strategy_fn in strategies[:4]:
            try:
                result = strategy_fn()
                # Check if any technique produces flags
                if isinstance(result, list) and result and isinstance(result[0], str):
                    found = []
                    for item in result:
                        found.extend(_find_flags(item, self.prefix))
                    self.all_flags.extend(found)
            except Exception as e:
                print(f"[!] Technique '{name}' failed: {e}")
            print()

        # Run flag-extracting techniques
        for name, strategy_fn in strategies[4:]:
            try:
                flags = strategy_fn()
                if flags:
                    self.all_flags.extend(flags)
                    if self.all_flags:
                        break
            except Exception as e:
                print(f"[!] Technique '{name}' failed: {e}")
            print()

        # Try symbolic execution if we have opcodes and bytecode
        if not self.all_flags and self.opcodes and self.bytecode_segments:
            try:
                flags = self.technique_symbolic()
                self.all_flags.extend(flags)
            except Exception as e:
                print(f"[!] Symbolic execution failed: {e}")

        self.all_flags = _deduplicate(self.all_flags)

        if self.all_flags:
            self.all_flags.sort(
                key=lambda f: _score_flag(f, self.prefix), reverse=True,
            )
            best = self.all_flags[0]
            print(f"\nEXTRACTED FLAG: {best}")
            if len(self.all_flags) > 1:
                print(f"[*] Also found: {self.all_flags[1:]}")
        else:
            print("\n[-] No flags found via VM analysis.")
            if self.opcodes:
                print("[*] Opcodes were extracted - manual analysis may help.")
            if self.bytecode_segments:
                print("[*] Bytecode was extracted - try symbolic execution with more context.")

        return self.all_flags


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken VM Analyzer -- custom VM/bytecode interpreter analysis",
    )
    parser.add_argument("--binary", required=True, help="Path to the VM binary")
    parser.add_argument(
        "--source", default=None,
        help="Path to decompiled source code (C/pseudocode)",
    )
    parser.add_argument(
        "--bytecode", default=None,
        help="Path to raw bytecode file (if separate from binary)",
    )
    parser.add_argument(
        "--prefix", default="flag",
        help="Flag prefix (default: 'flag')",
    )
    parser.add_argument(
        "--input-length", type=int, default=32,
        help="Expected input/flag length for symbolic execution (default: 32)",
    )
    parser.add_argument(
        "--timeout", type=int, default=TECHNIQUE_TIMEOUT,
        help="Timeout per technique in seconds (default: 30)",
    )
    args = parser.parse_args()

    binary = os.path.abspath(args.binary)

    # Validate binary
    if not os.path.isfile(binary):
        print(f"[-] File not found: {binary}")
        sys.exit(1)

    if not _is_elf(binary):
        print(f"[!] Warning: {binary} may not be an ELF binary")

    # Ensure executable
    if not os.access(binary, os.X_OK):
        try:
            os.chmod(binary, os.stat(binary).st_mode | 0o111)
        except OSError as e:
            print(f"[-] Cannot make executable: {e}")

    analyzer = VMAnalyzer(
        binary_path=binary,
        source_path=args.source,
        bytecode_path=args.bytecode,
        prefix=args.prefix,
        input_length=args.input_length,
        timeout=args.timeout,
    )

    found = analyzer.solve()
    sys.exit(0 if found else 1)


if __name__ == "__main__":
    main()
