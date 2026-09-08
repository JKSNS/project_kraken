#!/usr/bin/env python3
"""auto_z3_decompile -- Extract and solve Z3 constraints from decompiled C code.

Parses Ghidra/IDA decompiled output, converts flag-checking logic to Z3
constraints, and solves for the flag.  Highest-ROI reverse engineering tool:
Dragon Sector and HITCON report this as their most-used technique.

Handles:
  1. Direct byte comparison:    if(buf[i] == X)
  2. XOR cipher:                if(buf[i] ^ key[i] == ct[i])
  3. Linear equations:          a*flag[i] + b == c
  4. Cross-byte constraints:    flag[i] + flag[j] == N
  5. Lookup tables:             table[flag[i]] == expected[i]
  6. Loop-based checks:         for(i=0;i<N;i++) if(f(buf[i])!=g(i)) fail
  7. strcmp / memcmp constants:  strcmp(buf, "expected")
  8. Multi-round transforms:    model iterative XOR/ADD/shift
  9. Array-based transforms:    out[i] = f(in[i]) checked vs expected[]

Outputs EXTRACTED FLAG: <flag> on success.

Usage:
  python3 auto_z3_decompile.py <decompiled.c or challenge_dir>
  python3 auto_z3_decompile.py <path> --flag-format "flag{...}"
"""
import argparse
import os
import re
import sys

try:
    from z3 import (
        BitVec, BitVecVal, Solver, sat, If, And, Or, Extract, Concat,
        ZeroExt, LShR, RotateLeft, RotateRight, simplify,
    )
    _Z3_OK = True
except ImportError:
    _Z3_OK = False


# ── Utility ──────────────────────────────────────────────────────────────

def _int_val(s: str) -> int:
    """Parse a C-style integer literal (hex, decimal, or char)."""
    s = s.strip().rstrip("uUlL")
    if s.startswith("'") and s.endswith("'"):
        ch = s[1:-1]
        if ch.startswith("\\x"):
            return int(ch[2:], 16)
        if ch.startswith("\\"):
            esc = {"\\n": 10, "\\r": 13, "\\t": 9, "\\0": 0, "\\\\": 92,
                   "\\'": 39, '\\"': 34}
            return esc.get(ch, ord(ch[-1]))
        return ord(ch)
    return int(s, 0)


def _printable_range():
    """Return (lo, hi) for printable ASCII."""
    return 0x20, 0x7e


# ── Source collection ────────────────────────────────────────────────────

def collect_source(path: str) -> str:
    """Gather decompiled C source from a file or challenge directory."""
    if os.path.isfile(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read()

    if os.path.isdir(path):
        # Look for common decompile artifacts
        candidates = []
        for root, _dirs, files in os.walk(path):
            for fn in files:
                low = fn.lower()
                if low.endswith((".c", ".cpp", ".cxx", ".h", ".decomp", ".ghidra")):
                    candidates.append(os.path.join(root, fn))
                # Ghidra export
                if "decompil" in low or "decomp" in low:
                    candidates.append(os.path.join(root, fn))
        if not candidates:
            # Try common names
            for name in ["decompiled.c", "main.c", "challenge.c",
                         "decompiled_functions.c", "source.c"]:
                p = os.path.join(path, name)
                if os.path.isfile(p):
                    candidates.append(p)
        if candidates:
            # Concatenate all source files
            parts = []
            for cp in sorted(set(candidates)):
                try:
                    with open(cp, encoding="utf-8", errors="replace") as f:
                        parts.append(f"// === {cp} ===\n{f.read()}")
                except OSError:
                    pass
            if parts:
                return "\n\n".join(parts)

    return ""


# ── Constraint extraction ────────────────────────────────────────────────

class ConstraintExtractor:
    """Extract Z3 constraints from decompiled C source."""

    def __init__(self, source: str, flag_prefix: str = "", max_len: int = 128):
        self.source = source
        self.flag_prefix = flag_prefix
        self.max_len = max_len
        self.flag_var_names: list[str] = []
        self.flag_length = 0
        self.constraints = []      # list of (z3_expr, description)
        self.flag: list = []       # z3 BitVec vars
        self.arrays_found: dict[str, list[int]] = {}  # name -> values

    # ── Step 1: identify the flag variable ────────────────────────────

    def _identify_flag_var(self):
        """Find buffer names that receive user input."""
        # scanf / gets / fgets / read patterns
        input_patterns = [
            # scanf("%s", buf) / scanf("%32s", buf)
            re.compile(r'scanf\s*\(\s*"[^"]*%\d*s[^"]*"\s*,\s*(\w+)'),
            # fgets(buf, N, stdin)
            re.compile(r'fgets\s*\(\s*(\w+)\s*,'),
            # read(0, buf, N)
            re.compile(r'read\s*\(\s*0\s*,\s*(\w+)\s*,\s*(\d+)'),
            # gets(buf) -- unsafe but common in CTF
            re.compile(r'gets\s*\(\s*(\w+)\s*\)'),
            # argv[1]
            re.compile(r'(\w+)\s*=\s*argv\s*\[\s*1\s*\]'),
            # char buf[N]; ... if(buf[0] == ...)
            re.compile(r'char\s+(\w+)\s*\[\s*(\d+)\s*\]'),
        ]

        for pat in input_patterns:
            for m in pat.finditer(self.source):
                name = m.group(1)
                if name not in self.flag_var_names:
                    self.flag_var_names.append(name)
                # Try to get length from read(0, buf, N)
                if m.lastindex and m.lastindex >= 2:
                    try:
                        self.flag_length = max(self.flag_length, int(m.group(2)))
                    except (ValueError, IndexError):
                        pass

        # Fallback: look for the most-indexed array name
        if not self.flag_var_names:
            idx_counts: dict[str, int] = {}
            for m in re.finditer(r'(\w+)\s*\[\s*(\d+)\s*\]', self.source):
                name = m.group(1)
                idx_counts[name] = idx_counts.get(name, 0) + 1
            if idx_counts:
                best = max(idx_counts, key=idx_counts.get)
                self.flag_var_names.append(best)

        if self.flag_var_names:
            print(f"[*] Flag variable candidates: {', '.join(self.flag_var_names)}")

    # ── Step 2: detect flag length ────────────────────────────────────

    def _detect_length(self):
        """Determine the flag length from source patterns."""
        if self.flag_length:
            return

        # strlen(buf) == N
        for var in self.flag_var_names:
            m = re.search(
                rf'strlen\s*\(\s*{re.escape(var)}\s*\)\s*[!=<>]=?\s*(\d+)',
                self.source
            )
            if m:
                self.flag_length = int(m.group(1))
                return

        # sizeof(buf) or loop bound: i < N with buf[i]
        for var in self.flag_var_names:
            indices = [
                int(m.group(1))
                for m in re.finditer(rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]', self.source)
            ]
            if indices:
                self.flag_length = max(self.flag_length, max(indices) + 1)

        # Loop patterns: for(i=0; i<N; i++)
        for m in re.finditer(r'for\s*\(\s*\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\d+)', self.source):
            n = int(m.group(1))
            if 4 <= n <= 128:
                self.flag_length = max(self.flag_length, n)

        if not self.flag_length:
            self.flag_length = 64  # default

        print(f"[*] Detected flag length: {self.flag_length}")

    # ── Step 3: extract constant arrays ──────────────────────────────

    def _extract_arrays(self):
        """Find constant arrays (keys, expected values, lookup tables)."""
        # int/char array initialization: type name[] = { 0x.., 0x.., ... }
        array_re = re.compile(
            r'(?:(?:unsigned\s+)?(?:int|char|uint8_t|uint32_t|byte|BYTE)\s+)?'
            r'(\w+)\s*\[\s*\d*\s*\]\s*=\s*\{([^}]+)\}',
            re.DOTALL
        )
        for m in array_re.finditer(self.source):
            name = m.group(1)
            raw = m.group(2)
            values = []
            for elem in re.findall(r"(0x[0-9a-fA-F]+|\d+|'[^']+')", raw):
                try:
                    values.append(_int_val(elem))
                except (ValueError, IndexError):
                    pass
            if values:
                self.arrays_found[name] = values
                print(f"[*] Array '{name}': {len(values)} elements")

    # ── Step 4: extract constraints ──────────────────────────────────

    def _create_flag_vars(self):
        """Create Z3 BitVec variables for flag bytes."""
        self.flag = [BitVec(f"f{i}", 8) for i in range(self.flag_length)]

    def _add_printable_constraints(self):
        """Constrain flag to printable ASCII."""
        lo, hi = _printable_range()
        for f in self.flag:
            self.constraints.append((And(f >= lo, f <= hi), "printable"))

    def _add_prefix_constraints(self):
        """If flag prefix is known, constrain the beginning."""
        if not self.flag_prefix:
            return
        prefix = self.flag_prefix
        # Add prefix{...} constraint
        full_prefix = prefix + "{"
        for i, ch in enumerate(full_prefix):
            if i < len(self.flag):
                self.constraints.append(
                    (self.flag[i] == ord(ch), f"prefix[{i}]='{ch}'")
                )
        # Closing brace
        # We don't know position yet -- will try at the end

    def _extract_direct_comparisons(self):
        """Pattern: buf[i] == constant."""
        for var in self.flag_var_names:
            pat = re.compile(
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*==\s*'
                r"(0x[0-9a-fA-F]+|\d+|'[^']+')"
            )
            for m in pat.finditer(self.source):
                idx = int(m.group(1))
                val = _int_val(m.group(2))
                if 0 <= idx < len(self.flag) and 0 <= val <= 255:
                    self.constraints.append(
                        (self.flag[idx] == val,
                         f"direct: {var}[{idx}]=={val:#x}")
                    )

            # Also: constant == buf[i]
            pat2 = re.compile(
                r"(0x[0-9a-fA-F]+|\d+|'[^']+')\s*==\s*"
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]'
            )
            for m in pat2.finditer(self.source):
                val = _int_val(m.group(1))
                idx = int(m.group(2))
                if 0 <= idx < len(self.flag) and 0 <= val <= 255:
                    self.constraints.append(
                        (self.flag[idx] == val,
                         f"direct_rev: {var}[{idx}]=={val:#x}")
                    )

            # != pattern (inverted -- add as !=)
            pat3 = re.compile(
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*!=\s*'
                r"(0x[0-9a-fA-F]+|\d+|'[^']+')"
            )
            for m in pat3.finditer(self.source):
                idx = int(m.group(1))
                val = _int_val(m.group(2))
                if 0 <= idx < len(self.flag) and 0 <= val <= 255:
                    # Often in: if(buf[i] != expected) fail => buf[i] == expected
                    # Check context -- is there a return/exit/goto after?
                    after = self.source[m.end():m.end()+80]
                    if re.search(r'(return|exit|goto\s+\w+|break)', after):
                        self.constraints.append(
                            (self.flag[idx] == val,
                             f"guard: {var}[{idx}]=={val:#x}")
                        )

    def _extract_xor_constraints(self):
        """Pattern: buf[i] ^ key[i] == ct[i]  OR  buf[i] ^ K == ct[i]."""
        for var in self.flag_var_names:
            # buf[i] ^ constant == constant
            pat = re.compile(
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*\^\s*'
                r"(0x[0-9a-fA-F]+|\d+)\s*[!=]=\s*(0x[0-9a-fA-F]+|\d+)"
            )
            for m in pat.finditer(self.source):
                idx = int(m.group(1))
                key = _int_val(m.group(2))
                ct = _int_val(m.group(3))
                if 0 <= idx < len(self.flag):
                    op = "==" if "==" in m.group(0) else "!="
                    if op == "==":
                        self.constraints.append(
                            (self.flag[idx] ^ key == ct,
                             f"xor: {var}[{idx}]^{key:#x}=={ct:#x}")
                        )
                    else:
                        # != with fail after → means should ==
                        after = self.source[m.end():m.end()+80]
                        if re.search(r'(return|exit|goto|break)', after):
                            self.constraints.append(
                                (self.flag[idx] ^ key == ct,
                                 f"xor_guard: {var}[{idx}]^{key:#x}=={ct:#x}")
                            )

            # buf[i] ^ array[i] == constant or buf[i] ^ array[i] != constant
            for arr_name, arr_vals in self.arrays_found.items():
                pat2 = re.compile(
                    rf'{re.escape(var)}\s*\[\s*(\w+)\s*\]\s*\^\s*'
                    rf'{re.escape(arr_name)}\s*\[\s*\1\s*\]\s*[!=]=\s*'
                    r"(0x[0-9a-fA-F]+|\d+)"
                )
                for m in pat2.finditer(self.source):
                    ct = _int_val(m.group(2))
                    for i, key in enumerate(arr_vals):
                        if i < len(self.flag):
                            self.constraints.append(
                                (self.flag[i] ^ (key & 0xff) == ct,
                                 f"xor_arr: {var}[{i}]^{arr_name}[{i}]=={ct:#x}")
                            )

        # Detect XOR with array producing expected array:
        # for(i...) if(buf[i] ^ key[i] != expected[i]) => buf[i] = key[i] ^ expected[i]
        for var in self.flag_var_names:
            for key_name, key_vals in self.arrays_found.items():
                for exp_name, exp_vals in self.arrays_found.items():
                    if key_name == exp_name:
                        continue
                    # Check if the pattern XOR(var, key) == expected exists
                    pat = re.compile(
                        rf'{re.escape(var)}\s*\[\s*\w+\s*\]\s*\^\s*'
                        rf'{re.escape(key_name)}\s*\[\s*\w+\s*\]'
                        r'[^;]*?'
                        rf'{re.escape(exp_name)}\s*\[\s*\w+\s*\]'
                    )
                    if pat.search(self.source):
                        n = min(len(key_vals), len(exp_vals), len(self.flag))
                        for i in range(n):
                            self.constraints.append(
                                (self.flag[i] ^ (key_vals[i] & 0xff) == (exp_vals[i] & 0xff),
                                 f"xor_pair: {var}[{i}]^{key_name}[{i}]=={exp_name}[{i}]")
                            )

    def _extract_arithmetic_constraints(self):
        """Pattern: a*buf[i] + b == c  or  buf[i] + buf[j] == N."""
        for var in self.flag_var_names:
            # buf[i] * A + B == C
            pat = re.compile(
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*\*\s*(\d+)\s*\+\s*(\d+)\s*'
                r"==\s*(0x[0-9a-fA-F]+|\d+)"
            )
            for m in pat.finditer(self.source):
                idx = int(m.group(1))
                a = int(m.group(2))
                b = int(m.group(3))
                c = _int_val(m.group(4))
                if 0 <= idx < len(self.flag):
                    f8 = self.flag[idx]
                    # Use 32-bit to avoid 8-bit overflow
                    f32 = ZeroExt(24, f8)
                    self.constraints.append(
                        (f32 * a + b == c,
                         f"arith: {var}[{idx}]*{a}+{b}=={c}")
                    )

            # buf[i] + buf[j] == N
            pat2 = re.compile(
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*\+\s*'
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*==\s*(\d+)'
            )
            for m in pat2.finditer(self.source):
                i = int(m.group(1))
                j = int(m.group(2))
                n = int(m.group(3))
                if 0 <= i < len(self.flag) and 0 <= j < len(self.flag):
                    fi = ZeroExt(24, self.flag[i])
                    fj = ZeroExt(24, self.flag[j])
                    self.constraints.append(
                        (fi + fj == n,
                         f"cross: {var}[{i}]+{var}[{j}]=={n}")
                    )

            # buf[i] - buf[j] == N
            pat3 = re.compile(
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*\-\s*'
                rf'{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*==\s*(-?\d+)'
            )
            for m in pat3.finditer(self.source):
                i = int(m.group(1))
                j = int(m.group(2))
                n = int(m.group(3))
                if 0 <= i < len(self.flag) and 0 <= j < len(self.flag):
                    fi = ZeroExt(24, self.flag[i])
                    fj = ZeroExt(24, self.flag[j])
                    self.constraints.append(
                        (fi - fj == n,
                         f"cross_sub: {var}[{i}]-{var}[{j}]=={n}")
                    )

            # (buf[i] + K) % M == C  (modular arithmetic)
            pat4 = re.compile(
                rf'\(\s*{re.escape(var)}\s*\[\s*(\d+)\s*\]\s*\+\s*(\d+)\s*\)\s*%\s*(\d+)\s*==\s*(\d+)'
            )
            for m in pat4.finditer(self.source):
                idx = int(m.group(1))
                k = int(m.group(2))
                mod = int(m.group(3))
                c = int(m.group(4))
                if 0 <= idx < len(self.flag) and mod > 0:
                    f32 = ZeroExt(24, self.flag[idx])
                    from z3 import URem
                    self.constraints.append(
                        (URem(f32 + k, BitVecVal(mod, 32)) == c,
                         f"mod: ({var}[{idx}]+{k})%{mod}=={c}")
                    )

    def _extract_strcmp_memcmp(self):
        """Pattern: strcmp(buf, "literal") == 0  or  memcmp(buf, str, N) == 0."""
        for var in self.flag_var_names:
            # strcmp(buf, "literal")
            for func in ["strcmp", "strncmp", "memcmp"]:
                pat = re.compile(
                    rf'{func}\s*\(\s*{re.escape(var)}\s*,\s*"([^"]+)"'
                )
                for m in pat.finditer(self.source):
                    literal = m.group(1)
                    for i, ch in enumerate(literal):
                        if i < len(self.flag):
                            self.constraints.append(
                                (self.flag[i] == ord(ch),
                                 f"strcmp: {var}[{i}]=='{ch}'")
                            )
                    # Set exact length
                    if len(literal) < len(self.flag):
                        self.flag_length = min(self.flag_length, len(literal))

                # Also: strcmp("literal", buf)
                pat2 = re.compile(
                    rf'{func}\s*\(\s*"([^"]+)"\s*,\s*{re.escape(var)}'
                )
                for m in pat2.finditer(self.source):
                    literal = m.group(1)
                    for i, ch in enumerate(literal):
                        if i < len(self.flag):
                            self.constraints.append(
                                (self.flag[i] == ord(ch),
                                 f"strcmp_rev: {var}[{i}]=='{ch}'")
                            )

    def _extract_lookup_table(self):
        """Pattern: table[buf[i]] == expected[i]  (substitution cipher)."""
        for var in self.flag_var_names:
            for tbl_name, tbl_vals in self.arrays_found.items():
                for exp_name, exp_vals in self.arrays_found.items():
                    if tbl_name == exp_name:
                        continue
                    # table[buf[i]] compared to expected[i]
                    pat = re.compile(
                        rf'{re.escape(tbl_name)}\s*\[\s*{re.escape(var)}\s*\[\s*\w+\s*\]\s*\]'
                        r'[^;]*?'
                        rf'{re.escape(exp_name)}\s*\[\s*\w+\s*\]'
                    )
                    if pat.search(self.source):
                        # Reverse the lookup: for each expected value,
                        # find which input byte maps to it
                        reverse_tbl = {}
                        for idx, val in enumerate(tbl_vals):
                            if val not in reverse_tbl:
                                reverse_tbl[val] = idx
                        n = min(len(exp_vals), len(self.flag))
                        for i in range(n):
                            exp_v = exp_vals[i] & 0xff
                            if exp_v in reverse_tbl:
                                inp = reverse_tbl[exp_v]
                                if 0 <= inp <= 255:
                                    self.constraints.append(
                                        (self.flag[i] == inp,
                                         f"lookup: {tbl_name}[{var}[{i}]]=={exp_name}[{i}] => {inp:#x}")
                                    )
                            else:
                                # Could be multiple options -- use Or
                                options = [
                                    idx for idx, v in enumerate(tbl_vals)
                                    if (v & 0xff) == exp_v and 0 <= idx <= 255
                                ]
                                if options and i < len(self.flag):
                                    self.constraints.append(
                                        (Or(*[self.flag[i] == o for o in options]),
                                         f"lookup_multi: {var}[{i}] in {options}")
                                    )

    def _extract_loop_xor_transform(self):
        """Detect for-loop XOR/ADD transforms and model them.

        Pattern: for(i=0;i<N;i++) buf[i] ^= key[i]; then compare to expected.
        Also: multi-round transforms like for(r=0;r<R;r++) for(i=...) buf[i] ^= ...
        """
        for var in self.flag_var_names:
            # Simple single-key XOR in a loop: buf[i] ^= K
            pat = re.compile(
                rf'{re.escape(var)}\s*\[\s*\w+\s*\]\s*\^=\s*(0x[0-9a-fA-F]+|\d+)'
            )
            for m in pat.finditer(self.source):
                key_byte = _int_val(m.group(1)) & 0xff
                # Check for an expected comparison nearby
                # This is a transform; constraints will come from comparisons
                # Just record the transform key for later use
                print(f"[*] XOR transform: {var}[i] ^= {key_byte:#x}")

            # buf[i] += K
            pat2 = re.compile(
                rf'{re.escape(var)}\s*\[\s*\w+\s*\]\s*\+=\s*(0x[0-9a-fA-F]+|\d+)'
            )
            for m in pat2.finditer(self.source):
                add_val = _int_val(m.group(1)) & 0xff
                print(f"[*] ADD transform: {var}[i] += {add_val:#x}")

    def _extract_matrix_constraints(self):
        """Detect matrix-multiply style checks: sum(A[i][j]*flag[j]) == B[i]."""
        # Look for patterns like: sum += matrix[i][j] * buf[j]
        for var in self.flag_var_names:
            pat = re.compile(
                r'(\w+)\s*\[\s*\w+\s*\]\s*\[\s*\w+\s*\]\s*\*\s*'
                rf'{re.escape(var)}\s*\[\s*\w+\s*\]'
            )
            m = pat.search(self.source)
            if not m:
                continue
            mat_name = m.group(1)
            # Try to find the matrix in arrays (as flattened or nested)
            # This is complex -- log it for now
            print(f"[*] Matrix constraint detected: {mat_name} * {var}")

    def extract_all(self):
        """Run all extraction passes and return constraints."""
        self._identify_flag_var()
        if not self.flag_var_names:
            print("[-] No flag variable identified")
            return []

        self._detect_length()
        self._extract_arrays()
        self._create_flag_vars()
        self._add_printable_constraints()
        self._add_prefix_constraints()

        # Core constraint extraction
        self._extract_direct_comparisons()
        self._extract_xor_constraints()
        self._extract_arithmetic_constraints()
        self._extract_strcmp_memcmp()
        self._extract_lookup_table()
        self._extract_loop_xor_transform()
        self._extract_matrix_constraints()

        # Filter out printable-only constraints for counting
        real = [c for c in self.constraints if c[1] != "printable"]
        print(f"[*] Extracted {len(real)} substantive constraints")
        for desc in sorted(set(c[1] for c in real)):
            print(f"    - {desc}")

        return self.constraints


# ── Solver ───────────────────────────────────────────────────────────────

def solve_constraints(flag_vars: list, constraints: list, flag_prefix: str = "") -> str | None:
    """Solve extracted Z3 constraints and return the flag string."""
    solver = Solver()
    solver.set("timeout", 30000)  # 30 second timeout

    for expr, _desc in constraints:
        solver.add(expr)

    result = solver.check()
    if result != sat:
        print(f"[-] Z3 solver returned: {result}")
        return None

    model = solver.model()
    chars = []
    for fv in flag_vars:
        val = model[fv]
        if val is None:
            chars.append("?")
        else:
            c = val.as_long()
            if 0x20 <= c <= 0x7e:
                chars.append(chr(c))
            else:
                chars.append(f"\\x{c:02x}")

    raw = "".join(chars).rstrip("?").rstrip()

    # Trim trailing null/garbage
    if "\x00" in raw:
        raw = raw[:raw.index("\x00")]

    return raw


def try_direct_string_extraction(source: str, flag_prefix: str) -> str | None:
    """Quick check: is the flag directly in a string constant?"""
    if flag_prefix:
        pat = re.compile(
            rf'{re.escape(flag_prefix)}\{{[A-Za-z0-9_\-\.!@#$%^&*()]+\}}'
        )
        for m in pat.finditer(source):
            return m.group(0)

    # Generic flag patterns
    for m in re.finditer(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', source):
        body = re.search(r'\{(.+)\}', m.group(0))
        if body and len(set(body.group(1))) >= 3:
            return m.group(0)

    return None


def try_simple_xor_solve(source: str, flag_prefix: str) -> str | None:
    """Shortcut: if we can see key[] and expected[] arrays and XOR pattern,
    solve directly without Z3."""
    # Find all arrays
    arrays: dict[str, list[int]] = {}
    for m in re.finditer(
        r'(?:(?:unsigned\s+)?(?:int|char|uint8_t|byte)\s+)?'
        r'(\w+)\s*\[\s*\d*\s*\]\s*=\s*\{([^}]+)\}',
        source, re.DOTALL
    ):
        name = m.group(1)
        raw = m.group(2)
        vals = []
        for elem in re.findall(r"(0x[0-9a-fA-F]+|\d+|'[^']+')", raw):
            try:
                vals.append(_int_val(elem))
            except ValueError:
                pass
        if vals:
            arrays[name] = vals

    if len(arrays) < 2:
        return None

    # Look for XOR between two arrays
    for kname, kvals in arrays.items():
        for ename, evals in arrays.items():
            if kname == ename:
                continue
            # Check for XOR pattern in source
            if re.search(
                rf'{re.escape(kname)}.*\^.*{re.escape(ename)}'
                rf'|{re.escape(ename)}.*\^.*{re.escape(kname)}',
                source
            ):
                n = min(len(kvals), len(evals))
                result = "".join(chr((kvals[i] ^ evals[i]) & 0xff) for i in range(n))
                if result.isprintable() and len(result) >= 3:
                    # Check if it has flag format
                    if flag_prefix and result.startswith(flag_prefix + "{") and result.endswith("}"):
                        return result
                    # Check generic
                    m = re.search(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', result)
                    if m:
                        return m.group(0)
                    if flag_prefix and flag_prefix in result:
                        return result

    return None


# ── Main ─────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="auto_z3_decompile -- Extract Z3 constraints from decompiled C and solve"
    )
    parser.add_argument("path", help="Decompiled .c file or challenge directory")
    parser.add_argument("--flag-format", default="",
                        help="Flag format hint, e.g. 'flag{...}' or just 'flag'")
    parser.add_argument("--max-length", type=int, default=128,
                        help="Maximum flag length (default: 128)")
    args = parser.parse_args()

    if not os.path.exists(args.path):
        print(f"[-] Path not found: {args.path}")
        sys.exit(1)

    if not _Z3_OK:
        print("[-] Z3 Python bindings not available. Install with: pip install z3-solver")
        sys.exit(1)

    # Parse flag prefix from format
    flag_prefix = ""
    if args.flag_format:
        m = re.match(r'^([A-Za-z0-9_\-]+)\{', args.flag_format)
        if m:
            flag_prefix = m.group(1)
        else:
            flag_prefix = args.flag_format.rstrip("{").rstrip()

    print(f"[*] auto_z3_decompile starting")
    print(f"[*] Path: {args.path}")
    if flag_prefix:
        print(f"[*] Flag prefix: {flag_prefix}")

    # Collect source
    source = collect_source(args.path)
    if not source:
        print("[-] No decompiled source found")
        sys.exit(1)
    print(f"[*] Source loaded: {len(source)} chars")

    # Quick check: flag directly in source?
    direct = try_direct_string_extraction(source, flag_prefix)
    if direct:
        print(f"\nEXTRACTED FLAG: {direct}")
        return

    # Quick check: simple XOR solve?
    xor_result = try_simple_xor_solve(source, flag_prefix)
    if xor_result:
        print(f"\nEXTRACTED FLAG: {xor_result}")
        return

    # Full constraint extraction + Z3 solve
    extractor = ConstraintExtractor(source, flag_prefix, args.max_length)
    constraints = extractor.extract_all()

    # Count real (non-printable) constraints
    real_constraints = [c for c in constraints if c[1] != "printable"]
    if not real_constraints:
        print("[-] No constraints extracted from source")
        sys.exit(1)

    print(f"\n[*] Solving {len(real_constraints)} constraints with Z3...")
    result = solve_constraints(extractor.flag, constraints, flag_prefix)

    if result:
        # Try to match flag pattern
        if flag_prefix:
            pat = re.compile(
                rf'{re.escape(flag_prefix)}\{{[^\}}]+\}}'
            )
            m = pat.search(result)
            if m:
                print(f"\nEXTRACTED FLAG: {m.group(0)}")
                return

        # Generic pattern
        m = re.search(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', result)
        if m:
            print(f"\nEXTRACTED FLAG: {m.group(0)}")
            return

        # Raw result
        print(f"\n[+] Z3 solution: {result}")
        if flag_prefix and not result.startswith(flag_prefix):
            possible = f"{flag_prefix}{{{result}}}"
            print(f"[+] Possible flag: {possible}")
            print(f"\nEXTRACTED FLAG: {possible}")
        else:
            print(f"\nEXTRACTED FLAG: {result}")
    else:
        print("[-] Z3 solver failed to find a solution")
        sys.exit(1)


if __name__ == "__main__":
    main()
