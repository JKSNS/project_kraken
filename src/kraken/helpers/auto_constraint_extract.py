#!/usr/bin/env python3
"""auto_constraint_extract -- Extract flags from scripting constraint challenges.

Deterministically parses JS/Python source files for character-by-character
flag constraints and reconstructs the flag without needing an LLM.

Handles patterns like:
  JS:  flag[0] === 'v', flag.charCodeAt(1) === 101, flag.charAt(2) === 'r'
  Py:  flag[0] == 'v', ord(flag[0]) == 118, flag[i] ^ key[i] == expected[i]

Outputs EXTRACTED FLAG: <flag> on success.
"""
import os
import re
import sys


def _extract_js_char_constraints(text: str) -> dict[int, int]:
    """Extract character constraints from JS source.

    Returns dict mapping position -> char code.
    """
    constraints: dict[int, int] = {}

    # Pattern: flag[N] === 'c' or flag[N] == 'c' (single char)
    for m in re.finditer(
        r"""(?:flag|input|key|ans|password|secret|pw|pass)\s*\[\s*(\d+)\s*\]\s*[!=]==?\s*['"](.)['"]""",
        text,
    ):
        pos = int(m.group(1))
        constraints[pos] = ord(m.group(2))

    # Pattern: flag.charAt(N) === 'c'
    for m in re.finditer(
        r"""(?:flag|input|key|ans|password|secret|pw|pass)\.charAt\s*\(\s*(\d+)\s*\)\s*[!=]==?\s*['"](.)['"]""",
        text,
    ):
        pos = int(m.group(1))
        constraints[pos] = ord(m.group(2))

    # Pattern: flag.charCodeAt(N) === NN
    for m in re.finditer(
        r"""(?:flag|input|key|ans|password|secret|pw|pass)\.charCodeAt\s*\(\s*(\d+)\s*\)\s*[!=]==?\s*(\d+)""",
        text,
    ):
        pos = int(m.group(1))
        constraints[pos] = int(m.group(2))

    # Pattern: 'c' === flag[N] or 'c' == flag[N] (reversed comparison)
    for m in re.finditer(
        r"""['"](.)['\"]\s*[!=]==?\s*(?:flag|input|key|ans|password|secret|pw|pass)\s*\[\s*(\d+)\s*\]""",
        text,
    ):
        pos = int(m.group(2))
        if pos not in constraints:
            constraints[pos] = ord(m.group(1))

    # Pattern: NN === flag.charCodeAt(N) (reversed)
    for m in re.finditer(
        r"""(\d+)\s*[!=]==?\s*(?:flag|input|key|ans|password|secret|pw|pass)\.charCodeAt\s*\(\s*(\d+)\s*\)""",
        text,
    ):
        pos = int(m.group(2))
        if pos not in constraints:
            constraints[pos] = int(m.group(1))

    return constraints


def _extract_js_length(text: str) -> int:
    """Extract flag length constraint from JS source."""
    # flag.length === N
    m = re.search(
        r"""(?:flag|input|key|ans|password|secret|pw|pass)\.length\s*[!=]==?\s*(\d+)""",
        text,
    )
    if m:
        return int(m.group(1))

    # N === flag.length (reversed)
    m = re.search(
        r"""(\d+)\s*[!=]==?\s*(?:flag|input|key|ans|password|secret|pw|pass)\.length""",
        text,
    )
    if m:
        return int(m.group(1))

    return 0


def _extract_js_substring(text: str) -> dict[int, int]:
    """Extract substring/slice comparisons."""
    constraints: dict[int, int] = {}

    # flag.substring(a, b) === 'str' or flag.slice(a, b) === 'str'
    for m in re.finditer(
        r"""(?:flag|input|key|ans|password|secret|pw|pass)\.(?:substring|slice)\s*\(\s*(\d+)\s*,\s*(\d+)\s*\)\s*[!=]==?\s*['"]([^'"]+)['"]""",
        text,
    ):
        start = int(m.group(1))
        value = m.group(3)
        for i, c in enumerate(value):
            pos = start + i
            if pos not in constraints:
                constraints[pos] = ord(c)

    return constraints


def _extract_py_char_constraints(text: str) -> dict[int, int]:
    """Extract character constraints from Python source.

    Returns dict mapping position -> char code.
    """
    constraints: dict[int, int] = {}

    # Pattern: flag[N] == 'c'
    for m in re.finditer(
        r"""(?:flag|inp|user_input|password|secret|key|ans)\s*\[\s*(\d+)\s*\]\s*[!=]=\s*['"](.)['"]""",
        text,
    ):
        pos = int(m.group(1))
        constraints[pos] = ord(m.group(2))

    # Pattern: ord(flag[N]) == NN
    for m in re.finditer(
        r"""ord\s*\(\s*(?:flag|inp|user_input|password|secret|key|ans)\s*\[\s*(\d+)\s*\]\s*\)\s*[!=]=\s*(\d+)""",
        text,
    ):
        pos = int(m.group(1))
        constraints[pos] = int(m.group(2))

    return constraints


def _extract_py_length(text: str) -> int:
    """Extract flag length constraint from Python source."""
    m = re.search(
        r"""len\s*\(\s*(?:flag|inp|user_input|password|secret|key|ans)\s*\)\s*[!=]=\s*(\d+)""",
        text,
    )
    if m:
        return int(m.group(1))
    return 0


def _extract_xor_arrays(text: str) -> dict[int, int]:
    """Extract flag from XOR key/expected pairs in Python/JS.

    Handles patterns like:
      key = [0x12, 0x34, ...]
      expected = [0x56, 0x78, ...]
      where flag[i] ^ key[i] == expected[i]
    """
    constraints: dict[int, int] = {}

    # Find array assignments with hex or int literals
    arrays: dict[str, list[int]] = {}
    for m in re.finditer(
        r"""(\w+)\s*=\s*\[([^\]]{5,})\]""",
        text,
    ):
        name = m.group(1).lower()
        body = m.group(2)
        # Parse array elements (hex or decimal)
        elems = []
        for num_m in re.finditer(r'0x([0-9a-fA-F]+)|(\d+)', body):
            if num_m.group(1):
                elems.append(int(num_m.group(1), 16))
            elif num_m.group(2):
                val = int(num_m.group(2))
                if val < 256:
                    elems.append(val)
        if len(elems) >= 3:
            arrays[name] = elems

    # Look for XOR pattern: flag[i] ^ key[i] == expected[i]
    xor_m = re.search(
        r"""(?:flag|inp|input|msg)\s*\[\s*\w+\s*\]\s*\^\s*(\w+)\s*\[\s*\w+\s*\]\s*[!=]=\s*(\w+)\s*\[\s*\w+\s*\]"""
        r"""|(\w+)\s*\[\s*\w+\s*\]\s*\^\s*(?:flag|inp|input|msg)\s*\[\s*\w+\s*\]\s*[!=]=\s*(\w+)\s*\[\s*\w+\s*\]""",
        text,
    )
    if xor_m:
        key_name = (xor_m.group(1) or xor_m.group(3) or "").lower()
        exp_name = (xor_m.group(2) or xor_m.group(4) or "").lower()
        key_arr = arrays.get(key_name, [])
        exp_arr = arrays.get(exp_name, [])
        if key_arr and exp_arr and len(key_arr) == len(exp_arr):
            for i in range(len(key_arr)):
                constraints[i] = key_arr[i] ^ exp_arr[i]
            return constraints

    # Also try: zip-based XOR pattern
    # [ord(c) ^ k for c, k in zip(msg, key)] == expected
    # or: [c ^ k for c, k in zip(encoded, key)]
    # If we have exactly 2 arrays of same length that XOR to printable ASCII, try it
    arr_names = list(arrays.keys())
    for i in range(len(arr_names)):
        for j in range(i + 1, len(arr_names)):
            a = arrays[arr_names[i]]
            b = arrays[arr_names[j]]
            if len(a) != len(b) or len(a) < 5:
                continue
            xored = [x ^ y for x, y in zip(a, b)]
            # Check if result is mostly printable ASCII
            printable = sum(1 for c in xored if 32 <= c <= 126)
            if printable > len(xored) * 0.8:
                for k, c in enumerate(xored):
                    constraints[k] = c
                return constraints

    return constraints


def _extract_direct_comparison(text: str) -> str:
    """Extract flag from direct string comparison.

    Handles: flag === 'literal' / flag == 'literal' / input == 'literal'
    """
    # Direct equality with long enough string
    for m in re.finditer(
        r"""(?:flag|input|key|ans|password|secret|pw|pass)\s*[!=]==?\s*['"]([^'"]{6,})['"]""",
        text,
    ):
        candidate = m.group(1)
        # Must look like a flag (contains { or is all printable)
        if '{' in candidate or candidate.isprintable():
            return candidate

    # Reversed: 'literal' === flag
    for m in re.finditer(
        r"""['"]([^'"]{6,})['"]\s*[!=]==?\s*(?:flag|input|key|ans|password|secret|pw|pass)""",
        text,
    ):
        candidate = m.group(1)
        if '{' in candidate or candidate.isprintable():
            return candidate

    return ""


def _build_flag(constraints: dict[int, int], length: int = 0) -> str:
    """Build flag string from position -> char code map."""
    if not constraints:
        return ""

    max_pos = max(constraints.keys())
    if length:
        max_pos = max(max_pos, length - 1)

    result = []
    for i in range(max_pos + 1):
        if i in constraints:
            c = constraints[i]
            if 32 <= c <= 126:
                result.append(chr(c))
            else:
                result.append('?')
        else:
            result.append('?')

    flag = "".join(result)

    # Only return if we have enough known characters (>70%)
    known = sum(1 for c in flag if c != '?')
    if known < len(flag) * 0.7:
        return ""

    return flag


def _solve_js_via_node(text: str, filepath: str) -> str:
    """Solve obfuscated JS constraint challenges by brute-forcing in Node.js.

    Detects if-statement with &&-connected conditions on flag[i].charCodeAt(),
    generates a Node.js solver that brute-forces each character position, and
    returns the recovered flag.  Works with arbitrarily obfuscated index/value
    expressions because Node.js evaluates them natively.
    """
    import shutil
    import subprocess
    import tempfile

    if not shutil.which("node"):
        return ""

    # Must have: flag variable with charCodeAt checks connected by &&
    if "charCodeAt" not in text or "&&" not in text:
        return ""

    # Extract the flag length
    length_m = re.search(r'\.length\s*[!=]==?\s*(\d+)', text)
    if not length_m:
        return ""
    flag_len = int(length_m.group(1))
    if flag_len < 4 or flag_len > 200:
        return ""

    # Detect the flag variable name (what receives prompt/readline/argv input)
    var_m = re.search(
        r"""(?:let|var|const)\s+(\w+)\s*=\s*(?:prompt|readline|process\.argv)""",
        text,
    )
    flag_var = var_m.group(1) if var_m else "flag"

    # Extract the full condition from if(...) using balanced parenthesis matching
    condition = ""
    for if_m in re.finditer(r'if\s*\(', text):
        start = if_m.end() - 1  # point at the '('
        depth = 0
        end = start
        for i in range(start, len(text)):
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        candidate = text[start + 1:end].strip()
        # Pick the condition with the most && (the constraint block)
        if candidate.count("&&") > condition.count("&&"):
            condition = candidate
    if not condition or condition.count("&&") < 3:
        return ""

    # Generate a Node.js brute-force solver
    solver_js = f"""
// Mock browser globals for Node.js compatibility
if (typeof document === 'undefined') {{
    // Match browser's document.toString() = "[object HTMLDocument]"
    global.document = {{ toString() {{ return "[object HTMLDocument]"; }} }};
}}

// Split conditions at top-level && boundaries
function splitConditions(expr) {{
    const parts = [];
    let depth = 0, start = 0;
    for (let i = 0; i < expr.length; i++) {{
        if (expr[i] === '(') depth++;
        else if (expr[i] === ')') depth--;
        else if (expr[i] === '&' && expr[i+1] === '&' && depth <= 1) {{
            parts.push(expr.slice(start, i).trim());
            start = i + 2;
        }}
    }}
    parts.push(expr.slice(start).trim());
    return parts.filter(p => p.length > 0);
}}

const condition = {repr(condition)};
const parts = splitConditions(condition);
const N = {flag_len};
const {flag_var} = new Array(N).fill('A');

// For each condition (except length check), brute-force the character
for (const part of parts) {{
    if (part.includes('.length')) continue;

    let found = false;
    for (let pos = 0; pos < N && !found; pos++) {{
        const saved = {flag_var}[pos];
        // Check if condition already passes without touching this position
        try {{ if (eval(part)) {{ {flag_var}[pos] = saved; continue; }} }} catch (e) {{}}
        for (let c = 32; c < 127; c++) {{
            {flag_var}[pos] = String.fromCharCode(c);
            try {{
                if (eval(part)) {{
                    // Verify this position actually matters: restore saved and check it fails
                    {flag_var}[pos] = saved;
                    let stillPasses = false;
                    try {{ stillPasses = eval(part); }} catch (e2) {{}}
                    if (stillPasses) {{
                        // This position doesn't affect the condition -- skip it
                        continue;
                    }}
                    {flag_var}[pos] = String.fromCharCode(c);
                    found = true;
                    break;
                }}
            }} catch (e) {{}}
        }}
        if (!found) {flag_var}[pos] = saved;
    }}
}}

const result = {flag_var}.join('');
// Verify: check all conditions pass together
try {{
    if (eval(condition)) {{
        console.log('EXTRACTED FLAG: ' + result);
    }} else {{
        // Partial result -- output anyway for prefix-wrapping
        console.log(result);
    }}
}} catch (e) {{
    console.log(result);
}}
"""

    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".js", delete=False, dir=os.path.dirname(filepath)
        ) as f:
            f.write(solver_js)
            solver_path = f.name

        proc = subprocess.run(
            ["node", solver_path],
            capture_output=True, text=True, timeout=30,
        )
        os.unlink(solver_path)

        output = proc.stdout.strip()
        if not output:
            return ""

        # Check for EXTRACTED FLAG marker
        m = re.search(r'EXTRACTED FLAG:\s*(.+)', output)
        if m:
            return m.group(1).strip()

        # Return raw output if it's mostly printable
        if len(output) >= 4 and output.isprintable():
            return output

    except (subprocess.TimeoutExpired, OSError):
        try:
            os.unlink(solver_path)
        except Exception:
            pass

    return ""


def scan_file(filepath: str) -> list[str]:
    """Scan a source file for constraint-based flag extraction."""
    try:
        text = open(filepath, encoding="utf-8", errors="replace").read()
    except OSError:
        return []

    results = []
    ext = os.path.splitext(filepath)[1].lower()

    # Strategy 1: Direct string comparison
    direct = _extract_direct_comparison(text)
    if direct:
        results.append(direct)

    # Strategy 2: Character-by-character constraints
    constraints: dict[int, int] = {}
    length = 0

    if ext in (".js", ".ts", ".html"):
        constraints.update(_extract_js_char_constraints(text))
        constraints.update(_extract_js_substring(text))
        length = _extract_js_length(text)
    elif ext in (".py", ".rb"):
        constraints.update(_extract_py_char_constraints(text))
        length = _extract_py_length(text)
    else:
        # Try both
        constraints.update(_extract_js_char_constraints(text))
        constraints.update(_extract_js_substring(text))
        constraints.update(_extract_py_char_constraints(text))
        length = _extract_js_length(text) or _extract_py_length(text)

    flag = _build_flag(constraints, length)
    if flag:
        results.append(flag)

    # Strategy 3: XOR array pairs
    xor_constraints = _extract_xor_arrays(text)
    xor_flag = _build_flag(xor_constraints)
    if xor_flag and xor_flag != flag:
        results.append(xor_flag)

    # Strategy 4: Node.js brute-force for obfuscated JS constraints
    if ext in (".js", ".ts", ".html") and not results:
        node_flag = _solve_js_via_node(text, filepath)
        if node_flag:
            results.append(node_flag)

    return results


def main():
    if len(sys.argv) < 2:
        print("Usage: auto_constraint_extract.py <file_or_dir> [--flag-format FORMAT]", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    flag_format = ""
    if "--flag-format" in sys.argv:
        idx = sys.argv.index("--flag-format")
        if idx + 1 < len(sys.argv):
            flag_format = sys.argv[idx + 1]

    # Collect files
    files = []
    _EXTS = {".js", ".py", ".php", ".rb", ".ts", ".c", ".html"}
    _SKIP_DIRS = {"node_modules", ".git", "__pycache__", "solutions", ".venv", "venv"}
    if os.path.isdir(target):
        for name in os.listdir(target):
            if name.startswith("solve_attempt") or name in _SKIP_DIRS:
                continue
            full = os.path.join(target, name)
            if os.path.isdir(full):
                continue
            ext = os.path.splitext(name)[1].lower()
            if ext in _EXTS:
                files.append(full)
    elif os.path.isfile(target):
        files.append(target)
    else:
        print(f"Not found: {target}", file=sys.stderr)
        sys.exit(1)

    all_candidates = []
    for f in files:
        candidates = scan_file(f)
        all_candidates.extend(candidates)

    if not all_candidates:
        print("No constraints found", file=sys.stderr)
        sys.exit(1)

    # Check for flag patterns
    flag_pattern = re.compile(r'[a-zA-Z_]{2,}\{[^}]{3,}\}')
    for c in all_candidates:
        m = flag_pattern.search(c)
        if m:
            print(f"EXTRACTED FLAG: {m.group(0)}")
            sys.exit(0)

    # Output raw candidates for prefix-wrapping
    print("=== Constraint-extracted candidates: ===")
    for c in all_candidates:
        c = c.strip()
        if len(c) >= 4 and c.isprintable():
            print(c)


if __name__ == "__main__":
    main()
