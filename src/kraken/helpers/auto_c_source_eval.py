#!/usr/bin/env python3
"""Evaluate C source arithmetic expressions and convert products to flag.

Handles patterns like:
  long long A = 79, B = 5568417557, ...
  a[] = { A * B },  b[] = { C * D * E * F * G }, ...

where the products encode flag bytes as hex pairs (e.g. 0x666c6167 -> "flag").
"""
import re
import sys
import argparse


def extract_constants(source: str) -> dict[str, int]:
    """Extract named integer constants from C source."""
    constants: dict[str, int] = {}
    # Match patterns like: A = 79, B = 5568417557
    for m in re.finditer(r'\b([A-Za-z_]\w*)\s*=\s*(-?\d+)', source):
        name, value = m.group(1), int(m.group(2))
        constants[name] = value
    return constants


def extract_expressions(source: str) -> list[str]:
    """Extract array initializer expressions like { A * B }."""
    exprs = []
    # Match { expr } patterns in array initializers
    for m in re.finditer(r'\{\s*([A-Za-z0-9_\s*+\-/()]+)\s*\}', source):
        expr = m.group(1).strip()
        if re.search(r'[A-Za-z]', expr):  # must have variable names
            exprs.append(expr)
    return exprs


def evaluate_expression(expr: str, constants: dict[str, int]) -> int | None:
    """Safely evaluate a C arithmetic expression with known constants."""
    # Replace variable names with their values
    safe_expr = expr
    for name, value in sorted(constants.items(), key=lambda x: -len(x[0])):
        safe_expr = re.sub(r'\b' + re.escape(name) + r'\b', str(value), safe_expr)

    # Only allow digits, operators, spaces, parens
    if not re.match(r'^[\d\s*+\-/()]+$', safe_expr):
        return None

    try:
        return eval(safe_expr)  # safe: only numeric expressions
    except Exception:
        return None


def hex_to_ascii(value: int) -> str:
    """Convert an integer to ASCII via its hex representation."""
    if value <= 0:
        return ""
    hex_str = hex(value)[2:]
    if len(hex_str) % 2:
        hex_str = "0" + hex_str
    try:
        return bytes.fromhex(hex_str).decode("ascii", errors="replace")
    except (ValueError, UnicodeDecodeError):
        return ""


def try_hex_comments(source: str) -> str | None:
    """Try to extract flag from hex comments in C source.

    Matches patterns like: // 666c61677b 73757033725f7634 ...
    Only accepts hex groups where even-length and decodes to printable ASCII.
    """
    for line in source.splitlines():
        m = re.search(r'//\s*((?:[0-9a-fA-F]+\s*)+)', line)
        if not m:
            continue
        parts = m.group(1).strip().split()
        # All parts must be even-length hex and contain at least one a-f
        hex_parts = []
        valid = True
        for p in parts:
            if len(p) % 2 != 0 or len(p) < 4:
                valid = False
                break
            if not all(c in "0123456789abcdefABCDEF" for c in p):
                valid = False
                break
            # Must have at least one hex letter to distinguish from decimal
            if not any(c in "abcdefABCDEF" for c in p):
                valid = False
                break
            hex_parts.append(p)

        if not valid or not hex_parts:
            continue

        combined = "".join(hex_parts)
        try:
            result = bytes.fromhex(combined).decode("ascii")
            # All bytes should be printable ASCII
            if all(32 <= ord(c) <= 126 for c in result) and len(result) >= 4:
                return result
        except (ValueError, UnicodeDecodeError):
            continue
    return None


def try_char_assignments(source: str) -> str | None:
    """Extract flag from char assignment patterns.

    Detects patterns like:
      final[0] = TWIST('f');
      final[1] = TWIST('l');
    or:
      buf[0] = 'H';
      buf[1] = 'e';
    """
    # Pattern 1: MACRO('char') or FUNC('char') assignments
    chars = re.findall(r"\[\s*\d+\s*\]\s*=\s*\w+\s*\(\s*'(.)'\s*\)", source)
    if len(chars) >= 4:
        result = "".join(chars)
        if all(32 <= ord(c) <= 126 for c in result):
            return result

    # Pattern 2: Direct char assignments: buf[N] = 'c';
    chars = re.findall(r"\[\s*\d+\s*\]\s*=\s*'(.)'\s*;", source)
    if len(chars) >= 4:
        result = "".join(chars)
        if all(32 <= ord(c) <= 126 for c in result):
            return result

    # Pattern 3: Hex byte assignments: buf[N] = 0x66;
    hex_chars = re.findall(r"\[\s*\d+\s*\]\s*=\s*0x([0-9a-fA-F]{2})\s*;", source)
    if len(hex_chars) >= 4:
        try:
            result = "".join(chr(int(h, 16)) for h in hex_chars)
            if all(32 <= ord(c) <= 126 for c in result):
                return result
        except (ValueError, OverflowError):
            pass

    return None


def main():
    parser = argparse.ArgumentParser(description="Kraken C Source Expression Evaluator")
    parser.add_argument("source", help="Path to C source file")
    args = parser.parse_args()

    try:
        with open(args.source) as f:
            source = f.read()
    except OSError as e:
        print(f"[-] Cannot read {args.source}: {e}")
        sys.exit(1)

    print(f"[*] Analyzing C source: {args.source}")

    # Method 1: Try hex comments first
    hex_flag = try_hex_comments(source)
    if hex_flag:
        print(f"[+] C_SOURCE_EVAL SUCCESS (hex comments)")
        print(f"[+] EXTRACTED FLAG: {hex_flag}")
        sys.exit(0)

    # Method 1.5: Try char assignment patterns (TWIST, direct char, hex bytes)
    char_flag = try_char_assignments(source)
    if char_flag:
        print(f"[+] C_SOURCE_EVAL SUCCESS (char assignments)")
        print(f"[+] EXTRACTED FLAG: {char_flag}")
        sys.exit(0)

    # Method 2: Evaluate arithmetic expressions
    constants = extract_constants(source)
    if not constants:
        print("[-] No constants found in source")
        sys.exit(1)

    print(f"[*] Found {len(constants)} constants")
    expressions = extract_expressions(source)
    if not expressions:
        print("[-] No array expressions found")
        sys.exit(1)

    print(f"[*] Found {len(expressions)} expressions")

    # Evaluate and convert
    flag_parts = []
    for expr in expressions:
        value = evaluate_expression(expr, constants)
        if value is not None:
            ascii_part = hex_to_ascii(value)
            if ascii_part:
                flag_parts.append(ascii_part)
                print(f"[*] {expr.strip()} = {value} = 0x{value:x} = '{ascii_part}'")

    if flag_parts:
        flag = "".join(flag_parts)
        print(f"\n[+] C_SOURCE_EVAL SUCCESS")
        print(f"[+] EXTRACTED FLAG: {flag}")
    else:
        print("[-] No valid flag parts extracted")
        sys.exit(1)


if __name__ == "__main__":
    main()
