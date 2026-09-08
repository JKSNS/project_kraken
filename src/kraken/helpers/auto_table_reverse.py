#!/usr/bin/env python3
"""Reverse substitution-table ciphers from C source with header includes.

Detects C programs that use a translation table (table-inc.h) to encrypt
input and compare against stored ciphertext (flag-inc.h). Builds the
reverse lookup table and decrypts the flag.

Patterns detected:
  - table-inc.h: { src, dst } pairs defining a byte substitution
  - flag-inc.h: char ans[] = "\\xNN\\xNN..." encrypted flag bytes
"""
import os
import re
import sys
import argparse


def find_header(challenge_dir: str, pattern: str) -> str | None:
    """Find a header file matching the pattern in the challenge directory."""
    for root, _, files in os.walk(challenge_dir):
        for f in files:
            if re.search(pattern, f, re.IGNORECASE):
                return os.path.join(root, f)
    return None


def parse_table_header(path: str) -> dict[int, int]:
    """Parse { src, dst } pairs from a table header file.

    Returns reverse map: dst -> src (for decryption).
    """
    content = open(path).read()
    reverse_map: dict[int, int] = {}
    for m in re.finditer(r'\{\s*(\d+)\s*,\s*(\d+)\s*\}', content):
        src, dst = int(m.group(1)), int(m.group(2))
        reverse_map[dst] = src
    return reverse_map


def parse_flag_header(path: str) -> list[int]:
    """Parse encrypted flag bytes from char ans[] = "\\xNN..." declaration."""
    content = open(path).read()

    # Match the string literal contents
    m = re.search(r'char\s+\w+\[\]\s*=\s*"([^"]+)"', content)
    if not m:
        return []

    raw = m.group(1)
    encrypted: list[int] = []

    i = 0
    while i < len(raw):
        if raw[i] == '\\' and i + 1 < len(raw) and raw[i + 1] == 'x':
            # \xNN hex escape -- grab as many hex digits as available (C takes up to 2)
            hex_str = ""
            j = i + 2
            while j < len(raw) and j < i + 4 and raw[j] in "0123456789abcdefABCDEF":
                hex_str += raw[j]
                j += 1
            if hex_str:
                encrypted.append(int(hex_str, 16))
            i = j
        elif raw[i] == '\\' and i + 1 < len(raw):
            # Other escape sequences
            esc = raw[i + 1]
            escape_map = {'n': 10, 'r': 13, 't': 9, '0': 0, '\\': 92, "'": 39, '"': 34}
            encrypted.append(escape_map.get(esc, ord(esc)))
            i += 2
        else:
            encrypted.append(ord(raw[i]))
            i += 1

    return encrypted


def detect_challenge(challenge_dir: str) -> bool:
    """Check if this looks like a table-substitution challenge."""
    table_h = find_header(challenge_dir, r'table.*\.h$')
    flag_h = find_header(challenge_dir, r'flag.*\.h$')
    if table_h and flag_h:
        return True

    # Also check C source files for #include of table/flag headers
    for root, _, files in os.walk(challenge_dir):
        for f in files:
            if f.endswith('.c'):
                try:
                    src = open(os.path.join(root, f)).read()
                    if re.search(r'#include\s*".*table.*\.h"', src) and \
                       re.search(r'#include\s*".*flag.*\.h"', src):
                        return True
                except OSError:
                    pass
    return False


def main():
    parser = argparse.ArgumentParser(description="Kraken Table Reverse Solver")
    parser.add_argument("challenge_dir", help="Path to challenge directory")
    args = parser.parse_args()

    challenge_dir = args.challenge_dir
    if not os.path.isdir(challenge_dir):
        print(f"[-] Not a directory: {challenge_dir}")
        sys.exit(1)

    print(f"[*] Scanning for table-substitution challenge in {challenge_dir}")

    # Find header files
    table_h = find_header(challenge_dir, r'table.*\.h$')
    flag_h = find_header(challenge_dir, r'flag.*\.h$')

    if not table_h:
        print("[-] No table header file found")
        sys.exit(1)
    if not flag_h:
        print("[-] No flag header file found")
        sys.exit(1)

    print(f"[*] Table header: {table_h}")
    print(f"[*] Flag header: {flag_h}")

    # Parse table
    reverse_map = parse_table_header(table_h)
    if not reverse_map:
        print("[-] No substitution pairs found in table header")
        sys.exit(1)
    print(f"[*] Built reverse map with {len(reverse_map)} entries")

    # Parse encrypted flag
    encrypted = parse_flag_header(flag_h)
    if not encrypted:
        print("[-] No encrypted bytes found in flag header")
        sys.exit(1)
    print(f"[*] Encrypted flag: {len(encrypted)} bytes")

    # Decrypt
    decrypted = []
    for i, byte_val in enumerate(encrypted):
        if byte_val in reverse_map:
            decrypted.append(chr(reverse_map[byte_val]))
        else:
            print(f"[-] No reverse mapping for byte {byte_val} at position {i}")
            decrypted.append('?')

    flag = "".join(decrypted)
    print(f"\n[+] TABLE_REVERSE SUCCESS")
    print(f"[+] EXTRACTED FLAG: {flag}")


if __name__ == "__main__":
    main()
