#!/usr/bin/env python3
"""
C-PRNG Predictor + XOR Solver for Kraken Agent

Usage:
  python3 auto_c_rand.py --seed 0x13337 --count 50
  python3 auto_c_rand.py --seed 0x13337 --count 32 --binary ./plants --prefix "vere{"
"""
import subprocess
import os
import re
import struct
import argparse
import sys
import tempfile

C_TEMPLATE = """
#include <stdio.h>
#include <stdlib.h>

int main() {{
    srand({seed});
    for (int i = 0; i < {count}; i++) {{
        printf("%d\\n", rand());
    }}
    return 0;
}}
"""


def generate_rand_sequence(seed, count):
    """Generate C rand() sequence by compiling+running a small C program."""
    print(f"[*] Generating {count} C rand() values using seed {seed}...")
    code = C_TEMPLATE.format(seed=seed, count=count)

    with tempfile.NamedTemporaryFile(mode="w", suffix=".c", delete=False) as f:
        c_path = f.name
        f.write(code)
    bin_path = c_path.replace(".c", "")

    try:
        compile_proc = subprocess.run(
            ["gcc", c_path, "-o", bin_path],
            capture_output=True, text=True,
        )
        if compile_proc.returncode != 0:
            print(f"[-] Compilation failed: {compile_proc.stderr}")
            sys.exit(1)

        run_proc = subprocess.run([bin_path], capture_output=True, text=True)
        values = [int(v) for v in run_proc.stdout.strip().split() if v.strip()]
        print(f"[+] Generated {len(values)} rand() values")
        if values:
            print(f"[+] First 5: {values[:5]}")
        return values
    finally:
        for p in (c_path, bin_path):
            try:
                os.remove(p)
            except OSError:
                pass


def extract_expected_from_binary(binary_path, count):
    """Extract expected int32 arrays from the binary's data sections.

    Looks for arrays of 4-byte integers in .rodata/.data sections that
    could be the encrypted flag bytes.
    """
    try:
        # Use objdump to get data section contents
        proc = subprocess.run(
            ["objdump", "-s", "-j", ".rodata", binary_path],
            capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            # Try .data section instead
            proc = subprocess.run(
                ["objdump", "-s", "-j", ".data", binary_path],
                capture_output=True, text=True, timeout=10,
            )

        hex_data = ""
        for line in proc.stdout.splitlines():
            # objdump -s lines: " addr hex hex hex hex  ascii"
            m = re.match(r'\s+[0-9a-f]+\s+((?:[0-9a-f]{2,8}\s?)+)', line)
            if m:
                hex_data += m.group(1).replace(" ", "")

        if not hex_data or len(hex_data) < count * 8:
            return []

        raw = bytes.fromhex(hex_data)
        # Extract all possible int32 arrays of the right length
        arrays = []
        for offset in range(0, len(raw) - count * 4 + 1, 4):
            arr = list(struct.unpack_from(f"<{count}i", raw, offset))
            # Heuristic: skip arrays that are all zeros or all the same
            if len(set(arr)) > 1 and not all(v == 0 for v in arr):
                arrays.append(arr)
        return arrays
    except Exception as e:
        print(f"[!] Binary extraction failed: {e}")
        return []


def try_xor_solve(rand_values, expected_arrays, prefix=""):
    """Try XOR reversal: flag[i] = expected[i] ^ (rand[i] % modulus)."""
    moduli = [256, 128, 0x100, 0x7f, 0x80]
    count = len(rand_values)

    for expected in expected_arrays:
        if len(expected) < count:
            continue
        for mod in moduli:
            result = []
            for i in range(count):
                c = expected[i] ^ (rand_values[i] % mod)
                c = c & 0xFF
                result.append(c)

            # Check if result is printable ASCII
            try:
                text = bytes(result).decode("ascii")
            except (ValueError, UnicodeDecodeError):
                continue

            if not all(0x20 <= b <= 0x7e for b in result):
                continue

            # Check prefix match
            if prefix and not text.startswith(prefix):
                continue

            print(f"[+] XOR solve success (mod={mod}): {text}")
            return text

    return None


def main():
    parser = argparse.ArgumentParser(description="Kraken C-PRNG Generator + XOR Solver")
    parser.add_argument("--seed", required=True, help="Seed for srand() -- hex (0x...) or decimal")
    parser.add_argument("--count", type=int, default=50, help="Number of rand() calls to generate")
    parser.add_argument("--binary", default="", help="Path to challenge binary (for XOR solve)")
    parser.add_argument("--prefix", default="", help="Expected flag prefix (e.g. 'vere{')")
    args = parser.parse_args()

    # Parse seed (hex or decimal)
    seed_str = args.seed.strip()
    if seed_str.startswith("0x") or seed_str.startswith("0X"):
        seed = int(seed_str, 16)
    else:
        seed = int(seed_str)

    rand_values = generate_rand_sequence(seed, args.count)
    if not rand_values:
        print("[-] No rand values generated")
        sys.exit(1)

    # Save values for downstream use
    with open("rand_output.txt", "w") as f:
        f.write("\n".join(str(v) for v in rand_values) + "\n")
    print(f"[+] Saved to rand_output.txt")

    # If --binary provided, attempt XOR solve
    if args.binary and os.path.exists(args.binary):
        print(f"[*] Extracting expected arrays from {args.binary}...")
        expected_arrays = extract_expected_from_binary(args.binary, args.count)
        print(f"[*] Found {len(expected_arrays)} candidate arrays")

        if expected_arrays:
            flag = try_xor_solve(rand_values, expected_arrays, prefix=args.prefix)
            if flag:
                print(f"EXTRACTED FLAG: {flag}")
                sys.exit(0)
            else:
                print("[-] XOR solve did not produce a valid flag")
        else:
            print("[-] No candidate arrays found in binary")

    print("[*] Done -- rand values available in rand_output.txt")


if __name__ == "__main__":
    main()
