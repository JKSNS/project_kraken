#!/usr/bin/env python3
"""
Regex-based Z3 Solver for Kraken Agent
Usage: python3 auto_regex_z3.py decompile.c --length 35
"""
import re
import argparse
import sys
from z3 import *

def solve(c_file, length):
    print(f"[*] Reading {c_file}...")
    try:
        with open(c_file, 'r') as f:
            code = f.read()
    except Exception as e:
        print(f"[-] Error reading file: {e}")
        sys.exit(1)

    # =====================================================================
    # AGENT: MODIFY THIS REGEX PATTERN TO MATCH THE C CODE
    # Example C code:  local_48 = (input[0] + 0x5) ^ 0x12; ... if (local_48 == 0x33)
    # Target match groups: (index), (add_val), (xor_val), (target_val)
    # =====================================================================
    pattern = r'\[(\d+)\] \+ (0x[0-9a-fA-F]+).*?\^ (0x[0-9a-fA-F]+).*?== (0x[0-9a-fA-F]+)'
    
    matches = re.findall(pattern, code)
    
    if not matches:
        print("[-] Regex failed to find any math patterns.")
        print("[-] TIP: Cat the relevant C code and tweak the regex pattern in auto_regex_z3.py.")
        sys.exit(1)
        
    print(f"[*] Found {len(matches)} constraint matches. Building Z3 solver...")

    solver = Solver()
    
    # Create an array of 8-bit vectors for the flag
    flag = [BitVec(f'f{i}', 8) for i in range(length)]
    
    # Constrain to printable ASCII to speed up solver
    for i in range(length):
        solver.add(flag[i] >= 32, flag[i] <= 126)

    # =====================================================================
    # AGENT: MODIFY THIS LOOP TO MATCH YOUR REGEX GROUPS AND MATH
    # =====================================================================
    for match in matches:
        try:
            # Parse regex groups (adjust base 16/10 depending on binary)
            idx = int(match[0])
            add_val = int(match[1], 16)
            xor_val = int(match[2], 16)
            target = int(match[3], 16)
            
            # Ensure index is within bounds
            if idx < length:
                # Add explicit C-precedence math here
                solver.add(((flag[idx] + add_val) ^ xor_val) == target)
        except Exception as e:
            print(f"[-] Error parsing match {match}: {e}")

    print("[*] Checking satisfiability...")
    if solver.check() == sat:
        m = solver.model()
        res = ""
        for i in range(length):
            # model_completion=True prevents NoneType crashes
            val = m.eval(flag[i], model_completion=True).as_long()
            res += chr(val)
        print(f"\n[+] FLAG FOUND: vere{{{res}}}")
    else:
        print("\n[-] Z3 returned UNSAT. The constraints are impossible.")
        print("[-] TIP: Check operator precedence (+ before ^) and verify your regex groups mapped correctly.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kraken Regex Z3 Solver")
    parser.add_argument("file", help="Path to the decompiled C file")
    parser.add_argument("--length", type=int, default=30, help="Expected flag length")
    args = parser.parse_args()
    
    solve(args.file, args.length)
