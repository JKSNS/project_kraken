#!/usr/bin/env python3
"""
Lazy C-Logic Brute Forcer for Kraken Agent
Usage: python3 auto_c_brute.py --logic logic.c --length 35
"""
import subprocess
import os
import argparse
import sys

# The bulletproof C template. 
# It provides standard includes, loops over the flag length, and loops over printable ASCII.
C_TEMPLATE = """
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int main() {
    printf("vere{");
    
    // INJECTED TARGET ARRAY AND VARIABLES
    {globals}

    // Brute force each position
    for (int i = 0; i < {length}; i++) {
        int found = 0;
        
        // Loop through printable ASCII
        for (char c = 32; c <= 126; c++) {
            
            // --- INJECTED GHIDRA LOGIC ---
            // The logic must set a condition where if 'c' is correct, it prints 'c' and sets found=1.
            {logic}
            // -----------------------------
            
            if (found) {
                break; // Move to next character in the flag
            }
        }
        if (!found) {
            printf("?"); // Placeholder for failed byte
        }
    }
    printf("}\\n");
    return 0;
}
"""

def build_and_run(globals_snippet, logic_snippet, length):
    print("[*] Generating C wrapper...")
    code = C_TEMPLATE.format(length=length, globals=globals_snippet, logic=logic_snippet)
    
    with open("kraken_brute.c", "w") as f:
        f.write(code)
        
    print("[*] Compiling with GCC...")
    compile_proc = subprocess.run(
        ["gcc", "kraken_brute.c", "-o", "kraken_brute", "-O3"], 
        capture_output=True, 
        text=True
    )
    
    if compile_proc.returncode != 0:
        print("[-] COMPILATION FAILED. Fix your C syntax:")
        print("---------------------------------------------------")
        print(compile_proc.stderr.strip())
        print("---------------------------------------------------")
        sys.exit(1)
        
    print("[*] Running brute force executable...")
    try:
        run_proc = subprocess.run(
            ["./kraken_brute"], 
            capture_output=True, 
            text=True,
            timeout=10 # Hard timeout to prevent infinite loops
        )
        print(f"\n[+] EXECUTION COMPLETE")
        print(f"[+] OUTPUT: {run_proc.stdout.strip()}")
    except subprocess.TimeoutExpired:
        print("\n[-] EXECUTION TIMED OUT: Your C logic resulted in an infinite loop.")
    finally:
        # Cleanup artifacts so workspace stays clean
        if os.path.exists("kraken_brute.c"):
            os.remove("kraken_brute.c")
        if os.path.exists("kraken_brute"):
            os.remove("kraken_brute")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kraken C-Logic Brute Forcer")
    parser.add_argument("--globals", required=True, help="File containing target arrays or global variables")
    parser.add_argument("--logic", required=True, help="File containing the inner loop check logic")
    parser.add_argument("--length", type=int, required=True, help="Expected length of the flag interior")
    args = parser.parse_args()
    
    try:
        with open(args.globals, 'r') as f:
            globals_snippet = f.read()
        with open(args.logic, 'r') as f:
            logic_snippet = f.read()
    except Exception as e:
        print(f"[-] Error reading snippet files: {e}")
        sys.exit(1)
        
    build_and_run(globals_snippet, logic_snippet, args.length)
