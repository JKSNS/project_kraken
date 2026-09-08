#!/usr/bin/env python3
"""
GDB Comparison Tracer for Kraken Agent
Usage: python3 auto_gdb_cmp.py <binary_path> --input "vere{dummy_flag_12345}"
"""
import subprocess
import argparse
import sys

GDB_SCRIPT = """
set pagination off
set logging file gdb_out.txt
set logging on

# Break on common comparison functions
catch syscall read
break strcmp
break strncmp
break memcmp

commands
    silent
    printf "============== CMP HIT ==============\\n"
    printf "Arg1 (RDI): %s\\n", (char*)$rdi
    printf "Arg2 (RSI): %s\\n", (char*)$rsi
    printf "Arg1 (Hex): "
    x/16xb $rdi
    printf "Arg2 (Hex): "
    x/16xb $rsi
    printf "=====================================\\n"
    continue
end

run {args}
quit
"""

def solve(binary, test_input):
    print(f"[*] Tracing comparisons in {binary} with input: '{test_input}'")
    
    # Save the GDB batch script
    with open("trace.gdb", "w") as f:
        # If binary takes input via argv
        f.write(GDB_SCRIPT.replace("{args}", f"'{test_input}'"))
        
    print("[*] Running GDB...")
    # Run GDB. If binary expects stdin, we pipe it.
    cmd = f"echo '{test_input}' | gdb -q -batch -x trace.gdb {binary}"
    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    with open("gdb_out.txt", "r") as f:
        output = f.read()
        
    hits = output.count("CMP HIT")
    print(f"[+] GDB Trace complete. Found {hits} comparison calls.")
    
    if hits > 0:
        print("\n[+] EXTRACTED COMPARISONS:")
        for line in output.split('\n'):
            if "Arg1" in line or "Arg2" in line or "CMP HIT" in line:
                print(line.strip())
    else:
        print("[-] No standard comparison functions (strcmp/memcmp) were hit.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", help="Path to the binary")
    parser.add_argument("--input", default="vere{dummy_flag_to_track_in_memory}", help="Input to feed the binary")
    args = parser.parse_args()
    solve(args.binary, args.input)
