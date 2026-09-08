#!/usr/bin/env python3
"""
Universal Angr Wrapper for Kraken Agent
Usage (stdin): python3 auto_angr.py ./chal --find "Correct"
Usage (argv):  python3 auto_angr.py ./chal --find "Correct" --arg
"""
import angr
import claripy
import sys
import argparse
import logging
import signal

logging.getLogger('angr').setLevel(logging.CRITICAL)
logging.getLogger('os').setLevel(logging.CRITICAL)

def timeout_handler(signum, frame):
    print("\n[-] ANGR TIMEOUT: State explosion detected. Exploration took too long.")
    sys.exit(1)

def solve(binary_path, success_string, fail_string, max_length, timeout, use_arg):
    print(f"[*] Initializing Angr for: {binary_path}")
    print(f"[*] Target Success String: '{success_string}'")
    print(f"[*] Input Mode: {'ARGV (Command Line Argument)' if use_arg else 'STDIN (Standard Input)'}")
    
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

    try:
        proj = angr.Project(binary_path, auto_load_libs=False)
        
        # Create symbolic bitvectors for the flag characters
        flag_chars = [claripy.BVS(f'flag_{i}', 8) for i in range(max_length)]
        
        if use_arg:
            # For argv, we don't necessarily need a newline at the end
            flag = claripy.Concat(*flag_chars)
            state = proj.factory.full_init_state(
                args=[binary_path, flag],
                add_options=angr.options.unicorn,
            )
        else:
            # For stdin, append a newline
            flag = claripy.Concat(*flag_chars + [claripy.BVV(b'\n')])
            state = proj.factory.full_init_state(
                args=[binary_path],
                add_options=angr.options.unicorn,
                stdin=flag,
            )
        
        # Constrain the flag to printable ASCII
        for char in flag_chars:
            state.solver.add(char >= 0x20)
            state.solver.add(char <= 0x7e)
            
        simgr = proj.factory.simulation_manager(state)
        
        def is_successful(state):
            stdout = state.posix.dumps(sys.stdout.fileno())
            return success_string.encode().lower() in stdout.lower()

        def should_abort(state):
            if fail_string:
                stdout = state.posix.dumps(sys.stdout.fileno())
                return fail_string.encode().lower() in stdout.lower()
            return False
            
        print(f"[*] Exploring binary paths... (Timeout: {timeout}s)")
        simgr.explore(find=is_successful, avoid=should_abort)
        
        if simgr.found:
            found_state = simgr.found[0]
            if use_arg:
                # Extract the evaluated argv[1] constraint
                solution = found_state.solver.eval(flag, cast_to=bytes).decode('utf-8', 'ignore')
            else:
                solution = found_state.posix.dumps(sys.stdin.fileno()).decode('utf-8', 'ignore')
            
            print(f"\n[+] ANGR SUCCESS")
            print(f"[+] EXTRACTED FLAG: {solution.strip()}")
            return True
        else:
            print("\n[-] ANGR FAILED: Reached end of execution without finding the success string.")
            print("[-] TIP 1: Check if the binary expects an argument (--arg) instead of stdin.")
            print("[-] TIP 2: Ensure your --find string exactly matches the binary's success output.")
            return False

    except Exception as e:
        print(f"\n[-] ANGR FATAL ERROR: {str(e)}")
        return False
    finally:
        signal.alarm(0)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Kraken Universal Angr Solver")
    parser.add_argument("binary", help="Path to the executable binary")
    parser.add_argument("--find", required=True, help="Substring that indicates a correct flag (e.g., 'Correct!')")
    parser.add_argument("--avoid", default=None, help="Substring that indicates a wrong flag")
    parser.add_argument("--length", type=int, default=40, help="Maximum expected flag length")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds")
    parser.add_argument("--arg", action="store_true", help="Pass the flag as argv[1] instead of stdin")
    
    args = parser.parse_args()
    solve(args.binary, args.find, args.avoid, args.length, args.timeout, args.arg)
