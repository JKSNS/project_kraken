#!/usr/bin/env python3
"""Kraken Advanced Angr -- robust symbolic execution for complex binaries.

Improves on the basic angr solver with:
  1. Targeted exploration -- aim for specific addresses, not string matching
  2. State pruning -- kill states stuck in loops or too deep
  3. Function hooks -- summarize libc functions for performance
  4. Multi-strategy -- try direct, function-level, and backward approaches
  5. Timeout recovery -- graceful degradation instead of hard timeout
  6. Heuristic address detection -- find success/failure blocks automatically
  7. Concretization strategies -- handle symbolic pointers without explosion

Usage:
  python3 auto_angr_advanced.py --binary ./challenge --prefix flag --timeout 300
  python3 auto_angr_advanced.py --binary ./challenge --find 0x401256 --avoid 0x401300
  python3 auto_angr_advanced.py --binary ./challenge --find 0x401256 --arg --length 32
  python3 auto_angr_advanced.py --binary ./challenge --prefix flag --strategy all
"""
import argparse
import os
import re
import signal
import subprocess
import sys
import time


def _check_angr():
    """Check if angr is available and import it."""
    try:
        import angr
        import claripy
        return angr, claripy
    except ImportError:
        print("[-] angr not installed. Install with: pip install angr")
        sys.exit(1)


class AngrAdvanced:
    """Multi-strategy symbolic execution solver."""

    def __init__(self, binary_path, prefix="flag", timeout=120,
                 find_addr=None, avoid_addrs=None, max_length=64,
                 use_arg=False, strategies=None):
        self.binary = os.path.abspath(binary_path)
        self.prefix = prefix
        self.timeout = timeout
        self.find_addr = find_addr
        self.avoid_addrs = avoid_addrs or []
        self.max_length = max_length
        self.use_arg = use_arg
        self.strategies = strategies or ["direct", "function_level", "backward"]
        self.flag_pattern = re.compile(
            rf'{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}'
        )

        # Will be populated during setup
        self.angr = None
        self.claripy = None
        self.project = None
        self.success_addrs = []
        self.failure_addrs = []

    # ── Project setup ────────────────────────────────────────────────

    def setup_project(self):
        """Initialize angr project with optimizations."""
        self.angr, self.claripy = _check_angr()

        import logging
        logging.getLogger("angr").setLevel(logging.CRITICAL)
        logging.getLogger("cle").setLevel(logging.CRITICAL)
        logging.getLogger("pyvex").setLevel(logging.CRITICAL)

        print(f"[*] Loading binary: {self.binary}")
        self.project = self.angr.Project(self.binary, auto_load_libs=False)
        print(f"[*] Architecture: {self.project.arch.name}")
        print(f"[*] Entry point: {self.project.entry:#x}")

        # Find interesting addresses if not provided
        if self.find_addr:
            self.success_addrs = [self.find_addr]
        else:
            self.success_addrs = self._find_success_addresses()

        if not self.avoid_addrs:
            self.failure_addrs = self._find_failure_addresses()
        else:
            self.failure_addrs = self.avoid_addrs

        if self.success_addrs:
            print(f"[*] Target addresses: {', '.join(f'{a:#x}' for a in self.success_addrs)}")
        if self.failure_addrs:
            print(f"[*] Avoid addresses: {', '.join(f'{a:#x}' for a in self.failure_addrs[:5])}")
            if len(self.failure_addrs) > 5:
                print(f"    ... and {len(self.failure_addrs) - 5} more")

    # ── Heuristic address detection ──────────────────────────────────

    def _find_success_addresses(self):
        """Heuristically find the 'success' addresses.

        Looks for basic blocks that reference success-related strings
        like "Correct", "flag{", "You win", etc.
        """
        addrs = []
        success_strings = [
            b"Correct", b"correct", b"CORRECT",
            b"flag{", b"FLAG{", b"flag:",
            b"You win", b"you win", b"Congrat",
            b"Success", b"success", b"ACCESS GRANTED",
            b"Well done", b"Good job", b"Yes!",
            b"That's right", b"Accepted",
        ]

        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            return addrs

        # Also get string addresses
        string_addrs = self._get_string_addresses(success_strings)

        # Search for instructions referencing these strings
        for line in proc.stdout.splitlines():
            for addr in string_addrs:
                if f"{addr:#x}" in line or f"{addr:x}" in line:
                    # Get the address of this instruction
                    m = re.match(r'\s*([0-9a-fA-F]+):', line)
                    if m:
                        inst_addr = int(m.group(1), 16)
                        if inst_addr not in addrs:
                            addrs.append(inst_addr)

        # Also look for puts/printf calls near success strings
        current_func_addrs = []
        found_success_string = False
        for line in proc.stdout.splitlines():
            m = re.match(r'\s*([0-9a-fA-F]+):', line)
            if m:
                current_addr = int(m.group(1), 16)
                current_func_addrs.append(current_addr)

            # Check for string references
            for s in success_strings:
                try:
                    s_str = s.decode("ascii")
                    if s_str.lower() in line.lower():
                        found_success_string = True
                        break
                except Exception:
                    pass

            if found_success_string and ("call" in line and
                                        ("puts" in line or "printf" in line)):
                m = re.match(r'\s*([0-9a-fA-F]+):', line)
                if m:
                    addr = int(m.group(1), 16)
                    if addr not in addrs:
                        addrs.append(addr)
                found_success_string = False

        return addrs[:10]  # Limit to 10 targets

    def _find_failure_addresses(self):
        """Heuristically find 'failure' addresses."""
        addrs = []
        failure_strings = [
            b"Wrong", b"wrong", b"WRONG",
            b"Incorrect", b"incorrect", b"INCORRECT",
            b"Try again", b"try again", b"DENIED",
            b"Failed", b"failed", b"FAILED",
            b"Nope", b"nope", b"No!",
            b"Access denied", b"ACCESS DENIED",
            b"Invalid", b"invalid",
        ]

        string_addrs = self._get_string_addresses(failure_strings)

        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            return addrs

        for line in proc.stdout.splitlines():
            for addr in string_addrs:
                if f"{addr:#x}" in line or f"{addr:x}" in line:
                    m = re.match(r'\s*([0-9a-fA-F]+):', line)
                    if m:
                        inst_addr = int(m.group(1), 16)
                        if inst_addr not in addrs:
                            addrs.append(inst_addr)

        # Also add exit() / abort() call sites as avoids
        for line in proc.stdout.splitlines():
            if "call" in line and ("exit" in line or "abort" in line):
                m = re.match(r'\s*([0-9a-fA-F]+):', line)
                if m:
                    addr = int(m.group(1), 16)
                    if addr not in addrs:
                        addrs.append(addr)

        return addrs[:50]  # Can have many failure paths

    def _get_string_addresses(self, string_list):
        """Get virtual addresses where specific strings appear."""
        addrs = []
        try:
            proc = subprocess.run(
                ["strings", "-a", "-t", "x", "-n", "4", self.binary],
                capture_output=True, text=True, timeout=15,
            )
            for line in proc.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2:
                    for target in string_list:
                        try:
                            if target.decode("ascii", errors="replace").lower() in parts[1].lower():
                                addr = int(parts[0], 16)
                                addrs.append(addr)
                                break
                        except Exception:
                            pass
        except Exception:
            pass
        return addrs

    # ── Function hooks ───────────────────────────────────────────────

    def add_hooks(self):
        """Hook complex functions with summaries for performance."""
        angr = self.angr

        # Hook printf to capture output without full simulation
        class PrintfHook(angr.SimProcedure):
            def run(self, fmt_str, *args):
                return self.state.solver.BVV(0, self.state.arch.bits)

        # Hook time/random for determinism
        class TimeHook(angr.SimProcedure):
            def run(self):
                return self.state.solver.BVV(0x5f3759df, 32)

        class RandHook(angr.SimProcedure):
            def run(self):
                return self.state.solver.BVV(42, 32)

        class SrandHook(angr.SimProcedure):
            def run(self, seed):
                return

        class SleepHook(angr.SimProcedure):
            def run(self, seconds):
                return self.state.solver.BVV(0, 32)

        class AlarmHook(angr.SimProcedure):
            def run(self, seconds):
                return self.state.solver.BVV(0, 32)

        class PtraceHook(angr.SimProcedure):
            """Neutralize anti-debugging: always return 0 (success)."""
            def run(self, request, pid, addr, data):
                return self.state.solver.BVV(0, self.state.arch.bits)

        # Extended hooks for common libc functions

        class StrlenHook(angr.SimProcedure):
            """Symbolic-aware strlen."""
            def run(self, s):
                return self.inline_call(
                    angr.SIM_PROCEDURES["libc"]["strlen"], s
                ).ret_expr

        class MemcpyHook(angr.SimProcedure):
            """Copy memory symbolically."""
            def run(self, dst, src, n):
                n_concrete = self.state.solver.min(n)
                if n_concrete > 0 and n_concrete <= 4096:
                    data = self.state.memory.load(src, n_concrete)
                    self.state.memory.store(dst, data)
                return dst

        class MemsetHook(angr.SimProcedure):
            """Fill memory with a byte."""
            def run(self, dst, c, n):
                n_concrete = self.state.solver.min(n)
                c_byte = self.state.solver.eval(c) & 0xff
                if n_concrete > 0 and n_concrete <= 4096:
                    fill = self.state.solver.BVV(
                        bytes([c_byte] * n_concrete), n_concrete * 8
                    )
                    self.state.memory.store(dst, fill)
                return dst

        class AtoiHook(angr.SimProcedure):
            """Return a symbolic 32-bit int for atoi."""
            def run(self, s):
                return self.state.solver.BVS("atoi_result", 32)

        class StrtolHook(angr.SimProcedure):
            """Return a symbolic long for strtol."""
            def run(self, nptr, endptr, base):
                return self.state.solver.BVS("strtol_result", self.state.arch.bits)

        class StrcmpHook(angr.SimProcedure):
            """strcmp: return 0 when strings are equal (symbolic-friendly)."""
            def run(self, s1, s2):
                return self.inline_call(
                    angr.SIM_PROCEDURES["libc"]["strcmp"], s1, s2
                ).ret_expr

        class StrncmpHook(angr.SimProcedure):
            """strncmp: bounded string comparison."""
            def run(self, s1, s2, n):
                return self.inline_call(
                    angr.SIM_PROCEDURES["libc"]["strncmp"], s1, s2, n
                ).ret_expr

        class MemcmpHook(angr.SimProcedure):
            """memcmp: byte-level comparison."""
            def run(self, s1, s2, n):
                return self.inline_call(
                    angr.SIM_PROCEDURES["libc"]["memcmp"], s1, s2, n
                ).ret_expr

        # Apply hooks
        hooks = {
            "printf": PrintfHook,
            "time": TimeHook,
            "rand": RandHook,
            "srand": SrandHook,
            "sleep": SleepHook,
            "alarm": AlarmHook,
            "ptrace": PtraceHook,
            "strlen": StrlenHook,
            "memcpy": MemcpyHook,
            "memset": MemsetHook,
            "atoi": AtoiHook,
            "strtol": StrtolHook,
            "strcmp": StrcmpHook,
            "strncmp": StrncmpHook,
            "memcmp": MemcmpHook,
        }

        hooked = []
        for name, hook_cls in hooks.items():
            try:
                self.project.hook_symbol(name, hook_cls())
                hooked.append(name)
            except Exception:
                pass  # Symbol might not exist

        if hooked:
            print(f"[*] Hooked {len(hooked)} functions: {', '.join(hooked)}")

    # ── State configuration ──────────────────────────────────────────

    def create_initial_state(self):
        """Create and configure the initial symbolic state."""
        angr = self.angr
        claripy = self.claripy

        # Create symbolic input
        flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(self.max_length)]

        if self.use_arg:
            # Input via argv[1]
            flag_sym = claripy.Concat(*flag_chars)
            state = self.project.factory.full_init_state(
                args=[self.binary, flag_sym],
                add_options=angr.options.unicorn | {
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                },
            )
        else:
            # Input via stdin
            flag_sym = claripy.Concat(*flag_chars + [claripy.BVV(b"\n")])
            state = self.project.factory.full_init_state(
                args=[self.binary],
                add_options=angr.options.unicorn | {
                    angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                },
                stdin=flag_sym,
            )

        # Constrain to printable ASCII
        for char in flag_chars:
            state.solver.add(char >= 0x20)
            state.solver.add(char <= 0x7e)

        # If we know the prefix, constrain it
        if self.prefix:
            prefix_bytes = self.prefix.encode()
            for i, b in enumerate(prefix_bytes):
                if i < len(flag_chars):
                    state.solver.add(flag_chars[i] == b)
            # Also constrain the { after prefix
            if len(prefix_bytes) < len(flag_chars):
                state.solver.add(flag_chars[len(prefix_bytes)] == ord("{"))

        self.flag_chars = flag_chars
        self.flag_sym = flag_sym if self.use_arg else flag_sym
        return state

    # ── Exploration strategies ───────────────────────────────────────

    def _try_direct(self):
        """Strategy 1: Direct exploration with address targets and pruning."""
        print("[*] Strategy: direct exploration with pruning")

        state = self.create_initial_state()
        sm = self.project.factory.simulation_manager(state)

        # Exploration with pruning callback
        start_time = time.time()
        step_count = 0
        pruned_count = 0

        while sm.active and time.time() - start_time < self.timeout:
            sm.step()
            step_count += 1

            # Prune states that are too deep (likely in infinite loops)
            deep_states = [s for s in sm.active if s.history.depth > 500]
            if deep_states:
                sm.move("active", "pruned",
                        filter_func=lambda s: s.history.depth > 500)
                pruned_count += len(deep_states)

            # Prune states stuck in tight loops
            for s in list(sm.active):
                recent = list(s.history.bbl_addrs.hardcopy[-30:])
                if len(recent) >= 30 and len(set(recent)) < 5:
                    sm.active.remove(s)
                    pruned_count += 1

            # Limit active states to prevent explosion
            if len(sm.active) > 128:
                # Keep states closest to targets (by address proximity)
                if self.success_addrs:
                    sm.active.sort(
                        key=lambda s: min(
                            abs(s.addr - target)
                            for target in self.success_addrs
                        )
                    )
                sm.active = sm.active[:64]
                pruned_count += 64

            # Check for found states (address-based)
            if self.success_addrs:
                for s in list(sm.active):
                    if s.addr in self.success_addrs:
                        sm.found.append(s)
                        sm.active.remove(s)

            # Also check via string matching in output
            for s in list(sm.active):
                try:
                    stdout = s.posix.dumps(1)
                    if stdout:
                        stdout_str = stdout.decode("utf-8", errors="replace").lower()
                        for kw in ["correct", "flag{", "you win", "success", "congrat"]:
                            if kw in stdout_str:
                                sm.found.append(s)
                                if s in sm.active:
                                    sm.active.remove(s)
                                break
                except Exception:
                    pass

            # Move states at failure addresses to deadended
            if self.failure_addrs:
                sm.move("active", "deadended",
                        filter_func=lambda s: s.addr in self.failure_addrs)

            if sm.found:
                break

            # Progress reporting
            if step_count % 100 == 0:
                elapsed = time.time() - start_time
                print(f"    Step {step_count}: {len(sm.active)} active, "
                      f"{len(sm.deadended)} dead, {pruned_count} pruned, "
                      f"{elapsed:.0f}s elapsed")

        elapsed = time.time() - start_time
        print(f"[*] Exploration complete: {step_count} steps, {elapsed:.1f}s, "
              f"{pruned_count} states pruned")

        if sm.found:
            return self._extract_solution(sm.found[0])
        return None

    def _try_string_match(self):
        """Strategy 2: Standard string-matching exploration (fallback)."""
        print("[*] Strategy: string-matching exploration")

        state = self.create_initial_state()
        sm = self.project.factory.simulation_manager(state)

        success_keywords = ["correct", "flag{", "you win", "success", "congrat"]
        failure_keywords = ["wrong", "incorrect", "fail", "denied", "invalid", "nope", "try again"]

        def is_success(s):
            try:
                stdout = s.posix.dumps(1)
                if stdout:
                    text = stdout.decode("utf-8", errors="replace").lower()
                    return any(kw in text for kw in success_keywords)
            except Exception:
                pass
            return False

        def is_failure(s):
            try:
                stdout = s.posix.dumps(1)
                if stdout:
                    text = stdout.decode("utf-8", errors="replace").lower()
                    return any(kw in text for kw in failure_keywords)
            except Exception:
                pass
            return False

        # Set timeout via SIGALRM
        def timeout_handler(signum, frame):
            raise TimeoutError("Exploration timed out")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.timeout)

        try:
            sm.explore(find=is_success, avoid=is_failure)
        except TimeoutError:
            print(f"[-] String-match exploration timed out after {self.timeout}s")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        if sm.found:
            return self._extract_solution(sm.found[0])
        return None

    def _try_function_level(self):
        """Strategy 3: Start exploration from the comparison function."""
        print("[*] Strategy: function-level (start from comparison)")

        # Find comparison function addresses
        cmp_addrs = self._find_comparison_functions()
        if not cmp_addrs:
            print("[-] No comparison functions found, skipping")
            return None

        # For each comparison function, try starting exploration there
        for func_name, func_addr in cmp_addrs[:3]:
            print(f"    Trying from: {func_name} @ {func_addr:#x}")

            claripy = self.claripy
            flag_chars = [claripy.BVS(f"flag_{i}", 8) for i in range(self.max_length)]
            flag_sym = claripy.Concat(*flag_chars)

            # Create state starting at the comparison function
            state = self.project.factory.blank_state(
                addr=func_addr,
                add_options=self.angr.options.unicorn | {
                    self.angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                    self.angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                },
            )

            # Put symbolic data in RDI (first argument -- common for strcmp/memcmp)
            buf_addr = 0x10000000
            state.memory.store(buf_addr, flag_sym)
            state.regs.rdi = buf_addr

            for char in flag_chars:
                state.solver.add(char >= 0x20)
                state.solver.add(char <= 0x7e)

            sm = self.project.factory.simulation_manager(state)

            start_time = time.time()
            while sm.active and time.time() - start_time < min(30, self.timeout // 3):
                sm.step()

                # Check if any state has returned from the function
                for s in list(sm.active):
                    try:
                        ret_val = s.solver.eval(s.regs.rax)
                        # strcmp returns 0 on match
                        if ret_val == 0 and s.solver.satisfiable():
                            solution = s.solver.eval(flag_sym, cast_to=bytes)
                            decoded = solution.rstrip(b"\x00").decode("utf-8", errors="replace")
                            if decoded and len(decoded) >= 3:
                                print(f"[+] Found solution from comparison: {decoded}")
                                return decoded
                    except Exception:
                        pass

                if len(sm.active) > 32:
                    sm.active = sm.active[:16]

        return None

    def _find_comparison_functions(self):
        """Find comparison functions (strcmp, memcmp, etc.) and their callers."""
        cmp_funcs = []
        try:
            proc = subprocess.run(
                ["objdump", "-d", "--no-show-raw-insn", self.binary],
                capture_output=True, text=True, timeout=30,
            )
        except Exception:
            return []

        current_func = None
        current_addr = None

        for line in proc.stdout.splitlines():
            func_match = re.match(r'^([0-9a-fA-F]+)\s+<([^>]+)>:', line)
            if func_match:
                current_func = func_match.group(2)
                current_addr = int(func_match.group(1), 16)
                continue

            if current_func and "call" in line:
                for cmp_name in ["strcmp", "strncmp", "memcmp", "bcmp"]:
                    if cmp_name in line:
                        # Record the calling function
                        cmp_funcs.append((current_func, current_addr))
                        break

        return list(set(cmp_funcs))

    def _try_backward(self):
        """Strategy 4: Backward exploration from target address.

        If we know the success address, start from there and work backward
        to determine what constraints must be satisfied.
        """
        if not self.success_addrs:
            print("[-] No target address for backward strategy")
            return None

        print("[*] Strategy: backward from target")

        target = self.success_addrs[0]

        # Use CFG to find paths to target
        try:
            print(f"    Building CFG targeting {target:#x}...")
            cfg = self.project.analyses.CFGFast(normalize=True)
        except Exception as e:
            print(f"[-] CFG construction failed: {e}")
            return None

        # Find the node containing our target address
        target_node = cfg.model.get_any_node(target)
        if not target_node:
            print(f"[-] Target address {target:#x} not found in CFG")
            return None

        # Get predecessors (blocks that lead to the target)
        predecessors = list(cfg.model.get_predecessors(target_node))
        if not predecessors:
            print("[-] No predecessors found for target node")
            return None

        print(f"    Target has {len(predecessors)} predecessor block(s)")

        # Try exploring from entry to each predecessor
        for pred in predecessors[:3]:
            print(f"    Trying to reach predecessor @ {pred.addr:#x}")

            state = self.create_initial_state()
            sm = self.project.factory.simulation_manager(state)

            start_time = time.time()
            timeout = min(60, self.timeout // 3)

            try:
                sm.explore(
                    find=pred.addr,
                    avoid=self.failure_addrs,
                    num_find=1,
                )
            except Exception as e:
                print(f"    Exploration failed: {e}")
                continue

            if sm.found:
                result = self._extract_solution(sm.found[0])
                if result:
                    return result

        return None

    def _try_veritesting(self):
        """Strategy 5: Veritesting for path merging.

        Veritesting (an angr exploration technique) merges paths at join
        points to reduce state explosion.  Effective for binaries that
        check each flag byte independently.
        """
        print("[*] Strategy: veritesting (path merging)")

        state = self.create_initial_state()
        sm = self.project.factory.simulation_manager(state)

        # Apply veritesting
        try:
            sm.use_technique(
                self.angr.exploration_techniques.Veritesting()
            )
        except Exception as e:
            print(f"[-] Veritesting setup failed: {e}")
            return None

        start_time = time.time()
        timeout = min(self.timeout, 120)

        def timeout_handler(signum, frame):
            raise TimeoutError("Veritesting timed out")

        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(timeout)

        try:
            if self.success_addrs:
                sm.explore(
                    find=self.success_addrs,
                    avoid=self.failure_addrs,
                )
            else:
                # String-matching fallback
                success_kw = ["correct", "flag{", "you win", "success", "congrat"]

                def is_ok(s):
                    try:
                        out = s.posix.dumps(1)
                        if out:
                            t = out.decode("utf-8", errors="replace").lower()
                            return any(k in t for k in success_kw)
                    except Exception:
                        pass
                    return False

                sm.explore(find=is_ok, avoid=self.failure_addrs)
        except TimeoutError:
            elapsed = time.time() - start_time
            print(f"[-] Veritesting timed out after {elapsed:.0f}s")
        except Exception as e:
            print(f"[-] Veritesting failed: {e}")
        finally:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)

        elapsed = time.time() - start_time
        print(f"[*] Veritesting: {elapsed:.1f}s, "
              f"{len(sm.found)} found, {len(sm.active)} active")

        if sm.found:
            return self._extract_solution(sm.found[0])
        return None

    def _try_dfs(self):
        """Strategy 6: Depth-first search for deep execution paths.

        DFS is better than BFS for binaries with linear flag checks where
        the correct path is narrow but deep.
        """
        print("[*] Strategy: depth-first search")

        state = self.create_initial_state()
        sm = self.project.factory.simulation_manager(state)

        try:
            sm.use_technique(
                self.angr.exploration_techniques.DFS()
            )
        except Exception as e:
            print(f"[-] DFS setup failed: {e}")
            return None

        start_time = time.time()
        timeout = min(self.timeout, 120)
        step_count = 0

        while sm.active and time.time() - start_time < timeout:
            sm.step()
            step_count += 1

            # Check for found states
            if self.success_addrs:
                for s in list(sm.active):
                    if s.addr in self.success_addrs:
                        sm.found.append(s)
                        sm.active.remove(s)

            # String match check
            for s in list(sm.active):
                try:
                    stdout = s.posix.dumps(1)
                    if stdout:
                        text = stdout.decode("utf-8", errors="replace").lower()
                        for kw in ["correct", "flag{", "you win", "success"]:
                            if kw in text:
                                sm.found.append(s)
                                if s in sm.active:
                                    sm.active.remove(s)
                                break
                except Exception:
                    pass

            # Avoid failure addresses
            if self.failure_addrs:
                sm.move("active", "deadended",
                        filter_func=lambda s: s.addr in self.failure_addrs)

            if sm.found:
                break

            # Prune extremely deep states
            sm.move("active", "deadended",
                    filter_func=lambda s: s.history.depth > 1000)

            # Limit total active states
            if len(sm.active) > 64:
                sm.active = sm.active[:32]

            if step_count % 200 == 0:
                elapsed = time.time() - start_time
                print(f"    Step {step_count}: {len(sm.active)} active, "
                      f"{elapsed:.0f}s elapsed")

        elapsed = time.time() - start_time
        print(f"[*] DFS: {step_count} steps, {elapsed:.1f}s")

        if sm.found:
            return self._extract_solution(sm.found[0])
        return None

    def _try_file_input(self):
        """Strategy 7: Handle binaries that read from files.

        Some CTF reversing challenges read from a file (e.g., 'input.txt',
        'flag.txt').  This strategy creates a symbolic file so angr can
        reason about the file contents.
        """
        print("[*] Strategy: symbolic file input")

        # Detect file names the binary might open
        file_names = self._find_input_files()
        if not file_names:
            print("[-] No input file references detected")
            return None

        for fname in file_names[:3]:
            print(f"    Trying symbolic file: {fname}")

            claripy = self.claripy

            # Create symbolic file content
            flag_chars = [claripy.BVS(f"ff_{i}", 8) for i in range(self.max_length)]
            file_content = claripy.Concat(*flag_chars)

            try:
                simfile = self.angr.SimFile(fname, content=file_content,
                                            size=self.max_length)
                state = self.project.factory.full_init_state(
                    args=[self.binary],
                    fs={fname: simfile},
                    add_options=self.angr.options.unicorn | {
                        self.angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
                        self.angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
                    },
                )
            except Exception as e:
                print(f"    SimFile setup failed: {e}")
                continue

            # Constrain to printable ASCII
            for ch in flag_chars:
                state.solver.add(ch >= 0x20)
                state.solver.add(ch <= 0x7e)

            sm = self.project.factory.simulation_manager(state)

            start_time = time.time()
            timeout = min(60, self.timeout // 3)

            def timeout_handler(signum, frame):
                raise TimeoutError()

            old_handler = signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(timeout)

            try:
                if self.success_addrs:
                    sm.explore(find=self.success_addrs, avoid=self.failure_addrs)
                else:
                    success_kw = ["correct", "flag{", "you win", "success"]

                    def is_ok(s):
                        try:
                            out = s.posix.dumps(1)
                            if out:
                                t = out.decode("utf-8", errors="replace").lower()
                                return any(k in t for k in success_kw)
                        except Exception:
                            pass
                        return False

                    sm.explore(find=is_ok, avoid=self.failure_addrs)
            except TimeoutError:
                pass
            except Exception as e:
                print(f"    Exploration failed: {e}")
            finally:
                signal.alarm(0)
                signal.signal(signal.SIGALRM, old_handler)

            if sm.found:
                found_state = sm.found[0]
                try:
                    solution = found_state.solver.eval(file_content, cast_to=bytes)
                    decoded = solution.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
                    if decoded and len(decoded) >= 3:
                        print(f"[+] Found file input solution: {decoded}")

                        # Check stdout too
                        try:
                            stdout = found_state.posix.dumps(1)
                            if stdout:
                                print(f"[*] Binary stdout: {stdout.decode('utf-8', errors='replace').strip()}")
                        except Exception:
                            pass

                        # Match flag pattern
                        m = self.flag_pattern.search(decoded)
                        if m:
                            return m.group(0)
                        m = re.search(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', decoded)
                        if m:
                            return m.group(0)
                        return decoded
                except Exception as e:
                    print(f"    Solution extraction failed: {e}")

        return None

    def _find_input_files(self):
        """Detect file names referenced in the binary for file-based input."""
        names = []
        try:
            proc = subprocess.run(
                ["strings", "-a", "-n", "4", self.binary],
                capture_output=True, text=True, timeout=15,
            )
            for line in proc.stdout.splitlines():
                s = line.strip()
                # Common CTF input file names
                if s in ("input.txt", "flag.txt", "key.txt", "secret.txt",
                         "data.txt", "input", "flag", "message.txt",
                         "plaintext.txt", "cipher.txt"):
                    if s not in names:
                        names.append(s)
                # Paths ending in common extensions
                if re.match(r'^[a-zA-Z0-9_.\-/]+\.(txt|bin|dat|key|enc)$', s):
                    if s not in names and len(s) < 50:
                        names.append(s)
        except Exception:
            pass
        return names

    # ── Solution extraction ──────────────────────────────────────────

    def _extract_solution(self, state):
        """Extract the solving input from a found state."""
        try:
            if self.use_arg:
                # Extract argv[1]
                flag_sym = self.claripy.Concat(*self.flag_chars)
                solution = state.solver.eval(flag_sym, cast_to=bytes)
                decoded = solution.rstrip(b"\x00").decode("utf-8", errors="replace")
            else:
                # Extract stdin
                stdin_data = state.posix.dumps(0)
                decoded = stdin_data.decode("utf-8", errors="replace").strip()

            # Also get stdout to show what the binary printed
            try:
                stdout = state.posix.dumps(1)
                if stdout:
                    print(f"[*] Binary stdout: {stdout.decode('utf-8', errors='replace').strip()}")
            except Exception:
                pass

            if decoded:
                # Clean up: remove trailing null bytes and control chars
                decoded = decoded.rstrip("\x00").strip()

                # Check if it matches flag pattern
                m = self.flag_pattern.search(decoded)
                if m:
                    return m.group(0)

                # Check generic flag pattern
                m = re.search(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', decoded)
                if m:
                    return m.group(0)

                # Return raw solution
                return decoded

        except Exception as e:
            print(f"[-] Solution extraction failed: {e}")

        return None

    # ── Main solve loop ──────────────────────────────────────────────

    def solve(self):
        """Main solve loop: try multiple strategies."""
        self.setup_project()
        self.add_hooks()

        strategy_map = {
            "direct": ("direct exploration with pruning", self._try_direct),
            "string_match": ("string-matching exploration", self._try_string_match),
            "function_level": ("function-level exploration", self._try_function_level),
            "backward": ("backward from target", self._try_backward),
            "veritesting": ("veritesting (path merging)", self._try_veritesting),
            "dfs": ("depth-first search", self._try_dfs),
            "file_input": ("symbolic file input", self._try_file_input),
        }

        for strategy_name in self.strategies:
            if strategy_name not in strategy_map:
                if strategy_name == "all":
                    # Run all strategies
                    self.strategies = list(strategy_map.keys())
                    return self.solve()
                print(f"[-] Unknown strategy: {strategy_name}")
                continue

            desc, strategy_func = strategy_map[strategy_name]
            print(f"\n{'=' * 60}")
            print(f"[*] Trying angr strategy: {desc}")
            print(f"{'=' * 60}")

            try:
                result = strategy_func()
                if result:
                    # Check for flag pattern
                    m = self.flag_pattern.search(result)
                    if m:
                        print(f"\nEXTRACTED FLAG: {m.group(0)}")
                        return m.group(0)

                    # Check generic pattern
                    m = re.search(r'[A-Za-z0-9_]{2,20}\{[^}]{3,}\}', result)
                    if m:
                        print(f"\nEXTRACTED FLAG: {m.group(0)}")
                        return m.group(0)

                    # Raw result
                    print(f"\n[+] ANGR SUCCESS")
                    print(f"[+] EXTRACTED INPUT: {result}")
                    # Print as flag format if it looks like body
                    if not "{" in result and len(result) >= 3:
                        possible_flag = f"{self.prefix}{{{result}}}"
                        print(f"[+] Possible flag: {possible_flag}")
                    return result
            except Exception as e:
                print(f"[-] Strategy {desc} failed: {e}")

        print("\n[-] All angr strategies exhausted without finding a solution")
        print("[-] Tips:")
        print("    1. Try --arg if the binary expects argv instead of stdin")
        print("    2. Try specifying --find and --avoid addresses manually")
        print("    3. Try increasing --timeout (current: {self.timeout}s)")
        print("    4. Try increasing --length if the flag is longer than expected")
        return None


# ── CLI ──────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Kraken Advanced Angr -- robust symbolic execution solver"
    )
    parser.add_argument("--binary", required=True, help="Path to binary")
    parser.add_argument("--prefix", default="flag",
                        help="Flag prefix (default: flag)")
    parser.add_argument("--find", type=str, default=None,
                        help="Address to find (hex, e.g. 0x401256)")
    parser.add_argument("--avoid", type=str, nargs="*", default=None,
                        help="Address(es) to avoid (hex)")
    parser.add_argument("--length", type=int, default=64,
                        help="Maximum input length (default: 64)")
    parser.add_argument("--timeout", type=int, default=120,
                        help="Timeout in seconds (default: 120)")
    parser.add_argument("--arg", action="store_true",
                        help="Pass input as argv[1] instead of stdin")
    parser.add_argument("--strategy", type=str, nargs="*",
                        default=["direct", "string_match", "function_level"],
                        choices=["direct", "string_match", "function_level",
                                 "backward", "veritesting", "dfs",
                                 "file_input", "all"],
                        help="Strategies to try (default: direct string_match function_level)")

    args = parser.parse_args()

    if not os.path.isfile(args.binary):
        print(f"[-] File not found: {args.binary}")
        sys.exit(1)

    # Parse hex addresses
    find_addr = None
    if args.find:
        try:
            find_addr = int(args.find, 16)
        except ValueError:
            print(f"[-] Invalid address: {args.find}")
            sys.exit(1)

    avoid_addrs = []
    if args.avoid:
        for a in args.avoid:
            try:
                avoid_addrs.append(int(a, 16))
            except ValueError:
                print(f"[-] Invalid avoid address: {a}")
                sys.exit(1)

    solver = AngrAdvanced(
        args.binary,
        prefix=args.prefix,
        timeout=args.timeout,
        find_addr=find_addr,
        avoid_addrs=avoid_addrs,
        max_length=args.length,
        use_arg=args.arg,
        strategies=args.strategy,
    )
    solver.solve()


if __name__ == "__main__":
    main()
