#!/usr/bin/env python3
"""License-crackme angr solver -- copy of kraken helpers/auto_angr.py, modified.

Goal: find the CONSTRAINTS that make a license valid (not just one key).
Single angr solve. gcc -O0, stripped target.

Usage:
  python3 solve_license_angr.py ./chal --find VALID --avoid INVALID --arg
  python3 solve_license_angr.py ./chal --find VALID --arg --length 22 \
      --charset digits --no-unicorn --prefix 12345678901234567 --enumerate 5

Modifications vs auto_angr.py:
  - dumps the per-byte solved value AND the symbolic constraints angr collected
    on the input (the actual "constraints that lead to a valid license"),
  - enumerates up to N distinct valid licenses to expose fixed vs free bytes,
  - auto-tries a small set of common success/fail markers if --find is omitted,
  - case-INSENSITIVE marker matching (so --find VALID matches upper-case output),
  - --charset {printable,alnum,upper,digits}: constrain the symbolic input
    alphabet (narrow sets collapse the per-char isdigit/isalpha fork),
  - --no-unicorn: drop the unicorn engine (it thrashes on fully-symbolic input),
  - --prefix STR: pin leading bytes to a concrete (valid) body so the checksum
    sum stays a small AST -- otherwise the target's own `Debug: Sum=%d` printf
    forces angr to format a 21-term symbolic sum and hangs. angr still solves the
    remaining bytes INCLUDING the checksum from the binary's real logic,
  - --veritesting: optional path-merging DSE (note: can fault on SimProcedure
    regions for some targets -- leave off unless exploration explodes).
"""

import argparse
import logging
import signal
import sys

import angr
import claripy

logging.getLogger("angr").setLevel(logging.CRITICAL)
logging.getLogger("cle").setLevel(logging.CRITICAL)

DEFAULT_SUCCESS = ["valid", "correct", "granted", "congrat", "success", "accepted", "welcome"]
DEFAULT_FAIL = ["invalid", "incorrect", "wrong", "denied", "nope", "try again", "fail"]


def _charset_constraint(c, charset):
    """Return a claripy constraint restricting byte `c` to the named alphabet."""
    digit = claripy.And(c >= 0x30, c <= 0x39)  # 0-9
    upper = claripy.And(c >= 0x41, c <= 0x5A)  # A-Z
    lower = claripy.And(c >= 0x61, c <= 0x7A)  # a-z
    if charset == "digits":
        return digit
    if charset == "upper":
        return claripy.Or(digit, upper)  # base36 body, upper-only
    if charset == "alnum":
        return claripy.Or(digit, upper, lower)  # full base36
    return claripy.And(c >= 0x20, c <= 0x7E)  # printable (default)


def _timeout(signum, frame):
    print("\n[-] ANGR TIMEOUT: narrow --length/--charset, add --prefix, or --no-unicorn.")
    sys.exit(1)


def solve(
    path,
    finds,
    avoids,
    max_len,
    timeout,
    use_arg,
    enumerate_n,
    charset="printable",
    veritesting=False,
    no_unicorn=False,
    prefix=b"",
):
    if isinstance(prefix, str):
        prefix = prefix.encode()
    if len(prefix) > max_len:
        max_len = len(prefix)
    print(f"[*] angr load: {path}  (auto_load_libs=False)")
    print(
        f"[*] input mode: {'argv[1]' if use_arg else 'stdin'}  ·  max_len={max_len}  ·  charset={charset}"
        f"  ·  prefix={prefix!r}{'  ·  no-unicorn' if no_unicorn else ''}"
        f"{'  ·  veritesting' if veritesting else ''}"
    )
    print(f"[*] find={finds}  avoid={avoids}")
    signal.signal(signal.SIGALRM, _timeout)
    signal.alarm(timeout)
    try:
        proj = angr.Project(path, auto_load_libs=False)
        # leading bytes concrete (the seeded body), the rest symbolic
        key = []
        for i in range(max_len):
            if i < len(prefix):
                key.append(claripy.BVV(prefix[i], 8))
            else:
                key.append(claripy.BVS(f"k_{i}", 8))
        # unicorn accelerates concrete stretches but can thrash on fully-symbolic input
        opts = set() if no_unicorn else angr.options.unicorn
        if use_arg:
            sym = claripy.Concat(*key)
            state = proj.factory.full_init_state(args=[path, sym], add_options=opts)
        else:
            sym = claripy.Concat(*key + [claripy.BVV(b"\n")])
            state = proj.factory.full_init_state(args=[path], add_options=opts, stdin=sym)
        # constrain only the SYMBOLIC bytes to the chosen alphabet
        for c in key:
            if c.symbolic:
                state.solver.add(_charset_constraint(c, charset))

        simgr = proj.factory.simulation_manager(state)
        if veritesting:
            simgr.use_technique(angr.exploration_techniques.Veritesting())

        def hit(st, words):
            out = st.posix.dumps(1).lower()
            # case-insensitive: out is lowered, so lower the marker too
            return any(w.lower().encode() in out for w in words)

        print(f"[*] exploring (timeout {timeout}s)…")
        # success = a success marker present AND no fail marker (handles substring
        # traps like "VALID" ⊂ "INVALID": the INVALID output also contains "valid").
        simgr.explore(
            find=lambda s: hit(s, finds) and not hit(s, avoids),
            avoid=(lambda s: hit(s, avoids)) if avoids else None,
        )

        if not simgr.found:
            print("\n[-] no satisfying path. Try: --arg / different --find / larger --length / longer --prefix.")
            return False
        fs = simgr.found[0]
        sol = fs.solver.eval(sym, cast_to=bytes).rstrip(b"\n")
        print("\n[+] ANGR SUCCESS")
        print(f"[+] VALID LICENSE: {sol!r}")
        print(f"[+] EXTRACTED FLAG: {sol.decode('latin-1', 'replace').strip()}")

        # --- the constraints that lead to a valid license ---
        print("\n[+] PER-BYTE solved values (C=concrete prefix, S=angr-solved):")
        for i, c in enumerate(key):
            v = fs.solver.eval(c)
            tag = "C" if i < len(prefix) else "S"
            print(f"    key[{i:2}] = 0x{v:02x} ({chr(v) if 32 <= v < 127 else '.'})  [{tag}]")
        cons = [
            c for c in fs.solver.constraints if any(k.op == "BVS" and k.args[0] in str(c) for k in key if k.symbolic)
        ]
        print(f"\n[+] SYMBOLIC CONSTRAINTS on the input ({len(cons)}):")
        for c in cons[:80]:
            print("    " + str(c))

        # --- expose fixed vs free bytes by enumerating alternatives ---
        if enumerate_n > 1:
            print(f"\n[+] up to {enumerate_n} distinct valid licenses (reveals which bytes are fixed):")
            seen = set()
            for sval in fs.solver.eval_upto(sym, enumerate_n, cast_to=bytes):
                s = sval.rstrip(b"\n")
                if s not in seen:
                    seen.add(s)
                    print(f"    {s!r}")
        return True
    except Exception as e:
        print(f"\n[-] ANGR ERROR: {e}")
        return False
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="License-crackme angr solver (constraint-finding)")
    ap.add_argument("binary")
    ap.add_argument("--find", action="append", help="success marker (repeatable; default: common set)")
    ap.add_argument("--avoid", action="append", help="failure marker (repeatable; default: common set)")
    ap.add_argument("--length", type=int, default=32)
    ap.add_argument("--timeout", type=int, default=120)
    ap.add_argument("--arg", action="store_true", help="license via argv[1] instead of stdin")
    ap.add_argument("--enumerate", type=int, default=3, dest="enumerate_n")
    ap.add_argument(
        "--charset",
        choices=["printable", "alnum", "upper", "digits"],
        default="printable",
        help="restrict symbolic input bytes (narrow = tames checksum-loop state explosion)",
    )
    ap.add_argument("--prefix", default="", help="pin leading body bytes to a concrete valid string")
    ap.add_argument("--veritesting", action="store_true", help="path-merging DSE (can fault on some targets)")
    ap.add_argument("--no-unicorn", action="store_true", help="disable unicorn engine (helps fully-symbolic input)")
    a = ap.parse_args()
    solve(
        a.binary,
        a.find or DEFAULT_SUCCESS,
        a.avoid or DEFAULT_FAIL,
        a.length,
        a.timeout,
        a.arg,
        a.enumerate_n,
        a.charset,
        a.veritesting,
        a.no_unicorn,
        a.prefix,
    )
