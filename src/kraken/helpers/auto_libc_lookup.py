#!/usr/bin/env python3
"""auto_libc_lookup -- Identify libc version from leaked function addresses.

Given one or more leaked libc function addresses, identifies the glibc version
and returns offsets for key exploitation primitives (system, /bin/sh, one_gadgets).

Two modes:
  1. Lookup mode: Given leaked addresses, identify libc and print offsets
  2. Offset mode: Given a libc binary, extract all useful offsets

Usage:
  python3 auto_libc_lookup.py --leak puts=0x7f1234580970
  python3 auto_libc_lookup.py --leak puts=0x7f1234580970 --leak printf=0x7f123464e10
  python3 auto_libc_lookup.py --leak __libc_start_main_ret=0x7f12340270b3
  python3 auto_libc_lookup.py --libc ./libc.so.6
  python3 auto_libc_lookup.py --last12 puts=970 --last12 printf=e10

Outputs (to stdout):
  LIBC_VERSION: 2.38
  LIBC_BASE: 0x7f1234500000
  SYSTEM: 0x58740
  BINSH: 0x1d8678
  ONE_GADGETS: 0xebc81,0xebc85,0xebc88

Outputs EXTRACTED FLAG: <flag> if a flag is found in libc binary strings.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import Any


def _e(ver: str, arch: str, syms: dict, gadgets: list[int] | None = None) -> dict:
    """Build a LIBC_DB entry."""
    return {
        "id": f"glibc-{ver}-{arch}", "arch": arch, "version": ver,
        "symbols": syms, "one_gadgets": gadgets or [],
    }


# Shorthand keys: p=puts, f=printf, s=system, m=__libc_start_main,
#                  r=__libc_start_main_ret, b=str_bin_sh
def _s(p: int, f: int, s: int, b: int,
       m: int = 0, r: int = 0) -> dict:
    """Build symbols dict from compact args."""
    d: dict[str, int] = {
        "puts": p, "printf": f, "system": s, "str_bin_sh": b,
    }
    if m:
        d["__libc_start_main"] = m
    if r:
        d["__libc_start_main_ret"] = r
    return d


# Built-in glibc offset database: amd64 (2.19-2.40) + i386 (2.19-2.38)
LIBC_DB: list[dict[str, Any]] = [
    # amd64
    _e("2.19", "amd64", _s(0x6fd60, 0x54340, 0x41490, 0x1756f2, 0x21dd0, 0x21f45),
       [0x41bce, 0x41bd2, 0x41bd6]),
    _e("2.23", "amd64", _s(0x6f690, 0x55800, 0x45390, 0x18cd57, 0x20740, 0x20830),
       [0x45216, 0x4526a, 0xf02a4, 0xf1147]),
    _e("2.27", "amd64", _s(0x77980, 0x64e80, 0x48170, 0x1a5439, 0x21a50, 0x21b97),
       [0x4f2a5, 0x4f302, 0x10a2fc]),
    _e("2.28", "amd64", _s(0x71910, 0x5f8f0, 0x44a30, 0x181519, 0x21560, 0x216a3),
       [0x448a3, 0xe5456, 0xe5459, 0xe545c]),
    _e("2.29", "amd64", _s(0x72fa0, 0x60e10, 0x47cb0, 0x19a2e0, 0x23f90, 0x240e6),
       [0xe21ce, 0xe21d1, 0xe21d4]),
    _e("2.31", "amd64", _s(0x80970, 0x64e10, 0x4f420, 0x1b3e9a, 0x26fc0, 0x270b3),
       [0xe3afe, 0xe3b01, 0xe3b04]),
    _e("2.33", "amd64", _s(0x7a0d0, 0x5dab0, 0x4e520, 0x1abf05, 0x28a10, 0x28a90),
       [0xde78f, 0xde792, 0xde795]),
    _e("2.34", "amd64", _s(0x7e4e0, 0x5f340, 0x4fc60, 0x1b45bd, 0x29510, 0x29590),
       [0xe4fc1, 0xe4fc5, 0xe4fc8]),
    _e("2.35", "amd64", _s(0x80e50, 0x60770, 0x50d70, 0x1d8698, 0x29d10, 0x29d90),
       [0xebcf1, 0xebcf5, 0xebcf8]),
    _e("2.36", "amd64", _s(0x80e50, 0x60770, 0x50d70, 0x1d8698, 0x29d10, 0x29d90),
       [0xebcf1, 0xebcf5, 0xebcf8]),
    _e("2.37", "amd64", _s(0x87bd0, 0x606f0, 0x58740, 0x1d8678, 0x29d10, 0x29d90),
       [0xebc81, 0xebc85, 0xebc88]),
    _e("2.38", "amd64", _s(0x87bd0, 0x600f0, 0x58740, 0x1d8678, 0x2a150, 0x2a1ca),
       [0xebc81, 0xebc85, 0xebc88]),
    _e("2.39", "amd64", _s(0x87bd0, 0x61eb0, 0x58740, 0x1d8678, 0x2a150, 0x2a1ca),
       [0xebc81, 0xebc85, 0xebc88]),
    _e("2.40", "amd64", _s(0x88980, 0x62a30, 0x59060, 0x1db020, 0x2a510, 0x2a58a),
       [0xebc81, 0xebc85, 0xebc88]),
    # i386
    _e("2.19", "i386", _s(0x5fca0, 0x4d280, 0x3ada0, 0x15da84)),
    _e("2.23", "i386", _s(0x5fca0, 0x4d280, 0x3ada0, 0x15ba0b)),
    _e("2.27", "i386", _s(0x67360, 0x51430, 0x3cd10, 0x17b8cf)),
    _e("2.31", "i386", _s(0x6e030, 0x52430, 0x41360, 0x18c338)),
    _e("2.35", "i386", _s(0x6e9f0, 0x54670, 0x44cc0, 0x1b18a2)),
    _e("2.38", "i386", _s(0x6f8c0, 0x55560, 0x45b30, 0x1b2da0)),
]


# ---------------------------------------------------------------------------
# Matching algorithms
# ---------------------------------------------------------------------------


def identify_libc(leaks: dict[str, int], arch: str = "amd64") -> list[dict]:
    """Match leaked addresses against known libc versions.

    Args:
        leaks: Mapping of function name to leaked runtime address,
               e.g. {"puts": 0x7f1234580970}.
        arch:  Target architecture ("amd64" or "i386").

    Returns:
        List of matching entries sorted by confidence (number of matching leaks).
    """
    matches: list[dict] = []
    for entry in LIBC_DB:
        if entry["arch"] != arch:
            continue
        base_candidates: list[int] = []
        for func_name, leaked_addr in leaks.items():
            known_off = entry["symbols"].get(func_name)
            if known_off is None:
                continue
            candidate_base = leaked_addr - known_off
            # Base must be page-aligned and positive
            if candidate_base & 0xFFF == 0 and candidate_base > 0:
                base_candidates.append(candidate_base)
        if not base_candidates:
            continue
        # All leaked addresses must agree on the same base
        if len(set(base_candidates)) == 1:
            matches.append({
                "entry": entry, "base": base_candidates[0],
                "confidence": len(base_candidates),
            })
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return matches


def identify_by_last12(last12: dict[str, int], arch: str = "amd64") -> list[dict]:
    """Match by last 12 bits of leaked addresses (partial-leak mode).

    The low 12 bits (page offset) are deterministic per libc build, so even
    with ASLR the page offset can fingerprint the libc version.
    """
    matches: list[dict] = []
    for entry in LIBC_DB:
        if entry["arch"] != arch:
            continue
        match_count = 0
        for func_name, bits12 in last12.items():
            known_off = entry["symbols"].get(func_name)
            if known_off is not None and (known_off & 0xFFF) == bits12:
                match_count += 1
        if match_count > 0:
            matches.append({"entry": entry, "confidence": match_count})
    matches.sort(key=lambda m: m["confidence"], reverse=True)
    return matches


# ---------------------------------------------------------------------------
# Libc binary analysis (pwntools with readelf/strings fallback)
# ---------------------------------------------------------------------------

FLAG_RE = re.compile(
    r"(?:flag|ctf|picoCTF|HTB|CACI|ractf|bcactf)\{[^}]+\}", re.IGNORECASE,
)


def analyze_libc_binary(path: str) -> dict[str, int]:
    """Extract offsets from a libc.so binary.

    Tries pwntools ELF first, falls back to readelf + strings.
    """
    result: dict[str, int] = {}
    # Try pwntools
    try:
        from pwn import ELF  # type: ignore[import-untyped]
        elf = ELF(path, checksec=False)
        for sym in ("system", "puts", "printf", "__libc_start_main"):
            val = elf.symbols.get(sym)
            if val:
                result[sym] = val
        binsh = next(elf.search(b"/bin/sh"), None)
        if binsh is not None:
            result["str_bin_sh"] = binsh
        return result
    except Exception:
        pass
    # Fallback: readelf
    try:
        out = subprocess.check_output(
            ["readelf", "-sW", path], stderr=subprocess.DEVNULL, text=True,
        )
        for line in out.splitlines():
            for sym in ("system", "puts", "printf", "__libc_start_main"):
                if f" {sym}@@" in line or f" {sym}\n" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            result[sym] = int(parts[1], 16)
                        except ValueError:
                            pass
    except Exception:
        pass
    # Fallback: strings for /bin/sh
    try:
        out = subprocess.check_output(
            ["strings", "-t", "x", path], stderr=subprocess.DEVNULL, text=True,
        )
        for line in out.splitlines():
            if "/bin/sh" in line:
                parts = line.strip().split(None, 1)
                if parts:
                    try:
                        result["str_bin_sh"] = int(parts[0], 16)
                    except ValueError:
                        pass
                    break
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------


def _print_result(entry: dict, base: int | None, as_json: bool = False) -> None:
    """Print identified libc information to stdout."""
    print(f"LIBC_VERSION: {entry['version']}")
    print(f"LIBC_ID: {entry['id']}")
    if base is not None:
        print(f"LIBC_BASE: {hex(base)}")
    print(f"SYSTEM: {hex(entry['symbols']['system'])}")
    print(f"BINSH: {hex(entry['symbols']['str_bin_sh'])}")
    if entry.get("one_gadgets"):
        print(f"ONE_GADGETS: {','.join(hex(g) for g in entry['one_gadgets'])}")
    for name, off in sorted(entry["symbols"].items()):
        print(f"OFFSET_{name}: {hex(off)}")
    if as_json:
        print(json.dumps({
            "version": entry["version"], "id": entry["id"],
            "base": hex(base) if base else None,
            "symbols": {k: hex(v) for k, v in entry["symbols"].items()},
            "one_gadgets": [hex(g) for g in entry.get("one_gadgets", [])],
        }, indent=2))


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Identify libc version from leaked function addresses",
    )
    parser.add_argument(
        "--leak", action="append", metavar="FUNC=ADDR",
        help="Leaked address, e.g. puts=0x7f1234580970 (repeatable)",
    )
    parser.add_argument(
        "--last12", action="append", metavar="FUNC=BITS",
        help="Last 12 bits of leaked address, e.g. puts=970 (repeatable)",
    )
    parser.add_argument("--libc", metavar="PATH", help="Path to libc.so binary")
    parser.add_argument(
        "--arch", default="amd64", choices=["amd64", "i386"],
        help="Target architecture (default: amd64)",
    )
    parser.add_argument("--json", action="store_true", help="Also output as JSON")
    args = parser.parse_args()

    # Mode 1: analyse a local libc binary
    if args.libc:
        path = os.path.expanduser(args.libc)
        if not os.path.isfile(path):
            print(f"[-] File not found: {path}", file=sys.stderr)
            sys.exit(1)
        info = analyze_libc_binary(path)
        if not info:
            print("[-] Could not extract symbols from binary", file=sys.stderr)
            sys.exit(1)
        for k, v in sorted(info.items()):
            print(f"{k.upper()}: {hex(v)}")
        try:
            data = open(path, "rb").read()
            for m in FLAG_RE.finditer(data.decode("latin-1")):
                print(f"EXTRACTED FLAG: {m.group(0)}")
        except Exception:
            pass
        return

    # Parse leak arguments
    leaks: dict[str, int] = {}
    if args.leak:
        for item in args.leak:
            if "=" not in item:
                print(f"[-] Invalid --leak format: {item!r}", file=sys.stderr)
                sys.exit(1)
            name, addr_s = item.split("=", 1)
            try:
                leaks[name] = int(addr_s, 0)
            except ValueError:
                print(f"[-] Invalid address: {addr_s!r}", file=sys.stderr)
                sys.exit(1)

    last12_map: dict[str, int] = {}
    if args.last12:
        for item in args.last12:
            if "=" not in item:
                print(f"[-] Invalid --last12 format: {item!r}", file=sys.stderr)
                sys.exit(1)
            name, bits_s = item.split("=", 1)
            try:
                last12_map[name] = int(bits_s, 16)
            except ValueError:
                print(f"[-] Invalid hex bits: {bits_s!r}", file=sys.stderr)
                sys.exit(1)

    # Mode 2: lookup by leaked addresses
    if leaks:
        results = identify_libc(leaks, args.arch)
    elif last12_map:
        results = identify_by_last12(last12_map, args.arch)
    else:
        print("Error: provide --leak, --last12, or --libc", file=sys.stderr)
        sys.exit(1)

    if not results:
        print("[-] No matching libc found", file=sys.stderr)
        sys.exit(1)

    best = results[0]
    _print_result(best["entry"], best.get("base"), as_json=args.json)

    if len(results) > 1:
        print(f"\n[+] {len(results) - 1} additional candidate(s):")
        for alt in results[1:]:
            e = alt["entry"]
            extra = f", base={hex(alt['base'])}" if "base" in alt else ""
            print(f"    {e['id']} (confidence={alt['confidence']}{extra})")


if __name__ == "__main__":
    main()
