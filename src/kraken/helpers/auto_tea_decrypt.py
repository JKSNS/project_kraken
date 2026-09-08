#!/usr/bin/env python3
"""Kraken helper -- TEA/XTEA/XXTEA block cipher decryption.

Handles the TEA family of lightweight block ciphers commonly found in CTF
reverse engineering challenges. Supports:
- TEA (Tiny Encryption Algorithm) -- 64 rounds default
- XTEA (Extended TEA) -- 32 rounds default  
- XXTEA (Corrected Block TEA) -- variable rounds
- Automatic endianness detection and correction
- Key/ciphertext extraction from binary analysis

Usage:
    python3 auto_tea_decrypt.py --ciphertext "0x63216c73 0x35655933" --key "1 5 8 15" --algo xtea
    python3 auto_tea_decrypt.py --binary ./vm --auto
    python3 auto_tea_decrypt.py --challenge-dir /path/to/challenge --prefix "flag{"
"""

from __future__ import annotations

import argparse
import itertools
import os
import re
import struct
import subprocess
import sys
from ctypes import c_uint32
from pathlib import Path


def tea_decrypt(v: tuple[int, int], k: tuple[int, int, int, int], rounds: int = 64) -> tuple[int, int]:
    """Standard TEA decryption."""
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9E3779B9
    total = c_uint32(delta * rounds)
    for _ in range(rounds):
        v1.value -= ((v0.value << 4) + k[2]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + k[3])
        v0.value -= ((v1.value << 4) + k[0]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + k[1])
        total.value -= delta
    return v0.value, v1.value


def xtea_decrypt(v: tuple[int, int], k: tuple[int, int, int, int], rounds: int = 32) -> tuple[int, int]:
    """XTEA decryption -- the most common variant in CTFs."""
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9E3779B9
    total = c_uint32(delta * rounds)
    for _ in range(rounds):
        v1.value -= ((v0.value << 4) + k[(total.value >> 11) & 3]) ^ (v0.value + total.value) ^ ((v0.value >> 5) + k[(total.value >> 11) & 3])
        total.value -= delta
        v0.value -= ((v1.value << 4) + k[total.value & 3]) ^ (v1.value + total.value) ^ ((v1.value >> 5) + k[total.value & 3])
    return v0.value, v1.value


def xtea_decrypt_standard(v: tuple[int, int], k: tuple[int, int, int, int], rounds: int = 32) -> tuple[int, int]:
    """Standard XTEA decrypt matching most reference implementations."""
    v0, v1 = c_uint32(v[0]), c_uint32(v[1])
    delta = 0x9E3779B9
    total = c_uint32(delta * rounds)
    k0, k1, k2, k3 = k
    for _ in range(rounds):
        v1.value -= ((v0.value << 4) + k2) ^ (v0.value + total.value) ^ ((v0.value >> 5) + k3)
        v0.value -= ((v1.value << 4) + k0) ^ (v1.value + total.value) ^ ((v1.value >> 5) + k1)
        total.value -= delta
    return v0.value, v1.value


def blocks_to_string_le(blocks: list[tuple[int, int]]) -> str:
    """Convert decrypted blocks to string using LITTLE-endian (most common for TEA)."""
    result = b""
    for v0, v1 in blocks:
        result += struct.pack("<I", v0) + struct.pack("<I", v1)
    return result.rstrip(b"\x00").decode("ascii", errors="replace")


def blocks_to_string_be(blocks: list[tuple[int, int]]) -> str:
    """Convert decrypted blocks to string using BIG-endian."""
    result = b""
    for v0, v1 in blocks:
        result += struct.pack(">I", v0) + struct.pack(">I", v1)
    return result.rstrip(b"\x00").decode("ascii", errors="replace")


def try_all_endianness(blocks: list[tuple[int, int]], prefix: str = "flag{") -> str | None:
    """Try both endianness options and return whichever matches the prefix."""
    le = blocks_to_string_le(blocks)
    be = blocks_to_string_be(blocks)
    if le.startswith(prefix):
        return le
    if be.startswith(prefix):
        return be
    # Try with printability heuristic
    le_printable = all(32 <= ord(c) < 127 for c in le if c != "\x00")
    be_printable = all(32 <= ord(c) < 127 for c in be if c != "\x00")
    if le_printable and not be_printable:
        return le
    if be_printable and not le_printable:
        return be
    # Default to little-endian (more common in CTF TEA challenges)
    return le


def parse_int_arg(s: str) -> int:
    """Parse an integer from hex or decimal string."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def extract_tea_params_from_source(challenge_dir: str) -> dict | None:
    """Try to extract TEA/XTEA parameters from source code in challenge dir."""
    params = {"algo": None, "key": None, "ciphertext": None, "rounds": None}
    
    source_files = []
    for ext in ("*.c", "*.cpp", "*.py", "*.java", "*.rs"):
        source_files.extend(Path(challenge_dir).rglob(ext))
    
    for src in source_files:
        try:
            content = src.read_text(errors="ignore")
        except Exception:
            continue
        
        # Detect algorithm
        if "xtea" in content.lower() or "XTEA" in content:
            params["algo"] = "xtea"
        elif "xxtea" in content.lower():
            params["algo"] = "xxtea"
        elif re.search(r"\btea\b", content.lower()):
            params["algo"] = "tea"
        
        # Detect delta constant
        if "0x9e3779b9" in content.lower() or "0x9E3779B9" in content:
            if not params["algo"]:
                params["algo"] = "xtea"  # most common
        
        # Try to find key array
        key_match = re.search(r"key\s*[\[{=]\s*[\[{]?\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)", content)
        if not key_match:
            key_match = re.search(r"key\s*[\[{=]\s*[\[{]?\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)\s*,\s*(0x[0-9a-fA-F]+)", content)
        if key_match:
            params["key"] = tuple(parse_int_arg(key_match.group(i)) for i in range(1, 5))
    
    if params["algo"] and params["key"]:
        return params
    return None


def scan_for_flag(text: str, prefix: str = "flag{") -> str | None:
    """Extract a flag from decrypted text."""
    pattern = re.escape(prefix) + r"[^}]*}"
    m = re.search(pattern, text)
    return m.group(0) if m else None


def main():
    parser = argparse.ArgumentParser(description="TEA/XTEA/XXTEA block cipher decryption")
    parser.add_argument("--ciphertext", help="Ciphertext as space-separated hex uint32 pairs (e.g., '0x63216c73 0x35655933')")
    parser.add_argument("--key", help="Key as 4 space-separated integers (e.g., '1 5 8 15' or '0x1 0x5 0x8 0xf')")
    parser.add_argument("--algo", choices=["tea", "xtea", "xxtea"], default="xtea", help="Algorithm variant")
    parser.add_argument("--rounds", type=int, help="Number of rounds (default: 64 for TEA, 32 for XTEA)")
    parser.add_argument("--prefix", default="flag{", help="Expected flag prefix for endianness detection")
    parser.add_argument("--challenge-dir", help="Challenge directory (auto-extract params from source)")
    parser.add_argument("--binary", help="Binary to analyze for TEA constants")
    args = parser.parse_args()

    # Auto-extract from challenge dir
    if args.challenge_dir and not args.ciphertext:
        params = extract_tea_params_from_source(args.challenge_dir)
        if params:
            print(f"[*] Auto-detected: algo={params['algo']}, key={params['key']}")
            if params["algo"]:
                args.algo = params["algo"]
            if params["key"] and not args.key:
                args.key = " ".join(str(k) for k in params["key"])

    if not args.ciphertext or not args.key:
        print("[-] Need --ciphertext and --key (or --challenge-dir with source code)")
        sys.exit(1)

    # Parse ciphertext blocks
    ct_values = [parse_int_arg(x) for x in args.ciphertext.split()]
    if len(ct_values) % 2 != 0:
        print("[-] Ciphertext must have even number of uint32 values")
        sys.exit(1)
    blocks = [(ct_values[i], ct_values[i + 1]) for i in range(0, len(ct_values), 2)]

    # Parse key
    key = tuple(parse_int_arg(x) for x in args.key.split())
    if len(key) != 4:
        print("[-] Key must be exactly 4 uint32 values")
        sys.exit(1)

    # Set default rounds
    if not args.rounds:
        args.rounds = 64 if args.algo == "tea" else 32

    print(f"[*] Algorithm: {args.algo.upper()}, rounds: {args.rounds}")
    print(f"[*] Key: [{', '.join(hex(k) for k in key)}]")
    print(f"[*] Ciphertext blocks: {len(blocks)}")

    # Decrypt
    decrypted = []
    for v0, v1 in blocks:
        if args.algo == "tea":
            d = tea_decrypt((v0, v1), key, args.rounds)
        elif args.algo == "xtea":
            d = xtea_decrypt_standard((v0, v1), key, args.rounds)
        else:
            print("[-] XXTEA not yet implemented")
            sys.exit(1)
        decrypted.append(d)
        print(f"    ({hex(v0)}, {hex(v1)}) -> ({hex(d[0])}, {hex(d[1])})")

    # Try both endianness
    result = try_all_endianness(decrypted, args.prefix)
    print(f"\n[+] Decrypted (auto-endian): {result}")

    le = blocks_to_string_le(decrypted)
    be = blocks_to_string_be(decrypted)
    print(f"    Little-endian: {le}")
    print(f"    Big-endian:    {be}")

    # Scan for flag
    flag = scan_for_flag(result or "", args.prefix)
    if not flag:
        flag = scan_for_flag(le, args.prefix) or scan_for_flag(be, args.prefix)

    if flag:
        print(f"\nFLAG_CANDIDATE: {flag}")
    else:
        print(f"\n[-] No flag found with prefix '{args.prefix}'")


if __name__ == "__main__":
    main()
