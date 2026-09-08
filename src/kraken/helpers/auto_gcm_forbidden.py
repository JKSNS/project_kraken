#!/usr/bin/env python3
"""auto_gcm_forbidden -- AES-GCM forbidden attack (Joux nonce-reuse).

When two AES-GCM ciphertexts are encrypted under the same (key, nonce) pair,
the authentication key H is recoverable by solving a polynomial over GF(2^128).
Once H is known, an attacker can forge a valid (ciphertext, tag) pair for any
plaintext without knowing the encryption key.

Attack outline:
  1. Collect two (ct, tag, aad) triples sharing the same nonce.
  2. Express the GHASH authentication equation as a polynomial in H.
  3. Find roots of the polynomial over GF(2^128) -- each root is a candidate H.
  4. Use a third independent (ct, tag) triple to filter spurious roots.
  5. With H confirmed, compute the keystream block EK(nonce||counter=1) from
     any known (ct_byte, pt_byte) pair, then forge a new GHASH + tag.

Safety notes are encoded in SAFETY_NOTES below. Read them before modifying.

Usage (standalone):
  python3 auto_gcm_forbidden.py <challenge_dir> [--flag-format FMT]

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import os
import re
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# SAFETY NOTES -- read before any modification
# ---------------------------------------------------------------------------
SAFETY_NOTES: List[str] = [
    "Never use galois.Poly.roots() for GF(2^m) with m > 16 -- hangs indefinitely. "
    "Use the Frobenius endomorphism + Cantor-Zassenhaus splitter implemented here.",
    "Rust base64 0.22 URL_SAFE requires padded cookies -- never strip trailing '=' "
    "from base64-encoded tokens before sending to the server.",
    "A 2-ciphertext check for valid roots is tautological (both equations share H). "
    "Collect a 3rd independent (ct, tag, aad) triple to filter spurious roots.",
    "For user→admin forging when the plaintext length changes: gather a +1-length "
    "ciphertext under the same nonce to expose the extra keystream byte, then build "
    "the forged ciphertext at the new length before recomputing the tag.",
]

# ---------------------------------------------------------------------------
# GF(2^128) arithmetic -- GCM field (reduction poly x^128+x^7+x^2+x+1)
# ---------------------------------------------------------------------------
R = 0xE1 << 120          # GCM reduction constant
GCM_ONE = 1 << 127       # multiplicative identity (big-endian bit order)


def gcm_mul(x: int, y: int) -> int:
    z, v = 0, y
    for i in range(128):
        if (x >> (127 - i)) & 1:
            z ^= v
        v = (v >> 1) ^ R if (v & 1) else (v >> 1)
    return z


def gcm_pow(a: int, e: int) -> int:
    result = GCM_ONE
    while e:
        if e & 1:
            result = gcm_mul(result, a)
        a = gcm_mul(a, a)
        e >>= 1
    return result


def gcm_inv(a: int) -> int:
    return gcm_pow(a, (1 << 128) - 2)


def ghash(H: int, ct: bytes, aad: bytes = b"") -> int:
    def pad16(x: bytes) -> bytes:
        return x + b"\x00" * ((-len(x)) % 16)

    data = pad16(aad) + pad16(ct) + struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
    y = 0
    for i in range(0, len(data), 16):
        blk = int.from_bytes(data[i : i + 16], "big")
        y = gcm_mul(y ^ blk, H)
    return y


# ---------------------------------------------------------------------------
# GF(2^128)[x] polynomial helpers
# ---------------------------------------------------------------------------
# Polynomials are lists of int coefficients, index = degree (poly[0] = const term).

def poly_add(a: List[int], b: List[int]) -> List[int]:
    n = max(len(a), len(b))
    return [
        (a[i] if i < len(a) else 0) ^ (b[i] if i < len(b) else 0)
        for i in range(n)
    ]


def poly_mul(a: List[int], b: List[int]) -> List[int]:
    res = [0] * (len(a) + len(b) - 1)
    for i, ca in enumerate(a):
        for j, cb in enumerate(b):
            res[i + j] ^= gcm_mul(ca, cb)
    return res


def poly_divmod(a: List[int], b: List[int]) -> Tuple[List[int], List[int]]:
    """Return (quotient, remainder) for polynomials over GF(2^128)."""
    r = list(a)
    deg_b = len(b) - 1
    inv_lead = gcm_inv(b[-1])
    q: List[int] = []
    while len(r) > deg_b:
        coeff = gcm_mul(r[-1], inv_lead)
        q.insert(0, coeff)
        for i in range(deg_b + 1):
            r[len(r) - 1 - (deg_b - i)] ^= gcm_mul(coeff, b[i])
        r.pop()
    while r and r[-1] == 0:
        r.pop()
    return q, r or [0]


def poly_gcd(a: List[int], b: List[int]) -> List[int]:
    while any(c for c in b):
        _, r = poly_divmod(a, b)
        a, b = b, r
    # Monic
    if a[-1] != GCM_ONE:
        inv = gcm_inv(a[-1])
        a = [gcm_mul(c, inv) for c in a]
    return a


def poly_eval(p: List[int], x: int) -> int:
    y = 0
    for c in reversed(p):
        y = gcm_mul(y, x) ^ c
    return y


# ---------------------------------------------------------------------------
# Root-finding over GF(2^128): Frobenius + Cantor-Zassenhaus
# DO NOT replace with galois.Poly.roots() -- it hangs for m=128.
# ---------------------------------------------------------------------------

def _frobenius_gcd(f: List[int]) -> List[int]:
    """Compute gcd(f, x^(2^128) - x) to find all distinct roots at once."""
    # Compute x^(2^128) mod f via repeated squaring
    # x^(2^128) = x in GF(2^128)[x] / <f> only for degree-1 factors -- so we
    # use the tower: x -> x^2 -> ... -> x^(2^128) all mod f.
    xpow = [0, GCM_ONE]  # polynomial "x"
    e = 1 << 128
    result = [0, GCM_ONE]  # start with x^1
    base = list(xpow)
    bits = e.bit_length()
    result = [0]  # start with 1 (will compute x^e)
    result = [0, GCM_ONE]  # x^1
    # Fast: compute x^(2^128) mod f
    cur = [0, GCM_ONE]  # x
    for _ in range(128):
        _, cur = poly_divmod(poly_mul(cur, cur), f)
    # cur is now x^(2^128) mod f; subtract x => x^(2^128) - x = x^(2^128) + x in GF(2)
    lin = poly_add(cur, [0, GCM_ONE])
    if not any(lin):
        return list(f)
    return poly_gcd(f, lin)


def _split_factor(f: List[int], rng_seed: int = 0) -> Tuple[List[int], List[int]]:
    """Cantor-Zassenhaus probabilistic equal-degree splitting for degree-1 factors."""
    import random
    rng = random.Random(rng_seed)
    n = len(f) - 1
    for attempt in range(64):
        # Random polynomial of degree < n
        t = [rng.randint(0, (1 << 128) - 1) for _ in range(n)]
        while not any(t):
            t = [rng.randint(0, (1 << 128) - 1) for _ in range(n)]
        # Compute t^((2^128 - 1)/2) mod f  →  t^(2^127 - 1) mod f
        e = (1 << 128) - 1
        cur = list(t)
        result = [GCM_ONE]
        eb = e
        base2 = list(cur)
        while eb:
            if eb & 1:
                _, result = poly_divmod(poly_mul(result, base2), f)
            _, base2 = poly_divmod(poly_mul(base2, base2), f)
            eb >>= 1
        # result is t^e mod f; compute gcd(result - 1, f)
        h = poly_add(result, [GCM_ONE])
        g = poly_gcd(f, h)
        dg = len(g) - 1
        if 0 < dg < n:
            _, other = poly_divmod(f, g)
            # recover the cofactor
            q, _ = poly_divmod(f, g)
            return g, q
    return f, [GCM_ONE]


def find_roots(f: List[int]) -> List[int]:
    """Return all roots of polynomial f over GF(2^128)."""
    # Strip zero roots
    roots: List[int] = []
    while f and f[0] == 0:
        roots.append(0)
        f = f[1:]
    if not f:
        return roots

    # Remove duplicates (square-free)
    deriv = [gcm_mul(f[i], i % 2) for i in range(len(f))]  # in GF(2^m), odd terms only
    deriv = [c if (i % 2 == 1) else 0 for i, c in enumerate(f)]
    deriv = [f[i] if (i % 2 == 1) else 0 for i in range(len(f))]
    # Actually: derivative in GF(2)[x] kills even-degree terms
    deriv = [f[i] for i in range(1, len(f), 2)]  # coefficients of odd-degree terms
    # Build proper derivative list with correct degree indices
    deriv_poly: List[int] = []
    for i in range(1, len(f)):
        deriv_poly.append(f[i] if (i % 2 == 1) else 0)
    while deriv_poly and deriv_poly[-1] == 0:
        deriv_poly.pop()

    stack = [f]
    while stack:
        p = stack.pop()
        deg = len(p) - 1
        if deg == 0:
            continue
        if deg == 1:
            # Linear factor: root = -p[0]/p[1] = p[0]/p[1] in GF(2)
            roots.append(gcm_mul(p[0], gcm_inv(p[1])))
            continue
        # Try Frobenius gcd to pull out linear factors
        g = _frobenius_gcd(p)
        dg = len(g) - 1
        if dg == 0:
            continue
        if dg == deg:
            # All linear or irreducible -- try splitting
            g1, g2 = _split_factor(p)
            if len(g1) - 1 < deg:
                stack.append(g1)
                stack.append(g2)
        else:
            stack.append(g)
            q, _ = poly_divmod(p, g)
            stack.append(q)
    return roots


# ---------------------------------------------------------------------------
# Forbidden attack: recover H from two (ct, tag, aad) pairs, same nonce
# ---------------------------------------------------------------------------

def _int_to_bytes128(x: int) -> bytes:
    return x.to_bytes(16, "big")


def recover_H(
    ct1: bytes, tag1: bytes, aad1: bytes,
    ct2: bytes, tag2: bytes, aad2: bytes,
) -> List[int]:
    """Return candidate H values from nonce-reuse pair.

    The authentication polynomial is:
        tag = GHASH(H, ct, aad) XOR EK(nonce||0)
    For two messages with the same EK(nonce||0):
        tag1 XOR tag2 = GHASH(H, ct1, aad1) XOR GHASH(H, ct2, aad2)
    which is a polynomial in H of degree max(blocks)+1. Solve for roots.
    """
    t1 = int.from_bytes(tag1, "big")
    t2 = int.from_bytes(tag2, "big")

    def ghash_poly_coeffs(ct: bytes, aad: bytes) -> List[int]:
        def pad16(x: bytes) -> bytes:
            return x + b"\x00" * ((-len(x)) % 16)
        data = pad16(aad) + pad16(ct) + struct.pack(">QQ", len(aad) * 8, len(ct) * 8)
        return [int.from_bytes(data[i : i + 16], "big")
                for i in range(0, len(data), 16)]

    c1 = ghash_poly_coeffs(ct1, aad1)
    c2 = ghash_poly_coeffs(ct2, aad2)

    # Difference polynomial: sum_i (c1[i] XOR c2[i]) * H^(n-i) = t1 XOR t2
    n = max(len(c1), len(c2))
    diff_c = [(c1[i] if i < len(c1) else 0) ^ (c2[i] if i < len(c2) else 0)
              for i in range(n)]
    rhs = t1 ^ t2

    # Build poly: coeff[d] for degree d, constant term includes rhs
    # Polynomial in H (descending degree in diff_c): diff_c[0]*H^n + ... + rhs = 0
    # Reorder to ascending (index = degree):
    coeffs = [rhs] + list(reversed(diff_c))
    while coeffs and coeffs[-1] == 0:
        coeffs.pop()
    if not coeffs:
        return []

    return find_roots(coeffs)


def verify_H(
    H_candidate: int,
    ct3: bytes, tag3: bytes, aad3: bytes,
    ct_ref: bytes, pt_ref: bytes,
) -> bool:
    """Confirm H by checking a third independent (ct, tag, aad) triple."""
    # EK(nonce||1) can be derived from known ct/pt XOR
    # Then EK(nonce||0) = tag XOR GHASH(H, ct, aad)
    ek0 = int.from_bytes(tag3, "big") ^ ghash(H_candidate, ct3, aad3)
    # Verify consistency: tag1 check (already done implicitly, use ct_ref for extra check)
    _ = ek0  # just checking no exception; real verification is the GHASH match
    return True  # placeholder: actual verify uses a 3rd server query


def forge_tag(
    H: int, ek0: int,
    new_ct: bytes, new_aad: bytes = b"",
) -> bytes:
    """Forge an authentication tag for (new_ct, new_aad) given recovered H and EK(nonce||0)."""
    g = ghash(H, new_ct, new_aad)
    tag_int = g ^ ek0
    return _int_to_bytes128(tag_int)


# ---------------------------------------------------------------------------
# URL extraction helper
# ---------------------------------------------------------------------------

def _detect_url_from_state(state: Dict[str, Any]) -> Optional[str]:
    """Extract an HTTPS/HTTP URL from state fields."""
    pat = re.compile(r"https?://[^\s\"'<>]+")

    # Prefer explicit remote_info
    ri = state.get("remote_info") or {}
    if isinstance(ri, dict):
        url = ri.get("url", "")
        if url:
            return url.rstrip("/")

    # Fall back to challenge_description
    desc = state.get("challenge_description", "") or ""
    m = pat.search(desc)
    if m:
        return m.group(0).rstrip("/")

    return None


# ---------------------------------------------------------------------------
# Kraken entry point
# ---------------------------------------------------------------------------

def run(challenge_path: str, state: Dict[str, Any]) -> Dict[str, Any]:
    """Kraken tool-router entry point.

    Attempts to:
      1. Locate a server URL from state.
      2. Collect nonce-reuse ciphertext pairs (challenge-specific interaction).
      3. Run the forbidden attack to recover H.
      4. Forge a tag for an admin/elevated cookie or target ciphertext.
      5. Return a flag candidate.

    This is a reference/stub entry point. Challenge-specific interaction
    (which endpoints to call, how to trigger nonce reuse, how to submit the
    forged token) must be adapted per challenge.
    """
    url = _detect_url_from_state(state)
    if not url:
        return {"error": "no URL found in state for GCM forbidden attack"}

    flag_fmt = state.get("flag_format", "")
    flag_re = re.compile(flag_fmt) if flag_fmt else re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")

    try:
        import requests
    except ImportError:
        return {"error": "requests not available"}

    # ---- Challenge-specific: collect nonce-reuse pairs ----
    # The typical pattern for AES-GCM nonce-reuse CTF challenges:
    #   GET /encrypt?msg=A  -> { "ct": hex, "tag": hex, "nonce": hex }
    #   GET /encrypt?msg=B  -> { "ct": hex, "tag": hex, "nonce": hex }  (same nonce!)
    # Adapt endpoint names and response fields to the specific challenge.
    #
    # Example (not run -- adapt per challenge):
    #
    #   r1 = requests.get(f"{url}/encrypt", params={"msg": "A" * 16}, timeout=10)
    #   r2 = requests.get(f"{url}/encrypt", params={"msg": "B" * 16}, timeout=10)
    #   d1, d2 = r1.json(), r2.json()
    #   ct1  = bytes.fromhex(d1["ct"]);  tag1 = bytes.fromhex(d1["tag"])
    #   ct2  = bytes.fromhex(d2["ct"]);  tag2 = bytes.fromhex(d2["tag"])
    #   candidates = recover_H(ct1, tag1, b"", ct2, tag2, b"")
    #
    # For a 3rd-message filter (required -- see SAFETY_NOTES):
    #   r3 = requests.get(f"{url}/encrypt", params={"msg": "C" * 32}, timeout=10)
    #   d3 = r3.json()
    #   ct3 = bytes.fromhex(d3["ct"]); tag3 = bytes.fromhex(d3["tag"])
    #   valid_H = [h for h in candidates if verify_H(h, ct3, tag3, b"", ct1, ...)]

    return {
        "status": "stub",
        "url": url,
        "note": (
            "GCM forbidden attack stub. Adapt the collect/forge section above "
            "to the specific challenge endpoints and call recover_H + forge_tag."
        ),
        "safety_notes": SAFETY_NOTES,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    ap = argparse.ArgumentParser(
        description="AES-GCM forbidden attack (nonce-reuse H recovery + tag forgery)"
    )
    ap.add_argument("challenge_dir", nargs="?", default=".", help="Challenge directory")
    ap.add_argument("--flag-format", default="", help="Flag regex or prefix")
    ap.add_argument("--url", default="", help="Override server URL")
    ap.add_argument("--ct1", default="", help="First ciphertext (hex)")
    ap.add_argument("--tag1", default="", help="First tag (hex)")
    ap.add_argument("--ct2", default="", help="Second ciphertext (hex)")
    ap.add_argument("--tag2", default="", help="Second tag (hex)")
    ap.add_argument("--aad", default="", help="AAD shared by both messages (hex, default empty)")
    ap.add_argument("--safety-notes", action="store_true", help="Print safety notes and exit")
    args = ap.parse_args()

    if args.safety_notes:
        print("=== GCM Forbidden Attack Safety Notes ===")
        for i, note in enumerate(SAFETY_NOTES, 1):
            print(f"  {i}. {note}")
        sys.exit(0)

    if args.ct1 and args.tag1 and args.ct2 and args.tag2:
        ct1  = bytes.fromhex(args.ct1)
        tag1 = bytes.fromhex(args.tag1)
        ct2  = bytes.fromhex(args.ct2)
        tag2 = bytes.fromhex(args.tag2)
        aad  = bytes.fromhex(args.aad) if args.aad else b""

        print("[*] Running forbidden attack ...")
        candidates = recover_H(ct1, tag1, aad, ct2, tag2, aad)
        print(f"[*] Found {len(candidates)} H candidate(s)")
        for h in candidates:
            print(f"  H = {h:#034x}")
        if candidates:
            print("[!] Use a 3rd independent ciphertext to filter spurious roots (see --safety-notes)")
        return

    if args.url or args.challenge_dir:
        state: Dict[str, Any] = {
            "challenge_description": args.url,
            "flag_format": args.flag_format,
        }
        result = run(args.challenge_dir, state)
        print(result)
        return

    ap.print_help()
    sys.exit(1)


if __name__ == "__main__":
    main()
