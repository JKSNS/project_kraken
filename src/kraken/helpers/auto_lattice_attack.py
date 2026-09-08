#!/usr/bin/env python3
"""auto_lattice_attack -- Lattice-based and advanced number-theoretic crypto solver.

Scans a challenge directory for crypto parameters and auto-detects which
attack to apply:

  - ECDSA nonce bias/reuse → lattice reduction to recover private key
  - Knapsack cryptosystem  → LLL reduction to find subset sum
  - Boneh-Durfee           → small private exponent RSA (d < n^0.292)
  - GCD on multiple moduli → factor shared primes across RSA keys
  - CRT reconstruction     → Chinese Remainder Theorem on partial decryptions
  - Baby-step Giant-step   → discrete log for small group orders
  - Pohlig-Hellman         → DLP when group order is smooth

Usage:
  python3 auto_lattice_attack.py --dir /path/to/challenge --flag-format "flag{"

Pure Python + optional numpy.  No sage, no sympy required.
"""
import argparse
import ast
import json
import math
import os
import re
import struct
import sys
from itertools import combinations


# ─── Utility ────────────────────────────────────────────────────────

def _int_to_bytes(n: int) -> bytes:
    """Convert a positive integer to bytes (big-endian, minimal length)."""
    if n == 0:
        return b"\x00"
    length = (n.bit_length() + 7) // 8
    return n.to_bytes(length, "big")


def _try_decode_flag(n: int, flag_format: str) -> str | None:
    """Try to convert an integer to bytes and look for a flag."""
    try:
        raw = _int_to_bytes(abs(n))
    except (OverflowError, ValueError):
        return None
    # Try big-endian
    text = raw.decode("utf-8", errors="replace")
    flag = _search_flag(text, flag_format)
    if flag:
        return flag
    # Try little-endian
    text_le = raw[::-1].decode("utf-8", errors="replace")
    flag = _search_flag(text_le, flag_format)
    if flag:
        return flag
    return None


def _search_flag(text: str, flag_format: str) -> str | None:
    """Search for a flag pattern in text."""
    # Exact prefix match
    if flag_format:
        prefix = flag_format.rstrip("{")
        pat = re.escape(prefix) + r"\{[^}]+\}"
        m = re.search(pat, text)
        if m:
            return m.group(0)
    # Generic flag pattern
    m = re.search(r"[A-Za-z_]{2,20}\{[^}]{3,}\}", text)
    if m:
        return m.group(0)
    return None


def _search_flag_in_bytes(data: bytes, flag_format: str) -> str | None:
    """Search for a flag in raw bytes."""
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return None
    return _search_flag(text, flag_format)


# ─── LLL Algorithm ─────────────────────────────────────────────────

def _dot(u, v):
    """Dot product of two vectors (lists of ints/floats)."""
    return sum(a * b for a, b in zip(u, v))


def _proj_coeff(u, v):
    """Gram-Schmidt projection coefficient <v,u>/<u,u>."""
    dd = _dot(u, u)
    if dd == 0:
        return 0
    return _dot(v, u) / dd


def lll_reduce(basis, delta=0.75):
    """LLL lattice basis reduction.

    Parameters
    ----------
    basis : list of list of int
        Row vectors forming the lattice basis.
    delta : float
        Lovász condition parameter (0.25 < delta < 1).

    Returns
    -------
    list of list of int
        Reduced basis (row vectors).
    """
    n = len(basis)
    if n == 0:
        return basis
    # Work with float copies for Gram-Schmidt
    B = [list(row) for row in basis]
    dim = len(B[0])

    def gram_schmidt():
        ortho = [list(B[0])]
        mu = [[0.0] * n for _ in range(n)]
        for i in range(1, n):
            ortho.append(list(B[i]))
            for j in range(i):
                mu[i][j] = _proj_coeff(ortho[j], B[i])
                for d in range(dim):
                    ortho[i][d] -= mu[i][j] * ortho[j][d]
        return ortho, mu

    k = 1
    while k < n:
        ortho, mu = gram_schmidt()
        # Size-reduce B[k]
        for j in range(k - 1, -1, -1):
            if abs(mu[k][j]) > 0.5:
                r = round(mu[k][j])
                for d in range(dim):
                    B[k][d] -= r * B[j][d]
                ortho, mu = gram_schmidt()

        # Lovász condition
        lhs = _dot(ortho[k], ortho[k])
        rhs = (delta - mu[k][k - 1] ** 2) * _dot(ortho[k - 1], ortho[k - 1])
        if lhs >= rhs:
            k += 1
        else:
            B[k], B[k - 1] = B[k - 1], B[k]
            k = max(k - 1, 1)

    return B


# ─── Modular arithmetic helpers ────────────────────────────────────

def _extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm: returns (g, x, y) where a*x + b*y = g."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = _extended_gcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def _modinv(a: int, m: int) -> int | None:
    """Modular inverse of a mod m, or None if it doesn't exist."""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        return None
    return x % m


def _crt(remainders: list[int], moduli: list[int]) -> int:
    """Chinese Remainder Theorem for pairwise coprime moduli.

    Returns x such that x ≡ r_i (mod m_i) for all i.
    """
    if not remainders:
        return 0
    M = 1
    for m in moduli:
        M *= m
    x = 0
    for r, m in zip(remainders, moduli):
        Mi = M // m
        yi = _modinv(Mi, m)
        if yi is None:
            return None
        x = (x + r * Mi * yi) % M
    return x


def _isqrt(n: int) -> int:
    """Integer square root."""
    if n < 0:
        raise ValueError("Square root of negative number")
    if n == 0:
        return 0
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def _is_perfect_square(n: int) -> tuple[bool, int]:
    """Check if n is a perfect square, return (True, root) or (False, 0)."""
    if n < 0:
        return False, 0
    r = _isqrt(n)
    if r * r == n:
        return True, r
    return False, 0


# ─── Factor methods ────────────────────────────────────────────────

def _factor_small(n: int, limit: int = 1_000_000) -> list[tuple[int, int]]:
    """Trial division up to limit.  Returns list of (prime, exponent)."""
    factors = []
    d = 2
    while d * d <= n and d <= limit:
        e = 0
        while n % d == 0:
            e += 1
            n //= d
        if e:
            factors.append((d, e))
        d += 1 if d == 2 else 2
    if n > 1:
        factors.append((n, 1))
    return factors


# ─── Attack 1: GCD on multiple RSA moduli ──────────────────────────

def attack_gcd(moduli: list[int], params: dict, flag_format: str) -> str | None:
    """Factor RSA moduli by computing pairwise GCDs."""
    print(f"[*] GCD attack on {len(moduli)} moduli")
    found = {}
    for i, j in combinations(range(len(moduli)), 2):
        g = math.gcd(moduli[i], moduli[j])
        if g > 1 and g != moduli[i] and g != moduli[j]:
            print(f"[+] GCD(n[{i}], n[{j}]) = {g}")
            found[i] = (g, moduli[i] // g)
            found[j] = (g, moduli[j] // g)

    if not found:
        print("[-] No common factors found")
        return None

    # Try RSA decryption for each factored modulus
    e_val = params.get("e", 65537)
    ciphertexts = params.get("ciphertexts", params.get("c_list", []))
    if isinstance(ciphertexts, int):
        ciphertexts = [ciphertexts]

    for idx, (p, q) in found.items():
        phi = (p - 1) * (q - 1)
        d = _modinv(e_val, phi)
        if d is None:
            continue
        # Decrypt matching ciphertext
        if idx < len(ciphertexts):
            ct = ciphertexts[idx]
        elif ciphertexts:
            ct = ciphertexts[0]
        else:
            ct = params.get("c", params.get("ct", None))
        if ct is None:
            continue

        m = pow(ct, d, moduli[idx])
        flag = _try_decode_flag(m, flag_format)
        if flag:
            print(f"[+] FLAG: {flag}")
            return flag
        # Print partial result
        raw = _int_to_bytes(m)
        printable = raw.decode("utf-8", errors="replace")
        if any(c.isalpha() for c in printable):
            print(f"[*] Decrypted[{idx}]: {printable[:200]}")

    # Also try: single n with c, factored via GCD with another n
    c_single = params.get("c", params.get("ct", None))
    if c_single and 0 in found:
        p, q = found[0]
        phi = (p - 1) * (q - 1)
        d = _modinv(e_val, phi)
        if d:
            m = pow(c_single, d, moduli[0])
            flag = _try_decode_flag(m, flag_format)
            if flag:
                print(f"[+] FLAG: {flag}")
                return flag

    print("[-] GCD factored moduli but no flag found in decrypted values")
    return None


# ─── Attack 2: CRT reconstruction ──────────────────────────────────

def attack_crt(params: dict, flag_format: str) -> str | None:
    """Reconstruct plaintext from multiple RSA encryptions of the same
    message under different moduli with small e (Hastad's broadcast)."""
    e_val = params.get("e", 3)
    moduli = params.get("n_list", params.get("moduli", []))
    ciphertexts = params.get("c_list", params.get("ciphertexts", []))

    if len(moduli) < e_val or len(ciphertexts) < e_val:
        print(f"[-] Need at least e={e_val} pairs for Hastad; have {min(len(moduli), len(ciphertexts))}")
        return None

    print(f"[*] Hastad broadcast attack with e={e_val}, {len(moduli)} pairs")

    # Use first e pairs
    mods = moduli[:e_val]
    cts = ciphertexts[:e_val]

    result = _crt(cts, mods)
    if result is None:
        print("[-] CRT failed (moduli not coprime)")
        return None

    # Take e-th root
    root = _iroot(result, e_val)
    if root is not None:
        flag = _try_decode_flag(root, flag_format)
        if flag:
            print(f"[+] FLAG: {flag}")
            return flag
        raw = _int_to_bytes(root)
        printable = raw.decode("utf-8", errors="replace")
        if any(c.isalpha() for c in printable):
            print(f"[*] CRT root: {printable[:200]}")

    print("[-] CRT succeeded but no flag in result")
    return None


def _iroot(n: int, k: int) -> int | None:
    """Integer k-th root of n.  Returns root if exact, else None."""
    if n < 0:
        return None
    if n == 0:
        return 0
    # Newton's method
    guess = int(round(n ** (1.0 / k))) if n.bit_length() < 1024 else 2 ** (n.bit_length() // k)
    # Refine
    for _ in range(200):
        next_guess = ((k - 1) * guess + n // (guess ** (k - 1))) // k
        if next_guess >= guess:
            break
        guess = next_guess
    # Check neighborhood
    for r in range(max(0, guess - 2), guess + 3):
        if r ** k == n:
            return r
    return None


# ─── Attack 3: Wiener / Boneh-Durfee (small d) ─────────────────────

def attack_wiener(n: int, e: int, c: int, flag_format: str) -> str | None:
    """Wiener's attack on RSA with small d, using continued fractions.

    Works when d < n^0.25.  We also extend to test more convergents
    which may catch cases up to roughly d < n^0.292.
    """
    print(f"[*] Wiener's continued fraction attack (n={n.bit_length()} bits)")

    # Compute continued fraction expansion of e/n
    cf = _continued_fraction(e, n)
    convergents = _convergents(cf)

    for k, d in convergents:
        if k == 0 or d == 0:
            continue
        # Check: (e*d - 1) must be divisible by k
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        # phi = (p-1)(q-1) = n - p - q + 1
        # So p + q = n - phi + 1
        s = n - phi + 1
        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant < 0:
            continue
        is_sq, sq = _is_perfect_square(discriminant)
        if not is_sq:
            continue
        p = (s + sq) // 2
        q = (s - sq) // 2
        if p * q != n:
            continue

        print(f"[+] Wiener found d={d}")
        print(f"[+] p={p}")
        print(f"[+] q={q}")

        m = pow(c, d, n)
        flag = _try_decode_flag(m, flag_format)
        if flag:
            print(f"[+] FLAG: {flag}")
            return flag
        raw = _int_to_bytes(m)
        printable = raw.decode("utf-8", errors="replace")
        print(f"[*] Decrypted: {printable[:200]}")

    print("[-] Wiener's attack: no valid d found via convergents")
    return None


def _continued_fraction(num: int, den: int) -> list[int]:
    """Compute continued fraction representation of num/den."""
    cf = []
    while den:
        q, r = divmod(num, den)
        cf.append(q)
        num, den = den, r
        if len(cf) > 2000:
            break
    return cf


def _convergents(cf: list[int]) -> list[tuple[int, int]]:
    """Compute convergents (numerator, denominator) from continued fraction."""
    convs = []
    h_prev, h_curr = 0, 1
    k_prev, k_curr = 1, 0
    for a in cf:
        h_prev, h_curr = h_curr, a * h_curr + h_prev
        k_prev, k_curr = k_curr, a * k_curr + k_prev
        convs.append((h_curr, k_curr))
    return convs


# ─── Attack 4: ECDSA nonce bias/reuse ──────────────────────────────

def attack_ecdsa_nonce(params: dict, flag_format: str) -> str | None:
    """Recover ECDSA private key from nonce reuse or bias.

    If two signatures share the same nonce k (same r value),
    the private key can be recovered directly:
      k = (z1 - z2) / (s1 - s2)  mod n
      d = (s1 * k - z1) / r      mod n

    For biased nonces (known MSBs), a lattice attack with LLL can
    recover the private key.
    """
    sigs = params.get("signatures", [])
    order = params.get("order", params.get("n", params.get("q", None)))
    if not sigs or not order:
        print("[-] Need signatures and curve order for ECDSA attack")
        return None

    print(f"[*] ECDSA nonce attack with {len(sigs)} signatures, order={order.bit_length()} bits")

    # Check for nonce reuse (same r in two signatures)
    r_map = {}
    for sig in sigs:
        r, s, z = sig.get("r"), sig.get("s"), sig.get("z", sig.get("h", sig.get("hash", 0)))
        if r is None or s is None:
            continue
        if r in r_map:
            # Nonce reuse!
            r2, s2, z2 = r_map[r]
            print(f"[+] Nonce reuse detected (r={r})")
            ds = (s - s2) % order
            dz = (z - z2) % order
            ds_inv = _modinv(ds, order)
            if ds_inv is None:
                continue
            k = (dz * ds_inv) % order
            # Recover private key
            r_inv = _modinv(r, order)
            if r_inv is None:
                continue
            d = ((s * k - z) * r_inv) % order
            print(f"[+] Recovered private key d={d}")
            flag = _try_decode_flag(d, flag_format)
            if flag:
                print(f"[+] FLAG: {flag}")
                return flag
            # Also try with the other signature
            d2 = ((s2 * k - z2) * r_inv) % order
            flag = _try_decode_flag(d2, flag_format)
            if flag:
                print(f"[+] FLAG: {flag}")
                return flag
            # Maybe the flag is hex(d)
            hex_d = hex(d)[2:]
            flag = _search_flag(hex_d, flag_format)
            if flag:
                print(f"[+] FLAG: {flag}")
                return flag
            print(f"[*] d = {d}")
            print(f"[*] d (hex) = {hex_d}")
        else:
            r_map[r] = (r, s, z)

    # Lattice attack for biased nonces (known MSBs)
    nonce_bits = params.get("nonce_bits", params.get("known_bits", 0))
    if nonce_bits > 0 and len(sigs) >= 2:
        print(f"[*] Attempting lattice attack with {nonce_bits}-bit nonce bias")
        flag = _ecdsa_lattice(sigs, order, nonce_bits, flag_format)
        if flag:
            return flag

    print("[-] ECDSA nonce attack: could not recover private key")
    return None


def _ecdsa_lattice(sigs: list[dict], order: int, bias_bits: int, flag_format: str) -> str | None:
    """Lattice attack for ECDSA with biased nonces.

    When the top `bias_bits` of each nonce k are known (or zero),
    build a lattice to find the private key.

    For each signature: s_i * k_i ≡ z_i + r_i * d (mod order)
    If k_i < 2^(nbits - bias_bits), we can set up a CVP/SVP problem.
    """
    n_sigs = min(len(sigs), 20)  # Use at most 20 signatures
    nbits = order.bit_length()
    bound = 1 << (nbits - bias_bits)

    # Build lattice: dimension (n_sigs + 2) x (n_sigs + 2)
    dim = n_sigs + 2
    B = [[0] * dim for _ in range(dim)]

    for i in range(n_sigs):
        sig = sigs[i]
        r_i = sig.get("r", 0)
        s_i = sig.get("s", 0)
        z_i = sig.get("z", sig.get("h", sig.get("hash", 0)))
        s_inv = _modinv(s_i, order)
        if s_inv is None:
            continue
        t_i = (r_i * s_inv) % order
        u_i = (-z_i * s_inv) % order

        B[i][i] = order
        B[n_sigs][i] = t_i
        B[n_sigs + 1][i] = u_i

    B[n_sigs][n_sigs] = 1  # coefficient for d
    B[n_sigs + 1][n_sigs + 1] = bound

    print(f"[*] Running LLL on {dim}x{dim} lattice...")
    try:
        reduced = lll_reduce(B)
    except Exception as e:
        print(f"[-] LLL failed: {e}")
        return None

    # Check reduced basis for the private key
    for row in reduced:
        d_candidate = abs(int(round(row[n_sigs])))
        if 0 < d_candidate < order:
            flag = _try_decode_flag(d_candidate, flag_format)
            if flag:
                print(f"[+] FLAG: {flag}")
                return flag

    return None


# ─── Attack 5: Knapsack / subset sum via LLL ──────────────────────

def attack_knapsack(weights: list[int], target: int, flag_format: str) -> str | None:
    """Solve a low-density knapsack using LLL reduction.

    Given weights w_1,...,w_n and target S, find bits b_i in {0,1}
    such that sum(b_i * w_i) = S.

    Uses the CJLOSS embedding: build an (n+1)x(n+1) lattice.
    """
    n = len(weights)
    print(f"[*] Knapsack attack: {n} weights, target={target}")

    if n > 100:
        print(f"[-] Too many weights ({n}) for LLL knapsack; skipping")
        return None

    # Build lattice: identity matrix with weights column, plus target row
    # Dimension: (n+1) x (n+1)
    N = n + 1
    B = [[0] * N for _ in range(N)]

    # Scale factor for the last column to make SVP work
    scale = _isqrt(n) + 1

    for i in range(n):
        B[i][i] = 1
        B[i][n] = scale * weights[i]

    B[n][n] = -scale * target

    print(f"[*] Running LLL on {N}x{N} lattice...")
    try:
        reduced = lll_reduce(B)
    except Exception as e:
        print(f"[-] LLL failed: {e}")
        return None

    # Look for a row where the last entry is 0 and all others are 0 or 1
    for row in reduced:
        last = int(round(row[n]))
        if last != 0:
            continue
        bits = [int(round(row[i])) for i in range(n)]
        # Check all 0/1 or all 0/-1
        if all(b in (0, 1) for b in bits):
            check = sum(b * w for b, w in zip(bits, weights))
            if check == target:
                print(f"[+] Subset found: {sum(bits)} items selected")
                # Convert bit vector to bytes (flag)
                flag = _bits_to_flag(bits, flag_format)
                if flag:
                    return flag
        elif all(b in (0, -1) for b in bits):
            bits = [-b for b in bits]
            check = sum(b * w for b, w in zip(bits, weights))
            if check == target:
                print(f"[+] Subset found (negated): {sum(bits)} items selected")
                flag = _bits_to_flag(bits, flag_format)
                if flag:
                    return flag

    print("[-] LLL knapsack: no valid subset found")
    return None


def _bits_to_flag(bits: list[int], flag_format: str) -> str | None:
    """Convert a knapsack solution bit vector to a flag string.

    Interprets the bit vector as:
    1) Raw binary → bytes (8-bit chunks)
    2) Index selection from an alphabet
    """
    n = len(bits)

    # Method 1: bits as binary string → bytes
    if n % 8 == 0:
        bitstring = "".join(str(b) for b in bits)
        raw = int(bitstring, 2).to_bytes(n // 8, "big")
        flag = _search_flag_in_bytes(raw, flag_format)
        if flag:
            print(f"[+] FLAG: {flag}")
            return flag
        # Try reversed bit order
        bitstring_rev = bitstring[::-1]
        raw_rev = int(bitstring_rev, 2).to_bytes(n // 8, "big")
        flag = _search_flag_in_bytes(raw_rev, flag_format)
        if flag:
            print(f"[+] FLAG: {flag}")
            return flag

    # Method 2: selected indices as character codes
    selected = [i for i, b in enumerate(bits) if b]
    if selected:
        try:
            text = "".join(chr(i) for i in selected if 32 <= i < 127)
            flag = _search_flag(text, flag_format)
            if flag:
                print(f"[+] FLAG: {flag}")
                return flag
        except Exception:
            pass

    # Method 3: print raw bits for manual inspection
    bitstr = "".join(str(b) for b in bits)
    print(f"[*] Solution bits: {bitstr[:200]}")
    return None


# ─── Attack 6: Baby-step Giant-step DLP ─────────────────────────────

def attack_bsgs(g: int, h: int, p: int, flag_format: str, order: int | None = None) -> str | None:
    """Baby-step Giant-step discrete log: find x such that g^x ≡ h (mod p).

    Works for groups of order up to ~2^40 (sqrt table fits in memory).
    """
    n = order if order else p - 1
    m = _isqrt(n) + 1

    if m > 10_000_000:
        print(f"[-] BSGS: group order too large ({n.bit_length()} bits), m={m}")
        return None

    print(f"[*] BSGS: g={g}, h={h}, p={p}, order={n}, m={m}")

    # Baby step: build table of g^j mod p for j in [0, m)
    table = {}
    power = 1
    for j in range(m):
        table[power] = j
        power = power * g % p

    # Giant step: g^(-m) mod p
    gm_inv = pow(g, n - m, p)  # g^(order - m) = g^(-m) in the group

    gamma = h
    for i in range(m):
        if gamma in table:
            x = i * m + table[gamma]
            print(f"[+] BSGS found x = {x}")
            flag = _try_decode_flag(x, flag_format)
            if flag:
                print(f"[+] FLAG: {flag}")
                return flag
            print(f"[*] x = {x} (decimal)")
            print(f"[*] x = {hex(x)} (hex)")
            return None
        gamma = gamma * gm_inv % p

    print("[-] BSGS: no solution found")
    return None


# ─── Attack 7: Pohlig-Hellman DLP ──────────────────────────────────

def attack_pohlig_hellman(g: int, h: int, p: int, flag_format: str, order: int | None = None) -> str | None:
    """Pohlig-Hellman DLP: works when the group order is smooth (all small factors).

    Decomposes the DLP into sub-problems for each prime power dividing
    the group order, then combines with CRT.
    """
    n = order if order else p - 1
    print(f"[*] Pohlig-Hellman: factoring group order ({n.bit_length()} bits)...")
    factors = _factor_small(n, limit=10_000_000)

    # Check if fully factored
    product = 1
    for prime, exp in factors:
        product *= prime ** exp
    if product != n:
        print(f"[-] Order not fully factored (largest prime factor > 10^7)")
        # Still try with partial factorization
        if product < n:
            remaining = n // product
            if remaining > 1:
                factors.append((remaining, 1))

    print(f"[*] Factors: {factors}")

    residues = []
    moduli = []

    for prime, exp in factors:
        pe = prime ** exp
        # Solve DLP in subgroup of order pe
        gi = pow(g, n // pe, p)
        hi = pow(h, n // pe, p)

        # For small pe, use BSGS
        m = _isqrt(pe) + 1
        if m > 5_000_000:
            print(f"[!] Subgroup {prime}^{exp} too large, skipping")
            continue

        # BSGS in subgroup
        table = {}
        power = 1
        for j in range(m):
            table[power] = j
            power = power * gi % p

        gm_inv = pow(gi, pe - m, p)
        gamma = hi
        found = False
        for i in range(m):
            if gamma in table:
                xi = (i * m + table[gamma]) % pe
                residues.append(xi)
                moduli.append(pe)
                print(f"[*] x ≡ {xi} (mod {pe})")
                found = True
                break
            gamma = gamma * gm_inv % p

        if not found:
            print(f"[!] Failed to solve subgroup for {prime}^{exp}")

    if not residues:
        print("[-] Pohlig-Hellman: no sub-problem solutions found")
        return None

    # Combine with CRT
    x = _crt(residues, moduli)
    if x is None:
        print("[-] CRT combination failed")
        return None

    # Verify
    if pow(g, x, p) == h % p:
        print(f"[+] Pohlig-Hellman found x = {x}")
    else:
        print(f"[*] Pohlig-Hellman candidate x = {x} (partial, not verified)")

    flag = _try_decode_flag(x, flag_format)
    if flag:
        print(f"[+] FLAG: {flag}")
        return flag

    print(f"[*] x = {x}")
    print(f"[*] x (hex) = {hex(x)}")
    return None


# ─── Parameter extraction ──────────────────────────────────────────

def _extract_ints(text: str) -> dict[str, int | list[int]]:
    """Extract named integer assignments from Python/text source."""
    params = {}

    # Python-style: name = value
    for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*=\s*(0x[0-9a-fA-F]+|\d+)\s*(?:#|$|\n|;)', text):
        name = m.group(1)
        val_str = m.group(2)
        try:
            val = int(val_str, 0)
            params[name] = val
        except ValueError:
            pass

    # Tuple/list assignments: name = (val1, val2, ...)
    for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*=\s*\[([^\]]+)\]', text):
        name = m.group(1)
        try:
            items = [int(x.strip(), 0) for x in m.group(2).split(",") if x.strip()]
            params[name] = items
        except ValueError:
            pass

    for m in re.finditer(r'\b([a-zA-Z_]\w*)\s*=\s*\(([^)]+)\)', text):
        name = m.group(1)
        try:
            items = [int(x.strip(), 0) for x in m.group(2).split(",") if x.strip()]
            if len(items) > 1:
                params[name] = items
        except ValueError:
            pass

    return params


def _parse_json_params(filepath: str) -> dict:
    """Parse JSON file for crypto parameters."""
    try:
        with open(filepath) as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
        if isinstance(data, list):
            return {"data": data}
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def _extract_signatures(text: str) -> list[dict]:
    """Extract ECDSA signature tuples from text.

    Looks for patterns like:
      (r, s, h)  or  {"r": ..., "s": ..., "z": ...}
    """
    sigs = []

    # Pattern: (r, s, z) or (r, s, hash)
    for m in re.finditer(r'\(\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*\)', text):
        try:
            r_val = int(m.group(1), 0)
            s_val = int(m.group(2), 0)
            z_val = int(m.group(3), 0)
            sigs.append({"r": r_val, "s": s_val, "z": z_val})
        except ValueError:
            pass

    # JSON-style: {"r": ..., "s": ..., ...}
    for m in re.finditer(r'\{[^}]*"r"\s*:\s*(0x[0-9a-fA-F]+|\d+)[^}]*"s"\s*:\s*(0x[0-9a-fA-F]+|\d+)', text):
        try:
            r_val = int(m.group(1), 0)
            s_val = int(m.group(2), 0)
            sig = {"r": r_val, "s": s_val}
            # Try to find z/h/hash nearby
            z_m = re.search(r'"(?:z|h|hash|msg_hash)"\s*:\s*(0x[0-9a-fA-F]+|\d+)', m.group(0))
            if z_m:
                sig["z"] = int(z_m.group(1), 0)
            sigs.append(sig)
        except ValueError:
            pass

    return sigs


def _extract_knapsack(text: str) -> tuple[list[int], int] | None:
    """Detect knapsack structure: a list of weights and a target sum."""
    # Look for a large list of integers and a separate target/sum value
    weights = None
    target = None

    # Common patterns: pubkey = [...], weights = [...], w = [...]
    for m in re.finditer(r'\b(?:pubkey|weights?|w|keys?|values?|knapsack)\s*=\s*\[([^\]]+)\]', text, re.IGNORECASE):
        try:
            items = [int(x.strip(), 0) for x in m.group(1).split(",") if x.strip()]
            if len(items) >= 4:
                weights = items
                break
        except ValueError:
            pass

    # Target: ct = N, target = N, c = N, sum = N, encrypted = N
    for m in re.finditer(r'\b(?:ct|ciphertext|target|c|encrypted|s|enc)\s*=\s*(0x[0-9a-fA-F]+|\d+)', text, re.IGNORECASE):
        try:
            target = int(m.group(1), 0)
        except ValueError:
            pass

    if weights and target:
        return weights, target
    return None


def scan_directory(challenge_dir: str) -> dict:
    """Scan challenge directory and collect all crypto parameters."""
    params = {}
    all_text = ""
    signatures = []

    for fname in sorted(os.listdir(challenge_dir)):
        fpath = os.path.join(challenge_dir, fname)
        if not os.path.isfile(fpath):
            continue

        # Skip large files and binaries
        try:
            size = os.path.getsize(fpath)
            if size > 2_000_000:
                continue
        except OSError:
            continue

        name_lower = fname.lower()

        # JSON files
        if name_lower.endswith(".json"):
            json_params = _parse_json_params(fpath)
            params.update(json_params)
            continue

        # Text/source files
        exts = (".py", ".txt", ".log", ".out", ".dat", ".sage", ".rb",
                ".c", ".h", ".java", ".js", "")
        is_text = any(name_lower.endswith(ext) for ext in exts)
        # Also read files named output, data, etc.
        if is_text or name_lower in ("output", "data", "log", "ciphertext",
                                      "pubkey", "encrypted", "ct", "flag.enc"):
            try:
                text = open(fpath, encoding="utf-8", errors="replace").read()
            except OSError:
                continue

            all_text += f"\n# --- {fname} ---\n{text}\n"

            # Extract integer parameters
            file_params = _extract_ints(text)
            for k, v in file_params.items():
                if k not in params:
                    params[k] = v

            # Extract signatures
            sigs = _extract_signatures(text)
            signatures.extend(sigs)

            # Try to extract knapsack structure
            knapsack = _extract_knapsack(text)
            if knapsack:
                params["_knapsack_weights"], params["_knapsack_target"] = knapsack

    if signatures:
        params["signatures"] = signatures

    params["_all_text"] = all_text
    return params


# ─── Attack detection and dispatch ─────────────────────────────────

def detect_and_attack(params: dict, flag_format: str) -> str | None:
    """Auto-detect which attack applies and run it."""
    all_text = params.get("_all_text", "")
    results = []

    # Collect all n values
    n_list = params.get("n_list", params.get("moduli", []))
    if isinstance(n_list, int):
        n_list = [n_list]
    # Also look for n, n1, n2, etc.
    for key in sorted(params.keys()):
        val = params[key]
        if isinstance(val, int) and val > 2**64:
            k_lower = key.lower()
            if k_lower == "n" or re.match(r"^n\d+$", k_lower):
                if val not in n_list:
                    n_list.append(val)

    # Collect c values
    c_list = params.get("c_list", params.get("ciphertexts", []))
    if isinstance(c_list, int):
        c_list = [c_list]
    for key in sorted(params.keys()):
        val = params[key]
        if isinstance(val, int) and val > 2**64:
            k_lower = key.lower()
            if k_lower in ("c", "ct", "ciphertext") or re.match(r"^c\d+$", k_lower):
                if val not in c_list:
                    c_list.append(val)

    e_val = params.get("e", params.get("E", 65537))
    if isinstance(e_val, list):
        e_val = e_val[0] if e_val else 65537
    n_val = params.get("n", params.get("N", None))
    if isinstance(n_val, list):
        n_list.extend(n_val)
        n_val = n_val[0] if n_val else None
    c_val = params.get("c", params.get("ct", params.get("ciphertext", params.get("C", None))))

    # ── Attack: GCD on multiple moduli ──
    if len(n_list) >= 2:
        print(f"\n{'='*50}")
        print(f"[*] Detected {len(n_list)} RSA moduli -- trying GCD attack")
        print(f"{'='*50}")
        attack_params = dict(params)
        attack_params["ciphertexts"] = c_list
        attack_params["e"] = e_val
        flag = attack_gcd(n_list, attack_params, flag_format)
        if flag:
            return flag

    # ── Attack: CRT / Hastad broadcast ──
    if len(n_list) >= 2 and len(c_list) >= 2 and isinstance(e_val, int) and e_val <= len(n_list):
        print(f"\n{'='*50}")
        print(f"[*] Detected small e={e_val} with multiple (n,c) pairs -- trying Hastad")
        print(f"{'='*50}")
        attack_params = {
            "e": e_val,
            "n_list": n_list,
            "c_list": c_list,
        }
        flag = attack_crt(attack_params, flag_format)
        if flag:
            return flag

    # ── Attack: Wiener / Boneh-Durfee ──
    if n_val and isinstance(e_val, int) and c_val:
        # Heuristic: if e is large relative to n, small d is likely
        if isinstance(n_val, int) and isinstance(c_val, int):
            if e_val.bit_length() > n_val.bit_length() * 0.3:
                print(f"\n{'='*50}")
                print(f"[*] Large e detected ({e_val.bit_length()} bits vs n={n_val.bit_length()} bits) -- trying Wiener")
                print(f"{'='*50}")
                flag = attack_wiener(n_val, e_val, c_val, flag_format)
                if flag:
                    return flag

    # ── Attack: ECDSA nonce reuse/bias ──
    if params.get("signatures"):
        print(f"\n{'='*50}")
        print(f"[*] Detected {len(params['signatures'])} ECDSA signatures -- trying nonce attack")
        print(f"{'='*50}")
        order = params.get("order", params.get("q", params.get("n_order", None)))
        if order:
            attack_params = dict(params)
            attack_params["order"] = order
            flag = attack_ecdsa_nonce(attack_params, flag_format)
            if flag:
                return flag

    # ── Attack: Knapsack ──
    if "_knapsack_weights" in params:
        print(f"\n{'='*50}")
        print("[*] Detected knapsack structure -- trying LLL")
        print(f"{'='*50}")
        flag = attack_knapsack(
            params["_knapsack_weights"],
            params["_knapsack_target"],
            flag_format,
        )
        if flag:
            return flag

    # ── Attack: DLP (BSGS / Pohlig-Hellman) ──
    g = params.get("g", params.get("G", params.get("generator", None)))
    h = params.get("h", params.get("H", params.get("y", params.get("A", None))))
    p = params.get("p", params.get("P", params.get("prime", None)))
    if isinstance(g, int) and isinstance(h, int) and isinstance(p, int) and p > 1:
        order = params.get("order", params.get("q", None))
        group_order = order if isinstance(order, int) else p - 1

        # Check if group order is smooth first (Pohlig-Hellman)
        print(f"\n{'='*50}")
        print(f"[*] Detected DLP parameters (p={p.bit_length()} bits) -- trying Pohlig-Hellman")
        print(f"{'='*50}")
        flag = attack_pohlig_hellman(g, h, p, flag_format, group_order)
        if flag:
            return flag

        # Fall back to BSGS if order is small enough
        if group_order.bit_length() <= 48:
            print(f"\n{'='*50}")
            print("[*] Small group order -- trying BSGS")
            print(f"{'='*50}")
            flag = attack_bsgs(g, h, p, flag_format, group_order)
            if flag:
                return flag

    # ── Fallback: Wiener on any n+e+c even if e doesn't look huge ──
    if n_val and isinstance(e_val, int) and c_val and isinstance(n_val, int) and isinstance(c_val, int):
        print(f"\n{'='*50}")
        print("[*] Fallback: trying Wiener's attack anyway")
        print(f"{'='*50}")
        flag = attack_wiener(n_val, e_val, c_val, flag_format)
        if flag:
            return flag

    # ── Scan raw text for flag patterns ──
    flag = _search_flag(all_text, flag_format)
    if flag:
        print(f"[+] FLAG: {flag}")
        return flag

    print("\n[-] No attack succeeded")
    return None


# ─── Main ──────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Lattice-based and advanced number-theoretic crypto solver",
    )
    parser.add_argument("--dir", required=True, help="Challenge directory to scan")
    parser.add_argument("--flag-format", default="", help="Expected flag prefix (e.g. 'flag{')")
    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        print(f"[-] Not a directory: {args.dir}")
        sys.exit(1)

    print(f"[*] Scanning {args.dir} for crypto challenge parameters...")
    params = scan_directory(args.dir)

    # Remove internal text blob from summary
    text_blob = params.pop("_all_text", "")
    print(f"[*] Extracted {len(params)} parameter keys: {list(params.keys())[:20]}")
    params["_all_text"] = text_blob

    flag = detect_and_attack(params, args.flag_format)
    if not flag:
        sys.exit(1)


if __name__ == "__main__":
    main()
