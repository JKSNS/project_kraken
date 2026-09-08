#!/usr/bin/env python3
"""Solve EC-Vigenere (ECXOR) challenges via known-plaintext attack.

Detects challenges using elliptic curve point addition as a Vigenere-style
cipher and recovers the key using the known plaintext prefix "flag{" plus
character frequency scoring for remaining key bytes.

The encryption scheme is:
  C[i] = topoint(msg[i]) + topoint(key[i % keylen])
where topoint(n) = n * G on an elliptic curve (Ed25519).

Key recovery:
  1. Known plaintext "flag{" recovers key[0:5] directly
  2. Remaining key bytes brute-forced with printable ASCII scoring
"""
import os
import re
import sys
import base64
import argparse


# ── Inline Ed25519 point arithmetic (from RFC 8032) ──────────────────
# Embedded to avoid dependency on challenge-provided rfc8032.py

_p = 2**255 - 19
_d = -121665 * pow(121666, _p - 2, _p) % _p


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % _p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % _p
    C = 2 * P[3] * Q[3] * _d % _p
    D = 2 * P[2] * Q[2] % _p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % _p, G * H % _p, F * G % _p, E * H % _p)


def _point_mul(s, P):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _recover_x(y, sign):
    if y >= _p:
        return None
    x2 = (y * y - 1) * pow(_d * y * y + 1, _p - 2, _p) % _p
    if x2 == 0:
        return 0 if not sign else None
    x = pow(x2, (_p + 3) // 8, _p)
    if (x * x - x2) % _p != 0:
        x = x * pow(2, (_p - 1) // 4, _p) % _p
    if (x * x - x2) % _p != 0:
        return None
    if (x & 1) != sign:
        x = _p - x
    return x


_g_y = 4 * pow(5, _p - 2, _p) % _p
_g_x = _recover_x(_g_y, 0)
_G = (_g_x, _g_y, 1, _g_x * _g_y % _p)


def _point_compress(P):
    zinv = pow(P[2], _p - 2, _p)
    x = P[0] * zinv % _p
    y = P[1] * zinv % _p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _p)


def _negate(P):
    return (P[0], -P[1], -P[2], P[3])


# ── Precomputed lookup table ─────────────────────────────────────────

_POINT_TABLE = None  # list of 256 points
_COMPRESS_TO_BYTE = None  # compressed bytes -> byte value


def _init_tables():
    global _POINT_TABLE, _COMPRESS_TO_BYTE
    if _POINT_TABLE is not None:
        return
    _POINT_TABLE = []
    _COMPRESS_TO_BYTE = {}
    for i in range(256):
        pt = _point_mul(i, _G)
        _POINT_TABLE.append(pt)
        _COMPRESS_TO_BYTE[_point_compress(pt)] = i


def _topoint(n):
    return _POINT_TABLE[n]


def _frompoint(P):
    compressed = _point_compress(P)
    return _COMPRESS_TO_BYTE.get(compressed)


# ── Challenge detection ──────────────────────────────────────────────

def detect_challenge(challenge_dir: str) -> bool:
    """Check if this looks like an EC-Vigenere challenge."""
    has_curve = False
    has_ciphertext = False

    for f in os.listdir(challenge_dir):
        fp = os.path.join(challenge_dir, f)
        if not os.path.isfile(fp):
            continue

        name_lower = f.lower()

        # Check for rfc8032 module or curve point operations in Python
        if name_lower.endswith('.py'):
            try:
                src = open(fp).read(4096)
                if 'point_add' in src and 'point_mul' in src:
                    has_curve = True
                if 'topoint' in src and 'frompoint' in src:
                    has_curve = True
            except OSError:
                pass

        # Check for ciphertext file with base64-encoded curve points
        if name_lower in ('ciphertext', 'ct', 'encrypted', 'output'):
            try:
                data = open(fp).read(200)
                if ';' in data and '=' in data:
                    has_ciphertext = True
            except OSError:
                pass

    return has_curve and has_ciphertext


# ── Solver ───────────────────────────────────────────────────────────

def find_keylen(challenge_dir: str) -> int:
    """Extract KEYLEN from encryption script."""
    for f in os.listdir(challenge_dir):
        if f.endswith('.py'):
            try:
                src = open(os.path.join(challenge_dir, f)).read()
                m = re.search(r'KEYLEN\s*=\s*(\d+)', src)
                if m:
                    return int(m.group(1))
            except OSError:
                pass
    return 12  # default


def find_ciphertext(challenge_dir: str) -> str | None:
    """Find the ciphertext file."""
    # Priority 1: file named 'ciphertext'
    for name in ('ciphertext', 'ct', 'encrypted', 'output'):
        path = os.path.join(challenge_dir, name)
        if os.path.isfile(path):
            return path

    # Priority 2: any file with base64-semicolon pattern
    for f in os.listdir(challenge_dir):
        fp = os.path.join(challenge_dir, f)
        if not os.path.isfile(fp) or f.endswith('.py'):
            continue
        try:
            data = open(fp).read(200)
            if ';' in data and '=' in data and len(data) > 100:
                return fp
        except OSError:
            pass

    return None


def score_text(chars: list[str | None]) -> float:
    """Score a list of decrypted characters for English-like text."""
    score = 0.0
    for c in chars:
        if c is None:
            continue
        o = ord(c)
        if 97 <= o <= 122:  # lowercase
            score += 3.0
        elif o == 32:  # space
            score += 3.0
        elif 65 <= o <= 90:  # uppercase
            score += 2.0
        elif o in (44, 46, 39, 33, 63, 59, 58, 45, 34):  # punctuation
            score += 2.0
        elif 48 <= o <= 57:  # digits
            score += 1.5
        elif o == 10 or o == 13:  # newline
            score += 1.0
        elif 32 <= o <= 126:  # other printable
            score += 1.0
        elif o == 123 or o == 125:  # { }
            score += 2.0
        elif o == 95:  # underscore (common in flags)
            score += 2.5
        # non-printable: score stays 0
    return score


def solve(challenge_dir: str) -> str | None:
    """Solve an EC-Vigenere challenge."""
    print("[*] Initializing Ed25519 point table (256 entries)...")
    _init_tables()
    print("[*] Point table ready")

    # Find and read ciphertext
    ct_path = find_ciphertext(challenge_dir)
    if not ct_path:
        print("[-] No ciphertext file found")
        return None

    ct_data = open(ct_path).read().strip()
    ct_parts = ct_data.split(';')
    print(f"[*] Ciphertext: {len(ct_parts)} encrypted points")

    # Decompress all ciphertext points
    ct_points = []
    for part in ct_parts:
        part = part.strip()
        if not part:
            continue
        try:
            raw = base64.b64decode(part)
            pt = _point_decompress(raw)
            if pt is None:
                print(f"[-] Failed to decompress point")
                return None
            ct_points.append(pt)
        except Exception as e:
            print(f"[-] Base64/decompress error: {e}")
            return None

    print(f"[*] Decompressed {len(ct_points)} points")

    keylen = find_keylen(challenge_dir)
    print(f"[*] Key length: {keylen}")

    # Step 1: Recover key[0:5] from known plaintext "flag{"
    known = "flag{"
    key = [0] * keylen
    print("[*] Recovering key bytes 0-4 from known plaintext 'flag{'...")

    for i in range(min(len(known), keylen)):
        # C[i] = topoint(ord(msg[i])) + topoint(key[i])
        # topoint(key[i]) = C[i] - topoint(ord(msg[i]))
        key_point = _point_add(ct_points[i], _negate(_topoint(ord(known[i]))))
        kb = _frompoint(key_point)
        if kb is None:
            print(f"[-] Could not recover key byte {i}")
            return None
        key[i] = kb
        print(f"[*]   key[{i}] = {kb}")

    # Step 2: Brute-force remaining key bytes
    print(f"[*] Brute-forcing key bytes {len(known)}-{keylen - 1}...")

    for ki in range(len(known), keylen):
        # Find all ciphertext positions that use this key byte
        positions = [j for j in range(len(ct_points)) if j % keylen == ki]

        best_score = -1.0
        best_byte = 0

        for candidate in range(256):
            # Decrypt all positions with this candidate
            decrypted = []
            valid = True
            for pos in positions:
                pt = _point_add(ct_points[pos], _negate(_topoint(candidate)))
                byte_val = _frompoint(pt)
                if byte_val is not None:
                    decrypted.append(chr(byte_val))
                else:
                    decrypted.append(None)
                    valid = False

            s = score_text(decrypted)
            if s > best_score:
                best_score = s
                best_byte = candidate

        key[ki] = best_byte
        print(f"[*]   key[{ki}] = {best_byte} (score={best_score:.1f})")

    # Step 3: Decrypt full message
    print("[*] Decrypting full message...")
    message = []
    for i, ct_pt in enumerate(ct_points):
        ki = i % keylen
        pt = _point_add(ct_pt, _negate(_topoint(key[ki])))
        byte_val = _frompoint(pt)
        if byte_val is not None:
            message.append(chr(byte_val))
        else:
            message.append('?')

    plaintext = "".join(message)
    print(f"[*] Decrypted {len(plaintext)} characters")

    # Extract flag
    m = re.search(r'[a-zA-Z_]+\{[^}]+\}', plaintext)
    if m:
        flag = m.group(0)
        print(f"\n[+] EC_VIGENERE SUCCESS")
        print(f"[+] EXTRACTED FLAG: {flag}")
        return flag
    else:
        # Try the whole plaintext up to first non-printable
        printable = ""
        for c in plaintext:
            if 32 <= ord(c) <= 126:
                printable += c
            else:
                break
        if printable and len(printable) > 10:
            print(f"[*] Decrypted text: {printable[:200]}")
        print("[-] No flag pattern found in decrypted text")
        return None


def main():
    parser = argparse.ArgumentParser(description="Kraken EC-Vigenere Solver")
    parser.add_argument("challenge_dir", help="Path to challenge directory")
    args = parser.parse_args()

    if not os.path.isdir(args.challenge_dir):
        print(f"[-] Not a directory: {args.challenge_dir}")
        sys.exit(1)

    print(f"[*] Scanning for EC-Vigenere challenge in {args.challenge_dir}")

    flag = solve(args.challenge_dir)
    if not flag:
        sys.exit(1)


if __name__ == "__main__":
    main()
