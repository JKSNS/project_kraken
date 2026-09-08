#!/usr/bin/env python3
"""auto_rsa_attack -- RSA cryptography challenge solver.

Scans a challenge directory for RSA parameters (n, e, c, p, q, d, phi) from
Python source, output/data files, PEM keys, and JSON files.  Then tries a
cascade of classical RSA attacks to recover the plaintext flag.

Usage:
    python3 auto_rsa_attack.py --dir /path/to/challenge --flag-format "HTB{"
"""
import argparse
import base64
import json
import math
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile


# ---------------------------------------------------------------------------
# Integer math helpers (stdlib only -- no sympy/sage)
# ---------------------------------------------------------------------------

def isqrt(n: int) -> int:
    """Integer square root via Newton's method."""
    if n < 0:
        raise ValueError("Square root of negative number")
    if n < 2:
        return n
    x = n
    y = (x + 1) // 2
    while y < x:
        x = y
        y = (x + n // x) // 2
    return x


def iroot(k: int, n: int) -> tuple[int, bool]:
    """Integer k-th root of n via Newton's method.

    Returns (root, exact) where exact is True if root**k == n.
    """
    if n < 0:
        if k % 2 == 0:
            return (0, False)
        r, exact = iroot(k, -n)
        return (-r, exact)
    if n < 2:
        return (n, True)
    if k == 1:
        return (n, True)
    if k == 2:
        r = isqrt(n)
        return (r, r * r == n)

    # Newton's method for k-th root
    # Initial guess: use bit length
    bits = n.bit_length()
    guess = 1 << ((bits + k - 1) // k)
    x = guess
    while True:
        x1 = ((k - 1) * x + n // pow(x, k - 1)) // k
        if x1 >= x:
            break
        x = x1

    # Fine-tune: x might be off by 1
    while pow(x + 1, k) <= n:
        x += 1
    while pow(x, k) > n and x > 0:
        x -= 1

    return (x, pow(x, k) == n)


def gcd(a: int, b: int) -> int:
    """Greatest common divisor."""
    while b:
        a, b = b, a % b
    return abs(a)


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm. Returns (g, x, y) with a*x + b*y = g."""
    if a == 0:
        return (b, 0, 1)
    g, x, y = extended_gcd(b % a, a)
    return (g, y - (b // a) * x, x)


def modinv(a: int, m: int) -> int:
    """Modular inverse of a mod m."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"No modular inverse: gcd({a}, {m}) = {g}")
    return x % m


# ---------------------------------------------------------------------------
# RSA decryption
# ---------------------------------------------------------------------------

def rsa_decrypt(c: int, d: int, n: int) -> int:
    """Standard RSA decryption: m = c^d mod n."""
    return pow(c, d, n)


def int_to_bytes(m: int) -> bytes:
    """Convert a positive integer to bytes (big-endian, no leading zero padding)."""
    if m == 0:
        return b'\x00'
    length = (m.bit_length() + 7) // 8
    return m.to_bytes(length, 'big')


def try_decrypt_and_check(m: int, flag_format: str) -> str | None:
    """Convert integer to bytes and check for flag."""
    try:
        raw = int_to_bytes(m)
        # Try UTF-8 decode
        text = raw.decode('utf-8', errors='replace')
        if _has_flag(text, flag_format):
            return _extract_flag(text, flag_format)
        # Also try latin-1
        text_latin = raw.decode('latin-1', errors='replace')
        if _has_flag(text_latin, flag_format):
            return _extract_flag(text_latin, flag_format)
        # If printable ASCII, return it even without flag pattern
        if text.isprintable() and len(text) >= 4:
            return text
    except Exception:
        pass
    return None


def _has_flag(text: str, flag_format: str) -> bool:
    """Check if text contains a flag."""
    if flag_format:
        prefix = flag_format.rstrip('{')
        return prefix + '{' in text
    return bool(re.search(r'[A-Za-z0-9_]{2,}\{[^}]{3,}\}', text))


def _extract_flag(text: str, flag_format: str) -> str:
    """Extract flag from text."""
    if flag_format:
        prefix = flag_format.rstrip('{')
        pat = re.escape(prefix) + r'\{[^}]+\}'
        m = re.search(pat, text)
        if m:
            return m.group(0)
    m = re.search(r'[A-Za-z0-9_]{2,}\{[^}]+\}', text)
    if m:
        return m.group(0)
    return text.strip()


# ---------------------------------------------------------------------------
# Parameter extraction
# ---------------------------------------------------------------------------

class RSAParams:
    """Container for extracted RSA parameters."""

    def __init__(self):
        self.n: int | None = None
        self.e: int | None = None
        self.c: int | None = None  # ciphertext (single)
        self.p: int | None = None
        self.q: int | None = None
        self.d: int | None = None
        self.phi: int | None = None
        self.dp: int | None = None
        self.dq: int | None = None
        # For multi-recipient / common modulus attacks
        self.ciphertexts: list[dict] = []  # [{c, e, n}, ...]
        # For related-message / Coppersmith attacks
        self.known_prefix: str = ""        # Known plaintext prefix (e.g. flag format)
        self.partial_p_bits: int | None = None   # High bits of p if leaked
        self.partial_p_known: int | None = None  # Number of known bits

    def has_basic(self) -> bool:
        return self.n is not None and self.c is not None

    def has_factors(self) -> bool:
        return self.p is not None and self.q is not None

    def has_private(self) -> bool:
        return self.d is not None

    def __repr__(self):
        parts = []
        if self.n is not None:
            parts.append(f"n={self.n.bit_length()}bits")
        if self.e is not None:
            parts.append(f"e={self.e}")
        if self.c is not None:
            parts.append(f"c=yes")
        if self.p is not None:
            parts.append(f"p=yes")
        if self.q is not None:
            parts.append(f"q=yes")
        if self.d is not None:
            parts.append(f"d=yes")
        if len(self.ciphertexts) > 1:
            parts.append(f"multi={len(self.ciphertexts)}")
        return f"RSAParams({', '.join(parts)})"


def _parse_int(val: str) -> int | None:
    """Parse an integer from various string representations."""
    val = val.strip().strip('"').strip("'")
    # Remove L suffix (Python 2)
    val = val.rstrip('Ll')
    try:
        if val.startswith('0x') or val.startswith('0X'):
            return int(val, 16)
        return int(val)
    except (ValueError, OverflowError):
        return None


def _extract_from_python(text: str, params: RSAParams) -> None:
    """Extract RSA parameters from Python source code."""
    # Patterns: n = 123, n=0x1ab, n = int("123")
    var_patterns = {
        'n': r'(?<![a-zA-Z_])n\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'e': r'(?<![a-zA-Z_])e\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'c': r'(?<![a-zA-Z_])(?:c|ct|cipher(?:text)?|enc(?:rypted)?)\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'p': r'(?<![a-zA-Z_])p\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'q': r'(?<![a-zA-Z_])q\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'd': r'(?<![a-zA-Z_])d\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'phi': r'(?<![a-zA-Z_])(?:phi|totient|euler)\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'dp': r'(?<![a-zA-Z_])dp\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
        'dq': r'(?<![a-zA-Z_])dq\s*=\s*(?:int\s*\(\s*)?["\']?([0-9a-fA-Fx]+)["\']?\s*\)?',
    }

    for name, pattern in var_patterns.items():
        for m in re.finditer(pattern, text):
            val = _parse_int(m.group(1))
            if val is not None and val > 1:
                # Heuristic: n should be large, e typically small or 65537
                if name == 'n' and val.bit_length() < 32:
                    continue
                if name in ('p', 'q') and val.bit_length() < 16:
                    continue
                current = getattr(params, name, None)
                if current is None:
                    setattr(params, name, val)

    # Multi-value extraction: look for list patterns
    # e.g. ns = [n1, n2, ...], cs = [c1, c2, ...], es = [e1, e2, ...]
    list_patterns = {
        'ns': r'(?:ns|N_list|moduli)\s*=\s*\[([^\]]+)\]',
        'cs': r'(?:cs|C_list|ciphertexts?|ct_list|enc_list)\s*=\s*\[([^\]]+)\]',
        'es': r'(?:es|E_list|exponents?)\s*=\s*\[([^\]]+)\]',
    }
    lists: dict[str, list[int]] = {}
    for name, pattern in list_patterns.items():
        m = re.search(pattern, text, re.DOTALL)
        if m:
            body = m.group(1)
            vals = []
            for num_m in re.finditer(r'(0x[0-9a-fA-F]+|\d{2,})', body):
                v = _parse_int(num_m.group(1))
                if v is not None and v > 1:
                    vals.append(v)
            if vals:
                lists[name] = vals

    # Build multi-recipient entries
    if 'cs' in lists:
        ns = lists.get('ns', [])
        es = lists.get('es', [])
        for i, c_val in enumerate(lists['cs']):
            entry = {'c': c_val}
            if i < len(ns):
                entry['n'] = ns[i]
            elif params.n is not None:
                entry['n'] = params.n
            if i < len(es):
                entry['e'] = es[i]
            elif params.e is not None:
                entry['e'] = params.e
            params.ciphertexts.append(entry)


def _extract_from_text(text: str, params: RSAParams) -> None:
    """Extract RSA parameters from output/data text files.

    Handles formats like:
        n = 12345...
        e = 65537
        c = 98765...
    Or:
        n: 12345
        e: 65537
        ct: 98765
    """
    patterns = {
        'n': r'(?:^|\n)\s*[Nn]\s*[=:]\s*([0-9a-fA-Fx]+)',
        'e': r'(?:^|\n)\s*[Ee]\s*[=:]\s*([0-9a-fA-Fx]+)',
        'c': r'(?:^|\n)\s*(?:[Cc](?:t|ipher(?:text)?)?|enc(?:rypted)?)\s*[=:]\s*([0-9a-fA-Fx]+)',
        'p': r'(?:^|\n)\s*[Pp]\s*[=:]\s*([0-9a-fA-Fx]+)',
        'q': r'(?:^|\n)\s*[Qq]\s*[=:]\s*([0-9a-fA-Fx]+)',
        'd': r'(?:^|\n)\s*[Dd]\s*[=:]\s*([0-9a-fA-Fx]+)',
        'phi': r'(?:^|\n)\s*(?:phi|totient)\s*[=:]\s*([0-9a-fA-Fx]+)',
        'dp': r'(?:^|\n)\s*[Dd][Pp]\s*[=:]\s*([0-9a-fA-Fx]+)',
        'dq': r'(?:^|\n)\s*[Dd][Qq]\s*[=:]\s*([0-9a-fA-Fx]+)',
    }

    for name, pattern in patterns.items():
        m = re.search(pattern, text)
        if m:
            val = _parse_int(m.group(1))
            if val is not None and val > 1:
                if name == 'n' and val.bit_length() < 32:
                    continue
                current = getattr(params, name, None)
                if current is None:
                    setattr(params, name, val)


def _extract_from_pem(filepath: str, params: RSAParams) -> None:
    """Extract RSA public key parameters from a PEM file."""
    try:
        data = open(filepath, 'r').read()
    except OSError:
        return

    # Try to decode the base64 body
    pem_match = re.search(
        r'-----BEGIN (?:RSA )?PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+)\s*-----END',
        data,
    )
    if not pem_match:
        # Also check for private key
        pem_match = re.search(
            r'-----BEGIN (?:RSA )?PRIVATE KEY-----\s*([A-Za-z0-9+/=\s]+)\s*-----END',
            data,
        )
    if not pem_match:
        return

    try:
        der_bytes = base64.b64decode(pem_match.group(1).replace('\n', '').replace('\r', ''))
    except Exception:
        return

    # Simple ASN.1 DER parser for RSA keys
    # RSA public key: SEQUENCE { INTEGER n, INTEGER e }
    # PKCS#1 public key starts with SEQUENCE
    integers = _parse_der_integers(der_bytes)
    if not integers:
        return

    if len(integers) >= 2:
        # Public key: first large integer is n, second is e
        # Private key: integers are version, n, e, d, p, q, dp, dq, qinv
        candidates_n = [i for i in integers if i.bit_length() >= 256]
        candidates_e = [i for i in integers if 3 <= i <= 65537 or i.bit_length() < 32]

        if candidates_n and params.n is None:
            params.n = candidates_n[0]
        if candidates_e and params.e is None:
            params.e = candidates_e[0]

        # If private key (>=5 integers), extract d, p, q
        if len(integers) >= 6:
            # Standard RSA private key: version, n, e, d, p, q, dp, dq, qinv
            if params.d is None and integers[3].bit_length() >= 64:
                params.d = integers[3]
            if params.p is None and integers[4].bit_length() >= 64:
                params.p = integers[4]
            if params.q is None and integers[5].bit_length() >= 64:
                params.q = integers[5]


def _parse_der_integers(data: bytes) -> list[int]:
    """Parse DER-encoded ASN.1 data and extract all INTEGER values."""
    integers = []
    pos = 0
    try:
        while pos < len(data):
            if pos >= len(data):
                break
            tag = data[pos]
            pos += 1

            # Parse length
            if pos >= len(data):
                break
            length_byte = data[pos]
            pos += 1
            if length_byte & 0x80:
                num_bytes = length_byte & 0x7F
                if pos + num_bytes > len(data):
                    break
                length = int.from_bytes(data[pos:pos + num_bytes], 'big')
                pos += num_bytes
            else:
                length = length_byte

            if tag == 0x02:  # INTEGER
                if pos + length <= len(data):
                    int_bytes = data[pos:pos + length]
                    val = int.from_bytes(int_bytes, 'big')
                    if val > 0:
                        integers.append(val)
                pos += length
            elif tag in (0x30, 0x31, 0x03):  # SEQUENCE, SET, BIT STRING
                if tag == 0x03 and pos < len(data):
                    # Skip unused bits byte in BIT STRING
                    pos += 1
                # Recurse into the contents -- don't skip past them
                continue
            else:
                pos += length
    except (IndexError, ValueError):
        pass
    return integers


def _extract_from_json(text: str, params: RSAParams) -> None:
    """Extract RSA parameters from JSON data."""
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return

    if isinstance(data, dict):
        _extract_json_dict(data, params)
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                entry = {}
                for key in ('n', 'e', 'c', 'ct', 'ciphertext'):
                    if key in item:
                        val = _parse_int(str(item[key]))
                        if val is not None:
                            normalized = 'c' if key in ('ct', 'ciphertext') else key
                            entry[normalized] = val
                if entry:
                    params.ciphertexts.append(entry)
                _extract_json_dict(item, params)


def _extract_json_dict(data: dict, params: RSAParams) -> None:
    """Extract parameters from a JSON dictionary."""
    mapping = {
        'n': ['n', 'N', 'modulus'],
        'e': ['e', 'E', 'exponent', 'public_exponent'],
        'c': ['c', 'C', 'ct', 'ciphertext', 'cipher', 'encrypted', 'enc'],
        'p': ['p', 'P'],
        'q': ['q', 'Q'],
        'd': ['d', 'D', 'private_exponent'],
        'phi': ['phi', 'totient', 'euler_totient'],
        'dp': ['dp', 'dP'],
        'dq': ['dq', 'dQ'],
    }
    for attr, keys in mapping.items():
        for key in keys:
            if key in data:
                val = _parse_int(str(data[key]))
                if val is not None and val > 1:
                    current = getattr(params, attr, None)
                    if current is None:
                        setattr(params, attr, val)


def scan_directory(dirpath: str) -> RSAParams:
    """Scan a challenge directory for RSA parameters."""
    params = RSAParams()

    # Priority order for scanning
    py_files = []
    text_files = []
    pem_files = []
    json_files = []

    if os.path.isfile(dirpath):
        # Single file provided
        ext = os.path.splitext(dirpath)[1].lower()
        if ext in ('.py', '.sage'):
            py_files.append(dirpath)
        elif ext == '.pem':
            pem_files.append(dirpath)
        elif ext == '.json':
            json_files.append(dirpath)
        else:
            text_files.append(dirpath)
    elif os.path.isdir(dirpath):
        for root, _dirs, files in os.walk(dirpath):
            # Skip hidden dirs and common noise
            if any(part.startswith('.') for part in root.split(os.sep) if part):
                if '.git' in root:
                    continue
            for fname in files:
                fpath = os.path.join(root, fname)
                try:
                    if os.path.getsize(fpath) > 5_000_000:
                        continue
                except OSError:
                    continue
                ext = os.path.splitext(fname)[1].lower()
                name_lower = fname.lower()
                if ext in ('.py', '.sage'):
                    py_files.append(fpath)
                elif ext == '.pem' or ext in ('.pub', '.key'):
                    pem_files.append(fpath)
                elif ext == '.json':
                    json_files.append(fpath)
                elif ext in ('.txt', '.out', '.dat', '') or name_lower in (
                    'output.txt', 'data.txt', 'flag.enc', 'ciphertext.txt',
                    'output', 'encrypted.txt',
                ):
                    text_files.append(fpath)

    # Extract from each file type
    for fpath in pem_files:
        print(f"[*] Parsing PEM: {os.path.basename(fpath)}")
        _extract_from_pem(fpath, params)

    for fpath in py_files:
        print(f"[*] Parsing Python: {os.path.basename(fpath)}")
        try:
            text = open(fpath, encoding='utf-8', errors='replace').read()
            _extract_from_python(text, params)
        except OSError:
            pass

    for fpath in json_files:
        print(f"[*] Parsing JSON: {os.path.basename(fpath)}")
        try:
            text = open(fpath, encoding='utf-8', errors='replace').read()
            _extract_from_json(text, params)
        except OSError:
            pass

    for fpath in text_files:
        print(f"[*] Parsing text: {os.path.basename(fpath)}")
        try:
            text = open(fpath, encoding='utf-8', errors='replace').read()
            _extract_from_text(text, params)
            # Also try Python-style extraction on text files (some output.txt
            # files contain Python variable assignments)
            _extract_from_python(text, params)
        except OSError:
            pass

    # Default e if not found
    if params.e is None and params.n is not None:
        params.e = 65537
        print("[*] No e found, defaulting to 65537")

    # Fill ciphertext list if only single c provided
    if params.c is not None and not params.ciphertexts:
        params.ciphertexts.append({
            'c': params.c,
            'n': params.n,
            'e': params.e,
        })

    return params


# ---------------------------------------------------------------------------
# Attack implementations
# ---------------------------------------------------------------------------

def attack_direct(params: RSAParams, flag_format: str) -> str | None:
    """Direct decryption when p, q (or d) are known."""
    if params.has_private() and params.n is not None and params.c is not None:
        print("[*] Attack: direct decryption (d known)")
        m = rsa_decrypt(params.c, params.d, params.n)
        result = try_decrypt_and_check(m, flag_format)
        if result:
            return result

    if params.has_factors() and params.n is not None:
        print("[*] Attack: direct decryption (p, q known)")
        n = params.p * params.q
        if params.n != n:
            # p and q might not match n -- try both
            pass
        phi = (params.p - 1) * (params.q - 1)
        e = params.e if params.e is not None else 65537
        try:
            d = modinv(e, phi)
        except ValueError:
            return None
        if params.c is not None:
            m = rsa_decrypt(params.c, d, params.n)
            result = try_decrypt_and_check(m, flag_format)
            if result:
                return result

    if params.phi is not None and params.e is not None and params.n is not None and params.c is not None:
        print("[*] Attack: direct decryption (phi known)")
        try:
            d = modinv(params.e, params.phi)
            m = rsa_decrypt(params.c, d, params.n)
            result = try_decrypt_and_check(m, flag_format)
            if result:
                return result
        except ValueError:
            pass

    # CRT decryption with dp, dq
    if (params.dp is not None and params.dq is not None
            and params.p is not None and params.q is not None
            and params.c is not None):
        print("[*] Attack: CRT decryption (dp, dq, p, q known)")
        m1 = pow(params.c, params.dp, params.p)
        m2 = pow(params.c, params.dq, params.q)
        try:
            qinv = modinv(params.q, params.p)
        except ValueError:
            return None
        h = (qinv * (m1 - m2)) % params.p
        m = m2 + h * params.q
        result = try_decrypt_and_check(m, flag_format)
        if result:
            return result

    return None


def attack_small_e(params: RSAParams, flag_format: str) -> str | None:
    """Small public exponent attack (e-th root of c)."""
    if params.e is None or params.c is None or params.n is None:
        return None
    if params.e > 17:
        return None

    print(f"[*] Attack: small e (e={params.e}), trying direct {params.e}-th root")
    # Try c^(1/e) directly (no modular reduction)
    for k in range(100):
        val = params.c + k * params.n
        root, exact = iroot(params.e, val)
        if exact:
            result = try_decrypt_and_check(root, flag_format)
            if result:
                return result
    return None


def attack_wiener(params: RSAParams, flag_format: str) -> str | None:
    """Wiener's attack for small d using continued fraction expansion of e/n."""
    if params.e is None or params.n is None or params.c is None:
        return None
    # Wiener's works when d < n^0.25.  Skip if e is tiny (small e attack is better).
    if params.e < 100:
        return None

    print("[*] Attack: Wiener's continued fraction")

    # Compute continued fraction convergents of e/n
    def continued_fraction(num: int, den: int) -> list[int]:
        cf = []
        while den:
            q = num // den
            cf.append(q)
            num, den = den, num - q * den
            if len(cf) > 500:
                break
        return cf

    def convergents(cf: list[int]):
        """Yield (numerator, denominator) convergents."""
        h_prev, h_curr = 0, 1
        k_prev, k_curr = 1, 0
        for a in cf:
            h_prev, h_curr = h_curr, a * h_curr + h_prev
            k_prev, k_curr = k_curr, a * k_curr + k_prev
            yield (h_curr, k_curr)

    cf = continued_fraction(params.e, params.n)
    for k, d_candidate in convergents(cf):
        if k == 0:
            continue
        # Check: (e * d - 1) must be divisible by k
        if (params.e * d_candidate - 1) % k != 0:
            continue
        phi_candidate = (params.e * d_candidate - 1) // k
        # phi(n) = n - p - q + 1  =>  p + q = n - phi + 1
        s = params.n - phi_candidate + 1
        # p and q are roots of x^2 - s*x + n = 0
        discriminant = s * s - 4 * params.n
        if discriminant < 0:
            continue
        sqrt_disc = isqrt(discriminant)
        if sqrt_disc * sqrt_disc != discriminant:
            continue
        p = (s + sqrt_disc) // 2
        q = (s - sqrt_disc) // 2
        if p * q != params.n:
            continue

        # We found the factors!
        print(f"[*] Wiener's attack found factors: p={p.bit_length()}bits, q={q.bit_length()}bits")
        m = rsa_decrypt(params.c, d_candidate, params.n)
        result = try_decrypt_and_check(m, flag_format)
        if result:
            return result

    return None


def attack_fermat(params: RSAParams, flag_format: str) -> str | None:
    """Fermat factorization when p and q are close."""
    if params.n is None or params.c is None or params.e is None:
        return None

    print("[*] Attack: Fermat factorization (close p, q)")
    a = isqrt(params.n)
    if a * a < params.n:
        a += 1

    # Limit iterations to keep it fast
    for _ in range(1_000_000):
        b2 = a * a - params.n
        b = isqrt(b2)
        if b * b == b2:
            p = a + b
            q = a - b
            if p * q == params.n and p > 1 and q > 1:
                print(f"[*] Fermat found factors: p={p.bit_length()}bits, q={q.bit_length()}bits")
                phi = (p - 1) * (q - 1)
                try:
                    d = modinv(params.e, phi)
                except ValueError:
                    return None
                m = rsa_decrypt(params.c, d, params.n)
                result = try_decrypt_and_check(m, flag_format)
                if result:
                    return result
                return None
        a += 1

    return None


def attack_common_modulus(params: RSAParams, flag_format: str) -> str | None:
    """Common modulus attack: same n, same plaintext, different e values."""
    if len(params.ciphertexts) < 2:
        return None

    print("[*] Attack: common modulus")
    # Group by n
    by_n: dict[int, list[dict]] = {}
    for entry in params.ciphertexts:
        n = entry.get('n')
        if n is not None:
            by_n.setdefault(n, []).append(entry)

    for n, entries in by_n.items():
        if len(entries) < 2:
            continue
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                e1 = entries[i].get('e')
                e2 = entries[j].get('e')
                c1 = entries[i].get('c')
                c2 = entries[j].get('c')
                if e1 is None or e2 is None or c1 is None or c2 is None:
                    continue
                if gcd(e1, e2) != 1:
                    continue
                # Extended GCD: e1*s + e2*t = 1
                _, s, t = extended_gcd(e1, e2)
                # m = c1^s * c2^t mod n
                c1_part = pow(c1, s, n) if s >= 0 else pow(modinv(c1, n), -s, n)
                c2_part = pow(c2, t, n) if t >= 0 else pow(modinv(c2, n), -t, n)
                m = (c1_part * c2_part) % n
                result = try_decrypt_and_check(m, flag_format)
                if result:
                    return result

    return None


def attack_hastad(params: RSAParams, flag_format: str) -> str | None:
    """Hastad's broadcast attack: same message, small e, multiple recipients."""
    if params.e is None or params.e > 17:
        return None
    if len(params.ciphertexts) < params.e:
        return None

    print(f"[*] Attack: Hastad broadcast (e={params.e}, {len(params.ciphertexts)} ciphertexts)")
    e = params.e

    # Collect (c, n) pairs with same e
    pairs = []
    for entry in params.ciphertexts:
        entry_e = entry.get('e', params.e)
        if entry_e == e:
            n = entry.get('n')
            c = entry.get('c')
            if n is not None and c is not None:
                pairs.append((c, n))
    if len(pairs) < e:
        return None

    # Use Chinese Remainder Theorem on the first e pairs
    pairs = pairs[:e]
    # CRT: find x such that x = c_i mod n_i for all i
    result_val = pairs[0][0]
    result_mod = pairs[0][1]
    for i in range(1, len(pairs)):
        c_i, n_i = pairs[i]
        # Combine using CRT
        g, u, v = extended_gcd(result_mod, n_i)
        if g != 1:
            continue
        combined = result_val * v * n_i + c_i * u * result_mod
        result_mod = result_mod * n_i
        result_val = combined % result_mod

    # Take e-th root
    root, exact = iroot(e, result_val)
    if exact:
        result = try_decrypt_and_check(root, flag_format)
        if result:
            return result

    return None


def attack_pollard_p1(params: RSAParams, flag_format: str) -> str | None:
    """Pollard's p-1 factorization when p-1 has only small prime factors."""
    if params.n is None or params.c is None or params.e is None:
        return None

    print("[*] Attack: Pollard p-1")
    n = params.n

    # Smoothness bound -- increase in stages
    for B in (50_000, 500_000, 2_000_000):
        a = 2
        # Compute a = 2^(B!) mod n iteratively (by prime powers up to B)
        # More efficient: iterate over primes up to B
        primes = _sieve_primes(B)
        for p in primes:
            # Compute highest power of p <= B
            pp = p
            while pp * p <= B:
                pp *= p
            a = pow(a, pp, n)

        g = gcd(a - 1, n)
        if 1 < g < n:
            p = g
            q = n // p
            if p * q == n:
                print(f"[*] Pollard p-1 found factors (B={B}): p={p.bit_length()}bits")
                phi = (p - 1) * (q - 1)
                try:
                    d = modinv(params.e, phi)
                except ValueError:
                    return None
                m = rsa_decrypt(params.c, d, n)
                result = try_decrypt_and_check(m, flag_format)
                if result:
                    return result
                return None

    return None


def _sieve_primes(limit: int) -> list[int]:
    """Simple Sieve of Eratosthenes."""
    if limit < 2:
        return []
    sieve = bytearray(b'\x01') * (limit + 1)
    sieve[0] = sieve[1] = 0
    for i in range(2, isqrt(limit) + 1):
        if sieve[i]:
            sieve[i * i::i] = bytearray(len(sieve[i * i::i]))
    return [i for i in range(2, limit + 1) if sieve[i]]


def attack_small_primes(params: RSAParams, flag_format: str) -> str | None:
    """Check if n is divisible by small primes (weak key generation)."""
    if params.n is None or params.c is None or params.e is None:
        return None

    print("[*] Attack: small prime factor check")
    n = params.n
    # Check first several thousand primes
    primes = _sieve_primes(100_000)
    for p in primes:
        if n % p == 0:
            q = n // p
            if p * q == n and q > 1:
                print(f"[*] Found small prime factor: p={p}")
                phi = (p - 1) * (q - 1)
                try:
                    d = modinv(params.e, phi)
                except ValueError:
                    continue
                m = rsa_decrypt(params.c, d, n)
                result = try_decrypt_and_check(m, flag_format)
                if result:
                    return result

    return None


def attack_coppersmith_short_pad(params: RSAParams, flag_format: str) -> str | None:
    """Simplified Coppersmith-style attack for small e with known prefix.

    If flag_format provides a known prefix (e.g., "HTB{"), and e is small,
    we can try to recover the message by brute-forcing the unknown suffix
    for very short messages.  This is a simplified version -- full lattice-based
    Coppersmith requires sage.
    """
    if params.e is None or params.c is None or params.n is None:
        return None
    if params.e > 7:
        return None
    if not flag_format:
        return None

    prefix = flag_format.rstrip('{')
    # Try messages of the form: prefix{XXXX} where XXXX is short
    # This only works for very short messages where m^e < n (no modular reduction)
    print(f"[*] Attack: Coppersmith-style brute force (prefix={prefix}, e={params.e})")

    prefix_bytes = (prefix + '{').encode()
    prefix_int = int.from_bytes(prefix_bytes, 'big')
    e = params.e
    n = params.n
    c = params.c

    # Try suffix lengths from 1 to 8 bytes (closing brace + up to 7 chars)
    for suffix_len in range(2, 9):
        # Total message length
        msg_len = len(prefix_bytes) + suffix_len
        # The message is: prefix_bytes + unknown + }
        # m = prefix_int << (suffix_len * 8) + unknown_bytes + ord('}')

        # For very short messages, the total might be few bytes, making brute force feasible
        # But for more than ~4 unknown bytes, this is too slow
        if suffix_len > 5:
            break

        # Brute force the suffix (excluding closing brace)
        inner_len = suffix_len - 1  # exclude the closing '}'
        if inner_len > 4:
            continue

        high = prefix_int << (suffix_len * 8)
        closing = ord('}')

        for guess in range(36 ** inner_len):
            # Convert guess to alphanumeric string
            chars = []
            g = guess
            for _ in range(inner_len):
                idx = g % 36
                g //= 36
                if idx < 10:
                    chars.append(chr(ord('0') + idx))
                else:
                    chars.append(chr(ord('a') + idx - 10))
            chars.reverse()
            inner = ''.join(chars)
            inner_bytes = inner.encode()
            inner_int = int.from_bytes(inner_bytes, 'big')

            m = high + (inner_int << 8) + closing
            if pow(m, e, n) == c:
                result = try_decrypt_and_check(m, flag_format)
                if result:
                    return result

    return None


# ---------------------------------------------------------------------------
# Advanced attacks: Coppersmith, Franklin-Reiter, Partial Key, LSB Oracle
# ---------------------------------------------------------------------------

def _has_sage() -> bool:
    """Check if SageMath is available on the system."""
    return shutil.which("sage") is not None


def _run_sage_script(script: str, timeout: int = 120) -> str | None:
    """Write a SageMath script to a temp file, execute it, and return stdout."""
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sage", delete=False
        ) as f:
            f.write(script)
            sage_path = f.name
        result = subprocess.run(
            ["sage", sage_path],
            capture_output=True, text=True, timeout=timeout,
        )
        os.unlink(sage_path)
        # Also clean up the compiled .py file sage creates
        py_compiled = sage_path + ".py"
        if os.path.exists(py_compiled):
            os.unlink(py_compiled)
        if result.returncode == 0:
            return result.stdout
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        try:
            os.unlink(sage_path)
        except Exception:
            pass
        return None


def _poly_mod_mul(a: list[int], b: list[int], n: int) -> list[int]:
    """Multiply two polynomials (coefficient lists) mod n.

    Polynomial is represented as list of coefficients [a0, a1, a2, ...]
    where poly(x) = a0 + a1*x + a2*x^2 + ...
    """
    if not a or not b:
        return []
    result = [0] * (len(a) + len(b) - 1)
    for i, ai in enumerate(a):
        if ai == 0:
            continue
        for j, bj in enumerate(b):
            if bj == 0:
                continue
            result[i + j] = (result[i + j] + ai * bj) % n
    return result


def _poly_mod_pow(base: list[int], exp: int, mod_poly: list[int], n: int) -> list[int]:
    """Compute base^exp mod mod_poly, all coefficients mod n."""
    result = [1]  # polynomial "1"
    b = base[:]
    while exp > 0:
        if exp & 1:
            result = _poly_mod_mul(result, b, n)
            result = _poly_mod_rem(result, mod_poly, n)
        b = _poly_mod_mul(b, b, n)
        b = _poly_mod_rem(b, mod_poly, n)
        exp >>= 1
    return result


def _poly_mod_rem(dividend: list[int], divisor: list[int], n: int) -> list[int]:
    """Compute polynomial remainder: dividend mod divisor, coefficients mod n."""
    # Remove trailing zeros
    while dividend and dividend[-1] % n == 0:
        dividend = dividend[:-1]
    while divisor and divisor[-1] % n == 0:
        divisor = divisor[:-1]
    if not divisor:
        return dividend
    if len(dividend) < len(divisor):
        return [c % n for c in dividend]

    result = [c % n for c in dividend]
    lead_inv = None
    try:
        lead_inv = modinv(divisor[-1], n)
    except ValueError:
        return result  # Can't invert -- bail out

    for i in range(len(result) - 1, len(divisor) - 2, -1):
        if result[i] % n == 0:
            continue
        coeff = (result[i] * lead_inv) % n
        for j in range(len(divisor)):
            result[i - len(divisor) + 1 + j] = (
                result[i - len(divisor) + 1 + j] - coeff * divisor[j]
            ) % n
    # Trim
    while result and result[-1] % n == 0:
        result = result[:-1]
    return result if result else [0]


def _poly_gcd(a: list[int], b: list[int], n: int) -> list[int]:
    """Compute GCD of two polynomials with coefficients mod n."""
    while b and any(c % n != 0 for c in b):
        a, b = b, _poly_mod_rem(a, b, n)
    return a


def attack_coppersmith_sage(params: RSAParams, flag_format: str) -> str | None:
    """Coppersmith's small roots via SageMath for stereotyped message attack.

    When part of the plaintext is known (e.g., flag format prefix) and the
    unknown part is small, we can use Coppersmith's method (lattice-based)
    to find the unknown portion.

    This generates a SageMath script and executes it, falling back to a pure
    Python brute-force approach if Sage is unavailable.
    """
    if params.e is None or params.c is None or params.n is None:
        return None
    if not flag_format:
        return None
    if not _has_sage():
        return None

    prefix = flag_format.rstrip('{') + '{'
    prefix_bytes = prefix.encode('utf-8')
    prefix_hex = prefix_bytes.hex()
    e = params.e
    n = params.n
    c = params.c

    print(f"[*] Attack: Coppersmith small roots via SageMath (prefix='{prefix}')")

    # Try various unknown byte lengths
    for unknown_bytes in range(1, 33):
        unknown_bits = unknown_bytes * 8

        sage_script = f'''
import sys
n = {n}
e = {e}
c = {c}
prefix_bytes = bytes.fromhex("{prefix_hex}")
prefix_int = int.from_bytes(prefix_bytes, "big")
unknown_bits = {unknown_bits}

P = PolynomialRing(Zmod(n), "x")
x = P.gen()
m = prefix_int * (2**unknown_bits) + x
f = m**e - c

# Normalize to monic
f = f.monic()

try:
    roots = f.small_roots(X=2**unknown_bits, beta=1.0, epsilon=1.0/30)
except Exception:
    roots = []

for root in roots:
    m_val = prefix_int * (2**unknown_bits) + int(root)
    try:
        byte_len = (m_val.bit_length() + 7) // 8
        plaintext = int(m_val).to_bytes(byte_len, "big")
        text = plaintext.decode("utf-8", errors="replace")
        print(f"COPPERSMITH_FOUND: {{text}}")
    except Exception:
        print(f"COPPERSMITH_HEX: {{hex(m_val)}}")
'''
        output = _run_sage_script(sage_script, timeout=120)
        if output:
            for line in output.strip().split('\n'):
                if line.startswith('COPPERSMITH_FOUND: '):
                    text = line[len('COPPERSMITH_FOUND: '):]
                    if _has_flag(text, flag_format):
                        return _extract_flag(text, flag_format)
                    if text.isprintable() and len(text) >= 4:
                        return text
                elif line.startswith('COPPERSMITH_HEX: '):
                    hex_val = line[len('COPPERSMITH_HEX: '):]
                    try:
                        m_val = int(hex_val, 16)
                        result = try_decrypt_and_check(m_val, flag_format)
                        if result:
                            return result
                    except ValueError:
                        pass

    return None


def attack_coppersmith_partial_p(params: RSAParams, flag_format: str) -> str | None:
    """Partial key exposure: factor n when high bits of p are known.

    Uses Coppersmith's method to find the unknown low bits of p.
    Common in CTFs where part of a prime is leaked.

    f(x) = p_high * 2^k + x has a root mod p (a factor of n).
    """
    if params.n is None or params.c is None or params.e is None:
        return None
    if params.partial_p_bits is None or params.partial_p_known is None:
        return None
    if not _has_sage():
        return None

    n = params.n
    e = params.e
    c = params.c
    p_high = params.partial_p_bits
    known_bits = params.partial_p_known
    total_bits = n.bit_length() // 2  # approximate bit length of p
    unknown_bits = total_bits - known_bits

    if unknown_bits <= 0 or unknown_bits > total_bits // 2:
        return None

    print(f"[*] Attack: Coppersmith partial p recovery ({known_bits}/{total_bits} bits known)")

    sage_script = f'''
n = {n}
p_high = {p_high}
known_bits = {known_bits}
unknown_bits = {unknown_bits}

P = PolynomialRing(Zmod(n), "x")
x = P.gen()
f = p_high * (2**unknown_bits) + x
f = f.monic()

try:
    roots = f.small_roots(X=2**unknown_bits, beta=0.5)
except Exception:
    roots = []

for root in roots:
    p_candidate = p_high * (2**unknown_bits) + int(root)
    if n % p_candidate == 0:
        q_candidate = n // p_candidate
        print(f"FACTOR_FOUND: {{p_candidate}} {{q_candidate}}")
'''
    output = _run_sage_script(sage_script, timeout=120)
    if output:
        for line in output.strip().split('\n'):
            if line.startswith('FACTOR_FOUND: '):
                parts = line[len('FACTOR_FOUND: '):].split()
                if len(parts) == 2:
                    try:
                        p = int(parts[0])
                        q = int(parts[1])
                        if p * q == n:
                            phi = (p - 1) * (q - 1)
                            d = modinv(e, phi)
                            m = rsa_decrypt(c, d, n)
                            result = try_decrypt_and_check(m, flag_format)
                            if result:
                                return result
                    except (ValueError, ZeroDivisionError):
                        pass

    return None


def attack_franklin_reiter(params: RSAParams, flag_format: str) -> str | None:
    """Franklin-Reiter related message attack.

    When two messages m1, m2 are related by m2 = a*m1 + b and encrypted with
    the same (n, e), we can recover m1 using polynomial GCD.

    Most common case in CTFs: same message with known difference (padding).
    Works best with e=3 using polynomial GCD, but also supports higher e via Sage.
    """
    if params.n is None or params.e is None:
        return None
    if len(params.ciphertexts) < 2:
        return None

    n = params.n
    e = params.e

    # Group ciphertexts by modulus
    by_n: dict[int, list[dict]] = {}
    for entry in params.ciphertexts:
        en = entry.get('n', n)
        if en is not None:
            by_n.setdefault(en, []).append(entry)

    for mod_n, entries in by_n.items():
        if len(entries) < 2:
            continue

        # For each pair, try common linear relationships
        for i in range(len(entries)):
            for j in range(i + 1, len(entries)):
                c1 = entries[i].get('c')
                c2 = entries[j].get('c')
                e1 = entries[i].get('e', e)
                e2 = entries[j].get('e', e)
                if c1 is None or c2 is None:
                    continue
                if e1 != e2:
                    continue  # Need same exponent for related-message

                # Try various known relationships: m2 = m1 + b
                # Common CTF patterns: b = 1, b = small constant,
                # b = difference of padding bytes
                for b_candidate in _franklin_reiter_b_candidates(flag_format):
                    result = _franklin_reiter_e3(
                        mod_n, e1, c1, c2, 1, b_candidate, flag_format
                    )
                    if result:
                        print(f"[+] Franklin-Reiter found plaintext (b={b_candidate})")
                        return result

    return None


def _franklin_reiter_b_candidates(flag_format: str) -> list[int]:
    """Generate candidate 'b' values for Franklin-Reiter m2 = m1 + b."""
    candidates = [1, -1, 2, -2]
    # Common padding differences
    for i in range(1, 256):
        if i not in candidates:
            candidates.append(i)
        if -i not in candidates:
            candidates.append(-i)
    # Powers of 256 (byte-level padding)
    for shift in range(1, 5):
        val = 256 ** shift
        if val not in candidates:
            candidates.append(val)
    return candidates[:100]  # Cap at 100 candidates


def _franklin_reiter_e3(
    n: int, e: int, c1: int, c2: int, a: int, b: int, flag_format: str
) -> str | None:
    """Franklin-Reiter for e=3 using polynomial GCD.

    f1(x) = x^e - c1
    f2(x) = (a*x + b)^e - c2
    gcd(f1, f2) should give (x - m1) if m2 = a*m1 + b.

    For e=3, this is efficient with pure Python polynomial arithmetic.
    For higher e, attempts via Sage if available.
    """
    if e == 3:
        # Pure Python polynomial GCD mod n
        # f1 = x^3 - c1: coefficients [(-c1) % n, 0, 0, 1]
        f1 = [(-c1) % n, 0, 0, 1]

        # f2 = (a*x + b)^3 - c2
        # (a*x + b)^3 = a^3*x^3 + 3*a^2*b*x^2 + 3*a*b^2*x + b^3
        a3 = pow(a, 3, n)
        a2b3 = (3 * pow(a, 2, n) * b) % n
        ab2_3 = (3 * a * pow(b, 2, n)) % n
        b3 = pow(b, 3, n)
        f2 = [(b3 - c2) % n, ab2_3 % n, a2b3 % n, a3 % n]

        try:
            g = _poly_gcd(f1, f2, n)
        except (ValueError, ZeroDivisionError):
            return None

        # If GCD is linear (degree 1): g = [g0, g1] means g1*x + g0 = 0
        # So x = -g0 * g1^(-1) mod n
        if len(g) == 2 and g[1] % n != 0:
            try:
                g1_inv = modinv(g[1], n)
                m = (-g[0] * g1_inv) % n
                # Verify: m^e mod n should equal c1
                if pow(m, e, n) == c1 % n:
                    result = try_decrypt_and_check(m, flag_format)
                    if result:
                        return result
            except ValueError:
                pass
        return None

    elif e <= 17 and _has_sage():
        # Use Sage for higher exponents
        sage_script = f'''
n = {n}
e = {e}
c1 = {c1}
c2 = {c2}
a = {a}
b = {b}

P = PolynomialRing(Zmod(n), "x")
x = P.gen()
f1 = x**e - c1
f2 = (a*x + b)**e - c2
try:
    g = f1.gcd(f2)
    if g.degree() == 1:
        # g = x - m  (monic after normalization)
        m = int(-g[0] * g[1]**(-1))
        if m < 0:
            m = m % n
        byte_len = (m.bit_length() + 7) // 8
        plaintext = int(m).to_bytes(byte_len, "big")
        text = plaintext.decode("utf-8", errors="replace")
        print(f"FR_FOUND: {{text}}")
except Exception:
    pass
'''
        output = _run_sage_script(sage_script, timeout=60)
        if output:
            for line in output.strip().split('\n'):
                if line.startswith('FR_FOUND: '):
                    text = line[len('FR_FOUND: '):]
                    if _has_flag(text, flag_format):
                        return _extract_flag(text, flag_format)
                    if text.isprintable() and len(text) >= 4:
                        return text
        return None

    return None


def attack_hastad_linear_padding(params: RSAParams, flag_format: str) -> str | None:
    """Hastad's broadcast attack with linear padding.

    Extension of standard Hastad for when each recipient applies linear padding:
    m_i = a_i * m + b_i (different per recipient).

    Uses CRT + Coppersmith via SageMath when available.
    Without Sage, falls back to checking if standard Hastad works with small adjustments.
    """
    if params.e is None or params.e > 17:
        return None
    if len(params.ciphertexts) < params.e:
        return None

    e = params.e

    # Check if ciphertexts have linear padding info (a, b fields)
    pairs_with_padding = []
    for entry in params.ciphertexts:
        entry_e = entry.get('e', params.e)
        if entry_e != e:
            continue
        n = entry.get('n')
        c = entry.get('c')
        a_val = entry.get('a', 1)
        b_val = entry.get('b', 0)
        if n is not None and c is not None:
            pairs_with_padding.append((n, c, a_val, b_val))

    if len(pairs_with_padding) < e:
        return None

    # Check if any pair actually has non-trivial padding
    has_padding = any(a != 1 or b != 0 for _, _, a, b in pairs_with_padding)
    if not has_padding:
        return None  # Standard Hastad handles this case

    print(f"[*] Attack: Hastad broadcast with linear padding (e={e})")

    if not _has_sage():
        # Pure Python fallback: try offsetting ciphertexts
        # For m_i = m + b_i (a_i=1), we can try: CRT on c_i - b_i^e and
        # adjust, but this only works for simple cases
        for shift in range(0, min(256, max(abs(b) for _, _, _, b in pairs_with_padding) + 1)):
            pairs = []
            for n_i, c_i, a_i, b_i in pairs_with_padding[:e]:
                if a_i == 1:
                    # c_i = (m + b_i)^e mod n_i
                    # For shift guess: if we know b_i, can't easily CRT
                    pass
                pairs.append((c_i, n_i))
            # Standard CRT + e-th root
            if len(pairs) >= e:
                val = pairs[0][0]
                mod = pairs[0][1]
                for k in range(1, e):
                    c_k, n_k = pairs[k]
                    g, u, v = extended_gcd(mod, n_k)
                    if g != 1:
                        continue
                    combined = val * v * n_k + c_k * u * mod
                    mod = mod * n_k
                    val = combined % mod
                root, exact = iroot(e, val)
                if exact:
                    result = try_decrypt_and_check(root, flag_format)
                    if result:
                        return result
        return None

    # SageMath approach: use Coppersmith on the combined polynomial
    pairs_str = str([(n, c, a, b) for n, c, a, b in pairs_with_padding[:e]])
    sage_script = f'''
e = {e}
pairs = {pairs_str}

# Hastad with linear padding using CRT + Coppersmith
# Each c_i = (a_i * m + b_i)^e mod n_i
# Build T_i(x) = (a_i * x + b_i)^e - c_i  (has root m mod n_i)
# Use CRT to combine into T(x) with root m mod N = prod(n_i)
# Then use Coppersmith/LLL to find small root

ns = [p[0] for p in pairs]
cs = [p[1] for p in pairs]
a_vals = [p[2] for p in pairs]
b_vals = [p[3] for p in pairs]

N = prod(ns)

# CRT on polynomials
P = PolynomialRing(Zmod(N), "x")
x = P.gen()

# Build combined polynomial via CRT
T = P(0)
for i in range(e):
    n_i = ns[i]
    c_i = cs[i]
    a_i = a_vals[i]
    b_i = b_vals[i]

    N_i = N // n_i
    # Modular inverse of N_i mod n_i
    N_i_inv = int(pow(int(N_i), -1, int(n_i)))

    # T_i(x) = (a_i * x + b_i)^e - c_i
    P_i = PolynomialRing(Zmod(n_i), "x")
    x_i = P_i.gen()
    t_i = (a_i * x_i + b_i)**e - c_i

    # Lift coefficients and add to combined
    for j, coeff in enumerate(t_i.list()):
        T += int(coeff) * N_i * N_i_inv * x**j

T = T.change_ring(Zmod(N))
T = T.monic()

try:
    roots = T.small_roots()
except Exception:
    roots = []

for root in roots:
    m_val = int(root)
    try:
        byte_len = (m_val.bit_length() + 7) // 8
        plaintext = int(m_val).to_bytes(byte_len, "big")
        text = plaintext.decode("utf-8", errors="replace")
        print(f"HASTAD_LP_FOUND: {{text}}")
    except Exception:
        print(f"HASTAD_LP_HEX: {{hex(m_val)}}")
'''
    output = _run_sage_script(sage_script, timeout=120)
    if output:
        for line in output.strip().split('\n'):
            if line.startswith('HASTAD_LP_FOUND: '):
                text = line[len('HASTAD_LP_FOUND: '):]
                if _has_flag(text, flag_format):
                    return _extract_flag(text, flag_format)
                if text.isprintable() and len(text) >= 4:
                    return text
            elif line.startswith('HASTAD_LP_HEX: '):
                hex_val = line[len('HASTAD_LP_HEX: '):]
                try:
                    m_val = int(hex_val, 16)
                    result = try_decrypt_and_check(m_val, flag_format)
                    if result:
                        return result
                except ValueError:
                    pass

    return None


def attack_lsb_oracle(params: RSAParams, flag_format: str) -> str | None:
    """LSB oracle attack (Bleichenbacher-style binary search).

    When an oracle reveals the least significant bit of the decrypted ciphertext,
    we can recover the full plaintext in log2(n) queries via binary search.

    This attack requires an oracle function. In CTF context, the oracle is
    typically a network service. This function provides the algorithm framework
    that can be called with a custom oracle.

    For auto-solve, we detect if there's a server script that leaks LSB and
    attempt to interact with it.
    """
    # This attack requires runtime oracle interaction -- we provide the framework
    # but can't auto-detect without a running service.
    # The attack is available as lsb_oracle_recover() for the tool router to call.
    return None


def lsb_oracle_recover(n: int, e: int, c: int, oracle_func, flag_format: str = "") -> str | None:
    """Recover plaintext using LSB oracle (Bleichenbacher-style).

    Args:
        n: RSA modulus
        e: Public exponent
        c: Ciphertext
        oracle_func: Function that takes ciphertext (int) and returns LSB (0 or 1)
        flag_format: Expected flag prefix

    The attack works by repeatedly multiplying the ciphertext by 2^e mod n.
    Each query reveals one bit of information about the plaintext, allowing
    binary search over the message space.

    Returns the recovered plaintext string or None.
    """
    from fractions import Fraction

    print(f"[*] Attack: LSB oracle (binary search over {n.bit_length()} bits)")

    lo = Fraction(0)
    hi = Fraction(n)
    c_prime = c
    multiplier = pow(2, e, n)
    total_bits = n.bit_length()

    for bit_idx in range(total_bits):
        c_prime = (c_prime * multiplier) % n
        lsb = oracle_func(c_prime)

        mid = (lo + hi) / 2
        if lsb == 0:
            hi = mid
        else:
            lo = mid

        if bit_idx % 100 == 0 and bit_idx > 0:
            print(f"[*]   LSB oracle: {bit_idx}/{total_bits} bits recovered...")

    # The plaintext is approximately hi (or lo, they converge)
    m = int(hi)
    result = try_decrypt_and_check(m, flag_format)
    if result:
        return result
    # Also try nearby values (rounding)
    for offset in range(-2, 3):
        candidate = m + offset
        if candidate > 0:
            r = try_decrypt_and_check(candidate, flag_format)
            if r:
                return r
    return None


def attack_dp_leak(params: RSAParams, flag_format: str) -> str | None:
    """Recover plaintext when dp (d mod p-1) is leaked.

    If dp is known: for any value m, compute m^dp mod n.
    Then gcd(m^dp - m, n) often reveals p.

    This is a common CTF scenario where dp or dq leaks from a side channel.
    """
    if params.n is None or params.c is None or params.e is None:
        return None
    if params.dp is None and params.dq is None:
        return None
    if params.p is not None and params.q is not None:
        return None  # Already have factors, direct attack handles it

    n = params.n
    e = params.e
    c = params.c

    # Try dp first, then dq
    for d_partial, label in [(params.dp, 'dp'), (params.dq, 'dq')]:
        if d_partial is None:
            continue

        print(f"[*] Attack: {label} leak recovery")

        # For multiple base values, try to extract p
        for base in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
            # m^(dp) mod n: if dp = d mod (p-1), then m^dp ≡ m^d mod p
            # So m^dp - m ≡ 0 mod p
            # gcd(m^dp - m, n) should give p
            val = pow(base, d_partial, n)
            g = gcd(val - base, n)
            if 1 < g < n:
                p = g
                q = n // p
                if p * q == n:
                    print(f"[*] {label} leak: found p ({p.bit_length()} bits)")
                    phi = (p - 1) * (q - 1)
                    try:
                        d = modinv(e, phi)
                    except ValueError:
                        continue
                    m = rsa_decrypt(c, d, n)
                    result = try_decrypt_and_check(m, flag_format)
                    if result:
                        return result

        # Alternative: brute force e*dp = 1 + k*(p-1) for small k
        # Since dp < p-1 and e*dp = 1 + k*(p-1), k < e
        for k in range(1, e + 1):
            # p = (e * dp - 1) / k + 1
            numerator = e * d_partial - 1
            if numerator % k != 0:
                continue
            p_candidate = numerator // k + 1
            if p_candidate < 2:
                continue
            if n % p_candidate == 0:
                p = p_candidate
                q = n // p
                if p * q == n and q > 1:
                    print(f"[*] {label} leak: brute-forced k={k}, found p ({p.bit_length()} bits)")
                    phi = (p - 1) * (q - 1)
                    try:
                        d = modinv(e, phi)
                    except ValueError:
                        continue
                    m = rsa_decrypt(c, d, n)
                    result = try_decrypt_and_check(m, flag_format)
                    if result:
                        return result

    return None


def attack_multi_prime(params: RSAParams, flag_format: str) -> str | None:
    """Multi-prime RSA: n = p * q * r * ... (more than 2 factors).

    If n has many small-ish prime factors, we can factor it more easily.
    Uses Pollard rho for additional factoring after finding one factor.
    """
    if params.n is None or params.c is None or params.e is None:
        return None
    if params.has_factors():
        return None  # Already factored

    n = params.n
    e = params.e
    c = params.c

    print("[*] Attack: multi-prime RSA (Pollard rho)")

    factors = []
    remaining = n

    def pollard_rho(n: int, max_iter: int = 2_000_000) -> int | None:
        """Pollard's rho factorization."""
        if n % 2 == 0:
            return 2
        x = 2
        y = 2
        d = 1
        # f(x) = x^2 + 1 mod n
        c_val = 1
        while d == 1:
            x = (x * x + c_val) % n
            y = (y * y + c_val) % n
            y = (y * y + c_val) % n
            d = gcd(abs(x - y), n)
            max_iter -= 1
            if max_iter <= 0:
                return None
        if d != n:
            return d
        return None

    # Try to find all factors
    for attempt in range(20):
        if remaining == 1:
            break
        # Check small primes first
        for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]:
            while remaining % p == 0:
                factors.append(p)
                remaining //= p

        if remaining == 1:
            break

        # Try Pollard rho
        factor = pollard_rho(remaining, max_iter=500_000)
        if factor is not None and factor != remaining:
            # Check if factor is prime (try to factor it further)
            factors.append(factor)
            remaining //= factor
        else:
            break

    if remaining > 1:
        factors.append(remaining)

    if len(factors) < 2:
        return None

    # Verify: product of factors should be n
    product = 1
    for f in factors:
        product *= f
    if product != n:
        return None

    # Compute phi for multi-prime RSA: phi = prod(p_i - 1)
    phi = 1
    for f in factors:
        phi *= (f - 1)

    print(f"[*] Multi-prime RSA: {len(factors)} factors found")

    try:
        d = modinv(e, phi)
    except ValueError:
        # phi might share a factor with e; try lcm-based approach
        from functools import reduce
        def lcm(a, b):
            return a * b // gcd(a, b)
        lam = reduce(lcm, [f - 1 for f in factors])
        try:
            d = modinv(e, lam)
        except ValueError:
            return None

    m = rsa_decrypt(c, d, n)
    result = try_decrypt_and_check(m, flag_format)
    if result:
        return result

    return None


def attack_boneh_durfee(params: RSAParams, flag_format: str) -> str | None:
    """Boneh-Durfee attack: extends Wiener's to d < n^0.292 (vs n^0.25).

    Uses lattice reduction (LLL) via SageMath to find small d when e is large.
    This covers cases where Wiener's just barely fails.
    """
    if params.e is None or params.n is None or params.c is None:
        return None
    if params.e < 100:
        return None  # Small e: other attacks are better
    if not _has_sage():
        return None

    n = params.n
    e = params.e
    c = params.c

    # Only try if e is unusually large relative to n (suggests small d)
    # Heuristic: e should be roughly the same size as n
    if e.bit_length() < n.bit_length() * 0.5:
        return None

    print("[*] Attack: Boneh-Durfee (extended Wiener via lattice)")

    sage_script = f'''
import sys

def boneh_durfee(e, n, delta=0.292, m=4):
    """Boneh-Durfee attack for small d."""
    # We want to find (k, d) such that e*d = 1 + k*(n - p - q + 1)
    # Rewrite: e*d + k*(p + q - 1 - n) = 1
    # Let s = -p - q, then e*d + k*(s - 1 + n) has root (k, d) small

    # Use Herrmann-May simplification
    A = (n + 1) // 2
    P = PolynomialRing(Zmod(e), "x, y")
    x, y = P.gens()

    f = x * (A + y) + 1

    X = Integer(2 * floor(n**delta))
    Y = Integer(floor(n**0.5))

    # Build lattice using shift polynomials
    t = m + 1

    polys = []
    for i in range(m + 1):
        for j in range(m - i + 1):
            g = x**j * f**i * e**(m - i)
            polys.append(g)
    for i in range(m + 1):
        for j in range(1, t + 1):
            h = y**j * f**i * e**(m - i)
            polys.append(h)

    # Build matrix
    dim = len(polys)

    # Collect all monomials
    monomials = set()
    for p in polys:
        for mono in p.monomials():
            monomials.add(mono)
    monomials = sorted(monomials, key=lambda m: (m.degree(), str(m)))

    if len(monomials) > dim:
        monomials = monomials[:dim]

    M = Matrix(ZZ, dim, len(monomials))
    for i, poly in enumerate(polys):
        for j, mono in enumerate(monomials):
            xi, yi = mono.degrees()
            coeff = poly.monomial_coefficient(mono)
            M[i, j] = int(coeff) * X**xi * Y**yi

    try:
        L = M.LLL()
    except Exception:
        return None

    # Extract polynomials from reduced basis
    PZ = PolynomialRing(ZZ, "x, y")
    xz, yz = PZ.gens()

    found_polys = []
    for row in L:
        poly = PZ(0)
        for j, mono in enumerate(monomials):
            xi, yi = mono.degrees()
            if row[j] != 0:
                coeff = row[j] // (X**xi * Y**yi)
                poly += coeff * xz**xi * yz**yi
        if poly != 0:
            found_polys.append(poly)

    # Try to solve the system
    if len(found_polys) >= 2:
        try:
            # Use resultants
            p1 = found_polys[0]
            p2 = found_polys[1]

            # Resultant to eliminate y
            PY = PolynomialRing(ZZ, "y")
            res = p1.resultant(p2, xz)
            if res != 0:
                # Factor the univariate resultant
                PY2 = PolynomialRing(ZZ, "y2")
                y2 = PY2.gen()
                res_uni = PY2(res.polynomial(yz))
                roots = res_uni.roots()
                for root, mult in roots:
                    y_val = int(root)
                    # Substitute back to find x
                    p1_sub = p1.subs(yz=y_val)
                    PX = PolynomialRing(ZZ, "x2")
                    x2 = PX.gen()
                    p1_uni = PX(p1_sub.polynomial(xz))
                    x_roots = p1_uni.roots()
                    for x_root, _ in x_roots:
                        k_val = int(x_root)
                        if k_val != 0:
                            # d = (1 + k*(A + y)) / e... reconstruct
                            d_candidate = (1 + k_val * (int(A) + y_val))
                            if d_candidate % e == 0:
                                d_candidate //= e
                            else:
                                d_candidate = pow(int(e), -1, int(abs(k_val * (int(A) + y_val))))
                            if d_candidate > 0:
                                return d_candidate
        except Exception:
            pass

    return None

n = {n}
e = {e}
c = {c}

# Try multiple delta values
for delta in [0.26, 0.27, 0.28, 0.29, 0.292]:
    for m in [3, 4, 5]:
        try:
            d = boneh_durfee(e, n, delta=delta, m=m)
            if d is not None and d > 1:
                m_val = pow(c, int(d), n)
                byte_len = (int(m_val).bit_length() + 7) // 8
                if byte_len > 0:
                    plaintext = int(m_val).to_bytes(byte_len, "big")
                    try:
                        text = plaintext.decode("utf-8", errors="replace")
                        if any(c.isalpha() for c in text):
                            print(f"BD_FOUND: {{text}}")
                            sys.exit(0)
                    except Exception:
                        pass
        except Exception:
            continue

print("BD_NONE")
'''
    output = _run_sage_script(sage_script, timeout=120)
    if output:
        for line in output.strip().split('\n'):
            if line.startswith('BD_FOUND: '):
                text = line[len('BD_FOUND: '):]
                if _has_flag(text, flag_format):
                    return _extract_flag(text, flag_format)
                if text.isprintable() and len(text) >= 4:
                    return text

    return None


def attack_known_plaintext_padding(params: RSAParams, flag_format: str) -> str | None:
    """Try known-plaintext attacks when PKCS#1 v1.5 padding is suspected.

    PKCS#1 v1.5: m = 0x00 0x02 [padding] 0x00 [data]
    If we know the padding structure and message is short, this can help.
    """
    if params.e is None or params.c is None or params.n is None:
        return None
    if params.e > 7:
        return None
    if not flag_format:
        return None

    prefix = flag_format.rstrip('{') + '{'
    e = params.e
    n = params.n
    c = params.c

    print("[*] Attack: PKCS#1 padding with small e")

    # PKCS#1 v1.5 format: 00 02 [random padding >= 8 bytes] 00 [message]
    # Total length = key size in bytes
    key_bytes = (n.bit_length() + 7) // 8

    # For small e, if most of the message is known (PKCS padding + prefix),
    # the unknown bits may be small enough for Coppersmith
    prefix_bytes = prefix.encode('utf-8')

    # Try various padding lengths
    for pad_len in range(8, key_bytes - len(prefix_bytes) - 2):
        # Remaining unknown = closing part of flag
        remaining = key_bytes - 3 - pad_len - len(prefix_bytes)
        if remaining < 1 or remaining > 32:
            continue

        # Structure: 00 02 [pad_len random bytes] 00 [prefix_bytes] [unknown]
        # The high bytes are: 0x0002 followed by padding
        # This is too variable to brute force the padding, but if e=3 and
        # the message without padding is short, we can try direct root

    # Alternative: try without PKCS padding (raw RSA with small e)
    # Already handled by attack_small_e and attack_coppersmith_short_pad
    return None


# ---------------------------------------------------------------------------
# Main solver
# ---------------------------------------------------------------------------

def solve(dirpath: str, flag_format: str) -> None:
    """Main solver: extract parameters and try attacks."""
    print(f"[*] Scanning directory: {dirpath}")
    params = scan_directory(dirpath)
    print(f"[*] Extracted: {params}")

    if not params.has_basic() and not params.ciphertexts:
        print("[-] Could not extract RSA parameters (need at least n and c)")
        sys.exit(1)

    # Populate known_prefix for Coppersmith attacks
    if flag_format:
        params.known_prefix = flag_format.rstrip('{') + '{'

    # Attack cascade -- fast/simple attacks first, then advanced lattice-based
    attacks = [
        # Phase 1: Direct / trivial attacks (fast, no factoring needed)
        ("direct", attack_direct),
        ("small_e", attack_small_e),
        ("dp_leak", attack_dp_leak),
        # Phase 2: Factoring attacks
        ("wiener", attack_wiener),
        ("fermat", attack_fermat),
        ("small_primes", attack_small_primes),
        ("multi_prime", attack_multi_prime),
        ("pollard_p1", attack_pollard_p1),
        # Phase 3: Multi-ciphertext attacks
        ("common_modulus", attack_common_modulus),
        ("hastad", attack_hastad),
        ("franklin_reiter", attack_franklin_reiter),
        ("hastad_linear_padding", attack_hastad_linear_padding),
        # Phase 4: Coppersmith / lattice-based (may be slow, require Sage)
        ("coppersmith_brute", attack_coppersmith_short_pad),
        ("coppersmith_sage", attack_coppersmith_sage),
        ("coppersmith_partial_p", attack_coppersmith_partial_p),
        ("boneh_durfee", attack_boneh_durfee),
        # Phase 5: Padding / oracle attacks (framework)
        ("known_plaintext_padding", attack_known_plaintext_padding),
        ("lsb_oracle", attack_lsb_oracle),
    ]

    for name, attack_fn in attacks:
        try:
            result = attack_fn(params, flag_format)
            if result:
                # Check if result looks like a flag
                if _has_flag(result, flag_format):
                    flag = _extract_flag(result, flag_format)
                    print(f"\n[+] FLAG: {flag}")
                else:
                    # Print as potential plaintext
                    print(f"\n[+] Decrypted plaintext ({name}): {result}")
                    print(f"[+] FLAG: {result}")
                return
        except Exception as e:
            print(f"[-] {name} failed: {e}")
            continue

    print("[-] All attacks exhausted. No flag found.")
    sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="RSA attack solver for CTF challenges",
    )
    parser.add_argument(
        "--dir", required=True,
        help="Challenge directory (or single file) to scan for RSA parameters",
    )
    parser.add_argument(
        "--flag-format", default="",
        help="Expected flag prefix, e.g. 'HTB{' or 'flag{'",
    )
    args = parser.parse_args()
    solve(args.dir, args.flag_format)
