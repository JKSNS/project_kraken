#!/usr/bin/env python3
"""Kraken helper -- comprehensive crypto attack suite for CTF challenges.

Original capabilities (preserved):
  - RC4, AES-ECB, AES-CBC decryption with known key

New capabilities:
  - CBC bit-flipping attack (modify ciphertext to change plaintext)
  - AES-CTR nonce reuse / two-time pad detection and crib dragging
  - Hash length extension (MD5, SHA1, SHA256)
  - DES weak/semi-weak key detection
  - ECB byte-at-a-time oracle decryption
  - Challenge directory auto-scanning and attack selection

Usage:
    # Original interface (backward compatible)
    python3 auto_crypto.py --algo rc4 --key "123456" --ct "hex_ciphertext"

    # New: auto-scan challenge directory
    python3 auto_crypto.py --dir /path/to/challenge --flag-format "flag{"

    # New: CBC bit-flip
    python3 auto_crypto.py --cbc-bitflip --ct AABB... --known "user=guest" \\
        --target "user=admin" --block-index 1

    # New: CTR nonce reuse
    python3 auto_crypto.py --ctr-reuse --ct1 AABB... --ct2 CCDD...

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import math
import os
import re
import struct
import sys
from pathlib import Path

try:
    from Crypto.Cipher import AES, ARC4, DES
    from Crypto.Util.Padding import unpad, pad
    _HAS_CRYPTO = True
except ImportError:
    _HAS_CRYPTO = False

# ─── Flag scanning ────────────────────────────────────────────────────
DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")


def _scan_flags(text: str, flag_format: str = "") -> list[str]:
    """Return all flag-like strings found in *text*."""
    flags: list[str] = []
    if flag_format:
        prefix = flag_format.rstrip("{")
        try:
            pat = re.compile(re.escape(prefix) + r"\{[^}]{3,}\}")
            flags.extend(m.group(0) for m in pat.finditer(text))
        except re.error:
            pass
    flags.extend(m.group(0) for m in DEFAULT_FLAG_RE.finditer(text))
    seen: set[str] = set()
    unique: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _emit_flag(flag: str) -> None:
    """Print flag in the standard EXTRACTED FLAG format."""
    print(f"EXTRACTED FLAG: {flag}")


# ═══════════════════════════════════════════════════════════════════════
#  Original functionality (preserved exactly)
# ═══════════════════════════════════════════════════════════════════════

def solve(algo: str, key_hex: str, ct_hex: str, iv_hex: str | None = None,
          flag_format: str = "") -> str | None:
    """Decrypt ciphertext with known key. Returns plaintext or None."""
    if not _HAS_CRYPTO:
        print("[-] pycryptodome is not installed. Run: pip install pycryptodome")
        return None

    try:
        key = bytes.fromhex(key_hex)
        ct = bytes.fromhex(ct_hex)
        iv = bytes.fromhex(iv_hex) if iv_hex else None
    except ValueError:
        print("[-] Error parsing hex inputs. Ensure key, ct, and iv are valid hex strings.")
        return None

    print(f"[*] Attempting {algo.upper()} decryption...")
    pt = None
    try:
        if algo.lower() == "rc4":
            cipher = ARC4.new(key)
            pt = cipher.decrypt(ct)
            print(f"[+] Decrypted: {pt}")
            try:
                print(f"[+] ASCII: {pt.decode()}")
            except Exception:
                pass

        elif algo.lower() == "aes-ecb":
            cipher = AES.new(key, AES.MODE_ECB)
            pt = cipher.decrypt(ct)
            try:
                pt = unpad(pt, AES.block_size)
            except Exception:
                print("[!] Warning: PKCS7 Unpad failed, showing raw bytes.")
            print(f"[+] Decrypted: {pt}")
            try:
                print(f"[+] ASCII: {pt.decode()}")
            except Exception:
                pass

        elif algo.lower() == "aes-cbc":
            if not iv:
                print("[-] AES-CBC requires an IV (--iv).")
                return None
            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = cipher.decrypt(ct)
            try:
                pt = unpad(pt, AES.block_size)
            except Exception:
                print("[!] Warning: PKCS7 Unpad failed, showing raw bytes.")
            print(f"[+] Decrypted: {pt}")
            try:
                print(f"[+] ASCII: {pt.decode()}")
            except Exception:
                pass

        elif algo.lower() == "aes-ctr":
            if not iv:
                # Use zero nonce
                iv = b"\x00" * 8
            cipher = AES.new(key, AES.MODE_CTR, nonce=iv[:8])
            pt = cipher.decrypt(ct)
            print(f"[+] Decrypted: {pt}")
            try:
                print(f"[+] ASCII: {pt.decode()}")
            except Exception:
                pass

        elif algo.lower() == "des":
            cipher = DES.new(key[:8], DES.MODE_ECB)
            pt = cipher.decrypt(ct)
            try:
                pt = unpad(pt, DES.block_size)
            except Exception:
                print("[!] Warning: PKCS7 Unpad failed, showing raw bytes.")
            print(f"[+] Decrypted: {pt}")
            try:
                print(f"[+] ASCII: {pt.decode()}")
            except Exception:
                pass

        elif algo.lower() == "des-cbc":
            if not iv:
                print("[-] DES-CBC requires an IV (--iv).")
                return None
            cipher = DES.new(key[:8], DES.MODE_CBC, iv[:8])
            pt = cipher.decrypt(ct)
            try:
                pt = unpad(pt, DES.block_size)
            except Exception:
                print("[!] Warning: PKCS7 Unpad failed, showing raw bytes.")
            print(f"[+] Decrypted: {pt}")
            try:
                print(f"[+] ASCII: {pt.decode()}")
            except Exception:
                pass

        else:
            print(f"[-] Unsupported algorithm: {algo}. "
                  "Use: rc4, aes-ecb, aes-cbc, aes-ctr, des, des-cbc")
    except Exception as e:
        print(f"[-] Decryption failed: {e}")

    # Check for flags in plaintext
    if pt is not None:
        try:
            text = pt.decode("utf-8", errors="replace")
            for flag in _scan_flags(text, flag_format):
                _emit_flag(flag)
        except Exception:
            pass

    return pt


# ═══════════════════════════════════════════════════════════════════════
#  CBC Bit-Flipping Attack
# ═══════════════════════════════════════════════════════════════════════

def cbc_bitflip(ciphertext: bytes, block_size: int, known_plain: bytes,
                target_plain: bytes, block_index: int) -> bytes:
    """Modify ciphertext to change plaintext at block_index via CBC bit-flip.

    In CBC mode, plaintext block P[i] = D(C[i]) ^ C[i-1].
    By modifying C[i-1], we can change P[i] without knowing the key.

    new_C[i-1][j] = C[i-1][j] ^ known_P[i][j] ^ target_P[i][j]

    Args:
        ciphertext: Full ciphertext (IV prepended if applicable)
        block_size: Block size in bytes (8 for DES, 16 for AES)
        known_plain: Known plaintext of the target block
        target_plain: Desired plaintext for the target block
        block_index: Which block to modify (0-indexed from first data block)

    Returns:
        Modified ciphertext with the bit-flip applied.
    """
    ct = bytearray(ciphertext)
    prev_block_start = (block_index - 1) * block_size

    # If block_index is 0, we flip the IV (which is ct[0:block_size])
    if block_index == 0:
        prev_block_start = 0
    elif prev_block_start < 0:
        raise ValueError("block_index must be >= 0 (0 flips IV)")

    for j in range(min(len(known_plain), len(target_plain), block_size)):
        if prev_block_start + j < len(ct):
            ct[prev_block_start + j] ^= known_plain[j] ^ target_plain[j]

    return bytes(ct)


def auto_cbc_bitflip(ciphertext: bytes, block_size: int = 16,
                     flag_format: str = "") -> list[tuple[bytes, str]]:
    """Try common CBC bit-flip targets automatically.

    Returns list of (modified_ct, description) pairs.
    """
    results: list[tuple[bytes, str]] = []

    # Common bit-flip targets in CTF challenges
    common_targets = [
        (b"admin=0", b"admin=1", "admin flag flip"),
        (b"admin=false", b"admin=true\x00", "admin bool flip"),
        (b"role=user\x00\x00\x00\x00\x00", b"role=admin\x00\x00\x00\x00", "role escalation"),
        (b"is_admin=0", b"is_admin=1", "is_admin flip"),
        (b"logged_in=0", b"logged_in=1", "login flip"),
        (b"guest\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
         b"admin\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", "user to admin"),
        (b";admin=fals", b";admin=true", "cookie admin flip"),
    ]

    num_blocks = len(ciphertext) // block_size
    for known, target, desc in common_targets:
        known = known[:block_size]
        target = target[:block_size]
        for bi in range(1, num_blocks):
            try:
                modified = cbc_bitflip(ciphertext, block_size, known, target, bi)
                results.append((modified, f"{desc} (block {bi})"))
            except (ValueError, IndexError):
                continue

    return results


# ═══════════════════════════════════════════════════════════════════════
#  AES-CTR Nonce Reuse / Two-Time Pad
# ═══════════════════════════════════════════════════════════════════════

def detect_ctr_reuse(ciphertexts: list[bytes]) -> bool:
    """Detect if two ciphertexts were encrypted with the same CTR nonce.

    When the same keystream is reused, XOR of two ciphertexts produces
    XOR of two plaintexts, which tends to be mostly printable ASCII.
    """
    for i, c1 in enumerate(ciphertexts):
        for c2 in ciphertexts[i + 1:]:
            xored = bytes(a ^ b for a, b in zip(c1, c2))
            if not xored:
                continue
            # If XOR result has significant printable ASCII, likely same nonce
            # XOR of two ASCII texts produces ~30-50% printable chars typically
            printable = sum(1 for b in xored if 32 <= b < 127)
            if printable > len(xored) * 0.3:
                return True
    return False


def crib_drag(ct1: bytes, ct2: bytes,
              cribs: list[bytes] | None = None) -> list[tuple[int, bytes, str]]:
    """Crib dragging attack on two-time pad.

    XOR the two ciphertexts, then drag known plaintext fragments (cribs)
    across the result to recover the other plaintext.

    Args:
        ct1: First ciphertext
        ct2: Second ciphertext
        cribs: Known plaintext fragments to try. If None, uses defaults.

    Returns:
        List of (position, crib, recovered_text) tuples where the
        recovered text is printable ASCII.
    """
    xored = bytes(a ^ b for a, b in zip(ct1, ct2))

    if cribs is None:
        cribs = [
            b"the ", b"The ", b" the ", b"flag", b"FLAG", b"CTF",
            b"flag{", b"FLAG{", b"ctf{", b"HTB{", b"picoCTF{",
            b" is ", b" are ", b" was ", b" and ", b" for ",
            b"admin", b"password", b"secret", b"key",
            b"http://", b"https://", b"GET ", b"POST ",
            b"import ", b"from ", b"def ", b"class ",
            b"\x00\x00\x00", b"true", b"false", b"null",
        ]

    results: list[tuple[int, bytes, str]] = []
    for crib in cribs:
        for pos in range(len(xored) - len(crib) + 1):
            candidate = bytes(x ^ c for x, c in zip(xored[pos:], crib))
            if all(32 <= b < 127 for b in candidate):
                results.append((pos, crib, candidate.decode("ascii")))

    # Deduplicate and sort by position
    seen: set[tuple[int, str]] = set()
    unique: list[tuple[int, bytes, str]] = []
    for pos, crib, text in results:
        key = (pos, text)
        if key not in seen:
            seen.add(key)
            unique.append((pos, crib, text))
    unique.sort(key=lambda x: x[0])

    return unique


def many_time_pad_attack(ciphertexts: list[bytes],
                         flag_format: str = "") -> list[str]:
    """Attack multiple ciphertexts encrypted with the same stream/OTP.

    Uses the "space trick": space XOR letter = letter with flipped case.
    This allows statistical recovery of the keystream.
    """
    if len(ciphertexts) < 2:
        return []

    max_len = max(len(c) for c in ciphertexts)
    # For each position, count how many XORs with other ciphertexts yield letters
    keystream = bytearray(max_len)
    confidence = [0] * max_len

    for pos in range(max_len):
        byte_candidates: dict[int, int] = {}
        for i, c1 in enumerate(ciphertexts):
            if pos >= len(c1):
                continue
            # Count: how many other CTs produce a letter when XORed at this pos?
            letter_count = 0
            for j, c2 in enumerate(ciphertexts):
                if i == j or pos >= len(c2):
                    continue
                xor_byte = c1[pos] ^ c2[pos]
                # Space (0x20) XOR letter = letter with case flipped
                if 65 <= xor_byte <= 122:
                    letter_count += 1

            if letter_count > len(ciphertexts) // 2:
                # This ciphertext byte is likely XOR of space (0x20) with keystream
                key_byte = c1[pos] ^ 0x20
                byte_candidates[key_byte] = byte_candidates.get(key_byte, 0) + letter_count

        if byte_candidates:
            best = max(byte_candidates, key=byte_candidates.get)  # type: ignore
            keystream[pos] = best
            confidence[pos] = byte_candidates[best]

    # Decrypt all ciphertexts with recovered keystream
    flags: list[str] = []
    for ct in ciphertexts:
        decrypted = bytes(c ^ k for c, k in zip(ct, keystream))
        try:
            text = decrypted.decode("ascii", errors="replace")
            flags.extend(_scan_flags(text, flag_format))
        except Exception:
            pass

    return list(dict.fromkeys(flags))


# ═══════════════════════════════════════════════════════════════════════
#  Hash Length Extension Attack
# ═══════════════════════════════════════════════════════════════════════

def _md_pad(msg_len: int, hash_type: str = "md5") -> bytes:
    """Compute Merkle-Damgard padding for a message of given length.

    MD5 uses little-endian length; SHA uses big-endian.
    """
    # Padding: 0x80 + zeros + 8-byte length
    bit_len = msg_len * 8

    # Number of zero bytes needed
    if hash_type in ("md5",):
        block_size = 64
        # Pad to 56 mod 64
        pad_len = (56 - (msg_len + 1) % block_size) % block_size
        padding = b"\x80" + b"\x00" * pad_len
        # Length in bits, little-endian 64-bit
        padding += struct.pack("<Q", bit_len)
    else:
        # SHA1, SHA256: big-endian
        block_size = 64
        pad_len = (56 - (msg_len + 1) % block_size) % block_size
        padding = b"\x80" + b"\x00" * pad_len
        padding += struct.pack(">Q", bit_len)

    return padding


def _split_hash(hash_hex: str, hash_type: str = "md5") -> tuple[int, ...]:
    """Split a hex hash string into state words."""
    raw = bytes.fromhex(hash_hex)
    if hash_type == "md5":
        # 4 x 32-bit words, little-endian
        return struct.unpack("<4I", raw)
    elif hash_type == "sha1":
        # 5 x 32-bit words, big-endian
        return struct.unpack(">5I", raw)
    elif hash_type == "sha256":
        # 8 x 32-bit words, big-endian
        return struct.unpack(">8I", raw)
    raise ValueError(f"Unsupported hash type: {hash_type}")


def hash_length_extension(known_hash: str, known_data: bytes, append_data: bytes,
                          key_length_range: range = range(1, 33),
                          hash_type: str = "md5") -> list[tuple[str, bytes]]:
    """Compute H(key || known_data || padding || append_data) without knowing key.

    Implements the Merkle-Damgard length extension attack for MD5, SHA1, SHA256.

    Args:
        known_hash: Hex-encoded hash of (key || known_data)
        known_data: The known data portion (without the secret key)
        append_data: Data to append after the padding
        key_length_range: Range of possible key lengths to try
        hash_type: Hash algorithm ("md5", "sha1", "sha256")

    Returns:
        List of (extended_hash, extended_message) for each possible key length.
        The extended_message is: known_data || padding || append_data
        (the server sees: key || known_data || padding || append_data)
    """
    results: list[tuple[str, bytes]] = []

    try:
        state_words = _split_hash(known_hash, hash_type)
    except (ValueError, struct.error) as e:
        print(f"[-] Cannot parse hash: {e}")
        return results

    for key_len in key_length_range:
        # Total length of key + known_data
        total_len = key_len + len(known_data)
        # Compute the padding that would be applied
        padding = _md_pad(total_len, hash_type)
        # The forged message (what the server sees after the key):
        # known_data || padding || append_data
        forged_msg = known_data + padding + append_data

        # Now compute hash(key || known_data || padding || append_data)
        # by initializing the hash with the known state and hashing append_data
        # with the correct length counter
        new_len = total_len + len(padding) + len(append_data)

        try:
            if hash_type == "md5":
                extended_hash = _md5_extend(state_words, append_data,
                                            total_len + len(padding))
            elif hash_type == "sha1":
                extended_hash = _sha1_extend(state_words, append_data,
                                             total_len + len(padding))
            elif hash_type == "sha256":
                extended_hash = _sha256_extend(state_words, append_data,
                                               total_len + len(padding))
            else:
                continue

            if extended_hash:
                results.append((extended_hash, forged_msg))
        except Exception:
            continue

    return results


def _md5_extend(state: tuple[int, ...], data: bytes, prior_len: int) -> str | None:
    """Extend an MD5 hash with additional data given the internal state.

    Uses pure Python MD5 implementation to resume from a known state.
    """
    try:
        import _md5  # CPython internal
        # This approach doesn't work on all platforms; fall back
    except ImportError:
        pass

    # Pure Python MD5 extension using hashlib internals
    # We construct the hash object with the correct state
    try:
        # Use hlextend if available
        import hlextend  # type: ignore
        sha = hlextend.new("md5")
        return sha.extend(data.decode("latin-1"), state, prior_len,
                          data.decode("latin-1"))
    except ImportError:
        pass

    # Pure Python fallback: manual MD5 compression
    # For CTF purposes, we compute via the hashpumpy approach
    try:
        import hashpumpy  # type: ignore
        new_hash, new_msg = hashpumpy.hashpump(
            state if isinstance(state, str) else struct.pack("<4I", *state).hex(),
            data, b"", prior_len)
        return new_hash
    except ImportError:
        pass

    # Minimal pure-Python MD5 length extension
    return _pure_md5_extend(state, data, prior_len)


def _pure_md5_extend(state: tuple[int, ...], data: bytes, prior_len: int) -> str | None:
    """Pure Python MD5 length extension (no external dependencies)."""
    # MD5 constants
    S = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ]
    K = [int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF for i in range(64)]

    def left_rotate(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def md5_compress(block: bytes, h0: int, h1: int, h2: int, h3: int) -> tuple[int, int, int, int]:
        M = list(struct.unpack("<16I", block))
        a, b, c, d = h0, h1, h2, h3
        for i in range(64):
            if i < 16:
                f = (b & c) | (~b & d)
                g = i
            elif i < 32:
                f = (d & b) | (~d & c)
                g = (5 * i + 1) % 16
            elif i < 48:
                f = b ^ c ^ d
                g = (3 * i + 5) % 16
            else:
                f = c ^ (b | ~d)
                g = (7 * i) % 16
            f = (f + a + K[i] + M[g]) & 0xFFFFFFFF
            a = d
            d = c
            c = b
            b = (b + left_rotate(f, S[i])) & 0xFFFFFFFF
        return (h0 + a) & 0xFFFFFFFF, (h1 + b) & 0xFFFFFFFF, \
               (h2 + c) & 0xFFFFFFFF, (h3 + d) & 0xFFFFFFFF

    # Pad the append data
    total_len = prior_len + len(data)
    padded = data + _md_pad(total_len, "md5")
    # But we need to adjust: the padding encodes the TOTAL length including prior
    # Recompute: pad the data as if total_len bytes have been processed
    bit_len = total_len * 8
    pad_len = (56 - (total_len + 1) % 64) % 64
    padded = data + b"\x80" + b"\x00" * pad_len + struct.pack("<Q", bit_len)

    h0, h1, h2, h3 = state
    # Process each 64-byte block
    for i in range(0, len(padded), 64):
        block = padded[i:i + 64]
        if len(block) < 64:
            break
        h0, h1, h2, h3 = md5_compress(block, h0, h1, h2, h3)

    return struct.pack("<4I", h0, h1, h2, h3).hex()


def _sha1_extend(state: tuple[int, ...], data: bytes, prior_len: int) -> str | None:
    """Extend a SHA1 hash. Uses hashpumpy or hlextend if available."""
    try:
        import hashpumpy
        original_hash = struct.pack(">5I", *state).hex()
        new_hash, _ = hashpumpy.hashpump(original_hash, b"", data, prior_len)
        return new_hash.hex() if isinstance(new_hash, bytes) else new_hash
    except ImportError:
        pass
    return None


def _sha256_extend(state: tuple[int, ...], data: bytes, prior_len: int) -> str | None:
    """Extend a SHA256 hash. Uses hashpumpy or hlextend if available."""
    try:
        import hashpumpy
        original_hash = struct.pack(">8I", *state).hex()
        new_hash, _ = hashpumpy.hashpump(original_hash, b"", data, prior_len)
        return new_hash.hex() if isinstance(new_hash, bytes) else new_hash
    except ImportError:
        pass
    return None


# ═══════════════════════════════════════════════════════════════════════
#  DES Weak Key Detection
# ═══════════════════════════════════════════════════════════════════════

DES_WEAK_KEYS = [
    bytes.fromhex("0101010101010101"),
    bytes.fromhex("FEFEFEFEFEFEFEFE"),
    bytes.fromhex("E0E0E0E0F1F1F1F1"),
    bytes.fromhex("1F1F1F1F0E0E0E0E"),
]

DES_SEMI_WEAK_PAIRS = [
    (bytes.fromhex("01FE01FE01FE01FE"), bytes.fromhex("FE01FE01FE01FE01")),
    (bytes.fromhex("1FE01FE00EF10EF1"), bytes.fromhex("E01FE01FF10EF10E")),
    (bytes.fromhex("01E001E001F101F1"), bytes.fromhex("E001E001F101F101")),
    (bytes.fromhex("1FFE1FFE0EFE0EFE"), bytes.fromhex("FE1FFE1FFE0EFE0E")),
    (bytes.fromhex("011F011F010E010E"), bytes.fromhex("1F011F010E010E01")),
    (bytes.fromhex("E0FEE0FEF1FEF1FE"), bytes.fromhex("FEE0FEE0FEF1FEF1")),
]


def is_des_weak_key(key: bytes) -> bool:
    """Check if a DES key is a weak key."""
    return key in DES_WEAK_KEYS


def is_des_semi_weak_key(key: bytes) -> tuple[bool, bytes | None]:
    """Check if a DES key is a semi-weak key. Returns (is_semi_weak, paired_key)."""
    for k1, k2 in DES_SEMI_WEAK_PAIRS:
        if key == k1:
            return True, k2
        if key == k2:
            return True, k1
    return False, None


def des_weak_key_attack(ciphertext: bytes, flag_format: str = "") -> list[str]:
    """Try decrypting with all DES weak keys."""
    if not _HAS_CRYPTO:
        return []

    flags: list[str] = []
    all_keys = list(DES_WEAK_KEYS)
    for k1, k2 in DES_SEMI_WEAK_PAIRS:
        all_keys.extend([k1, k2])

    for key in all_keys:
        try:
            cipher = DES.new(key, DES.MODE_ECB)
            pt = cipher.decrypt(ciphertext[:8 * (len(ciphertext) // 8)])
            try:
                text = pt.decode("ascii", errors="replace")
                flags.extend(_scan_flags(text, flag_format))
            except Exception:
                pass
        except Exception:
            continue

    return list(dict.fromkeys(flags))


# ═══════════════════════════════════════════════════════════════════════
#  ECB Byte-at-a-Time Oracle Decryption
# ═══════════════════════════════════════════════════════════════════════

def ecb_detect_block_size(oracle_func) -> int:
    """Detect the block size of an ECB oracle by increasing input length."""
    initial_len = len(oracle_func(b""))
    for i in range(1, 256):
        new_len = len(oracle_func(b"A" * i))
        if new_len > initial_len:
            return new_len - initial_len
    return 16  # default


def ecb_detect_prefix_len(oracle_func, block_size: int) -> int:
    """Detect the length of the unknown prefix in an ECB oracle."""
    # Find two consecutive identical blocks
    for pad_len in range(block_size * 3):
        ct = oracle_func(b"A" * (pad_len + block_size * 2))
        blocks = [ct[i:i + block_size] for i in range(0, len(ct), block_size)]
        for i in range(len(blocks) - 1):
            if blocks[i] == blocks[i + 1]:
                # prefix_len + pad_len aligns to block boundary
                return i * block_size - pad_len
    return 0


def ecb_byte_at_a_time(oracle_func, block_size: int = 16,
                        known_prefix_len: int = 0,
                        flag_format: str = "") -> bytes:
    """Decrypt unknown suffix via ECB oracle one byte at a time.

    The oracle encrypts: prefix || attacker_input || unknown_suffix
    We control attacker_input and can observe the ciphertext.

    Args:
        oracle_func: Function that takes bytes input and returns ciphertext bytes
        block_size: ECB block size (typically 16 for AES)
        known_prefix_len: Length of any fixed prefix before our input
        flag_format: Expected flag format for early termination

    Returns:
        Recovered suffix bytes
    """
    # Determine total suffix length
    base_len = len(oracle_func(b""))

    # Align prefix to block boundary
    prefix_pad = (block_size - known_prefix_len % block_size) % block_size
    aligned_base = len(oracle_func(b"A" * prefix_pad))
    suffix_len = aligned_base - known_prefix_len - prefix_pad

    recovered = bytearray()
    print(f"[*] ECB oracle: block_size={block_size}, prefix_len={known_prefix_len}, "
          f"suffix_len={suffix_len}")

    for byte_idx in range(suffix_len):
        # Pad so that the target byte is the last byte of a block
        pad_len = prefix_pad + (block_size - 1 - (byte_idx % block_size))
        padding = b"A" * pad_len

        # Which block contains our target byte?
        target_block = (known_prefix_len + pad_len + byte_idx) // block_size
        block_start = target_block * block_size
        block_end = block_start + block_size

        # Get the target block's ciphertext
        target_ct = oracle_func(padding)[block_start:block_end]

        # Brute-force the last byte
        found = False
        test_prefix = padding + bytes(recovered)
        for candidate in range(256):
            test_input = test_prefix + bytes([candidate])
            # Only send the right amount to align
            test_ct = oracle_func(test_input[:pad_len + byte_idx + 1])
            if test_ct[block_start:block_end] == target_ct:
                recovered.append(candidate)
                found = True
                break

        if not found:
            print(f"[!] Could not recover byte at index {byte_idx}")
            break

        # Check if we've found a flag
        try:
            text = recovered.decode("ascii", errors="replace")
            flags = _scan_flags(text, flag_format)
            if flags:
                for f in flags:
                    _emit_flag(f)
                return bytes(recovered)
        except Exception:
            pass

    return bytes(recovered)


# ═══════════════════════════════════════════════════════════════════════
#  Challenge Directory Auto-Scan
# ═══════════════════════════════════════════════════════════════════════

def _read_file_bytes(path: str, limit: int = 1_000_000) -> bytes:
    """Read file as bytes, up to limit."""
    try:
        with open(path, "rb") as f:
            return f.read(limit)
    except OSError:
        return b""


def _read_file_text(path: str, limit: int = 500_000) -> str:
    """Read file as text, up to limit."""
    try:
        with open(path, "r", errors="replace") as f:
            return f.read(limit)
    except OSError:
        return ""


def _detect_crypto_type(challenge_dir: str) -> dict:
    """Scan challenge directory and detect crypto scheme.

    Returns a dict with:
      - type: str (cbc_bitflip, ctr_reuse, hash_extension, des_weak, ecb_oracle, etc.)
      - files: dict of relevant file paths and contents
      - params: dict of detected parameters
    """
    result: dict = {"type": "unknown", "files": {}, "params": {}}

    if not os.path.isdir(challenge_dir):
        return result

    py_files: list[str] = []
    data_files: list[str] = []
    ct_files: list[str] = []

    for root, _dirs, files in os.walk(challenge_dir):
        depth = root.replace(challenge_dir, "").count(os.sep)
        if depth > 2:
            continue
        for fname in files:
            fpath = os.path.join(root, fname)
            lower = fname.lower()
            if lower.endswith(".py"):
                py_files.append(fpath)
            elif lower.endswith((".txt", ".dat", ".json", ".out", ".hex")):
                data_files.append(fpath)
            elif lower in ("ciphertext", "ct", "encrypted", "output", "flag.enc"):
                ct_files.append(fpath)

    # Read Python source files to detect crypto patterns
    all_source = ""
    for pyf in py_files:
        src = _read_file_text(pyf)
        all_source += src + "\n"
        result["files"][pyf] = src

    source_lower = all_source.lower()

    # Detect CBC patterns
    if "cbc" in source_lower and ("bitflip" in source_lower or "bit_flip" in source_lower
                                   or "admin" in source_lower):
        result["type"] = "cbc_bitflip"
    elif "mode_cbc" in source_lower or "aes.mode_cbc" in source_lower:
        if "admin" in source_lower or "role" in source_lower:
            result["type"] = "cbc_bitflip"

    # Detect CTR nonce reuse
    if "mode_ctr" in source_lower or "ctr" in source_lower:
        if "nonce" in source_lower and ("same" in source_lower or "reuse" in source_lower
                                         or "fixed" in source_lower):
            result["type"] = "ctr_reuse"

    # Detect two-time pad / XOR stream reuse
    if "xor" in source_lower and ("same key" in source_lower or "reuse" in source_lower
                                   or "otp" in source_lower):
        result["type"] = "ctr_reuse"

    # Detect hash length extension
    if "hmac" not in source_lower:  # HMAC is NOT vulnerable
        if ("hash" in source_lower and "secret" in source_lower) or \
           "length.ext" in source_lower:
            result["type"] = "hash_extension"
        if "md5" in source_lower and "sign" in source_lower:
            result["type"] = "hash_extension"

    # Detect DES
    if "des" in source_lower and "weak" in source_lower:
        result["type"] = "des_weak"

    # Detect ECB oracle
    if "mode_ecb" in source_lower or "ecb" in source_lower:
        if "oracle" in source_lower or "encrypt(" in source_lower:
            result["type"] = "ecb_oracle"

    # Collect ciphertext data
    for ctf in ct_files + data_files:
        data = _read_file_bytes(ctf)
        if data:
            result["files"][ctf] = data

    return result


def auto_solve_challenge(challenge_dir: str, flag_format: str = "") -> list[str]:
    """Auto-detect and solve crypto challenges from a directory."""
    flags: list[str] = []

    detection = _detect_crypto_type(challenge_dir)
    crypto_type = detection["type"]
    print(f"[*] Detected crypto type: {crypto_type}")

    if crypto_type == "cbc_bitflip":
        # Look for ciphertext in data files
        for path, data in detection["files"].items():
            if isinstance(data, bytes) and len(data) >= 32:
                print(f"[*] Trying CBC bit-flip on {path}")
                results = auto_cbc_bitflip(data, 16, flag_format)
                for modified_ct, desc in results:
                    print(f"[+] {desc}: {modified_ct.hex()}")

    elif crypto_type == "ctr_reuse":
        # Collect all ciphertexts
        cts: list[bytes] = []
        for path, data in detection["files"].items():
            if isinstance(data, bytes):
                cts.append(data)
            elif isinstance(data, str):
                # Try to parse hex ciphertexts from text files
                for line in data.splitlines():
                    line = line.strip()
                    try:
                        cts.append(bytes.fromhex(line))
                    except ValueError:
                        pass
        if len(cts) >= 2:
            if detect_ctr_reuse(cts):
                print("[+] CTR nonce reuse detected!")
                # Try many-time-pad attack
                mtp_flags = many_time_pad_attack(cts, flag_format)
                flags.extend(mtp_flags)
                # Try crib dragging on all pairs
                for i in range(len(cts)):
                    for j in range(i + 1, len(cts)):
                        results = crib_drag(cts[i], cts[j])
                        for pos, crib, text in results:
                            candidate_flags = _scan_flags(text, flag_format)
                            flags.extend(candidate_flags)
                            if candidate_flags:
                                print(f"[+] Crib drag hit at pos {pos} "
                                      f"(crib={crib!r}): {text}")

    elif crypto_type == "des_weak":
        for path, data in detection["files"].items():
            if isinstance(data, bytes) and len(data) >= 8:
                print(f"[*] Trying DES weak key attack on {path}")
                flags.extend(des_weak_key_attack(data, flag_format))

    elif crypto_type == "hash_extension":
        print("[*] Hash length extension detected (requires oracle interaction)")
        # This attack typically needs server interaction;
        # we print guidance and attempt offline if possible

    # Always try: look for encrypted data with keys in source
    for path, content in detection["files"].items():
        if not isinstance(content, str):
            continue
        # Look for hardcoded keys and ciphertexts in Python source
        key_matches = re.findall(
            r'(?:key|KEY|secret)\s*=\s*(?:b["\']([^"\']+)["\']|'
            r'bytes\.fromhex\(["\']([0-9a-fA-F]+)["\']\))',
            content)
        ct_matches = re.findall(
            r'(?:ct|ciphertext|cipher_text|encrypted|enc)\s*=\s*'
            r'(?:b["\']([^"\']+)["\']|'
            r'bytes\.fromhex\(["\']([0-9a-fA-F]+)["\']\))',
            content)
        iv_matches = re.findall(
            r'(?:iv|IV|nonce)\s*=\s*'
            r'(?:b["\']([^"\']+)["\']|'
            r'bytes\.fromhex\(["\']([0-9a-fA-F]+)["\']\))',
            content)

        if key_matches and ct_matches:
            for km in key_matches:
                key_hex = km[1] if km[1] else km[0].encode().hex()
                for cm in ct_matches:
                    ct_hex = cm[1] if cm[1] else cm[0].encode().hex()
                    iv_hex = None
                    if iv_matches:
                        ivm = iv_matches[0]
                        iv_hex = ivm[1] if ivm[1] else ivm[0].encode().hex()

                    # Try each algorithm
                    for algo in ["aes-ecb", "aes-cbc", "aes-ctr", "rc4",
                                 "des", "des-cbc"]:
                        if algo in ("aes-cbc", "des-cbc") and not iv_hex:
                            continue
                        print(f"[*] Trying {algo} with key={key_hex[:16]}... "
                              f"ct={ct_hex[:16]}...")
                        pt = solve(algo, key_hex, ct_hex, iv_hex, flag_format)
                        if pt:
                            try:
                                text = pt.decode("utf-8", errors="replace")
                                found = _scan_flags(text, flag_format)
                                flags.extend(found)
                                if found:
                                    break
                            except Exception:
                                pass

    return list(dict.fromkeys(flags))


# ═══════════════════════════════════════════════════════════════════════
#  Main
# ═══════════════════════════════════════════════════════════════════════

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Comprehensive crypto attack suite for CTF challenges")

    # Original interface (backward compatible)
    parser.add_argument("--algo",
                        choices=["rc4", "aes-ecb", "aes-cbc", "aes-ctr",
                                 "des", "des-cbc"],
                        help="Algorithm to use")
    parser.add_argument("--key", help="Key in hex format")
    parser.add_argument("--ct", help="Ciphertext in hex format")
    parser.add_argument("--iv", default=None, help="IV in hex format (for CBC/CTR)")

    # New: directory scanning
    parser.add_argument("--dir", help="Challenge directory to auto-scan")
    parser.add_argument("--flag-format", "--flag_format", default="",
                        help="Expected flag format (e.g. 'flag{')")

    # New: CBC bit-flip
    parser.add_argument("--cbc-bitflip", action="store_true",
                        help="Perform CBC bit-flip attack")
    parser.add_argument("--known", help="Known plaintext (for bit-flip)")
    parser.add_argument("--target", help="Target plaintext (for bit-flip)")
    parser.add_argument("--block-index", type=int, default=1,
                        help="Block index to flip (default: 1)")
    parser.add_argument("--block-size", type=int, default=16,
                        help="Block size (default: 16)")

    # New: CTR nonce reuse
    parser.add_argument("--ctr-reuse", action="store_true",
                        help="Detect and exploit CTR nonce reuse")
    parser.add_argument("--ct1", help="First ciphertext (hex)")
    parser.add_argument("--ct2", help="Second ciphertext (hex)")

    # New: Hash length extension
    parser.add_argument("--hash-extend", action="store_true",
                        help="Hash length extension attack")
    parser.add_argument("--hash", help="Known hash (hex)")
    parser.add_argument("--data", help="Known data")
    parser.add_argument("--append", help="Data to append")
    parser.add_argument("--hash-type", default="md5",
                        choices=["md5", "sha1", "sha256"])

    args = parser.parse_args()

    # Dispatch to the appropriate mode
    if args.dir:
        # Auto-scan challenge directory
        flags = auto_solve_challenge(args.dir, args.flag_format)
        if flags:
            for f in flags:
                _emit_flag(f)
        else:
            print("[-] No flags found via auto-scan")

    elif args.cbc_bitflip and args.ct:
        ct = bytes.fromhex(args.ct)
        if args.known and args.target:
            modified = cbc_bitflip(
                ct, args.block_size,
                args.known.encode(), args.target.encode(),
                args.block_index)
            print(f"[+] Modified ciphertext: {modified.hex()}")
        else:
            results = auto_cbc_bitflip(ct, args.block_size, args.flag_format)
            for modified_ct, desc in results:
                print(f"[+] {desc}: {modified_ct.hex()}")

    elif args.ctr_reuse and args.ct1 and args.ct2:
        ct1 = bytes.fromhex(args.ct1)
        ct2 = bytes.fromhex(args.ct2)
        if detect_ctr_reuse([ct1, ct2]):
            print("[+] CTR nonce reuse detected!")
        results = crib_drag(ct1, ct2)
        for pos, crib, text in results:
            print(f"[+] pos={pos} crib={crib!r} => {text}")
            for f in _scan_flags(text, args.flag_format):
                _emit_flag(f)

    elif args.hash_extend and args.hash and args.data and args.append:
        results = hash_length_extension(
            args.hash, args.data.encode(), args.append.encode(),
            hash_type=args.hash_type)
        for ext_hash, ext_msg in results:
            print(f"[+] key_len=?: hash={ext_hash} msg={ext_msg.hex()}")

    elif args.algo and args.key and args.ct:
        # Original interface
        solve(args.algo, args.key, args.ct, args.iv, args.flag_format)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
