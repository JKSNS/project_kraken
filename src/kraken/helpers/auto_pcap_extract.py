#!/usr/bin/env python3
"""auto_pcap_extract -- Extract flags from PCAP/PCAPNG network captures.

Scans challenge directory for .pcap/.pcapng files and uses scapy to:
  - Reassemble TCP streams by 4-tuple
  - Extract HTTP request/response bodies
  - Extract DNS query names and TXT record data
  - Extract binaries (PE/ELF) from HTTP downloads
  - Search binaries and challenge source files for encryption keys/salts
  - Extract base64 blobs from C2/non-HTTP TCP streams
  - Try AES decryption (PBKDF2+CBC) with discovered keys
  - Decode PowerShell encoded commands (UTF-16LE base64)
  - USB HID keyboard keystroke reconstruction
  - DNS tunneling detection and decoding
  - TLS decryption with keylog files
  - FTP file transfer extraction
  - SMTP/email extraction from PCAP
  - Regex-scan all payloads for flag patterns

Outputs EXTRACTED FLAG: <flag> on success.
"""
import base64
import hashlib
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

try:
    from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Raw, rdpcap
except ImportError as e:
    print(f"[-] scapy import failed: {e}", file=sys.stderr)
    sys.exit(1)

# Try to import crypto libraries (optional, for AES decryption)
_HAS_PYCRYPTO = False
_HAS_CRYPTOGRAPHY = False
try:
    from Crypto.Cipher import AES as _PyCryptoAES
    _HAS_PYCRYPTO = True
except ImportError:
    pass
if not _HAS_PYCRYPTO:
    try:
        from cryptography.hazmat.primitives.ciphers import (
            Cipher as _CryChipher,
            algorithms as _cry_alg,
            modes as _cry_modes,
        )
        _HAS_CRYPTOGRAPHY = True
    except ImportError:
        pass

_HAS_CRYPTO = _HAS_PYCRYPTO or _HAS_CRYPTOGRAPHY

# Common .NET / system strings to reject as key candidates
_REJECT_KEYWORDS = {
    "system", "microsoft", "version", "public", "assembly", "runtime",
    "culture", "token", "mscorlib", "http", "windows", "namespace",
    "class", "interface", "module", "object", "collection", "attribute",
    "exception", "eventargs", "handler", "delegate", "generic", "nullable",
    "diagnostics", "security", "reflection", "resources", "threadstart",
    "icomparable", "ienumerable", "idisposable", "iconvertible",
    "typeinitializer", "constructor", "destructor", "compilergenerated",
    "debuggable", "targetframework", "assemblytitle", "assemblyproduct",
    "assemblydescription", "assemblycompany", "assemblyversion",
    "assemblyculture", "assemblyconfiguration", "assemblytrademark",
    "internalsvisible", "comvisible", "guidattribute",
}


def _reassemble_tcp_streams(packets) -> dict[tuple, bytes]:
    """Group packets by (src,dst,sport,dport) 4-tuple and concat Raw payloads."""
    streams: dict[tuple, bytes] = defaultdict(bytes)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
            key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)
            streams[key] += bytes(pkt[Raw].load)
    return dict(streams)


def _extract_http_payloads(packets) -> list[str]:
    """Parse HTTP request/response bodies from reassembled TCP streams."""
    payloads = []
    for _key, data in _reassemble_tcp_streams(packets).items():
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            continue
        parts = re.split(r"(?=HTTP/[\d.]+\s|GET |POST |PUT |DELETE |HEAD )", text)
        for part in parts:
            for sep in ("\r\n\r\n", "\n\n"):
                if sep in part:
                    body = part.split(sep, 1)[1].strip()
                    if len(body) >= 3:
                        payloads.append(body)
                    break
    return payloads


def _extract_dns_queries(packets) -> list[str]:
    """Pull DNS qname values and TXT record rdata."""
    results = []
    for pkt in packets:
        if not pkt.haslayer(DNS):
            continue
        dns = pkt[DNS]
        if dns.haslayer(DNSQR):
            qname = dns[DNSQR].qname
            if isinstance(qname, bytes):
                qname = qname.decode("utf-8", errors="replace")
            qname = qname.rstrip(".")
            if len(qname) >= 3:
                results.append(qname)
        # Walk answer RRs for TXT records
        if dns.ancount and dns.ancount > 0:
            ans = dns.an
            for _ in range(dns.ancount):
                if not isinstance(ans, DNSRR):
                    break
                if ans.type == 16:  # TXT
                    rdata = ans.rdata
                    items = rdata if isinstance(rdata, (list, tuple)) else [rdata]
                    for item in items:
                        txt = item.decode("utf-8", errors="replace") if isinstance(item, bytes) else str(item)
                        if len(txt) >= 3:
                            results.append(txt)
                try:
                    ans = ans.payload
                except Exception:
                    break
    return results


def _try_base64_decode(data: str) -> list[str]:
    """Find and decode long base64 strings within data."""
    results = []
    for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,2}", data):
        try:
            decoded = base64.b64decode(m.group(0)).decode("utf-8", errors="replace")
            printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
            if printable > len(decoded) * 0.7 and len(decoded) >= 3:
                results.append(decoded)
        except Exception:
            pass
    return results


def _search_for_flags(data: str, flag_format: str = "") -> list[str]:
    """Regex scan for flag patterns in text data."""
    flags = re.findall(r"[a-zA-Z_]{2,}\{[^}]{3,}\}", data)
    if flag_format:
        try:
            flags.extend(re.findall(flag_format, data))
        except re.error:
            pass
    return flags


# ---------------------------------------------------------------------------
# Binary extraction from HTTP streams
# ---------------------------------------------------------------------------

def _extract_binaries_from_streams(streams: dict[tuple, bytes]) -> list[bytes]:
    """Extract PE (MZ) and ELF binaries from HTTP response bodies in TCP streams."""
    binaries = []
    for _key, data in streams.items():
        # Look for HTTP response followed by binary data
        for sep in (b"\r\n\r\n", b"\n\n"):
            idx = data.find(sep)
            if idx < 0:
                continue
            header_text = data[:idx].decode("ascii", errors="replace").lower()
            if "http/" not in header_text:
                continue
            body = data[idx + len(sep):]
            if len(body) < 64:
                continue
            # Check for PE (MZ) header
            if body[:2] == b"MZ":
                binaries.append(body)
                print(f"[*] Extracted PE binary from HTTP stream ({len(body)} bytes)")
            # Check for ELF header
            elif body[:4] == b"\x7fELF":
                binaries.append(body)
                print(f"[*] Extracted ELF binary from HTTP stream ({len(body)} bytes)")
        # Also check for raw binary (no HTTP headers) with MZ/ELF header
        if data[:2] == b"MZ" and len(data) > 256:
            if data not in binaries:
                binaries.append(data)
        elif data[:4] == b"\x7fELF" and len(data) > 256:
            if data not in binaries:
                binaries.append(data)
    return binaries


# ---------------------------------------------------------------------------
# String extraction from binaries
# ---------------------------------------------------------------------------

def _extract_strings_from_binary(data: bytes, min_len: int = 6) -> tuple[list[str], list[str]]:
    """Extract ASCII and UTF-16LE strings from binary data.

    Returns (ascii_strings, utf16_strings).
    """
    ascii_strings = []
    utf16_strings = []
    seen = set()
    # ASCII strings
    for m in re.finditer(rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}", data):
        s = m.group(0).decode("ascii")
        if s not in seen:
            seen.add(s)
            ascii_strings.append(s)
    # UTF-16LE strings (common in .NET)
    for m in re.finditer(rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}", data):
        try:
            s = m.group(0).decode("utf-16-le")
            if s not in seen:
                seen.add(s)
                utf16_strings.append(s)
        except Exception:
            pass
    return ascii_strings, utf16_strings


def _is_plausible_key(s: str) -> bool:
    """Check if a string could be a cryptographic key or password."""
    if len(s) < 8 or len(s) > 128:
        return False
    # Must be printable, no spaces
    if not re.match(r"^[\x21-\x7e]+$", s):
        return False
    # Reject common .NET / system names
    lower = s.lower()
    for kw in _REJECT_KEYWORDS:
        if kw in lower:
            return False
    # Reject camelCase method/property names (set_Foo, get_Bar, etc.)
    if re.match(r"^(?:set|get|add|remove|is|has|can|on)_[A-Z]", s):
        return False
    # Reject if it looks like a .NET type name (contains dots)
    if "." in s:
        return False
    # Reject version strings (v4.0.30319, etc.)
    if re.match(r"^v?\d+\.\d+", s):
        return False
    # Reject PE header strings
    if "program" in lower and ("cannot" in lower or "dos" in lower):
        return False
    # Accept if it has mixed case + digits (key-like)
    has_upper = any(c.isupper() for c in s)
    has_lower = any(c.islower() for c in s)
    has_digit = any(c.isdigit() for c in s)
    has_special = any(c in "_-+/=!@#$%^&*" for c in s)
    # Good keys usually have mixed character types
    char_types = sum([has_upper, has_lower, has_digit, has_special])
    if char_types >= 3:
        return True
    # Accept 2 types only if the string has enough entropy (not a common word)
    if char_types >= 2 and len(s) >= 10:
        return True
    return False


def _is_plausible_salt(s: str) -> bool:
    """Check if a string could be a cryptographic salt."""
    if len(s) < 4 or len(s) > 64:
        return False
    # Must be printable, no spaces (salts don't typically have spaces)
    if not re.match(r"^[\x21-\x7e]+$", s):
        return False
    # Reject system strings
    lower = s.lower()
    for kw in _REJECT_KEYWORDS:
        if kw in lower:
            return False
    # Reject if it looks like a sentence or PE header
    if " " in s or "program" in lower:
        return False
    # Reject version strings
    if re.match(r"^v?\d+\.\d+", s):
        return False
    # Reject camelCase method/property names
    if re.match(r"^(?:set|get|add|remove|is|has|can|on)_[A-Z]", s):
        return False
    # Reject if contains dots (looks like type name)
    if "." in s:
        return False
    # Salts are often shorter and contain special chars or mixed chars
    has_special = any(c in "_-!@#$%^&*" for c in s)
    has_digit = any(c.isdigit() for c in s)
    if has_special or has_digit:
        return True
    return False


# ---------------------------------------------------------------------------
# Key/salt extraction from binaries
# ---------------------------------------------------------------------------

def _extract_keys_from_binary(binary_data: bytes) -> list[dict]:
    """Extract encryption keys/salts from a PE or ELF binary.

    Strategy: Check for crypto indicators, then extract plausible key+salt
    strings and return all combinations for brute-forcing.
    """
    ascii_strings, utf16_strings = _extract_strings_from_binary(binary_data, min_len=6)
    all_strings = ascii_strings + utf16_strings

    # Check if binary has crypto indicators
    crypto_indicators = [
        "AES", "Rfc2898", "PBKDF", "CryptoStream", "CreateDecryptor",
        "CreateEncryptor", "DeriveBytes", "SymmetricAlgorithm",
        "RijndaelManaged",
    ]
    has_crypto = any(
        any(ind in s for ind in crypto_indicators)
        for s in all_strings
    )

    if not has_crypto:
        return []

    print("[*] Binary has crypto indicators, extracting key candidates...")

    # Find plausible keys and salts
    key_candidates = [s for s in all_strings if _is_plausible_key(s)]
    salt_candidates = [s for s in all_strings if _is_plausible_salt(s)]

    # Also look for explicit key assignment patterns in source-like strings
    for s in all_strings:
        for m in re.finditer(
            r'(?:encrypt|decrypt|aes|key|password|secret|pass)\w*\s*[=:]\s*["\']([^"\']{6,})["\']',
            s, re.IGNORECASE,
        ):
            val = m.group(1)
            if val not in key_candidates:
                key_candidates.append(val)

    # Look for byte array salts in source patterns
    salt_byte_arrays = []
    for s in all_strings:
        for m in re.finditer(r'new\s+byte\s*\[\s*\d*\s*\]\s*\{([^}]+)\}', s):
            val = m.group(1)
            if re.match(r"[\d,\s]+$", val):
                try:
                    byte_vals = [int(x.strip()) for x in val.split(",") if x.strip()]
                    if all(0 <= b <= 255 for b in byte_vals) and len(byte_vals) >= 4:
                        salt_byte_arrays.append(bytes(byte_vals))
                except (ValueError, OverflowError):
                    pass

    if key_candidates:
        print(f"[*] Found {len(key_candidates)} key candidate(s), {len(salt_candidates)} salt candidate(s)")

    # Build key+salt combinations, prioritizing paired combos over empty salt
    candidates = []

    # Priority 1: key + byte-array salt (from source patterns)
    for key in key_candidates:
        for sb in salt_byte_arrays:
            candidates.append({"key": key, "salt": sb, "type": "pbkdf2_aes"})

    # Priority 2: key + salt string combos
    for key in key_candidates:
        for salt in salt_candidates:
            if salt != key:  # don't pair with self
                candidates.append({"key": key, "salt": salt.encode("utf-8"), "type": "pbkdf2_aes"})

    # Priority 3 (LOW): key with empty salt -- only if no salts found at all
    if not salt_candidates and not salt_byte_arrays:
        for key in key_candidates:
            candidates.append({"key": key, "salt": b"", "type": "pbkdf2_aes"})

    return candidates


# ---------------------------------------------------------------------------
# Key extraction from source files
# ---------------------------------------------------------------------------

def _scan_source_files_for_keys(challenge_dir: str) -> list[dict]:
    """Scan challenge source files (.cs, .py, .java, .js, .c, .cpp) for crypto keys/salts."""
    source_exts = (".cs", ".py", ".java", ".js", ".c", ".cpp", ".go", ".rb", ".php")
    candidates = []
    if not os.path.isdir(challenge_dir):
        return candidates

    for root, _dirs, files in os.walk(challenge_dir):
        # Skip solution/metadata directories
        if any(skip in root for skip in ["metadata/solution", ".git", "__pycache__", "node_modules"]):
            continue
        for fname in files:
            if not fname.lower().endswith(source_exts):
                continue
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="replace") as f:
                    content = f.read(256_000)
            except Exception:
                continue
            if not content.strip():
                continue
            print(f"[*] Scanning source file for keys: {fpath}")

            key_patterns = [
                r'(?:encrypt|decrypt|aes|key|password|secret|pass)\w*\s*[=:]\s*["\']([^"\']{6,})["\']',
                r'_(?:key|pass|secret|encrypt)\w*\s*[=:]\s*["\']([^"\']{6,})["\']',
            ]
            salt_patterns = [
                r'(?:salt|iv|nonce)\w*\s*[=:]\s*["\']([^"\']{4,})["\']',
                r'new\s+byte\s*\[\s*\d*\s*\]\s*\{([^}]+)\}',
            ]

            found_keys = set()
            found_salts = set()
            found_salt_bytes = []

            for pat in key_patterns:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    found_keys.add(m.group(1))
            for pat in salt_patterns:
                for m in re.finditer(pat, content, re.IGNORECASE):
                    val = m.group(1)
                    if re.match(r"[\d,\s]+$", val):
                        try:
                            byte_vals = [int(x.strip()) for x in val.split(",") if x.strip()]
                            if all(0 <= b <= 255 for b in byte_vals) and len(byte_vals) >= 4:
                                found_salt_bytes.append(bytes(byte_vals))
                        except (ValueError, OverflowError):
                            pass
                    else:
                        found_salts.add(val)

            for key in found_keys:
                for sb in found_salt_bytes:
                    candidates.append({"key": key, "salt": sb, "type": "pbkdf2_aes"})
                for salt in found_salts:
                    candidates.append({"key": key, "salt": salt.encode("utf-8"), "type": "pbkdf2_aes"})
                if not found_salts and not found_salt_bytes:
                    candidates.append({"key": key, "salt": b"", "type": "pbkdf2_aes"})

            if candidates:
                print(f"    Found {len(found_keys)} key(s), {len(found_salts) + len(found_salt_bytes)} salt(s)")

    return candidates


# ---------------------------------------------------------------------------
# Encrypted blob extraction from TCP streams
# ---------------------------------------------------------------------------

def _extract_encrypted_blobs(streams: dict[tuple, bytes]) -> list[tuple[str, tuple]]:
    """Extract base64-encoded blobs from non-HTTP TCP streams (C2 traffic).

    Returns list of (base64_string, stream_key) tuples.
    """
    blobs = []
    for key, data in streams.items():
        try:
            text = data.decode("utf-8", errors="replace")
        except Exception:
            continue

        # Skip streams that look purely like HTTP
        stripped = text.strip()
        if stripped.startswith(("HTTP/1", "GET ", "POST ")):
            # But still check non-HTTP parts
            pass

        # Find base64 blobs: at least 16 chars of base64
        for m in re.finditer(r"[A-Za-z0-9+/]{16,}={0,3}", text):
            blob = m.group(0)
            try:
                decoded = base64.b64decode(blob)
                # Valid base64 that's 16+ bytes (AES block size)
                if len(decoded) >= 16 and len(decoded) % 16 == 0:
                    blobs.append((blob, key))
            except Exception:
                pass

    return blobs


# ---------------------------------------------------------------------------
# AES Decryption
# ---------------------------------------------------------------------------

def _try_aes_decrypt(ciphertext: bytes, key_bytes: bytes, iv_bytes: bytes) -> str | None:
    """Try AES-CBC decryption with given key and IV. Returns plaintext or None."""
    if len(key_bytes) not in (16, 24, 32) or len(iv_bytes) != 16:
        return None
    if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
        return None
    try:
        if _HAS_PYCRYPTO:
            from Crypto.Cipher import AES
            cipher = AES.new(key_bytes, AES.MODE_CBC, iv_bytes)
            pt = cipher.decrypt(ciphertext)
        elif _HAS_CRYPTOGRAPHY:
            cipher = _CryChipher(_cry_alg.AES(key_bytes), _cry_modes.CBC(iv_bytes))
            decryptor = cipher.decryptor()
            pt = decryptor.update(ciphertext) + decryptor.finalize()
        else:
            return None

        # Remove PKCS7 padding
        if pt:
            pad_len = pt[-1]
            if 0 < pad_len <= 16 and all(b == pad_len for b in pt[-pad_len:]):
                pt = pt[:-pad_len]

        if not pt:
            return None

        # Check if result is mostly ASCII-printable (not just Unicode-printable,
        # since replacement chars \ufffd count as printable but indicate garbage)
        ascii_printable = sum(1 for b in pt if 32 <= b <= 126 or b in (9, 10, 13))
        if len(pt) > 0 and ascii_printable > len(pt) * 0.7:
            return pt.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def _try_decrypt_with_candidates(
    blobs: list[tuple[str, tuple]],
    key_candidates: list[dict],
    flag_format: str = "",
) -> tuple[list[str], list[str]]:
    """Try decrypting base64 blobs with key candidates using PBKDF2+AES-CBC.

    Returns (flags, decrypted_texts) tuple.
    """
    if not _HAS_CRYPTO or not blobs or not key_candidates:
        return [], []

    flags = []
    all_decrypted_texts = []

    # PBKDF2 iteration counts to try
    iteration_counts = [1000, 1, 100, 10000]

    seen_combos = set()
    found_working_key = False

    for cand in key_candidates:
        if found_working_key:
            break

        key_str = cand["key"]
        salt = cand["salt"]
        salt_bytes = salt if isinstance(salt, bytes) else salt.encode("utf-8")
        cache_key = (key_str, salt_bytes)
        if cache_key in seen_combos:
            continue
        seen_combos.add(cache_key)

        for iterations in iteration_counts:
            try:
                # PBKDF2 to derive key + IV (32 + 16 = 48 bytes)
                dk = hashlib.pbkdf2_hmac(
                    "sha1", key_str.encode("utf-8"), salt_bytes,
                    iterations, dklen=48,
                )
                aes_key = dk[:32]
                aes_iv = dk[32:48]

                # Test with first few blobs -- require at least 2 successful decryptions
                success_count = 0
                test_limit = min(5, len(blobs))
                for b64_blob, _stream_key in blobs[:test_limit]:
                    try:
                        ct = base64.b64decode(b64_blob)
                    except Exception:
                        continue
                    text = _try_aes_decrypt(ct, aes_key, aes_iv)
                    if text:
                        success_count += 1

                # Require at least 2 successful decryptions (or 1 if only 1 blob)
                min_required = min(2, len(blobs))
                if success_count < min_required:
                    continue

                print(
                    f"[+] PBKDF2 key works! key={key_str!r} "
                    f"salt={salt_bytes!r} iterations={iterations} "
                    f"(decrypted {success_count}/{test_limit})"
                )
                found_working_key = True

                # Decrypt ALL blobs with this key
                for b64_blob, _stream_key in blobs:
                    try:
                        ct = base64.b64decode(b64_blob)
                    except Exception:
                        continue
                    text = _try_aes_decrypt(ct, aes_key, aes_iv)
                    if text:
                        all_decrypted_texts.append(text)
                        found = _search_for_flags(text, flag_format)
                        flags.extend(found)

                break  # found working iteration count

            except Exception:
                continue

    # Scan all decrypted texts for flag fragments and parts
    if all_decrypted_texts:
        combined = "\n".join(all_decrypted_texts)
        print(f"[*] Decrypted {len(all_decrypted_texts)} blobs total")
        # Try to assemble multi-part flags from decrypted text alone
        flags.extend(_assemble_flag_parts(combined, flag_format))
        # Also do base64 decode within decrypted text
        for text in all_decrypted_texts:
            for decoded in _try_base64_decode(text):
                flags.extend(_search_for_flags(decoded, flag_format))

    return flags, all_decrypted_texts


def _assemble_flag_parts(text: str, flag_format: str = "") -> list[str]:
    """Try to find and assemble multi-part flags from text.

    Handles patterns like:
      - 'PREFIX{part1' in one message, 'part2}' in another
      - Explicit 'Nth flag part: value' markers
      - Flag prefix in one blob, flag body/suffix in labeled parts or suffixes
    """
    flags = []

    # Determine prefix to look for
    if flag_format:
        prefix = re.sub(r"[\\{}\[\]().*+?|]", "", flag_format)
    else:
        prefix = ""

    prefixes = [prefix] if prefix else []
    prefixes.extend(["flag", "FLAG", "ctf", "CTF", "HTB", "picoCTF", "ASIS"])

    # Collect labeled flag parts: "Nth flag part: value" on same line
    labeled_parts = {}
    # Match "Nth flag part:" followed by value on the SAME LINE (no newlines)
    # Use [^\S\n] to match horizontal whitespace only (not newlines)
    for m in re.finditer(
        r"(\d+)(?:st|nd|rd|th)\s+flag\s+part[^\S\n]*[:=][^\S\n]*([^\n]+)",
        text, re.IGNORECASE,
    ):
        part_text = m.group(2).strip()
        # Extract just the flag-like portion (alphanumeric + underscore + dash)
        flag_portion = re.match(r"([A-Za-z0-9_\-{}]+)", part_text)
        if flag_portion:
            labeled_parts[int(m.group(1))] = flag_portion.group(1)

    # Find flag-prefixed partial strings (PREFIX{ followed by flag chars, no closing })
    prefix_bodies = []
    for pfx in prefixes:
        if not pfx:
            continue
        pattern = re.escape(pfx) + r"\{([A-Za-z0-9_\-]+)"
        for m in re.finditer(pattern, text):
            body = m.group(1)
            after = text[m.end():m.end() + 1]
            if after == "}":
                continue  # Already a complete flag
            prefix_bodies.append((pfx, body))

    # Find potential flag suffixes: flag-like strings ending with }
    suffix_candidates = []
    for m in re.finditer(r"([A-Za-z0-9_\-]{3,})\}", text):
        candidate = m.group(1) + "}"
        # Verify it's not part of a complete flag already found
        before_pos = m.start() - 1
        if before_pos >= 0 and text[before_pos] == "{":
            continue  # Part of {content}
        suffix_candidates.append(candidate)

    # Strategy 1: prefix + labeled middle parts + suffix
    for pfx, body_start in prefix_bodies:
        # Get labeled parts excluding any that are too long (likely garbage)
        clean_parts = {
            k: v for k, v in labeled_parts.items()
            if len(v) < 100 and re.match(r"^[A-Za-z0-9_\-{}]+$", v)
        }

        # Try: prefix + middle labeled parts + suffix
        for suffix in suffix_candidates:
            middle = ""
            for idx in sorted(clean_parts.keys()):
                middle += clean_parts[idx]
            assembled = f"{pfx}{{{body_start}{middle}{suffix}"
            if re.match(r"^[A-Za-z]+\{[A-Za-z0-9_\-.]+\}$", assembled) and len(assembled) > 15:
                flags.append(assembled)

        # Try: prefix + each labeled part individually + suffix
        if clean_parts:
            for suffix in suffix_candidates:
                for _idx, part in clean_parts.items():
                    assembled = f"{pfx}{{{body_start}{part}{suffix}"
                    if re.match(r"^[A-Za-z]+\{[A-Za-z0-9_\-.]+\}$", assembled) and len(assembled) > 15:
                        flags.append(assembled)

        # Try: prefix + suffix (no middle)
        for suffix in suffix_candidates:
            assembled = f"{pfx}{{{body_start}{suffix}"
            if re.match(r"^[A-Za-z]+\{[A-Za-z0-9_\-.]+\}$", assembled) and len(assembled) > 15:
                flags.append(assembled)

    # Strategy 2: Just from labeled parts if they form a complete flag
    if len(labeled_parts) >= 2:
        assembled = "".join(labeled_parts[k] for k in sorted(labeled_parts.keys()))
        if len(assembled) > 10:
            flags.append(assembled)

    return flags


# ---------------------------------------------------------------------------
# PowerShell encoded command decoding
# ---------------------------------------------------------------------------

def _decode_powershell_commands(text: str, flag_format: str = "") -> tuple[list[str], list[str]]:
    """Find and decode PowerShell encoded commands (UTF-16LE base64).

    Returns (flags, decoded_texts) tuple.
    """
    flags = []
    decoded_texts = []

    # Pattern for powershell encoded commands
    ps_patterns = [
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*-(?:encoded(?:command)?|enc|e)\s+"?([A-Za-z0-9+/=]+)"?',
        r'(?:powershell(?:\.exe)?)\s+(?:-\w+\s+)*-(?:encoded(?:command)?|enc|e)\s+([A-Za-z0-9+/=]{20,})',
    ]

    matched_b64 = set()
    for pattern in ps_patterns:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            b64_data = m.group(1).strip('"').strip("'")
            if b64_data in matched_b64:
                continue
            matched_b64.add(b64_data)
            try:
                decoded = base64.b64decode(b64_data).decode("utf-16-le", errors="replace")
                if len(decoded) > 3:
                    print(f"[+] Decoded PowerShell command ({len(decoded)} chars)")
                    decoded_texts.append(decoded)
                    flags.extend(_search_for_flags(decoded, flag_format))
                    # Search for flag-like strings in quoted values
                    for tm in re.finditer(r'"([^"]{10,})"', decoded):
                        val = tm.group(1)
                        if any(c in val for c in "{}_"):
                            flags.extend(_search_for_flags(val, flag_format))
                    # Also look for flag parts in TaskName or similar
                    for tm in re.finditer(
                        r'(?:TaskName|Name|Key|Value)\s+"([^"]+)"', decoded
                    ):
                        val = tm.group(1)
                        # Check if this could be a flag suffix (contains } or flag-like chars)
                        if re.match(r"^[A-Za-z0-9_\-{}]+$", val):
                            print(f"[+] Found potential flag part in PS command: {val}")
            except Exception:
                pass

    # Also look for standalone large base64 that decodes to UTF-16LE
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,3}", text):
        b64_data = m.group(0)
        if b64_data in matched_b64:
            continue
        try:
            decoded_bytes = base64.b64decode(b64_data)
            # Check if it's UTF-16LE (odd bytes should be mostly 0x00 for ASCII content)
            if len(decoded_bytes) >= 4 and len(decoded_bytes) % 2 == 0:
                zero_count = sum(
                    1 for i in range(1, len(decoded_bytes), 2)
                    if decoded_bytes[i] == 0
                )
                if zero_count > len(decoded_bytes) // 4:
                    decoded = decoded_bytes.decode("utf-16-le", errors="replace")
                    printable = sum(
                        1 for c in decoded if c.isprintable() or c in "\n\r\t"
                    )
                    if printable > len(decoded) * 0.7 and len(decoded) >= 10:
                        print(f"[+] Decoded UTF-16LE base64 blob ({len(decoded)} chars)")
                        decoded_texts.append(decoded)
                        flags.extend(_search_for_flags(decoded, flag_format))
        except Exception:
            pass

    return flags, decoded_texts


# ---------------------------------------------------------------------------
# USB HID Keyboard Reconstruction
# ---------------------------------------------------------------------------

HID_KEYCODE_MAP = {
    0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e',
    0x09: 'f', 0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j',
    0x0e: 'k', 0x0f: 'l', 0x10: 'm', 0x11: 'n', 0x12: 'o',
    0x13: 'p', 0x14: 'q', 0x15: 'r', 0x16: 's', 0x17: 't',
    0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x', 0x1c: 'y',
    0x1d: 'z', 0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4',
    0x22: '5', 0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9',
    0x27: '0', 0x28: '\n', 0x29: '\x1b', 0x2a: '\b', 0x2b: '\t',
    0x2c: ' ', 0x2d: '-', 0x2e: '=', 0x2f: '[', 0x30: ']',
    0x31: '\\', 0x33: ';', 0x34: "'", 0x35: '`', 0x36: ',',
    0x37: '.', 0x38: '/',
}

HID_SHIFT_MAP = {
    '1': '!', '2': '@', '3': '#', '4': '$', '5': '%',
    '6': '^', '7': '&', '8': '*', '9': '(', '0': ')',
    '-': '_', '=': '+', '[': '{', ']': '}', '\\': '|',
    ';': ':', "'": '"', '`': '~', ',': '<', '.': '>', '/': '?',
}


def _extract_usb_keystrokes_tshark(pcap_path: str) -> str:
    """Extract keystrokes from USB HID keyboard capture using tshark."""
    typed_text = []

    # Try multiple tshark field names (varies by version)
    field_options = [
        ['-e', 'usb.capdata', '-Y', 'usb.capdata && usb.data_len == 8'],
        ['-e', 'usbhid.data', '-Y', 'usbhid.data'],
        ['-e', 'usb.capdata', '-Y', 'usb.transfer_type == 0x01'],
    ]

    raw_lines = []
    for fields in field_options:
        try:
            result = subprocess.run(
                ['tshark', '-r', pcap_path, '-T', 'fields'] + fields,
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0 and result.stdout.strip():
                raw_lines = [l for l in result.stdout.strip().split('\n') if l.strip()]
                if raw_lines:
                    break
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    if not raw_lines:
        return ""

    prev_keycode = 0
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        try:
            data = bytes.fromhex(line.replace(':', ''))
        except (ValueError, IndexError):
            continue

        if len(data) < 3:
            continue

        modifier = data[0]
        keycode = data[2]
        if keycode == 0:
            prev_keycode = 0
            continue

        # Handle backspace
        if keycode == 0x2a:
            if typed_text:
                typed_text.pop()
            continue

        shift = (modifier & 0x22) != 0  # left shift (bit 1) or right shift (bit 5)
        char = HID_KEYCODE_MAP.get(keycode, '')
        if not char:
            continue

        if shift and char.isalpha():
            char = char.upper()
        elif shift and char in HID_SHIFT_MAP:
            char = HID_SHIFT_MAP[char]

        typed_text.append(char)
        prev_keycode = keycode

    return ''.join(typed_text)


def _extract_usb_keystrokes_scapy(packets) -> str:
    """Extract USB HID keystrokes from raw packet data (scapy fallback)."""
    typed_text = []

    for pkt in packets:
        if not pkt.haslayer(Raw):
            continue
        raw_data = bytes(pkt[Raw].load)

        # USB HID keyboard reports are 8 bytes
        if len(raw_data) != 8:
            continue

        modifier = raw_data[0]
        keycode = raw_data[2]

        if keycode == 0:
            continue
        if keycode == 0x2a:  # backspace
            if typed_text:
                typed_text.pop()
            continue

        shift = (modifier & 0x22) != 0
        char = HID_KEYCODE_MAP.get(keycode, '')
        if not char:
            continue

        if shift and char.isalpha():
            char = char.upper()
        elif shift and char in HID_SHIFT_MAP:
            char = HID_SHIFT_MAP[char]

        typed_text.append(char)

    return ''.join(typed_text)


def extract_usb_keystrokes(pcap_path: str, packets=None) -> str:
    """Extract keystrokes from USB HID keyboard capture.

    Tries tshark first (better USB parsing), falls back to scapy raw data.
    """
    # Try tshark first
    result = _extract_usb_keystrokes_tshark(pcap_path)
    if result and len(result) >= 3:
        return result

    # Fallback: parse raw packet data with scapy
    if packets is not None:
        result = _extract_usb_keystrokes_scapy(packets)
        if result and len(result) >= 3:
            return result

    return ""


# ---------------------------------------------------------------------------
# DNS Tunneling Detection
# ---------------------------------------------------------------------------

def extract_dns_tunnel(pcap_path: str, packets=None) -> list[str]:
    """Detect and decode DNS tunneling (data exfiltrated in subdomain labels).

    Common DNS tunneling encodes data as hex or base64 in subdomain labels:
      e.g., 666c61677b.evil.com or ZmxhZ3t.evil.com
    """
    results = []

    # Collect DNS query names
    query_names = []

    # Try tshark first for better DNS parsing
    try:
        result = subprocess.run(
            ['tshark', '-r', pcap_path, '-T', 'fields', '-e', 'dns.qry.name',
             '-Y', 'dns.qry.type == 1 || dns.qry.type == 28 || dns.qry.type == 16'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            query_names = [l.strip() for l in result.stdout.strip().split('\n') if l.strip()]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Fallback to scapy
    if not query_names and packets is not None:
        for pkt in packets:
            if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                qname = pkt[DNS][DNSQR].qname
                if isinstance(qname, bytes):
                    qname = qname.decode('utf-8', errors='replace')
                qname = qname.rstrip('.')
                if qname:
                    query_names.append(qname)

    if not query_names:
        return results

    # Group by base domain (last 2 labels)
    from collections import Counter
    domain_groups = defaultdict(list)
    for qname in query_names:
        parts = qname.split('.')
        if len(parts) >= 3:
            base = '.'.join(parts[-2:])
            subdomain = '.'.join(parts[:-2])
            domain_groups[base].append(subdomain)

    # Identify tunneling: domains with many unique subdomains
    for base_domain, subdomains in domain_groups.items():
        unique_subs = list(dict.fromkeys(subdomains))  # preserve order, deduplicate
        if len(unique_subs) < 3:
            continue

        print(f"[*] DNS tunnel candidate: {base_domain} ({len(unique_subs)} unique subdomains)")

        # Concatenate all subdomain labels (remove dots within labels)
        concat_labels = ''.join(s.replace('.', '') for s in unique_subs)

        # Try hex decode
        try:
            hex_decoded = bytes.fromhex(concat_labels).decode('utf-8', errors='replace')
            printable = sum(1 for c in hex_decoded if c.isprintable() or c in '\n\r\t')
            if len(hex_decoded) >= 3 and printable > len(hex_decoded) * 0.6:
                print(f"[+] DNS tunnel hex decode: {hex_decoded[:100]}")
                results.append(hex_decoded)
        except (ValueError, UnicodeDecodeError):
            pass

        # Try base64 decode (with and without padding)
        for b64_input in [concat_labels, concat_labels + '=', concat_labels + '==']:
            try:
                b64_decoded = base64.b64decode(b64_input).decode('utf-8', errors='replace')
                printable = sum(1 for c in b64_decoded if c.isprintable() or c in '\n\r\t')
                if len(b64_decoded) >= 3 and printable > len(b64_decoded) * 0.6:
                    print(f"[+] DNS tunnel base64 decode: {b64_decoded[:100]}")
                    results.append(b64_decoded)
                    break
            except (ValueError, UnicodeDecodeError):
                pass

        # Try base32 decode
        for b32_input in [concat_labels.upper(), concat_labels.upper() + '='*((8 - len(concat_labels) % 8) % 8)]:
            try:
                b32_decoded = base64.b32decode(b32_input).decode('utf-8', errors='replace')
                printable = sum(1 for c in b32_decoded if c.isprintable() or c in '\n\r\t')
                if len(b32_decoded) >= 3 and printable > len(b32_decoded) * 0.6:
                    print(f"[+] DNS tunnel base32 decode: {b32_decoded[:100]}")
                    results.append(b32_decoded)
                    break
            except (ValueError, UnicodeDecodeError):
                pass

        # Also check individual subdomains for direct data
        for sub in unique_subs:
            label = sub.replace('.', '')
            # Try hex decode of individual label
            try:
                decoded = bytes.fromhex(label).decode('utf-8', errors='replace')
                if len(decoded) >= 3:
                    results.append(decoded)
            except (ValueError, UnicodeDecodeError):
                pass

    return results


# ---------------------------------------------------------------------------
# TLS Decryption with Keylog Files
# ---------------------------------------------------------------------------

def _find_keylog_files(challenge_dir: str) -> list[str]:
    """Scan challenge directory for TLS keylog files."""
    keylog_names = [
        'sslkeys.log', 'sslkeylog.log', 'premaster.txt', 'keylog.txt',
        'tls_keys.log', 'keys.log', 'master_secret.log', 'ssl.log',
        'sslkeys', 'keylog', 'premaster', 'tls.keys',
    ]

    found = []
    if not os.path.isdir(challenge_dir):
        return found

    for root, _dirs, files in os.walk(challenge_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            fname_lower = fname.lower()

            # Check known keylog names
            if fname_lower in keylog_names:
                found.append(fpath)
                continue

            # Check file content for keylog format markers
            if fname_lower.endswith(('.log', '.txt', '.keys')):
                try:
                    with open(fpath, 'r', errors='replace') as f:
                        header = f.read(512)
                    if any(marker in header for marker in [
                        'CLIENT_RANDOM', 'RSA ', 'CLIENT_HANDSHAKE_TRAFFIC_SECRET',
                        'SERVER_HANDSHAKE_TRAFFIC_SECRET', 'CLIENT_TRAFFIC_SECRET',
                    ]):
                        found.append(fpath)
                except (OSError, PermissionError):
                    pass

    return found


def extract_tls_decrypted(pcap_path: str, challenge_dir: str, flag_format: str = "") -> list[str]:
    """Decrypt TLS traffic using keylog files and extract flags."""
    results = []

    keylog_files = _find_keylog_files(challenge_dir)
    if not keylog_files:
        return results

    for keylog_path in keylog_files:
        print(f"[*] Trying TLS decryption with keylog: {os.path.basename(keylog_path)}")

        # Use tshark to decrypt and extract HTTP data
        tshark_attempts = [
            # Extract HTTP bodies from decrypted traffic
            ['tshark', '-r', pcap_path,
             '-o', f'tls.keylog_file:{keylog_path}',
             '-Y', 'http', '-T', 'fields',
             '-e', 'http.response.code', '-e', 'http.content_type',
             '-e', 'http.file_data', '-e', 'http.request.uri'],
            # Extract all decrypted data as text
            ['tshark', '-r', pcap_path,
             '-o', f'tls.keylog_file:{keylog_path}',
             '-Y', 'tls.app_data || http', '-T', 'fields',
             '-e', 'tcp.payload', '-e', 'http.file_data'],
            # Follow TLS stream
            ['tshark', '-r', pcap_path,
             '-o', f'tls.keylog_file:{keylog_path}',
             '-q', '-z', 'follow,tls,ascii,0'],
        ]

        for cmd in tshark_attempts:
            try:
                result = subprocess.run(
                    cmd, capture_output=True, text=True, timeout=30
                )
                if result.returncode == 0 and result.stdout.strip():
                    output = result.stdout
                    # Check for flags in the decrypted output
                    flags = _search_for_flags(output, flag_format)
                    if flags:
                        print(f"[+] Found flags in TLS-decrypted traffic!")
                        results.extend(flags)
                    # Also search for base64 in decrypted output
                    for decoded in _try_base64_decode(output):
                        results.extend(_search_for_flags(decoded, flag_format))

                    # Add raw output for further analysis
                    if len(output) >= 10:
                        results.append(output)
            except (FileNotFoundError, subprocess.TimeoutExpired):
                pass

        # Also try exporting decrypted objects
        tmpdir = tempfile.mkdtemp(prefix="kraken_tls_")
        try:
            for export_type in ['http', 'imf', 'smb', 'tftp']:
                subprocess.run(
                    ['tshark', '-r', pcap_path,
                     '-o', f'tls.keylog_file:{keylog_path}',
                     '--export-objects', f'{export_type},{tmpdir}'],
                    capture_output=True, text=True, timeout=30
                )
            # Scan exported objects
            for fname in os.listdir(tmpdir):
                fpath = os.path.join(tmpdir, fname)
                try:
                    with open(fpath, 'rb') as f:
                        data = f.read(1024 * 1024)
                    text = data.decode('utf-8', errors='replace')
                    flags = _search_for_flags(text, flag_format)
                    if flags:
                        print(f"[+] Flag found in TLS-exported file: {fname}")
                        results.extend(flags)
                except OSError:
                    pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    return results


# ---------------------------------------------------------------------------
# FTP File Transfer Extraction
# ---------------------------------------------------------------------------

def extract_ftp_transfers(pcap_path: str, packets=None, flag_format: str = "") -> list[str]:
    """Extract FTP commands, credentials, and transferred files from PCAP."""
    results = []

    # Try tshark first for FTP parsing
    try:
        # Extract FTP commands and responses
        result = subprocess.run(
            ['tshark', '-r', pcap_path, '-T', 'fields',
             '-e', 'ftp.request.command', '-e', 'ftp.request.arg',
             '-e', 'ftp.response.code', '-e', 'ftp.response.arg',
             '-Y', 'ftp'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"[*] FTP traffic detected")
            ftp_text = result.stdout
            flags = _search_for_flags(ftp_text, flag_format)
            if flags:
                results.extend(flags)

            # Look for credentials
            for line in ftp_text.split('\n'):
                if 'USER' in line or 'PASS' in line:
                    print(f"  [*] FTP credential: {line.strip()}")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Extract FTP data transfers
    try:
        result = subprocess.run(
            ['tshark', '-r', pcap_path, '-T', 'fields',
             '-e', 'ftp-data.command', '-e', 'tcp.payload',
             '-Y', 'ftp-data'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            flags = _search_for_flags(result.stdout, flag_format)
            if flags:
                print(f"[+] Flag found in FTP data transfer!")
                results.extend(flags)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Export FTP transferred objects using tshark
    tmpdir = tempfile.mkdtemp(prefix="kraken_ftp_")
    try:
        subprocess.run(
            ['tshark', '-r', pcap_path,
             '--export-objects', f'ftp-data,{tmpdir}'],
            capture_output=True, text=True, timeout=30
        )
        for fname in os.listdir(tmpdir):
            fpath = os.path.join(tmpdir, fname)
            try:
                with open(fpath, 'rb') as f:
                    data = f.read(1024 * 1024)
                text = data.decode('utf-8', errors='replace')
                flags = _search_for_flags(text, flag_format)
                if flags:
                    print(f"[+] Flag found in FTP file: {fname}")
                    results.extend(flags)
            except OSError:
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Scapy fallback: extract FTP data from port 21 TCP streams
    if not results and packets is not None:
        for pkt in packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
                continue
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if sport == 21 or dport == 21:
                try:
                    payload = bytes(pkt[Raw].load).decode('utf-8', errors='replace')
                    flags = _search_for_flags(payload, flag_format)
                    if flags:
                        results.extend(flags)
                    # Collect responses
                    if payload.strip():
                        results.append(payload.strip())
                except Exception:
                    pass

    return results


# ---------------------------------------------------------------------------
# SMTP/Email Extraction from PCAP
# ---------------------------------------------------------------------------

def extract_smtp_emails(pcap_path: str, packets=None, flag_format: str = "") -> list[str]:
    """Extract SMTP email content from PCAP traffic."""
    results = []

    # Try tshark for SMTP parsing
    try:
        result = subprocess.run(
            ['tshark', '-r', pcap_path, '-T', 'fields',
             '-e', 'smtp.req.parameter', '-e', 'smtp.rsp.parameter',
             '-e', 'imf.subject', '-e', 'imf.from', '-e', 'imf.to',
             '-e', 'mime.content_type',
             '-Y', 'smtp || imf'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"[*] SMTP/email traffic detected")
            flags = _search_for_flags(result.stdout, flag_format)
            if flags:
                results.extend(flags)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Follow SMTP TCP streams for full email bodies
    try:
        # Get SMTP stream indices
        result = subprocess.run(
            ['tshark', '-r', pcap_path, '-T', 'fields',
             '-e', 'tcp.stream', '-Y', 'smtp',
             '-2', '-R', 'smtp'],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            stream_ids = set()
            for line in result.stdout.strip().split('\n'):
                sid = line.strip()
                if sid.isdigit():
                    stream_ids.add(int(sid))

            for sid in list(stream_ids)[:10]:  # Limit to 10 streams
                try:
                    follow_result = subprocess.run(
                        ['tshark', '-r', pcap_path, '-q',
                         '-z', f'follow,tcp,ascii,{sid}'],
                        capture_output=True, text=True, timeout=30
                    )
                    if follow_result.returncode == 0 and follow_result.stdout.strip():
                        email_text = follow_result.stdout
                        flags = _search_for_flags(email_text, flag_format)
                        if flags:
                            print(f"[+] Flag found in SMTP stream {sid}!")
                            results.extend(flags)

                        # Decode base64 MIME parts
                        for decoded in _try_base64_decode(email_text):
                            flags = _search_for_flags(decoded, flag_format)
                            if flags:
                                results.extend(flags)

                        # Look for MIME-encoded attachments
                        if 'Content-Transfer-Encoding: base64' in email_text:
                            # Extract base64 blocks between MIME boundaries
                            mime_parts = re.split(r'--[A-Za-z0-9_\-]+', email_text)
                            for part in mime_parts:
                                if 'base64' in part:
                                    # Get the base64 content after the headers
                                    b64_match = re.search(r'\r?\n\r?\n([A-Za-z0-9+/\s=]+)', part)
                                    if b64_match:
                                        b64_data = b64_match.group(1).replace('\n', '').replace('\r', '').strip()
                                        try:
                                            decoded_bytes = base64.b64decode(b64_data)
                                            decoded_text = decoded_bytes.decode('utf-8', errors='replace')
                                            flags = _search_for_flags(decoded_text, flag_format)
                                            if flags:
                                                print(f"[+] Flag in MIME attachment!")
                                                results.extend(flags)
                                        except Exception:
                                            pass
                except subprocess.TimeoutExpired:
                    pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Export IMF (email) objects
    tmpdir = tempfile.mkdtemp(prefix="kraken_smtp_")
    try:
        subprocess.run(
            ['tshark', '-r', pcap_path,
             '--export-objects', f'imf,{tmpdir}'],
            capture_output=True, text=True, timeout=30
        )
        for fname in os.listdir(tmpdir):
            fpath = os.path.join(tmpdir, fname)
            try:
                with open(fpath, 'rb') as f:
                    data = f.read(1024 * 1024)
                text = data.decode('utf-8', errors='replace')
                flags = _search_for_flags(text, flag_format)
                if flags:
                    print(f"[+] Flag in exported email: {fname}")
                    results.extend(flags)
                # Also try base64
                for decoded in _try_base64_decode(text):
                    results.extend(_search_for_flags(decoded, flag_format))
            except OSError:
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    # Scapy fallback: extract from port 25/587 TCP streams
    if not results and packets is not None:
        smtp_data = defaultdict(bytes)
        for pkt in packets:
            if not (pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP)):
                continue
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
            if sport in (25, 587, 465) or dport in (25, 587, 465):
                key = (pkt[IP].src, pkt[IP].dst, sport, dport)
                smtp_data[key] += bytes(pkt[Raw].load)

        for _key, data in smtp_data.items():
            try:
                text = data.decode('utf-8', errors='replace')
                flags = _search_for_flags(text, flag_format)
                if flags:
                    results.extend(flags)
                for decoded in _try_base64_decode(text):
                    results.extend(_search_for_flags(decoded, flag_format))
            except Exception:
                pass

    return results


# ---------------------------------------------------------------------------
# HTTP Object Export (tshark)
# ---------------------------------------------------------------------------

def _export_http_objects(pcap_path: str, flag_format: str = "") -> list[str]:
    """Use tshark --export-objects to extract HTTP transferred files."""
    results = []
    tmpdir = tempfile.mkdtemp(prefix="kraken_http_")
    try:
        subprocess.run(
            ['tshark', '-r', pcap_path,
             '--export-objects', f'http,{tmpdir}'],
            capture_output=True, text=True, timeout=30
        )
        exported = os.listdir(tmpdir)
        if exported:
            print(f"[*] Exported {len(exported)} HTTP object(s)")
        for fname in exported:
            fpath = os.path.join(tmpdir, fname)
            try:
                with open(fpath, 'rb') as f:
                    data = f.read(1024 * 1024)
                text = data.decode('utf-8', errors='replace')
                flags = _search_for_flags(text, flag_format)
                if flags:
                    print(f"[+] Flag in HTTP object: {fname}")
                    results.extend(flags)
            except OSError:
                pass
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    finally:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)
    return results


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def main():
    if len(sys.argv) < 2:
        print(
            "Usage: auto_pcap_extract.py <challenge_dir> [--flag-format FORMAT] [--dir DIR]",
            file=sys.stderr,
        )
        sys.exit(1)

    target = sys.argv[1]
    flag_format = ""
    challenge_dir = ""

    # Parse arguments
    if "--flag-format" in sys.argv:
        idx = sys.argv.index("--flag-format")
        if idx + 1 < len(sys.argv):
            flag_format = sys.argv[idx + 1]

    if "--dir" in sys.argv:
        idx = sys.argv.index("--dir")
        if idx + 1 < len(sys.argv):
            target = sys.argv[idx + 1]
            challenge_dir = target

    if not challenge_dir:
        challenge_dir = target if os.path.isdir(target) else os.path.dirname(target)

    # Scan for pcap files (walk subdirectories too)
    pcap_files = []
    if os.path.isdir(target):
        for root, _dirs, files in os.walk(target):
            for name in files:
                if name.lower().endswith((".pcap", ".pcapng")):
                    pcap_files.append(os.path.join(root, name))
    elif os.path.isfile(target) and target.lower().endswith((".pcap", ".pcapng")):
        pcap_files.append(target)

    if not pcap_files:
        print("[-] No .pcap/.pcapng files found", file=sys.stderr)
        sys.exit(1)

    all_flags = []
    all_decoded_texts = []  # Accumulate all decoded/decrypted text for cross-phase assembly
    for pcap_path in pcap_files:
        print(f"[*] Processing: {pcap_path}")
        try:
            packets = rdpcap(pcap_path)
        except Exception as e:
            print(f"[-] Failed to read {pcap_path}: {e}", file=sys.stderr)
            continue

        print(f"[*] Loaded {len(packets)} packets")

        streams = _reassemble_tcp_streams(packets)
        http_payloads = _extract_http_payloads(packets)
        dns_queries = _extract_dns_queries(packets)
        print(
            f"[*] TCP streams: {len(streams)}, "
            f"HTTP payloads: {len(http_payloads)}, "
            f"DNS queries: {len(dns_queries)}"
        )

        # Collect all searchable text
        searchable = []
        for data in streams.values():
            try:
                searchable.append(data.decode("utf-8", errors="replace"))
            except Exception:
                pass
        searchable.extend(http_payloads)
        searchable.extend(dns_queries)

        # Phase 1: Direct flag search in cleartext
        for text in searchable:
            all_flags.extend(_search_for_flags(text, flag_format))
            for decoded in _try_base64_decode(text):
                all_flags.extend(_search_for_flags(decoded, flag_format))

        # Phase 2: Decode PowerShell encoded commands
        for text in searchable:
            ps_flags, ps_texts = _decode_powershell_commands(text, flag_format)
            all_flags.extend(ps_flags)
            all_decoded_texts.extend(ps_texts)

        # Phase 3: Extract binaries and search for crypto keys
        binaries = _extract_binaries_from_streams(streams)
        key_candidates = []
        for binary in binaries:
            key_candidates.extend(_extract_keys_from_binary(binary))

        # Phase 4: Also scan challenge source files for keys
        if challenge_dir:
            key_candidates.extend(_scan_source_files_for_keys(challenge_dir))

        # Phase 5: Extract encrypted blobs and try decryption
        if key_candidates:
            encrypted_blobs = _extract_encrypted_blobs(streams)
            if encrypted_blobs:
                print(
                    f"[*] Found {len(encrypted_blobs)} encrypted base64 blobs, "
                    f"trying {len(key_candidates)} key candidates..."
                )
                decrypted_flags, decrypted_texts = _try_decrypt_with_candidates(
                    encrypted_blobs, key_candidates, flag_format,
                )
                all_flags.extend(decrypted_flags)
                all_decoded_texts.extend(decrypted_texts)

        # Phase 5b: USB HID keyboard extraction
        print("[*] Checking for USB HID keyboard data...")
        usb_text = extract_usb_keystrokes(pcap_path, packets)
        if usb_text:
            print(f"[+] USB keyboard reconstruction: {usb_text[:200]}")
            all_flags.extend(_search_for_flags(usb_text, flag_format))
            all_decoded_texts.append(usb_text)

        # Phase 5c: DNS tunneling detection
        print("[*] Checking for DNS tunneling...")
        tunnel_results = extract_dns_tunnel(pcap_path, packets)
        for tunnel_text in tunnel_results:
            all_flags.extend(_search_for_flags(tunnel_text, flag_format))
            all_decoded_texts.append(tunnel_text)

        # Phase 5d: TLS decryption with keylog files
        if challenge_dir:
            tls_results = extract_tls_decrypted(pcap_path, challenge_dir, flag_format)
            for tls_text in tls_results:
                all_flags.extend(_search_for_flags(tls_text, flag_format))

        # Phase 5e: FTP file transfer extraction
        ftp_results = extract_ftp_transfers(pcap_path, packets, flag_format)
        for ftp_text in ftp_results:
            all_flags.extend(_search_for_flags(ftp_text, flag_format))

        # Phase 5f: SMTP/email extraction
        smtp_results = extract_smtp_emails(pcap_path, packets, flag_format)
        for smtp_text in smtp_results:
            all_flags.extend(_search_for_flags(smtp_text, flag_format))

        # Phase 5g: HTTP object export via tshark
        http_obj_flags = _export_http_objects(pcap_path, flag_format)
        all_flags.extend(http_obj_flags)

    # Phase 6: Cross-phase flag assembly
    # Combine ALL decoded/decrypted text and try to assemble multi-part flags
    if all_decoded_texts:
        combined_text = "\n".join(all_decoded_texts)
        assembled = _assemble_flag_parts(combined_text, flag_format)
        all_flags.extend(assembled)

    # Deduplicate preserving order
    seen, unique = set(), []
    for f in all_flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)

    if unique:
        # Score candidates: prefer clean ASCII flags with proper format
        def _flag_score(f: str) -> tuple:
            """Score flag quality: (is_clean, has_prefix_format, length)."""
            # Check if all chars are clean ASCII
            is_clean = all(32 <= ord(c) <= 126 for c in f)
            # Check if it matches PREFIX{content} format
            has_format = bool(re.match(r"^[A-Za-z]+\{[A-Za-z0-9_\-.]+\}$", f))
            # Check if it matches the specified flag_format
            matches_format = False
            if flag_format:
                try:
                    if re.search(flag_format, f):
                        matches_format = True
                except re.error:
                    pass
            return (is_clean, has_format, matches_format, len(f))

        best = max(unique, key=_flag_score)

        if len(unique) > 1:
            print(f"[*] Found {len(unique)} flag candidates:")
            for f in unique:
                score = _flag_score(f)
                label = " [BEST]" if f == best else ""
                # Truncate display for non-clean flags
                display = f if all(32 <= ord(c) <= 126 for c in f) else f[:60] + "..."
                print(f"    {display}{label}")
        print(f"\nEXTRACTED FLAG: {best}")
    else:
        print("[-] No flags found in packet data", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
