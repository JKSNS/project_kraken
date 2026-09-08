#!/usr/bin/env python3
"""Substitution / classical cipher solver for CTF challenges.

Attacks (in order):
  1. Caesar / ROT-N (all 26 shifts)
  2. ROT13 (special case, redundant but explicit)
  3. Trithemius cipher (positional shift: c[i] = (p[i] + i) mod 26)
  4. Atbash (A<->Z, B<->Y, ...)
  5. Vigenere (IC + Kasiski + frequency analysis)
  6. Simple substitution (frequency analysis for long ciphertexts)
  7. Affine cipher (all valid (a, b) pairs where gcd(a, 26) == 1)

Usage:
  python3 auto_substitution_cipher.py --dir /path/to/challenge --flag-format "HTB{"
"""
import argparse
import math
import os
import re
import string
import sys
from collections import Counter


# ── English frequency data ──────────────────────────────────────────────

ENGLISH_FREQ = {
    'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97,
    'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25,
    'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36,
    'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29,
    'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10,
    'Z': 0.07,
}

# Common English words for scoring plaintext quality
COMMON_WORDS = {
    'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can',
    'her', 'was', 'one', 'our', 'out', 'has', 'had', 'hot', 'how',
    'its', 'let', 'may', 'new', 'now', 'old', 'see', 'way', 'who',
    'did', 'get', 'has', 'him', 'his', 'she', 'too', 'use', 'man',
    'day', 'any', 'say', 'each', 'make', 'like', 'long', 'look',
    'many', 'some', 'them', 'then', 'than', 'been', 'have', 'from',
    'word', 'what', 'were', 'when', 'your', 'said', 'that', 'this',
    'with', 'will', 'they', 'been', 'call', 'come', 'could', 'first',
    'into', 'just', 'know', 'take', 'people', 'flag', 'crypto',
    'cipher', 'key', 'text', 'message', 'secret', 'encode', 'decode',
}

ENGLISH_IC = 0.0667  # Index of Coincidence for English


# ── Utility helpers ─────────────────────────────────────────────────────

def _alpha_only(text: str) -> str:
    """Return only alphabetic characters from text."""
    return ''.join(c for c in text if c.isalpha())


def _is_printable_meaningful(text: str) -> bool:
    """Check if text is mostly printable ASCII with some letter content."""
    if not text:
        return False
    printable = sum(1 for c in text if c.isprintable())
    alpha = sum(1 for c in text if c.isalpha())
    return printable > len(text) * 0.85 and alpha > len(text) * 0.3


def _score_english(text: str) -> float:
    """Score how English-like a piece of text is (higher = better)."""
    score = 0.0
    lower = text.lower()

    # Word matching bonus
    words = re.findall(r'[a-z]+', lower)
    if words:
        matched = sum(1 for w in words if w in COMMON_WORDS)
        score += matched * 10.0

    # Frequency correlation for letters
    alpha = _alpha_only(lower)
    if len(alpha) >= 10:
        freq = Counter(alpha)
        total = len(alpha)
        chi2 = 0.0
        for letter in string.ascii_lowercase:
            observed = freq.get(letter, 0) / total * 100
            expected = ENGLISH_FREQ.get(letter.upper(), 0)
            if expected > 0:
                chi2 += (observed - expected) ** 2 / expected
        # Lower chi2 = closer to English; invert for scoring
        score += max(0, 100 - chi2)

    # Penalize non-printable characters
    non_print = sum(1 for c in text if not c.isprintable() and c not in '\n\r\t')
    score -= non_print * 20

    return score


_COMMON_BIGRAMS = {
    'th', 'he', 'in', 'er', 'an', 'on', 'en', 'at', 'es', 'ed',
    'te', 'ti', 'or', 'st', 'ar', 'nd', 'to', 'nt', 'is', 'of',
    'it', 'al', 'as', 'ha', 'ng', 'co', 're', 'se', 'de', 'ou',
    'le', 'ro', 'sa', 'ea', 'ra', 'ri', 'ne', 'li', 'la', 'el',
    'ma', 'di', 'ic', 'ei', 'si', 'lo', 'om', 'ur', 'ec', 'no',
    'ca', 'un', 'na', 'io', 'us', 'ta', 'ch', 'ge', 'me', 'pe',
    'dy', 'da', 'ty', 'cr', 'ry', 'pt', 'ke', 'ag', 'bi', 'ci',
}


def _score_flag_body(text: str) -> float:
    """Score text for how flag-body-like it is (for wrap candidate ranking).

    CTF flag bodies typically contain: lowercase letters, digits, underscores.
    Higher score = more likely to be the correct decryption.
    Uses bigram frequency to distinguish real words from random letters.
    """
    score = 0.0
    if not text:
        return score

    # Reward lowercase letters and underscores (common in flag bodies)
    for c in text:
        if c.islower():
            score += 1.0
        elif c.isdigit():
            score += 1.0
        elif c == '_':
            score += 1.0
        elif c.isupper():
            score += 0.5
        elif c.isprintable():
            score += 0.2
        else:
            score -= 5.0

    # Bigram analysis -- strong signal for real words vs random letters
    lower = text.lower()
    alpha_segments = re.findall(r'[a-z]{2,}', lower)
    bigram_hits = 0
    bigram_total = 0
    for seg in alpha_segments:
        for i in range(len(seg) - 1):
            bigram_total += 1
            if seg[i:i + 2] in _COMMON_BIGRAMS:
                bigram_hits += 1
    if bigram_total > 0:
        bigram_ratio = bigram_hits / bigram_total
        score += bigram_ratio * 50.0  # Strong weight for bigram quality

    # Bonus for common English words/substrings in the body
    for word in COMMON_WORDS:
        if word in lower and len(word) >= 3:
            score += 15.0

    return score


def _check_flag(text: str, flag_format: str) -> str | None:
    """Check if text contains the flag format. Return the flag or None."""
    if not flag_format:
        # Generic flag pattern
        m = re.search(r'[A-Za-z_]{2,}\{[^}]{3,}\}', text)
        if m:
            return m.group(0)
        return None

    # Build a regex from the flag format prefix
    # flag_format is like "HTB{" or "flag{"
    prefix = flag_format.rstrip('{')
    # Search for prefix{...}
    pattern = re.escape(prefix) + r'\{[^}]{1,}\}'
    m = re.search(pattern, text, re.IGNORECASE)
    if m:
        return m.group(0)
    return None


# ── Cipher implementations ─────────────────────────────────────────────

def caesar_shift(text: str, shift: int) -> str:
    """Apply a Caesar shift to text, preserving case and non-alpha chars."""
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base + shift) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)


def trithemius_decrypt(text: str) -> str:
    """Reverse Trithemius cipher: p[i] = (c[i] - i) mod 26.

    Only alpha characters count for the positional index; non-alpha
    chars are preserved in place but do NOT increment the position counter.
    """
    result = []
    pos = 0
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shifted = (ord(c) - base - pos) % 26
            result.append(chr(shifted + base))
            pos += 1
        else:
            result.append(c)
    return ''.join(result)


def trithemius_decrypt_all_positions(text: str) -> str:
    """Reverse Trithemius cipher treating ALL characters (including non-alpha)
    as incrementing the position index, but only shifting alpha characters.

    This variant is used by some challenge implementations where the
    encryption loop increments i for every character, not just letters.
    """
    result = []
    for i, c in enumerate(text):
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            shifted = (ord(c) - base - i) % 26
            result.append(chr(shifted + base))
        else:
            result.append(c)
    return ''.join(result)


def atbash(text: str) -> str:
    """Apply Atbash cipher: A<->Z, B<->Y, etc."""
    result = []
    for c in text:
        if c.isalpha():
            if c.isupper():
                result.append(chr(ord('Z') - (ord(c) - ord('A'))))
            else:
                result.append(chr(ord('z') - (ord(c) - ord('a'))))
        else:
            result.append(c)
    return ''.join(result)


def affine_decrypt(text: str, a: int, b: int) -> str:
    """Decrypt affine cipher: p = a_inv * (c - b) mod 26."""
    a_inv = pow(a, -1, 26)
    result = []
    for c in text:
        if c.isalpha():
            base = ord('A') if c.isupper() else ord('a')
            y = ord(c) - base
            result.append(chr((a_inv * (y - b)) % 26 + base))
        else:
            result.append(c)
    return ''.join(result)


def _compute_ic(text: str) -> float:
    """Compute Index of Coincidence for a string of letters."""
    n = len(text)
    if n <= 1:
        return 0.0
    freq = Counter(text.upper())
    total = sum(f * (f - 1) for f in freq.values())
    return total / (n * (n - 1))


def _kasiski_key_lengths(text: str) -> list[int]:
    """Use Kasiski examination to find likely key lengths."""
    alpha = _alpha_only(text).upper()
    if len(alpha) < 20:
        return list(range(1, 21))

    # Find repeated trigrams and compute distances between them
    distances: list[int] = []
    trigrams: dict[str, list[int]] = {}
    for i in range(len(alpha) - 2):
        tri = alpha[i:i + 3]
        if tri in trigrams:
            for prev_pos in trigrams[tri]:
                distances.append(i - prev_pos)
            trigrams[tri].append(i)
        else:
            trigrams[tri] = [i]

    if not distances:
        return list(range(1, 21))

    # Find GCD-based key length candidates
    factor_counts: Counter = Counter()
    for d in distances:
        for f in range(2, min(d + 1, 21)):
            if d % f == 0:
                factor_counts[f] += 1

    # Sort by frequency, return top candidates
    candidates = [f for f, _ in factor_counts.most_common(10)]
    # Always include 1-20 as fallback
    for i in range(1, 21):
        if i not in candidates:
            candidates.append(i)
    return candidates


def _ic_key_length(text: str, max_len: int = 20) -> list[int]:
    """Use Index of Coincidence to rank key length candidates."""
    alpha = _alpha_only(text).upper()
    if len(alpha) < 20:
        return list(range(1, max_len + 1))

    scores: list[tuple[float, int]] = []
    for kl in range(1, max_len + 1):
        # Split into columns
        columns = ['' for _ in range(kl)]
        for i, c in enumerate(alpha):
            columns[i % kl] += c
        # Average IC across columns
        avg_ic = sum(_compute_ic(col) for col in columns) / kl
        scores.append((abs(avg_ic - ENGLISH_IC), kl))

    scores.sort()
    return [kl for _, kl in scores]


def vigenere_decrypt(text: str, key: str) -> str:
    """Decrypt Vigenere cipher with a known key."""
    result = []
    ki = 0
    key_upper = key.upper()
    for c in text:
        if c.isalpha():
            shift = ord(key_upper[ki % len(key_upper)]) - ord('A')
            base = ord('A') if c.isupper() else ord('a')
            result.append(chr((ord(c) - base - shift) % 26 + base))
            ki += 1
        else:
            result.append(c)
    return ''.join(result)


def _recover_vigenere_key(text: str, key_len: int) -> str:
    """Recover Vigenere key of given length using frequency analysis."""
    alpha = _alpha_only(text).upper()
    key = []

    for col_idx in range(key_len):
        column = alpha[col_idx::key_len]
        if not column:
            key.append('A')
            continue

        # Try all 26 shifts and pick the one that best matches English frequencies
        best_shift = 0
        best_score = float('inf')
        col_len = len(column)

        for shift in range(26):
            chi2 = 0.0
            freq = Counter()
            for c in column:
                decrypted = chr((ord(c) - ord('A') - shift) % 26 + ord('A'))
                freq[decrypted] += 1

            for letter in string.ascii_uppercase:
                observed = freq.get(letter, 0) / col_len * 100
                expected = ENGLISH_FREQ.get(letter, 0)
                if expected > 0:
                    chi2 += (observed - expected) ** 2 / expected

            if chi2 < best_score:
                best_score = chi2
                best_shift = shift

        key.append(chr(best_shift + ord('A')))

    return ''.join(key)


def _frequency_substitution(text: str) -> str:
    """Attempt simple mono-alphabetic substitution via frequency analysis.

    Maps ciphertext letters to English letters by frequency rank.
    This is a rough heuristic -- works best on long ciphertexts.
    """
    alpha = _alpha_only(text).upper()
    if len(alpha) < 50:
        return ''

    freq = Counter(alpha)
    # Sort ciphertext letters by frequency (most common first)
    ct_order = [letter for letter, _ in freq.most_common()]
    # English letters by frequency
    en_order = sorted(ENGLISH_FREQ.keys(), key=lambda k: ENGLISH_FREQ[k], reverse=True)

    mapping: dict[str, str] = {}
    for i, ct_letter in enumerate(ct_order):
        if i < len(en_order):
            mapping[ct_letter] = en_order[i]

    result = []
    for c in text:
        if c.isalpha():
            mapped = mapping.get(c.upper(), '?')
            result.append(mapped.lower() if c.islower() else mapped)
        else:
            result.append(c)
    return ''.join(result)


# ── Cipher detection from source code ──────────────────────────────────

def _detect_cipher_from_source(challenge_dir: str) -> str | None:
    """Scan Python/source files for encryption patterns to identify the cipher.

    Returns one of: 'trithemius', 'caesar', 'vigenere', 'atbash', 'affine', or None.
    """
    for root, _dirs, files in os.walk(challenge_dir):
        for fname in files:
            if not fname.endswith(('.py', '.sage', '.rb', '.c', '.cpp')):
                continue
            fpath = os.path.join(root, fname)
            try:
                src = open(fpath, encoding='utf-8', errors='replace').read()
            except OSError:
                continue

            # Trithemius: positional shift -- look for (ord(c) + i) or enumerate usage with shift
            if re.search(r'(?:ord\s*\(\s*\w+\s*\)\s*[-+]\s*\w*i\b|'
                         r'chr\s*\(\s*\(\s*ord.*?[+]\s*(?:i|index|pos|idx|count))',
                         src, re.IGNORECASE):
                print(f"[*] Detected Trithemius-like cipher in {fname}")
                return 'trithemius'
            if re.search(r'enumerate', src) and re.search(r'ord.*?[+].*?%\s*26', src):
                print(f"[*] Detected Trithemius-like cipher (enumerate+shift) in {fname}")
                return 'trithemius'

            # Caesar: fixed shift
            if re.search(r'(?:shift|key|rot|caesar)', src, re.IGNORECASE) and \
               re.search(r'%\s*26', src):
                # But NOT if it also uses a key array or position -- that's Vigenere/Trithemius
                if not re.search(r'enumerate|key\[|key_len', src, re.IGNORECASE):
                    print(f"[*] Detected Caesar-like cipher in {fname}")
                    return 'caesar'

            # Vigenere: key cycling
            if re.search(r'key\s*\[.*?%.*?len\s*\(\s*key', src, re.IGNORECASE):
                print(f"[*] Detected Vigenere-like cipher in {fname}")
                return 'vigenere'

            # Atbash: reverse alphabet mapping
            if re.search(r'(?:25\s*-|ord.*?[Zz].*?-|reverse|atbash)', src, re.IGNORECASE):
                if re.search(r'%\s*26', src):
                    print(f"[*] Detected Atbash-like cipher in {fname}")
                    return 'atbash'

            # Affine: a*x + b mod 26
            if re.search(r'\*.*?%\s*26', src) and re.search(r'[+].*?%\s*26', src):
                if not re.search(r'enumerate|key\[', src, re.IGNORECASE):
                    print(f"[*] Detected Affine-like cipher in {fname}")
                    return 'affine'

    return None


# ── File scanning ───────────────────────────────────────────────────────

def _scan_for_ciphertext(challenge_dir: str) -> list[tuple[str, str]]:
    """Scan the challenge directory for files containing ciphertext.

    Returns a list of (filepath, content) tuples for candidate files.
    Also extracts ciphertext from Python source variables.
    """
    candidates: list[tuple[str, str]] = []

    # Priority filenames for ciphertext
    priority_names = {
        'output.txt', 'ciphertext.txt', 'ct.txt', 'encrypted.txt',
        'cipher.txt', 'flag.txt', 'message.txt', 'encoded.txt',
        'out.txt', 'output', 'ciphertext', 'data.txt',
    }

    for root, _dirs, files in os.walk(challenge_dir):
        for fname in files:
            fpath = os.path.join(root, fname)
            name_lower = fname.lower()

            # Skip very large files and non-text files
            try:
                size = os.path.getsize(fpath)
                if size > 500_000 or size == 0:
                    continue
            except OSError:
                continue

            # Priority files: read directly as ciphertext
            if name_lower in priority_names:
                try:
                    content = open(fpath, encoding='utf-8', errors='replace').read()
                    if content.strip():
                        candidates.append((fpath, content.strip()))
                except OSError:
                    pass
                continue

            # .txt and .enc files
            if name_lower.endswith(('.txt', '.enc', '.ct')):
                try:
                    content = open(fpath, encoding='utf-8', errors='replace').read()
                    if content.strip():
                        candidates.append((fpath, content.strip()))
                except OSError:
                    pass
                continue

            # Python source files -- look for ciphertext variables
            if name_lower.endswith('.py'):
                try:
                    src = open(fpath, encoding='utf-8', errors='replace').read()
                except OSError:
                    continue

                # Match variable assignments containing quoted strings
                # e.g., ct = "DJF{...}", encrypted = '...'
                for m in re.finditer(
                    r'''(?:ct|ciphertext|encrypted|cipher|enc|output|flag_enc|c)\s*=\s*['"](.*?)['"]''',
                    src, re.IGNORECASE,
                ):
                    val = m.group(1)
                    if len(val) >= 4:
                        candidates.append((fpath, val))

                # Also match print("...") calls containing ciphertext
                for m in re.finditer(r'''print\s*\(\s*f?['"]([^'"]{10,})['"]''', src):
                    val = m.group(1)
                    if len(val) >= 10 and sum(1 for c in val if c.isalpha()) > len(val) * 0.5:
                        candidates.append((fpath, val))

    return candidates


def _extract_wrapping_hint(text: str) -> str | None:
    """Look for instructions like 'wrap with HTB{}' or 'flag format: HTB{}'.

    Returns the flag prefix if found (e.g., 'HTB').
    """
    patterns = [
        r'wrap.*?(?:with|in)\s+(\w+)\{',
        r'flag\s*(?:format|is)\s*[:=]?\s*(\w+)\{',
        r'(\w+)\{.*?\}.*?format',
        r'Make sure.*?wrap.*?(\w+)\{',
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return None


def _separate_ciphertext_and_hints(content: str) -> tuple[str, str | None]:
    """Separate ciphertext from wrapping hints / instructions.

    Returns (ciphertext, wrap_prefix_or_none).
    """
    lines = content.strip().split('\n')

    # Look for wrapping hints in any line
    wrap_prefix = None
    ct_lines = []
    for line in lines:
        hint = _extract_wrapping_hint(line)
        if hint:
            wrap_prefix = hint
            # This line is an instruction, not ciphertext
            # But only skip it if there are other lines with actual ciphertext
            if len(lines) > 1:
                continue
        ct_lines.append(line)

    ciphertext = '\n'.join(ct_lines).strip()
    return ciphertext, wrap_prefix


# ── Main solver ─────────────────────────────────────────────────────────

def solve(challenge_dir: str, flag_format: str) -> str | None:
    """Try all classical cipher attacks against ciphertext found in the challenge dir."""
    print(f"[*] Scanning for ciphertext in {challenge_dir}")

    ct_candidates = _scan_for_ciphertext(challenge_dir)
    if not ct_candidates:
        print("[-] No ciphertext files found")
        return None

    print(f"[*] Found {len(ct_candidates)} candidate text(s)")

    # Try to detect cipher type from source code
    detected_cipher = _detect_cipher_from_source(challenge_dir)
    if detected_cipher:
        print(f"[*] Source code analysis suggests: {detected_cipher}")

    # Derive the flag prefix from --flag-format (e.g., "HTB{" -> "HTB")
    flag_prefix = flag_format.rstrip('{') if flag_format else ''

    for fpath, raw_content in ct_candidates:
        print(f"\n[*] Trying: {fpath}")

        ciphertext, wrap_prefix = _separate_ciphertext_and_hints(raw_content)
        if not ciphertext:
            continue

        # If wrapping hint found, use it as the flag prefix for this ciphertext
        effective_prefix = flag_format
        if wrap_prefix and not flag_format:
            effective_prefix = wrap_prefix + '{'
            print(f"[*] Detected wrapping hint: wrap with {wrap_prefix}{{...}}")

        # Track the best non-flag result for reporting
        best_score = -1.0
        best_result = ''
        best_method = ''

        # For wrapping mode: collect (score, flag, method) candidates and pick the best
        wrap_candidates: list[tuple[float, str, str]] = []
        raw_ct_score = _score_english(ciphertext)

        def _try_wrap(decrypted: str, method: str) -> None:
            """If a wrapping hint exists, record a wrapping candidate.

            Does not return immediately -- candidates are ranked at the end.
            """
            if not wrap_prefix:
                return
            body = decrypted.strip()
            if not body or not all(c.isprintable() for c in body):
                return
            wrapped = f"{wrap_prefix}{{{body}}}"
            found = _check_flag(wrapped, effective_prefix)
            if found:
                score = _score_flag_body(decrypted)
                wrap_candidates.append((score, found, method))

        # ── Attack 1: Caesar / ROT-N ────────────────────────────────
        print("[*] Trying Caesar/ROT-N (26 shifts)...")
        for shift in range(26):
            decrypted = caesar_shift(ciphertext, shift)
            flag = _check_flag(decrypted, effective_prefix)
            if flag:
                print(f"[+] Caesar shift={shift} found flag!")
                print(f"[+] FLAG: {flag}")
                return flag
            if shift != 0:
                _try_wrap(decrypted, f"Caesar shift={shift}")

            s = _score_english(decrypted)
            if s > best_score:
                best_score = s
                best_result = decrypted
                best_method = f"Caesar shift={shift}"

        # ── Attack 2: ROT13 (explicit, already covered above) ──────
        # shift=13 already tried in the Caesar loop above

        # ── Attack 3: Trithemius cipher ─────────────────────────────
        print("[*] Trying Trithemius cipher (positional shift)...")
        for decrypt_fn, variant in [
            (trithemius_decrypt, "alpha-only positions"),
            (trithemius_decrypt_all_positions, "all positions"),
        ]:
            decrypted = decrypt_fn(ciphertext)
            flag = _check_flag(decrypted, effective_prefix)
            if flag:
                print(f"[+] Trithemius ({variant}) found flag!")
                print(f"[+] FLAG: {flag}")
                return flag
            _try_wrap(decrypted, f"Trithemius ({variant})")
            s = _score_english(decrypted)
            if s > best_score:
                best_score = s
                best_result = decrypted
                best_method = f"Trithemius ({variant})"

        # ── Attack 4: Atbash ────────────────────────────────────────
        print("[*] Trying Atbash cipher...")
        decrypted = atbash(ciphertext)
        flag = _check_flag(decrypted, effective_prefix)
        if flag:
            print(f"[+] Atbash found flag!")
            print(f"[+] FLAG: {flag}")
            return flag
        _try_wrap(decrypted, "Atbash")
        s = _score_english(decrypted)
        if s > best_score:
            best_score = s
            best_result = decrypted
            best_method = "Atbash"

        # ── Attack 5: Vigenere ──────────────────────────────────────
        alpha_len = len(_alpha_only(ciphertext))
        if alpha_len >= 20:
            print("[*] Trying Vigenere cipher (IC + frequency analysis)...")
            # Merge IC and Kasiski candidates
            ic_candidates = _ic_key_length(ciphertext)
            kasiski_candidates = _kasiski_key_lengths(ciphertext)
            # Prioritize IC-ranked, then Kasiski
            seen_kl: set[int] = set()
            key_lengths: list[int] = []
            for kl in ic_candidates + kasiski_candidates:
                if kl not in seen_kl and 1 <= kl <= 20:
                    seen_kl.add(kl)
                    key_lengths.append(kl)

            for kl in key_lengths:
                key = _recover_vigenere_key(ciphertext, kl)
                decrypted = vigenere_decrypt(ciphertext, key)
                flag = _check_flag(decrypted, effective_prefix)
                if flag:
                    print(f"[+] Vigenere key='{key}' (len={kl}) found flag!")
                    print(f"[+] FLAG: {flag}")
                    return flag
                _try_wrap(decrypted, f"Vigenere key='{key}' (len={kl})")

                s = _score_english(decrypted)
                if s > best_score:
                    best_score = s
                    best_result = decrypted
                    best_method = f"Vigenere key='{key}' (len={kl})"

            # If we have a known flag prefix, try using it to derive the Vigenere key directly
            if flag_prefix:
                print(f"[*] Trying Vigenere known-plaintext with prefix '{flag_prefix}{{' ...")
                known_pt = flag_prefix + '{'
                ct_alpha = _alpha_only(ciphertext).upper()
                pt_alpha = _alpha_only(known_pt).upper()
                if len(pt_alpha) >= 3 and len(ct_alpha) >= len(pt_alpha):
                    derived_key_bytes = []
                    for i in range(len(pt_alpha)):
                        shift = (ord(ct_alpha[i]) - ord(pt_alpha[i])) % 26
                        derived_key_bytes.append(chr(shift + ord('A')))

                    # Try key lengths that are factors of what we derived
                    for kl in range(1, len(derived_key_bytes) + 1):
                        candidate_key = ''.join(derived_key_bytes[:kl])
                        # Verify: does repeating this key match the full derived bytes?
                        matches = True
                        for i in range(len(derived_key_bytes)):
                            if derived_key_bytes[i] != candidate_key[i % kl]:
                                matches = False
                                break
                        if not matches:
                            continue
                        decrypted = vigenere_decrypt(ciphertext, candidate_key)
                        flag = _check_flag(decrypted, effective_prefix)
                        if flag:
                            print(f"[+] Vigenere known-plaintext key='{candidate_key}' found flag!")
                            print(f"[+] FLAG: {flag}")
                            return flag

        # ── Attack 6: Simple substitution (frequency analysis) ──────
        if alpha_len >= 50:
            print("[*] Trying simple substitution (frequency analysis)...")
            decrypted = _frequency_substitution(ciphertext)
            if decrypted:
                flag = _check_flag(decrypted, effective_prefix)
                if flag:
                    print(f"[+] Frequency analysis found flag!")
                    print(f"[+] FLAG: {flag}")
                    return flag
                s = _score_english(decrypted)
                if s > best_score:
                    best_score = s
                    best_result = decrypted
                    best_method = "Frequency analysis"

        # ── Attack 7: Affine cipher ─────────────────────────────────
        print("[*] Trying Affine cipher (all valid a,b pairs)...")
        for a in range(1, 26):
            if math.gcd(a, 26) != 1:
                continue
            for b in range(26):
                if a == 1 and b == 0:
                    continue  # identity, skip
                decrypted = affine_decrypt(ciphertext, a, b)
                flag = _check_flag(decrypted, effective_prefix)
                if flag:
                    print(f"[+] Affine a={a}, b={b} found flag!")
                    print(f"[+] FLAG: {flag}")
                    return flag
                _try_wrap(decrypted, f"Affine a={a}, b={b}")

        # ── Select best wrapping candidate ──────────────────────────
        if wrap_candidates:
            # If source code analysis identified the cipher, prefer that method
            if detected_cipher:
                cipher_keyword = detected_cipher.lower()
                # Find candidates whose method matches the detected cipher
                matching = [
                    (s, f, m) for s, f, m in wrap_candidates
                    if cipher_keyword in m.lower()
                ]
                if matching:
                    # Among matching candidates, pick highest score
                    matching.sort(key=lambda x: x[0], reverse=True)
                    best_wrap_score, best_wrap_flag, best_wrap_method = matching[0]
                    print(f"\n[+] Source-detected cipher match ({best_wrap_method}, score={best_wrap_score:.1f}):")
                    print(f"[+] FLAG: {best_wrap_flag}")
                    return best_wrap_flag

            # Fallback: pick the highest-scoring wrap candidate
            wrap_candidates.sort(key=lambda x: x[0], reverse=True)
            best_wrap_score, best_wrap_flag, best_wrap_method = wrap_candidates[0]
            print(f"\n[+] Best wrapped result ({best_wrap_method}, score={best_wrap_score:.1f}):")
            print(f"[+] FLAG: {best_wrap_flag}")
            return best_wrap_flag

        # Report best non-flag result for this file
        if best_score > 0 and best_result:
            print(f"\n[*] Best decryption ({best_method}, score={best_score:.1f}):")
            print(f"[*]   {best_result[:200]}")

    print("\n[-] No flag found with any classical cipher attack")
    return None


def main():
    parser = argparse.ArgumentParser(
        description="Kraken Classical/Substitution Cipher Solver",
    )
    parser.add_argument("--dir", required=True, help="Path to challenge directory")
    parser.add_argument("--flag-format", default="", help="Expected flag prefix (e.g., 'HTB{')")
    args = parser.parse_args()

    if not os.path.isdir(args.dir):
        print(f"[-] Not a directory: {args.dir}")
        sys.exit(1)

    flag = solve(args.dir, args.flag_format)
    if not flag:
        sys.exit(1)


if __name__ == "__main__":
    main()
