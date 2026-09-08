#!/usr/bin/env python3
"""auto_hash_crack -- Crack password hashes using hints from challenge descriptions.

Scans challenge directory for:
  - README/description files to extract hints (names, dates, keywords)
  - Text files for hash patterns (MD5, SHA1, SHA256)

Tries cracking found hashes with:
  - Name + date patterns (e.g., Aaron + YYYYMMDD, MMDDYYYY)
  - Small built-in wordlist
  - Common CTF password patterns

Outputs EXTRACTED FLAG: flag{cracked_password} on success.
"""
import argparse
import hashlib
import itertools
import json
import os
import re
import sys


# Hash lengths to algorithm mapping
_HASH_TYPES = {
    32: ("md5", hashlib.md5),
    40: ("sha1", hashlib.sha1),
    64: ("sha256", hashlib.sha256),
}

# Built-in small wordlist for common CTF passwords
_WORDLIST = [
    "password", "admin", "flag", "secret", "root", "test", "guest",
    "letmein", "welcome", "monkey", "dragon", "master", "login",
    "abc123", "qwerty", "123456", "password1", "iloveyou", "trustno1",
    "sunshine", "princess", "football", "shadow", "superman", "michael",
    "hunter2", "changeme", "default", "p@ssw0rd",
]


def _find_hashes(text: str) -> list[tuple[str, str, callable]]:
    """Find hex hash strings in text. Returns [(hash_hex, algo_name, hash_fn)]."""
    results = []
    # Match hex strings that look like hashes (standalone or in backticks/quotes)
    for m in re.finditer(r'(?:^|[\s`\'":])([0-9a-fA-F]{32,64})(?:$|[\s`\'":,.])', text, re.MULTILINE):
        h = m.group(1)
        if len(h) in _HASH_TYPES:
            algo_name, hash_fn = _HASH_TYPES[len(h)]
            # Skip if it looks like a non-hash hex string (all same digit, etc.)
            if len(set(h.lower())) < 4:
                continue
            results.append((h.lower(), algo_name, hash_fn))
    return results


def _extract_hints(text: str) -> dict:
    """Extract names, dates, and keywords from challenge description text."""
    hints = {
        "names": [],
        "years": [],
        "dates_mmdd": [],
        "keywords": [],
    }

    # Extract capitalized names (2+ chars, start with uppercase)
    name_pattern = re.compile(r'\b([A-Z][a-z]{1,15})\b')
    # Filter out common English words
    _SKIP_WORDS = {
        "The", "This", "That", "Can", "You", "His", "Her", "Use", "Hash",
        "Once", "Hint", "Author", "Lab", "National", "Pacific", "Northwest",
        "Challenge", "Flag", "Password", "Simple", "Important", "Crack",
        "Brute", "Force", "Mode", "Rules", "Approach",
    }
    for m in name_pattern.finditer(text):
        name = m.group(1)
        if name not in _SKIP_WORDS and len(name) >= 3:
            if name not in hints["names"]:
                hints["names"].append(name)

    # Extract 4-digit years (1900-2025)
    for m in re.finditer(r'\b(19[0-9]{2}|20[0-2][0-9])\b', text):
        y = m.group(1)
        if y not in hints["years"]:
            hints["years"].append(y)

    # Extract date-like patterns (YYYY-MM-DD, MM/DD/YYYY, etc.)
    for m in re.finditer(r'(\d{4})[-/](\d{2})[-/](\d{2})', text):
        y, mo, d = m.group(1), m.group(2), m.group(3)
        hints["dates_mmdd"].append((y, mo, d))
    for m in re.finditer(r'(\d{2})[-/](\d{2})[-/](\d{4})', text):
        mo, d, y = m.group(1), m.group(2), m.group(3)
        hints["dates_mmdd"].append((y, mo, d))

    # Extract keywords that might be password-relevant
    kw_pattern = re.compile(r'\b(name|birthday|birth|date|born|year|simple|like|uses?)\b', re.IGNORECASE)
    for m in kw_pattern.finditer(text):
        kw = m.group(1).lower()
        if kw not in hints["keywords"]:
            hints["keywords"].append(kw)

    return hints


def _generate_candidates(hints: dict) -> list[str]:
    """Generate password candidates from extracted hints."""
    candidates = []
    names = hints.get("names", [])
    keywords = hints.get("keywords", [])

    # Generate date components: all months (01-12) x days (01-31)
    months = [f"{m:02d}" for m in range(1, 13)]
    days = [f"{d:02d}" for d in range(1, 32)]

    # For birthday-related challenges, always use a wide birth-year range
    # regardless of what years appear in the text (those may be irrelevant)
    has_birthday_hint = any(k in keywords for k in ("birthday", "birth", "born", "date"))
    if has_birthday_hint:
        years = [str(y) for y in range(1950, 2010)]
    else:
        years = hints.get("years", [])
        if not years:
            years = [str(y) for y in range(1970, 2005)]

    # Name + YYYYMMDD patterns (highest priority for birthday-based challenges)
    for name in names:
        for year in years:
            for month in months:
                for day in days:
                    # YYYYMMDD
                    candidates.append(f"{name}{year}{month}{day}")
                    # name in lowercase
                    candidates.append(f"{name.lower()}{year}{month}{day}")
                    # MMDDYYYY
                    candidates.append(f"{name}{month}{day}{year}")
                    candidates.append(f"{name.lower()}{month}{day}{year}")
                    # DDMMYYYY
                    candidates.append(f"{name}{day}{month}{year}")
                    candidates.append(f"{name.lower()}{day}{month}{year}")

    # Name + simple number suffixes
    for name in names:
        for n in list(range(0, 100)) + [123, 1234, 12345, 321, 456, 789]:
            candidates.append(f"{name}{n}")
            candidates.append(f"{name.lower()}{n}")
            candidates.append(f"{n}{name}")

    # Name variations alone
    for name in names:
        candidates.append(name)
        candidates.append(name.lower())
        candidates.append(name.upper())
        candidates.append(name + "!")
        candidates.append(name + "1")

    # Built-in wordlist
    candidates.extend(_WORDLIST)

    # Common CTF flag bodies
    ctf_bodies = [
        "password", "p@ssw0rd", "cr4ck3d", "h4sh", "w3ak", "br0k3n",
        "hashcat", "john", "cracked", "weak", "easy", "simple",
    ]
    candidates.extend(ctf_bodies)

    return candidates


def _try_crack(hash_hex: str, hash_fn: callable, candidates: list[str]) -> str | None:
    """Try each candidate against the hash. Returns cracked password or None."""
    target = hash_hex.lower()
    for candidate in candidates:
        computed = hash_fn(candidate.encode("utf-8")).hexdigest()
        if computed == target:
            return candidate
    return None


def main():
    parser = argparse.ArgumentParser(description="Kraken Hash Cracker")
    parser.add_argument("challenge_dir", help="Path to challenge directory")
    parser.add_argument("--flag-format", default="", help="Expected flag format regex")
    args = parser.parse_args()

    challenge_dir = args.challenge_dir
    if not os.path.isdir(challenge_dir):
        print(f"[-] Not a directory: {challenge_dir}")
        sys.exit(1)

    print(f"[*] Scanning challenge directory: {challenge_dir}")

    # Collect all text from readable files
    all_text = ""
    text_files = []
    for root, _dirs, fnames in os.walk(challenge_dir):
        for name in fnames:
            fpath = os.path.join(root, name)
            ext = os.path.splitext(name)[1].lower()
            # Read text-like files
            if ext in ("", ".txt", ".md", ".json", ".yml", ".yaml", ".cfg",
                        ".ini", ".sh", ".py", ".c", ".h", ".html", ".xml"):
                try:
                    if os.path.getsize(fpath) < 500_000:
                        content = open(fpath, encoding="utf-8", errors="replace").read()
                        all_text += "\n" + content
                        text_files.append(fpath)
                except OSError:
                    pass

    if not text_files:
        print("[-] No text files found")
        sys.exit(1)

    print(f"[*] Scanned {len(text_files)} text files")

    # Find hashes
    hashes = _find_hashes(all_text)
    if not hashes:
        print("[-] No hash patterns found")
        sys.exit(1)

    # Deduplicate hashes
    seen = set()
    unique_hashes = []
    for h, algo, fn in hashes:
        if h not in seen:
            seen.add(h)
            unique_hashes.append((h, algo, fn))

    print(f"[*] Found {len(unique_hashes)} unique hash(es)")
    for h, algo, _ in unique_hashes:
        print(f"    {algo}: {h}")

    # Extract hints from text
    hints = _extract_hints(all_text)
    print(f"[*] Hints: names={hints['names']}, years={hints['years']}, keywords={hints['keywords']}")

    # Generate candidates
    candidates = _generate_candidates(hints)
    print(f"[*] Generated {len(candidates)} candidates")

    # Try cracking each hash
    for hash_hex, algo_name, hash_fn in unique_hashes:
        print(f"[*] Cracking {algo_name} hash: {hash_hex}")
        password = _try_crack(hash_hex, hash_fn, candidates)
        if password:
            print(f"[+] HASH_CRACK SUCCESS ({algo_name})")
            print(f"[+] Password: {password}")

            # Determine flag format
            flag_format = args.flag_format
            prefix = "flag"
            if flag_format:
                prefix_m = re.match(r'([A-Za-z_]+)\\?\{', flag_format)
                if prefix_m:
                    prefix = prefix_m.group(1)

            flag = f"{prefix}{{{password}}}"
            print(f"[+] EXTRACTED FLAG: {flag}")
            return

    print("[-] HASH_CRACK FAILED: No candidates matched")
    sys.exit(1)


if __name__ == "__main__":
    main()
