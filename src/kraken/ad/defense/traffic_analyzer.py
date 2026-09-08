"""Analyze network traffic to detect opponent exploits.

Captures traffic on the game interface and analyzes pcap files for
exploit patterns, shellcode, flag exfiltration, and repeated attack
signatures across teams.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import struct
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger("kraken.ad.defense.traffic_analyzer")


class TrafficAnalyzer:
    """Analyze pcap files to detect and extract opponent exploit patterns.

    Capabilities:
    - Start/stop tcpdump captures per tick
    - Extract TCP stream payloads using tshark
    - Detect known attack patterns (shellcode, format strings, ROP)
    - Identify repeated payloads across teams (likely automated exploits)
    - Extract potential flag exfiltration
    - Replay captured attacks for verification
    """

    # Known shellcode byte patterns (common x86/x64 NOP sleds and syscalls)
    SHELLCODE_PATTERNS = [
        rb"\x90{8,}",  # NOP sled
        rb"\x31\xc0\x50\x68",  # push /bin/sh setup
        rb"\x48\x31\xd2\x48\xbb",  # x64 execve setup
        rb"\x6a\x3b\x58",  # x64 syscall execve
        rb"\xcd\x80",  # int 0x80 (x86 syscall)
        rb"\x0f\x05",  # syscall (x64)
    ]

    # Format string attack indicators
    FORMAT_STRING_PATTERNS = [
        rb"%n",
        rb"%hn",
        rb"%hhn",
        rb"%\d+\$n",
        rb"%\d+\$hn",
        rb"AAAA" + rb"%",  # Classic format string probe
    ]

    # ROP indicators
    ROP_PATTERNS = [
        rb"[\x00-\xff]{4}([\x00-\x7f][\x00]{3}){3,}",  # Multiple near-null addresses (32-bit)
    ]

    def __init__(
        self,
        interface: str = "game",
        our_team_id: int = 1,
        pcap_dir: str = "./pcaps",
    ):
        self.interface = interface
        self.our_team_id = our_team_id
        self.pcap_dir = Path(pcap_dir)
        self.known_patterns: Set[bytes] = set()
        self.attack_log: List[Dict] = []
        self._capture_proc: Optional[asyncio.subprocess.Process] = None

    def start_capture(
        self,
        output_dir: str,
        duration: Optional[int] = None,
        filter_expr: str = "",
    ) -> Optional[str]:
        """Start tcpdump capture on game interface.

        Args:
            output_dir: Directory to write pcap files.
            duration: Capture duration in seconds (None for indefinite).
            filter_expr: Optional BPF filter expression.

        Returns:
            Path to the pcap file being written, or None on error.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        timestamp = int(time.time())
        pcap_path = str(out_dir / f"capture_{timestamp}.pcap")

        cmd = [
            "tcpdump",
            "-i", self.interface,
            "-w", pcap_path,
            "-U",  # Packet-buffered output
        ]

        if duration:
            cmd.extend(["-G", str(duration), "-W", "1"])

        if filter_expr:
            cmd.append(filter_expr)

        try:
            # Stop any existing capture first
            self.stop_capture()

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self._capture_proc = proc  # type: ignore
            logger.info("Started capture on %s -> %s", self.interface, pcap_path)
            return pcap_path
        except FileNotFoundError:
            logger.warning("tcpdump not found -- traffic capture disabled")
            return None
        except PermissionError:
            logger.warning("No permission for tcpdump -- try running as root or with CAP_NET_RAW")
            return None
        except Exception as exc:
            logger.warning("Failed to start capture: %s", exc)
            return None

    def stop_capture(self) -> None:
        """Stop any running tcpdump capture."""
        if self._capture_proc is not None:
            try:
                self._capture_proc.terminate()  # type: ignore
                self._capture_proc.wait(timeout=5)  # type: ignore
            except Exception:
                try:
                    self._capture_proc.kill()  # type: ignore
                except Exception:
                    pass
            self._capture_proc = None

    def analyze_pcap(self, pcap_path: str) -> List[Dict]:
        """Analyze a pcap file for exploit patterns.

        Returns list of detected attack dicts with keys:
        - source_ip, dest_ip, dest_port, timestamp
        - payload (hex), vuln_type, confidence
        """
        if not Path(pcap_path).exists():
            logger.warning("PCAP not found: %s", pcap_path)
            return []

        attacks: List[Dict] = []

        # Extract TCP streams using tshark
        streams = self._extract_tcp_streams(pcap_path)

        for stream_info in streams:
            payload = stream_info.get("payload", b"")
            if len(payload) < 4:
                continue

            # Check for shellcode
            for pattern in self.SHELLCODE_PATTERNS:
                if re.search(pattern, payload):
                    attacks.append(
                        {
                            "source_ip": stream_info.get("src_ip", ""),
                            "dest_ip": stream_info.get("dst_ip", ""),
                            "dest_port": stream_info.get("dst_port", 0),
                            "port": stream_info.get("dst_port", 0),
                            "timestamp": stream_info.get("timestamp", ""),
                            "payload": payload,
                            "vuln_type": "shellcode",
                            "confidence": "high",
                            "service": stream_info.get("service", ""),
                        }
                    )
                    break

            # Check for format string attacks
            for pattern in self.FORMAT_STRING_PATTERNS:
                if re.search(pattern, payload):
                    attacks.append(
                        {
                            "source_ip": stream_info.get("src_ip", ""),
                            "dest_ip": stream_info.get("dst_ip", ""),
                            "dest_port": stream_info.get("dst_port", 0),
                            "port": stream_info.get("dst_port", 0),
                            "timestamp": stream_info.get("timestamp", ""),
                            "payload": payload,
                            "vuln_type": "format_string",
                            "confidence": "high",
                            "service": stream_info.get("service", ""),
                        }
                    )
                    break

            # Check for buffer overflow (long payloads with repeated patterns)
            if len(payload) > 200:
                # Check for cyclic pattern (De Bruijn)
                if self._has_cyclic_pattern(payload):
                    attacks.append(
                        {
                            "source_ip": stream_info.get("src_ip", ""),
                            "dest_ip": stream_info.get("dst_ip", ""),
                            "dest_port": stream_info.get("dst_port", 0),
                            "port": stream_info.get("dst_port", 0),
                            "timestamp": stream_info.get("timestamp", ""),
                            "payload": payload,
                            "vuln_type": "buffer_overflow",
                            "confidence": "medium",
                            "service": stream_info.get("service", ""),
                        }
                    )

        if attacks:
            self.attack_log.extend(attacks)
            logger.info(
                "Detected %d potential attacks in %s", len(attacks), pcap_path
            )

        return attacks

    def extract_exploit_payloads(self, pcap_path: str) -> List[bytes]:
        """Extract potential exploit payloads from traffic.

        Looks for non-standard payloads that are likely exploit attempts:
        - High entropy binary data
        - Known shellcode sequences
        - Unusually large payloads to specific ports
        """
        streams = self._extract_tcp_streams(pcap_path)
        payloads = []

        for stream in streams:
            payload = stream.get("payload", b"")
            if len(payload) < 10:
                continue

            # Check if payload is "interesting" (not just HTTP/plaintext)
            non_printable = sum(
                1 for b in payload if b < 0x20 or b > 0x7E
            )
            ratio = non_printable / len(payload) if payload else 0

            # High binary content ratio suggests exploit payload
            if ratio > 0.3 and len(payload) > 20:
                payloads.append(payload)
            # Long payloads to non-HTTP ports
            elif len(payload) > 500 and stream.get("dst_port", 0) not in (80, 443, 8080):
                payloads.append(payload)

        return payloads

    def detect_new_attacks(self, pcap_path: str) -> List[Dict]:
        """Compare traffic against known patterns, return only NEW attacks."""
        all_attacks = self.analyze_pcap(pcap_path)
        new_attacks = []

        for attack in all_attacks:
            payload = attack.get("payload", b"")
            # Create a fingerprint (first 64 bytes + length)
            fingerprint = bytes(payload[:64]) + struct.pack(">I", len(payload))
            if fingerprint not in self.known_patterns:
                self.known_patterns.add(fingerprint)
                new_attacks.append(attack)

        if new_attacks:
            logger.info(
                "Detected %d NEW attack patterns (of %d total)",
                len(new_attacks),
                len(all_attacks),
            )

        return new_attacks

    def replay_attack(
        self,
        payload: bytes,
        target_ip: str,
        target_port: int,
        timeout: float = 5.0,
    ) -> bool:
        """Replay a captured attack payload to verify it works.

        Sends the raw payload to the target and checks if the response
        contains a flag-like string. Use with caution -- only replay
        against your OWN services for verification.
        """
        import socket

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_ip, target_port))
            sock.sendall(payload)
            response = sock.recv(4096)
            sock.close()

            # Check if response contains flag-like data
            response_text = response.decode("utf-8", errors="replace")
            if re.search(r"[A-Z0-9]{31}=", response_text):
                logger.info(
                    "Replay against %s:%d yielded a flag!", target_ip, target_port
                )
                return True
            return False

        except Exception as exc:
            logger.debug(
                "Replay to %s:%d failed: %s", target_ip, target_port, exc
            )
            return False

    def find_flag_exfiltration(self, pcap_path: str, flag_regex: str = r"[A-Z0-9]{31}=") -> List[Dict]:
        """Search pcap for outbound flag data (opponent stealing our flags)."""
        results = []
        pattern = re.compile(flag_regex.encode() if isinstance(flag_regex, str) else flag_regex)

        streams = self._extract_tcp_streams(pcap_path)
        for stream in streams:
            payload = stream.get("payload", b"")
            matches = pattern.findall(payload)
            if matches:
                results.append(
                    {
                        "source_ip": stream.get("src_ip", ""),
                        "dest_ip": stream.get("dst_ip", ""),
                        "flags_found": [m.decode() if isinstance(m, bytes) else m for m in matches],
                        "direction": "outbound" if stream.get("is_outbound") else "inbound",
                    }
                )

        return results

    def _extract_tcp_streams(self, pcap_path: str) -> List[Dict]:
        """Extract TCP stream data using tshark."""
        streams: List[Dict] = []

        try:
            # Use tshark to extract TCP stream info
            result = subprocess.run(
                [
                    "tshark",
                    "-r", pcap_path,
                    "-T", "fields",
                    "-e", "ip.src",
                    "-e", "ip.dst",
                    "-e", "tcp.dstport",
                    "-e", "tcp.payload",
                    "-e", "frame.time_epoch",
                    "-Y", "tcp.payload",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )

            for line in result.stdout.splitlines():
                parts = line.strip().split("\t")
                if len(parts) < 4:
                    continue

                src_ip = parts[0]
                dst_ip = parts[1]
                try:
                    dst_port = int(parts[2]) if parts[2] else 0
                except ValueError:
                    dst_port = 0

                try:
                    payload = bytes.fromhex(parts[3].replace(":", ""))
                except (ValueError, IndexError):
                    payload = b""

                timestamp = parts[4] if len(parts) > 4 else ""

                streams.append(
                    {
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": dst_port,
                        "payload": payload,
                        "timestamp": timestamp,
                        "is_outbound": str(self.our_team_id) in src_ip,
                        "service": "",
                    }
                )

        except FileNotFoundError:
            logger.warning("tshark not found -- install wireshark-cli for traffic analysis")
        except subprocess.TimeoutExpired:
            logger.warning("tshark timed out analyzing %s", pcap_path)
        except Exception as exc:
            logger.warning("Failed to extract TCP streams: %s", exc)

        return streams

    def extract_exploit_from_attack(self, attack: dict) -> str | None:
        """Convert a detected attack pattern into a deployable exploit script.

        Generates a standalone pwntools-based Python script that replays the
        captured payload against an arbitrary host.  The script prints any
        flag-like strings found in the response.

        Args:
            attack: dict with keys ``source_ip``, ``dest_port``,
                    ``payload`` (bytes), ``type`` / ``vuln_type``.

        Returns:
            Absolute path to the generated exploit script, or ``None`` if the
            payload is too small to be useful.
        """
        payload = attack.get("payload", b"")
        dest_port = attack.get("dest_port", 0)
        attack_type = attack.get("type") or attack.get("vuln_type", "unknown")

        if not payload or len(payload) < 4:
            return None

        exploit_code = (
            "#!/usr/bin/env python3\n"
            '"""Auto-generated exploit from captured traffic.\n'
            f"Attack type: {attack_type}\n"
            f"Original source: {attack.get('source_ip', 'unknown')}\n"
            f"Target port: {dest_port}\n"
            '"""\n'
            "import re\n"
            "import sys\n"
            "\n"
            "from pwn import context, remote\n"
            "\n"
            'context.log_level = "error"\n'
            "\n"
            "\n"
            f"def exploit(host, port={dest_port}):\n"
            "    try:\n"
            "        r = remote(host, port, timeout=10)\n"
            f"        payload = {repr(payload)}\n"
            "        r.send(payload)\n"
            "\n"
            "        # Try to receive flag\n"
            "        try:\n"
            '            data = r.recvall(timeout=5).decode(errors="replace")\n'
            "        except Exception:\n"
            '            data = ""\n'
            "        r.close()\n"
            "\n"
            "        # Extract flags\n"
            '        flags = re.findall(r"[A-Za-z0-9_]{2,}\\{[^}]{3,}\\}", data)\n'
            "        for flag in flags:\n"
            "            print(flag)\n"
            "        return flags\n"
            "    except Exception:\n"
            "        return []\n"
            "\n"
            "\n"
            'if __name__ == "__main__":\n'
            '    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"\n'
            "    flags = exploit(host)\n"
            "    if not flags:\n"
            "        sys.exit(1)\n"
        )

        # Save to exploit directory
        exploit_dir = (
            self.exploit_dir
            if hasattr(self, "exploit_dir")
            else "/tmp/kraken_exploits"
        )
        os.makedirs(exploit_dir, exist_ok=True)

        filename = f"replay_{attack_type}_{dest_port}.py"
        filepath = os.path.join(exploit_dir, filename)

        with open(filepath, "w") as f:
            f.write(exploit_code)
        os.chmod(filepath, 0o755)

        logger.info(
            "Generated replay exploit: %s (type=%s, port=%d)",
            filepath,
            attack_type,
            dest_port,
        )
        return filepath

    def replay_and_verify(
        self,
        attack: dict,
        own_service_host: str = "localhost",
    ) -> bool:
        """Replay captured attack against our own service to verify it works.

        Generates an exploit script from *attack*, runs it against
        *own_service_host*, and returns ``True`` if a flag was extracted.
        The subprocess is killed after 15 seconds to avoid hangs.

        Args:
            attack: Attack dict (same format as :meth:`extract_exploit_from_attack`).
            own_service_host: Hostname/IP of our own service instance.

        Returns:
            ``True`` if the replayed exploit produced a flag.
        """
        exploit_path = self.extract_exploit_from_attack(attack)
        if not exploit_path:
            return False

        try:
            result = subprocess.run(
                ["python3", exploit_path, own_service_host],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.stdout.strip():
                logger.info(
                    "Replay verified: %s produced output against %s",
                    exploit_path,
                    own_service_host,
                )
                return True
        except FileNotFoundError:
            logger.warning("python3 not found -- cannot replay exploit")
        except subprocess.TimeoutExpired:
            logger.debug("Replay timed out for %s", exploit_path)
        except Exception as exc:
            logger.debug("Replay error for %s: %s", exploit_path, exc)

        return False

    @staticmethod
    def _has_cyclic_pattern(data: bytes) -> bool:
        """Detect De Bruijn / cyclic pattern in binary data (pwntools-style)."""
        if len(data) < 20:
            return False

        # Check for 4-byte repeating pattern with incrementing values
        # Cyclic patterns typically have sequential ASCII characters
        ascii_runs = 0
        for i in range(len(data) - 4):
            chunk = data[i : i + 4]
            if all(0x41 <= b <= 0x7A for b in chunk):
                ascii_runs += 1

        # If > 60% of the payload is ASCII 4-byte chunks, likely cyclic
        return ascii_runs > (len(data) / 4) * 0.6
