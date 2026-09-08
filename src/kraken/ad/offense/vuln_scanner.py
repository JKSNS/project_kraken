"""Automated vulnerability discovery for A/D services.

Integrates with Kraken's existing decompilation and analysis pipeline
to automatically find exploitable vulnerabilities in challenge binaries.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger("kraken.ad.offense.vuln_scanner")


@dataclass
class Vulnerability:
    """A discovered vulnerability in a service."""

    service: str
    vuln_type: str  # buffer_overflow, format_string, sql_injection, command_injection, etc.
    description: str
    severity: str = "medium"  # low, medium, high, critical
    location: str = ""  # Function or file location
    exploit_hint: str = ""  # Suggested exploitation approach
    verified: bool = False
    binary_path: str = ""


class VulnScanner:
    """Scan service binaries and source code for exploitable vulnerabilities.

    Uses static analysis techniques (string scanning, pattern matching,
    symbol analysis) to identify common vulnerability classes:
    - Buffer overflows (gets, strcpy, sprintf, no bounds checking)
    - Format string bugs (printf(user_input))
    - Command injection (system, popen with user input)
    - SQL injection (string concatenation in queries)
    - Path traversal (unsanitized file paths)
    - Hardcoded credentials
    """

    # Dangerous C function patterns
    DANGEROUS_FUNCTIONS = {
        "gets": ("buffer_overflow", "critical", "gets() has no bounds checking"),
        "strcpy": ("buffer_overflow", "high", "strcpy() has no bounds checking"),
        "strcat": ("buffer_overflow", "high", "strcat() has no bounds checking"),
        "sprintf": ("buffer_overflow", "high", "sprintf() has no bounds checking"),
        "scanf": ("buffer_overflow", "medium", "scanf() may overflow with %s"),
        "system": ("command_injection", "critical", "system() may allow command injection"),
        "popen": ("command_injection", "high", "popen() may allow command injection"),
        "exec": ("command_injection", "high", "exec*() may allow command injection"),
    }

    # Source code vulnerability patterns
    SOURCE_PATTERNS = {
        "format_string": [
            re.compile(r"printf\s*\(\s*[a-zA-Z_]\w*\s*\)"),  # printf(var)
            re.compile(r"fprintf\s*\(\s*\w+\s*,\s*[a-zA-Z_]\w*\s*\)"),
            re.compile(r"syslog\s*\(\s*\w+\s*,\s*[a-zA-Z_]\w*\s*\)"),
        ],
        "sql_injection": [
            re.compile(r'["\'].*SELECT.*\+.*["\']', re.IGNORECASE),
            re.compile(r'["\'].*INSERT.*\+.*["\']', re.IGNORECASE),
            re.compile(r'f["\'].*SELECT.*\{', re.IGNORECASE),
            re.compile(r"execute\s*\(\s*f['\"]", re.IGNORECASE),
        ],
        "command_injection": [
            re.compile(r"os\.system\s*\("),
            re.compile(r"subprocess\.\w+\s*\(\s*[^)\[]*\+"),
            re.compile(r"subprocess\.\w+\s*\(\s*f['\"]"),
            re.compile(r"`.*\$\{?[a-zA-Z_]"),  # backtick with variable
        ],
        "path_traversal": [
            re.compile(r"open\s*\(.*\+.*\)"),
            re.compile(r"os\.path\.join\s*\([^)]*request"),
            re.compile(r'sendfile\s*\(.*\+.*["\']'),
        ],
        "hardcoded_cred": [
            re.compile(r'password\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
            re.compile(r'secret\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
            re.compile(r'api_key\s*=\s*["\'][^"\']{3,}["\']', re.IGNORECASE),
        ],
    }

    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []

    def scan_binary(self, binary_path: str, service: str = "") -> List[Vulnerability]:
        """Scan a binary for common vulnerabilities using static analysis.

        Uses ``nm``, ``strings``, ``objdump`` to identify dangerous functions
        and patterns.
        """
        path = Path(binary_path)
        if not path.exists():
            logger.warning("Binary not found: %s", binary_path)
            return []

        service = service or path.stem
        vulns: List[Vulnerability] = []

        # Check imported symbols for dangerous functions
        vulns.extend(self._scan_symbols(binary_path, service))

        # Check strings for interesting patterns
        vulns.extend(self._scan_strings(binary_path, service))

        # Check security features (NX, PIE, canary, RELRO)
        vulns.extend(self._check_protections(binary_path, service))

        for v in vulns:
            v.binary_path = binary_path

        self.vulnerabilities.extend(vulns)
        logger.info(
            "Found %d potential vulnerabilities in %s", len(vulns), binary_path
        )
        return vulns

    def scan_source(self, source_path: str, service: str = "") -> List[Vulnerability]:
        """Scan source code for common vulnerability patterns."""
        path = Path(source_path)
        if not path.exists():
            logger.warning("Source not found: %s", source_path)
            return []

        service = service or path.stem
        vulns: List[Vulnerability] = []

        try:
            content = path.read_text(errors="replace")
        except Exception as exc:
            logger.warning("Cannot read %s: %s", source_path, exc)
            return []

        for vuln_type, patterns in self.SOURCE_PATTERNS.items():
            for pattern in patterns:
                for match in pattern.finditer(content):
                    # Find line number
                    line_no = content[: match.start()].count("\n") + 1
                    vulns.append(
                        Vulnerability(
                            service=service,
                            vuln_type=vuln_type,
                            description=f"Potential {vuln_type} at line {line_no}: {match.group()[:80]}",
                            severity="high" if vuln_type in ("command_injection", "sql_injection") else "medium",
                            location=f"{path.name}:{line_no}",
                        )
                    )

        self.vulnerabilities.extend(vulns)
        return vulns

    def scan_directory(self, dir_path: str, service: str = "") -> List[Vulnerability]:
        """Recursively scan a directory for vulnerabilities."""
        path = Path(dir_path)
        if not path.is_dir():
            return []

        vulns: List[Vulnerability] = []
        source_extensions = {".c", ".cpp", ".py", ".rb", ".php", ".js", ".go", ".rs"}

        for file in path.rglob("*"):
            if not file.is_file():
                continue
            if file.suffix in source_extensions:
                vulns.extend(self.scan_source(str(file), service))
            elif file.stat().st_mode & 0o111 and file.suffix == "":
                # Executable binary
                vulns.extend(self.scan_binary(str(file), service))

        return vulns

    def _scan_symbols(self, binary_path: str, service: str) -> List[Vulnerability]:
        """Check binary's imported symbols for dangerous functions."""
        vulns = []
        try:
            result = subprocess.run(
                ["nm", "-D", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            symbols = result.stdout
        except Exception:
            return []

        for func, (vuln_type, severity, desc) in self.DANGEROUS_FUNCTIONS.items():
            if f" {func}\n" in symbols or f" {func}@" in symbols:
                vulns.append(
                    Vulnerability(
                        service=service,
                        vuln_type=vuln_type,
                        description=f"Uses {func}(): {desc}",
                        severity=severity,
                        location=f"imported symbol: {func}",
                        exploit_hint=self._get_exploit_hint(func),
                    )
                )

        return vulns

    def _scan_strings(self, binary_path: str, service: str) -> List[Vulnerability]:
        """Check binary strings for interesting patterns."""
        vulns = []
        try:
            result = subprocess.run(
                ["strings", "-n", "6", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            strings_output = result.stdout
        except Exception:
            return []

        # Check for hardcoded paths, credentials, etc.
        for line in strings_output.splitlines():
            line = line.strip()

            # SQL queries
            if re.search(r"SELECT\s+.*FROM", line, re.IGNORECASE):
                vulns.append(
                    Vulnerability(
                        service=service,
                        vuln_type="sql_injection",
                        description=f"Embedded SQL query: {line[:80]}",
                        severity="high",
                        location="binary string",
                    )
                )

            # Shell commands
            if re.search(r"^(/bin/sh|/bin/bash|sh -c)", line):
                vulns.append(
                    Vulnerability(
                        service=service,
                        vuln_type="command_injection",
                        description=f"Shell reference: {line[:80]}",
                        severity="medium",
                        location="binary string",
                    )
                )

            # Hardcoded credentials (common patterns)
            if re.search(
                r"(password|passwd|secret|token)\s*[:=]\s*\S+",
                line,
                re.IGNORECASE,
            ):
                vulns.append(
                    Vulnerability(
                        service=service,
                        vuln_type="hardcoded_cred",
                        description=f"Possible hardcoded credential: {line[:60]}",
                        severity="high",
                        location="binary string",
                    )
                )

        return vulns

    def _check_protections(self, binary_path: str, service: str) -> List[Vulnerability]:
        """Check binary security features (NX, PIE, canary, RELRO)."""
        vulns = []
        try:
            result = subprocess.run(
                ["readelf", "-l", "-d", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            output = result.stdout

            # Check for missing NX (no execute on stack)
            result_h = subprocess.run(
                ["readelf", "-l", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "GNU_STACK" in result_h.stdout:
                for line in result_h.stdout.splitlines():
                    if "GNU_STACK" in line and "RWE" in line:
                        vulns.append(
                            Vulnerability(
                                service=service,
                                vuln_type="missing_nx",
                                description="Stack is executable (no NX/DEP)",
                                severity="high",
                                location="ELF headers",
                                exploit_hint="Stack-based shellcode execution possible",
                            )
                        )

            # Check for missing RELRO
            if "BIND_NOW" not in output:
                vulns.append(
                    Vulnerability(
                        service=service,
                        vuln_type="partial_relro",
                        description="No full RELRO -- GOT overwrite possible",
                        severity="medium",
                        location="ELF headers",
                        exploit_hint="GOT overwrite to redirect function calls",
                    )
                )

            # Check for PIE
            result_file = subprocess.run(
                ["file", binary_path],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if "executable" in result_file.stdout and "pie" not in result_file.stdout.lower():
                vulns.append(
                    Vulnerability(
                        service=service,
                        vuln_type="no_pie",
                        description="Not position-independent (no PIE/ASLR for binary)",
                        severity="medium",
                        location="ELF type",
                        exploit_hint="Fixed addresses for ROP gadgets and functions",
                    )
                )

            # Check for stack canary
            if "__stack_chk_fail" not in output:
                vulns.append(
                    Vulnerability(
                        service=service,
                        vuln_type="no_canary",
                        description="No stack canary detected",
                        severity="medium",
                        location="dynamic symbols",
                        exploit_hint="Stack buffer overflows won't be detected",
                    )
                )

        except Exception as exc:
            logger.debug("Protection check failed for %s: %s", binary_path, exc)

        return vulns

    @staticmethod
    def _get_exploit_hint(func: str) -> str:
        """Return exploitation hints for specific dangerous functions."""
        hints = {
            "gets": "Overflow stack buffer via stdin. Find return address offset with pattern.",
            "strcpy": "Overflow destination buffer. Check buffer size vs input length.",
            "strcat": "Overflow by appending to nearly-full buffer.",
            "sprintf": "Overflow with long format string arguments.",
            "scanf": "Overflow with long input for %s format specifier.",
            "system": "Inject commands via semicolons, pipes, or backticks in user input.",
            "popen": "Inject commands in the command string argument.",
            "exec": "Control arguments to exec*() family.",
        }
        return hints.get(func, "")

    def get_summary(self) -> Dict[str, List[Dict]]:
        """Return vulnerability summary grouped by service."""
        summary: Dict[str, List[Dict]] = {}
        for v in self.vulnerabilities:
            if v.service not in summary:
                summary[v.service] = []
            summary[v.service].append(
                {
                    "type": v.vuln_type,
                    "severity": v.severity,
                    "description": v.description,
                    "location": v.location,
                    "hint": v.exploit_hint,
                }
            )
        return summary
