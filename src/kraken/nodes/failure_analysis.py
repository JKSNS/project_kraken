"""Failure analysis -- deterministic diagnosis of solve script failures (#1, #2).

Provides two capabilities:
1. ``diagnose_failure()`` -- classifies script failure type from stderr/stdout
   and produces actionable hints for the next solve attempt.
2. ``extract_script_findings()`` -- scans stdout for intermediate results
   (hex values, decoded strings, keys, addresses, partial flags).

Both are deterministic (no LLM calls) and run between flag_validator → solve_engine
on self-correction retries.
"""
from __future__ import annotations

import re


# ── Failure diagnosis (#1) ──────────────────────────────────────────

# (pattern, diagnosis, hint)
_FAILURE_PATTERNS: list[tuple[str, str, str]] = [
    # Import / dependency errors
    (r"ModuleNotFoundError: No module named ['\"](\w+)['\"]",
     "missing_module",
     "Module '{match}' is not installed. Use only: pwntools, angr, claripy, lief, z3, "
     "pycryptodome, ctypes, struct, capstone, base64, hashlib, itertools, subprocess, os, re, sys."),

    (r"ImportError: cannot import name ['\"](\w+)['\"]",
     "import_error",
     "Import failed for '{match}'. Check the correct import path for this library."),

    # File / path errors
    (r"FileNotFoundError: \[Errno 2\] No such file or directory: ['\"]([^'\"]+)['\"]",
     "file_not_found",
     "File '{match}' does not exist. Verify the binary path and use the exact path from challenge_path."),

    (r"PermissionError: \[Errno 13\] Permission denied: ['\"]([^'\"]+)['\"]",
     "permission_denied",
     "Permission denied for '{match}'. Use /tmp/ for output files. If running the binary, ensure chmod +x."),

    # Timeout / resource
    (r"Script timed out after (\d+)s",
     "timeout",
     "Script timed out after {match}s. For angr: reduce stdin_length, add more constraints, or use "
     "veritesting=True. For brute-force: reduce search space or use smarter pruning."),

    (r"MemoryError|killed|Killed|OOM",
     "memory_error",
     "Out of memory. For angr: reduce stdin_length and use auto_load_libs=False. "
     "Avoid loading large binaries entirely into memory."),

    # angr-specific
    (r"angr.*(?:timed? ?out|timeout|no (?:solution|path) found)",
     "angr_timeout",
     "angr exploration timed out. Try: shorter stdin_length (32 instead of 64), "
     "add veritesting=True, narrow find/avoid addresses, or try string-based find/avoid."),

    (r"UNSAT",
     "angr_unsat",
     "angr returned UNSAT. The constraints may be too strict, or the binary uses "
     "anti-symbolic techniques. Try: different stdin_length, relax printable constraints, "
     "or switch to a different approach (dynamic/brute-force/patching)."),

    # Segfault / crash
    (r"Segmentation fault|SIGSEGV|segfault",
     "segfault",
     "Binary crashed with segfault. If running the binary: check input length "
     "(may be a buffer overflow -- could be intentional for pwn). "
     "If using angr/lief: check binary path and auto_load_libs setting."),

    (r"Traceback.*SyntaxError",
     "syntax_error",
     "Generated code has syntax errors. Ensure complete function definitions, "
     "matched parentheses, and proper indentation."),

    # z3-specific
    (r"z3.*unknown|z3.*timeout",
     "z3_timeout",
     "z3 solver timed out or returned unknown. Simplify constraints or break the "
     "problem into smaller sub-problems."),

    # Script logic errors
    (r"IndexError: (?:list|string) index out of range",
     "index_error",
     "Index out of range -- the script assumes a data structure size that doesn't match. "
     "Check array/string lengths before indexing."),

    (r"KeyError: ['\"]([^'\"]+)['\"]",
     "key_error",
     "KeyError for '{match}'. Check that the expected key/section/symbol exists in the binary."),

    (r"ValueError: (?:invalid literal|could not convert)",
     "value_error",
     "Value conversion failed. Check data types -- the extracted data may be in a "
     "different format than expected (hex vs decimal, bytes vs string)."),

    # Binary-specific
    (r"No section named|section.*not found|get_section.*None",
     "missing_section",
     "Binary section not found. Check section names with lief.parse(binary).sections. "
     "Custom sections may have different names than expected."),

    (r"lief.*(?:error|failed|cannot)",
     "lief_error",
     "lief binary parsing failed. The binary may be corrupted, stripped, or in an "
     "unsupported format. Try reading raw bytes with open() instead."),

]


def diagnose_failure(stdout: str, stderr: str, exit_code: int) -> str:
    """Classify a solve script failure and return actionable diagnosis.

    Returns a concise string describing what went wrong and how to fix it.
    """
    combined = f"{stderr}\n{stdout}"
    diagnoses: list[str] = []

    for pattern, category, hint_template in _FAILURE_PATTERNS:
        match = re.search(pattern, combined, re.IGNORECASE | re.MULTILINE)
        if match:
            # Fill in captured group if present
            match_val = match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0)
            hint = hint_template.replace("{match}", match_val)
            diagnoses.append(f"[{category}] {hint}")

    # Check for empty output specifically (deterministic; do not infer from regex)
    if not stdout.strip() and not stderr.strip() and exit_code == 0:
        diagnoses.append(
            "[no_output] Script exited successfully but produced no output. "
            "Add print() to output the flag."
        )

    if exit_code != 0 and not diagnoses:
        diagnoses.append(
            f"[unknown_failure] Script exited with code {exit_code}. "
            f"stderr: {stderr[:200]}. stdout: {stdout[:200]}. "
            "Try a fundamentally different approach."
        )

    return " | ".join(diagnoses) if diagnoses else ""


# ── Script findings extraction (#2) ─────────────────────────────────

# Patterns for intermediate results in script output
_FINDING_PATTERNS: list[tuple[str, str]] = [
    # Structured findings from solve engine (# FINDING: key=value) -- highest priority
    (r"#\s*FINDING:\s*(\S+=.+)", "finding"),

    # Hex values (keys, addresses, decrypted data)
    (r"(?:key|Key|KEY)[:\s=]+(?:0x)?([0-9a-fA-F]{2,64})", "key"),
    (r"(?:flag|Flag|FLAG)[:\s=]+([^\s\n]{4,100})", "partial_flag"),
    (r"(?:decrypted|Decrypted|DECRYPTED|decoded|Decoded)[:\s=]+([^\n]{4,200})", "decrypted"),
    (r"(?:password|Password|PASS)[:\s=]+([^\s\n]{2,100})", "password"),
    (r"(?:secret|Secret|SECRET)[:\s=]+([^\s\n]{2,100})", "secret"),
    (r"(?:solution|Solution|SOLUTION)[:\s=]+([^\n]{2,200})", "solution"),
    (r"(?:input|Input|INPUT)[:\s=]+([^\n]{2,200})", "input"),
    (r"(?:offset|Offset|OFFSET)[:\s=]+(?:0x)?([0-9a-fA-F]+|\d+)", "offset"),
    (r"(?:address|Address|ADDR)[:\s=]+(?:0x)?([0-9a-fA-F]+)", "address"),

    # angr/z3 results
    (r"SAT\|([0-9a-fA-F]+)\|", "angr_solution_hex"),
    (r"(?:satisf(?:iable|ied)).*?:?\s*([^\n]{4,200})", "sat_result"),

    # XOR / crypto results
    (r"XOR.*?(?:key|result)[:\s=]+([^\n]{2,100})", "xor_result"),
    (r"(?:base64|b64).*?(?:decoded?)[:\s=]+([^\n]{2,200})", "b64_decoded"),

    # General hex dumps (at least 8 hex chars)
    (r"(?:result|output|data|bytes?)[:\s=]+(?:b['\"])?([0-9a-fA-F]{8,})", "hex_data"),

    # Printable ASCII strings that look like flags
    (r"([A-Za-z0-9_\-]{4,})\{[A-Za-z0-9_\-]{2,}\}", "flag_like"),
]


def extract_script_findings(stdout: str, stderr: str) -> list[str]:
    """Extract intermediate results from solve script output.

    Returns a list of finding strings like:
      ["key: 0xdeadbeef", "decrypted: hello_world"]
    """
    combined = f"{stdout}\n{stderr}"
    findings: list[str] = []
    seen: set[str] = set()

    for pattern, category in _FINDING_PATTERNS:
        for match in re.finditer(pattern, combined, re.IGNORECASE):
            value = match.group(1).strip() if match.lastindex else match.group(0).strip()
            # Deduplicate and filter noise
            if value in seen or len(value) < 3:
                continue
            seen.add(value)
            findings.append(f"{category}: {value[:200]}")

    return findings[:20]  # Cap at 20 findings to avoid noise
