"""Deterministic parameter extractor -- parses decompiled C to extract solve
parameters using regex/heuristics.  No LLM calls."""
from __future__ import annotations

import re
from typing import Any


# ---------------------------------------------------------------------------
# Positive / negative keyword lists used to classify output strings
# ---------------------------------------------------------------------------
# Strong indicators -- these unambiguously signal success/failure
_STRONG_POSITIVE = re.compile(
    r"(?i)\b(?:correct|success|congrat|well\s*done|bravo|you\s*win|you\s*got)\b"
)
_WEAK_POSITIVE = re.compile(
    r"(?i)\b(?:right|yes|good|nice|win)\b"
)
_POSITIVE_WORDS = re.compile(
    r"(?i)\b(?:correct|success|win|right|yes|good|congrat|well\s*done|bravo|nice)\b"
)
_NEGATIVE_WORDS = re.compile(
    r"(?i)\b(?:wrong|incorrect|fail|bad|error|denied|invalid|nope|nop|try\s*again|lose|lost)\b"
)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def extract_solve_params(
    decompiled_functions: dict[str, str],
    strings: list[str],
    binary_info: dict[str, Any],
) -> dict[str, Any]:
    """Extract solve parameters from decompiled C code without any LLM calls.

    Parameters
    ----------
    decompiled_functions:
        Mapping of function name -> decompiled C source (e.g. from Ghidra).
    strings:
        List of printable strings extracted from the binary.
    binary_info:
        Metadata dict (architecture, endianness, etc.) -- currently unused but
        reserved for future heuristics.

    Returns
    -------
    dict with the following keys:
        input_mode, input_length, success_string, fail_string,
        flag_format_prefix, key_constants, has_strcmp, comparison_target,
        loop_bound, crypto_indicators, uses_random, random_seed
    """
    all_code = "\n".join(decompiled_functions.values())
    main_code = decompiled_functions.get("main", "")

    return {
        "input_mode": _detect_input_mode(main_code, all_code),
        "input_length": _detect_input_length(main_code, all_code),
        "success_string": _detect_success_string(all_code, strings),
        "fail_string": _detect_fail_string(all_code, strings),
        "flag_format_prefix": _detect_flag_prefix(strings),
        "key_constants": _extract_key_constants(all_code),
        "has_strcmp": _detect_strcmp(all_code),
        "comparison_target": _extract_comparison_target(all_code),
        "loop_bound": _detect_loop_bound(main_code, all_code),
        "crypto_indicators": _detect_crypto_indicators(all_code),
        "uses_random": _detect_random(all_code),
        "random_seed": _extract_random_seed(all_code),
        "timing_indicator": _detect_timing_indicator(all_code),
        "charset_range": _detect_charset_range(all_code),
        "has_flag_gate": _detect_flag_gate(all_code),
        "no_user_input": _detect_no_user_input(main_code, all_code),
    }


# ---------------------------------------------------------------------------
# Input mode detection
# ---------------------------------------------------------------------------

_ARGV_PATTERNS = [
    re.compile(r"if\s*\(\s*argc\s*[!=<>]=?\s*\d"),
    re.compile(r"argv\s*\[\s*1\s*\]"),
    re.compile(r"argv\s*\[\s*\d+\s*\]"),
    # Ghidra-style: param_1 == 2 (argc check) or param_2[1] (argv access)
    re.compile(r"if\s*\(\s*param_1\s*[!=]=\s*2\s*\)"),
    re.compile(r"param_2\s*\[\s*\d+\s*\]"),
    # Ghidra: *(param_2 + 8) or *(long *)(param_2 + 8) for argv[1]
    re.compile(r"\*\s*\(?(?:long\s*\*\s*\)?\s*\()?\s*param_2\s*\+\s*\d"),
]

_STDIN_PATTERNS = [
    re.compile(r"fgets\s*\("),
    re.compile(r"scanf\s*\("),
    re.compile(r"read\s*\(\s*0\s*,"),
    re.compile(r"__isoc99_scanf"),
    re.compile(r"getline\s*\("),
    re.compile(r"gets\s*\("),
    re.compile(r"fread\s*\("),
]


def _detect_input_mode(main_code: str, all_code: str) -> str:
    """Return 'arg', 'stdin', or 'unknown'."""
    # Prefer main() for input detection, fall back to all code
    for code in (main_code, all_code) if main_code else (all_code,):
        has_argv = any(p.search(code) for p in _ARGV_PATTERNS)
        has_stdin = any(p.search(code) for p in _STDIN_PATTERNS)
        if has_argv and not has_stdin:
            return "arg"
        if has_stdin and not has_argv:
            return "stdin"
        if has_argv and has_stdin:
            # Both present -- argv is more likely the primary input path
            return "arg"
    return "unknown"


# ---------------------------------------------------------------------------
# Input length detection
# ---------------------------------------------------------------------------

def _detect_input_length(main_code: str, all_code: str) -> int | None:
    """Try to extract the expected input length from strlen checks or loops."""
    for code in (main_code, all_code) if main_code else (all_code,):
        # strlen(x) == N  or  strlen(x) != N  (direct comparison)
        m = re.search(r"strlen\s*\([^)]+\)\s*[!=]=\s*(\d+)", code)
        if m:
            return int(m.group(1))

        # Indirect: var = strlen(...); ... if (var != N)
        # Find strlen assignment variable, then match comparison on it
        strlen_match = re.search(
            r"(\w+)\s*=\s*strlen\s*\(", code
        )
        if strlen_match:
            var = re.escape(strlen_match.group(1))
            m = re.search(
                rf"(?:if\s*\(\s*)?{var}\s*[!=]=\s*(\d+)", code
            )
            if m:
                val = int(m.group(1))
                if 1 <= val <= 1024:
                    return val
            # Hex variant for the same variable
            m = re.search(
                rf"{var}\s*[!=]=\s*0x([0-9a-fA-F]+)", code
            )
            if m:
                return int(m.group(1), 16)

        # Ghidra-style: sVar1 != 0x1b  (hex comparison -- check hex BEFORE decimal)
        m = re.search(r"sVar\d+\s*[!=]=\s*0x([0-9a-fA-F]+)", code)
        if m:
            return int(m.group(1), 16)

        # Ghidra-style: sVar1 == 27  (decimal, only if no hex match)
        m = re.search(r"sVar\d+\s*[!=]=\s*(\d+)", code)
        if m:
            val = int(m.group(1))
            if val > 0:
                return val

        # Hex length comparison: if (var != 0x1b)
        m = re.search(
            r"if\s*\(\s*\w+\s*[!=]=\s*0x([0-9a-fA-F]+)\s*\)", code
        )
        if m:
            val = int(m.group(1), 16)
            # Only consider plausible lengths (4..256)
            if 4 <= val <= 256:
                return val

    # Fallback: loop bound in main
    lb = _detect_loop_bound(main_code, all_code)
    return lb


# ---------------------------------------------------------------------------
# Loop bound detection
# ---------------------------------------------------------------------------

def _detect_loop_bound(main_code: str, all_code: str) -> int | None:
    """Extract the most common / first for-loop upper bound."""
    for code in (main_code, all_code) if main_code else (all_code,):
        matches = re.findall(r"for\s*\([^;]+;\s*\w+\s*<\s*(\d+)", code)
        if matches:
            # Return the first reasonable bound
            for raw in matches:
                val = int(raw)
                if 1 <= val <= 10000:
                    return val
        # Hex variant
        matches = re.findall(
            r"for\s*\([^;]+;\s*\w+\s*<\s*0x([0-9a-fA-F]+)", code
        )
        if matches:
            for raw in matches:
                val = int(raw, 16)
                if 1 <= val <= 10000:
                    return val
    return None


# ---------------------------------------------------------------------------
# Success / fail string detection
# ---------------------------------------------------------------------------

def _find_output_strings(code: str) -> list[str]:
    """Return all literal strings inside puts() / printf() calls."""
    results: list[str] = []
    for m in re.finditer(r'puts\s*\(\s*"([^"]+)"\s*\)', code):
        results.append(m.group(1))
    for m in re.finditer(r'printf\s*\(\s*"([^"]+)"', code):
        results.append(m.group(1))
    return results


def _detect_success_string(all_code: str, strings: list[str]) -> str | None:
    """Find the most likely success output string.

    Prioritises strong indicators (correct, success, congratulations) over
    weaker ones (good, win, right) to avoid false positives on usage text.
    """
    code_strings = _find_output_strings(all_code)
    all_candidates = code_strings + strings

    # First pass: strong positive keywords
    for s in all_candidates:
        if _STRONG_POSITIVE.search(s):
            return s
    # Second pass: weaker positive keywords
    for s in all_candidates:
        if _WEAK_POSITIVE.search(s):
            return s
    return None


def _detect_fail_string(all_code: str, strings: list[str]) -> str | None:
    """Find the most likely failure output string."""
    code_strings = _find_output_strings(all_code)
    all_candidates = code_strings + strings

    for s in all_candidates:
        if _NEGATIVE_WORDS.search(s):
            return s
    return None


# ---------------------------------------------------------------------------
# Flag format prefix
# ---------------------------------------------------------------------------

_FLAG_PREFIX_RE = re.compile(r"([A-Za-z0-9_]+\{)")


def _detect_flag_prefix(strings: list[str]) -> str | None:
    """Detect flag format prefix like 'CTF{', 'flag{', 'vere{' etc."""
    for s in strings:
        m = _FLAG_PREFIX_RE.search(s)
        if m:
            return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Key constants
# ---------------------------------------------------------------------------

def _extract_key_constants(all_code: str) -> list[int]:
    """Extract hex literals from XOR/arithmetic operations."""
    raw = re.findall(r"[\^+\-]\s*0x([0-9a-fA-F]+)", all_code)
    seen: set[int] = set()
    result: list[int] = []
    for h in raw:
        val = int(h, 16)
        if val not in seen:
            seen.add(val)
            result.append(val)
    return result


# ---------------------------------------------------------------------------
# strcmp / comparison target
# ---------------------------------------------------------------------------

def _detect_strcmp(all_code: str) -> bool:
    """Check if the code calls strcmp / memcmp / strncmp."""
    return bool(
        re.search(r"\b(?:strcmp|memcmp|strncmp)\s*\(", all_code)
    )


def _extract_comparison_target(all_code: str) -> str | None:
    """Extract the string literal compared via strcmp/memcmp/strncmp."""
    m = re.search(
        r'(?:strcmp|memcmp|strncmp)\s*\([^,]+,\s*"([^"]*)"', all_code
    )
    if m:
        return m.group(1)
    # Try reversed argument order: strcmp("literal", var)
    m = re.search(
        r'(?:strcmp|memcmp|strncmp)\s*\(\s*"([^"]*)"', all_code
    )
    if m:
        return m.group(1)
    return None


# ---------------------------------------------------------------------------
# Crypto indicators
# ---------------------------------------------------------------------------

def _detect_crypto_indicators(all_code: str) -> list[str]:
    """Identify cryptographic patterns in the code."""
    indicators: list[str] = []

    # XOR on byte arrays (^ operator with byte-level context)
    if re.search(r"\^\s*0x[0-9a-fA-F]{1,2}\b", all_code) or re.search(
        r"\w+\s*\[\s*\w+\s*\]\s*\^", all_code
    ):
        indicators.append("xor")

    # Base64 detection
    if re.search(
        r"(?:base64|ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/)",
        all_code,
    ) or re.search(r"\bbase64\b", all_code, re.IGNORECASE):
        indicators.append("base64")

    # Caesar / ROT: addition/subtraction with modulo 26
    if re.search(r"%\s*26\b", all_code) or re.search(
        r"%\s*0x1a\b", all_code
    ):
        indicators.append("caesar")

    # Substitution table: large array of bytes used for lookup
    if re.search(r"\w+\s*\[\s*\w+\s*\[\s*\w+\s*\]\s*\]", all_code):
        indicators.append("substitution")

    # RC4: S-box initialisation pattern (256-element loop + swap)
    if re.search(r"for\s*\([^;]+;\s*\w+\s*<\s*256", all_code) and re.search(
        r"swap|temp\s*=", all_code, re.IGNORECASE
    ):
        indicators.append("rc4")

    # AES indicators
    if re.search(r"(?:SubBytes|MixColumns|ShiftRows|AddRoundKey)", all_code):
        indicators.append("aes")

    return indicators


# ---------------------------------------------------------------------------
# Random / srand detection
# ---------------------------------------------------------------------------

def _detect_random(all_code: str) -> bool:
    """Check if srand or rand is used (C source or assembly)."""
    # C source: srand( or rand(
    if re.search(r"\b(?:srand|rand)\s*\(", all_code):
        return True
    # Assembly: call srand@plt, call rand@plt
    if re.search(r"\bcall\s+.*\b(?:srand|rand)(?:@plt)?\b", all_code):
        return True
    return False


def _extract_random_seed(all_code: str) -> int | None:
    """Extract the seed passed to srand() if it's a constant.

    Handles both C source (srand(0x13337)) and assembly (mov edi, 0x13337
    before call srand@plt).
    """
    # C source: srand(0xDEAD) or srand(12345)
    m = re.search(r"srand\s*\(\s*(0x[0-9a-fA-F]+)\s*\)", all_code)
    if m:
        return int(m.group(1), 16)
    m = re.search(r"srand\s*\(\s*(\d+)\s*\)", all_code)
    if m:
        return int(m.group(1))

    # Assembly: backward scan from 'call srand' to find mov with edi/rdi
    # Supports both Intel syntax (mov edi, 0x13337) and AT&T (mov $0x13337,%edi)
    lines = all_code.splitlines()
    for i, line in enumerate(lines):
        if re.search(r"\bcall\s+.*\bsrand(?:@plt)?\b", line):
            # Scan backwards up to 5 lines for mov with edi/rdi
            for j in range(max(0, i - 5), i):
                # Intel syntax: mov edi, 0x13337
                m = re.search(
                    r"\bmov\w*\s+(?:edi|rdi)\s*,\s*\$?(0x[0-9a-fA-F]+)",
                    lines[j],
                )
                if m:
                    return int(m.group(1), 16)
                # AT&T syntax: mov $0x13337,%edi  or  movl $0x13337,%edi
                m = re.search(
                    r"\bmov\w*\s+\$?(0x[0-9a-fA-F]+)\s*,\s*%(?:edi|rdi)",
                    lines[j],
                )
                if m:
                    return int(m.group(1), 16)
                # Intel decimal: mov edi, 12345
                m = re.search(
                    r"\bmov\w*\s+(?:edi|rdi)\s*,\s*\$?(\d+)",
                    lines[j],
                )
                if m:
                    return int(m.group(1))
                # AT&T decimal: mov $12345,%edi
                m = re.search(
                    r"\bmov\w*\s+\$(\d+)\s*,\s*%(?:edi|rdi)",
                    lines[j],
                )
                if m:
                    return int(m.group(1))
    return None


# ---------------------------------------------------------------------------
# Timing indicator detection (for remote timing side-channel challenges)
# ---------------------------------------------------------------------------

def _detect_timing_indicator(all_code: str) -> bool:
    """Detect sleep + input co-occurrence suggesting a timing side-channel.

    Returns True when code contains both a delay function (sleep/usleep/nanosleep)
    and a character-level input function (getchar/read/recv/fgetc).
    """
    has_sleep = bool(re.search(r"\b(?:sleep|usleep|nanosleep)\s*\(", all_code))
    has_char_input = bool(re.search(
        r"\b(?:getchar|fgetc|read|recv|getc)\s*\(", all_code
    ))
    return has_sleep and has_char_input


# ---------------------------------------------------------------------------
# Charset range detection (for brute-force / timing attack charset selection)
# ---------------------------------------------------------------------------

def _detect_charset_range(all_code: str) -> str | None:
    """Detect charset ranges from comparison constants in the code.

    Maps common ASCII ranges to charset names:
        0x61-0x7a / 'a'-'z'  -> lowercase
        0x41-0x5a / 'A'-'Z'  -> uppercase
        0x30-0x39 / '0'-'9'  -> (contributes to alphanum)
        0x20-0x7e             -> printable
    """
    code_lower = all_code

    has_lower = bool(re.search(
        r"(?:0x61|0x7a|'a'|'z'|97\b|122\b)", code_lower
    ))
    has_upper = bool(re.search(
        r"(?:0x41|0x5a|'A'|'Z'|65\b|90\b)", code_lower
    ))
    has_digit = bool(re.search(
        r"(?:0x30|0x39|'0'|'9'|48\b|57\b)", code_lower
    ))
    has_printable = bool(re.search(
        r"(?:0x20|0x7e|32\b|126\b)", code_lower
    ))

    if has_printable:
        return "printable"
    if has_lower and has_upper and has_digit:
        return "alphanum"
    if has_lower and has_upper:
        return "alpha"
    if has_lower:
        return "lowercase"
    if has_upper:
        return "uppercase"
    if has_digit:
        return "hex"

    return None


# ---------------------------------------------------------------------------
# Flag gate detection (boolean variables that gate flag output)
# ---------------------------------------------------------------------------

_FLAG_GATE_PATTERNS = [
    # C-level patterns from decompiled code:
    # var = 0; ... if (var) { print_flag(); }
    # bool found = false; ... found = true; ... if (found) puts(flag);
    re.compile(r"\b(?:found|success|valid|passed|result|ok|done|check|verified|match)\s*=\s*(?:0|false|FALSE)\s*;"),
    # var = 0; later: if (var != 0) or if (var == 1)
    re.compile(r"\b\w+\s*=\s*0\s*;[^}]{0,500}if\s*\(\s*\w+\s*(?:!=\s*0|==\s*1)", re.DOTALL),
    # ECS/game patterns: CanMove, enable, active set to false
    re.compile(r"\b(?:can_move|enabled?|active|alive|running)\s*=\s*(?:0|false)\s*;", re.IGNORECASE),
    # Ghidra-style: local_xx = 0; followed by conditional on same var
    re.compile(r"local_[0-9a-f]+\s*=\s*0\s*;"),
]


def _detect_flag_gate(all_code: str) -> bool:
    """Detect boolean flag-gate patterns in decompiled code.

    Returns True when the code contains patterns suggesting a boolean
    variable is initialized to 0/false and later tested to decide
    whether to print/reveal the flag.
    """
    for pat in _FLAG_GATE_PATTERNS:
        if pat.search(all_code):
            return True
    return False


# ---------------------------------------------------------------------------
# No-user-input detection (binary that doesn't read stdin/argv)
# ---------------------------------------------------------------------------

def _detect_no_user_input(main_code: str, all_code: str) -> bool:
    """Return True if the binary appears to take NO user input.

    Binaries that don't read input but contain flag-related logic are
    candidates for flag-gate patching (patch a boolean and run).
    """
    has_argv = any(p.search(all_code) for p in _ARGV_PATTERNS)
    has_stdin = any(p.search(all_code) for p in _STDIN_PATTERNS)
    return not has_argv and not has_stdin
