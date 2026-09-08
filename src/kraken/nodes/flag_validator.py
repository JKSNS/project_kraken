"""Flag validator node -- deterministic regex match against flag_format.

This node checks the most recent solve script output for the flag pattern.
Routes to END on success, or back into the retry loop on failure.

Enhancement: checks output files for flag (#8).
Enhancement: detects hardcoded flag hallucinations in script source (#8).
Enhancement: runs failure diagnosis and script findings extraction (#1, #2).
"""

from __future__ import annotations

import asyncio
import glob
import os
import re

from kraken.state import KrakenState
from kraken.config import BudgetConfig
from kraken.nodes.failure_analysis import diagnose_failure, extract_script_findings
from kraken.logging.structured import get_logger
from kraken.storage.ledger import append_ledger_entry

log = get_logger(__name__)

# Common file paths where scripts might write flags
_FLAG_FILE_GLOBS = [
    "/tmp/flag*",
    "/tmp/output*",
    "/tmp/result*",
    "./flag*",
    "./output*",
]

# Broad fallback patterns used when flag_format is an invalid regex
_FALLBACK_FLAG_PATTERNS = [
    r"\w+\{[^\}]+\}",         # generic: word{content}
    r"flag\{[^\}]+\}",        # common CTF format
    r"ctf\{[^\}]+\}",         # CTF-specific
    r"[A-Z]{3,}\{[^\}]+\}",  # UPPERCASE{content}
]


_COMMON_FLAG_PATTERNS = [
    r"picoCTF\{[^\}]{2,200}\}",
    r"flag\{[^\}]{2,200}\}",
    r"FLAG\{[^\}]{2,200}\}",
    r"uiuctf\{[^\}]{2,200}\}",
    r"ctf\{[^\}]{2,200}\}",
    r"CTF\{[^\}]{2,200}\}",
    r"HTB\{[^\}]{2,200}\}",
    r"CSAW\{[^\}]{2,200}\}",
    r"DUCTF\{[^\}]{2,200}\}",
    r"DEAD\{[^\}]{2,200}\}",
    r"TUCTF\{[^\}]{2,200}\}",
    r"hack\{[^\}]{2,200}\}",
    r"HACK\{[^\}]{2,200}\}",
    r"SEC\{[^\}]{2,200}\}",
    r"OSCTF\{[^\}]{2,200}\}",
    r"vere\{[^\}]{2,200}\}",
    r"VERE\{[^\}]{2,200}\}",
]


# ── Runtime noise prefixes ──────────────────────────────────────────
# Prefixes that look like flag{} format but come from binary metadata,
# compiler internals, or language runtime strings -- never valid CTF flags.
_RUNTIME_NOISE_PREFIXES = {
    # Rust internals
    "rspunycode", "rustc", "rustup", "cargo", "clippy",
    "libcore", "liballoc", "libstd", "librustc", "libtest",
    # LLVM / DWARF / debug internals
    "llvm", "gimli", "dwarf", "debug", "debuginfo",
    # Go internals
    "goarch", "goos", "goroot", "gopath", "gomod",
    "runtime", "syscall",
    # C/C++ internals
    "glibc", "libgcc", "libstdc", "libasan", "libtsan", "libubsan",
    "cxxabi", "gnulib",
    # Linker / ELF metadata
    "elfdata", "elfclass", "elfmag", "elfosabi",
    # Build system artifacts
    "cmake", "autoconf", "automake", "configure",
    # Generic namespace fragments
    "internal", "builtin",
}


def _is_suspicious_low_diversity_flag(flag: str) -> bool:
    """Reject low-entropy candidates that often come from LLM guess drift.

    Example failure mode: ``vere{thpsaaaaaaaaaaaaaaaaaaaaa}``.
    """
    m = re.match(r"^[A-Za-z0-9_\-]{1,32}\{([^}]*)\}$", flag or "")
    if not m:
        return False
    body = m.group(1)
    # Always reject bodies with only 1 unique character (e.g. "^^^^^^^")
    if len(set(body)) <= 1 and len(body) >= 3:
        return True
    if len(body) < 12:
        return False
    # Binary strings (only '0' and '1') are legitimate CTF flags
    if set(body) <= {'0', '1'}:
        return False
    # Hex-only strings are also legitimate (hash outputs, computed values)
    if re.match(r'^[0-9a-fA-F]+$', body):
        return False
    unique_ratio = len(set(body)) / max(1, len(body))
    return unique_ratio <= 0.25


def _is_runtime_noise_flag(candidate: str, flag_format: str = "") -> bool:
    """Reject candidates whose prefix is a known runtime/compiler namespace.

    Binary metadata (Rust punycode, LLVM debug info, Go runtime, etc.) often
    contains strings like ``rspunycode{-}`` that match the generic
    ``prefix{body}`` flag pattern but are never valid CTF flags.

    If a known ``flag_format`` is provided (e.g. ``flag\\{...\\}``), we also
    check whether the candidate's prefix matches the expected one. A mismatch
    combined with a noise prefix is a definite reject.
    """
    m = re.match(r"^([A-Za-z0-9_\-]+)\{", candidate or "")
    if not m:
        return False
    prefix = m.group(1).lower()

    # Direct match against known noise prefixes
    if prefix in _RUNTIME_NOISE_PREFIXES:
        return True

    # If we know the expected flag prefix, reject noise-like prefixes that
    # don't match it. Extract expected prefix from flag_format.
    if flag_format:
        fmt_m = re.match(r"([A-Za-z0-9_]+)", flag_format)
        if fmt_m:
            expected_prefix = fmt_m.group(1).lower()
            if prefix != expected_prefix and prefix in _RUNTIME_NOISE_PREFIXES:
                return True  # already covered above, but explicit for clarity

    return False


def _normalized_flag_pattern(flag_format: str) -> str:
    r"""Normalize weak placeholder formats into a usable strict regex.

    Example: ``vere{}`` -> ``vere\{[A-Za-z0-9_]{4,200}\}``
    """
    if not flag_format:
        return r"flag\{[^}]{4,200}\}"

    if "{}" in flag_format:
        prefix = flag_format.split("{}", 1)[0]
        prefix = re.escape(prefix)
        return rf"{prefix}\{{[^}}]{{4,200}}\}}"

    return flag_format


def _is_likely_printable_flag(flag: str) -> bool:
    """Heuristic guard against mojibake/garbage flag candidates.

    Accept only flags composed of printable ASCII bytes (32..126).
    """
    if not flag:
        return False
    return all(32 <= ord(ch) <= 126 for ch in flag)


def _is_likely_ctf_body(flag: str, flag_format: str = "") -> bool:
    """Heuristic guard for malformed candidates while staying category-agnostic.

    Accept printable flags with a single brace-pair and body length bounds.
    Reject nested-brace artifacts like ``vere{vere{...}``.
    Also accept braceless flags (hex strings, base64, etc.) when the flag_format
    itself does not require braces.
    """
    # Check if flag_format requires braces -- if not, accept braceless flags
    format_has_braces = "{" in (flag_format or "")

    # Try standard prefix{body} format first
    m = re.match(r"^[A-Za-z0-9_\-]{1,32}\{([^}]*)\}$", flag)
    if m:
        body = m.group(1)
        if not (1 <= len(body) <= 200):
            return False
        if "{" in body or "}" in body:
            return False
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in body):
            return False
        return True

    # If flag_format doesn't require braces, accept braceless printable flags
    if not format_has_braces:
        if not (4 <= len(flag) <= 200):
            return False
        if any(ord(ch) < 32 or ord(ch) > 126 for ch in flag):
            return False
        # Accept hex strings, base64, alphanumeric strings
        if re.match(r"^[A-Za-z0-9+/=_\-]+$", flag):
            return True

    return False


def _looks_like_binary_success(output: bytes) -> bool | None:
    text = (output or b"").lower()
    if not text:
        return None
    positive = [b"correct", b"congrat", b"success", b"you win", b"well done", b"access granted", b"flag"]
    negative = [b"wrong", b"invalid", b"incorrect", b"try again", b"nope", b"failed", b"access denied"]
    if any(p in text for p in positive):
        return True
    if any(n in text for n in negative):
        return False
    return None


def _extract_flag_candidate(stdout: str, stderr: str, flag_format: str) -> tuple[str | None, str]:
    """Multi-pass flag extraction with deterministic provenance."""
    # Pass 1: strict challenge regex in stdout/stderr
    m = _safe_search(flag_format, stdout)
    if m:
        return m.group(0), "strict_stdout"
    m = _safe_search(flag_format, stderr)
    if m:
        return m.group(0), "strict_stderr"

    # Pass 2: common CTF formats
    combined = f"{stdout}\n{stderr}"
    for pat in _COMMON_FLAG_PATTERNS:
        m = _safe_search(pat, combined)
        if m:
            return m.group(0), f"common:{pat}"

    # Pass 3: brace token heuristic for prefixless/variant formats
    for m in re.finditer(r"[A-Za-z0-9_\-]{0,20}\{[^}]{4,200}\}", combined):
        token = m.group(0)
        if 6 <= len(token) <= 220:
            return token, "brace_heuristic"

    return None, "none"


def _preview(text: str, limit: int = 240) -> str:
    compact = " ".join((text or "").split())
    return compact[:limit]


def _safe_search(pattern: str, text: str) -> re.Match | None:
    """Try re.search(pattern, text). Falls back through _FALLBACK_FLAG_PATTERNS on re.error."""
    try:
        return re.search(pattern, text)
    except re.error as e:
        log.warning("flag_validator_bad_regex", pattern=pattern[:80], error=str(e))
        for fallback in _FALLBACK_FLAG_PATTERNS:
            try:
                m = re.search(fallback, text)
                if m:
                    log.info("flag_validator_fallback_matched", fallback=fallback)
                    return m
            except re.error:
                continue
    return None


def _safe_finditer(pattern: str, text: str):
    """Try re.finditer(pattern, text). Falls back to empty iterator on re.error."""
    try:
        yield from re.finditer(pattern, text)
    except re.error as e:
        log.warning("flag_validator_bad_regex_finditer", pattern=pattern[:80], error=str(e))
        for fallback in _FALLBACK_FLAG_PATTERNS:
            try:
                yield from re.finditer(fallback, text)
                return
            except re.error:
                continue


def _check_output_files(flag_format: str) -> str | None:
    """Check common output file locations for the flag (#8)."""
    for pattern in _FLAG_FILE_GLOBS:
        for path in glob.glob(pattern):
            try:
                content = open(path, "r", errors="replace").read(4096)
                match = _safe_search(flag_format, content)
                if match:
                    return match.group(0)
            except (OSError, IOError):
                continue
    return None


async def _verify_flag_with_binary(
    binary_path: str,
    flag_candidate: str,
    timeout: int = 8,
) -> bool | None:
    """Run the binary with flag_candidate as stdin to see if it's accepted.

    Returns:
        True  -- binary printed positive confirmation (correct/success/win…)
        False -- binary printed rejection (wrong/invalid/incorrect…)
        None  -- inconclusive (timeout, crash, no clear signal, or non-executable)

    This is used to detect red-herring flag strings embedded in the binary that
    the LLM might submit directly without computing the real answer.
    """
    if not binary_path or not os.path.isfile(binary_path):
        return None
    if not os.access(binary_path, os.X_OK):
        return None  # Not executable, skip
    # Only verify against native ELF binaries -- skip PE (.exe), Java, etc.
    try:
        with open(binary_path, "rb") as _f:
            _magic = _f.read(4)
        if _magic[:2] == b"MZ":  # PE/Windows executable (.exe/.dll)
            return None
        if _magic != b"\x7fELF":  # Not a native ELF binary
            return None
    except OSError:
        return None

    _POSITIVE = [b"correct", b"congratulation", b"success", b"you win",
                 b"flag is", b"well done", b"right answer", b"access granted"]
    _NEGATIVE = [b"wrong", b"invalid", b"incorrect", b"try again",
                 b"bad flag", b"nope", b"failed", b"access denied"]

    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=flag_candidate.encode() + b"\n"),
            timeout=timeout,
        )
        combined = (stdout + stderr).lower()
        verdict = _looks_like_binary_success(combined)
        if verdict is True:
            return True
        if verdict is False:
            return False
        # Non-zero exit without explicit negative words is inconclusive, not rejection.
        # Many binaries crash or segfault on unexpected input format.
        return None
    except asyncio.TimeoutError:
        if proc is not None and proc.returncode is None:
            proc.kill()
            try:
                await proc.communicate()
            except Exception:
                pass
        return None
    except (OSError, PermissionError):
        return None
    except Exception as exc:
        log.debug("flag_verify_binary_error", error=str(exc))
        return None


def _detect_hallucinated_flag(code: str, flag_format: str) -> bool:
    """Detect if the script hardcodes a flag-format string literal (#8).

    Returns True if the script contains a string matching the flag format
    in a string literal context (quotes), which indicates the LLM
    hallucinated the flag rather than computing it.

    Exception: scripts that use subprocess/angr/z3/external tools are likely
    computing the flag, not hallucinating it. In this case the flag appearing
    as a string literal may be the script printing a computed result.
    """
    code_lower = code.lower()
    # Scripts using external tools or solvers are computing, not hallucinating
    computation_indicators = [
        "subprocess", "angr", "claripy", "z3.", "z3.Solver",
        "popen", "os.system", "run(", "check_output",
        "Popen", "communicate(", "auto_angr",
        # Common computation in LLM-generated solvers
        "open(", "chr(", "ord(", "struct.",
        "base64", "binascii", "hashlib",
        "decode(", "encode(",
        "bytes.fromhex", "bytearray(",
        # Crypto and CTF libraries
        "Crypto", "AES", "DES", "pwn", "pwntools",
        "sympy", "ctypes", "numpy",
        "xor", "decrypt", "encrypt", "cipher",
    ]
    if any(ind in code for ind in computation_indicators):
        return False

    # Look for flag-format strings inside string literals
    for match in _safe_finditer(flag_format, code):
        flag_candidate = match.group(0)
        pos = match.start()
        # Check if it's inside a string literal (preceded by a quote)
        before = code[max(0, pos - 5):pos]
        if any(q in before for q in ['"', "'", 'b"', "b'"]):
            # Exception: if it's in a comment, format string, or regex pattern
            line_start = code.rfind("\n", 0, pos)
            line = code[line_start:pos] if line_start != -1 else code[:pos]
            if "#" in line or "re." in line or "regex" in line or "pattern" in line or "format" in line:
                continue
            log.warning("flag_hallucination_detected")
            return True
    return False


async def flag_validator(state: KrakenState) -> dict:
    """Check if the latest solve attempt captured the flag."""
    flag_format = state.get("flag_format", r"flag\{[a-zA-Z0-9_]+\}")
    flag_pattern = _normalized_flag_pattern(flag_format)
    solve_scripts = state.get("solve_scripts", [])

    # Check tool_flag_candidate from the tool_router before checking solve_scripts
    tool_candidate = state.get("tool_flag_candidate", "")
    if tool_candidate:
        if (_is_likely_printable_flag(tool_candidate)
                and _is_likely_ctf_body(tool_candidate, flag_format)
                and not _is_suspicious_low_diversity_flag(tool_candidate)
                and not _is_runtime_noise_flag(tool_candidate, flag_format)):
            log.info("flag_found_from_tool_router", flag=tool_candidate)
            return _success_result(tool_candidate, "Flag extracted by deterministic tool cascade", state=state)
        else:
            log.warning("tool_flag_candidate_rejected", candidate=tool_candidate)

    if not solve_scripts:
        log.warning("flag_validator_no_scripts")
        return {
            "next_node": "manager",
            "recent_actions": [{
                "action": "flag_validator",
                "reasoning": "No solve scripts to validate",
                "result_summary": "FAIL: no scripts executed",
            }],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    latest = state.get("current_attempt") or solve_scripts[-1]
    stdout = latest.get("stdout", "")
    stderr = latest.get("stderr", "")
    exit_code = latest.get("exit_code", 1)
    code = latest.get("code", "")

    # Helper: check if flag candidate is suspicious (static string in binary → possible red herring)
    binary_path_val = state.get("challenge_path", "") or ""
    strings_of_interest = state.get("strings_of_interest", []) or []
    _red_herring_flag: str | None = None  # set if we confirmed and rejected a red herring
    rejected_candidate_reason: str = ""

    async def _is_red_herring(flag_candidate: str) -> bool:
        """Return True if flag looks like a red herring and binary confirms rejection."""
        in_static_strings = any(flag_candidate in str(s) for s in strings_of_interest)
        if not in_static_strings:
            return False
        log.info("flag_in_static_strings", hint="possible red herring")
        verified = await _verify_flag_with_binary(binary_path_val, flag_candidate)
        if verified is False:
            log.warning("flag_red_herring_confirmed")
            return True
        return False

    async def _binary_accepts(flag_candidate: str) -> bool | None:
        """Check candidate directly against challenge binary when executable.

        This is stricter than red-herring checks: we use it for *any* extracted
        candidate to avoid accepting near-miss strings that happen to match the
        regex but are rejected by the binary.
        """
        verified = await _verify_flag_with_binary(binary_path_val, flag_candidate)
        if verified is False:
            log.warning("flag_candidate_rejected_by_binary")
        elif verified is True:
            log.info("flag_candidate_accepted_by_binary")
        return verified

    log.info(
        "flag_validator_attempt_io",
        attempt=latest.get("attempt_num", "?"),
        exit_code=exit_code,
        stdout_len=len(stdout),
        stderr_len=len(stderr),
        stdout_head=_preview(stdout[:800]),
        stdout_tail=_preview(stdout[-800:]),
        stderr_head=_preview(stderr[:800]),
        stderr_tail=_preview(stderr[-800:]),
    )

    flag, source = _extract_flag_candidate(stdout, stderr, flag_pattern)
    if flag:
        if not _is_likely_printable_flag(flag):
            rejected_candidate_reason = "candidate contains non-printable bytes"
            log.warning("flag_validator_rejecting_non_printable", source=source)
            flag = None
        elif not _is_likely_ctf_body(flag, flag_format):
            rejected_candidate_reason = "candidate appears malformed (nested braces or invalid body structure)"
            log.warning("flag_validator_rejecting_malformed", source=source)
            flag = None
        elif _is_suspicious_low_diversity_flag(flag):
            rejected_candidate_reason = "candidate appears low-diversity and likely guessed instead of computed"
            log.warning("flag_validator_rejecting_low_diversity", source=source)
            flag = None
        elif _is_runtime_noise_flag(flag, flag_format):
            rejected_candidate_reason = "candidate prefix is a known runtime/compiler namespace, not a CTF flag"
            log.warning("flag_validator_rejecting_runtime_noise", source=source, flag=flag)
            flag = None

    if flag:
        # Verify it's not a hallucinated flag from source code
        if code and flag in code and _detect_hallucinated_flag(code, re.escape(flag)):
            # Hallucination suspected -- verify with binary before rejecting
            binary_override = await _binary_accepts(flag)
            if binary_override is True:
                log.info("hallucination_overridden_by_binary", flag=flag)
                return _success_result(flag, f"Flag from {source}, confirmed by binary despite hallucination suspicion", state=state)
            elif binary_override is False:
                # Binary explicitly rejected -- this IS a hallucination
                log.warning("flag_validator_rejecting_hallucinated", source=source)
                # Fall through to retry -- treat as failure
            else:
                # binary_override is None (inconclusive) -- binary can't confirm or deny.
                # For crypto/encoding challenges the flag is computed output, not input,
                # so binary verification will always be inconclusive.  Accept the flag.
                log.info("hallucination_accepted_inconclusive_binary", flag=flag)
                return _success_result(flag, f"Flag from {source}, accepted (binary verification inconclusive)", state=state)
        else:
            if await _is_red_herring(flag):
                _red_herring_flag = flag  # track for diagnosis
            else:
                binary_verdict = await _binary_accepts(flag)
                if binary_verdict is False:
                    _red_herring_flag = flag
                else:
                    log.info("flag_found", attempt=latest.get("attempt_num", "?"), source=source)
                    return _success_result(flag, f"Flag extracted from {source}", state=state)

    # Check output files (#8)
    file_flag = _check_output_files(flag_pattern)
    if file_flag:
        if _is_likely_printable_flag(file_flag) and _is_likely_ctf_body(file_flag, flag_format):
            binary_verdict = await _binary_accepts(file_flag)
            if binary_verdict is not False:
                log.info("flag_found_file")
                return _success_result(file_flag, "Flag regex matched in output file", state=state)

    # ── Failure path: run diagnosis and extract findings (#1, #2) ────

    # Detect nested-brace malformed candidate patterns even when strict regex misses.
    if not rejected_candidate_reason:
        nested = re.search(r"([A-Za-z0-9_\-]{1,32})\{[A-Za-z0-9_\-]{1,32}\{[^}]{1,200}\}", f"{stdout}\n{stderr}")
        if nested:
            rejected_candidate_reason = "candidate appears malformed (nested brace token detected)"

    # Diagnose the failure
    diagnosis = diagnose_failure(stdout, stderr, exit_code)
    if stdout.strip() and "[empty_output]" in diagnosis:
        diagnosis = diagnosis.replace("[empty_output]", "[stdout_present]")

    # Override diagnosis if we rejected an obviously malformed candidate.
    if rejected_candidate_reason:
        diagnosis = (
            "[malformed_flag_candidate] Extracted a brace-matching token that is structurally invalid. "
            f"Reason: {rejected_candidate_reason}. "
            "Do not reuse prior candidate text. Recompute from validation logic or helper outputs and ensure exactly one prefix{body} pair."
        )

    # Override diagnosis if we detected and rejected a red herring
    if _red_herring_flag:
        append_ledger_entry(
            state.get("solve_ledger_path", ""),
            "> RED HERRING DETECTED: A previously extracted token matched format but was rejected by binary behavior. Do not reuse it.",
        )
        diagnosis = (
            "RED HERRING DETECTED: A flag-format candidate was found in stdout "
            f"but it also exists as a static string in the binary AND the binary rejected it when "
            f"submitted as input. This is a deliberate decoy embedded in the binary. "
            f"DO NOT submit it again. REVERSE the actual algorithm -- compute the real flag "
            f"mathematically from the decompiled logic instead of reading strings."
        )

    # Extract intermediate findings from script output
    findings = extract_script_findings(stdout, stderr)
    if rejected_candidate_reason:
        findings.append(
            "Previous candidate was malformed (nested braces/invalid structure). On next attempt, validate exact prefix and produce one brace pair only."
        )

    # Determine retry vs escalate
    current_strategy_attempts = sum(
        1 for s in solve_scripts
        if s.get("strategy") == state.get("current_strategy")
    )
    budget_cfg = BudgetConfig()
    max_self_corrections = budget_cfg.max_self_corrections

    if current_strategy_attempts < max_self_corrections:
        route = "solve_engine"
        reason = f"Self-correction attempt {current_strategy_attempts}/{max_self_corrections}"
    else:
        route = "manager"
        reason = f"Exhausted {max_self_corrections} self-corrections, escalating to manager"

    log.info(
        "flag_not_found",
        exit_code=exit_code,
        stdout_len=len(stdout),
        stderr_len=len(stderr),
        route=route,
        diagnosis=diagnosis[:200] if diagnosis else "none",
        findings_count=len(findings),
    )

    # ── Track rejected flags for hallucination loop detection ──────
    new_rejected: list[str] = []
    if flag:
        new_rejected.append(flag)
    if _red_herring_flag and _red_herring_flag not in new_rejected:
        new_rejected.append(_red_herring_flag)

    # Detect hallucination loop: same flag submitted 2+ times
    prev_rejected = state.get("rejected_flags", []) or []
    all_rejected = prev_rejected + new_rejected
    if flag and all_rejected.count(flag) >= 2:
        repeat_count = all_rejected.count(flag)
        diagnosis = (
            f"[hallucination_loop] You have submitted '{flag}' {repeat_count} times and it was REJECTED every time. "
            f"This flag is WRONG -- stop generating it. You are hallucinating this value. "
            f"MANDATORY: Use a completely different approach. Read the source files carefully, "
            f"execute the challenge code using subprocess, or reverse the algorithm step by step. "
            f"DO NOT guess or make up flag values."
        )
        append_ledger_entry(
            state.get("solve_ledger_path", ""),
            f"> HALLUCINATION LOOP: '{flag}' rejected {repeat_count} times. Forcing strategy pivot.",
        )
        # Force escalation to manager for strategy pivot on 3+ repeats
        if repeat_count >= 3:
            route = "manager"
            reason = f"Hallucination loop detected: '{flag}' rejected {repeat_count} times, forcing manager pivot"

    updates: dict = {
        "next_node": route,
        "rejected_flags": new_rejected,
        "error_log": [{
            "node": "flag_validator",
            "error": f"Flag not found. exit={exit_code}, stdout={stdout[:200]}, stderr={stderr[:200]}",
            "strategy": state.get("current_strategy", ""),
            "attempt": current_strategy_attempts,
        }],
        "recent_actions": [{
            "action": "flag_validator",
            "reasoning": reason,
            "result_summary": f"FAIL: exit={exit_code}, no flag match. Route → {route}",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }

    # Inject failure diagnosis for self-correction (#1)
    if diagnosis:
        updates["failure_diagnosis"] = diagnosis

    # Inject script findings for next attempt (#2)
    if findings:
        updates["script_findings"] = findings

    # --- RAG: Record failure trajectory when escalating to manager ---
    if route == "manager":
        try:
            from kraken.knowledge.trajectory import TrajectoryStore
            _traj = TrajectoryStore()
            failure_type = "unknown"
            if isinstance(diagnosis, dict):
                failure_type = diagnosis.get("type", "unknown")
            elif isinstance(diagnosis, str) and diagnosis:
                # Extract a short failure type from the diagnosis string
                if "hallucination_loop" in diagnosis:
                    failure_type = "hallucination_loop"
                elif "RED HERRING" in diagnosis:
                    failure_type = "red_herring"
                elif "malformed_flag" in diagnosis:
                    failure_type = "malformed_flag"
                else:
                    failure_type = "exhausted_retries"
            _traj.record_failure(state, failure_type=failure_type)
            log.info("trajectory_recorded", type="failure", challenge=state.get("challenge_id"))
        except Exception:
            pass  # Qdrant unavailable -- don't break the flow

    return updates


def _success_result(flag: str, reasoning: str, state: dict | None = None) -> dict:
    """Build success return dict.

    When *state* is provided and A/D mode is active, this also triggers
    post-solve hooks:
      1. ExploitBridge -- generate a standalone pwntools exploit script and
         register it with ExploitManager for automated throwing.
      2. TrajectoryStore -- record the solve trajectory to the knowledge base
         for future RAG retrieval.
    """
    result = {
        "flag": flag,
        "next_node": "__end__",
        "recent_actions": [{
            "action": "flag_validator",
            "reasoning": reasoning,
            "result_summary": "SUCCESS: flag extracted and validated",
        }],
    }

    if state is not None:
        # --- Post-solve hook 1: A/D exploit generation ---
        try:
            if state.get("ad_mode") or os.environ.get("KRAKEN_AD_MODE"):
                from kraken.ad.offense.exploit_bridge import ExploitBridge
                from kraken.ad.offense.exploit_manager import ExploitManager

                exploit_dir = state.get("ad_exploit_dir", "./exploits")
                service_name = state.get(
                    "ad_service_name",
                    state.get("challenge_id", "unknown"),
                )
                bridge = ExploitBridge(exploit_dir=exploit_dir)

                # Attach a live ExploitManager so the script is registered
                # for automated throwing immediately.
                manager = ExploitManager(exploit_dir=exploit_dir)
                manager.load_exploits()
                bridge.attach_manager(manager)

                # Build solve result dict in the format ExploitBridge expects
                solve_result = {
                    "flag_found": True,
                    "flag": flag,
                    "solving_tool": _resolve_solving_tool(state),
                    "session": {
                        "extracted_params": state.get("extracted_params", {}),
                        "cascade_results": state.get("tool_cascade_results", []),
                        "challenge_path": state.get("challenge_path", ""),
                    },
                    "params": state.get("extracted_params", {}),
                }

                challenge_id = state.get("challenge_id", "unknown")
                script_name = f"auto_{challenge_id}.py"

                exploit_path = bridge.from_solve_result(
                    solve_result,
                    service_name=service_name,
                    binary_path=state.get("challenge_path", ""),
                    script_name=script_name,
                )
                if exploit_path:
                    log.info(
                        "ad_exploit_generated",
                        path=str(exploit_path),
                        service=service_name,
                    )
        except Exception as e:
            log.warning("ad_exploit_generation_failed", error=str(e))

        # --- Post-solve hook 2: RAG trajectory recording ---
        try:
            from kraken.knowledge.trajectory import TrajectoryStore

            store = TrajectoryStore()
            store.record_solve(state)
            log.info("trajectory_recorded", type="solve", challenge=state.get("challenge_id"))
        except Exception:
            pass  # Qdrant unavailable -- don't break the solve

    return result


def _resolve_solving_tool(state: dict) -> str:
    """Best-effort extraction of the tool name that produced the flag.

    Checks the most recent solve script, tool cascade results, and the
    ``current_strategy`` state field (in that order).
    """
    # 1. Latest solve script may carry the tool name
    scripts = state.get("solve_scripts", [])
    if scripts:
        latest = scripts[-1]
        tool = latest.get("tool", "") or latest.get("strategy", "")
        if tool:
            return tool

    # 2. Last successful tool cascade entry
    cascade = state.get("tool_cascade_results", [])
    if cascade:
        last = cascade[-1]
        tool = last.get("tool", "")
        if tool:
            return tool

    # 3. Fallback to current strategy
    return state.get("current_strategy", "")


def route_from_validator(state: KrakenState) -> str:
    """Conditional edge function for flag_validator output."""
    return state.get("next_node", "manager")
