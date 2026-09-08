"""Codex agentic fallback for hard challenges.

When a challenge exhausts Kraken's normal deterministic pipeline and
solve_engine retries, this module hands the challenge directory to
Codex as a completely independent agentic solver.  Codex reads files,
writes scripts, executes them, iterates -- a fundamentally different
approach from Kraken's "generate one script and run it" loop.

This is NOT model racing (same prompt → multiple models).  It's a
strategy pivot: Kraken's structured pipeline failed, so we let an
unconstrained agent try from scratch with full file access.

USAGE:
    Gated on ``is_codex_fallback_enabled()`` which checks the env var
    ``KRAKEN_ENABLE_CODEX_FALLBACK=1``.

    Programmatically (called from solve_engine escalation path):
        from kraken.execution.racing import codex_fallback, is_codex_fallback_enabled
        if is_codex_fallback_enabled() and not state.get("racing_attempted"):
            result = await codex_fallback(state)
            if result and result.flag:
                ...

    The ``codex:rescue`` skill is also available interactively in
    Claude Code sessions for manual investigation of stuck challenges.

REQUIREMENTS:
    - ``codex`` CLI installed and logged in (subscription-based, no API key)
    - ``codex login`` must have been run in this environment
"""

from __future__ import annotations

import asyncio
import os
import re
import time
from dataclasses import dataclass

from kraken.logging.structured import get_logger

log = get_logger(__name__)


@dataclass
class FallbackResult:
    """Result from a Codex fallback attempt."""
    flag: str | None = None
    stdout: str = ""
    stderr: str = ""
    last_message: str = ""
    exit_code: int = -1
    elapsed: float = 0.0
    error: str | None = None


_codex_logged_in: bool | None = None  # cached after first probe


def _is_codex_available() -> bool:
    """Check if codex CLI is installed and authenticated."""
    global _codex_logged_in
    if _codex_logged_in is not None:
        return _codex_logged_in
    import shutil
    import subprocess
    if not shutil.which("codex"):
        _codex_logged_in = False
        return False
    try:
        result = subprocess.run(
            ["codex", "login", "status"],
            capture_output=True, text=True, timeout=5,
        )
        _codex_logged_in = result.returncode == 0
    except Exception:
        _codex_logged_in = False
    return _codex_logged_in


def is_codex_fallback_enabled() -> bool:
    """Check if Codex fallback is enabled and available."""
    enabled = os.environ.get("KRAKEN_ENABLE_CODEX_FALLBACK", "").lower() in ("1", "true", "yes")
    # Also honor the legacy racing flag
    if not enabled:
        enabled = os.environ.get("KRAKEN_ENABLE_RACING", "").lower() in ("1", "true", "yes")
    if not enabled:
        return False
    return _is_codex_available()


def _extract_flag(output: str, flag_format: str) -> str | None:
    """Extract flag from output using flag format pattern."""
    if not output:
        return None
    if flag_format:
        try:
            m = re.search(flag_format, output)
            if m:
                return m.group(0)
        except re.error:
            pass
    for pat in [r"[A-Za-z0-9_]{2,20}\{[^\}]{4,200}\}", r"flag\{[^\}]+\}"]:
        m = re.search(pat, output)
        if m:
            return m.group(0)
    return None


def _dump_kraken_artifacts(state: dict, challenge_dir: str) -> None:
    """Write Kraken's analysis artifacts to the challenge dir for Codex to read.

    Codex is agentic -- it reads files. By dumping what Kraken already knows
    into the challenge directory, Codex starts with full context instead of
    re-discovering everything from scratch.
    """
    from kraken.storage.artifact_store import get_artifact
    import json

    artifacts_dir = os.path.join(challenge_dir, ".kraken_analysis")
    os.makedirs(artifacts_dir, exist_ok=True)

    # Decompiled functions
    funcs = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    if isinstance(funcs, dict) and funcs:
        with open(os.path.join(artifacts_dir, "decompiled.c"), "w") as f:
            for name, code in funcs.items():
                f.write(f"// {name}\n{code}\n\n")

    # Binary info
    binary_info = state.get("binary_info")
    if isinstance(binary_info, dict) and binary_info:
        with open(os.path.join(artifacts_dir, "binary_info.json"), "w") as f:
            json.dump(binary_info, f, indent=2, default=str)

    # Strings of interest
    strings = state.get("strings_of_interest", [])
    if strings:
        with open(os.path.join(artifacts_dir, "strings.txt"), "w") as f:
            f.write("\n".join(strings[:200]))

    # Extracted parameters
    params = state.get("extracted_params")
    if isinstance(params, dict) and params:
        with open(os.path.join(artifacts_dir, "params.json"), "w") as f:
            json.dump(params, f, indent=2, default=str)

    # Tool results summary
    tool_summary = state.get("tool_results_summary", "")
    if tool_summary:
        with open(os.path.join(artifacts_dir, "tool_results.txt"), "w") as f:
            f.write(tool_summary[:5000])

    # Strategy hypothesis
    hypothesis = state.get("strategy_hypothesis", "")
    if hypothesis:
        with open(os.path.join(artifacts_dir, "hypothesis.txt"), "w") as f:
            f.write(hypothesis)


def _build_codex_prompt(state: dict) -> str:
    """Build a prompt for Codex that leverages its agentic capabilities.

    Codex gets a rich prompt with everything Kraken already discovered,
    plus instructions to take a fundamentally different approach.
    """
    challenge_id = state.get("challenge_id", "unknown")
    challenge_type = state.get("challenge_type", "unknown")
    description = state.get("challenge_description", "")
    flag_format = state.get("flag_format", "flag{...}")

    # What Kraken already tried
    scripts = state.get("solve_scripts", [])
    failure_notes = []
    for s in scripts[-5:]:
        strategy = s.get("strategy", "unknown")
        stderr = (s.get("stderr") or "")[:150]
        if stderr:
            failure_notes.append(f"- {strategy}: {stderr}")
    failures = "\n".join(failure_notes) if failure_notes else "None"

    # What Kraken found (summary)
    findings = []
    if state.get("challenge_type"):
        findings.append(f"Category: {state['challenge_type']}")
    if state.get("strategy_hypothesis"):
        findings.append(f"Hypothesis: {state['strategy_hypothesis'][:200]}")
    bi = state.get("binary_info", {})
    if isinstance(bi, dict) and bi.get("file_type"):
        findings.append(f"Binary: {bi['file_type']}")
    findings_text = "\n".join(findings) if findings else "None"

    return f"""Solve this CTF challenge. The flag format is: {flag_format}

Challenge: {challenge_id}
Category: {challenge_type}
Description: {description}

## What a previous solver already discovered

{findings_text}

Check .kraken_analysis/ for full decompiled code, binary info, extracted
parameters, and tool results from the previous automated analysis.

## What has been tried and FAILED (don't repeat these)

{failures}

## Your task

All challenge files are in the current directory. You have full access to
read files, write scripts, compile code, run binaries, and use any tools.
Try a fundamentally different approach from the failed attempts above.
Print the flag to stdout when found."""


async def codex_fallback(
    state: dict,
    timeout: float = 300.0,
    model: str = "",
) -> FallbackResult:
    """Hand a challenge to Codex as an independent agentic solver.

    Codex gets the challenge directory and full autonomy to read files,
    write scripts, and execute them.  This is a strategy pivot, not
    a retry of the same approach.

    Args:
        state: Current KrakenState dict
        timeout: Max wall-clock time for Codex (default 5 min)
        model: Codex model override (default: Codex's default)

    Returns:
        FallbackResult with flag if found, or diagnostic output
    """
    if not _is_codex_available():
        return FallbackResult(error="Codex not available (not installed or not logged in)")

    challenge_dir = state.get("challenge_dir", state.get("solve_workspace", "/tmp"))
    flag_format = state.get("flag_format", "")

    # Dump Kraken's analysis artifacts so Codex can read them
    try:
        _dump_kraken_artifacts(state, challenge_dir)
    except Exception as e:
        log.warning("codex_fallback_artifact_dump_failed", error=str(e)[:100])

    prompt = _build_codex_prompt(state)

    output_file = os.path.join(challenge_dir, ".codex_fallback_output.txt")

    cmd = [
        "codex", "exec",
        "--dangerously-bypass-approvals-and-sandbox",
        "--ephemeral",
        "-C", challenge_dir,
        "--skip-git-repo-check",
        "-o", output_file,
        "--color", "never",
    ]
    if model:
        cmd.extend(["-m", model])
    cmd.append(prompt)

    log.info("codex_fallback_start", challenge=state.get("challenge_id"), cwd=challenge_dir)
    t0 = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
        stdout = stdout_bytes.decode(errors="replace")[:8000]
        stderr = stderr_bytes.decode(errors="replace")[:3000]
        exit_code = proc.returncode or 0
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - t0
        log.warning("codex_fallback_timeout", elapsed=round(elapsed, 1), timeout=timeout)
        return FallbackResult(error=f"Codex timed out after {timeout}s", elapsed=elapsed)
    except Exception as e:
        elapsed = time.monotonic() - t0
        log.warning("codex_fallback_error", error=str(e))
        return FallbackResult(error=f"Codex failed: {e}", elapsed=elapsed)

    elapsed = time.monotonic() - t0

    # Read Codex's final message
    last_message = ""
    try:
        if os.path.exists(output_file):
            with open(output_file) as f:
                last_message = f.read()[:5000]
            os.unlink(output_file)
    except OSError:
        pass

    # Search all output for flag
    all_output = f"{stdout}\n{stderr}\n{last_message}"
    flag = _extract_flag(all_output, flag_format)

    log.info(
        "codex_fallback_complete",
        flag_found=flag is not None,
        exit_code=exit_code,
        elapsed=round(elapsed, 1),
        stdout_len=len(stdout),
    )

    return FallbackResult(
        flag=flag,
        stdout=stdout[:5000],
        stderr=stderr[:2000],
        last_message=last_message,
        exit_code=exit_code,
        elapsed=elapsed,
    )


# ── Codex Research: learn unfamiliar domains before solving ──────────


@dataclass
class ResearchResult:
    """Result from a Codex research query."""
    knowledge: str = ""       # actionable knowledge (techniques, code snippets, tool usage)
    code_snippets: str = ""   # extracted code blocks ready to use
    elapsed: float = 0.0
    error: str | None = None


async def codex_research(
    query: str,
    context: str = "",
    timeout: float = 120.0,
) -> ResearchResult:
    """Ask Codex to research an unfamiliar domain and return actionable knowledge.

    Unlike codex_fallback (which tries to solve), this asks Codex to LEARN:
    search the web, read documentation, find writeups, and distill the
    knowledge into techniques and code snippets that Kraken's solve_engine
    can use.

    Use cases:
        - Crypto: "How to attack ECDSA with biased nonces using SageMath"
        - Rev: "How to decompile and analyze NixOS derivation files"
        - Pwn: "ret2dlresolve technique for partial RELRO binaries"
        - Misc: "Esoteric language interpreter for Malbolge"

    Args:
        query: What to research (domain, technique, tool usage)
        context: Optional challenge context to focus the research
        timeout: Max research time (default 2 min)

    Returns:
        ResearchResult with distilled knowledge and code snippets
    """
    if not _is_codex_available():
        return ResearchResult(error="Codex not available")

    prompt_parts = [
        "You are a CTF security researcher. Research the following topic and return ACTIONABLE knowledge.",
        "",
        f"## Research Query",
        f"{query}",
    ]

    if context:
        prompt_parts.extend([
            "",
            "## Challenge Context",
            context,
        ])

    prompt_parts.extend([
        "",
        "## What to Return",
        "1. A concise explanation of the technique/domain (2-3 paragraphs max)",
        "2. Working code snippets (Python/SageMath/shell) that demonstrate the technique",
        "3. Key tool commands (e.g., `sage`, `openssl`, `z3`, specific library imports)",
        "4. Common pitfalls and how to avoid them",
        "",
        "Focus on PRACTICAL, COPY-PASTE-READY code. No theory lectures.",
        "If SageMath is needed, show the exact SageMath script.",
        "If a specific library is needed, show the pip install + import + usage.",
    ])

    prompt = "\n".join(prompt_parts)

    import tempfile
    output_file = tempfile.mktemp(suffix=".txt", prefix="codex_research_")

    cmd = [
        "codex", "exec",
        "--dangerously-bypass-approvals-and-sandbox",
        "--ephemeral",
        "--skip-git-repo-check",
        "-o", output_file,
        "--color", "never",
        prompt,
    ]

    log.info("codex_research_start", query=query[:100])
    t0 = time.monotonic()

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
        stdout = stdout_bytes.decode(errors="replace")[:8000]
    except asyncio.TimeoutError:
        elapsed = time.monotonic() - t0
        log.warning("codex_research_timeout", query=query[:60], elapsed=round(elapsed, 1))
        return ResearchResult(error=f"Research timed out after {timeout}s", elapsed=elapsed)
    except Exception as e:
        elapsed = time.monotonic() - t0
        return ResearchResult(error=f"Research failed: {e}", elapsed=elapsed)

    elapsed = time.monotonic() - t0

    # Read the final output
    last_message = ""
    try:
        if os.path.exists(output_file):
            with open(output_file) as f:
                last_message = f.read()[:8000]
            os.unlink(output_file)
    except OSError:
        pass

    knowledge = last_message or stdout

    # Extract code blocks from the knowledge
    code_blocks = re.findall(r"```(?:python|sage|sh|bash)?\s*\n(.*?)```", knowledge, re.DOTALL)
    code_snippets = "\n\n".join(code_blocks) if code_blocks else ""

    log.info(
        "codex_research_complete",
        query=query[:60],
        knowledge_len=len(knowledge),
        code_snippets=len(code_snippets),
        elapsed=round(elapsed, 1),
    )

    return ResearchResult(
        knowledge=knowledge,
        code_snippets=code_snippets,
        elapsed=elapsed,
    )
