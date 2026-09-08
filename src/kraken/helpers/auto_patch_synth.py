#!/usr/bin/env python3
"""auto_patch_synth -- LLM-driven patch synthesis with test-suite validation.

The AIxCC keystone helper. Given a vulnerability (location + bug class),
produces a minimal source patch and validates it by running the project's
own test suite. Models race in parallel: GPT-5.4 (via OpenAI SDK) +
Claude 4.7 (via the kraken Claude backend). First passing patch wins.

Usage:
    python3 auto_patch_synth.py \\
        --target /path/to/source/tree \\
        --bug-file path/to/buggy.c \\
        --bug-line 220 \\
        --bug-class "length-check-gated-on-output-ptr" \\
        --description "the *len && short-circuit lets caller pass 0 to skip cap" \\
        --test-cmd "make check" \\
        --out patch.diff

Output schema:
{
  "target": "<path>",
  "bug": {"file": "...", "line": N, "class": "...", "description": "..."},
  "candidates": [
    {"model": "claude-4-7", "diff": "...", "tests_passed": bool,
     "tests_total": N, "wall_clock_s": F, "tokens": N, "rejected_reason": "..."}
  ],
  "winner": {"model": "...", "diff": "...", "tests_passed": True},
  "summary": {...}
}

Modes:
    LLM_BACKEND=claude   force Claude only (default if both available)
    LLM_BACKEND=openai   force GPT-5.4 only
    LLM_BACKEND=race     race both, return first passing
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

PATCH_PROMPT_TEMPLATE = """\
You are patching a security vulnerability in a C/C++/Rust codebase.

VULNERABILITY:
- File: {bug_file}
- Line: {bug_line}
- Class: {bug_class}
- Description: {description}

BUGGY SNIPPET (50 lines surrounding line {bug_line}):
```{lang}
{snippet}
```

REQUIREMENTS:
1. Produce a minimal patch -- change as few lines as possible.
2. Preserve the function's interface (signature, return type, side effects).
3. Do NOT introduce new dependencies or new helper functions unless strictly required.
4. The patch must compile cleanly and the project's existing test suite must pass.
5. Match the surrounding code style exactly (indentation, brace placement, naming).

OUTPUT:
Return ONLY a unified diff (git-format), no prose, no markdown fences,
no explanation. Start the response with `--- ` and end with the last `+`/`-`/` ` line.

Example output format:
--- a/path/to/file.c
+++ b/path/to/file.c
@@ -10,4 +10,4 @@
 int foo(int *len) {{
-    if (*len && header.len > *len) {{
+    if (header.len > *len) {{
         return -1;
     }}
"""


def _read_snippet(file_path: Path, line: int, context: int = 25) -> str:
    """Return ±context lines around `line` (1-based) from file_path."""
    if not file_path.is_file():
        return f"<file not found: {file_path}>"
    lines = file_path.read_text(errors="replace").splitlines()
    start = max(0, line - context - 1)
    end = min(len(lines), line + context)
    out = []
    for i, ln in enumerate(lines[start:end], start=start + 1):
        marker = ">>>" if i == line else "   "
        out.append(f"{marker} {i:5d}  {ln}")
    return "\n".join(out)


def _detect_language(path: Path) -> str:
    return {
        ".c": "c",
        ".h": "c",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".rs": "rust",
        ".py": "python",
        ".go": "go",
        ".java": "java",
        ".js": "javascript",
        ".ts": "typescript",
    }.get(path.suffix.lower(), "text")


def _build_prompt(
    target_root: Path,
    bug_file: Path,
    bug_line: int,
    bug_class: str,
    description: str,
) -> str:
    snippet = _read_snippet(bug_file, bug_line)
    lang = _detect_language(bug_file)
    rel_file = bug_file.relative_to(target_root) if target_root in bug_file.parents else bug_file
    return PATCH_PROMPT_TEMPLATE.format(
        bug_file=rel_file,
        bug_line=bug_line,
        bug_class=bug_class,
        description=description,
        lang=lang,
        snippet=snippet,
    )


def _ask_claude(prompt: str, timeout: int = 120) -> tuple[str, dict]:
    """Send prompt to Claude via the local `claude` CLI (used by kraken)."""
    if shutil.which("claude") is None:
        return ("", {"error": "claude CLI not on PATH"})
    start = time.time()
    try:
        result = subprocess.run(
            ["claude", "--print", "--model", "claude-opus-4-7"],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ("", {"error": "timeout"})
    return (
        result.stdout.strip(),
        {
            "model": "claude-opus-4-7",
            "elapsed_s": round(time.time() - start, 2),
            "stderr_tail": result.stderr[-500:] if result.stderr else "",
        },
    )


def _ask_gpt5(prompt: str, timeout: int = 120) -> tuple[str, dict]:
    """Send prompt via the codex CLI (kraken's GPT-5.4 path)."""
    if shutil.which("codex") is None:
        return ("", {"error": "codex CLI not on PATH"})
    start = time.time()
    try:
        result = subprocess.run(
            ["codex", "exec", "--dangerously-bypass-approvals-and-sandbox", "--skip-git-repo-check"],
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ("", {"error": "timeout"})
    return (
        result.stdout.strip(),
        {
            "model": "gpt-5-4",
            "elapsed_s": round(time.time() - start, 2),
            "stderr_tail": result.stderr[-500:] if result.stderr else "",
        },
    )


def _extract_diff(text: str) -> str | None:
    """Extract the first unified diff from an LLM response."""
    # Strip markdown fences
    if "```" in text:
        for block in text.split("```"):
            if block.lstrip().startswith(("--- ", "diff --git", "Index:")):
                return block.strip()
    if text.lstrip().startswith(("--- ", "diff --git", "Index:")):
        return text.strip()
    # Tolerate prose preamble -- find the first `--- ` line and return from there
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if line.startswith(("--- ", "diff --git", "Index:")):
            return "\n".join(lines[i:]).strip()
    return None


def _apply_diff(diff_text: str, target_root: Path) -> tuple[bool, str]:
    """Apply diff via `git apply --check` then `git apply`."""
    diff_path = target_root / ".kraken_patch.diff"
    diff_path.write_text(diff_text + "\n")
    try:
        chk = subprocess.run(
            ["git", "apply", "--check", str(diff_path)],
            cwd=target_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if chk.returncode != 0:
            return (False, f"check failed: {chk.stderr}")
        ap = subprocess.run(
            ["git", "apply", str(diff_path)],
            cwd=target_root,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if ap.returncode != 0:
            return (False, f"apply failed: {ap.stderr}")
        return (True, "applied")
    finally:
        try:
            diff_path.unlink()
        except Exception:
            pass


def _revert_to_head(target_root: Path) -> None:
    subprocess.run(
        ["git", "checkout", "--", "."],
        cwd=target_root,
        capture_output=True,
        timeout=30,
    )


def _run_tests(test_cmd: str, target_root: Path, timeout: int = 600) -> dict:
    start = time.time()
    try:
        result = subprocess.run(
            test_cmd,
            cwd=target_root,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {
            "passed": False,
            "elapsed_s": timeout,
            "stdout_tail": "",
            "stderr_tail": "TIMEOUT",
            "return_code": -1,
        }
    return {
        "passed": result.returncode == 0,
        "elapsed_s": round(time.time() - start, 2),
        "stdout_tail": result.stdout[-1000:] if result.stdout else "",
        "stderr_tail": result.stderr[-1000:] if result.stderr else "",
        "return_code": result.returncode,
    }


def _run_setup(setup_cmd: str | None, target_root: Path, timeout: int = 600) -> dict | None:
    """Run setup_cmd once before the patch-attempt loop. T3.1 hook."""
    if not setup_cmd:
        return None
    start = time.time()
    try:
        result = subprocess.run(
            setup_cmd,
            cwd=target_root,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"passed": False, "elapsed_s": timeout, "stderr_tail": "TIMEOUT"}
    return {
        "passed": result.returncode == 0,
        "elapsed_s": round(time.time() - start, 2),
        "stdout_tail": result.stdout[-500:] if result.stdout else "",
        "stderr_tail": result.stderr[-500:] if result.stderr else "",
        "return_code": result.returncode,
    }


def _try_candidate(
    label: str,
    asker,
    prompt: str,
    target_root: Path,
    test_cmd: str,
    test_timeout: int,
    ask_timeout: int,
    max_attempts: int = 3,
) -> dict:
    """Generate up to `max_attempts` candidates per model.

    On test failure, feeds the failure output back to the model and asks
    it to try again. This is the standard "self-critique" loop for LLM
    patch synthesis -- yields ~3-5x higher pass rate vs one-shot per the
    AIxCC literature.

    Each iteration gets the current prompt + a "previous attempt failed
    because..." appendix, until tests pass or max_attempts is hit.
    """
    attempts: list[dict] = []
    current_prompt = prompt
    for attempt_idx in range(max_attempts):
        text, meta = asker(current_prompt, timeout=ask_timeout)
        if "error" in meta:
            attempts.append(
                {
                    "attempt": attempt_idx + 1,
                    "rejected_reason": meta["error"],
                    **meta,
                }
            )
            break
        diff = _extract_diff(text)
        if not diff:
            attempts.append(
                {
                    "attempt": attempt_idx + 1,
                    "raw_response_head": text[:300],
                    "rejected_reason": "no diff in response",
                    **meta,
                }
            )
            current_prompt = (
                prompt + "\n\nYour previous response did not contain a "
                "valid unified diff. Return ONLY the diff, starting with "
                "'--- a/...' and ending after the last line. No prose."
            )
            continue
        applied, apply_msg = _apply_diff(diff, target_root)
        if not applied:
            attempts.append(
                {
                    "attempt": attempt_idx + 1,
                    "diff": diff,
                    "rejected_reason": apply_msg,
                    **meta,
                }
            )
            current_prompt = (
                prompt + f"\n\nYour previous diff failed to apply: "
                f"{apply_msg}\nLikely cause: line numbers in @@ headers "
                f"don't match the source. Re-read the buggy snippet's "
                f"line numbers and emit a diff with correct @@ headers."
            )
            continue
        test_result = _run_tests(test_cmd, target_root, timeout=test_timeout)
        _revert_to_head(target_root)
        if test_result["passed"]:
            return {
                "model": label,
                "diff": diff,
                "tests": test_result,
                "tests_passed": True,
                "attempts": attempt_idx + 1,
                **meta,
            }
        # Tests failed -- feed the failure back for the next attempt
        attempts.append(
            {
                "attempt": attempt_idx + 1,
                "diff": diff,
                "tests": test_result,
                "tests_passed": False,
                **meta,
            }
        )
        # Build a richer prompt with the test output + any sibling .c
        # context (test files often live in the same dir as the bug).
        sibling_context = _gather_sibling_context(target_root, exclude_path=None)
        current_prompt = prompt + (
            "\n\nYour previous attempt applied cleanly but tests failed:\n"
            "```\n" + test_result["stdout_tail"] + "\n" + test_result["stderr_tail"] + "\n```\n\n"
            "ADDITIONAL CONTEXT -- sibling source files in the bug's "
            "directory (often the test or caller that defines what "
            '"fixed" means):\n\n' + sibling_context + "\n\nYour previous diff was:\n" + diff + "\n\n"
            "Try again. The patch must close the bug AND keep all "
            "tests passing. Emit only the new unified diff."
        )
    return {
        "model": label,
        "tests_passed": False,
        "attempts": len(attempts),
        "attempt_history": attempts,
    }


def _gather_sibling_context(target_root: Path, exclude_path: Path | None, max_chars: int = 4000) -> str:
    """Gather sibling .c/.h/.rs/.py files from the bug-file's directory
    so the model sees test code + caller context that defines "fixed"."""
    out = []
    used = 0
    for ext in ("*.c", "*.h", "*.rs", "*.py"):
        for p in target_root.rglob(ext):
            if any(part in {".git", "__pycache__", "build", "target", "node_modules"} for part in p.parts):
                continue
            if exclude_path and p == exclude_path:
                continue
            try:
                content = p.read_text(errors="replace")
            except Exception:
                continue
            rel = p.relative_to(target_root)
            chunk = f"=== {rel} ===\n{content}\n"
            if used + len(chunk) > max_chars:
                chunk = chunk[: max_chars - used] + "\n... (truncated)\n"
                out.append(chunk)
                return "\n".join(out)
            out.append(chunk)
            used += len(chunk)
    return "\n".join(out)


def synthesize(
    target_root: Path,
    bug_file: Path,
    bug_line: int,
    bug_class: str,
    description: str,
    test_cmd: str,
    backend: str = "race",
    test_timeout: int = 600,
    ask_timeout: int = 180,
    setup_cmd: str | None = None,
    regression_cmd: str | None = None,
    setup_timeout: int = 900,
) -> dict[str, Any]:
    # Always resolve paths to absolute -- git apply needs absolute when
    # cwd != current process cwd, and several callers pass relative paths.
    target_root = target_root.resolve()
    bug_file = bug_file.resolve()
    prompt = _build_prompt(target_root, bug_file, bug_line, bug_class, description)
    candidates: list[dict] = []

    # T3.1: run setup_cmd once before any patch attempts. If setup fails
    # we still try patching -- some setups partial-fail (e.g. pip install
    # warns about deps but the package builds). Result captured for
    # post-mortem analysis.
    setup_result = _run_setup(setup_cmd, target_root, timeout=setup_timeout)

    askers = []
    if backend in ("claude", "race"):
        askers.append(("claude-opus-4-7", _ask_claude))
    if backend in ("openai", "race"):
        askers.append(("gpt-5-4", _ask_gpt5))

    if not askers:
        return {"error": f"unknown backend {backend!r}"}

    if backend == "race":
        with ThreadPoolExecutor(max_workers=len(askers)) as ex:
            futures = {
                ex.submit(_try_candidate, label, asker, prompt, target_root, test_cmd, test_timeout, ask_timeout): label
                for label, asker in askers
            }
            for fut in as_completed(futures):
                candidates.append(fut.result())
                if candidates[-1].get("tests_passed"):
                    # Cancel remaining asks (best-effort; in-flight may still complete)
                    for f in futures:
                        f.cancel()
                    break
    else:
        for label, asker in askers:
            candidates.append(_try_candidate(label, asker, prompt, target_root, test_cmd, test_timeout, ask_timeout))
            if candidates[-1].get("tests_passed"):
                break

    winner = next((c for c in candidates if c.get("tests_passed")), None)

    # T3.2: regression check -- when we have a winner, re-apply its diff
    # and run regression_cmd to surface "did this break something else?"
    # Codex's specific concern. Result is informational only; doesn't
    # gate the win. If regression_cmd is None, we skip the step.
    regression_result = None
    if winner and regression_cmd:
        try:
            applied, _msg = _apply_diff(winner["diff"], target_root)
            if applied:
                regression_result = _run_tests(
                    regression_cmd,
                    target_root,
                    timeout=test_timeout * 2,
                )
                _revert_to_head(target_root)
        except Exception as e:
            regression_result = {"passed": False, "error": str(e)}

    _result = {
        "target": str(target_root),
        "bug": {
            "file": str(bug_file),
            "line": bug_line,
            "class": bug_class,
            "description": description,
        },
        "setup_cmd": setup_cmd,
        "test_cmd": test_cmd,
        "regression_cmd": regression_cmd,
        "setup_result": setup_result,
        "regression_result": regression_result,
        "backend": backend,
        "candidates": candidates,
        "winner": winner,
        "summary": {
            "candidate_count": len(candidates),
            "passing_count": sum(1 for c in candidates if c.get("tests_passed")),
            "first_pass_model": winner["model"] if winner else None,
            "setup_passed": setup_result["passed"] if setup_result else None,
            "regression_passed": regression_result["passed"] if regression_result else None,
        },
    }
    # Emit cross-helper event to case_state. case_id defaults to the
    # target_root's name (= the CVE id when called from benchmarks/cve/).
    try:
        import sys as _sys
        from pathlib import Path as _Path

        _h = _Path(__file__).resolve().parent
        if str(_h) not in _sys.path:
            _sys.path.insert(0, str(_h))
        import auto_case_state as _cs  # type: ignore

        case_id = target_root.name
        _cs.record(
            case_id,
            "auto_patch_synth",
            "patch_attempt",
            {
                "bug_file": str(bug_file.relative_to(target_root))
                if target_root in bug_file.parents
                else str(bug_file),
                "bug_line": bug_line,
                "bug_class": bug_class,
                "winner_model": winner["model"] if winner else None,
                "winner_diff_chars": len(winner["diff"]) if winner else 0,
                "candidate_count": len(candidates),
                "tests_passed": bool(winner),
            },
        )
        if winner:
            _cs.record(
                case_id,
                "auto_patch_synth",
                "winning_patch",
                {"diff": winner["diff"]},
            )
    except Exception:
        pass  # case_state is best-effort
    return _result


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--target", required=True, type=Path, help="root of source tree (must be a git repo)")
    p.add_argument("--bug-file", required=True, type=Path)
    p.add_argument("--bug-line", required=True, type=int)
    p.add_argument("--bug-class", required=True)
    p.add_argument("--description", required=True)
    p.add_argument("--test-cmd", required=True, help="shell command that exits 0 iff tests pass")
    p.add_argument("--setup-cmd", default=None, help="optional bootstrap command run once before patch attempts (T3.1)")
    p.add_argument(
        "--regression-cmd", default=None, help="optional broader test sweep run once after a winner lands (T3.2)"
    )
    p.add_argument("--backend", default=os.environ.get("LLM_BACKEND", "race"), choices=["claude", "openai", "race"])
    p.add_argument("--test-timeout", type=int, default=600)
    p.add_argument("--ask-timeout", type=int, default=180)
    p.add_argument("--setup-timeout", type=int, default=900)
    p.add_argument("--out", type=Path)
    args = p.parse_args(argv)

    if not args.target.is_dir():
        print(f"[-] target not a directory: {args.target}", file=sys.stderr)
        return 1
    if not args.bug_file.is_file():
        print(f"[-] bug-file not a file: {args.bug_file}", file=sys.stderr)
        return 1

    result = synthesize(
        args.target,
        args.bug_file,
        args.bug_line,
        args.bug_class,
        args.description,
        args.test_cmd,
        backend=args.backend,
        test_timeout=args.test_timeout,
        ask_timeout=args.ask_timeout,
        setup_cmd=args.setup_cmd,
        regression_cmd=args.regression_cmd,
        setup_timeout=args.setup_timeout,
    )

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2))
        if result.get("winner"):
            (args.out.parent / (args.out.stem + ".diff")).write_text(result["winner"]["diff"] + "\n")
            print(f"wrote {args.out} + .diff (winner: {result['winner']['model']})")
        else:
            print(f"wrote {args.out} -- no passing patch from {result['summary']['candidate_count']} candidates")
    else:
        json.dump(result, sys.stdout, indent=2)
        print()

    return 0 if result.get("winner") else 1


if __name__ == "__main__":
    sys.exit(main())
