"""Orchestrator -- challenge intake, graph invocation, cost monitoring, cleanup.

Pure Python lifecycle management. No LLM calls.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from datetime import UTC
from pathlib import Path

from kraken.config import CheckpointerConfig, KrakenConfig
from kraken.graph import build_graph
from kraken.logging.cost_tracker import CostTracker
from kraken.logging.structured import configure_logging, get_logger
from kraken.runtime import create_runtime
from kraken.state import initial_state
from kraken.storage.ledger import initialize_ledger

log = get_logger(__name__)


_ADDITIVE_STATE_FIELDS = {
    "solve_scripts",
    "strategies_tried",
    "error_log",
    "recent_actions",
    "node_timings",
    "solve_path",
}


def _safe_workspace_name(challenge_id: str) -> str:
    """Return a filesystem-safe workspace directory name for a challenge."""
    raw = (challenge_id or "challenge").strip()
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", raw).strip("._")
    return f"{safe or 'challenge'}_solution_artifacts"


def _attempt_sudo_prepare_workspace(target: Path) -> bool:
    """Best-effort non-interactive sudo mkdir/chown for workspace creation.

    This handles common `su ... claude` flows where CWD is root-owned but the
    `claude` user has passwordless sudo rights.
    """
    sudo = shutil.which("sudo")
    if sudo is None:
        return False

    user = os.environ.get("SUDO_USER") or os.environ.get("USER") or ""
    group = os.environ.get("SUDO_GID") or ""

    try:
        mk = subprocess.run([sudo, "-n", "mkdir", "-p", str(target)], capture_output=True, text=True)
        if mk.returncode != 0:
            return False

        if user:
            # Prefer chown to invoking user; group may be empty in some shells.
            owner = f"{user}:{group}" if group else user
            ch = subprocess.run([sudo, "-n", "chown", owner, str(target)], capture_output=True, text=True)
            if ch.returncode != 0:
                # directory exists; still consider mkdir success sufficient
                pass
        return True
    except Exception:
        return False


def _resolve_solve_workspace(challenge_id: str) -> str:
    """Resolve per-challenge workspace path.

    Default behavior is strict and deterministic: use invocation CWD
    (or ``KRAKEN_SOLVE_WORKSPACE_BASE`` when provided).

    Optional fallback mode can be enabled with
    ``KRAKEN_SOLVE_WORKSPACE_FALLBACK=1`` to try: home, then /tmp.
    """
    workspace_name = _safe_workspace_name(challenge_id)

    env_base = os.environ.get("KRAKEN_SOLVE_WORKSPACE_BASE", "").strip()
    if env_base:
        base = Path(env_base).expanduser()
    else:
        # Default to results/ directory to keep CWD clean
        base = Path.cwd() / "results"
    try:
        base = base.resolve()
    except Exception:
        pass

    target = base / workspace_name
    fail_reason = ""
    try:
        target.mkdir(parents=True, exist_ok=True)
        return str(target)
    except Exception as exc:
        # Best-effort sudo creation for root-owned CWD under `su ... claude` workflows
        allow_sudo = os.environ.get("KRAKEN_SOLVE_WORKSPACE_USE_SUDO", "1").strip() in {"1", "true", "yes"}
        if allow_sudo and _attempt_sudo_prepare_workspace(target):
            try:
                target.mkdir(parents=True, exist_ok=True)
                return str(target)
            except Exception:
                pass

        fail_reason = str(exc)
        fallback_enabled = os.environ.get("KRAKEN_SOLVE_WORKSPACE_FALLBACK", "0").strip() in {"1", "true", "yes"}
        if not fallback_enabled:
            raise RuntimeError(
                "Unable to create solve workspace in invocation directory. "
                f"Tried: {target} ({exc}). "
                "If running via `su` as a non-owner user, either grant write permission to CWD, "
                "or allow auto-sudo workspace creation (default) with passwordless sudo, "
                "or set KRAKEN_SOLVE_WORKSPACE_BASE to a writable location. "
                "To allow fallback to home/tmp, set KRAKEN_SOLVE_WORKSPACE_FALLBACK=1."
            )

    errors = [f"{target}: {fail_reason}"]
    for alt in (Path.home(), Path("/tmp")):
        try:
            alt = alt.resolve()
        except Exception:
            pass
        if alt == base:
            continue
        alt_target = alt / workspace_name
        try:
            alt_target.mkdir(parents=True, exist_ok=True)
            return str(alt_target)
        except Exception as e:
            errors.append(f"{alt_target}: {e}")

    raise RuntimeError("Unable to create writable solve workspace. Tried: " + "; ".join(errors))


def _inject_helper_scripts(solve_workspace: str) -> list[str]:
    """Copy helper scripts into solve workspace for script-operator workflow."""
    helpers_src = Path(__file__).resolve().parent / "helpers"
    if not helpers_src.exists() or not helpers_src.is_dir():
        return []

    dst = Path(solve_workspace)
    copied: list[str] = []
    for helper in sorted(helpers_src.glob("*.py")):
        target = dst / helper.name
        shutil.copy2(helper, target)
        current_mode = target.stat().st_mode
        target.chmod(current_mode | 0o111)
        copied.append(str(target))
    return copied


def _merge_state_update(existing: dict, update: dict) -> dict:
    """Merge a node update into local result state while preserving additive fields.

    LangGraph applies reducers (e.g. list concatenation) internally. Progress streaming
    events only include the current node delta, so a naive ``{**a, **b}`` merge loses
    earlier list values. This helper mirrors additive semantics for summary/reporting.
    """
    merged = dict(existing)
    for key, value in update.items():
        if key in _ADDITIVE_STATE_FIELDS and isinstance(value, list):
            prev = merged.get(key, [])
            if isinstance(prev, list):
                merged[key] = [*prev, *value]
            else:
                merged[key] = list(value)
        else:
            merged[key] = value
    return merged


def _probe_ollama_endpoint(base_url: str, timeout_s: float = 1.5) -> bool:
    """Return True if an Ollama endpoint responds to /api/tags."""
    url = f"{base_url.rstrip('/')}/api/tags"
    req = urllib.request.Request(url, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            return 200 <= getattr(resp, "status", 0) < 300
    except Exception:
        return False


def _verify_and_select_ollama_endpoint(current: str) -> str:
    """Select a working Ollama endpoint for this run, preferring host.docker.internal."""
    preferred = [
        "http://host.docker.internal:11434",
        "http://localhost:11434",
    ]

    candidates: list[str] = []
    seen: set[str] = set()
    for candidate in [*preferred, current]:
        normalized = (candidate or "").rstrip("/")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        candidates.append(normalized)

    for candidate in candidates:
        if _probe_ollama_endpoint(candidate):
            return candidate

    raise RuntimeError(
        "Ollama pre-run verification failed: could not reach a working endpoint. "
        "Tried host.docker.internal and localhost. "
        "Ensure Ollama is running and reachable from this runtime."
    )


def _wait_for_ollama_recovery(base_url: str, max_wait: int = 60, interval: int = 5) -> bool:
    """Wait for Ollama to recover after a crash. Returns True if recovered."""
    import sys

    candidates = [
        "http://host.docker.internal:11434",
        "http://localhost:11434",
    ]
    seen = set()
    for c in [base_url, *candidates]:
        n = (c or "").rstrip("/")
        if n and n not in seen:
            seen.add(n)

    elapsed = 0
    while elapsed < max_wait:
        for endpoint in seen:
            if _probe_ollama_endpoint(endpoint, timeout_s=3.0):
                if elapsed > 0:
                    sys.stderr.write(f"\n  Ollama recovered after {elapsed}s\n")
                return True
        time.sleep(interval)
        elapsed += interval
        sys.stderr.write(f"\r  Waiting for Ollama recovery... {elapsed}/{max_wait}s")
        sys.stderr.flush()

    sys.stderr.write(f"\n  Ollama did not recover after {max_wait}s\n")
    return False


def _normalize_challenge_id(challenge_config: dict, challenge_json_path: str | None = None) -> dict:
    """Normalize challenge_id with safe fallbacks for stale JSON templates.

    Prefer explicit non-placeholder IDs. If ID is missing or a common placeholder
    (e.g. "Basic"), derive from challenge JSON filename or binary path stem.
    """
    cfg = dict(challenge_config or {})
    raw_id = str(cfg.get("challenge_id") or cfg.get("name") or "").strip()
    placeholders = {"", "basic", "challenge", "unknown", "sample", "test"}

    if raw_id.lower() not in placeholders:
        cfg["challenge_id"] = raw_id
        return cfg

    if challenge_json_path:
        stem = Path(challenge_json_path).stem.strip()
        if stem:
            cfg["challenge_id"] = stem
            return cfg

    bin_path = str(cfg.get("path") or cfg.get("challenge_path") or "").strip()
    if bin_path:
        stem = Path(bin_path).stem.strip()
        if stem:
            cfg["challenge_id"] = stem
            return cfg

    cfg["challenge_id"] = raw_id or "challenge"
    return cfg


def _build_dir_challenge_config(cp: Path, category: str | None = None) -> dict:
    """Build a minimal challenge config from a bare challenge directory.

    This is the sole builder for the ``kraken solve <directory>`` CLI path.
    ``solve()`` reads ``challenge_config["path"]``, so this MUST set ``path``
    (a regression here previously crashed the documented quickstart with
    ``KeyError: 'path'``). ``challenge_path`` is kept for older consumers.
    """
    desc = ""
    desc_file = cp / "description.txt"
    if desc_file.is_file():
        desc = desc_file.read_text(errors="replace")[:5000]
    return {
        "challenge_id": cp.name,
        "path": str(cp),
        "challenge_path": str(cp),
        "description": desc,
        "category": category or "rev",
    }


def _normalize_flag_format(raw: str) -> str:
    """Convert a user-friendly flag format template to a proper regex.

    Examples:
        'vere{}'       → r'vere\\{[^}]+\\}'
        'flag{}'       → r'flag\\{[^}]+\\}'
        'CTF{}'        → r'CTF\\{[^}]+\\}'
        'flag{...}'    → r'flag\\{[^}]+\\}'
        r'flag\\{.*\\}'  → r'flag\\{.*\\}' (already a regex, pass through)
    """
    import re

    s = raw.strip()
    # Already a proper regex (contains backslash-escaped braces or regex metacharacters)
    if r"\{" in s or r"\}" in s:
        return s
    # Template format: prefix{} or prefix{...} or prefix{*}
    match = re.match(r"^([A-Za-z0-9_]+)\{([^}]*)\}$", s)
    if match:
        prefix = re.escape(match.group(1))
        inner = match.group(2).strip()
        if not inner or inner in ("...", "*", "?"):
            return prefix + r"\{[^}]+\}"
        # User provided inner content -- escape it as literal
        return prefix + r"\{" + re.escape(inner) + r"\}"
    return s


def _detect_flag_format_from_files(challenge_path: str) -> str:
    """Scan challenge files AND binary strings for flag prefix patterns.

    Returns a format string like 'vere{}' if a non-default prefix is found,
    or empty string if only 'flag{' or nothing detected.

    Detection sources (in priority order):
    1. Explicit format declarations in description/readme (e.g. "flag format is vere{...}")
    2. Prefix occurrences in source files (.py, .js, .c, etc.)
    3. Prefix occurrences in binary strings (via `strings` command)
    """
    target = Path(challenge_path)
    if not target.exists():
        return ""

    # ── Phase 1: Check description files for explicit format declarations ──
    _DESC_NAMES = {"description.txt", "readme.txt", "readme.md", "description.md"}
    # Patterns like: "flag format is vere{...}", "flags look like CTF{...}", "submit in format ABC{}"
    _EXPLICIT_FMT = re.compile(
        r"(?:flag\s+format|flags?\s+(?:look|are|is)|submit.*?format|format.*?flag)[^.]{0,40}?"
        r'[`"\']?([a-zA-Z_]{2,20})\{',
        re.IGNORECASE,
    )

    if target.is_dir():
        for name in _DESC_NAMES:
            desc_file = target / name
            if desc_file.is_file():
                try:
                    desc_text = desc_file.read_text(errors="replace")[:10000]
                    m = _EXPLICIT_FMT.search(desc_text)
                    if m and m.group(1).lower() != "flag":
                        return f"{m.group(1)}{{}}"
                except OSError:
                    pass

    # ── Phase 2: Scan source files for prefix{...} patterns ──
    files = []
    if target.is_dir():
        _SCAN_EXTS = {
            ".js",
            ".py",
            ".php",
            ".c",
            ".cpp",
            ".h",
            ".rb",
            ".txt",
            ".html",
            ".java",
            ".go",
            ".rs",
            ".sh",
            ".md",
        }
        for entry in target.iterdir():
            if entry.is_file() and entry.suffix.lower() in _SCAN_EXTS and entry.stat().st_size < 200_000:
                files.append(entry)
    elif target.is_file():
        files.append(target)

    # Count prefix occurrences across all files
    prefix_counts: dict[str, int] = {}
    flag_pattern = re.compile(r"\b([a-zA-Z_]{2,20})\{")
    # Skip common programming constructs
    _CODE_BRACES = {
        "if",
        "for",
        "while",
        "else",
        "try",
        "catch",
        "switch",
        "case",
        "function",
        "class",
        "return",
        "var",
        "let",
        "const",
        "new",
        "typeof",
        "instanceof",
        "export",
        "import",
        "from",
        "async",
        "await",
        "yield",
        "throw",
        "delete",
        "void",
        "enum",
        "with",
        "struct",
        "union",
        "namespace",
        "template",
        "define",
        "include",
        "pragma",
        "typedef",
        "extern",
        "static",
        "register",
        "volatile",
        "match",
        "fn",
        "pub",
        "impl",
        "trait",
        "mod",
        "use",
        "crate",
        "func",
        "package",
        "defer",
        "go",
        "select",
        "chan",
        "range",
        "elif",
        "except",
        "finally",
        "lambda",
        "nonlocal",
        "global",
        "assert",
        "raise",
        "pass",
        "break",
        "continue",
        "print",
        "super",
        "this",
        "self",
        "null",
        "true",
        "false",
        "None",
        "default",
        "do",
        "abstract",
        "interface",
        "extends",
        "implements",
        "final",
        "protected",
        "private",
        "public",
        "throws",
        "synchronized",
    }

    for f in files:
        try:
            text = f.read_text(errors="replace")[:50000]
        except OSError:
            continue
        # Description/readme files get 10x weight (flag format is explicitly stated there)
        weight = 10 if f.name.lower() in _DESC_NAMES else 1
        for m in flag_pattern.finditer(text):
            prefix = m.group(1)
            if prefix.lower() not in _CODE_BRACES:
                prefix_counts[prefix] = prefix_counts.get(prefix, 0) + weight

    # ── Phase 3: Scan binary strings for flag-like prefixes ──
    binaries = []
    if target.is_dir():
        for entry in target.iterdir():
            if entry.is_file() and entry.stat().st_size < 10_000_000:
                # Heuristic: no text extension and not too large
                if entry.suffix.lower() not in _SCAN_EXTS and entry.suffix.lower() not in {
                    ".json",
                    ".yaml",
                    ".yml",
                    ".xml",
                    ".csv",
                    ".zip",
                    ".gz",
                    ".tar",
                    ".png",
                    ".jpg",
                    ".gif",
                }:
                    binaries.append(entry)
    elif target.is_file() and target.suffix.lower() not in {".txt", ".py", ".js", ".c", ".json"}:
        binaries.append(target)

    for binary in binaries:
        try:
            import subprocess

            result = subprocess.run(
                ["strings", "-n", "4", str(binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                for m in flag_pattern.finditer(result.stdout[:100000]):
                    prefix = m.group(1)
                    if prefix.lower() not in _CODE_BRACES and len(prefix) >= 3:
                        # Binary strings get 2x weight (more reliable than code constructs)
                        prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 2
        except (OSError, subprocess.TimeoutExpired):
            pass

    if not prefix_counts:
        return ""

    # Pick the most frequent non-"flag" prefix
    best_prefix = max(prefix_counts, key=prefix_counts.get)  # type: ignore[arg-type]
    if best_prefix.lower() == "flag":
        return ""
    return f"{best_prefix}{{}}"


def _requires_remote_server(description: str) -> bool:
    """Check if a challenge description indicates a remote server is needed."""
    desc_lower = description.lower()
    _REMOTE_PATTERNS = [
        r"\bnc\s+\S+\s+\d+",  # nc host port
        r"\bnetcat\b",  # netcat
        r"\bconnect\s+to\b",  # connect to
        r"\bremote\s+server\b",  # remote server
        r"\bserver\s+at\b",  # server at
        r"\bhost\s*[:=]\s*\S+.*\bport\b",  # host: ... port
        r"\bssh\s+\S+",  # ssh user@host
        r"(?:http|https|ftp)://\S+:\d+",  # URLs with port
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[:\s]+\d{2,5}",  # IP:port or IP port
    ]
    return any(re.search(pat, desc_lower) for pat in _REMOTE_PATTERNS)


# Node display names for progress
_NODE_LABELS = {
    "triage": "Triage (binary metadata)",
    "unpack": "Unpack (conditional)",
    "decompile": "Decompile (Ghidra)",
    "normalize": "Normalize (rename vars)",
    "classify": "Classify (challenge type)",
    "constraint_solver": "Specialist: constraint solver",
    "crypto_decode": "Specialist: crypto decode",
    "dynamic_analysis": "Specialist: dynamic analysis",
    "keygen": "Specialist: keygen",
    "pwn_specialist": "Specialist: pwn exploit",
    "fuzzing_specialist": "Specialist: fuzzing",
    "web_specialist": "Specialist: web vulnerability",
    "dotnet_specialist": "Specialist: .NET RE",
    "firmware_specialist": "Specialist: firmware RE",
    "solve_engine": "Solve Engine (write + run script)",
    "flag_validator": "Flag Validator",
    "manager": "Manager (retry routing)",
    "context_compressor": "Context Compressor",
}


def _get_checkpointer(config: CheckpointerConfig):
    """Create checkpointer based on config."""
    if config.checkpointer == "sqlite":
        from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver

        return AsyncSqliteSaver.from_conn_string(config.sqlite_path)
    elif config.checkpointer == "postgres":
        from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver

        return AsyncPostgresSaver.from_conn_string(config.postgres_uri)
    else:
        from langgraph.checkpoint.memory import MemorySaver

        return MemorySaver()


def _print_progress(node_name: str, step: int, elapsed: float, extra: str = ""):
    """Print a live progress line to stderr."""
    import sys

    label = _NODE_LABELS.get(node_name, node_name)
    mins, secs = divmod(int(elapsed), 60)
    time_str = f"{mins}m{secs:02d}s" if mins else f"{secs}s"
    line = f"\r[step {step:>3}] [{time_str:>6}] {label}"
    if extra:
        line += f" -- {extra}"
    # Pad to clear previous longer lines
    sys.stderr.write(f"{line:<100}\r")
    sys.stderr.flush()


def _print_solve_summary(summary: dict):
    """Print a human-readable solve summary to stderr."""
    import sys

    challenge_id = summary.get("challenge_id", "unknown")
    solved = summary.get("solved", False)
    flag = summary.get("flag", "")
    duration = summary.get("duration_seconds", 0)
    ctype = summary.get("challenge_type", "unknown")
    strategies = summary.get("strategies_tried", [])
    timings = summary.get("node_timings", [])

    mins, secs = divmod(int(duration), 60)
    time_str = f"{mins}m{secs:02d}s" if mins else f"{secs}s"

    result_str = "SOLVED" if solved else "UNSOLVED"

    w = sys.stderr.write
    w(f"\n{'=' * 60}\n")
    w(f"  SOLVE SUMMARY: {challenge_id}\n")
    w(f"{'=' * 60}\n\n")
    w(f"  Result:  {result_str}\n")
    if flag:
        w(f"  Flag:    {flag}\n")
    w(f"  Time:    {time_str} ({duration:.1f}s)\n")
    w(f"  Type:    {ctype}\n")

    if timings:
        w("\n  Solve Path:\n")
        w(f"  {'─' * 50}\n")
        for t in timings:
            label = _NODE_LABELS.get(t["node"], t["node"])
            w(f"  {t['duration_s']:>7.1f}s  {label}\n")
        w(f"  {'─' * 50}\n")

    if strategies:
        w("\n  Strategies attempted:\n")
        for i, s in enumerate(strategies, 1):
            w(f"    {i}. {s}\n")
    else:
        w("\n  Strategies attempted: (none -- solved on first try)\n")

    w(f"{'=' * 60}\n")
    sys.stderr.flush()


class Orchestrator:
    """Top-level orchestrator for KRAKEN."""

    TERMINATION_CONDITIONS = {
        "flag_found": "Flag regex matched in solve script stdout",
        "time_exceeded": "Wall clock > timeout_minutes",
        "max_steps": "Total graph iterations > max_steps",
        "manager_gives_up": "Manager declares unsolvable after max_strategies",
    }

    def __init__(self, config: KrakenConfig | None = None):
        self.config = config or KrakenConfig()
        self.cost_tracker = CostTracker()

    async def solve(self, challenge_config: dict, progress: bool = True) -> dict:
        """Solve a challenge.

        Args:
            challenge_config: Dict with challenge_id, path, description, flag_format, etc.
            progress: Show live progress bar to stderr.

        Returns:
            Dict with solved, flag, cost, steps, duration_seconds.
        """
        import sys

        challenge_id = challenge_config["challenge_id"]
        challenge_path = challenge_config["path"]
        description = challenge_config.get("description", "")
        raw_flag_fmt = challenge_config.get("flag_format", self.config.default_flag_format)
        flag_format = _normalize_flag_format(raw_flag_fmt)

        # Auto-detect flag format from challenge source files if using the default
        # "flag" prefix. An explicitly requested format is always honored: otherwise
        # auto-detect would lock onto any word{...} in the files (e.g. an encoded
        # synt{...} ciphertext) and report it as the flag.
        _pfx_m = re.match(r"^([A-Za-z_]+)", raw_flag_fmt)
        _uses_default_prefix = not _pfx_m or _pfx_m.group(1).lower() == "flag"
        _explicit_format = challenge_config.get("flag_format_explicit", False)
        if _uses_default_prefix and not _explicit_format:
            detected = _detect_flag_format_from_files(challenge_path)
            if detected:
                flag_format = _normalize_flag_format(detected)
                log.info("flag_format_auto_detected", detected=detected, normalized=flag_format)

        category = challenge_config.get("category", "rev")
        benchmark = challenge_config.get("benchmark", False)

        # Backend override (from --local)
        if "backend" in challenge_config:
            os.environ["KRAKEN_BACKEND"] = challenge_config["backend"]
            self.config.models.backend = challenge_config["backend"]

        # Per-tier model override (from --local)
        if "model_high" in challenge_config:
            for tier in ("model_high", "model_mid", "model_low"):
                if tier in challenge_config:
                    os.environ[f"KRAKEN_{tier.upper()}"] = challenge_config[tier]
                    setattr(self.config.models, tier, challenge_config[tier])
        elif "model" in challenge_config:
            # Single model override -- sets all tiers to same model
            model = challenge_config["model"]
            os.environ["KRAKEN_MODEL_HIGH"] = model
            os.environ["KRAKEN_MODEL_MID"] = model
            os.environ["KRAKEN_MODEL_LOW"] = model
            self.config.models.model_high = model
            self.config.models.model_mid = model
            self.config.models.model_low = model

        runtime_provider = os.environ.get("KRAKEN_RUNTIME_PROVIDER", self.config.runtime.provider)
        # Runtime adapter is not yet wired into all tools, but validating selection early
        # makes runtime mode explicit in logs and catches invalid config values.
        create_runtime(runtime_provider)

        execution_mode = f"{runtime_provider}+{self.config.models.backend}"
        if runtime_provider == "claude_code" and self.config.models.backend == "ollama":
            log.info("claude_code_ollama_mode", note="Claude Code runtime using local Ollama backend")

        if self.config.models.backend == "ollama":
            selected_ollama = _verify_and_select_ollama_endpoint(self.config.models.ollama_base_url)
            self.config.models.ollama_base_url = selected_ollama
            os.environ["KRAKEN_OLLAMA_BASE_URL"] = selected_ollama
            log.info("ollama_prerun_endpoint_selected", endpoint=selected_ollama, execution_mode=execution_mode)

        log.info(
            "orchestrator_start",
            challenge=challenge_id,
            path=challenge_path,
            runtime_provider=runtime_provider,
            backend=self.config.models.backend,
            execution_mode=execution_mode,
        )
        start_time = time.monotonic()

        if progress:
            sys.stderr.write(f"\n{'=' * 60}\n")
            sys.stderr.write(f"  KRAKEN solving: {challenge_id}\n")
            sys.stderr.write(f"  Binary: {challenge_path}\n")
            sys.stderr.write(f"{'=' * 60}\n\n")
            sys.stderr.flush()

        # Read description from file if not provided in config
        if not description:
            desc_file = Path(challenge_path) / "description.txt"
            if desc_file.is_file():
                try:
                    description = desc_file.read_text(errors="replace")[:5000]
                except OSError:
                    pass

        # Early bail: challenge requires a remote server we can't reach
        # Skip only if no remote_info was pre-populated (e.g. by benchmark adapter)
        has_remote_info = bool(
            challenge_config.get("remote") or challenge_config.get("state", {}).get("remote_info", {}).get("host")
        )
        if _requires_remote_server(description) and not has_remote_info:
            log.info("skip_remote_required", challenge=challenge_id, reason="Challenge requires remote server access")
            elapsed = time.monotonic() - start_time
            return {
                "solved": False,
                "flag": "",
                "error": "Challenge requires remote server (not available in offline mode)",
                "challenge_type": category,
                "steps": 0,
                "duration_seconds": round(elapsed, 1),
                "cost_usd": 0.0,
                "solve_path": [],
                "node_timings": [],
                "strategies_tried": [],
            }

        # Build per-challenge solve workspace (prefer CWD; fallback to home/tmp if needed)
        solve_workspace = _resolve_solve_workspace(challenge_id)
        solve_ledger_path = initialize_ledger(solve_workspace, challenge_id)
        helper_scripts = _inject_helper_scripts(solve_workspace)
        if helper_scripts:
            log.info("orchestrator_helpers_injected", count=len(helper_scripts), workspace=solve_workspace)

        # Build initial state
        state = initial_state(
            challenge_id=challenge_id,
            challenge_path=challenge_path,
            description=description,
            flag_format=flag_format,
            category=category,
            benchmark=benchmark,
            solve_workspace=solve_workspace,
        )
        state["solve_ledger_path"] = solve_ledger_path

        # Phase 1: Initialize artifact store
        if self.config.evolution.enable_artifact_store:
            artifact_dir = str(Path(solve_workspace) / ".artifacts")
            state["artifact_store_path"] = artifact_dir

        # Seed remote_info from challenge JSON if provided
        if "remote" in challenge_config and isinstance(challenge_config["remote"], dict):
            remote = challenge_config["remote"]
            state["remote_info"] = {
                "host": remote.get("host", ""),
                "port": remote.get("port", 0),
                "protocol": remote.get("protocol", "tcp"),
                "source": "challenge_config",
            }

        # Build graph
        checkpointer = _get_checkpointer(self.config.checkpointer)
        graph = build_graph(checkpointer=checkpointer)

        # Run graph with streaming for progress
        thread_id = f"kraken-{challenge_id}-{int(time.time())}"
        config = {"configurable": {"thread_id": thread_id}}
        step = 0
        result = state
        timeout_seconds = self.config.budget.timeout_minutes * 60
        node_timings: list[dict] = []
        solve_path: list[str] = []
        node_start: float = time.monotonic()

        try:
            async for event in graph.astream(state, config=config, stream_mode="updates"):
                for node_name, node_output in event.items():
                    step += 1
                    now = time.monotonic()
                    elapsed = now - start_time
                    duration = now - node_start

                    # Track timing
                    node_timings.append({"node": node_name, "duration_s": round(duration, 1)})
                    solve_path.append(node_name)
                    node_start = now

                    # Build extra info from node output
                    extra = ""
                    if isinstance(node_output, dict):
                        if "challenge_type" in node_output:
                            extra = f"type={node_output['challenge_type']}"
                        elif "flag" in node_output and node_output["flag"]:
                            extra = "FLAG FOUND!"
                        elif "next_node" in node_output:
                            extra = f"-> {node_output['next_node']}"

                    if progress:
                        _print_progress(node_name, step, elapsed, extra)

                    # Merge updates into result
                    if isinstance(node_output, dict):
                        result = _merge_state_update(result, node_output)

                    # Session checkpoint (if session_manager attached)
                    if hasattr(self, "_session_id") and self._session_id:
                        try:
                            from kraken.runtime.session import SessionManager

                            sm = SessionManager(os.environ.get("KRAKEN_RUNTIME_WORKSPACE", "."))
                            sm.save_checkpoint(self._session_id, result)
                        except Exception:
                            pass

                    # Enforce timeout
                    if elapsed > timeout_seconds:
                        raise TimeoutError(f"Wall clock timeout ({self.config.budget.timeout_minutes}m) exceeded")

        except TimeoutError as te:
            log.warning("orchestrator_timeout", error=str(te))
            result["error_log"] = result.get("error_log", []) + [{"node": "orchestrator", "error": str(te)}]
        except Exception as e:
            log.error("orchestrator_error", error=str(e))
            result["error_log"] = result.get("error_log", []) + [{"node": "orchestrator", "error": str(e)}]

        # Prefer canonical graph state (already reducer-merged) when available.
        try:
            snapshot = await graph.aget_state(config)
            if snapshot and getattr(snapshot, "values", None):
                result = snapshot.values
        except Exception as exc:
            log.debug("orchestrator_state_snapshot_failed", error=str(exc))

        if progress:
            sys.stderr.write("\n\n")
            sys.stderr.flush()

        # Inject timing data into result
        result["node_timings"] = node_timings
        result["solve_path"] = solve_path

        elapsed = time.monotonic() - start_time
        flag = result.get("flag", "")
        solved = bool(flag)

        summary = {
            "solved": solved,
            "flag": flag,
            "cost_usd": round(self.cost_tracker.total_cost, 4),
            "steps": result.get("iteration_count", 0),
            "duration_seconds": round(elapsed, 1),
            "strategies_tried": result.get("strategies_tried", []),
            "challenge_id": challenge_id,
            "challenge_type": result.get("challenge_type", ""),
            "solve_path": solve_path,
            "node_timings": node_timings,
        }

        if progress:
            _print_solve_summary(summary)

        log.info(
            "orchestrator_complete", **{k: v for k, v in summary.items() if k not in ("node_timings", "solve_path")}
        )

        # Emit comprehensive artifact bundle
        try:
            from kraken.storage.artifacts import emit_artifacts

            emit_artifacts(result, summary, workspace=solve_workspace)
        except Exception as exc:
            log.debug("artifact_emission_failed", error=str(exc))

        return summary


async def solve_challenge(challenge_json_path: str) -> dict:
    """Convenience function to solve a challenge from a JSON file."""
    configure_logging()
    config_data = json.loads(Path(challenge_json_path).read_text())
    config_data = _normalize_challenge_id(config_data, challenge_json_path)
    orchestrator = Orchestrator()
    return await orchestrator.solve(config_data)


def create_challenge() -> int:
    """Interactive challenge config creation."""
    print("\n=== KRAKEN Challenge Creator ===\n")

    # Challenge ID
    challenge_id = input("Challenge ID (unique name, e.g. crackme-01): ").strip()
    if not challenge_id:
        print("Error: challenge ID is required.")
        return 1

    # Path to binary
    raw_path = input("Path to challenge binary or directory: ").strip()
    if not raw_path:
        print("Error: path is required.")
        return 1
    challenge_path = str(Path(raw_path).expanduser().resolve())
    if not Path(challenge_path).exists():
        print(f"Warning: '{challenge_path}' does not exist yet.")

    # Category
    categories = ["rev", "pwn", "crypto", "misc"]
    print(f"Category [{', '.join(categories)}]")
    category = input("  (default: rev): ").strip().lower() or "rev"

    # Description
    description = input("Description (challenge prompt, or press Enter to skip): ").strip()

    # Flag format
    import re as _re

    default_fmt = r"flag\{[a-zA-Z0-9_]+\}"
    while True:
        raw_fmt = input(f"Flag format regex (default: {default_fmt}): ").strip() or default_fmt
        flag_format = _normalize_flag_format(raw_fmt)
        try:
            _re.compile(flag_format)
            break
        except _re.error as e:
            print(f"  Invalid regex: {e}  (try again)")

    # Model
    default_model = "sonnet"
    model = input(f"Model (default: {default_model}, or ollama tag like 'glm-4.7-flash'): ").strip() or default_model

    # Remote
    remote = None
    has_remote = input("Does this challenge have a remote server? [y/N]: ").strip().lower()
    if has_remote == "y":
        host = input("  Remote host: ").strip()
        port_str = input("  Remote port: ").strip()
        if host and port_str.isdigit():
            remote = {"host": host, "port": int(port_str)}

    # Build config
    config = {
        "challenge_id": challenge_id,
        "path": challenge_path,
        "category": category,
        "model": model,
    }
    if description:
        config["description"] = description
    if flag_format != default_fmt:
        config["flag_format"] = flag_format
    if remote:
        config["remote"] = remote

    # Preview
    print("\n--- Generated Config ---")
    print(json.dumps(config, indent=4))

    # Output path
    default_out = f"{challenge_id}.json"
    out_path = input(f"\nSave to (default: {default_out}): ").strip() or default_out
    out = Path(out_path)

    if out.exists():
        overwrite = input(f"'{out}' already exists. Overwrite? [y/N]: ").strip().lower()
        if overwrite != "y":
            print("Aborted.")
            return 1

    out.write_text(json.dumps(config, indent=4) + "\n")
    print(f"\nSaved to {out}")
    print(f"Run:  kraken {out}")
    return 0


def _cmd_solve_all(args) -> int:
    """Batch solve all challenge subdirectories."""

    root = Path(args.directory).resolve()
    if not root.is_dir():
        print(f"Error: {root} is not a directory")
        return 1

    configure_logging(json_output=args.verbose)

    # Discover challenge subdirectories
    challenges = []
    for sub in sorted(root.iterdir()):
        if not sub.is_dir() or sub.name.startswith(".") or sub.name == "solutions":
            continue

        # Check for challenge.json -- use it if present
        cj = sub / "challenge.json"
        if cj.exists():
            try:
                meta = json.loads(cj.read_text())
                challenges.append(
                    {
                        "challenge_id": meta.get("name", sub.name),
                        "path": str(sub),
                        "description": meta.get("description", ""),
                        "flag_format": meta.get("flag_format", args.flag_format),
                        "category": meta.get("category", args.category),
                    }
                )
                continue
            except (json.JSONDecodeError, KeyError):
                pass

        # No challenge.json -- treat folder name as ID
        desc = ""
        desc_file = sub / "description.txt"
        if desc_file.is_file():
            try:
                desc = desc_file.read_text(errors="replace")[:5000]
            except OSError:
                pass
        challenges.append(
            {
                "challenge_id": sub.name,
                "path": str(sub),
                "description": desc,
                "flag_format": args.flag_format,
                "category": args.category,
            }
        )

    if not challenges:
        print(f"No challenge subdirectories found in {root}")
        return 1

    flag_format = _normalize_flag_format(args.flag_format)

    config = KrakenConfig()
    config.budget.timeout_minutes = args.timeout

    # Apply model overrides
    if args.model:
        config.models.model_high = args.model
        config.models.model_mid = args.model
        config.models.model_low = args.model
    if args.local:
        large, small = args.local
        config.models.backend = "ollama"
        config.models.model_high = large
        config.models.model_mid = large
        config.models.model_low = small

    # Organize solution artifacts under results/{folder}_run_MMDD_HHMM/
    from datetime import datetime as _dt

    _tag = re.sub(r"[^A-Za-z0-9._-]+", "_", root.name).strip("._") or "solve"
    solutions_dir = Path("results") / f"{_tag}_run_{_dt.now().strftime('%m%d_%H%M')}"
    solutions_dir.mkdir(parents=True, exist_ok=True)
    os.environ["KRAKEN_SOLVE_WORKSPACE_BASE"] = str(solutions_dir)

    # Build model override dict to inject into each challenge config
    _model_overrides: dict[str, str] = {}
    if args.local:
        large, small = args.local
        _model_overrides = {
            "backend": "ollama",
            "model_high": large,
            "model_mid": large,
            "model_low": small,
        }
    elif args.model:
        _model_overrides = {
            "model_high": args.model,
            "model_mid": args.model,
            "model_low": args.model,
        }
    if getattr(args, "backend", None):
        _model_overrides["backend"] = args.backend
        config.models.backend = args.backend

    for chal in challenges:
        chal["flag_format"] = flag_format
        chal.update(_model_overrides)

    concurrency = getattr(args, "concurrency", 0) or len(challenges)

    print(f"\n{'─' * 60}")
    print(f"  KRAKEN solve-all: {len(challenges)} challenges in {root.name}/")
    print(f"  Parallel: {concurrency} concurrent  Timeout: {args.timeout}min")
    print(f"  Flag format: {args.flag_format}  Results: {solutions_dir.resolve()}/")
    print(f"{'─' * 60}\n")

    # ── Parallel execution ────────────────────────────────────────
    import time as _time

    solved = 0
    failed = 0
    results: list[dict] = []
    _lock = asyncio.Lock()
    _detected_prefix = ""
    _wall_start = _time.monotonic()

    async def _solve_one(idx: int, chal: dict, sem: asyncio.Semaphore) -> dict:
        nonlocal solved, failed, _detected_prefix
        cid = chal["challenge_id"]

        async with sem:
            # Dynamic flag format from early solves
            async with _lock:
                if _detected_prefix:
                    chal["flag_format"] = _normalize_flag_format(f"{_detected_prefix}{{}}")

            print(f"  [{idx + 1}/{len(challenges)}] {cid} ▶", flush=True)

            orchestrator = Orchestrator(config=config)
            try:
                result = await asyncio.wait_for(
                    orchestrator.solve(chal, progress=False),
                    timeout=args.timeout * 60,
                )
            except TimeoutError:
                result = {"solved": False, "flag": "", "error": "timeout"}
            except Exception as e:
                result = {"solved": False, "flag": "", "error": str(e)[:200]}

            result["challenge_id"] = cid

            async with _lock:
                results.append(result)
                if result.get("solved"):
                    solved += 1
                    flag = result.get("flag", "")
                    dur = result.get("duration_seconds", 0)
                    print(
                        f"  [{idx + 1}/{len(challenges)}] {cid} \033[32mSOLVED\033[0m {flag} ({dur:.0f}s)", flush=True
                    )
                    # Auto-lock flag format from first solve
                    if not _detected_prefix and flag:
                        prefix_m = re.match(r"^([A-Za-z0-9_]+)\{", flag)
                        if prefix_m:
                            _detected_prefix = prefix_m.group(1)
                            print(
                                f"  \033[34m[locked]\033[0m Flag format: {_detected_prefix}{{...}} -- applying to all remaining",
                                flush=True,
                            )
                else:
                    failed += 1
                    err = (result.get("error") or "")[:40]
                    print(f"  [{idx + 1}/{len(challenges)}] {cid} \033[31mFAILED\033[0m {err}", flush=True)

            return result

    async def _run_all():
        sem = asyncio.Semaphore(concurrency)
        tasks = [_solve_one(i, chal, sem) for i, chal in enumerate(challenges)]
        await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(_run_all())

    wall_time = _time.monotonic() - _wall_start

    print(f"\n{'─' * 60}")
    print(f"  Results: {solved} solved, {failed} failed out of {len(challenges)}")
    print(f"  Wall time: {wall_time:.0f}s (parallel)")
    print(f"{'─' * 60}\n")

    # Split results into concise summary and detailed analytics
    _ANALYTICS_KEYS = {"node_timings", "solve_path", "strategies_tried", "steps"}

    concise_results = []
    analytics_results = []
    for r in results:
        concise = {k: v for k, v in r.items() if k not in _ANALYTICS_KEYS}
        concise_results.append(concise)
        analytics_results.append(r)  # full record

    out_file = solutions_dir / "kraken_results.json"
    out_file.write_text(json.dumps(concise_results, indent=2, default=str))
    print(f"Results saved to {out_file}")

    analytics_file = solutions_dir / "kraken_analytics.json"
    analytics_file.write_text(json.dumps(analytics_results, indent=2, default=str))
    print(f"Analytics saved to {analytics_file}")

    # Write comprehensive solve ledger
    _write_solve_ledger(solutions_dir, results, root.name, args)

    return 0 if solved > 0 else 1


def _cmd_ctf(args) -> int:
    """Live CTF competition: pull challenges from CTFd, parallel solve, auto-submit flags.

    Flow:
        1. Connect to CTFd instance with API token
        2. Pull all challenges (metadata + file attachments)
        3. Create workspace: ctfs/{ctf_name}/{category}/{challenge}/
        4. Parallel solve all challenges
        5. Auto-submit high-confidence flags back to CTFd
        6. Print scoreboard and save results
    """

    configure_logging(json_output=args.verbose)

    # ── Step 1: Connect to CTFd ──────────────────────────────────────
    from kraken.platform.ctfd_workspace import CTFdClient

    print(f"\n{'━' * 60}")
    print("  KRAKEN CTF -- Live Competition Mode")
    print(f"  Target: {args.url}")
    print(f"{'━' * 60}\n")

    client = CTFdClient(args.url, token=args.token)

    print(f"  Connecting to {args.url}...", end=" ", flush=True)
    try:
        ctf_challenges = client.pull_challenges()
        print(f"\033[32m{len(ctf_challenges)} challenges found\033[0m")
    except Exception as e:
        print(f"\033[31mFAILED\033[0m: {e}")
        return 1

    if not ctf_challenges:
        print("  No challenges available.")
        return 1

    # Skip already-solved challenges
    unsolved = [c for c in ctf_challenges if not c.solved_by_me]
    if len(unsolved) < len(ctf_challenges):
        print(f"  Skipping {len(ctf_challenges) - len(unsolved)} already-solved challenges")
    ctf_challenges = unsolved

    # ── Step 2: Set up workspace ─────────────────────────────────────
    print("  Setting up workspace...", end=" ", flush=True)
    workspace = client.setup_workspace(ctf_challenges, base_dir="ctfs")
    print(f"\033[32m{workspace}\033[0m")

    # Category breakdown
    categories = {}
    for c in ctf_challenges:
        categories.setdefault(c.category, []).append(c)
    for cat, chals in sorted(categories.items()):
        print(f"    {cat}: {len(chals)} challenges")

    # ── Step 3: Build solve configs ──────────────────────────────────
    # Build a mapping from challenge_id → CTFd challenge (for flag submission)
    ctfd_id_map: dict[str, int] = {}

    solve_challenges = []
    for chal in ctf_challenges:
        safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", chal.name).strip("._")
        ctfd_id_map[safe_name] = chal.id

        desc = chal.description or ""  # already cleaned by CTFdClient._clean_html

        solve_challenges.append(
            {
                "challenge_id": safe_name,
                "path": chal.local_dir,
                "description": desc,
                "flag_format": r"[A-Za-z0-9_]{2,20}\{[^\}]+\}",  # broad -- will auto-lock from first solve
                "category": chal.category,
                "backend": args.backend,
            }
        )

    # ── Step 4: Enable Codex fallback ────────────────────────────────
    os.environ["KRAKEN_ENABLE_CODEX_FALLBACK"] = "1"

    solutions_dir = workspace / "results"
    solutions_dir.mkdir(parents=True, exist_ok=True)
    os.environ["KRAKEN_SOLVE_WORKSPACE_BASE"] = str(solutions_dir)

    config = KrakenConfig()
    config.budget.timeout_minutes = args.timeout
    config.models.backend = args.backend

    concurrency = args.concurrency or len(solve_challenges)

    print(f"\n{'─' * 60}")
    print(f"  Launching {len(solve_challenges)} solvers (parallel: {concurrency})")
    print(f"  Timeout: {args.timeout}min  Backend: {args.backend}")
    print(f"  Auto-submit: {'OFF' if args.no_submit else 'ON (high confidence only)'}")
    print(f"{'─' * 60}\n")

    # ── Step 5: Parallel solve ───────────────────────────────────────
    import time as _time

    solved = 0
    failed = 0
    submitted = 0
    results: list[dict] = []
    _lock = asyncio.Lock()
    _detected_prefix = ""
    _wall_start = _time.monotonic()

    async def _solve_one(idx: int, chal: dict, sem: asyncio.Semaphore) -> dict:
        nonlocal solved, failed, submitted, _detected_prefix
        cid = chal["challenge_id"]

        async with sem:
            # Apply locked flag format
            async with _lock:
                if _detected_prefix:
                    chal["flag_format"] = _normalize_flag_format(f"{_detected_prefix}{{}}")

            print(f"  [{idx + 1}/{len(solve_challenges)}] {cid} ▶", flush=True)

            orchestrator = Orchestrator(config=config)
            try:
                result = await asyncio.wait_for(
                    orchestrator.solve(chal, progress=False),
                    timeout=args.timeout * 60,
                )
            except TimeoutError:
                result = {"solved": False, "flag": "", "error": "timeout"}
            except Exception as e:
                result = {"solved": False, "flag": "", "error": str(e)[:200]}

            result["challenge_id"] = cid

            async with _lock:
                results.append(result)
                if result.get("solved"):
                    solved += 1
                    flag = result.get("flag", "")
                    dur = result.get("duration_seconds", 0)
                    print(
                        f"  [{idx + 1}/{len(solve_challenges)}] {cid} \033[32mSOLVED\033[0m {flag} ({dur:.0f}s)",
                        flush=True,
                    )

                    # Auto-lock flag format
                    if not _detected_prefix and flag:
                        prefix_m = re.match(r"^([A-Za-z0-9_]+)\{", flag)
                        if prefix_m:
                            _detected_prefix = prefix_m.group(1)
                            print(f"  \033[34m[locked]\033[0m Flag format: {_detected_prefix}{{...}}", flush=True)

                    # Auto-submit
                    if not args.no_submit and cid in ctfd_id_map:
                        fmt = _normalize_flag_format(f"{_detected_prefix}{{}}") if _detected_prefix else ""
                        sub = client.submit_flag(ctfd_id_map[cid], flag, flag_format=fmt)
                        result["submit_status"] = sub.status
                        if sub.status == "correct":
                            submitted += 1
                            print(
                                f"  [{idx + 1}/{len(solve_challenges)}] {cid} \033[32m[+] SUBMITTED\033[0m", flush=True
                            )
                        elif sub.status == "skipped":
                            print(
                                f"  [{idx + 1}/{len(solve_challenges)}] {cid} \033[33m⊘ SKIP SUBMIT\033[0m {sub.message}",
                                flush=True,
                            )
                        elif sub.status == "already_solved":
                            submitted += 1
                            print(
                                f"  [{idx + 1}/{len(solve_challenges)}] {cid} \033[34m[+] ALREADY SOLVED\033[0m",
                                flush=True,
                            )
                        else:
                            print(
                                f"  [{idx + 1}/{len(solve_challenges)}] {cid} \033[31m[x] {sub.status}\033[0m {sub.message}",
                                flush=True,
                            )
                else:
                    failed += 1
                    err = (result.get("error") or "")[:40]
                    print(f"  [{idx + 1}/{len(solve_challenges)}] {cid} \033[31mFAILED\033[0m {err}", flush=True)

            return result

    async def _run_all():
        sem = asyncio.Semaphore(concurrency)
        tasks = [_solve_one(i, chal, sem) for i, chal in enumerate(solve_challenges)]
        await asyncio.gather(*tasks, return_exceptions=True)

    asyncio.run(_run_all())

    wall_time = _time.monotonic() - _wall_start

    # ── Step 6: Results ──────────────────────────────────────────────
    print(f"\n{'━' * 60}")
    print("  KRAKEN CTF -- Competition Results")
    print(f"{'━' * 60}")
    print(f"  CTF:       {client.ctf_name}")
    print(f"  Solved:    {solved}/{len(solve_challenges)}")
    print(f"  Submitted: {submitted}")
    print(f"  Failed:    {failed}")
    print(f"  Wall time: {wall_time:.0f}s (parallel)")
    if _detected_prefix:
        print(f"  Flag fmt:  {_detected_prefix}{{...}}")
    print(f"{'━' * 60}\n")

    # Save results
    out_file = solutions_dir / "ctf_results.json"
    out_file.write_text(json.dumps(results, indent=2, default=str))
    print(f"  Results: {out_file}")

    # Write solve ledger
    _write_solve_ledger(solutions_dir, results, client.ctf_name, args)

    return 0 if solved > 0 else 1


def _write_solve_ledger(solutions_dir: Path, results: list[dict], folder_name: str, args) -> None:
    """Write a comprehensive solve_ledger.md summarizing all challenge results."""
    from datetime import datetime

    ledger_path = solutions_dir / "solve_ledger.md"
    solved_count = sum(1 for r in results if r.get("solved"))
    total = len(results)
    total_time = sum(r.get("duration_seconds", 0) for r in results)

    lines = [
        f"# Solve Ledger: {folder_name}/",
        "",
        f"**Date**: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Backend**: {'ollama' if args.local else (args.model or 'default')}",
    ]
    if args.local:
        lines.append(f"**Model**: {args.local[0]}")
    lines.extend(
        [
            f"**Timeout**: {args.timeout}min per challenge",
            f"**Score**: {solved_count}/{total} ({100 * solved_count // max(total, 1)}%)",
            f"**Total time**: {total_time:.0f}s",
            "",
            "## Results",
            "",
            "| # | Challenge | Status | Flag | Time |",
            "|---|-----------|--------|------|------|",
        ]
    )

    for i, r in enumerate(results, 1):
        cid = r.get("challenge_id", "?")
        status = "SOLVED" if r.get("solved") else "FAILED"
        flag = r.get("flag", "") or r.get("error", "")[:30] or "-"
        dur = r.get("duration_seconds", 0)
        time_str = f"{dur:.1f}s" if dur else "timeout"
        lines.append(f"| {i} | {cid} | {status} | `{flag}` | {time_str} |")

    lines.extend(["", "## Per-Challenge Details", ""])

    for r in results:
        cid = r.get("challenge_id", "?")
        status = "SOLVED" if r.get("solved") else "FAILED"
        lines.append(f"### {cid} -- {status}")
        lines.append("")

        if r.get("flag"):
            lines.append(f"**Flag**: `{r['flag']}`")
        if r.get("error"):
            lines.append(f"**Error**: {r['error']}")
        if r.get("duration_seconds"):
            lines.append(f"**Duration**: {r['duration_seconds']:.1f}s")
        if r.get("challenge_type"):
            lines.append(f"**Type**: {r['challenge_type']}")

        strategies = r.get("strategies_tried", [])
        if strategies:
            lines.append(f"**Strategies**: {', '.join(strategies)}")

        solve_path = r.get("solve_path", [])
        if solve_path:
            lines.append(f"**Solve path**: {' → '.join(solve_path)}")

        timings = r.get("node_timings", [])
        if timings:
            lines.append("")
            lines.append("| Node | Time |")
            lines.append("|------|------|")
            for t in timings:
                lines.append(f"| {t['node']} | {t['duration_s']:.1f}s |")

        lines.append("")

    ledger_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Solve ledger saved to {ledger_path}")


def main():
    """CLI entry point."""
    import argparse
    import sys

    # Backwards compat: `kraken basic.json` -> `kraken solve basic.json`
    # Must happen before argparse sees sys.argv, because Python 3.14+
    # validates subparser choices even with parse_known_args().
    if len(sys.argv) > 1 and sys.argv[1] not in ("solve", "solve-all", "ctf", "init", "knowledge", "-h", "--help"):
        sys.argv.insert(1, "solve")

    parser = argparse.ArgumentParser(description="KRAKEN: Autonomous CTF Solver")
    subparsers = parser.add_subparsers(dest="command")

    # solve -- positional challenge path
    solve_parser = subparsers.add_parser("solve", help="Solve a challenge")
    solve_parser.add_argument("challenge", help="Path to challenge JSON config or directory")
    solve_parser.add_argument("--model", type=str, default=None, help="Model name (overrides config)")
    solve_parser.add_argument(
        "--backend", type=str, default=None, choices=["claude", "anthropic", "openai", "ollama"], help="LLM backend"
    )
    solve_parser.add_argument(
        "--local",
        nargs=2,
        metavar=("LARGE", "SMALL"),
        help="Use local Ollama: --local <large_model> <small_model>",
    )
    solve_parser.add_argument("--flag-format", type=str, default=None, help="Flag format (e.g., 'vere{}', 'flag{}')")
    solve_parser.add_argument("--category", type=str, default=None, help="Challenge category")
    solve_parser.add_argument("--timeout", type=int, default=30, help="Timeout in minutes")
    solve_parser.add_argument("--benchmark", action="store_true", help="Benchmark mode")
    solve_parser.add_argument("--verbose", action="store_true", help="Verbose JSON logging")
    solve_parser.add_argument("--no-progress", action="store_true", help="Disable progress display")
    solve_parser.add_argument(
        "--report",
        type=str,
        nargs="?",
        const="writeup",
        default=None,
        choices=["writeup", "analysis", "benchmark"],
        help="Generate report after solve (default: writeup)",
    )
    solve_parser.add_argument("--report-out", type=str, default=None, help="Report output file path")

    # solve-all -- batch solve a directory of challenges
    batch_parser = subparsers.add_parser("solve-all", help="Solve all challenges in a directory")
    batch_parser.add_argument("directory", help="Directory containing challenge subdirectories")
    batch_parser.add_argument("--model", type=str, default=None, help="Model (overrides config)")
    batch_parser.add_argument(
        "--backend", type=str, default=None, choices=["claude", "anthropic", "openai", "ollama"], help="LLM backend"
    )
    batch_parser.add_argument(
        "--local",
        nargs=2,
        metavar=("LARGE", "SMALL"),
        help="Use local Ollama: --local <large_model> <small_model>",
    )
    batch_parser.add_argument("--timeout", type=int, default=30, help="Timeout per challenge in minutes")
    batch_parser.add_argument("--concurrency", "-j", type=int, default=0, help="Max parallel solvers (default: all)")
    batch_parser.add_argument("--flag-format", type=str, default="flag{}", help="Flag format (default: flag{})")
    batch_parser.add_argument("--category", type=str, default="rev", help="Category for all challenges (default: rev)")
    batch_parser.add_argument("--verbose", action="store_true", help="Verbose JSON logging")

    # ctf -- live competition mode (pull from CTFd + parallel solve + auto-submit)
    ctf_parser = subparsers.add_parser("ctf", help="Run a live CTF competition from a CTFd instance")
    ctf_parser.add_argument("url", help="CTFd instance URL (e.g., https://ctf.example.com)")
    ctf_parser.add_argument("--token", type=str, required=True, help="CTFd API access token")
    ctf_parser.add_argument("--timeout", type=int, default=10, help="Timeout per challenge in minutes (default: 10)")
    ctf_parser.add_argument("--concurrency", "-j", type=int, default=0, help="Max parallel solvers (default: all)")
    ctf_parser.add_argument("--no-submit", action="store_true", help="Don't auto-submit flags (just solve)")
    ctf_parser.add_argument(
        "--backend",
        type=str,
        default="claude",
        choices=["claude", "anthropic", "openai", "ollama"],
        help="LLM backend (default: claude)",
    )
    ctf_parser.add_argument("--verbose", action="store_true", help="Verbose JSON logging")

    # init -- interactive challenge creation
    subparsers.add_parser("init", help="Create a challenge config interactively")

    # knowledge -- query solve knowledge base
    kb_parser = subparsers.add_parser("knowledge", help="Query the solve knowledge base")
    kb_parser.add_argument("--solves-root", default="benchmarks", help="Root directory with solve artifacts")
    kb_parser.add_argument("--technique", "-t", default="", help="Query by technique name")
    kb_parser.add_argument("--type", "-T", dest="constraint_type", default="", help="Query by constraint type")
    kb_parser.add_argument("--similar", "-s", default="", help="Find challenges similar to NAME")
    kb_parser.add_argument("--suggest", default="", help="Path to binary for approach suggestion")
    kb_parser.add_argument("--stats", action="store_true", help="Show aggregate statistics")
    kb_parser.add_argument("--list", "-l", action="store_true", help="List all indexed challenges")
    kb_parser.add_argument("--json", "-j", action="store_true", help="Output as JSON")

    args = parser.parse_args()

    if args.command == "knowledge":
        # Delegate to knowledge module CLI -- inject parsed args (no "knowledge" subcommand)
        sys.argv = [
            "kraken",
            *(["--solves-root", args.solves_root] if args.solves_root != "benchmarks" else []),
            *(["--technique", args.technique] if args.technique else []),
            *(["--type", args.constraint_type] if args.constraint_type else []),
            *(["--similar", args.similar] if args.similar else []),
            *(["--suggest", args.suggest] if args.suggest else []),
            *(["--stats"] if args.stats else []),
            *(["--list"] if getattr(args, "list", False) else []),
            *(["--json"] if args.json else []),
        ]
        from kraken.storage.solve_knowledge import cli_main

        cli_main()
        return 0

    if args.command == "init":
        return create_challenge()

    if args.command == "ctf":
        return _cmd_ctf(args)

    if args.command == "solve-all":
        return _cmd_solve_all(args)

    if args.command == "solve":
        challenge_path = args.challenge
        timeout = args.timeout
        verbose = args.verbose
        show_progress = not args.no_progress
    else:
        parser.print_help()
        return 1

    configure_logging(json_output=verbose)

    config = KrakenConfig()
    config.budget.timeout_minutes = timeout

    # --backend: set LLM backend explicitly
    if args.backend:
        config.models.backend = args.backend

    orchestrator = Orchestrator(config=config)

    # Support both JSON config files and bare directory paths
    cp = Path(challenge_path)
    if cp.is_file() and cp.suffix == ".json":
        challenge_config = json.loads(cp.read_text())
        challenge_config = _normalize_challenge_id(challenge_config, challenge_path)
    elif cp.is_dir():
        challenge_config = _build_dir_challenge_config(cp, args.category)
    else:
        # Legacy: treat as JSON
        challenge_config = json.loads(cp.read_text())
        challenge_config = _normalize_challenge_id(challenge_config, challenge_path)

    # CLI --model overrides everything
    if args.model:
        challenge_config["model"] = args.model

    # --backend flag on solve command
    if args.backend:
        challenge_config["backend"] = args.backend

    # --flag-format (explicitly requested on the CLI, so honor it over auto-detect)
    if args.flag_format:
        challenge_config["flag_format"] = _normalize_flag_format(args.flag_format)
        challenge_config["flag_format_explicit"] = True

    # --category
    if args.category:
        challenge_config["category"] = args.category

    # --local: set backend=ollama with large/small model split
    if args.local:
        large, small = args.local
        challenge_config["backend"] = "ollama"
        challenge_config["model_high"] = large
        challenge_config["model_mid"] = large
        challenge_config["model_low"] = small

    # --benchmark
    if args.benchmark:
        challenge_config["benchmark"] = True

    result = asyncio.run(orchestrator.solve(challenge_config, progress=show_progress))

    print(json.dumps(result, indent=2))

    if result["solved"]:
        print(f"\nFLAG: {result['flag']}")
    else:
        print("\nChallenge not solved.")

    # Generate report if requested
    if args.report:
        from kraken.reporting import generate_report

        report_path = args.report_out or f"{challenge_config.get('challenge_id', 'report')}_{args.report}.md"
        report = generate_report(result, state=result, mode=args.report, output_path=report_path)
        print(f"\nReport written to: {report_path}")

    return 0 if result["solved"] else 1


if __name__ == "__main__":
    exit(main())
