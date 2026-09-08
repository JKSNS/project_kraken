"""Loop detection for Kraken solve graphs.

Tracks recent node visits and solve script signatures to detect
repetitive cycles that waste budget without progress.  Inspired by
ctf-agent's sliding-window approach but adapted for Kraken's
deterministic-first architecture:

  1. **Node-level**: detects repeated graph cycles
     (e.g. manager -> solve_engine -> flag_validator -> manager x5)
  2. **Script-level**: detects near-identical solve scripts across
     attempts (same code hash submitted repeatedly)
  3. **Output-level**: detects identical stdout/stderr across
     consecutive tool executions

All three layers are exposed via simple check functions that return
a verdict: None (no loop), "warn", or "break".
"""

from __future__ import annotations

import hashlib
from collections import deque
from dataclasses import dataclass, field


# ── Verdicts ────────────────────────────────────────────────────────

VERDICT_WARN = "warn"
VERDICT_BREAK = "break"

LOOP_WARNING = (
    "LOOP DETECTED: You have repeated the exact same action multiple "
    "times with identical results.  STOP repeating this approach.  "
    "Step back, reconsider, and try a completely different technique "
    "or tool."
)


# ── Node-cycle detector ────────────────────────────────────────────

@dataclass
class NodeCycleDetector:
    """Detect repeated node-visit sequences in the graph.

    Maintains a sliding window of the last *window* node names.
    If the same cycle of length 2..max_cycle_len repeats
    *break_threshold* times within the window, returns "break".
    """

    window: int = 20
    warn_threshold: int = 3
    break_threshold: int = 5
    max_cycle_len: int = 4
    _history: deque[str] = field(default_factory=lambda: deque(maxlen=20))

    def __post_init__(self) -> None:
        self._history = deque(maxlen=self.window)

    def record(self, node_name: str) -> str | None:
        """Append *node_name* and check for cycles.

        Returns ``None``, ``"warn"``, or ``"break"``.
        """
        self._history.append(node_name)
        history = list(self._history)
        n = len(history)

        for cycle_len in range(2, self.max_cycle_len + 1):
            if n < cycle_len * self.warn_threshold:
                continue
            cycle = tuple(history[-cycle_len:])
            count = 0
            for i in range(n - cycle_len, -1, -cycle_len):
                if tuple(history[i:i + cycle_len]) == cycle:
                    count += 1
                else:
                    break
            if count >= self.break_threshold:
                return VERDICT_BREAK
            if count >= self.warn_threshold:
                return VERDICT_WARN
        return None

    def reset(self) -> None:
        self._history.clear()


# ── Script-signature detector ──────────────────────────────────────

def _code_hash(code: str) -> str:
    """Normalize whitespace and hash code for dedup."""
    normalized = " ".join(code.split())
    return hashlib.sha256(normalized.encode()).hexdigest()[:16]


@dataclass
class ScriptRepeatDetector:
    """Detect repeated solve scripts (same code submitted multiple times).

    Tracks content hashes of recent scripts.  If the same hash appears
    *break_threshold* times within the last *window* scripts, returns
    "break".
    """

    window: int = 12
    warn_threshold: int = 2
    break_threshold: int = 3
    _hashes: deque[str] = field(default_factory=lambda: deque(maxlen=12))

    def __post_init__(self) -> None:
        self._hashes = deque(maxlen=self.window)

    def check(self, code: str) -> str | None:
        """Record a script and check for repeats."""
        h = _code_hash(code)
        self._hashes.append(h)
        count = self._hashes.count(h)
        if count >= self.break_threshold:
            return VERDICT_BREAK
        if count >= self.warn_threshold:
            return VERDICT_WARN
        return None

    def reset(self) -> None:
        self._hashes.clear()


# ── Tool-output detector (for tool_router cascade) ────────────────

def _output_sig(tool_name: str, stdout: str, exit_code: int) -> str:
    """Create a signature from tool name + truncated output + exit code."""
    content = f"{tool_name}:{exit_code}:{stdout[:500]}"
    return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class ToolOutputRepeatDetector:
    """Detect identical tool outputs across cascade runs.

    If the same tool produces the same output *break_threshold* times
    across cascade invocations, signals that rerunning it is pointless.
    """

    window: int = 16
    warn_threshold: int = 3
    break_threshold: int = 5
    _sigs: deque[str] = field(default_factory=lambda: deque(maxlen=16))

    def __post_init__(self) -> None:
        self._sigs = deque(maxlen=self.window)

    def check(self, tool_name: str, stdout: str, exit_code: int) -> str | None:
        sig = _output_sig(tool_name, stdout, exit_code)
        self._sigs.append(sig)
        count = self._sigs.count(sig)
        if count >= self.break_threshold:
            return VERDICT_BREAK
        if count >= self.warn_threshold:
            return VERDICT_WARN
        return None

    def reset(self) -> None:
        self._sigs.clear()


# ── Convenience: check solve history from state dict ──────────────

def check_solve_script_loop(state: dict) -> str | None:
    """One-shot check against solve_scripts already in state.

    Examines the last 12 solve scripts for repeated code hashes.
    Returns None, "warn", or "break".
    """
    scripts = state.get("solve_scripts", [])
    if len(scripts) < 2:
        return None

    detector = ScriptRepeatDetector()
    verdict = None
    for script in scripts[-12:]:
        code = script.get("code", "")
        if not code:
            continue
        v = detector.check(code)
        if v is not None:
            verdict = v
    return verdict


def check_node_cycle(state: dict) -> str | None:
    """One-shot check against solve_path already in state.

    Examines the last 20 node visits for repeating cycles.
    Returns None, "warn", or "break".
    """
    solve_path = state.get("solve_path", [])
    if len(solve_path) < 6:
        return None

    detector = NodeCycleDetector()
    verdict = None
    for node in solve_path[-20:]:
        v = detector.record(node)
        if v is not None:
            verdict = v
    return verdict
