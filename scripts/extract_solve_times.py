#!/usr/bin/env python3
"""Solve-time extractor (hybrid: in-solve tracking + postmortem JSONL).

Reconstructs accurate time-to-solve for each challenge in a CTF workspace using
two sources, in priority order:

1. **Primary -- per-challenge `session.json`:** Written by the solving agent
   itself during the solve. Contains `total_elapsed`, `start_ts`, `end_ts`.
   This is the authoritative source and is required for parallel Agent
   fan-outs (e.g. `/solve-all`) because subagent transcripts are NOT persisted
   to `~/.claude/projects/` -- their internal tool calls are invisible to
   postmortem JSONL reconstruction.

2. **Fallback -- JSONL postmortem:** Greps `~/.claude/projects/<project>/*.jsonl`
   for events referencing the challenge path, detects flag.txt writes as the
   end anchor, and computes the window. Only works for cascade/MCP solves that
   run in the main session -- NOT for parallel Agent spawns.

A batch-anchor filter rejects events (git status, ls, flag-summary messages)
where a single event would anchor more than 2 challenges simultaneously.

Usage:
    python3 scripts/extract_solve_times.py ctfs/byu-eos-ctf
    python3 scripts/extract_solve_times.py ctfs/byu-eos-ctf --update-readmes
    python3 scripts/extract_solve_times.py ctfs/byu-eos-ctf --session 2ffb0cd2
    python3 scripts/extract_solve_times.py ctfs/byu-eos-ctf --no-jsonl   # only session.json

Output:
    {workspace}/solve_times.json    -- authoritative time-to-solve map
    (with --update-readmes) injects "**Solve time:** Ns" into each README

To ensure accurate times are captured at solve time, agents spawned by
`/solve-all` MUST write `session.json` with:
    {
      "challenge": "Category/Name",
      "start_ts": 1712800000.0,
      "end_ts":   1712800228.0,
      "total_elapsed": 228,
      "source": "agent" | "cascade" | "mcp"
    }
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# ── Event parsing ────────────────────────────────────────────────────────────


def _parse_ts(s: str) -> float | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def _event_text(ev: dict) -> str:
    """Flatten all text in an event -- tool args, tool results, message content."""
    parts: list[str] = []
    msg = ev.get("message") or {}
    content = msg.get("content")
    if isinstance(content, str):
        parts.append(content)
    elif isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                parts.append(block.get("text") or "")
            elif block.get("type") == "tool_use":
                parts.append(json.dumps(block.get("input") or {}))
            elif block.get("type") == "tool_result":
                c = block.get("content")
                if isinstance(c, str):
                    parts.append(c)
                elif isinstance(c, list):
                    for b in c:
                        if isinstance(b, dict) and b.get("type") == "text":
                            parts.append(b.get("text") or "")
    tur = ev.get("toolUseResult")
    if isinstance(tur, dict):
        parts.append(json.dumps(tur))
    elif isinstance(tur, str):
        parts.append(tur)
    att = ev.get("attachment")
    if isinstance(att, dict):
        parts.append(json.dumps(att))
    return "\n".join(parts)


def _iter_events(log_dir: Path, session_filter: str | None = None):
    for f in sorted(log_dir.glob("*.jsonl")):
        if session_filter and session_filter not in f.name:
            continue
        try:
            with f.open() as fh:
                for line in fh:
                    try:
                        yield f.stem, json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue


# ── Challenge discovery ──────────────────────────────────────────────────────


@dataclass
class Challenge:
    workspace: Path
    category: str
    dir_name: str
    path: Path
    flag: str | None = None

    @property
    def rel_path(self) -> str:
        return str(self.path.relative_to(self.workspace.parent))

    @property
    def name_tokens(self) -> list[str]:
        return [
            str(self.path),
            str(self.path.resolve()),
            self.rel_path,
            f"{self.category}/{self.dir_name}",
            self.dir_name,
        ]


def discover_challenges(workspace: Path) -> list[Challenge]:
    chals: list[Challenge] = []
    for chal_dir in sorted(workspace.glob("*/*")):
        if not chal_dir.is_dir() or chal_dir.name.startswith("pass"):
            continue
        if not (chal_dir / "challenge.json").exists():
            continue
        flag_f = chal_dir / "flag.txt"
        flag = None
        if flag_f.exists():
            try:
                first = flag_f.read_text().strip().splitlines()
                if first and "{" in first[0]:
                    flag = first[0]
            except OSError:
                pass
        chals.append(
            Challenge(
                workspace=workspace,
                category=chal_dir.parent.name,
                dir_name=chal_dir.name,
                path=chal_dir,
                flag=flag,
            )
        )
    return chals


# ── Time reconstruction ──────────────────────────────────────────────────────


@dataclass
class Window:
    start_ts: float | None = None
    end_ts: float | None = None
    start_src: str = ""
    end_src: str = ""
    event_count: int = 0
    session_ids: set[str] = field(default_factory=set)
    source: str = "jsonl"  # "session.json" (authoritative) | "jsonl" (postmortem)

    @property
    def elapsed(self) -> int | None:
        if self.start_ts is None or self.end_ts is None:
            return None
        return max(0, int(round(self.end_ts - self.start_ts)))


def _window_from_session_json(chal: Challenge) -> Window | None:
    """Primary source: per-challenge session.json written by the solving agent.

    Schema (any of these fields satisfies a valid window):
        total_elapsed: int (seconds)
        start_ts: float (unix) OR start: ISO string
        end_ts: float (unix) OR end: ISO string
    """
    sj = chal.path / "session.json"
    if not sj.exists():
        return None
    try:
        data = json.loads(sj.read_text())
    except (json.JSONDecodeError, OSError):
        return None

    w = Window(source="session.json")

    def _coerce_ts(val) -> float | None:
        if val is None:
            return None
        if isinstance(val, (int, float)):
            return float(val)
        if isinstance(val, str):
            return _parse_ts(val)
        return None

    w.start_ts = _coerce_ts(data.get("start_ts") or data.get("start"))
    w.end_ts = _coerce_ts(data.get("end_ts") or data.get("end"))

    # If total_elapsed is present, use it to synthesize a window even without
    # start/end timestamps. We anchor end_ts to the mtime of session.json
    # (last write) and back-compute start_ts.
    elapsed = data.get("total_elapsed")
    if elapsed is not None and (w.start_ts is None or w.end_ts is None):
        try:
            end_ts = sj.stat().st_mtime
            w.end_ts = end_ts
            w.start_ts = end_ts - float(elapsed)
        except OSError:
            pass

    if w.start_ts is None or w.end_ts is None:
        return None

    w.event_count = 1
    return w


def _path_tokens(chal: Challenge) -> list[str]:
    """Candidate substrings that uniquely identify this challenge in event text."""
    tokens = set()
    tokens.add(f"{chal.category}/{chal.dir_name}")
    tokens.add(str(chal.path))
    try:
        tokens.add(str(chal.path.resolve()))
    except Exception:
        pass
    # Quoted forms that appear in tool inputs
    tokens.add(f'"{chal.category}/{chal.dir_name}"')
    return [t for t in tokens if t]


def _is_flag_anchor(text: str, chal: Challenge, path_tokens: list[str]) -> bool:
    """Strict anchor: event writes flag.txt at this specific challenge path.

    We do NOT accept "flag string appears + path mentioned" because that matches
    batch summary messages that list all flags at once, producing identical
    end-times for many challenges. The actual flag-capture event is the `Write`
    or `Edit` tool call that persists `flag.txt` to the challenge directory.
    """
    for tok in path_tokens:
        if f"{tok}/flag.txt" in text:
            return True
    return False


def build_windows(
    chals: list[Challenge],
    log_dir: Path,
    session_filter: str | None = None,
    after: float | None = None,
    before: float | None = None,
) -> dict[str, Window]:
    """Two-pass reconstruction:

    1. For each challenge, collect ALL (ts, session_id, is_anchor) triples where
       the event text references the challenge path.
    2. End = earliest flag-anchor event (first flag capture wins).
    3. Start = earliest non-anchor event in the SAME session as that anchor,
       before the anchor timestamp. Falls back to first event overall if no
       same-session prior event exists.

    This rejects later writeup/documentation sessions that re-mention the
    challenge path long after the flag was captured.
    """
    token_map = {f"{c.category}/{c.dir_name}": _path_tokens(c) for c in chals}
    chal_map = {f"{c.category}/{c.dir_name}": c for c in chals}

    # key → list of (ts, session_id, is_anchor)
    hits: dict[str, list[tuple[float, str, bool]]] = {k: [] for k in token_map}

    # Threshold: an event whose text matches "flag.txt" anchor for MORE than
    # this many distinct challenges is a batch listing (git status, ls, etc.)
    # and must NOT be treated as an anchor for any of them.
    BATCH_ANCHOR_THRESHOLD = 2

    for sess_id, ev in _iter_events(log_dir, session_filter):
        ts_raw = ev.get("timestamp")
        ts = _parse_ts(ts_raw) if isinstance(ts_raw, str) else None
        if ts is None:
            continue
        if after is not None and ts < after:
            continue
        if before is not None and ts > before:
            continue
        text = _event_text(ev)
        if not text:
            continue

        # First: figure out which challenges this event hits and whether it's
        # a plausible anchor for each.
        per_key: list[tuple[str, bool]] = []
        for key, tokens in token_map.items():
            if not any(tok in text for tok in tokens):
                continue
            chal = chal_map[key]
            is_anchor = _is_flag_anchor(text, chal, tokens)
            per_key.append((key, is_anchor))

        if not per_key:
            continue

        # If this event "anchors" many challenges at once, it's a batch listing
        # (git status, ls, flag-summary message). Strip anchor status from ALL.
        anchor_count = sum(1 for _, a in per_key if a)
        if anchor_count > BATCH_ANCHOR_THRESHOLD:
            per_key = [(k, False) for k, _ in per_key]

        for key, is_anchor in per_key:
            hits[key].append((ts, sess_id, is_anchor))

    windows: dict[str, Window] = {}
    for key, events in hits.items():
        w = Window()
        if not events:
            windows[key] = w
            continue
        w.event_count = len(events)
        w.session_ids = {s for _, s, _ in events}

        # End = earliest flag anchor
        anchors = [(ts, sid) for ts, sid, a in events if a]
        if anchors:
            anchors.sort()
            w.end_ts, w.end_src = anchors[0]
            # Start = earliest event in same session, ≤ end_ts
            same_session = [(ts, sid) for ts, sid, _ in events if sid == w.end_src and ts <= w.end_ts]
            if same_session:
                same_session.sort()
                w.start_ts, w.start_src = same_session[0]
            else:
                first = min(events, key=lambda e: e[0])
                w.start_ts, w.start_src = first[0], first[1]
        else:
            # No flag anchor (unsolved) -- still record the window for debugging,
            # but elapsed will be meaningless, so leave start/end None.
            pass
        windows[key] = w

    return windows


# ── Output ───────────────────────────────────────────────────────────────────


def write_json(workspace: Path, chals: list[Challenge], windows: dict[str, Window]) -> Path:
    out = {
        "workspace": str(workspace),
        "generated_at": datetime.now(UTC).isoformat(),
        "challenges": [],
    }
    for c in chals:
        key = f"{c.category}/{c.dir_name}"
        w = windows[key]
        out["challenges"].append(
            {
                "category": c.category,
                "name": c.dir_name,
                "flag": c.flag,
                "elapsed_seconds": w.elapsed,
                "source": w.source,
                "start": datetime.fromtimestamp(w.start_ts, UTC).isoformat() if w.start_ts else None,
                "end": datetime.fromtimestamp(w.end_ts, UTC).isoformat() if w.end_ts else None,
                "event_count": w.event_count,
                "sessions": sorted(w.session_ids),
            }
        )
    out_path = workspace / "solve_times.json"
    out_path.write_text(json.dumps(out, indent=2))
    return out_path


README_MARKER = "<!-- solve-time: extracted -->"


def update_readme(chal: Challenge, window: Window) -> bool:
    if window.elapsed is None:
        return False
    readme = chal.path / "README.md"
    if not readme.exists():
        return False
    line = f"**Solve time:** {window.elapsed}s {README_MARKER}"
    txt = readme.read_text()
    if README_MARKER in txt:
        txt = re.sub(r"\*\*Solve time:\*\*[^\n]*" + re.escape(README_MARKER), line, txt)
    else:
        lines = txt.splitlines()
        inserted = False
        for i, ln in enumerate(lines):
            if ln.startswith("# "):
                lines.insert(i + 1, "")
                lines.insert(i + 2, line)
                inserted = True
                break
        if not inserted:
            lines.insert(0, line)
        txt = "\n".join(lines)
    readme.write_text(txt)
    return True


# ── CLI ──────────────────────────────────────────────────────────────────────


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("workspace", help="CTF workspace dir, e.g. ctfs/byu-eos-ctf")
    ap.add_argument(
        "--log-dir",
        default=str(Path.home() / ".claude/projects/-home-kraken"),
        help="Claude Code session log directory",
    )
    ap.add_argument("--session", help="Filter to sessions whose filename contains this substring")
    ap.add_argument("--after", help="Ignore events before this ISO timestamp (e.g. 2026-04-10T00:00:00Z)")
    ap.add_argument("--before", help="Ignore events after this ISO timestamp")
    ap.add_argument(
        "--update-readmes", action="store_true", help="Inject '**Solve time:** Ns' into each challenge README"
    )
    ap.add_argument("--no-jsonl", action="store_true", help="Disable JSONL postmortem fallback; only use session.json")
    ap.add_argument(
        "--no-session-json", action="store_true", help="Disable session.json primary source; only use JSONL"
    )
    args = ap.parse_args()

    workspace = Path(args.workspace).resolve()
    if not workspace.is_dir():
        print(f"workspace not found: {workspace}", file=sys.stderr)
        return 1

    log_dir = Path(args.log_dir)
    if not log_dir.is_dir():
        print(f"log dir not found: {log_dir}", file=sys.stderr)
        return 1

    after = _parse_ts(args.after) if args.after else None
    before = _parse_ts(args.before) if args.before else None

    chals = discover_challenges(workspace)
    if not chals:
        print("no challenges found (need category/name/challenge.json layout)", file=sys.stderr)
        return 1

    print(f"workspace: {workspace}")
    print(f"challenges: {len(chals)}")
    print(f"log dir: {log_dir}")
    if args.session:
        print(f"session filter: {args.session}")

    # Primary: per-challenge session.json (authoritative, in-solve tracking)
    windows: dict[str, Window] = {}
    session_json_hits = 0
    if not args.no_session_json:
        for c in chals:
            w = _window_from_session_json(c)
            if w is not None:
                windows[f"{c.category}/{c.dir_name}"] = w
                session_json_hits += 1
        if session_json_hits:
            print(f"session.json hits: {session_json_hits}/{len(chals)}")

    # Fallback: JSONL postmortem for challenges without session.json
    if not args.no_jsonl:
        missing = [c for c in chals if f"{c.category}/{c.dir_name}" not in windows]
        if missing:
            jsonl_windows = build_windows(missing, log_dir, args.session, after, before)
            for k, w in jsonl_windows.items():
                windows[k] = w
            jsonl_solved = sum(
                1
                for c in missing
                if windows.get(f"{c.category}/{c.dir_name}")
                and windows[f"{c.category}/{c.dir_name}"].elapsed is not None
            )
            print(f"jsonl postmortem hits: {jsonl_solved}/{len(missing)}")

    # Ensure every challenge has a window entry (even if empty)
    for c in chals:
        key = f"{c.category}/{c.dir_name}"
        if key not in windows:
            windows[key] = Window()

    solved = sum(1 for c in chals if windows[f"{c.category}/{c.dir_name}"].elapsed is not None)
    print(f"reconstructed elapsed for {solved}/{len(chals)} challenges")

    out_path = write_json(workspace, chals, windows)
    print(f"wrote {out_path}")

    updated = 0
    if args.update_readmes:
        for c in chals:
            if update_readme(c, windows[f"{c.category}/{c.dir_name}"]):
                updated += 1
        print(f"updated READMEs: {updated}")

    # Summary table
    print()
    print(f"{'Category':<12} {'Challenge':<40} {'Elapsed':>8}")
    print("-" * 62)
    for c in chals:
        w = windows[f"{c.category}/{c.dir_name}"]
        elapsed = f"{w.elapsed}s" if w.elapsed is not None else "--"
        print(f"{c.category:<12} {c.dir_name[:40]:<40} {elapsed:>8}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
