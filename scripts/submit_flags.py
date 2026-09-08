#!/usr/bin/env python3
"""Submit validated flag.txt files from a solve-all workspace to CTFd.

Reads flag.txt under every {category}/{challenge}/ inside a CTFd workspace,
applies strict validation gates (format match, reject known placeholders),
then submits via CTFdClient.submit_flag -- one attempt per challenge, matching
the Kraken flag-submission policy.

Usage:
    python3 scripts/submit_flags.py --url https://ctf.example.com \\
        --token ctfd_xxx --dir ctfs/eos --format "byuctf{}"
    python3 scripts/submit_flags.py --url ... --token ... --dir ctfs/eos --dry-run
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kraken.ctfd import CTFdClient

PLACEHOLDER_PATTERNS = [
    r"fake[_ ]?flag",
    r"test[_ ]?(local[_ ]?)?flag",
    r"\bexample\b",
    r"placeholder",
    r"\bunknown\b",
    r"not[_ ]?captured",
    r"no[_ ]?remote",
    r"flag[_ ]?not[_ ]",
    r"name[_ ]?of[_ ]",
    r"\bunsolved\b",
    r"\bfailed\b",
    r"endpoint[_ ]?available",
    r"fake",
    r"xxxxx",
    r"\?\?\?\?",
]


def looks_like_placeholder(flag: str) -> bool:
    for pat in PLACEHOLDER_PATTERNS:
        if re.search(pat, flag, re.IGNORECASE):
            return True
    return False


def flag_regex_from_format(fmt: str) -> re.Pattern:
    brace_open = fmt.find("{")
    prefix = fmt[:brace_open] if brace_open >= 0 else fmt
    prefix_esc = re.escape(prefix)
    # Allow 1+ non-brace, non-whitespace char between braces -- some challenges
    # have single-digit flags like byuctf{8}.
    return re.compile(rf"^{prefix_esc}\{{[^}}\s]{{1,}}\}}$")


def load_solved_set(workspace: Path) -> set[str]:
    """Return names of challenges whose status is SOLVED/ALREADY_SOLVED
    according to pass_state.json, so we skip them on repeat runs.

    This makes submit_flags.py idempotent -- running it twice never
    re-submits a validated flag.
    """
    state_path = workspace / "pass_state.json"
    if not state_path.exists():
        return set()
    try:
        raw = json.loads(state_path.read_text())
    except Exception:
        return set()
    return {
        name
        for name, entry in raw.items()
        if entry.get("status") in {"SOLVED", "ALREADY_SOLVED"}
        or entry.get("failure_class") in {"SOLVED", "ALREADY_SOLVED"}
    }


def load_incorrect_set(workspace: Path) -> set[str]:
    """Return names of challenges that already received an incorrect
    submission. The one-attempt rule means we never resubmit these.
    """
    state_path = workspace / "pass_state.json"
    if not state_path.exists():
        return set()
    try:
        raw = json.loads(state_path.read_text())
    except Exception:
        return set()
    return {
        name
        for name, entry in raw.items()
        if entry.get("status") == "INCORRECT"
        or entry.get("failure_class") == "ALREADY_SUBMITTED_INCORRECT"
    }


def collect_candidates(workspace: Path, fmt_re: re.Pattern) -> list[dict]:
    already_solved = load_solved_set(workspace)
    already_incorrect = load_incorrect_set(workspace)

    candidates = []
    for flag_file in sorted(workspace.glob("*/*/flag.txt")):
        raw = flag_file.read_text(errors="replace").strip()
        first_line = raw.splitlines()[0].strip() if raw else ""
        chal_dir = flag_file.parent
        meta_path = chal_dir / "challenge.json"
        meta = json.loads(meta_path.read_text()) if meta_path.exists() else {}
        name = meta.get("name", chal_dir.name)
        entry = {
            "path": str(chal_dir),
            "category": chal_dir.parent.name,
            "name": name,
            "ctfd_id": meta.get("ctfd_id"),
            "flag": first_line,
            "valid": False,
            "reason": "",
        }
        if name in already_solved:
            entry["reason"] = "already solved (pass_state.json)"
        elif name in already_incorrect:
            entry["reason"] = "one-attempt rule: prior submission was incorrect"
        elif not first_line:
            entry["reason"] = "empty"
        elif not fmt_re.match(first_line):
            entry["reason"] = f"format mismatch (wanted {fmt_re.pattern})"
        elif looks_like_placeholder(first_line):
            entry["reason"] = "placeholder/testing flag"
        elif entry["ctfd_id"] is None:
            entry["reason"] = "no ctfd_id in challenge.json"
        else:
            entry["valid"] = True
        candidates.append(entry)
    return candidates


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--url", required=True, help="CTFd base URL")
    ap.add_argument("--token", required=True, help="CTFd API token")
    ap.add_argument("--dir", required=True, help="Workspace dir (e.g. ctfs/eos)")
    ap.add_argument("--format", default="byuctf{}", help='Flag format (default: "byuctf{}")')
    ap.add_argument("--dry-run", action="store_true", help="Validate only, do not submit")
    ap.add_argument("--sleep", type=float, default=0.5, help="Seconds between submissions")
    args = ap.parse_args()

    workspace = Path(args.dir)
    if not workspace.is_dir():
        print(f"ERROR: {workspace} is not a directory", file=sys.stderr)
        return 2

    fmt_re = flag_regex_from_format(args.format)
    candidates = collect_candidates(workspace, fmt_re)

    valid = [c for c in candidates if c["valid"]]
    rejected = [c for c in candidates if not c["valid"]]

    print(f"Workspace: {workspace}")
    print(f"Flag format: {args.format}  regex: {fmt_re.pattern}")
    print(f"Candidates: {len(candidates)}  valid: {len(valid)}  rejected: {len(rejected)}\n")

    if rejected:
        print("REJECTED (will not submit):")
        for c in rejected:
            flag_disp = c["flag"][:60] if c["flag"] else "(empty)"
            print(f"  [{c['category']:10}] {c['name']:35} → {c['reason']}")
            print(f"    flag: {flag_disp}")
        print()

    if not valid:
        print("Nothing valid to submit.")
        return 0

    print("VALID (ready to submit):")
    for c in valid:
        print(f"  [{c['category']:10}] {c['name']:35} → {c['flag']}")
    print()

    if args.dry_run:
        print("--dry-run: no submissions performed.")
        return 0

    client = CTFdClient(url=args.url, token=args.token, timeout=30)
    results = {"correct": [], "incorrect": [], "already_solved": [], "error": []}

    for c in valid:
        print(f"[SUBMIT] {c['name']:35} → ", end="", flush=True)
        try:
            # Pass empty flag_format: CTFdClient treats it as a regex, and our
            # upstream validation already confirmed shape. Letting the client
            # re-check with "byuctf{}" would fail (it's a template, not regex).
            r = client.submit_flag(
                challenge_id=c["ctfd_id"],
                flag=c["flag"],
                flag_format="",
            )
            status = r.status if hasattr(r, "status") else str(r)
            msg = getattr(r, "message", "")
            print(f"{status}  {msg}")
            if status == "correct":
                results["correct"].append(c)
            elif status == "already_solved":
                results["already_solved"].append(c)
            elif status == "incorrect":
                results["incorrect"].append(c)
            else:
                results["error"].append((c, status, msg))
        except Exception as exc:
            print(f"ERROR {exc}")
            results["error"].append((c, "exception", str(exc)))
        time.sleep(args.sleep)

    print("\n=== Summary ===")
    print(f"  correct:        {len(results['correct'])}")
    print(f"  already_solved: {len(results['already_solved'])}")
    print(f"  incorrect:      {len(results['incorrect'])}")
    print(f"  error:          {len(results['error'])}")

    if results["incorrect"]:
        print("\nIncorrect flags (needs investigation):")
        for c in results["incorrect"]:
            print(f"  {c['name']:35} → {c['flag']}")
    if results["error"]:
        print("\nErrors:")
        for c, status, msg in results["error"]:
            print(f"  {c['name']:35} → {status}: {msg}")

    receipt_path = workspace / "submission_receipt.json"
    receipt = {
        "url": args.url,
        "workspace": str(workspace),
        "submitted_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "correct": [c["name"] for c in results["correct"]],
        "already_solved": [c["name"] for c in results["already_solved"]],
        "incorrect": [c["name"] for c in results["incorrect"]],
        "error": [(c["name"], s, m) for c, s, m in results["error"]],
        "rejected": [{"name": c["name"], "reason": c["reason"], "flag": c["flag"]} for c in rejected],
    }
    receipt_path.write_text(json.dumps(receipt, indent=2))
    print(f"\nReceipt: {receipt_path}")
    return 0 if not results["incorrect"] and not results["error"] else 1


if __name__ == "__main__":
    sys.exit(main())
