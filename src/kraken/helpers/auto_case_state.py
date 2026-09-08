#!/usr/bin/env python3
"""auto_case_state -- SQLite-backed evidence/decision ledger for kraken helpers.

The 10x missing piece named by both my adversarial audit and Codex's
review: a shared memory across helpers. Every kraken helper today
emits JSON to disk; nothing reads each other's output. The tick
orchestrator glues invocations, not findings.

This helper is the bridge. Every helper appends `(case_id, ts, helper,
kind, payload_json)` rows after producing output; downstream consumers
query by `kind` (e.g. all "io_call_site" events from any helper that
produced them).

Schema:
    events       (id, case_id, ts, helper, kind, payload_json, run_id)
    runs         (id, case_id, ts, helper, args_json, exit_code, elapsed_s)
    artifacts    (id, case_id, ts, helper, path, kind, sha256, size_bytes)

Usage as a library (from another helper):
    from auto_case_state import record, query, latest
    case_id = "CVE-DSU-read-packet"
    record(case_id, "auto_strip_recover", "io_call_site",
           {"caller": "main", "callee": "read_packet", ...})
    sites = query(case_id, kind="io_call_site")

Usage as CLI:
    # Inspect a case's events
    python3 auto_case_state.py list --case CVE-DSU-read-packet
    python3 auto_case_state.py list --case CVE-DSU-read-packet --kind io_call_site

    # Record from shell scripts:
    echo '{"foo": "bar"}' | python3 auto_case_state.py record \\
        --case CVE-X --helper my_script --kind discovery

    # Stats
    python3 auto_case_state.py stats
    python3 auto_case_state.py stats --case CVE-X

The DB lives at $KRAKEN_CASE_STATE_DB or ~/.kraken/case_state.db.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sqlite3
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

# ── DB location + schema ──────────────────────────────────────────────


def _db_path() -> Path:
    p = os.environ.get("KRAKEN_CASE_STATE_DB")
    if p:
        return Path(p)
    return Path.home() / ".kraken" / "case_state.db"


SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    helper TEXT NOT NULL,
    kind TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    run_id INTEGER,
    FOREIGN KEY (run_id) REFERENCES runs(id)
);
CREATE INDEX IF NOT EXISTS idx_events_case ON events(case_id);
CREATE INDEX IF NOT EXISTS idx_events_kind ON events(kind);
CREATE INDEX IF NOT EXISTS idx_events_helper ON events(helper);
CREATE INDEX IF NOT EXISTS idx_events_case_kind ON events(case_id, kind);

CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    helper TEXT NOT NULL,
    args_json TEXT,
    exit_code INTEGER,
    elapsed_s REAL
);
CREATE INDEX IF NOT EXISTS idx_runs_case ON runs(case_id);

CREATE TABLE IF NOT EXISTS artifacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    ts INTEGER NOT NULL,
    helper TEXT NOT NULL,
    path TEXT NOT NULL,
    kind TEXT,
    sha256 TEXT,
    size_bytes INTEGER,
    verification_status TEXT DEFAULT 'unknown'
        CHECK(verification_status IN ('verified','hypothesis','recall','unknown')),
    confidence REAL,
    verified_at INTEGER,
    verified_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_artifacts_case ON artifacts(case_id);
CREATE INDEX IF NOT EXISTS idx_artifacts_path ON artifacts(path);

-- v0.2.2 binaries table for similar-case prior-art lookup.
-- One row per unique sha256; populated from dossier fingerprint.
CREATE TABLE IF NOT EXISTS binaries (
    sha256 TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    first_seen_ts INTEGER NOT NULL,
    last_seen_ts INTEGER NOT NULL,
    filename TEXT,
    arch TEXT,
    endian TEXT,
    format TEXT,
    size_bytes INTEGER,
    function_count INTEGER,
    section_count INTEGER,
    import_count INTEGER,
    imphash TEXT,
    string_bag_sha TEXT,
    section_headers_stripped INTEGER,
    fingerprint_json TEXT NOT NULL,
    verification_status TEXT DEFAULT 'unknown'
        CHECK(verification_status IN ('verified','hypothesis','recall','unknown'))
);
CREATE INDEX IF NOT EXISTS idx_binaries_case ON binaries(case_id);
CREATE INDEX IF NOT EXISTS idx_binaries_arch ON binaries(arch);
CREATE INDEX IF NOT EXISTS idx_binaries_imphash ON binaries(imphash);
CREATE INDEX IF NOT EXISTS idx_binaries_string_bag ON binaries(string_bag_sha);
"""


def _migrate_v0_2_2(conn: sqlite3.Connection) -> None:
    """Add v0.2.2 columns to existing artifacts tables. SQLite ignores the
    CHECK on ALTER TABLE ADD COLUMN, so we use a plain TEXT default."""
    cur = conn.execute("PRAGMA table_info(artifacts)")
    existing_cols = {row[1] for row in cur.fetchall()}
    if "verification_status" not in existing_cols:
        conn.execute("ALTER TABLE artifacts ADD COLUMN verification_status TEXT DEFAULT 'unknown'")
    if "confidence" not in existing_cols:
        conn.execute("ALTER TABLE artifacts ADD COLUMN confidence REAL")
    if "verified_at" not in existing_cols:
        conn.execute("ALTER TABLE artifacts ADD COLUMN verified_at INTEGER")
    if "verified_by" not in existing_cols:
        conn.execute("ALTER TABLE artifacts ADD COLUMN verified_by TEXT")


@contextmanager
def _connect(db: Path | None = None) -> Iterator[sqlite3.Connection]:
    """Connect to the case-state DB, creating + migrating schema if needed."""
    db_path = db or _db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), timeout=30)
    conn.row_factory = sqlite3.Row
    try:
        conn.executescript(SCHEMA)
        _migrate_v0_2_2(conn)
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ── library API ───────────────────────────────────────────────────────


def record(
    case_id: str,
    helper: str,
    kind: str,
    payload: dict | list | str,
    run_id: int | None = None,
) -> int:
    """Append a single event. Returns the new event id."""
    if not isinstance(payload, str):
        payload_json = json.dumps(payload, default=str)
    else:
        payload_json = payload
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO events(case_id, ts, helper, kind, payload_json, run_id) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, int(time.time()), helper, kind, payload_json, run_id),
        )
        return cur.lastrowid or 0


def record_run(
    case_id: str,
    helper: str,
    args: list[str] | None = None,
    exit_code: int | None = None,
    elapsed_s: float | None = None,
) -> int:
    """Record a helper invocation (one per CLI run)."""
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO runs(case_id, ts, helper, args_json, exit_code, elapsed_s) VALUES (?, ?, ?, ?, ?, ?)",
            (case_id, int(time.time()), helper, json.dumps(args or []), exit_code, elapsed_s),
        )
        return cur.lastrowid or 0


def record_artifact(
    case_id: str,
    helper: str,
    path: Path | str,
    kind: str | None = None,
) -> int:
    """Record a file artifact (sha256 + size auto-computed)."""
    pp = Path(path)
    sha = ""
    size = None
    if pp.is_file():
        h = hashlib.sha256()
        with open(pp, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        sha = h.hexdigest()
        size = pp.stat().st_size
    with _connect() as conn:
        cur = conn.execute(
            "INSERT INTO artifacts(case_id, ts, helper, path, kind, sha256, size_bytes) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (case_id, int(time.time()), helper, str(pp), kind, sha, size),
        )
        return cur.lastrowid or 0


# ── v0.2.2: binaries table for prior-art lookup ─────────────────────────


def record_binary(case_id: str, fingerprint: dict) -> str:
    """Persist a binary's fingerprint for prior-art lookup. Idempotent on
    sha256 (UPSERT)."""
    sha = fingerprint.get("sha256", "")
    if not sha:
        return ""
    chars = fingerprint.get("characteristics") or {}
    now = int(time.time())
    with _connect() as conn:
        # SQLite UPSERT: refresh last_seen + case_id; preserve first_seen
        conn.execute(
            """
            INSERT INTO binaries (
                sha256, case_id, first_seen_ts, last_seen_ts,
                filename, arch, endian, format, size_bytes,
                function_count, section_count, import_count,
                imphash, string_bag_sha, section_headers_stripped,
                fingerprint_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(sha256) DO UPDATE SET
                last_seen_ts = excluded.last_seen_ts,
                case_id      = excluded.case_id,
                fingerprint_json = excluded.fingerprint_json
            """,
            (
                sha,
                case_id,
                now,
                now,
                fingerprint.get("filename"),
                fingerprint.get("arch"),
                fingerprint.get("endian"),
                fingerprint.get("format"),
                fingerprint.get("size_bytes"),
                fingerprint.get("function_count"),
                fingerprint.get("section_count"),
                fingerprint.get("import_count"),
                fingerprint.get("imphash"),
                fingerprint.get("string_bag_sha"),
                int(bool(chars.get("section_headers_stripped"))),
                json.dumps(fingerprint, default=str),
            ),
        )
    return sha


def find_similar(fingerprint: dict, *, k: int = 5, min_sim: float = 0.0) -> list[dict]:
    """Return top-k binaries by similarity to the given fingerprint.

    Cheap multi-modal scoring (matching the v2 plan):
      - imphash exact match → +0.40
      - import-set Jaccard → up to +0.40
      - string-bag-sha exact match → +0.30
      - arch + format match → required (anything else returns 0)
    """
    target_sha = fingerprint.get("sha256", "")
    target_arch = fingerprint.get("arch")
    target_format = fingerprint.get("format")
    target_imphash = fingerprint.get("imphash")
    target_imports = set(fingerprint.get("imports") or [])
    target_string_bag = fingerprint.get("string_bag_sha")

    with _connect() as conn:
        rows = conn.execute(
            "SELECT * FROM binaries WHERE arch = ? AND format = ? AND sha256 != ?",
            (target_arch, target_format, target_sha),
        ).fetchall()
    candidates: list[dict] = []
    for row in rows:
        try:
            other_fp = json.loads(row["fingerprint_json"])
        except (json.JSONDecodeError, TypeError):
            other_fp = {}
        score = 0.0
        signals: list[str] = []
        if target_imphash and target_imphash == row["imphash"]:
            score += 0.40
            signals.append("imphash_exact")
        else:
            other_imports = set(other_fp.get("imports") or [])
            if target_imports or other_imports:
                j = len(target_imports & other_imports) / max(len(target_imports | other_imports), 1)
                score += j * 0.40
                if j > 0.5:
                    signals.append(f"import_jaccard={j:.2f}")
        if target_string_bag and target_string_bag == row["string_bag_sha"]:
            score += 0.30
            signals.append("string_bag_exact")
        # arch + format always match per the WHERE clause
        score += 0.30
        if score < min_sim:
            continue
        candidates.append(
            {
                "sha256": row["sha256"],
                "case_id": row["case_id"],
                "filename": row["filename"],
                "arch": row["arch"],
                "format": row["format"],
                "first_seen_ts": row["first_seen_ts"],
                "verification_status": row["verification_status"],
                "similarity": round(score, 3),
                "signals": signals,
            }
        )
    candidates.sort(key=lambda c: -c["similarity"])
    return candidates[:k]


def query(
    case_id: str | None = None,
    kind: str | None = None,
    helper: str | None = None,
    limit: int | None = 1000,
) -> list[dict]:
    """Query events. All filter args are optional; empty filter returns
    the latest `limit` events globally."""
    where = []
    args: list[Any] = []
    if case_id:
        where.append("case_id = ?")
        args.append(case_id)
    if kind:
        where.append("kind = ?")
        args.append(kind)
    if helper:
        where.append("helper = ?")
        args.append(helper)
    sql = "SELECT * FROM events"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY ts DESC, id DESC"
    if limit:
        sql += f" LIMIT {int(limit)}"
    with _connect() as conn:
        rows = conn.execute(sql, args).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        try:
            d["payload"] = json.loads(d.pop("payload_json"))
        except Exception:
            d["payload"] = d.pop("payload_json", None)
        out.append(d)
    return out


def latest(case_id: str, kind: str, helper: str | None = None) -> dict | None:
    """Return the most recent event matching (case_id, kind[, helper])."""
    rows = query(case_id=case_id, kind=kind, helper=helper, limit=1)
    return rows[0] if rows else None


def stats(case_id: str | None = None) -> dict[str, Any]:
    """Aggregate counts (events / runs / artifacts) per helper + kind."""
    with _connect() as conn:
        if case_id:
            ev = conn.execute(
                "SELECT helper, kind, COUNT(*) c FROM events WHERE case_id=? GROUP BY helper, kind ORDER BY c DESC",
                (case_id,),
            ).fetchall()
            runs = conn.execute(
                "SELECT helper, COUNT(*) c, AVG(elapsed_s) avg_s FROM runs WHERE case_id=? GROUP BY helper",
                (case_id,),
            ).fetchall()
            arts = conn.execute(
                "SELECT COUNT(*) c, SUM(size_bytes) total_bytes FROM artifacts WHERE case_id=?",
                (case_id,),
            ).fetchone()
        else:
            ev = conn.execute(
                "SELECT helper, kind, COUNT(*) c FROM events GROUP BY helper, kind ORDER BY c DESC"
            ).fetchall()
            runs = conn.execute("SELECT helper, COUNT(*) c, AVG(elapsed_s) avg_s FROM runs GROUP BY helper").fetchall()
            arts = conn.execute("SELECT COUNT(*) c, SUM(size_bytes) total_bytes FROM artifacts").fetchone()
    return {
        "case_id": case_id,
        "events_by_helper_kind": [dict(r) for r in ev],
        "runs_by_helper": [dict(r) for r in runs],
        "artifacts": dict(arts) if arts else {"c": 0, "total_bytes": 0},
    }


def list_cases() -> list[dict]:
    """List all cases with their event counts + first/last seen."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT case_id, COUNT(*) events, MIN(ts) first_ts, MAX(ts) last_ts "
            "FROM events GROUP BY case_id ORDER BY last_ts DESC"
        ).fetchall()
    return [dict(r) for r in rows]


# ── CLI ───────────────────────────────────────────────────────────────


def cmd_record(args) -> int:
    payload_text = sys.stdin.read().strip()
    if not payload_text:
        print("[-] no payload on stdin", file=sys.stderr)
        return 1
    try:
        payload = json.loads(payload_text)
    except Exception:
        # Treat as plain string
        payload = payload_text
    eid = record(args.case, args.helper, args.kind, payload)
    print(json.dumps({"event_id": eid}))
    return 0


def cmd_list(args) -> int:
    rows = query(case_id=args.case, kind=args.kind, helper=args.helper, limit=args.limit)
    for r in rows:
        ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(r["ts"]))
        payload_str = json.dumps(r["payload"], default=str)[:200]
        print(f"[{r['id']:>5}] {ts}  {r['helper']:<30} {r['kind']:<28} {payload_str}")
    return 0


def cmd_stats(args) -> int:
    s = stats(args.case)
    print(json.dumps(s, indent=2, default=str))
    return 0


def cmd_cases(args) -> int:
    cases = list_cases()
    for c in cases:
        first = time.strftime("%Y-%m-%d %H:%M", time.localtime(c["first_ts"]))
        last = time.strftime("%Y-%m-%d %H:%M", time.localtime(c["last_ts"]))
        print(f"  {c['case_id']:<40} events={c['events']:>5}  first={first}  last={last}")
    return 0


def cmd_clear(args) -> int:
    if not args.confirm:
        print("[-] pass --confirm to actually clear", file=sys.stderr)
        return 1
    with _connect() as conn:
        if args.case:
            conn.execute("DELETE FROM events WHERE case_id=?", (args.case,))
            conn.execute("DELETE FROM runs   WHERE case_id=?", (args.case,))
            conn.execute("DELETE FROM artifacts WHERE case_id=?", (args.case,))
            print(f"cleared case {args.case}")
        else:
            conn.execute("DELETE FROM events")
            conn.execute("DELETE FROM runs")
            conn.execute("DELETE FROM artifacts")
            print("cleared all events")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("record")
    s.add_argument("--case", required=True)
    s.add_argument("--helper", required=True)
    s.add_argument("--kind", required=True)
    s.set_defaults(func=cmd_record)

    s = sub.add_parser("list")
    s.add_argument("--case")
    s.add_argument("--kind")
    s.add_argument("--helper")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_list)

    s = sub.add_parser("stats")
    s.add_argument("--case")
    s.set_defaults(func=cmd_stats)

    s = sub.add_parser("cases")
    s.set_defaults(func=cmd_cases)

    s = sub.add_parser("clear")
    s.add_argument("--case")
    s.add_argument("--confirm", action="store_true")
    s.set_defaults(func=cmd_clear)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
