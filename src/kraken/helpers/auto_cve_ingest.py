#!/usr/bin/env python3
"""auto_cve_ingest -- pull CVEs from OSV.dev and bootstrap a benchmark target.

Replaces hand-curating CVEs in benchmarks/cve/. Given a CVE ID or an OSV
package query, this:

  1. Fetches the OSV record (https://api.osv.dev/v1/vulns/<id>).
  2. Identifies the upstream fix commit URL (`fixed` events, "introduced"
     ranges, or affected.ranges.events).
  3. Clones the repo at the parent of the fix commit (= "buggy state").
  4. Extracts the actual fix patch from the parent..fix range.
  5. Generates `benchmarks/cve/<cve_id>/expected.json` describing the
     bug location (file + line, derived from the fix patch's removals)
     plus the upstream patch as the reference solution.
  6. Optionally writes a `Makefile` / `test.sh` based on detected build
     system (Cargo / autoconf / cmake / Make / pyproject).

Usage:
    # Single CVE by ID:
    python3 auto_cve_ingest.py --cve CVE-2024-30171
    # Package-scoped batch (top-N per ecosystem):
    python3 auto_cve_ingest.py --ecosystem PyPI --package requests --max 5
    # Bulk (read CVE IDs from stdin):
    cat ids.txt | python3 auto_cve_ingest.py --stdin

Output: each successfully-ingested CVE writes to:
    benchmarks/cve/<id>/
        expected.json          # the bug record
        upstream_fix.diff      # ground-truth patch (for similarity scoring)
        repo/                  # checkout of the buggy parent commit
        meta.json              # OSV record + fix commit info

Notes:
- We DON'T auto-derive `--test-cmd`. The repo's own test suite is project-
  specific; the human still picks the right command for now. Future:
  build-system shim that auto-generates these.
- Some OSV records lack fix commit URLs (just version ranges). Those are
  skipped with a warning.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

OSV_API = "https://api.osv.dev"
USER_AGENT = "kraken-auto-cve-ingest/1.0"

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
CVE_DIR = REPO_ROOT / "benchmarks" / "cve"


# ── HTTP ──────────────────────────────────────────────────────────────


def _fetch_json(url: str, timeout: float = 30.0) -> dict | list:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(url: str, body: dict, timeout: float = 30.0) -> dict:
    data = json.dumps(body).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def fetch_osv_record(cve_id: str) -> dict | None:
    """Fetch a single OSV record by CVE / GHSA / OSV ID."""
    url = f"{OSV_API}/v1/vulns/{urllib.parse.quote(cve_id)}"
    try:
        return _fetch_json(url)
    except Exception as e:
        print(f"[-] OSV fetch failed for {cve_id}: {e}", file=sys.stderr)
        return None


def query_osv_by_package(
    ecosystem: str,
    package: str,
    max_results: int = 5,
) -> list[str]:
    """List OSV vuln IDs for a given ecosystem/package."""
    body = {"package": {"ecosystem": ecosystem, "name": package}}
    try:
        result = _post_json(f"{OSV_API}/v1/query", body)
    except Exception as e:
        print(f"[-] OSV query failed: {e}", file=sys.stderr)
        return []
    return [v.get("id") for v in result.get("vulns", [])[:max_results] if v.get("id")]


# ── fix-commit extraction ─────────────────────────────────────────────


def _extract_fix_commits(record: dict) -> list[dict]:
    """Find fix commits in an OSV record. Returns list of
    {repo_url, fix_commit, introduced_commit?, parent_commit_known?}."""
    out = []
    for affected in record.get("affected", []):
        # ecosystem-version events
        for r in affected.get("ranges", []):
            if r.get("type") not in ("GIT", "git", "GIT_COMMIT"):
                continue
            repo = r.get("repo", "")
            introduced = None
            fixed = None
            for ev in r.get("events", []):
                if "introduced" in ev:
                    introduced = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
            if fixed and repo:
                out.append(
                    {
                        "repo_url": repo,
                        "fix_commit": fixed,
                        "introduced_commit": introduced,
                        "package": affected.get("package", {}),
                    }
                )
    # Also check `references` for commit-shaped URLs
    for ref in record.get("references", []):
        url = ref.get("url", "")
        m = re.match(
            r"https?://(?:github\.com|gitlab\.com|gitea\.\w+|"
            r"git\.kernel\.org)/([^/]+/[^/]+)/commit/([a-f0-9]{7,40})",
            url,
        )
        if m and ref.get("type") in ("FIX", "PATCH"):
            host_path, commit = m.group(1), m.group(2)
            repo_url = url.split("/commit/")[0] + ".git"
            out.append(
                {
                    "repo_url": repo_url,
                    "fix_commit": commit,
                    "introduced_commit": None,
                    "package": {},
                }
            )
    # Dedupe by (repo_url, fix_commit)
    seen = set()
    deduped = []
    for item in out:
        k = (item["repo_url"], item["fix_commit"])
        if k in seen:
            continue
        seen.add(k)
        deduped.append(item)
    return deduped


def _git_clone_at_parent(
    repo_url: str,
    fix_commit: str,
    dest: Path,
    depth: int = 50,
) -> tuple[bool, str]:
    """Clone repo at the *parent* of fix_commit (= the buggy state).

    Uses partial clone to keep size manageable on huge repos. Returns
    (success, info)."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.exists():
        return (False, f"destination exists: {dest}")
    try:
        # Init + fetch the specific commit (and its parents up to depth)
        subprocess.run(
            ["git", "init", "-q", str(dest)],
            check=True,
            timeout=30,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "remote", "add", "origin", repo_url],
            check=True,
            timeout=30,
            capture_output=True,
        )
        subprocess.run(
            ["git", "-C", str(dest), "fetch", "--depth", str(depth), "origin", fix_commit],
            check=True,
            timeout=300,
            capture_output=True,
        )
        # Find parent commit
        parent_proc = subprocess.run(
            ["git", "-C", str(dest), "rev-parse", f"{fix_commit}^"],
            check=True,
            timeout=30,
            capture_output=True,
            text=True,
        )
        parent = parent_proc.stdout.strip()
        # Checkout parent
        subprocess.run(
            ["git", "-C", str(dest), "checkout", "-q", parent],
            check=True,
            timeout=60,
            capture_output=True,
        )
        return (True, f"parent={parent}")
    except subprocess.CalledProcessError as e:
        return (False, f"git failed: {e.stderr.decode(errors='replace')[-300:]}")
    except subprocess.TimeoutExpired:
        return (False, "git timeout")
    except Exception as e:
        return (False, f"unexpected: {e}")


def _extract_patch_diff(repo_dir: Path, fix_commit: str) -> str | None:
    """Return the unified diff for fix_commit (parent..fix)."""
    try:
        proc = subprocess.run(
            ["git", "-C", str(repo_dir), "show", fix_commit, "--format=", "--no-color"],
            check=True,
            timeout=30,
            capture_output=True,
            text=True,
        )
        return proc.stdout
    except Exception:
        return None


SOURCE_EXTS = {
    ".c",
    ".h",
    ".cpp",
    ".cc",
    ".hpp",
    ".cxx",
    ".rs",
    ".py",
    ".go",
    ".java",
    ".js",
    ".ts",
    ".rb",
    ".pl",
    ".sh",
    ".lua",
    ".php",
}

# Files we should NOT pick as the "bug location" even if they have removals.
# These are metadata / changelog / build-config noise that often gets touched
# in the same commit as the real fix.
NON_SOURCE_PATTERNS = [
    re.compile(
        r"(?i)^(changes|changelog|news|readme|authors|contributors|todo|hacking|maintainers|copying|license|notice)(\..*)?$"
    ),
    re.compile(r"(?i)^version(\.\w+)?$"),
    re.compile(r"(?i)^manifest(\.in)?$"),
    re.compile(r"(?i)release[\-_ ]?notes"),
    re.compile(r"(?i)\.spec(\.in)?$"),  # rpm specs
    re.compile(r"\.po$"),  # translations
    re.compile(r"^Cargo\.toml$"),
    re.compile(r"^pyproject\.toml$"),
    re.compile(r"^setup\.(py|cfg)$"),
    re.compile(r"^pom\.xml$"),
    re.compile(r"^configure\.ac$"),
    re.compile(r"^configure$"),
    re.compile(r"^Makefile(\.am|\.in)?$"),
    re.compile(r"^CMakeLists\.txt$"),
    re.compile(r"\.result$"),
    re.compile(r"\.expected$"),
    re.compile(r"^\.gitignore$"),
    re.compile(r"^\.gitattributes$"),
    re.compile(r"\.gitlab-ci\.yml$"),
    re.compile(r"^\.github/"),
    re.compile(r"(?i)^mysql-test/"),
    re.compile(r"(?i)/(test|tests)/(?:.*\.(result|expected|out)$)"),
]


def _is_real_source(filename: str) -> bool:
    """Filter out metadata/changelog/build files."""
    name = Path(filename).name
    for pat in NON_SOURCE_PATTERNS:
        if pat.search(filename) or pat.search(name):
            return False
    suffix = Path(filename).suffix.lower()
    return suffix in SOURCE_EXTS


def _parse_diff_files(diff_text: str) -> list[dict]:
    """Parse the unified diff into per-file records:
    [{'file': str, 'first_remove_line': int | None,
      'remove_count': int, 'add_count': int, 'is_source': bool}]"""
    files: list[dict] = []
    current: dict | None = None
    current_old_line: int | None = None
    for line in diff_text.splitlines():
        if line.startswith("--- a/"):
            if current is not None:
                files.append(current)
            current = {
                "file": line[6:].strip(),
                "first_remove_line": None,
                "remove_count": 0,
                "add_count": 0,
            }
            current_old_line = None
        elif line.startswith("+++ b/") and current is not None:
            current["file"] = line[6:].strip()  # prefer +++ side
        elif line.startswith("@@") and current is not None:
            m = re.match(r"@@ -(\d+)(?:,\d+)? \+\d+", line)
            if m:
                current_old_line = int(m.group(1))
        elif line.startswith("-") and not line.startswith("---") and current is not None:
            if current["first_remove_line"] is None and current_old_line is not None:
                current["first_remove_line"] = current_old_line
            current["remove_count"] += 1
            if current_old_line is not None:
                current_old_line += 1
        elif line.startswith("+") and not line.startswith("+++") and current is not None:
            current["add_count"] += 1
        elif line.startswith(" ") and current_old_line is not None:
            current_old_line += 1
    if current is not None:
        files.append(current)
    for f in files:
        f["is_source"] = _is_real_source(f["file"])
    return files


def _identify_bug_location(diff_text: str) -> tuple[str | None, int | None]:
    """Pick the most representative (file, line) from the patch.

    Strategy:
      1. Filter to real source files (skip changelog / readme /
         build-config / *.result / etc.)
      2. Among source files, pick the one with the most lines
         changed (remove + add count) -- that's most likely "the
         actual fix" rather than incidental edits.
      3. Use that file's first removed line, or first added line if
         there are no removals (= a pure addition fix).
      4. If no source file matches, fall back to the original "first
         file, first remove" heuristic so we always emit something.
    """
    files = _parse_diff_files(diff_text)
    source_files = [f for f in files if f["is_source"]]
    candidates = source_files if source_files else files
    if not candidates:
        return (None, None)
    # Pick the file with the most lines changed
    best = max(candidates, key=lambda f: f["remove_count"] + f["add_count"])
    if best["first_remove_line"] is not None:
        return (best["file"], best["first_remove_line"])
    # Pure-addition fix -- fall back to the @@ line of the first hunk.
    # We didn't track first_add_line; re-scan the diff for this file.
    capturing = False
    for line in diff_text.splitlines():
        if line.startswith("--- a/") or line.startswith("+++ b/"):
            capturing = line.endswith(best["file"])
        elif capturing and line.startswith("@@"):
            m = re.match(r"@@ -(\d+)", line)
            if m:
                return (best["file"], int(m.group(1)))
    return (best["file"], 1)


def _detect_build_system(repo_dir: Path) -> dict[str, Any]:
    """Heuristic detection of build/test system. Suggests both setup_cmd
    (one-time bootstrap) and test_cmd (runs after each patch attempt).

    Priority: Cargo > pyproject > cmake > autoconf > Make. Higher-priority
    systems usually have better-defined tests; fall through when missing.
    """
    out: dict[str, Any] = {"detected": []}

    # Order matters -- first-match wins for setup_cmd / test_cmd
    if (repo_dir / "Cargo.toml").exists():
        out["detected"].append("cargo")
        out.setdefault("setup_cmd_hint", "cargo build --offline 2>/dev/null || cargo build")
        out.setdefault("test_cmd_hint", "cargo test --quiet")

    if (repo_dir / "pyproject.toml").exists() or (repo_dir / "setup.py").exists() or (repo_dir / "setup.cfg").exists():
        out["detected"].append("python")
        out.setdefault(
            "setup_cmd_hint",
            "python3 -m pip install --break-system-packages -e . 2>/dev/null || true",
        )
        out.setdefault("test_cmd_hint", "python3 -m pytest -q --timeout=30 2>&1 | tail -5")

    if (repo_dir / "CMakeLists.txt").exists():
        out["detected"].append("cmake")
        out.setdefault(
            "setup_cmd_hint",
            "mkdir -p build && cd build && cmake .. -DCMAKE_BUILD_TYPE=Debug",
        )
        out.setdefault("test_cmd_hint", "cd build && make -j$(nproc) && ctest --output-on-failure")

    if (repo_dir / "configure.ac").exists() or (repo_dir / "configure").exists():
        out["detected"].append("autoconf")
        if (repo_dir / "configure.ac").exists() and not (repo_dir / "configure").exists():
            out.setdefault(
                "setup_cmd_hint",
                "autoreconf -i 2>/dev/null && ./configure",
            )
        else:
            out.setdefault("setup_cmd_hint", "./configure")
        out.setdefault("test_cmd_hint", "make -j$(nproc) && make -s check")

    if (repo_dir / "Makefile").exists() or (repo_dir / "makefile").exists():
        out["detected"].append("make")
        out.setdefault("test_cmd_hint", "make -s check || make -s test || make -s tests")

    if (repo_dir / "pom.xml").exists():
        out["detected"].append("maven")
        out.setdefault("setup_cmd_hint", "mvn -q -DskipTests=true install")
        out.setdefault("test_cmd_hint", "mvn -q test")

    if (repo_dir / "build.gradle").exists() or (repo_dir / "build.gradle.kts").exists():
        out["detected"].append("gradle")
        out.setdefault("test_cmd_hint", "./gradlew test --no-daemon")

    if (repo_dir / "package.json").exists():
        out["detected"].append("npm")
        out.setdefault("setup_cmd_hint", "npm ci 2>/dev/null || npm install")
        out.setdefault("test_cmd_hint", "npm test")

    if (repo_dir / "go.mod").exists():
        out["detected"].append("go")
        out.setdefault("test_cmd_hint", "go test ./... -timeout=60s")

    return out


# ── main pipeline ─────────────────────────────────────────────────────


def ingest(cve_id: str, force: bool = False) -> dict[str, Any]:
    target_dir = CVE_DIR / cve_id
    if target_dir.exists() and not force:
        return {"cve": cve_id, "skipped": True, "reason": f"{target_dir} already exists; use --force"}
    if target_dir.exists() and force:
        # Wipe before re-cloning. Be conservative: only delete if the
        # directory looks like our own ingest output (has expected.json
        # or repo/ subdir) -- never blow up arbitrary user data.
        looks_ours = (
            (target_dir / "expected.json").is_file()
            or (target_dir / "repo").is_dir()
            or (target_dir / "meta.json").is_file()
        )
        if looks_ours:
            import shutil as _shutil

            _shutil.rmtree(target_dir, ignore_errors=True)
        else:
            return {
                "cve": cve_id,
                "skipped": True,
                "reason": f"{target_dir} exists and doesn't look like ingest output; refusing to delete",
            }

    record = fetch_osv_record(cve_id)
    if not record:
        return {"cve": cve_id, "error": "no OSV record"}

    fixes = _extract_fix_commits(record)
    if not fixes:
        return {
            "cve": cve_id,
            "error": "no fix commits in OSV record",
            "summary_url": f"https://osv.dev/vulnerability/{cve_id}",
        }

    # Try fix commits in order until one clones successfully
    target_dir.mkdir(parents=True, exist_ok=True)
    for fix in fixes:
        repo_dir = target_dir / "repo"
        ok, info = _git_clone_at_parent(
            fix["repo_url"],
            fix["fix_commit"],
            repo_dir,
        )
        if not ok:
            print(f"[*] skipping fix {fix['fix_commit'][:12]}: {info}", file=sys.stderr)
            continue
        diff_text = _extract_patch_diff(repo_dir, fix["fix_commit"])
        if not diff_text:
            (target_dir / "_failed.txt").write_text(f"could not extract diff for {fix['fix_commit']}")
            continue
        bug_file, bug_line = _identify_bug_location(diff_text)
        build_system = _detect_build_system(repo_dir)

        # Write artefacts
        (target_dir / "upstream_fix.diff").write_text(diff_text)
        (target_dir / "meta.json").write_text(
            json.dumps(
                {
                    "cve": cve_id,
                    "osv_record": record,
                    "selected_fix": fix,
                    "parent_info": info,
                    "build_system": build_system,
                },
                indent=2,
            )
        )

        expected = {
            "_comment": (
                "Auto-ingested from OSV.dev. Upstream patch lives in "
                "upstream_fix.diff; bug location is the first removed line "
                "of the first hunk."
            ),
            "id": cve_id,
            "category": "auto-ingested",
            "severity": record.get("database_specific", {}).get("severity", "unknown"),
            "summary": (record.get("summary") or "")[:300],
            "language": _guess_language(bug_file or ""),
            "bug": {
                "file": bug_file or "<unknown>",
                "line": bug_line or 1,
                "class": "auto-ingested",
                "description": (record.get("details") or "")[:600],
            },
            "setup_cmd": build_system.get("setup_cmd_hint"),
            "test_cmd": build_system.get("test_cmd_hint", "true  # set me!"),
            "regression_cmd": None,  # T3.2: optional broader test sweep
            "expected_artifacts": ["winner"],
            "scoring": {
                "target_recall": 1.0,
                "target_wall_clock_seconds": 1200,
                "thresholds": {"winner_present": 1.0, "tests_passed": 1.0},
            },
            "auto_ingested": True,
        }
        (target_dir / "expected.json").write_text(json.dumps(expected, indent=2))

        return {
            "cve": cve_id,
            "ok": True,
            "target_dir": str(target_dir),
            "bug_file": bug_file,
            "bug_line": bug_line,
            "fix_commit": fix["fix_commit"],
            "build_system": build_system.get("detected"),
            "test_cmd_hint": build_system.get("test_cmd_hint"),
        }

    return {"cve": cve_id, "error": "all candidate fix commits failed to clone"}


def _guess_language(filename: str) -> str:
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
        ".rb": "ruby",
    }.get(Path(filename).suffix.lower(), "unknown")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--cve", help="single CVE / GHSA / OSV ID")
    p.add_argument("--ecosystem", help="OSV ecosystem (e.g. PyPI, npm, Maven)")
    p.add_argument("--package", help="package name within --ecosystem")
    p.add_argument("--max", type=int, default=5, help="max CVEs per package query")
    p.add_argument("--stdin", action="store_true", help="read CVE IDs from stdin")
    p.add_argument("--force", action="store_true", help="re-ingest even if benchmarks/cve/<id>/ exists")
    args = p.parse_args(argv)

    ids: list[str] = []
    if args.cve:
        ids.append(args.cve)
    if args.ecosystem and args.package:
        ids.extend(query_osv_by_package(args.ecosystem, args.package, args.max))
    if args.stdin:
        ids.extend(line.strip() for line in sys.stdin if line.strip() and not line.startswith("#"))

    if not ids:
        p.error("provide --cve, --ecosystem+--package, or --stdin")

    results = []
    for cve_id in ids:
        print(f"[*] ingesting {cve_id}...", file=sys.stderr)
        r = ingest(cve_id, force=args.force)
        results.append(r)
        if r.get("ok"):
            print(f"  [+] {cve_id} → {r['target_dir']} (bug @ {r['bug_file']}:{r['bug_line']})", file=sys.stderr)
        elif r.get("skipped"):
            print(f"  · {cve_id} skipped ({r['reason']})", file=sys.stderr)
        else:
            print(f"  [x] {cve_id} ({r.get('error', 'unknown')})", file=sys.stderr)

    json.dump({"results": results, "ok_count": sum(1 for r in results if r.get("ok"))}, sys.stdout, indent=2)
    print()
    return 0 if any(r.get("ok") for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
