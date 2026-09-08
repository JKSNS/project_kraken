#!/usr/bin/env python3
"""Extract flags from git-based CTF challenges.

Handles zip archives containing .git directories. Walks all branches
and commits looking for flag patterns, .pyc files (decompiles them),
base64-encoded strings, and secret files.
"""
import base64
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

FLAG_PATTERNS = [
    re.compile(r'[a-zA-Z]+\{[^}]{3,200}\}'),
    re.compile(r'[Ff][Ll][Aa][Gg]\{[^}]+\}'),
]

BASE64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

# Files likely to contain flags or secrets
INTERESTING_FILES = re.compile(
    r'(flag|secret|key|password|token|hidden|debug|\.pyc|\.env)'
    r'|(__pycache__)', re.IGNORECASE
)


def search_text_for_flags(text: str) -> list[str]:
    flags = []
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            candidate = m.group(0)
            if len(candidate) > 6:
                flags.append(candidate)
    return flags


def try_decode_base64(text: str) -> list[str]:
    results = []
    for m in BASE64_RE.finditer(text):
        raw = m.group(0)
        try:
            decoded = base64.b64decode(raw + '==').decode(errors='replace')
            flags = search_text_for_flags(decoded)
            if flags:
                results.extend(flags)
            elif len(decoded) > 4 and all(32 <= ord(c) <= 126 for c in decoded):
                results.append(decoded)
        except Exception:
            pass
    return results


def extract_zip_with_git(zip_path: str, dest: str) -> bool:
    """Extract a zip file and verify it contains a .git directory."""
    try:
        with zipfile.ZipFile(zip_path, 'r') as zf:
            zf.extractall(dest)
    except Exception as e:
        print(f"[-] Cannot extract zip: {e}", file=sys.stderr)
        return False

    # Find the .git directory -- it might be nested one level
    if os.path.isdir(os.path.join(dest, '.git')):
        return True
    for entry in os.listdir(dest):
        subdir = os.path.join(dest, entry)
        if os.path.isdir(subdir) and os.path.isdir(os.path.join(subdir, '.git')):
            # Move contents up
            for item in os.listdir(subdir):
                src = os.path.join(subdir, item)
                dst = os.path.join(dest, item)
                if not os.path.exists(dst):
                    shutil.move(src, dst)
            return True
    return False


def git_cmd(args: list[str], cwd: str, timeout: int = 10) -> str | None:
    """Run a git command and return stdout."""
    try:
        result = subprocess.run(
            ['git'] + args, cwd=cwd, capture_output=True,
            text=True, timeout=timeout
        )
        return result.stdout
    except Exception:
        return None


def get_all_branches(cwd: str) -> list[str]:
    """Get all branch names."""
    output = git_cmd(['branch', '-a', '--format=%(refname:short)'], cwd)
    if not output:
        return []
    return [b.strip() for b in output.strip().splitlines() if b.strip()]


def get_all_commits(cwd: str, branch: str = '') -> list[str]:
    """Get all commit hashes on a branch."""
    args = ['log', '--format=%H', '--all'] if not branch else ['log', '--format=%H', branch]
    output = git_cmd(args, cwd)
    if not output:
        return []
    return [h.strip() for h in output.strip().splitlines() if h.strip()]


def get_tree_files(cwd: str, commit: str) -> list[str]:
    """Get all file paths in a commit's tree."""
    output = git_cmd(['ls-tree', '-r', '--name-only', commit], cwd)
    if not output:
        return []
    return [f.strip() for f in output.strip().splitlines() if f.strip()]


def extract_file_from_commit(cwd: str, commit: str, filepath: str) -> bytes | None:
    """Extract a file's contents from a specific commit."""
    try:
        result = subprocess.run(
            ['git', 'show', f'{commit}:{filepath}'],
            cwd=cwd, capture_output=True, timeout=10
        )
        if result.returncode == 0:
            return result.stdout
        return None
    except Exception:
        return None


def decompile_pyc(pyc_data: bytes) -> str | None:
    """Attempt to decompile a .pyc file using uncompyle6."""
    tmpdir = tempfile.mkdtemp()
    try:
        pyc_path = os.path.join(tmpdir, 'decompile.pyc')
        py_path = os.path.join(tmpdir, 'decompile.py')
        with open(pyc_path, 'wb') as f:
            f.write(pyc_data)

        result = subprocess.run(
            ['uncompyle6', pyc_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode == 0 and result.stdout:
            return result.stdout

        # Try pycdc as fallback
        try:
            result = subprocess.run(
                ['pycdc', pyc_path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except FileNotFoundError:
            pass

        return None
    except Exception:
        return None
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def solve_seed_array(source: str) -> str | None:
    """Extract and solve seed tuple arrays from decompiled Python source.

    Pattern: seed = [(idx, char), ...] → sort by idx → join → base64 decode
    """
    # Match seed array patterns
    seed_match = re.search(
        r'seed\s*=\s*\[(.*?)\]',
        source, re.DOTALL
    )
    if not seed_match:
        return None

    seed_text = seed_match.group(1)
    # Extract tuples: (int, 'char') or (int, "char")
    tuples = re.findall(r'\(\s*(\d+)\s*,\s*[\'"](.)[\'"]', seed_text)
    if len(tuples) < 4:
        return None

    # Sort by index and concatenate
    sorted_chars = [c for _, c in sorted(tuples, key=lambda x: int(x[0]))]
    b64_string = ''.join(sorted_chars)

    # Try base64 decode
    try:
        decoded = base64.b64decode(b64_string).decode()
        flags = search_text_for_flags(decoded)
        if flags:
            return flags[0]
        return decoded
    except Exception:
        return None


def search_git_repo(repo_dir: str) -> list[str]:
    """Search all branches and commits in a git repo for flags."""
    found = []

    # Get all commits across all branches
    all_commits = get_all_commits(repo_dir)
    if not all_commits:
        return found

    # Track files we've already checked (commit:path)
    checked = set()

    for commit in all_commits:
        files = get_tree_files(repo_dir, commit)
        for filepath in files:
            key = f"{commit[:8]}:{filepath}"
            if key in checked:
                continue
            checked.add(key)

            name_lower = filepath.lower()

            # Only process interesting files to save time
            if not INTERESTING_FILES.search(filepath):
                # Also check text/source files for flag patterns
                if not name_lower.endswith(('.txt', '.py', '.sh', '.md', '.json', '.env', '.cfg')):
                    continue

            data = extract_file_from_commit(repo_dir, commit, filepath)
            if not data:
                continue

            # Handle .pyc files
            if name_lower.endswith('.pyc'):
                source = decompile_pyc(data)
                if source:
                    # Check for flag patterns in decompiled source
                    found.extend(search_text_for_flags(source))

                    # Try seed array solving
                    seed_result = solve_seed_array(source)
                    if seed_result:
                        found.append(seed_result)

                    # Check for base64 in decompiled source
                    found.extend(try_decode_base64(source))
                continue

            # Handle text/source files
            try:
                text = data.decode(errors='replace')
            except Exception:
                continue

            if len(text) > 200_000:
                continue

            found.extend(search_text_for_flags(text))
            found.extend(try_decode_base64(text))

    # Also search git log messages for flags
    log_output = git_cmd(['log', '--all', '--format=%s%n%b'], repo_dir)
    if log_output:
        found.extend(search_text_for_flags(log_output))
        found.extend(try_decode_base64(log_output))

    # Search git diff for flags (shows deleted content too)
    diff_output = git_cmd(['log', '--all', '-p', '--max-count=20'], repo_dir, timeout=30)
    if diff_output:
        found.extend(search_text_for_flags(diff_output))

    return found


def main():
    if len(sys.argv) < 2:
        print("Usage: auto_git_extract.py <zip_path>", file=sys.stderr)
        sys.exit(1)

    zip_path = sys.argv[1]
    if not os.path.exists(zip_path):
        print(f"[-] File not found: {zip_path}", file=sys.stderr)
        sys.exit(1)

    if not zip_path.lower().endswith('.zip'):
        print(f"[-] Not a zip file: {zip_path}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Extracting git repo from: {zip_path}")
    tmpdir = tempfile.mkdtemp(prefix='kraken_git_')

    try:
        if not extract_zip_with_git(zip_path, tmpdir):
            print("[-] No .git directory found in archive", file=sys.stderr)
            sys.exit(1)

        print(f"[*] Git repo extracted to: {tmpdir}")
        branches = get_all_branches(tmpdir)
        commits = get_all_commits(tmpdir)
        print(f"[*] Branches: {branches}")
        print(f"[*] Total commits: {len(commits)}")

        flags = search_git_repo(tmpdir)

        # Deduplicate and print
        seen = set()
        for flag in flags:
            if flag not in seen:
                seen.add(flag)
                print(f"EXTRACTED FLAG: {flag}")

        if not seen:
            print("[-] No flags found in git repository")
            sys.exit(1)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == '__main__':
    main()
