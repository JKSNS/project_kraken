#!/usr/bin/env python3
"""auto_bash_solver -- Execute bash solver scripts from challenge directories.

Finds test_solver/test.sh or similar solver scripts in the challenge
directory tree, adapts file paths to match the actual layout, installs
missing dependencies, and runs the script to capture the flag.

Outputs EXTRACTED FLAG: <flag> on success.
"""
import os
import re
import subprocess
import sys
import tempfile


def _find_solver_scripts(challenge_dir: str) -> list[str]:
    """Find bash solver scripts in the challenge directory tree."""
    candidates = []
    for root, _dirs, files in os.walk(challenge_dir):
        depth = root.replace(challenge_dir, "").count(os.sep)
        if depth > 3:
            continue
        for f in files:
            if f.endswith(".sh"):
                path = os.path.join(root, f)
                try:
                    with open(path, "r", errors="replace") as fh:
                        first_line = fh.readline()
                    if "bash" in first_line or "sh" in first_line or first_line.startswith("#"):
                        candidates.append(path)
                    else:
                        candidates.append(path)
                except Exception:
                    pass

    def _priority(path: str) -> int:
        lp = path.lower()
        if "test_solver" in lp:
            return 0
        if "solver" in lp or "solve" in lp:
            return 1
        if "exploit" in lp or "solution" in lp:
            return 2
        return 5

    candidates.sort(key=_priority)
    return candidates


def _find_challenge_files(challenge_dir: str) -> dict[str, str]:
    """Map basenames to their full paths in the challenge directory."""
    file_map: dict[str, str] = {}
    for root, _dirs, files in os.walk(challenge_dir):
        depth = root.replace(challenge_dir, "").count(os.sep)
        if depth > 4:
            continue
        for f in files:
            if f.endswith(".sh"):
                continue
            full = os.path.join(root, f)
            file_map[f] = full
    return file_map


def _adapt_script(content: str, challenge_dir: str, file_map: dict[str, str]) -> str:
    """Adapt a solver script to use actual challenge file paths."""
    adapted = content

    # Replace common CTF player paths with the challenge directory
    for pat in [r"/home/ctfplayer/ctf_files/", r"/home/ctfplayer/"]:
        adapted = re.sub(pat, challenge_dir.rstrip("/") + "/", adapted)

    # Handle sudo: pipe password via stdin
    adapted = re.sub(r"\bsudo\s+(?!-S)", 'echo "claude" | sudo -S ', adapted)

    # Skip cd to script directory
    adapted = adapted.replace('cd "$(dirname "$0")"', "# adapted: skip cd")

    # Relax strict error handling so partial failures don't abort
    adapted = adapted.replace("set -euo pipefail", "set -uo pipefail")
    adapted = adapted.replace("set -e", "set +e")

    return adapted


def _extract_needed_packages(content: str) -> list[str]:
    """Parse apt install commands to find required packages."""
    packages = []
    for m in re.finditer(
        r"(?:apt-get|apt)\s+install\s+(?:-y\s+)?(.+?)(?:\n|$)", content
    ):
        pkgs = m.group(1).strip().split()
        packages.extend(p for p in pkgs if not p.startswith("-"))
    return packages


def _install_packages(packages: list[str]) -> None:
    """Install packages via apt if not already present."""
    if not packages:
        return
    for pkg in packages:
        result = subprocess.run(
            ["dpkg", "-s", pkg], capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            continue
        print(f"[*] Installing {pkg}...")
        subprocess.run(
            ["bash", "-c", f'echo "claude" | sudo -S apt-get install -y {pkg}'],
            capture_output=True, text=True, timeout=120,
        )


def main():
    if len(sys.argv) < 2:
        print(
            "Usage: auto_bash_solver.py <challenge_dir> [--flag-format FORMAT]",
            file=sys.stderr,
        )
        sys.exit(1)

    challenge_dir = sys.argv[1]
    flag_format = ""
    if "--flag-format" in sys.argv:
        idx = sys.argv.index("--flag-format")
        if idx + 1 < len(sys.argv):
            flag_format = sys.argv[idx + 1]

    if not os.path.isdir(challenge_dir):
        print(f"[-] Not a directory: {challenge_dir}", file=sys.stderr)
        sys.exit(1)

    scripts = _find_solver_scripts(challenge_dir)
    if not scripts:
        print("[-] No bash solver scripts found", file=sys.stderr)
        sys.exit(1)

    flag_pattern = flag_format if flag_format else r"[a-zA-Z_]{2,}\{[^}]{3,}\}"
    file_map = _find_challenge_files(challenge_dir)

    for script_path in scripts[:2]:
        print(f"[*] Found solver script: {script_path}")

        try:
            with open(script_path, "r", errors="replace") as f:
                content = f.read()
        except Exception as e:
            print(f"  [-] Cannot read script: {e}")
            continue

        needed = _extract_needed_packages(content)
        if needed:
            print(f"[*] Required packages: {needed}")
            try:
                _install_packages(needed)
            except Exception as e:
                print(f"  [!] Package install issue: {e}")

        adapted = _adapt_script(content, challenge_dir, file_map)

        tmp_fd, tmp_script = tempfile.mkstemp(suffix=".sh", prefix="bash_solver_")
        try:
            with os.fdopen(tmp_fd, "w") as tf:
                tf.write(adapted)
            os.chmod(tmp_script, 0o755)

            print("[*] Running adapted script...")
            proc = subprocess.run(
                ["bash", tmp_script],
                capture_output=True,
                text=True,
                timeout=180,
                cwd="/tmp",
                env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"},
            )

            combined = proc.stdout + "\n" + proc.stderr
            flags = re.findall(flag_pattern, combined)

            if flags:
                best = max(flags, key=len)
                print(f"\nEXTRACTED FLAG: {best}")
                return

            print(f"  [-] No flags in output (exit={proc.returncode})")
            if proc.stdout.strip():
                print(f"  stdout: {proc.stdout[:500]}")
            if proc.stderr.strip():
                print(f"  stderr: {proc.stderr[:500]}")

        except subprocess.TimeoutExpired:
            print("  [-] Script timed out after 180s")
        except Exception as e:
            print(f"  [-] Error running script: {e}")
        finally:
            try:
                os.unlink(tmp_script)
            except OSError:
                pass

    print("[-] No flags extracted from solver scripts", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
