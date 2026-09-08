"""Ghidra headless analysis wrapper with auto-install."""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
import time
from pathlib import Path
from dataclasses import dataclass, field

from kraken.tools.base import ToolResult

# Ghidra release to auto-install
_GHIDRA_VERSION = "12.0.3"
_GHIDRA_ZIP = f"ghidra_{_GHIDRA_VERSION}_PUBLIC.zip"
_GHIDRA_URL = (
    f"https://github.com/NationalSecurityAgency/ghidra/releases/download/"
    f"Ghidra_{_GHIDRA_VERSION}_build/{_GHIDRA_ZIP}"
)
_GHIDRA_DIR_NAME = f"ghidra_{_GHIDRA_VERSION}_PUBLIC"
_DEFAULT_INSTALL_PREFIX = "/opt"

# Java home for Ghidra (requires JDK 21+)
_JAVA_HOME = os.environ.get("JAVA_HOME", "/usr/lib/jvm/java-21")


def _tool_roots() -> list[Path]:
    """Candidate shared tool roots across common users in containers."""
    roots = [Path("/opt"), Path("/root/tools"), Path(_DEFAULT_INSTALL_PREFIX)]
    for home in Path("/home").glob("*"):
        tools = home / "tools"
        if tools.is_dir() and tools not in roots:
            roots.append(tools)
    return roots


def _is_usable_headless(headless: Path) -> bool:
    """True when analyzeHeadless exists and is executable for this runtime user."""
    # Non-root runtimes should never prefer /root tool installs.
    # Check this FIRST to avoid PermissionError from stat() on /root paths.
    if os.geteuid() != 0:
        try:
            if str(headless).startswith("/root/") or headless.resolve().is_relative_to(Path("/root")):
                return False
        except (PermissionError, OSError):
            if str(headless).startswith("/root/"):
                return False
    try:
        if not headless.exists() or not os.access(headless, os.X_OK):
            return False
    except (PermissionError, OSError):
        return False
    return True


def _attempt_permission_repair(headless: Path) -> None:
    """Best-effort permission repair for root-owned Ghidra installs.

    Only runs as root. Makes script(s) executable and ensures parent dirs are traversable.
    """
    if os.geteuid() != 0:
        return
    try:
        if headless.exists():
            headless.chmod(0o755)
            support_dir = headless.parent
            for sh in support_dir.glob("*.sh"):
                try:
                    sh.chmod(0o755)
                except Exception:
                    pass
            # Ensure directory traversal bits on parent chain
            for d in [support_dir, support_dir.parent, support_dir.parent.parent, Path("/root")]:
                if d.exists():
                    mode = d.stat().st_mode & 0o777
                    d.chmod(mode | 0o111)
    except Exception:
        # Keep this best-effort; discovery fallback still applies.
        pass


@dataclass
class GhidraConfig:
    ghidra_install_dir: str = field(
        default_factory=lambda: os.environ.get(
            "GHIDRA_INSTALL_DIR",
            "/opt/ghidra",
        )
    )
    timeout: int = 300


def _find_ghidra() -> str | None:
    """Search for an existing Ghidra installation.

    Checks, in order:
    1. GHIDRA_INSTALL_DIR env var
    2. Common install locations under /opt
    3. User home directory
    """
    # 1. Env var
    env_dir = os.environ.get("GHIDRA_INSTALL_DIR")
    if env_dir:
        headless = Path(env_dir) / "support" / "analyzeHeadless"
        if _is_usable_headless(headless):
            return env_dir

    # 2. Common locations -- search user tools dir, /opt, and home
    search_dirs = [Path(_DEFAULT_INSTALL_PREFIX) / _GHIDRA_DIR_NAME, Path(_DEFAULT_INSTALL_PREFIX) / "ghidra"]
    for root in _tool_roots():
        gh = root / _GHIDRA_DIR_NAME
        if gh not in search_dirs:
            search_dirs.append(gh)

    # Also glob tool roots for ghidra* installs
    for parent in _tool_roots():
        try:
            if not parent.is_dir():
                continue
            for p in sorted(parent.glob("ghidra*"), reverse=True):
                if p.is_dir() and p not in search_dirs:
                    search_dirs.append(p)
        except (PermissionError, OSError):
            continue

    for d in search_dirs:
        headless = d / "support" / "analyzeHeadless"
        if _is_usable_headless(headless):
            return str(d)

    return None


async def ensure_ghidra(config: GhidraConfig) -> GhidraConfig:
    """Ensure Ghidra is installed. Auto-install if not found.

    Returns an updated GhidraConfig with the resolved install path.
    """
    # Check if already available at configured path
    headless = Path(config.ghidra_install_dir) / "support" / "analyzeHeadless"
    if _is_usable_headless(headless):
        return config

    # Search common locations
    found = _find_ghidra()
    if found:
        config.ghidra_install_dir = found
        return config

    # Auto-install
    install_dir = Path(_DEFAULT_INSTALL_PREFIX) / _GHIDRA_DIR_NAME
    if install_dir.exists():
        # Directory exists but analyzeHeadless missing -- might be corrupt
        shutil.rmtree(install_dir, ignore_errors=True)

    # Pick download tool
    download_cmd: list[str]
    zip_path = Path(tempfile.gettempdir()) / _GHIDRA_ZIP
    if shutil.which("wget"):
        download_cmd = ["wget", "-q", "-O", str(zip_path), _GHIDRA_URL]
    elif shutil.which("curl"):
        download_cmd = ["curl", "-fsSL", "-o", str(zip_path), _GHIDRA_URL]
    else:
        raise RuntimeError(
            "Cannot auto-install Ghidra: neither 'wget' nor 'curl' found."
        )

    # Download
    proc = await asyncio.create_subprocess_exec(
        *download_cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    _, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)
    if proc.returncode != 0:
        raise RuntimeError(
            f"Failed to download Ghidra: {stderr.decode(errors='replace')}"
        )

    # Extract using Python zipfile (no external unzip needed)
    import zipfile
    try:
        with zipfile.ZipFile(str(zip_path), "r") as zf:
            zf.extractall(_DEFAULT_INSTALL_PREFIX)
    except zipfile.BadZipFile as exc:
        raise RuntimeError(f"Failed to extract Ghidra: {exc}") from exc

    # Cleanup zip
    zip_path.unlink(missing_ok=True)

    # Verify
    headless = install_dir / "support" / "analyzeHeadless"
    if not headless.exists():
        raise RuntimeError(
            f"Ghidra extracted but analyzeHeadless not found at {headless}"
        )

    # zipfile doesn't preserve Unix execute bits -- fix all scripts
    for script in (install_dir / "support").glob("*.sh"):
        script.chmod(0o755)
    headless.chmod(0o755)

    config.ghidra_install_dir = str(install_dir)
    os.environ["GHIDRA_INSTALL_DIR"] = str(install_dir)
    return config


async def run_ghidra_headless(
    binary_path: str,
    script_name: str,
    script_args: list[str] | None = None,
    config: GhidraConfig | None = None,
    workspace_dir: str | None = None,
) -> ToolResult:
    """Run a Ghidra headless script on a binary."""
    cfg = config or GhidraConfig()

    # If caller passed an unusable root-scoped path under a non-root runtime,
    # ignore it and let discovery pick a shared/permitted install.
    if os.geteuid() != 0 and str(cfg.ghidra_install_dir).startswith("/root/"):
        cfg = GhidraConfig(ghidra_install_dir="")

    # Ensure Ghidra is installed before running
    try:
        cfg = await ensure_ghidra(cfg)
    except Exception as e:
        return ToolResult(tool="ghidra", success=False, error=str(e))

    headless = Path(cfg.ghidra_install_dir) / "support" / "analyzeHeadless"

    if workspace_dir:
        root = Path(workspace_dir).resolve() / "ghidra"
        root.mkdir(parents=True, exist_ok=True)
        proj_dir = root / f"project_{int(time.time() * 1000)}"
        proj_dir.mkdir(parents=True, exist_ok=True)
        cleanup_project = False
    else:
        proj_dir = Path(tempfile.mkdtemp(prefix="kraken_ghidra_"))
        cleanup_project = True

    try:
        output_file = proj_dir / "output.json"
        cmd = [
            str(headless),
            str(proj_dir), "kraken_proj",
            "-import", binary_path,
            "-postScript", script_name,
            *(script_args or []),
            str(output_file),
            "-scriptPath", str(Path(__file__).resolve().parent.parent.parent.parent / "ghidra_scripts"),
        ]
        if cleanup_project:
            cmd.append("-deleteProject")

        # Set JAVA_HOME so Ghidra can find the JDK
        env = os.environ.copy()
        java_home = _JAVA_HOME
        if Path(java_home).is_dir():
            env["JAVA_HOME"] = java_home
            env["PATH"] = f"{java_home}/bin:{env.get('PATH', '')}"

        try:
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
            except PermissionError:
                _attempt_permission_repair(headless)
                # Some environments mount tool dirs as noexec for non-root users.
                # Retry by invoking the script through bash.
                proc = await asyncio.create_subprocess_exec(
                    "/bin/bash", *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=env,
                )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=cfg.timeout)

            if output_file.exists():
                data = json.loads(output_file.read_text())
            else:
                data = {"raw_stdout": stdout.decode(errors="replace")}

            return ToolResult(
                tool="ghidra",
                success=proc.returncode == 0,
                data=data,
                stdout=stdout.decode(errors="replace"),
                stderr=stderr.decode(errors="replace"),
            )
        except asyncio.TimeoutError:
            return ToolResult(tool="ghidra", success=False, error=f"Ghidra timed out after {cfg.timeout}s")
        except FileNotFoundError:
            return ToolResult(tool="ghidra", success=False, error=f"Ghidra not found at {headless}")
    finally:
        if cleanup_project:
            import shutil

            shutil.rmtree(proj_dir, ignore_errors=True)


async def decompile_all_functions(
    binary_path: str,
    config: GhidraConfig | None = None,
    workspace_dir: str | None = None,
) -> ToolResult:
    """Decompile all functions in a binary."""
    return await run_ghidra_headless(binary_path, "DecompileAllFunctions.java", config=config, workspace_dir=workspace_dir)


async def extract_call_graph(
    binary_path: str,
    config: GhidraConfig | None = None,
    workspace_dir: str | None = None,
) -> ToolResult:
    """Extract call graph from a binary."""
    return await run_ghidra_headless(binary_path, "ExtractCallGraph.java", config=config, workspace_dir=workspace_dir)
