"""Tool auto-installer -- KRAKEN's self-provisioning capability.

When a required external tool (mono, ilspycmd, dnfile, etc.) is missing,
KRAKEN tries to install it autonomously rather than giving up.

Install strategies (tried in order):
1. pip install          -- pure Python packages (dnfile, pefile, capstone)
2. apt-get install      -- system packages (mono-runtime, mono-utils, binutils)
3. sudo apt-get install -- same as above but with privilege escalation
4. dotnet tool install  -- .NET global tools (ilspycmd)
5. snap install         -- snaps (fallback for some tools)

Results are cached in-process to avoid re-running on every call.
"""
from __future__ import annotations

import asyncio
import shutil
import sys
from typing import Callable

from kraken.logging.structured import get_logger

log = get_logger(__name__)

# ── In-process install cache ──────────────────────────────────────────
# Maps tool name → True (available) or False (could not install)
_install_cache: dict[str, bool] = {}


# ── Install strategy definitions ─────────────────────────────────────

async def _run_cmd(*args: str, env: dict | None = None, timeout: int = 120) -> bool:
    """Run a command and return True on exit code 0."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        ok = proc.returncode == 0
        if not ok:
            log.debug(
                "installer_cmd_failed",
                cmd=" ".join(args),
                rc=proc.returncode,
                stderr=stderr.decode(errors="replace")[:300],
            )
        return ok
    except asyncio.TimeoutError:
        log.warning("installer_cmd_timeout", cmd=" ".join(args))
        return False
    except Exception as exc:
        log.warning("installer_cmd_error", cmd=" ".join(args), error=str(exc))
        return False


async def _pip_install(package: str) -> bool:
    """Install a Python package with pip."""
    return await _run_cmd(sys.executable, "-m", "pip", "install", "--quiet", package)


async def _apt_install(*packages: str, sudo: bool = False) -> bool:
    """Install system packages via apt-get."""
    cmd = (["sudo"] if sudo else []) + [
        "apt-get", "install", "-y", "--no-install-recommends", *packages
    ]
    # Set DEBIAN_FRONTEND=noninteractive to prevent interactive prompts
    import os
    env = {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}
    return await _run_cmd(*cmd, env=env)


async def _dotnet_tool_install(package: str) -> bool:
    """Install a .NET global tool."""
    dotnet = shutil.which("dotnet")
    if not dotnet:
        return False
    return await _run_cmd(dotnet, "tool", "install", "--global", package)


async def _snap_install(package: str, *flags: str) -> bool:
    """Install a snap package."""
    snap = shutil.which("snap")
    if not snap:
        return False
    return await _run_cmd(snap, "install", package, *flags)


# ── Tool registry ────────────────────────────────────────────────────
# Maps binary name → list of install strategies to try in order.
# Each strategy is an async callable that returns True on success.

ToolStrategy = list[Callable[[], "asyncio.Future[bool]"]]

_TOOL_STRATEGIES: dict[str, list] = {
    # .NET runtimes
    "mono": [
        lambda: _apt_install("mono-runtime"),
        lambda: _apt_install("mono-runtime", sudo=True),
        lambda: _snap_install("mono", "--classic"),
    ],
    "dotnet": [
        # dotnet tool install requires the SDK, not just the runtime or host
        lambda: _apt_install("dotnet-sdk-8.0"),
        lambda: _apt_install("dotnet-sdk-8.0", sudo=True),
        lambda: _apt_install("dotnet-sdk-9.0", sudo=True),
    ],

    # .NET decompilers
    "ilspycmd": [
        # Needs dotnet SDK -- try installing SDK then the tool
        lambda: _dotnet_tool_install("ilspycmd"),
        lambda: _apt_install("dotnet-sdk-8.0") or _dotnet_tool_install("ilspycmd"),
        lambda: _apt_install("dotnet-sdk-8.0", sudo=True) or _dotnet_tool_install("ilspycmd"),
    ],
    "monodis": [
        lambda: _apt_install("mono-utils"),
        lambda: _apt_install("mono-utils", sudo=True),
    ],

    # Python analysis libraries (installed into current venv)
    "dnfile": [
        lambda: _pip_install("dnfile"),
    ],
    "pefile": [
        lambda: _pip_install("pefile"),
    ],
    "capstone": [
        lambda: _pip_install("capstone"),
    ],
    "angr": [
        lambda: _pip_install("angr"),
    ],
    "z3-solver": [
        lambda: _pip_install("z3-solver"),
    ],
    "pwntools": [
        lambda: _pip_install("pwntools"),
    ],

    # Binary analysis tools
    "strings": [
        lambda: _apt_install("binutils"),
        lambda: _apt_install("binutils", sudo=True),
    ],
    "objdump": [
        lambda: _apt_install("binutils"),
        lambda: _apt_install("binutils", sudo=True),
    ],
    "readelf": [
        lambda: _apt_install("binutils"),
        lambda: _apt_install("binutils", sudo=True),
    ],
    "file": [
        lambda: _apt_install("file"),
        lambda: _apt_install("file", sudo=True),
    ],
    "binwalk": [
        lambda: _pip_install("binwalk"),
        lambda: _apt_install("binwalk"),
        lambda: _apt_install("binwalk", sudo=True),
    ],
    "gdb": [
        lambda: _apt_install("gdb"),
        lambda: _apt_install("gdb", sudo=True),
    ],
    "strace": [
        lambda: _apt_install("strace"),
        lambda: _apt_install("strace", sudo=True),
    ],
    "ltrace": [
        lambda: _apt_install("ltrace"),
        lambda: _apt_install("ltrace", sudo=True),
    ],

    # Fuzzing
    "afl-fuzz": [
        lambda: _apt_install("afl++"),
        lambda: _apt_install("afl++", sudo=True),
        lambda: _apt_install("afl"),
        lambda: _apt_install("afl", sudo=True),
    ],
}


# ── Public API ────────────────────────────────────────────────────────

async def ensure_tool(tool: str) -> bool:
    """Ensure a tool is available, installing it if necessary.

    Args:
        tool: Binary name (as would be passed to shutil.which) OR
              Python package name (e.g. "dnfile", "angr").

    Returns:
        True if the tool is available (either was installed or already present).
        False if all install strategies failed.
    """
    # Fast path: already cached
    if tool in _install_cache:
        return _install_cache[tool]

    # Fast path: already on PATH
    if shutil.which(tool) is not None:
        _install_cache[tool] = True
        return True

    # Also check if it's importable as a Python module
    if _is_python_package(tool):
        _install_cache[tool] = True
        return True

    strategies = _TOOL_STRATEGIES.get(tool)
    if not strategies:
        log.warning("installer_no_strategy", tool=tool)
        _install_cache[tool] = False
        return False

    log.info("installer_start", tool=tool, strategies=len(strategies))

    for i, strategy in enumerate(strategies):
        log.info("installer_trying_strategy", tool=tool, attempt=i + 1, total=len(strategies))
        try:
            ok = await strategy()
        except Exception as exc:
            log.warning("installer_strategy_error", tool=tool, attempt=i + 1, error=str(exc))
            ok = False

        if ok:
            # Verify the tool is now available
            available = shutil.which(tool) is not None or _is_python_package(tool)
            if available:
                log.info("installer_success", tool=tool, strategy=i + 1)
                _install_cache[tool] = True
                return True
            else:
                log.warning(
                    "installer_strategy_ok_but_tool_missing",
                    tool=tool,
                    strategy=i + 1,
                )

    log.warning("installer_all_strategies_failed", tool=tool)
    _install_cache[tool] = False
    return False


async def ensure_tools(*tools: str) -> dict[str, bool]:
    """Ensure multiple tools are available concurrently.

    Returns:
        Dict mapping tool name → availability (True/False).
    """
    results = await asyncio.gather(*[ensure_tool(t) for t in tools])
    return dict(zip(tools, results))


def is_available(tool: str) -> bool:
    """Synchronous check: is a tool currently available?

    Does NOT attempt installation. Use ensure_tool() for that.
    """
    if tool in _install_cache:
        return _install_cache[tool]
    available = shutil.which(tool) is not None or _is_python_package(tool)
    if available:
        _install_cache[tool] = True
    return available


def _is_python_package(name: str) -> bool:
    """Check if a Python package is importable (handles pip-only packages)."""
    import importlib.util
    # Normalize: pefile → pefile, z3-solver → z3, pwntools → pwn
    module_name = name.replace("-", "_").split("-")[0]
    special = {"pwntools": "pwn", "z3-solver": "z3"}
    module_name = special.get(name, module_name)
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ModuleNotFoundError, ValueError):
        return False
