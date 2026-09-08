"""Unpack node -- conditional binary unpacking (#6).

Runs between triage and decompile when the binary appears packed
(high entropy detected). Tries UPX first, then generic dynamic dump.
Falls through to decompile on failure (Ghidra can sometimes handle packed binaries).
"""
from __future__ import annotations

import asyncio
import os
import shutil
import tempfile
from pathlib import Path

from kraken.state import KrakenState
from kraken.logging.structured import get_logger

log = get_logger(__name__)


async def _try_upx_unpack(binary_path: str) -> str | None:
    """Attempt UPX unpacking. Returns path to unpacked binary or None."""
    if not shutil.which("upx"):
        log.info("unpack_upx_not_found")
        return None

    # Copy to temp to avoid modifying original
    with tempfile.NamedTemporaryFile(delete=False, suffix="_unpacked") as tmp:
        tmp_path = tmp.name

    shutil.copy2(binary_path, tmp_path)

    try:
        proc = await asyncio.create_subprocess_exec(
            "upx", "-d", tmp_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)

        if proc.returncode == 0:
            log.info("unpack_upx_success", output=stdout.decode(errors="replace")[:200])
            os.chmod(tmp_path, 0o755)
            return tmp_path
        else:
            log.info("unpack_upx_failed", stderr=stderr.decode(errors="replace")[:200])
            Path(tmp_path).unlink(missing_ok=True)
            return None
    except asyncio.TimeoutError:
        log.warning("unpack_upx_timeout")
        Path(tmp_path).unlink(missing_ok=True)
        return None
    except Exception as e:
        log.warning("unpack_upx_error", error=str(e))
        Path(tmp_path).unlink(missing_ok=True)
        return None


async def _try_dynamic_dump(binary_path: str) -> str | None:
    """Attempt dynamic OEP dump by running binary briefly and dumping .text.

    Uses lief to extract the .text section after potential runtime unpacking.
    This is a best-effort heuristic for simple packers.
    """
    try:
        # Run binary briefly to trigger self-unpacking
        proc = await asyncio.create_subprocess_exec(
            binary_path,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            await asyncio.wait_for(proc.communicate(input=b"\n"), timeout=3)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()

        # After running, some packers unpack in-place or leave traces
        # For now, we can't reliably dump from memory without ptrace
        # This is a placeholder for future LD_PRELOAD-based dumping
        return None
    except Exception as e:
        log.warning("unpack_dynamic_dump_error", error=str(e))
        return None


async def unpack(state: KrakenState) -> dict:
    """Conditional unpack: only runs if binary appears packed.

    If the binary is not packed, returns immediately (no-op).
    Tries UPX first, then dynamic dump as fallback.
    Updates challenge_path if unpacking succeeds.
    """
    binary_info = state.get("binary_info", {})
    binary_path = state["challenge_path"]

    entropy = binary_info.get("entropy", {})
    likely_packed = entropy.get("likely_packed", False)

    # Check for known packer signatures in strings
    strings = state.get("strings_of_interest", [])
    upx_detected = any("UPX" in s or "upx" in s for s in strings[:100])

    if not likely_packed and not upx_detected:
        log.info("unpack_skip", reason="binary not packed")
        return {
            "recent_actions": [{
                "action": "unpack",
                "reasoning": "Skipped -- binary not detected as packed",
                "result_summary": "No unpacking needed",
            }],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    log.info("unpack_start", likely_packed=likely_packed, upx_detected=upx_detected)

    # Strategy 1: UPX unpack
    unpacked_path = await _try_upx_unpack(binary_path)

    # Strategy 2: Dynamic dump (future enhancement)
    if unpacked_path is None:
        unpacked_path = await _try_dynamic_dump(binary_path)

    if unpacked_path:
        log.info("unpack_success", original=binary_path, unpacked=unpacked_path)
        return {
            "challenge_path": unpacked_path,
            "recent_actions": [{
                "action": "unpack",
                "reasoning": f"Unpacked binary (packed={'UPX' if upx_detected else 'entropy'})",
                "result_summary": f"Unpacked → {unpacked_path}",
            }],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    log.info("unpack_failed_continuing", reason="all unpack strategies failed")
    return {
        "recent_actions": [{
            "action": "unpack",
            "reasoning": "Binary appears packed but unpacking failed -- proceeding with packed binary",
            "result_summary": "Unpack failed, using original binary",
        }],
        "error_log": [{
            "node": "unpack",
            "error": "Unpacking failed (tried UPX, dynamic dump). Ghidra may still produce partial results.",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
