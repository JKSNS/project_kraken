#!/usr/bin/env python3
"""auto_firmware_extract -- binwalk + unblob orchestrator for firmware blobs.

Lives in src/kraken/helpers/ (shared substrate per the two-arm convention)
but is primarily consumed by KRAKEN's firmware-recon flow.

Input: a firmware blob (uImage, .bin, .img, vendor-packaged blob, etc.).
Output: a dict with extracted_dir, list of detected filesystem roots,
list of ELF executables found, formats detected, plus (always) a status
string that's honest about what worked and what didn't.

Behaviour matrix:
    binwalk available    → use binwalk -e (with --no-rebuild + --max-size cap)
    binwalk + unblob     → unblob first (more accurate on modern formats),
                            binwalk fallback
    nothing available    → return a structured "needs_extractor" finding
                            with the install instructions

Output is intentionally JSON-serialisable so the playbook engine can
pass it through ${steps.<id>.outputs.<field>} substitution.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

DEFAULT_MAX_SIZE_MB = 200  # cap on input we'll attempt to extract
DEFAULT_BUDGET_S = 120


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _detect_extractors() -> dict:
    return {
        "binwalk": shutil.which("binwalk") is not None,
        "unblob": shutil.which("unblob") is not None,
        "unsquashfs": shutil.which("unsquashfs") is not None,
        "cpio": shutil.which("cpio") is not None,
    }


def _is_elf(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) == b"\x7fELF"
    except OSError:
        return False


def _walk_for_elfs(root: Path, *, max_count: int = 5000) -> list[str]:
    elfs: list[str] = []
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.is_symlink():
            continue
        if _is_elf(p):
            elfs.append(str(p))
            if len(elfs) >= max_count:
                break
    return sorted(elfs)


# Priority order for "most-interesting" binary in a firmware FS -- favour
# network-exposed daemons that take operator-controlled input. Ranked by
# typical attack surface in OpenWrt-class firmware.
_PRIORITY_BINARY_NAMES = (
    "uhttpd",  # OpenWrt's HTTP daemon (LuCI front-end)
    "dropbear",  # SSH daemon
    "lighttpd",
    "nginx",
    "apache2",
    "telnetd",
    "ftpd",
    "vsftpd",
    "miniupnpd",
    "hostapd",
    "wpa_supplicant",
    "dnsmasq",
    "smbd",
    "samba",
    "vsf",
    "tinyproxy",
    "sshd",
)


def _rank_priority_targets(elfs: list[str], top_k: int = 5) -> list[dict]:
    """Pick the highest-attack-surface ELFs from an extracted FS by name + path."""
    ranked: list[tuple[int, str, str]] = []
    for path in elfs:
        name = Path(path).name.lower()
        score = 0
        reason_bits: list[str] = []
        for i, candidate in enumerate(_PRIORITY_BINARY_NAMES):
            if name == candidate or name.startswith(candidate):
                score = 100 - i  # earlier = higher priority
                reason_bits.append(f"matches_priority_name:{candidate}")
                break
        # Bonus for /usr/sbin (daemons typically live here)
        if "/usr/sbin/" in path or "/sbin/" in path:
            score += 5
            reason_bits.append("daemon_path")
        # CGI scripts are often the front door to RCE
        if "/cgi-bin/" in path or "/www/" in path:
            score += 8
            reason_bits.append("web_front_end_path")
        if score > 0:
            ranked.append((score, path, "; ".join(reason_bits)))
    ranked.sort(key=lambda x: -x[0])
    return [{"path": path, "score": score, "reason": reason} for score, path, reason in ranked[:top_k]]


def _detect_fs_roots(extracted_dir: Path) -> list[str]:
    """Heuristic: any directory containing a recognisable Linux FS layout
    (bin/ + sbin/ + etc/) is a 'rootfs root'. Returns paths to those roots.
    """
    roots: list[str] = []
    for p in extracted_dir.rglob("*"):
        if not p.is_dir():
            continue
        names = {child.name for child in p.iterdir() if child.is_dir()}
        # Loose match -- Linux roots have multiple of these
        score = sum(1 for n in ("bin", "sbin", "etc", "lib", "usr", "var") if n in names)
        if score >= 3:
            roots.append(str(p))
    return sorted(roots)


def _run_binwalk(blob: Path, out_dir: Path, *, budget_s: int) -> dict:
    """Run binwalk -e in out_dir; return structured outcome."""
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    # binwalk -C sets the output directory; it'll create _<basename>.extracted/
    try:
        result = subprocess.run(
            ["binwalk", "-e", "-C", str(out_dir), str(blob)],
            capture_output=True,
            text=True,
            timeout=budget_s,
        )
    except subprocess.TimeoutExpired:
        return {
            "extractor": "binwalk",
            "status": "timeout",
            "elapsed_s": round(time.time() - t0, 2),
            "stderr_tail": "",
        }
    return {
        "extractor": "binwalk",
        "status": "ok" if result.returncode == 0 else "nonzero_exit",
        "exit_code": result.returncode,
        "elapsed_s": round(time.time() - t0, 2),
        "stderr_tail": (result.stderr or "")[-1000:],
        "stdout_tail": (result.stdout or "")[-2000:],
    }


def _formats_from_binwalk_signatures(blob: Path) -> list[str]:
    """A read-only `binwalk` invocation that just reports detected
    signatures; useful for the dossier even when extraction fails."""
    try:
        result = subprocess.run(
            ["binwalk", str(blob)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []
    formats: list[str] = []
    for line in (result.stdout or "").splitlines():
        # binwalk output lines look like "0    0x0    uImage header, image..."
        parts = line.split(None, 2)
        if len(parts) >= 3 and parts[0].isdigit():
            desc = parts[2].split(",")[0].strip()
            if desc and desc not in formats:
                formats.append(desc)
    return formats


def extract_firmware(
    blob: str | Path,
    *,
    out_dir: str | Path | None = None,
    budget_s: int = DEFAULT_BUDGET_S,
    max_size_mb: int = DEFAULT_MAX_SIZE_MB,
) -> dict:
    """Top-level entry. Always returns a dict; never raises on extraction
    failure (only on bad inputs)."""
    blob_path = Path(blob).resolve()
    if not blob_path.exists():
        return {
            "status": "input_missing",
            "blob": str(blob_path),
            "error": f"blob does not exist: {blob_path}",
        }
    size = blob_path.stat().st_size
    if size > max_size_mb * 1024 * 1024:
        return {
            "status": "input_too_large",
            "blob": str(blob_path),
            "size_bytes": size,
            "max_size_mb": max_size_mb,
            "error": f"blob exceeds {max_size_mb} MB cap",
        }

    sha = _sha256(blob_path)
    out_dir = Path(out_dir) if out_dir else Path("extracted") / sha[:8]
    out_dir.mkdir(parents=True, exist_ok=True)

    extractors = _detect_extractors()
    formats_detected = _formats_from_binwalk_signatures(blob_path) if extractors["binwalk"] else []

    if not (extractors["binwalk"] or extractors["unblob"]):
        return {
            "status": "needs_extractor",
            "blob": str(blob_path),
            "sha256": sha,
            "size_bytes": size,
            "extractors_available": extractors,
            "formats_detected": formats_detected,
            "next_steps": [
                "apt-get install binwalk squashfs-tools cpio",
                "or: pip install unblob",
                "after install, re-run; output dir: " + str(out_dir),
            ],
        }

    extraction = _run_binwalk(blob_path, out_dir, budget_s=budget_s)

    extracted_dir = out_dir
    fs_roots = _detect_fs_roots(extracted_dir)

    # ── Vendor-UBI chain (Marvell / Linksys WRT-style packaging) ─────
    # When binwalk produces .ubi files but no fs_roots, try the
    # ubireader_extract_images → unsquashfs chain. v0.2.2 found that
    # binwalk-extracted .ubi was malformed; ubireader_extract_images on
    # the ORIGINAL blob (not the binwalk artifact) finds the volumes
    # cleanly, and the contained .ubifs file is often actually SquashFS.
    ubi_chain_used = False
    if not fs_roots and shutil.which("ubireader_extract_images") and shutil.which("unsquashfs"):
        ubi_out = out_dir / "ubi_volumes"
        try:
            subprocess.run(
                ["ubireader_extract_images", str(blob_path), "-o", str(ubi_out)],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        # ubireader writes .ubifs files; some are SquashFS in disguise
        for ubifs_file in ubi_out.rglob("*.ubifs"):
            if ubifs_file.stat().st_size == 0:
                continue
            with ubifs_file.open("rb") as f:
                magic = f.read(4)
            sq_out = out_dir / f"ubi_squashfs_{ubifs_file.stem}"
            if magic == b"hsqs":  # SquashFS magic (little-endian)
                try:
                    subprocess.run(
                        ["unsquashfs", "-d", str(sq_out), str(ubifs_file)],
                        capture_output=True,
                        text=True,
                        timeout=120,
                    )
                    ubi_chain_used = True
                except (FileNotFoundError, subprocess.TimeoutExpired):
                    pass
        # Re-detect fs_roots after the UBI chain
        if ubi_chain_used:
            fs_roots = _detect_fs_roots(extracted_dir)
    elfs = _walk_for_elfs(extracted_dir) if fs_roots else _walk_for_elfs(extracted_dir)

    priority_targets = _rank_priority_targets(elfs)
    priority_target_first = priority_targets[0]["path"] if priority_targets else (elfs[0] if elfs else "")

    return {
        "status": "ok" if extraction["status"] == "ok" and (fs_roots or elfs) else "partial",
        "blob": str(blob_path),
        "sha256": sha,
        "size_bytes": size,
        "out_dir": str(out_dir),
        "extracted_dir": str(extracted_dir),
        "fs_roots": fs_roots,
        "fs_root_count": len(fs_roots),
        "executables": elfs,
        "executable_count": len(elfs),
        "priority_targets": priority_targets,
        "priority_target_first": priority_target_first,
        "formats_detected": formats_detected,
        "extraction": extraction,
        "extractors_available": extractors,
    }


# ── Playbook-friendly entry ───────────────────────────────────────────


def playbook_extract_firmware(
    *,
    target: str,
    out_dir: str | None = None,
    budget_s: int = DEFAULT_BUDGET_S,
) -> dict:
    """Wrapper used by the playbook engine. Same as `extract_firmware` --
    keyword-only, plain types."""
    return extract_firmware(
        target,
        out_dir=out_dir,
        budget_s=int(budget_s) if budget_s else DEFAULT_BUDGET_S,
    )


# ── CLI ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auto_firmware_extract",
        description="Extract a firmware blob (binwalk + unblob orchestrator)",
    )
    parser.add_argument("blob", help="Path to firmware blob")
    parser.add_argument("--out-dir", default=None, help="Output dir (default: extracted/<sha8>)")
    parser.add_argument(
        "--budget",
        type=int,
        default=DEFAULT_BUDGET_S,
        help=f"Wall-clock cap for extraction (default {DEFAULT_BUDGET_S}s)",
    )
    parser.add_argument("--json", action="store_true", help="Emit JSON only (default: human summary)")
    args = parser.parse_args(argv)

    result = extract_firmware(args.blob, out_dir=args.out_dir, budget_s=args.budget)

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result["status"] == "ok" else 2

    # Human summary
    print(f"firmware: {result.get('blob')}")
    print(f"  sha256: {result.get('sha256', 'n/a')}")
    print(f"  size:   {result.get('size_bytes', 0):,} bytes")
    print(f"  status: {result.get('status')}")
    if result.get("formats_detected"):
        print(f"  formats: {', '.join(result['formats_detected'][:5])}")
    if result.get("extracted_dir"):
        print(f"  extracted to: {result['extracted_dir']}")
    print(f"  fs_roots: {result.get('fs_root_count', 0)}")
    print(f"  executables: {result.get('executable_count', 0)} ELFs")
    if result.get("status") == "needs_extractor":
        print("  next steps:")
        for s in result.get("next_steps", []):
            print(f"    - {s}")
    return 0 if result["status"] == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
