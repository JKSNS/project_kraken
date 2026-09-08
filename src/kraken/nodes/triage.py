"""Triage node -- deterministic initial analysis of challenge binary.

Runs all binary info tools and populates state with metadata.
No LLM calls -- purely subprocess-based.

If challenge_path is a directory, auto-detects the most likely binary
inside it (by file type, size, and executable bit).

Enhanced with pwntools ELF and lief analysis for deeper binary insight.
All independent analyses run concurrently via asyncio.gather().
"""

from __future__ import annotations

import asyncio
import base64
import math
import os
import re
from pathlib import Path

from kraken.storage.ledger import append_ledger_entry
from kraken.logging.structured import get_logger
from kraken.state import KrakenState
from kraken.tools.binary_info import (
    collect_binary_info,
    file_info,
    strings_extract,
    strings_grep,
)

log = get_logger(__name__)

# file(1) output substrings that indicate a real binary (not text, image, etc.)
_BINARY_SIGNATURES = [
    "ELF",
    "PE32",
    "Mach-O",
    "shared object",
    "executable",
    "relocatable",
    "object",
]

# Files to always skip when scanning a challenge directory
_SKIP_NAMES = {
    "readme",
    "readme.md",
    "readme.txt",
    "flag.txt",
    "description",
    "challenge.json",
    "challenge.yaml",
    "challenge.yml",
    "makefile",
    "dockerfile",
    ".gitignore",
    "license",
    "license.txt",
}

_SKIP_EXTENSIONS = {
    ".md",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".c",
    ".cpp",
    ".h",
    ".py",
    ".sh",
    ".html",
    ".css",
    ".js",
    ".java",
    ".rs",
    ".png",
    ".jpg",
    ".gif",
    ".svg",
}


def _check_magic(path: Path) -> str | None:
    """Check file magic bytes to identify binary type without `file` command."""
    try:
        with open(path, "rb") as f:
            header = f.read(16)
    except OSError:
        return None

    if len(header) < 4:
        return None

    # ELF: \x7fELF
    if header[:4] == b"\x7fELF":
        return "ELF"
    # Near-miss ELF: first byte corrupted but "ELF" magic intact
    if header[1:4] == b"ELF":
        return "ELF (corrupted)"
    # PE: MZ header -- check for .NET CLR to give a better type
    if header[:2] == b"MZ":
        if _is_dotnet_pe(path):
            return "PE32 (.NET)"
        return "PE32"
    # Mach-O: various magic values
    if header[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "Mach-O"
    # Mach-O universal (fat binary)
    if header[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "Mach-O"
    return None


def _is_dotnet_pe(path: Path) -> bool:
    """Return True if this PE file is a .NET assembly (has CLR runtime header)."""
    try:
        import pefile

        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR"]])
        clr = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return clr.VirtualAddress != 0 and clr.Size != 0
    except Exception:
        pass
    # Fallback: look for mscoree.dll in the raw bytes
    try:
        data = path.read_bytes()
        return b"mscoree.dll" in data or b"_CorExeMain" in data
    except Exception:
        return False


async def _find_binary_in_dir(dir_path: Path, max_depth: int = 3) -> Path | None:
    """Find the most likely challenge binary inside a directory.

    Strategy:
    1. Recursively scan up to max_depth levels deep.
    2. Check magic bytes (ELF/PE/Mach-O) -- works without `file` command.
    3. Fall back to `file` command if magic bytes don't match.
    4. Prefer files with the executable bit set.
    5. Among matches, prefer the largest file (more likely the real binary).
    """
    candidates: list[tuple[Path, str, int]] = []  # (path, file_type, size)

    for entry in sorted(dir_path.rglob("*")):
        if not entry.is_file():
            continue
        # Enforce max depth
        try:
            rel_depth = len(entry.relative_to(dir_path).parts)
        except ValueError:
            continue
        if rel_depth > max_depth:
            continue
        # Skip dotfiles, known non-binary files, and extracted dirs
        if entry.name.startswith("."):
            continue
        if entry.name.lower() in _SKIP_NAMES:
            continue
        if entry.suffix.lower() in _SKIP_EXTENSIONS:
            continue
        if "_extracted" in entry.parts:
            continue

        size = entry.stat().st_size if entry.exists() else 0

        # Fast check: magic bytes
        magic = _check_magic(entry)
        if magic:
            candidates.append((entry, magic, size))
            continue

        # Slow check: file(1) command
        result = await file_info(str(entry))
        ftype = result.data.get("file_type", "") if result.success else ""
        if any(sig in ftype for sig in _BINARY_SIGNATURES):
            candidates.append((entry, ftype, size))

    if not candidates:
        return None

    # Prefer executable files, then largest
    def score(item: tuple[Path, str, int]) -> tuple[int, int]:
        path, _, sz = item
        has_exec = os.access(str(path), os.X_OK)
        return (1 if has_exec else 0, sz)

    candidates.sort(key=score, reverse=True)
    return candidates[0][0]


async def _extract_archives(dir_path: Path) -> Path | None:
    """Extract archives in challenge dir (recursive) and return path to extracted binary."""
    archive_exts = {".zip", ".tar", ".gz", ".7z", ".bz2", ".xz"}
    archives = [
        f
        for f in dir_path.rglob("*")
        if f.is_file() and f.suffix.lower() in archive_exts and "_extracted" not in f.parts
    ]
    if not archives:
        return None

    extract_dir = dir_path / "_extracted"
    extract_dir.mkdir(exist_ok=True)

    for archive in archives:
        ext = archive.suffix.lower()
        if ext == ".zip":
            cmd = ["unzip", "-o", str(archive), "-d", str(extract_dir)]
        elif ext in (".tar", ".gz", ".bz2", ".xz"):
            cmd = ["tar", "xf", str(archive), "-C", str(extract_dir)]
        elif ext == ".7z":
            cmd = ["7z", "x", str(archive), f"-o{extract_dir}", "-y"]
        else:
            continue
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()

    # Re-scan extracted directory for binaries
    return await _find_binary_in_dir(extract_dir)


# ── Text extensions eligible for content preview ──────────────────
_TEXT_EXTENSIONS = {
    ".py",
    ".c",
    ".cpp",
    ".h",
    ".js",
    ".html",
    ".yml",
    ".yaml",
    ".json",
    ".sh",
    ".md",
    ".txt",
    ".rs",
    ".go",
    ".java",
    ".css",
    ".toml",
    ".cfg",
    ".ini",
    ".xml",
    ".sql",
    ".rb",
    ".pl",
}


def _inventory_directory(dir_path: Path) -> dict:
    """Inventory all files in a challenge directory.

    Returns a dict keyed by filename with metadata for each file.
    """
    inventory: dict = {}
    for entry in sorted(dir_path.rglob("*")):
        if not entry.is_file():
            continue
        if entry.name.startswith("."):
            continue

        rel = str(entry.relative_to(dir_path))
        size = entry.stat().st_size

        # Determine file type
        magic = _check_magic(entry)
        if magic:
            ftype = f"binary ({magic})"
        else:
            ftype = f"text ({entry.suffix})" if entry.suffix else "unknown"

        info: dict = {
            "path": str(entry),
            "type": ftype,
            "size": size,
        }

        # Read content preview for text files
        if entry.suffix.lower() in _TEXT_EXTENSIONS and size < 500_000:
            try:
                info["content_preview"] = entry.read_text(errors="replace")[:2000]
            except OSError:
                pass

        # Note archive contents
        ext_lower = entry.suffix.lower()
        if ext_lower in (".zip", ".tar", ".gz", ".7z", ".bz2", ".xz"):
            info["type"] = f"archive ({ext_lower})"

        # Note PDF files
        if ext_lower == ".pdf":
            info["type"] = "document (PDF)"

        # Note PCAP/network capture files
        if ext_lower in (".pcap", ".pcapng"):
            info["type"] = "network capture (PCAP)"

        # Note image files with specific type
        if ext_lower in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".tiff"):
            info["type"] = f"image ({ext_lower})"

        # Note email files
        if ext_lower == ".eml":
            info["type"] = "email message"

        inventory[rel] = info

    return inventory


def _detect_remote_from_text(text: str) -> dict:
    """Detect remote server info from challenge description text.

    Recognises common CTF patterns like 'nc host port', HTTPS URLs,
    'Connect to host:port', and standalone 'host:port'.

    HTTPS URL extraction is highest priority -- CTFd challenge descriptions
    frequently embed the live challenge URL (e.g. https://chall.ctf.com) which
    is the authoritative endpoint.  Without this, solvers incorrectly report
    REMOTE_OFFLINE when the live URL was never probed.
    """
    if not text:
        return {}

    # ── Highest priority: bare HTTPS/HTTP URL ─────────────────────────────────
    # Matches https://host, https://host:port, https://host/path
    url_match = re.search(r"(https?://[^\s\"'<>]{4,})", text)
    if url_match:
        url = url_match.group(1).rstrip(".,;)")
        # Parse host and port from URL
        url_host_match = re.match(r"https?://([^\s/:]+)(?::(\d+))?", url)
        if url_host_match:
            host = url_host_match.group(1)
            port = int(url_host_match.group(2)) if url_host_match.group(2) else (443 if url.startswith("https") else 80)
            return {
                "host": host,
                "port": port,
                "url": url,
                "protocol": "https" if url.startswith("https") else "http",
                "source": "description_url",
            }

    patterns = [
        # nc / ncat host port
        r"(?:nc|ncat)\s+([\w.\-]+)\s+(\d{2,5})",
        # nc / ncat host:port
        r"(?:nc|ncat)\s+([\w.\-]+):(\d{2,5})",
        # socat ... TCP:host:port
        r"socat\s+.*TCP[46]?:([\w.\-]+):(\d{2,5})",
        # Connect to host:port / connect to host port
        r"[Cc]onnect\s+to\s+([\w.\-]+)[:\s]+(\d{2,5})",
        # Standalone host:port on its own line
        r"^\s*([\w.\-]+):(\d{2,5})\s*$",
    ]

    for pattern in patterns:
        match = re.search(pattern, text, re.MULTILINE)
        if match:
            host, port_str = match.group(1), match.group(2)
            port = int(port_str)
            if 1 <= port <= 65535:
                return {
                    "host": host,
                    "port": port,
                    "protocol": "tcp",
                    "source": "description",
                }
    return {}


def _detect_remote_from_docker_compose(content: str) -> dict:
    """Extract exposed port from docker-compose content.

    Tries YAML parsing first, falls back to regex for resilience.
    """
    if not content:
        return {}

    # Try yaml.safe_load
    try:
        import yaml

        data = yaml.safe_load(content)
        if isinstance(data, dict) and "services" in data:
            for svc_name, svc in data["services"].items():
                ports = svc.get("ports", [])
                for p in ports:
                    p_str = str(p)
                    # "1337:1337" or "0.0.0.0:1337:1337"
                    parts = p_str.split(":")
                    if len(parts) >= 2:
                        ext_port = parts[-2] if len(parts) >= 2 else parts[0]
                        # ext_port might be "0.0.0.0" in "0.0.0.0:1337:1337"
                        try:
                            port = int(parts[0]) if len(parts) == 2 else int(parts[1])
                        except ValueError:
                            continue
                        if 1 <= port <= 65535:
                            return {
                                "host": "localhost",
                                "port": port,
                                "protocol": "tcp",
                                "source": "docker-compose",
                            }
    except Exception:
        pass

    # Fallback: regex for ports mapping
    port_match = re.search(r'ports:\s*\n\s*-\s*["\']?(\d{2,5}):\d{2,5}["\']?', content)
    if port_match:
        port = int(port_match.group(1))
        if 1 <= port <= 65535:
            return {
                "host": "localhost",
                "port": port,
                "protocol": "tcp",
                "source": "docker-compose",
            }

    return {}


# ── Enhanced analysis helpers ─────────────────────────────────────


async def _pwntools_analysis(binary_path: str) -> dict:
    """Run pwntools ELF analysis -- symbols, GOT/PLT, checksec."""
    try:
        from kraken.tools.dynamic import pwntools_analyze

        result = await pwntools_analyze(binary_path)
        if result.success and result.data:
            return result.data
    except Exception as e:
        log.warning("triage_pwntools_failed", error=str(e))
    return {}


async def _lief_analysis(binary_path: str) -> dict:
    """Run lief ELF analysis -- sections, imports, anti-debug detection."""
    try:
        from kraken.tools.dynamic import lief_analyze

        result = await lief_analyze(binary_path)
        if result.success and result.data:
            return result.data
    except Exception as e:
        log.warning("triage_lief_failed", error=str(e))
    return {}


async def _run_strings(binary_path: str, flag_format: str) -> tuple[list[str], list[str]]:
    """Extract and filter strings from binary. Returns (interesting, flag_matches)."""
    strings_result = await strings_extract(binary_path)
    all_strings = strings_result.data.get("strings", []) if strings_result.success else []

    # Filter to interesting strings
    interesting = [
        s
        for s in all_strings
        if len(s) >= 6
        or any(
            kw in s.lower()
            for kw in [
                "flag",
                "key",
                "pass",
                "secret",
                "correct",
                "wrong",
                "invalid",
                "http",
                "://",
                "base64",
                "encrypt",
                "decrypt",
                "xor",
            ]
        )
    ]

    # Check for flag-format strings
    flag_strings = await strings_grep(binary_path, flag_format)
    flag_matches = []
    if flag_strings.success and flag_strings.data.get("matched"):
        flag_matches = flag_strings.data["matched"]

    return interesting, flag_matches


async def _quick_run(binary_path: str) -> dict:
    """Quick test run of the binary with empty input to see default behavior."""
    try:
        from kraken.tools.dynamic import subprocess_trace

        result = await subprocess_trace(binary_path, stdin_input="\n", timeout=5)
        if result.success and result.data:
            return {
                "stdout": result.data.get("stdout", "")[:500],
                "stderr": result.data.get("stderr", "")[:500],
                "exit_code": result.data.get("exit_code", -1),
            }
    except Exception as e:
        log.warning("triage_quick_run_failed", error=str(e))
    return {}


def _detect_encodings(strings_of_interest: list[str], binary_info: dict) -> dict:
    """Detect encoding schemes present in the binary's strings.

    Checks for base64, hex, base91/base85, custom alphabets, and nested
    encodings (up to 3 layers deep).
    """
    detected: set[str] = set()
    evidence: list[dict] = []
    chains: list[list[str]] = []

    _B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
    _HEX_RE = re.compile(r"[0-9a-fA-F]{16,}")
    # base91 uses printable ASCII 0x21-0x7E excluding quotes
    _B91_RE = re.compile(r"[!-~]{16,}")

    def _shannon_entropy(s: str) -> float:
        if not s:
            return 0.0
        freq: dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        length = len(s)
        return -sum((count / length) * math.log2(count / length) for count in freq.values())

    def _try_decode(s: str, depth: int = 0) -> list[tuple[str, str, str]]:
        """Try to decode a string, returning list of (encoding, decoded_preview, chain)."""
        if depth > 3 or len(s) < 4:
            return []
        results: list[tuple[str, str, str]] = []

        # Base64
        for m in _B64_RE.finditer(s):
            candidate = m.group()
            if len(candidate) % 4 in (0, 2, 3):
                try:
                    dec = base64.b64decode(candidate + "=" * (-len(candidate) % 4))
                    preview = dec[:40]
                    if all(0x20 <= b <= 0x7E for b in preview) and len(preview) > 2:
                        results.append(("base64", preview.decode("ascii", errors="replace"), candidate[:60]))
                except Exception:
                    pass

        # Hex strings (even length)
        for m in _HEX_RE.finditer(s):
            candidate = m.group()
            if len(candidate) % 2 == 0:
                try:
                    dec = bytes.fromhex(candidate)
                    preview = dec[:40]
                    if all(0x20 <= b <= 0x7E for b in preview) and len(preview) > 2:
                        results.append(("hex", preview.decode("ascii", errors="replace"), candidate[:60]))
                except Exception:
                    pass

        # Base85 (ascii85)
        try:
            dec = base64.a85decode(s.encode("ascii"))
            if all(0x20 <= b <= 0x7E for b in dec[:40]) and len(dec) > 2:
                results.append(("base85", dec[:40].decode("ascii", errors="replace"), s[:60]))
        except Exception:
            pass

        return results

    for s in strings_of_interest[:200]:
        if len(s) < 8:
            continue

        # Check for base64 patterns
        if _B64_RE.search(s):
            decoded_items = _try_decode(s)
            for enc, preview, original in decoded_items:
                detected.add(enc)
                evidence.append(
                    {
                        "string": original,
                        "encoding": enc,
                        "decoded_preview": preview,
                    }
                )

        # Check for hex strings
        if _HEX_RE.search(s) and len(s) >= 16:
            m = _HEX_RE.search(s)
            if m and len(m.group()) % 2 == 0:
                try:
                    dec = bytes.fromhex(m.group())
                    if any(0x20 <= b <= 0x7E for b in dec[:20]):
                        detected.add("hex")
                        evidence.append(
                            {
                                "string": m.group()[:60],
                                "encoding": "hex",
                                "decoded_preview": dec[:40].decode("ascii", errors="replace"),
                            }
                        )
                except Exception:
                    pass

        # Check for base91-like or custom encoding
        entropy = _shannon_entropy(s)
        charset = set(s)
        if entropy > 5.5 and len(charset) < 95 and len(s) >= 12:
            # High entropy over limited charset suggests custom encoding
            if all(0x21 <= ord(c) <= 0x7E for c in s):
                detected.add("custom_encoding")
                evidence.append(
                    {
                        "string": s[:60],
                        "encoding": "custom_encoding",
                        "decoded_preview": f"entropy={entropy:.1f}, charset_size={len(charset)}",
                    }
                )

        # Check for base91 specifically (chars in 0x21-0x7E range, high density)
        if _B91_RE.fullmatch(s) and entropy > 5.0 and 40 < len(charset) < 92:
            detected.add("base91")
            if "base91" not in {e.get("encoding") for e in evidence}:
                evidence.append(
                    {
                        "string": s[:60],
                        "encoding": "base91",
                        "decoded_preview": f"entropy={entropy:.1f}, charset_size={len(charset)}",
                    }
                )

    # Detect possible encoding chains from evidence
    if len(detected) > 1:
        enc_list = sorted(detected)
        chains.append(enc_list)

    return {
        "detected_encodings": sorted(detected),
        "encoding_evidence": evidence[:10],
        "possible_chains": chains,
    }


async def triage(state: KrakenState) -> dict:
    """Deterministic triage: collect all binary metadata.

    Runs all independent analyses concurrently for speed.
    """
    binary_path = state["challenge_path"]
    flag_format = state.get("flag_format", r"flag\{[a-zA-Z0-9_]+\}")

    log.info("triage_start", binary=binary_path)

    # If path is a directory, find the actual binary inside it
    path_obj = Path(binary_path)
    resolved_path = binary_path

    # ── Directory handling ─────────────────────────────────────────
    is_directory = path_obj.is_dir()
    has_binary = False
    challenge_files: dict = {}

    if is_directory:
        log.info("triage_scanning_directory", directory=binary_path)
        # Inventory all files first
        challenge_files = _inventory_directory(path_obj)
        log.info("triage_inventory", file_count=len(challenge_files))

        found = await _find_binary_in_dir(path_obj)
        if found is None:
            found = await _extract_archives(path_obj)
            if found:
                log.info("triage.archive_extracted", binary=str(found))
        if found:
            resolved_path = str(found)
            has_binary = True
            log.info("triage_binary_found", binary=resolved_path)
        else:
            log.info("triage_directory_no_binary", directory=binary_path, file_count=len(challenge_files))
    else:
        # Validate the file actually exists before proceeding
        if not path_obj.exists():
            log.error("triage_binary_not_found", path=binary_path)
            return {
                "binary_info": {"file_type": "NOT FOUND", "error": f"File does not exist: {binary_path}"},
                "strings_of_interest": [],
                "recent_actions": [
                    {
                        "action": "triage",
                        "reasoning": f"Binary not found at {binary_path}",
                        "result_summary": f"FATAL: {binary_path} does not exist. Fix the path in challenge.json",
                    }
                ],
            }
        has_binary = True

    # ── Detect special file types that need different handling ────
    _ext = path_obj.suffix.lower() if not is_directory else ""
    _is_pyc = _ext == ".pyc"
    _is_macro = _ext in (".xlsm", ".xls", ".xlsb", ".doc", ".docm", ".pptm")
    _is_script = _ext in (".py", ".js", ".rb", ".pl", ".sh", ".ps1")

    # ── Binary analysis (only if we have an actual binary) ────────
    binary_info: dict = {}
    strings_of_interest: list = []
    flag_matches: list = []

    if has_binary:
        (
            binary_info,
            (interesting_strings, flag_matches),
            pwntools_data,
            lief_data,
            quick_run_data,
        ) = await asyncio.gather(
            collect_binary_info(resolved_path),
            _run_strings(resolved_path, flag_format),
            _pwntools_analysis(resolved_path),
            _lief_analysis(resolved_path),
            _quick_run(resolved_path),
        )

        # Merge flag matches at the top of interesting strings
        if flag_matches:
            log.info("triage_flag_in_strings", count=len(flag_matches))
            interesting_strings = flag_matches + interesting_strings

        # Deduplicate
        strings_of_interest = list(dict.fromkeys(interesting_strings))

        # ── Encoding detection on strings ────────────────────────
        encoding_hints = _detect_encodings(strings_of_interest, binary_info)
        if encoding_hints.get("detected_encodings"):
            binary_info["encoding_hints"] = encoding_hints
            log.info(
                "triage_encodings_detected",
                encodings=encoding_hints["detected_encodings"],
                evidence_count=len(encoding_hints.get("encoding_evidence", [])),
            )

        # ── Merge pwntools/lief data into binary_info ────────────
        if pwntools_data:
            pwn_symbols = pwntools_data.get("symbols", {})
            if len(pwn_symbols) > len(binary_info.get("symbols", {})):
                binary_info["symbols"] = pwn_symbols
                log.info("triage_pwntools_symbols", count=len(pwn_symbols))
            binary_info["got"] = pwntools_data.get("got", {})
            binary_info["plt"] = pwntools_data.get("plt", {})
            binary_info["checksec_pwntools"] = pwntools_data.get("checksec", {})
            binary_info["entry_point"] = pwntools_data.get("entry", "")

        if lief_data:
            binary_info["imports"] = lief_data.get("imports", [])
            binary_info["exports"] = lief_data.get("exports", [])
            binary_info["custom_sections"] = lief_data.get("custom_sections", [])
            binary_info["anti_debug_indicators"] = lief_data.get("anti_debug_indicators", [])
            binary_info["lief_sections"] = lief_data.get("sections", [])

            if lief_data.get("anti_debug_indicators"):
                log.info("triage_anti_debug_detected", indicators=lief_data["anti_debug_indicators"])

        if quick_run_data:
            binary_info["quick_run"] = quick_run_data

        # Corrupted ELF detection -- flag for downstream nodes
        if "(corrupted)" in binary_info.get("file_type", ""):
            binary_info["corruption_detected"] = True
            log.info("triage_corrupted_elf", binary=resolved_path)
        else:
            # Also check via magic bytes on the resolved path
            resolved = Path(resolved_path)
            _magic_check = _check_magic(resolved)
            if _magic_check and "(corrupted)" in _magic_check:
                binary_info["corruption_detected"] = True
                log.info("triage_corrupted_elf", binary=resolved_path)

        # .NET detection -- annotate binary_info so classify sees it
        resolved = Path(resolved_path)
        if _is_dotnet_pe(resolved) or "(.NET)" in binary_info.get("file_type", ""):
            binary_info["is_dotnet"] = True
            binary_info["dotnet_note"] = (
                "This is a .NET/CIL assembly. Ghidra only sees the native PE stub. "
                "To decompile, use: ilspycmd, dnSpy, dotPeek, or monodis. "
                "Install: dotnet tool install -g ilspycmd"
            )
            log.info("triage_dotnet_detected", binary=resolved_path)

        # Python bytecode (.pyc) detection
        if _is_pyc:
            binary_info["is_pyc"] = True
            binary_info["file_type"] = "Python bytecode (.pyc)"
            # Try to get Python version from magic bytes
            try:
                with open(resolved_path, "rb") as f:
                    magic = f.read(4)
                import struct

                magic_int = struct.unpack("<I", magic)[0] & 0xFFFF
                # Python 3.8 = 3413, 3.9 = 3425, etc.
                binary_info["pyc_magic"] = hex(magic_int)
            except Exception:
                pass
            log.info("triage_pyc_detected", binary=resolved_path)

        # Macro/VBA document detection
        if _is_macro:
            binary_info["is_macro"] = True
            binary_info["file_type"] = f"Office macro document ({_ext})"
            log.info("triage_macro_detected", binary=resolved_path, ext=_ext)

        log.info(
            "triage_complete",
            file_type=binary_info.get("file_type", "unknown"),
            num_strings=len(strings_of_interest),
            num_symbols=len(binary_info.get("symbols", {})),
            likely_packed=binary_info.get("entropy", {}).get("likely_packed", False),
            has_anti_debug=bool(binary_info.get("anti_debug_indicators")),
        )
    else:
        # No binary -- summarize from file inventory
        log.info("triage_complete_no_binary", file_count=len(challenge_files))

    # ── Remote server detection ───────────────────────────────────
    remote_info: dict = state.get("remote_info", {})

    # 1. From challenge description (highest priority -- CTF prompt)
    desc = state.get("challenge_description", "")
    # Auto-extract description from inventoried text files if not already set
    if not desc:
        for fname, finfo in challenge_files.items():
            if fname.lower() in ("description.txt", "readme.md", "readme.txt", "description.md"):
                desc = finfo.get("content_preview", "")
                if desc:
                    break
    if desc and not remote_info:
        remote_info = _detect_remote_from_text(desc)

    # 2. From docker-compose.yml if found
    if not remote_info:
        for fname, finfo in challenge_files.items():
            if "docker-compose" in fname.lower():
                preview = finfo.get("content_preview", "")
                if preview:
                    remote_info = _detect_remote_from_docker_compose(preview)
                    if remote_info:
                        break

    if remote_info:
        log.info("triage_remote_detected", **remote_info)

    updates: dict = {
        "binary_info": binary_info,
        "strings_of_interest": strings_of_interest,
        "symbols": binary_info.get("symbols", {}),
        "challenge_files": challenge_files,
        "remote_info": remote_info,
        "recent_actions": [
            {
                "action": "triage",
                "reasoning": "Initial deterministic analysis"
                + (
                    " (parallel: binary_info + strings + pwntools + lief + quick_run)"
                    if has_binary
                    else " (directory-only: file inventory)"
                ),
                "result_summary": (
                    (
                        f"File: {binary_info.get('file_type', 'unknown')[:80]}, "
                        f"{len(strings_of_interest)} interesting strings, "
                        f"{len(binary_info.get('symbols', {}))} symbols, "
                        f"packed={binary_info.get('entropy', {}).get('likely_packed', False)}"
                        + (
                            f", anti_debug={binary_info.get('anti_debug_indicators', [])}"
                            if binary_info.get("anti_debug_indicators")
                            else ""
                        )
                        + (
                            f", {len(binary_info.get('custom_sections', []))} custom sections"
                            if binary_info.get("custom_sections")
                            else ""
                        )
                    )
                    if has_binary
                    else "No binary found"
                )
                + (f", {len(challenge_files)} challenge files" if challenge_files else "")
                + (f", remote={remote_info.get('host', '')}:{remote_info.get('port', '')}" if remote_info else ""),
            }
        ],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }

    # ── Early flag detection: if flag is already visible, short-circuit ──
    # This sets tool_flag_candidate so route_after_tools sends straight
    # to flag_validator, skipping the LLM solve engine entirely.
    # Safe: if wrong, flag_validator rejects it and the pipeline retries normally.
    _early_flag = ""
    _flag_re = re.compile(flag_format) if flag_format else None

    # Check 1: flag in strings output (e.g., hardcoded flag in binary)
    if flag_matches and _flag_re:
        for fm in flag_matches:
            m = _flag_re.search(fm)
            if m and len(m.group(0)) >= 8:
                _early_flag = m.group(0)
                break

    # Check 2: flag in quick_run stdout (binary prints flag with no input)
    if not _early_flag and quick_run_data and _flag_re:
        qr_output = quick_run_data.get("stdout", "") + " " + quick_run_data.get("stderr", "")
        m = _flag_re.search(qr_output)
        if m and len(m.group(0)) >= 8:
            _early_flag = m.group(0)

    # Check 3: flag in challenge file contents (plaintext flag files)
    if not _early_flag and _flag_re:
        for name, info in challenge_files.items():
            preview = info.get("content_preview", "")
            if preview:
                m = _flag_re.search(preview)
                if m and len(m.group(0)) >= 8:
                    _early_flag = m.group(0)
                    break

    if _early_flag:
        updates["tool_flag_candidate"] = _early_flag
        log.info("triage_early_flag", flag=_early_flag)

    # If we resolved a directory to a binary, update the path for downstream nodes
    if resolved_path != binary_path:
        updates["challenge_path"] = resolved_path

    # Prior-art exploit search (universal). Surfaces existing exploits as
    # authoritative threat-model documentation -- discovered during the eCTF
    # validation pass: any target shipping `solve*.py` / `exploit*.py` /
    # `pwn*.py` / `attack*.py` tells you the bug class + transport + threat
    # model in 90 lines.
    if is_directory:
        try:
            import sys as _sys
            from pathlib import Path as _Path

            _helpers = _Path(__file__).resolve().parent.parent / "helpers"
            if str(_helpers) not in _sys.path:
                _sys.path.insert(0, str(_helpers))
            import auto_existing_exploits  # type: ignore

            ee = auto_existing_exploits.analyze(path_obj, max_snippet=10)
            if ee.get("exploits"):
                updates["prior_art_exploits"] = ee["exploits"]
                transports = {e.get("transport") for e in ee["exploits"]}
                if "serial" in transports:
                    updates["prior_art_routing_hint"] = "firmware"
                elif "tcp" in transports:
                    updates["prior_art_routing_hint"] = "remote_pwn"
                elif "http" in transports:
                    updates["prior_art_routing_hint"] = "web"
                log.info(
                    "triage.prior_art",
                    exploit_count=len(ee["exploits"]),
                    transports=sorted(t for t in transports if t),
                )
            # Emit case_state event so other helpers + the orchestrator
            # can query for prior-art findings (10x gap closure).
            try:
                import auto_case_state as _cs  # type: ignore

                _cs.record(
                    path_obj.name,
                    "kraken.triage",
                    "triage_summary",
                    {
                        "binary": str(resolved_path),
                        "file_type": binary_info.get("file_type", "unknown"),
                        "architecture": binary_info.get("architecture", "unknown"),
                        "prior_art_exploits": len(ee.get("exploits", [])),
                        "prior_art_routing_hint": updates.get("prior_art_routing_hint"),
                    },
                )
            except Exception:
                pass
        except Exception as e:
            log.warning("triage.prior_art_failed", error=str(e))

    append_ledger_entry(
        state.get("solve_ledger_path", ""),
        (
            f"- file_type: {binary_info.get('file_type', 'unknown')}\n"
            f"- architecture: {binary_info.get('architecture', 'unknown')}\n"
            f"- likely_packed: {binary_info.get('entropy', {}).get('likely_packed', False)}\n"
            f"- anti_debug: {bool(binary_info.get('anti_debug_indicators'))}\n"
            f"- prior_art_exploits: {len(updates.get('prior_art_exploits', []))}\n"
        ),
    )

    return updates
