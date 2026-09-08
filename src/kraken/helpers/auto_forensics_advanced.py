#!/usr/bin/env python3
"""auto_forensics_advanced -- Advanced forensics: memory, disk, registry, browser, email.

Extends the existing forensics capabilities (PCAP, steg, file carve) with
analysis of memory dumps, disk images, registry hives, SQLite databases,
email files, and browser artifacts.

Capabilities:
  - Volatility3 memory forensics: process list, cmdline, handles, netscan,
    bash history, file scanning, hash dumping
  - Disk image analysis: mount + walk, foremost/scalpel file carving,
    deleted file recovery
  - Registry analysis: parse Windows registry hives (requires python-registry)
  - Email forensics: .eml/.mbox parsing, attachment extraction, header analysis
  - Browser forensics: SQLite databases (cookies, history, bookmarks, downloads,
    saved passwords, localStorage)
  - Timeline analysis: event timeline from multiple sources
  - Windows Event Log (EVTX) parsing
  - NTFS Alternate Data Streams detection
  - Windows Prefetch file parsing
  - Raw string scanning as universal fallback

Outputs EXTRACTED FLAG: <flag> on success.
"""
from __future__ import annotations

import argparse
import base64
import email
import email.policy
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile

DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")


def _flag_re(prefix: str = "flag") -> re.Pattern:
    """Build flag regex from prefix."""
    return re.compile(rf"{re.escape(prefix)}\{{[A-Za-z0-9_\-\.]+\}}")


def _find_flags(text: str, pattern: re.Pattern) -> list[str]:
    """Extract all flag matches from text."""
    return pattern.findall(text)


def _detect_evidence_type(evidence_path: str) -> str:
    """Detect evidence type from file extension and magic bytes."""
    ext = os.path.splitext(evidence_path)[1].lower()

    # Check by extension first
    ext_map = {
        ".raw": "memory",
        ".vmem": "memory",
        ".dmp": "memory",
        ".mem": "memory",
        ".hibernation": "memory",
        ".dd": "disk",
        ".img": "disk",
        ".e01": "disk",
        ".iso": "disk",
        ".vmdk": "disk",
        ".qcow2": "disk",
        ".reg": "registry",
        ".db": "database",
        ".sqlite": "database",
        ".sqlite3": "database",
        ".eml": "email",
        ".mbox": "email",
        ".msg": "email",
        ".evtx": "evtx",
        ".evt": "evtx",
        ".pf": "prefetch",
    }

    if ext in ext_map:
        return ext_map[ext]

    # Check with `file` command for magic bytes
    try:
        result = subprocess.run(
            ["file", "-b", evidence_path],
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout.lower()

        if any(kw in output for kw in ("memory dump", "hibernation", "crash dump")):
            return "memory"
        if any(kw in output for kw in ("filesystem", "disk image", "boot sector", "fat", "ext2", "ntfs")):
            return "disk"
        if "registry" in output:
            return "registry"
        if "sqlite" in output:
            return "database"
        if any(kw in output for kw in ("mail", "rfc 822", "smtp")):
            return "email"
        if "data" in output and os.path.getsize(evidence_path) > 1024 * 1024:
            # Large "data" files are often memory dumps
            return "memory"
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass

    return "unknown"


def _strings_scan(filepath: str, flag_pattern: re.Pattern, min_len: int = 6) -> list[str]:
    """Run strings command and search for flags. Universal fallback."""
    flags: list[str] = []
    try:
        result = subprocess.run(
            ["strings", "-n", str(min_len), filepath],
            capture_output=True,
            text=True,
            timeout=120,
        )
        for line in result.stdout.splitlines():
            flags.extend(_find_flags(line, flag_pattern))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        # Fallback: manual ASCII extraction
        try:
            with open(filepath, "rb") as f:
                # Read in chunks to handle large files
                chunk_size = 10 * 1024 * 1024  # 10MB
                while True:
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    text = chunk.decode("utf-8", errors="ignore")
                    for line in text.splitlines():
                        flags.extend(_find_flags(line, flag_pattern))
        except OSError:
            pass
    return flags


def _base64_scan(text: str, flag_pattern: re.Pattern) -> list[str]:
    """Find and decode base64 strings, searching for flags in decoded content."""
    flags: list[str] = []
    for m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            decoded = base64.b64decode(m.group(0)).decode("utf-8", errors="replace")
            printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
            if printable > len(decoded) * 0.7 and len(decoded) >= 3:
                flags.extend(_find_flags(decoded, flag_pattern))
        except Exception:
            pass
    return flags


# ---------------------------------------------------------------------------
# Memory analysis
# ---------------------------------------------------------------------------

def analyze_memory(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Analyze memory dump with Volatility3 and raw string scanning."""
    flags: list[str] = []

    # Try Volatility3 commands
    vol_cmd = _find_volatility()
    if vol_cmd:
        print("[*] Running Volatility3 analysis...")

        # Windows plugins
        win_plugins = [
            "windows.info",
            "windows.pslist",
            "windows.cmdline",
            "windows.filescan",
            "windows.netscan",
            "windows.hashdump",
            "windows.envars",
            "windows.registry.hivelist",
        ]
        # Linux plugins
        linux_plugins = [
            "linux.bash",
            "linux.pslist",
            "linux.psaux",
            "linux.check_syscall",
            "linux.proc.Maps",
        ]

        os_detected = _detect_memory_os(evidence_path, vol_cmd)
        plugins = win_plugins if os_detected == "windows" else linux_plugins
        if os_detected == "unknown":
            plugins = win_plugins + linux_plugins

        for plugin in plugins:
            print(f"  [*] Running {plugin}...")
            try:
                result = subprocess.run(
                    vol_cmd + ["-f", evidence_path, plugin],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                found = _find_flags(result.stdout, flag_pattern)
                if found:
                    print(f"  [+] Flag found in {plugin} output!")
                    flags.extend(found)
                # Also check base64 in output
                flags.extend(_base64_scan(result.stdout, flag_pattern))
            except subprocess.TimeoutExpired:
                print(f"  [-] {plugin} timed out")
            except FileNotFoundError:
                break

        # Dump files from memory
        tmp_dump = tempfile.mkdtemp(prefix="kraken_vol_")
        try:
            print("[*] Attempting file extraction from memory...")
            for plugin in ["windows.dumpfiles", "windows.memmap"]:
                try:
                    subprocess.run(
                        vol_cmd + ["-f", evidence_path, plugin, "--dump-dir", tmp_dump],
                        capture_output=True,
                        text=True,
                        timeout=180,
                    )
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    pass

            # Scan dumped files
            for root, _dirs, files in os.walk(tmp_dump):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read(1024 * 1024)
                        text = data.decode("utf-8", errors="ignore")
                        found = _find_flags(text, flag_pattern)
                        if found:
                            print(f"  [+] Flag found in dumped file: {fname}")
                            flags.extend(found)
                    except OSError:
                        pass
        finally:
            shutil.rmtree(tmp_dump, ignore_errors=True)

    else:
        print("[*] Volatility3 not found, using raw string scanning")

    # Raw string search (always run as fallback)
    print("[*] Running raw string scan on memory dump...")
    flags.extend(_strings_scan(evidence_path, flag_pattern))

    return flags


def _find_volatility() -> list[str] | None:
    """Find the Volatility3 command (vol, vol3, python -m volatility3)."""
    for cmd in [["vol"], ["vol3"], ["volatility3"], [sys.executable, "-m", "volatility3"]]:
        try:
            result = subprocess.run(
                cmd + ["-h"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 or "volatility" in result.stdout.lower():
                return cmd
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
    return None


def _detect_memory_os(evidence_path: str, vol_cmd: list[str]) -> str:
    """Detect OS from memory dump using Volatility3 banners.info."""
    try:
        result = subprocess.run(
            vol_cmd + ["-f", evidence_path, "banners.Banners"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout.lower()
        if "windows" in output:
            return "windows"
        if "linux" in output:
            return "linux"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    # Check first bytes for hints
    try:
        with open(evidence_path, "rb") as f:
            header = f.read(4096)
        if b"PAGEDU" in header or b"MDMP" in header:
            return "windows"
        if b"ELF" in header:
            return "linux"
    except OSError:
        pass

    return "unknown"


# ---------------------------------------------------------------------------
# Disk image analysis
# ---------------------------------------------------------------------------

def analyze_disk(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Analyze disk image: mount, walk, carve."""
    flags: list[str] = []

    # Method 1: Try mounting
    mount_point = tempfile.mkdtemp(prefix="kraken_mount_")
    mounted = False

    try:
        print("[*] Attempting to mount disk image...")
        result = subprocess.run(
            ["mount", "-o", "ro,loop,noexec,nosuid", evidence_path, mount_point],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            mounted = True
            print("[+] Image mounted successfully")

            file_count = 0
            for root, _dirs, files in os.walk(mount_point):
                for fname in files:
                    filepath = os.path.join(root, fname)
                    file_count += 1
                    try:
                        size = os.path.getsize(filepath)
                        if size > 50 * 1024 * 1024:  # Skip files > 50MB
                            continue
                        with open(filepath, "rb") as fh:
                            data = fh.read(1024 * 1024)
                        text = data.decode("utf-8", errors="ignore")
                        found = _find_flags(text, flag_pattern)
                        if found:
                            relpath = os.path.relpath(filepath, mount_point)
                            print(f"  [+] Flag found in mounted file: {relpath}")
                            flags.extend(found)
                    except (OSError, PermissionError):
                        pass

            print(f"  [*] Scanned {file_count} files in mounted image")
        else:
            print(f"  [-] Mount failed: {result.stderr[:200]}")

    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        print(f"  [-] Mount error: {exc}")
    finally:
        if mounted:
            try:
                subprocess.run(
                    ["umount", mount_point],
                    capture_output=True,
                    timeout=10,
                )
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        shutil.rmtree(mount_point, ignore_errors=True)

    # Method 2: File carving with foremost
    if not flags:
        print("[*] Trying file carving with foremost...")
        carve_dir = tempfile.mkdtemp(prefix="kraken_carve_")
        try:
            result = subprocess.run(
                ["foremost", "-i", evidence_path, "-o", os.path.join(carve_dir, "output")],
                capture_output=True,
                text=True,
                timeout=300,
            )
            # Search carved files
            for root, _dirs, files in os.walk(carve_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read(1024 * 1024)
                        text = data.decode("utf-8", errors="ignore")
                        found = _find_flags(text, flag_pattern)
                        if found:
                            print(f"  [+] Flag found in carved file: {fname}")
                            flags.extend(found)
                    except OSError:
                        pass
        except (FileNotFoundError, subprocess.TimeoutExpired):
            print("  [-] foremost not available or timed out")
        finally:
            shutil.rmtree(carve_dir, ignore_errors=True)

    # Method 3: Try scalpel if foremost unavailable
    if not flags:
        try:
            carve_dir = tempfile.mkdtemp(prefix="kraken_scalpel_")
            subprocess.run(
                ["scalpel", evidence_path, "-o", carve_dir],
                capture_output=True,
                text=True,
                timeout=300,
            )
            for root, _dirs, files in os.walk(carve_dir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "rb") as f:
                            data = f.read(1024 * 1024)
                        text = data.decode("utf-8", errors="ignore")
                        found = _find_flags(text, flag_pattern)
                        if found:
                            print(f"  [+] Flag found in scalpel output: {fname}")
                            flags.extend(found)
                    except OSError:
                        pass
            shutil.rmtree(carve_dir, ignore_errors=True)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    # Method 4: Raw strings scan
    if not flags:
        print("[*] Running raw string scan on disk image...")
        flags.extend(_strings_scan(evidence_path, flag_pattern))

    return flags


# ---------------------------------------------------------------------------
# Registry analysis
# ---------------------------------------------------------------------------

def analyze_registry(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Parse Windows registry hive for flag data."""
    flags: list[str] = []

    # Try python-registry
    try:
        from Registry import Registry

        print("[*] Parsing registry hive with python-registry...")
        reg = Registry.Registry(evidence_path)

        def _walk_registry(key, depth=0):
            if depth > 20:
                return
            try:
                for value in key.values():
                    try:
                        val_data = str(value.value())
                        found = _find_flags(val_data, flag_pattern)
                        if found:
                            print(f"  [+] Flag in registry: {key.path()}\\{value.name()}")
                            flags.extend(found)
                    except Exception:
                        pass
                for subkey in key.subkeys():
                    _walk_registry(subkey, depth + 1)
            except Exception:
                pass

        _walk_registry(reg.root())
        print(f"  [*] Registry scan complete")

    except ImportError:
        print("[*] python-registry not available, using raw string scan")
        flags.extend(_strings_scan(evidence_path, flag_pattern))
    except Exception as exc:
        print(f"[-] Registry parse error: {exc}")
        flags.extend(_strings_scan(evidence_path, flag_pattern))

    return flags


# ---------------------------------------------------------------------------
# Database analysis
# ---------------------------------------------------------------------------

def analyze_database(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Analyze SQLite database for flag data."""
    flags: list[str] = []

    try:
        conn = sqlite3.connect(f"file:{evidence_path}?mode=ro", uri=True)
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        cursor = conn.cursor()

        # List all tables
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        print(f"[*] Found {len(tables)} table(s): {', '.join(tables[:10])}")

        for table in tables:
            try:
                # Get column info
                cursor.execute(f"PRAGMA table_info([{table}])")
                columns = [row[1] for row in cursor.fetchall()]

                # Read all rows
                cursor.execute(f"SELECT * FROM [{table}] LIMIT 10000")
                for row in cursor.fetchall():
                    row_text = " ".join(str(col) for col in row if col is not None)
                    found = _find_flags(row_text, flag_pattern)
                    if found:
                        print(f"  [+] Flag in table '{table}'")
                        flags.extend(found)

                    # Check for base64 content
                    for col in row:
                        if isinstance(col, str) and len(col) > 20:
                            flags.extend(_base64_scan(col, flag_pattern))
                        elif isinstance(col, bytes):
                            text = col.decode("utf-8", errors="ignore")
                            found = _find_flags(text, flag_pattern)
                            if found:
                                flags.extend(found)

            except sqlite3.OperationalError:
                pass

        conn.close()

    except sqlite3.Error as exc:
        print(f"[-] SQLite error: {exc}")
        # Fallback to strings
        flags.extend(_strings_scan(evidence_path, flag_pattern))

    # Browser-specific analysis
    if not flags:
        flags.extend(_analyze_browser_db(evidence_path, flag_pattern))

    # Enhanced browser analysis (passwords, localStorage, autofill, etc.)
    if not flags:
        flags.extend(_analyze_browser_db_enhanced(evidence_path, flag_pattern))

    return flags


def _analyze_browser_db(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Check for browser-specific tables (cookies, history, bookmarks)."""
    flags: list[str] = []

    try:
        conn = sqlite3.connect(f"file:{evidence_path}?mode=ro", uri=True)
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0].lower() for row in cursor.fetchall()}

        # Chrome/Firefox history
        if "urls" in tables or "moz_places" in tables:
            print("  [*] Browser history detected")
            for tbl in ["urls", "moz_places"]:
                if tbl.lower() in tables:
                    try:
                        cursor.execute(f"SELECT * FROM [{tbl}]")
                        for row in cursor.fetchall():
                            text = " ".join(str(c) for c in row if c)
                            flags.extend(_find_flags(text, flag_pattern))
                    except sqlite3.OperationalError:
                        pass

        # Cookies
        if "cookies" in tables or "moz_cookies" in tables:
            print("  [*] Browser cookies detected")
            for tbl in ["cookies", "moz_cookies"]:
                if tbl.lower() in tables:
                    try:
                        cursor.execute(f"SELECT * FROM [{tbl}]")
                        for row in cursor.fetchall():
                            text = " ".join(str(c) for c in row if c)
                            flags.extend(_find_flags(text, flag_pattern))
                    except sqlite3.OperationalError:
                        pass

        # Bookmarks
        if "bookmarks" in tables or "moz_bookmarks" in tables:
            print("  [*] Browser bookmarks detected")
            for tbl in ["bookmarks", "moz_bookmarks"]:
                if tbl.lower() in tables:
                    try:
                        cursor.execute(f"SELECT * FROM [{tbl}]")
                        for row in cursor.fetchall():
                            text = " ".join(str(c) for c in row if c)
                            flags.extend(_find_flags(text, flag_pattern))
                    except sqlite3.OperationalError:
                        pass

        # Downloads
        if "downloads" in tables or "moz_downloads" in tables:
            print("  [*] Browser downloads detected")
            for tbl in ["downloads", "moz_downloads"]:
                if tbl.lower() in tables:
                    try:
                        cursor.execute(f"SELECT * FROM [{tbl}]")
                        for row in cursor.fetchall():
                            text = " ".join(str(c) for c in row if c)
                            flags.extend(_find_flags(text, flag_pattern))
                    except sqlite3.OperationalError:
                        pass

        conn.close()
    except sqlite3.Error:
        pass

    return flags


# ---------------------------------------------------------------------------
# Email analysis
# ---------------------------------------------------------------------------

def analyze_email(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Parse email files (.eml, .mbox) for flag data."""
    flags: list[str] = []

    ext = os.path.splitext(evidence_path)[1].lower()

    if ext == ".mbox":
        flags.extend(_analyze_mbox(evidence_path, flag_pattern))
    else:
        # Single .eml or similar
        flags.extend(_analyze_eml(evidence_path, flag_pattern))

    return flags


def _analyze_eml(filepath: str, flag_pattern: re.Pattern) -> list[str]:
    """Parse a single .eml file."""
    flags: list[str] = []

    try:
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f, policy=email.policy.default)
    except Exception as exc:
        print(f"[-] Failed to parse email: {exc}")
        # Fallback to raw scan
        return _strings_scan(filepath, flag_pattern)

    print(f"[*] Email: From={msg.get('From', '?')}, Subject={msg.get('Subject', '?')}")

    # Check headers
    for header in msg.keys():
        value = str(msg[header])
        flags.extend(_find_flags(value, flag_pattern))

    # Check body parts
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition = str(part.get("Content-Disposition", ""))

            if content_type in ("text/plain", "text/html"):
                try:
                    body = part.get_content()
                    if isinstance(body, bytes):
                        body = body.decode("utf-8", errors="replace")
                    body = str(body)
                    flags.extend(_find_flags(body, flag_pattern))
                    flags.extend(_base64_scan(body, flag_pattern))
                except Exception:
                    pass

            # Check attachments
            if "attachment" in disposition or part.get_filename():
                fname = part.get_filename() or "attachment"
                print(f"  [*] Attachment: {fname}")
                try:
                    payload = part.get_payload(decode=True)
                    if payload:
                        text = payload.decode("utf-8", errors="ignore")
                        flags.extend(_find_flags(text, flag_pattern))
                except Exception:
                    pass
    else:
        try:
            body = msg.get_content()
            if isinstance(body, bytes):
                body = body.decode("utf-8", errors="replace")
            body = str(body)
            flags.extend(_find_flags(body, flag_pattern))
            flags.extend(_base64_scan(body, flag_pattern))
        except Exception:
            pass

    return flags


def _analyze_mbox(filepath: str, flag_pattern: re.Pattern) -> list[str]:
    """Parse an mbox file containing multiple emails."""
    flags: list[str] = []

    try:
        import mailbox

        mbox = mailbox.mbox(filepath)
        msg_count = 0

        for msg in mbox:
            msg_count += 1
            subject = msg.get("Subject", "?")
            print(f"  [*] Message {msg_count}: {subject}")

            # Check all parts
            if msg.is_multipart():
                for part in msg.walk():
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            text = payload.decode("utf-8", errors="replace")
                            flags.extend(_find_flags(text, flag_pattern))
                    except Exception:
                        pass
            else:
                try:
                    payload = msg.get_payload(decode=True)
                    if payload:
                        text = payload.decode("utf-8", errors="replace")
                        flags.extend(_find_flags(text, flag_pattern))
                except Exception:
                    pass

        mbox.close()
        print(f"  [*] Processed {msg_count} messages")

    except Exception as exc:
        print(f"[-] mbox parse error: {exc}")
        flags.extend(_strings_scan(filepath, flag_pattern))

    return flags


# ---------------------------------------------------------------------------
# Windows Event Log (EVTX) Parsing
# ---------------------------------------------------------------------------

def analyze_evtx(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Parse Windows Event Log files (.evtx) for flags and artifacts."""
    flags: list[str] = []

    # Try python-evtx library
    try:
        import Evtx.Evtx as evtx

        print("[*] Parsing EVTX with python-evtx...")
        record_count = 0
        with evtx.Evtx(evidence_path) as log:
            for record in log.records():
                record_count += 1
                try:
                    xml = record.xml()
                    found = _find_flags(xml, flag_pattern)
                    if found:
                        print(f"  [+] Flag in event record {record_count}")
                        flags.extend(found)

                    # Also check for base64 in event data
                    flags.extend(_base64_scan(xml, flag_pattern))

                    # Look for interesting event data: command lines, scripts, etc.
                    # Event ID 4688 = process creation, 4104 = PowerShell script block
                    if 'CommandLine' in xml or 'ScriptBlockText' in xml:
                        # Extract content between tags
                        for tag in ['CommandLine', 'ScriptBlockText', 'ParentCommandLine']:
                            for m in re.finditer(
                                rf'<Data Name="{tag}">([^<]+)</Data>', xml
                            ):
                                found = _find_flags(m.group(1), flag_pattern)
                                if found:
                                    flags.extend(found)
                except Exception:
                    pass

        print(f"  [*] Processed {record_count} event records")

    except ImportError:
        print("[*] python-evtx not available, trying evtxexport CLI...")

        # Try evtxexport CLI tool
        try:
            result = subprocess.run(
                ['evtxexport', evidence_path],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout:
                found = _find_flags(result.stdout, flag_pattern)
                if found:
                    print(f"  [+] Flag found in evtxexport output")
                    flags.extend(found)
                flags.extend(_base64_scan(result.stdout, flag_pattern))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Try evtx_dump (Rust tool)
        try:
            result = subprocess.run(
                ['evtx_dump', evidence_path],
                capture_output=True, text=True, timeout=120
            )
            if result.returncode == 0 and result.stdout:
                found = _find_flags(result.stdout, flag_pattern)
                if found:
                    print(f"  [+] Flag found in evtx_dump output")
                    flags.extend(found)
                flags.extend(_base64_scan(result.stdout, flag_pattern))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        # Fallback: raw string scan
        if not flags:
            print("[*] Falling back to raw string scan on EVTX...")
            flags.extend(_strings_scan(evidence_path, flag_pattern))

    except Exception as exc:
        print(f"[-] EVTX parse error: {exc}")
        flags.extend(_strings_scan(evidence_path, flag_pattern))

    return flags


# ---------------------------------------------------------------------------
# NTFS Alternate Data Streams
# ---------------------------------------------------------------------------

def scan_ads(mount_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Scan for NTFS Alternate Data Streams containing hidden data."""
    flags: list[str] = []

    # Method 1: Use getfattr to find extended attributes
    try:
        result = subprocess.run(
            ['getfattr', '-R', '-d', '-m', '-', mount_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"[*] Found extended attributes in {mount_path}")
            found = _find_flags(result.stdout, flag_pattern)
            if found:
                flags.extend(found)
            # Decode any base64 in attribute values
            flags.extend(_base64_scan(result.stdout, flag_pattern))
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Method 2: Use ntfs-3g streams_xattr or custom ntfs utils
    try:
        result = subprocess.run(
            ['ntfs-3g.streams', '-l', mount_path],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            print(f"[*] NTFS streams found")
            found = _find_flags(result.stdout, flag_pattern)
            if found:
                flags.extend(found)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # Method 3: Walk filesystem and check for ADS using 7z
    for root, dirs, files in os.walk(mount_path):
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                # Use 7z to list alternate streams
                result = subprocess.run(
                    ['7z', 'l', '-slt', fpath],
                    capture_output=True, text=True, timeout=10
                )
                if result.returncode == 0 and ':' in result.stdout:
                    # Look for ADS entries (filename:streamname)
                    for line in result.stdout.split('\n'):
                        if 'Path = ' in line and ':' in line:
                            stream_name = line.split(':', 1)[1].strip()
                            if stream_name and stream_name not in ('$DATA', ''):
                                print(f"  [*] ADS found: {fname}:{stream_name}")
                                # Try to extract the stream
                                try:
                                    extract_result = subprocess.run(
                                        ['7z', 'e', '-so', f'{fpath}:{stream_name}'],
                                        capture_output=True, timeout=10
                                    )
                                    if extract_result.returncode == 0:
                                        text = extract_result.stdout.decode('utf-8', errors='replace')
                                        found = _find_flags(text, flag_pattern)
                                        if found:
                                            flags.extend(found)
                                except (subprocess.TimeoutExpired, Exception):
                                    pass
            except (FileNotFoundError, subprocess.TimeoutExpired):
                break  # 7z not available
            except Exception:
                continue

    return flags


# ---------------------------------------------------------------------------
# Enhanced Browser Artifact Extraction
# ---------------------------------------------------------------------------

def _analyze_browser_db_enhanced(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Enhanced browser artifact extraction: passwords, localStorage, sessions."""
    flags: list[str] = []

    try:
        conn = sqlite3.connect(f"file:{evidence_path}?mode=ro", uri=True)
        conn.text_factory = lambda b: b.decode("utf-8", errors="replace")
        cursor = conn.cursor()

        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = {row[0].lower(): row[0] for row in cursor.fetchall()}

        # Chrome Login Data (saved passwords)
        if "logins" in tables:
            print("  [*] Chrome saved passwords detected")
            try:
                cursor.execute(f"SELECT origin_url, username_value, password_value FROM [{tables['logins']}]")
                for row in cursor.fetchall():
                    text = " ".join(str(c) for c in row if c)
                    found = _find_flags(text, flag_pattern)
                    if found:
                        print(f"  [+] Flag in saved passwords")
                        flags.extend(found)
                    # Password value might be encrypted blob or plaintext
                    if row[2]:
                        if isinstance(row[2], bytes):
                            pwd_text = row[2].decode('utf-8', errors='replace')
                        else:
                            pwd_text = str(row[2])
                        found = _find_flags(pwd_text, flag_pattern)
                        if found:
                            flags.extend(found)
            except sqlite3.OperationalError:
                pass

        # Chrome/Firefox localStorage (webappsstore.sqlite / Web Data)
        if "webappsstore2" in tables:
            print("  [*] Firefox localStorage detected")
            try:
                cursor.execute(f"SELECT key, value FROM [{tables['webappsstore2']}]")
                for row in cursor.fetchall():
                    text = " ".join(str(c) for c in row if c)
                    found = _find_flags(text, flag_pattern)
                    if found:
                        flags.extend(found)
            except sqlite3.OperationalError:
                pass

        # Firefox form history
        if "moz_formhistory" in tables:
            print("  [*] Firefox form history detected")
            try:
                cursor.execute(f"SELECT fieldname, value FROM [{tables['moz_formhistory']}]")
                for row in cursor.fetchall():
                    text = " ".join(str(c) for c in row if c)
                    found = _find_flags(text, flag_pattern)
                    if found:
                        flags.extend(found)
            except sqlite3.OperationalError:
                pass

        # Session storage / tabs
        for tbl_name in ["session_tabs", "tabs", "moz_session"]:
            if tbl_name in tables:
                print(f"  [*] Browser session data detected: {tbl_name}")
                try:
                    cursor.execute(f"SELECT * FROM [{tables[tbl_name]}]")
                    for row in cursor.fetchall():
                        text = " ".join(str(c) for c in row if c)
                        found = _find_flags(text, flag_pattern)
                        if found:
                            flags.extend(found)
                except sqlite3.OperationalError:
                    pass

        # Chrome autofill
        if "autofill" in tables:
            print("  [*] Chrome autofill data detected")
            try:
                cursor.execute(f"SELECT name, value FROM [{tables['autofill']}]")
                for row in cursor.fetchall():
                    text = " ".join(str(c) for c in row if c)
                    found = _find_flags(text, flag_pattern)
                    if found:
                        flags.extend(found)
            except sqlite3.OperationalError:
                pass

        # Chrome/Firefox search terms
        for tbl_name in ["keyword_search_terms", "moz_inputhistory"]:
            if tbl_name in tables:
                print(f"  [*] Search history detected: {tbl_name}")
                try:
                    cursor.execute(f"SELECT * FROM [{tables[tbl_name]}]")
                    for row in cursor.fetchall():
                        text = " ".join(str(c) for c in row if c)
                        found = _find_flags(text, flag_pattern)
                        if found:
                            flags.extend(found)
                except sqlite3.OperationalError:
                    pass

        conn.close()
    except sqlite3.Error:
        pass

    return flags


# ---------------------------------------------------------------------------
# Windows Prefetch File Parsing
# ---------------------------------------------------------------------------

def analyze_prefetch(evidence_path: str, flag_pattern: re.Pattern) -> list[str]:
    """Parse Windows Prefetch (.pf) files for execution history and flags."""
    flags: list[str] = []

    try:
        with open(evidence_path, 'rb') as f:
            data = f.read()
    except OSError as exc:
        print(f"[-] Cannot read prefetch file: {exc}")
        return flags

    if len(data) < 84:
        return flags

    # Check Prefetch signature
    # Prefetch files can be uncompressed or compressed (MAM)
    is_compressed = False
    if data[:4] == b'MAM\x04':
        # Windows 10 compressed prefetch
        is_compressed = True
        print("[*] Compressed prefetch (Windows 10+), trying decompression...")
        try:
            import lzma
            # Skip MAM header (8 bytes), decompress with LZMA/xpress
            decompressed = lzma.decompress(data[8:])
            data = decompressed
        except (ImportError, Exception):
            # Try raw string scan on compressed data
            pass

    # Check for SCCA signature at offset 4
    if len(data) >= 8:
        sig = data[4:8]
        if sig == b'SCCA':
            print("[*] Valid Prefetch file detected")

            # Parse header
            try:
                pf_version = struct.unpack_from('<I', data, 0)[0]
                # File size at offset 12
                file_size = struct.unpack_from('<I', data, 12)[0]

                # Executable name: 60 bytes of UTF-16LE at offset 16
                exe_name_raw = data[16:76]
                try:
                    exe_name = exe_name_raw.decode('utf-16-le').rstrip('\x00')
                    print(f"  [*] Executable: {exe_name}")
                except UnicodeDecodeError:
                    exe_name = ""

                # Run count at offset 208 (v26/v30) or offset 128 (v17/v23)
                if pf_version >= 26:
                    run_count = struct.unpack_from('<I', data, 208)[0]
                else:
                    run_count = struct.unpack_from('<I', data, 128)[0] if len(data) > 132 else 0

                print(f"  [*] Run count: {run_count}")

                # Check executable name for flag
                found = _find_flags(exe_name, flag_pattern)
                if found:
                    flags.extend(found)

            except (struct.error, Exception) as exc:
                print(f"  [-] Prefetch parse error: {exc}")

    # Also scan strings (works even if parsing fails)
    # Extract UTF-16LE strings (common in prefetch files)
    try:
        text_utf16 = data.decode('utf-16-le', errors='replace')
        found = _find_flags(text_utf16, flag_pattern)
        if found:
            print(f"  [+] Flag found in prefetch UTF-16 strings")
            flags.extend(found)
    except Exception:
        pass

    # Standard string scan
    flags.extend(_strings_scan(evidence_path, flag_pattern))

    return flags


# ---------------------------------------------------------------------------
# Filesystem Walk with Deep Inspection
# ---------------------------------------------------------------------------

def _deep_file_scan(filepath: str, flag_pattern: re.Pattern) -> list[str]:
    """Deep scan a single file: check for embedded archives, encoded data, etc."""
    flags: list[str] = []

    try:
        with open(filepath, 'rb') as f:
            data = f.read(2 * 1024 * 1024)  # Read up to 2MB
    except (OSError, PermissionError):
        return flags

    # Text scan
    text = data.decode('utf-8', errors='ignore')
    found = _find_flags(text, flag_pattern)
    if found:
        flags.extend(found)

    # Base64 scan
    flags.extend(_base64_scan(text, flag_pattern))

    # Check for ZIP/embedded archives
    zip_sig = b'PK\x03\x04'
    idx = data.find(zip_sig)
    if idx > 0:
        # There's an embedded ZIP
        tmpdir = tempfile.mkdtemp(prefix="kraken_embedded_")
        try:
            import zipfile
            import io
            zf = zipfile.ZipFile(io.BytesIO(data[idx:]))
            zf.extractall(tmpdir)
            for root, _dirs, files in os.walk(tmpdir):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, 'rb') as f:
                            fdata = f.read(1024 * 1024)
                        ftext = fdata.decode('utf-8', errors='ignore')
                        found = _find_flags(ftext, flag_pattern)
                        if found:
                            print(f"  [+] Flag in embedded archive: {fname}")
                            flags.extend(found)
                    except Exception:
                        pass
        except Exception:
            pass
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # Hex-encoded strings (common in forensics challenges)
    for m in re.finditer(r'(?:[0-9a-fA-F]{2}){6,}', text):
        hex_str = m.group(0)
        try:
            decoded = bytes.fromhex(hex_str).decode('utf-8', errors='replace')
            printable = sum(1 for c in decoded if c.isprintable() or c in '\n\r\t')
            if len(decoded) >= 3 and printable > len(decoded) * 0.6:
                found = _find_flags(decoded, flag_pattern)
                if found:
                    flags.extend(found)
        except (ValueError, UnicodeDecodeError):
            pass

    return flags


# ---------------------------------------------------------------------------
# Directory scanning
# ---------------------------------------------------------------------------

def analyze_directory(challenge_dir: str, flag_pattern: re.Pattern) -> list[str]:
    """Scan a challenge directory for evidence files and analyze each one."""
    flags: list[str] = []

    evidence_exts = {
        ".raw", ".vmem", ".dmp", ".mem",
        ".dd", ".img", ".e01", ".iso", ".vmdk", ".qcow2",
        ".reg",
        ".db", ".sqlite", ".sqlite3",
        ".eml", ".mbox", ".msg",
        ".evtx", ".evt",
        ".pf",
    }

    evidence_files = []
    for name in os.listdir(challenge_dir):
        fpath = os.path.join(challenge_dir, name)
        if not os.path.isfile(fpath):
            continue
        ext = os.path.splitext(name)[1].lower()
        if ext in evidence_exts:
            evidence_files.append(fpath)
        elif name.lower() in ("evidence", "memory", "dump", "registry"):
            evidence_files.append(fpath)

    if not evidence_files:
        print(f"[-] No recognized evidence files in {challenge_dir}")
        # Try analyzing all non-text files
        for name in os.listdir(challenge_dir):
            fpath = os.path.join(challenge_dir, name)
            if os.path.isfile(fpath) and not name.lower().endswith((".md", ".txt", ".json", ".yaml", ".yml")):
                evidence_files.append(fpath)

    if not evidence_files:
        print("[-] No files to analyze")
        return flags

    print(f"[*] Found {len(evidence_files)} evidence file(s)")

    for fpath in evidence_files:
        fname = os.path.basename(fpath)
        print(f"\n[*] Analyzing: {fname}")

        etype = _detect_evidence_type(fpath)
        print(f"[*] Detected type: {etype}")

        if etype == "memory":
            found = analyze_memory(fpath, flag_pattern)
        elif etype == "disk":
            found = analyze_disk(fpath, flag_pattern)
        elif etype == "registry":
            found = analyze_registry(fpath, flag_pattern)
        elif etype == "database":
            found = analyze_database(fpath, flag_pattern)
        elif etype == "email":
            found = analyze_email(fpath, flag_pattern)
        elif etype == "evtx":
            found = analyze_evtx(fpath, flag_pattern)
        elif etype == "prefetch":
            found = analyze_prefetch(fpath, flag_pattern)
        else:
            print("[*] Unknown type, trying deep file scan + raw string scan")
            found = _deep_file_scan(fpath, flag_pattern)
            if not found:
                found = _strings_scan(fpath, flag_pattern)

        flags.extend(found)

    # Check for NTFS ADS on the entire directory
    print("\n[*] Checking for NTFS Alternate Data Streams...")
    ads_flags = scan_ads(challenge_dir, flag_pattern)
    flags.extend(ads_flags)

    return flags


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Kraken Advanced Forensics -- memory, disk, registry, browser, email analysis"
    )
    parser.add_argument(
        "--evidence",
        help="Evidence file path (single file mode)",
    )
    parser.add_argument(
        "--dir",
        help="Challenge directory to scan for evidence files",
    )
    parser.add_argument(
        "--prefix",
        default="flag",
        help="Flag prefix (default: flag)",
    )
    parser.add_argument(
        "--type",
        choices=["memory", "disk", "registry", "database", "email", "evtx", "prefetch"],
        help="Force evidence type (auto-detected if not specified)",
    )
    parser.add_argument(
        "--flag-format",
        default="",
        help="Custom flag format regex",
    )
    args = parser.parse_args()

    if not args.evidence and not args.dir:
        # Check positional argument
        if len(sys.argv) >= 2 and not sys.argv[1].startswith("--"):
            target = sys.argv[1]
            if os.path.isdir(target):
                args.dir = target
            elif os.path.isfile(target):
                args.evidence = target
            else:
                print(f"[-] Not found: {target}", file=sys.stderr)
                sys.exit(1)
        else:
            print("[-] Provide --evidence FILE or --dir DIRECTORY", file=sys.stderr)
            sys.exit(1)

    # Build flag pattern
    if args.flag_format:
        try:
            pattern = re.compile(args.flag_format)
        except re.error:
            pattern = _flag_re(args.prefix)
    else:
        pattern = _flag_re(args.prefix)

    all_flags: list[str] = []

    if args.evidence:
        if not os.path.isfile(args.evidence):
            print(f"[-] Not a file: {args.evidence}", file=sys.stderr)
            sys.exit(1)

        etype = args.type or _detect_evidence_type(args.evidence)
        print(f"[*] Evidence: {args.evidence}")
        print(f"[*] Type: {etype}")

        if etype == "memory":
            all_flags = analyze_memory(args.evidence, pattern)
        elif etype == "disk":
            all_flags = analyze_disk(args.evidence, pattern)
        elif etype == "registry":
            all_flags = analyze_registry(args.evidence, pattern)
        elif etype == "database":
            all_flags = analyze_database(args.evidence, pattern)
        elif etype == "email":
            all_flags = analyze_email(args.evidence, pattern)
        elif etype == "evtx":
            all_flags = analyze_evtx(args.evidence, pattern)
        elif etype == "prefetch":
            all_flags = analyze_prefetch(args.evidence, pattern)
        else:
            print("[*] Unknown type, trying deep file scan + string scan")
            all_flags = _deep_file_scan(args.evidence, pattern)
            if not all_flags:
                all_flags = _strings_scan(args.evidence, pattern)

    elif args.dir:
        if not os.path.isdir(args.dir):
            print(f"[-] Not a directory: {args.dir}", file=sys.stderr)
            sys.exit(1)
        all_flags = analyze_directory(args.dir, pattern)

    # Deduplicate
    seen = set()
    unique = []
    for f in all_flags:
        if f not in seen:
            seen.add(f)
            unique.append(f)

    if unique:
        print(f"\n[+] Found {len(unique)} flag(s)")
        for f in unique:
            print(f"  [+] {f}")
        # Prefer known CTF prefixes
        _KNOWN_PREFIXES = (
            "flag{", "FLAG{", "ctf{", "CTF{", "picoCTF{", "HTB{",
            "csawctf{", "vere{", "VERE{",
        )
        prefixed = [f for f in unique if any(f.startswith(p) for p in _KNOWN_PREFIXES)]
        best = max(prefixed, key=len) if prefixed else max(unique, key=len)
        print(f"\nEXTRACTED FLAG: {best}")
    else:
        print("\n[-] No flags found")
        sys.exit(1)


if __name__ == "__main__":
    main()
