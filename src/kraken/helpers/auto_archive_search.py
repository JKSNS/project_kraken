#!/usr/bin/env python3
"""Search archive files (.tar, .tar.gz, .zip, .7z) for CTF flags.

Handles Docker image tarballs: reads layer configs, Dockerfiles,
and decodes base64 strings found in image history.
Also handles 7z archives via the ``7z`` command.
"""
import base64
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

FLAG_PATTERNS = [
    re.compile(r'[a-zA-Z]+\{[^\}]{3,200}\}'),
    re.compile(r'[Ff][Ll][Aa][Gg]\{[^\}]+\}'),
]

BASE64_RE = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')


def search_text_for_flags(text: str) -> list[str]:
    flags = []
    for pat in FLAG_PATTERNS:
        for m in pat.finditer(text):
            candidate = m.group(0)
            if len(candidate) > 6:
                flags.append(candidate)
    return flags


def try_decode_base64(text: str) -> list[str]:
    """Find and decode base64 strings, return any that contain flag patterns."""
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


def search_tar(path: str) -> list[str]:
    """Search a tar archive for flags."""
    found = []
    try:
        # Try gzip first, then plain tar
        try:
            tf = tarfile.open(path, 'r:gz')
        except Exception:
            tf = tarfile.open(path, 'r:')
    except Exception as e:
        print(f"Cannot open tar: {e}", file=sys.stderr)
        return found

    with tf:
        for member in tf.getmembers():
            # Skip very large files
            if member.size > 500_000 or member.size == 0:
                continue
            if member.isdir():
                continue

            name_lower = member.name.lower()

            try:
                f = tf.extractfile(member)
                if not f:
                    continue
                data = f.read()
            except Exception:
                continue

            # JSON files (Docker image configs)
            if name_lower.endswith('.json'):
                try:
                    jdata = json.loads(data)
                    text = json.dumps(jdata)
                    found.extend(search_text_for_flags(text))
                    found.extend(try_decode_base64(text))

                    # Docker image history
                    if isinstance(jdata, dict) and 'history' in jdata:
                        for h in jdata['history']:
                            cmd = h.get('created_by', '')
                            found.extend(search_text_for_flags(cmd))
                            found.extend(try_decode_base64(cmd))
                except (json.JSONDecodeError, AttributeError):
                    pass

            # Text files, Dockerfiles, scripts
            if (name_lower.endswith(('.txt', '.md', '.sh', '.py', '.yml', '.yaml', '.env', '.cfg', '.conf'))
                    or 'dockerfile' in name_lower
                    or 'flag' in name_lower):
                try:
                    text = data.decode(errors='replace')
                    found.extend(search_text_for_flags(text))
                    found.extend(try_decode_base64(text))
                except Exception:
                    pass

            # Nested tar files (Docker layers)
            if name_lower.endswith(('.tar', 'layer.tar')):
                import io
                try:
                    inner_tf = tarfile.open(fileobj=io.BytesIO(data), mode='r:')
                    with inner_tf:
                        for inner_m in inner_tf.getmembers():
                            if inner_m.size > 100_000 or inner_m.size == 0:
                                continue
                            if inner_m.isdir():
                                continue
                            inner_name = inner_m.name.lower()
                            if ('flag' in inner_name or 'docker' in inner_name
                                    or inner_name.endswith(('.txt', '.env', '.sh', '.py', '.conf'))):
                                try:
                                    inner_f = inner_tf.extractfile(inner_m)
                                    if inner_f:
                                        inner_text = inner_f.read().decode(errors='replace')
                                        found.extend(search_text_for_flags(inner_text))
                                        found.extend(try_decode_base64(inner_text))
                                except Exception:
                                    pass
                except Exception:
                    pass

    return found


def search_zip(path: str) -> list[str]:
    """Search a zip archive for flags."""
    found = []
    try:
        with zipfile.ZipFile(path, 'r') as zf:
            for name in zf.namelist():
                info = zf.getinfo(name)
                if info.file_size > 500_000 or info.file_size == 0:
                    continue
                name_lower = name.lower()
                if (name_lower.endswith(('.txt', '.md', '.sh', '.py', '.json', '.yml', '.env', '.cfg', '.conf'))
                        or 'flag' in name_lower
                        or 'docker' in name_lower):
                    try:
                        text = zf.read(name).decode(errors='replace')
                        found.extend(search_text_for_flags(text))
                        found.extend(try_decode_base64(text))
                    except Exception:
                        pass
    except Exception as e:
        print(f"Cannot open zip: {e}", file=sys.stderr)
    return found


def _strings_scan(fpath: str) -> list[str]:
    """Run ``strings`` on a file and search output for flags.

    Scans line-by-line to avoid multi-line false positives from binary data.
    """
    try:
        proc = subprocess.run(
            ["strings", fpath], capture_output=True, text=True, timeout=30,
        )
        flags: list[str] = []
        for line in proc.stdout.splitlines():
            flags.extend(search_text_for_flags(line))
        return flags
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def search_7z(path: str) -> list[str]:
    """Extract a .7z archive to a temp dir and search contents for flags.

    For large files (e.g. disk images), runs ``strings`` to find flag
    patterns without loading the full file into memory.
    """
    found: list[str] = []
    tmpdir = tempfile.mkdtemp(prefix="archive_7z_")
    try:
        proc = subprocess.run(
            ["7z", "x", path, f"-o{tmpdir}", "-y"],
            capture_output=True, timeout=60,
        )
        if proc.returncode != 0:
            print(f"7z extraction failed: {proc.stderr.decode(errors='replace')[:200]}",
                  file=sys.stderr)
            return found

        # Walk extracted contents
        for root, _dirs, files in os.walk(tmpdir):
            for name in files:
                fpath = os.path.join(root, name)
                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    continue

                name_lower = name.lower()

                # Small text-like files: read and search directly
                if fsize <= 500_000 and fsize > 0:
                    if (name_lower.endswith(
                        ('.txt', '.md', '.sh', '.py', '.json', '.yml',
                         '.env', '.cfg', '.conf'))
                            or 'flag' in name_lower
                            or 'docker' in name_lower):
                        try:
                            text = open(fpath, errors='replace').read()
                            found.extend(search_text_for_flags(text))
                            found.extend(try_decode_base64(text))
                        except OSError:
                            pass

                # Disk images and large binary files: use strings scan
                if (name_lower.endswith(('.img', '.raw', '.dd', '.bin', '.iso',
                                         '.vmdk', '.qcow2'))
                        or fsize > 500_000):
                    print(f"  [*] strings scan on {name} ({fsize} bytes)")
                    r = _strings_scan(fpath)
                    if r:
                        print(f"  [+] found {len(r)} flag(s) in {name}")
                        found.extend(r)

                # Nested archives: recurse
                if name_lower.endswith(('.tar', '.tar.gz', '.tgz')):
                    found.extend(search_tar(fpath))
                elif name_lower.endswith('.zip'):
                    found.extend(search_zip(fpath))
                elif name_lower.endswith('.7z'):
                    found.extend(search_7z(fpath))

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

    return found


def main():
    if len(sys.argv) < 2:
        print("Usage: auto_archive_search.py <archive_path>", file=sys.stderr)
        sys.exit(1)

    path = sys.argv[1]
    if not Path(path).exists():
        print(f"File not found: {path}", file=sys.stderr)
        sys.exit(1)

    name_lower = path.lower()
    if name_lower.endswith('.7z'):
        flags = search_7z(path)
    elif name_lower.endswith(('.tar', '.tar.gz', '.tgz')):
        flags = search_tar(path)
    elif name_lower.endswith('.zip'):
        flags = search_zip(path)
    else:
        # Try tar first, then zip
        flags = search_tar(path)
        if not flags:
            flags = search_zip(path)

    # Deduplicate and print
    seen = set()
    for flag in flags:
        if flag not in seen:
            seen.add(flag)
            print(f"EXTRACTED FLAG: {flag}")

    if not seen:
        print("No flags found in archive")
        sys.exit(1)


if __name__ == '__main__':
    main()
