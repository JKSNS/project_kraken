#!/usr/bin/env python3
"""auto_file_carve -- Carve embedded files and extract hidden flags.

Applies binwalk extraction, EOF-appended-data scanning, strings, and
base64 decoding to all files in a challenge directory.
Outputs EXTRACTED FLAG: <flag> on success.
"""
import base64, os, re, shutil, subprocess, sys, tempfile

EOF_MARKERS = [b"IEND\xaeB\x60\x82", b"\xff\xd9", b"PK\x05\x06"]
DEFAULT_FLAG_RE = re.compile(r"[a-zA-Z_]{2,}\{[^}]{3,}\}")


def _flag_re(fmt):
    if fmt:
        try: return re.compile(fmt)
        except re.error: pass
    return DEFAULT_FLAG_RE


def _find(text, pat):
    return pat.findall(text)


def _binwalk_carve(fpath):
    d = tempfile.mkdtemp(prefix="carve_")
    try:
        subprocess.run(["binwalk", "-e", "--directory", d, fpath],
                       capture_output=True, timeout=30)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        shutil.rmtree(d, ignore_errors=True); return None
    try:
        if any(os.scandir(d)): return d
    except OSError: pass
    shutil.rmtree(d, ignore_errors=True); return None


def _scan_extracted(d, pat):
    flags = []
    for root, _, files in os.walk(d):
        for n in files:
            try: flags.extend(_find(open(os.path.join(root, n), errors="replace").read(), pat))
            except OSError: pass
    return flags


def _check_appended(fpath, pat):
    flags = []
    try: raw = open(fpath, "rb").read()
    except OSError: return flags
    for marker in EOF_MARKERS:
        idx = raw.find(marker)
        if idx < 0: continue
        after = raw[idx + len(marker):]
        if len(after) < 4: continue
        text = after.decode("utf-8", errors="replace")
        if sum(c.isprintable() or c in "\n\r\t" for c in text) > len(text) * 0.5:
            flags.extend(_find(text, pat))
    return flags


def _strings_scan(fpath, pat):
    try:
        p = subprocess.run(["strings", fpath], capture_output=True, text=True, timeout=30)
        return _find(p.stdout, pat)
    except (subprocess.TimeoutExpired, FileNotFoundError): return []


def _extract_7z(fpath):
    """Extract a .7z archive to a temp directory, return the dir path or None."""
    d = tempfile.mkdtemp(prefix="carve_7z_")
    try:
        subprocess.run(["7z", "x", fpath, f"-o{d}", "-y"],
                       capture_output=True, timeout=60)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        shutil.rmtree(d, ignore_errors=True)
        return None
    try:
        if any(os.scandir(d)):
            return d
    except OSError:
        pass
    shutil.rmtree(d, ignore_errors=True)
    return None


def _disk_image_scan(fpath, pat):
    """Run ``strings`` on disk images and other large binary files.

    Scans line-by-line to avoid multi-line false positives from binary data
    (e.g. ``Xx{`` followed by pages of Latin text then ``}``).
    """
    try:
        p = subprocess.run(["strings", fpath], capture_output=True, text=True, timeout=60)
        flags = []
        for line in p.stdout.splitlines():
            flags.extend(_find(line, pat))
        return flags
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []


def _base64_scan(fpath, pat):
    flags = []
    try: text = open(fpath, errors="replace").read()
    except OSError: return flags
    for m in re.finditer(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            dec = base64.b64decode(m.group(0)).decode("utf-8", errors="replace")
            flags.extend(_find(dec, pat))
        except Exception: pass
    return flags


def main():
    if len(sys.argv) < 2:
        print("Usage: auto_file_carve.py <challenge_dir> [--flag-format FMT]",
              file=sys.stderr); sys.exit(1)

    cdir, fmt = sys.argv[1], ""
    if "--flag-format" in sys.argv:
        i = sys.argv.index("--flag-format")
        if i + 1 < len(sys.argv): fmt = sys.argv[i + 1]

    pat, all_flags, tmps = _flag_re(fmt), [], []
    if not os.path.isdir(cdir):
        print(f"Not a directory: {cdir}", file=sys.stderr); sys.exit(1)

    _SKIP_NAMES = {"readme", "readme.md", "readme.txt", "description",
                   "description.md", "description.txt", "flag.txt",
                   "challenge.json", "challenge.yaml", "challenge.yml",
                   "makefile", "dockerfile", "license", "license.txt"}
    files = [os.path.join(cdir, f) for f in os.listdir(cdir)
             if not f.startswith(".") and os.path.isfile(os.path.join(cdir, f))
             and f.lower() not in _SKIP_NAMES]

    # Extract .7z archives first so their contents can be scanned
    archive_dirs: list[str] = []
    for fp in files[:]:
        if fp.lower().endswith(".7z"):
            edir = _extract_7z(fp)
            if edir:
                archive_dirs.append(edir)
                tmps.append(edir)
                # Add extracted files to scan list
                for root, _, fnames in os.walk(edir):
                    for fn in fnames:
                        efp = os.path.join(root, fn)
                        if fn.lower() not in _SKIP_NAMES:
                            files.append(efp)

    print(f"[*] Scanning {len(files)} file(s) in {cdir}")

    _DISK_IMAGE_EXTS = {".img", ".raw", ".dd", ".bin", ".iso", ".vmdk", ".qcow2"}

    for fp in files:
        fname = os.path.basename(fp)
        print(f"[*] Processing: {fname}")

        fext = os.path.splitext(fname)[1].lower()
        fsize = 0
        try:
            fsize = os.path.getsize(fp)
        except OSError:
            pass

        # Skip heavy scans on archive files (they're handled by extraction above)
        _ARCHIVE_EXTS = {".7z", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz"}
        if fext in _ARCHIVE_EXTS:
            continue

        # 0. Disk images / large binaries: strings-only scan (skip other methods)
        is_disk_image = fext in _DISK_IMAGE_EXTS or (fsize > 1_000_000 and fext not in _ARCHIVE_EXTS)
        if is_disk_image:
            print(f"  [*] disk image scan ({fsize} bytes)")
            r = _disk_image_scan(fp, pat)
            if r:
                print(f"  [+] disk image: {r}")
                all_flags.extend(r)
            continue  # skip binwalk/appended/base64 on large disk images

        # 1. binwalk carve
        edir = _binwalk_carve(fp)
        if edir:
            tmps.append(edir)
            r = _scan_extracted(edir, pat)
            if r: print(f"  [+] binwalk: {r}"); all_flags.extend(r)
        # 2. Appended data after EOF markers
        r = _check_appended(fp, pat)
        if r: print(f"  [+] appended: {r}"); all_flags.extend(r)
        # 3. strings scan
        r = _strings_scan(fp, pat)
        if r: print(f"  [+] strings: {r}"); all_flags.extend(r)
        # 4. base64 decode scan
        r = _base64_scan(fp, pat)
        if r: print(f"  [+] base64: {r}"); all_flags.extend(r)

    for t in tmps: shutil.rmtree(t, ignore_errors=True)

    seen = set()
    unique = [f for f in all_flags if f not in seen and not seen.add(f)]
    if unique:
        # Prefer candidates with known CTF flag prefixes over arbitrary XX{...}
        _KNOWN_PREFIXES = ("flag{", "FLAG{", "ctf{", "CTF{", "picoCTF{", "HTB{",
                           "csawctf{", "vere{", "VERE{", "hack{", "HACK{",
                           "key{", "KEY{", "SEKAI{")
        prefixed = [f for f in unique if any(f.startswith(p) for p in _KNOWN_PREFIXES)]
        # Filter out non-printable or pipe-char-heavy candidates (ICC profile data)
        clean = [f for f in unique if f.isprintable() and '|' not in f]
        if prefixed:
            best = max(prefixed, key=len)
        elif clean:
            best = max(clean, key=len)
        else:
            best = max(unique, key=len)
        print(f"\n[+] Found {len(unique)} flag(s)")
        print(f"EXTRACTED FLAG: {best}")
    else:
        print("\n[-] No flags found"); sys.exit(1)


if __name__ == "__main__":
    main()
