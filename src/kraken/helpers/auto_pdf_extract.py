#!/usr/bin/env python3
"""auto_pdf_extract -- Extract text from PDFs and scan for flag patterns.

Uses pdftotext (poppler-utils) for extraction.
Outputs EXTRACTED FLAG: <flag> on success.
"""
import os
import re
import subprocess
import sys
from pathlib import Path


def extract_text(pdf_path: str) -> str:
    """Extract text from a PDF using pdftotext."""
    try:
        proc = subprocess.run(
            ["pdftotext", pdf_path, "-"],
            capture_output=True, timeout=30,
        )
        if proc.returncode == 0:
            return proc.stdout.decode(errors="replace")
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return ""


def main():
    if len(sys.argv) < 2:
        print("Usage: auto_pdf_extract.py <file_or_dir> [--flag-format FORMAT]", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    flag_format = ""
    if "--flag-format" in sys.argv:
        idx = sys.argv.index("--flag-format")
        if idx + 1 < len(sys.argv):
            flag_format = sys.argv[idx + 1]

    # Collect PDF files
    pdfs: list[str] = []
    if os.path.isdir(target):
        for f in Path(target).rglob("*.pdf"):
            pdfs.append(str(f))
    elif os.path.isfile(target) and target.lower().endswith(".pdf"):
        pdfs.append(target)

    if not pdfs:
        print("No PDFs found", file=sys.stderr)
        sys.exit(1)

    all_text: list[str] = []
    for pdf in pdfs:
        text = extract_text(pdf)
        if text:
            all_text.append(text)

    combined = "\n".join(all_text)
    if not combined.strip():
        print("No text extracted from PDFs", file=sys.stderr)
        sys.exit(1)

    print(f"=== Extracted {len(combined)} chars from {len(pdfs)} PDF(s) ===")
    print(combined[:2000])

    # Scan for flag patterns
    if flag_format:
        try:
            flags = re.findall(flag_format, combined)
        except re.error:
            flags = []
    else:
        flags = []

    # Also try common patterns
    common_patterns = [
        r"[A-Za-z0-9_]{1,20}\{[^}]+\}",
        r"flag\{[^}]+\}",
        r"FLAG\{[^}]+\}",
        r"HTB\{[^}]+\}",
        r"picoCTF\{[^}]+\}",
    ]
    for pat in common_patterns:
        flags.extend(re.findall(pat, combined))

    # Deduplicate
    seen: set[str] = set()
    unique_flags: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            unique_flags.append(f)

    if unique_flags:
        best = max(unique_flags, key=len)
        print(f"\nEXTRACTED FLAG: {best}")
    else:
        print("\nNo flag patterns found in PDF text", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
