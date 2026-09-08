#!/usr/bin/env python3
"""auto_sbom -- extract binary SBOM + correlate against NVD CVE feed (E.4).

Most IoT bugs are KNOWN n-day bugs in outdated bundled components.
This helper:
  1. Extracts version-string fingerprints from a binary (libssl, libcurl,
     dropbear, busybox, openssh, etc.)
  2. Looks them up in a local NVD snapshot (or the live NVD API)
  3. Reports unpatched CVEs

Output: SBOM_REPORT.md alongside the binary's dossier.

Per master TODO E.4 acceptance: dossier of dropbear surfaces "uses
libssl X.Y → CVE-2023-XXXX (unpatched in this firmware)".
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.request
from pathlib import Path

# Common library version-string regex patterns
COMPONENT_PATTERNS = [
    ("openssl", re.compile(rb"OpenSSL[\s/]+(\d+\.\d+\.\d+[a-z]?)")),
    ("libssl", re.compile(rb"OpenSSL[\s/]+(\d+\.\d+\.\d+[a-z]?)")),
    ("dropbear", re.compile(rb"[Dd]ropbear[\s/_v]+(\d+\.\d+)")),
    ("busybox", re.compile(rb"BusyBox[\s/v]+(\d+\.\d+\.\d+)")),
    ("openssh", re.compile(rb"OpenSSH[_\s]+(\d+\.\d+(?:\.\d+)?)")),
    ("libcurl", re.compile(rb"libcurl[\s/]+(\d+\.\d+\.\d+)")),
    ("zlib", re.compile(rb"zlib\s+(\d+\.\d+(?:\.\d+)?)")),
    ("libpng", re.compile(rb"libpng\s+(?:version\s+)?(\d+\.\d+\.\d+)")),
    ("nginx", re.compile(rb"nginx/(\d+\.\d+\.\d+)")),
    ("apache", re.compile(rb"Apache(?:/| )(\d+\.\d+\.\d+)")),
    ("uhttpd", re.compile(rb"uhttpd[/\s]+(\d+\.\d+(?:\.\d+)?)")),
    ("hostapd", re.compile(rb"hostapd v?(\d+\.\d+)")),
    ("samba", re.compile(rb"Samba.+?(\d+\.\d+\.\d+)")),
    ("dnsmasq", re.compile(rb"dnsmasq[\s/-]v?(\d+\.\d+(?:\.\d+)?)")),
    ("wpa_supplicant", re.compile(rb"wpa_supplicant v(\d+\.\d+)")),
    ("expat", re.compile(rb"expat_(\d+\.\d+\.\d+)")),
]


def extract_components(binary: Path) -> list:
    """Run strings on the binary; match against component patterns."""
    try:
        with binary.open("rb") as f:
            data = f.read()
    except OSError:
        return []
    found = []
    for name, pattern in COMPONENT_PATTERNS:
        for m in pattern.finditer(data):
            version = m.group(1).decode("latin-1", errors="replace")
            entry = {"component": name, "version": version}
            if entry not in found:
                found.append(entry)
    return found


def query_nvd_for_component(component: str, version: str, *, online: bool = False) -> list:
    """Look up CVEs for component@version. Online: query NVD JSON API."""
    if not online:
        return []  # offline mode -- operator pulls a local NVD snapshot
    # NVD API v2.0
    url = (
        "https://services.nvd.nist.gov/rest/json/cves/2.0?"
        "keywordSearch=" + component + "+" + version + "&resultsPerPage=20"
    )
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "KrakenSBOM/1.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read())
    except Exception:
        return []
    out = []
    for v in (data.get("vulnerabilities") or [])[:20]:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        descs = cve.get("descriptions", [])
        en_desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
        cvss_metrics = cve.get("metrics", {}).get("cvssMetricV31", [])
        cvss = cvss_metrics[0].get("cvssData", {}).get("baseScore") if cvss_metrics else None
        out.append(
            {
                "cve_id": cve_id,
                "cvss": cvss,
                "description": en_desc[:300],
            }
        )
    return out


def sbom_report(binary: Path, *, online: bool = False) -> dict:
    components = extract_components(binary)
    findings = []
    for c in components:
        cves = query_nvd_for_component(c["component"], c["version"], online=online)
        if cves:
            findings.append(
                {
                    "component": c["component"],
                    "version": c["version"],
                    "candidate_cves": cves,
                    "cve_count": len(cves),
                }
            )
        else:
            findings.append(
                {
                    "component": c["component"],
                    "version": c["version"],
                    "candidate_cves": [],
                    "note": "online=False or no NVD hits",
                }
            )
    return {
        "binary": str(binary),
        "components_detected": len(components),
        "components_with_cves": sum(1 for f in findings if f.get("candidate_cves")),
        "findings": findings,
    }


def render_md(report: dict) -> str:
    lines = [
        "# SBOM + NVD correlation report",
        "",
        f"_binary: `{report['binary']}`_",
        "",
        f"- components detected: **{report['components_detected']}**",
        f"- components with NVD CVE hits: **{report['components_with_cves']}**",
        "",
        "## Per-component",
        "",
    ]
    for f in report.get("findings") or []:
        lines.append(f"### {f['component']} {f['version']}")
        lines.append("")
        if f.get("candidate_cves"):
            lines.append("| CVE | CVSS | description |")
            lines.append("|---|---:|---|")
            for cve in f["candidate_cves"]:
                lines.append(f"| {cve['cve_id']} | {cve.get('cvss') or '--'} | {(cve.get('description') or '')[:120]} |")
        else:
            lines.append("- " + (f.get("note") or "no CVEs"))
        lines.append("")
    return "\n".join(lines)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="auto_sbom")
    p.add_argument("binary")
    p.add_argument("--online", action="store_true", help="Query NVD live API (rate-limited; needs network)")
    p.add_argument("--out", default=None)
    args = p.parse_args(argv)
    report = sbom_report(Path(args.binary), online=args.online)
    md = render_md(report)
    if args.out:
        Path(args.out).write_text(md)
        print("wrote " + args.out)
    print(md)
    print()
    print(json.dumps({k: v for k, v in report.items() if k != "findings"}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
