"""Solve engine node -- generates and executes solve scripts.

Uses ``direct_generate()`` (bypassing langchain-ollama) for reliability.

Enhancements:
- Call-graph-aware function budget (#5)
- Strategy-based timeout differentiation (#9)
- Failure diagnosis + script findings integration (#1, #2)
- Secondary types context (#3)
- Inner debugging loop: generate → execute → fix → re-execute (#agentic)
- Auto-pip-install for missing modules (#agentic)
- Scripting-language-aware prompting (#agentic)
"""
from __future__ import annotations

import ast
import asyncio
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from kraken.state import KrakenState
from kraken.models import direct_generate
from kraken.config import ModelConfig, EvolutionConfig
from kraken.storage.artifact_store import get_artifact
from kraken.tools.script_executor import execute_script
from kraken.logging.structured import get_logger
from kraken.storage.ledger import append_ledger_entry, read_ledger_tail, read_ledger_all

log = get_logger(__name__)

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "prompts"

# ── Strategy-based timeout mapping (#9) ──────────────────────────────

_STRATEGY_TIMEOUTS: dict[str, int] = {
    "constraint": 300,   # angr is slow
    "crypto": 60,        # brute-force on larger inputs needs time
    "dotnet": 120,       # mono/dotnet execution + decompilation
    "dynamic": 60,       # ptrace/instrumentation
    "keygen": 30,        # key reversal is fast
    "pwn": 120,          # exploit + interaction
    "fuzzing": 300,      # fuzzing harnesses need time
    "web": 60,           # web exploit scripts
    "firmware": 120,     # firmware extraction + analysis
}
_DEFAULT_TIMEOUT = 120

# ── False-positive detection for inner loop ────────────────────────
_FAILURE_SIGNALS = [
    "no solution", "unsatisfiable", "unsat", "not found", "error:",
    "traceback", "exception", "failed", "timeout", "no flag",
    "no result", "could not", "unable to",
]

async def _codex_fallback_branch(state: KrakenState) -> dict:
    """Hand the challenge to Codex as an independent agentic solver."""
    from kraken.execution.racing import codex_fallback

    attempt_num = len(state.get("solve_scripts", [])) + 1
    log.info("solve_engine_codex_fallback", attempt_num=attempt_num)

    append_ledger_entry(
        state.get("solve_ledger_path", ""),
        f"Attempt #{attempt_num}: CODEX FALLBACK -- handing to agentic solver",
    )

    result = await codex_fallback(state)

    if result.error:
        append_ledger_entry(
            state.get("solve_ledger_path", ""),
            f"  Codex fallback error: {result.error}",
        )
        return {
            "solve_scripts": [{"attempt_num": attempt_num, "strategy": "codex_fallback", "exit_code": 1, "stdout": "", "stderr": result.error, "code": ""}],
            "current_attempt": {"code": "", "stdout": "", "stderr": result.error, "exit_code": 1, "attempt_num": attempt_num, "strategy": "codex_fallback"},
            "racing_attempted": True,
            "recent_actions": [{"action": "solve_engine", "reasoning": f"Codex fallback failed: {result.error}", "result_summary": "FAIL: codex fallback error"}],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    append_ledger_entry(
        state.get("solve_ledger_path", ""),
        f"  Codex result: flag={'YES' if result.flag else 'NO'} "
        f"exit={result.exit_code} elapsed={result.elapsed:.1f}s",
    )

    summary = {
        "attempt_num": attempt_num,
        "strategy": "codex_fallback",
        "exit_code": result.exit_code,
        "stdout": result.stdout[:300] if result.stdout else "",
        "stderr": result.stderr[:300] if result.stderr else "",
        "code": "",
    }

    return {
        "solve_scripts": [summary],
        "current_attempt": {
            "code": "", "stdout": result.stdout, "stderr": result.stderr,
            "exit_code": result.exit_code, "attempt_num": attempt_num,
            "strategy": "codex_fallback",
        },
        "racing_attempted": True,
        "recent_actions": [{"action": "solve_engine", "reasoning": f"Codex fallback -- flag: {result.flag}", "result_summary": f"Codex: {'SOLVED' if result.flag else 'no flag'}"}],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }


ANGR_ARG_FLIP_HINT = (
    "Angr failed to find the path. Did you get the Input Mode wrong? If you used STDIN, "
    "try adding '--arg'. If you used '--arg', try removing it. Also double check that your "
    "'--find' string perfectly matches the binary output."
)


def _has_angr_failed_marker(text: str) -> bool:
    return "[-] angr failed" in (text or "").lower()


def _recent_angr_failed(previous_attempts: list[dict]) -> bool:
    for attempt in reversed(previous_attempts[-4:]):
        if _has_angr_failed_marker(str(attempt.get("stdout", ""))) or _has_angr_failed_marker(str(attempt.get("stderr", ""))):
            return True
    return False



def _derive_flat_z3_mode(state: KrakenState, previous_attempts: list[dict]) -> bool:
    """Decide when to force literal flat Z3 mapping for unstable crypto/keygen loops.

    This guardrail targets small-model failure loops where generated scripts keep
    building transformation arrays/lambdas and then crash with IndexError.
    """
    ctype = (state.get("challenge_type") or "").lower()
    if ctype not in {"crypto", "constraint", "keygen", "dynamic"}:
        return False

    diagnosis = (state.get("failure_diagnosis") or "").lower()
    if "index_error" in diagnosis or "index out of range" in diagnosis:
        return True

    recent = previous_attempts[-4:]
    idx_errors = 0
    for att in recent:
        stderr = str(att.get("stderr", "")).lower()
        if "indexerror" in stderr and "out of range" in stderr:
            idx_errors += 1

    return idx_errors >= 2


def _get_timeout(state: dict) -> int:
    """Determine script execution timeout based on challenge type (#9)."""
    challenge_type = state.get("challenge_type", "")
    strategy = state.get("current_strategy", "").lower()

    # Check challenge type first
    if challenge_type in _STRATEGY_TIMEOUTS:
        return _STRATEGY_TIMEOUTS[challenge_type]

    # Infer from strategy keywords
    if any(kw in strategy for kw in ["angr", "symbolic", "z3", "constraint"]):
        return 300
    if any(kw in strategy for kw in ["xor", "crypto", "cipher", "decode", "base64"]):
        return 30
    if any(kw in strategy for kw in ["brute", "brute-force"]):
        return 180

    return _DEFAULT_TIMEOUT


def _extract_code(content: str) -> str:
    """Extract Python code from LLM response, handling various formats."""
    # Strip <think> blocks that local models sometimes insert
    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

    # Try explicit code blocks first (prefer longest match)
    patterns = [
        r"```[Pp]ython\s*\n(.*?)```",
        r"```py\s*\n(.*?)```",
        r"```\s*\n(.*?)```",
    ]
    best_block = ""
    for pattern in patterns:
        for match in re.finditer(pattern, content, re.DOTALL):
            code = match.group(1).strip()
            if code and len(code) > len(best_block):
                best_block = code
    if best_block:
        return best_block

    lines = content.strip().splitlines()
    if lines and (
        lines[0].startswith("import ")
        or lines[0].startswith("from ")
        or lines[0].startswith("#!/")
        or lines[0].startswith("def ")
    ):
        return content.strip()

    # Find the first code-like line and extract from there
    for i, line in enumerate(lines):
        if line.strip().startswith(("import ", "from ", "def ", "class ", "#!/")):
            return "\n".join(lines[i:]).strip()

    return content.strip()


def _is_mostly_prose(content: str) -> bool:
    """Detect if LLM output is mostly prose/explanation rather than code.

    Returns True if the content has very low code density, indicating
    the model rambled instead of writing a script.
    """
    lines = content.strip().splitlines()
    if not lines:
        return True

    code_indicators = (
        "import ", "from ", "def ", "class ", "if ", "for ", "while ",
        "return ", "print(", "    ", "\t", "#!", "try:", "except",
        "with ", "=", "+=", "-=", "open(", "subprocess", "os.",
    )
    code_lines = sum(
        1 for l in lines
        if any(l.strip().startswith(kw) or kw in l for kw in code_indicators)
    )
    ratio = code_lines / max(len(lines), 1)
    # If less than 20% of lines look like code, it's prose
    return ratio < 0.2 and len(lines) > 5


def _repair_truncated_code(src: str) -> str:
    """Best-effort recovery for length-truncated model output.

    Some local models stop mid-block when hitting token limits, producing
    syntax errors like "'(' was never closed". This helper first tries
    delimiter balancing, then trims trailing lines until parse succeeds.
    """
    lines = src.splitlines()
    if len(lines) < 3:
        return src

    # 1) Try line-local balancing for unclosed delimiters.
    fixed_lines: list[str] = []
    for ln in lines:
        delta_p = ln.count("(") - ln.count(")")
        delta_b = ln.count("[") - ln.count("]")
        delta_c = ln.count("{") - ln.count("}")
        if delta_p > 0:
            ln += ")" * delta_p
        if delta_b > 0:
            ln += "]" * delta_b
        if delta_c > 0:
            ln += "}" * delta_c
        fixed_lines.append(ln)
    balanced = "\n".join(fixed_lines).rstrip() + "\n"
    try:
        ast.parse(balanced)
        return balanced
    except SyntaxError:
        pass

    # 2) Fallback: trim tail until a parseable prefix remains.
    for i in range(len(lines), 2, -1):
        candidate = "\n".join(lines[:i]).rstrip() + "\n"
        try:
            ast.parse(candidate)
            return candidate
        except SyntaxError:
            continue
    return src




def _enforce_script_contract(code: str) -> tuple[str, str | None]:
    """Enforce solve-script contract before execution.

    Returns (possibly rewritten_code, error_message).
    """
    max_lines = 260

    def _remove_banned_imports(src: str) -> str:
        out: list[str] = []
        for ln in src.splitlines():
            stripped = ln.strip()
            if stripped.startswith("import requests") or stripped.startswith("from requests"):
                continue
            out.append(ln)
        return "\n".join(out)

    def _ensure_main_wrapper(src: str) -> str:
        try:
            tree = ast.parse(src)
        except SyntaxError:
            return src

        lines = src.splitlines()
        has_main = any(isinstance(n, ast.FunctionDef) and n.name == "main" for n in tree.body)
        has_guard = False
        for n in tree.body:
            if isinstance(n, ast.If) and isinstance(n.test, ast.Compare):
                t = n.test
                if (
                    isinstance(t.left, ast.Name)
                    and t.left.id == "__name__"
                    and len(t.comparators) == 1
                    and isinstance(t.comparators[0], ast.Constant)
                    and t.comparators[0].value == "__main__"
                ):
                    has_guard = True

        if has_main and has_guard:
            return src

        imports_and_defs: list[str] = []
        top_level_exec: list[str] = []

        for n in tree.body:
            segment = ast.get_source_segment(src, n) or ""
            if not segment.strip() and hasattr(n, "lineno"):
                start_i = max(0, n.lineno - 1)
                end_i = max(start_i + 1, getattr(n, "end_lineno", n.lineno))
                segment = "\n".join(lines[start_i:end_i])

            if isinstance(n, (ast.Import, ast.ImportFrom, ast.FunctionDef, ast.ClassDef)):
                imports_and_defs.append(segment)
            elif isinstance(n, ast.Expr) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
                imports_and_defs.append(segment)  # module docstring
            elif isinstance(n, ast.If):
                # Skip existing __main__ guard body; we'll add a deterministic guard.
                continue
            else:
                top_level_exec.append(segment)

        wrapped: list[str] = []
        wrapped.extend([x for x in imports_and_defs if x.strip()])
        wrapped.append("")
        wrapped.append("def main():")
        if top_level_exec:
            for block in top_level_exec:
                for ln in (block or "").splitlines():
                    wrapped.append(f"    {ln}" if ln.strip() else "")
        else:
            wrapped.append("    pass")

        wrapped.append("")
        wrapped.append("if __name__ == '__main__':")
        wrapped.append("    main()")
        return "\n".join(wrapped).strip() + "\n"

    # 1) remove banned imports (network-heavy / non-deterministic)
    code = _remove_banned_imports(code)

    # 2) parse once
    try:
        ast.parse(code)
    except SyntaxError as exc:
        return code, f"SyntaxError before execution: {exc}"

    # 3) ensure wrapper contract (auto-repair instead of hard reject)
    code = _ensure_main_wrapper(code)

    # 4) final parse + requirements
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return code, f"SyntaxError after contract repair: {exc}"

    # line budget (after repair)
    if len(code.splitlines()) > max_lines:
        return code, f"Script exceeds {max_lines}-line contract limit"

    # Auto-repair: force byte-bounded chr() arguments to reduce runtime failures.
    class _ChrByteBounder(ast.NodeTransformer):
        def visit_Call(self, node: ast.Call):
            node = self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id == "chr" and node.args:
                node.args[0] = ast.BinOp(left=node.args[0], op=ast.BitAnd(), right=ast.Constant(value=0xFF))
            return node

    repaired_tree = _ChrByteBounder().visit(tree)
    ast.fix_missing_locations(repaired_tree)
    code = ast.unparse(repaired_tree) + "\n"

    # Re-parse after rewrite
    try:
        tree = ast.parse(code)
    except SyntaxError as exc:
        return code, f"SyntaxError after chr() normalization: {exc}"

    # Ensure main contains a print call; auto-repair with print(flag) when absent.
    main_def = next((n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "main"), None)
    if main_def is None:
        return code, "Script must define main()"

    has_main_print = any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "print"
        for node in ast.walk(main_def)
    )
    if not has_main_print:
        main_def.body.append(
            ast.Expr(
                value=ast.Call(
                    func=ast.Name(id="print", ctx=ast.Load()),
                    args=[ast.Name(id="flag", ctx=ast.Load())],
                    keywords=[],
                )
            )
        )
        ast.fix_missing_locations(tree)
        code = ast.unparse(tree) + "\n"

    return code, None


def _preview_text(text: str, limit: int = 240) -> str:
    compact = " ".join((text or "").split())
    return compact[:limit]


def _build_attempt_ledger(previous_attempts: list[dict]) -> str:
    """Summarize recent failures in compact form for prompt grounding."""
    if not previous_attempts:
        return ""

    recent = previous_attempts[-5:]
    lines: list[str] = []
    for attempt in recent:
        stderr = _preview_text(attempt.get("stderr", ""), 120)
        stdout = _preview_text(attempt.get("stdout", ""), 80)
        lines.append(
            f"- attempt={attempt.get('attempt_num', '?')} exit={attempt.get('exit_code', '?')} "
            f"stderr='{stderr}' stdout='{stdout}'"
        )
    return "\n".join(lines)

def _build_specialist_summary(state: dict) -> str:
    """Build a concise specialist summary from state for the solve engine prompt.

    Aggregates actionable insights from constraint_solver, crypto_decode,
    dynamic_analysis, keygen, and pwn_specialist into a short paragraph.
    """
    parts: list[str] = []

    # Angr/constraint results
    angr = state.get("angr_results", {})
    if angr:
        if angr.get("satisfiable"):
            sol = angr.get("solution_ascii", angr.get("solution", ""))
            parts.append(f"[angr] SATISFIABLE -- solution: {str(sol)[:80]}")
        elif angr.get("crypto_analysis"):
            ca = angr["crypto_analysis"]
            algo = ca.get("algorithm", "unknown")
            approach = ca.get("reverse_approach", "")
            parts.append(f"[crypto] Algorithm: {algo}. Approach: {approach[:120]}")

            concrete = ca.get("concrete_crypto_data", {})
            if concrete.get("dlopen_pattern"):
                parts.append("[crypto] Binary uses dlopen/dlsym -- extract library and call functions via ctypes")
            if concrete.get("encoding_chains"):
                chains = concrete["encoding_chains"][:2]
                for ch in chains:
                    parts.append(f"[crypto] Encoding chain: {' → '.join(ch.get('chain', []))}")
            if concrete.get("crypto_imports"):
                parts.append(f"[crypto] Crypto imports: {', '.join(str(x) for x in concrete['crypto_imports'][:5])}")
            if concrete.get("xor_results"):
                xr = concrete["xor_results"][0]
                parts.append(f"[crypto] XOR key {xr.get('key', '?')} produced: {xr.get('preview', '')[:60]}")

        # Pwn analysis (#11)
        elif angr.get("pwn_analysis"):
            pa = angr["pwn_analysis"]
            vuln = pa.get("vulnerability", "unknown")
            strategy = pa.get("exploit_strategy", "")
            parts.append(f"[pwn] Vulnerability: {vuln}. Strategy: {strategy[:120]}")
            if pa.get("offset"):
                parts.append(f"[pwn] Buffer offset: {pa['offset']}")
            vi = pa.get("vuln_indicators", {})
            for hint in vi.get("gadget_hints", [])[:3]:
                parts.append(f"[pwn] {hint}")

    # Dynamic traces
    traces = state.get("dynamic_traces", [])
    if traces:
        for t in traces:
            ttype = t.get("type", "")
            if ttype == "anti_debug_patch":
                parts.append(f"[dynamic] Anti-debug patched ({t.get('patches_applied', 0)} patches) → {t.get('patched', '')}")
            elif ttype == "multi_input_trace":
                num = t.get("num_inputs", 0)
                parts.append(f"[dynamic] Tested {num} inputs via differential analysis")
            elif ttype == "angr_symbolic_trace" and t.get("data", {}).get("satisfiable"):
                parts.append("[dynamic] angr found a satisfying input during dynamic analysis")
            elif ttype == "encrypted_data_extraction":
                sects = t.get("custom_sections", [])
                if sects:
                    parts.append(f"[dynamic] Extracted encrypted sections: {', '.join(sects)}")

    # Fuzzing analysis
    fuzz = angr.get("fuzz_analysis", {}) if angr else {}
    if fuzz:
        targets = fuzz.get("top_targets", [])
        if targets:
            parts.append(f"[fuzzing] Top targets: {', '.join(t.get('function', '') for t in targets[:3])}")
        if fuzz.get("harness_strategy"):
            parts.append(f"[fuzzing] Harness: {fuzz['harness_strategy'][:100]}")

    # Web analysis
    web = angr.get("web_analysis", {}) if angr else {}
    if web:
        vulns = web.get("vulnerability_indicators", {})
        for vuln_type, indicators in vulns.items():
            if indicators:
                parts.append(f"[web] {vuln_type}: {', '.join(str(i) for i in indicators[:3])}")
        if web.get("exploit_strategy"):
            parts.append(f"[web] Strategy: {web['exploit_strategy'][:100]}")

    # Firmware analysis
    fw = angr.get("firmware_analysis", {}) if angr else {}
    if fw:
        if fw.get("firmware_type"):
            parts.append(f"[firmware] Type: {fw['firmware_type']}")
        if fw.get("credentials_found"):
            parts.append(f"[firmware] Creds: {fw['credentials_found'][:80]}")
        if fw.get("re_approach"):
            parts.append(f"[firmware] Approach: {fw['re_approach'][:100]}")

    # .NET analysis
    dn = angr.get("dotnet_analysis", {}) if angr else {}
    if dn:
        runtimes = dn.get("available_runtimes", [])
        decompilers = dn.get("available_decompilers", [])
        if runtimes:
            parts.append(f"[dotnet] Runtimes available: {', '.join(runtimes)} -- use subprocess(['{runtimes[0]}', binary_path], input=b'...')")
        if decompilers:
            parts.append(f"[dotnet] Decompilers: {', '.join(decompilers)}")
            if "ilspycmd" in decompilers:
                parts.append("[dotnet] Get C# source: subprocess(['ilspycmd', binary_path])")
            if "monodis" in decompilers:
                parts.append("[dotnet] Get CIL disasm: subprocess(['monodis', '--output=/dev/stdout', binary_path])")
        if not runtimes and not decompilers:
            parts.append("[dotnet] No runtime/decompiler available -- use __pe_metadata__ section for PE structure")
        ro = dn.get("runtime_output", {})
        if ro and ro.get("stdout"):
            parts.append(f"[dotnet] Quick run stdout: {ro['stdout'][:150]}")

    # Strategy hypothesis (from specialist)
    hyp = state.get("strategy_hypothesis", "")
    if hyp and not any(hyp[:30] in p for p in parts):
        parts.append(f"[strategy] {hyp[:150]}")

    return "\n".join(parts) if parts else ""


# ── Category-specific system prompt guidance (Change 3) ───────────
CATEGORY_PROMPTS = {
    "crypto": (
        "You are solving a CRYPTOGRAPHY challenge. Common patterns: "
        "Look for XOR with known plaintext, RSA with small e/d, AES with ECB/CBC mode issues. "
        "Check if PRNG is predictable (MT19937 with known outputs, LCG). "
        "Try frequency analysis for substitution ciphers. "
        "If RSA: check if n is factorable, e is small, or d can be recovered via Wiener/Boneh-Durfee. "
        "If you see base64/hex encoded data, decode it first before analyzing."
    ),
    "constraint": (
        "You are solving a CONSTRAINT/KEYGEN challenge. Common patterns: "
        "The binary checks input character-by-character or via a transform. "
        "Extract the comparison values and work backwards. "
        "Use Z3 if the check involves arithmetic: from z3 import *. "
        "Look for XOR, addition, multiplication transforms on input bytes. "
        "Check if there's a lookup table (substitution cipher)."
    ),
    "pwn": (
        "You are solving a BINARY EXPLOITATION (pwn) challenge. Common patterns: "
        "Find buffer overflow offset (cyclic pattern or source code analysis). "
        "Check protections: checksec output tells you NX, PIE, canary, RELRO. "
        "No PIE + No canary: simple ROP chain to system('/bin/sh'). "
        "Has canary: leak via format string or brute-force if fork(). "
        "PIE: partial overwrite (last 1-2 bytes) or leak first. "
        "After getting shell: cat /flag*"
    ),
    "forensics": (
        "You are solving a FORENSICS challenge. Common patterns: "
        "PCAP: reassemble TCP streams, extract HTTP bodies, check DNS queries. "
        "Disk image: mount and search, check deleted files, ADS. "
        "Memory dump: use volatility3 plugins. "
        "Look for base64, hex encoding in extracted data."
    ),
    "dynamic": (
        "You are solving a DYNAMIC ANALYSIS challenge. Common patterns: "
        "Run with strace/ltrace to see syscalls and library calls. "
        "Use GDB to set breakpoints at comparison functions. "
        "Hook strcmp/memcmp to extract expected values. "
        "Check for anti-debug (ptrace, timing checks) and bypass."
    ),
    "keygen": (
        "You are solving a KEYGEN/KEY-REVERSAL challenge. Common patterns: "
        "The binary validates a key/password via per-byte transforms. "
        "Extract the target values and reverse the transform. "
        "Prefer forward brute-force over printable ASCII when the transform is complex."
    ),
}


def _parse_tool_findings(tool_cascade_results: list[dict]) -> dict:
    """Parse structured findings from tool outputs.

    Tools output markers like:
        FINDING: key=0xDEADBEEF
        FINDING: decoded=hello_world
        FINDING: algorithm=AES-CBC
        FINDING: equation=x[0]+x[1]==65
        EXTRACTED FLAG: flag{...}

    Also extracts useful data from stdout even without markers:
        - Base64 decoded strings
        - Hex values
        - File paths discovered
        - Error patterns (what was tried and failed)
    """
    findings: dict = {
        "keys": [],
        "decoded_strings": [],
        "algorithms": [],
        "equations": [],
        "file_paths": [],
        "constants": {},
        "partial_flags": [],
        "tools_succeeded": [],
        "tools_failed": [],
        "tools_with_output": [],
    }

    if not tool_cascade_results or not isinstance(tool_cascade_results, list):
        return findings

    for result in tool_cascade_results:
        if not isinstance(result, dict):
            continue

        tool = result.get("tool", "unknown")
        stdout = str(result.get("stdout", "") or "")
        exit_code = result.get("exit_code", -1)

        if exit_code == 0 and stdout.strip():
            findings["tools_with_output"].append(tool)
        if exit_code == 0:
            findings["tools_succeeded"].append(tool)
        else:
            findings["tools_failed"].append(tool)

        # Parse FINDING: markers
        try:
            for m in re.finditer(r'FINDING:\s*(\w+)\s*=\s*(.+)', stdout):
                name, value = m.group(1), m.group(2).strip()
                findings["constants"][name] = value
        except Exception:
            pass

        # Parse EXTRACTED FLAG: markers
        try:
            for m in re.finditer(r'EXTRACTED FLAG:\s*(\S+)', stdout):
                findings["partial_flags"].append(m.group(1))
        except Exception:
            pass

        # Extract hex constants from output
        try:
            for m in re.finditer(r'\b(0x[0-9a-fA-F]{4,})\b', stdout):
                val = m.group(1)
                if val not in findings["keys"]:
                    findings["keys"].append(val)
        except Exception:
            pass

        # Extract base64 decoded strings
        try:
            for m in re.finditer(r'decoded?[:\s]+["\']?([^\s"\']{4,})["\']?', stdout, re.I):
                val = m.group(1)
                if val not in findings["decoded_strings"]:
                    findings["decoded_strings"].append(val)
        except Exception:
            pass

        # Extract algorithm identifications
        try:
            for algo in ["AES", "DES", "RSA", "XOR", "RC4", "TEA", "XTEA", "Blowfish", "ChaCha"]:
                if algo.lower() in stdout.lower() and algo not in findings["algorithms"]:
                    findings["algorithms"].append(algo)
        except Exception:
            pass

        # Extract equation patterns
        try:
            for m in re.finditer(r'(?:equation|constraint|check):\s*(.+)', stdout, re.I):
                eq = m.group(1).strip()
                if eq and eq not in findings["equations"]:
                    findings["equations"].append(eq)
        except Exception:
            pass

        # Extract discovered file paths
        try:
            for m in re.finditer(r'(?:file|path|wrote|saved|extracted):\s*(/[^\s]+)', stdout, re.I):
                fp = m.group(1).strip()
                if fp not in findings["file_paths"]:
                    findings["file_paths"].append(fp)
        except Exception:
            pass

    return findings


def _build_constants_block(tool_findings: dict) -> str:
    """Build a code-comment block of extracted constants for the solve prompt."""
    parts: list[str] = []

    if tool_findings.get("constants"):
        parts.append("# === EXTRACTED CONSTANTS (from tool analysis -- USE THESE, do NOT recompute) ===")
        for name, value in tool_findings["constants"].items():
            parts.append(f"# {name.upper()} = {value}")

    if tool_findings.get("keys"):
        parts.append("# Discovered keys/values:")
        for k in tool_findings["keys"][:10]:
            parts.append(f"# KEY: {k}")

    if tool_findings.get("algorithms"):
        parts.append(f"# Detected algorithms: {', '.join(set(tool_findings['algorithms']))}")

    if tool_findings.get("decoded_strings"):
        parts.append("# Decoded strings:")
        for s in tool_findings["decoded_strings"][:5]:
            parts.append(f"# DECODED: {s}")

    if tool_findings.get("equations"):
        parts.append("# Extracted equations/constraints:")
        for eq in tool_findings["equations"][:10]:
            parts.append(f"# CONSTRAINT: {eq}")

    if tool_findings.get("file_paths"):
        parts.append("# Discovered files:")
        for fp in tool_findings["file_paths"][:5]:
            parts.append(f"# FILE: {fp}")

    if tool_findings.get("partial_flags"):
        parts.append("# Partial/candidate flags from tools:")
        for pf in tool_findings["partial_flags"][:3]:
            parts.append(f"# CANDIDATE: {pf}")

    return "\n".join(parts) if parts else ""


def _build_params_code(extracted_params: dict) -> str:
    """Build prescriptive code comments from extracted parameters (Change 4)."""
    if not extracted_params or not isinstance(extracted_params, dict):
        return ""

    parts: list[str] = []
    parts.append("# === EXTRACTED PARAMETERS (use this I/O pattern) ===")

    input_mode = extracted_params.get("input_mode", "")
    if input_mode == "stdin":
        parts.append("# INPUT: via stdin (pipe input to process)")
        parts.append("# proc = subprocess.run([binary], input=flag_bytes, capture_output=True)")
    elif input_mode == "arg":
        parts.append("# INPUT: via command-line argument")
        parts.append("# proc = subprocess.run([binary, flag_string], capture_output=True)")

    success = extracted_params.get("success_string")
    if success:
        parts.append(f'# SUCCESS_MARKER = "{success}"')
        parts.append("# Check: if SUCCESS_MARKER in proc.stdout.decode(): print('CORRECT')")

    fail = extracted_params.get("fail_string")
    if fail:
        parts.append(f'# FAIL_MARKER = "{fail}"')

    length = extracted_params.get("input_length")
    if length:
        parts.append(f"# FLAG_LENGTH = {length}")

    comparison = extracted_params.get("comparison_target")
    if comparison:
        parts.append(f"# COMPARISON_TARGET = {comparison}")

    crypto = extracted_params.get("crypto_indicators")
    if crypto and isinstance(crypto, list):
        parts.append(f"# CRYPTO_PATTERNS = {crypto}")

    constants = extracted_params.get("key_constants")
    if constants and isinstance(constants, list):
        parts.append(f"# KEY_CONSTANTS = {constants[:10]}")

    seed = extracted_params.get("random_seed")
    if seed:
        parts.append(f"# RANDOM_SEED = {seed}")

    return "\n".join(parts) if len(parts) > 1 else ""


def _latest_linter_rejection(state: KrakenState, previous_attempts: list[dict]) -> str:
    """Return latest contract/linter rejection reason, if present."""
    diagnosis = str(state.get("failure_diagnosis", "") or "")
    if diagnosis.startswith("[script_contract]"):
        return diagnosis.replace("[script_contract]", "", 1).strip()

    for attempt in reversed(previous_attempts[-4:]):
        stderr = str(attempt.get("stderr", "") or "")
        if "contract" in stderr.lower() or "flat-z3 mode violation" in stderr.lower():
            return stderr[:400]
    return ""


def _build_working_memory(state: KrakenState, max_tail_chars: int = 2000, max_signal_lines: int = 14) -> str:
    """Build compact working memory optimized for low-context local models."""
    ledger_path = state.get("solve_ledger_path", "")
    tail = read_ledger_tail(ledger_path, max_chars=max_tail_chars)
    full = read_ledger_all(ledger_path)
    if not full:
        return tail

    signals: list[str] = []
    for raw in reversed(full.splitlines()):
        line = raw.strip()
        if not line:
            continue
        if (
            line.startswith("> STRATEGY PIVOT")
            or "RED HERRING" in line
            or line.startswith("Attempt #")
            or "LINTER REJECTION" in line
            or "silently failing" in line.lower()
        ):
            signals.append(line)
        if len(signals) >= max_signal_lines:
            break

    signal_block = "\n".join(reversed(signals))
    return (f"[critical_signals]\n{signal_block}\n\n[recent_tail]\n{tail}" if signal_block else tail)


def _count_no_solution_signals(state: KrakenState, previous_attempts: list[dict]) -> int:
    count = 0
    for attempt in previous_attempts[-10:]:
        stdout = str(attempt.get("stdout", "") or "").lower()
        stderr = str(attempt.get("stderr", "") or "").lower()
        if "no solution found" in stdout or "unsat" in stdout or "unsatisfiable" in stdout:
            count += 1
        elif "no solution found" in stderr or "unsat" in stderr or "unsatisfiable" in stderr:
            count += 1
    return count


# ── Agentic inner-loop helpers ────────────────────────────────────

# Common pip aliases for CTF modules
_PIP_ALIASES = {
    "Crypto": "pycryptodome",
    "Cryptodome": "pycryptodome",
    "cv2": "opencv-python-headless",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
    "yaml": "pyyaml",
    "bs4": "beautifulsoup4",
    "gmpy2": "gmpy2",
    "sage": "sagemath",
    "pwn": "pwntools",
}


def _detect_missing_module(stderr: str) -> str | None:
    """Extract module name from ModuleNotFoundError/ImportError in stderr."""
    for pattern in [
        r"ModuleNotFoundError: No module named '([^']+)'",
        r"ImportError: No module named '([^']+)'",
    ]:
        m = re.search(pattern, stderr or "")
        if m:
            return m.group(1).split(".")[0]
    return None


async def _auto_pip_install(module: str) -> bool:
    """Try to pip install a missing module. Returns True on success."""
    pip_name = _PIP_ALIASES.get(module, module)
    log.info("auto_pip_install", module=module, pip_name=pip_name)
    try:
        proc = await asyncio.create_subprocess_exec(
            "pip", "install", "--quiet", pip_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        if proc.returncode == 0:
            log.info("auto_pip_install_ok", module=pip_name)
            return True
        log.warning("auto_pip_install_fail", module=pip_name, stderr=stderr.decode(errors="replace")[:200])
        return False
    except Exception as exc:
        log.warning("auto_pip_install_error", module=pip_name, error=str(exc))
        return False


def _build_fix_prompt(
    code: str,
    exit_code: int,
    stdout: str,
    stderr: str,
    attempt_num: int,
    flag_format: str,
    challenge_id: str = "",
    challenge_context: str = "",
    tool_results: str = "",
    extracted_params: dict | None = None,
    functions_summary: str = "",
) -> str:
    """Build a prompt asking the LLM to fix a failing script.

    Includes challenge context, tool results, extracted parameters, and
    key decompiled functions so the LLM can make informed corrections.
    """
    ctx = ""
    if challenge_context:
        ctx = f"### Challenge Context\n{challenge_context[:3000]}\n\n"

    # Extracted parameters -- tiny but extremely useful
    params_block = ""
    if extracted_params and isinstance(extracted_params, dict):
        param_lines = []
        for k in ("input_mode", "input_length", "success_string", "fail_string",
                   "comparison_target", "crypto_indicators", "key_constants"):
            v = extracted_params.get(k)
            if v:
                param_lines.append(f"- {k}: {v}")
        if param_lines:
            params_block = "### Extracted Parameters\n" + "\n".join(param_lines) + "\n\n"

    # Tool results -- what tools already found
    tools_block = ""
    if tool_results:
        tools_block = f"### Tool Results (what has been found so far)\n{tool_results[:800]}\n\n"

    # Key functions -- the actual decompiled code
    funcs_block = ""
    if functions_summary:
        funcs_block = f"### Key Functions (from decompilation)\n{functions_summary}\n\n"

    return (
        f"## Fix Required -- {challenge_id} (attempt #{attempt_num})\n\n"
        f"{ctx}"
        f"{params_block}"
        f"{tools_block}"
        f"{funcs_block}"
        f"Your script crashed or produced no useful output.\n\n"
        f"### Your Code\n```python\n{code[:4000]}\n```\n\n"
        f"### Execution Result\n"
        f"- Exit code: {exit_code}\n"
        f"- stderr:\n```\n{stderr[:800]}\n```\n"
        f"- stdout:\n```\n{stdout[:400]}\n```\n\n"
        f"### Flag Format: {flag_format}\n\n"
        "Fix the bug and output ONLY the corrected Python code in a ```python block. "
        "Keep the same general approach but fix the specific error. "
        "If the approach is fundamentally broken, try a simpler technique."
    )


def _detect_source_languages(challenge_files: dict) -> list[str]:
    """Detect scripting languages present in challenge files."""
    langs = set()
    for name in challenge_files:
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext == "js":
            langs.add("javascript")
        elif ext == "php":
            langs.add("php")
        elif ext == "rb":
            langs.add("ruby")
        elif ext in ("sh", "bash"):
            langs.add("bash")
    return sorted(langs)


def _syntax_repair_pass(code: str) -> str:
    """Combined syntax repair: truncation recovery + line stripping."""
    try:
        ast.parse(code)
        return code
    except SyntaxError:
        pass

    repaired = _repair_truncated_code(code)
    try:
        ast.parse(repaired)
        return repaired
    except SyntaxError:
        pass

    # Strip non-code lines (explanatory text the LLM included)
    cleaned_lines = []
    for line in code.splitlines():
        stripped = line.strip()
        if stripped and not stripped[0].isalpha():
            cleaned_lines.append(line)
        elif any(stripped.startswith(kw) for kw in [
            "import ", "from ", "def ", "class ", "if ", "for ", "while ",
            "try:", "except", "with ", "return ", "print(", "    ", "\t",
            "#", "else:", "elif ", "finally:", "raise ", "assert ",
            "break", "continue", "pass", "yield ", "async ", "await ",
        ]) or stripped == "":
            cleaned_lines.append(line)
    cleaned = "\n".join(cleaned_lines)
    try:
        ast.parse(cleaned)
        return cleaned
    except SyntaxError:
        pass

    return code


_FUNC_BUDGET = 60_000  # max total chars of function code in the prompt


def _budget_functions(
    functions: dict,
    call_graph: dict,
    strings: list[str],
    specialist_summary: str,
    budget: int = _FUNC_BUDGET,
    max_funcs: int = 25,
) -> dict:
    """Include functions within a character budget, prioritized by relevance (#5).

    Priority order:
    1. Functions mentioned in specialist summary (crypto imports, strcmp callees)
    2. Functions containing flag-format strings or key comparison patterns
    3. Functions called by main (1 level deep from call_graph)
    4. Remaining functions by size (ascending -- small utility functions first)
    """
    if not functions:
        return {}

    # Score each function for relevance
    scores: dict[str, int] = {}
    spec_lower = specialist_summary.lower()

    for name, code in functions.items():
        score = 0
        name_lower = name.lower().split("@")[0]  # strip address suffix

        # Priority 1: mentioned in specialist summary
        if name_lower in spec_lower:
            score += 100

        # Priority 2: contains key indicators
        code_lower = code.lower()
        if any(kw in code_lower for kw in ["flag", "key", "password", "secret"]):
            score += 50
        if any(kw in code_lower for kw in ["strcmp", "check", "verify", "valid"]):
            score += 40
        if any(kw in code_lower for kw in ["encrypt", "decrypt", "xor", "cipher"]):
            score += 40

        # Priority 3: called by main or entry functions
        for caller, callees in call_graph.items():
            caller_lower = caller.lower()
            if "main" in caller_lower or "entry" in caller_lower:
                if isinstance(callees, list) and any(name_lower in str(c).lower() for c in callees):
                    score += 30

        # Priority 4: shorter functions get slight boost (utility/helpers)
        if len(code) < 500:
            score += 10

        scores[name] = score

    # Sort by score descending, then by code length ascending
    sorted_items = sorted(
        functions.items(),
        key=lambda x: (-scores.get(x[0], 0), len(x[1])),
    )
    items = sorted_items[:max_funcs]

    total = sum(len(v) for _, v in items)
    if total <= budget:
        return dict(items)

    # Proportional allocation with minimum guarantee
    result = {}
    for k, v in items:
        share = int(budget * len(v) / total) if total > 0 else budget
        result[k] = v[:max(share, 2000)]  # at least 2000 per function
    return result


async def solve_engine(state: KrakenState) -> dict:
    """Generate a solve script and execute it."""

    # ── Codex fallback: hand to agentic solver as strategy pivot ────
    if state.get("current_strategy") == "codex_fallback":
        return await _codex_fallback_branch(state)

    env = Environment(loader=FileSystemLoader(str(_PROMPTS_DIR)))

    cfg = ModelConfig()

    # Template selection: compact for small models, full for Claude
    use_compact = False
    if cfg.solve_template_mode == "compact":
        use_compact = True
    elif cfg.solve_template_mode == "auto":
        # Auto: use compact when backend is ollama
        use_compact = cfg.backend == "ollama"
    # else "full" → use_compact stays False

    template_name = "solve_engine_compact.j2" if use_compact else "solve_engine.j2"
    template = env.get_template(template_name)

    functions = get_artifact(state, "decompiled_functions", "decompiled_functions_handle")
    previous = state.get("solve_scripts", [])
    previous_full = [a for a in previous if isinstance(a, dict)]
    current_attempt = state.get("current_attempt", {}) if isinstance(state.get("current_attempt", {}), dict) else {}
    if current_attempt:
        previous_full = [*previous_full, current_attempt]
    attempt_num = len(previous) + 1
    working_memory = _build_working_memory(state, max_tail_chars=2000)

    # Build specialist summary from state (concise actionable hints)
    specialist_summary = _build_specialist_summary(state)

    # Phase 7: Delegation for complex challenges
    if EvolutionConfig().enable_delegation:
        from kraken.agents.delegate import plan_decomposition, delegate_parallel
        subtasks = plan_decomposition(state, functions)
        if subtasks:
            delegate_results = await delegate_parallel(subtasks, cfg)
            findings = [f"[{r.task_id}] {r.output[:300]}" for r in delegate_results if r.success and r.output]
            if findings:
                specialist_summary += "\n\n## Delegation Findings\n" + "\n".join(findings)

    # ── Codex research: learn unfamiliar domains before codegen ─────
    # Triggers when: Codex is available, challenge has failed 3+ times,
    # and the challenge involves domains that benefit from web research.
    _research_domains = {"crypto", "blockchain", "misc", "scripting", "forensics"}
    _ctype = (state.get("challenge_type") or "").lower()
    _attempts_so_far = len(previous)
    if (
        _attempts_so_far >= 3
        and _ctype in _research_domains
        and not state.get("_research_done")
    ):
        from kraken.execution.racing import codex_research, _is_codex_available
        if _is_codex_available():
            _hypothesis = state.get("strategy_hypothesis", "")
            _desc = state.get("challenge_description", "")[:300]
            _query = (
                f"CTF {_ctype} challenge: {state.get('challenge_id', 'unknown')}. "
                f"{_hypothesis[:200]}. "
                f"What tools, libraries, or techniques solve this? "
                f"Need working code (Python/SageMath/shell)."
            )
            _research = await codex_research(_query, context=_desc, timeout=90)
            if _research.knowledge and not _research.error:
                specialist_summary += f"\n\n## Codex Research\n{_research.knowledge[:2000]}"
                if _research.code_snippets:
                    specialist_summary += f"\n\n## Research Code Snippets\n```\n{_research.code_snippets[:1500]}\n```"
                log.info("solve_engine_research_injected", knowledge_len=len(_research.knowledge))
                append_ledger_entry(
                    state.get("solve_ledger_path", ""),
                    f"[research] Codex researched {_ctype} domain ({_research.elapsed:.0f}s, {len(_research.knowledge)} chars)",
                )

    if use_compact:
        specialist_summary = specialist_summary[:500]
    attempt_ledger = _build_attempt_ledger(previous_full)

    # Call-graph-aware function budgeting (#5)
    compact_max_funcs = 3 if use_compact else 25
    compact_budget = 15000 if use_compact else _FUNC_BUDGET
    budgeted_functions = _budget_functions(
        functions,
        state.get("call_graph", {}),
        state.get("strings_of_interest", []),
        specialist_summary,
        budget=compact_budget,
        max_funcs=compact_max_funcs,
    )

    force_flat_z3 = _derive_flat_z3_mode(state, previous)
    latest_linter_rejection = _latest_linter_rejection(state, previous_full)
    no_solution_count = _count_no_solution_signals(state, previous_full)

    # List workspace files so the LLM knows what tools and artifacts are available
    workspace_files: list[str] = []
    _ws = state.get("solve_workspace", "")
    if _ws and Path(_ws).is_dir():
        workspace_files = sorted(f.name for f in Path(_ws).iterdir() if f.is_file())

    # ── Build 1-line summaries of ALL previous attempts ─────────────
    attempt_history: list[str] = []
    for i, att in enumerate(previous_full):
        exit_c = att.get("exit_code", "?")
        strat = str(att.get("strategy", "?"))[:40]
        stdout_hint = str(att.get("stdout", ""))[:60].replace("\n", " ")
        stderr_hint = str(att.get("stderr", ""))[:60].replace("\n", " ")
        attempt_history.append(
            f"#{i+1} [{strat}] exit={exit_c} out={stdout_hint} err={stderr_hint}"
        )
    attempt_history = attempt_history[:15]  # Cap at 15 lines

    helpers_dir = str(Path(__file__).resolve().parent.parent / "helpers")
    prompt = template.render(
        challenge_id=state.get("challenge_id", "unknown"),
        challenge_description=state.get("challenge_description", ""),
        binary_path=state.get("challenge_path", ""),
        challenge_dir=state.get("challenge_dir", ""),
        flag_format=state.get("flag_format", ""),
        strategy=state.get("current_strategy", ""),
        attempt_num=attempt_num,
        binary_info=state.get("binary_info", {}),
        helpers_dir=helpers_dir,
        functions=budgeted_functions,
        strings=state.get("strings_of_interest", []),
        annotations=state.get("function_annotations", {}),
        angr_results=state.get("angr_results", {}),
        dynamic_traces=state.get("dynamic_traces", []),
        previous_attempts=previous_full[-3:],
        working_memory=working_memory,
        challenge_files=state.get("challenge_files", {}),
        remote_info=state.get("remote_info", {}),
        specialist_summary=specialist_summary,
        # New template variables
        challenge_type=state.get("challenge_type", ""),
        secondary_types=state.get("secondary_types", []),
        failure_diagnosis=state.get("failure_diagnosis", ""),
        script_findings=state.get("script_findings", []),
        attempt_ledger=attempt_ledger,
        force_flat_z3=force_flat_z3,
        workspace_files=workspace_files,
        solve_workspace=_ws,
        category=state.get("category", ""),
        # New compact template variables
        extracted_params=state.get("extracted_params", {}),
        tool_results=state.get("tool_results_summary", ""),
        max_functions=compact_max_funcs,
        attempt_history=attempt_history,
    )

    if latest_linter_rejection:
        prompt = (
            "LINTER REJECTION: Your previous code was REJECTED before execution. "
            f"Reason: {latest_linter_rejection}. "
            "You MUST fix this structural violation immediately. "
            "Do not submit the same code structure.\n\n"
            + prompt
        )

    if no_solution_count > 1:
        prompt = (
            "STRATEGY PIVOT REQUIRED: repeated UNSAT/No-solution detected. "
            "Manual constraint transcription is clearly not working for this challenge. "
            "Switch to a fundamentally different approach: "
            "programmatic extraction (regex parsing of decompiled text), "
            "dynamic analysis (angr symbolic execution, GDB tracing), "
            "compiled brute-force (extract C logic and brute-force in compiled C), "
            "or any other technique that avoids manual math transcription.\n\n"
            + prompt
        )

    if _recent_angr_failed(previous_full):
        prompt = (
            f"ANGR FAILURE RECOVERY: {ANGR_ARG_FLIP_HINT}\n\n"
            + prompt
        )

    # ── Hallucination loop detection ──────────────────────────────────
    rejected_flags = state.get("rejected_flags", []) or []
    if rejected_flags:
        from collections import Counter
        flag_counts = Counter(rejected_flags)
        repeated = [(f, c) for f, c in flag_counts.items() if c >= 2]
        if repeated:
            blocklist = ", ".join(f"'{f}'" for f, _ in repeated)
            prompt = (
                f"CRITICAL -- HALLUCINATION ALERT: The following flags have been submitted "
                f"and REJECTED multiple times: {blocklist}. "
                f"These values are WRONG. Do NOT output them again under any circumstances. "
                f"You MUST use a different approach: execute the challenge files with subprocess, "
                f"parse the actual source code programmatically, or reverse the algorithm. "
                f"DO NOT guess flag values.\n\n"
                + prompt
            )

    # ── Change 2: Structured tool findings integration ──────────────
    tool_findings = _parse_tool_findings(state.get("tool_cascade_results", []))
    constants_block = _build_constants_block(tool_findings)

    # Still show the raw tool summary for context, but also inject structured data
    tool_summary = state.get("tool_results_summary", "")
    if tool_summary or constants_block:
        tool_block_parts: list[str] = []
        if constants_block:
            tool_block_parts.append(constants_block)
        if tool_summary:
            tool_block_parts.append(
                f"PRE-RUN TOOL RESULTS:\n{tool_summary[:2000]}\n"
                "Build on these findings. Do not re-run tools that already produced output."
            )
        prompt = "\n\n".join(tool_block_parts) + "\n\n" + prompt

    # ── Change 4: Prescriptive extracted params ──────────────────────
    params_code = _build_params_code(state.get("extracted_params", {}))
    if params_code:
        prompt = params_code + "\n\n" + prompt

    # ── Change 5: Script findings on EVERY attempt, not just retries ─
    script_findings = state.get("script_findings", [])
    failure_diagnosis = state.get("failure_diagnosis", "")
    if script_findings or failure_diagnosis:
        findings_block_parts: list[str] = ["# === PREVIOUS ANALYSIS FINDINGS ==="]
        for finding in (script_findings or [])[:10]:
            findings_block_parts.append(f"# {finding}")
        if failure_diagnosis and isinstance(failure_diagnosis, str):
            findings_block_parts.append(f"# Failure type: {failure_diagnosis[:200]}")
        elif failure_diagnosis and isinstance(failure_diagnosis, dict):
            findings_block_parts.append(f"# Failure type: {failure_diagnosis.get('type', 'unknown')}")
            suggestion = failure_diagnosis.get("suggestion", "")
            if suggestion:
                findings_block_parts.append(f"# Suggestion: {suggestion}")
        if len(findings_block_parts) > 1:  # More than just the header
            prompt = "\n".join(findings_block_parts) + "\n\n" + prompt

    # ── RAG: retrieve context from similar solved challenges ────────
    # Only query Qdrant when explicitly enabled (adds ~700ms latency per attempt)
    if state.get("enable_rag") or os.environ.get("KRAKEN_ENABLE_RAG"):
        try:
            from kraken.knowledge.rag import SolveRAG
            _rag = SolveRAG()
            rag_context = _rag.get_full_context(state)
            if rag_context:
                prompt = rag_context + "\n\n" + prompt
                log.info("solve_engine_rag_injected", context_len=len(rag_context))
        except Exception:
            pass  # Qdrant unavailable -- graceful degradation

    log.info("solve_engine_start", attempt=attempt_num, strategy=state.get("current_strategy", ""), prompt_len=len(prompt))

    # ── System prompt ─────────────────────────────────────────────────
    _SYSTEM_PROMPT = (
        "You are a CTF reverse engineering expert. "
        "Do NOT use <think> tags. Do NOT include reasoning or explanation. "
        "Output ONLY a Python code block -- no text before or after the code block. "
        "Script contract: <=200 lines, define exactly one main(), include if __name__ == '__main__': main(), "
        "and print(flag) or print(result) in main. "
        "Use one focused approach per script. "
        "Every constant must come from provided analysis artifacts. "
        "Review your <working_memory>. Do not repeat failed approaches -- build on previous findings. "
        "No ghost-debugging: if a script produces no output, the logic is silently failing. "
        "You can use helper tools in your workspace, write custom scripts, or combine both. "
        "Adapt your approach to the challenge type -- there is no single right technique. "
        "If you discover intermediate values (keys, offsets, decoded bytes, partial results), "
        "print them as '# FINDING: name=value' comments to stdout so they persist across attempts."
    )
    _SYSTEM_PROMPT += (
        " For long decompiled math chains, prefer programmatic extraction or dynamic analysis "
        "over manual transcription."
    )
    if state.get("challenge_type", "") == "crypto":
        _SYSTEM_PROMPT += (
            " For byte-transform crypto checks, prefer forward brute-force over printable ASCII (32..126) "
            "with exact decompiled operations and '& 0xFF' at every arithmetic step."
        )

    # ── Change 3: Category-specific system prompt guidance ───────────
    _category = (state.get("challenge_type") or "").lower()
    if _category in CATEGORY_PROMPTS:
        _SYSTEM_PROMPT += " " + CATEGORY_PROMPTS[_category]

    if force_flat_z3:
        _SYSTEM_PROMPT += (
            " PRIORITY OVERRIDE: use flat literal Z3 constraint mapping. "
            "Do NOT build transformation arrays/lambda lists and do NOT index helper lists by input position. "
            "Translate decompiled temporaries and checks line-by-line with BitVec(8) variables."
        )
    if use_compact:
        _SYSTEM_PROMPT += (
            " TOOL-FIRST APPROACH: Check extracted parameters above. "
            "If input_mode and success_string are known, your FIRST action should be to call "
            "the appropriate helper tool (auto_angr, auto_regex_z3, etc.) with correct arguments. "
            "Only write custom code if no helper tool fits the problem. "
            "Keep scripts under 80 lines."
        )

    # ── Scripting language awareness ──────────────────────────────────
    source_langs = _detect_source_languages(state.get("challenge_files", {}))
    if source_langs:
        lang_hints = []
        for lang in source_langs:
            if lang == "javascript":
                lang_hints.append(
                    "For JavaScript: write a Python script that uses "
                    "subprocess.run(['node', '-e', js_code]) or subprocess.run(['node', 'file.js']) "
                    "to execute JS natively. Read the .js file, understand the logic, and use Node."
                )
            elif lang == "php":
                lang_hints.append(
                    "For PHP: write a Python script that uses "
                    "subprocess.run(['php', '-r', php_code]) or subprocess.run(['php', 'file.php']) "
                    "to execute PHP natively."
                )
            elif lang == "ruby":
                lang_hints.append(
                    "For Ruby: use subprocess.run(['ruby', '-e', ruby_code]) or subprocess.run(['ruby', 'file.rb'])."
                )
            elif lang == "bash":
                lang_hints.append(
                    "For Bash: use subprocess.run(['bash', 'file.sh']) to execute shell scripts."
                )
        _SYSTEM_PROMPT += (
            " SCRIPTING CHALLENGE: Source files are in " + "/".join(source_langs) + ". "
            + " ".join(lang_hints)
            + " Don't manually rewrite the language logic in Python -- use the native interpreter "
            "via subprocess, then parse its output. You can pip install any missing packages."
        )

    # ── Execution setup ───────────────────────────────────────────────
    timeout = _get_timeout(state)
    exec_cwd = state.get("challenge_dir") or state.get("solve_workspace") or None
    artifact_dir = state.get("solve_workspace") or exec_cwd or None
    max_inner_fixes = cfg.solve_inner_retries
    challenge_id = state.get("challenge_id", "unknown")
    flag_format = state.get("flag_format", "")

    # ── Build minimal challenge context for fix prompts ──────────────
    _fix_context_parts = []
    if state.get("challenge_description"):
        _fix_context_parts.append(f"Description: {state['challenge_description'][:500]}")
    for name, info in list(state.get("challenge_files", {}).items())[:3]:
        preview = (info.get("content_preview") or "")[:1500]
        if preview:
            _fix_context_parts.append(f"File {name}:\n```\n{preview}\n```")
    _fix_challenge_context = "\n".join(_fix_context_parts)

    # ── Build function summary for fix prompts (top 2 by budget score) ──
    _fix_functions_summary = ""
    if budgeted_functions:
        _func_parts = []
        for fname, fcode in list(budgeted_functions.items())[:2]:
            _func_parts.append(f"```c\n// {fname}\n{fcode[:2000]}\n```")
        _fix_functions_summary = "\n".join(_func_parts)


    # ── Inner debugging loop: generate → execute → fix → re-execute ──
    code = ""
    exec_result = None
    final_contract_error = None
    inner_attempts_log: list[str] = []

    for inner_iter in range(1 + max_inner_fixes):
        # ── Step 1: Generate code ─────────────────────────────────────
        if inner_iter == 0:
            content = await direct_generate(
                prompt, "high", cfg,
                system_prompt=_SYSTEM_PROMPT,
                num_predict=cfg.solve_num_predict,
            )
        else:
            # Build enriched tool results for fix prompt: structured + raw
            _fix_tool_results = ""
            if constants_block:
                _fix_tool_results = constants_block + "\n"
            _raw_summary = state.get("tool_results_summary", "")
            if _raw_summary:
                _fix_tool_results += _raw_summary[:600]
            fix_prompt = _build_fix_prompt(
                code,
                exec_result.exit_code if exec_result else 1,
                exec_result.stdout if exec_result else "",
                exec_result.stderr if exec_result else "empty code",
                attempt_num, flag_format, challenge_id,
                challenge_context=_fix_challenge_context,
                tool_results=_fix_tool_results[:800],
                extracted_params=state.get("extracted_params"),
                functions_summary=_fix_functions_summary,
            )
            log.info(
                "solve_engine_inner_fix",
                iteration=inner_iter,
                stderr_head=_preview_text(
                    (exec_result.stderr if exec_result else ""), 200
                ),
            )
            content = await direct_generate(
                fix_prompt, "high", cfg,
                system_prompt=_SYSTEM_PROMPT,
                num_predict=min(cfg.solve_num_predict, 12288),
            )

        # ── Step 2: Extract + syntax repair ───────────────────────────
        # Detect prose-heavy response (model rambled instead of writing code)
        if _is_mostly_prose(content):
            log.warning("solve_engine_prose_detected", content_len=len(content), preview=content[:200])
            inner_attempts_log.append(f"  [inner {inner_iter}] prose detected, no code block")
            if inner_iter < max_inner_fixes:
                class _Prose:
                    exit_code = 1
                    stdout = ""
                    stderr = (
                        "You wrote an explanation instead of code. "
                        "Output ONLY a ```python code block with a complete solve script. "
                        "No explanation, no text, no reasoning -- JUST the code."
                    )
                exec_result = _Prose()
                continue

        code = _extract_code(content)
        code = _syntax_repair_pass(code)

        # Empty check
        stripped_code = "\n".join(
            l for l in code.splitlines()
            if l.strip() and not l.strip().startswith("#")
        )
        if len(stripped_code.strip()) < 10:
            log.warning("solve_engine_empty_code", inner_iter=inner_iter, content_preview=content[:300])
            inner_attempts_log.append(f"  [inner {inner_iter}] empty code generated")
            if inner_iter < max_inner_fixes:
                # Create minimal exec_result for fix prompt
                class _Empty:
                    exit_code = 1
                    stdout = ""
                    stderr = "LLM generated empty or trivial code. Output ONLY a Python code block."
                exec_result = _Empty()
                continue
            break

        # ── Step 3: Contract enforcement ──────────────────────────────
        code, contract_error = _enforce_script_contract(code)
        if not contract_error and force_flat_z3:
            lowered = code.lower()
            banned = [
                "transformations[", "lambda",
                "for i in range(27)", "for i in range(30)",
                "model[flag[i]]", "print(flag)",
            ]
            if any(tok in lowered for tok in banned):
                contract_error = (
                    "Flat-Z3 mode violation: code still uses transformation/lambda/indexed-table "
                    "patterns or symbolic print placeholders. Use literal line-by-line BitVec constraints "
                    "and concrete model extraction (model.eval(v).as_long())."
                )

        if contract_error:
            log.warning("solve_engine_contract_reject", inner_iter=inner_iter, error=contract_error[:200])
            inner_attempts_log.append(f"  [inner {inner_iter}] contract: {contract_error[:120]}")
            if inner_iter < max_inner_fixes:
                class _Contract:
                    exit_code = 1
                    stdout = ""
                    stderr = contract_error[:400]
                exec_result = _Contract()
                final_contract_error = contract_error
                continue
            final_contract_error = contract_error
            break
        final_contract_error = None

        # ── Step 4: Execute ───────────────────────────────────────────
        log.info("solve_engine_executing", inner_iter=inner_iter, code_lines=code.count("\n") + 1, timeout=timeout)
        exec_result = await execute_script(code, timeout=timeout, cwd=exec_cwd, artifact_dir=artifact_dir)

        # ── Step 5: Auto-pip-install missing modules ──────────────────
        missing = _detect_missing_module(exec_result.stderr)
        if missing:
            installed = await _auto_pip_install(missing)
            if installed:
                log.info("solve_engine_rerun_after_install", module=missing)
                exec_result = await execute_script(code, timeout=timeout, cwd=exec_cwd, artifact_dir=artifact_dir)
                # Check for a second missing module (chained deps)
                missing2 = _detect_missing_module(exec_result.stderr)
                if missing2 and missing2 != missing:
                    if await _auto_pip_install(missing2):
                        exec_result = await execute_script(code, timeout=timeout, cwd=exec_cwd, artifact_dir=artifact_dir)

        # Log this inner attempt
        inner_attempts_log.append(
            f"  [inner {inner_iter}] exit={exec_result.exit_code} "
            f"stdout={_preview_text(exec_result.stdout, 80)} "
            f"stderr={_preview_text(exec_result.stderr, 80)}"
        )

        # ── Step 6: Success check (with false-positive detection) ────
        if exec_result.exit_code == 0 and exec_result.stdout.strip():
            # Check for failure signals in stdout (script ran but didn't solve)
            stdout_lower = exec_result.stdout.lower()
            has_failure_signal = any(
                sig in stdout_lower for sig in _FAILURE_SIGNALS
            )
            # Check if stdout contains something matching flag format
            has_flag_match = bool(
                flag_format and re.search(flag_format, exec_result.stdout)
            )

            if has_flag_match:
                log.info("solve_engine_inner_success", inner_iter=inner_iter, flag_match=True)
                break  # Likely found the flag -- send to validator
            if not has_failure_signal:
                log.info("solve_engine_inner_success", inner_iter=inner_iter, flag_match=False)
                break  # No flag match but no failure signals -- send to validator
            # Has failure signal -- continue fixing if retries remain
            if inner_iter < max_inner_fixes:
                log.info(
                    "solve_engine_inner_false_positive",
                    inner_iter=inner_iter,
                    stdout_head=_preview_text(exec_result.stdout, 120),
                )
                _fp_stderr = (
                    f"Script ran but output contains failure indicator. "
                    f"Output does not match expected flag format: {flag_format}. "
                    f"Fix your approach -- the current logic isn't finding the solution."
                )
                class _FalsePositive:
                    exit_code = 0
                    stdout = exec_result.stdout
                    stderr = _fp_stderr
                exec_result = _FalsePositive()
                continue
            break  # Out of retries, send to validator anyway

        # Continue to next fix iteration if we have retries left
        if inner_iter < max_inner_fixes:
            append_ledger_entry(
                state.get("solve_ledger_path", ""),
                f"  [inner fix {inner_iter + 1}/{max_inner_fixes}] "
                f"exit={exec_result.exit_code} err={_preview_text(exec_result.stderr, 120)}"
            )

    # ── Post-loop: handle final state ─────────────────────────────────

    # If we never got past contract enforcement, return contract error
    if final_contract_error and exec_result is None:
        log.warning("solve_engine_contract_reject_final", error=final_contract_error[:200])
        append_ledger_entry(
            state.get("solve_ledger_path", ""),
            f"Attempt #{attempt_num}: contract rejection after {len(inner_attempts_log)} inner attempts: {final_contract_error[:200]}",
        )
        compact = {
            "attempt_num": attempt_num,
            "strategy": state.get("current_strategy", ""),
            "exit_code": 1,
            "stdout": "",
            "stderr": final_contract_error[:300],
            "code": code[:800],
        }
        return {
            "solve_scripts": [compact],
            "current_attempt": {
                "code": code, "stdout": "", "stderr": final_contract_error,
                "exit_code": 1, "attempt_num": attempt_num,
                "strategy": state.get("current_strategy", ""),
            },
            "failure_diagnosis": f"[script_contract] {final_contract_error}",
            "error_log": [{"node": "solve_engine", "error": final_contract_error, "strategy": state.get("current_strategy", "")}],
            "recent_actions": [{"action": "solve_engine", "reasoning": f"Attempt #{attempt_num} rejected by contract after inner fixes", "result_summary": f"FAIL: {final_contract_error[:100]}"}],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # If exec_result is None (all inner iterations produced empty code), build a failure
    if exec_result is None or not hasattr(exec_result, "exit_code"):
        append_ledger_entry(
            state.get("solve_ledger_path", ""),
            f"Attempt #{attempt_num}: all {len(inner_attempts_log)} inner iterations produced empty/invalid code",
        )
        compact = {
            "attempt_num": attempt_num, "strategy": state.get("current_strategy", ""),
            "exit_code": 1, "stdout": "", "stderr": "All inner iterations failed to produce valid code",
            "code": code[:800],
        }
        return {
            "solve_scripts": [compact],
            "current_attempt": {"code": code, "stdout": "", "stderr": "All inner iterations failed", "exit_code": 1, "attempt_num": attempt_num, "strategy": state.get("current_strategy", "")},
            "error_log": [{"node": "solve_engine", "error": "All inner iterations failed", "strategy": state.get("current_strategy", "")}],
            "recent_actions": [{"action": "solve_engine", "reasoning": f"Attempt #{attempt_num} failed: all inner iterations empty", "result_summary": "FAIL: empty code across all retries"}],
            "iteration_count": state.get("iteration_count", 0) + 1,
        }

    # ── Build final result from best exec_result ──────────────────────
    attempt = {
        "code": code,
        "stdout": exec_result.stdout,
        "stderr": exec_result.stderr,
        "exit_code": exec_result.exit_code,
        "attempt_num": attempt_num,
        "strategy": state.get("current_strategy", ""),
    }
    if isinstance(getattr(exec_result, "data", None), dict):
        attempt["script_path"] = exec_result.data.get("script_path", "")
        attempt["stdout_path"] = exec_result.data.get("stdout_path", "")
        attempt["stderr_path"] = exec_result.data.get("stderr_path", "")

    log.info(
        "solve_engine_result",
        exit_code=exec_result.exit_code,
        stdout_len=len(exec_result.stdout),
        stderr_len=len(exec_result.stderr),
        inner_iterations=len(inner_attempts_log),
        stdout_head=_preview_text(exec_result.stdout[:800]),
        stdout_tail=_preview_text(exec_result.stdout[-800:]),
        stderr_head=_preview_text(exec_result.stderr[:800]),
        stderr_tail=_preview_text(exec_result.stderr[-800:]),
    )

    script_name = Path(attempt.get("script_path", "")).name or f"solve_attempt_{attempt_num}.py"
    if exec_result.exit_code != 0:
        status = "Python Crash"
    elif exec_result.stdout.strip() or exec_result.stderr.strip():
        status = "Executed"
    else:
        status = "Executed"

    output_preview = _preview_text(exec_result.stdout or exec_result.stderr, 240)
    if not output_preview:
        output_preview = "Script executed but produced no output. Logic is silently failing."

    # Include inner loop summary in ledger
    inner_summary = f" ({len(inner_attempts_log)} inner iterations)" if len(inner_attempts_log) > 1 else ""
    append_ledger_entry(
        state.get("solve_ledger_path", ""),
        f"Attempt #{attempt_num}{inner_summary}: Wrote {script_name}. Result: {status}. Output: {output_preview}",
    )

    summary_attempt = {
        "attempt_num": attempt_num,
        "strategy": state.get("current_strategy", ""),
        "exit_code": exec_result.exit_code,
        "stdout": _preview_text(exec_result.stdout, 300),
        "stderr": _preview_text(exec_result.stderr, 300),
        "code": code[:800],
        "stdout_preview": _preview_text(exec_result.stdout, 200),
        "stderr_preview": _preview_text(exec_result.stderr, 200),
    }

    runtime_hint = ""
    low_stderr = (exec_result.stderr or "").lower()
    if "indexerror" in low_stderr:
        runtime_hint = (
            "FATAL ERROR: You got an IndexError. THIS IS BECAUSE YOU USED A LOOP OR ARRAY. "
            "Rewrite the script by unrolling the loop entirely. Write every constraint line-by-line."
        )
    elif "bitvecval" in low_stderr or "z3.z3types.z3exception" in low_stderr:
        runtime_hint = (
            "FATAL ERROR: Z3 Type Casting failed. Ensure you are comparing BitVecs to integers, "
            "and that you are NOT iterating over a BitVecRef object."
        )

    if runtime_hint:
        append_ledger_entry(state.get("solve_ledger_path", ""), runtime_hint)

    updates = {
        "solve_scripts": [summary_attempt],
        "current_attempt": attempt,
        "recent_actions": [{
            "action": "solve_engine",
            "reasoning": f"Generated and executed solve script attempt #{attempt_num}{inner_summary}",
            "result_summary": f"exit={exec_result.exit_code}, stdout={exec_result.stdout[:200]}",
        }],
        "iteration_count": state.get("iteration_count", 0) + 1,
    }
    if runtime_hint:
        updates["failure_diagnosis"] = f"[runtime_guardrail] {runtime_hint}"

    if _has_angr_failed_marker(exec_result.stdout) or _has_angr_failed_marker(exec_result.stderr):
        updates["script_findings"] = [ANGR_ARG_FLIP_HINT]

    return updates
