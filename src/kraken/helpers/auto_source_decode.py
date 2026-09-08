#!/usr/bin/env python3
"""auto_source_decode -- Extract and decode encoded strings from source files.

Scans JS/PHP/Python/Rust/Go/C/any text source for:
  - Base64-encoded strings
  - Hex-encoded strings
  - Shell command pipelines (echo|tr|rev etc.)
  - charCodeAt / chr() sequences
  - Array literals with reversible patterns
  - Rust macro-obfuscated strings (obfstr!, include_str!, macro!("..."))
  - C/C++ __attribute__((constructor)) strings
  - Go //go:embed flag references

Outputs EXTRACTED FLAG: <flag> on success.
"""
import base64
import email
import os
import re
import subprocess
import sys
import urllib.parse


def _decode_base64_strings(text: str) -> list[str]:
    """Find and decode all plausible base64 strings in source code."""
    results = []
    # Match quoted base64 strings (min 8 chars to avoid noise)
    b64_pattern = re.compile(
        r"""(?:['"])([A-Za-z0-9+/]{8,}={0,2})(?:['"])""",
    )
    for m in b64_pattern.finditer(text):
        candidate = m.group(1)
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            # Only keep if it's mostly printable
            printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
            if printable > len(decoded) * 0.7 and len(decoded) >= 3:
                results.append(decoded)
        except Exception:
            pass

    # Also try unquoted base64 strings (standalone on a line, min 12 chars)
    unquoted_b64 = re.compile(
        r"^[ \t]*([A-Za-z0-9+/]{12,}={0,2})[ \t]*$",
        re.MULTILINE,
    )
    for m in unquoted_b64.finditer(text):
        candidate = m.group(1)
        if candidate in {r.strip() for r in results}:
            continue
        try:
            decoded = base64.b64decode(candidate).decode("utf-8", errors="replace")
            printable = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
            if printable > len(decoded) * 0.7 and len(decoded) >= 3:
                results.append(decoded)
        except Exception:
            pass

    # Also try base64_decode() / atob() argument patterns
    fn_pattern = re.compile(
        r"""(?:base64_decode|atob|b64decode)\s*\(\s*['"]([A-Za-z0-9+/]{4,}={0,2})['"]""",
    )
    for m in fn_pattern.finditer(text):
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            if decoded not in results:
                results.append(decoded)
        except Exception:
            pass

    return results


def _decode_hex_strings(text: str) -> list[str]:
    """Find and decode hex-encoded strings."""
    results = []
    # Quoted hex strings (even length, min 8 chars)
    hex_pattern = re.compile(r"""(?:['"])([0-9a-fA-F]{8,})(?:['"])""")
    for m in hex_pattern.finditer(text):
        candidate = m.group(1)
        if len(candidate) % 2 != 0:
            continue
        try:
            decoded = bytes.fromhex(candidate).decode("utf-8", errors="replace")
            printable = sum(1 for c in decoded if c.isprintable())
            if printable > len(decoded) * 0.7 and len(decoded) >= 3:
                results.append(decoded)
        except Exception:
            pass
    return results


def _extract_chr_sequences(text: str) -> list[str]:
    """Extract chr(N) / String.fromCharCode(N,...) sequences."""
    results = []

    # Python chr() chains: chr(65) + chr(66) + ...
    chr_chain = re.compile(r'chr\s*\(\s*(\d+)\s*\)')
    codes = [int(m.group(1)) for m in chr_chain.finditer(text)]
    if codes:
        try:
            decoded = "".join(chr(c) for c in codes if 0 <= c < 128)
            if len(decoded) >= 3:
                results.append(decoded)
        except Exception:
            pass

    # JS String.fromCharCode(65, 66, ...)
    fcc_pattern = re.compile(
        r'String\.fromCharCode\s*\(([^)]+)\)',
    )
    for m in fcc_pattern.finditer(text):
        try:
            codes = [int(x.strip()) for x in m.group(1).split(",") if x.strip().isdigit()]
            decoded = "".join(chr(c) for c in codes if 0 <= c < 128)
            if len(decoded) >= 3:
                results.append(decoded)
        except Exception:
            pass

    return results


def _extract_js_arrays(text: str) -> list[str]:
    """Extract string array literals and try reversals."""
    results = []
    # Match arrays of short quoted strings: ['ab','cd','ef']
    arr_pattern = re.compile(
        r"""\[(?:\s*['"]([^'"]{1,4})['"]\s*,?\s*){3,}\]""",
    )
    for m in arr_pattern.finditer(text):
        chunk = m.group(0)
        # Extract individual elements
        elems = re.findall(r"""['"]([^'"]{1,4})['"]""", chunk)
        if len(elems) < 3:
            continue

        # Try: concatenate as-is
        joined = "".join(elems)
        if len(joined) >= 6:
            results.append(joined)

        # Try: reverse each element then concatenate
        rev_joined = "".join(e[::-1] for e in elems)
        if rev_joined != joined and len(rev_joined) >= 6:
            results.append(rev_joined)

    return results


def _simulate_shell_commands(text: str) -> list[str]:
    """Find shell command strings and try to simulate them."""
    results = []
    # Pattern: echo ... | tr ... | rev (or similar pipelines)
    shell_pattern = re.compile(
        r"""(?:['"])(echo\s+[^'"]{3,}(?:\|[^'"]+)*)(?:['"])""",
    )
    for m in shell_pattern.finditer(text):
        cmd = m.group(1)
        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = proc.stdout.strip()
            if output and len(output) >= 3:
                results.append(output)
        except Exception:
            pass

    # Also try: shell_exec('...') patterns (PHP)
    shellexec_pattern = re.compile(
        r"""shell_exec\s*\(\s*['"]([^'"]+)['"]""",
    )
    for m in shellexec_pattern.finditer(text):
        cmd = m.group(1)
        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = proc.stdout.strip()
            if output and len(output) >= 3:
                results.append(output)
        except Exception:
            pass

    return results


def _find_flags(candidates: list[str], flag_format: str = "") -> list[str]:
    """Check candidates for flag patterns."""
    flags = []
    for c in candidates:
        # Direct flag pattern
        m = re.search(r'[a-zA-Z_]{2,}\{[^}]{3,}\}', c)
        if m:
            flags.append(m.group(0))
            continue
        # Check if candidate IS a flag body that needs wrapping
        if flag_format:
            prefix_m = re.match(r'([A-Za-z_]+)\\?\{', flag_format)
            if prefix_m:
                prefix = prefix_m.group(1)
                # If candidate starts with prefix{ already
                if c.startswith(prefix + "{"):
                    full = c if c.endswith("}") else c + "}"
                    # Reject empty-body flags like "vere{}"
                    body_m = re.match(r'^[A-Za-z_]+\{(.+)\}$', full)
                    if body_m and len(body_m.group(1).strip()) >= 2:
                        flags.append(full)
    return flags


def _execute_decoded_shell_commands(candidates: list[str]) -> list[str]:
    """Try to execute decoded strings that look like shell commands."""
    results = []
    shell_prefixes = ("echo ", "printf ", "cat ", "base64 ", "xxd ")
    for c in candidates:
        c_stripped = c.strip()
        if not any(c_stripped.startswith(p) for p in shell_prefixes):
            continue
        try:
            proc = subprocess.run(
                ["bash", "-c", c_stripped],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = proc.stdout.strip()
            if output and len(output) >= 2:
                results.append(output)
        except Exception:
            pass
    return results


def _extract_scattered_chars(text: str) -> list[str]:
    """Extract flag from single-char string literals scattered in a Python list expression.

    Handles patterns like: [a:=__import__('x'), 'v', b:=__import__('y'), 'e', ...]
    where the flag chars are standalone single-char string entries in a list.
    """
    # Must look like a Python list with __import__ calls (obfuscation pattern)
    if '__import__' not in text:
        return []
    # Must be a single long list expression (starts with [, ends with ])
    stripped = text.strip()
    if not (stripped.startswith('[') and stripped.endswith(']')):
        return []

    # Extract standalone single-char string literals from the list.
    # These are entries that are just 'c' -- not part of __import__('module'),
    # not comparisons like 'vere'=='vere{', not walrus assignments like x:='c'.
    # Strategy: split by commas at top level, check each element.
    chars = []
    depth = 0
    in_str = ''  # track string delimiters to skip contents
    start = 1  # skip opening [
    for i in range(1, len(stripped) - 1):
        ch = stripped[i]
        if in_str:
            if ch == in_str and stripped[i - 1] != '\\':
                in_str = ''
            continue
        if ch in ("'", '"'):
            in_str = ch
            continue
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        elif ch == ',' and depth == 0:
            elem = stripped[start:i].strip()
            start = i + 1
            # Check if element is a standalone single-char string
            # Only keep flag-relevant chars (letters, digits, underscore, braces)
            m = re.match(r"^'(.)'$", elem) or re.match(r'^"(.)"$', elem)
            if m and re.match(r'[a-zA-Z0-9_{}]', m.group(1)):
                chars.append(m.group(1))
    # Handle last element
    elem = stripped[start:-1].strip()
    m = re.match(r"^'(.)'$", elem) or re.match(r'^"(.)"$', elem)
    if m and re.match(r'[a-zA-Z0-9_{}]', m.group(1)):
        chars.append(m.group(1))

    if len(chars) >= 5:
        return [''.join(chars)]
    return []


def _trace_php_obfuscated(text: str) -> list[str]:
    """Trace PHP function-alias chains to extract flag from obfuscated code.

    Handles patterns like:
      function h($h){return base64_decode($h);}
      function o($o){return chr($o);}
      function i($i,$j){return $i.$j;}
      g(i(i(i(h('...'), o(115)), h('...')), o(125)))
    """
    if '<?php' not in text and '<?PHP' not in text and '<?=' not in text:
        return []

    # Step 1: Parse function aliases
    funcs: dict[str, str] = {}  # name -> type
    for m in re.finditer(
        r'function\s+(\w+)\s*\([^)]*\)\s*\{([^}]+)\}', text
    ):
        name, body = m.group(1), m.group(2).strip()
        if 'base64_decode' in body:
            funcs[name] = 'base64'
        elif re.search(r'\breturn\s+chr\s*\(', body):
            funcs[name] = 'chr'
        elif 'shell_exec' in body:
            funcs[name] = 'shell_exec'
        elif re.search(r'\breturn\s+\$\w+\s*\.\s*\$\w+\s*;', body):
            funcs[name] = 'concat'
        elif re.search(r'\becho\s+\$\w+', body):
            funcs[name] = 'echo'
        elif re.search(r'\breturn\s+\$\w+\s*;$', body):
            funcs[name] = 'identity'
        elif 'substr' in body:
            funcs[name] = 'substr'
        elif 'die' in body:
            funcs[name] = 'die'

    if not funcs:
        return []

    # Step 2: Infer variable values from assertions
    # Pattern: j(k($a,0,4) != h('cm9vdA=='), ...) -- means $a starts with 'root'
    inferred_vars: dict[str, str] = {}
    b64_func = next((n for n, t in funcs.items() if t == 'base64'), None)
    if b64_func:
        # Find assertions: someFunc( substr_func($var, 0, N) != b64_func('...'), ...)
        # This means the variable's first N chars equal the base64-decoded value
        for m in re.finditer(
            rf'\b\w+\s*\(\s*\w+\s*\(\s*\w+\s*\(\s*(\$\w+)\s*,\s*0\s*,\s*\d+\s*\)\s*\)\s*!=\s*\w+\s*\(\s*{re.escape(b64_func)}\s*\(\s*[\'"]([A-Za-z0-9+/=]+)[\'"]\s*\)',
            text,
        ):
            var_name = m.group(1)
            try:
                import base64 as b64m
                value = b64m.b64decode(m.group(2)).decode('utf-8', errors='replace')
                inferred_vars[var_name] = value
            except Exception:
                pass

        # Simpler pattern: identity(substr($a,0,N)) != identity(b64('...'))
        for m in re.finditer(
            rf'(\$\w+)\s*,\s*0\s*,\s*(\d+).*?!=.*?{re.escape(b64_func)}\s*\(\s*[\'"]([A-Za-z0-9+/=]+)[\'"]',
            text,
        ):
            var_name = m.group(1)
            try:
                import base64 as b64m
                value = b64m.b64decode(m.group(3)).decode('utf-8', errors='replace')
                if var_name not in inferred_vars:
                    inferred_vars[var_name] = value
            except Exception:
                pass

    # Step 3: Evaluate the output expression
    # Find the echo function and trace its argument
    echo_func = next((n for n, t in funcs.items() if t == 'echo'), None)
    if not echo_func:
        return []

    def eval_expr(expr: str) -> str:
        """Recursively evaluate a PHP expression."""
        expr = expr.strip()
        if not expr:
            return ''

        # String literal
        sm = re.match(r"^'([^']*)'$", expr)
        if sm:
            return sm.group(1)
        sm = re.match(r'^"([^"]*)"$', expr)
        if sm:
            return sm.group(1)

        # Number literal
        if re.match(r'^\d+$', expr):
            return expr

        # Function call: name(args...)
        fm = re.match(r'^(\w+)\s*\(', expr)
        if fm:
            fname = fm.group(1)
            ftype = funcs.get(fname, '')
            # Find matching closing paren
            depth, start = 0, fm.end() - 1
            for i in range(start, len(expr)):
                if expr[i] == '(':
                    depth += 1
                elif expr[i] == ')':
                    depth -= 1
                    if depth == 0:
                        inner = expr[start + 1:i]
                        break
            else:
                return ''

            if ftype == 'base64':
                arg = eval_expr(inner)
                try:
                    import base64 as b64m
                    return b64m.b64decode(arg).decode('utf-8', errors='replace')
                except Exception:
                    return ''
            elif ftype == 'chr':
                arg = eval_expr(inner)
                try:
                    return chr(int(arg))
                except (ValueError, OverflowError):
                    return ''
            elif ftype == 'identity':
                return eval_expr(inner)
            elif ftype == 'concat':
                # Split on top-level comma
                args = _split_php_args(inner)
                return ''.join(eval_expr(a) for a in args)
            elif ftype == 'echo':
                return eval_expr(inner)
            elif ftype == 'shell_exec':
                cmd = eval_expr(inner)
                if cmd and cmd.split()[0] in ('echo', 'printf'):
                    try:
                        proc = subprocess.run(
                            ['bash', '-c', cmd],
                            capture_output=True, text=True, timeout=5,
                        )
                        return proc.stdout.strip()
                    except Exception:
                        return ''
                return ''
            elif ftype == 'substr':
                args = _split_php_args(inner)
                if len(args) >= 3:
                    s = eval_expr(args[0])
                    try:
                        start_idx = int(eval_expr(args[1]))
                        length = _eval_php_arithmetic(args[2], funcs)
                        return s[start_idx:start_idx + length]
                    except (ValueError, TypeError):
                        pass
                return ''
            elif ftype == 'die':
                return ''
            else:
                # Unknown function -- try evaluating inner
                return eval_expr(inner)

        # Variable reference -- check inferred values
        vm = re.match(r'^\$(\w+)$', expr)
        if vm:
            return inferred_vars.get('$' + vm.group(1), '')

        return ''

    # Find the largest echo_func call (the one that constructs the flag,
    # not short calls like g('') used for arithmetic)
    echo_pattern = re.compile(rf'\b{re.escape(echo_func)}\s*\(')
    best_echo = None
    best_len = 0
    for m in echo_pattern.finditer(text):
        # Measure enclosed expression length via balanced parens
        depth = 0
        end = m.end() - 1
        for i in range(m.end() - 1, len(text)):
            if text[i] == '(':
                depth += 1
            elif text[i] == ')':
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
        expr_len = end - m.start()
        if expr_len > best_len:
            best_len = expr_len
            best_echo = (m.start(), end)

    if not best_echo:
        return []

    echo_expr = text[best_echo[0]:best_echo[1]]
    result = eval_expr(echo_expr)
    if result and len(result) >= 5:
        return [result]

    return []


def _split_php_args(expr: str) -> list[str]:
    """Split PHP function arguments at top-level commas."""
    args = []
    depth = 0
    start = 0
    for i, ch in enumerate(expr):
        if ch in '([':
            depth += 1
        elif ch in ')]':
            depth -= 1
        elif ch == ',' and depth == 0:
            args.append(expr[start:i].strip())
            start = i + 1
    args.append(expr[start:].strip())
    return [a for a in args if a]


def _eval_php_arithmetic(expr: str, funcs: dict[str, str]) -> int:
    """Evaluate simple PHP arithmetic expressions (for substr length etc.)."""
    expr = expr.strip()
    if re.match(r'^\d+$', expr):
        return int(expr)
    # Pattern: N-N or N+N
    m = re.match(r'^(\d+)\s*([+\-*/])\s*(\d+)$', expr)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op == '+':
            return a + b
        if op == '-':
            return a - b
        if op == '*':
            return a * b
        if op == '/':
            return a // b
    # Pattern: func('')+func('')+... where func returns 1 (echo function)
    # Count how many func('') calls there are
    echo_func = next((n for n, t in funcs.items() if t == 'echo'), None)
    if echo_func:
        count = len(re.findall(rf"{re.escape(echo_func)}\s*\(\s*['\"]['\"]", expr))
        if count >= 1:
            return count
    return 0


def _extract_shell_flag_assembly(text: str) -> list[str]:
    """Extract flags assembled from shell variable concatenation and commands.

    Handles patterns like:
      part1=$(echo '...' | rev)
      part2=$(echo '...' | base64 -d)
      echo "${part1}${part2}"
    """
    results = []

    # Extract variable assignments: VAR=value or VAR=$(command)
    var_values: dict[str, str] = {}

    # Simple assignments: VAR="value" or VAR='value'
    for m in re.finditer(r'''(\w+)=["']([^"']+)["']''', text):
        var_values[m.group(1)] = m.group(2)

    # Command substitution: VAR=$(command)
    for m in re.finditer(r'(\w+)=\$\(([^)]+)\)', text):
        var_name = m.group(1)
        cmd = m.group(2)
        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                var_values[var_name] = proc.stdout.strip()
        except Exception:
            pass

    # Backtick substitution: VAR=`command`
    for m in re.finditer(r'(\w+)=`([^`]+)`', text):
        var_name = m.group(1)
        cmd = m.group(2)
        try:
            proc = subprocess.run(
                ["bash", "-c", cmd],
                capture_output=True, text=True, timeout=5,
            )
            if proc.returncode == 0 and proc.stdout.strip():
                var_values[var_name] = proc.stdout.strip()
        except Exception:
            pass

    if not var_values:
        return results

    # Look for echo/printf statements that concatenate variables
    for m in re.finditer(r'(?:echo|printf)\s+.*(\$\{?\w+\}?.*\$\{?\w+\}?)', text):
        line = m.group(0)
        # Substitute known variables
        expanded = line
        for var, val in var_values.items():
            expanded = expanded.replace(f"${{{var}}}", val)
            expanded = expanded.replace(f"${var}", val)
        # Check if the expanded string contains a flag
        flag_m = re.search(r'[A-Za-z0-9_]{1,20}\{[^}]+\}', expanded)
        if flag_m:
            results.append(flag_m.group(0))

    # Also try concatenating all variable values to see if they form a flag
    if len(var_values) >= 2:
        all_vals = list(var_values.values())
        combined = "".join(all_vals)
        flag_m = re.search(r'[A-Za-z0-9_]{1,20}\{[^}]+\}', combined)
        if flag_m:
            results.append(flag_m.group(0))

    return results


def _extract_rust_macro_strings(text: str) -> list[str]:
    """Extract string literals from Rust compile-time obfuscation macros.

    Handles:
      - obfstr!("...") / obfstr::obfstr!("...") -- compile-time string obfuscation
      - include_str!("...") -- compile-time file inclusion
      - Any macro!("flag{...}") pattern -- generic macro string extraction
      - concat!("a", "b") -- compile-time string concatenation
      - env!("VAR") -- environment variable at compile time (extracts var name)
    """
    results = []

    # Pattern 1: obfstr!("...") -- the primary obfuscation macro.
    # Handles both obfstr!("...") and obfstr::obfstr!("...")
    # The ! is part of Rust macro invocation syntax.
    obfstr_pat = re.compile(
        r"""(?:obfstr::)?obfstr!\s*\(\s*["']([^"']+)["']\s*\)""",
    )
    for m in obfstr_pat.finditer(text):
        s = m.group(1)
        if len(s) >= 3:
            results.append(s)

    # Pattern 2: include_str!("...") -- file path may hint at flag location
    include_str_pat = re.compile(
        r"""include_str!\s*\(\s*["']([^"']+)["']\s*\)""",
    )
    for m in include_str_pat.finditer(text):
        s = m.group(1)
        if len(s) >= 3:
            results.append(s)

    # Pattern 3: concat!("a", "b", ...) -- concatenate fragments
    concat_pat = re.compile(
        r"""concat!\s*\(([^)]+)\)""",
    )
    for m in concat_pat.finditer(text):
        inner = m.group(1)
        parts = re.findall(r"""["']([^"']*)["']""", inner)
        if parts:
            joined = "".join(parts)
            if len(joined) >= 3:
                results.append(joined)

    # Pattern 4: Generic macro!("string") where string looks like a flag.
    # Catches custom macros that wrap flag literals.
    # Only extract strings that contain flag-like content (at least one { } pair
    # or printable ASCII of sufficient length).
    generic_macro_pat = re.compile(
        r"""\w+!\s*\(\s*["']([^"']{5,})["']\s*[,)]""",
    )
    for m in generic_macro_pat.finditer(text):
        s = m.group(1)
        # Skip strings already captured by specific patterns above
        if s in results:
            continue
        # Only keep if it looks flag-relevant (has braces or is long enough)
        if '{' in s and '}' in s:
            results.append(s)
        elif len(s) >= 10 and s.isprintable():
            results.append(s)

    return results


def _extract_c_constructor_strings(text: str) -> list[str]:
    """Extract flag strings from C/C++ __attribute__((constructor)) functions.

    In CTF challenges, flags are sometimes hidden in constructor functions
    that run before main(). This extracts string literals from those functions.

    Also handles:
      - __attribute__((section(".init_array")))
      - Strings in __attribute__((destructor)) functions
    """
    results = []

    # Find __attribute__((constructor)) or __attribute__((destructor)) function bodies
    # Match the function signature and capture the body up to the closing brace
    attr_pat = re.compile(
        r'__attribute__\s*\(\s*\(\s*(?:constructor|destructor|'
        r'section\s*\(\s*"[^"]*"\s*\))\s*\)\s*\)'
        r'[^{]*\{',
        re.DOTALL,
    )
    for m in attr_pat.finditer(text):
        # Find the matching closing brace for this function body
        start = m.end()
        depth = 1
        end = start
        for i in range(start, min(start + 5000, len(text))):
            if text[i] == '{':
                depth += 1
            elif text[i] == '}':
                depth -= 1
                if depth == 0:
                    end = i
                    break
        body = text[start:end]

        # Extract all string literals from the function body
        for sm in re.finditer(r'"([^"]{3,})"', body):
            s = sm.group(1)
            if s.isprintable() and any(c.isalnum() for c in s):
                results.append(s)

    return results


def _extract_go_embed_strings(text: str) -> list[str]:
    """Extract flag-relevant content from Go //go:embed directives.

    In Go, //go:embed can embed file contents at compile time:
      //go:embed flag.txt
      var flag string

    This extracts the embedded file paths and also scans for flag patterns
    near embed directives.
    """
    results = []

    # Pattern: //go:embed <filename>
    embed_pat = re.compile(r'//go:embed\s+(\S+)')
    for m in embed_pat.finditer(text):
        filepath = m.group(1)
        # The filename itself might be interesting (flag.txt, secret, etc.)
        if len(filepath) >= 3:
            results.append(filepath)

    # Also look for Go const/var blocks containing flag strings
    # var flag = "flag{...}" or const flag = "flag{...}"
    go_string_pat = re.compile(
        r'(?:var|const)\s+\w+\s*(?:string)?\s*=\s*[`"]((?:[^`"\\]|\\.)*)(?:[`"])',
    )
    for m in go_string_pat.finditer(text):
        s = m.group(1)
        if len(s) >= 3 and s.isprintable():
            results.append(s)

    return results


def _extract_reversed_flag_fragments(text: str) -> list[str]:
    """Scan each line of text, reverse it, check for flag prefix patterns.

    Catches challenges like "It Has Begun" where flag parts are stored
    reversed in shell scripts (e.g. `user@tS_u0y_ll1w{BTH` → `HTB{w1ll_y0u_St`).
    """
    known_prefixes = (
        "HTB{", "flag{", "FLAG{", "CTF{", "ctf{", "picoCTF{", "SEKAI{",
        "csawctf{", "vere{", "VERE{", "hack{", "HACK{", "key{", "KEY{",
    )
    results = []
    for line in text.splitlines():
        stripped = line.strip()
        if len(stripped) < 4:
            continue
        rev = stripped[::-1]
        for prefix in known_prefixes:
            if prefix in rev:
                idx = rev.index(prefix)
                tail = rev[idx:]
                # If there's a closing brace, extract the complete flag
                if "}" in tail:
                    end = tail.index("}") + 1
                    fragment = tail[:end]
                else:
                    # Partial fragment -- stop at earliest delimiter
                    fragment = tail
                    earliest = len(fragment)
                    for stop_ch in (" ", "@", '"', "'", "\t", "\\"):
                        pos = fragment.find(stop_ch, len(prefix))
                        if pos != -1 and pos < earliest:
                            earliest = pos
                    fragment = fragment[:earliest]
                fragment = fragment.strip()
                if len(fragment) >= 4 and fragment not in results:
                    results.append(fragment)
    return results


def _assemble_fragments(fragments: list[str], flag_format: str) -> str | None:
    """Try combining decoded fragments to form a complete flag."""
    if not fragments:
        return None
    # Filter to ASCII-printable, flag-relevant fragments (skip binary garbage)
    clean = list(dict.fromkeys(
        f for f in fragments
        if len(f) >= 3 and f.isascii() and f.isprintable()
        and any(c.isalnum() for c in f)
    ))
    if not clean or len(clean) > 8:
        return None
    from itertools import permutations
    # Build the pattern to match
    pat = flag_format or r"[A-Za-z0-9_]+\{[^}]+\}"
    # Try concatenation in all orderings (limit to 4 fragments to avoid factorial explosion)
    for r in range(2, min(len(clean), 5) + 1):
        for perm in permutations(clean, r):
            combined = "".join(perm)
            m = re.search(pat, combined)
            if m:
                return m.group(0)
    return None


def _decode_eml_file(filepath: str, flag_format: str = "") -> list[str]:
    """Parse a MIME .eml file, decode all parts, and search for flags.

    Walks all MIME parts, base64-decodes encoded parts, URL-decodes any
    percent-encoded content (common in phishing email JS payloads), and
    searches all decoded text for flag patterns.
    """
    try:
        raw = open(filepath, "rb").read()
    except OSError:
        return []

    msg = email.message_from_bytes(raw)
    candidates: list[str] = []

    for part in msg.walk():
        # Skip multipart containers
        if part.get_content_maintype() == "multipart":
            continue

        # Get decoded payload (handles base64/quoted-printable via get_payload(decode=True))
        payload = part.get_payload(decode=True)
        if not payload:
            continue

        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:
            continue

        # URL-decode the text (handles %xx sequences in JS like unescape())
        try:
            url_decoded = urllib.parse.unquote(text)
        except Exception:
            url_decoded = text

        # Search both raw decoded and URL-decoded text
        for content in (text, url_decoded):
            # Direct flag search
            flags = _find_flags([content], flag_format)
            candidates.extend(flags)

            # Also run all standard decoders on the content
            candidates.extend(_decode_base64_strings(content))
            candidates.extend(_decode_hex_strings(content))
            candidates.extend(_extract_chr_sequences(content))

    return candidates


def _scan_plaintext_flags(text: str, flag_format: str = "") -> list[str]:
    """Scan raw text for plaintext flags matching common CTF flag patterns.

    This catches flags stored in plaintext (e.g. in flag.txt, README, source
    comments) that aren't encoded in any way.
    """
    results = []
    # Build pattern from flag_format if provided (e.g. "flag{" -> flag\{.+?\})
    if flag_format:
        prefix_m = re.match(r'([A-Za-z0-9_]+)\{', flag_format.replace('\\', ''))
        if prefix_m:
            prefix = re.escape(prefix_m.group(1))
            # Match the prefix{ ... } with at least 2 chars in body
            pat = re.compile(prefix + r'\{[^}]{2,}\}')
            for m in pat.finditer(text):
                results.append(m.group(0))

    # Generic flag pattern: word{ ... } with at least 3 chars in body
    generic = re.compile(r'[a-zA-Z_]{2,20}\{[^}]{3,}\}')
    for m in generic.finditer(text):
        candidate = m.group(0)
        if candidate not in results:
            results.append(candidate)

    return results


def scan_file(filepath: str, flag_format: str = "") -> list[str]:
    """Scan a single file for encoded content and return decoded candidates."""
    try:
        text = open(filepath, encoding="utf-8", errors="replace").read()
    except OSError:
        return []

    candidates = []

    # Strategy -1: Plaintext flag search (catches flags stored as-is in flag.txt etc.)
    plaintext_flags = _scan_plaintext_flags(text, flag_format)
    candidates.extend(plaintext_flags)

    # Strategy 0: MIME/EML parsing (email forensics)
    ext = os.path.splitext(filepath)[1].lower()
    if ext == ".eml":
        eml_results = _decode_eml_file(filepath, flag_format)
        candidates.extend(eml_results)

    # Strategy 0a: PHP obfuscation tracing (function-alias chains)
    # Run first -- if it produces a complete flag, it's the highest quality result.
    if ext == ".php":
        php_results = _trace_php_obfuscated(text)
        candidates.extend(php_results)

    # Strategy 0b: Scattered single-char literals (Python obfuscation)
    if ext == ".py":
        scattered = _extract_scattered_chars(text)
        candidates.extend(scattered)

    # Strategy 0c: Shell script flag assembly (variable concatenation)
    if ext == ".sh":
        shell_results = _extract_shell_flag_assembly(text)
        candidates.extend(shell_results)

    # Strategy 0d: Rust macro-obfuscated strings (obfstr!, include_str!, etc.)
    if ext in (".rs", ".toml"):
        rust_results = _extract_rust_macro_strings(text)
        candidates.extend(rust_results)

    # Strategy 0e: C/C++ __attribute__((constructor)) strings
    if ext in (".c", ".h", ".cpp", ".cc", ".cxx", ".hpp"):
        c_attr_results = _extract_c_constructor_strings(text)
        candidates.extend(c_attr_results)

    # Strategy 0f: Go //go:embed and const/var flag strings
    if ext == ".go":
        go_results = _extract_go_embed_strings(text)
        candidates.extend(go_results)

    # Strategy 0g: Reversed flag fragments (any file type)
    reversed_frags = _extract_reversed_flag_fragments(text)
    candidates.extend(reversed_frags)

    candidates.extend(_decode_base64_strings(text))
    candidates.extend(_decode_hex_strings(text))
    candidates.extend(_extract_chr_sequences(text))
    candidates.extend(_extract_js_arrays(text))
    candidates.extend(_simulate_shell_commands(text))

    # Second pass: try to execute decoded strings that look like shell commands
    # (catches base64-encoded shell commands like in PHP challenges)
    candidates.extend(_execute_decoded_shell_commands(candidates))

    return candidates


def main():
    if len(sys.argv) < 2:
        print("Usage: auto_source_decode.py <file_or_dir> [--flag-format FORMAT]", file=sys.stderr)
        sys.exit(1)

    target = sys.argv[1]
    flag_format = ""
    if "--flag-format" in sys.argv:
        idx = sys.argv.index("--flag-format")
        if idx + 1 < len(sys.argv):
            flag_format = sys.argv[idx + 1]

    SOURCE_EXTS = {".js", ".php", ".py", ".rb", ".pl", ".sh", ".c", ".h",
                    ".cpp", ".cc", ".cxx", ".hpp", ".rs", ".go", ".toml",
                    ".txt", ".html", ".xml", ".json", ".yml", ".yaml",
                    ".cfg", ".conf", ".ini", ".bat", ".ps1", ".vbs", ".eml"}
    ARCHIVE_EXTS = {".zip", ".gz", ".tar", ".tgz", ".bz2"}

    # Extract any archives found in the target directory
    extract_dirs: list[str] = []
    if os.path.isdir(target):
        for root, _dirs, fnames in os.walk(target):
            for name in fnames:
                ext = os.path.splitext(name)[1].lower()
                if ext in ARCHIVE_EXTS:
                    archive_path = os.path.join(root, name)
                    import tempfile, zipfile, tarfile
                    tmpdir = tempfile.mkdtemp(prefix="source_decode_")
                    extract_dirs.append(tmpdir)
                    try:
                        if zipfile.is_zipfile(archive_path):
                            with zipfile.ZipFile(archive_path) as zf:
                                zf.extractall(tmpdir)
                        elif tarfile.is_tarfile(archive_path):
                            with tarfile.open(archive_path) as tf:
                                tf.extractall(tmpdir)
                    except Exception:
                        pass

    # Priority scan: look for flag.txt files first (common CTF pattern)
    # These often contain the flag in plaintext and should be checked before
    # any decoding strategies.
    FLAG_FILENAMES = {"flag.txt", "flag", "FLAG.txt", "FLAG"}
    MAX_DEPTH = 4  # Don't recurse too deep

    if os.path.isdir(target):
        for root, _dirs, fnames in os.walk(target):
            # Enforce max depth
            depth = root[len(target):].count(os.sep)
            if depth >= MAX_DEPTH:
                _dirs.clear()
                continue
            for name in fnames:
                if name in FLAG_FILENAMES:
                    fpath = os.path.join(root, name)
                    try:
                        if os.path.getsize(fpath) < 500_000:
                            content = open(fpath, encoding="utf-8", errors="replace").read()
                            plaintext_flags = _scan_plaintext_flags(content, flag_format)
                            if plaintext_flags:
                                best = max(plaintext_flags, key=len)
                                print(f"=== Found flag in {fpath} ===")
                                print(f"\nEXTRACTED FLAG: {best}")
                                sys.exit(0)
                    except OSError:
                        pass

    # Collect files to scan (recursively)
    files = []
    scan_roots = [target] + extract_dirs
    for scan_root in scan_roots:
        if os.path.isdir(scan_root):
            for root, _dirs, fnames in os.walk(scan_root):
                # Enforce max depth
                depth = root[len(scan_root):].count(os.sep)
                if depth >= MAX_DEPTH:
                    _dirs.clear()
                    continue
                for name in fnames:
                    ext = os.path.splitext(name)[1].lower()
                    if ext in SOURCE_EXTS or ext == "":
                        fpath = os.path.join(root, name)
                        # Skip very large files
                        try:
                            if os.path.getsize(fpath) < 500_000:
                                files.append(fpath)
                        except OSError:
                            pass
        elif os.path.isfile(scan_root):
            files.append(scan_root)

    if not files:
        print(f"No scannable files found in: {target}", file=sys.stderr)
        sys.exit(1)

    all_candidates = []
    for f in files:
        candidates = scan_file(f, flag_format)
        all_candidates.extend(candidates)

    if not all_candidates:
        print("No encoded content found", file=sys.stderr)
        sys.exit(1)

    # Print all decoded strings (deduped)
    seen = set()
    print("=== Decoded strings found ===")
    for c in all_candidates:
        if c in seen:
            continue
        seen.add(c)
        print(f"  {c}")

    # Check for flags
    flags = _find_flags(all_candidates, flag_format)

    # Fragment assembly: always try combining fragments (may produce longer/better flag)
    assembled = _assemble_fragments(all_candidates, flag_format)
    if assembled:
        flags.append(assembled)
        print(f"  [assembled from fragments] {assembled}")

    if flags:
        # Print the best flag (longest)
        best = max(flags, key=len)
        print(f"\nEXTRACTED FLAG: {best}")
    else:
        # Output all candidates so tool_router's prefix-wrap logic can try.
        # Preserve insertion order -- reversed variants come AFTER originals,
        # and _check_for_flag iterates from bottom up, so reversed (more
        # likely correct) variants get found first.
        print("\n=== No flag pattern matched, raw candidates: ===")
        seen_raw = set()
        for c in all_candidates:
            c = c.strip()
            if len(c) >= 4 and c not in seen_raw and c.isprintable():
                seen_raw.add(c)
                print(c)


if __name__ == "__main__":
    main()
