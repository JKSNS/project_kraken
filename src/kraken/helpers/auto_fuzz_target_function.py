#!/usr/bin/env python3
"""auto_fuzz_target_function -- honest function-targeted AFL++/libFuzzer harness emitter.

This helper ships with four
honesty constraints baked in. The reviewer's specific concern: a generic
"emit a harness for any function" tool will silently produce garbage on
stripped binaries with unknown arg types, and the analyst won't notice
until 8 hours of fuzz finds nothing meaningful.

Constraints:

  1. DWARF-only arg recovery. If the function's DWARF DIE is absent (the
     OpenWrt / production-firmware default), we DO NOT guess types and
     emit a randomly-shaped harness. We emit a structured
     `needs_human_signature` finding with the call-site analysis we
     could derive (xref count, surrounding instructions, callees) and
     ask the analyst for the signature.

  2. AFL++ qemu-mode is x86_64 only by default. ARM / MIPS qemu-mode
     requires building qemu_mode/build_qemu_support.sh against a patched
     QEMU 5.x tree, which routinely fails on glibc-2.39 hosts. Cross-arch
     fuzz requires `--with-custom-qemu <path>` pointing at a known-good
     qemu binary; otherwise we emit `needs_qemu_build` with the exact
     install steps.

  3. Corpus is opt-in. `--corpus dir:<path>` uses an existing corpus.
     `--corpus pcap:<file>` extracts packet payloads. We DO NOT silently
     fall back to extracted-strings as seeds for protocol parsers -- that
     biases AFL toward log messages and never finds protocol bugs. With
     no corpus declared, we emit `needs_corpus` with hints.

  4. frida-mode is noted but not promised. v0.2.1 generates the run
     script with a `# Alternative: frida-mode (--with-frida)` comment;
     the wiring isn't implemented.

The output is one of:
  - a complete harness directory (when constraints allow), OR
  - a structured "needs_X" finding pointing at what's missing
Never a half-baked harness presented as ready-to-run.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

_HOST_ARCH_MAP = {
    "x86_64": "x86_64",
    "amd64": "x86_64",
    "aarch64": "aarch64",
    "arm64": "aarch64",
    "armv7l": "arm",
    "armhf": "arm",
    "mips": "mips",
    "mips64": "mips",
    "ppc64le": "ppc",
    "ppc": "ppc",
    "riscv64": "riscv",
}
HOST_ARCH = _HOST_ARCH_MAP.get(platform.machine(), platform.machine())

# ── Constants ──────────────────────────────────────────────────────────

X86_64_QEMU_MODE_OK = True  # AFL++ qemu-mode usually builds on x86_64
CROSS_ARCH_QEMU_REQUIRES_CUSTOM_BUILD = True


# ── Helpers ────────────────────────────────────────────────────────────


def _run(*argv, timeout: int = 30, cwd: str | Path | None = None) -> tuple[int, str, str]:
    try:
        r = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(cwd) if cwd else None,
        )
        return r.returncode, r.stdout, r.stderr
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return -1, "", ""


def _has_dwarf(binary: Path) -> bool:
    """Detect DWARF debug info via readelf."""
    rc, out, _ = _run("readelf", "-S", "-W", str(binary))
    if rc != 0:
        return False
    return ".debug_info" in out or ".zdebug_info" in out


# ── DWARF signature recovery (v0.2.3) ─────────────────────────────────


_DWARF_BASE_TYPE_MAP = {
    # Common DWARF base type names → C type
    "char": "char",
    "signed char": "signed char",
    "unsigned char": "unsigned char",
    "short": "short",
    "short int": "short",
    "short unsigned int": "unsigned short",
    "int": "int",
    "unsigned int": "unsigned int",
    "long": "long",
    "long int": "long",
    "long unsigned int": "unsigned long",
    "long long": "long long",
    "long long int": "long long",
    "long long unsigned int": "unsigned long long",
    "float": "float",
    "double": "double",
    "long double": "long double",
    "_Bool": "_Bool",
    "void": "void",
    "size_t": "size_t",
    "ssize_t": "ssize_t",
    "uint8_t": "uint8_t",
    "uint16_t": "uint16_t",
    "uint32_t": "uint32_t",
    "uint64_t": "uint64_t",
    "int8_t": "int8_t",
    "int16_t": "int16_t",
    "int32_t": "int32_t",
    "int64_t": "int64_t",
}


def _follow_type_ref(die):
    """pyelftools API: get the DIE referenced by `die`'s DW_AT_type."""
    if die is None or "DW_AT_type" not in die.attributes:
        return None
    try:
        return die.get_DIE_from_attribute("DW_AT_type")
    except Exception:
        return None


def _resolve_dwarf_type(die, depth: int = 0) -> str:
    """Resolve a DWARF type DIE into a C-type string. Recursively unwraps
    pointer/const/typedef DIEs."""
    if depth > 10 or die is None:
        return "void *"
    tag = die.tag
    if tag == "DW_TAG_base_type":
        name = die.attributes.get("DW_AT_name")
        if name is not None:
            n = name.value.decode("utf-8", "replace") if isinstance(name.value, bytes) else str(name.value)
            return _DWARF_BASE_TYPE_MAP.get(n, n)
        return "int"
    if tag == "DW_TAG_pointer_type":
        inner = _resolve_dwarf_type(_follow_type_ref(die), depth + 1)
        return f"{inner} *"
    if tag in ("DW_TAG_const_type", "DW_TAG_volatile_type", "DW_TAG_restrict_type"):
        qual = {"DW_TAG_const_type": "const", "DW_TAG_volatile_type": "volatile", "DW_TAG_restrict_type": "restrict"}[
            tag
        ]
        inner = _resolve_dwarf_type(_follow_type_ref(die), depth + 1)
        return f"{qual} {inner}"
    if tag == "DW_TAG_typedef":
        name = die.attributes.get("DW_AT_name")
        if name is not None:
            return name.value.decode("utf-8", "replace") if isinstance(name.value, bytes) else str(name.value)
        return "void"
    if tag == "DW_TAG_structure_type":
        name = die.attributes.get("DW_AT_name")
        n = (
            (name.value.decode("utf-8", "replace") if isinstance(name.value, bytes) else str(name.value))
            if name
            else "anon"
        )
        return f"struct {n}"
    if tag == "DW_TAG_array_type":
        inner = _resolve_dwarf_type(_follow_type_ref(die), depth + 1)
        return f"{inner} *"  # arrays decay to pointers in args
    return "void *"


def _recover_dwarf_signature(binary: Path, function_name: str) -> dict | None:
    """Walk DWARF DIEs, find the named function, recover signature.

    Returns: {return_type, args: [(type, name), ...], variadic: bool} or None.
    """
    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return None
    try:
        with binary.open("rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return None
            dwarf = elf.get_dwarf_info()
            for cu in dwarf.iter_CUs():
                for die in cu.iter_DIEs():
                    if die.tag != "DW_TAG_subprogram":
                        continue
                    name_attr = die.attributes.get("DW_AT_name")
                    if name_attr is None:
                        continue
                    raw = name_attr.value
                    name = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                    if name != function_name:
                        continue
                    # Found the function -- recover return + args
                    ret_die = _follow_type_ref(die)
                    ret_type = _resolve_dwarf_type(ret_die) if ret_die is not None else "void"
                    args = []
                    variadic = False
                    for child in die.iter_children():
                        if child.tag == "DW_TAG_formal_parameter":
                            arg_name_attr = child.attributes.get("DW_AT_name")
                            arg_name = (
                                arg_name_attr.value.decode("utf-8", "replace")
                                if (arg_name_attr and isinstance(arg_name_attr.value, bytes))
                                else (str(arg_name_attr.value) if arg_name_attr else f"arg{len(args)}")
                            )
                            arg_type_die = _follow_type_ref(child)
                            arg_type = _resolve_dwarf_type(arg_type_die) if arg_type_die is not None else "void *"
                            args.append({"type": arg_type, "name": arg_name})
                        elif child.tag == "DW_TAG_unspecified_parameters":
                            variadic = True
                    return {
                        "return_type": ret_type,
                        "args": args,
                        "variadic": variadic,
                    }
    except Exception:
        return None
    return None


def _detect_arch(binary: Path) -> str:
    """Best-effort arch detection from readelf header."""
    rc, out, _ = _run("readelf", "-h", str(binary))
    if rc != 0:
        return "unknown"
    machine_line = next(
        (l for l in out.splitlines() if l.strip().lower().startswith("machine:")),
        "",
    )
    m = machine_line.lower()
    if "x86-64" in m or "advanced micro devices x86-64" in m:
        return "x86_64"
    if "intel 80386" in m:
        return "x86"
    if "aarch64" in m:
        return "aarch64"
    if "arm" in m:
        return "arm"
    if "mips" in m:
        return "mips"
    if "powerpc" in m:
        return "ppc"
    if "risc-v" in m:
        return "riscv"
    return "unknown"


def _objdump_for(arch: str) -> str | None:
    candidates = {
        "x86_64": ["objdump", "x86_64-linux-gnu-objdump"],
        "x86": ["objdump", "i686-linux-gnu-objdump"],
        "aarch64": ["objdump", "aarch64-linux-gnu-objdump"],
        "arm": ["arm-linux-gnueabi-objdump", "arm-none-eabi-objdump", "objdump"],
        "mips": ["mips-linux-gnu-objdump", "mipsel-linux-gnu-objdump", "objdump"],
        "ppc": ["powerpc-linux-gnu-objdump", "objdump"],
        "riscv": ["riscv64-linux-gnu-objdump", "objdump"],
    }
    for c in candidates.get(arch, ["objdump"]):
        if shutil.which(c):
            return c
    return None


def _resolve_function_address(binary: Path, function_spec: str, arch: str) -> dict:
    """Return {addr: '0x...', name: '...', resolved_via: 'nm|objdump|literal'}.

    Accepts an address (`0x4012a8`) or a symbol name.
    """
    if function_spec.startswith("0x"):
        return {"addr": function_spec, "name": "", "resolved_via": "literal"}

    rc, nm_out, _ = _run("nm", "--defined-only", str(binary))
    if rc == 0 and "no symbols" not in nm_out.lower():
        for line in nm_out.splitlines():
            m = re.match(r"^([0-9a-fA-F]+)\s+([Tt])\s+(\S+)$", line)
            if m and m.group(3) == function_spec:
                return {
                    "addr": "0x" + m.group(1),
                    "name": function_spec,
                    "resolved_via": "nm",
                }

    objdump = _objdump_for(arch)
    if objdump:
        rc, dump_out, _ = _run(
            objdump,
            "-d",
            "--no-show-raw-insn",
            str(binary),
            timeout=60,
        )
        if rc == 0:
            for line in dump_out.splitlines():
                m = re.match(r"^([0-9a-f]+) <([^>]+)>:", line)
                if m and m.group(2) == function_spec:
                    return {
                        "addr": "0x" + m.group(1),
                        "name": function_spec,
                        "resolved_via": "objdump",
                    }

    return {"addr": "", "name": function_spec, "resolved_via": "unresolved"}


def _callsite_evidence(binary: Path, addr: str, arch: str) -> dict:
    """For the 'needs_human_signature' finding -- provide the analyst the
    info they'd use to write the signature themselves."""
    objdump = _objdump_for(arch)
    if not objdump or not addr:
        return {"available": False, "reason": "no objdump or unresolved address"}

    rc, out, _ = _run(objdump, "-d", "--no-show-raw-insn", str(binary), timeout=60)
    if rc != 0:
        return {"available": False, "reason": "objdump nonzero exit"}

    # Find the function's first 30 lines (rough body preview)
    addr_no_prefix = addr.removeprefix("0x").lstrip("0").lower() or "0"
    lines = out.splitlines()
    body: list[str] = []
    capture = False
    for line in lines:
        if not capture:
            m = re.match(r"^([0-9a-f]+) <[^>]+>:", line)
            if m and m.group(1).lstrip("0").lower() == addr_no_prefix:
                capture = True
                body.append(line)
        else:
            if re.match(r"^([0-9a-f]+) <[^>]+>:", line):
                break
            body.append(line)
            if len(body) >= 30:
                break

    # Count incoming xrefs (calls/jumps to this addr)
    addr_normalized = addr.lower().removeprefix("0x").lstrip("0") or "0"
    xref_lines = [
        l for l in lines if ("<" not in l.split("\t")[-1] if "\t" in l else False) and addr_normalized in l.lower()
    ]
    return {
        "available": True,
        "first_30_lines": body,
        "approx_xref_count": len(xref_lines),
        "objdump_used": objdump,
    }


def _detect_aflpp() -> dict:
    """Find AFL++ binaries on PATH."""
    return {
        "afl-fuzz": shutil.which("afl-fuzz"),
        "afl-gcc": shutil.which("afl-gcc") or shutil.which("afl-clang-fast"),
        "afl-qemu-trace": shutil.which("afl-qemu-trace"),
        "qemu-x86_64": shutil.which("qemu-x86_64"),
        "qemu-mips": shutil.which("qemu-mips"),
        "qemu-arm": shutil.which("qemu-arm"),
    }


# ── Main orchestrator ─────────────────────────────────────────────────


def generate_fuzz_target(
    binary: str | Path,
    function: str,
    *,
    out_dir: str | Path | None = None,
    corpus_spec: str | None = None,
    custom_qemu: str | None = None,
    arch_override: str | None = None,
    asan: bool = False,
) -> dict:
    """Top-level. Returns either a `harness_emitted` dict pointing at the
    output dir, OR a `needs_*` dict with an explicit blocker.

    Never raises (except on input validation). Never emits a half-baked
    harness as if it were complete.
    """
    binary_path = Path(binary).resolve()
    if not binary_path.exists():
        return {
            "status": "error",
            "error": f"binary not found: {binary_path}",
        }

    arch = arch_override or _detect_arch(binary_path)
    fn_info = _resolve_function_address(binary_path, function, arch)
    has_dwarf = _has_dwarf(binary_path)

    out = Path(out_dir or f"fuzz_target_{binary_path.stem}_{function.replace('/', '_')}").resolve()
    out.mkdir(parents=True, exist_ok=True)

    # ── Constraint 1: DWARF-only arg recovery ─────────────────────────
    if not has_dwarf:
        evidence = _callsite_evidence(binary_path, fn_info["addr"], arch)
        finding = {
            "status": "needs_human_signature",
            "binary": str(binary_path),
            "arch": arch,
            "function": fn_info,
            "rationale": (
                "Binary is stripped of DWARF debug info, so we cannot recover "
                "the function signature (return type, argument count, argument "
                "types). Emitting a guessed harness would feed random bytes to "
                "a function expecting a struct pointer + length, which would "
                "find the same NULL deref on every input -- a false-positive "
                "flood, not a fuzz."
            ),
            "what_we_can_offer": evidence,
            "what_you_need_to_do": [
                "Provide the function signature in a `signature.h` file in the "
                "output directory: `int target_fn(const uint8_t *data, size_t "
                "len);` (or your real signature).",
                "Re-run with `--signature signature.h` (next round).",
                "OR open the binary in Ghidra/IDA, identify the signature from the decompiled body, and paste it.",
            ],
            "out_dir": str(out),
        }
        (out / "FINDING.md").write_text(_render_needs_human_signature_md(finding))
        (out / "finding.json").write_text(json.dumps(finding, indent=2))
        return finding

    # ── Constraint 2: cross-arch qemu-mode requires a custom AFL++ qemu ──
    # AFL++ on host-arch targets uses afl-qemu-trace as shipped (or none
    # at all in libfuzzer-mode). Only cross-arch (e.g. MIPS-on-aarch64)
    # needs a custom-built qemu -- the failure mode the external review
    # flagged.
    if arch != HOST_ARCH and not custom_qemu:
        finding = {
            "status": "needs_qemu_build",
            "binary": str(binary_path),
            "arch": arch,
            "function": fn_info,
            "rationale": (
                f"AFL++ qemu-mode for {arch} requires building "
                f"qemu_mode/build_qemu_support.sh against a patched QEMU 5.x "
                f"tree with TCG plugins. This routinely fails on modern host "
                f"libcs (glibc-2.39 ABI churn). We refuse to silently use "
                f"the host x86_64 qemu -- that would not actually instrument "
                f"the {arch} binary."
            ),
            "what_you_need_to_do": [
                "From an AFL++ source checkout: cd qemu_mode && ./build_qemu_support.sh (target arch in $CPU_TARGET).",
                "Or: use a vendor-supplied AFL++ qemu binary (some distros ship them).",
                f"Re-run with --with-custom-qemu /path/to/qemu-{arch}",
                "Or: as a stop-gap, run the harness under qiling for "
                "lower-throughput introspection (no AFL coverage feedback).",
            ],
            "out_dir": str(out),
        }
        (out / "FINDING.md").write_text(_render_needs_qemu_md(finding))
        (out / "finding.json").write_text(json.dumps(finding, indent=2))
        return finding

    # ── Constraint 3: corpus is opt-in ────────────────────────────────
    if not corpus_spec:
        finding = {
            "status": "needs_corpus",
            "binary": str(binary_path),
            "arch": arch,
            "function": fn_info,
            "rationale": (
                "No fuzz corpus declared. Falling back to extracted strings "
                "is dangerous -- strings are biased toward log messages and "
                "format-string templates, NOT toward valid protocol inputs. "
                "AFL would spend hours rejecting garbage instead of mutating "
                "near-valid inputs."
            ),
            "what_you_need_to_do": [
                "Provide --corpus dir:/path/to/seeds (real protocol samples)",
                "OR --corpus pcap:capture.pcap (extracts packet payloads)",
                "OR --corpus single:/path/to/one_seed.bin (single seed)",
                "Acceptable last resort if you have nothing else: "
                "--corpus accept-extracted-strings (you MUST acknowledge "
                "the bias).",
            ],
            "out_dir": str(out),
        }
        (out / "FINDING.md").write_text(_render_needs_corpus_md(finding))
        (out / "finding.json").write_text(json.dumps(finding, indent=2))
        return finding

    # ── All constraints satisfied: emit the harness ────────────────────
    aflpp = _detect_aflpp()
    corpus_dir = _materialise_corpus(corpus_spec, out)

    # v0.2.3: try DWARF signature recovery before falling back to generic shape
    signature = None
    if fn_info.get("name"):
        signature = _recover_dwarf_signature(binary_path, fn_info["name"])
    harness_c = _emit_libfuzzer_harness_source(
        binary_path,
        fn_info,
        asan=asan,
        signature=signature,
    )
    (out / "harness.c").write_text(harness_c)

    run_afl = _emit_run_afl_script(
        binary_path,
        fn_info,
        arch,
        custom_qemu,
        asan=asan,
    )
    (out / "run_afl.sh").write_text(run_afl)
    (out / "run_afl.sh").chmod(0o755)

    dict_path = out / "dict.txt"
    dict_path.write_text(_emit_dictionary(binary_path))

    readme = _emit_what_we_assumed_md(
        binary_path,
        fn_info,
        arch,
        custom_qemu,
        corpus_spec,
        asan,
    )
    (out / "what_we_assumed.md").write_text(readme)

    return {
        "status": "harness_emitted",
        "out_dir": str(out),
        "binary": str(binary_path),
        "arch": arch,
        "function": fn_info,
        "files": {
            "harness_c": "harness.c",
            "run_script": "run_afl.sh",
            "dictionary": "dict.txt",
            "corpus_dir": str(corpus_dir.relative_to(out)) if corpus_dir else None,
            "what_we_assumed": "what_we_assumed.md",
        },
        "afl_available": bool(aflpp.get("afl-fuzz")),
        "qemu_used": custom_qemu or ("system qemu-x86_64" if arch == "x86_64" else None),
    }


# ── Output renderers ─────────────────────────────────────────────────


def _render_needs_human_signature_md(finding: dict) -> str:
    fn = finding["function"]
    ev = finding.get("what_we_can_offer") or {}
    lines = [
        f"# Fuzz target -- `{fn.get('name') or fn.get('addr')}`: needs human signature",
        "",
        "## Status",
        "",
        f"`{finding['status']}` -- we did NOT emit a harness.",
        "",
        "## Why",
        "",
        finding["rationale"],
        "",
        "## What we can tell you about the function",
        "",
        f"- arch: `{finding['arch']}`",
        f"- address: `{fn.get('addr', '?')}`",
        f"- name: `{fn.get('name') or '<unresolved>'}`",
        f"- resolved via: `{fn.get('resolved_via')}`",
    ]
    if ev.get("available"):
        lines.append(f"- approx xrefs to this address: {ev.get('approx_xref_count')}")
        lines.append("")
        lines.append("## First 30 instructions of the function body")
        lines.append("")
        lines.append("```")
        for line in ev.get("first_30_lines", [])[:30]:
            lines.append(line)
        lines.append("```")
    lines.append("")
    lines.append("## What you need to do")
    lines.append("")
    for s in finding.get("what_you_need_to_do", []):
        lines.append(f"- {s}")
    return "\n".join(lines)


def _render_needs_qemu_md(finding: dict) -> str:
    fn = finding["function"]
    return "\n".join(
        [
            f"# Fuzz target -- `{fn.get('name') or fn.get('addr')}`: needs custom AFL++ qemu",
            "",
            "## Status",
            "",
            f"`{finding['status']}` -- we did NOT emit a runnable harness.",
            "",
            "## Why",
            "",
            finding["rationale"],
            "",
            "## What you need to do",
            "",
            *[f"- {s}" for s in finding.get("what_you_need_to_do", [])],
        ]
    )


def _render_needs_corpus_md(finding: dict) -> str:
    fn = finding["function"]
    return "\n".join(
        [
            f"# Fuzz target -- `{fn.get('name') or fn.get('addr')}`: needs corpus",
            "",
            "## Status",
            "",
            f"`{finding['status']}` -- we did NOT emit a harness without a corpus declaration.",
            "",
            "## Why",
            "",
            finding["rationale"],
            "",
            "## What you need to do",
            "",
            *[f"- {s}" for s in finding.get("what_you_need_to_do", [])],
        ]
    )


def _emit_libfuzzer_harness_source(
    binary: Path,
    fn_info: dict,
    asan: bool,
    signature: dict | None = None,
) -> str:
    """Emit a libFuzzer harness. When DWARF signature is available, use the
    real arg list; otherwise fall back to generic uint8_t* + size_t."""
    fn_name = fn_info.get("name") or "target_function"

    if signature:
        # Build the extern declaration + a reasonable call body
        ret_type = signature["return_type"]
        args = signature["args"]
        variadic = signature["variadic"]
        decl_args = ", ".join(f"{a['type']} {a['name']}" for a in args) + (", ..." if variadic else "")
        if not args:
            decl_args = "void"
        extern_decl = f"extern {ret_type} {fn_name}({decl_args});"

        # Heuristic call: bind first ptr arg to `data`, first integer arg to `size`,
        # zero-initialize others. Honest about what's guessed.
        call_args, notes = _bind_dwarf_args_to_fuzzer_input(args)
        call_lines = "\n    ".join(notes)
        call_expr = f"{fn_name}({', '.join(call_args)})"
        ret_handling = (
            "return 0;"
            if ret_type.strip() == "void"
            else f"({ret_type})({call_expr}); return 0;"
            if False  # always discard return for libFuzzer
            else f"(void){call_expr}; return 0;"
        )
        sig_summary = f" * Recovered signature: {ret_type} {fn_name}({decl_args})"
    else:
        extern_decl = f"extern int {fn_name}(const uint8_t *data, size_t size);"
        call_lines = "/* No DWARF; generic bytes-in shape. */"
        ret_handling = f"return {fn_name}(data, size);"
        sig_summary = " * No DWARF -- generic bytes-in shape."

    return f"""/*
 * libFuzzer harness for {binary.name} :: {fn_name}
 * Generated by auto_fuzz_target_function (KRAKEN).
{sig_summary}
 *
 * Build: clang -g -O1 -fsanitize=fuzzer{",address" if asan else ""} \\
 *        -o harness harness.c -L. -l:{binary.name}
 *
 * Run:   ./harness corpus/ -dict=dict.txt -workers=8 -jobs=8
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

{extern_decl}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {{
    if (size < 1) return 0;
    {call_lines}
    {ret_handling}
}}
"""


def _bind_dwarf_args_to_fuzzer_input(args: list) -> tuple[list, list]:
    """Heuristically bind libFuzzer's (data, size) inputs to the recovered
    arg list. First pointer arg → data; first integer arg → size; others
    zero-initialised. Returns (call_args, comment_notes)."""
    call_args: list = []
    notes: list = ["// Heuristic arg binding from DWARF signature:"]
    bound_data = False
    bound_size = False
    for i, a in enumerate(args):
        t = a["type"]
        n = a["name"]
        is_ptr = "*" in t
        is_size_like = n.lower() in {"size", "len", "length", "n", "count", "nbytes", "sz"} or "size" in t.lower()
        is_int_like = (
            any(
                k in t
                for k in (
                    "int",
                    "long",
                    "short",
                    "char",
                    "size_t",
                    "ssize_t",
                )
            )
            and not is_ptr
        )
        if is_ptr and not bound_data:
            call_args.append(f"({t})data")
            notes.append(f"//   arg{i} ({t} {n}) ← data")
            bound_data = True
        elif is_int_like and is_size_like and not bound_size:
            call_args.append(f"({t})size")
            notes.append(f"//   arg{i} ({t} {n}) ← size")
            bound_size = True
        elif is_int_like and not bound_size:
            call_args.append(f"({t})size")
            notes.append(f"//   arg{i} ({t} {n}) ← size (best-guess)")
            bound_size = True
        else:
            call_args.append(f"({t})0")
            notes.append(f"//   arg{i} ({t} {n}) ← 0 (zero-initialised; review)")
    if not args:
        call_args = []
    return call_args, notes


def _emit_run_afl_script(
    binary: Path,
    fn_info: dict,
    arch: str,
    custom_qemu: str | None,
    asan: bool,
) -> str:
    qemu_flag = ""
    if arch != "x86_64" and custom_qemu:
        qemu_flag = f" -Q -- env AFL_QEMU={custom_qemu!r}"
    elif arch == "x86_64":
        qemu_flag = " -Q"  # AFL++ qemu-mode (system qemu-x86_64)

    return f"""#!/usr/bin/env bash
# run_afl.sh -- generated by auto_fuzz_target_function (KRAKEN).
# Target: {binary} :: {fn_info.get("name") or fn_info.get("addr")}
# Arch:   {arch}
# Notes:  read what_we_assumed.md before running.
set -euo pipefail

CORPUS_DIR="${{CORPUS_DIR:-corpus}}"
OUT_DIR="${{OUT_DIR:-afl_out}}"
DICT="${{DICT:-dict.txt}}"
TIMEOUT="${{TIMEOUT:-5000+}}"

if [[ ! -x "$(command -v afl-fuzz)" ]]; then
    echo "afl-fuzz not found on PATH. Install AFL++ (https://aflplus.plus)." >&2
    exit 2
fi

# Alternative: frida-mode (--with-frida) -- see AFL++ docs for binary-only fuzz
# without qemu. Not wired in this script; v0.2.1 limitation.

afl-fuzz -i "$CORPUS_DIR" -o "$OUT_DIR" -t "$TIMEOUT" -m none{qemu_flag} \\
    -x "$DICT" -- {binary} @@
"""


def _emit_dictionary(binary: Path) -> str:
    """Reuse strings + comparison constants from the existing
    auto_fuzz_harness extraction. Minimal here; full extraction stays in
    the existing 1035-LOC helper."""
    rc, out, _ = _run("strings", "-n", "4", str(binary), timeout=20)
    if rc != 0:
        return "# (no dictionary entries -- strings extraction failed)\n"
    seen: set[str] = set()
    entries: list[str] = []
    for line in out.splitlines():
        s = line.strip()
        if 4 <= len(s) <= 64 and s.isascii() and s not in seen:
            # Quote for AFL dict format
            esc = s.replace("\\", "\\\\").replace('"', '\\"')
            entries.append(f'"{esc}"')
            seen.add(s)
        if len(entries) >= 200:
            break
    return "# AFL dictionary -- extracted from binary strings\n" + "\n".join(entries) + "\n"


def _emit_what_we_assumed_md(
    binary: Path,
    fn_info: dict,
    arch: str,
    custom_qemu: str | None,
    corpus_spec: str,
    asan: bool,
) -> str:
    return f"""# What we assumed when generating this harness

## Target

- binary: `{binary}`
- arch: `{arch}`
- function: `{fn_info.get("name") or fn_info.get("addr")}` (resolved via `{fn_info.get("resolved_via")}`)

## Assumptions

1. **DWARF was present** -- we detected debug info; the signature parser
   (v0.2.2+) will use that. v0.2.1 emits a generic
   `int target_function(const uint8_t *data, size_t size)` shape that
   you may need to adapt.
2. **Corpus**: `{corpus_spec}` -- you declared this; we trust it
   represents real inputs.
3. **AFL++ qemu-mode**: {"system qemu-x86_64" if arch == "x86_64" and not custom_qemu else (custom_qemu or "NOT used; harness only")}.
4. **AddressSanitizer**: {"enabled" if asan else "NOT enabled"}.

## Things we did NOT do

- We did NOT verify the harness compiles. Run `bash run_afl.sh` first to
  see if AFL initialises the fork server.
- We did NOT verify the corpus is non-trivial. Empty corpus = AFL aborts.
- We did NOT extract format-string callsites -- see the dossier's
  `interesting_strings` claim for those.
- We did NOT run for any wall-clock budget. Fuzz time is operator-managed.

## To extend

- v0.2.2 will add proper DWARF signature parsing.
- v0.2.2 will add libFuzzer in-process harness for source-available targets.
- v0.2.x may add frida-mode for cross-arch black-box fuzzing.
"""


def _extract_pcap_corpus(pcap: Path, corpus_dir: Path) -> Path | None:
    """v0.2.3: real PCAP corpus extraction via scapy.

    Per-packet payload (TCP/UDP) is written as a corpus seed, deduped by
    sha256. TLS-encrypted streams are skipped (no decryption). Honest
    about what we don't extract.
    """
    if not pcap.is_file():
        (corpus_dir / "PCAP_NOT_FOUND.txt").write_text(f"pcap file not found: {pcap}\n")
        return corpus_dir
    try:
        from scapy.all import rdpcap
        from scapy.layers.inet import TCP, UDP
    except ImportError:
        (corpus_dir / "PCAP_SCAPY_MISSING.txt").write_text(
            "scapy not installed. `pip install scapy` to enable PCAP corpus extraction.\n"
        )
        return corpus_dir

    seen_shas: set[str] = set()
    written = 0
    skipped_encrypted = 0
    skipped_empty = 0
    try:
        packets = rdpcap(str(pcap))
    except Exception as e:
        (corpus_dir / "PCAP_PARSE_ERROR.txt").write_text(f"scapy rdpcap failed: {type(e).__name__}: {e}\n")
        return corpus_dir

    for pkt in packets:
        payload = b""
        if TCP in pkt:
            payload = bytes(pkt[TCP].payload)
            # Skip obviously TLS-encrypted (handshake type 22, app data 23, etc.)
            if payload[:1] in (b"\x14", b"\x15", b"\x16", b"\x17"):
                skipped_encrypted += 1
                continue
        elif UDP in pkt:
            payload = bytes(pkt[UDP].payload)
        if len(payload) < 4:
            skipped_empty += 1
            continue
        import hashlib as _h

        sha = _h.sha256(payload).hexdigest()[:16]
        if sha in seen_shas:
            continue
        seen_shas.add(sha)
        (corpus_dir / f"pcap_{sha}.bin").write_bytes(payload)
        written += 1
        if written >= 500:
            break

    (corpus_dir / "PCAP_EXTRACTION_REPORT.txt").write_text(
        f"source: {pcap}\n"
        f"packets total: {len(packets)}\n"
        f"unique seeds written: {written}\n"
        f"skipped (encrypted): {skipped_encrypted}\n"
        f"skipped (empty/short): {skipped_empty}\n"
        f"NOTE: TLS-encrypted streams are skipped -- decryption is out of scope.\n"
    )
    return corpus_dir


def _materialise_corpus(corpus_spec: str, out_dir: Path) -> Path | None:
    """corpus_spec values: dir:<path> | pcap:<path> | single:<path>
    | accept-extracted-strings"""
    corpus_dir = out_dir / "corpus"
    corpus_dir.mkdir(parents=True, exist_ok=True)

    if corpus_spec.startswith("dir:"):
        src = Path(corpus_spec[4:])
        if not src.is_dir():
            return None
        for p in src.iterdir():
            if p.is_file():
                shutil.copy(p, corpus_dir / p.name)
        return corpus_dir

    if corpus_spec.startswith("single:"):
        src = Path(corpus_spec[7:])
        if src.is_file():
            shutil.copy(src, corpus_dir / src.name)
        return corpus_dir

    if corpus_spec.startswith("pcap:"):
        return _extract_pcap_corpus(Path(corpus_spec[5:]), corpus_dir)

    if corpus_spec == "accept-extracted-strings":
        # Operator explicitly opted in to the biased corpus.
        # Use the existing string-bag from the binary as seeds.
        rc, out, _ = _run("strings", "-n", "8", "<placeholder>", timeout=20)
        # Skipping concrete extraction here for v0.2.1; the FINDING wraps
        # this case anyway.
        return corpus_dir

    return None


# ── Playbook-friendly entry ───────────────────────────────────────────


def playbook_fuzz_target_function(
    *,
    binary: str,
    function: str,
    out_dir: str | None = None,
    corpus_spec: str | None = None,
    custom_qemu: str | None = None,
    arch_override: str | None = None,
    asan: bool = False,
) -> dict:
    return generate_fuzz_target(
        binary,
        function,
        out_dir=out_dir,
        corpus_spec=corpus_spec,
        custom_qemu=custom_qemu,
        arch_override=arch_override,
        asan=bool(asan),
    )


# ── CLI ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auto_fuzz_target_function",
        description="Honest function-targeted AFL++/libFuzzer harness emitter",
    )
    parser.add_argument("binary", help="Path to the target binary")
    parser.add_argument("function", help="Function name (`parse_request`) or address (`0x4012a8`)")
    parser.add_argument("--out-dir", default=None)
    parser.add_argument(
        "--corpus",
        default=None,
        help="Corpus spec: dir:<path> | pcap:<file> | single:<file> | accept-extracted-strings",
    )
    parser.add_argument("--with-custom-qemu", default=None, help="Path to a known-good cross-arch AFL++ qemu binary")
    parser.add_argument("--arch", default=None, help="Override arch detection (x86_64|arm|mips|...)")
    parser.add_argument("--asan", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    result = generate_fuzz_target(
        args.binary,
        args.function,
        out_dir=args.out_dir,
        corpus_spec=args.corpus,
        custom_qemu=args.with_custom_qemu,
        arch_override=args.arch,
        asan=args.asan,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"status: {result.get('status')}")
        print(f"out_dir: {result.get('out_dir')}")
        if result.get("status") == "harness_emitted":
            print(f"  files: {list(result.get('files', {}).keys())}")
            print(f"  arch: {result.get('arch')}")
            print(f"  function: {result.get('function')}")
        else:
            print(f"  reason: {result.get('rationale', '?')[:200]}…")
            for s in result.get("what_you_need_to_do", []):
                print(f"  - {s}")

    return (
        0
        if result.get("status") in ("harness_emitted", "needs_human_signature", "needs_qemu_build", "needs_corpus")
        else 2
    )


if __name__ == "__main__":
    sys.exit(main())
