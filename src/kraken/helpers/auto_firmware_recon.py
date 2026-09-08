#!/usr/bin/env python3
"""auto_firmware_recon -- orchestrate week-1 firmware analysis helpers.

Runs the bare-metal recon helpers in one shot, producing a single
`firmware_recon.json` artifact that downstream cascade nodes consume.

Per `docs/kraken_research_mode_synthesis.md`, this is the entrypoint
for "research-target" workspaces. It detects what the inputs allow
(unstripped ELF? sibling builds? linker script? source tree? prior
exploits?) and runs the helpers that fit, never failing if a helper
can't run -- degraded outputs are better than no outputs.

Usage:
    python3 auto_firmware_recon.py <target_dir> [--out PATH]

Output schema:
{
  "target_dir": "<path>",
  "schema_version": "1.0",
  "elapsed_seconds": N,
  "is_research_target": bool,
  "detection": {
    "has_firmware_dir": bool,
    "has_unstripped_elf": bool,
    "has_dwarf": bool,
    "has_linker_script": bool,
    "has_sibling_builds": bool,
    "has_existing_exploits": bool,
    "is_cortex_m": bool
  },
  "components": {
    "secrets_diff":         <output of auto_secrets_diff>,
    "memory_map":           <output of auto_memory_map>,
    "structs":              <output of auto_dwarf_structs>,
    "decompile":            <output of auto_unstripped_decompile (filtered)>,
    "existing_exploits":    <output of auto_existing_exploits>
  },
  "warnings": [...]
}
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

import auto_dwarf_structs
import auto_existing_exploits
import auto_ingress_contracts
import auto_memory_map

# Local helper imports -- same package
import auto_secrets_diff
import auto_source_structs
import auto_source_structs_rust
import auto_unstripped_decompile
from elftools.elf.elffile import ELFFile

KEY_SYMBOLS = (
    "check_pin",
    "validate_challenge_response",
    "validate_permission",
    "main",
    "init",
    "read_packet",
    "write_packet",
    "list",
    "read",
    "write",
    "receive",
    "interrogate",
    "listen",
    "go_to_jail",
    "check_jail",
    "mpu_init",
    "__stack_chk_fail",
)

# Vendor / build / cache directories to skip when walking source trees.
# Used by detection scans + every source-mode helper invocation in
# run_recon() so the heuristics stay consistent.
SKIP = {
    # Crypto libs
    "wolfssl",
    "openssl",
    "mbedtls",
    "libsodium",
    # MCU vendor SDKs
    "driverlib",
    "tivaware",
    "ti_drivers",
    "ti-cgt",
    "stm32cube",
    "stm32f",
    "stm32l",
    "stm32h",
    "cmsis",
    "nrf",
    "esp-idf",
    "freertos",
    # Build/cache/IDE
    "node_modules",
    ".git",
    "__pycache__",
    "target",
    "vendor",
    "build",
    ".venv",
    "venv",
    ".cache",
}


def detect(target_dir: Path) -> dict[str, Any]:
    """Inspect the target dir to decide which helpers can run."""
    detection: dict[str, Any] = {
        "has_firmware_dir": False,
        "has_unstripped_elf": False,
        "has_dwarf": False,
        "has_linker_script": False,
        "has_sibling_builds": False,
        "has_existing_exploits": False,
        "is_cortex_m": False,
        "elf_paths": [],
        "bin_paths": [],
        "linker_script": None,
        "preferred_elf": None,
        # Source-mode signals (when no ELF ships)
        "has_c_source": False,
        "has_rust_source": False,
        "language": None,
    }

    # Firmware dir hint
    for d in target_dir.rglob("firmware"):
        if d.is_dir():
            detection["has_firmware_dir"] = True
            break

    # Find ELFs (skip vendored crypto + MCU SDKs + build artefacts; SKIP at module level)
    elfs = []
    bins = []
    for path in target_dir.rglob("*.elf"):
        if any(p.lower() in SKIP for p in path.parts):
            continue
        elfs.append(path)
    for path in target_dir.rglob("*.bin"):
        if any(p.lower() in SKIP for p in path.parts):
            continue
        bins.append(path)

    detection["elf_paths"] = [str(p) for p in elfs]
    detection["bin_paths"] = [str(p) for p in bins]

    # Sibling builds = >1 .bin files of the same size
    if len(bins) >= 2:
        sizes = {p: p.stat().st_size for p in bins}
        from collections import Counter

        most_common_size, count = Counter(sizes.values()).most_common(1)[0]
        if count >= 2:
            detection["has_sibling_builds"] = True
            detection["sibling_bins"] = [str(p) for p, s in sizes.items() if s == most_common_size]

    # Pick a "preferred" ELF (largest with DWARF -- typically the dev build)
    best_elf = None
    best_score = -1
    for elf_path in elfs:
        try:
            with open(elf_path, "rb") as f:
                elf = ELFFile(f)
                e_machine = elf["e_machine"]
                if e_machine == "EM_ARM":
                    detection["is_cortex_m"] = True
                has_dwarf = elf.has_dwarf_info()
                symtab = elf.get_section_by_name(".symtab")
                is_unstripped = symtab is not None and symtab.num_symbols() > 10
                if has_dwarf:
                    detection["has_dwarf"] = True
                if is_unstripped:
                    detection["has_unstripped_elf"] = True
                # Score: prefer DWARF + unstripped + size
                score = (1000 if has_dwarf else 0) + (500 if is_unstripped else 0) + elf_path.stat().st_size // 1024
                if score > best_score:
                    best_score = score
                    best_elf = elf_path
        except Exception:
            continue

    detection["preferred_elf"] = str(best_elf) if best_elf else None

    # Linker script
    for ext in ("*.ld", "*.cmd"):
        for ld in target_dir.rglob(ext):
            if any(p.lower() in SKIP for p in ld.parts):
                continue
            detection["linker_script"] = str(ld)
            detection["has_linker_script"] = True
            break
        if detection["has_linker_script"]:
            break

    # Existing exploits
    EXPLOIT_PATTERNS = (
        "solve*.py",
        "exploit*.py",
        "pwn*.py",
        "attack*.py",
        "exp.py",
    )
    for pat in EXPLOIT_PATTERNS:
        if any(target_dir.rglob(pat)):
            detection["has_existing_exploits"] = True
            break

    # Source-language detection (used when no ELF ships)
    has_c, has_rust, has_cargo = False, False, False
    rust_skip = SKIP | {"target", "vendor", "ascon-c"}
    c_skip = SKIP | {"target", "vendor"}
    for path in target_dir.rglob("Cargo.toml"):
        if any(p.lower() in rust_skip for p in path.parts):
            continue
        has_cargo = True
        break
    for path in target_dir.rglob("*.h"):
        if any(p.lower() in c_skip for p in path.parts):
            continue
        has_c = True
        break
    if not has_c:
        for path in target_dir.rglob("*.c"):
            if any(p.lower() in c_skip for p in path.parts):
                continue
            has_c = True
            break
    for path in target_dir.rglob("*.rs"):
        if any(p.lower() in rust_skip for p in path.parts):
            continue
        has_rust = True
        break
    detection["has_c_source"] = has_c
    detection["has_rust_source"] = has_rust
    detection["has_cargo_toml"] = has_cargo
    # Primary-language hint: if Cargo.toml is present in firmware/, treat as
    # Rust-primary. Vendored C in ascon-c/etc. shouldn't override that.
    if has_cargo:
        detection["language"] = "rust"
    elif has_c and has_rust:
        detection["language"] = "c+rust"
    elif has_c:
        detection["language"] = "c"
    elif has_rust:
        detection["language"] = "rust"

    return detection


def run_recon(target_dir: Path) -> dict[str, Any]:
    start = time.time()
    detection = detect(target_dir)
    components: dict[str, Any] = {}
    warnings: list[str] = []

    # secrets_diff: needs ≥2 sibling builds
    if detection["has_sibling_builds"]:
        try:
            sibling_paths = [Path(p) for p in detection["sibling_bins"]]
            components["secrets_diff"] = auto_secrets_diff.analyze(sibling_paths, exclude_outliers=True)
        except Exception as e:
            warnings.append(f"secrets_diff failed: {e}")

    # memory_map: ELF + linker script preferred; falls back to linker-only
    # for source-only repos (still gets RAM/flash region table).
    if detection["preferred_elf"] or detection["has_linker_script"]:
        try:
            elf = Path(detection["preferred_elf"]) if detection["preferred_elf"] else None
            ld = Path(detection["linker_script"]) if detection["has_linker_script"] else None
            components["memory_map"] = auto_memory_map.analyze(elf, ld)
        except Exception as e:
            warnings.append(f"memory_map failed: {e}")

    # structs: prefer DWARF (ground truth); fall back to source-mode
    # (tree-sitter) when no ELF ships. The source extractor produces the
    # same JSON schema, so downstream consumers don't care which path ran.
    if detection["has_dwarf"] and detection["preferred_elf"]:
        try:
            components["structs"] = auto_dwarf_structs.extract(Path(detection["preferred_elf"]))
            components["structs"]["source"] = "dwarf"
        except Exception as e:
            warnings.append(f"structs (dwarf) failed: {e}")
    elif detection.get("language") == "rust":
        try:
            sources = []
            for p in target_dir.rglob("*.rs"):
                if any(part in {".git", "target", "vendor", "ascon-c"} for part in p.parts):
                    continue
                sources.append(p)
            if sources:
                result = auto_source_structs_rust.extract(sources)
                result["source"] = "tree-sitter-rust"
                components["structs"] = result
        except Exception as e:
            warnings.append(f"structs (tree-sitter-rust) failed: {e}")
    elif detection["has_c_source"]:
        try:
            sources = []
            for ext in ("*.h", "*.c"):
                for p in target_dir.rglob(ext):
                    if any(part.lower() in SKIP for part in p.parts):
                        continue
                    sources.append(p)
            if sources:
                result = auto_source_structs.extract(sources)
                result["source"] = "tree-sitter-c"
                components["structs"] = result
        except Exception as e:
            warnings.append(f"structs (tree-sitter-c) failed: {e}")

    # decompile: needs unstripped ELF; sample only the key symbols
    if detection["has_unstripped_elf"] and detection["preferred_elf"]:
        try:
            import re

            filter_re = re.compile(r"^(" + "|".join(KEY_SYMBOLS) + r")$")
            components["decompile"] = auto_unstripped_decompile.analyze(
                Path(detection["preferred_elf"]), filter_re, insns_per_fn=8
            )
        except Exception as e:
            warnings.append(f"decompile failed: {e}")

    # existing_exploits: always run
    try:
        components["existing_exploits"] = auto_existing_exploits.analyze(target_dir, max_snippet=20)
    except Exception as e:
        warnings.append(f"existing_exploits failed: {e}")

    # ingress_contracts: C-source-mode only (tree-sitter-c keystone helper)
    if detection["has_c_source"] and detection.get("language") in ("c", "c+rust"):
        try:
            sources = []
            for ext in ("*.c", "*.h"):
                for p in target_dir.rglob(ext):
                    if any(part.lower() in SKIP for part in p.parts):
                        continue
                    sources.append(p)
            if sources:
                components["ingress_contracts"] = auto_ingress_contracts.extract(sources)
        except Exception as e:
            warnings.append(f"ingress_contracts failed: {e}")

    elapsed = time.time() - start

    is_research = (
        detection["has_firmware_dir"]
        or (detection["has_unstripped_elf"] and detection["has_linker_script"])
        or detection["has_sibling_builds"]
        # eCTF 2024/2025 dropped the `firmware/` convention in favour of
        # `application_processor/` + `component/` (2024) or
        # `decoder/` + `design/` (2025). Trigger research-mode on:
        #   - Rust + Cargo.toml in target tree (firmware-like build), OR
        #   - C source + linker script (any embedded layout)
        or (detection["has_rust_source"] and detection["has_cargo_toml"])
        or (detection["has_c_source"] and detection["has_linker_script"])
    )

    result = {
        "target_dir": str(target_dir),
        "schema_version": "1.0",
        "elapsed_seconds": round(elapsed, 2),
        "is_research_target": is_research,
        "detection": detection,
        "components": components,
        "warnings": warnings,
    }
    # Emit case_state events for downstream consumers
    try:
        import sys as _sys

        _h = str(Path(__file__).resolve().parent)
        if _h not in _sys.path:
            _sys.path.insert(0, _h)
        import auto_case_state as _cs  # type: ignore

        case_id = target_dir.name
        _cs.record(
            case_id,
            "auto_firmware_recon",
            "recon_summary",
            {
                "is_research_target": is_research,
                "language": detection.get("language"),
                "is_cortex_m": detection.get("is_cortex_m"),
                "has_dwarf": detection.get("has_dwarf"),
                "preferred_elf": detection.get("preferred_elf"),
                "components": list(components.keys()),
                "elapsed_s": round(elapsed, 2),
            },
        )
        # Surface ingress anomalies as their own events (downstream
        # consumers can `query(kind="ingress_anomaly")` directly)
        ic = components.get("ingress_contracts", {})
        for cs in ic.get("transport_callsites", []):
            for anom in cs.get("anomalies", []):
                _cs.record(
                    case_id,
                    "auto_firmware_recon",
                    "ingress_anomaly",
                    {
                        "caller": cs.get("caller"),
                        "callee": cs.get("callee"),
                        "callsite_file": cs.get("callsite_file"),
                        "callsite_line": cs.get("callsite_line"),
                        "anomaly": anom,
                    },
                )
        # Surface existing exploits found
        ee = components.get("existing_exploits", {})
        for ex in ee.get("exploits", []):
            _cs.record(
                case_id,
                "auto_firmware_recon",
                "prior_art_exploit",
                {
                    "path": ex.get("path"),
                    "transport": ex.get("transport"),
                    "primitives": ex.get("primitives"),
                },
            )
    except Exception:
        pass  # case_state is best-effort
    return result


def _print_summary(result: dict[str, Any]) -> None:
    d = result["detection"]
    print(f"target: {result['target_dir']}")
    print(f"is_research_target={result['is_research_target']}  elapsed={result['elapsed_seconds']}s")
    print()
    print("DETECTION:")
    print(f"  firmware_dir       : {d['has_firmware_dir']}")
    print(f"  cortex-m ELF       : {d['is_cortex_m']}")
    print(f"  unstripped ELF     : {d['has_unstripped_elf']}")
    print(f"  DWARF debug info   : {d['has_dwarf']}")
    print(f"  linker script      : {d['has_linker_script']}")
    print(f"  sibling builds     : {d['has_sibling_builds']}")
    print(f"  existing exploits  : {d['has_existing_exploits']}")
    print(f"  preferred ELF      : {d['preferred_elf']}")
    print()
    print("COMPONENTS:")
    for name, c in result["components"].items():
        if isinstance(c, dict) and "summary" in c:
            print(f"  {name:<22} [+]  {c.get('summary')}")
        elif isinstance(c, dict) and "error" in c:
            print(f"  {name:<22} [x]  {c['error']}")
        else:
            keys = list(c.keys())[:5] if isinstance(c, dict) else "--"
            print(f"  {name:<22} [+]  keys={keys}")
    if result["warnings"]:
        print()
        print("WARNINGS:")
        for w in result["warnings"]:
            print(f"  [!] {w}")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("target_dir", type=Path, help="root of target tree")
    p.add_argument("--out", type=Path, help="write JSON to this path")
    p.add_argument("--json", action="store_true", help="emit JSON to stdout")
    args = p.parse_args(argv)

    if not args.target_dir.is_dir():
        print(f"[-] not a directory: {args.target_dir}", file=sys.stderr)
        return 1

    result = run_recon(args.target_dir)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, default=str))
        print(f"wrote {args.out} ({result['elapsed_seconds']}s)")
    elif args.json:
        json.dump(result, sys.stdout, indent=2, default=str)
        print()
    else:
        _print_summary(result)

    return 0


if __name__ == "__main__":
    sys.exit(main())
