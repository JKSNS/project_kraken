#!/usr/bin/env python3
"""auto_ghidra_recover -- Ghidra-headless 4th-tier function recovery.

Closes the v0.2.3 Phase B baseline gap where r2 -A beat capstone PT_LOAD
recovery on raw function counts. Ghidra's analyzer typically finds even
more functions than r2, with real symbol names rather than sub_<addr>
placeholders.

Honest about wall-clock cost: Ghidra is the SLOWEST tier (10-60s per
binary on commodity hardware) and produces a multi-hundred-MB project
artifact. Use it when you actually need the depth, or when you want to
HAND OFF the project to a human reverse engineer for manual validation.

Output dirs:
    project_dir/<project>/<binary>.gpr  -- Ghidra project (importable!)
    out_dir/ghidra_recovery.json        -- function recovery JSON
    out_dir/ghidra_command.txt          -- exact command used (reproducibility)

Per the user's request: the .gpr project artifact is preserved so the
operator can `analyzeHeadless --import-project ...` or open in the
Ghidra GUI to manually validate findings. KRAKEN produces analyst-
ready output the analyst can re-walk in their own tools.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

GHIDRA_HOME_CANDIDATES = (
    os.environ.get("GHIDRA_HOME"),
    "$HOME/software/ghidra",  # persistent install (this host)
    "/opt/ghidra",  # common Linux install path
    "/usr/local/ghidra",  # alt install path
)
SCRIPT_NAME = "function_dump.py"


def _repo_root() -> Path:
    """Best-effort repo-root detection -- climb until pyproject.toml found."""
    here = Path(__file__).resolve()
    for parent in [here, *here.parents]:
        if (parent / "pyproject.toml").exists():
            return parent
    return Path.cwd()


def _default_artifacts_dir() -> Path:
    """Repo-relative artifacts/ghidra/ -- preserved across machines."""
    p = _repo_root() / "artifacts" / "ghidra" / "ghidra_projects"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _default_script_dir() -> Path:
    return _repo_root() / "ghidra_scripts"


def _find_ghidra() -> Path | None:
    """Find a working Ghidra install. Tries env var first, then standard
    paths, then PATH lookup."""
    for candidate in GHIDRA_HOME_CANDIDATES:
        if not candidate:
            continue
        p = Path(candidate) / "support" / "analyzeHeadless"
        if p.exists():
            return Path(candidate)
    h = shutil.which("analyzeHeadless")
    if h:
        return Path(h).resolve().parents[1]
    return None


def host_decompiler_arch() -> tuple:
    """Return (host_arch_normalised, has_ghidra_decompiler) -- Ghidra 11.x
    ships decompiler for: linux_x86_64, mac_arm_64, mac_x86_64,
    win_x86_64. Notably NOT linux_arm_64."""
    import platform

    machine = platform.machine().lower()
    system = platform.system().lower()
    arch_map = {
        "x86_64": "x86_64",
        "amd64": "x86_64",
        "aarch64": "arm_64",
        "arm64": "arm_64",
    }
    norm = arch_map.get(machine, machine)
    ghidra_home = _find_ghidra()
    if not ghidra_home:
        return (norm, False)
    plat_dir = "%s_%s" % (system, norm)
    decompiler = ghidra_home / "Ghidra" / "Features" / "Decompiler" / "os" / plat_dir / "decompile"
    return (norm, decompiler.exists())


def recover_with_ghidra(
    target: str | Path,
    *,
    out_dir: str | Path | None = None,
    project_dir: str | Path | None = None,
    project_name: str = "kraken_proj",
    budget_s: int = 120,
    keep_project: bool = True,
) -> dict:
    """Run analyzeHeadless on `target`, parse the JSON output, return a dict.

    Always returns a dict; on error returns one with `status: error`.
    """
    target_path = Path(target).resolve()
    if not target_path.exists():
        return {"status": "error", "error": "target not found", "path": str(target_path)}

    ghidra_home = _find_ghidra()
    if ghidra_home is None:
        return {
            "status": "needs_ghidra",
            "rationale": (
                "Ghidra not found. Install at $HOME/software/ghidra/ "
                "or set GHIDRA_HOME. Download from "
                "https://github.com/NationalSecurityAgency/ghidra/releases"
            ),
        }

    if out_dir is None:
        # Default: repo-relative artifacts dir, preserved across machines.
        out_dir = _default_artifacts_dir() / target_path.stem
    out_dir = Path(out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    project_dir = Path(project_dir or out_dir / "project").resolve()
    project_dir.mkdir(parents=True, exist_ok=True)

    json_out = out_dir / "ghidra_recovery.json"
    cmd_log = out_dir / "ghidra_command.txt"

    analyze = ghidra_home / "support" / "analyzeHeadless"
    script_dir = str(_default_script_dir())
    cmd = [
        str(analyze),
        str(project_dir),
        project_name,
        "-import",
        str(target_path),
        "-scriptPath",
        script_dir,
        "-postScript",
        SCRIPT_NAME,
        "-overwrite",
    ]
    cmd_log.write_text(" ".join(cmd) + "\n")

    env = dict(os.environ)
    env["KRAKEN_GHIDRA_OUT"] = str(json_out)

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=budget_s,
            env=env,
        )
    except subprocess.TimeoutExpired:
        return {
            "status": "timeout",
            "elapsed_s": round(time.time() - t0, 2),
            "out_dir": str(out_dir),
        }

    elapsed = round(time.time() - t0, 2)
    log = (result.stderr or "") + (result.stdout or "")

    if not json_out.exists():
        return {
            "status": "failed",
            "exit_code": result.returncode,
            "elapsed_s": elapsed,
            "out_dir": str(out_dir),
            "log_tail": log[-1500:],
        }

    try:
        data = json.loads(json_out.read_text())
    except json.JSONDecodeError as e:
        return {
            "status": "json_parse_error",
            "error": str(e),
            "elapsed_s": elapsed,
            "out_dir": str(out_dir),
        }

    fns = data.get("functions") or []
    real_named = [f for f in fns if not (f["name"].startswith("FUN_") or f["name"].startswith("sub_"))]
    sub_named = len(fns) - len(real_named)

    return {
        "status": "ok",
        "function_count": data.get("function_count", len(fns)),
        "real_named_count": len(real_named),
        "placeholder_named_count": sub_named,
        "program_arch": data.get("program_arch"),
        "program_endian": data.get("program_endian"),
        "elapsed_s": elapsed,
        "out_dir": str(out_dir),
        "json_path": str(json_out),
        "project_dir": str(project_dir),
        "project_name": project_name,
        "command": " ".join(cmd),
        "ghidra_home": str(ghidra_home),
        "functions": fns[:200],  # cap for JSON-serialisation
        "_note": (
            "The Ghidra project at `project_dir/project_name.rep` is "
            "preserved so the operator can open it in the Ghidra GUI for "
            "manual validation."
        ),
    }


# ── Playbook-friendly entry ───────────────────────────────────────────


def playbook_recover_with_ghidra(*, target: str, out_dir: str | None = None, budget_s: int = 120) -> dict:
    return recover_with_ghidra(
        target,
        out_dir=out_dir,
        budget_s=int(budget_s) if budget_s else 120,
    )


# ── CLI ──────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="auto_ghidra_recover",
        description="Ghidra-headless 4th-tier function recovery",
    )
    p.add_argument("target")
    p.add_argument("--out-dir", default=None)
    p.add_argument("--project-dir", default=None)
    p.add_argument("--budget", type=int, default=120)
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    result = recover_with_ghidra(
        args.target,
        out_dir=args.out_dir,
        project_dir=args.project_dir,
        budget_s=args.budget,
    )

    if args.json:
        print(json.dumps(result, indent=2))
        return 0 if result.get("status") == "ok" else 2

    print("status: %s" % result.get("status"))
    if result.get("status") == "ok":
        print("  arch:                %s / %s" % (result.get("program_arch"), result.get("program_endian")))
        print("  functions:           %d total" % result.get("function_count", 0))
        print("    real-named:        %d" % result.get("real_named_count", 0))
        print("    placeholders:      %d" % result.get("placeholder_named_count", 0))
        print("  wall-clock:          %.2fs" % result.get("elapsed_s", 0))
        print("  out_dir:             %s" % result.get("out_dir"))
        print("  ghidra project (importable in your local Ghidra GUI):")
        print("    %s/%s.rep" % (result.get("project_dir"), result.get("project_name")))
    else:
        print("  out_dir: %s" % result.get("out_dir"))
        if result.get("log_tail"):
            print("  log_tail:")
            for line in (result["log_tail"]).splitlines()[-10:]:
                print("    %s" % line)
    return 0 if result.get("status") == "ok" else 2


if __name__ == "__main__":
    sys.exit(main())
