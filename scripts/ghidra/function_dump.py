# @category Kraken
# @menupath
# @toolbar
"""Ghidra-headless post-script for KRAKEN (Jython 2.7 compatible).

Walks every function in the program after auto-analysis and emits JSON
to a known output path. The calling Python wrapper reads the JSON file
back.

Output schema:
    {
      "function_count": int,
      "functions": [{"name": str, "addr": "0x...", "size": int}, ...],
      "program_name": str,
      "program_arch": str,
      "program_endian": str,
    }

Output path: ${KRAKEN_GHIDRA_OUT} env var, or /tmp/kraken_ghidra_out.json.
"""

import json
import os

OUT_PATH = os.environ.get("KRAKEN_GHIDRA_OUT", "/tmp/kraken_ghidra_out.json")

prog = currentProgram  # Ghidra binding (defined by analyzeHeadless)
fm = prog.getFunctionManager()
fns = []
for fn in fm.getFunctions(True):
    addr = fn.getEntryPoint()
    size = 0
    try:
        body = fn.getBody()
        if body is not None:
            size = body.getNumAddresses()
    except Exception:
        pass
    fns.append(
        {
            "name": fn.getName(),
            "addr": "0x%s" % str(addr),
            "size": int(size),
        }
    )

result = {
    "function_count": len(fns),
    "functions": fns,
    "program_name": prog.getName(),
    "program_arch": str(prog.getLanguage().getProcessor()),
    "program_endian": "big" if prog.getLanguage().isBigEndian() else "little",
}

f = open(OUT_PATH, "w")
try:
    json.dump(result, f, indent=2)
finally:
    f.close()

print("[kraken-ghidra] wrote %d functions to %s" % (len(fns), OUT_PATH))
