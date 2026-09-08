# Ghidra script - emit JSON list of all CALL instructions whose target is an
# imported function. Used by KRAKEN's decompiler-recovery cascade when
# native pyelftools+capstone walking can't resolve MIPS PIC %got_page+%got_ofst.
#
# Invocation:
#   analyzeHeadless <proj> <name> -import <binary> -postscript list_import_call_sites.py \
#       -scriptPath <repo>/scripts/ghidra
#
# Output: writes to a file path given via the KRAKEN_GHIDRA_OUT env var
# (default: /tmp/kraken_ghidra_out.json). Format:
#   [{"caller": "fn_name", "caller_addr": "0xXXXX", "call_addr": "0xXXXX",
#     "callee": "import_name"}, ...]
#
# This is JYTHON (Ghidra runs Python 2.7).

# @category Kraken
# @runtime Jython

import json
import os

OUT_PATH = os.environ.get("KRAKEN_GHIDRA_OUT", "/tmp/kraken_ghidra_out.json")

records = []

prog = currentProgram
fm = prog.getFunctionManager()
listing = prog.getListing()
sm = prog.getSymbolTable()

# Build set of imported / external symbol addresses
import_addrs = {}  # addr_int -> name
for sym in sm.getExternalSymbols():
    name = sym.getName()
    addr = sym.getAddress()
    if addr is not None:
        import_addrs[addr.getOffset()] = name

# Also add functions marked as external (imp_*, thunk_*, etc.)
for fn in fm.getExternalFunctions():
    name = fn.getName()
    # Get the call-site (entry point)
    entry = fn.getEntryPoint()
    if entry is not None:
        import_addrs[entry.getOffset()] = name

# Walk every function; for each CALL/JAL instruction, check if target is an import
for fn in fm.getFunctions(True):
    fn_name = fn.getName()
    fn_entry = fn.getEntryPoint().getOffset()

    body = fn.getBody()
    instr_iter = listing.getInstructions(body, True)
    for ins in instr_iter:
        flow = ins.getFlowType()
        if not (flow.isCall() or flow.isJump() and flow.isComputed()):
            continue
        # Get flow targets
        targets = ins.getFlows()
        if not targets:
            continue
        for tgt in targets:
            t_off = tgt.getOffset()
            # Look up by exact address first
            callee_name = import_addrs.get(t_off)
            # Also check if the target itself is a function whose body calls an import (PLT thunk)
            if callee_name is None:
                tgt_fn = fm.getFunctionAt(tgt)
                if tgt_fn is not None:
                    name = tgt_fn.getName()
                    # Ghidra naming convention for thunks: <symbol>, _<symbol>, or PTR_<symbol>
                    # If it's a thunk to an imported function, follow it
                    if tgt_fn.isThunk():
                        thunked = tgt_fn.getThunkedFunction(True)
                        if thunked is not None:
                            callee_name = thunked.getName()
                    elif name in import_addrs.values():
                        callee_name = name
            if callee_name:
                records.append(
                    {
                        "caller": fn_name,
                        "caller_addr": "0x%x" % fn_entry,
                        "call_addr": "0x%x" % ins.getAddress().getOffset(),
                        "callee": callee_name,
                    }
                )

# Write output
with open(OUT_PATH, "w") as f:
    json.dump(records, f)

print("[kraken-ghidra] wrote %d call-site records to %s" % (len(records), OUT_PATH))
