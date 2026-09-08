# helpers/

The analysis-tool library. This is the deterministic muscle behind KRAKEN's
"model-last" design: roughly 100 `auto_*.py` scripts that do the computational
work of a CTF, disassembly, symbolic execution, classic-crypto breaking, file
carving, pwn primitives, so the cascade can resolve most static challenges with
**no model call at all**.

## The contract

Every tool is a single file named `auto_<thing>.py` exposing one public entry
point:

```python
def run(objective: str, **kwargs) -> list[dict]:
    """Do the work; return a list of result dicts (findings, artifacts, a flag)."""
```

Keeping the surface this uniform is what lets the router treat a hundred different
tools identically: it hands each one an objective and reads back a list of dicts,
without knowing whether it just ran `angr` or a Caesar-cipher brute-forcer.

## Registration and routing

`registry.py` loads `tool_meta.json`, which maps each registered tool to its
category, the challenge types it applies to, and its routing metadata. The tool
router (`../nodes/tool_router.py`) reads that metadata to decide which tools to
fire, in what order, for a given challenge, and the learned optimizer reorders
that sequence over time so winning tools run first.

To add a tool: drop an `auto_<thing>.py` here following the `run()` contract, then
register it in `tool_meta.json` (and, if it should run without metadata present,
in the router's fallback lists).

## Known coverage gap (tracked, not hidden)

About 19 older helper scripts (for example `auto_ghidra_recover`,
`auto_crash_triage`, `auto_poc_generator`) predate `tool_meta.json` and are **not
yet registered**, so the router never fires them. This is a real
capability-expansion gap, left visible on purpose: it is asserted by two
strict-`xfail` tests in `tests/unit/tools/test_registry.py` rather than papered
over. Registering them (with routing metadata and coverage) is exactly the kind of
additive improvement that makes the library better over time.
