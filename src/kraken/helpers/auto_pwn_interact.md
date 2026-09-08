# auto_pwn_interact

`auto_pwn_interact.py` is a standalone helper (CLI + importable API) for
interactive remote pwn: multi-step send/recv, leak to libc to ROP, and ret2win
against live or interactive services where a one-shot static solve can't drive
the back-and-forth.

It works today with no wiring: the cascade runs it through the generic
shell-out path (`kraken_run_tool`), and its entry is already in the tool
registry (`tool_meta.json`). This document covers two things: the optional steps
to promote it to a first-class router/MCP/slash tool, and the programmatic API
for agents that import it directly.

The helper follows the standard tool contract: it prints
`EXTRACTED FLAG: <flag>` and exits 0 on success, non-zero otherwise, so the
existing `_run_tool` / `EXTRACTED FLAG:` parse in the MCP layer reads it
unchanged.

## Registry entry (`src/kraken/helpers/tool_meta.json`)

Already present in the `"tools"` object; this is the only edit `registry.py`
needs to recognise a new tool:

```json
"auto_pwn_interact": {
  "description": "Interactive remote-pwn loop (leak->libc->ROP, ret2win, multi-step send/recv) for live/interactive pwn",
  "universal": false,
  "needs_binary": true,
  "timeout": 300,
  "command_style": "custom"
}
```

## Promoting it to a first-class cascade tool (optional)

By default the tool is available but not auto-scheduled by the router. To have
the router build and run it in the pwn cascade, add the command builder and the
cascade wiring below. Apply them together: the ordering-list additions make the
cascade *run* the tool, which requires the command builder to exist first.
Adding the ordering entries alone would queue a tool the router can't build a
command for.

Ordering lists in `tool_meta.json`: add `"auto_pwn_interact"` to the
`"remote_tools"` array (so it's injected when `remote_info` has a host) and to
the `"pwn"` list inside `"type_specific"`, right after `auto_pwn_solve`, so
interactive exploitation is tried ahead of the generic banner-grab:

```json
"pwn": ["auto_pwn_solve", "auto_pwn_interact", "auto_heap_exploit", "...", "auto_process_interact"]
```

Command builder in `src/kraken/nodes/tool_router.py`, next to
`_build_pwn_solve_command` (it mirrors that builder plus the remote fields from
`_build_remote_interact_command`):

```python
def _build_pwn_interact_command(params: dict, state: KrakenState) -> str | None:
    """Build a command for the interactive remote-pwn loop driver."""
    helpers_dir = str(_HELPERS_DIR)
    remote_info = state.get("remote_info", {})
    host, port = remote_info.get("host"), remote_info.get("port")
    binary_path = state.get("challenge_path", "")

    if host and port:
        target = f"{host}:{port}"
        cmd = f'python3 {helpers_dir}/auto_pwn_interact.py "{target}" --remote'
        if binary_path and not os.path.isdir(binary_path):
            cmd += f' --binary "{binary_path}"'          # local copy for offsets/gadgets
    elif binary_path and not os.path.isdir(binary_path):
        cmd = f'python3 {helpers_dir}/auto_pwn_interact.py "{binary_path}"'
    else:
        return None

    # Source file (improves offset detection) -- same scan as _build_pwn_solve_command.
    for name, info in state.get("challenge_files", {}).items():
        if name.endswith(".c"):
            p = info.get("path", "")
            if p and os.path.exists(p):
                cmd += f' --source "{p}"'
                break

    if state.get("libc_path"):
        cmd += f' --libc "{state["libc_path"]}"'
    win = params.get("win_addr")
    if win:
        cmd += f' --win-addr "{win}"'
    if state.get("flag_format"):
        cmd += f' --flag-format "{state["flag_format"]}"'
    return cmd
```

Register it in the command-builder dispatch dict (the one that already maps
`"auto_pwn_solve": _build_pwn_solve_command`):

```python
"auto_pwn_interact": _build_pwn_interact_command,
```

## MCP tool (optional)

Modelled on `kraken_remote_interact` (same `_run_tool` + `EXTRACTED FLAG:`
parse):

```python
@mcp.tool()
async def kraken_pwn_interact(
    target: str,
    is_remote: bool = False,
    binary: str | None = None,
    source: str | None = None,
    libc: str | None = None,
    win_addr: str | None = None,
    leak_func: str = "puts",
    flag_format: str = r"flag\{[^}]+\}",
    timeout: float = 300.0,
) -> dict:
    """Interactive remote-pwn loop: multi-step send/recv, leak->libc->ROP, ret2win.

    For live/interactive pwn (pwn.college, HTB) where a static solve can't drive
    the back-and-forth. `target` is a local binary path, or "host:port" with
    is_remote=True. Provide `binary` (a local copy) when exploiting a remote
    target so offsets/gadgets can be analysed locally.

    Returns dict with: transcript, flag_found, flag.
    """
    try:
        from kraken.nodes.tool_router import _run_tool

        helpers_dir = str(Path(__file__).resolve().parent / "helpers")
        cmd = f'python3 {helpers_dir}/auto_pwn_interact.py "{target}"'
        if is_remote:
            cmd += " --remote"
        if binary:
            cmd += f' --binary "{binary}"'
        if source:
            cmd += f' --source "{source}"'
        if libc:
            cmd += f' --libc "{libc}"'
        if win_addr:
            cmd += f' --win-addr "{win_addr}"'
        if leak_func:
            cmd += f' --leak-func "{leak_func}"'
        if flag_format:
            cmd += f' --flag-format "{flag_format}"'

        result = await _run_tool(cmd, None, int(timeout))

        flag = None
        marker = re.search(r"EXTRACTED FLAG:\s*(.+)", result["stdout"])
        if marker:
            flag = marker.group(1).strip()

        return {
            "transcript": result["stdout"],
            "flag_found": flag is not None,
            "flag": flag or "",
        }
    except Exception as exc:
        return _err("kraken_pwn_interact", exc)
```

## Slash command (optional)

Create `.claude/commands/pwn.md` with the body below (mirror the same body into
your Codex surface if you maintain one):

```markdown
Drive an interactive remote-pwn exploit loop against a binary or live service.

Expected format: `<binary|host:port> [extra_args_json]`
Input: $ARGUMENTS

Parse the arguments:
- First token = target. A path ending without `:` is a local binary; a
  `host:port` token is a live service (set is_remote=true).
- Optional JSON dict of extra args, e.g.
  `{"binary": "./vuln", "libc": "./libc.so.6", "win_addr": "win", "leak_func": "puts", "flag_format": "flag\\{.*\\}"}`

Call `kraken_pwn_interact` with the parsed arguments. When exploiting a remote
`host:port`, ALWAYS pass `binary` (a local copy of the challenge ELF) so the
tool can analyse offsets and gadgets locally.

The tool auto-runs the standard stages in order: banner scan -> ret2win
(explicit `win_addr` or autodetected `win()`) -> leak `puts@got` -> resolve
libc -> ret2libc -> one_gadget fallbacks. It logs the full send/recv transcript.

Report:
- The command/target that was executed
- Whether a flag was found, and the flag
- The interaction transcript (truncate if long)

If no flag: inspect the transcript. Common next moves -- supply `--libc` for a
matched libc, set an explicit `win_addr`, adjust `leak_func` (e.g. `printf`),
or drop to a manual `InteractiveSession` (see the helper docstring) to script
a bespoke leak/overflow sequence.
```

## Programmatic API

For agents that import the helper directly:

```python
from kraken.helpers import auto_pwn_interact as pwn

# One-shot: try all stages, return [{flag, found, target, transcript, stages}]
results = pwn.run("chal.ctf.io:1337", remote=True, binary="./vuln",
                  libc="./libc.so.6", flag_format=r"flag\{[^}]+\}")

# Multi-step driving (observe -> decide -> act):
conn = pwn.PwnConnection.open_remote("chal.ctf.io", 1337)   # or .open_local("./vuln")
sess = pwn.InteractiveSession(conn, binary="./vuln", libc_path="./libc.so.6",
                              flag_format=r"flag\{[^}]+\}")

def decide(obs: pwn.Observation):
    if obs.contains("Menu"):
        return pwn.Action.sendline(b"1")
    leak = obs.leak()                       # parse a leaked address from output
    if leak:
        sess.resolve_libc("puts", leak)     # reuse auto_libc_lookup DB / --libc
        return pwn.Action.ret2libc()        # build + send system("/bin/sh")
    return pwn.Action.ret2win("win")        # build + send padding -> win()

flag = sess.run_loop(decide, max_steps=16)
```

`step(decide)` runs exactly one observe->decide->act cycle; `run_loop` repeats
until an `Action.finish()`, a flag, or EOF. `StageBuilder` (reuses
`auto_pwn_solve.PwnSolver` for offsets/gadgets and `auto_libc_lookup` for libc)
backs the `build_ret2win` / `build_ret2libc` / `build_rop` /
`build_format_string` / `build_one_gadget` payloads.
