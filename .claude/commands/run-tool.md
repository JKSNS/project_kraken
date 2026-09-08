Run a specific kraken tool against a challenge.

Expected format: `tool_name challenge_path [extra_args_json]`
Input: $ARGUMENTS

Parse the arguments:
- First word = tool name (e.g. `auto_angr`, `auto_gdb_cmp`, `auto_xor_brute`)
- Second word = challenge path
- Optional third = JSON dict of extra args (e.g. `{"success_string": "Correct!", "input_length": 32}`)

Call `kraken_run_tool` with the parsed arguments.

Report:
- The command that was executed
- Exit code
- Full stdout (truncated if very long)
- Whether a flag was found
- The flag if found

If the tool failed, suggest what to try differently (different tool, different extra_args, etc.).
