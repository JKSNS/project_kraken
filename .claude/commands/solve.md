Solve the CTF challenge at: $ARGUMENTS

Use the kraken MCP tools in this exact workflow. Do NOT skip steps, each step feeds the next.
All session data is automatically captured and saved for post-solve analysis.

## Solve Timer

You MUST record accurate wall-clock solve times. At the very start of the solve:
```bash
date +%s > /tmp/solve_start_CHALLENGENAME
```
At the end (after flag is found or solve is abandoned):
```bash
echo $(( $(date +%s) - $(cat /tmp/solve_start_CHALLENGENAME) ))
```
Record the exact seconds in `session.json` as `total_elapsed` and in the README metrics table.
Do NOT estimate, use the actual timer values.

## Output Directory Convention, CRITICAL

Solve artifacts go **alongside the challenge files** in the same directory.
- Challenge at `VERE/pwn/week3/overwrite/` → artifacts written to `VERE/pwn/week3/overwrite/`
- Challenge at `challenges/xor/` → artifacts written to `challenges/xor/`

Do NOT create a separate `solves/` directory. Ever.

## Step 1: Full Solve (Primary Path)

Call `kraken_full_solve` with:
- challenge_path: the challenge path
- save_session: true
- output_dir: the challenge path itself (artifacts alongside source)

This runs the complete pipeline (triage → decompile → extract_params → tool_cascade) in one call
and saves all artifacts to the output directory.

If `flag_found` is true → go to Step 3 with the flag.

## Step 2: Manual Fallback (If Step 1 finds no flag)

Analyze the `session.cascade_results` from the full_solve response. Look at which tools ran, what they found.

Then write a custom Python solve script based on the decompiled code (available in `session.decompile_result`)
and tool outputs. Run it with `kraken_run_script`.

### Artifact Capture During Manual Solve

Even when solving manually, you MUST capture artifacts throughout the process. For each step of your analysis:

1. **Save the solve script** to `{challenge_path}/solve.py` with a docstring explaining the approach
2. **Save intermediate analysis** as JSON to `{challenge_path}/artifacts/`:
   - `analysis.json`, your observations, identified patterns, key findings
   - `source_extract.txt`, relevant extracted source code or decompiled output
   - Any other intermediate data that informed the solve
3. **Update session.json** with manual solve metadata:
   ```json
   {
     "solve_method": "manual",
     "manual_steps": ["description of each step taken"],
     "tools_used": ["list of tools/techniques"],
     "key_insights": ["what made the solve work"]
   }
   ```

If the script finds a flag → go to Step 3.
Max 3 script attempts, then report FAILED and move on.

## Step 3: Validate

Call `kraken_validate_flag` with the candidate flag. If binary_info from triage shows an ELF/PE binary,
pass its path as `binary_path`.

## Step 4: Report & Artifacts

After solving (or failing):

1. Call `kraken_solve_report` with:
   - session_path: the `session_path` returned from Step 1
   - format: "mindmap"
   Display the mindmap output to show the solve decision tree.

2. Ensure the challenge directory has the complete artifact set:
   ```
   {challenge_path}/
   ├── README.md           (detailed writeup: description, approach, tools, key insights, metrics)
   ├── flag.txt            (the captured flag)
   ├── solve.py            (reproducible solve script with docstring)
   ├── session.json        (full pipeline metadata with total_elapsed = exact seconds)
   └── artifacts/
       ├── triage.json      (binary info, strings, file type)
       ├── decompile.json   (decompiled source / disassembly)
       ├── params.json      (extracted solve parameters)
       ├── cascade.json     (tool cascade results)
       ├── timeline.jsonl   (per-step timing trace)
       ├── analysis.json    (manual analysis notes, if applicable)
       └── source_extract.txt (relevant source code, if applicable)
   ```

3. If any artifact files are missing (e.g., from a manual solve that didn't use the MCP pipeline),
   create them manually with the information gathered during the solve.

4. Report:
   - The final flag
   - Which tool found it (solving_tool)
   - Total elapsed time
   - Path to saved artifacts
