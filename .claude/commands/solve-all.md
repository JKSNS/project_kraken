Solve ALL CTF challenges in the directory: $ARGUMENTS

## Architecture: Hybrid Parallel Solver

Run the hybrid solver which automatically routes each challenge to the fastest engine:

```bash
python3 scripts/hybrid_solve.py $ARGUMENTS
```

The solver:
1. **Triages all challenges**, reads descriptions, detects remote services
2. **Classifies into tiers:**
   - STATIC (no remote) → kraken cascade (deterministic, <30s)
   - REMOTE (has nc host:port) → Codex GPT-5.4 (direct shell, parallel)
3. **Launches all engines in parallel**, cascade + Codex run simultaneously
4. **Cascade failures auto-fallback to Codex**
5. **Reports results** with per-challenge timing

If the hybrid solver is unavailable or you need manual control, fall back to parallel agents:

### Manual Fallback: Parallel Agents

Spawn one agent per challenge, all in ONE message:

Each agent gets `mode: "bypassPermissions"` and this prompt:
```
Solve: {challenge_path}
Target: {host}:{port}
Description: {description}

START TIMER: record `int(time.time())` as start_ts before doing anything else.

Write a pwntools exploit, run it, get the flag.
Use kraken_triage and kraken_decompile for analysis.
Max 3 attempts.

Write {challenge_path}/flag.txt and {challenge_path}/README.md.

END TIMER: record `int(time.time())` as end_ts once flag is captured (or abandoned).

CRITICAL: Write {challenge_path}/session.json with this exact schema so the
postmortem extractor can reconstruct solve times -- subagent transcripts are
NOT persisted to ~/.claude/projects/, so session.json is the ONLY reliable
source for parallel-agent solve times:

  {
    "challenge": "Category/Name",
    "start_ts": <unix_seconds_float>,
    "end_ts":   <unix_seconds_float>,
    "total_elapsed": <int_seconds>,
    "source": "agent",
    "status": "SOLVED|FAILED",
    "flag": "..."
  }

Return: {"challenge": "name", "status": "SOLVED|FAILED", "flag": "...", "tool": "...", "elapsed": seconds}
```

## Rules
- Hybrid solver is the default. Use it.
- ALL work runs in parallel. Wall-clock = max(individual tasks).
- Artifacts go alongside challenge files, never in a separate directory.
- Max 3 script attempts per challenge.
- **Every challenge dir MUST contain session.json with start_ts/end_ts/total_elapsed.**
  This is the authoritative source for postmortem time-to-solve validation via
  `scripts/extract_solve_times.py`. Without it, parallel-agent times are lost.
