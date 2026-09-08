Generate comprehensive writeup documentation for a CTF workspace: $ARGUMENTS

Argument: path to a CTF workspace directory (e.g. `ctfs/byu-eos-ctf`). If omitted, use the
current working directory.

This command audits every challenge and produces three layers of documentation:
1. **Category READMEs**, one per category dir, table of all challenges with flags + times
2. **Challenge READMEs**, ensure every challenge has one (create stubs for missing)
3. **Top-level summary**, update WRITEUP.md or create one if absent

---

## Step 0: Reconstruct solve times

BEFORE collecting challenge data, run the solve-time extractor to get accurate
per-challenge wall-clock times. It reads per-challenge `session.json` first
(authoritative, written by solving agents) and falls back to grepping
`~/.claude/projects/<project>/*.jsonl` for cascade/MCP solves:

```bash
python3 scripts/extract_solve_times.py $ARGUMENTS --update-readmes
```

This writes `{workspace}/solve_times.json` with elapsed seconds + source
(`session.json` authoritative vs `jsonl` postmortem) for every challenge, and
injects `**Solve time:** Ns` markers into each challenge README. The data
collection script in Step 1 will pick up those markers.

Missing solve times mean the challenge was solved by a parallel Agent subagent
that didn't write `session.json`, note which and flag them so future runs can
fix the agent prompts per `/solve-all`.

---

## Step 1: Collect challenge data

Run this Python script to gather all challenge metadata:

```python
import json, re
from pathlib import Path

workspace = Path("$ARGUMENTS" or ".")
rows = []
for chal_dir in sorted(workspace.glob("*/*")):
    if not chal_dir.is_dir() or chal_dir.name.startswith("pass"):
        continue
    meta_f  = chal_dir / "challenge.json"
    flag_f  = chal_dir / "flag.txt"
    readme_f = chal_dir / "README.md"
    if not meta_f.exists():
        continue
    meta = json.loads(meta_f.read_text())
    flag = ""
    if flag_f.exists():
        lines = flag_f.read_text().strip().splitlines()
        flag = lines[0] if lines else ""
    # Extract elapsed time from README metrics table
    elapsed = None
    approach = ""
    if readme_f.exists():
        txt = readme_f.read_text()
        for pat in [r"Total elapsed\s*\|[^|]*\|\s*(\d+)", r"\|\s*(\d+)s\s*\|",
                    r"Solve time[^\d]*(\d+)s", r"(\d+) seconds"]:
            m = re.search(pat, txt)
            if m:
                elapsed = int(m.group(1))
                break
        # One-line approach: first non-header paragraph
        lines = [l.strip() for l in txt.splitlines() if l.strip() and not l.startswith("#")]
        approach = lines[0][:120] if lines else ""
    rows.append({
        "category": chal_dir.parent.name,
        "name": meta.get("name", chal_dir.name),
        "value": meta.get("value", 0),
        "solves": meta.get("solves", 0),
        "flag": flag,
        "elapsed": elapsed,
        "solved": bool(flag and "{" in flag and not flag.startswith("UNSOLVED")),
        "approach": approach,
        "path": str(chal_dir.relative_to(workspace)),
        "has_readme": readme_f.exists(),
    })
print(json.dumps(rows, indent=2))
```

---

## Step 2: Generate category READMEs

For each category directory, write `{category}/README.md` with this structure:

```markdown
# {Category} -- BYU EOS CTF 2026

**{solved}/{total} solved** | {sum_points} pts earned

| Challenge | Points | Flag | Time | Approach |
|-----------|-------:|------|-----:|----------|
| [Name](Challenge_Dir/) | 500 | `byuctf{...}` | 228s | One-line approach |
| [Name](Challenge_Dir/) | 419 | *unsolved* | -- | Reason |
```

Rules for the table:
- Link challenge name to its directory
- Flag: show verbatim if solved, `*unsolved*` if not, `*incorrect submission*` if flag.txt exists but was confirmed wrong
- Time: from README metrics if available, `--` if unknown
- Approach: single sentence, max 100 chars, from the challenge README

---

## Step 3: Ensure every challenge has a README

For any challenge directory missing a README, create a minimal one:

```markdown
# {Challenge Name} ({Category}, {value}pts)

**Flag:** `{flag}` *(captured)* / *unsolved*

## Description
{challenge description from challenge.json}

## Approach
*TODO: document solve approach*

## Artifacts
- `flag.txt` -- captured flag
- `challenge.json` -- challenge metadata
```

---

## Step 4: Update top-level WRITEUP.md

Find or create `WRITEUP.md` in the workspace root. Ensure it has:
- An overall metrics table (total solves, points, solve %, placement if known)
- A full flag index, ONE table listing every challenge: category | name | flag | time
- Links to category READMEs

The full flag index table format:

```markdown
## Complete Flag Index

| Category | Challenge | Points | Flag | Time |
|----------|-----------|-------:|------|-----:|
| Crypto | [AES Scissor Co. 3](Crypto/AES_Scissor_Co._3/) | 500 | `byuctf{n0m_n0m_c00k13_a4fb6c0f}` | 228s |
```

Sort by category, then by challenge name within category.

---

## Step 5: Verify and report

Print a summary:
```
Category READMEs generated: N
Challenge READMEs created/updated: N
Missing flags (unsolved): N
Challenges with unknown solve time: N
```

Flag any challenges where:
- `flag.txt` is missing entirely
- `flag.txt` contains a placeholder (UNSOLVED, TODO, etc.)
- README is missing

---

## Output convention

All files written to their natural location inside the workspace. Never create a separate
`writeups/` or `docs/` directory, documentation lives with the challenge files.

After generating, commit with:
```
git add {workspace}/
git commit -m "Add solve writeups and category READMEs for {ctf_name}"
```
