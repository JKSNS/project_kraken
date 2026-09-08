Run a live CTF competition: $ARGUMENTS

You are the competition operator. Parse the arguments and run `kraken ctf`.

## Argument Formats

```
/ctf https://ctf.example.com --token ctfd_abc123
/ctf https://ctf.example.com --token ctfd_abc123 --timeout 15 -j 5
/ctf ./local-challenges/                          (already downloaded, use /solve-all instead)
```

## What This Does

The `kraken ctf` command handles everything autonomously:

1. **Pulls all challenges** from the CTFd instance (metadata + file attachments)
2. **Creates workspace** at `ctfs/{ctf_name}/{category}/{challenge}/`
3. **Parallel solves** all unsolved challenges (skips already-solved ones)
4. **Auto-submits** high-confidence flags back to CTFd
5. **Locks flag format** from the first successful solve
6. **Codex fallback** enabled automatically for stuck challenges

## How to Run

```bash
KRAKEN_ENABLE_CODEX_FALLBACK=1 \
kraken ctf {url} --token {token} --timeout 10 -j 10
```

Or just tell me the URL and token, and I'll run it:

```bash
kraken ctf "$URL" --token "$TOKEN"
```

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--token` | required | CTFd API access token |
| `--timeout` | 10 min | Per-challenge timeout |
| `-j` / `--concurrency` | all | Max parallel solvers |
| `--no-submit` | off | Disable auto flag submission |
| `--backend` | claude | LLM backend |
| `--verbose` | off | JSON logging |

## Flag Submission Policy

Flags are submitted automatically, but only when ALL of these are true:
- Flag matches the locked format (e.g., `CTF{...}`)
- Flag is not a known false positive (`flag{test}`, `flag{example}`, etc.)
- Flag contains braces and is at least 4 characters
- One attempt per challenge (no brute-force)

Use `--no-submit` to disable auto-submission and review flags manually.

## After the Competition

Results are saved to `ctfs/{ctf_name}/results/`:
- `ctf_results.json`, per-challenge solve status + submitted flags
- `solve_ledger.md`, human-readable competition report
- Per-challenge artifacts alongside their source files

## If Challenges Are Already Downloaded

Use `/solve-all` instead:
```
/solve-all ./path/to/challenges/
```
