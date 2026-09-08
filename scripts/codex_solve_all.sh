#!/usr/bin/env bash
# codex_solve_all.sh -- Parallel CTF solver using Codex (GPT-5.4)
#
# Spawns one Codex instance per challenge in parallel.
# Zero agent overhead -- direct shell execution.
#
# Usage:
#   ./scripts/codex_solve_all.sh ./challenges/pwn "flag{}"
#   ./scripts/codex_solve_all.sh challenges/ "CTF{}"
#
# Requirements:
#   - codex CLI installed and authenticated (codex login)
#   - VPN/network access to remote targets
#   - pwntools installed (pip install pwntools)
set -euo pipefail

CHALLENGE_DIR="${1:?Usage: $0 <challenge_dir> [flag_format]}"
FLAG_FORMAT="${2:-flag\{\}}"
MAX_PARALLEL="${3:-8}"
TIMEOUT="${4:-480}"

# Discover challenges
CHALLENGES=()
for d in "$CHALLENGE_DIR"/*/; do
    [ -d "$d" ] && CHALLENGES+=("$d")
done

if [ ${#CHALLENGES[@]} -eq 0 ]; then
    echo "No challenge directories found in $CHALLENGE_DIR"
    exit 1
fi

echo "============================================================"
echo "  CODEX PARALLEL SOLVER"
echo "============================================================"
echo "  Challenges: ${#CHALLENGES[@]}"
echo "  Flag format: $FLAG_FORMAT"
echo "  Max parallel: $MAX_PARALLEL"
echo "  Timeout: ${TIMEOUT}s per challenge"
echo "============================================================"
echo ""

BATCH_START=$(date +%s)
RESULTS_DIR=$(mktemp -d /tmp/codex_solve_XXXXXX)

solve_one() {
    local CHAL_PATH="$1"
    local CHAL_NAME=$(basename "$CHAL_PATH")
    local DESC=""
    local RESULT_FILE="$RESULTS_DIR/${CHAL_NAME}.json"
    local LOG_FILE="$RESULTS_DIR/${CHAL_NAME}.log"

    # Read description
    if [ -f "$CHAL_PATH/description.txt" ]; then
        DESC=$(cat "$CHAL_PATH/description.txt")
    fi

    local START=$(date +%s)

    echo "[$(date +%H:%M:%S)] Starting: $CHAL_NAME"

    # Run Codex with full prompt
    timeout "$TIMEOUT" codex exec --dangerously-bypass-approvals-and-sandbox \
        "You are solving a CTF pwn challenge.

Challenge directory: $(realpath "$CHAL_PATH")
Description: $DESC
Flag format: $FLAG_FORMAT

Instructions:
1. Run 'file' and 'checksec' on the binary in the challenge directory
2. Run 'objdump -d' to disassemble key functions (main, vuln, win if they exist)
3. Read description.txt for the remote target (nc host port)
4. Write a pwntools exploit script at $(realpath "$CHAL_PATH")/exploit.py
5. Run the exploit: cd $(realpath "$CHAL_PATH") && python3 exploit.py
6. If it fails, analyze the error and try again (max 3 attempts)
7. When you get a shell, run 'cat /ctf/flag.txt' or 'cat flag.txt'
8. Write the flag to $(realpath "$CHAL_PATH")/flag.txt

Key tips:
- These are Ubuntu 24.04 containers with libc 2.39-0ubuntu8.2
- Check for PIE, canary, NX, RELRO with checksec
- For PIE binaries, look for address leaks or partial overwrites
- For libc exploits, use known offsets for 2.39-0ubuntu8: puts=0x87bd0, system=0x58740, /bin/sh=0x1cb42f
- Buffer overflow offset is typically 40 (0x28) for these challenges

Output ONLY the flag at the very end of your response, on its own line, like: FLAG=vere{...}" \
        > "$LOG_FILE" 2>&1

    local EXIT_CODE=$?
    local ELAPSED=$(( $(date +%s) - START ))

    # Extract flag from output or flag.txt
    local FLAG=""
    if [ -f "$CHAL_PATH/flag.txt" ]; then
        FLAG=$(cat "$CHAL_PATH/flag.txt" | tr -d '\n')
    fi
    if [ -z "$FLAG" ]; then
        FLAG=$(grep -oP 'FLAG=\K.*' "$LOG_FILE" 2>/dev/null | tail -1 || true)
    fi
    if [ -z "$FLAG" ]; then
        FLAG=$(grep -oP 'vere\{[^}]+\}' "$LOG_FILE" 2>/dev/null | tail -1 || true)
    fi

    local STATUS="FAILED"
    if [ -n "$FLAG" ]; then
        STATUS="SOLVED"
        echo "$FLAG" > "$CHAL_PATH/flag.txt"
    fi

    # Write result JSON
    cat > "$RESULT_FILE" << ENDJSON
{"challenge": "$CHAL_NAME", "status": "$STATUS", "flag": "$FLAG", "elapsed": $ELAPSED, "exit_code": $EXIT_CODE}
ENDJSON

    if [ "$STATUS" = "SOLVED" ]; then
        echo "[$(date +%H:%M:%S)] [+] $CHAL_NAME SOLVED in ${ELAPSED}s → $FLAG"
    else
        echo "[$(date +%H:%M:%S)] [x] $CHAL_NAME FAILED in ${ELAPSED}s (exit=$EXIT_CODE)"
    fi
}

# Launch all in parallel (up to MAX_PARALLEL)
PIDS=()
for CHAL in "${CHALLENGES[@]}"; do
    solve_one "$CHAL" &
    PIDS+=($!)

    # Throttle if we hit max parallel
    while [ $(jobs -r | wc -l) -ge "$MAX_PARALLEL" ]; do
        sleep 1
    done
done

# Wait for all
for PID in "${PIDS[@]}"; do
    wait "$PID" 2>/dev/null || true
done

BATCH_ELAPSED=$(( $(date +%s) - BATCH_START ))

# Collect and print results
echo ""
echo "============================================================"
echo "  RESULTS"
echo "============================================================"
echo ""
echo "| # | Challenge | Status | Flag | Time |"
echo "|---|-----------|--------|------|------|"

SOLVED=0
TOTAL=0
for RESULT_FILE in "$RESULTS_DIR"/*.json; do
    [ -f "$RESULT_FILE" ] || continue
    TOTAL=$((TOTAL + 1))
    CHAL=$(python3 -c "import json; print(json.load(open('$RESULT_FILE'))['challenge'])")
    STATUS=$(python3 -c "import json; print(json.load(open('$RESULT_FILE'))['status'])")
    FLAG=$(python3 -c "import json; print(json.load(open('$RESULT_FILE'))['flag'])")
    ELAPSED=$(python3 -c "import json; print(json.load(open('$RESULT_FILE'))['elapsed'])")

    if [ "$STATUS" = "SOLVED" ]; then
        SOLVED=$((SOLVED + 1))
    fi

    echo "| $TOTAL | $CHAL | $STATUS | $FLAG | ${ELAPSED}s |"
done

echo ""
RATE=$(python3 -c "print(f'{$SOLVED/$TOTAL*100:.0f}%')" 2>/dev/null || echo "?%")
echo "Score: $SOLVED/$TOTAL ($RATE) in ${BATCH_ELAPSED}s (parallel)"
echo "Results: $RESULTS_DIR/"

# Cleanup
rm -rf "$RESULTS_DIR"
