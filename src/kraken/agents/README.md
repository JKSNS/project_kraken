# agents/

The agentic delegation seat. This is the harness's escape hatch: when the
deterministic cascade, the model-written solve script, and interactive
exploitation have all stalled, `delegate.py` hands the challenge to a full
agentic fallback (Tier 4) with file access and no graph constraint, the
once-per-challenge last resort.

It is deliberately small. KRAKEN's posture is to reach for open-ended agency
*last*, not first; this package is where that last step lives, kept separate from
the deterministic core so the boundary stays clear. Driven from
`../nodes/solve_engine.py` and the live-competition autopilot.
