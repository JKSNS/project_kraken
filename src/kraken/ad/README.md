# ad/ (Attack-Defense)

The attack-defense (A-D) engine. Where the rest of KRAKEN plays *jeopardy* (read a
challenge, capture a flag), this plays the other CTF format: every team runs the
same services, and each tick you must both **attack** every opponent and
**defend** your own services while keeping them up.

Entry point: `kraken-ad` (`cli.py`).

- `offense/`, each tick, build a task for every opponent x every service and
  mass-throw exploits under a concurrency limit; submit captured flags immediately
  through a deduplicated, rate-limited submitter; prune exploits whose success rate
  drops. A jeopardy solve or a static finding is turned into a standalone pwntools
  exploit and deployed.
- `defense/`, analyze the prior tick's packet capture for shellcode,
  format-string, and cyclic-overflow signatures; auto-patch the service with an
  SLA-gated rollback; replay caught attacks back at opponents; install dynamic
  firewall blocks.
- `infra/`, the tick engine, scoreboard/game-protocol adapters (Faust, iCTF,
  Nautilus, generic), and SLA monitoring that tie a full round together.

**Maturity: growing.** This engine is built and carries substantial unit coverage,
but it has **not** been proven across a full live A-D competition. Read it as an
architecture with tests, not a track record. See `../README.md`.
