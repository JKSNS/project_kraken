"""Kraken Attack/Defense -- tick-based A/D CTF infrastructure.

Subsystem for DEF CON Finals-style Attack/Defense competitions where teams
simultaneously exploit opponent services while defending their own.

Key components:
  - engine.GameEngine: Tick-based game loop orchestrating all operations
  - offense/: Exploit management, throwing, and flag submission
  - defense/: Traffic analysis, auto-patching, SLA monitoring, firewall
  - infra/: Team management, networking, scoreboard, container management
  - cli: ``kraken-ad`` command-line entry point

Usage::

    from kraken.ad.engine import GameEngine, GameConfig
    from kraken.ad.config import load_config

    config = load_config("game_config.yaml")
    engine = GameEngine(config)
    asyncio.run(engine.run())
"""

__version__ = "0.1.0"
