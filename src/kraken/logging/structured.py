"""Structlog JSON configuration."""
from __future__ import annotations

import logging
from pathlib import Path

import structlog


def configure_logging(
    *,
    json_output: bool = True,
    level: str = "INFO",
    log_file: str | Path | None = None,
    extra_file: str | Path | None = None,
) -> None:
    """Configure structlog + stdlib logging.

    Args:
        json_output: Use JSON renderer (True) or console renderer (False).
        level: Log level string.
        log_file: If set, ALL output goes to this file (no terminal output).
        extra_file: If set, output goes to terminal AND this file.
                    Mutually exclusive intent with log_file: use log_file for
                    file-only, extra_file for terminal+file.
    """
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]
    if json_output:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            *shared_processors,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )

    formatter = structlog.stdlib.ProcessorFormatter(
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            renderer,
        ]
    )

    root = logging.getLogger()
    root.handlers.clear()

    if log_file is not None:
        # File only (quiet mode)
        handler = logging.FileHandler(str(log_file), mode="a")
        handler.setFormatter(formatter)
        root.addHandler(handler)
    else:
        # Terminal
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)
        root.addHandler(handler)

        # Also write to file if extra_file is provided
        if extra_file is not None:
            fh = logging.FileHandler(str(extra_file), mode="a")
            fh.setFormatter(formatter)
            root.addHandler(fh)

    root.setLevel(getattr(logging, level.upper()))


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    return structlog.get_logger(name)
