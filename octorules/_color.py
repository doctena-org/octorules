"""ANSI color utilities for CLI output.

Provides:

- :class:`Pen` — semantic text colorizer (``pen.success("done")``).
- :class:`ColoredFormatter` — logging formatter with level-based + per-message coloring.
- :func:`supports_color` — TTY / ``NO_COLOR`` / ``FORCE_COLOR`` detection.
"""

import logging
import os
import sys
from typing import ClassVar

# ---------------------------------------------------------------------------
# Raw ANSI codes — private; callers use Pen methods or ColoredFormatter.
# The only exception is formatter.py's _CHANGE_COLORS dict, which needs
# the raw codes for its per-change-type color mapping.
# ---------------------------------------------------------------------------

_GREEN = "\033[32m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_BOLD = "\033[1m"
_DIM = "\033[2m"
_RESET = "\033[0m"


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
def supports_color(stream: object | None = None) -> bool:
    """Check if *stream* supports ANSI color.

    Respects the ``NO_COLOR`` (https://no-color.org/) and ``FORCE_COLOR``
    environment variables.  When *stream* is ``None``, checks ``sys.stdout``.
    """
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("FORCE_COLOR") is not None:
        return True
    if stream is None:
        stream = sys.stdout
    return hasattr(stream, "isatty") and stream.isatty()


# ---------------------------------------------------------------------------
# Pen — semantic colorizer
# ---------------------------------------------------------------------------
class Pen:
    """Semantic text colorizer.

    Wraps text in ANSI codes when color is enabled, returns plain text
    otherwise.  Immutable after construction, thread-safe.

    Usage::

        p = Pen(use_color=True)
        print(p.header("Zone example.com:") + " 3 changes")
        print(p.success("  cache_rules: done"))
    """

    __slots__ = ("use_color",)

    def __init__(self, use_color: bool) -> None:
        self.use_color = use_color

    def _wrap(self, text: str, code: str) -> str:
        if not self.use_color:
            return text
        return f"{code}{text}{_RESET}"

    # Semantic roles — each maps to exactly one ANSI code.
    def error(self, text: str) -> str:
        return self._wrap(text, _RED)

    def warning(self, text: str) -> str:
        return self._wrap(text, _YELLOW)

    def success(self, text: str) -> str:
        return self._wrap(text, _GREEN)

    def info(self, text: str) -> str:
        return self._wrap(text, _CYAN)

    def header(self, text: str) -> str:
        return self._wrap(text, _BOLD)

    def muted(self, text: str) -> str:
        return self._wrap(text, _DIM)

    # Escape hatch for raw ANSI codes (plan diff change-type colors).
    def raw(self, text: str, code: str) -> str:
        return self._wrap(text, code)


def pen(stream: object | None = None) -> Pen:
    """Return a :class:`Pen` for *stream* (default: ``sys.stdout``)."""
    return Pen(supports_color(stream))


# ---------------------------------------------------------------------------
# ColoredFormatter — logging integration
# ---------------------------------------------------------------------------
class ColoredFormatter(logging.Formatter):
    """Logging formatter with ANSI color support.

    Colors by log level (ERROR=red, WARNING=yellow, DEBUG=dim) with
    optional per-message overrides via ``extra={"color": "success"}``.

    The ``color`` extra value is a semantic name matching :class:`Pen`
    methods: ``"error"``, ``"warning"``, ``"success"``, ``"info"``,
    ``"header"``, ``"muted"``.
    """

    _LEVEL_CODE: ClassVar[dict[int, str]] = {
        logging.ERROR: _RED,
        logging.WARNING: _YELLOW,
        logging.DEBUG: _DIM,
    }
    _SEMANTIC_CODE: ClassVar[dict[str, str]] = {
        "error": _RED,
        "warning": _YELLOW,
        "success": _GREEN,
        "info": _CYAN,
        "header": _BOLD,
        "muted": _DIM,
    }

    def __init__(self, fmt: str = "%(message)s", *, use_color: bool = True) -> None:
        super().__init__(fmt)
        self.use_color = use_color

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        if not self.use_color:
            return message
        # Per-message semantic override takes priority.
        color_name = getattr(record, "color", None)
        if color_name is not None:
            code = self._SEMANTIC_CODE.get(color_name)
        else:
            code = self._LEVEL_CODE.get(record.levelno)
        if code is not None:
            return f"{code}{message}{_RESET}"
        return message
