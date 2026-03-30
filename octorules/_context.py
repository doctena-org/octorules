"""Process-wide context flags for output control."""

from __future__ import annotations

import contextvars

_quiet: contextvars.ContextVar[bool] = contextvars.ContextVar("quiet", default=False)


def set_quiet(value: bool) -> None:
    """Set the quiet flag (suppresses informational stdout output)."""
    _quiet.set(value)


def is_quiet() -> bool:
    """Return True if informational stdout output should be suppressed."""
    return _quiet.get()
