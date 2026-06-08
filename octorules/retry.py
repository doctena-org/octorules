"""Retry utilities for provider operations.

Provides a shared :func:`retry_with_backoff` helper so all providers
use consistent exponential backoff with jitter instead of rolling
their own retry loops.
"""

import logging
import random
import time
from collections.abc import Callable
from typing import TypeVar

log = logging.getLogger(__name__)

T = TypeVar("T")


def retry_with_backoff(
    operation: Callable[[], T],
    *,
    retryable: tuple[type[BaseException], ...],
    max_attempts: int = 3,
    backoff: tuple[float, ...] = (1.0, 2.0, 4.0),
    jitter: float = 0.5,
    label: str = "",
) -> T:
    """Execute *operation*, retrying on *retryable* exceptions with backoff.

    Each retry sleeps for ``backoff[attempt] + uniform(0, jitter)`` seconds.
    If *backoff* has fewer entries than ``max_attempts - 1``, the last entry
    is reused.

    Args:
        operation: Zero-argument callable to execute.
        retryable: Exception types that trigger a retry.
        max_attempts: Maximum number of attempts (including the first).
        backoff: Sleep durations between retries.
        jitter: Maximum random jitter added to each sleep (uniform [0, jitter]).
        label: Human-readable label for log messages.

    Returns:
        The return value of *operation* on success.

    Raises:
        The last caught exception if all attempts are exhausted.
    """
    if not backoff:
        backoff = (0.0,)
    last_exc: BaseException | None = None
    for attempt in range(max_attempts):
        try:
            return operation()
        except retryable as exc:
            last_exc = exc
            if attempt < max_attempts - 1:
                idx = min(attempt, len(backoff) - 1)
                delay = backoff[idx] + random.uniform(0, jitter)
                log.warning(
                    "%s: attempt %d/%d failed (%s), retrying in %.1fs",
                    label or "retry",
                    attempt + 1,
                    max_attempts,
                    exc,
                    delay,
                )
                time.sleep(delay)
            else:
                log.warning(
                    "%s: attempt %d/%d failed (%s), giving up",
                    label or "retry",
                    attempt + 1,
                    max_attempts,
                    exc,
                )
    # Reachable only when max_attempts < 1 (the loop body never ran, so no
    # exception was captured). An explicit raise survives `python -O`, which
    # would strip an assert and turn `raise last_exc` into `raise None`.
    if last_exc is None:
        raise ValueError(f"max_attempts must be >= 1, got {max_attempts}")
    raise last_exc
