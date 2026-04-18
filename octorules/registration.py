"""Thread-safe idempotent registration decorator.

Every provider historically ships a zero-arg ``register_*_linter()``
function that must be safe to call many times (entry-point discovery,
test setup, explicit imports) and safe to call concurrently (test
parallelism, lazy threads).  The canonical pattern was repeated in 18
call sites across core + 5 providers::

    _registered = False
    _register_lock = threading.Lock()

    def register_my_thing() -> None:
        global _registered
        with _register_lock:
            if _registered:
                return
            ...
            _registered = True

Consolidated here in v0.26.0.  Usage::

    from octorules.registration import idempotent_registration

    @idempotent_registration
    def register_my_thing() -> None:
        ...  # imports + register_* calls

Subsequent calls are no-ops.  The very first concurrent race is
serialized by a per-function Lock allocated at decoration time.
"""

from __future__ import annotations

import functools
import threading
from collections.abc import Callable

__all__ = ["idempotent_registration"]


def idempotent_registration(fn: Callable[[], None]) -> Callable[[], None]:
    """Wrap a zero-arg registration function so that:

    1. The first call executes ``fn()``.
    2. Subsequent calls are silent no-ops.
    3. Concurrent first calls are serialized — only one executes ``fn``.

    The wrapper preserves the original function's name and docstring.
    """
    lock = threading.Lock()
    done = False

    @functools.wraps(fn)
    def wrapper() -> None:
        nonlocal done
        # Fast path: already done, no lock needed after the initial race.
        if done:
            return
        with lock:
            if done:
                return
            fn()
            done = True

    return wrapper
