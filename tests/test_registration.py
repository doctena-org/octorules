"""Tests for octorules.registration.idempotent_registration."""

from __future__ import annotations

import threading

import pytest

from octorules.registration import idempotent_registration


class TestIdempotentRegistration:
    def test_first_call_executes(self):
        calls = []

        @idempotent_registration
        def register() -> None:
            calls.append(1)

        register()
        assert calls == [1]

    def test_repeat_calls_are_noops(self):
        calls = []

        @idempotent_registration
        def register() -> None:
            calls.append(1)

        for _ in range(5):
            register()
        assert calls == [1]

    def test_wraps_preserves_name_and_doc(self):
        @idempotent_registration
        def register_something() -> None:
            """Do the thing."""

        assert register_something.__name__ == "register_something"
        assert register_something.__doc__ == "Do the thing."

    def test_distinct_decorations_have_independent_state(self):
        a_calls: list[int] = []
        b_calls: list[int] = []

        @idempotent_registration
        def register_a() -> None:
            a_calls.append(1)

        @idempotent_registration
        def register_b() -> None:
            b_calls.append(1)

        register_a()
        register_b()
        register_a()
        register_b()

        assert a_calls == [1]
        assert b_calls == [1]

    def test_concurrent_first_calls_execute_fn_exactly_once(self):
        # Regression: if the lock is missing or the flag is read outside
        # the lock, many threads will all observe done=False and every
        # one of them will execute fn() before the first setter wins.
        calls: list[int] = []
        barrier = threading.Barrier(20)

        @idempotent_registration
        def register() -> None:
            calls.append(1)

        def worker() -> None:
            barrier.wait()
            register()

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert calls == [1]

    def test_exception_in_first_call_does_not_mark_as_done(self):
        # If registration raises, the flag must not flip — otherwise a
        # transient error (e.g. a lazy import failure) would permanently
        # leave the system unregistered with no retry path.
        attempts: list[int] = []

        @idempotent_registration
        def register() -> None:
            attempts.append(len(attempts) + 1)
            if attempts[-1] == 1:
                raise RuntimeError("first-call failure")

        with pytest.raises(RuntimeError):
            register()
        assert attempts == [1]

        # Second call retries and succeeds.
        register()
        assert attempts == [1, 2]

        # Third call is a no-op.
        register()
        assert attempts == [1, 2]
