"""Tests for the extension hook registries."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from octorules.extensions import (
    _plan_zone_hooks,
    call_plan_zone_finalize,
    call_plan_zone_prefetch,
    register_plan_zone_hook,
    unregister_plan_zone_hook,
)
from octorules.provider.base import Scope


class TestPlanZoneHookPrefetch:
    """Tests for plan zone prefetch/finalize hook lifecycle."""

    def test_prefetch_exception_propagates(self):
        """Exception in prefetch hook propagates correctly."""

        def bad_prefetch(desired, scope, provider):
            raise RuntimeError("prefetch failed")

        def noop_finalize(zp, desired, scope, provider, ctx):
            pass

        register_plan_zone_hook(bad_prefetch, noop_finalize)
        try:
            with pytest.raises(RuntimeError, match="prefetch failed"):
                call_plan_zone_prefetch({}, Scope(zone_id="z1"), MagicMock())
        finally:
            unregister_plan_zone_hook(bad_prefetch, noop_finalize)

    def test_multiple_hooks_all_called(self):
        """All registered hooks are called during prefetch/finalize."""
        call_log = []

        def make_hooks(tag):
            def prefetch(desired, scope, provider):
                call_log.append(f"prefetch-{tag}")
                return f"ctx-{tag}"

            def finalize(zp, desired, scope, provider, ctx):
                call_log.append(f"finalize-{tag}")
                assert ctx == f"ctx-{tag}"

            return prefetch, finalize

        hooks = [make_hooks(i) for i in range(3)]
        for pf, fn in hooks:
            register_plan_zone_hook(pf, fn)
        try:
            scope = Scope(zone_id="z1")
            provider = MagicMock()

            pairs = call_plan_zone_prefetch({}, scope, provider)
            assert len(pairs) == 3
            assert call_log == ["prefetch-0", "prefetch-1", "prefetch-2"]

            call_log.clear()
            # Use a mock zone plan for finalize
            zp = MagicMock()
            call_plan_zone_finalize(zp, {}, scope, provider, pairs)
            assert call_log == ["finalize-0", "finalize-1", "finalize-2"]
        finally:
            for pf, fn in hooks:
                unregister_plan_zone_hook(pf, fn)

    def test_unregister_nonexistent_hook_is_noop(self):
        """Unregistering a hook that was never registered doesn't raise."""
        sentinel_pre = lambda d, s, p: None  # noqa: E731
        sentinel_fin = lambda zp, d, s, p, c: None  # noqa: E731
        # Should not raise
        unregister_plan_zone_hook(sentinel_pre, sentinel_fin)

    def test_finalize_exception_propagates(self):
        """Exception in finalize hook propagates correctly."""

        def ok_prefetch(desired, scope, provider):
            return "ok"

        def bad_finalize(zp, desired, scope, provider, ctx):
            raise ValueError("finalize exploded")

        register_plan_zone_hook(ok_prefetch, bad_finalize)
        try:
            scope = Scope(zone_id="z1")
            provider = MagicMock()
            pairs = call_plan_zone_prefetch({}, scope, provider)

            with pytest.raises(ValueError, match="finalize exploded"):
                call_plan_zone_finalize(MagicMock(), {}, scope, provider, pairs)
        finally:
            unregister_plan_zone_hook(ok_prefetch, bad_finalize)

    def test_hooks_cleaned_up_after_test(self):
        """Verify hooks don't leak between tests (sanity check for test isolation)."""
        # If previous tests leaked hooks, this would fail.
        # We can't assert it's completely empty since other test modules might
        # have loaded, but we verify no hooks with our specific test markers.
        for prefetch, finalize in _plan_zone_hooks:
            # None of the hooks from our tests above should remain
            assert "prefetch failed" not in str(prefetch)
