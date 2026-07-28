"""Tests for the extension hook registries."""

from unittest.mock import MagicMock

import pytest

from octorules.extensions import (
    _apply_extensions,
    _audit_extensions,
    _plan_zone_hooks,
    _validate_extensions,
    _validate_hook_signature,
    call_audit_extensions,
    call_plan_zone_finalize,
    call_plan_zone_prefetch,
    call_validate_extensions,
    get_format_extensions,
    register_apply_extension,
    register_audit_extension,
    register_format_extension,
    register_plan_zone_hook,
    register_validate_extension,
    unregister_apply_extension,
    unregister_audit_extension,
    unregister_format_extension,
    unregister_plan_zone_hook,
    unregister_validate_extension,
)
from octorules.provider.base import Scope


class TestPlanZoneHookPrefetch:
    """Tests for plan zone prefetch/finalize hook lifecycle."""

    def test_prefetch_exception_propagates(self):
        """Exception in prefetch hook propagates correctly."""

        def bad_prefetch(all_desired, scope, provider):
            raise RuntimeError("prefetch failed")

        def noop_finalize(zp, all_desired, scope, provider, ctx):
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
            def prefetch(all_desired, scope, provider):
                call_log.append(f"prefetch-{tag}")
                return f"ctx-{tag}"

            def finalize(zp, all_desired, scope, provider, ctx):
                call_log.append(f"finalize-{tag}")
                assert ctx == f"ctx-{tag}"

            return prefetch, finalize

        # Account for hooks registered by real providers (e.g. Page Shield)
        baseline = len(_plan_zone_hooks)

        hooks = [make_hooks(i) for i in range(3)]
        for pf, fn in hooks:
            register_plan_zone_hook(pf, fn)
        try:
            scope = Scope(zone_id="z1")
            provider = MagicMock()

            pairs = call_plan_zone_prefetch({}, scope, provider)
            assert len(pairs) == baseline + 3
            # Prefetch hooks run concurrently — order is non-deterministic,
            # but all three must have been called.
            assert set(call_log) == {"prefetch-0", "prefetch-1", "prefetch-2"}

            call_log.clear()
            zp = MagicMock()
            call_plan_zone_finalize(zp, {}, scope, provider, pairs)
            assert call_log == ["finalize-0", "finalize-1", "finalize-2"]
        finally:
            for pf, fn in hooks:
                unregister_plan_zone_hook(pf, fn)

    def test_unregister_nonexistent_hook_is_noop(self):
        """Unregistering a hook that was never registered doesn't raise and
        leaves the registry unchanged."""

        # Cannot use lambdas with wrong param names — use proper signatures
        def sentinel_pre(all_desired, scope, provider):
            return None

        def sentinel_fin(zp, all_desired, scope, provider, ctx):
            return None

        before = list(_plan_zone_hooks)
        unregister_plan_zone_hook(sentinel_pre, sentinel_fin)  # Should not raise
        assert (sentinel_pre, sentinel_fin) not in _plan_zone_hooks
        assert _plan_zone_hooks == before

    def test_finalize_exception_propagates(self):
        """Exception in finalize hook propagates correctly."""

        def ok_prefetch(all_desired, scope, provider):
            return "ok"

        def bad_finalize(zp, all_desired, scope, provider, ctx):
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

    def test_concurrent_prefetch_preserves_result_order(self):
        """Results are returned in registration order, not completion order."""
        import threading
        import time

        barrier = threading.Barrier(3)

        def make_hooks(tag, delay):
            def prefetch(all_desired, scope, provider):
                barrier.wait()  # Synchronize all hooks to start together
                time.sleep(delay)
                return f"ctx-{tag}"

            def finalize(zp, all_desired, scope, provider, ctx):
                pass

            return prefetch, finalize

        # Hook-1 completes fastest, hook-0 and hook-2 are slower.
        hooks = [
            make_hooks(0, 0.1),  # registered first, slow
            make_hooks(1, 0.0),  # registered second, fastest
            make_hooks(2, 0.05),  # registered third, medium
        ]
        for pf, fn in hooks:
            register_plan_zone_hook(pf, fn)
        try:
            scope = Scope(zone_id="z1")
            provider = MagicMock()
            pairs = call_plan_zone_prefetch({}, scope, provider)

            # Extract our test results (skip any baseline hooks from real providers).
            our_pairs = [
                (fin, ctx) for fin, ctx in pairs if isinstance(ctx, str) and ctx.startswith("ctx-")
            ]
            assert len(our_pairs) == 3
            # Must be in registration order (0, 1, 2) not completion order (1, 2, 0).
            assert [ctx for _fin, ctx in our_pairs] == ["ctx-0", "ctx-1", "ctx-2"]
        finally:
            for pf, fn in hooks:
                unregister_plan_zone_hook(pf, fn)

    def test_prefetch_error_cancels_concurrent_hooks(self):
        """Error in one concurrent hook propagates without hanging."""
        from octorules.provider.exceptions import ProviderAuthError

        def ok_prefetch_0(all_desired, scope, provider):
            return "ctx-0"

        def ok_finalize_0(zp, all_desired, scope, provider, ctx):
            pass

        def bad_prefetch(all_desired, scope, provider):
            raise ProviderAuthError("auth expired")

        def bad_finalize(zp, all_desired, scope, provider, ctx):
            pass

        def ok_prefetch_2(all_desired, scope, provider):
            return "ctx-2"

        def ok_finalize_2(zp, all_desired, scope, provider, ctx):
            pass

        hooks = [
            (ok_prefetch_0, ok_finalize_0),
            (bad_prefetch, bad_finalize),
            (ok_prefetch_2, ok_finalize_2),
        ]
        for pf, fn in hooks:
            register_plan_zone_hook(pf, fn)
        try:
            with pytest.raises(ProviderAuthError, match="auth expired"):
                call_plan_zone_prefetch({}, Scope(zone_id="z1"), MagicMock())
        finally:
            for pf, fn in hooks:
                unregister_plan_zone_hook(pf, fn)

    def test_hooks_cleaned_up_after_test(self):
        """Verify hooks don't leak between tests (sanity check for test isolation)."""
        # If previous tests leaked hooks, this would fail.
        # We can't assert it's completely empty since other test modules might
        # have loaded, but we verify no hooks with our specific test markers.
        for prefetch, _finalize in _plan_zone_hooks:
            # None of the hooks from our tests above should remain
            assert "prefetch failed" not in str(prefetch)


class TestHookSignatureValidation:
    """Tests for _validate_hook_signature and registration-time validation."""

    def test_valid_prefetch_hook_accepted(self):
        """Prefetch hook with correct signature is accepted and registered."""

        def my_prefetch(all_desired, scope, provider):
            return None

        def my_finalize(zp, all_desired, scope, provider, ctx):
            pass

        register_plan_zone_hook(my_prefetch, my_finalize)
        assert (my_prefetch, my_finalize) in _plan_zone_hooks
        unregister_plan_zone_hook(my_prefetch, my_finalize)
        assert (my_prefetch, my_finalize) not in _plan_zone_hooks

    def test_invalid_prefetch_hook_rejected(self):
        """Prefetch hook with wrong parameter names raises TypeError."""

        def bad_prefetch(data, scope, prov):
            return None

        def ok_finalize(zp, all_desired, scope, provider, ctx):
            pass

        with pytest.raises(TypeError, match="plan_zone_prefetch hook.*incorrect signature"):
            register_plan_zone_hook(bad_prefetch, ok_finalize)

    def test_invalid_finalize_hook_rejected(self):
        """Finalize hook with wrong parameter names raises TypeError."""

        def ok_prefetch(all_desired, scope, provider):
            return None

        def bad_finalize(zone_plan, desired, scope, provider, context):
            pass

        with pytest.raises(TypeError, match="plan_zone_finalize hook.*incorrect signature"):
            register_plan_zone_hook(ok_prefetch, bad_finalize)

    def test_extra_kwargs_accepted(self):
        """Hook with **kwargs is accepted (forward-compatible) and registered."""

        def my_prefetch(all_desired, scope, provider, **kwargs):
            return None

        def my_finalize(zp, all_desired, scope, provider, ctx, **kwargs):
            pass

        register_plan_zone_hook(my_prefetch, my_finalize)
        assert (my_prefetch, my_finalize) in _plan_zone_hooks
        unregister_plan_zone_hook(my_prefetch, my_finalize)
        assert (my_prefetch, my_finalize) not in _plan_zone_hooks

    def test_extra_args_accepted(self):
        """Hook with *args is accepted (ignored in validation) and registered."""

        def my_prefetch(all_desired, scope, provider, *args):
            return None

        def my_finalize(zp, all_desired, scope, provider, ctx, *args):
            pass

        register_plan_zone_hook(my_prefetch, my_finalize)
        assert (my_prefetch, my_finalize) in _plan_zone_hooks
        unregister_plan_zone_hook(my_prefetch, my_finalize)
        assert (my_prefetch, my_finalize) not in _plan_zone_hooks

    def test_wrong_param_names_same_count_rejected(self):
        """Hook with wrong param names (even if count matches) is rejected."""

        def bad(x, y, z):
            return None

        with pytest.raises(TypeError, match="incorrect signature"):
            _validate_hook_signature("test", bad, ("all_desired", "scope", "provider"))

    def test_wrong_param_count_rejected(self):
        """Hook with wrong number of params is rejected."""

        def too_few(scope, provider):
            return None

        with pytest.raises(TypeError, match="incorrect signature"):
            _validate_hook_signature("test", too_few, ("all_desired", "scope", "provider"))

    def test_apply_extension_validation(self):
        """Apply extension validates signature at registration."""

        def bad_apply(zone_plan, plans, scope, prov):
            return [], None

        with pytest.raises(TypeError, match="apply_extension hook.*incorrect signature"):
            register_apply_extension("test_bad", bad_apply)

    def test_valid_apply_extension_accepted(self):
        """Apply extension with correct signature is accepted and registered."""

        def ok_apply(zp, plans, scope, provider):
            return [], None

        register_apply_extension("test_ok_apply", ok_apply)
        assert _apply_extensions.get("test_ok_apply") is ok_apply
        unregister_apply_extension("test_ok_apply")
        assert "test_ok_apply" not in _apply_extensions

    def test_validate_extension_validation(self):
        """Validate extension validates signature at registration."""

        def bad_validate(data, zone, errs, out):
            pass

        with pytest.raises(TypeError, match="validate_extension hook.*incorrect signature"):
            register_validate_extension(bad_validate)

    def test_valid_validate_extension_accepted(self):
        """Validate extension with correct signature is accepted and registered."""

        def ok_validate(desired, zone_name, errors, lines):
            pass

        register_validate_extension(ok_validate)
        assert ok_validate in _validate_extensions
        unregister_validate_extension(ok_validate)
        assert ok_validate not in _validate_extensions

    def test_audit_extension_validation(self):
        """Audit extension validates signature at registration."""

        def bad_audit(data, phase):
            return []

        with pytest.raises(TypeError, match="audit_extension hook.*incorrect signature"):
            register_audit_extension("test_bad", bad_audit)

    def test_valid_audit_extension_accepted(self):
        """Audit extension with correct signature is accepted and registered."""

        def ok_audit(rules_data, phase_name):
            return []

        register_audit_extension("test_ok_audit", ok_audit)
        assert _audit_extensions.get("test_ok_audit") is ok_audit
        unregister_audit_extension("test_ok_audit")
        assert "test_ok_audit" not in _audit_extensions

    def test_error_message_includes_qualname(self):
        """Error message includes the function's qualified name."""

        def my_special_function(x, y, z):
            pass

        with pytest.raises(
            TypeError,
            match=r"my_special_function.*Expected parameters:.*got:",
        ):
            _validate_hook_signature(
                "test", my_special_function, ("all_desired", "scope", "provider")
            )

    def test_error_message_includes_hook_type(self):
        """Error message includes the hook type for context."""

        def bad(x):
            pass

        with pytest.raises(TypeError, match="^audit_extension hook"):
            _validate_hook_signature("audit_extension", bad, ("rules_data", "phase_name"))


class TestAuditExtensionErrorHandling:
    """Tests for audit extension error handling (strict vs best-effort)."""

    def test_audit_best_effort_returns_partial(self):
        """Default (non-strict): failing extension is recorded but doesn't abort."""
        from octorules.audit import RuleIPInfo

        def good_audit(rules_data, phase_name):
            return [
                RuleIPInfo(
                    zone_name="z",
                    phase_name=phase_name,
                    ref="r1",
                    action="block",
                    ip_ranges=["10.0.0.0/8"],
                )
            ]

        def bad_audit(rules_data, phase_name):
            raise RuntimeError("audit exploded")

        register_audit_extension("good", good_audit)
        register_audit_extension("bad", bad_audit)
        try:
            results, failed = call_audit_extensions({"waf": []}, "waf")
            assert len(results) == 1
            assert results[0].ref == "r1"
            assert "bad" in failed
        finally:
            unregister_audit_extension("good")
            unregister_audit_extension("bad")

    def test_audit_strict_raises(self):
        """strict=True: failing extension raises immediately."""

        def bad_audit(rules_data, phase_name):
            raise RuntimeError("strict boom")

        register_audit_extension("strict_bad", bad_audit)
        try:
            with pytest.raises(RuntimeError, match="strict boom"):
                call_audit_extensions({"waf": []}, "waf", strict=True)
        finally:
            unregister_audit_extension("strict_bad")

    def test_audit_strict_false_is_default(self):
        """Explicit strict=False matches default behavior."""

        def bad_audit(rules_data, phase_name):
            raise ValueError("non-fatal")

        register_audit_extension("strict_false", bad_audit)
        try:
            results, failed = call_audit_extensions({"waf": []}, "waf", strict=False)
            assert results == []
            assert "strict_false" in failed
        finally:
            unregister_audit_extension("strict_false")


class TestRegistrySnapshotSafety:
    """Tests that call_* functions snapshot registries before iterating.

    This prevents ``RuntimeError: dictionary changed size during iteration``
    when a hook registration happens concurrently with iteration.
    """

    def test_get_format_extensions_returns_snapshot(self):
        """get_format_extensions() returns a copy, not a live reference."""
        sentinel_name = "_snapshot_test_fmt"
        # Ensure clean state
        unregister_format_extension(sentinel_name)

        snapshot = get_format_extensions()
        assert isinstance(snapshot, dict)
        assert sentinel_name not in snapshot

        # Register a new format extension AFTER taking the snapshot.
        fmt = MagicMock()
        register_format_extension(sentinel_name, fmt)
        try:
            # The snapshot must NOT contain the newly registered extension.
            assert sentinel_name not in snapshot
            # But a fresh call should see it.
            assert sentinel_name in get_format_extensions()
        finally:
            unregister_format_extension(sentinel_name)

    def test_call_validate_extensions_snapshot_during_iteration(self):
        """Iteration over a snapshot is safe even if a hook mutates the registry.

        We register a validate hook that, when called, registers *another*
        validate hook.  Without snapshotting, this would raise
        ``RuntimeError: list changed size during iteration``.
        """
        call_log = []
        inner_registered = False

        def inner_hook(desired, zone_name, errors, lines):
            call_log.append("inner")

        def mutating_hook(desired, zone_name, errors, lines):
            nonlocal inner_registered
            call_log.append("mutating")
            # Mutate the live registry during iteration — the snapshot
            # protects against RuntimeError here.
            if not inner_registered:
                register_validate_extension(inner_hook)
                inner_registered = True

        register_validate_extension(mutating_hook)
        try:
            # Must NOT raise RuntimeError.
            call_validate_extensions({}, "example.com", [], [])
            assert "mutating" in call_log
            # inner_hook was registered by mutating_hook, but the iteration
            # used a snapshot so inner_hook was NOT called in this pass.
            assert "inner" not in call_log

            # A second call should now invoke both hooks because inner_hook
            # is part of the registry.
            call_log.clear()
            call_validate_extensions({}, "example.com", [], [])
            assert "mutating" in call_log
            assert "inner" in call_log
        finally:
            unregister_validate_extension(mutating_hook)
            unregister_validate_extension(inner_hook)
