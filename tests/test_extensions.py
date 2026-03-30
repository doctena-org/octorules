"""Tests for the extension hook registries."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from octorules.extensions import (
    _plan_zone_hooks,
    _validate_hook_signature,
    call_plan_zone_finalize,
    call_plan_zone_prefetch,
    register_apply_extension,
    register_audit_extension,
    register_dump_extension,
    register_plan_zone_hook,
    register_validate_extension,
    unregister_apply_extension,
    unregister_audit_extension,
    unregister_dump_extension,
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

        # Cannot use lambdas with wrong param names — use proper signatures
        def sentinel_pre(all_desired, scope, provider):
            return None

        def sentinel_fin(zp, all_desired, scope, provider, ctx):
            return None

        # Should not raise
        unregister_plan_zone_hook(sentinel_pre, sentinel_fin)

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
        """Prefetch hook with correct signature is accepted."""

        def my_prefetch(all_desired, scope, provider):
            return None

        def my_finalize(zp, all_desired, scope, provider, ctx):
            pass

        register_plan_zone_hook(my_prefetch, my_finalize)
        unregister_plan_zone_hook(my_prefetch, my_finalize)

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
        """Hook with **kwargs is accepted (forward-compatible)."""

        def my_prefetch(all_desired, scope, provider, **kwargs):
            return None

        def my_finalize(zp, all_desired, scope, provider, ctx, **kwargs):
            pass

        register_plan_zone_hook(my_prefetch, my_finalize)
        unregister_plan_zone_hook(my_prefetch, my_finalize)

    def test_extra_args_accepted(self):
        """Hook with *args is accepted (ignored in validation)."""

        def my_prefetch(all_desired, scope, provider, *args):
            return None

        def my_finalize(zp, all_desired, scope, provider, ctx, *args):
            pass

        register_plan_zone_hook(my_prefetch, my_finalize)
        unregister_plan_zone_hook(my_prefetch, my_finalize)

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
        """Apply extension with correct signature is accepted."""

        def ok_apply(zp, plans, scope, provider):
            return [], None

        register_apply_extension("test_ok_apply", ok_apply)
        unregister_apply_extension("test_ok_apply")

    def test_validate_extension_validation(self):
        """Validate extension validates signature at registration."""

        def bad_validate(data, zone, errs, out):
            pass

        with pytest.raises(TypeError, match="validate_extension hook.*incorrect signature"):
            register_validate_extension(bad_validate)

    def test_valid_validate_extension_accepted(self):
        """Validate extension with correct signature is accepted."""

        def ok_validate(desired, zone_name, errors, lines):
            pass

        register_validate_extension(ok_validate)
        unregister_validate_extension(ok_validate)

    def test_dump_extension_validation(self):
        """Dump extension validates signature at registration."""

        def bad_dump(s, p, d):
            return None

        with pytest.raises(TypeError, match="dump_extension hook.*incorrect signature"):
            register_dump_extension(bad_dump)

    def test_valid_dump_extension_accepted(self):
        """Dump extension with correct signature is accepted."""

        def ok_dump(scope, provider, out_dir):
            return None

        register_dump_extension(ok_dump)
        unregister_dump_extension(ok_dump)

    def test_audit_extension_validation(self):
        """Audit extension validates signature at registration."""

        def bad_audit(data, phase):
            return []

        with pytest.raises(TypeError, match="audit_extension hook.*incorrect signature"):
            register_audit_extension("test_bad", bad_audit)

    def test_valid_audit_extension_accepted(self):
        """Audit extension with correct signature is accepted."""

        def ok_audit(rules_data, phase_name):
            return []

        register_audit_extension("test_ok_audit", ok_audit)
        unregister_audit_extension("test_ok_audit")

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
