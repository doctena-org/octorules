"""Tests for the extension hook registries."""

from unittest.mock import MagicMock

import pytest

from octorules.extensions import (
    _VALIDATE_PARAMS,
    ProviderExtension,
    _audit_extensions,
    _validate_extensions,
    _validate_hook_signature,
    call_audit_extensions,
    call_plan_zone_finalize,
    call_plan_zone_prefetch,
    call_validate_extensions,
    get_format_extensions,
    register_audit_extension,
    register_format_extension,
    register_validate_extension,
    unregister_audit_extension,
    unregister_format_extension,
    unregister_validate_extension,
)
from octorules.provider.base import Scope


class _FakeProvider:
    """A provider whose extensions are supplied directly."""

    def __init__(self, extensions):
        self.extensions = extensions


def _ext(name, prefetch=None, finalize=None):
    """Build a one-off ProviderExtension with the given stages."""

    class _E(ProviderExtension):
        section = ""  # always applicable

        def prefetch(self, desired, scope, provider):
            return prefetch(desired, scope, provider) if prefetch else None

        def finalize(self, zp, desired, scope, provider, ctx):
            if finalize:
                finalize(zp, desired, scope, provider, ctx)

    _E.__name__ = name
    return _E()


class TestProviderExtensionPrefetch:
    """Prefetch runs the provider's own extensions, concurrently."""

    def test_prefetch_exception_propagates(self):
        def boom(desired, scope, provider):
            raise RuntimeError("prefetch failed")

        provider = _FakeProvider([_ext("Boom", prefetch=boom)])
        with pytest.raises(RuntimeError, match="prefetch failed"):
            call_plan_zone_prefetch({}, Scope(zone_id="z1"), provider)

    def test_all_extensions_called(self):
        calls = []
        exts = [
            _ext(f"E{i}", prefetch=lambda d, s, p, i=i: calls.append(i) or f"ctx-{i}")
            for i in range(3)
        ]
        pairs = call_plan_zone_prefetch({}, Scope(zone_id="z1"), _FakeProvider(exts))
        assert sorted(calls) == [0, 1, 2]
        assert [ctx for _e, ctx in pairs] == ["ctx-0", "ctx-1", "ctx-2"]

    def test_only_applicable_extensions_run(self):
        """Core applies the section check, so an extension whose section is
        absent never runs — the guard every hook used to repeat by hand."""
        ran = []

        class _Scoped(ProviderExtension):
            section = "someprov.thing"

            def prefetch(self, desired, scope, provider):
                ran.append("yes")
                return "ctx"

        provider = _FakeProvider([_Scoped()])
        assert call_plan_zone_prefetch({}, Scope(zone_id="z1"), provider) == []
        assert ran == []
        pairs = call_plan_zone_prefetch({"someprov.thing": {}}, Scope(zone_id="z1"), provider)
        assert ran == ["yes"] and [c for _e, c in pairs] == ["ctx"]

    def test_no_extensions_is_a_noop(self):
        assert call_plan_zone_prefetch({}, Scope(zone_id="z1"), _FakeProvider([])) == []
        # A provider predating the property at all.
        assert call_plan_zone_prefetch({}, Scope(zone_id="z1"), object()) == []

    def test_finalize_exception_propagates(self):
        def boom(zp, desired, scope, provider, ctx):
            raise RuntimeError("finalize failed")

        provider = _FakeProvider([_ext("Boom", finalize=boom)])
        pairs = call_plan_zone_prefetch({}, Scope(zone_id="z1"), provider)
        with pytest.raises(RuntimeError, match="finalize failed"):
            call_plan_zone_finalize(MagicMock(), {}, Scope(zone_id="z1"), provider, pairs)

    def test_concurrent_prefetch_preserves_result_order(self):
        """Results come back in extension order, not completion order."""
        import threading
        import time

        barrier = threading.Barrier(3)

        def make(tag, delay):
            def prefetch(desired, scope, provider):
                barrier.wait()  # start together
                time.sleep(delay)
                return f"ctx-{tag}"

            return _ext(f"E{tag}", prefetch=prefetch)

        # Index 1 finishes first, index 0 last.
        exts = [make(0, 0.1), make(1, 0.0), make(2, 0.05)]
        pairs = call_plan_zone_prefetch({}, Scope(zone_id="z1"), _FakeProvider(exts))
        assert [ctx for _e, ctx in pairs] == ["ctx-0", "ctx-1", "ctx-2"]

    def test_prefetch_error_cancels_concurrent_extensions(self):
        """An error propagates without hanging the others."""
        from octorules.provider.exceptions import ProviderAuthError

        def bad(desired, scope, provider):
            raise ProviderAuthError("auth expired")

        exts = [
            _ext("Ok0", prefetch=lambda d, s, p: "ctx-0"),
            _ext("Bad", prefetch=bad),
            _ext("Ok2", prefetch=lambda d, s, p: "ctx-2"),
        ]
        with pytest.raises(ProviderAuthError, match="auth expired"):
            call_plan_zone_prefetch({}, Scope(zone_id="z1"), _FakeProvider(exts))


class TestHookSignatureValidation:
    """Tests for _validate_hook_signature and registration-time validation."""

    def test_extra_kwargs_accepted(self):
        """A hook with **kwargs stays valid — forward-compatible."""

        def my_validate(desired, zone_name, errors, lines, **kwargs):
            pass

        _validate_hook_signature("validate_extension", my_validate, _VALIDATE_PARAMS)

    def test_extra_args_accepted(self):
        """A hook with *args stays valid — only named parameters are checked."""

        def my_validate(desired, zone_name, errors, lines, *args):
            pass

        _validate_hook_signature("validate_extension", my_validate, _VALIDATE_PARAMS)

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
    """Tests for audit extension error handling (best-effort with recording)."""

    def test_audit_best_effort_returns_partial(self):
        """A failing extension is recorded but doesn't abort the others."""
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

    def test_audit_failure_is_recorded_not_raised(self):
        """A failing extension is recorded in ``failed`` and never propagates."""

        def bad_audit(rules_data, phase_name):
            raise ValueError("non-fatal")

        register_audit_extension("recorded_bad", bad_audit)
        try:
            results, failed = call_audit_extensions({"waf": []}, "waf")
            assert results == []
            assert "recorded_bad" in failed
        finally:
            unregister_audit_extension("recorded_bad")


class TestFormatExtensionInterface:
    """register_format_extension checks the protocol's four methods.

    A formatter missing one registers fine and then fails inside plan
    rendering, for only the output mode that needs the missing method — so
    text output can look healthy while ``--format html`` crashes.
    """

    class _Complete:
        def format_text(self, plans, use_color):
            return []

        def format_json(self, plans):
            return []

        def format_markdown(self, plans, pending_diffs):
            return []

        def format_html(self, plans, lines):
            return (0, 0, 0, 0)

    def test_complete_formatter_registers(self):
        name = "_iface_complete"
        try:
            register_format_extension(name, self._Complete())
            assert name in get_format_extensions()
        finally:
            unregister_format_extension(name)

    def test_missing_one_method_is_rejected(self):
        class _NoHtml(TestFormatExtensionInterface._Complete):
            format_html = None

        with pytest.raises(TypeError) as exc:
            register_format_extension("_iface_no_html", _NoHtml())
        assert "format_html" in str(exc.value)
        assert "_iface_no_html" in str(exc.value)
        assert "_iface_no_html" not in get_format_extensions()

    def test_message_lists_every_missing_method(self):
        class _Empty:
            pass

        with pytest.raises(TypeError) as exc:
            register_format_extension("_iface_empty", _Empty())
        msg = str(exc.value)
        for m in ("format_text", "format_json", "format_markdown", "format_html"):
            assert m in msg

    def test_non_callable_attribute_is_not_a_method(self):
        class _Attr(TestFormatExtensionInterface._Complete):
            format_json = "not callable"

        with pytest.raises(TypeError):
            register_format_extension("_iface_attr", _Attr())


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
