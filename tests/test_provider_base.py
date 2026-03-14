"""Tests for the provider base protocol and shared types."""

from __future__ import annotations

from octorules.provider import CloudflareProvider
from octorules.provider.base import BaseProvider, PhaseRulesResult, Scope


class TestBaseProviderProtocol:
    def test_cloudflare_provider_satisfies_base_protocol(self):
        """CloudflareProvider must be recognized as a BaseProvider at runtime."""
        # Use __new__ to avoid __init__ (which needs a token/client).
        # Note: issubclass() doesn't work with runtime_checkable protocols that
        # have non-method members (properties), so we use isinstance() instead.
        instance = CloudflareProvider.__new__(CloudflareProvider)
        assert isinstance(instance, BaseProvider)


class TestScopeImportPaths:
    def test_scope_importable_from_provider(self):
        from octorules.provider import Scope as ScopeFromProvider

        assert ScopeFromProvider is Scope

    def test_scope_importable_from_base(self):
        from octorules.provider.base import Scope as ScopeFromBase

        assert ScopeFromBase is Scope

    def test_phase_rules_result_importable_from_provider(self):
        from octorules.provider import PhaseRulesResult as PRRFromProvider

        assert PRRFromProvider is PhaseRulesResult

    def test_phase_rules_result_importable_from_base(self):
        from octorules.provider.base import PhaseRulesResult as PRRFromBase

        assert PRRFromBase is PhaseRulesResult


class TestExceptionsImportPaths:
    def test_exceptions_importable_from_provider_exceptions(self):
        from octorules.provider.exceptions import (
            ProviderAuthError,
            ProviderConnectionError,
            ProviderError,
        )

        assert issubclass(ProviderAuthError, ProviderError)
        assert issubclass(ProviderConnectionError, ProviderError)

    def test_base_exceptions_defined(self):
        from octorules.provider.exceptions import (
            ProviderAuthError,
            ProviderConnectionError,
            ProviderError,
        )

        assert issubclass(ProviderAuthError, ProviderError)
        assert issubclass(ProviderConnectionError, ProviderError)


class TestBaseProviderImportPath:
    def test_base_provider_importable_from_provider(self):
        from octorules.provider import BaseProvider as BPFromProvider

        assert BPFromProvider is BaseProvider

    def test_base_provider_importable_from_base(self):
        from octorules.provider.base import BaseProvider as BPFromBase

        assert BPFromBase is BaseProvider
