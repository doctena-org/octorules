"""Tests for the provider base protocol and shared types."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from octorules.provider.base import (
    SUPPORTS_CUSTOM_RULESETS,
    SUPPORTS_LISTS,
    SUPPORTS_PAGE_SHIELD,
    SUPPORTS_ZONE_DISCOVERY,
    BaseProvider,
    PhaseRulesResult,
    Scope,
    provider_supports,
)

_cf_installed: bool
try:
    import octorules_cloudflare  # noqa: F401

    _cf_installed = True
except ImportError:
    _cf_installed = False


class TestBaseProviderProtocol:
    @pytest.mark.skipif(not _cf_installed, reason="octorules-cloudflare not installed")
    def test_cloudflare_provider_satisfies_base_protocol(self):
        """CloudflareProvider must be recognized as a BaseProvider at runtime."""
        from octorules.provider import CloudflareProvider

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


class TestProviderSupports:
    def test_with_full_supports(self):
        prov = MagicMock()
        prov.SUPPORTS = frozenset({SUPPORTS_CUSTOM_RULESETS, SUPPORTS_LISTS, SUPPORTS_PAGE_SHIELD})
        assert provider_supports(prov, SUPPORTS_CUSTOM_RULESETS)
        assert provider_supports(prov, SUPPORTS_LISTS)
        assert provider_supports(prov, SUPPORTS_PAGE_SHIELD)

    def test_with_partial_supports(self):
        prov = MagicMock()
        prov.SUPPORTS = frozenset({SUPPORTS_CUSTOM_RULESETS, SUPPORTS_LISTS})
        assert provider_supports(prov, SUPPORTS_CUSTOM_RULESETS)
        assert provider_supports(prov, SUPPORTS_LISTS)
        assert not provider_supports(prov, SUPPORTS_PAGE_SHIELD)

    def test_with_empty_supports(self):
        prov = MagicMock()
        prov.SUPPORTS = frozenset()
        assert not provider_supports(prov, SUPPORTS_CUSTOM_RULESETS)
        assert not provider_supports(prov, SUPPORTS_LISTS)
        assert not provider_supports(prov, SUPPORTS_PAGE_SHIELD)

    def test_without_supports_attribute(self):
        """Providers without SUPPORTS are assumed to support everything."""
        prov = MagicMock(spec=[])
        assert provider_supports(prov, SUPPORTS_CUSTOM_RULESETS)
        assert provider_supports(prov, SUPPORTS_LISTS)
        assert provider_supports(prov, SUPPORTS_PAGE_SHIELD)

    def test_constants_importable_from_provider(self):
        from octorules.provider import (
            SUPPORTS_CUSTOM_RULESETS as C,
        )
        from octorules.provider import (
            SUPPORTS_LISTS as L,
        )
        from octorules.provider import (
            SUPPORTS_PAGE_SHIELD as P,
        )
        from octorules.provider import (
            provider_supports as ps,
        )

        assert C == "custom_rulesets"
        assert L == "lists"
        assert P == "page_shield"
        assert ps is provider_supports


class TestSupportsZoneDiscovery:
    def test_constant_value(self):
        assert SUPPORTS_ZONE_DISCOVERY == "zone_discovery"

    def test_importable_from_provider(self):
        from octorules.provider import SUPPORTS_ZONE_DISCOVERY as ZD

        assert ZD == "zone_discovery"
