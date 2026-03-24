"""Tests for the provider base protocol and shared types."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
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

# Check provider availability without importing (avoids phase registration
# collisions with conftest's test phases).
_PROVIDERS = {
    "octorules_cloudflare": "octorules_cloudflare:CloudflareProvider",
    "octorules_aws": "octorules_aws:AwsWafProvider",
    "octorules_google": "octorules_google:CloudArmorProvider",
}
_available_providers = {
    pkg: class_path
    for pkg, class_path in _PROVIDERS.items()
    if importlib.util.find_spec(pkg) is not None
}


class TestBaseProviderProtocol:
    @pytest.mark.parametrize(
        "pkg,class_path",
        [
            pytest.param(
                pkg,
                cp,
                id=pkg,
                marks=pytest.mark.skipif(
                    pkg not in _available_providers, reason=f"{pkg} not installed"
                ),
            )
            for pkg, cp in _PROVIDERS.items()
        ],
    )
    def test_provider_satisfies_base_protocol(self, pkg, class_path):
        """Each installed provider must be recognized as a BaseProvider at runtime.

        Runs in a subprocess to avoid phase registration collisions with
        conftest's test phases.
        """
        module, cls_name = class_path.split(":")
        code = (
            f"from {module} import {cls_name}\n"
            f"from octorules.provider.base import BaseProvider\n"
            f"instance = {cls_name}.__new__({cls_name})\n"
            f"assert isinstance(instance, BaseProvider), "
            f"'{cls_name} does not satisfy BaseProvider protocol'\n"
            f"print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout


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
