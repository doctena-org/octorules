"""Tests for the provider split (Phase 4) — backward compat and core-without-cloudflare."""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from octorules.config import ConfigError
from octorules.provider.base import BaseProvider, PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError


class TestBackwardCompatImportPaths:
    def test_cloudflare_provider_from_provider(self):
        from octorules.provider import CloudflareProvider

        assert CloudflareProvider is not None

    def test_scope_from_provider(self):
        from octorules.provider import Scope as S

        assert S is Scope

    def test_phase_rules_result_from_provider(self):
        from octorules.provider import PhaseRulesResult as PRR

        assert PRR is PhaseRulesResult

    def test_base_provider_from_provider(self):
        from octorules.provider import BaseProvider as BP

        assert BP is BaseProvider

    def test_cloudflare_provider_isinstance_base(self):
        from octorules.provider import CloudflareProvider

        instance = CloudflareProvider.__new__(CloudflareProvider)
        assert isinstance(instance, BaseProvider)


class TestCoreWithoutCloudflare:
    """Subprocess tests that verify core behavior without cloudflare installed."""

    def test_import_octorules_without_cloudflare(self):
        """'import octorules' should succeed even without cloudflare SDK."""
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import sys;"
                    "sys.modules['cloudflare'] = None;"
                    "sys.modules['octorules_cloudflare'] = None;"
                    "from octorules.provider import CloudflareProvider;"
                    "assert CloudflareProvider is None;"
                    "print('OK')"
                ),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_plan_error_without_cloudflare(self):
        """_init_provider should raise ConfigError when no provider is available."""
        with patch("octorules.commands.CloudflareProvider", None):
            from octorules.commands import _init_provider

            config = MagicMock()
            config.provider_class = None
            with pytest.raises(ConfigError, match="No provider available"):
                _init_provider(config)


class TestExceptionHierarchy:
    def test_provider_auth_error_is_provider_error(self):
        assert issubclass(ProviderAuthError, ProviderError)

    def test_provider_error_is_exception(self):
        assert issubclass(ProviderError, Exception)

    def test_catch_auth_error_as_provider_error(self):
        """ProviderAuthError can be caught by except ProviderError."""
        with pytest.raises(ProviderError):
            raise ProviderAuthError("test")
