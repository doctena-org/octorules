"""Tests for the provider split (Phase 4) — backward compat and core-without-cloudflare."""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import patch

import pytest

from octorules.config import ConfigError
from octorules.provider.base import BaseProvider, PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

_cf_installed: bool
try:
    import octorules_cloudflare  # noqa: F401

    _cf_installed = True
except ImportError:
    _cf_installed = False


class TestBackwardCompatImportPaths:
    @pytest.mark.skipif(not _cf_installed, reason="octorules-cloudflare not installed")
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

    @pytest.mark.skipif(not _cf_installed, reason="octorules-cloudflare not installed")
    def test_cloudflare_provider_isinstance_base(self):
        from octorules.provider import CloudflareProvider

        instance = CloudflareProvider.__new__(CloudflareProvider)
        assert isinstance(instance, BaseProvider)


class TestCoreWithoutCloudflare:
    """Subprocess tests that verify core behavior without cloudflare installed."""

    def test_import_octorules_without_cloudflare(self):
        """Importing CloudflareProvider without octorules-cloudflare raises ImportError."""
        code = (
            "import sys\n"
            "sys.modules['cloudflare'] = None\n"
            "sys.modules['octorules_cloudflare'] = None\n"
            "try:\n"
            "    from octorules.provider import CloudflareProvider\n"
            "except ImportError as e:\n"
            "    assert 'octorules-cloudflare' in str(e)\n"
            "    print('OK')\n"
            "else:\n"
            "    raise AssertionError('expected ImportError')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_plan_error_without_cloudflare(self):
        """_resolve_provider_class should raise ConfigError when no provider class is found."""
        with (
            patch("octorules.commands._get_cloudflare_provider", return_value=None),
            patch("importlib.metadata.entry_points", return_value=[]),
        ):
            from octorules.commands import _resolve_provider_class

            with pytest.raises(ConfigError, match="No provider class found"):
                _resolve_provider_class("unknown_provider", None)


class TestExceptionHierarchy:
    def test_provider_auth_error_is_provider_error(self):
        assert issubclass(ProviderAuthError, ProviderError)

    def test_provider_error_is_exception(self):
        assert issubclass(ProviderError, Exception)

    def test_catch_auth_error_as_provider_error(self):
        """ProviderAuthError can be caught by except ProviderError."""
        with pytest.raises(ProviderError):
            raise ProviderAuthError("test")
