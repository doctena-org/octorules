"""Tests for the provider split (Phase 4) — backward compat and core-without-cloudflare."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from unittest.mock import patch

import pytest

from octorules.config import ConfigError
from octorules.provider.base import BaseProvider, PhaseRulesResult, Scope
from octorules.provider.exceptions import ProviderAuthError, ProviderError

_cf_installed = importlib.util.find_spec("octorules_cloudflare") is not None
_aws_installed = importlib.util.find_spec("octorules_aws") is not None
_google_installed = importlib.util.find_spec("octorules_google") is not None

# (import_path, package_name) for parametrized tests
_PROVIDER_IMPORTS = [
    pytest.param(
        "octorules.provider",
        "CloudflareProvider",
        "octorules_cloudflare",
        id="cloudflare",
        marks=pytest.mark.skipif(not _cf_installed, reason="octorules-cloudflare not installed"),
    ),
    pytest.param(
        "octorules_aws",
        "AwsWafProvider",
        "octorules_aws",
        id="aws",
        marks=pytest.mark.skipif(not _aws_installed, reason="octorules-aws not installed"),
    ),
    pytest.param(
        "octorules_google",
        "CloudArmorProvider",
        "octorules_google",
        id="google",
        marks=pytest.mark.skipif(not _google_installed, reason="octorules-google not installed"),
    ),
]


class TestBackwardCompatImportPaths:
    @pytest.mark.parametrize("module,cls_name,pkg", _PROVIDER_IMPORTS)
    def test_provider_importable(self, module, cls_name, pkg):
        """Each installed provider class is importable (subprocess)."""
        code = f"from {module} import {cls_name}\nassert {cls_name} is not None\nprint('OK')\n"
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_scope_from_provider(self):
        from octorules.provider import Scope as S

        assert S is Scope

    def test_phase_rules_result_from_provider(self):
        from octorules.provider import PhaseRulesResult as PRR

        assert PRR is PhaseRulesResult

    def test_base_provider_from_provider(self):
        from octorules.provider import BaseProvider as BP

        assert BP is BaseProvider

    @pytest.mark.parametrize("module,cls_name,pkg", _PROVIDER_IMPORTS)
    def test_provider_isinstance_base(self, module, cls_name, pkg):
        """Each installed provider satisfies BaseProvider protocol (subprocess)."""
        code = (
            f"from {module} import {cls_name}\n"
            f"from octorules.provider.base import BaseProvider\n"
            f"instance = {cls_name}.__new__({cls_name})\n"
            f"assert isinstance(instance, BaseProvider)\n"
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
            patch("octorules.commands._providers._get_cloudflare_provider", return_value=None),
            patch("importlib.metadata.entry_points", return_value=[]),
        ):
            from octorules.commands import _resolve_provider_class

            with pytest.raises(ConfigError, match="No provider class found"):
                _resolve_provider_class("unknown_provider", None)


_all_providers_installed = _cf_installed and _aws_installed and _google_installed


@pytest.mark.skipif(not _all_providers_installed, reason="not all providers installed")
class TestMultiProviderCoexistence:
    """Verify all three providers can coexist in a single process."""

    def test_all_phases_register_without_collision(self):
        """Importing all providers registers phases with no name/ID collisions."""
        code = (
            "import octorules_cloudflare\n"
            "import octorules_aws\n"
            "import octorules_google\n"
            "from octorules.phases import PHASES, PHASE_BY_NAME, PHASE_BY_PROVIDER_ID\n"
            "# All three must register without raising\n"
            "assert len(PHASES) > 0\n"
            "# Every phase has a unique provider ID\n"
            "assert len(PHASE_BY_PROVIDER_ID) == len(PHASES)\n"
            "# PHASE_BY_NAME may include aliases, so >= PHASES is expected\n"
            "assert len(PHASE_BY_NAME) >= len(PHASES)\n"
            "# Sanity: each provider contributed phases\n"
            "names = set(PHASE_BY_NAME)\n"
            "assert any(n.startswith('aws_waf_') for n in names), 'no AWS phases'\n"
            "assert any(n.startswith('gcloud_armor_') for n in names), 'no Google phases'\n"
            "assert 'redirect_rules' in names, 'no Cloudflare phases'\n"
            "print(f'OK {len(PHASES)} phases')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_api_fields_merge_across_providers(self):
        """API field registrations from multiple providers accumulate, not overwrite."""
        code = (
            "import octorules_cloudflare\n"
            "import octorules_aws\n"
            "import octorules_google\n"
            "from octorules.phases import get_api_fields\n"
            "rule_fields = get_api_fields('rule')\n"
            "# CF registers id, version, last_updated, categories, logging\n"
            "assert 'id' in rule_fields\n"
            "assert 'version' in rule_fields\n"
            "# AWS registers OverrideAction\n"
            "assert 'OverrideAction' in rule_fields\n"
            "# Google registers kind, preview\n"
            "assert 'kind' in rule_fields\n"
            "assert 'preview' in rule_fields\n"
            "print(f'OK {len(rule_fields)} rule fields')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_all_providers_have_unique_phase_prefixes(self):
        """No two providers share a phase friendly_name."""
        code = (
            "import octorules_cloudflare\n"
            "import octorules_aws\n"
            "import octorules_google\n"
            "from octorules.phases import PHASES\n"
            "names = [p.friendly_name for p in PHASES]\n"
            "assert len(names) == len(set(names)), f'duplicate phase names: {names}'\n"
            "ids = [p.provider_id for p in PHASES]\n"
            "assert len(ids) == len(set(ids)), f'duplicate provider IDs: {ids}'\n"
            "print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout


@pytest.mark.skipif(not _all_providers_installed, reason="not all providers installed")
class TestEntryPointDiscovery:
    """Verify entry-point based provider discovery with real installed packages."""

    @pytest.mark.parametrize(
        "provider_name,expected_cls",
        [
            pytest.param("cloudflare", "CloudflareProvider", id="cloudflare"),
            pytest.param("aws", "AwsWafProvider", id="aws"),
            pytest.param("google", "CloudArmorProvider", id="google"),
        ],
    )
    def test_resolve_provider_class_via_entry_point(self, provider_name, expected_cls):
        """_resolve_provider_class finds each provider by name via entry points."""
        code = (
            f"from octorules.commands import _resolve_provider_class\n"
            f"cls = _resolve_provider_class({provider_name!r}, None)\n"
            f"assert cls.__name__ == {expected_cls!r}\n"
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

    def test_discover_provider_modules_loads_all(self):
        """_discover_provider_modules triggers phase registration for all providers."""
        code = (
            "from octorules.phases import PHASES\n"
            "before = len(PHASES)\n"
            "from octorules.commands import _discover_provider_modules\n"
            "_discover_provider_modules()\n"
            "after = len(PHASES)\n"
            "assert after > before, f'no phases registered: {before} -> {after}'\n"
            "# Verify at least one phase from each provider\n"
            "from octorules.phases import PHASE_BY_NAME\n"
            "names = set(PHASE_BY_NAME)\n"
            "assert any(n.startswith('aws_waf_') for n in names), 'AWS not loaded'\n"
            "assert any(n.startswith('gcloud_armor_') for n in names), 'Google not loaded'\n"
            "assert 'redirect_rules' in names, 'Cloudflare not loaded'\n"
            "print(f'OK {after} phases')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout

    def test_discover_provider_modules_is_idempotent(self):
        """Calling _discover_provider_modules twice does not raise."""
        code = (
            "from octorules.commands import _discover_provider_modules\n"
            "_discover_provider_modules()\n"
            "from octorules.phases import PHASES\n"
            "count = len(PHASES)\n"
            "# Second call should not re-register (providers guard against double-reg)\n"
            "_discover_provider_modules()\n"
            "assert len(PHASES) == count, 'phase count changed on second call'\n"
            "print('OK')\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr
        assert "OK" in result.stdout


class TestExceptionHierarchy:
    def test_provider_auth_error_is_provider_error(self):
        assert issubclass(ProviderAuthError, ProviderError)

    def test_provider_error_is_exception(self):
        assert issubclass(ProviderError, Exception)

    def test_catch_auth_error_as_provider_error(self):
        """ProviderAuthError can be caught by except ProviderError."""
        with pytest.raises(ProviderError):
            raise ProviderAuthError("test")
