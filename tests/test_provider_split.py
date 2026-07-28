"""Tests for the provider split (Phase 4) — backward compat and core-without-cloudflare.

Phase registration is idempotent (same name+id pair → no-op), so most tests
run in-process without subprocess isolation.  Only tests that mutate
``sys.modules`` or need a pristine registry use subprocesses.
"""

import importlib
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

_PROVIDER_IMPORTS = [
    pytest.param(
        "octorules_cloudflare",
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
        """Each installed provider class is importable in-process."""
        mod = importlib.import_module(module)
        cls = getattr(mod, cls_name)
        assert cls is not None

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
        """Each installed provider satisfies BaseProvider protocol."""
        mod = importlib.import_module(module)
        cls = getattr(mod, cls_name)
        instance = cls.__new__(cls)
        assert isinstance(instance, BaseProvider)


class TestCoreWithoutCloudflare:
    """Subprocess tests that verify core behavior without cloudflare installed.

    These genuinely need subprocess isolation because they manipulate sys.modules.
    """

    def test_cloudflare_provider_not_in_core(self):
        """CloudflareProvider is no longer re-exported from octorules.provider."""
        with pytest.raises(ImportError):
            from octorules.provider import CloudflareProvider  # noqa: F401

    def test_plan_error_without_provider(self):
        """_resolve_provider_class should raise ConfigError when no provider class is found."""
        with patch("importlib.metadata.entry_points", return_value=[]):
            from octorules.commands import _resolve_provider_class

            with pytest.raises(ConfigError, match="No provider class found"):
                _resolve_provider_class("unknown_provider", None)


_all_providers_installed = _cf_installed and _aws_installed and _google_installed


@pytest.mark.skipif(not _all_providers_installed, reason="not all providers installed")
class TestMultiProviderCoexistence:
    """Verify all three providers can coexist in a single process.

    Idempotent phase registration allows importing providers even though
    conftest already registered phases with the same names.
    """

    def test_all_phases_register_without_collision(self):
        """Importing all providers registers phases with no name/ID collisions."""
        import octorules_aws  # noqa: F401
        import octorules_cloudflare  # noqa: F401
        import octorules_google  # noqa: F401

        from octorules.phases import PHASE_BY_NAME, PHASE_BY_PROVIDER_ID, PHASES

        assert len(PHASES) > 0
        assert len(PHASE_BY_PROVIDER_ID) == len(PHASES)
        assert len(PHASE_BY_NAME) >= len(PHASES)
        names = set(PHASE_BY_NAME)
        assert any(n.startswith("aws.") for n in names), "no AWS phases"
        assert any(n.startswith("google.") for n in names), "no Google phases"
        assert "fakeprov.redirect_rules" in names, "no Cloudflare phases"

    def test_api_fields_merge_across_providers(self):
        """API field registrations from multiple providers accumulate, not overwrite."""
        import octorules_aws  # noqa: F401
        import octorules_cloudflare  # noqa: F401
        import octorules_google  # noqa: F401

        from octorules.phases import get_api_fields

        rule_fields = get_api_fields("rule")
        assert "id" in rule_fields
        assert "version" in rule_fields
        assert "OverrideAction" in rule_fields
        assert "kind" in rule_fields
        assert "preview" in rule_fields

    def test_all_providers_have_unique_phase_prefixes(self):
        """No two providers share a phase friendly_name."""
        import octorules_aws  # noqa: F401
        import octorules_cloudflare  # noqa: F401
        import octorules_google  # noqa: F401

        from octorules.phases import PHASES

        names = [p.friendly_name for p in PHASES]
        assert len(names) == len(set(names)), f"duplicate phase names: {names}"
        ids = [p.provider_id for p in PHASES]
        assert len(ids) == len(set(ids)), f"duplicate provider IDs: {ids}"


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
        from octorules.commands import _resolve_provider_class

        cls = _resolve_provider_class(provider_name, None)
        assert cls.__name__ == expected_cls

    def test_discover_provider_modules_loads_all(self):
        """_discover_provider_modules triggers phase registration for all providers."""
        from octorules.commands import _discover_provider_modules
        from octorules.phases import PHASE_BY_NAME, PHASES

        _discover_provider_modules()
        assert len(PHASES) > 0
        names = set(PHASE_BY_NAME)
        assert any(n.startswith("aws.") for n in names), "AWS not loaded"
        assert any(n.startswith("google.") for n in names), "Google not loaded"
        assert "fakeprov.redirect_rules" in names, "Cloudflare not loaded"

    def test_discover_provider_modules_is_idempotent(self):
        """Calling _discover_provider_modules twice does not raise."""
        from octorules.commands import _discover_provider_modules
        from octorules.phases import PHASES

        _discover_provider_modules()
        count = len(PHASES)
        _discover_provider_modules()
        assert len(PHASES) == count, "phase count changed on second call"


class TestDiscoverProviderFailure:
    """Verify _discover_provider_modules logs WARNING on broken entry-points.

    Needs subprocess isolation to patch entry_points without affecting other tests.
    """

    def test_logs_warning_on_load_failure(self):
        """Failed entry-point loads are logged at WARNING level."""
        code = (
            "import logging, sys\n"
            "from unittest.mock import MagicMock, patch\n"
            "logging.basicConfig(level=logging.WARNING, stream=sys.stderr)\n"
            "bad_ep = MagicMock()\n"
            "bad_ep.name = 'broken_provider'\n"
            "bad_ep.load.side_effect = ImportError('no_such_module')\n"
            "with patch('importlib.metadata.entry_points', return_value=[bad_ep]):\n"
            "    from octorules.commands._providers import _discover_provider_modules\n"
            "    _discover_provider_modules()\n"
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
        assert "broken_provider" in result.stderr
        assert "no_such_module" in result.stderr


class TestExceptionHierarchy:
    def test_provider_auth_error_is_provider_error(self):
        assert issubclass(ProviderAuthError, ProviderError)

    def test_provider_error_is_exception(self):
        assert issubclass(ProviderError, Exception)

    def test_catch_auth_error_as_provider_error(self):
        """ProviderAuthError can be caught by except ProviderError."""
        with pytest.raises(ProviderError):
            raise ProviderAuthError("test")
