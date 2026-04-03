"""Tests for the provider factory (_init_providers, etc.)."""

import importlib.util
from unittest.mock import MagicMock, patch

import pytest

from octorules.commands import (
    _init_providers,
    _load_provider_class,
    _resolve_provider_class,
)
from octorules.config import ConfigError

_cf_installed = importlib.util.find_spec("octorules_cloudflare") is not None
_aws_installed = importlib.util.find_spec("octorules_aws") is not None
_google_installed = importlib.util.find_spec("octorules_google") is not None


def _mock_config(**overrides):
    cfg = MagicMock()
    # The new Config has providers dict, not provider_kwargs/provider_class
    cfg.providers = {
        "cloudflare": MagicMock(
            name="cloudflare",
            class_path=None,
            kwargs={"token": "test-token", "max_workers": 1},
        )
    }
    cfg.zones = {}
    cfg.max_workers = 1
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


_PROVIDER_CLASS_PATHS = [
    pytest.param(
        "octorules_cloudflare.CloudflareProvider",
        id="cloudflare",
        marks=pytest.mark.skipif(not _cf_installed, reason="octorules-cloudflare not installed"),
    ),
    pytest.param(
        "octorules_aws.AwsWafProvider",
        id="aws",
        marks=pytest.mark.skipif(not _aws_installed, reason="octorules-aws not installed"),
    ),
    pytest.param(
        "octorules_google.CloudArmorProvider",
        id="google",
        marks=pytest.mark.skipif(not _google_installed, reason="octorules-google not installed"),
    ),
]


class TestLoadProviderClass:
    @pytest.mark.parametrize("class_path", _PROVIDER_CLASS_PATHS)
    def test_load_existing_class(self, class_path):
        """_load_provider_class resolves a real provider class path."""
        cls = _load_provider_class(class_path)
        assert cls is not None

    def test_invalid_path_no_dot(self):
        with pytest.raises(ConfigError, match="Invalid provider class path"):
            _load_provider_class("CloudflareProvider")

    def test_module_not_found(self):
        with pytest.raises(ModuleNotFoundError):
            _load_provider_class("nonexistent.module.FakeProvider")

    def test_class_not_found_in_module(self):
        with pytest.raises(ConfigError, match="not found in module"):
            _load_provider_class("octorules.provider.NonexistentClass")


class TestConfigProviderClassField:
    def test_config_without_class_key(self, tmp_path):
        """Config without 'class' key defaults to None."""
        from octorules.config import Config

        config_yaml = tmp_path / "config.yaml"
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_yaml.write_text(
            f"""\
providers:
  cloudflare:
    token: test-token
  rules:
    directory: {rules_dir}
"""
        )
        config = Config.from_file(config_yaml)
        assert config.providers["cloudflare"].class_path is None

    def test_config_with_class_key(self, tmp_path):
        """Config with 'class' key stores the value."""
        from octorules.config import Config

        config_yaml = tmp_path / "config.yaml"
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_yaml.write_text(
            f"""\
providers:
  cloudflare:
    token: test-token
    class: octorules.provider.CloudflareProvider
  rules:
    directory: {rules_dir}
"""
        )
        config = Config.from_file(config_yaml)
        assert config.providers["cloudflare"].class_path == "octorules.provider.CloudflareProvider"


class TestProviderKwargsPassthrough:
    def test_all_provider_keys_forwarded(self, tmp_path):
        """All non-framework keys are forwarded as provider kwargs."""
        from octorules.config import Config

        config_yaml = tmp_path / "config.yaml"
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_yaml.write_text(
            f"""\
providers:
  aws:
    region: us-west-2
    waf_scope: CLOUDFRONT
  rules:
    directory: {rules_dir}
"""
        )
        config = Config.from_file(config_yaml)
        assert config.providers["aws"].kwargs["region"] == "us-west-2"
        assert config.providers["aws"].kwargs["waf_scope"] == "CLOUDFRONT"
        assert "class" not in config.providers["aws"].kwargs
        assert "safety" not in config.providers["aws"].kwargs

    def test_env_resolution_on_all_string_values(self, tmp_path, monkeypatch):
        """env/ prefix is resolved on all string values, not just token."""
        from octorules.config import Config

        monkeypatch.setenv("MY_REGION", "eu-central-1")
        config_yaml = tmp_path / "config.yaml"
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_yaml.write_text(
            f"""\
providers:
  aws:
    region: env/MY_REGION
  rules:
    directory: {rules_dir}
"""
        )
        config = Config.from_file(config_yaml)
        config.resolve_secrets()
        assert config.providers["aws"].kwargs["region"] == "eu-central-1"


class TestInitProviders:
    @patch("octorules.commands._providers.resolve_zone_ids")
    @patch("octorules.commands._providers._resolve_provider_class")
    def test_single_provider(self, mock_resolve_cls, mock_resolve_zones):
        """_init_providers creates one provider from config.providers."""
        mock_cls = MagicMock()
        mock_cls.__module__ = "octorules.provider"
        mock_cls.return_value = MagicMock()
        mock_resolve_cls.return_value = mock_cls

        config = _mock_config()
        providers = _init_providers(config)

        mock_resolve_cls.assert_called_once_with("cloudflare", None)
        mock_cls.assert_called_once_with(token="test-token", max_workers=1)
        assert "cloudflare" in providers
        assert providers["cloudflare"] is mock_cls.return_value

    @patch("octorules.commands._providers.resolve_zone_ids")
    @patch("octorules.commands._providers._resolve_provider_class")
    def test_resolve_zone_ids_called(self, mock_resolve_cls, mock_resolve_zones):
        """_init_providers calls resolve_zone_ids with per-provider fns."""
        mock_cls = MagicMock()
        mock_cls.__module__ = "octorules.provider"
        mock_instance = MagicMock()
        mock_cls.return_value = mock_instance
        mock_resolve_cls.return_value = mock_cls

        config = _mock_config()
        _init_providers(config)

        mock_resolve_zones.assert_called_once()
        call_args = mock_resolve_zones.call_args
        assert call_args[0][0] is config
        # Second arg is a dict of {name: provider.resolve_zone_id}
        resolve_fns = call_args[0][1]
        assert "cloudflare" in resolve_fns
        assert resolve_fns["cloudflare"] is mock_instance.resolve_zone_id


class TestResolveProviderClass:
    @pytest.mark.parametrize("class_path", _PROVIDER_CLASS_PATHS)
    def test_explicit_class_path(self, class_path):
        """class_path provided -> loaded via _load_provider_class."""
        provider_name = class_path.rsplit(".", 1)[0].replace("octorules.", "").replace("_", "-")
        cls = _resolve_provider_class(provider_name, class_path)
        assert cls is not None

    @patch("importlib.metadata.entry_points")
    def test_entry_point_discovery(self, mock_eps):
        """Entry point matching the provider name is used."""
        mock_ep = MagicMock()
        mock_ep.name = "mycloud"
        sentinel_cls = type("MyCloudProvider", (), {})
        mock_ep.load.return_value = sentinel_cls
        mock_eps.return_value = [mock_ep]

        cls = _resolve_provider_class("mycloud", None)
        assert cls is sentinel_cls
        mock_eps.assert_called_once_with(group="octorules.providers")

    @patch("importlib.metadata.entry_points")
    def test_no_class_no_entry_point(self, mock_eps):
        """No class, no entry point -> ConfigError."""
        mock_eps.return_value = []
        with pytest.raises(ConfigError, match="No provider class found"):
            _resolve_provider_class("unknown", None)
