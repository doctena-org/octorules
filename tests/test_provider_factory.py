"""Tests for the provider factory (_init_provider and _load_provider_class)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from octorules.commands import _init_provider, _load_provider_class
from octorules.config import ConfigError
from octorules.provider import CloudflareProvider


def _mock_config(**overrides):
    cfg = MagicMock()
    cfg.token = "test-token"
    cfg.max_retries = 0
    cfg.timeout = None
    cfg.max_workers = 1
    cfg.provider_class = None
    cfg.zones = {}
    for k, v in overrides.items():
        setattr(cfg, k, v)
    return cfg


class TestInitProviderDefault:
    @patch("octorules.commands.CloudflareProvider")
    @patch("octorules.commands.resolve_zone_ids")
    def test_default_creates_cloudflare(self, mock_resolve, mock_cls):
        """Default _init_provider creates CloudflareProvider."""
        mock_cls.return_value = MagicMock()
        config = _mock_config()
        provider = _init_provider(config)
        mock_cls.assert_called_once_with("test-token", max_retries=0, timeout=None, max_workers=1)
        assert provider is mock_cls.return_value


class TestInitProviderCustomClass:
    @patch("octorules.commands.resolve_zone_ids")
    def test_provider_cls_parameter(self, mock_resolve):
        """Explicit provider_cls parameter is used."""
        mock_cls = MagicMock()
        mock_cls.return_value = MagicMock()
        config = _mock_config()
        provider = _init_provider(config, provider_cls=mock_cls)
        mock_cls.assert_called_once_with("test-token", max_retries=0, timeout=None, max_workers=1)
        assert provider is mock_cls.return_value


class TestInitProviderDynamicImport:
    @patch("octorules.commands.resolve_zone_ids")
    @patch("octorules.commands.CloudflareProvider")
    def test_dynamic_import_from_config(self, mock_cf_cls, mock_resolve):
        """Config provider_class triggers dynamic import."""
        config = _mock_config(provider_class="octorules.provider.CloudflareProvider")
        provider = _init_provider(config)
        # Should have used the real CloudflareProvider (imported dynamically),
        # not the one patched in the commands module
        assert provider is not mock_cf_cls.return_value

    @patch("octorules.commands.resolve_zone_ids")
    def test_provider_cls_overrides_config(self, mock_resolve):
        """Explicit provider_cls takes precedence over config.provider_class."""
        mock_cls = MagicMock()
        mock_cls.return_value = MagicMock()
        config = _mock_config(provider_class="octorules.provider.CloudflareProvider")
        provider = _init_provider(config, provider_cls=mock_cls)
        mock_cls.assert_called_once()
        assert provider is mock_cls.return_value


class TestLoadProviderClass:
    def test_load_existing_class(self):
        cls = _load_provider_class("octorules.provider.CloudflareProvider")
        assert cls is CloudflareProvider

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
        assert config.provider_class is None

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
        assert config.provider_class == "octorules.provider.CloudflareProvider"
