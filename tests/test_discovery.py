"""Tests for dynamic zone discovery."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from octorules.commands import _discover_zones
from octorules.config import Config, ProviderConfig, ZoneConfig
from octorules.provider.base import SUPPORTS_ZONE_DISCOVERY


class TestDiscoverZones:
    def test_wildcard_discovers_zones(self, tmp_path):
        """Template + list_zones() + YAML file -> zone added."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "found.com.yaml").write_text("redirect_rules: []\n")

        prov = MagicMock()
        prov.SUPPORTS = frozenset({SUPPORTS_ZONE_DISCOVERY})
        prov.list_zones.return_value = ["found.com"]

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zone_templates={
                "*": ZoneConfig(name="*", sources=["rules"], targets=["cloudflare"]),
            },
        )
        _discover_zones(config, {"cloudflare": prov})
        assert "found.com" in config.zones
        prov.list_zones.assert_called_once()

    def test_explicit_zone_takes_precedence(self, tmp_path):
        """Same name in zones and discovered -> explicit wins."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "explicit.com.yaml").write_text("redirect_rules: []\n")

        prov = MagicMock()
        prov.SUPPORTS = frozenset({SUPPORTS_ZONE_DISCOVERY})
        prov.list_zones.return_value = ["explicit.com"]

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zones={
                "explicit.com": ZoneConfig(
                    name="explicit.com", targets=["cloudflare"], always_dry_run=True
                ),
            },
            zone_templates={
                "*": ZoneConfig(name="*", targets=["cloudflare"]),
            },
        )
        _discover_zones(config, {"cloudflare": prov})
        # Explicit config preserved, not overwritten
        assert config.zones["explicit.com"].always_dry_run is True

    def test_no_yaml_file_skipped(self, tmp_path):
        """Discovered zone without YAML not added."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        prov = MagicMock()
        prov.SUPPORTS = frozenset({SUPPORTS_ZONE_DISCOVERY})
        prov.list_zones.return_value = ["no-yaml.com"]

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zone_templates={
                "*": ZoneConfig(name="*", targets=["cloudflare"]),
            },
        )
        _discover_zones(config, {"cloudflare": prov})
        assert "no-yaml.com" not in config.zones

    def test_no_templates_noop(self, tmp_path):
        """No '*' -> _discover_zones returns immediately."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        prov = MagicMock()
        prov.SUPPORTS = frozenset({SUPPORTS_ZONE_DISCOVERY})

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
        )
        _discover_zones(config, {"cloudflare": prov})
        prov.list_zones.assert_not_called()

    def test_unsupported_provider_warns(self, tmp_path, caplog):
        """Provider without SUPPORTS_ZONE_DISCOVERY -> warning logged."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()

        prov = MagicMock()
        prov.SUPPORTS = frozenset()  # No zone_discovery

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zone_templates={
                "*": ZoneConfig(name="*", targets=["cloudflare"]),
            },
        )
        with caplog.at_level(logging.WARNING):
            _discover_zones(config, {"cloudflare": prov})
        assert "does not support zone discovery" in caplog.text
        prov.list_zones.assert_not_called()

    def test_discovered_inherits_template(self, tmp_path):
        """Discovered zones inherit template's targets, processors, safety, sources."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "new.com.yaml").write_text("redirect_rules: []\n")

        prov = MagicMock()
        prov.SUPPORTS = frozenset({SUPPORTS_ZONE_DISCOVERY})
        prov.list_zones.return_value = ["new.com"]

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zone_templates={
                "*": ZoneConfig(
                    name="*",
                    sources=["rules", "cloudflare"],
                    targets=["cloudflare"],
                    processors=["my_proc"],
                    delete_threshold=10.0,
                    always_dry_run=True,
                ),
            },
        )
        _discover_zones(config, {"cloudflare": prov})
        zc = config.zones["new.com"]
        assert zc.sources == ["rules", "cloudflare"]
        assert zc.targets == ["cloudflare"]
        assert zc.processors == ["my_proc"]
        assert zc.delete_threshold == 10.0
        assert zc.always_dry_run is True
