"""Tests for config loading."""

from __future__ import annotations

import pytest

from octorules.config import (
    Config,
    ConfigError,
    ZoneConfig,
    resolve_value,
    resolve_zone_ids,
    slugify,
)
from octorules.plan_output import PlanHtml, PlanJson, PlanText


def _cfg(extra_cf="", extra_zone="", zone_name="example.com"):
    """Build a minimal config YAML string in providers: format."""
    return (
        f"providers:\n"
        f"  cloudflare:\n"
        f"    token: tok\n"
        f"{extra_cf}"
        f"  rules:\n"
        f"    directory: ./rules\n"
        f"zones:\n"
        f"  {zone_name}:\n"
        f"    sources:\n"
        f"      - rules\n"
        f"      - cloudflare\n"
        f"{extra_zone}"
    )


class TestResolveValue:
    def test_plain_string(self):
        assert resolve_value("hello") == "hello"

    def test_env_prefix(self, monkeypatch):
        monkeypatch.setenv("MY_TOKEN", "secret123")
        assert resolve_value("env/MY_TOKEN") == "secret123"

    def test_env_prefix_missing(self, monkeypatch):
        monkeypatch.delenv("MISSING_VAR", raising=False)
        with pytest.raises(ConfigError, match="MISSING_VAR"):
            resolve_value("env/MISSING_VAR")


class TestConfig:
    def test_load_minimal(self, tmp_config):
        config = Config.from_file(tmp_config)
        assert config.token == "test-token-123"
        assert config.rules_dir == (tmp_config.parent / "rules").resolve()
        assert "example.com" in config.zones
        assert config.zones["example.com"].zone_id is None
        assert config.zones["example.com"].sources == ["rules"]

    def test_env_token(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CF_TOKEN", "env-token-value")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: env/CF_TOKEN\n  rules: {}\n"
            "zones:\n  example.com:\n    sources:\n      - rules\n"
        )
        config = Config.from_file(config_file)
        assert config.token == "env-token-value"

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            Config.from_file(tmp_path / "nope.yaml")

    def test_missing_token(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("providers:\n  cloudflare:\n    other: value\n")
        with pytest.raises(ConfigError, match="token"):
            Config.from_file(config_file)

    def test_zone_id_always_none_from_config(self, tmp_path):
        """Zone from config always has zone_id=None (resolved at runtime)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n  rules: {}\n"
            "zones:\n  example.com:\n    sources:\n      - rules\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].zone_id is None

    def test_default_rules_dir(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("providers:\n  cloudflare:\n    token: tok\nzones: {}\n")
        config = Config.from_file(config_file)
        assert config.rules_dir == (tmp_path / "rules").resolve()

    def test_rules_directory_from_providers(self, tmp_path):
        """providers.rules.directory overrides the default."""
        rules_dir = tmp_path / "my-rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n"
            "  rules:\n    directory: ./my-rules\nzones: {}\n"
        )
        config = Config.from_file(config_file)
        assert config.rules_dir == rules_dir.resolve()

    def test_load_zone_rules(self, tmp_config):
        rules_dir = tmp_config.parent / "rules"
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: test-redirect\n"
            "    description: Test\n"
            "    expression: 'true'\n"
        )
        config = Config.from_file(tmp_config)
        rules = config.load_zone_rules("example.com")
        assert "redirect_rules" in rules
        assert rules["redirect_rules"][0]["ref"] == "test-redirect"

    def test_load_zone_rules_missing_file(self, tmp_config):
        config = Config.from_file(tmp_config)
        assert config.load_zone_rules("nonexistent.com") == {}

    def test_load_zone_rules_skips_when_not_in_sources(self, tmp_path):
        """Zone without 'rules' in sources should not load rules file."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules:\n  - ref: r1\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n  rules: {}\n"
            "zones:\n  example.com:\n    sources:\n      - cloudflare\n"
        )
        config = Config.from_file(config_file)
        assert config.load_zone_rules("example.com") == {}

    def test_not_a_mapping(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("- just\n- a\n- list\n")
        with pytest.raises(ConfigError, match="YAML mapping"):
            Config.from_file(config_file)

    def test_providers_not_a_mapping(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("providers: just-a-string\n")
        with pytest.raises(ConfigError, match="'providers' must be a mapping"):
            Config.from_file(config_file)

    def test_cloudflare_not_a_mapping(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("providers:\n  cloudflare: just-a-string\n")
        with pytest.raises(ConfigError, match="'providers.cloudflare' must be a mapping"):
            Config.from_file(config_file)

    def test_zones_not_a_mapping(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones:\n  - not-a-mapping\n"
        )
        with pytest.raises(ConfigError, match="'zones' must be a mapping"):
            Config.from_file(config_file)

    def test_zone_entry_not_a_mapping(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones:\n  bad.com: just-a-string\n"
        )
        with pytest.raises(ConfigError, match="must be a mapping"):
            Config.from_file(config_file)

    def test_missing_rules_dir_warns(self, tmp_path, caplog):
        import logging

        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n"
            "  rules:\n    directory: ./nonexistent\nzones: {}\n"
        )
        with caplog.at_level(logging.WARNING, logger="octorules"):
            Config.from_file(config_file)
        assert "rules directory does not exist" in caplog.text

    def test_malformed_yaml_raises_config_error(self, tmp_path):
        """Malformed YAML should raise ConfigError, not yaml.YAMLError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {\nbad yaml here\n"
        )
        with pytest.raises(ConfigError, match="Invalid YAML"):
            Config.from_file(config_file)

    def test_malformed_rules_yaml_raises_config_error(self, tmp_config):
        """Malformed YAML in a rules file should raise ConfigError."""
        rules_dir = tmp_config.parent / "rules"
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n  bad: [unclosed\n")
        config = Config.from_file(tmp_config)
        with pytest.raises(ConfigError, match="Invalid YAML"):
            config.load_zone_rules("example.com")

    def test_load_zone_rules_missing_logs_debug(self, tmp_config, caplog):
        """Missing rules file should log at debug level."""
        import logging

        config = Config.from_file(tmp_config)
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            result = config.load_zone_rules("nonexistent.com")
        assert result == {}
        assert "No rules file for zone nonexistent.com" in caplog.text

    def test_load_zone_rules_non_dict_yaml(self, tmp_config):
        """A rules file that parses to a non-dict (e.g. a list) raises ConfigError."""
        rules_dir = tmp_config.parent / "rules"
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text("- just\n- a\n- list\n")
        config = Config.from_file(tmp_config)
        with pytest.raises(ConfigError, match="not a YAML mapping"):
            config.load_zone_rules("example.com")

    def test_always_dry_run_default_false(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert config.zones["example.com"].always_dry_run is False

    def test_always_dry_run_true(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    always_dry_run: true\n"))
        config = Config.from_file(config_file)
        assert config.zones["example.com"].always_dry_run is True

    def test_always_dry_run_false(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    always_dry_run: false\n"))
        config = Config.from_file(config_file)
        assert config.zones["example.com"].always_dry_run is False


class TestSourcesValidation:
    """Tests for zone sources validation."""

    def test_unknown_provider_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n"
            "zones:\n  example.com:\n    sources:\n      - unknown_provider\n"
        )
        with pytest.raises(ConfigError, match="unknown provider 'unknown_provider'"):
            Config.from_file(config_file)

    def test_non_list_sources_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n  rules: {}\n"
            "zones:\n  example.com:\n    sources: rules\n"
        )
        with pytest.raises(ConfigError, match="sources.*must be a list"):
            Config.from_file(config_file)

    def test_empty_sources_allowed(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n  rules: {}\n"
            "zones:\n  example.com:\n    sources: []\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].sources == []

    def test_valid_sources(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n  rules: {}\n"
            "zones:\n  example.com:\n    sources:\n      - rules\n      - cloudflare\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].sources == ["rules", "cloudflare"]


class TestIncludeDirective:
    """Tests for YAML !include directive."""

    def test_include_zone_config(self, tmp_path):
        """Include an entire zone config from a separate file."""
        zones_dir = tmp_path / "zones"
        zones_dir.mkdir()
        (zones_dir / "example.yaml").write_text("sources:\n  - rules\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\n  rules: {}\n"
            "zones:\n  example.com: !include zones/example.yaml\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].sources == ["rules"]

    def test_include_rules_list(self, tmp_path):
        """Include a rules list into a phase key."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        shared_dir = tmp_path / "rules" / "shared"
        shared_dir.mkdir()
        (shared_dir / "redirects.yaml").write_text("- ref: shared-r1\n  expression: 'true'\n")
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules: !include shared/redirects.yaml\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        rules = config.load_zone_rules("example.com")
        assert rules["redirect_rules"][0]["ref"] == "shared-r1"

    def test_nested_includes(self, tmp_path):
        """A includes B includes C."""
        (tmp_path / "c.yaml").write_text("value: deep\n")
        (tmp_path / "b.yaml").write_text("nested: !include c.yaml\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\nextra: !include b.yaml\n"
        )
        from octorules.config import _yaml_load

        data = _yaml_load(config_file)
        assert data["extra"]["nested"]["value"] == "deep"

    def test_relative_path_resolution(self, tmp_path):
        """Paths resolve relative to the file containing the !include."""
        sub_dir = tmp_path / "sub"
        sub_dir.mkdir()
        (sub_dir / "fragment.yaml").write_text("key: resolved\n")
        (sub_dir / "middle.yaml").write_text("data: !include fragment.yaml\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\n"
            "extra: !include sub/middle.yaml\n"
        )
        from octorules.config import _yaml_load

        data = _yaml_load(config_file)
        assert data["extra"]["data"]["key"] == "resolved"

    def test_missing_include_raises_config_error(self, tmp_path):
        """Missing include file raises ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\n"
            "extra: !include nonexistent.yaml\n"
        )
        with pytest.raises(ConfigError, match="Include file not found"):
            Config.from_file(config_file)

    def test_circular_include_raises_config_error(self, tmp_path):
        """Circular include detected raises ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\nextra: !include config.yaml\n"
        )
        with pytest.raises(ConfigError, match="Circular include"):
            Config.from_file(config_file)

    def test_three_level_includes(self, tmp_path):
        """A includes B includes C (three levels deep)."""
        from octorules.config import _yaml_load

        (tmp_path / "c.yaml").write_text("answer: 42\n")
        (tmp_path / "b.yaml").write_text("level2: !include c.yaml\n")
        (tmp_path / "a.yaml").write_text("level1: !include b.yaml\n")
        data = _yaml_load(tmp_path / "a.yaml")
        assert data["level1"]["level2"]["answer"] == 42

    def test_include_malformed_yaml_raises(self, tmp_path):
        """Malformed YAML in an included file should raise ConfigError."""
        (tmp_path / "bad.yaml").write_text("key: [unclosed\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\nextra: !include bad.yaml\n"
        )
        with pytest.raises(ConfigError, match="Invalid YAML"):
            Config.from_file(config_file)

    def test_indirect_circular_include(self, tmp_path):
        """A includes B includes A (indirect circular)."""
        (tmp_path / "a.yaml").write_text("data: !include b.yaml\n")
        (tmp_path / "b.yaml").write_text("data: !include a.yaml\n")
        with pytest.raises(ConfigError, match="Circular include"):
            from octorules.config import _yaml_load

            _yaml_load(tmp_path / "a.yaml")

    def test_backward_compatible_no_includes(self, tmp_config):
        """Config without any includes still works."""
        config = Config.from_file(tmp_config)
        assert config.token == "test-token-123"
        assert "example.com" in config.zones

    def test_rules_file_with_include(self, tmp_path):
        """Rules file with !include works via load_zone_rules()."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        shared_dir = rules_dir / "shared"
        shared_dir.mkdir()
        (shared_dir / "common.yaml").write_text("- ref: common-r1\n  expression: 'true'\n")
        (rules_dir / "example.com.yaml").write_text("redirect_rules: !include shared/common.yaml\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        rules = config.load_zone_rules("example.com")
        assert rules["redirect_rules"][0]["ref"] == "common-r1"

    def test_include_path_traversal_blocked(self, tmp_path):
        """!include with path traversal (../) should raise ConfigError."""
        (tmp_path / "secret.yaml").write_text("key: stolen\n")
        sub_dir = tmp_path / "sub"
        sub_dir.mkdir()
        config_file = sub_dir / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\nextra: !include ../secret.yaml\n"
        )
        with pytest.raises(ConfigError, match="escapes base directory"):
            Config.from_file(config_file)

    def test_include_absolute_path_blocked(self, tmp_path):
        """!include with absolute path outside base should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\nextra: !include /etc/passwd\n"
        )
        with pytest.raises(ConfigError, match="escapes base directory"):
            Config.from_file(config_file)

    def test_include_subdirectory_allowed(self, tmp_path):
        """!include within a subdirectory should still work."""
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "data.yaml").write_text("value: ok\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\nextra: !include sub/data.yaml\n"
        )
        from octorules.config import _yaml_load

        data = _yaml_load(config_file)
        assert data["extra"]["value"] == "ok"


class TestPathTraversal:
    """Tests for path traversal protection in file loading."""

    def test_zone_name_traversal_blocked(self, tmp_path):
        """Zone name with ../ should raise ConfigError."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(token="tok", rules_dir=rules_dir, zones={})
        with pytest.raises(ConfigError, match="resolves outside rules directory"):
            config.load_zone_rules("../../etc/passwd")

    def test_account_name_sanitized_by_slugify(self, tmp_path):
        """Account name with traversal chars is sanitized by slugify."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(token="tok", rules_dir=rules_dir, zones={})
        # slugify("../../etc/passwd") → "etc-passwd", which is safe
        # Should not raise — just returns empty (no file found)
        result = config.load_account_rules("../../etc/passwd")
        assert result == {}


class TestYamlLoaderEquivalence:
    """Verify that our direct SafeLoader usage matches yaml.load() behavior."""

    def test_plain_yaml_matches_yaml_load(self, tmp_path):
        """Direct loader API produces same result as yaml.load for plain YAML."""
        import yaml

        from octorules.config import _make_include_loader, _yaml_load

        content = "key: value\nlist:\n  - 1\n  - two\nnested:\n  a: true\n  b: null\n"
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(content)

        loader_cls = _make_include_loader(tmp_path, {yaml_file.resolve()})
        with open(yaml_file, encoding="utf-8") as f:
            expected = yaml.load(f, Loader=loader_cls)  # noqa: S506
        actual = _yaml_load(yaml_file)
        assert actual == expected

    def test_include_matches_yaml_load(self, tmp_path):
        """Direct loader API produces same result as yaml.load for !include."""
        import yaml

        from octorules.config import _make_include_loader, _yaml_load

        (tmp_path / "fragment.yaml").write_text("- item1\n- item2\n")
        yaml_file = tmp_path / "main.yaml"
        yaml_file.write_text("data: !include fragment.yaml\nother: 42\n")

        loader_cls = _make_include_loader(tmp_path, {yaml_file.resolve()})
        with open(yaml_file, encoding="utf-8") as f:
            expected = yaml.load(f, Loader=loader_cls)  # noqa: S506
        actual = _yaml_load(yaml_file)
        assert actual == expected
        assert actual["data"] == ["item1", "item2"]

    def test_empty_file_matches_yaml_load(self, tmp_path):
        """Empty YAML file returns None, same as yaml.load."""
        import yaml

        from octorules.config import _make_include_loader, _yaml_load

        yaml_file = tmp_path / "empty.yaml"
        yaml_file.write_text("")

        loader_cls = _make_include_loader(tmp_path, {yaml_file.resolve()})
        with open(yaml_file, encoding="utf-8") as f:
            expected = yaml.load(f, Loader=loader_cls)  # noqa: S506
        actual = _yaml_load(yaml_file)
        assert actual == expected
        assert actual is None

    def test_complex_types_match_yaml_load(self, tmp_path):
        """Scalars, anchors, and multiline strings match yaml.load output."""
        import yaml

        from octorules.config import _make_include_loader, _yaml_load

        content = (
            "string: hello\n"
            "integer: 42\n"
            "float: 3.14\n"
            "boolean: true\n"
            "null_val: null\n"
            "multiline: |\n"
            "  line1\n"
            "  line2\n"
            "anchor: &ref\n"
            "  x: 1\n"
            "alias: *ref\n"
        )
        yaml_file = tmp_path / "complex.yaml"
        yaml_file.write_text(content)

        loader_cls = _make_include_loader(tmp_path, {yaml_file.resolve()})
        with open(yaml_file, encoding="utf-8") as f:
            expected = yaml.load(f, Loader=loader_cls)  # noqa: S506
        actual = _yaml_load(yaml_file)
        assert actual == expected


class TestMaxWorkers:
    """Tests for manager.max_workers config parsing."""

    def test_default_max_workers(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert config.max_workers == 4

    def test_parse_max_workers(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager:\n  max_workers: 4\n")
        config = Config.from_file(config_file)
        assert config.max_workers == 4

    def test_invalid_max_workers_zero(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager:\n  max_workers: 0\n")
        with pytest.raises(ConfigError, match="max_workers"):
            Config.from_file(config_file)

    def test_invalid_max_workers_negative(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager:\n  max_workers: -1\n")
        with pytest.raises(ConfigError, match="max_workers"):
            Config.from_file(config_file)

    def test_type_coercion(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager:\n  max_workers: '2'\n")
        config = Config.from_file(config_file)
        assert config.max_workers == 2
        assert isinstance(config.max_workers, int)


class TestMaxRetries:
    """Tests for providers.cloudflare.max_retries config parsing."""

    def test_default_max_retries_is_2(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert config.max_retries == 2

    def test_parse_max_retries(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    max_retries: 5\n"))
        config = Config.from_file(config_file)
        assert config.max_retries == 5

    def test_max_retries_zero_allowed(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    max_retries: 0\n"))
        config = Config.from_file(config_file)
        assert config.max_retries == 0

    def test_negative_max_retries_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    max_retries: -1\n"))
        with pytest.raises(ConfigError, match="max_retries"):
            Config.from_file(config_file)


class TestTimeout:
    """Tests for providers.cloudflare.timeout config parsing."""

    def test_default_timeout_is_none(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert config.timeout is None

    def test_parse_timeout(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    timeout: 30\n"))
        config = Config.from_file(config_file)
        assert config.timeout == 30.0

    def test_parse_timeout_float(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    timeout: 10.5\n"))
        config = Config.from_file(config_file)
        assert config.timeout == 10.5

    def test_zero_timeout_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    timeout: 0\n"))
        with pytest.raises(ConfigError, match="timeout"):
            Config.from_file(config_file)

    def test_negative_timeout_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    timeout: -5\n"))
        with pytest.raises(ConfigError, match="timeout"):
            Config.from_file(config_file)


class TestAllowUnmanaged:
    """Tests for allow_unmanaged zone config."""

    def test_default_false(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert config.zones["example.com"].allow_unmanaged is False

    def test_allow_unmanaged_true(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    allow_unmanaged: true\n"))
        config = Config.from_file(config_file)
        assert config.zones["example.com"].allow_unmanaged is True

    def test_allow_unmanaged_false(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    allow_unmanaged: false\n"))
        config = Config.from_file(config_file)
        assert config.zones["example.com"].allow_unmanaged is False


class TestSafetyThresholds:
    """Tests for safety threshold config parsing."""

    def test_default_thresholds(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 30.0
        assert zone.update_threshold == 30.0
        assert zone.min_existing == 3

    def test_global_override(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        safety = (
            "    safety:\n"
            "      delete_threshold: 50\n"
            "      update_threshold: 40\n"
            "      min_existing: 5\n"
        )
        config_file.write_text(_cfg(extra_cf=safety))
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 50.0
        assert zone.update_threshold == 40.0
        assert zone.min_existing == 5

    def test_per_zone_override(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(
                extra_cf="    safety:\n      delete_threshold: 50\n",
                extra_zone="    safety:\n      delete_threshold: 70\n",
            )
        )
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 70.0
        assert zone.update_threshold == 30.0

    def test_type_coercion(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        safety = "    safety:\n      delete_threshold: '25'\n      min_existing: '10'\n"
        config_file.write_text(_cfg(extra_cf=safety))
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 25.0
        assert isinstance(zone.delete_threshold, float)
        assert zone.min_existing == 10
        assert isinstance(zone.min_existing, int)

    def test_negative_delete_threshold_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      delete_threshold: -1\n"))
        with pytest.raises(ConfigError, match="delete_threshold.*between 0 and 100"):
            Config.from_file(config_file)

    def test_over_100_delete_threshold_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      delete_threshold: 150\n"))
        with pytest.raises(ConfigError, match="delete_threshold.*between 0 and 100"):
            Config.from_file(config_file)

    def test_negative_update_threshold_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      update_threshold: -5\n"))
        with pytest.raises(ConfigError, match="update_threshold.*between 0 and 100"):
            Config.from_file(config_file)

    def test_over_100_update_threshold_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      update_threshold: 101\n"))
        with pytest.raises(ConfigError, match="update_threshold.*between 0 and 100"):
            Config.from_file(config_file)

    def test_negative_min_existing_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      min_existing: -1\n"))
        with pytest.raises(ConfigError, match="min_existing.*>= 0"):
            Config.from_file(config_file)

    def test_zero_thresholds_allowed(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        safety = (
            "    safety:\n"
            "      delete_threshold: 0\n"
            "      update_threshold: 0\n"
            "      min_existing: 0\n"
        )
        config_file.write_text(_cfg(extra_cf=safety))
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 0.0
        assert zone.update_threshold == 0.0
        assert zone.min_existing == 0

    def test_100_thresholds_allowed(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        safety = "    safety:\n      delete_threshold: 100\n      update_threshold: 100\n"
        config_file.write_text(_cfg(extra_cf=safety))
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 100.0
        assert zone.update_threshold == 100.0

    def test_per_zone_negative_threshold_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    safety:\n      delete_threshold: -10\n"))
        with pytest.raises(ConfigError, match="zones.*example.com.*delete_threshold"):
            Config.from_file(config_file)

    def test_global_safety_non_dict_raises(self, tmp_path):
        """Non-mapping safety value should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety: true\n"))
        with pytest.raises(ConfigError, match="'providers.cloudflare.safety' must be a mapping"):
            Config.from_file(config_file)

    def test_per_zone_safety_non_dict_raises(self, tmp_path):
        """Non-mapping per-zone safety value should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    safety: true\n"))
        with pytest.raises(ConfigError, match="zones.*example.com.*safety.*must be a mapping"):
            Config.from_file(config_file)

    def test_global_safety_null_treated_as_empty(self, tmp_path):
        """safety: null (YAML null) should use defaults, not raise."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n"))
        config = Config.from_file(config_file)
        assert config.zones["example.com"].delete_threshold == 30.0


class TestManagerSection:
    def test_manager_non_dict_raises(self, tmp_path):
        """Non-mapping manager value should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager: 4\n")
        with pytest.raises(ConfigError, match="'manager' must be a mapping"):
            Config.from_file(config_file)

    def test_manager_null_treated_as_empty(self, tmp_path):
        """manager: null should use defaults, not raise."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager:\n")
        config = Config.from_file(config_file)
        assert config.max_workers == 4


class TestResolveZoneIds:
    """Tests for the resolve_zone_ids function."""

    def test_resolves_all_zones(self):
        config = Config(
            token="tok",
            rules_dir="/tmp/rules",
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "b.com": ZoneConfig(name="b.com"),
            },
        )
        resolve_zone_ids(config, lambda name: f"id-for-{name}")
        assert config.zones["a.com"].zone_id == "id-for-a.com"
        assert config.zones["b.com"].zone_id == "id-for-b.com"

    def test_propagates_errors(self):
        config = Config(
            token="tok",
            rules_dir="/tmp/rules",
            zones={"bad.com": ZoneConfig(name="bad.com")},
        )

        def fail(name):
            raise ConfigError(f"No zone found for {name!r}")

        with pytest.raises(ConfigError, match="No zone found"):
            resolve_zone_ids(config, fail)

    def test_skips_already_resolved(self):
        """resolve_zone_ids skips zones that already have a zone_id."""
        config = Config(
            token="tok",
            rules_dir="/tmp/rules",
            zones={"x.com": ZoneConfig(name="x.com", zone_id="existing")},
        )
        called = []
        resolve_zone_ids(config, lambda name: called.append(name) or "new-value")
        assert config.zones["x.com"].zone_id == "existing"
        assert called == []

    def test_parallel_resolves_all_zones(self):
        """With max_workers > 1, all zones should still be resolved correctly."""
        config = Config(
            token="tok",
            rules_dir="/tmp/rules",
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "b.com": ZoneConfig(name="b.com"),
                "c.com": ZoneConfig(name="c.com"),
            },
        )
        resolve_zone_ids(config, lambda name: f"id-for-{name}", max_workers=3)
        assert config.zones["a.com"].zone_id == "id-for-a.com"
        assert config.zones["b.com"].zone_id == "id-for-b.com"
        assert config.zones["c.com"].zone_id == "id-for-c.com"

    def test_parallel_propagates_errors(self):
        """Parallel resolution should propagate errors from resolve_fn."""
        config = Config(
            token="tok",
            rules_dir="/tmp/rules",
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "bad.com": ZoneConfig(name="bad.com"),
            },
        )

        def fail_on_bad(name):
            if name == "bad.com":
                raise ConfigError(f"No zone found for {name!r}")
            return f"id-for-{name}"

        with pytest.raises(ConfigError, match="No zone found"):
            resolve_zone_ids(config, fail_on_bad, max_workers=2)

    def test_sequential_when_max_workers_1(self):
        """With max_workers=1, should resolve sequentially (no thread pool)."""
        import threading

        threads_seen = set()

        def track_thread(name):
            threads_seen.add(threading.current_thread().name)
            return f"id-for-{name}"

        config = Config(
            token="tok",
            rules_dir="/tmp/rules",
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "b.com": ZoneConfig(name="b.com"),
            },
        )
        resolve_zone_ids(config, track_thread, max_workers=1)
        # All calls should be on the main thread (current thread)
        assert len(threads_seen) == 1
        assert threading.current_thread().name in threads_seen

    def test_uses_config_max_workers_by_default(self):
        """When max_workers is not passed, should use config.max_workers."""
        config = Config(
            token="tok",
            rules_dir="/tmp/rules",
            max_workers=4,
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "b.com": ZoneConfig(name="b.com"),
                "c.com": ZoneConfig(name="c.com"),
            },
        )
        resolve_zone_ids(config, lambda name: f"id-for-{name}")
        assert config.zones["a.com"].zone_id == "id-for-a.com"
        assert config.zones["b.com"].zone_id == "id-for-b.com"
        assert config.zones["c.com"].zone_id == "id-for-c.com"


class TestPlanOutputs:
    """Tests for manager.plan_outputs config parsing."""

    def test_default_empty(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert config.plan_outputs == {}

    def test_single_class(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg()
            + "manager:\n"
            + "  plan_outputs:\n"
            + "    text:\n"
            + "      class: octorules.plan_output.PlanText\n"
        )
        config = Config.from_file(config_file)
        assert "text" in config.plan_outputs
        assert isinstance(config.plan_outputs["text"], PlanText)
        assert config.plan_outputs["text"].name == "text"
        assert config.plan_outputs["text"].path is None

    def test_with_path(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg()
            + "manager:\n"
            + "  plan_outputs:\n"
            + "    html:\n"
            + "      class: octorules.plan_output.PlanHtml\n"
            + "      path: /tmp/plan.html\n"
        )
        config = Config.from_file(config_file)
        assert isinstance(config.plan_outputs["html"], PlanHtml)
        assert config.plan_outputs["html"].path == "/tmp/plan.html"

    def test_multiple_outputs(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg()
            + "manager:\n"
            + "  plan_outputs:\n"
            + "    text:\n"
            + "      class: octorules.plan_output.PlanText\n"
            + "    json:\n"
            + "      class: octorules.plan_output.PlanJson\n"
            + "      path: /tmp/plan.json\n"
        )
        config = Config.from_file(config_file)
        assert len(config.plan_outputs) == 2
        assert isinstance(config.plan_outputs["text"], PlanText)
        assert isinstance(config.plan_outputs["json"], PlanJson)
        assert config.plan_outputs["json"].path == "/tmp/plan.json"

    def test_missing_class_key(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg()
            + "manager:\n"
            + "  plan_outputs:\n"
            + "    text:\n"
            + "      path: /tmp/out.txt\n"
        )
        with pytest.raises(ConfigError, match="missing required 'class' key"):
            Config.from_file(config_file)

    def test_unknown_class(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg() + "manager:\n" + "  plan_outputs:\n" + "    bad:\n" + "      class: foo.Bar\n"
        )
        with pytest.raises(ConfigError, match="unknown class 'foo.Bar'"):
            Config.from_file(config_file)

    def test_entry_not_mapping(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg() + "manager:\n" + "  plan_outputs:\n" + "    text: just-a-string\n"
        )
        with pytest.raises(ConfigError, match="must be a mapping"):
            Config.from_file(config_file)

    def test_not_a_dict(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg() + "manager:\n" + "  plan_outputs:\n" + "    - item1\n" + "    - item2\n"
        )
        with pytest.raises(ConfigError, match="'manager.plan_outputs' must be a mapping"):
            Config.from_file(config_file)


class TestSlugify:
    def test_simple_name(self):
        assert slugify("Acme Corp") == "acme-corp"

    def test_special_characters(self):
        assert slugify("Doctena S.A.") == "doctena-s-a"

    def test_already_slugified(self):
        assert slugify("my-account") == "my-account"

    def test_mixed_case_and_numbers(self):
        assert slugify("My Account 123") == "my-account-123"

    def test_leading_trailing_special(self):
        assert slugify("--hello--") == "hello"

    def test_empty_string(self):
        assert slugify("") == ""

    def test_only_special_chars(self):
        assert slugify("...") == ""


class TestLoadAccountRules:
    def test_load_existing_file(self, tmp_config):
        rules_dir = tmp_config.parent / "rules"
        rules_file = rules_dir / "acme-corp.yaml"
        rules_file.write_text(
            "waf_custom_rules:\n  - ref: w1\n    expression: 'true'\n    action: block\n"
        )
        config = Config.from_file(tmp_config)
        rules = config.load_account_rules("Acme Corp")
        assert "waf_custom_rules" in rules
        assert rules["waf_custom_rules"][0]["ref"] == "w1"

    def test_missing_file_returns_empty(self, tmp_config):
        config = Config.from_file(tmp_config)
        assert config.load_account_rules("Nonexistent Account") == {}

    def test_missing_file_logs_debug(self, tmp_config, caplog):
        import logging

        config = Config.from_file(tmp_config)
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            config.load_account_rules("Nonexistent Account")
        assert "No rules file for account Nonexistent Account" in caplog.text

    def test_non_dict_yaml_raises(self, tmp_config):
        rules_dir = tmp_config.parent / "rules"
        rules_file = rules_dir / "bad-account.yaml"
        rules_file.write_text("- just\n- a\n- list\n")
        config = Config.from_file(tmp_config)
        with pytest.raises(ConfigError, match="not a YAML mapping"):
            config.load_account_rules("Bad Account")
