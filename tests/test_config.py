"""Tests for config loading."""

import pytest

from octorules.config import (
    Config,
    ConfigError,
    ContextDict,
    ProviderConfig,
    ZoneConfig,
    _ctx,
    _resolve_deep,
    _resolve_secret,
    resolve_value,
    resolve_zone_ids,
    slugify,
)
from octorules.plan_output import PlanOutput
from octorules.secret import BaseSecrets


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
        assert config.providers["cloudflare"].kwargs["token"] == "test-token-123"
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
        # Before resolve_secrets(), kwargs contain raw values
        assert config.providers["cloudflare"].kwargs["token"] == "env/CF_TOKEN"
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["token"] == "env-token-value"

    def test_missing_file(self, tmp_path):
        with pytest.raises(ConfigError, match="not found"):
            Config.from_file(tmp_path / "nope.yaml")

    def test_omitted_token_not_in_kwargs(self, tmp_path):
        """Token is optional — providers that don't need it can omit it."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("providers:\n  cloudflare:\n    other: value\n")
        config = Config.from_file(config_file)
        assert "token" not in config.providers["cloudflare"].kwargs

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

    def test_provider_not_a_mapping(self, tmp_path):
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

    def test_always_dry_run_string_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone='    always_dry_run: "yes"\n'))
        with pytest.raises(ConfigError, match="always_dry_run.*must be a boolean"):
            Config.from_file(config_file)


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
        assert config.providers["cloudflare"].kwargs["token"] == "test-token-123"
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

    # -- load_zone_rules --

    def test_zone_name_traversal_blocked(self, tmp_path):
        """Zone name with ../ should raise ConfigError."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        with pytest.raises(ConfigError, match="resolves outside rules directory"):
            config.load_zone_rules("../../etc/passwd")

    def test_zone_name_single_dotdot_blocked(self, tmp_path):
        """Zone name with a single ../ escape should raise ConfigError."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        with pytest.raises(ConfigError, match="resolves outside rules directory"):
            config.load_zone_rules("../secret")

    def test_zone_name_absolute_path_blocked(self, tmp_path):
        """Zone name that is an absolute path should raise ConfigError."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        with pytest.raises(ConfigError, match="resolves outside rules directory"):
            config.load_zone_rules("/etc/passwd")

    def test_zone_name_embedded_dotdot_blocked(self, tmp_path):
        """Zone name with embedded ../ segments should raise ConfigError."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        with pytest.raises(ConfigError, match="resolves outside rules directory"):
            config.load_zone_rules("subdir/../../etc/passwd")

    def test_zone_name_safe_subdirectory_allowed(self, tmp_path):
        """Zone name that stays within rules_dir should not raise."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        # Normal zone name — no file exists, so returns empty dict (no error)
        result = config.load_zone_rules("example.com")
        assert result == {}

    # -- load_account_rules --

    def test_account_name_sanitized_by_slugify(self, tmp_path):
        """Account name with traversal chars is sanitized by slugify."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        # slugify("../../etc/passwd") → "etc-passwd", which is safe
        # Should not raise — just returns empty (no file found)
        result = config.load_account_rules("../../etc/passwd")
        assert result == {}

    def test_account_name_dotdot_sanitized(self, tmp_path):
        """Account name with ../ is sanitized to a safe slug by slugify."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        # slugify("../secret") → "secret", which is safe within rules_dir
        result = config.load_account_rules("../secret")
        assert result == {}

    def test_account_name_absolute_path_sanitized(self, tmp_path):
        """Account name that looks like an absolute path is sanitized by slugify."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        # slugify("/etc/passwd") → "etc-passwd", which is safe
        result = config.load_account_rules("/etc/passwd")
        assert result == {}

    def test_account_name_slugify_prevents_escape(self, tmp_path):
        """Verify slugify strips all dangerous characters from account names."""
        dangerous_names = [
            "../../etc/passwd",
            "../secret",
            "/etc/shadow",
            "subdir/../../etc/passwd",
            "....//....//etc/passwd",
        ]
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(rules_dir=rules_dir, zones={})
        for name in dangerous_names:
            slug = slugify(name)
            # Slug must not contain path separators or dot-dot sequences
            assert "/" not in slug, f"slugify({name!r}) = {slug!r} contains '/'"
            assert ".." not in slug, f"slugify({name!r}) = {slug!r} contains '..'"
            # Must not raise — slugified name is always safe
            result = config.load_account_rules(name)
            assert result == {}, f"Expected empty dict for account name {name!r}"


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
            expected = yaml.load(f, Loader=loader_cls)
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
            expected = yaml.load(f, Loader=loader_cls)
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
            expected = yaml.load(f, Loader=loader_cls)
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
            expected = yaml.load(f, Loader=loader_cls)
        actual = _yaml_load(yaml_file)
        assert actual == expected


class TestMaxWorkers:
    """Tests for manager.max_workers config parsing."""

    def test_default_max_workers(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert config.max_workers == 1

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

    def test_invalid_max_workers_non_numeric(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager:\n  max_workers: abc\n")
        with pytest.raises(ConfigError, match="max_workers.*must be an integer"):
            Config.from_file(config_file)

    def test_invalid_max_workers_list(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg() + "manager:\n  max_workers:\n    - 1\n    - 2\n")
        with pytest.raises(ConfigError, match="max_workers.*must be an integer"):
            Config.from_file(config_file)


class TestMaxRetries:
    """Tests for provider max_retries config parsing."""

    def test_max_retries_forwarded_to_kwargs(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    max_retries: 5\n"))
        config = Config.from_file(config_file)
        assert config.providers["cloudflare"].kwargs["max_retries"] == 5

    def test_max_retries_omitted_not_in_kwargs(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert "max_retries" not in config.providers["cloudflare"].kwargs


class TestTimeout:
    """Tests for provider timeout config parsing."""

    def test_timeout_forwarded_to_kwargs(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    timeout: 30\n"))
        config = Config.from_file(config_file)
        assert config.providers["cloudflare"].kwargs["timeout"] == 30

    def test_timeout_omitted_not_in_kwargs(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        assert "timeout" not in config.providers["cloudflare"].kwargs


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

    def test_allow_unmanaged_string_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone='    allow_unmanaged: "yes"\n'))
        with pytest.raises(ConfigError, match="allow_unmanaged.*must be a boolean"):
            Config.from_file(config_file)


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
        with pytest.raises(
            ConfigError, match="'providers\\.cloudflare\\.safety' must be a mapping"
        ):
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

    def test_provider_non_numeric_delete_threshold_raises(self, tmp_path):
        """Non-numeric delete_threshold at provider level should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      delete_threshold: oops\n"))
        with pytest.raises(ConfigError, match="delete_threshold.*must be numeric.*oops"):
            Config.from_file(config_file)

    def test_provider_non_numeric_update_threshold_raises(self, tmp_path):
        """Non-numeric update_threshold at provider level should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      update_threshold: bad\n"))
        with pytest.raises(ConfigError, match="update_threshold.*must be numeric.*bad"):
            Config.from_file(config_file)

    def test_provider_non_integer_min_existing_raises(self, tmp_path):
        """Non-integer min_existing at provider level should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      min_existing: nope\n"))
        with pytest.raises(ConfigError, match="min_existing.*must be an integer.*nope"):
            Config.from_file(config_file)

    def test_zone_non_numeric_delete_threshold_raises(self, tmp_path):
        """Non-numeric delete_threshold at zone level should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    safety:\n      delete_threshold: oops\n"))
        with pytest.raises(ConfigError, match="delete_threshold.*must be numeric.*oops"):
            Config.from_file(config_file)

    def test_zone_non_numeric_update_threshold_raises(self, tmp_path):
        """Non-numeric update_threshold at zone level should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    safety:\n      update_threshold: bad\n"))
        with pytest.raises(ConfigError, match="update_threshold.*must be numeric.*bad"):
            Config.from_file(config_file)

    def test_zone_non_integer_min_existing_raises(self, tmp_path):
        """Non-integer min_existing at zone level should raise ConfigError."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_zone="    safety:\n      min_existing: nope\n"))
        with pytest.raises(ConfigError, match="min_existing.*must be an integer.*nope"):
            Config.from_file(config_file)


class TestDuplicateYamlKeys:
    """CORE001: Duplicate YAML keys raise ConfigError."""

    def test_duplicate_top_level_key_raises(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: env/CF_TOKEN\n"
            "rules:\n"
            "  directory: ./rules\n"
            "rules:\n"
            "  directory: ./other\n"
        )
        with pytest.raises(ConfigError, match="Duplicate YAML key 'rules'"):
            Config.from_file(config_file)

    def test_duplicate_key_in_zone_raises(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "redirect_rules:\n"
            "  - ref: r2\n"
            "    expression: 'false'\n"
        )
        config = Config(rules_dir=rules_dir, zones={"example.com": ZoneConfig(name="example.com")})
        with pytest.raises(ConfigError, match="Duplicate YAML key 'redirect_rules'"):
            config.load_zone_rules("example.com")

    def test_no_duplicate_keys_ok(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        config = Config.from_file(config_file)
        # Populated: providers and zones should be non-empty given _cfg().
        assert config.providers
        assert config.zones

    def test_nested_duplicate_key_raises(self, tmp_path):
        """Duplicate keys inside a nested mapping are also caught."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: env/CF_TOKEN\n"
            "    token: env/CF_TOKEN2\n"
            "rules:\n"
            "  directory: ./rules\n"
        )
        with pytest.raises(ConfigError, match="Duplicate YAML key 'token'"):
            Config.from_file(config_file)


class TestSafetyThresholdSanity:
    """Warn when delete_threshold < update_threshold."""

    def test_inverted_thresholds_warns(self, tmp_path, caplog):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(extra_cf="    safety:\n      delete_threshold: 10\n      update_threshold: 50\n")
        )
        Config.from_file(config_file)
        assert "delete_threshold" in caplog.text
        assert "less restricted" in caplog.text

    def test_zone_level_inverted_thresholds_warns(self, tmp_path, caplog):
        """Also fires for zone-level safety thresholds."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(extra_zone="    safety:\n      delete_threshold: 5\n      update_threshold: 40\n")
        )
        Config.from_file(config_file)
        assert "delete_threshold" in caplog.text
        assert "less restricted" in caplog.text

    def test_equal_thresholds_no_warning(self, tmp_path, caplog):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(extra_cf="    safety:\n      delete_threshold: 30\n      update_threshold: 30\n")
        )
        Config.from_file(config_file)
        assert "less restricted" not in caplog.text


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
        assert config.max_workers == 1


class TestResolveZoneIds:
    """Tests for the resolve_zone_ids function."""

    def test_resolves_all_zones(self):
        config = Config(
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

    def test_non_config_error_wrapped(self):
        """Non-ConfigError exceptions from resolve_fn are wrapped with zone context."""
        config = Config(
            rules_dir="/tmp/rules",
            zones={"fail.com": ZoneConfig(name="fail.com")},
        )

        def explode(name):
            raise RuntimeError("connection refused")

        with pytest.raises(ConfigError, match="Failed to resolve zone 'fail.com'"):
            resolve_zone_ids(config, explode)

    def test_non_config_error_wrapped_parallel(self):
        """Non-ConfigError wrapping also works in the parallel path."""
        config = Config(
            rules_dir="/tmp/rules",
            zones={
                "ok.com": ZoneConfig(name="ok.com"),
                "fail.com": ZoneConfig(name="fail.com"),
            },
        )

        def maybe_explode(name):
            if name == "fail.com":
                raise ConnectionError("timeout")
            return f"id-for-{name}"

        with pytest.raises(ConfigError, match="Failed to resolve zone 'fail.com'"):
            resolve_zone_ids(config, maybe_explode, max_workers=2)

    def test_zone_filter_resolves_only_listed_zones(self):
        """zone_filter restricts which zones are resolved."""
        resolved = []

        def tracking_resolve(name):
            resolved.append(name)
            return f"id-for-{name}"

        config = Config(
            rules_dir="/tmp/rules",
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "b.com": ZoneConfig(name="b.com"),
                "c.com": ZoneConfig(name="c.com"),
            },
        )
        resolve_zone_ids(config, tracking_resolve, zone_filter=["a.com", "c.com"])
        # a.com and c.com resolved
        assert config.zones["a.com"].zone_id == "id-for-a.com"
        assert config.zones["c.com"].zone_id == "id-for-c.com"
        # b.com was NOT resolved
        assert config.zones["b.com"].zone_id is None
        # resolve_fn was only called for the filtered zones
        assert sorted(resolved) == ["a.com", "c.com"]

    def test_zone_filter_none_resolves_all(self):
        """zone_filter=None resolves all zones (backward compat)."""
        config = Config(
            rules_dir="/tmp/rules",
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "b.com": ZoneConfig(name="b.com"),
                "c.com": ZoneConfig(name="c.com"),
            },
        )
        resolve_zone_ids(config, lambda name: f"id-for-{name}", zone_filter=None)
        assert config.zones["a.com"].zone_id == "id-for-a.com"
        assert config.zones["b.com"].zone_id == "id-for-b.com"
        assert config.zones["c.com"].zone_id == "id-for-c.com"

    def test_zone_filter_empty_list_resolves_all(self):
        """zone_filter=[] is falsy, so it behaves like None (resolves all)."""
        resolved = []

        def tracking_resolve(name):
            resolved.append(name)
            return f"id-for-{name}"

        config = Config(
            rules_dir="/tmp/rules",
            zones={
                "a.com": ZoneConfig(name="a.com"),
                "b.com": ZoneConfig(name="b.com"),
                "c.com": ZoneConfig(name="c.com"),
            },
        )
        resolve_zone_ids(config, tracking_resolve, zone_filter=[])
        # Empty list is falsy — same behavior as None, all zones resolved
        assert config.zones["a.com"].zone_id == "id-for-a.com"
        assert config.zones["b.com"].zone_id == "id-for-b.com"
        assert config.zones["c.com"].zone_id == "id-for-c.com"
        assert sorted(resolved) == ["a.com", "b.com", "c.com"]


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
        assert isinstance(config.plan_outputs["text"], PlanOutput)
        assert config.plan_outputs["text"].fmt == "text"
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
        assert isinstance(config.plan_outputs["html"], PlanOutput)
        assert config.plan_outputs["html"].fmt == "html"
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
        assert isinstance(config.plan_outputs["text"], PlanOutput)
        assert config.plan_outputs["text"].fmt == "text"
        assert isinstance(config.plan_outputs["json"], PlanOutput)
        assert config.plan_outputs["json"].fmt == "json"
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


class TestRulesCache:
    """Tests for YAML rules caching in Config."""

    def test_zone_rules_cached(self, tmp_config):
        rules_dir = tmp_config.parent / "rules"
        zone_file = rules_dir / "example.com.yaml"
        zone_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        config = Config.from_file(tmp_config)
        first = config.load_zone_rules("example.com")
        second = config.load_zone_rules("example.com")
        assert first is second
        assert first["redirect_rules"][0]["ref"] == "r1"

    def test_account_rules_cached(self, tmp_config):
        rules_dir = tmp_config.parent / "rules"
        acct_file = rules_dir / "test-acct.yaml"
        acct_file.write_text("waf_custom_rules:\n  - ref: w1\n    expression: 'true'\n")
        config = Config.from_file(tmp_config)
        first = config.load_account_rules("Test Acct")
        second = config.load_account_rules("Test Acct")
        assert first is second

    def test_missing_zone_rules_cached_as_empty(self, tmp_config):
        config = Config.from_file(tmp_config)
        first = config.load_zone_rules("nonexistent.com")
        second = config.load_zone_rules("nonexistent.com")
        assert first == {}
        assert first is second

    def test_different_zones_independent(self, tmp_config):
        rules_dir = tmp_config.parent / "rules"
        (rules_dir / "a.com.yaml").write_text("redirect_rules:\n  - ref: a\n    expression: 't'\n")
        (rules_dir / "b.com.yaml").write_text("cache_rules:\n  - ref: b\n    expression: 't'\n")
        config = Config.from_file(tmp_config)
        a = config.load_zone_rules("a.com")
        b = config.load_zone_rules("b.com")
        assert "redirect_rules" in a
        assert "cache_rules" in b
        assert a is not b


class TestListsDir:
    def test_lists_dir_defaults_to_custom_lists(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg())
        (tmp_path / "rules").mkdir()
        config = Config.from_file(config_file)
        assert config.lists_dir == (tmp_path / "rules" / "custom_lists").resolve()

    def test_lists_dir_from_config(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        my_lists = rules_dir / "my_lists"
        my_lists.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "  lists:\n"
            "    directory: ./rules/my_lists\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        assert config.lists_dir == my_lists.resolve()

    def test_lists_dir_outside_rules_dir_raises(self, tmp_path):
        (tmp_path / "rules").mkdir()
        (tmp_path / "other").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "  lists:\n"
            "    directory: ./other\n"
            "zones: {}\n"
        )
        with pytest.raises(ConfigError, match="must be within the rules directory"):
            Config.from_file(config_file)

    def test_lists_dir_relative_to_config_file(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        rules_dir = sub / "rules"
        rules_dir.mkdir()
        lists_dir = rules_dir / "lists"
        lists_dir.mkdir()
        config_file = sub / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "  lists:\n"
            "    directory: ./rules/lists\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        assert config.lists_dir == lists_dir.resolve()

    def test_lists_dir_not_a_mapping_raises(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "  lists: notadict\n"
            "zones: {}\n"
        )
        with pytest.raises(ConfigError, match="'providers.lists' must be a mapping"):
            Config.from_file(config_file)

    def test_lists_dir_null_treated_as_empty(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "  lists:\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        assert config.lists_dir == (tmp_path / "rules" / "custom_lists").resolve()

    def test_lists_dir_post_init_default(self, tmp_path):
        """Config created directly (not via from_file) defaults lists_dir."""
        rules_dir = tmp_path / "rules"
        config = Config(rules_dir=rules_dir)
        assert config.lists_dir == rules_dir / "custom_lists"


class TestMultiProvider:
    """Tests for multi-provider configuration."""

    def test_two_providers_parsed(self, tmp_path):
        """Config with two providers should parse both into config.providers."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  aws:\n"
            "    region: us-west-2\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - cloudflare\n"
            "  my-web-acl:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - aws\n"
        )
        config = Config.from_file(config_file)
        assert "cloudflare" in config.providers
        assert "aws" in config.providers
        assert config.providers["cloudflare"].kwargs["token"] == "tok"
        assert config.providers["aws"].kwargs["region"] == "us-west-2"
        assert config.providers["cloudflare"].name == "cloudflare"
        assert config.providers["aws"].name == "aws"

    def test_multi_provider_requires_targets(self, tmp_path):
        """With multiple providers, zone without targets raises ConfigError."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  aws:\n"
            "    region: us-west-2\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        with pytest.raises(ConfigError, match="must specify 'targets'"):
            Config.from_file(config_file)

    def test_multi_provider_targets_auto_assign(self, tmp_path):
        """With one provider, zone without targets auto-assigns it."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].targets == ["cloudflare"]

    def test_multi_provider_targets_explicit(self, tmp_path):
        """With two providers, zone with explicit targets: [cloudflare] is parsed."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  aws:\n"
            "    region: us-west-2\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - cloudflare\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].targets == ["cloudflare"]

    def test_multi_target_accepted(self, tmp_path):
        """Zone with multiple targets is accepted (same provider class check is at init time)."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  aws:\n"
            "    region: us-west-2\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - cloudflare\n"
            "      - aws\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].targets == ["cloudflare", "aws"]

    def test_multi_target_safety_from_first_target(self, tmp_path):
        """Safety defaults come from the first target provider."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cf-prod:\n"
            "    class: octorules_cloudflare.CloudflareProvider\n"
            "    token: tok\n"
            "    safety:\n"
            "      delete_threshold: 10\n"
            "  cf-staging:\n"
            "    class: octorules_cloudflare.CloudflareProvider\n"
            "    token: tok2\n"
            "    safety:\n"
            "      delete_threshold: 50\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - cf-prod\n"
            "      - cf-staging\n"
        )
        config = Config.from_file(config_file)
        # Safety defaults come from first target (cf-prod)
        assert config.zones["example.com"].delete_threshold == 10.0

    def test_unknown_target_rejected(self, tmp_path):
        """Zone targeting an unknown provider raises ConfigError."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - unknown\n"
        )
        with pytest.raises(ConfigError, match="unknown provider 'unknown'"):
            Config.from_file(config_file)

    def test_targets_non_list_rejected(self, tmp_path):
        """Zone with targets as a string (not list) raises ConfigError."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets: cloudflare\n"
        )
        with pytest.raises(ConfigError, match="targets.*must be a list"):
            Config.from_file(config_file)

    def test_safety_from_target_provider(self, tmp_path):
        """Zone inherits safety defaults from its target provider."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "    safety:\n"
            "      delete_threshold: 50\n"
            "      update_threshold: 40\n"
            "      min_existing: 5\n"
            "  aws:\n"
            "    region: us-west-2\n"
            "    safety:\n"
            "      delete_threshold: 20\n"
            "      update_threshold: 10\n"
            "      min_existing: 1\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - cloudflare\n"
            "  my-web-acl:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - aws\n"
        )
        config = Config.from_file(config_file)
        cf_zone = config.zones["example.com"]
        assert cf_zone.delete_threshold == 50.0
        assert cf_zone.update_threshold == 40.0
        assert cf_zone.min_existing == 5

        aws_zone = config.zones["my-web-acl"]
        assert aws_zone.delete_threshold == 20.0
        assert aws_zone.update_threshold == 10.0
        assert aws_zone.min_existing == 1


class TestResolveDeep:
    """Tests for recursive env/ resolution in nested structures."""

    def test_recursive_env_resolution(self, tmp_path, monkeypatch):
        """Nested dict values with env/ prefixes are resolved recursively."""
        monkeypatch.setenv("NESTED_SECRET", "resolved-secret")
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "    nested:\n"
            "      inner: env/NESTED_SECRET\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["nested"]["inner"] == "resolved-secret"


class TestProcessorConfig:
    def test_processors_section_parsed(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "processors:\n"
            "  my_proc:\n"
            "    class: some.module.MyProcessor\n"
            "    setting: value\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    processors:\n"
            "      - my_proc\n"
        )
        config = Config.from_file(config_file)
        assert "my_proc" in config.processors
        assert config.processors["my_proc"].class_path == "some.module.MyProcessor"
        assert config.processors["my_proc"].kwargs == {"setting": "value"}
        assert config.zones["example.com"].processors == ["my_proc"]

    def test_zone_processors_validated(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    processors:\n"
            "      - nonexistent\n"
        )
        with pytest.raises(ConfigError, match="unknown processor"):
            Config.from_file(config_file)

    def test_zone_without_processors_ok(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        config = Config.from_file(config_file)
        assert config.zones["example.com"].processors == []

    def test_processor_env_resolution(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PROC_KEY", "secret")
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "processors:\n"
            "  my_proc:\n"
            "    class: some.module.MyProcessor\n"
            "    api_key: env/PROC_KEY\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.processors["my_proc"].kwargs["api_key"] == "secret"

    def test_processors_section_optional(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        config = Config.from_file(config_file)
        assert config.processors == {}

    def test_processor_requires_class(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "processors:\n"
            "  my_proc:\n"
            "    setting: value\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        with pytest.raises(ConfigError, match="missing required 'class'"):
            Config.from_file(config_file)


class TestZoneTemplates:
    def test_wildcard_parsed_as_template(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  '*':\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - cloudflare\n"
        )
        config = Config.from_file(config_file)
        assert "*" in config.zone_templates
        assert "*" not in config.zones

    def test_expand_templates_adds_matching_zones(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "discovered.com.yaml").write_text("redirect_rules: []\n")

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zone_templates={
                "*": ZoneConfig(
                    name="*",
                    sources=["rules"],
                    targets=["cloudflare"],
                    delete_threshold=15.0,
                ),
            },
        )
        config.expand_templates({"cloudflare": ["discovered.com"]})
        assert "discovered.com" in config.zones
        assert config.zones["discovered.com"].targets == ["cloudflare"]
        assert config.zones["discovered.com"].delete_threshold == 15.0

    def test_expand_templates_skips_existing(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "explicit.com.yaml").write_text("redirect_rules: []\n")

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zones={
                "explicit.com": ZoneConfig(name="explicit.com", targets=["cloudflare"]),
            },
            zone_templates={
                "*": ZoneConfig(name="*", targets=["cloudflare"]),
            },
        )
        config.expand_templates({"cloudflare": ["explicit.com"]})
        # explicit wins, no duplicate
        assert len([k for k in config.zones if k == "explicit.com"]) == 1

    def test_expand_templates_skips_no_yaml(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # No YAML file for this zone

        config = Config(
            rules_dir=rules_dir,
            providers={"cloudflare": ProviderConfig(name="cloudflare")},
            zone_templates={
                "*": ZoneConfig(name="*", targets=["cloudflare"]),
            },
        )
        config.expand_templates({"cloudflare": ["no-yaml.com"]})
        assert "no-yaml.com" not in config.zones


class TestSecretHandlers:
    """Tests for pluggable secret handler resolution."""

    def test_from_file_stores_raw_values(self, tmp_path):
        """from_file() stores raw unresolved secret references."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: env/SOME_VAR\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        # Before resolve_secrets(), raw value is stored
        assert config.providers["cloudflare"].kwargs["token"] == "env/SOME_VAR"

    def test_from_file_succeeds_without_env_var(self, tmp_path):
        """from_file() succeeds even when referenced env var is missing."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: env/MISSING_VAR\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        # Should NOT raise — secrets are not resolved yet
        config = Config.from_file(config_file)
        assert config.providers["cloudflare"].kwargs["token"] == "env/MISSING_VAR"

    def test_resolve_secrets_idempotent(self, tmp_path, monkeypatch):
        """Calling resolve_secrets() twice is a no-op."""
        monkeypatch.setenv("CF_TOKEN", "my-tok")
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: env/CF_TOKEN\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["token"] == "my-tok"
        config.resolve_secrets()  # second call is no-op
        assert config.providers["cloudflare"].kwargs["token"] == "my-tok"

    def test_no_section_env_works(self, tmp_path, monkeypatch):
        """Backward compat: env/ works without a secret_handlers section."""
        monkeypatch.setenv("CF_TOKEN", "my-tok")
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: env/CF_TOKEN\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["token"] == "my-tok"

    def test_custom_handler_from_config(self, tmp_path, monkeypatch):
        """A handler declared in config resolves its prefix."""
        monkeypatch.setenv("CF_TOKEN", "my-tok")
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers:\n"
            "  custom:\n"
            "    class: tests.test_config._StubSecrets\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: custom/ref123\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["token"] == "stub:ref123"

    def test_handler_kwargs_resolved_via_env(self, tmp_path, monkeypatch):
        """Handler kwargs bootstrap through the env handler."""
        monkeypatch.setenv("HANDLER_URL", "https://vault.internal")
        monkeypatch.setenv("CF_TOKEN", "my-tok")
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers:\n"
            "  custom:\n"
            "    class: tests.test_config._StubSecretsWithKwargs\n"
            "    url: env/HANDLER_URL\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: custom/ref\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["token"] == "stub:ref:https://vault.internal"

    def test_unknown_handler_passthrough(self, tmp_path):
        """Unknown prefix returns the string unchanged (after resolve_secrets)."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "    path: ./rules/sub\n"
            "    url: https://example.com/api\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["path"] == "./rules/sub"
        assert config.providers["cloudflare"].kwargs["url"] == "https://example.com/api"

    def test_missing_class_raises(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers:\n"
            "  bad:\n"
            "    url: https://vault\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        with pytest.raises(ConfigError, match="missing required 'class'"):
            Config.from_file(config_file)

    def test_not_a_mapping_raises(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers:\n"
            "  bad: not-a-mapping\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        with pytest.raises(ConfigError, match="must be a mapping"):
            Config.from_file(config_file)

    def test_section_null_ok(self, tmp_path):
        """secret_handlers: null is equivalent to absent."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers:\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        assert config.providers["cloudflare"].kwargs["token"] == "tok"

    def test_class_not_string_raises(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers:\n"
            "  bad:\n"
            "    class: 123\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        with pytest.raises(ConfigError, match="must be a string"):
            Config.from_file(config_file)

    def test_section_not_mapping_raises(self, tmp_path):
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers: [a, b]\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        with pytest.raises(ConfigError, match="'secret_handlers' must be a mapping"):
            Config.from_file(config_file)

    def test_entry_point_discovery(self, tmp_path, monkeypatch):
        """Entry-point secret handlers are discovered automatically."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: ep/ref42\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )

        # Mock entry_points to return our stub
        class FakeEP:
            name = "ep"

            def load(self):
                return _StubSecrets

        monkeypatch.setattr(
            "importlib.metadata.entry_points",
            lambda group: [FakeEP()] if group == "octorules.secret_handlers" else [],
        )
        config = Config.from_file(config_file)
        config.resolve_secrets()
        assert config.providers["cloudflare"].kwargs["token"] == "stub:ref42"

    def test_resolve_secret_no_slash(self):
        """Strings without / are returned unchanged."""
        assert _resolve_secret("plain", {"env": None}, "") == "plain"

    def test_resolve_deep_with_custom_handler(self):
        """_resolve_deep resolves nested values via handlers."""
        handler = _StubSecrets("custom")
        handlers = {"custom": handler}
        result = _resolve_deep(
            {"a": "custom/x", "b": [1, "custom/y"], "c": "plain"},
            handlers,
            "root",
        )
        assert result == {"a": "stub:x", "b": [1, "stub:y"], "c": "plain"}


# --- Stub handler classes for tests ---
class _StubSecrets(BaseSecrets):
    """Minimal stub that returns ``stub:{ref}``."""

    def fetch(self, ref: str, source: str) -> str:
        return f"stub:{ref}"


class _StubSecretsWithKwargs(BaseSecrets):
    """Stub that captures kwargs and includes them in the resolved value."""

    def __init__(self, name: str, **kwargs: str):
        super().__init__(name)
        self.url = kwargs.get("url", "")

    def fetch(self, ref: str, source: str) -> str:
        return f"stub:{ref}:{self.url}"


# --- ContextDict / YAML context tracking ---
class TestContextDict:
    def test_context_dict_preserves_data(self):
        cd = ContextDict({"a": 1, "b": 2}, context="config.yaml:5")
        assert cd["a"] == 1
        assert cd["b"] == 2
        assert cd.context == "config.yaml:5"

    def test_context_dict_default_empty_context(self):
        cd = ContextDict({"a": 1})
        assert cd.context == ""

    def test_ctx_with_context(self):
        cd = ContextDict({"a": 1}, context="config.yaml:5")
        assert _ctx(cd) == " (at config.yaml:5)"

    def test_ctx_without_context(self):
        assert _ctx({"a": 1}) == ""

    def test_ctx_empty_context(self):
        cd = ContextDict({"a": 1}, context="")
        assert _ctx(cd) == ""


class TestContextTracking:
    """Verify file:line context appears in ConfigError messages from YAML parsing."""

    def test_zone_error_has_line_number(self, tmp_path):
        """Zone-level error includes file:line context."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources: not-a-list\n"
        )
        with pytest.raises(ConfigError, match=r"must be a list.*\(at config\.yaml:\d+\)"):
            Config.from_file(config_file)

    def test_provider_error_has_line_number(self, tmp_path):
        """Provider section error includes file:line context."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare: not-a-mapping\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        with pytest.raises(ConfigError, match=r"must be a mapping"):
            Config.from_file(config_file)

    def test_processor_error_has_line_number(self, tmp_path):
        """Processor section error includes file:line context."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "processors:\n"
            "  my_proc:\n"
            "    no_class_key: value\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        with pytest.raises(ConfigError, match=r"missing required 'class' key.*\(at config\.yaml"):
            Config.from_file(config_file)

    def test_include_file_context(self, tmp_path):
        """Errors in !include'd files show the included filename."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        zone_file = tmp_path / "zone_cfg.yaml"
        zone_file.write_text("sources: not-a-list\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com: !include zone_cfg.yaml\n"
        )
        with pytest.raises(ConfigError, match=r"must be a list.*\(at zone_cfg\.yaml:\d+\)"):
            Config.from_file(config_file)

    def test_nested_mapping_context(self, tmp_path):
        """Nested mapping errors include context from the parent mapping."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    always_dry_run: yes_please\n"
        )
        with pytest.raises(
            ConfigError, match=r"always_dry_run.*must be a boolean.*\(at config\.yaml:\d+\)"
        ):
            Config.from_file(config_file)

    def test_zone_not_mapping_has_context(self, tmp_path):
        """Zone that is a scalar (not mapping) still reports context."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com: just-a-string\n"
        )
        with pytest.raises(ConfigError, match=r"must be a mapping"):
            Config.from_file(config_file)

    def test_no_context_on_plain_dict(self):
        """_ctx on a plain dict returns empty string — no crash."""
        assert _ctx({"foo": 1}) == ""

    def test_yaml_loader_produces_context_dicts(self, tmp_path):
        """YAML loader wraps mappings in ContextDict with file:line."""
        from octorules.config import _yaml_load

        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("top:\n  nested:\n    key: value\n")
        result = _yaml_load(yaml_file)
        assert isinstance(result, ContextDict)
        assert "test.yaml:1" in result.context
        nested = result["top"]
        assert isinstance(nested, ContextDict)
        assert "test.yaml:2" in nested.context


class TestIncludeEdgeCases:
    """Edge-case tests for !include: circular chains, deep nesting, special chars."""

    def test_three_way_circular_include(self, tmp_path):
        """A includes B, B includes C, C includes A — should detect the cycle."""
        (tmp_path / "a.yaml").write_text("data: !include b.yaml\n")
        (tmp_path / "b.yaml").write_text("data: !include c.yaml\n")
        (tmp_path / "c.yaml").write_text("data: !include a.yaml\n")
        from octorules.config import _yaml_load

        with pytest.raises(ConfigError, match="Circular include"):
            _yaml_load(tmp_path / "a.yaml")

    def test_four_way_circular_include(self, tmp_path):
        """A->B->C->D->A circular chain at depth 4."""
        (tmp_path / "a.yaml").write_text("x: !include b.yaml\n")
        (tmp_path / "b.yaml").write_text("x: !include c.yaml\n")
        (tmp_path / "c.yaml").write_text("x: !include d.yaml\n")
        (tmp_path / "d.yaml").write_text("x: !include a.yaml\n")
        from octorules.config import _yaml_load

        with pytest.raises(ConfigError, match="Circular include"):
            _yaml_load(tmp_path / "a.yaml")

    @pytest.mark.parametrize("depth", [4, 6, 10])
    def test_deeply_nested_includes(self, tmp_path, depth):
        """Chain of N nested includes (A->B->C->...->leaf) resolves correctly."""
        from octorules.config import _yaml_load

        # Create the leaf file
        (tmp_path / f"level{depth}.yaml").write_text("answer: 42\n")
        # Create intermediate files chaining from level0 down to level{depth}
        for i in range(depth):
            (tmp_path / f"level{i}.yaml").write_text(f"nested: !include level{i + 1}.yaml\n")
        data = _yaml_load(tmp_path / "level0.yaml")
        # Walk the nested chain to reach the leaf value
        node = data
        for _ in range(depth):
            node = node["nested"]
        assert node["answer"] == 42

    def test_include_filename_with_spaces(self, tmp_path):
        """!include with spaces in the filename works correctly."""
        from octorules.config import _yaml_load

        (tmp_path / "my fragment file.yaml").write_text("value: spaced\n")
        (tmp_path / "main.yaml").write_text("data: !include my fragment file.yaml\n")
        result = _yaml_load(tmp_path / "main.yaml")
        assert result["data"]["value"] == "spaced"

    def test_include_filename_with_unicode(self, tmp_path):
        """!include with unicode characters in the filename works correctly."""
        from octorules.config import _yaml_load

        (tmp_path / "regeln.yaml").write_text("value: unicode_ok\n")
        (tmp_path / "main.yaml").write_text("data: !include regeln.yaml\n")
        result = _yaml_load(tmp_path / "main.yaml")
        assert result["data"]["value"] == "unicode_ok"

    def test_include_filename_with_hyphens_and_dots(self, tmp_path):
        """!include with hyphens and dots in the filename."""
        from octorules.config import _yaml_load

        (tmp_path / "my-config.v2.yaml").write_text("version: 2\n")
        (tmp_path / "main.yaml").write_text("cfg: !include my-config.v2.yaml\n")
        result = _yaml_load(tmp_path / "main.yaml")
        assert result["cfg"]["version"] == 2

    def test_diamond_include_allowed(self, tmp_path):
        """Two files both include the same shared file — not a cycle."""
        from octorules.config import _yaml_load

        (tmp_path / "shared.yaml").write_text("shared_key: common\n")
        (tmp_path / "left.yaml").write_text("left: !include shared.yaml\n")
        (tmp_path / "right.yaml").write_text("right: !include shared.yaml\n")
        (tmp_path / "root.yaml").write_text("a: !include left.yaml\nb: !include right.yaml\n")
        result = _yaml_load(tmp_path / "root.yaml")
        assert result["a"]["left"]["shared_key"] == "common"
        assert result["b"]["right"]["shared_key"] == "common"

    def test_include_scalar_value(self, tmp_path):
        """!include that resolves to a scalar (not a mapping or list)."""
        from octorules.config import _yaml_load

        (tmp_path / "value.yaml").write_text("42\n")
        (tmp_path / "main.yaml").write_text("answer: !include value.yaml\n")
        result = _yaml_load(tmp_path / "main.yaml")
        assert result["answer"] == 42

    def test_include_list_value(self, tmp_path):
        """!include that resolves to a list."""
        from octorules.config import _yaml_load

        (tmp_path / "items.yaml").write_text("- one\n- two\n- three\n")
        (tmp_path / "main.yaml").write_text("items: !include items.yaml\n")
        result = _yaml_load(tmp_path / "main.yaml")
        assert result["items"] == ["one", "two", "three"]

    def test_include_empty_file(self, tmp_path):
        """!include of an empty file returns None for that key."""
        from octorules.config import _yaml_load

        (tmp_path / "empty.yaml").write_text("")
        (tmp_path / "main.yaml").write_text("data: !include empty.yaml\n")
        result = _yaml_load(tmp_path / "main.yaml")
        assert result["data"] is None

    def test_circular_via_config_from_file(self, tmp_path):
        """Circular include detected when loading through Config.from_file."""
        (tmp_path / "loop.yaml").write_text("extra: !include loop.yaml\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: tok\nzones: {}\nextra: !include loop.yaml\n"
        )
        with pytest.raises(ConfigError, match="Circular include"):
            Config.from_file(config_file)

    def test_path_traversal_via_dot_segments_in_nested_include(self, tmp_path):
        """Path traversal blocked even when nested includes try to escape."""
        sub = tmp_path / "sub"
        sub.mkdir()
        # The nested include tries ../../ to escape sub/
        (sub / "inner.yaml").write_text("bad: !include ../../etc/passwd\n")
        (sub / "outer.yaml").write_text("nested: !include inner.yaml\n")
        from octorules.config import _yaml_load

        with pytest.raises(ConfigError, match="escapes base directory"):
            _yaml_load(sub / "outer.yaml")


class TestSafetyThresholdInheritance:
    """Edge-case tests for multi-level safety threshold inheritance.

    Safety thresholds flow: hardcoded defaults -> provider safety -> zone safety.
    Each level should only override the fields it specifies, inheriting the rest.
    """

    def test_zone_inherits_unset_fields_from_provider(self, tmp_path):
        """Zone overrides delete_threshold; update_threshold and min_existing
        should still come from the provider, not fall back to hardcoded defaults."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(
                extra_cf=(
                    "    safety:\n"
                    "      delete_threshold: 50\n"
                    "      update_threshold: 40\n"
                    "      min_existing: 7\n"
                ),
                extra_zone="    safety:\n      delete_threshold: 80\n",
            )
        )
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 80.0  # overridden by zone
        assert zone.update_threshold == 40.0  # inherited from provider
        assert zone.min_existing == 7  # inherited from provider

    def test_zone_overrides_only_min_existing(self, tmp_path):
        """Zone overrides only min_existing; thresholds inherit from provider."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(
                extra_cf=(
                    "    safety:\n"
                    "      delete_threshold: 15\n"
                    "      update_threshold: 25\n"
                    "      min_existing: 10\n"
                ),
                extra_zone="    safety:\n      min_existing: 1\n",
            )
        )
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 15.0
        assert zone.update_threshold == 25.0
        assert zone.min_existing == 1

    def test_zone_overrides_all_three(self, tmp_path):
        """Zone overrides all three safety fields; provider values ignored."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(
                extra_cf=(
                    "    safety:\n"
                    "      delete_threshold: 10\n"
                    "      update_threshold: 20\n"
                    "      min_existing: 5\n"
                ),
                extra_zone=(
                    "    safety:\n"
                    "      delete_threshold: 90\n"
                    "      update_threshold: 80\n"
                    "      min_existing: 0\n"
                ),
            )
        )
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 90.0
        assert zone.update_threshold == 80.0
        assert zone.min_existing == 0

    def test_zone_empty_safety_inherits_all_from_provider(self, tmp_path):
        """Zone with empty safety: {} inherits all values from provider."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(
                extra_cf=(
                    "    safety:\n"
                    "      delete_threshold: 60\n"
                    "      update_threshold: 55\n"
                    "      min_existing: 8\n"
                ),
                extra_zone="    safety: {}\n",
            )
        )
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 60.0
        assert zone.update_threshold == 55.0
        assert zone.min_existing == 8

    def test_zone_null_safety_inherits_all_from_provider(self, tmp_path):
        """Zone with safety: null inherits all values from provider."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            _cfg(
                extra_cf=(
                    "    safety:\n"
                    "      delete_threshold: 45\n"
                    "      update_threshold: 35\n"
                    "      min_existing: 6\n"
                ),
                extra_zone="    safety:\n",
            )
        )
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 45.0
        assert zone.update_threshold == 35.0
        assert zone.min_existing == 6

    def test_provider_partial_safety_rest_defaults(self, tmp_path):
        """Provider sets only delete_threshold; zone inherits that, rest are
        hardcoded defaults (30.0, 30.0, 3)."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(_cfg(extra_cf="    safety:\n      delete_threshold: 99\n"))
        config = Config.from_file(config_file)
        zone = config.zones["example.com"]
        assert zone.delete_threshold == 99.0
        assert zone.update_threshold == 30.0  # hardcoded default
        assert zone.min_existing == 3  # hardcoded default

    def test_multi_zone_different_inheritance(self, tmp_path):
        """Two zones with different overrides against the same provider."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "    safety:\n"
            "      delete_threshold: 50\n"
            "      update_threshold: 40\n"
            "      min_existing: 5\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  zone-a.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    safety:\n"
            "      delete_threshold: 10\n"
            "  zone-b.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    safety:\n"
            "      min_existing: 0\n"
        )
        config = Config.from_file(config_file)

        zone_a = config.zones["zone-a.com"]
        assert zone_a.delete_threshold == 10.0  # zone override
        assert zone_a.update_threshold == 40.0  # inherited from provider
        assert zone_a.min_existing == 5  # inherited from provider

        zone_b = config.zones["zone-b.com"]
        assert zone_b.delete_threshold == 50.0  # inherited from provider
        assert zone_b.update_threshold == 40.0  # inherited from provider
        assert zone_b.min_existing == 0  # zone override

    def test_multi_provider_zone_inherits_from_correct_target(self, tmp_path):
        """Each zone inherits safety from its own target provider, not from the other."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  prov_a:\n"
            "    class: some.ProviderA\n"
            "    safety:\n"
            "      delete_threshold: 10\n"
            "      update_threshold: 20\n"
            "      min_existing: 1\n"
            "  prov_b:\n"
            "    class: some.ProviderB\n"
            "    safety:\n"
            "      delete_threshold: 90\n"
            "      update_threshold: 80\n"
            "      min_existing: 9\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  zone-x.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - prov_a\n"
            "  zone-y.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    targets:\n"
            "      - prov_b\n"
        )
        config = Config.from_file(config_file)

        zx = config.zones["zone-x.com"]
        assert zx.delete_threshold == 10.0
        assert zx.update_threshold == 20.0
        assert zx.min_existing == 1

        zy = config.zones["zone-y.com"]
        assert zy.delete_threshold == 90.0
        assert zy.update_threshold == 80.0
        assert zy.min_existing == 9


class TestUnknownConfigKeyWarnings:
    """Tests for unknown key warnings during config loading."""

    def test_unknown_zone_key_warns(self, tmp_path, caplog):
        """A typo in zone config (e.g. 'sorces') triggers a warning."""
        (tmp_path / "rules").mkdir()
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
            "    sorces:\n"
            "      - rules\n"
        )
        import logging

        with caplog.at_level(logging.WARNING, logger="octorules"):
            Config.from_file(cfg)
        assert "Unknown key 'sorces' in zones.example.com" in caplog.text

    def test_unknown_top_level_key_warns(self, tmp_path, caplog):
        """A typo at top level (e.g. 'provider' singular) triggers a warning."""
        (tmp_path / "rules").mkdir()
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "provider:\n"
            "  cloudflare: {}\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        import logging

        with caplog.at_level(logging.WARNING, logger="octorules"):
            Config.from_file(cfg)
        assert "Unknown top-level config key 'provider'" in caplog.text

    def test_known_keys_no_warning(self, tmp_path, caplog):
        """A valid config with no typos produces no 'Unknown key' warnings."""
        (tmp_path / "rules").mkdir()
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        import logging

        with caplog.at_level(logging.WARNING, logger="octorules"):
            Config.from_file(cfg)
        assert "Unknown key" not in caplog.text
        assert "Unknown top-level" not in caplog.text


class TestTargetPluginsForZone:
    """``Config.target_plugins_for_zone`` — per-zone lint-plugin routing."""

    def _config_with(self, tmp_path, zones_yaml: str, providers_yaml: str = "") -> Config:
        cfg = tmp_path / "config.yaml"
        prov = providers_yaml or "  cloudflare:\n    token: tok\n"
        # `rules:` is the framework-level rules source — every example config
        # declares it so `sources: [rules]` resolves.
        cfg.write_text(f"providers:\n{prov}  rules: {{}}\nzones:\n{zones_yaml}")
        (tmp_path / "rules").mkdir(exist_ok=True)
        return Config.from_file(cfg)

    def test_explicit_class_path(self, tmp_path):
        config = self._config_with(
            tmp_path,
            zones_yaml="  example.com:\n    targets: [cf-prod]\n    sources: [rules]\n",
            providers_yaml=(
                "  cf-prod:\n"
                "    class: octorules_cloudflare.provider.CloudflareProvider\n"
                "    token: tok\n"
            ),
        )
        assert config.target_plugins_for_zone("example.com") == {"cloudflare"}

    def test_implicit_provider_name(self, tmp_path):
        """No `class:` — fall back to the provider-config key when it
        matches a registered plugin (entry-point convention)."""
        # Register a "cloudflare" plugin so the fallback resolves.
        from octorules.linter.engine import LintContext, LintResult, Severity
        from octorules.linter.plugin import (
            LintPlugin,
            register_linter,
            unregister_linter,
        )

        def _noop(rules_data: dict, ctx: LintContext) -> None:
            del rules_data, ctx

        plugin = LintPlugin(
            name="cloudflare",
            lint_fn=_noop,
            rule_ids=frozenset({"CFTEST"}),
        )
        # Avoid duplicate-registration error if the real CF plugin is installed.
        try:
            register_linter(plugin)
            try:
                config = self._config_with(
                    tmp_path,
                    zones_yaml="  example.com:\n    targets: [cloudflare]\n    sources: [rules]\n",
                )
                assert config.target_plugins_for_zone("example.com") == {"cloudflare"}
            finally:
                unregister_linter("cloudflare")
        except ValueError:
            # Real CF plugin already registered — test the resolution against it.
            config = self._config_with(
                tmp_path,
                zones_yaml="  example.com:\n    targets: [cloudflare]\n    sources: [rules]\n",
            )
            assert config.target_plugins_for_zone("example.com") == {"cloudflare"}
            del LintResult, Severity  # silence unused imports

    def test_no_targets_returns_none(self, tmp_path):
        config = self._config_with(
            tmp_path,
            zones_yaml="  example.com:\n    sources: [rules]\n",
        )
        assert config.target_plugins_for_zone("example.com") is None

    def test_zone_not_in_config(self, tmp_path):
        config = self._config_with(tmp_path, zones_yaml="  example.com:\n    sources: [rules]\n")
        assert config.target_plugins_for_zone("not-a-zone") is None

    def test_non_octorules_class_path_returns_none(self, tmp_path):
        config = self._config_with(
            tmp_path,
            zones_yaml="  example.com:\n    targets: [acme-prod]\n    sources: [rules]\n",
            providers_yaml=("  acme-prod:\n    class: thirdparty.acme.provider.AcmeProvider\n"),
        )
        # Custom (non-octorules_*) class path — can't infer plugin name,
        # fall back so every registered plugin runs.
        assert config.target_plugins_for_zone("example.com") is None

    def test_multi_target_same_class(self, tmp_path):
        config = self._config_with(
            tmp_path,
            zones_yaml="  example.com:\n    targets: [cf-prod, cf-staging]\n    sources: [rules]\n",
            providers_yaml=(
                "  cf-prod:\n"
                "    class: octorules_cloudflare.provider.CloudflareProvider\n"
                "    token: a\n"
                "  cf-staging:\n"
                "    class: octorules_cloudflare.provider.CloudflareProvider\n"
                "    token: b\n"
            ),
        )
        assert config.target_plugins_for_zone("example.com") == {"cloudflare"}
