"""Tests for the octorules.secret sub-package."""

import pytest

from octorules.config import ConfigError, _resolve_deep, _resolve_secret
from octorules.secret import BaseSecrets, EnvironSecrets, SecretsException


class TestBaseSecrets:
    def test_init_sets_name_and_log(self):
        handler = BaseSecrets("test")
        assert handler.name == "test"
        assert handler.log.name == "octorules.secret.base.test"

    def test_fetch_raises_not_implemented(self):
        handler = BaseSecrets("test")
        with pytest.raises(NotImplementedError):
            handler.fetch("ref", "source")


class TestEnvironSecrets:
    def test_happy_path(self, monkeypatch):
        monkeypatch.setenv("MY_SECRET", "s3cret")
        handler = EnvironSecrets("env")
        assert handler.fetch("MY_SECRET", "providers.cf.token") == "s3cret"

    def test_missing_var_raises(self, monkeypatch):
        monkeypatch.delenv("NOPE", raising=False)
        handler = EnvironSecrets("env")
        with pytest.raises(SecretsException, match="NOPE"):
            handler.fetch("NOPE", "providers.cf.token")

    def test_source_in_error_message(self, monkeypatch):
        monkeypatch.delenv("MISSING", raising=False)
        handler = EnvironSecrets("env")
        with pytest.raises(SecretsException, match="providers.cf.token"):
            handler.fetch("MISSING", "providers.cf.token")


class TestSecretsException:
    def test_is_config_error(self):
        exc = SecretsException("boom")
        assert isinstance(exc, ConfigError)


# ---------------------------------------------------------------------------
# _resolve_secret
# ---------------------------------------------------------------------------
class TestResolveSecret:
    def test_known_handler_resolves(self, monkeypatch):
        monkeypatch.setenv("TOKEN", "abc123")
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_secret("env/TOKEN", handlers, "test") == "abc123"

    def test_unknown_handler_passthrough(self):
        """Prefixes not in the handler registry are returned unchanged."""
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_secret("file/path/to/secret", handlers, "test") == "file/path/to/secret"

    def test_no_slash_passthrough(self):
        """Values without / are not secret references."""
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_secret("plain_value", handlers, "test") == "plain_value"

    def test_non_string_passthrough(self):
        """Non-string values returned unchanged."""
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_secret(42, handlers, "test") == 42

    def test_url_passthrough(self):
        """URLs with slashes are not treated as secret refs."""
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_secret("https://example.com", handlers, "test") == "https://example.com"

    def test_path_passthrough(self):
        """File paths are not treated as secret refs."""
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_secret("./rules/zone.yaml", handlers, "test") == "./rules/zone.yaml"

    def test_handler_error_propagates(self, monkeypatch):
        """SecretsException from handler propagates."""
        monkeypatch.delenv("MISSING", raising=False)
        handlers = {"env": EnvironSecrets("env")}
        with pytest.raises(SecretsException):
            _resolve_secret("env/MISSING", handlers, "test")


# ---------------------------------------------------------------------------
# _resolve_deep
# ---------------------------------------------------------------------------
class TestResolveDeep:
    def test_nested_dict(self, monkeypatch):
        monkeypatch.setenv("TOKEN", "s3cret")
        handlers = {"env": EnvironSecrets("env")}
        data = {"provider": {"token": "env/TOKEN", "region": "us-east-1"}}
        result = _resolve_deep(data, handlers, "config")
        assert result["provider"]["token"] == "s3cret"
        assert result["provider"]["region"] == "us-east-1"

    def test_nested_list(self, monkeypatch):
        monkeypatch.setenv("KEY1", "val1")
        monkeypatch.setenv("KEY2", "val2")
        handlers = {"env": EnvironSecrets("env")}
        data = ["env/KEY1", "env/KEY2", "plain"]
        result = _resolve_deep(data, handlers, "list")
        assert result == ["val1", "val2", "plain"]

    def test_deeply_nested(self, monkeypatch):
        monkeypatch.setenv("DEEP", "found")
        handlers = {"env": EnvironSecrets("env")}
        data = {"a": {"b": {"c": [{"d": "env/DEEP"}]}}}
        result = _resolve_deep(data, handlers)
        assert result["a"]["b"]["c"][0]["d"] == "found"

    def test_non_string_leaves_unchanged(self):
        handlers = {"env": EnvironSecrets("env")}
        data = {"count": 42, "enabled": True, "ratio": 3.14, "empty": None}
        result = _resolve_deep(data, handlers, "config")
        assert result == data

    def test_error_includes_path_context(self, monkeypatch):
        """SecretsException from nested resolution includes source path."""
        monkeypatch.delenv("MISSING", raising=False)
        handlers = {"env": EnvironSecrets("env")}
        data = {"providers": {"bunny": {"api_key": "env/MISSING"}}}
        with pytest.raises(SecretsException, match="MISSING"):
            _resolve_deep(data, handlers, "config")

    def test_mixed_resolved_and_plain(self, monkeypatch):
        monkeypatch.setenv("SECRET", "resolved")
        handlers = {"env": EnvironSecrets("env")}
        data = {
            "token": "env/SECRET",
            "region": "us-east-1",
            "zones": ["zone-a", "zone-b"],
            "max_workers": 4,
        }
        result = _resolve_deep(data, handlers, "config")
        assert result["token"] == "resolved"
        assert result["region"] == "us-east-1"
        assert result["zones"] == ["zone-a", "zone-b"]
        assert result["max_workers"] == 4

    def test_empty_dict(self):
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_deep({}, handlers) == {}

    def test_empty_list(self):
        handlers = {"env": EnvironSecrets("env")}
        assert _resolve_deep([], handlers) == []

    def test_default_handlers_used(self, monkeypatch):
        """When handlers=None, _default_handlers() provides env handler."""
        monkeypatch.setenv("AUTO", "found")
        result = _resolve_deep({"key": "env/AUTO"})
        assert result["key"] == "found"
