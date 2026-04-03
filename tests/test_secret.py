"""Tests for the octorules.secret sub-package."""

import pytest

from octorules.config import ConfigError
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
