"""Failures at the edges of the tool produce a diagnosis, not a traceback.

Three paths that previously ended a run with a raw Python traceback naming
neither the input nor the cause:

* a third-party secret handler that constructs but has no ``fetch()``
* a YAML document nested deeply enough to exhaust the interpreter stack
* any unhandled exception reaching the CLI's top level
"""

import logging

import pytest

from octorules.config import Config, ConfigError, _check_secret_handler, _yaml_load


class _NoFetch:
    """A handler that imports and constructs cleanly but has no fetch()."""

    def __init__(self, name):
        self.name = name


class _FetchNotCallable:
    """fetch exists but is an attribute, not a method."""

    def __init__(self, name):
        self.name = name
        self.fetch = "not callable"


class _Good:
    def __init__(self, name):
        self.name = name

    def fetch(self, ref, source=""):
        return f"stub:{ref}"


class TestSecretHandlerInterface:
    def test_missing_fetch_is_rejected(self):
        with pytest.raises(ConfigError) as exc:
            _check_secret_handler(_NoFetch("vault"), "vault", "secret_handlers entry")
        msg = str(exc.value)
        assert "vault" in msg
        assert "fetch" in msg
        assert "_NoFetch" in msg, "the message must name the offending class"

    def test_non_callable_fetch_is_rejected(self):
        """An attribute named fetch is not an implementation of the interface."""
        with pytest.raises(ConfigError):
            _check_secret_handler(_FetchNotCallable("vault"), "vault", "secret_handlers entry")

    def test_valid_handler_passes(self):
        _check_secret_handler(_Good("vault"), "vault", "secret_handlers entry")

    def test_config_declared_handler_without_fetch_fails_at_load(self, tmp_path):
        """The failure must land at resolve time, not later mid-run."""
        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "secret_handlers:\n"
            "  broken:\n"
            "    class: tests.test_resilience._NoFetch\n"
            "providers:\n"
            "  cloudflare:\n"
            "    token: broken/ref\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )
        config = Config.from_file(config_file)
        with pytest.raises(ConfigError) as exc:
            config.resolve_secrets()
        assert "broken" in str(exc.value)
        assert "fetch" in str(exc.value)


class TestDeeplyNestedYaml:
    def test_recursion_error_becomes_config_error(self, tmp_path):
        """RecursionError is not a YAMLError, so it needs its own handler."""
        deep = tmp_path / "deep.yaml"
        deep.write_text("[" * 8000 + "]" * 8000)
        with pytest.raises(ConfigError) as exc:
            _yaml_load(deep)
        msg = str(exc.value)
        assert "deep.yaml" in msg
        assert "nested too deeply" in msg

    def test_ordinary_yaml_still_loads(self, tmp_path):
        ok = tmp_path / "ok.yaml"
        ok.write_text("a:\n  b:\n    c: 1\n")
        assert _yaml_load(ok) == {"a": {"b": {"c": 1}}}

    def test_malformed_yaml_still_reports_as_config_error(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text("a: [unclosed\n")
        with pytest.raises(ConfigError) as exc:
            _yaml_load(bad)
        assert "Invalid YAML" in str(exc.value)


class TestCliTopLevelHandler:
    def test_unexpected_exception_exits_1_without_traceback(self, tmp_path, monkeypatch, caplog):
        """A bug in a command must not end the run with a raw stack trace."""
        from octorules import cli

        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )

        def _boom(*a, **kw):
            raise RuntimeError("something internal broke")

        monkeypatch.setattr(cli, "cmd_lint", _boom)

        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
            cli.main(["--config", str(config_file), "lint"])

        assert exc.value.code == 1
        assert any("Unexpected error" in r.message for r in caplog.records)
        assert any("--debug" in r.message for r in caplog.records)

    def test_keyboard_interrupt_exits_130(self, tmp_path, monkeypatch, caplog):
        """Ctrl-C is a user action; 130 is the conventional shell code for it."""
        from octorules import cli

        (tmp_path / "rules").mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: tok\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones: {}\n"
        )

        def _interrupt(*a, **kw):
            raise KeyboardInterrupt

        monkeypatch.setattr(cli, "cmd_lint", _interrupt)

        with caplog.at_level(logging.ERROR), pytest.raises(SystemExit) as exc:
            cli.main(["--config", str(config_file), "lint"])

        assert exc.value.code == 130
        assert any("Interrupted" in r.message for r in caplog.records)
