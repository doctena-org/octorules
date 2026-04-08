"""Tests for the Manager class."""

from pathlib import Path
from unittest.mock import patch

import pytest

from octorules.config import Config, ConfigError
from octorules.manager import Manager


@pytest.fixture
def _cfg_path(tmp_path: Path) -> Path:
    """Create a minimal config file and rules dir, return config path."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    rules_file = rules_dir / "example.com.yaml"
    rules_file.write_text("redirect_rules:\n  - ref: test-redirect\n    expression: 'true'\n")
    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  cloudflare:\n"
        "    token: test-token\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  example.com:\n"
        "    sources:\n"
        "      - rules\n"
    )
    return config_file


class TestManagerInit:
    def test_init_from_path(self, _cfg_path):
        """Manager accepts a Path config."""
        mgr = Manager(_cfg_path)
        assert isinstance(mgr.config, Config)

    def test_init_from_string(self, _cfg_path):
        """Manager accepts a string path."""
        mgr = Manager(str(_cfg_path))
        assert isinstance(mgr.config, Config)

    def test_init_from_config_object(self, _cfg_path):
        """Manager accepts an existing Config object."""
        config = Config.from_file(_cfg_path)
        mgr = Manager(config)
        assert mgr.config is config

    def test_init_missing_config_raises(self, tmp_path):
        """Missing config file raises ConfigError."""
        with pytest.raises(ConfigError, match="Config file not found"):
            Manager(tmp_path / "nonexistent.yaml")


class TestManagerContextManager:
    def test_context_manager(self, _cfg_path):
        """Manager works as a context manager."""
        with Manager(_cfg_path) as mgr:
            assert isinstance(mgr, Manager)

    def test_close_idempotent(self, _cfg_path):
        """Calling close() twice does not error."""
        mgr = Manager(_cfg_path)
        mgr.close()
        mgr.close()  # Should not raise


class TestManagerDelegation:
    """Verify Manager methods delegate to cmd_* with correct parameters."""

    def test_plan_delegates(self, _cfg_path):
        mgr = Manager(_cfg_path)
        with patch("octorules.manager.cmd_plan", return_value=0) as mock:
            result = mgr.plan(zones=["example.com"], checksum=True, exit_code=True, scope="zones")
            assert result == 0
            mock.assert_called_once_with(
                mgr.config,
                ["example.com"],
                phase_filter=None,
                checksum=True,
                exit_code=True,
                scope_filter="zones",
            )

    def test_sync_delegates(self, _cfg_path):
        mgr = Manager(_cfg_path)
        with patch("octorules.manager.cmd_sync", return_value=0) as mock:
            result = mgr.sync(force=True, checksum="abc123")
            assert result == 0
            mock.assert_called_once_with(
                mgr.config,
                None,
                phase_filter=None,
                checksum="abc123",
                force=True,
                scope_filter="all",
            )

    def test_dump_delegates(self, _cfg_path):
        mgr = Manager(_cfg_path)
        with patch("octorules.manager.cmd_dump", return_value=0) as mock:
            result = mgr.dump(output_dir="/tmp/out", scope="zones")
            assert result == 0
            mock.assert_called_once_with(
                mgr.config,
                None,
                "/tmp/out",
                scope_filter="zones",
                phase_filter=None,
            )

    def test_lint_delegates(self, _cfg_path):
        mgr = Manager(_cfg_path)
        with patch("octorules.manager.cmd_lint", return_value=2) as mock:
            result = mgr.lint(
                severity="warning",
                exit_code=True,
                format="sarif",
                rules=["M013"],
                plan="enterprise",
                output="/tmp/lint.sarif",
            )
            assert result == 2
            mock.assert_called_once_with(
                mgr.config,
                None,
                phase_filter=None,
                lint_format="sarif",
                lint_severity="warning",
                lint_rules=["M013"],
                lint_plan="enterprise",
                output_file="/tmp/lint.sarif",
                exit_code=True,
            )

    def test_plan_with_phases(self, _cfg_path):
        """Phases are validated and passed through."""
        mgr = Manager(_cfg_path)
        with patch("octorules.manager.cmd_plan", return_value=0) as mock:
            mgr.plan(phases=["redirect_rules"])
            assert mock.call_args[1]["phase_filter"] == ["redirect_rules"]

    def test_invalid_phase_raises(self, _cfg_path):
        """Invalid phase names raise ConfigError before reaching cmd_*."""
        mgr = Manager(_cfg_path)
        with pytest.raises(ConfigError, match="Unknown phase"):
            mgr.plan(phases=["totally_fake_phase"])

    def test_plan_returns_nonzero_exit_code(self, _cfg_path):
        mgr = Manager(_cfg_path)
        with patch("octorules.manager.cmd_plan", return_value=2):
            assert mgr.plan(exit_code=True) == 2

    def test_sync_returns_nonzero_exit_code(self, _cfg_path):
        mgr = Manager(_cfg_path)
        with patch("octorules.manager.cmd_sync", return_value=1):
            assert mgr.sync() == 1

    def test_no_double_provider_init(self, _cfg_path):
        """Manager does not call _init_providers — cmd_* functions handle it."""
        with patch("octorules.commands._providers._init_providers") as mock_init:
            Manager(_cfg_path)
            # Manager.__init__ should NOT call _init_providers
            mock_init.assert_not_called()
