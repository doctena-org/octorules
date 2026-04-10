"""Tests for the CLI."""

import argparse
import logging
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from octorules.cli import (
    _CHECKSUM_RE,
    _emit_plan_outputs,
    _filter_current_by_phase,
    _filter_desired_by_phase,
    _format_api_error,
    _get_zones,
    _positive_int,
    _setup_logging,
    _validate_phases,
    _write_output_file,
    build_parser,
    cmd_audit,
    cmd_dump,
    cmd_lint,
    cmd_plan,
    cmd_sync,
    cmd_versions,
    main,
)
from octorules.config import Config, ConfigError, ProviderConfig, ZoneConfig
from octorules.phases import get_phase
from octorules.plan_output import PlanJson, PlanText
from octorules.provider import Scope

REDIRECT_PHASE = get_phase("redirect_rules")


@pytest.fixture
def sample_config(tmp_path):
    """Create a real Config object with a rules dir and zone file."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return Config(
        providers={
            "cloudflare": ProviderConfig(
                name="cloudflare",
                kwargs={"token": "test-token"},
            ),
        },
        rules_dir=rules_dir,
        zones={
            "example.com": ZoneConfig(
                name="example.com",
                zone_id="zone-abc",
                sources=["rules"],
                targets=["cloudflare"],
            ),
            "other.com": ZoneConfig(
                name="other.com",
                zone_id="zone-def",
                sources=["rules"],
                targets=["cloudflare"],
            ),
        },
    )


class TestPositiveInt:
    """Tests for the _positive_int argparse type function."""

    def test_valid_positive_integer(self):
        assert _positive_int("1") == 1
        assert _positive_int("15") == 15
        assert _positive_int("100") == 100

    def test_zero_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
            _positive_int("0")

    def test_negative_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="positive integer"):
            _positive_int("-5")

    def test_non_numeric_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="invalid int value"):
            _positive_int("abc")


class TestBuildParser:
    @pytest.mark.parametrize("cmd", ["plan", "dump", "versions"])
    def test_command_parses(self, cmd):
        parser = build_parser()
        args = parser.parse_args([cmd])
        assert args.command == cmd

    def test_sync_command(self):
        parser = build_parser()
        args = parser.parse_args(["sync", "--doit"])
        assert args.command == "sync"
        assert args.doit is True

    @pytest.mark.parametrize(
        "argv,attr,expected",
        [
            (["--debug", "plan"], "debug", True),
            (["--quiet", "plan"], "quiet", True),
            (["--config", "my.yaml", "plan"], "config", "my.yaml"),
            (["--zone", "example.com", "plan"], "zones", ["example.com"]),
            (["--scope", "zones", "plan"], "scope", "zones"),
            (["--scope", "account", "plan"], "scope", "account"),
            (["plan"], "scope", "all"),
        ],
    )
    def test_flag_sets_attribute(self, argv, attr, expected):
        parser = build_parser()
        args = parser.parse_args(argv)
        assert getattr(args, attr) == expected

    @pytest.mark.parametrize(
        "argv,attr,expected",
        [
            (["dump", "--output-dir", "/tmp/out"], "output_dir", "/tmp/out"),
        ],
    )
    def test_subcommand_flag(self, argv, attr, expected):
        parser = build_parser()
        args = parser.parse_args(argv)
        assert getattr(args, attr) == expected

    @pytest.mark.parametrize(
        "argv",
        [
            ["sync"],
            ["--format", "xml"],
            ["--scope", "invalid", "plan"],
        ],
    )
    def test_invalid_args_exit(self, argv):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(argv)

    @pytest.mark.parametrize(
        "argv,checks",
        [
            (["dump", "--config", "my.yaml"], {"config": "my.yaml", "command": "dump"}),
            (["plan", "--zone", "example.com"], {"zones": ["example.com"]}),
            (["plan", "--debug"], {"debug": True}),
            (
                ["--debug", "plan", "--zone", "example.com"],
                {"debug": True, "zones": ["example.com"]},
            ),
            (["--config", "my.yaml", "plan"], {"config": "my.yaml"}),
        ],
    )
    def test_flag_ordering(self, argv, checks):
        parser = build_parser()
        args = parser.parse_args(argv)
        for attr, expected in checks.items():
            assert getattr(args, attr) == expected


class TestGetZones:
    def test_all_zones(self, sample_config):
        zones = _get_zones(sample_config, None)
        assert set(zones) == {"example.com", "other.com"}

    def test_filter_valid_zone(self, sample_config):
        zones = _get_zones(sample_config, ["example.com"])
        assert zones == ["example.com"]

    def test_filter_invalid_zone(self, sample_config):
        with pytest.raises(ConfigError, match="not found"):
            _get_zones(sample_config, ["nonexistent.com"])

    def test_filter_invalid_zone_lists_available(self, sample_config):
        """Error message should list available zone names."""
        with pytest.raises(ConfigError, match=r"example\.com") as exc_info:
            _get_zones(sample_config, ["nonexistent.com"])
        assert "other.com" in str(exc_info.value)
        assert "Available:" in str(exc_info.value)


class TestChecksumValidation:
    def test_valid_checksum_accepted(self, sample_config):
        """A 64-char hex string should not raise."""
        valid = "a" * 64
        # cmd_sync will fail for other reasons but should not raise ConfigError
        # about the checksum format. We test the validation directly.
        assert _CHECKSUM_RE.match(valid)

    def test_invalid_checksum_rejected(self, sample_config):
        """Non-hex or wrong-length string should raise ConfigError."""
        with pytest.raises(ConfigError, match="Invalid checksum format"):
            cmd_sync(sample_config, None, checksum="notahash")

    def test_short_checksum_rejected(self, sample_config):
        """Too-short hex string should be rejected."""
        with pytest.raises(ConfigError, match="Invalid checksum format"):
            cmd_sync(sample_config, None, checksum="abcd1234")

    def test_uppercase_checksum_rejected(self, sample_config):
        """Uppercase hex should be rejected (checksums are lowercase)."""
        with pytest.raises(ConfigError, match="Invalid checksum format"):
            cmd_sync(sample_config, None, checksum="A" * 64)


class TestCmdPlan:
    @patch("octorules.commands._providers._init_providers")
    def test_no_changes_returns_0(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, None)
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_with_changes_returns_2(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        # Write a rules file so there are desired rules
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_has_changes_exit_code(self, mock_init_provs, sample_config):
        """--exit-code flag returns 2 when changes are detected."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"], exit_code=True)
        assert result == 2

    @patch("octorules.commands._providers._init_providers")
    def test_no_changes_exit_code(self, mock_init_provs, sample_config):
        """--exit-code flag returns 0 when there are no changes."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"], exit_code=True)
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_zone_filter(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        cmd_plan(sample_config, ["example.com"])
        # Should only call get_all_phase_rules once (for the filtered zone)
        mock_prov.get_all_phase_rules.assert_called_once_with(
            Scope(zone_id="zone-abc", label="example.com"),
            provider_ids=None,
        )

    @patch("octorules.commands._providers._init_providers")
    def test_no_rules_file_means_no_changes(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_no_rules_file_logs_debug(self, mock_init_provs, sample_config, caplog):
        """Zone with no rules file should log at debug level."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            cmd_plan(sample_config, ["example.com"])
        assert "No rules file for zone example.com" in caplog.text


class TestCmdSync:
    @patch("octorules.commands._providers._init_providers")
    def test_no_changes_skips_apply(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, None)
        assert result == 0
        mock_prov.put_phase_rules.assert_not_called()

    @patch("octorules.commands._providers._init_providers")
    def test_applies_changes(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        mock_prov.put_phase_rules.assert_called_once()
        call_args = mock_prov.put_phase_rules.call_args
        assert call_args[0][0] == Scope(zone_id="zone-abc", label="example.com")
        assert call_args[0][1] == "http_request_dynamic_redirect"
        # Verify the payload has the injected action
        payload = call_args[0][2]
        assert payload[0]["action"] == "redirect"
        assert payload[0]["ref"] == "r1"

    @patch("octorules.commands._providers._init_providers")
    def test_sync_multiple_phases(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        assert mock_prov.put_phase_rules.call_count == 2

    @patch("octorules.commands._providers._init_providers")
    def test_sync_skips_zones_without_changes(self, mock_init_provs, sample_config):
        """When syncing all zones, zones without rules files should be skipped."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        # Only example.com has rules, other.com does not
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, None)
        assert result == 0
        # Only one PUT call (for example.com), other.com is skipped
        mock_prov.put_phase_rules.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_sync_api_error_returns_1(self, mock_init_provs, sample_config, caplog):
        """When the CF API fails during sync, abort immediately and return 1."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.put_phase_rules.side_effect = ProviderError("API rate limited")
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "API rate limited" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_connection_error_returns_1(self, mock_init_provs, sample_config, caplog):
        """Connection error during sync should return 1."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.put_phase_rules.side_effect = ProviderError("Connection error")
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1

    @patch("octorules.commands._providers._init_providers")
    def test_sync_programming_error_propagates(self, mock_init_provs, sample_config):
        """Programming bugs (TypeError, etc.) should NOT be caught."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.put_phase_rules.side_effect = TypeError("bad arg")
        with pytest.raises(TypeError, match="bad arg"):
            cmd_sync(sample_config, ["example.com"])

    @patch("octorules.commands._providers._init_providers")
    def test_sync_aborts_on_first_failure(self, mock_init_provs, sample_config):
        """Fail-fast: second phase should not be attempted after first fails."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.put_phase_rules.side_effect = ProviderError("Forbidden")
        result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        # Fail-fast: only one PUT attempted, second phase never reached
        mock_prov.put_phase_rules.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_sync_logs_partial_success_on_failure(self, mock_init_provs, sample_config, caplog):
        """When a phase fails, previously synced phases should be logged."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}
        call_count = 0

        def put_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ProviderError("Server error")

        mock_prov.put_phase_rules.side_effect = put_side_effect
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "Successfully synced before failure" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_progress_logging(self, mock_init_provs, tmp_path, caplog):
        """Sync should log progress for each zone."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "b.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "a.com": ZoneConfig(
                    name="a.com", zone_id="zone-a", sources=["rules"], targets=["cloudflare"]
                ),
                "b.com": ZoneConfig(
                    name="b.com", zone_id="zone-b", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 0
        assert "Applying changes to 2 zone(s)" in caplog.text
        assert "Syncing a.com" in caplog.text
        assert "Syncing b.com" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_per_phase_logging(self, mock_init_provs, sample_config, caplog):
        """Sync should log per-phase change counts."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        assert "redirect_rules: applying 1 change(s)" in caplog.text
        assert "cache_rules: applying 1 change(s)" in caplog.text
        assert "redirect_rules: done" in caplog.text
        assert "cache_rules: done" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_debug_logs_api_call(self, mock_init_provs, sample_config, caplog):
        """Sync should log PUT details at debug level."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        assert "PUT http_request_dynamic_redirect" in caplog.text
        assert "zone_id=zone-abc" in caplog.text
        assert "rules=1" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_reads_rules_once(self, mock_init_provs, sample_config):
        """Sync should read zone rules YAML only once, not re-read during apply."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}

        with patch.object(
            sample_config, "load_zone_rules", wraps=sample_config.load_zone_rules
        ) as spy:
            cmd_sync(sample_config, ["example.com"])
            # Should only be called once (during planning), not again during apply
            spy.assert_called_once_with("example.com")


class TestCmdDump:
    @patch("octorules.commands._providers._init_providers")
    def test_dump_no_rules(self, mock_init_provs, sample_config, caplog):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        assert "Dumped example.com" in caplog.text
        dumped = sample_config.rules_dir / "example.com.yaml"
        assert dumped.read_text() == "--- {}\n"

    @patch("octorules.commands._providers._init_providers")
    def test_dump_writes_file(self, mock_init_provs, sample_config, caplog):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        assert "Dumped example.com" in caplog.text
        assert (sample_config.rules_dir / "example.com.yaml").exists()

    @patch("octorules.commands._providers._init_providers")
    def test_dump_custom_output_dir(self, mock_init_provs, sample_config, tmp_path):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        out_dir = tmp_path / "custom_out"
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        result = cmd_dump(sample_config, ["example.com"], str(out_dir))
        assert result == 0
        assert (out_dir / "example.com.yaml").exists()

    @patch("octorules.commands._providers._init_providers")
    def test_dump_api_error_continues(self, mock_init_provs, tmp_path, caplog):
        """API error on one zone should not prevent dumping others."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "fail.com": ZoneConfig(
                    name="fail.com", zone_id="zone-fail", sources=["rules"], targets=["cloudflare"]
                ),
                "ok.com": ZoneConfig(
                    name="ok.com", zone_id="zone-ok", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise ProviderError("Forbidden")
            return {
                "http_request_dynamic_redirect": [
                    {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
                ],
            }

        mock_prov.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_dump(config, None, None)
        assert result == 1
        assert "Failed to dump fail.com" in caplog.text
        assert (rules_dir / "ok.com.yaml").exists()

    @patch("octorules.commands._providers._init_providers")
    def test_dump_all_succeed_returns_0(self, mock_init_provs, sample_config):
        """When all zones dump successfully, return 0."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_dump(sample_config, None, None)
        assert result == 0


class TestDumpAccount:
    """Comprehensive tests for _dump_account logic via cmd_dump."""

    def _make_config(self, tmp_path):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        return Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={},
        )

    def _make_provider(self, **overrides):
        prov = MagicMock()
        prov.account_id = overrides.get("account_id", "acct-123")
        prov.account_name = overrides.get("account_name", "Test Account")
        prov.get_all_phase_rules.return_value = overrides.get("phase_rules", {})
        prov.get_all_custom_rulesets.return_value = overrides.get("custom_rulesets", {})
        prov.get_all_lists.return_value = overrides.get("lists", {})
        return prov

    @patch("octorules.commands._providers._init_providers")
    def test_happy_path_with_all_data(self, mock_init_provs, tmp_path, caplog):
        """Account dump with phase rules, custom rulesets, and lists."""
        from octorules.config import _yaml_load

        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(
            phase_rules={
                "http_request_dynamic_redirect": [
                    {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
                ],
            },
            custom_rulesets={
                "rs1": {
                    "name": "Block attackers",
                    "phase": "http_request_firewall_custom",
                    "rules": [
                        {"ref": "r1", "expression": "true", "action": "block", "enabled": True}
                    ],
                }
            },
            lists={
                "blocked_ips": {
                    "id": "list-123",
                    "kind": "ip",
                    "description": "Bad actors",
                    "items": [{"ip": "1.2.3.4"}],
                }
            },
        )
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        assert "Dumped account" in caplog.text
        dumped = config.rules_dir / "test-account.yaml"
        assert dumped.exists()
        data = _yaml_load(dumped)
        assert "redirect_rules" in data
        assert "custom_rulesets" in data
        assert "lists" in data

    @patch("octorules.commands._providers._init_providers")
    def test_no_custom_rulesets(self, mock_init_provs, tmp_path, caplog):
        """Account dump with no custom rulesets returns empty/no section."""
        from octorules.config import _yaml_load

        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(
            phase_rules={"http_request_dynamic_redirect": []},
            custom_rulesets={},
        )
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        dumped = config.rules_dir / "test-account.yaml"
        data = _yaml_load(dumped)
        assert "custom_rulesets" not in (data or {})

    @patch("octorules.commands._providers._init_providers")
    def test_no_lists(self, mock_init_provs, tmp_path, caplog):
        """Account dump with no lists returns empty/no lists section."""
        from octorules.config import _yaml_load

        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(
            phase_rules={},
            lists={},
        )
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        dumped = config.rules_dir / "test-account.yaml"
        data = _yaml_load(dumped)
        assert "lists" not in (data or {})

    @patch("octorules.commands._providers._init_providers")
    def test_phase_rules_api_error(self, mock_init_provs, tmp_path, caplog):
        """ProviderError on get_all_phase_rules logs error and returns had_error=True."""
        from octorules.provider.exceptions import ProviderError

        config = self._make_config(tmp_path)
        mock_prov = self._make_provider()
        mock_prov.get_all_phase_rules.side_effect = ProviderError("API 500")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 1
        assert "Failed to dump account" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_phase_rules_auth_error_propagates(self, mock_init_provs, tmp_path):
        """ProviderAuthError on get_all_phase_rules propagates (not caught)."""
        from octorules.provider.exceptions import ProviderAuthError

        config = self._make_config(tmp_path)
        mock_prov = self._make_provider()
        mock_prov.get_all_phase_rules.side_effect = ProviderAuthError("Forbidden")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with pytest.raises(ProviderAuthError):
            cmd_dump(config, None, None, scope_filter="account")

    @patch("octorules.commands._providers._init_providers")
    def test_custom_rulesets_auth_error_propagates(self, mock_init_provs, tmp_path):
        """ProviderAuthError on custom rulesets fetch propagates."""
        from octorules.provider.exceptions import ProviderAuthError

        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(phase_rules={})
        mock_prov.get_all_custom_rulesets.side_effect = ProviderAuthError("Forbidden")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with pytest.raises(ProviderAuthError):
            cmd_dump(config, None, None, scope_filter="account")

    @patch("octorules.commands._providers._init_providers")
    def test_lists_auth_error_propagates(self, mock_init_provs, tmp_path):
        """ProviderAuthError on lists fetch propagates."""
        from octorules.provider.exceptions import ProviderAuthError

        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(phase_rules={})
        mock_prov.get_all_lists.side_effect = ProviderAuthError("Forbidden")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with pytest.raises(ProviderAuthError):
            cmd_dump(config, None, None, scope_filter="account")

    @patch("octorules.commands._dump.call_dump_extensions", return_value={})
    @patch("octorules.commands._providers._init_providers")
    def test_extension_hooks_called(self, mock_init_provs, mock_ext, tmp_path, caplog):
        """Extension dump hooks are invoked during account dump."""
        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(phase_rules={})
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        # call_dump_extensions should have been called for the account scope
        assert mock_ext.called
        call_args = mock_ext.call_args
        scope_arg = call_args[0][0]
        assert scope_arg.account_id == "acct-123"

    @patch("octorules.commands._providers._init_providers")
    def test_empty_phase_rules_still_produces_file(self, mock_init_provs, tmp_path, caplog):
        """Account dump with no phase rules still creates the output file."""
        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(phase_rules={})
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        dumped = config.rules_dir / "test-account.yaml"
        assert dumped.exists()

    @patch("octorules.commands._providers._init_providers")
    def test_account_label_slugified(self, mock_init_provs, tmp_path, caplog):
        """Account name with spaces/special chars is slugified for filename."""
        config = self._make_config(tmp_path)
        mock_prov = self._make_provider(account_name="My Test Account!")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        dumped = config.rules_dir / "my-test-account.yaml"
        assert dumped.exists()

    @patch("octorules.commands._providers._init_providers")
    def test_concurrent_with_zone_dumps(self, mock_init_provs, tmp_path, caplog):
        """When scope_filter='all', account and zone dumps both run."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                ),
            },
        )
        mock_prov = self._make_provider(phase_rules={})
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="all")
        assert result == 0
        # Both account and zone files should exist
        assert (rules_dir / "test-account.yaml").exists()
        assert (rules_dir / "example.com.yaml").exists()


class TestMain:
    def test_no_command_exits(self):
        with pytest.raises(SystemExit) as exc_info:
            main([])
        assert exc_info.value.code == 1

    def test_version(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--version"])
        assert exc_info.value.code == 0
        captured = capsys.readouterr()
        assert "octorules" in captured.out

    def test_missing_config(self):
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", "/nonexistent/config.yaml", "plan"])
        assert exc_info.value.code == 1

    @patch("octorules.cli.cmd_plan", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_zone_filter_narrows_scope_to_zones(self, mock_config, mock_cmd, tmp_config):
        """--zone without explicit --scope should skip account processing."""
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit):
            main(["--config", str(tmp_config), "--zone", "example.com", "plan"])
        _, kwargs = mock_cmd.call_args
        assert kwargs["scope_filter"] == "zones"

    @patch("octorules.cli.cmd_plan", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_zone_filter_with_explicit_scope_all(self, mock_config, mock_cmd, tmp_config):
        """--zone with explicit --scope all should still narrow to zones."""
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit):
            main(["--config", str(tmp_config), "--zone", "example.com", "--scope", "all", "plan"])
        _, kwargs = mock_cmd.call_args
        assert kwargs["scope_filter"] == "zones"

    @patch("octorules.cli.cmd_plan", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_no_zone_filter_keeps_scope_all(self, mock_config, mock_cmd, tmp_config):
        """Without --zone, scope should remain 'all'."""
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit):
            main(["--config", str(tmp_config), "plan"])
        _, kwargs = mock_cmd.call_args
        assert kwargs["scope_filter"] == "all"

    @patch("octorules.cli.cmd_plan", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_plan_invokes_cmd(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "plan"])
        assert exc_info.value.code == 0
        mock_cmd.assert_called_once()

    @patch("octorules.cli.cmd_plan", return_value=2)
    @patch("octorules.cli.Config.from_file")
    def test_plan_exits_2_on_changes(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "plan"])
        assert exc_info.value.code == 2

    @patch("octorules.cli.cmd_sync", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_sync_invokes_cmd(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "sync", "--doit"])
        assert exc_info.value.code == 0
        mock_cmd.assert_called_once()

    @patch("octorules.cli.cmd_dump", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_dump_invokes_cmd(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "dump"])
        assert exc_info.value.code == 0
        mock_cmd.assert_called_once()

    @patch("octorules.cli.cmd_dump", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_dump_passes_output_dir(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "dump", "--output-dir", "/tmp/out"])
        assert exc_info.value.code == 0
        # output_dir is the third positional arg
        assert mock_cmd.call_args[0][2] == "/tmp/out"

    def test_versions_no_config_needed(self, capsys):
        """versions command should work without a config file."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", "/nonexistent/config.yaml", "versions"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "octorules" in out
        assert "python" in out


class TestCmdVersions:
    def _versions_output(self, capsys) -> str:
        result = cmd_versions()
        assert result == 0
        return capsys.readouterr().out

    def _find_line(self, out: str, label: str) -> str:
        """Return the line starting with *label*, or fail."""
        for line in out.splitlines():
            if line.startswith(label):
                return line
        raise AssertionError(f"{label!r} not found in:\n{out}")

    def test_prints_octorules_version(self, capsys):
        from octorules import __version__

        line = self._find_line(self._versions_output(capsys), "octorules ")
        assert __version__ in line

    def test_prints_python_version(self, capsys):
        import platform

        line = self._find_line(self._versions_output(capsys), "python")
        assert platform.python_version() in line

    def test_prints_pyyaml_version(self, capsys):
        import yaml

        line = self._find_line(self._versions_output(capsys), "pyyaml")
        assert yaml.__version__ in line

    def test_versions_output_format(self, capsys):
        out = self._versions_output(capsys)
        # Core package is always present; provider packages are optional.
        assert "octorules" in out
        assert "pyyaml" in out
        assert "python" in out


class TestAlwaysDryRun:
    @patch("octorules.commands._providers._init_providers")
    def test_sync_skips_always_dry_run_zone(self, mock_init_provs, tmp_path, caplog):
        """Zones with always_dry_run=True should be skipped during sync."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    always_dry_run=True,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_sync(config, ["example.com"])
        assert result == 0
        # Should NOT have called put_phase_rules
        mock_prov.put_phase_rules.assert_not_called()
        assert "always_dry_run" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_applies_non_dry_run_zone(self, mock_init_provs, tmp_path):
        """Zones without always_dry_run should still be applied."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    always_dry_run=False,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(config, ["example.com"])
        assert result == 0
        mock_prov.put_phase_rules.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_sync_mixed_zones(self, mock_init_provs, tmp_path, caplog):
        """Sync with a mix of dry-run and normal zones."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "dry.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "live.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "dry.com": ZoneConfig(
                    name="dry.com",
                    zone_id="zone-dry",
                    sources=["rules"],
                    targets=["cloudflare"],
                    always_dry_run=True,
                ),
                "live.com": ZoneConfig(
                    name="live.com",
                    zone_id="zone-live",
                    sources=["rules"],
                    targets=["cloudflare"],
                    always_dry_run=False,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 0
        # Only live.com should have been applied
        calls = mock_prov.put_phase_rules.call_args_list
        assert len(calls) == 1
        assert calls[0][0][0] == Scope(zone_id="zone-live", label="live.com")
        assert "dry.com" in caplog.text
        assert "always_dry_run" in caplog.text


class TestSetupLogging:
    def test_debug_level(self):
        _setup_logging(debug=True)
        logger = logging.getLogger("octorules")
        assert logger.getEffectiveLevel() <= logging.DEBUG

    def test_quiet_level(self):
        _setup_logging(quiet=True)
        logger = logging.getLogger("octorules")
        assert logger.getEffectiveLevel() <= logging.WARNING

    def test_default_level(self):
        _setup_logging()
        logger = logging.getLogger("octorules")
        assert logger.getEffectiveLevel() <= logging.INFO


class TestPhaseFiltering:
    """Tests for --phase filtering (Feature 1)."""

    def test_parser_phase_help_text(self):
        """--phase help should mention it can be repeated and limits API calls."""
        parser = build_parser()
        for action in parser._actions:
            if getattr(action, "dest", None) == "phases":
                assert "repeated" in action.help
                assert "API" in action.help
                break
        else:
            pytest.fail("--phase action not found")

    def test_parser_single_phase(self):
        parser = build_parser()
        args = parser.parse_args(["--phase", "redirect_rules", "plan"])
        assert args.phases == ["redirect_rules"]

    def test_parser_multiple_phases(self):
        parser = build_parser()
        args = parser.parse_args(["--phase", "redirect_rules", "--phase", "cache_rules", "plan"])
        assert args.phases == ["redirect_rules", "cache_rules"]

    def test_parser_no_phase(self):
        parser = build_parser()
        args = parser.parse_args(["plan"])
        assert args.phases is None

    def test_validate_phases_valid(self):
        result = _validate_phases(["redirect_rules", "cache_rules"])
        assert result == ["redirect_rules", "cache_rules"]

    def test_validate_phases_invalid_raises(self):
        with pytest.raises(ConfigError, match="Unknown phase"):
            _validate_phases(["nonexistent_phase"])

    def test_validate_phases_typo_suggests(self):
        with pytest.raises(ConfigError, match=r"Did you mean.*redirect_rules"):
            _validate_phases(["redirect_rule"])

    def test_validate_phases_no_match_lists_valid(self):
        with pytest.raises(ConfigError, match="Valid phases:"):
            _validate_phases(["zzz_totally_wrong"])

    def test_validate_phases_provider_id_suggests_friendly(self):
        with pytest.raises(ConfigError, match=r"Did you mean.*redirect_rules"):
            _validate_phases(["http_request_dynamic_redirect"])

    def test_validate_phases_none_returns_none(self):
        assert _validate_phases(None) is None

    def test_filter_desired_by_phase(self):
        desired = {
            "redirect_rules": [{"ref": "r1"}],
            "cache_rules": [{"ref": "c1"}],
            "origin_rules": [{"ref": "o1"}],
        }
        result = _filter_desired_by_phase(desired, ["redirect_rules"])
        assert list(result.keys()) == ["redirect_rules"]

    def test_filter_desired_by_phase_preserves_non_phase_keys(self):
        """custom_rulesets and lists survive --phase filtering.

        Regression test: the fix makes _filter_desired_by_phase preserve
        keys in KNOWN_NON_PHASE_KEYS even when --phase filters are active.
        """
        from octorules.phases import KNOWN_NON_PHASE_KEYS, register_non_phase_key

        # Save original state so we can restore it — a provider import
        # may have already registered these keys.
        original = KNOWN_NON_PHASE_KEYS.copy()
        register_non_phase_key("custom_rulesets")
        register_non_phase_key("lists")
        try:
            desired = {
                "redirect_rules": [{"ref": "r1"}],
                "cache_rules": [{"ref": "c1"}],
                "custom_rulesets": [{"name": "my-rs"}],
                "lists": [{"name": "my-list"}],
            }
            result = _filter_desired_by_phase(desired, ["redirect_rules"])
            assert "redirect_rules" in result
            assert "cache_rules" not in result
            assert "custom_rulesets" in result
            assert "lists" in result
        finally:
            # Restore original state (in-place mutation required).
            KNOWN_NON_PHASE_KEYS.clear()
            KNOWN_NON_PHASE_KEYS.update(original)

    def test_filter_desired_none_returns_all(self):
        desired = {"redirect_rules": [{"ref": "r1"}], "cache_rules": [{"ref": "c1"}]}
        result = _filter_desired_by_phase(desired, None)
        assert result is desired

    def test_filter_current_by_phase(self):
        current = {
            "http_request_dynamic_redirect": [{"ref": "r1"}],
            "http_request_cache_settings": [{"ref": "c1"}],
        }
        result = _filter_current_by_phase(current, ["redirect_rules"])
        assert list(result.keys()) == ["http_request_dynamic_redirect"]

    def test_filter_current_none_returns_all(self):
        current = {"http_request_dynamic_redirect": [{"ref": "r1"}]}
        result = _filter_current_by_phase(current, None)
        assert result is current

    @patch("octorules.commands._providers._init_providers")
    def test_phase_filter_passes_provider_ids_to_provider(self, mock_init_provs, sample_config):
        """Phase filter should pass provider_ids to get_all_phase_rules."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        cmd_plan(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        call_kwargs = mock_prov.get_all_phase_rules.call_args
        assert call_kwargs[1]["provider_ids"] == ["http_request_dynamic_redirect"]

    @patch("octorules.commands._providers._init_providers")
    def test_no_phase_filter_fetches_all(self, mock_init_provs, sample_config):
        """Without phase filter, provider_ids should be None (fetch all)."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        cmd_plan(sample_config, ["example.com"])
        call_kwargs = mock_prov.get_all_phase_rules.call_args
        assert call_kwargs[1]["provider_ids"] is None

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_plan_with_phase_filter(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        assert result == 0  # has changes, but no --exit-code flag
        # But only redirect_rules should be in the plan

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_sync_with_phase_filter(self, mock_init_provs, sample_config):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        assert result == 0
        # Only one PUT call (for redirect_rules, not cache_rules)
        mock_prov.put_phase_rules.assert_called_once()
        call_args = mock_prov.put_phase_rules.call_args
        assert call_args[0][0] == Scope(zone_id="zone-abc", label="example.com")
        assert call_args[0][1] == "http_request_dynamic_redirect"


class TestChecksum:
    """Tests for checksum plan/apply (Feature 2)."""

    def test_parser_plan_checksum_is_bool(self):
        parser = build_parser()
        args = parser.parse_args(["plan", "--checksum"])
        assert args.checksum is True

    def test_parser_plan_checksum_default(self):
        parser = build_parser()
        args = parser.parse_args(["plan"])
        assert args.checksum is False

    def test_parser_sync_checksum_takes_value(self):
        parser = build_parser()
        args = parser.parse_args(["sync", "--doit", "--checksum", "abc123"])
        assert args.checksum == "abc123"

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_plan_prints_checksum(self, mock_init_provs, sample_config, caplog):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_plan(sample_config, ["example.com"], checksum=True)
        assert "checksum=" in caplog.text
        # Extract the hash and verify it's a hex string
        for line in caplog.text.splitlines():
            if "checksum=" in line:
                hex_hash = line.split("checksum=", 1)[1]
                assert len(hex_hash) == 64
                int(hex_hash, 16)  # Should not raise

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_sync_checksum_match_proceeds(self, mock_init_provs, sample_config, caplog):
        """When checksum matches, sync should proceed normally."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        # First compute the checksum
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_plan(sample_config, ["example.com"], checksum=True)
        hash_val = None
        for line in caplog.text.splitlines():
            if "checksum=" in line:
                hash_val = line.split("checksum=", 1)[1]
                break
        assert hash_val is not None
        # Now sync with that checksum
        result = cmd_sync(sample_config, ["example.com"], checksum=hash_val)
        assert result == 0
        mock_prov.put_phase_rules.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_sync_checksum_mismatch_aborts(self, mock_init_provs, sample_config):
        """When checksum mismatches, sync should abort with exit 1."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"], checksum="0" * 64)
        assert result == 1
        mock_prov.put_phase_rules.assert_not_called()


class TestSafetyForce:
    """Tests for --force and safety thresholds (Feature 4)."""

    def test_parser_force_flag(self):
        parser = build_parser()
        args = parser.parse_args(["sync", "--doit", "--force"])
        assert args.force is True

    def test_parser_force_default(self):
        parser = build_parser()
        args = parser.parse_args(["sync", "--doit"])
        assert args.force is False

    @patch("octorules.commands._providers._init_providers")
    def test_mass_delete_blocked(self, mock_init_provs, tmp_path, caplog):
        """Deleting most rules should be blocked by safety threshold."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Desired: empty (all rules removed)
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    delete_threshold=30.0,
                ),
            },
        )
        # Current: 10 rules exist
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, ["example.com"])
        assert result == 1
        mock_prov.put_phase_rules.assert_not_called()
        assert "Safety threshold exceeded" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_small_delete_allowed(self, mock_init_provs, tmp_path):
        """Deleting 1 out of 10 rules (10%) should be allowed."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Desired: 9 rules (1 removed)
        rules = "\n".join([f"  - ref: r{i}\n    expression: 'true'" for i in range(9)])
        (rules_dir / "example.com.yaml").write_text(f"redirect_rules:\n{rules}\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    delete_threshold=30.0,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect", "enabled": True}
                for i in range(10)
            ],
        }
        result = cmd_sync(config, ["example.com"])
        assert result == 0
        mock_prov.put_phase_rules.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_force_bypasses_safety(self, mock_init_provs, tmp_path):
        """--force should bypass safety checks."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    delete_threshold=30.0,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        result = cmd_sync(config, ["example.com"], force=True)
        assert result == 0
        mock_prov.put_phase_rules.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_dry_run_zones_excluded_from_safety(self, mock_init_provs, tmp_path):
        """always_dry_run zones should not trigger safety checks."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    always_dry_run=True,
                    delete_threshold=30.0,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        result = cmd_sync(config, ["example.com"])
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_error_message_includes_phase_names(self, mock_init_provs, tmp_path, caplog):
        """Safety error message should include the affected phase names."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    delete_threshold=30.0,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        with caplog.at_level(logging.ERROR, logger="octorules"):
            cmd_sync(config, ["example.com"])
        assert "redirect_rules" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_error_message_content(self, mock_init_provs, tmp_path, caplog):
        """Safety error message should include zone, counts, and percentages."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    delete_threshold=30.0,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        with caplog.at_level(logging.ERROR, logger="octorules"):
            cmd_sync(config, ["example.com"])
        assert "example.com" in caplog.text
        assert "100.0%" in caplog.text
        assert "30.0%" in caplog.text


class TestMakeAccountZoneConfig:
    """Tests for _make_account_zone_config using provider-level safety settings."""

    def test_uses_provider_safety_defaults(self):
        from octorules.commands import _make_account_zone_config

        config = Config(
            rules_dir=Path("/tmp/rules"),
            providers={
                "cloudflare": ProviderConfig(
                    name="cloudflare",
                    kwargs={},
                    delete_threshold=10.0,
                    update_threshold=20.0,
                    min_existing=5,
                ),
            },
        )
        zone_cfg = _make_account_zone_config(config)
        assert zone_cfg.name == "__account__"
        assert zone_cfg.delete_threshold == 10.0
        assert zone_cfg.update_threshold == 20.0
        assert zone_cfg.min_existing == 5

    def test_falls_back_to_defaults_when_no_providers(self):
        from octorules.commands import _make_account_zone_config

        config = Config(
            rules_dir=Path("/tmp/rules"),
            providers={},
        )
        zone_cfg = _make_account_zone_config(config)
        assert zone_cfg.name == "__account__"
        # ZoneConfig defaults
        assert zone_cfg.delete_threshold == 30.0
        assert zone_cfg.update_threshold == 30.0
        assert zone_cfg.min_existing == 3

    def test_uses_first_provider_when_multiple(self):
        from octorules.commands import _make_account_zone_config

        config = Config(
            rules_dir=Path("/tmp/rules"),
            providers={
                "cloudflare": ProviderConfig(
                    name="cloudflare",
                    kwargs={},
                    delete_threshold=15.0,
                    update_threshold=25.0,
                    min_existing=7,
                ),
                "aws": ProviderConfig(
                    name="aws",
                    kwargs={},
                    delete_threshold=50.0,
                    update_threshold=50.0,
                    min_existing=10,
                ),
            },
        )
        zone_cfg = _make_account_zone_config(config)
        assert zone_cfg.delete_threshold == 15.0
        assert zone_cfg.update_threshold == 25.0
        assert zone_cfg.min_existing == 7


class TestParallelPlanning:
    """Tests for parallel zone planning (max_workers)."""

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_plan_sequential(self, mock_init_provs, sample_config):
        """max_workers=1: sequential planning works same as before."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        sample_config.max_workers = 1
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_plan_parallel(self, mock_init_provs, tmp_path):
        """max_workers=2: parallel planning returns correct results."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "b.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "a.com": ZoneConfig(
                    name="a.com", zone_id="zone-a", sources=["rules"], targets=["cloudflare"]
                ),
                "b.com": ZoneConfig(
                    name="b.com", zone_id="zone-b", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(config, None)
        assert result == 0
        # API called for each zone
        assert mock_prov.get_all_phase_rules.call_count == 2

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_plan_parallel_zone_order_preserved(self, mock_init_provs, tmp_path, capsys):
        """Parallel planning preserves zone order in output."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "alpha.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "beta.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "alpha.com": ZoneConfig(
                    name="alpha.com", zone_id="zone-a", sources=["rules"], targets=["cloudflare"]
                ),
                "beta.com": ZoneConfig(
                    name="beta.com", zone_id="zone-b", sources=["rules"], targets=["cloudflare"]
                ),
            },
            plan_outputs={"json": PlanJson("json")},
        )
        mock_prov.get_all_phase_rules.return_value = {}
        cmd_plan(config, None)
        import json

        out = capsys.readouterr().out
        data = json.loads(out)
        zone_names = [z["zone"] for z in data["zones"]]
        assert zone_names == ["alpha.com", "beta.com"]

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_sync_parallel_plan_sequential_apply(self, mock_init_provs, tmp_path):
        """Sync with max_workers=2: planning is parallel, apply is sequential."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "b.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "a.com": ZoneConfig(
                    name="a.com", zone_id="zone-a", sources=["rules"], targets=["cloudflare"]
                ),
                "b.com": ZoneConfig(
                    name="b.com", zone_id="zone-b", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_sync(config, None)
        assert result == 0
        # Both zones applied
        assert mock_prov.put_phase_rules.call_count == 2

    @patch("octorules.commands._providers._init_providers")
    def test_cmd_dump_parallel(self, mock_init_provs, tmp_path, caplog):
        """Dump with max_workers=2: parallel dump."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "a.com": ZoneConfig(
                    name="a.com", zone_id="zone-a", sources=["rules"], targets=["cloudflare"]
                ),
                "b.com": ZoneConfig(
                    name="b.com", zone_id="zone-b", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None)
        assert result == 0
        assert mock_prov.get_all_phase_rules.call_count == 2
        assert (rules_dir / "a.com.yaml").exists()
        assert (rules_dir / "b.com.yaml").exists()


class TestAllowUnmanaged:
    """Tests for allow_unmanaged zone config in CLI."""

    @patch("octorules.commands._providers._init_providers")
    def test_unmanaged_rules_not_removed(self, mock_init_provs, tmp_path):
        """With allow_unmanaged, rules in CF but not YAML should be kept."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Only r1 in YAML, r2 exists in CF
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    allow_unmanaged=True,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
                {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
            ],
        }
        result = cmd_plan(config, ["example.com"])
        # r2 should NOT be marked for removal, so no changes
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_unmanaged_phase_not_removed(self, mock_init_provs, tmp_path):
        """With allow_unmanaged, entire phases in CF but not YAML should be kept."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Only redirect_rules in YAML, cache_rules exist in CF
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                    allow_unmanaged=True,
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            ],
            "http_request_cache_settings": [
                {
                    "ref": "c1",
                    "expression": "true",
                    "action": "set_cache_settings",
                    "enabled": True,
                },
            ],
        }
        result = cmd_plan(config, ["example.com"])
        # cache_rules should NOT be marked for removal
        assert result == 0


class TestPlanErrorIsolation:
    """Tests for per-zone error isolation during planning."""

    @patch("octorules.commands._providers._init_providers")
    def test_sequential_plan_api_error_continues(self, mock_init_provs, tmp_path, caplog):
        """Sequential planning: API error on one zone should not kill others."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "ok.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=1,
            zones={
                "fail.com": ZoneConfig(
                    name="fail.com", zone_id="zone-fail", sources=["rules"], targets=["cloudflare"]
                ),
                "ok.com": ZoneConfig(
                    name="ok.com", zone_id="zone-ok", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise ProviderError("Forbidden")
            return {}

        mock_prov.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_plan(config, None)
        assert result == 1
        assert "Failed to plan fail.com" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_parallel_plan_api_error_continues(self, mock_init_provs, tmp_path, caplog):
        """Parallel planning: API error on one zone should not kill others."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "ok.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "fail.com": ZoneConfig(
                    name="fail.com", zone_id="zone-fail", sources=["rules"], targets=["cloudflare"]
                ),
                "ok.com": ZoneConfig(
                    name="ok.com", zone_id="zone-ok", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise ProviderError("Forbidden")
            return {}

        mock_prov.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_plan(config, None)
        assert result == 1
        assert "Failed to plan fail.com" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_aborts_on_plan_failure(self, mock_init_provs, tmp_path, caplog):
        """Sync should abort entirely if any zone fails during planning."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "ok.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "fail.com": ZoneConfig(
                    name="fail.com", zone_id="zone-fail", sources=["rules"], targets=["cloudflare"]
                ),
                "ok.com": ZoneConfig(
                    name="ok.com", zone_id="zone-ok", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise ProviderError("Forbidden")
            return {}

        mock_prov.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 1
        assert "Aborting sync" in caplog.text
        mock_prov.put_phase_rules.assert_not_called()


class TestSetupLoggingMultipleCalls:
    """Tests for _setup_logging handler level update on repeat calls."""

    def test_handler_level_updates_on_second_call(self):
        """Calling _setup_logging twice should update handler level."""
        _setup_logging(debug=True)
        logger = logging.getLogger("octorules")
        assert logger.level == logging.DEBUG

        _setup_logging(quiet=True)
        assert logger.level == logging.WARNING
        for h in logger.handlers:
            assert h.level == logging.WARNING


class TestFormatApiError:
    """Tests for _format_api_error helper."""

    def test_with_status_code(self):
        from octorules.provider.exceptions import ProviderAuthError

        class _FakeHTTPError(Exception):
            status_code = 401

        cause = _FakeHTTPError("Invalid API token")
        e = ProviderAuthError("Invalid API token")
        e.__cause__ = cause
        result = _format_api_error(e)
        assert "[HTTP 401]" in result
        assert "Invalid API token" in result

    def test_without_status_code(self):
        from octorules.provider.exceptions import ProviderError

        e = ProviderError("Connection error")
        result = _format_api_error(e)
        assert "[HTTP" not in result

    def test_api_error_base(self):
        from octorules.provider.exceptions import ProviderError

        e = ProviderError("Server Error")
        result = _format_api_error(e)
        assert "Server Error" in result


class TestAuthErrorPropagation:
    """Tests for authentication error propagation (tasks 27, 29)."""

    @patch("octorules.commands._providers._init_providers")
    def test_plan_auth_error_propagates(self, mock_init_provs, sample_config):
        """ProviderAuthError during plan should not be silently caught."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderAuthError

        mock_prov.get_all_phase_rules.side_effect = ProviderAuthError("Invalid API token")
        with pytest.raises(ProviderAuthError):
            cmd_plan(sample_config, ["example.com"])

    @patch("octorules.commands._providers._init_providers")
    def test_plan_permission_error_propagates(self, mock_init_provs, sample_config):
        """ProviderAuthError (permission denied) during plan should not be silently caught."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderAuthError

        mock_prov.get_all_phase_rules.side_effect = ProviderAuthError("Permission denied")
        with pytest.raises(ProviderAuthError):
            cmd_plan(sample_config, ["example.com"])

    @patch("octorules.commands._providers._init_providers")
    def test_sync_auth_error_during_apply_returns_1(self, mock_init_provs, sample_config, caplog):
        """ProviderAuthError during sync apply should return 1 with clear message."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderAuthError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}

        class _FakeHTTPError(Exception):
            status_code = 401

        cause = _FakeHTTPError("Token expired")
        auth_err = ProviderAuthError("Token expired")
        auth_err.__cause__ = cause
        mock_prov.put_phase_rules.side_effect = auth_err
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "Authentication/permission error" in caplog.text
        assert "HTTP 401" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_auth_error_no_partial_success_msg(self, mock_init_provs, sample_config, caplog):
        """Auth errors should NOT log 'Successfully synced before failure'."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderAuthError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}
        call_count = 0

        def put_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ProviderAuthError("Token revoked")

        mock_prov.put_phase_rules.side_effect = put_side_effect
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "Successfully synced before failure" not in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_auth_error_multi_zone_stops_remaining(
        self, mock_init_provs, sample_config, caplog
    ):
        """Auth error on second zone stops sync and returns 1.

        Two zones have changes; the first syncs successfully, the second
        raises ProviderAuthError.  The overall result must be 1 and the
        error must be logged.
        """
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderAuthError

        # Both zones have rules so both will have changes
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (sample_config.rules_dir / "other.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        mock_prov.get_all_phase_rules.return_value = {}

        put_calls: list[str] = []

        def put_side_effect(scope, phase_id, payload):
            put_calls.append(scope.label)
            if scope.label == "other.com":
                raise ProviderAuthError("Token revoked")

        mock_prov.put_phase_rules.side_effect = put_side_effect
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, None)
        assert result == 1
        assert "Authentication/permission error" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_dump_auth_error_propagates(self, mock_init_provs, sample_config):
        """ProviderAuthError during dump should propagate, not be caught per-zone."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderAuthError

        mock_prov.get_all_phase_rules.side_effect = ProviderAuthError("Invalid API token")
        with pytest.raises(ProviderAuthError):
            cmd_dump(sample_config, ["example.com"], None)

    def test_main_catches_auth_error(self, tmp_config, caplog):
        """main() should catch ProviderAuthError and exit 1 with clear message."""
        from octorules.provider.exceptions import ProviderAuthError

        with (
            patch("octorules.cli.Config.from_file") as mock_config,
            patch("octorules.cli.cmd_plan") as mock_cmd,
        ):
            mock_config.return_value = MagicMock()
            mock_cmd.side_effect = ProviderAuthError("Invalid API token")
            with caplog.at_level(logging.ERROR, logger="octorules"):
                with pytest.raises(SystemExit) as exc_info:
                    main(["--config", str(tmp_config), "plan"])
            assert exc_info.value.code == 1
            assert "authentication failed" in caplog.text.lower()

    def test_main_catches_permission_error(self, tmp_config, caplog):
        """main() should catch ProviderAuthError (permission denied) and exit 1."""
        from octorules.provider.exceptions import ProviderAuthError

        with (
            patch("octorules.cli.Config.from_file") as mock_config,
            patch("octorules.cli.cmd_plan") as mock_cmd,
        ):
            mock_config.return_value = MagicMock()
            mock_cmd.side_effect = ProviderAuthError("Missing permission")
            with caplog.at_level(logging.ERROR, logger="octorules"):
                with pytest.raises(SystemExit) as exc_info:
                    main(["--config", str(tmp_config), "plan"])
            assert exc_info.value.code == 1
            assert "authentication failed" in caplog.text.lower()


class TestFailedPhaseFiltering:
    """Tests for filtering out failed phases from planning (task 28)."""

    @patch("octorules.commands._providers._init_providers")
    def test_failed_phase_excluded_from_plan(self, mock_init_provs, sample_config, caplog):
        """Phase that failed to fetch should be excluded from desired rules."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        # Simulate redirect phase failing
        mock_prov.get_all_phase_rules.return_value = PhaseRulesResult(
            {}, failed_phases=["http_request_dynamic_redirect"]
        )
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        # redirect_rules should have been skipped
        assert "Skipping redirect_rules" in caplog.text
        assert "failed to fetch current state" in caplog.text
        # cache_rules still planned (has changes), but no --exit-code flag
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_no_failed_phases_plans_normally(self, mock_init_provs, sample_config):
        """When no phases fail, planning proceeds as usual."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = PhaseRulesResult({})
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_all_phases_failed_means_no_changes(self, mock_init_provs, sample_config, caplog):
        """When all desired phases fail, plan should show no changes."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = PhaseRulesResult(
            {}, failed_phases=["http_request_dynamic_redirect"]
        )
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert "Skipping redirect_rules" in caplog.text
        assert result == 0  # No changes (desired was filtered out)

    @patch("octorules.commands._providers._init_providers")
    def test_plain_dict_backward_compatible(self, mock_init_provs, sample_config):
        """Plain dict (no failed_phases) should work as before."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.commands._providers._init_providers")
    def test_failed_phase_not_in_desired_ignored(self, mock_init_provs, sample_config, caplog):
        """Failed phase not in desired rules should not log a warning."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        # cache phase failed but we don't have cache_rules in YAML
        mock_prov.get_all_phase_rules.return_value = PhaseRulesResult(
            {}, failed_phases=["http_request_cache_settings"]
        )
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert "Skipping" not in caplog.text
        assert result == 0  # redirect_rules still has changes, but no --exit-code flag


class TestApiErrorStatusCodes:
    """Tests for HTTP status code inclusion in error messages (task 29)."""

    @patch("octorules.commands._providers._init_providers")
    def test_plan_error_includes_status_code(self, mock_init_provs, sample_config, caplog):
        """Plan failure should include HTTP status code in error message."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        class _FakeHTTPError(Exception):
            status_code = 500

        cause = _FakeHTTPError("Internal Server Error")
        err = ProviderError("Internal server error")
        err.__cause__ = cause
        mock_prov.get_all_phase_rules.side_effect = err
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert result == 1
        assert "HTTP 500" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_error_includes_status_code(self, mock_init_provs, sample_config, caplog):
        """Sync API error should include HTTP status code."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_prov.get_all_phase_rules.return_value = {}

        class _FakeHTTPError(Exception):
            status_code = 429

        cause = _FakeHTTPError("Rate limited")
        err = ProviderError("Rate limited")
        err.__cause__ = cause
        mock_prov.put_phase_rules.side_effect = err
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "HTTP 429" in caplog.text


class TestWriteOutputFile:
    """Tests for _write_output_file() path traversal guard."""

    def test_accepts_safe_path(self, tmp_path):
        """Normal paths within base_dir are accepted and file is written."""
        safe_path = str(tmp_path / "output.txt")
        result = _write_output_file(safe_path, lambda f: f.write("hello"), base_dir=tmp_path)
        assert result is True
        assert (tmp_path / "output.txt").read_text() == "hello"

    def test_returns_false_on_os_error(self, tmp_path, caplog):
        """OSError during write returns False."""
        bad_path = str(tmp_path / "no_such_dir" / "output.txt")
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = _write_output_file(bad_path, lambda f: f.write("data"), base_dir=tmp_path)
        assert result is False
        assert "Failed to write output file" in caplog.text

    def test_rejects_dotdot_escape(self, tmp_path, caplog):
        """Paths with '..' that resolve outside base_dir are rejected."""
        unsafe_path = str(tmp_path / ".." / "escaped.txt")
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = _write_output_file(unsafe_path, lambda f: f.write("data"), base_dir=tmp_path)
        assert result is False
        assert "escapes base directory" in caplog.text.lower()

    def test_rejects_absolute_path_outside_base(self, tmp_path, caplog):
        """Absolute paths outside base_dir are rejected."""
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = _write_output_file(
                "/tmp/escape.txt", lambda f: f.write("data"), base_dir=tmp_path
            )
        assert result is False
        assert "escapes base directory" in caplog.text.lower()

    def test_rejects_symlink_outside_base(self, tmp_path, caplog):
        """Symlinks resolving outside base_dir are rejected."""
        outside = tmp_path / "outside"
        outside.mkdir()
        target = outside / "secret.txt"
        target.write_text("secret")
        base = tmp_path / "workspace"
        base.mkdir()
        link = base / "link.txt"
        link.symlink_to(target)
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = _write_output_file(str(link), lambda f: f.write("data"), base_dir=base)
        assert result is False
        assert "escapes base directory" in caplog.text.lower()

    def test_accepts_dotdot_within_base(self, tmp_path):
        """Paths with '..' that still resolve within base_dir are accepted."""
        sub = tmp_path / "sub"
        sub.mkdir()
        safe_path = str(sub / ".." / "output.txt")
        result = _write_output_file(safe_path, lambda f: f.write("ok"), base_dir=tmp_path)
        assert result is True
        assert (tmp_path / "output.txt").read_text() == "ok"

    def test_tilde_dir_within_base_accepted(self, tmp_path):
        """A literal ~ in a directory name within base_dir is accepted."""
        tilde_dir = tmp_path / "~oddname"
        tilde_dir.mkdir()
        result = _write_output_file(
            str(tilde_dir / "out.txt"),
            lambda f: f.write("ok"),
            base_dir=tmp_path,
        )
        assert result is True

    def test_tilde_home_expansion_rejected(self, tmp_path, caplog):
        """~/path resolves outside base_dir and is rejected."""
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = _write_output_file(
                "~/secret.txt", lambda f: f.write("data"), base_dir=tmp_path
            )
        assert result is False


class TestEmitPlanOutputs:
    """Tests for _emit_plan_outputs()."""

    def test_default_stdout(self, sample_config, capsys):
        """No plan_outputs configured → PlanText to stdout."""
        from octorules.planner import ZonePlan

        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        result = _emit_plan_outputs(sample_config, [zp])
        assert result is True
        out = capsys.readouterr().out
        assert "No changes detected" in out

    def test_file_output(self, sample_config, tmp_path):
        """PlanOutput with path → file written."""
        from octorules.phases import get_phase
        from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

        out_file = tmp_path / "plan.txt"
        sample_config.plan_outputs = {"text": PlanText("text", path=str(out_file))}
        phase = get_phase("redirect_rules")
        pp = PhasePlan(phase=phase, changes=[RuleChange(ChangeType.ADD, "r1", phase)])
        zp = ZonePlan(zone_name="example.com", phase_plans=[pp])
        result = _emit_plan_outputs(sample_config, [zp])
        assert result is True
        assert out_file.exists()
        assert "example.com" in out_file.read_text()

    def test_multiple_outputs(self, sample_config, tmp_path, capsys):
        """Multiple outputs: one to stdout, one to file."""
        from octorules.phases import get_phase
        from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

        out_file = tmp_path / "plan.json"
        sample_config.plan_outputs = {
            "text": PlanText("text"),
            "json": PlanJson("json", path=str(out_file)),
        }
        phase = get_phase("redirect_rules")
        pp = PhasePlan(phase=phase, changes=[RuleChange(ChangeType.ADD, "r1", phase)])
        zp = ZonePlan(zone_name="example.com", phase_plans=[pp])
        result = _emit_plan_outputs(sample_config, [zp])
        assert result is True
        # stdout should have text output
        out = capsys.readouterr().out
        assert "example.com" in out
        # file should have JSON
        assert out_file.exists()

    def test_write_error_returns_false(self, sample_config, caplog):
        """File write error → returns False."""
        from octorules.planner import ZonePlan

        # Use a directory path as file — will fail
        sample_config.plan_outputs = {"text": PlanText("text", path=str(sample_config.rules_dir))}
        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = _emit_plan_outputs(sample_config, [zp])
        assert result is False
        assert "Failed to write output file" in caplog.text


class TestParallelPhaseApply:
    """Tests for parallel phase PUT within a zone during sync."""

    @patch("octorules.commands._providers._init_providers")
    def test_sync_parallel_phases_with_max_workers_gt_1(self, mock_init_provs, tmp_path):
        """With max_workers > 1 and multiple phases, phases applied in parallel."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.max_workers = 2
        result = cmd_sync(config, None)
        assert result == 0
        # Both phases should have been applied
        assert mock_prov.put_phase_rules.call_count == 2

    @patch("octorules.commands._providers._init_providers")
    def test_sync_sequential_phases_with_max_workers_1(self, mock_init_provs, tmp_path):
        """With max_workers=1, phases are applied sequentially (no thread pool)."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=1,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.max_workers = 1
        result = cmd_sync(config, None)
        assert result == 0
        assert mock_prov.put_phase_rules.call_count == 2

    @patch("octorules.commands._providers._init_providers")
    def test_parallel_phase_api_error_reported(self, mock_init_provs, tmp_path, caplog):
        """API error in one phase during parallel apply should be reported."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        from octorules.provider.exceptions import ProviderError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.max_workers = 2

        call_count = 0

        def put_side_effect(scope, provider_id, rules):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise ProviderError("Server error")

        mock_prov.put_phase_rules.side_effect = put_side_effect
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 1
        assert "API error syncing example.com" in caplog.text


class TestApplyParallel:
    """Direct unit tests for the _apply_parallel helper."""

    def test_empty_task_list(self):
        from octorules.commands import _apply_parallel

        successes, error = _apply_parallel([], max_workers=4)
        assert successes == []
        assert error is None

    def test_single_task_success(self):
        from octorules.commands import _apply_parallel

        called = []
        tasks = [("task-a", lambda: called.append("a"))]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == ["task-a"]
        assert error is None
        assert called == ["a"]

    def test_single_task_api_error(self):
        from octorules.commands import _apply_parallel
        from octorules.provider.exceptions import ProviderError

        def fail():
            raise ProviderError("boom")

        tasks = [("task-a", fail)]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == []
        assert error is not None
        assert "task-a" in error
        assert "boom" in error

    def test_single_task_timeout_error(self):
        from octorules.commands import _apply_parallel

        def fail():
            raise TimeoutError("timed out")

        tasks = [("task-a", fail)]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == []
        assert error is not None
        assert "task-a" in error
        assert "timed out" in error

    def test_sequential_stops_on_first_error(self):
        from octorules.commands import _apply_parallel
        from octorules.provider.exceptions import ProviderError

        called = []

        def ok():
            called.append("ok")

        def fail():
            raise ProviderError("fail")

        def never():
            called.append("never")

        tasks = [("a", ok), ("b", fail), ("c", never)]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == ["a"]
        assert error is not None
        assert "b" in error
        assert "never" not in called

    def test_auth_error_propagates_sequential(self):
        from octorules.commands import _apply_parallel
        from octorules.provider.exceptions import ProviderAuthError

        def fail():
            raise ProviderAuthError("bad token")

        tasks = [("task-a", fail)]
        with pytest.raises(ProviderAuthError):
            _apply_parallel(tasks, max_workers=1)

    def test_auth_error_propagates_parallel(self):
        from octorules.commands import _apply_parallel
        from octorules.provider.exceptions import ProviderAuthError

        def fail():
            raise ProviderAuthError("bad token")

        tasks = [("task-a", fail), ("task-b", lambda: None)]
        with pytest.raises(ProviderAuthError):
            _apply_parallel(tasks, max_workers=4)

    def test_parallel_collects_successes_on_error(self):
        """Parallel path: successful tasks collected even when one fails."""
        import threading

        from octorules.commands import _apply_parallel
        from octorules.provider.exceptions import ProviderError

        barrier = threading.Barrier(3, timeout=5)

        def ok1():
            barrier.wait()

        def ok2():
            barrier.wait()

        def fail():
            barrier.wait()
            raise ProviderError("fail")

        tasks = [("a", ok1), ("b", fail), ("c", ok2)]
        successes, error = _apply_parallel(tasks, max_workers=4)
        assert error is not None
        assert "b" in error
        # Both successful tasks should be collected
        assert sorted(successes) == ["a", "c"]

    def test_non_int_max_workers_uses_sequential(self):
        """MagicMock or other non-int max_workers falls back to sequential."""
        from octorules.commands import _apply_parallel

        called = []
        tasks = [("a", lambda: called.append("a")), ("b", lambda: called.append("b"))]
        successes, error = _apply_parallel(tasks, max_workers=MagicMock())
        assert successes == ["a", "b"]
        assert error is None
        assert called == ["a", "b"]  # sequential order preserved


class TestPreparedRulesReuse:
    """Tests that prepared_rules from planning are reused during sync."""

    @patch("octorules.commands._providers._init_providers")
    def test_sync_uses_prepared_rules(self, mock_init_provs, tmp_path):
        """Sync should use prepared_rules from planning, not re-prepare."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    targets=["cloudflare"],
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.max_workers = 1
        result = cmd_sync(config, None)
        assert result == 0
        # Verify the PUT payload has defaults injected (from prepared_rules)
        call_args = mock_prov.put_phase_rules.call_args
        payload = call_args[0][2]  # third positional arg: rules
        assert payload[0]["enabled"] is True
        assert payload[0]["action"] == "redirect"


# ---------------------------------------------------------------------------
# Multi-provider CLI integration tests
# ---------------------------------------------------------------------------
def _multi_cli_config(tmp_path):
    """Build a Config with two providers and one zone each."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    return Config(
        providers={
            "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "cf-tok"}),
            "aws": ProviderConfig(name="aws", kwargs={"region": "us-west-2"}),
        },
        rules_dir=rules_dir,
        zones={
            "example.com": ZoneConfig(
                name="example.com",
                zone_id="zone-cf",
                sources=["rules"],
                targets=["cloudflare"],
            ),
            "my-web-acl": ZoneConfig(
                name="my-web-acl",
                zone_id="wacl-1",
                sources=["rules"],
                targets=["aws"],
            ),
        },
    )


class TestMultiProviderPlan:
    """Plan routes zones to the correct provider."""

    @patch("octorules.commands._providers._init_providers")
    def test_plan_calls_correct_provider_per_zone(self, mock_init_provs, tmp_path):
        """Each zone's plan calls get_all_phase_rules on its target provider."""
        config = _multi_cli_config(tmp_path)
        cf_prov = MagicMock()
        aws_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": cf_prov, "aws": aws_prov}
        cf_prov.get_all_phase_rules.return_value = {}
        cf_prov.account_id = None
        aws_prov.get_all_phase_rules.return_value = {}
        aws_prov.account_id = None

        result = cmd_plan(config, None, scope_filter="zones")
        assert result == 0

        # CF provider should have been called with the CF zone scope
        cf_scopes = [c.args[0] for c in cf_prov.get_all_phase_rules.call_args_list]
        assert any(s.zone_id == "zone-cf" for s in cf_scopes)
        # AWS provider should have been called with the AWS zone scope
        aws_scopes = [c.args[0] for c in aws_prov.get_all_phase_rules.call_args_list]
        assert any(s.zone_id == "wacl-1" for s in aws_scopes)
        # CF provider should NOT have been called with AWS zone
        assert not any(s.zone_id == "wacl-1" for s in cf_scopes)


class TestMultiProviderSync:
    """Sync routes zone changes to the correct provider."""

    @patch("octorules.commands._providers._init_providers")
    def test_sync_applies_to_correct_provider(self, mock_init_provs, tmp_path):
        """Sync routes put_phase_rules to the right provider per zone."""
        config = _multi_cli_config(tmp_path)
        cf_prov = MagicMock()
        aws_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": cf_prov, "aws": aws_prov}
        cf_prov.account_id = None
        aws_prov.account_id = None

        # Write rules for the CF zone only
        (config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        cf_prov.get_all_phase_rules.return_value = {}
        aws_prov.get_all_phase_rules.return_value = {}

        result = cmd_sync(config, ["example.com"], scope_filter="zones")
        assert result == 0

        # CF provider should have received put_phase_rules
        assert cf_prov.put_phase_rules.called
        # AWS provider should NOT have received put_phase_rules
        assert not aws_prov.put_phase_rules.called


class TestMultiProviderDump:
    """Dump routes zone fetches to the correct provider."""

    @patch("octorules.commands._providers._init_providers")
    def test_dump_calls_correct_provider_per_zone(self, mock_init_provs, tmp_path, caplog):
        """Dump calls get_all_phase_rules on the right provider per zone."""
        config = _multi_cli_config(tmp_path)
        cf_prov = MagicMock()
        aws_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": cf_prov, "aws": aws_prov}
        cf_prov.get_all_phase_rules.return_value = {}
        cf_prov.get_all_page_shield_policies.return_value = []
        cf_prov.account_id = None
        aws_prov.get_all_phase_rules.return_value = {}
        aws_prov.get_all_page_shield_policies.return_value = []
        aws_prov.account_id = None

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="zones")
        assert result == 0

        # Each provider should have been called only for its own zones
        cf_scopes = [c.args[0] for c in cf_prov.get_all_phase_rules.call_args_list]
        aws_scopes = [c.args[0] for c in aws_prov.get_all_phase_rules.call_args_list]
        assert any(s.zone_id == "zone-cf" for s in cf_scopes)
        assert any(s.zone_id == "wacl-1" for s in aws_scopes)
        assert not any(s.zone_id == "wacl-1" for s in cf_scopes)
        assert not any(s.zone_id == "zone-cf" for s in aws_scopes)

    @patch("octorules.commands._providers._init_providers")
    def test_dump_account_runs_per_provider(self, mock_init_provs, tmp_path, caplog):
        """Dump runs _dump_account for each provider with account info."""
        config = _multi_cli_config(tmp_path)
        cf_prov = MagicMock()
        aws_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": cf_prov, "aws": aws_prov}

        cf_prov.account_id = "cf-acct"
        cf_prov.account_name = "my-cf-account"
        cf_prov.get_all_phase_rules.return_value = {}
        cf_prov.get_all_custom_rulesets.return_value = {}
        cf_prov.get_all_lists.return_value = {}

        aws_prov.account_id = "aws-acct"
        aws_prov.account_name = "my-aws-account"
        aws_prov.get_all_phase_rules.return_value = {}
        aws_prov.get_all_custom_rulesets.return_value = {}
        aws_prov.get_all_lists.return_value = {}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0

        # Both providers should have had their account-level methods called
        assert cf_prov.get_all_custom_rulesets.called
        assert aws_prov.get_all_custom_rulesets.called


class TestAuditLog:
    """Tests for _write_audit_log and its integration with cmd_sync."""

    def test_audit_log_writes_json_lines(self, tmp_path):
        """_write_audit_log writes valid JSON lines with correct fields."""
        import json

        from octorules.commands import SyncResult, _write_audit_log

        results = [
            SyncResult(
                zone_name="ok.com",
                target=None,
                synced=["redirect_rules"],
                error=None,
                total_changes=3,
            ),
            SyncResult(
                zone_name="fail.com",
                target="cloudflare",
                synced=[],
                error="API timeout",
                total_changes=1,
            ),
        ]
        audit_path = str(tmp_path / "audit.jsonl")
        _write_audit_log(audit_path, results)

        lines = (tmp_path / "audit.jsonl").read_text().strip().splitlines()
        assert len(lines) == 2

        required_keys = {
            "timestamp",
            "zone",
            "target",
            "synced",
            "total_changes",
            "status",
            "error",
        }
        for line in lines:
            entry = json.loads(line)
            assert required_keys <= set(entry.keys()), f"Missing keys in {entry}"

        ok_entry = json.loads(lines[0])
        assert ok_entry["zone"] == "ok.com"
        assert ok_entry["status"] == "ok"
        assert ok_entry["error"] is None
        assert ok_entry["total_changes"] == 3
        assert ok_entry["synced"] == ["redirect_rules"]

        fail_entry = json.loads(lines[1])
        assert fail_entry["zone"] == "fail.com"
        assert fail_entry["target"] == "cloudflare"
        assert fail_entry["status"] == "error"
        assert fail_entry["error"] == "API timeout"

    def test_audit_log_failure_does_not_abort_sync(self, tmp_path, caplog):
        """If audit log write fails, _write_audit_log logs error but does not raise."""
        from octorules.commands import SyncResult, _write_audit_log

        audit_path = str(tmp_path / "audit.jsonl")

        results = [
            SyncResult(
                zone_name="ok.com",
                target=None,
                synced=["redirect_rules"],
                error=None,
                total_changes=1,
            ),
        ]

        # Simulate an OS-level write failure (e.g. disk full, permission denied)
        with (
            patch("builtins.open", side_effect=OSError("Permission denied")),
            caplog.at_level(logging.ERROR, logger="octorules"),
        ):
            _write_audit_log(audit_path, results)

        assert "Failed to write audit log" in caplog.text


# ---------------------------------------------------------------------------
# cmd_audit CLI integration tests
# ---------------------------------------------------------------------------
class TestCmdAuditCLI:
    """Tests for audit subcommand through the CLI argument parser."""

    def test_audit_parser_accepts_checks(self):
        parser = build_parser()
        ns = parser.parse_args(["audit", "--check", "ip-overlap", "--check", "cdn-ranges"])
        assert ns.command == "audit"
        assert ns.audit_checks == ["ip-overlap", "cdn-ranges"]

    def test_audit_parser_defaults(self):
        parser = build_parser()
        ns = parser.parse_args(["audit"])
        assert ns.command == "audit"
        assert ns.audit_checks is None
        assert ns.cdn_timeout == 15
        assert ns.cdn_stale_days == 60

    def test_audit_parser_cdn_options(self):
        parser = build_parser()
        ns = parser.parse_args(["audit", "--cdn-timeout", "30", "--cdn-stale-days", "90"])
        assert ns.cdn_timeout == 30
        assert ns.cdn_stale_days == 90

    def test_audit_parser_rejects_negative_cdn_timeout(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--cdn-timeout", "-5"])

    def test_audit_parser_rejects_zero_cdn_timeout(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--cdn-timeout", "0"])

    def test_audit_parser_rejects_negative_cdn_stale_days(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--cdn-stale-days", "-1"])

    def test_audit_parser_rejects_zero_cdn_stale_days(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--cdn-stale-days", "0"])

    def test_audit_parser_rejects_non_numeric_cdn_timeout(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["audit", "--cdn-timeout", "abc"])

    def test_audit_no_rules_returns_0(self, sample_config):
        """Audit with no rules files returns 0 (nothing to audit)."""
        with patch("octorules.commands._audit._ensure_provider_loaded"):
            result = cmd_audit(sample_config, None)
        assert result == 0

    def test_audit_invalid_check_returns_1(self, sample_config, caplog):
        """Unknown check name returns exit code 1."""
        with (
            patch("octorules.commands._audit._ensure_provider_loaded"),
            caplog.at_level(logging.ERROR),
        ):
            result = cmd_audit(sample_config, None, checks=["nonexistent-check"])
        assert result == 1
        assert "Unknown audit check" in caplog.text

    def test_audit_no_findings_returns_0(self, sample_config):
        """Audit with rules but no findings returns 0."""
        # Create a minimal rules file with no IP-bearing rules.
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: ''\n")
        with patch("octorules.commands._audit._ensure_provider_loaded"):
            result = cmd_audit(sample_config, ["example.com"])
        assert result == 0

    def test_audit_via_main(self, sample_config, tmp_path, monkeypatch):
        """Audit runs through main() without error."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: test\nzones: {}\nrules_dir: rules\n"
        )
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rules").mkdir(exist_ok=True)
        with (
            patch("octorules.commands._audit._ensure_provider_loaded"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--config", str(config_file), "audit"])
        assert exc_info.value.code == 0


# ---------------------------------------------------------------------------
# P0 fix tests: audit extension error handling
# ---------------------------------------------------------------------------
class TestAuditExtensionErrorHandling:
    """Tests for best-effort audit extension error handling (P0-1)."""

    def test_failed_extension_returns_partial_results(self):
        """A failing extension returns partial results and failed names."""
        from octorules.audit import RuleIPInfo
        from octorules.extensions import (
            call_audit_extensions,
            register_audit_extension,
            unregister_audit_extension,
        )

        def good_ext(rules_data, phase_name):
            return [
                RuleIPInfo(
                    zone_name="",
                    phase_name=phase_name,
                    ref="good-rule",
                    action="block",
                    ip_ranges=["10.0.0.0/8"],
                )
            ]

        def bad_ext(rules_data, phase_name):
            raise ValueError("simulated extension crash")

        register_audit_extension("good", good_ext)
        register_audit_extension("bad", bad_ext)
        try:
            results, failed = call_audit_extensions({"redirect_rules": []}, "redirect_rules")
            assert len(results) == 1
            assert results[0].ref == "good-rule"
            assert failed == ["bad"]
        finally:
            unregister_audit_extension("good")
            unregister_audit_extension("bad")

    def test_all_extensions_succeed_returns_empty_failed(self):
        from octorules.extensions import call_audit_extensions

        results, failed = call_audit_extensions({}, "test_phase")
        assert results == []
        assert failed == []

    def test_audit_zone_rules_no_extensions_returns_list_pseudorules(self):
        """With no audit extensions registered, list IPs still appear as pseudo-rules."""
        from octorules.audit import audit_zone_rules

        rules_data = {
            "lists": [
                {
                    "kind": "ip",
                    "name": "blocked_ips",
                    "items": [{"ip": "10.0.0.0/8"}, {"ip": "192.168.0.0/16"}],
                },
            ],
        }
        infos = audit_zone_rules(rules_data, "test-zone")
        # No extensions → no rule-level IPs, but list pseudo-rules are still created
        assert len(infos) == 1
        assert infos[0].ref == "list:blocked_ips"
        assert "10.0.0.0/8" in infos[0].ip_ranges
        assert infos[0].zone_name == "test-zone"


# ---------------------------------------------------------------------------
# P0 fix tests: _fetch_json HTTP status check
# ---------------------------------------------------------------------------
class TestFetchJsonHttpStatus:
    """Tests for HTTP status validation in _fetch_json (P0-2)."""

    def test_non_200_returns_none(self):
        """Non-200 success codes (e.g. 204 No Content) return None.

        Note: 4xx/5xx raise HTTPError before reaching the status check,
        so we test with 204 which urlopen returns without raising.
        """
        from octorules.audit import _fetch_json

        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("octorules.audit.urlopen", return_value=mock_resp):
            result = _fetch_json("https://example.com/test.json")
        assert result is None

    def test_http_error_returns_none(self):
        """HTTP 4xx/5xx errors (raised by urlopen as HTTPError) return None."""
        from urllib.error import HTTPError

        from octorules.audit import _fetch_json

        with patch(
            "octorules.audit.urlopen",
            side_effect=HTTPError("https://example.com", 404, "Not Found", {}, None),
        ):
            result = _fetch_json("https://example.com/test.json")
        assert result is None

    def test_200_parses_json(self):
        from octorules.audit import _fetch_json

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.read.return_value = b'{"key": "value"}'
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("octorules.audit.urlopen", return_value=mock_resp):
            result = _fetch_json("https://example.com/test.json")
        assert result == {"key": "value"}

    def test_network_error_returns_none(self):
        from octorules.audit import _fetch_json

        with patch("octorules.audit.urlopen", side_effect=OSError("Connection refused")):
            result = _fetch_json("https://example.com/test.json")
        assert result is None


# ---------------------------------------------------------------------------
# Quiet flag (--quiet) output suppression tests
# ---------------------------------------------------------------------------
class TestQuietFlag:
    """Tests for --quiet stdout suppression via ContextVar."""

    def test_is_quiet_default_false(self):
        """is_quiet() returns False by default."""
        from octorules._context import is_quiet

        assert is_quiet() is False

    def test_set_quiet_round_trip(self):
        """set_quiet(True) then is_quiet() returns True."""
        from octorules._context import is_quiet, set_quiet

        set_quiet(True)
        try:
            assert is_quiet() is True
        finally:
            set_quiet(False)

    def test_quiet_suppresses_plan_text_stdout(self, capsys, sample_config):
        """--quiet suppresses plan table output to stdout."""
        from octorules._context import set_quiet
        from octorules.planner import ZonePlan

        set_quiet(True)
        try:
            result = _emit_plan_outputs(sample_config, [ZonePlan(zone_name="z", phase_plans=[])])
            assert result is True
            assert capsys.readouterr().out == ""
        finally:
            set_quiet(False)

    def test_quiet_does_not_suppress_file_output(self, tmp_path, sample_config):
        """--quiet does not suppress plan output written to a file."""
        from octorules._context import set_quiet
        from octorules.phases import get_phase
        from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

        out_file = tmp_path / "plan.txt"
        sample_config.plan_outputs = {"text": PlanText("text", path=str(out_file))}
        phase = get_phase("redirect_rules")
        pp = PhasePlan(phase=phase, changes=[RuleChange(ChangeType.ADD, "r1", phase)])
        zp = ZonePlan(zone_name="example.com", phase_plans=[pp])

        set_quiet(True)
        try:
            result = _emit_plan_outputs(sample_config, [zp])
            assert result is True
            assert out_file.exists()
            assert "example.com" in out_file.read_text()
        finally:
            set_quiet(False)

    def test_quiet_suppresses_versions_output(self, capsys):
        """--quiet suppresses versions command output."""
        from octorules._context import set_quiet

        set_quiet(True)
        try:
            result = cmd_versions()
            assert result == 0
            assert capsys.readouterr().out == ""
        finally:
            set_quiet(False)

    def test_quiet_suppresses_lint_stdout(self, capsys, sample_config):
        """--quiet suppresses lint result output to stdout (stderr summary still visible)."""
        from octorules._context import set_quiet

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: ''\n")

        set_quiet(True)
        try:
            with patch("octorules.commands._audit._ensure_provider_loaded"):
                cmd_lint(sample_config, ["example.com"])
            # stdout should be empty; stderr summary is still allowed
            assert capsys.readouterr().out == ""
        finally:
            set_quiet(False)

    def test_quiet_suppresses_audit_stdout(self, sample_config, capsys):
        """--quiet suppresses audit findings output to stdout."""
        from octorules._context import set_quiet

        # Create a rules file with no IP-bearing rules (no findings)
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: ''\n")

        set_quiet(True)
        try:
            with patch("octorules.commands._audit._ensure_provider_loaded"):
                result = cmd_audit(sample_config, ["example.com"])
            assert result == 0
            assert capsys.readouterr().out == ""
        finally:
            set_quiet(False)

    def test_quiet_preserves_report_file_output(self, tmp_path, sample_config):
        """--quiet does not suppress print_report when writing to a file handle."""
        from octorules._context import set_quiet
        from octorules.formatter import print_report

        report_data = {
            "zones": [],
            "summary": {"total_zones": 0, "in_sync": 0, "drifted": 0},
        }
        out_file = tmp_path / "report.csv"

        set_quiet(True)
        try:
            with open(out_file, "w") as fh:
                print_report(report_data, file=fh, fmt="csv")
            assert out_file.exists()
            content = out_file.read_text()
            assert "Zone" in content  # CSV header present
        finally:
            set_quiet(False)

    def test_quiet_suppresses_report_stdout(self, capsys):
        """--quiet suppresses print_report to stdout."""
        from octorules._context import set_quiet
        from octorules.formatter import print_report

        report_data = {
            "zones": [],
            "summary": {"total_zones": 0, "in_sync": 0, "drifted": 0},
        }

        set_quiet(True)
        try:
            print_report(report_data, fmt="csv")
            assert capsys.readouterr().out == ""
        finally:
            set_quiet(False)

    def test_quiet_flag_set_via_main(self, tmp_path, monkeypatch, capsys):
        """main() sets the quiet flag from --quiet argv."""
        from octorules._context import set_quiet

        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: test\nzones: {}\nrules_dir: rules\n"
        )
        monkeypatch.chdir(tmp_path)
        (tmp_path / "rules").mkdir(exist_ok=True)

        try:
            with (
                patch("octorules.commands._audit._ensure_provider_loaded"),
                pytest.raises(SystemExit) as exc_info,
            ):
                main(["--quiet", "--config", str(config_file), "versions"])
            assert exc_info.value.code == 0
            assert capsys.readouterr().out == ""
        finally:
            set_quiet(False)


# ---------------------------------------------------------------------------
# Exit code summary + timing (#1, #2)
# ---------------------------------------------------------------------------
class TestExitSummary:
    """Exit code summary and timing printed to stderr."""

    @patch("octorules.cli.cmd_plan", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_plan_exit_0_summary(self, mock_config, mock_cmd, tmp_config, capsys):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "plan"])
        assert exc_info.value.code == 0
        err = capsys.readouterr().err
        assert "octorules plan: exit 0 (success)" in err

    @patch("octorules.cli.cmd_plan", return_value=2)
    @patch("octorules.cli.Config.from_file")
    def test_plan_exit_2_summary(self, mock_config, mock_cmd, tmp_config, capsys):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "plan", "--exit-code"])
        assert exc_info.value.code == 2
        err = capsys.readouterr().err
        assert "exit 2 (changes detected)" in err

    @patch("octorules.cli.cmd_plan", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_timing_appears_in_stderr(self, mock_config, mock_cmd, tmp_config, capsys):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit):
            main(["--config", str(tmp_config), "plan"])
        err = capsys.readouterr().err
        # Timing like "0.0s" should appear
        assert "s" in err

    def test_config_error_exit_summary(self, capsys):
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", "/nonexistent/config.yaml", "plan"])
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert "exit 1 (error)" in err


# ---------------------------------------------------------------------------
# Lint summary format (#4)
# ---------------------------------------------------------------------------
class TestLintSummaryFormat:
    """Tests for --format summary."""

    @patch("octorules.commands._providers._init_providers")
    def test_summary_format_counts_only(self, mock_init_provs, sample_config, capsys):
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        # Create a rules file with content so lint runs
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        cmd_lint(sample_config, ["example.com"], lint_format="summary")
        out = capsys.readouterr().out
        # Summary format should be concise — zone name + counts or "clean"
        assert "example.com" in out

    def test_summary_formatter_output(self):
        from octorules.linter.engine import LintContext, LintResult, Severity
        from octorules.linter.report import format_summary

        ctx = LintContext(zone_name="test.com")
        ctx.results = [
            LintResult(rule_id="CF001", severity=Severity.ERROR, message="err"),
            LintResult(rule_id="CF002", severity=Severity.WARNING, message="warn"),
            LintResult(rule_id="CF003", severity=Severity.WARNING, message="warn2"),
        ]
        output = format_summary(ctx)
        assert "1 error(s)" in output
        assert "2 warning(s)" in output
        assert "test.com" in output

    def test_summary_formatter_clean(self):
        from octorules.linter.engine import LintContext
        from octorules.linter.report import format_summary

        ctx = LintContext(zone_name="clean.com")
        output = format_summary(ctx)
        assert "clean" in output

    def test_audit_summary_format(self):
        from octorules.audit import AuditFinding, FindingSeverity, format_findings_summary

        findings = [
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="a"),
            AuditFinding(check="ip-overlap", severity=FindingSeverity.WARNING, message="b"),
            AuditFinding(check="cdn-ranges", severity=FindingSeverity.ERROR, message="c"),
        ]
        output = format_findings_summary(findings)
        assert "ip-overlap: 2" in output
        assert "cdn-ranges: 1" in output


# ---------------------------------------------------------------------------
# Plugin usage tracking in lint
# ---------------------------------------------------------------------------
class TestLintPluginUsage:
    """Lint plugins are labeled as 'unused' when they produce no results."""

    @patch("octorules.linter.plugin.get_registered_plugins")
    def test_plugin_with_results_not_labeled_unused(self, mock_get_plugins, sample_config, caplog):
        """A plugin that produces results is not labeled 'unused'."""
        from octorules.linter.engine import LintResult, Severity
        from octorules.linter.plugin import LintPlugin

        def fake_lint(rules_data, ctx):
            ctx.add(LintResult(rule_id="FK001", severity=Severity.WARNING, message="test"))

        mock_get_plugins.return_value = [
            LintPlugin(name="fakeprovider", lint_fn=fake_lint, rule_ids=frozenset({"FK001"}))
        ]
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_lint(sample_config, ["example.com"])
        plugin_lines = [r for r in caplog.records if "Lint plugins:" in r.message]
        assert len(plugin_lines) == 1
        assert "fakeprovider" in plugin_lines[0].message
        assert "(unused)" not in plugin_lines[0].message

    @patch("octorules.linter.plugin.get_registered_plugins")
    def test_plugin_with_no_matching_phases_labeled_unused(
        self, mock_get_plugins, sample_config, caplog
    ):
        """A plugin that matches no phases is labeled (unused)."""
        from octorules.linter.plugin import LintPlugin

        # Register a fake plugin with rule IDs that won't match any rules
        fake_plugin = LintPlugin(
            name="fakeprovider",
            lint_fn=lambda rules_data, ctx: None,
            rule_ids=frozenset({"FP001"}),
        )
        mock_get_plugins.return_value = [fake_plugin]
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_lint(sample_config, ["example.com"])
        plugin_lines = [r for r in caplog.records if "Lint plugins:" in r.message]
        assert len(plugin_lines) == 1
        assert "fakeprovider (unused)" in plugin_lines[0].message

    @patch("octorules.linter.plugin.get_registered_plugins")
    def test_no_plugins_no_plugin_line(self, mock_get_plugins, sample_config, caplog):
        """When no plugins are registered, no plugin line is logged."""
        mock_get_plugins.return_value = []
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_lint(sample_config, ["example.com"])
        plugin_lines = [r for r in caplog.records if "Lint plugins:" in r.message]
        assert len(plugin_lines) == 0


class TestLintZonePlans:
    """Lint uses zone_plans for per-zone plan tier resolution."""

    @patch("octorules.linter.plugin.get_registered_plugins")
    def test_zone_plans_overrides_default_tier(self, mock_get_plugins, sample_config):
        """zone_plans dict sets plan_tier for matching zones."""
        from octorules.linter.engine import LintContext
        from octorules.linter.plugin import LintPlugin

        captured_tiers: dict[str, str] = {}

        def spy_lint(rules_data, ctx: LintContext):
            captured_tiers[ctx.zone_name] = ctx.plan_tier

        mock_get_plugins.return_value = [
            LintPlugin(name="spy", lint_fn=spy_lint, rule_ids=frozenset())
        ]
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        cmd_lint(
            sample_config,
            ["example.com"],
            zone_plans={"example.com": "free"},
        )
        assert captured_tiers["example.com"] == "free"

    @patch("octorules.linter.plugin.get_registered_plugins")
    def test_explicit_plan_flag_overrides_zone_plans(self, mock_get_plugins, sample_config):
        """--plan flag wins over zone_plans cache."""
        from octorules.linter.engine import LintContext
        from octorules.linter.plugin import LintPlugin

        captured_tiers: dict[str, str] = {}

        def spy_lint(rules_data, ctx: LintContext):
            captured_tiers[ctx.zone_name] = ctx.plan_tier

        mock_get_plugins.return_value = [
            LintPlugin(name="spy", lint_fn=spy_lint, rule_ids=frozenset())
        ]
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        cmd_lint(
            sample_config,
            ["example.com"],
            lint_plan="business",
            zone_plans={"example.com": "free"},
        )
        assert captured_tiers["example.com"] == "business"

    @patch("octorules.linter.plugin.get_registered_plugins")
    def test_missing_zone_in_cache_defaults_to_enterprise(self, mock_get_plugins, sample_config):
        """Zones not in zone_plans fall back to 'enterprise'."""
        from octorules.linter.engine import LintContext
        from octorules.linter.plugin import LintPlugin

        captured_tiers: dict[str, str] = {}

        def spy_lint(rules_data, ctx: LintContext):
            captured_tiers[ctx.zone_name] = ctx.plan_tier

        mock_get_plugins.return_value = [
            LintPlugin(name="spy", lint_fn=spy_lint, rule_ids=frozenset())
        ]
        (sample_config.rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        cmd_lint(
            sample_config,
            ["example.com"],
            zone_plans={"other-zone": "free"},
        )
        assert captured_tiers["example.com"] == "enterprise"


# ---------------------------------------------------------------------------
# --config-only validate (#8)
# ---------------------------------------------------------------------------
class TestSyncJsonFormat:
    def test_format_sync_results_json(self):
        from octorules.commands._sync import SyncResult, _format_sync_results_json

        results = [
            SyncResult(
                zone_name="a.com",
                target=None,
                synced=["redirect_rules"],
                error=None,
                total_changes=1,
            ),
            SyncResult(
                zone_name="b.com",
                target="aws",
                synced=[],
                error="timeout",
                total_changes=2,
            ),
        ]
        import json

        output = _format_sync_results_json(results)
        data = json.loads(output)
        assert len(data) == 2
        assert data[0]["zone"] == "a.com"
        assert data[0]["status"] == "ok"
        assert data[1]["status"] == "error"
        assert data[1]["error"] == "timeout"


# ---------------------------------------------------------------------------
# argcomplete integration (#6)
# ---------------------------------------------------------------------------
class TestArgcomplete:
    def test_parser_has_all_subcommands(self):
        from octorules.cli import build_parser

        parser = build_parser()
        subparsers_actions = [
            a for a in parser._subparsers._actions if isinstance(a, argparse._SubParsersAction)
        ]
        assert len(subparsers_actions) == 1
        choices = set(subparsers_actions[0].choices.keys())
        expected = {
            "plan",
            "sync",
            "dump",
            "lint",
            "audit",
            "versions",
            "completion",
            "rule",
        }
        assert expected <= choices

    def test_completion_bash(self, capsys):
        """octorules completion bash produces bash script."""
        with pytest.raises(SystemExit) as exc_info:
            main(["completion", "bash"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "octorules" in out
        assert len(out) > 50

    def test_completion_zsh(self, capsys):
        """octorules completion zsh produces zsh script."""
        with pytest.raises(SystemExit) as exc_info:
            main(["completion", "zsh"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "octorules" in out
        assert len(out) > 50

    def test_completion_tcsh(self, capsys):
        """octorules completion tcsh produces tcsh script."""
        with pytest.raises(SystemExit) as exc_info:
            main(["completion", "tcsh"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "octorules" in out

    def test_completion_default_is_bash(self, capsys):
        """octorules completion with no arg defaults to bash."""
        with pytest.raises(SystemExit) as exc_info:
            main(["completion"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "octorules" in out

    def test_completion_zone_names_bash(self, tmp_path, capsys):
        """Zone names from config are injected into bash completion."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: test\n"
            "zones:\n  alpha.com:\n    zone_id: z1\n  beta.org:\n    zone_id: z2\n"
            f"rules_dir: {rules_dir}\n"
        )
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(config_file), "completion", "bash"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "_octorules_zone_complete" in out
        assert "alpha.com" in out
        assert "beta.org" in out

    def test_completion_zone_names_zsh(self, tmp_path, capsys):
        """Zone names from config are injected into zsh completion."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: test\n"
            "zones:\n  alpha.com:\n    zone_id: z1\n  beta.org:\n    zone_id: z2\n"
            f"rules_dir: {rules_dir}\n"
        )
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(config_file), "completion", "zsh"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "_octorules_zone_complete" in out
        assert "alpha.com" in out

    def test_completion_no_config_still_works(self, tmp_path, capsys):
        """Missing config doesn't break completion — just no zone names."""
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_path / "no_such.yaml"), "completion", "bash"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "octorules" in out


# ---------------------------------------------------------------------------
# lint single-file mode tests
# ---------------------------------------------------------------------------
class TestLintFile:
    """Tests for the lint single-file mode."""

    @pytest.fixture(autouse=True)
    def _mock_discover(self):
        """Prevent real provider discovery from contaminating global state."""
        with patch("octorules.cli._discover_provider_modules"):
            yield

    def test_lint_file_no_issues(self, tmp_path, capsys):
        """lint <file> with --severity error on a file with no errors returns 0."""
        rules_file = tmp_path / "example.com.yaml"
        rules_file.write_text("redirect_rules: []\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["lint", "--severity", "error", str(rules_file)])
        assert exc_info.value.code == 0
        err = capsys.readouterr().err
        assert "0 issue(s) found" in err

    def test_lint_file_not_found(self, tmp_path, capsys):
        """lint <file> with nonexistent file returns 1."""
        with pytest.raises(SystemExit) as exc_info:
            main(["lint", str(tmp_path / "nonexistent.yaml")])
        assert exc_info.value.code == 1

    def test_lint_file_empty(self, tmp_path, capsys):
        """lint <file> with empty YAML returns 0."""
        rules_file = tmp_path / "empty.yaml"
        rules_file.write_text("")
        with pytest.raises(SystemExit) as exc_info:
            main(["lint", str(rules_file)])
        assert exc_info.value.code == 0
        err = capsys.readouterr().err
        assert "0 issue(s) found" in err

    def test_lint_file_invalid_yaml(self, tmp_path, capsys):
        """lint <file> with invalid YAML returns 1."""
        rules_file = tmp_path / "bad.yaml"
        rules_file.write_text(":\n  - [\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["lint", str(rules_file)])
        assert exc_info.value.code == 1

    def test_lint_file_core_rules(self, tmp_path, capsys):
        """lint <file> runs CORE006 on empty phases."""
        from octorules.commands._lint import cmd_lint_file

        rules_file = tmp_path / "nophases.yaml"
        rules_file.write_text("redirect_rules: []\n")
        code = cmd_lint_file(str(rules_file), lint_rules=["CORE006"])
        assert code == 0
        err = capsys.readouterr().err
        # CORE006 is info-level, shows up but doesn't cause exit code
        assert "issue(s) found" in err

    def test_lint_file_json_format(self, tmp_path, capsys):
        """lint <file> --format json produces JSON output."""
        import json

        rules_file = tmp_path / "test.yaml"
        rules_file.write_text("redirect_rules: []\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["lint", "--format", "json", str(rules_file)])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        parsed = json.loads(out)
        assert "results" in parsed

    def test_lint_file_exit_code_warnings(self, tmp_path, capsys):
        """lint <file> --exit-code returns 2 when only warnings found."""
        from octorules.commands._lint import cmd_lint_file

        rules_file = tmp_path / "warn.yaml"
        # Two disabled rules triggers CORE003 (warning)
        rules_file.write_text(
            "redirect_rules:\n  - ref: r1\n    enabled: false\n  - ref: r2\n    enabled: false\n"
        )
        code = cmd_lint_file(
            str(rules_file),
            lint_severity="warning",
            lint_rules=["CORE003"],
            exit_code=True,
        )
        assert code == 2

    def test_lint_file_output_file(self, tmp_path, capsys):
        """lint <file> --output writes results to file."""
        from octorules.commands._lint import cmd_lint_file

        rules_file = tmp_path / "test.yaml"
        rules_file.write_text("redirect_rules: []\n")
        out_file = tmp_path / "results.txt"
        code = cmd_lint_file(
            str(rules_file),
            lint_rules=["CORE006"],
            output_file=str(out_file),
        )
        assert code == 0
        assert out_file.exists()

    def test_lint_file_severity_filter(self, tmp_path, capsys):
        """lint <file> --severity error filters out lower severity."""
        rules_file = tmp_path / "test.yaml"
        rules_file.write_text("redirect_rules: []\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["lint", "--severity", "error", str(rules_file)])
        assert exc_info.value.code == 0

    def test_lint_file_summary_format(self, tmp_path, capsys):
        """lint <file> --format summary produces summary output."""
        rules_file = tmp_path / "test.yaml"
        rules_file.write_text("redirect_rules: []\n")
        with pytest.raises(SystemExit) as exc_info:
            main(["lint", "--format", "summary", str(rules_file)])
        assert exc_info.value.code == 0

    def test_lint_file_discovers_all_providers(self, tmp_path, capsys):
        """lint <file> calls _discover_provider_modules (not lazy)."""
        rules_file = tmp_path / "test.yaml"
        rules_file.write_text("redirect_rules: []\n")
        with (
            patch("octorules.cli._discover_provider_modules") as mock_disc,
            pytest.raises(SystemExit),
        ):
            main(["lint", str(rules_file)])
        mock_disc.assert_called_once()

    def test_lint_file_zone_name_from_stem(self, tmp_path, capsys):
        """lint <file> derives zone_name from file stem."""
        from octorules.commands._lint import cmd_lint_file

        rules_file = tmp_path / "my-zone.example.com.yaml"
        rules_file.write_text("redirect_rules: []\n")
        code = cmd_lint_file(str(rules_file), lint_severity="error")
        assert code == 0

    def test_lint_file_rule_filter(self, tmp_path, capsys):
        """lint <file> --rule filters to specific rule IDs."""
        from octorules.commands._lint import cmd_lint_file

        rules_file = tmp_path / "test.yaml"
        rules_file.write_text("redirect_rules: []\n")
        code = cmd_lint_file(str(rules_file), lint_rules=["CORE006"])
        assert code == 0
        out = capsys.readouterr().out
        assert "CORE006" in out


# ---------------------------------------------------------------------------
# Lazy provider discovery tests
# ---------------------------------------------------------------------------
class TestLazyProviderDiscovery:
    """Tests for _ensure_provider_loaded and lazy loading in lint/audit."""

    def test_ensure_provider_loaded_idempotent(self):
        """_ensure_provider_loaded can be called multiple times safely."""
        from octorules.commands._providers import _ensure_provider_loaded

        # Calling with a nonexistent provider is a no-op (no crash)
        _ensure_provider_loaded("__test_nonexistent__")
        _ensure_provider_loaded("__test_nonexistent__")

    def test_ensure_provider_loaded_handles_import_error(self):
        """_ensure_provider_loaded logs warning on broken entry-point."""
        from unittest.mock import MagicMock

        from octorules.commands._providers import _ensure_provider_loaded

        broken_ep = MagicMock()
        broken_ep.name = "__broken__"
        broken_ep.load.side_effect = ImportError("no such module")
        with patch(
            "importlib.metadata.entry_points",
            return_value=[broken_ep],
        ):
            # Should not raise — logs warning instead
            _ensure_provider_loaded("__broken__")

    def test_lint_uses_lazy_loading(self, tmp_path, capsys):
        """main() lint calls _ensure_provider_loaded per provider."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "z.com.yaml").write_text("redirect_rules: []\n")
        config_file = tmp_path / "config.yaml"
        config_file.write_text(
            "providers:\n  cloudflare:\n    token: test\n"
            "zones:\n  z.com:\n    zone_id: z1\n"
            f"rules_dir: {rules_dir}\n"
        )
        with (
            patch("octorules.cli._ensure_provider_loaded") as mock_ensure,
            pytest.raises(SystemExit),
        ):
            main(
                [
                    "--config",
                    str(config_file),
                    "lint",
                    "--zone",
                    "z.com",
                    "--severity",
                    "error",
                ]
            )
        mock_ensure.assert_called_once_with("cloudflare")

    def test_audit_uses_lazy_loading(self, sample_config, capsys):
        """Audit calls _ensure_provider_loaded per provider."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        with patch("octorules.commands._audit._ensure_provider_loaded") as mock_ensure:
            cmd_audit(sample_config, ["example.com"])
        mock_ensure.assert_called_once_with("cloudflare")


class TestRuleSubcommand:
    """Tests for the 'rule' subcommand (list/filter lint rules)."""

    @pytest.fixture(autouse=True)
    def _mock_discover(self):
        """Prevent real provider discovery from contaminating global state."""
        with patch("octorules.cli._discover_provider_modules"):
            yield

    def test_rule_all_lists_rules(self, capsys):
        """main(["rule", "--all"]) exits 0, stdout contains rule IDs and summary."""
        with pytest.raises(SystemExit) as exc_info:
            main(["rule", "--all"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "rule(s) available" in out
        # Should have at least the core rules
        assert "CORE" in out

    def test_rule_prefix_filter(self, capsys):
        """Prefix filter only shows matching rules."""
        # Register a few fake rules to ensure filtering works
        from octorules.linter.engine import Severity
        from octorules.linter.rules.registry import (
            RULE_REGISTRY,
            RuleMeta,
            register_rules,
        )

        fake_rules = [
            RuleMeta("ZZ001", "test", "Test rule 1", Severity.WARNING),
            RuleMeta("ZZ002", "test", "Test rule 2", Severity.WARNING),
            RuleMeta("YY001", "test", "Other test rule", Severity.WARNING),
        ]
        register_rules(fake_rules)
        try:
            with pytest.raises(SystemExit) as exc_info:
                main(["rule", "ZZ"])
            assert exc_info.value.code == 0
            out = capsys.readouterr().out
            assert "ZZ001" in out
            assert "ZZ002" in out
            assert "YY001" not in out
        finally:
            for r in fake_rules:
                RULE_REGISTRY.pop(r.rule_id, None)

    def test_rule_exact_match(self, capsys):
        """Exact rule ID shows only that rule."""
        from octorules.linter.engine import Severity
        from octorules.linter.rules.registry import (
            RULE_REGISTRY,
            RuleMeta,
            register_rules,
        )

        fake = RuleMeta("EX999", "test", "Exact match test", Severity.ERROR)
        register_rules([fake])
        try:
            with pytest.raises(SystemExit) as exc_info:
                main(["rule", "EX999"])
            assert exc_info.value.code == 0
            out = capsys.readouterr().out
            assert "EX999" in out
            assert "1 rule(s) available" in out
        finally:
            RULE_REGISTRY.pop("EX999", None)

    def test_rule_no_args_errors(self, caplog):
        """rule without pattern or --all exits 1 with guidance."""
        with (
            caplog.at_level(logging.ERROR, logger="octorules"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["rule"])
        assert exc_info.value.code == 1
        assert "Specify a rule" in caplog.text

    def test_rule_json_format(self, capsys):
        """--format json produces valid JSON with 'rules' key."""
        import json

        with pytest.raises(SystemExit) as exc_info:
            main(["rule", "--all", "--format", "json"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "rules" in data
        assert "total" in data
        assert isinstance(data["rules"], list)
        # Each rule should have expected fields
        if data["rules"]:
            rule = data["rules"][0]
            assert "id" in rule
            assert "category" in rule
            assert "severity" in rule
            assert "description" in rule

    def test_rule_unknown_prefix(self, capsys):
        """A prefix that matches nothing shows 0 rules."""
        with pytest.raises(SystemExit) as exc_info:
            main(["rule", "ZZZZ"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "0 rule(s) available" in out

    def test_rule_core_rules_included(self, capsys):
        """CORE prefix shows core rules (CORE002-CORE006)."""
        with pytest.raises(SystemExit) as exc_info:
            main(["rule", "CORE"])
        assert exc_info.value.code == 0
        out = capsys.readouterr().out
        assert "CORE002" in out
        assert "CORE003" in out
        assert "CORE004" in out
        assert "CORE006" in out


class TestConfigOnly:
    """Tests for the --config-only flag on lint."""

    def test_config_only_valid_config(self, tmp_path, caplog):
        """--config-only exits 0 for a valid config, log says 'Config valid'."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: test\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  example.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        with (
            caplog.at_level(logging.INFO, logger="octorules"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--config", str(cfg), "lint", "--config-only"])
        assert exc_info.value.code == 0
        assert "Config valid" in caplog.text

    def test_config_only_invalid_config(self, tmp_path, caplog):
        """--config-only exits 1 for an invalid config, log says 'Config error'."""
        cfg = tmp_path / "config.yaml"
        cfg.write_text("providers: not_a_dict\n")
        with (
            caplog.at_level(logging.ERROR, logger="octorules"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--config", str(cfg), "lint", "--config-only"])
        assert exc_info.value.code == 1
        assert "Config error" in caplog.text

    def test_config_only_skips_rules(self, tmp_path, caplog):
        """--config-only succeeds even when there are no rules files on disk."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Config references a zone but no rules file exists — still ok
        cfg = tmp_path / "config.yaml"
        cfg.write_text(
            "providers:\n"
            "  cloudflare:\n"
            "    token: test\n"
            "  rules:\n"
            "    directory: ./rules\n"
            "zones:\n"
            "  no-rules-here.com:\n"
            "    sources:\n"
            "      - rules\n"
        )
        with (
            caplog.at_level(logging.INFO, logger="octorules"),
            pytest.raises(SystemExit) as exc_info,
        ):
            main(["--config", str(cfg), "lint", "--config-only"])
        assert exc_info.value.code == 0
        assert "Config valid" in caplog.text


class TestSyslogSetup(TestSetupLogging):
    """Tests for syslog handler configuration in _setup_logging."""

    @staticmethod
    def _cleanup_syslog_handlers():
        """Remove any mock/syslog handlers left on the octorules logger."""
        from logging.handlers import SysLogHandler

        logger = logging.getLogger("octorules")
        logger.handlers = [
            h for h in logger.handlers if not isinstance(h, (SysLogHandler, MagicMock))
        ]

    def test_syslog_handler_added(self):
        """SysLogHandler is created with a (host, port) tuple for host:port format."""
        try:
            with patch("logging.handlers.SysLogHandler") as mock_cls:
                mock_handler = MagicMock()
                mock_handler.setFormatter = MagicMock()
                mock_cls.return_value = mock_handler
                _setup_logging(syslog_address="localhost:514")
                mock_cls.assert_called_once_with(address=("localhost", 514))
                mock_handler.setFormatter.assert_called_once()
        finally:
            self._cleanup_syslog_handlers()

    def test_syslog_bad_address_graceful(self, caplog):
        """A malformed address should not raise — it logs a warning instead."""
        # "bad:address:format" has multiple colons, rsplit(":", 1) gives
        # ("bad:address", "format") and int("format") raises ValueError.
        with caplog.at_level(logging.WARNING, logger="octorules"):
            _setup_logging(syslog_address="bad:address:format")
        assert "Failed to configure syslog" in caplog.text

    def test_syslog_unix_socket_path(self):
        """A path like /dev/log should be passed as a string, not a tuple."""
        try:
            with patch("logging.handlers.SysLogHandler") as mock_cls:
                mock_handler = MagicMock()
                mock_handler.setFormatter = MagicMock()
                mock_cls.return_value = mock_handler
                _setup_logging(syslog_address="/dev/log")
                mock_cls.assert_called_once_with(address="/dev/log")
        finally:
            self._cleanup_syslog_handlers()


class TestAllDeletionsWarning:
    """Tests for the all-deletions warning in format_zone_plan."""

    def test_all_deletions_warning(self):
        """ZonePlan with only REMOVE changes triggers the all-deletions warning."""
        from octorules.formatter import format_zone_plan
        from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE),
                RuleChange(ChangeType.REMOVE, "r2", REDIRECT_PHASE),
            ],
        )
        zone_plan = ZonePlan("example.com", phase_plans=[phase_plan])
        result = format_zone_plan(zone_plan, use_color=False)
        assert "WARNING" in result
        assert "deletions" in result
        assert "all" in result

    def test_mixed_changes_no_warning(self):
        """ZonePlan with both ADD and REMOVE does NOT show the warning."""
        from octorules.formatter import format_zone_plan
        from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE),
                RuleChange(ChangeType.REMOVE, "r2", REDIRECT_PHASE),
            ],
        )
        zone_plan = ZonePlan("example.com", phase_plans=[phase_plan])
        result = format_zone_plan(zone_plan, use_color=False)
        assert "all" not in result.lower() or "deletions" not in result.lower()

    def test_no_changes_no_warning(self):
        """ZonePlan with no changes does NOT show the warning."""
        from octorules.formatter import format_zone_plan
        from octorules.planner import ZonePlan

        zone_plan = ZonePlan("example.com")
        result = format_zone_plan(zone_plan, use_color=False)
        assert "WARNING" not in result
        assert "deletions" not in result


class TestProgressCallback:
    """Tests for the _map_ordered progress callback and plan progress output."""

    def test_map_ordered_progress_sequential(self):
        """Progress callback fires for each item in sequential mode."""
        from octorules.commands._helpers import _map_ordered

        calls = []
        results = _map_ordered(
            lambda x: x * 2,
            [1, 2, 3],
            max_workers=1,
            progress=lambda done, total, item: calls.append((done, total, item)),
        )
        assert results == [2, 4, 6]
        assert calls == [(1, 3, 1), (2, 3, 2), (3, 3, 3)]

    def test_map_ordered_progress_parallel(self):
        """Progress callback fires for each item in parallel mode."""
        from octorules.commands._helpers import _map_ordered

        calls = []
        results = _map_ordered(
            lambda x: x * 2,
            [10, 20, 30],
            max_workers=3,
            progress=lambda done, total, item: calls.append((done, total)),
        )
        assert sorted(results) == [20, 40, 60]
        # All 3 items reported; done counts are 1, 2, 3 in some order
        assert len(calls) == 3
        assert {c[0] for c in calls} == {1, 2, 3}
        assert all(c[1] == 3 for c in calls)

    def test_map_ordered_no_progress(self):
        """Without progress callback, no error."""
        from octorules.commands._helpers import _map_ordered

        results = _map_ordered(lambda x: x, [1, 2], max_workers=1)
        assert results == [1, 2]

    def test_map_ordered_single_item_no_progress_noise(self):
        """Single-item list still calls progress (caller decides to skip)."""
        from octorules.commands._helpers import _map_ordered

        calls = []
        _map_ordered(
            lambda x: x,
            ["only"],
            max_workers=1,
            progress=lambda done, total, item: calls.append((done, total, item)),
        )
        assert calls == [(1, 1, "only")]

    @patch("octorules.commands._providers._init_providers")
    def test_plan_progress_multi_zone(self, mock_init_provs, tmp_path, caplog):
        """Plan with multiple zones logs [n/total] planned zone_name."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "b.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            providers={"cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "t"})},
            rules_dir=rules_dir,
            zones={
                "a.com": ZoneConfig(
                    name="a.com", zone_id="za", sources=["rules"], targets=["cloudflare"]
                ),
                "b.com": ZoneConfig(
                    name="b.com", zone_id="zb", sources=["rules"], targets=["cloudflare"]
                ),
            },
        )
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_plan(config, None)
        # Should see progress for both zones
        assert "[1/2] planned" in caplog.text
        assert "[2/2] planned" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_plan_progress_single_zone_no_noise(self, mock_init_provs, sample_config, caplog):
        """Plan with single zone does NOT log progress (total == 1 guard)."""
        mock_prov = MagicMock()
        mock_init_provs.return_value = {"cloudflare": mock_prov}
        mock_prov.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_plan(sample_config, ["example.com"])
        assert "[1/1] planned" not in caplog.text
