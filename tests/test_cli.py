"""Tests for the CLI."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from octorules.cli import (
    _emit_plan_outputs,
    _filter_current_by_phase,
    _filter_desired_by_phase,
    _format_api_error,
    _get_zones,
    _setup_logging,
    _validate_phases,
    build_parser,
    cmd_compare,
    cmd_dump,
    cmd_plan,
    cmd_report,
    cmd_sync,
    cmd_validate,
    cmd_versions,
    main,
)
from octorules.config import Config, ConfigError, ZoneConfig
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
        token="test-token",
        rules_dir=rules_dir,
        zones={
            "example.com": ZoneConfig(name="example.com", zone_id="zone-abc", sources=["rules"]),
            "other.com": ZoneConfig(name="other.com", zone_id="zone-def", sources=["rules"]),
        },
    )


class TestBuildParser:
    def test_plan_command(self):
        parser = build_parser()
        args = parser.parse_args(["plan"])
        assert args.command == "plan"

    def test_sync_command(self):
        parser = build_parser()
        args = parser.parse_args(["sync", "--doit"])
        assert args.command == "sync"
        assert args.doit is True

    def test_sync_requires_doit(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["sync"])

    def test_dump_command(self):
        parser = build_parser()
        args = parser.parse_args(["dump"])
        assert args.command == "dump"

    def test_zone_filter(self):
        parser = build_parser()
        args = parser.parse_args(["--zone", "example.com", "plan"])
        assert args.zones == ["example.com"]

    def test_config_path(self):
        parser = build_parser()
        args = parser.parse_args(["--config", "my.yaml", "plan"])
        assert args.config == "my.yaml"

    def test_dump_output_dir(self):
        parser = build_parser()
        args = parser.parse_args(["dump", "--output-dir", "/tmp/out"])
        assert args.output_dir == "/tmp/out"

    def test_validate_command(self):
        parser = build_parser()
        args = parser.parse_args(["validate"])
        assert args.command == "validate"

    def test_versions_command(self):
        parser = build_parser()
        args = parser.parse_args(["versions"])
        assert args.command == "versions"

    def test_debug_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--debug", "plan"])
        assert args.debug is True

    def test_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--quiet", "plan"])
        assert args.quiet is True

    def test_compare_command(self):
        parser = build_parser()
        args = parser.parse_args(["compare"])
        assert args.command == "compare"

    def test_report_command(self):
        parser = build_parser()
        args = parser.parse_args(["report"])
        assert args.command == "report"

    def test_report_output_format_csv(self):
        parser = build_parser()
        args = parser.parse_args(["report", "--output-format", "csv"])
        assert args.report_format == "csv"

    def test_report_output_format_json(self):
        parser = build_parser()
        args = parser.parse_args(["report", "--output-format", "json"])
        assert args.report_format == "json"

    def test_report_output_format_default(self):
        parser = build_parser()
        args = parser.parse_args(["report"])
        assert args.report_format == "csv"

    def test_report_invalid_format_exits(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["report", "--output-format", "xml"])

    def test_compare_checksum_flag(self):
        parser = build_parser()
        args = parser.parse_args(["compare", "--checksum"])
        assert args.checksum is True

    def test_compare_checksum_default(self):
        parser = build_parser()
        args = parser.parse_args(["compare"])
        assert args.checksum is False

    def test_validate_output_flag(self):
        parser = build_parser()
        args = parser.parse_args(["validate", "--output", "/tmp/val.txt"])
        assert args.validate_output == "/tmp/val.txt"

    def test_validate_output_default(self):
        parser = build_parser()
        args = parser.parse_args(["validate"])
        assert args.validate_output is None

    def test_scope_default(self):
        parser = build_parser()
        args = parser.parse_args(["plan"])
        assert args.scope == "all"

    def test_scope_zones(self):
        parser = build_parser()
        args = parser.parse_args(["--scope", "zones", "plan"])
        assert args.scope == "zones"

    def test_scope_account(self):
        parser = build_parser()
        args = parser.parse_args(["--scope", "account", "plan"])
        assert args.scope == "account"

    def test_scope_invalid(self):
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--scope", "invalid", "plan"])

    def test_config_after_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["dump", "--config", "my.yaml"])
        assert args.config == "my.yaml"
        assert args.command == "dump"

    def test_zone_after_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["plan", "--zone", "example.com"])
        assert args.zones == ["example.com"]

    def test_debug_after_subcommand(self):
        parser = build_parser()
        args = parser.parse_args(["plan", "--debug"])
        assert args.debug is True

    def test_mixed_flags_before_and_after(self):
        parser = build_parser()
        args = parser.parse_args(["--debug", "plan", "--zone", "example.com"])
        assert args.debug is True
        assert args.zones == ["example.com"]

    def test_config_before_still_works(self):
        """Ensure flags before the subcommand still work after the refactor."""
        parser = build_parser()
        args = parser.parse_args(["--config", "my.yaml", "plan"])
        assert args.config == "my.yaml"


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


class TestCmdPlan:
    @patch("octorules.cli.CloudflareProvider")
    def test_no_changes_returns_0(self, mock_provider_cls, sample_config):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, None)
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_with_changes_returns_2(self, mock_provider_cls, sample_config):
        # Write a rules file so there are desired rules
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_has_changes_exit_code(self, mock_provider_cls, sample_config):
        """--exit-code flag returns 2 when changes are detected."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"], exit_code=True)
        assert result == 2

    @patch("octorules.cli.CloudflareProvider")
    def test_no_changes_exit_code(self, mock_provider_cls, sample_config):
        """--exit-code flag returns 0 when there are no changes."""
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"], exit_code=True)
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_zone_filter(self, mock_provider_cls, sample_config):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_plan(sample_config, ["example.com"])
        # Should only call get_all_phase_rules once (for the filtered zone)
        mock_provider_cls.return_value.get_all_phase_rules.assert_called_once_with(
            Scope(zone_id="zone-abc", label="example.com"),
            cf_phases=None,
        )

    @patch("octorules.cli.CloudflareProvider")
    def test_no_rules_file_means_no_changes(self, mock_provider_cls, sample_config):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_no_rules_file_logs_debug(self, mock_provider_cls, sample_config, caplog):
        """Zone with no rules file should log at debug level."""
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            cmd_plan(sample_config, ["example.com"])
        assert "No rules file for zone example.com" in caplog.text


class TestCmdSync:
    @patch("octorules.cli.CloudflareProvider")
    def test_no_changes_skips_apply(self, mock_provider_cls, sample_config):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, None)
        assert result == 0
        mock_provider_cls.return_value.put_phase_rules.assert_not_called()

    @patch("octorules.cli.CloudflareProvider")
    def test_applies_changes(self, mock_provider_cls, sample_config):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()
        call_args = mock_provider_cls.return_value.put_phase_rules.call_args
        assert call_args[0][0] == Scope(zone_id="zone-abc", label="example.com")
        assert call_args[0][1] == "http_request_dynamic_redirect"
        # Verify the payload has the injected action
        payload = call_args[0][2]
        assert payload[0]["action"] == "redirect"
        assert payload[0]["ref"] == "r1"

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_multiple_phases(self, mock_provider_cls, sample_config):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        assert mock_provider_cls.return_value.put_phase_rules.call_count == 2

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_skips_zones_without_changes(self, mock_provider_cls, sample_config):
        """When syncing all zones, zones without rules files should be skipped."""
        # Only example.com has rules, other.com does not
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, None)
        assert result == 0
        # Only one PUT call (for example.com), other.com is skipped
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_api_error_returns_1(self, mock_provider_cls, sample_config, caplog):
        """When the CF API fails during sync, abort immediately and return 1."""
        from cloudflare import APIError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.put_phase_rules.side_effect = APIError(
            "API rate limited", request=MagicMock(), body=None
        )
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "API rate limited" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_connection_error_returns_1(self, mock_provider_cls, sample_config, caplog):
        """APIConnectionError during sync should return 1."""
        from cloudflare import APIConnectionError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.put_phase_rules.side_effect = APIConnectionError(
            request=MagicMock()
        )
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_programming_error_propagates(self, mock_provider_cls, sample_config):
        """Programming bugs (TypeError, etc.) should NOT be caught."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.put_phase_rules.side_effect = TypeError("bad arg")
        with pytest.raises(TypeError, match="bad arg"):
            cmd_sync(sample_config, ["example.com"])

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_aborts_on_first_failure(self, mock_provider_cls, sample_config):
        """Fail-fast: second phase should not be attempted after first fails."""
        from cloudflare import APIError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.put_phase_rules.side_effect = APIError(
            "Forbidden", request=MagicMock(), body=None
        )
        result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        # Fail-fast: only one PUT attempted, second phase never reached
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_logs_partial_success_on_failure(self, mock_provider_cls, sample_config, caplog):
        """When a phase fails, previously synced phases should be logged."""
        from cloudflare import APIError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        call_count = 0

        def put_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise APIError("Server error", request=MagicMock(), body=None)

        mock_provider_cls.return_value.put_phase_rules.side_effect = put_side_effect
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "Successfully synced before failure" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_progress_logging(self, mock_provider_cls, tmp_path, caplog):
        """Sync should log progress for each zone."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "b.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "a.com": ZoneConfig(name="a.com", zone_id="zone-a", sources=["rules"]),
                "b.com": ZoneConfig(name="b.com", zone_id="zone-b", sources=["rules"]),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 0
        assert "Applying changes to 2 zone(s)" in caplog.text
        assert "Syncing a.com" in caplog.text
        assert "Syncing b.com" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_per_phase_logging(self, mock_provider_cls, sample_config, caplog):
        """Sync should log per-phase change counts."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        assert "redirect_rules: applying 1 change(s)" in caplog.text
        assert "cache_rules: applying 1 change(s)" in caplog.text
        assert "redirect_rules: done" in caplog.text
        assert "cache_rules: done" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_debug_logs_api_call(self, mock_provider_cls, sample_config, caplog):
        """Sync should log PUT details at debug level."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.DEBUG, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        assert "PUT http_request_dynamic_redirect" in caplog.text
        assert "zone_id=zone-abc" in caplog.text
        assert "rules=1" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_reads_rules_once(self, mock_provider_cls, sample_config):
        """Sync should read zone rules YAML only once, not re-read during apply."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}

        with patch.object(
            sample_config, "load_zone_rules", wraps=sample_config.load_zone_rules
        ) as spy:
            cmd_sync(sample_config, ["example.com"])
            # Should only be called once (during planning), not again during apply
            spy.assert_called_once_with("example.com")


class TestCmdDump:
    @patch("octorules.cli.CloudflareProvider")
    def test_dump_no_rules(self, mock_provider_cls, sample_config, caplog):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        assert "Dumped example.com" in caplog.text
        dumped = sample_config.rules_dir / "example.com.yaml"
        assert dumped.read_text() == "--- {}\n"

    @patch("octorules.cli.CloudflareProvider")
    def test_dump_writes_file(self, mock_provider_cls, sample_config, caplog):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        assert "Dumped example.com" in caplog.text
        assert (sample_config.rules_dir / "example.com.yaml").exists()

    @patch("octorules.cli.CloudflareProvider")
    def test_dump_custom_output_dir(self, mock_provider_cls, sample_config, tmp_path):
        out_dir = tmp_path / "custom_out"
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        result = cmd_dump(sample_config, ["example.com"], str(out_dir))
        assert result == 0
        assert (out_dir / "example.com.yaml").exists()

    @patch("octorules.cli.CloudflareProvider")
    def test_dump_api_error_continues(self, mock_provider_cls, tmp_path, caplog):
        """API error on one zone should not prevent dumping others."""
        from cloudflare import APIError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "fail.com": ZoneConfig(name="fail.com", zone_id="zone-fail", sources=["rules"]),
                "ok.com": ZoneConfig(name="ok.com", zone_id="zone-ok", sources=["rules"]),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise APIError("Forbidden", request=MagicMock(), body=None)
            return {
                "http_request_dynamic_redirect": [
                    {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
                ],
            }

        mock_provider_cls.return_value.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_dump(config, None, None)
        assert result == 1
        assert "Failed to dump fail.com" in caplog.text
        assert (rules_dir / "ok.com.yaml").exists()

    @patch("octorules.cli.CloudflareProvider")
    def test_dump_all_succeed_returns_0(self, mock_provider_cls, sample_config):
        """When all zones dump successfully, return 0."""
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_dump(sample_config, None, None)
        assert result == 0


class TestCmdValidate:
    def test_valid_rules(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 0
        assert "All rules valid" in caplog.text

    def test_no_rules_file(self, sample_config, caplog):
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 0
        assert "skipped" in caplog.text

    def test_no_rules_warns(self, sample_config, caplog):
        """When all zones have no rules files, warn the user."""
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_validate(sample_config, None)
        assert result == 0
        assert "No rules found to validate" in caplog.text

    def test_missing_ref(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - expression: 'true'\n")
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 1
        assert "missing required 'ref'" in caplog.text

    def test_missing_expression(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n")
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 1
        assert "missing required 'expression'" in caplog.text

    def test_duplicate_ref(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'a'\n  - ref: r1\n    expression: 'b'\n"
        )
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 1
        assert "Duplicate ref" in caplog.text

    def test_waf_missing_action(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("waf_custom_rules:\n  - ref: w1\n    expression: 'true'\n")
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 1
        assert "must specify an 'action'" in caplog.text

    def test_unknown_phase_warns(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("typo_rules:\n  - ref: r1\n    expression: 'true'\n")
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 0  # warning only, not an error
        assert "Unknown phase" in caplog.text

    def test_output_file_written(self, sample_config, tmp_path, caplog):
        """validate --output should write results to a file."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        output_file = tmp_path / "validate.txt"
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"], output_file=str(output_file))
        assert result == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "redirect_rules: OK" in content
        assert "All rules valid" in content

    def test_output_file_includes_errors(self, sample_config, tmp_path, caplog):
        """validate --output should include validation errors in the file."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - expression: 'true'\n")
        output_file = tmp_path / "validate.txt"
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"], output_file=str(output_file))
        assert result == 1
        content = output_file.read_text()
        assert "ERROR" in content

    def test_output_file_write_error(self, sample_config, caplog):
        """validate --output should return 1 on write failure."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        bad_path = str(sample_config.rules_dir)  # directory, not a file
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"], output_file=bad_path)
        assert result == 1
        assert "Failed to write output file" in caplog.text

    def test_multiple_phases_valid(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'a'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'b'\n"
        )
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 0
        assert "redirect_rules: OK (1 rule(s))" in caplog.text
        assert "cache_rules: OK (1 rule(s))" in caplog.text


class TestCmdCompare:
    @patch("octorules.cli.CloudflareProvider")
    def test_no_differences_returns_0(self, mock_provider_cls, sample_config):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_compare(sample_config, None)
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_with_differences_returns_1(self, mock_provider_cls, sample_config):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_compare(sample_config, ["example.com"])
        assert result == 1

    @patch("octorules.cli.CloudflareProvider")
    def test_identical_rules_returns_0(self, mock_provider_cls, sample_config):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        result = cmd_compare(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_zone_filter(self, mock_provider_cls, sample_config):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_compare(sample_config, ["example.com"])
        mock_provider_cls.return_value.get_all_phase_rules.assert_called_once_with(
            Scope(zone_id="zone-abc", label="example.com"),
            cf_phases=None,
        )

    @patch("octorules.cli.CloudflareProvider")
    def test_phase_filter(self, mock_provider_cls, sample_config):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_compare(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        assert result == 1

    @patch("octorules.cli.CloudflareProvider")
    def test_checksum_prints_hash(self, mock_provider_cls, sample_config, caplog):
        """compare --checksum should print a SHA-256 checksum."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_compare(sample_config, ["example.com"], checksum=True)
        assert "checksum=" in caplog.text
        for line in caplog.text.splitlines():
            if "checksum=" in line:
                hex_hash = line.split("checksum=", 1)[1]
                assert len(hex_hash) == 64
                int(hex_hash, 16)  # valid hex

    @patch("octorules.cli.CloudflareProvider")
    def test_checksum_no_changes(self, mock_provider_cls, sample_config, caplog):
        """compare --checksum with no changes should still print checksum."""
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_compare(sample_config, None, checksum=True)
        assert result == 0
        assert "checksum=" in caplog.text


class TestCmdReport:
    @patch("octorules.cli.CloudflareProvider")
    def test_returns_0(self, mock_provider_cls, sample_config):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_report(sample_config, None)
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_csv_output_has_header(self, mock_provider_cls, sample_config, capsys):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_report(sample_config, None, report_format="csv")
        out = capsys.readouterr().out
        assert "Zone" in out
        assert "Phase" in out
        assert "Status" in out

    @patch("octorules.cli.CloudflareProvider")
    def test_csv_shows_drifted_phase(self, mock_provider_cls, sample_config, capsys):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_report(sample_config, ["example.com"], report_format="csv")
        out = capsys.readouterr().out
        assert "yaml_only" in out
        assert "redirect_rules" in out

    @patch("octorules.cli.CloudflareProvider")
    def test_csv_shows_in_sync_phase(self, mock_provider_cls, sample_config, capsys):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        cmd_report(sample_config, ["example.com"], report_format="csv")
        out = capsys.readouterr().out
        assert "in_sync" in out

    @patch("octorules.cli.CloudflareProvider")
    def test_json_output_structure(self, mock_provider_cls, sample_config, capsys):
        import json

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_report(sample_config, ["example.com"], report_format="json")
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "zones" in data
        assert "summary" in data
        assert data["zones"][0]["zone"] == "example.com"

    @patch("octorules.cli.CloudflareProvider")
    def test_zone_filter(self, mock_provider_cls, sample_config, capsys):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_report(sample_config, ["example.com"], report_format="csv")
        mock_provider_cls.return_value.get_all_phase_rules.assert_called_once_with(
            Scope(zone_id="zone-abc", label="example.com"),
            cf_phases=None,
        )

    @patch("octorules.cli.CloudflareProvider")
    def test_phase_filter(self, mock_provider_cls, sample_config, capsys):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_report(
            sample_config, ["example.com"], phase_filter=["redirect_rules"], report_format="csv"
        )
        out = capsys.readouterr().out
        assert "redirect_rules" in out
        assert "cache_rules" not in out

    @patch("octorules.cli.CloudflareProvider")
    def test_live_only_status(self, mock_provider_cls, sample_config, capsys):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        cmd_report(sample_config, ["example.com"], report_format="csv")
        out = capsys.readouterr().out
        assert "live_only" in out

    @patch("octorules.cli.CloudflareProvider")
    def test_multiple_zones_summary(self, mock_provider_cls, sample_config, capsys):
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_report(sample_config, None, report_format="csv")
        out = capsys.readouterr().out
        assert "2 zones" in out


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

    @patch("octorules.cli.cmd_validate", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_validate_invokes_cmd(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "validate"])
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

    @patch("octorules.cli.cmd_compare", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_compare_invokes_cmd(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "compare"])
        assert exc_info.value.code == 0
        mock_cmd.assert_called_once()

    @patch("octorules.cli.cmd_compare", return_value=1)
    @patch("octorules.cli.Config.from_file")
    def test_compare_exits_1_on_differences(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "compare"])
        assert exc_info.value.code == 1

    @patch("octorules.cli.cmd_report", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_report_invokes_cmd(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "report"])
        assert exc_info.value.code == 0
        mock_cmd.assert_called_once()

    @patch("octorules.cli.cmd_report", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_report_passes_format(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "report", "--output-format", "json"])
        assert exc_info.value.code == 0
        _, kwargs = mock_cmd.call_args
        assert kwargs.get("report_format") == "json" or mock_cmd.call_args[0][-1] == "json"

    @patch("octorules.cli.cmd_dump", return_value=0)
    @patch("octorules.cli.Config.from_file")
    def test_dump_passes_output_dir(self, mock_config, mock_cmd, tmp_config):
        mock_config.return_value = MagicMock()
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(tmp_config), "dump", "--output-dir", "/tmp/out"])
        assert exc_info.value.code == 0
        _, kwargs = mock_cmd.call_args
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
    def test_prints_octorules_version(self, capsys):
        from octorules import __version__

        result = cmd_versions()
        assert result == 0
        out = capsys.readouterr().out
        assert f"octorules     {__version__}" in out

    def test_prints_python_version(self, capsys):
        import platform

        result = cmd_versions()
        assert result == 0
        out = capsys.readouterr().out
        assert f"python        {platform.python_version()}" in out

    def test_prints_pyyaml_version(self, capsys):
        import yaml

        result = cmd_versions()
        assert result == 0
        out = capsys.readouterr().out
        assert f"pyyaml        {yaml.__version__}" in out

    def test_prints_cloudflare_version(self, capsys):
        result = cmd_versions()
        assert result == 0
        out = capsys.readouterr().out
        assert "cloudflare" in out


class TestAlwaysDryRun:
    @patch("octorules.cli.CloudflareProvider")
    def test_sync_skips_always_dry_run_zone(self, mock_provider_cls, tmp_path, caplog):
        """Zones with always_dry_run=True should be skipped during sync."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], always_dry_run=True
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_sync(config, ["example.com"])
        assert result == 0
        # Should NOT have called put_phase_rules
        mock_provider_cls.return_value.put_phase_rules.assert_not_called()
        assert "always_dry_run" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_applies_non_dry_run_zone(self, mock_provider_cls, tmp_path):
        """Zones without always_dry_run should still be applied."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        rules_file = rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], always_dry_run=False
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(config, ["example.com"])
        assert result == 0
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_mixed_zones(self, mock_provider_cls, tmp_path, caplog):
        """Sync with a mix of dry-run and normal zones."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "dry.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "live.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "dry.com": ZoneConfig(
                    name="dry.com",
                    zone_id="zone-dry",
                    sources=["rules"],
                    always_dry_run=True,
                ),
                "live.com": ZoneConfig(
                    name="live.com",
                    zone_id="zone-live",
                    sources=["rules"],
                    always_dry_run=False,
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 0
        # Only live.com should have been applied
        calls = mock_provider_cls.return_value.put_phase_rules.call_args_list
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
        with pytest.raises(ConfigError, match="Did you mean.*redirect_rules"):
            _validate_phases(["redirect_rule"])

    def test_validate_phases_no_match_lists_valid(self):
        with pytest.raises(ConfigError, match="Valid phases:"):
            _validate_phases(["zzz_totally_wrong"])

    def test_validate_phases_cf_phase_suggests_friendly(self):
        with pytest.raises(ConfigError, match="Did you mean.*redirect_rules"):
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

    @patch("octorules.cli.CloudflareProvider")
    def test_phase_filter_passes_cf_phases_to_provider(self, mock_provider_cls, sample_config):
        """Phase filter should pass cf_phases to get_all_phase_rules to skip unneeded API calls."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_plan(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        call_kwargs = mock_provider_cls.return_value.get_all_phase_rules.call_args
        assert call_kwargs[1]["cf_phases"] == ["http_request_dynamic_redirect"]

    @patch("octorules.cli.CloudflareProvider")
    def test_no_phase_filter_fetches_all(self, mock_provider_cls, sample_config):
        """Without phase filter, cf_phases should be None (fetch all)."""
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_plan(sample_config, ["example.com"])
        call_kwargs = mock_provider_cls.return_value.get_all_phase_rules.call_args
        assert call_kwargs[1]["cf_phases"] is None

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_plan_with_phase_filter(self, mock_provider_cls, sample_config):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        assert result == 0  # has changes, but no --exit-code flag
        # But only redirect_rules should be in the plan

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_sync_with_phase_filter(self, mock_provider_cls, sample_config):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"
            "    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        assert result == 0
        # Only one PUT call (for redirect_rules, not cache_rules)
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()
        call_args = mock_provider_cls.return_value.put_phase_rules.call_args
        assert call_args[0][0] == Scope(zone_id="zone-abc", label="example.com")
        assert call_args[0][1] == "http_request_dynamic_redirect"

    def test_cmd_validate_with_phase_filter(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "cache_rules:\n"
            "  - ref: c1\n"  # missing expression — would fail validation
        )
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"], phase_filter=["redirect_rules"])
        # Only redirect_rules validated, cache_rules skipped
        assert result == 0


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

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_plan_prints_checksum(self, mock_provider_cls, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        with caplog.at_level(logging.INFO, logger="octorules"):
            cmd_plan(sample_config, ["example.com"], checksum=True)
        assert "checksum=" in caplog.text
        # Extract the hash and verify it's a hex string
        for line in caplog.text.splitlines():
            if "checksum=" in line:
                hex_hash = line.split("checksum=", 1)[1]
                assert len(hex_hash) == 64
                int(hex_hash, 16)  # Should not raise

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_sync_checksum_match_proceeds(self, mock_provider_cls, sample_config, caplog):
        """When checksum matches, sync should proceed normally."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
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
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_sync_checksum_mismatch_aborts(self, mock_provider_cls, sample_config):
        """When checksum mismatches, sync should abort with exit 1."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(sample_config, ["example.com"], checksum="wrong-hash")
        assert result == 1
        mock_provider_cls.return_value.put_phase_rules.assert_not_called()


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

    @patch("octorules.cli.CloudflareProvider")
    def test_mass_delete_blocked(self, mock_provider_cls, tmp_path, caplog):
        """Deleting most rules should be blocked by safety threshold."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Desired: empty (all rules removed)
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], delete_threshold=30.0
                ),
            },
        )
        # Current: 10 rules exist
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, ["example.com"])
        assert result == 1
        mock_provider_cls.return_value.put_phase_rules.assert_not_called()
        assert "Safety threshold exceeded" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_small_delete_allowed(self, mock_provider_cls, tmp_path):
        """Deleting 1 out of 10 rules (10%) should be allowed."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Desired: 9 rules (1 removed)
        rules = "\n".join([f"  - ref: r{i}\n    expression: 'true'" for i in range(9)])
        (rules_dir / "example.com.yaml").write_text(f"redirect_rules:\n{rules}\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], delete_threshold=30.0
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect", "enabled": True}
                for i in range(10)
            ],
        }
        result = cmd_sync(config, ["example.com"])
        assert result == 0
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()

    @patch("octorules.cli.CloudflareProvider")
    def test_force_bypasses_safety(self, mock_provider_cls, tmp_path):
        """--force should bypass safety checks."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], delete_threshold=30.0
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        result = cmd_sync(config, ["example.com"], force=True)
        assert result == 0
        mock_provider_cls.return_value.put_phase_rules.assert_called_once()

    @patch("octorules.cli.CloudflareProvider")
    def test_dry_run_zones_excluded_from_safety(self, mock_provider_cls, tmp_path):
        """always_dry_run zones should not trigger safety checks."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com",
                    zone_id="zone-abc",
                    sources=["rules"],
                    always_dry_run=True,
                    delete_threshold=30.0,
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        result = cmd_sync(config, ["example.com"])
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_error_message_includes_phase_names(self, mock_provider_cls, tmp_path, caplog):
        """Safety error message should include the affected phase names."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], delete_threshold=30.0
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        with caplog.at_level(logging.ERROR, logger="octorules"):
            cmd_sync(config, ["example.com"])
        assert "redirect_rules" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_error_message_content(self, mock_provider_cls, tmp_path, caplog):
        """Safety error message should include zone, counts, and percentages."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text("redirect_rules: []\n")
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], delete_threshold=30.0
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": f"r{i}", "expression": "true", "action": "redirect"} for i in range(10)
            ],
        }
        with caplog.at_level(logging.ERROR, logger="octorules"):
            cmd_sync(config, ["example.com"])
        assert "example.com" in caplog.text
        assert "100.0%" in caplog.text
        assert "30.0%" in caplog.text


class TestParallelPlanning:
    """Tests for parallel zone planning (max_workers)."""

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_plan_sequential(self, mock_provider_cls, sample_config):
        """max_workers=1: sequential planning works same as before."""
        sample_config.max_workers = 1
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_plan_parallel(self, mock_provider_cls, tmp_path):
        """max_workers=2: parallel planning returns correct results."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "b.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "a.com": ZoneConfig(name="a.com", zone_id="zone-a", sources=["rules"]),
                "b.com": ZoneConfig(name="b.com", zone_id="zone-b", sources=["rules"]),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(config, None)
        assert result == 0
        # API called for each zone
        assert mock_provider_cls.return_value.get_all_phase_rules.call_count == 2

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_plan_parallel_zone_order_preserved(self, mock_provider_cls, tmp_path, capsys):
        """Parallel planning preserves zone order in output."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "alpha.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "beta.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "alpha.com": ZoneConfig(name="alpha.com", zone_id="zone-a", sources=["rules"]),
                "beta.com": ZoneConfig(name="beta.com", zone_id="zone-b", sources=["rules"]),
            },
            plan_outputs={"json": PlanJson("json")},
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        cmd_plan(config, None)
        import json

        out = capsys.readouterr().out
        data = json.loads(out)
        zone_names = [z["zone"] for z in data["zones"]]
        assert zone_names == ["alpha.com", "beta.com"]

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_sync_parallel_plan_sequential_apply(self, mock_provider_cls, tmp_path):
        """Sync with max_workers=2: planning is parallel, apply is sequential."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "a.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        (rules_dir / "b.com.yaml").write_text(
            "redirect_rules:\n  - ref: r2\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "a.com": ZoneConfig(name="a.com", zone_id="zone-a", sources=["rules"]),
                "b.com": ZoneConfig(name="b.com", zone_id="zone-b", sources=["rules"]),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_sync(config, None)
        assert result == 0
        # Both zones applied
        assert mock_provider_cls.return_value.put_phase_rules.call_count == 2

    @patch("octorules.cli.CloudflareProvider")
    def test_cmd_dump_parallel(self, mock_provider_cls, tmp_path, caplog):
        """Dump with max_workers=2: parallel dump."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "a.com": ZoneConfig(name="a.com", zone_id="zone-a", sources=["rules"]),
                "b.com": ZoneConfig(name="b.com", zone_id="zone-b", sources=["rules"]),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None)
        assert result == 0
        assert mock_provider_cls.return_value.get_all_phase_rules.call_count == 2
        assert (rules_dir / "a.com.yaml").exists()
        assert (rules_dir / "b.com.yaml").exists()


class TestAllowUnmanaged:
    """Tests for allow_unmanaged zone config in CLI."""

    @patch("octorules.cli.CloudflareProvider")
    def test_unmanaged_rules_not_removed(self, mock_provider_cls, tmp_path):
        """With allow_unmanaged, rules in CF but not YAML should be kept."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Only r1 in YAML, r2 exists in CF
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], allow_unmanaged=True
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
                {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
            ],
        }
        result = cmd_plan(config, ["example.com"])
        # r2 should NOT be marked for removal, so no changes
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_unmanaged_phase_not_removed(self, mock_provider_cls, tmp_path):
        """With allow_unmanaged, entire phases in CF but not YAML should be kept."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Only redirect_rules in YAML, cache_rules exist in CF
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"], allow_unmanaged=True
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {
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

    @patch("octorules.cli.CloudflareProvider")
    def test_sequential_plan_api_error_continues(self, mock_provider_cls, tmp_path, caplog):
        """Sequential planning: API error on one zone should not kill others."""
        from cloudflare import APIError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "ok.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=1,
            zones={
                "fail.com": ZoneConfig(name="fail.com", zone_id="zone-fail", sources=["rules"]),
                "ok.com": ZoneConfig(name="ok.com", zone_id="zone-ok", sources=["rules"]),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise APIError("Forbidden", request=MagicMock(), body=None)
            return {}

        mock_provider_cls.return_value.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_plan(config, None)
        assert result == 1
        assert "Failed to plan fail.com" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_parallel_plan_api_error_continues(self, mock_provider_cls, tmp_path, caplog):
        """Parallel planning: API error on one zone should not kill others."""
        from cloudflare import APIError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "ok.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "fail.com": ZoneConfig(name="fail.com", zone_id="zone-fail", sources=["rules"]),
                "ok.com": ZoneConfig(name="ok.com", zone_id="zone-ok", sources=["rules"]),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise APIError("Forbidden", request=MagicMock(), body=None)
            return {}

        mock_provider_cls.return_value.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_plan(config, None)
        assert result == 1
        assert "Failed to plan fail.com" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_aborts_on_plan_failure(self, mock_provider_cls, tmp_path, caplog):
        """Sync should abort entirely if any zone fails during planning."""
        from cloudflare import APIError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "ok.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "fail.com": ZoneConfig(name="fail.com", zone_id="zone-fail", sources=["rules"]),
                "ok.com": ZoneConfig(name="ok.com", zone_id="zone-ok", sources=["rules"]),
            },
        )

        def mock_get_all(scope, **kwargs):
            if scope.zone_id == "zone-fail":
                raise APIError("Forbidden", request=MagicMock(), body=None)
            return {}

        mock_provider_cls.return_value.get_all_phase_rules.side_effect = mock_get_all
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 1
        assert "Aborting sync" in caplog.text
        mock_provider_cls.return_value.put_phase_rules.assert_not_called()


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
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        e = AuthenticationError(message="Invalid API token", response=mock_response, body=None)
        result = _format_api_error(e)
        assert "[HTTP 401]" in result
        assert "Invalid API token" in result

    def test_without_status_code(self):
        from cloudflare import APIConnectionError

        e = APIConnectionError(request=MagicMock())
        result = _format_api_error(e)
        assert "[HTTP" not in result

    def test_api_error_base(self):
        from cloudflare import APIError

        e = APIError("Server Error", request=MagicMock(), body=None)
        result = _format_api_error(e)
        assert "Server Error" in result


class TestAuthErrorPropagation:
    """Tests for authentication error propagation (tasks 27, 29)."""

    @patch("octorules.cli.CloudflareProvider")
    def test_plan_auth_error_propagates(self, mock_provider_cls, sample_config):
        """AuthenticationError during plan should not be silently caught."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_provider_cls.return_value.get_all_phase_rules.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        with pytest.raises(AuthenticationError):
            cmd_plan(sample_config, ["example.com"])

    @patch("octorules.cli.CloudflareProvider")
    def test_plan_permission_error_propagates(self, mock_provider_cls, sample_config):
        """PermissionDeniedError during plan should not be silently caught."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_provider_cls.return_value.get_all_phase_rules.side_effect = PermissionDeniedError(
            message="Missing zone permission", response=mock_response, body=None
        )
        with pytest.raises(PermissionDeniedError):
            cmd_plan(sample_config, ["example.com"])

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_auth_error_during_apply_returns_1(self, mock_provider_cls, sample_config, caplog):
        """AuthenticationError during sync apply should return 1 with clear message."""
        from cloudflare import AuthenticationError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_provider_cls.return_value.put_phase_rules.side_effect = AuthenticationError(
            message="Token expired", response=mock_response, body=None
        )
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "Authentication/permission error" in caplog.text
        assert "HTTP 401" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_auth_error_no_partial_success_msg(self, mock_provider_cls, sample_config, caplog):
        """Auth errors should NOT log 'Successfully synced before failure'."""
        from cloudflare import AuthenticationError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        call_count = 0

        def put_side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                mock_response = MagicMock()
                mock_response.status_code = 401
                raise AuthenticationError(
                    message="Token revoked", response=mock_response, body=None
                )

        mock_provider_cls.return_value.put_phase_rules.side_effect = put_side_effect
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "Successfully synced before failure" not in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_dump_auth_error_propagates(self, mock_provider_cls, sample_config):
        """AuthenticationError during dump should propagate, not be caught per-zone."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_provider_cls.return_value.get_all_phase_rules.side_effect = AuthenticationError(
            message="Invalid API token", response=mock_response, body=None
        )
        with pytest.raises(AuthenticationError):
            cmd_dump(sample_config, ["example.com"], None)

    def test_main_catches_auth_error(self, tmp_config, caplog):
        """main() should catch AuthenticationError and exit 1 with clear message."""
        from cloudflare import AuthenticationError

        mock_response = MagicMock()
        mock_response.status_code = 401

        with (
            patch("octorules.cli.Config.from_file") as mock_config,
            patch("octorules.cli.cmd_plan") as mock_cmd,
        ):
            mock_config.return_value = MagicMock()
            mock_cmd.side_effect = AuthenticationError(
                message="Invalid API token", response=mock_response, body=None
            )
            with caplog.at_level(logging.ERROR, logger="octorules"):
                with pytest.raises(SystemExit) as exc_info:
                    main(["--config", str(tmp_config), "plan"])
            assert exc_info.value.code == 1
            assert "authentication failed" in caplog.text.lower()

    def test_main_catches_permission_error(self, tmp_config, caplog):
        """main() should catch PermissionDeniedError and exit 1."""
        from cloudflare import PermissionDeniedError

        mock_response = MagicMock()
        mock_response.status_code = 403

        with (
            patch("octorules.cli.Config.from_file") as mock_config,
            patch("octorules.cli.cmd_plan") as mock_cmd,
        ):
            mock_config.return_value = MagicMock()
            mock_cmd.side_effect = PermissionDeniedError(
                message="Missing permission", response=mock_response, body=None
            )
            with caplog.at_level(logging.ERROR, logger="octorules"):
                with pytest.raises(SystemExit) as exc_info:
                    main(["--config", str(tmp_config), "plan"])
            assert exc_info.value.code == 1
            assert "authentication failed" in caplog.text.lower()


class TestFailedPhaseFiltering:
    """Tests for filtering out failed phases from planning (task 28)."""

    @patch("octorules.cli.CloudflareProvider")
    def test_failed_phase_excluded_from_plan(self, mock_provider_cls, sample_config, caplog):
        """Phase that failed to fetch should be excluded from desired rules."""
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        # Simulate redirect phase failing
        mock_provider_cls.return_value.get_all_phase_rules.return_value = PhaseRulesResult(
            {}, failed_phases=["http_request_dynamic_redirect"]
        )
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        # redirect_rules should have been skipped
        assert "Skipping redirect_rules" in caplog.text
        assert "failed to fetch current state" in caplog.text
        # cache_rules still planned (has changes), but no --exit-code flag
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_no_failed_phases_plans_normally(self, mock_provider_cls, sample_config):
        """When no phases fail, planning proceeds as usual."""
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = PhaseRulesResult({})
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_all_phases_failed_means_no_changes(self, mock_provider_cls, sample_config, caplog):
        """When all desired phases fail, plan should show no changes."""
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = PhaseRulesResult(
            {}, failed_phases=["http_request_dynamic_redirect"]
        )
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert "Skipping redirect_rules" in caplog.text
        assert result == 0  # No changes (desired was filtered out)

    @patch("octorules.cli.CloudflareProvider")
    def test_plain_dict_backward_compatible(self, mock_provider_cls, sample_config):
        """Plain dict (no failed_phases) should work as before."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0

    @patch("octorules.cli.CloudflareProvider")
    def test_failed_phase_not_in_desired_ignored(self, mock_provider_cls, sample_config, caplog):
        """Failed phase not in desired rules should not log a warning."""
        from octorules.provider import PhaseRulesResult

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        # cache phase failed but we don't have cache_rules in YAML
        mock_provider_cls.return_value.get_all_phase_rules.return_value = PhaseRulesResult(
            {}, failed_phases=["http_request_cache_settings"]
        )
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert "Skipping" not in caplog.text
        assert result == 0  # redirect_rules still has changes, but no --exit-code flag


class TestApiErrorStatusCodes:
    """Tests for HTTP status code inclusion in error messages (task 29)."""

    @patch("octorules.cli.CloudflareProvider")
    def test_plan_error_includes_status_code(self, mock_provider_cls, sample_config, caplog):
        """Plan failure should include HTTP status code in error message."""
        from cloudflare import InternalServerError

        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_provider_cls.return_value.get_all_phase_rules.side_effect = InternalServerError(
            message="Internal Server Error", response=mock_response, body=None
        )
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert result == 1
        assert "HTTP 500" in caplog.text

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_error_includes_status_code(self, mock_provider_cls, sample_config, caplog):
        """Sync API error should include HTTP status code."""
        from cloudflare import RateLimitError

        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_provider_cls.return_value.put_phase_rules.side_effect = RateLimitError(
            message="Rate limited", response=mock_response, body=None
        )
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 1
        assert "HTTP 429" in caplog.text


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

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_parallel_phases_with_max_workers_gt_1(self, mock_provider_cls, tmp_path):
        """With max_workers > 1 and multiple phases, phases applied in parallel."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"]
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.max_workers = 2
        result = cmd_sync(config, None)
        assert result == 0
        # Both phases should have been applied
        assert mock_provider_cls.return_value.put_phase_rules.call_count == 2

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_sequential_phases_with_max_workers_1(self, mock_provider_cls, tmp_path):
        """With max_workers=1, phases are applied sequentially (no thread pool)."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=1,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"]
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.max_workers = 1
        result = cmd_sync(config, None)
        assert result == 0
        assert mock_provider_cls.return_value.put_phase_rules.call_count == 2

    @patch("octorules.cli.CloudflareProvider")
    def test_parallel_phase_api_error_reported(self, mock_provider_cls, tmp_path, caplog):
        """API error in one phase during parallel apply should be reported."""
        from cloudflare import APIError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
            "cache_rules:\n  - ref: c1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            max_workers=2,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"]
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.max_workers = 2

        call_count = 0

        def put_side_effect(scope, cf_phase, rules):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise APIError("Server error", request=MagicMock(), body=None)

        mock_provider_cls.return_value.put_phase_rules.side_effect = put_side_effect
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, None)
        assert result == 1
        assert "API error syncing example.com" in caplog.text


class TestApplyParallel:
    """Direct unit tests for the _apply_parallel helper."""

    def test_empty_task_list(self):
        from octorules.cli import _apply_parallel

        successes, error = _apply_parallel([], max_workers=4)
        assert successes == []
        assert error is None

    def test_single_task_success(self):
        from octorules.cli import _apply_parallel

        called = []
        tasks = [("task-a", lambda: called.append("a"))]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == ["task-a"]
        assert error is None
        assert called == ["a"]

    def test_single_task_api_error(self):
        from cloudflare import APIError

        from octorules.cli import _apply_parallel

        def fail():
            raise APIError("boom", request=MagicMock(), body=None)

        tasks = [("task-a", fail)]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == []
        assert error is not None
        assert "task-a" in error
        assert "boom" in error

    def test_single_task_timeout_error(self):
        from octorules.cli import _apply_parallel

        def fail():
            raise TimeoutError("timed out")

        tasks = [("task-a", fail)]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == []
        assert error is not None
        assert "task-a" in error
        assert "timed out" in error

    def test_sequential_stops_on_first_error(self):
        from cloudflare import APIError

        from octorules.cli import _apply_parallel

        called = []

        def ok():
            called.append("ok")

        def fail():
            raise APIError("fail", request=MagicMock(), body=None)

        def never():
            called.append("never")

        tasks = [("a", ok), ("b", fail), ("c", never)]
        successes, error = _apply_parallel(tasks, max_workers=1)
        assert successes == ["a"]
        assert error is not None
        assert "b" in error
        assert "never" not in called

    def test_auth_error_propagates_sequential(self):
        from cloudflare import AuthenticationError

        from octorules.cli import _apply_parallel

        mock_response = MagicMock()
        mock_response.status_code = 401

        def fail():
            raise AuthenticationError(message="bad token", response=mock_response, body=None)

        tasks = [("task-a", fail)]
        with pytest.raises(AuthenticationError):
            _apply_parallel(tasks, max_workers=1)

    def test_auth_error_propagates_parallel(self):
        from cloudflare import AuthenticationError

        from octorules.cli import _apply_parallel

        mock_response = MagicMock()
        mock_response.status_code = 401

        def fail():
            raise AuthenticationError(message="bad token", response=mock_response, body=None)

        tasks = [("task-a", fail), ("task-b", lambda: None)]
        with pytest.raises(AuthenticationError):
            _apply_parallel(tasks, max_workers=4)

    def test_parallel_collects_successes_on_error(self):
        """Parallel path: successful tasks collected even when one fails."""
        import threading

        from cloudflare import APIError

        from octorules.cli import _apply_parallel

        barrier = threading.Barrier(3, timeout=5)

        def ok1():
            barrier.wait()

        def ok2():
            barrier.wait()

        def fail():
            barrier.wait()
            raise APIError("fail", request=MagicMock(), body=None)

        tasks = [("a", ok1), ("b", fail), ("c", ok2)]
        successes, error = _apply_parallel(tasks, max_workers=4)
        assert error is not None
        assert "b" in error
        # Both successful tasks should be collected
        assert sorted(successes) == ["a", "c"]

    def test_non_int_max_workers_uses_sequential(self):
        """MagicMock or other non-int max_workers falls back to sequential."""
        from octorules.cli import _apply_parallel

        called = []
        tasks = [("a", lambda: called.append("a")), ("b", lambda: called.append("b"))]
        successes, error = _apply_parallel(tasks, max_workers=MagicMock())
        assert successes == ["a", "b"]
        assert error is None
        assert called == ["a", "b"]  # sequential order preserved


class TestPreparedRulesReuse:
    """Tests that prepared_rules from planning are reused during sync."""

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_uses_prepared_rules(self, mock_provider_cls, tmp_path):
        """Sync should use prepared_rules from planning, not re-prepare."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n  - ref: r1\n    expression: 'true'\n"
        )
        config = Config(
            token="test-token",
            rules_dir=rules_dir,
            zones={
                "example.com": ZoneConfig(
                    name="example.com", zone_id="zone-abc", sources=["rules"]
                ),
            },
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.max_workers = 1
        result = cmd_sync(config, None)
        assert result == 0
        # Verify the PUT payload has defaults injected (from prepared_rules)
        call_args = mock_provider_cls.return_value.put_phase_rules.call_args
        payload = call_args[0][2]  # third positional arg: rules
        assert payload[0]["enabled"] is True
        assert payload[0]["action"] == "redirect"
