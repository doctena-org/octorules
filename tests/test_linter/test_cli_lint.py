"""Tests for the 'octorules lint' CLI command."""

from __future__ import annotations

from pathlib import Path

import pytest

from octorules.cli import build_parser, cmd_lint, main
from octorules.config import Config


@pytest.fixture
def lint_config(tmp_path):
    """Create a minimal config and rules file for lint testing."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    # Valid rules file
    rules_file = rules_dir / "example.com.yaml"
    rules_file.write_text(
        "redirect_rules:\n"
        "  - ref: test-redirect\n"
        "    expression: 'http.host eq \"example.com\"'\n"
        "    action_parameters:\n"
        "      from_value:\n"
        "        target_url:\n"
        '          value: "/new"\n'
        "        status_code: 301\n"
    )

    # Rules file with issues
    bad_rules_file = rules_dir / "bad.example.com.yaml"
    bad_rules_file.write_text(
        "redirect_rules:\n"
        "  - expression: 'true'\n"  # missing ref
        "  - ref: test\n"  # missing expression
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  cloudflare:\n"
        "    token: test-token-123\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  example.com:\n"
        "    sources:\n"
        "      - rules\n"
        "  bad.example.com:\n"
        "    sources:\n"
        "      - rules\n"
    )

    return Config.from_file(config_file)


class TestBuildParser:
    def test_lint_subcommand_exists(self):
        parser = build_parser()
        args = parser.parse_args(["lint"])
        assert args.command == "lint"

    def test_lint_format_flag(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--format", "json"])
        assert args.lint_format == "json"

    def test_lint_severity_flag(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--severity", "error"])
        assert args.lint_severity == "error"

    def test_lint_plan_flag(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--plan", "free"])
        assert args.lint_plan == "free"

    def test_lint_exit_code_flag(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--exit-code"])
        assert args.lint_exit_code is True

    def test_lint_rule_filter(self):
        parser = build_parser()
        args = parser.parse_args(["lint", "--rule", "M001", "--rule", "M002"])
        assert args.lint_rules == ["M001", "M002"]

    def test_lint_defaults(self):
        parser = build_parser()
        args = parser.parse_args(["lint"])
        assert args.lint_format == "text"
        assert args.lint_severity == "info"
        assert args.lint_rules is None
        assert args.lint_plan is None
        assert args.lint_output is None
        assert args.lint_exit_code is False


class TestCmdLint:
    def test_valid_rules_exit_0(self, lint_config):
        rc = cmd_lint(lint_config, ["example.com"])
        assert rc == 0

    def test_invalid_rules_exit_1(self, lint_config):
        rc = cmd_lint(lint_config, ["bad.example.com"])
        assert rc == 1

    def test_exit_code_flag_warning(self, lint_config):
        # With --exit-code, warnings return 2
        rc = cmd_lint(lint_config, ["bad.example.com"], exit_code=True)
        # Missing ref is an error, so exit code should be 1
        assert rc == 1

    def test_severity_filter(self, lint_config):
        # Only show errors — should still detect M001
        rc = cmd_lint(lint_config, ["bad.example.com"], lint_severity="error")
        assert rc == 1

    def test_rule_filter(self, lint_config):
        # Only check M001 — should find the missing ref
        rc = cmd_lint(lint_config, ["bad.example.com"], lint_rules=["M001"])
        assert rc == 1

    def test_json_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad.example.com"], lint_format="json")
        captured = capsys.readouterr()
        assert '"rule_id"' in captured.out

    def test_sarif_format(self, lint_config, capsys):
        cmd_lint(lint_config, ["bad.example.com"], lint_format="sarif")
        captured = capsys.readouterr()
        assert '"version": "2.1.0"' in captured.out

    def test_output_file(self, lint_config, tmp_path):
        out_file = str(tmp_path / "lint-report.txt")
        cmd_lint(lint_config, ["bad.example.com"], output_file=out_file)
        assert Path(out_file).exists()
        content = Path(out_file).read_text()
        assert "M001" in content

    def test_no_rules_file(self, lint_config):
        # Zone without rules file — should exit 0
        rc = cmd_lint(lint_config, ["example.com"], phase_filter=["nonexistent_rules_phase"])
        assert rc == 0

    def test_plan_tier_affects_results(self, lint_config):
        # Free plan should trigger H001 if regex is used — not in our test fixture
        # But at minimum shouldn't crash
        rc = cmd_lint(lint_config, ["example.com"], lint_plan="free")
        assert rc == 0


class TestZonePlanResolution:
    """Tests for per-zone plan tier resolution in cmd_lint."""

    def test_explicit_plan_overrides_zone_plans(self, lint_config):
        """When --plan is passed, it wins over API-detected zone_plans."""
        rc = cmd_lint(
            lint_config,
            ["example.com"],
            lint_plan="free",
            zone_plans={"example.com": "enterprise"},
        )
        assert rc == 0

    def test_zone_plans_used_when_lint_plan_none(self, lint_config):
        """When --plan is omitted, zone_plans from API should be used."""
        rc = cmd_lint(
            lint_config,
            ["example.com"],
            lint_plan=None,
            zone_plans={"example.com": "free"},
        )
        # Should not crash, plan tier "free" is valid
        assert rc == 0

    def test_fallback_to_enterprise_when_no_plan_info(self, lint_config):
        """When no --plan and no zone_plans entry, fall back to 'enterprise'."""
        rc = cmd_lint(
            lint_config,
            ["example.com"],
            lint_plan=None,
            zone_plans={},
        )
        assert rc == 0


class TestMainLintCommand:
    def test_main_lint_no_crash(self, lint_config, tmp_path):
        config_file = tmp_path / "config.yaml"
        with pytest.raises(SystemExit) as exc_info:
            main(["--config", str(config_file), "lint", "--zone", "example.com"])
        assert exc_info.value.code == 0
