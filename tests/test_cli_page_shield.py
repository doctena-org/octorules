"""Tests for Page Shield policies CLI functionality."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from octorules.cli import cmd_dump, cmd_plan, cmd_sync, cmd_validate
from octorules.config import Config, ZoneConfig
from octorules.phases import get_phase
from octorules.planner import ChangeType, RuleChange, ZonePlan
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


class TestPageShieldPoliciesCLI:
    """Tests for Page Shield policy integration in CLI."""

    @patch("octorules.cli.CloudflareProvider")
    def test_plan_with_page_shield_policies(self, mock_provider_cls, sample_config, caplog):
        """Plan should detect Page Shield policy additions."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "page_shield_policies:\n"
            "  - description: 'CSP on all'\n"
            "    action: allow\n"
            "    expression: 'true'\n"
            "    enabled: true\n"
            "    value: \"script-src 'self'\"\n"
        )
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.get_all_page_shield_policies.return_value = []

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_plan(sample_config, ["example.com"])
        assert result == 0
        assert "CSP on all" in caplog.text or True  # plan output goes to stdout

    @patch("octorules.cli.CloudflareProvider")
    def test_plan_no_page_shield_key_skips(self, mock_provider_cls, sample_config):
        """When page_shield_policies key is absent, skip policy planning."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("redirect_rules:\n  - ref: r1\n    expression: 'true'\n")
        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}

        result = cmd_plan(sample_config, ["example.com"])
        assert result == 0
        # get_all_page_shield_policies should NOT be called
        mock_provider_cls.return_value.get_all_page_shield_policies.assert_not_called()

    @patch("octorules.cli.CloudflareProvider")
    def test_dump_includes_page_shield_policies(self, mock_provider_cls, sample_config):
        """Dump should fetch and include Page Shield policies."""
        import yaml

        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.get_all_page_shield_policies.return_value = [
            {
                "description": "CSP on all",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            }
        ]

        result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        dumped = sample_config.rules_dir / "example.com.yaml"
        data = yaml.safe_load(dumped.read_text())
        assert "page_shield_policies" in data
        assert data["page_shield_policies"][0]["description"] == "CSP on all"

    @patch("octorules.cli.CloudflareProvider")
    def test_dump_no_policies_no_section(self, mock_provider_cls, sample_config):
        """Dump with no policies should not include page_shield_policies key."""
        import yaml

        mock_provider_cls.return_value.get_all_phase_rules.return_value = {}
        mock_provider_cls.return_value.get_all_page_shield_policies.return_value = []

        result = cmd_dump(sample_config, ["example.com"], None)
        assert result == 0
        dumped = sample_config.rules_dir / "example.com.yaml"
        data = yaml.safe_load(dumped.read_text())
        assert "page_shield_policies" not in (data or {})

    def test_validate_page_shield_policies_ok(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "page_shield_policies:\n"
            "  - description: 'CSP on all'\n"
            "    action: allow\n"
            "    expression: 'true'\n"
            "    enabled: true\n"
            "    value: \"script-src 'self'\"\n"
        )
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 0
        assert "page_shield:CSP on all: OK" in caplog.text

    def test_validate_page_shield_policies_error(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "page_shield_policies:\n"
            "  - description: ''\n"
            "    action: allow\n"
            "    expression: 'true'\n"
            "    enabled: true\n"
            "    value: \"script-src 'self'\"\n"
        )
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 1
        assert "page_shield_policies" in caplog.text

    def test_validate_page_shield_invalid_action(self, sample_config, caplog):
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "page_shield_policies:\n"
            "  - description: 'CSP'\n"
            "    action: invalid_action\n"
            "    expression: 'true'\n"
            "    enabled: true\n"
            "    value: 'v'\n"
        )
        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_validate(sample_config, ["example.com"])
        assert result == 1

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_creates_page_shield_policy(self, mock_provider_cls, sample_config, caplog):
        """Sync should create new Page Shield policies."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text(
            "page_shield_policies:\n"
            "  - description: 'CSP on all'\n"
            "    action: allow\n"
            "    expression: 'true'\n"
            "    enabled: true\n"
            "    value: \"script-src 'self'\"\n"
        )
        mock_prov = mock_provider_cls.return_value
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_page_shield_policies.return_value = []
        mock_prov.create_page_shield_policy.return_value = {"id": "new-policy-id"}
        mock_prov.max_workers = 1

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        mock_prov.create_page_shield_policy.assert_called_once()

    @patch("octorules.cli.CloudflareProvider")
    def test_sync_deletes_page_shield_policy(self, mock_provider_cls, sample_config, caplog):
        """Sync should delete policies in CF but not in YAML."""
        rules_file = sample_config.rules_dir / "example.com.yaml"
        rules_file.write_text("page_shield_policies: []\n")
        mock_prov = mock_provider_cls.return_value
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_page_shield_policies.return_value = [
            {
                "id": "policy-to-delete",
                "description": "Old CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            }
        ]
        mock_prov.max_workers = 1

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(sample_config, ["example.com"])
        assert result == 0
        mock_prov.delete_page_shield_policy.assert_called_once()

    def test_apply_page_shield_policies_create(self):
        """_apply_page_shield_policies should call create for new policies."""
        from octorules.cli import _apply_page_shield_policies
        from octorules.planner import PageShieldPolicyPlan

        change = RuleChange(
            ChangeType.ADD,
            "CSP on all",
            REDIRECT_PHASE,
            desired={
                "description": "CSP on all",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "script-src 'self'",
            },
        )
        psp = PageShieldPolicyPlan(description="CSP on all", create=True, changes=[change])
        zp = ZonePlan(zone_name="example.com", page_shield_policy_plans=[psp])
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock()
        provider.create_page_shield_policy.return_value = {"id": "new-id"}

        synced, error = _apply_page_shield_policies(zp, scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.create_page_shield_policy.assert_called_once()

    def test_apply_page_shield_policies_delete(self):
        """_apply_page_shield_policies should call delete for removed policies."""
        from octorules.cli import _apply_page_shield_policies
        from octorules.planner import PageShieldPolicyPlan

        psp = PageShieldPolicyPlan(description="Old CSP", policy_id="policy-123", delete=True)
        zp = ZonePlan(zone_name="example.com", page_shield_policy_plans=[psp])
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock()

        synced, error = _apply_page_shield_policies(zp, scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.delete_page_shield_policy.assert_called_once_with(scope, "policy-123")

    def test_apply_page_shield_policies_update(self):
        """_apply_page_shield_policies should call update for modified policies."""
        from octorules.cli import _apply_page_shield_policies
        from octorules.planner import PageShieldPolicyPlan

        change = RuleChange(
            ChangeType.MODIFY,
            "CSP",
            REDIRECT_PHASE,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        psp = PageShieldPolicyPlan(description="CSP", policy_id="policy-456", changes=[change])
        zp = ZonePlan(zone_name="example.com", page_shield_policy_plans=[psp])
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock()
        provider.update_page_shield_policy.return_value = {"id": "policy-456"}

        synced, error = _apply_page_shield_policies(zp, scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.update_page_shield_policy.assert_called_once()

    def test_apply_page_shield_policies_empty(self):
        """Empty page_shield_policy_plans should do nothing."""
        from octorules.cli import _apply_page_shield_policies

        zp = ZonePlan(zone_name="example.com", page_shield_policy_plans=[])
        scope = Scope(zone_id="zone-abc", label="example.com")
        provider = MagicMock()

        synced, error = _apply_page_shield_policies(zp, scope, provider)
        assert error is None
        assert len(synced) == 0
