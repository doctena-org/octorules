"""Tests for custom rulesets CLI functionality."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from octorules.cli import cmd_dump, cmd_sync, cmd_validate
from octorules.config import Config, ProviderConfig, ZoneConfig
from octorules.planner import ChangeType, RuleChange, ZonePlan
from octorules.provider import Scope


class TestCustomRulesetsValidate:
    """Tests for custom_rulesets validation in cmd_validate."""

    def test_validate_custom_rulesets_ok(self, tmp_path, caplog):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n"
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
        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_validate(config, None)
        assert result == 0
        assert "custom_ruleset:Block" in caplog.text
        assert "OK" in caplog.text

    def test_validate_custom_rulesets_missing_action(self, tmp_path, caplog):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
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
        result = cmd_validate(config, None)
        assert result == 1

    def test_validate_custom_rulesets_no_unknown_phase_warning(self, tmp_path, caplog):
        """custom_rulesets should not trigger unknown phase warning."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "example.com.yaml").write_text(
            "redirect_rules:\n"
            "- ref: r1\n"
            "  expression: 'true'\n"
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r2\n"
            "    expression: 'true'\n"
            "    action: block\n"
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
        with caplog.at_level(logging.WARNING, logger="octorules"):
            cmd_validate(config, None)
        assert "Unknown phase" not in caplog.text
        assert "custom_rulesets" not in caplog.text or "OK" in caplog.text


class TestCustomRulesetsPlanAccount:
    """Tests for custom rulesets in _plan_account."""

    def _make_config(self, tmp_path, account_rules_yaml):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test-account.yaml").write_text(account_rules_yaml)
        return Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={},
        )

    def test_plan_account_with_custom_rulesets_existing(self, tmp_path):
        """_plan_account should plan custom rulesets that exist in provider."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n",
        )
        provider = MagicMock()
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        # Provider already has the ruleset with different rules
        provider.get_all_custom_rulesets.return_value = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r1", "expression": "true", "action": "log", "enabled": True}],
            }
        }

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.custom_ruleset_plans) == 1
        crp = zp.custom_ruleset_plans[0]
        assert crp.ruleset_id == "rs1"
        assert crp.ruleset_name == "Block attackers"
        assert crp.has_changes
        assert not crp.create
        assert not crp.delete

    def test_plan_account_with_custom_rulesets_create(self, tmp_path):
        """_plan_account should detect new custom rulesets as creates."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "custom_rulesets:\n"
            "- name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  capacity: 100\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n",
        )
        provider = MagicMock()
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        provider.get_all_custom_rulesets.return_value = {}  # empty = all rules are new

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.custom_ruleset_plans) == 1
        crp = zp.custom_ruleset_plans[0]
        assert crp.ruleset_id is None
        assert crp.create is True
        assert crp.ruleset_name == "Block attackers"
        assert crp.has_changes

    def test_plan_account_no_custom_rulesets(self, tmp_path):
        """_plan_account without custom_rulesets in YAML should still work."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "waf_custom_rules:\n"
            "- ref: deploy1\n"
            "  description: Deploy block ruleset\n"
            "  action: execute\n"
            "  expression: 'true'\n"
            "  action_parameters:\n"
            "    id: rs1\n",
        )
        provider = MagicMock()
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.custom_ruleset_plans) == 0
        provider.get_all_custom_rulesets.assert_not_called()

    def test_plan_account_custom_rulesets_no_changes(self, tmp_path):
        """When custom ruleset rules match current state, no changes."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n"
            "    enabled: true\n",
        )
        provider = MagicMock()
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        provider.get_all_custom_rulesets.return_value = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r1", "expression": "true", "action": "block", "enabled": True}],
            }
        }

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.custom_ruleset_plans) == 0  # no changes = not added

    def test_plan_account_custom_rulesets_api_error_graceful(self, tmp_path, caplog):
        """API error fetching custom rulesets should warn but still plan phases."""
        from octorules.commands import _plan_account
        from octorules.provider.exceptions import ProviderError

        config = self._make_config(
            tmp_path,
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n",
        )
        provider = MagicMock()
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        provider.get_all_custom_rulesets.side_effect = ProviderError("Server error")

        with caplog.at_level(logging.WARNING, logger="octorules"):
            zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert "Failed to fetch custom rulesets" in caplog.text
        # Changes still detected because current is empty fallback
        assert len(zp.custom_ruleset_plans) == 1


class TestCustomRulesetsDump:
    """Tests for custom rulesets in cmd_dump."""

    @patch("octorules.commands._providers._init_providers")
    def test_dump_account_includes_custom_rulesets(self, mock_init_provs, tmp_path, caplog):
        """Account dump should include custom_rulesets section."""
        import yaml

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={},
        )
        mock_prov = MagicMock()
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_custom_rulesets.return_value = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r1", "expression": "true", "action": "block", "enabled": True}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        assert "Dumped account" in caplog.text
        dumped = rules_dir / "test-account.yaml"
        assert dumped.exists()
        data = yaml.safe_load(dumped.read_text())
        assert "custom_rulesets" in data
        assert data["custom_rulesets"][0]["id"] == "rs1"
        assert data["custom_rulesets"][0]["name"] == "Block attackers"
        assert len(data["custom_rulesets"][0]["rules"]) == 1

    @patch("octorules.commands._providers._init_providers")
    def test_dump_account_custom_rulesets_api_error(self, mock_init_provs, tmp_path, caplog):
        """API error fetching custom rulesets should warn but still dump phases."""
        from octorules.provider.exceptions import ProviderError

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={},
        )
        mock_prov = MagicMock()
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_firewall_custom": [
                {"ref": "deploy1", "expression": "true", "action": "execute", "enabled": True}
            ],
        }
        mock_prov.get_all_custom_rulesets.side_effect = ProviderError("Timeout")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        assert "Failed to fetch custom rulesets" in caplog.text
        # Phase rules should still be dumped
        dumped = rules_dir / "test-account.yaml"
        assert dumped.exists()


class TestCustomRulesetsSync:
    """Tests for custom rulesets in cmd_sync."""

    def _make_account_config(self, tmp_path, account_rules_yaml):
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        (rules_dir / "test-account.yaml").write_text(account_rules_yaml)
        return Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            zones={},
        )

    @patch("octorules.commands._providers._init_providers")
    def test_sync_applies_custom_rulesets_update(self, mock_init_provs, tmp_path, caplog):
        """Sync should call put_custom_ruleset for existing custom ruleset changes."""
        config = self._make_account_config(
            tmp_path,
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n",
        )
        mock_prov = MagicMock()
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        # Provider has the ruleset but with different rules
        mock_prov.get_all_custom_rulesets.return_value = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r1", "expression": "true", "action": "log", "enabled": True}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(config, None, scope_filter="account")
        assert result == 0
        mock_prov.put_custom_ruleset.assert_called_once()
        call_args = mock_prov.put_custom_ruleset.call_args
        assert call_args[0][1] == "rs1"  # ruleset_id
        assert "custom_ruleset:Block attackers" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_creates_new_custom_ruleset(self, mock_init_provs, tmp_path, caplog):
        """Sync should call create_custom_ruleset for new rulesets."""
        config = self._make_account_config(
            tmp_path,
            "custom_rulesets:\n"
            "- name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  capacity: 100\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n",
        )
        mock_prov = MagicMock()
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_custom_rulesets.return_value = {}
        mock_prov.create_custom_ruleset.return_value = {
            "id": "new-rs-id",
            "name": "Block attackers",
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(config, None, scope_filter="account")
        assert result == 0
        mock_prov.create_custom_ruleset.assert_called_once()
        # After create, put_custom_ruleset should be called with the new ID
        mock_prov.put_custom_ruleset.assert_called_once()
        call_args = mock_prov.put_custom_ruleset.call_args
        assert call_args[0][1] == "new-rs-id"  # ruleset_id from create
        assert "custom_ruleset:Block attackers" in caplog.text

    @patch("octorules.commands._providers._init_providers")
    def test_sync_custom_rulesets_api_error(self, mock_init_provs, tmp_path, caplog):
        """API error applying custom ruleset should return 1."""
        from octorules.provider.exceptions import ProviderError

        config = self._make_account_config(
            tmp_path,
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n",
        )
        mock_prov = MagicMock()
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        # Provider has the ruleset with different rules so it's an update (not create)
        mock_prov.get_all_custom_rulesets.return_value = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r1", "expression": "true", "action": "log", "enabled": True}],
            }
        }
        mock_prov.put_custom_ruleset.side_effect = ProviderError("Forbidden")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, None, scope_filter="account")
        assert result == 1

    @patch("octorules.commands._providers._init_providers")
    def test_sync_no_changes_skips_apply(self, mock_init_provs, tmp_path):
        """When custom ruleset rules match, no PUT calls should be made."""
        config = self._make_account_config(
            tmp_path,
            "custom_rulesets:\n"
            "- id: rs1\n"
            "  name: Block attackers\n"
            "  phase: http_request_firewall_custom\n"
            "  rules:\n"
            "  - ref: r1\n"
            "    expression: 'true'\n"
            "    action: block\n"
            "    enabled: true\n",
        )
        mock_prov = MagicMock()
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_custom_rulesets.return_value = {
            "rs1": {
                "name": "Block attackers",
                "phase": "http_request_firewall_custom",
                "rules": [{"ref": "r1", "expression": "true", "action": "block", "enabled": True}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        result = cmd_sync(config, None, scope_filter="account")
        assert result == 0
        mock_prov.put_custom_ruleset.assert_not_called()
        mock_prov.put_phase_rules.assert_not_called()


class TestApplyCustomRulesets:
    """Tests for _apply_custom_rulesets helper."""

    def test_apply_success(self):
        from octorules.commands import _apply_custom_rulesets
        from octorules.planner import CustomRulesetPlan, _make_synthetic_phase

        phase = _make_synthetic_phase(
            "custom_ruleset",
            "Block attackers",
            "http_request_firewall_custom",
        )
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block attackers",
            phase="http_request_firewall_custom",
            changes=[RuleChange(ChangeType.ADD, "r1", phase)],
            prepared_rules=[{"ref": "r1", "expression": "true", "action": "block"}],
        )
        zp = ZonePlan(zone_name="test-account", custom_ruleset_plans=[crp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()

        synced, error = _apply_custom_rulesets(zp, scope, provider)
        assert error is None
        assert len(synced) == 1
        assert "custom_ruleset:Block attackers" in synced[0]
        provider.put_custom_ruleset.assert_called_once_with(scope, "rs1", crp.prepared_rules)

    def test_apply_api_error(self):
        from octorules.commands import _apply_custom_rulesets
        from octorules.planner import CustomRulesetPlan, _make_synthetic_phase
        from octorules.provider.exceptions import ProviderError

        phase = _make_synthetic_phase(
            "custom_ruleset",
            "Block attackers",
            "http_request_firewall_custom",
        )
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block attackers",
            phase="http_request_firewall_custom",
            changes=[RuleChange(ChangeType.ADD, "r1", phase)],
            prepared_rules=[{"ref": "r1", "expression": "true", "action": "block"}],
        )
        zp = ZonePlan(zone_name="test-account", custom_ruleset_plans=[crp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.put_custom_ruleset.side_effect = ProviderError("Forbidden")

        synced, error = _apply_custom_rulesets(zp, scope, provider)
        assert error is not None
        assert len(synced) == 0

    def test_apply_skips_no_prepared_rules(self, caplog):
        from octorules.commands import _apply_custom_rulesets
        from octorules.planner import CustomRulesetPlan, _make_synthetic_phase

        phase = _make_synthetic_phase(
            "custom_ruleset",
            "Block attackers",
            "http_request_firewall_custom",
        )
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block attackers",
            phase="http_request_firewall_custom",
            changes=[RuleChange(ChangeType.ADD, "r1", phase)],
            prepared_rules=None,  # no prepared rules
        )
        zp = ZonePlan(zone_name="test-account", custom_ruleset_plans=[crp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()

        with caplog.at_level(logging.WARNING, logger="octorules"):
            synced, error = _apply_custom_rulesets(zp, scope, provider)
        assert error is None
        assert len(synced) == 0
        provider.put_custom_ruleset.assert_not_called()
        assert "no prepared rules" in caplog.text

    def test_apply_no_changes_skipped(self):
        from octorules.commands import _apply_custom_rulesets
        from octorules.planner import CustomRulesetPlan

        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block attackers",
            phase="http_request_firewall_custom",
            changes=[],  # no changes
        )
        zp = ZonePlan(zone_name="test-account", custom_ruleset_plans=[crp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()

        synced, error = _apply_custom_rulesets(zp, scope, provider)
        assert error is None
        assert len(synced) == 0
        provider.put_custom_ruleset.assert_not_called()

    def test_sync_create_succeeds_put_fails(self):
        """When create_custom_ruleset succeeds but put_custom_ruleset fails, error is returned."""
        from octorules.commands import _apply_custom_rulesets
        from octorules.planner import CustomRulesetPlan, _make_synthetic_phase
        from octorules.provider.exceptions import ProviderError

        phase = _make_synthetic_phase(
            "custom_ruleset",
            "New RS",
            "http_request_firewall_custom",
        )
        crp = CustomRulesetPlan(
            ruleset_name="New RS",
            phase="http_request_firewall_custom",
            create=True,
            changes=[RuleChange(ChangeType.ADD, "r1", phase)],
            prepared_rules=[{"ref": "r1", "expression": "true", "action": "block"}],
        )
        zp = ZonePlan(zone_name="test-account", custom_ruleset_plans=[crp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.max_workers = 1
        # create succeeds and returns an ID
        provider.create_custom_ruleset.return_value = {"id": "new-id"}
        # put fails after create
        provider.put_custom_ruleset.side_effect = ProviderError("rate limited")

        _synced, error = _apply_custom_rulesets(zp, scope, provider)
        assert error is not None
        assert "rate limited" in error
        # create was called (the ruleset was created)
        provider.create_custom_ruleset.assert_called_once()
        # put was attempted with the new ID
        provider.put_custom_ruleset.assert_called_once()
        put_args = provider.put_custom_ruleset.call_args
        assert put_args[0][1] == "new-id"
