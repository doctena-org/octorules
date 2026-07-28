"""Tests for lists CLI functionality."""

import logging
from unittest.mock import MagicMock, patch

from octorules.cli import cmd_dump, cmd_sync
from octorules.config import Config, ProviderConfig
from octorules.planner import ChangeType, ListPlan, RuleChange, ZonePlan
from octorules.provider import Scope


class TestListsPlanAccount:
    """Tests for lists in _plan_account."""

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

    def test_plan_account_with_lists(self, tmp_path):
        """_plan_account should plan lists when present in YAML."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "lists:\n"
            "- name: blocked_ips\n"
            "  kind: ip\n"
            "  description: Bad actors\n"
            "  items:\n"
            "  - ip: '1.2.3.4'\n"
            "    comment: scanner\n",
        )
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        provider.get_all_lists.return_value = {}  # empty = new list

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.list_plans) == 1
        lp = zp.list_plans[0]
        assert lp.list_name == "blocked_ips"
        assert lp.create is True
        assert lp.has_changes

    def test_plan_account_no_lists(self, tmp_path):
        """_plan_account without lists key should not call get_all_lists."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "waf_custom_rules:\n"
            "- ref: deploy1\n"
            "  action: execute\n"
            "  expression: 'true'\n"
            "  action_parameters:\n"
            "    id: rs1\n",
        )
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.list_plans) == 0
        provider.get_all_lists.assert_not_called()

    def test_plan_account_lists_no_changes(self, tmp_path):
        """When list items match current state, no changes."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "lists:\n"
            "- name: blocked_ips\n"
            "  kind: ip\n"
            "  description: Bad actors\n"
            "  items:\n"
            "  - ip: '1.2.3.4'\n"
            "    comment: scanner\n",
        )
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        provider.get_all_lists.return_value = {
            "blocked_ips": {
                "id": "list-123",
                "kind": "ip",
                "description": "Bad actors",
                "items": [{"ip": "1.2.3.4", "comment": "scanner"}],
            }
        }

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.list_plans) == 0  # no changes = not added

    def test_plan_account_lists_deletion(self, tmp_path):
        """Lists in CF but not in YAML should be planned for deletion."""
        from octorules.commands import _plan_account

        config = self._make_config(
            tmp_path,
            "lists: []\n",  # empty list means all managed, existing deleted
        )
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        provider.get_all_lists.return_value = {
            "old_list": {
                "id": "list-999",
                "kind": "ip",
                "description": "Old",
                "items": [{"ip": "9.9.9.9"}],
            }
        }

        zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert len(zp.list_plans) == 1
        lp = zp.list_plans[0]
        assert lp.list_name == "old_list"
        assert lp.delete is True

    def test_plan_account_lists_api_error_graceful(self, tmp_path, caplog):
        """API error fetching lists should warn but still plan phases."""
        from octorules.commands import _plan_account
        from octorules.provider.exceptions import ProviderError

        config = self._make_config(
            tmp_path,
            "lists:\n- name: blocked_ips\n  kind: ip\n  items:\n  - ip: '1.2.3.4'\n",
        )
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.account_id = "acct-123"
        provider.account_name = "Test Account"
        provider.get_all_phase_rules.return_value = {}
        provider.get_all_lists.side_effect = ProviderError("Server error")

        with caplog.at_level(logging.WARNING, logger="octorules"):
            zp, _desired, _current = _plan_account(config, provider, None)
        assert zp is not None
        assert "Failed to fetch lists" in caplog.text
        # Changes still detected because current is empty fallback
        assert len(zp.list_plans) == 1


class TestListsDump:
    """Tests for lists in cmd_dump."""

    @patch("octorules.commands._providers._init_providers")
    def test_dump_account_includes_lists(self, mock_init_provs, tmp_path, caplog):
        """Account dump should include lists section."""
        from octorules.config import _yaml_load

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
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_custom_rulesets.return_value = {}
        mock_prov.get_all_lists.return_value = {
            "blocked_ips": {
                "id": "list-123",
                "kind": "ip",
                "description": "Bad actors",
                "items": [{"ip": "1.2.3.4", "comment": "scanner"}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        assert "Dumped account" in caplog.text
        dumped = rules_dir / "test-account.yaml"
        assert dumped.exists()
        data = _yaml_load(dumped)
        assert "lists" in data
        assert data["lists"][0]["name"] == "blocked_ips"
        assert data["lists"][0]["kind"] == "ip"
        assert data["lists"][0]["items"][0]["ip"] == "1.2.3.4"

    @patch("octorules.commands._providers._init_providers")
    def test_dump_account_lists_api_error(self, mock_init_provs, tmp_path, caplog):
        """API error fetching lists should warn but still dump phases."""
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
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.get_all_phase_rules.return_value = {
            "http_request_firewall_custom": [
                {"ref": "deploy1", "expression": "true", "action": "execute", "enabled": True}
            ],
        }
        mock_prov.get_all_custom_rulesets.return_value = {}
        mock_prov.get_all_lists.side_effect = ProviderError("Timeout")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        assert "Failed to fetch lists" in caplog.text
        dumped = rules_dir / "test-account.yaml"
        assert dumped.exists()

    @patch("octorules.commands._providers._init_providers")
    def test_dump_account_no_lists_returns_none(self, mock_init_provs, tmp_path, caplog):
        """When get_all_lists returns empty dict, lists section is omitted."""
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
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_custom_rulesets.return_value = {}
        mock_prov.get_all_lists.return_value = {}
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        dumped = rules_dir / "test-account.yaml"
        data = yaml.safe_load(dumped.read_text())
        assert "lists" not in (data or {})

    @patch("octorules.commands._providers._init_providers")
    def test_dump_account_uses_config_lists_dir(self, mock_init_provs, tmp_path, caplog):
        """Account dump should write list items to config.lists_dir."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        custom_dir = rules_dir / "my_lists"
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            lists_dir=custom_dir,
            zones={},
        )
        mock_prov = MagicMock()
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_custom_rulesets.return_value = {}
        mock_prov.get_all_lists.return_value = {
            "blocked_ips": {
                "id": "list-123",
                "kind": "ip",
                "description": "Bad actors",
                "items": [{"ip": "1.2.3.4", "comment": "scanner"}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, None, scope_filter="account")
        assert result == 0
        # Items should be written to the custom lists_dir, not the default
        assert (custom_dir / "blocked_ips.yaml").exists()
        assert not (rules_dir / "custom_lists").exists()

    @patch("octorules.commands._providers._init_providers")
    def test_dump_output_dir_override_ignores_config_lists_dir(
        self, mock_init_provs, tmp_path, caplog
    ):
        """When --output-dir is specified, lists_dir defaults to output_dir/custom_lists."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        custom_dir = rules_dir / "my_lists"
        config = Config(
            providers={
                "cloudflare": ProviderConfig(name="cloudflare", kwargs={"token": "test-token"})
            },
            rules_dir=rules_dir,
            lists_dir=custom_dir,
            zones={},
        )
        out_dir = tmp_path / "export"
        mock_prov = MagicMock()
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_custom_rulesets.return_value = {}
        mock_prov.get_all_lists.return_value = {
            "blocked_ips": {
                "id": "list-123",
                "kind": "ip",
                "description": "Bad actors",
                "items": [{"ip": "1.2.3.4", "comment": "scanner"}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_dump(config, None, str(out_dir), scope_filter="account")
        assert result == 0
        # Items should be under output_dir/custom_lists, not config.lists_dir
        assert (out_dir / "custom_lists" / "blocked_ips.yaml").exists()
        assert not custom_dir.exists()


class TestListsSync:
    """Tests for lists in cmd_sync."""

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
    def test_sync_creates_new_list(self, mock_init_provs, tmp_path, caplog):
        """Sync should call create_list + put_list_items for new lists."""
        config = self._make_account_config(
            tmp_path,
            "lists:\n"
            "- name: blocked_ips\n"
            "  kind: ip\n"
            "  description: Bad actors\n"
            "  items:\n"
            "  - ip: '1.2.3.4'\n"
            "    comment: scanner\n",
        )
        mock_prov = MagicMock()
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_lists.return_value = {}
        mock_prov.create_list.return_value = {"id": "new-list-id"}
        mock_prov.put_list_items.return_value = "op-123"
        mock_prov.poll_bulk_operation.return_value = "completed"
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(config, None, scope_filter="account")
        assert result == 0
        mock_prov.create_list.assert_called_once()
        call_args = mock_prov.create_list.call_args
        assert call_args[0][1] == "blocked_ips"
        assert call_args[0][2] == "ip"
        mock_prov.put_list_items.assert_called_once()
        mock_prov.poll_bulk_operation.assert_called_once()

    @patch("octorules.commands._providers._init_providers")
    def test_sync_deletes_removed_list(self, mock_init_provs, tmp_path, caplog):
        """Sync should call delete_list for lists in CF but not in YAML."""
        config = self._make_account_config(
            tmp_path,
            "lists: []\n",
        )
        mock_prov = MagicMock()
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_lists.return_value = {
            "old_list": {
                "id": "list-999",
                "kind": "ip",
                "description": "Old",
                "items": [{"ip": "9.9.9.9"}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.INFO, logger="octorules"):
            result = cmd_sync(config, None, scope_filter="account")
        assert result == 0
        mock_prov.delete_list.assert_called_once_with(
            Scope(account_id="acct-123", label="Test Account"),
            "list-999",
        )

    @patch("octorules.commands._providers._init_providers")
    def test_sync_no_list_changes_skips_apply(self, mock_init_provs, tmp_path):
        """When list items match, no API calls for lists should be made."""
        config = self._make_account_config(
            tmp_path,
            "lists:\n"
            "- name: blocked_ips\n"
            "  kind: ip\n"
            "  description: Bad actors\n"
            "  items:\n"
            "  - ip: '1.2.3.4'\n"
            "    comment: scanner\n",
        )
        mock_prov = MagicMock()
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_lists.return_value = {
            "blocked_ips": {
                "id": "list-123",
                "kind": "ip",
                "description": "Bad actors",
                "items": [{"ip": "1.2.3.4", "comment": "scanner"}],
            }
        }
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        result = cmd_sync(config, None, scope_filter="account")
        assert result == 0
        mock_prov.create_list.assert_not_called()
        mock_prov.put_list_items.assert_not_called()
        mock_prov.delete_list.assert_not_called()
        mock_prov.update_list_description.assert_not_called()

    @patch("octorules.commands._providers._init_providers")
    def test_sync_lists_api_error_returns_1(self, mock_init_provs, tmp_path, caplog):
        """API error during list create should return 1."""
        from octorules.provider.exceptions import ProviderError

        config = self._make_account_config(
            tmp_path,
            "lists:\n- name: blocked_ips\n  kind: ip\n  items:\n  - ip: '1.2.3.4'\n",
        )
        mock_prov = MagicMock()
        mock_prov.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        mock_prov.account_id = "acct-123"
        mock_prov.account_name = "Test Account"
        mock_prov.max_workers = 1
        mock_prov.get_all_phase_rules.return_value = {}
        mock_prov.get_all_lists.return_value = {}
        mock_prov.create_list.side_effect = ProviderError("Forbidden")
        mock_init_provs.return_value = {"cloudflare": mock_prov}

        with caplog.at_level(logging.ERROR, logger="octorules"):
            result = cmd_sync(config, None, scope_filter="account")
        assert result == 1


class TestApplyLists:
    """Tests for _apply_lists helper."""

    def _make_list_phase(self):
        from octorules.planner import _make_list_phase

        return _make_list_phase("test_list")

    def test_apply_create_and_items(self):
        from octorules.commands import _apply_lists

        phase = self._make_list_phase()
        lp = ListPlan(
            list_name="blocked_ips",
            list_kind="ip",
            create=True,
            description_change=(None, "Bad actors"),
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", phase)],
            prepared_items=[{"ip": "1.2.3.4", "comment": "scanner"}],
        )
        zp = ZonePlan(zone_name="test-account", list_plans=[lp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.create_list.return_value = {"id": "new-list-id"}
        provider.put_list_items.return_value = "op-123"
        provider.poll_bulk_operation.return_value = "completed"

        synced, error = _apply_lists(zp, scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.create_list.assert_called_once_with(scope, "blocked_ips", "ip", "Bad actors")
        provider.put_list_items.assert_called_once()
        provider.poll_bulk_operation.assert_called_once_with(scope, "op-123")

    def test_apply_delete(self):
        from octorules.commands import _apply_lists

        phase = self._make_list_phase()
        lp = ListPlan(
            list_name="old_list",
            list_id="list-999",
            list_kind="ip",
            delete=True,
            changes=[RuleChange(ChangeType.REMOVE, "9.9.9.9", phase)],
        )
        zp = ZonePlan(zone_name="test-account", list_plans=[lp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})

        synced, error = _apply_lists(zp, scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.delete_list.assert_called_once_with(scope, "list-999")

    def test_apply_description_update(self):
        from octorules.commands import _apply_lists

        lp = ListPlan(
            list_name="my_list",
            list_id="list-123",
            list_kind="ip",
            description_change=("old desc", "new desc"),
        )
        zp = ZonePlan(zone_name="test-account", list_plans=[lp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})

        synced, error = _apply_lists(zp, scope, provider)
        assert error is None
        assert len(synced) == 1
        provider.update_list_description.assert_called_once_with(scope, "list-123", "new desc")

    def test_apply_create_error_returns_error(self):
        from octorules.commands import _apply_lists
        from octorules.provider.exceptions import ProviderError

        lp = ListPlan(
            list_name="fail_list",
            list_kind="ip",
            create=True,
        )
        zp = ZonePlan(zone_name="test-account", list_plans=[lp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.create_list.side_effect = ProviderError("Forbidden")

        synced, error = _apply_lists(zp, scope, provider)
        assert error is not None
        assert len(synced) == 0

    def test_apply_item_update_timeout_returns_error(self):
        from octorules.commands import _apply_lists

        phase = self._make_list_phase()
        lp = ListPlan(
            list_name="slow_list",
            list_id="list-123",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", phase)],
            prepared_items=[{"ip": "1.2.3.4"}],
        )
        zp = ZonePlan(zone_name="test-account", list_plans=[lp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.put_list_items.return_value = "op-123"
        provider.poll_bulk_operation.side_effect = TimeoutError("Operation timed out")

        synced, error = _apply_lists(zp, scope, provider)
        assert error is not None
        assert "timed out" in error.lower()
        assert len(synced) == 0

    def test_apply_skips_no_prepared_items(self, caplog):
        from octorules.commands import _apply_lists

        phase = self._make_list_phase()
        lp = ListPlan(
            list_name="empty_list",
            list_id="list-123",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", phase)],
            prepared_items=None,  # no prepared items
        )
        zp = ZonePlan(zone_name="test-account", list_plans=[lp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})

        with caplog.at_level(logging.WARNING, logger="octorules"):
            synced, error = _apply_lists(zp, scope, provider)
        assert error is None
        assert len(synced) == 0
        provider.put_list_items.assert_not_called()
        assert "no prepared items" in caplog.text

    def test_apply_description_skipped_for_create(self):
        """Description update should be skipped for newly created lists (set during create)."""
        from octorules.commands import _apply_lists

        phase = self._make_list_phase()
        lp = ListPlan(
            list_name="new_list",
            list_kind="ip",
            create=True,
            description_change=(None, "My description"),
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", phase)],
            prepared_items=[{"ip": "1.2.3.4"}],
        )
        zp = ZonePlan(zone_name="test-account", list_plans=[lp])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})
        provider.create_list.return_value = {"id": "new-id"}
        provider.put_list_items.return_value = "op-123"
        provider.poll_bulk_operation.return_value = "completed"

        _synced, error = _apply_lists(zp, scope, provider)
        assert error is None
        # update_list_description should NOT be called (create already set it)
        provider.update_list_description.assert_not_called()

    def test_apply_empty_list_plans(self):
        from octorules.commands import _apply_lists

        zp = ZonePlan(zone_name="test-account", list_plans=[])
        scope = Scope(account_id="acct-123", label="Test Account")
        provider = MagicMock()
        provider.SUPPORTS = frozenset({"lists", "custom_rulesets", "zone_discovery"})

        synced, error = _apply_lists(zp, scope, provider)
        assert error is None
        assert len(synced) == 0
