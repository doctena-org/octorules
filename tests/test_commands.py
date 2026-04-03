"""Tests for _plan_all_scopes(), _PlanAllResult, and multi-provider routing."""

from collections import defaultdict
from unittest.mock import MagicMock, patch

import pytest

from octorules.commands import (
    _apply_zone_changes,
    _get_zone_provider,
    _get_zone_providers,
    _plan_all_scopes,
    _PlanAllResult,
    _validate_multi_target,
)
from octorules.config import Config, ConfigError, ProviderConfig, ZoneConfig
from octorules.phases import get_phase
from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan
from octorules.provider.base import BaseProvider, Scope


def _make_zone_cfg(name: str = "unknown") -> MagicMock:
    """Create a mock ZoneConfig with targets pointing to cloudflare."""
    return MagicMock(name=name, targets=["cloudflare"], sources=["rules"])


def _mock_config():
    cfg = MagicMock()
    # Use defaultdict so tests that patch _get_zones with arbitrary zone names
    # still find entries in config.zones.
    zones = defaultdict(_make_zone_cfg)
    zones["example.com"] = _make_zone_cfg("example.com")
    cfg.zones = zones
    cfg.max_workers = 1
    cfg.providers = {
        "cloudflare": MagicMock(
            name="cloudflare",
            class_path=None,
            kwargs={"token": "tok", "max_workers": 1},
        ),
    }
    return cfg


def _mock_provider():
    prov = MagicMock(spec=BaseProvider)
    prov.account_id = "acct-1"
    prov.account_name = "my-account"
    return prov


_REDIRECT_PHASE = get_phase("redirect_rules")


def _make_zone_plan(zone_name: str, *, with_changes: bool = False) -> ZonePlan:
    zp = ZonePlan(zone_name=zone_name)
    if with_changes:
        change = RuleChange(
            change_type=ChangeType.ADD,
            ref="r1",
            phase=_REDIRECT_PHASE,
            desired={"ref": "r1", "expression": "true"},
        )
        zp.phase_plans.append(PhasePlan(phase=_REDIRECT_PHASE, changes=[change]))
    return zp


class TestPlanAllResult:
    def test_initial_state(self):
        r = _PlanAllResult()
        assert r.zone_plans == []
        assert r.desired_by_zone == {}
        assert r.current_by_zone == {}
        assert r.failed == []
        assert r.scope_map == {}
        assert r.account_labels == []
        assert r.account_label is None
        assert r.provider_map == {}

    def test_add_zones(self):
        r = _PlanAllResult()
        zp = _make_zone_plan("example.com")
        r._add_zones([zp], {"example.com": {}}, {"example.com": {}}, ["bad.com"])
        assert len(r.zone_plans) == 1
        assert "example.com" in r.desired_by_zone
        assert "example.com" in r.current_by_zone
        assert r.failed == ["bad.com"]

    def test_add_account_with_plan(self):
        r = _PlanAllResult()
        zp = _make_zone_plan("my-account")
        prov = MagicMock()
        prov.account_id = "acct-1"
        prov.account_name = "my-account"
        r._add_account(zp, {"my-account": {}}, {"my-account": {}}, prov)
        assert len(r.zone_plans) == 1
        assert r.account_label == "my-account"
        assert r.account_labels == ["my-account"]
        assert "my-account" in r.scope_map
        assert r.provider_map[("my-account", None)] is prov

    def test_add_account_none_plan(self):
        r = _PlanAllResult()
        prov = MagicMock()
        r._add_account(None, {}, {}, prov)
        assert len(r.zone_plans) == 0
        assert r.account_label is None


_PATCHES = [
    patch("octorules.commands._plan._plan_account"),
    patch("octorules.commands._plan._plan_zones"),
    patch("octorules.commands._helpers._get_zones"),
]


def _apply_patches():
    mocks = [p.start() for p in _PATCHES]
    return mocks[2], mocks[1], mocks[0]  # get_zones, plan_zones, plan_acct


def _stop_patches():
    for p in _PATCHES:
        p.stop()


class TestPlanAllScopes:
    def setup_method(self):
        self.get_zones, self.plan_zones, self.plan_acct = _apply_patches()
        self.cfg = _mock_config()
        self.prov = _mock_provider()
        self.providers = {"cloudflare": self.prov}

    def teardown_method(self):
        _stop_patches()

    def test_zones_only(self):
        self.get_zones.return_value = ["example.com"]
        zp = _make_zone_plan("example.com")
        self.plan_zones.return_value = ([zp], {"example.com": {}}, {"example.com": {}}, [])

        r = _plan_all_scopes(self.cfg, self.providers, None, None, scope_filter="zones")
        assert len(r.zone_plans) == 1
        assert r.account_label is None
        self.plan_acct.assert_not_called()

    def test_account_only(self):
        acct_plan = _make_zone_plan("my-account")
        self.plan_acct.return_value = (acct_plan, {"my-account": {}}, {"my-account": {}})

        r = _plan_all_scopes(self.cfg, self.providers, None, None, scope_filter="account")
        assert len(r.zone_plans) == 1
        assert r.account_label == "my-account"
        self.plan_zones.assert_not_called()
        self.get_zones.assert_not_called()

    def test_all_scopes(self):
        self.get_zones.return_value = ["example.com"]
        zp = _make_zone_plan("example.com")
        self.plan_zones.return_value = ([zp], {"example.com": {}}, {"example.com": {}}, [])
        acct_plan = _make_zone_plan("my-account")
        self.plan_acct.return_value = (acct_plan, {"my-account": {}}, {"my-account": {}})

        r = _plan_all_scopes(self.cfg, self.providers, None, None, scope_filter="all")
        assert len(r.zone_plans) == 2
        assert r.account_label == "my-account"
        assert "my-account" in r.scope_map

    def test_zone_failures_collected(self):
        self.get_zones.return_value = ["a.com", "b.com"]
        self.plan_zones.return_value = ([], {}, {}, ["a.com"])

        r = _plan_all_scopes(self.cfg, self.providers, None, None, scope_filter="zones")
        assert r.failed == ["a.com"]

    def test_account_none_plan_no_append(self):
        self.plan_acct.return_value = (None, {}, {})

        r = _plan_all_scopes(self.cfg, self.providers, None, None, scope_filter="account")
        assert len(r.zone_plans) == 0
        assert r.account_label is None

    def test_executor_passed_to_plan_zones(self):
        self.get_zones.return_value = ["example.com"]
        self.plan_zones.return_value = ([], {}, {}, [])
        executor = MagicMock()

        _plan_all_scopes(
            self.cfg,
            self.providers,
            None,
            None,
            scope_filter="zones",
            executor=executor,
        )
        # executor is passed as positional arg
        call_args = self.plan_zones.call_args
        assert call_args[0][4] is executor

    def test_zone_filter_passed(self):
        self.get_zones.return_value = ["b.com"]
        self.plan_zones.return_value = ([], {}, {}, [])

        _plan_all_scopes(self.cfg, self.providers, ["b.com"], None, scope_filter="zones")
        self.get_zones.assert_called_once_with(self.cfg, ["b.com"])


# ---------------------------------------------------------------------------
# Multi-provider routing tests
# ---------------------------------------------------------------------------
def _make_mock_provider(account_id=None, account_name=None):
    """Create a mock provider with configurable account info."""
    prov = MagicMock(spec=BaseProvider)
    prov.account_id = account_id
    prov.account_name = account_name
    return prov


def _multi_provider_config(tmp_path):
    """Build a Config with two providers and zones routed to each."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok=True)
    return Config(
        providers={
            "cloudflare": ProviderConfig(
                name="cloudflare",
                kwargs={"token": "cf-tok"},
            ),
            "aws": ProviderConfig(
                name="aws",
                kwargs={"region": "us-west-2"},
            ),
        },
        rules_dir=rules_dir,
        zones={
            "example.com": ZoneConfig(
                name="example.com",
                zone_id="zone-cf",
                sources=["rules"],
                targets=["cloudflare"],
            ),
            "other.com": ZoneConfig(
                name="other.com",
                zone_id="zone-cf-2",
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


class TestGetZoneProvider:
    """Tests for _get_zone_provider routing."""

    def test_routes_to_correct_provider(self):
        cf_prov = _make_mock_provider()
        aws_prov = _make_mock_provider()
        providers = {"cloudflare": cf_prov, "aws": aws_prov}

        zone_cfg = ZoneConfig(name="example.com", targets=["cloudflare"])
        assert _get_zone_provider(zone_cfg, providers) is cf_prov

        zone_cfg2 = ZoneConfig(name="my-web-acl", targets=["aws"])
        assert _get_zone_provider(zone_cfg2, providers) is aws_prov

    def test_single_provider_no_targets(self):
        """With one provider, zones without targets fall back to it."""
        prov = _make_mock_provider()
        providers = {"cloudflare": prov}

        zone_cfg = ZoneConfig(name="example.com", targets=[])
        assert _get_zone_provider(zone_cfg, providers) is prov

    def test_multiple_providers_no_targets_raises(self):
        """With multiple providers, zone without targets raises ConfigError."""
        cf_prov = _make_mock_provider()
        aws_prov = _make_mock_provider()
        providers = {"cloudflare": cf_prov, "aws": aws_prov}

        zone_cfg = ZoneConfig(name="example.com", targets=[])
        with pytest.raises(ConfigError, match="no target and multiple providers"):
            _get_zone_provider(zone_cfg, providers)


class TestMultiProviderRouting:
    """Integration tests verifying correct provider is called per zone during plan/sync/dump."""

    @patch("octorules.commands._plan._plan_account")
    @patch("octorules.commands._plan._plan_zones")
    @patch("octorules.commands._helpers._get_zones")
    def test_plan_routes_zones_to_correct_provider(
        self, mock_get_zones, mock_plan_zones, mock_plan_acct, tmp_path
    ):
        """_plan_all_scopes populates provider_map with the correct provider per zone."""
        cfg = _multi_provider_config(tmp_path)
        cf_prov = _make_mock_provider()
        aws_prov = _make_mock_provider()
        providers = {"cloudflare": cf_prov, "aws": aws_prov}

        mock_get_zones.return_value = ["example.com", "other.com", "my-web-acl"]
        mock_plan_zones.return_value = (
            [
                _make_zone_plan("example.com"),
                _make_zone_plan("other.com"),
                _make_zone_plan("my-web-acl"),
            ],
            {"example.com": {}, "other.com": {}, "my-web-acl": {}},
            {"example.com": {}, "other.com": {}, "my-web-acl": {}},
            [],
        )

        r = _plan_all_scopes(cfg, providers, None, None, scope_filter="zones")

        # Verify provider_map routes each zone to the right provider
        assert r.provider_map[("example.com", None)] is cf_prov
        assert r.provider_map[("other.com", None)] is cf_prov
        assert r.provider_map[("my-web-acl", None)] is aws_prov

    @patch("octorules.commands._plan._plan_account")
    @patch("octorules.commands._plan._plan_zones")
    @patch("octorules.commands._helpers._get_zones")
    def test_plan_runs_account_for_each_provider_with_account_id(
        self, mock_get_zones, mock_plan_zones, mock_plan_acct, tmp_path
    ):
        """_plan_all_scopes runs _plan_account for every provider with account info."""
        cfg = _multi_provider_config(tmp_path)
        cf_prov = _make_mock_provider(account_id="cf-acct", account_name="my-cf-account")
        aws_prov = _make_mock_provider(account_id="aws-acct", account_name="my-aws-account")
        providers = {"cloudflare": cf_prov, "aws": aws_prov}

        mock_get_zones.return_value = ["example.com"]
        mock_plan_zones.return_value = (
            [_make_zone_plan("example.com")],
            {"example.com": {}},
            {"example.com": {}},
            [],
        )
        # Each account plan returns a ZonePlan
        cf_acct_plan = _make_zone_plan("my-cf-account")
        aws_acct_plan = _make_zone_plan("my-aws-account")
        mock_plan_acct.side_effect = [
            (cf_acct_plan, {"my-cf-account": {}}, {"my-cf-account": {}}),
            (aws_acct_plan, {"my-aws-account": {}}, {"my-aws-account": {}}),
        ]

        r = _plan_all_scopes(cfg, providers, None, None, scope_filter="all")

        # Both account planning calls should have been made
        assert mock_plan_acct.call_count == 2
        # Verify providers passed to _plan_account
        plan_acct_providers = {c.args[1] for c in mock_plan_acct.call_args_list}
        assert cf_prov in plan_acct_providers
        assert aws_prov in plan_acct_providers
        # Result should contain both account labels
        assert set(r.account_labels) == {"my-cf-account", "my-aws-account"}
        # provider_map should map account labels to their providers
        assert r.provider_map[("my-cf-account", None)] is cf_prov
        assert r.provider_map[("my-aws-account", None)] is aws_prov

    @patch("octorules.commands._plan._plan_account")
    @patch("octorules.commands._plan._plan_zones")
    @patch("octorules.commands._helpers._get_zones")
    def test_plan_skips_account_for_providers_without_account_id(
        self, mock_get_zones, mock_plan_zones, mock_plan_acct, tmp_path
    ):
        """Providers without account_id are skipped for account planning."""
        cfg = _multi_provider_config(tmp_path)
        cf_prov = _make_mock_provider(account_id="cf-acct", account_name="my-cf-account")
        aws_prov = _make_mock_provider(account_id=None, account_name=None)
        providers = {"cloudflare": cf_prov, "aws": aws_prov}

        mock_get_zones.return_value = []
        mock_plan_zones.return_value = ([], {}, {}, [])
        cf_acct_plan = _make_zone_plan("my-cf-account")
        mock_plan_acct.return_value = (cf_acct_plan, {"my-cf-account": {}}, {"my-cf-account": {}})

        r = _plan_all_scopes(cfg, providers, None, None, scope_filter="all")

        # Only CF provider should have been planned for account
        assert mock_plan_acct.call_count == 1
        assert mock_plan_acct.call_args[0][1] is cf_prov
        assert r.account_labels == ["my-cf-account"]

    @patch("octorules.commands._plan._plan_account")
    @patch("octorules.commands._plan._plan_zones")
    @patch("octorules.commands._helpers._get_zones")
    def test_plan_zones_passes_providers_dict(
        self, mock_get_zones, mock_plan_zones, mock_plan_acct, tmp_path
    ):
        """_plan_zones receives the full providers dict for per-zone lookup."""
        cfg = _multi_provider_config(tmp_path)
        cf_prov = _make_mock_provider()
        aws_prov = _make_mock_provider()
        providers = {"cloudflare": cf_prov, "aws": aws_prov}

        mock_get_zones.return_value = ["example.com"]
        mock_plan_zones.return_value = ([], {}, {}, [])

        _plan_all_scopes(cfg, providers, None, None, scope_filter="zones")

        # _plan_zones should receive the full providers dict
        assert mock_plan_zones.call_args[0][1] is providers

    @patch("octorules.commands._sync._apply_single_zone")
    @patch("octorules.commands._helpers._map_ordered")
    def test_apply_routes_to_correct_provider(self, mock_map, mock_apply, tmp_path):
        """_apply_zone_changes passes the correct provider per zone."""
        cfg = _multi_provider_config(tmp_path)
        cf_prov = _make_mock_provider()
        aws_prov = _make_mock_provider()
        providers = {"cloudflare": cf_prov, "aws": aws_prov}

        zp_cf = _make_zone_plan("example.com", with_changes=True)
        zp_aws = _make_zone_plan("my-web-acl", with_changes=True)

        provider_map = {("example.com", None): cf_prov, ("my-web-acl", None): aws_prov}

        # Make _map_ordered just call the function on each item
        def side_effect(fn, items, *a, **kw):
            return [fn(item) for item in items]

        mock_map.side_effect = side_effect
        mock_apply.return_value = ("zone", ["phase"], None)

        _apply_zone_changes(
            [zp_cf, zp_aws],
            {"example.com": {}, "my-web-acl": {}},
            cfg,
            providers,
            provider_map=provider_map,
        )

        # Verify _apply_single_zone was called with the right provider
        assert mock_apply.call_count == 2
        # First call: example.com -> cf_prov
        first_call_args = mock_apply.call_args_list[0]
        assert first_call_args[0][2].label == "example.com"  # Scope
        assert first_call_args[0][3] is cf_prov
        # Second call: my-web-acl -> aws_prov
        second_call_args = mock_apply.call_args_list[1]
        assert second_call_args[0][2].label == "my-web-acl"  # Scope
        assert second_call_args[0][3] is aws_prov

    @patch("octorules.commands._sync._apply_single_zone")
    @patch("octorules.commands._helpers._map_ordered")
    def test_apply_account_scope_uses_provider_map(self, mock_map, mock_apply, tmp_path):
        """Account-scope zone plans use scope_map and provider_map."""
        cfg = _multi_provider_config(tmp_path)
        cf_prov = _make_mock_provider(account_id="cf-acct", account_name="my-cf-account")
        providers = {"cloudflare": cf_prov}

        zp = _make_zone_plan("my-cf-account", with_changes=True)

        scope = Scope(account_id="cf-acct", label="my-cf-account")
        scope_map = {"my-cf-account": scope}
        provider_map = {("my-cf-account", None): cf_prov}

        def side_effect(fn, items, *a, **kw):
            return [fn(item) for item in items]

        mock_map.side_effect = side_effect
        mock_apply.return_value = ("my-cf-account", ["waf_custom_rules"], None)

        _apply_zone_changes(
            [zp],
            {"my-cf-account": {}},
            cfg,
            providers,
            scope_map=scope_map,
            provider_map=provider_map,
        )

        assert mock_apply.call_count == 1
        call_args = mock_apply.call_args_list[0]
        assert call_args[0][2] is scope
        assert call_args[0][3] is cf_prov


class TestMultiProviderResolveZoneIds:
    """Tests verifying resolve_zone_ids uses per-provider resolve functions."""

    def test_per_provider_resolve(self, tmp_path):
        """Each zone's ID is resolved by its target provider's resolve function."""
        from octorules.config import resolve_zone_ids

        cfg = _multi_provider_config(tmp_path)
        # Reset zone_ids to None so they need resolving
        for zc in cfg.zones.values():
            zc.zone_id = None

        cf_resolve = MagicMock(side_effect=lambda name: f"cf-{name}")
        aws_resolve = MagicMock(side_effect=lambda name: f"aws-{name}")

        resolve_zone_ids(cfg, {"cloudflare": cf_resolve, "aws": aws_resolve})

        # CF zones resolved via cf_resolve
        assert cfg.zones["example.com"].zone_id == "cf-example.com"
        assert cfg.zones["other.com"].zone_id == "cf-other.com"
        cf_resolve.assert_any_call("example.com")
        cf_resolve.assert_any_call("other.com")

        # AWS zone resolved via aws_resolve
        assert cfg.zones["my-web-acl"].zone_id == "aws-my-web-acl"
        aws_resolve.assert_called_once_with("my-web-acl")

    def test_single_callable_resolve(self, tmp_path):
        """When a single callable is passed, all zones use it (backward compat)."""
        from octorules.config import resolve_zone_ids

        cfg = _multi_provider_config(tmp_path)
        for zc in cfg.zones.values():
            zc.zone_id = None

        resolve_fn = MagicMock(side_effect=lambda name: f"id-{name}")

        resolve_zone_ids(cfg, resolve_fn)

        assert cfg.zones["example.com"].zone_id == "id-example.com"
        assert cfg.zones["other.com"].zone_id == "id-other.com"
        assert cfg.zones["my-web-acl"].zone_id == "id-my-web-acl"
        assert resolve_fn.call_count == 3


class TestInitProviderRemoved:
    """Verify _init_provider() is no longer exported."""

    def test_init_provider_not_in_commands(self):
        from octorules import commands

        assert not hasattr(commands, "_init_provider")


# ---------------------------------------------------------------------------
# Feature negotiation (SUPPORTS) tests
# ---------------------------------------------------------------------------
class TestSupportsGuards:
    """Verify that commands skip unsupported features and log warnings."""

    def _make_limited_provider(self, supports: frozenset[str]):
        """Create a mock provider with a limited SUPPORTS set."""
        prov = MagicMock(spec=BaseProvider)
        prov.SUPPORTS = supports
        prov.account_id = "acct-1"
        prov.account_name = "my-account"
        prov.get_all_phase_rules.return_value = {}
        return prov

    @patch("octorules.commands._plan._plan_account")
    @patch("octorules.commands._plan._plan_zones")
    @patch("octorules.commands._helpers._get_zones")
    def test_plan_account_skips_unsupported_custom_rulesets(
        self, mock_get_zones, mock_plan_zones, mock_plan_acct
    ):
        """custom_rulesets fetch is skipped when provider doesn't support it."""
        prov = self._make_limited_provider(frozenset())
        cfg = _mock_config()

        # _plan_account is called with the real function, so we patch at a lower level
        # Instead, test the actual _plan_account function directly
        mock_plan_acct.return_value = (None, {}, {})
        mock_get_zones.return_value = []
        mock_plan_zones.return_value = ([], {}, {}, [])

        _plan_all_scopes(cfg, {"cloudflare": prov}, None, None, scope_filter="all")
        # Provider with no SUPPORTS: _plan_account should still be called
        mock_plan_acct.assert_called()

    def test_plan_account_skips_custom_rulesets_when_unsupported(self, tmp_path):
        """When provider doesn't support custom_rulesets, fetch is skipped."""
        from octorules.commands import _plan_account

        prov = self._make_limited_provider(frozenset())
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        acct_rules = rules_dir / "my-account.yaml"
        acct_rules.write_text(
            "custom_rulesets:\n  - id: rs-1\n    name: test\n    phase: x\n    rules: []\n"
        )
        cfg = MagicMock()
        cfg.load_account_rules.return_value = {
            "custom_rulesets": [{"id": "rs-1", "name": "test", "phase": "x", "rules": []}],
        }

        _plan_account(cfg, prov, None)

        # get_all_custom_rulesets should NOT be called
        prov.get_all_custom_rulesets.assert_not_called()

    def test_plan_account_skips_lists_when_unsupported(self, tmp_path):
        """When provider doesn't support lists, fetch is skipped."""
        from octorules.commands import _plan_account

        prov = self._make_limited_provider(frozenset())
        cfg = MagicMock()
        cfg.load_account_rules.return_value = {
            "lists": [{"name": "blocklist", "kind": "ip", "items": []}],
        }

        _plan_account(cfg, prov, None)

        prov.get_all_lists.assert_not_called()

    def test_plan_account_fetches_when_supported(self, tmp_path):
        """When provider supports features, fetches proceed."""
        from octorules.commands import _plan_account

        prov = self._make_limited_provider(frozenset({"custom_rulesets", "lists"}))
        prov.get_all_custom_rulesets.return_value = {}
        prov.get_all_lists.return_value = {}
        cfg = MagicMock()
        cfg.load_account_rules.return_value = {
            "custom_rulesets": [{"id": "rs-1", "name": "test", "phase": "x", "rules": []}],
            "lists": [{"name": "blocklist", "kind": "ip", "items": []}],
        }

        _plan_account(cfg, prov, None)

        prov.get_all_custom_rulesets.assert_called_once()
        prov.get_all_lists.assert_called_once()

    def test_backward_compat_no_supports_fetches_everything(self, tmp_path):
        """Provider without SUPPORTS gets all features fetched."""
        from octorules.commands import _plan_account

        prov = MagicMock(spec=BaseProvider)
        # Explicitly remove SUPPORTS so getattr returns None
        del prov.SUPPORTS
        prov.account_id = "acct-1"
        prov.account_name = "my-account"
        prov.get_all_phase_rules.return_value = {}
        prov.get_all_custom_rulesets.return_value = {}
        prov.get_all_lists.return_value = {}
        cfg = MagicMock()
        cfg.load_account_rules.return_value = {
            "custom_rulesets": [{"id": "rs-1", "name": "test", "phase": "x", "rules": []}],
            "lists": [{"name": "blocklist", "kind": "ip", "items": []}],
        }

        _plan_account(cfg, prov, None)

        prov.get_all_custom_rulesets.assert_called_once()
        prov.get_all_lists.assert_called_once()


# ---------------------------------------------------------------------------
# Multi-target zone tests
# ---------------------------------------------------------------------------
class TestMultiTarget:
    """Tests for multi-target zone support."""

    def test_get_zone_providers_single_target(self):
        prov = MagicMock(spec=BaseProvider)
        providers = {"cloudflare": prov}
        zone_cfg = ZoneConfig(name="example.com", targets=["cloudflare"])
        result = _get_zone_providers(zone_cfg, providers)
        assert result == [("cloudflare", prov)]

    def test_get_zone_providers_multi_target(self):
        cf = MagicMock(spec=BaseProvider)
        cf2 = MagicMock(spec=BaseProvider)
        providers = {"cf-prod": cf, "cf-staging": cf2}
        zone_cfg = ZoneConfig(name="example.com", targets=["cf-prod", "cf-staging"])
        result = _get_zone_providers(zone_cfg, providers)
        assert result == [("cf-prod", cf), ("cf-staging", cf2)]

    def test_get_zone_providers_no_targets_single_provider(self):
        """With one provider, zones without targets fall back to it."""
        prov = MagicMock(spec=BaseProvider)
        providers = {"cloudflare": prov}
        zone_cfg = ZoneConfig(name="example.com", targets=[])
        result = _get_zone_providers(zone_cfg, providers)
        assert result == [("cloudflare", prov)]

    def test_validate_multi_target_same_class_passes(self, tmp_path):
        class FakeProvider:
            pass

        prov1 = FakeProvider()
        prov2 = FakeProvider()
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            rules_dir=rules_dir,
            providers={
                "cf-prod": ProviderConfig(name="cf-prod"),
                "cf-staging": ProviderConfig(name="cf-staging"),
            },
            zones={
                "example.com": ZoneConfig(name="example.com", targets=["cf-prod", "cf-staging"]),
            },
        )
        # Should not raise
        _validate_multi_target(config, {"cf-prod": prov1, "cf-staging": prov2})

    def test_validate_multi_target_different_class_fails(self, tmp_path):
        class ProviderA:
            pass

        class ProviderB:
            pass

        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        config = Config(
            rules_dir=rules_dir,
            providers={
                "cloudflare": ProviderConfig(name="cloudflare"),
                "aws": ProviderConfig(name="aws"),
            },
            zones={
                "example.com": ZoneConfig(name="example.com", targets=["cloudflare", "aws"]),
            },
        )
        with pytest.raises(ConfigError, match="different provider classes"):
            _validate_multi_target(config, {"cloudflare": ProviderA(), "aws": ProviderB()})

    def test_provider_map_tuple_key(self):
        """provider_map uses (zone_name, target) tuple keys."""
        r = _PlanAllResult()
        assert r.provider_map == {}

    @patch("octorules.commands._plan._plan_account")
    @patch("octorules.commands._plan._plan_zones")
    @patch("octorules.commands._helpers._get_zones")
    def test_plan_produces_plan_per_target(
        self, mock_get_zones, mock_plan_zones, mock_plan_acct, tmp_path
    ):
        """Multi-target zone produces one ZonePlan per target."""
        rules_dir = tmp_path / "rules"
        rules_dir.mkdir()
        # Create two ZonePlans for the same zone with different targets
        zp1 = _make_zone_plan("example.com")
        zp1.target = "cf-prod"
        zp2 = _make_zone_plan("example.com")
        zp2.target = "cf-staging"

        mock_get_zones.return_value = ["example.com"]
        mock_plan_zones.return_value = (
            [zp1, zp2],
            {zp1.plan_key: {}, zp2.plan_key: {}},
            {zp1.plan_key: {}, zp2.plan_key: {}},
            [],
        )

        cfg = _mock_config()
        cf1 = _mock_provider()
        cf2 = _mock_provider()
        # Patch zones to have multi-target config
        cfg.zones["example.com"] = MagicMock(
            name="example.com", targets=["cf-prod", "cf-staging"], sources=["rules"]
        )

        r = _plan_all_scopes(
            cfg,
            {"cf-prod": cf1, "cf-staging": cf2},
            None,
            None,
            scope_filter="zones",
        )
        assert len(r.zone_plans) == 2
        assert r.provider_map[("example.com", "cf-prod")] is cf1
        assert r.provider_map[("example.com", "cf-staging")] is cf2

    @patch("octorules.commands._plan._plan_account")
    @patch("octorules.commands._plan._plan_zones")
    @patch("octorules.commands._helpers._get_zones")
    def test_single_target_backward_compat(self, mock_get_zones, mock_plan_zones, mock_plan_acct):
        """Single-target zones still use (zone_name, None) key -- target is None."""
        cfg = _mock_config()
        prov = _mock_provider()
        providers = {"cloudflare": prov}

        mock_get_zones.return_value = ["example.com"]
        zp = _make_zone_plan("example.com")
        mock_plan_zones.return_value = ([zp], {"example.com": {}}, {"example.com": {}}, [])

        r = _plan_all_scopes(cfg, providers, None, None, scope_filter="zones")
        assert len(r.zone_plans) == 1
        assert r.zone_plans[0].target is None
        assert ("example.com", None) in r.provider_map


# ---------------------------------------------------------------------------
# Target-name threading tests
# ---------------------------------------------------------------------------
class TestTargetNameThreading:
    """Verify target_name is passed through to _plan_single_zone for target filtering."""

    def _make_limited_provider(self, supports: frozenset[str] | None = None):
        prov = MagicMock(spec=BaseProvider)
        prov.SUPPORTS = supports or frozenset()
        prov.account_id = "acct-1"
        prov.account_name = "my-account"
        prov.get_all_phase_rules.return_value = {}
        return prov

    def test_plan_single_zone_filters_by_target(self):
        """_plan_single_zone applies target filtering when target_name is given."""
        from octorules.commands import _plan_single_zone

        prov = self._make_limited_provider()
        cfg = MagicMock()
        cfg.zones = {
            "example.com": MagicMock(zone_id="z-1", allow_unmanaged=False, processors=[]),
        }
        cfg.load_zone_rules.return_value = {
            "waf_custom_rules": [
                {"ref": "both", "expression": "true", "action": "block"},
                {
                    "ref": "cf-only",
                    "expression": "true",
                    "action": "block",
                    "octorules": {"included": ["cloudflare"]},
                },
                {
                    "ref": "aws-only",
                    "expression": "true",
                    "action": "block",
                    "octorules": {"included": ["aws"]},
                },
            ],
        }

        _, zp, _, _ = _plan_single_zone(cfg, prov, "example.com", None, target_name="cloudflare")
        # Only "both" and "cf-only" should appear; "aws-only" filtered out
        added_refs = {c.ref for c in zp.phase_plans[0].changes if c.change_type.value == "add"}
        assert "both" in added_refs
        assert "cf-only" in added_refs
        assert "aws-only" not in added_refs

    def test_plan_single_zone_no_target_no_filter(self):
        """Without target_name, all rules pass through."""
        from octorules.commands import _plan_single_zone

        prov = self._make_limited_provider()
        cfg = MagicMock()
        cfg.zones = {
            "example.com": MagicMock(zone_id="z-1", allow_unmanaged=False, processors=[]),
        }
        cfg.load_zone_rules.return_value = {
            "waf_custom_rules": [
                {"ref": "r1", "expression": "true", "action": "block"},
                {
                    "ref": "r2",
                    "expression": "true",
                    "action": "block",
                    "octorules": {"included": ["cloudflare"]},
                },
            ],
        }

        _, zp, _, _ = _plan_single_zone(cfg, prov, "example.com", None)
        added_refs = {c.ref for c in zp.phase_plans[0].changes}
        assert added_refs == {"r1", "r2"}

    @patch("octorules.commands._plan._plan_single_zone_safe")
    def test_plan_zones_threads_target_name(self, mock_safe):
        """_plan_zones passes target_name to _plan_single_zone_safe."""
        from octorules.commands import _plan_zones

        cf = MagicMock(spec=BaseProvider)
        aws = MagicMock(spec=BaseProvider)
        providers = {"cloudflare": cf, "aws": aws}

        cfg = MagicMock()
        cfg.zones = {
            "a.com": MagicMock(targets=["cloudflare"]),
            "b.com": MagicMock(targets=["aws"]),
        }
        cfg.max_workers = 1

        mock_safe.side_effect = lambda *a, **kw: (
            a[2],  # zone_name
            ZonePlan(zone_name=a[2]),
            {},
            {},
        )

        _plan_zones(cfg, providers, ["a.com", "b.com"], None)

        # Check that target_name was passed
        calls = mock_safe.call_args_list
        assert calls[0].kwargs.get("target_name") == "cloudflare"
        assert calls[1].kwargs.get("target_name") == "aws"

    @patch("octorules.commands._plan._plan_single_zone_safe")
    def test_plan_zones_multi_target_threads_target_name(self, mock_safe):
        """Multi-target zones pass the real target_name for each."""
        from octorules.commands import _plan_zones

        cf1 = MagicMock(spec=BaseProvider)
        cf2 = MagicMock(spec=BaseProvider)
        providers = {"cf-prod": cf1, "cf-staging": cf2}

        cfg = MagicMock()
        cfg.zones = {
            "example.com": MagicMock(targets=["cf-prod", "cf-staging"]),
        }
        cfg.max_workers = 1

        mock_safe.side_effect = lambda *a, **kw: (
            a[2],
            ZonePlan(zone_name=a[2]),
            {},
            {},
        )

        _plan_zones(cfg, providers, ["example.com"], None)

        calls = mock_safe.call_args_list
        assert len(calls) == 2
        assert calls[0].kwargs.get("target_name") == "cf-prod"
        assert calls[1].kwargs.get("target_name") == "cf-staging"
