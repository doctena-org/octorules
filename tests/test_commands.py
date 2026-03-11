"""Tests for the _plan_all_scopes() helper and _PlanAllResult."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from octorules.commands import _plan_all_scopes, _PlanAllResult
from octorules.planner import ZonePlan
from octorules.provider import CloudflareProvider


def _mock_config():
    cfg = MagicMock()
    cfg.zones = {"example.com": MagicMock()}
    cfg.max_retries = 0
    cfg.timeout = None
    cfg.max_workers = 1
    cfg.token = "tok"
    cfg.account_id = "acct-1"
    return cfg


def _mock_provider():
    prov = MagicMock(spec=CloudflareProvider)
    prov.account_id = "acct-1"
    prov.account_name = "my-account"
    return prov


def _make_zone_plan(zone_name: str) -> ZonePlan:
    return ZonePlan(zone_name=zone_name)


class TestPlanAllResult:
    def test_initial_state(self):
        r = _PlanAllResult()
        assert r.zone_plans == []
        assert r.desired_by_zone == {}
        assert r.current_by_zone == {}
        assert r.failed == []
        assert r.scope_map == {}
        assert r.account_label is None

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
        assert "my-account" in r.scope_map

    def test_add_account_none_plan(self):
        r = _PlanAllResult()
        prov = MagicMock()
        r._add_account(None, {}, {}, prov)
        assert len(r.zone_plans) == 0
        assert r.account_label is None


_PATCHES = [
    patch("octorules.commands._plan_account"),
    patch("octorules.commands._plan_zones"),
    patch("octorules.commands._get_zones"),
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

    def teardown_method(self):
        _stop_patches()

    def test_zones_only(self):
        self.get_zones.return_value = ["example.com"]
        zp = _make_zone_plan("example.com")
        self.plan_zones.return_value = ([zp], {"example.com": {}}, {"example.com": {}}, [])

        r = _plan_all_scopes(self.cfg, self.prov, None, None, scope_filter="zones")
        assert len(r.zone_plans) == 1
        assert r.account_label is None
        self.plan_acct.assert_not_called()

    def test_account_only(self):
        acct_plan = _make_zone_plan("my-account")
        self.plan_acct.return_value = (acct_plan, {"my-account": {}}, {"my-account": {}})

        r = _plan_all_scopes(self.cfg, self.prov, None, None, scope_filter="account")
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

        r = _plan_all_scopes(self.cfg, self.prov, None, None, scope_filter="all")
        assert len(r.zone_plans) == 2
        assert r.account_label == "my-account"
        assert "my-account" in r.scope_map

    def test_zone_failures_collected(self):
        self.get_zones.return_value = ["a.com", "b.com"]
        self.plan_zones.return_value = ([], {}, {}, ["a.com"])

        r = _plan_all_scopes(self.cfg, self.prov, None, None, scope_filter="zones")
        assert r.failed == ["a.com"]

    def test_account_none_plan_no_append(self):
        self.plan_acct.return_value = (None, {}, {})

        r = _plan_all_scopes(self.cfg, self.prov, None, None, scope_filter="account")
        assert len(r.zone_plans) == 0
        assert r.account_label is None

    def test_executor_passed_to_plan_zones(self):
        self.get_zones.return_value = ["example.com"]
        self.plan_zones.return_value = ([], {}, {}, [])
        executor = MagicMock()

        _plan_all_scopes(
            self.cfg,
            self.prov,
            None,
            None,
            scope_filter="zones",
            executor=executor,
        )
        # executor is passed as positional arg (5th)
        assert self.plan_zones.call_args[0][-1] is executor

    def test_zone_filter_passed(self):
        self.get_zones.return_value = ["b.com"]
        self.plan_zones.return_value = ([], {}, {}, [])

        _plan_all_scopes(self.cfg, self.prov, ["b.com"], None, scope_filter="zones")
        self.get_zones.assert_called_once_with(self.cfg, ["b.com"])
