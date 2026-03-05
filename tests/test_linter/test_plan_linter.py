"""Tests for plan linter (Category H)."""

from __future__ import annotations

from octorules.linter.engine import LintContext
from octorules.linter.plan_linter import lint_plan_tier


def _lint(rules_data, plan_tier="free"):
    ctx = LintContext(plan_tier=plan_tier)
    lint_plan_tier(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestRegexAvailability:
    def test_h001_regex_on_free_plan(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="free",
        )
        assert "H001" in _ids(ctx)

    def test_h001_regex_on_pro_plan(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="pro",
        )
        assert "H001" in _ids(ctx)

    def test_h001_regex_on_business_plan_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="business",
        )
        assert "H001" not in _ids(ctx)

    def test_h001_regex_on_enterprise_plan_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path matches "^/api"',
                        "action": "block",
                    }
                ]
            },
            plan_tier="enterprise",
        )
        assert "H001" not in _ids(ctx)


class TestRuleLimits:
    def test_h002_exceeds_free_limit(self):
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(11)
        ]
        ctx = _lint({"redirect_rules": rules}, plan_tier="free")
        assert "H002" in _ids(ctx)

    def test_h002_within_free_limit(self):
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(10)
        ]
        ctx = _lint({"redirect_rules": rules}, plan_tier="free")
        assert "H002" not in _ids(ctx)

    def test_h002_enterprise_no_limit(self):
        rules = [
            {"ref": f"rule-{i}", "expression": f'http.host eq "host{i}.com"'} for i in range(200)
        ]
        ctx = _lint({"redirect_rules": rules}, plan_tier="enterprise")
        assert "H002" not in _ids(ctx)


class TestNonPhaseKeysIgnored:
    def test_custom_rulesets_skipped(self):
        ctx = _lint({"custom_rulesets": [{"ref": "x"}]}, plan_tier="free")
        assert len(ctx.results) == 0

    def test_lists_skipped(self):
        ctx = _lint({"lists": [{"ref": "x"}]}, plan_tier="free")
        assert len(ctx.results) == 0
