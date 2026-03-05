"""Tests for phase linter (Category B)."""

from __future__ import annotations

from octorules.linter.engine import LintContext
from octorules.linter.phase_linter import lint_phase_restrictions
from octorules.phases import PHASE_BY_NAME


def _lint(expression, phase_name):
    rule = {"ref": "test", "expression": expression}
    phase = PHASE_BY_NAME[phase_name]
    ctx = LintContext()
    lint_phase_restrictions(rule, phase, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestResponseFieldInRequestPhase:
    def test_b001_response_field_in_redirect(self):
        ctx = _lint("http.response.code eq 200", "redirect_rules")
        assert "B001" in _ids(ctx)

    def test_b001_response_field_in_waf(self):
        ctx = _lint("http.response.code eq 200", "waf_custom_rules")
        assert "B001" in _ids(ctx)

    def test_b001_response_field_in_response_phase_ok(self):
        ctx = _lint("http.response.code eq 200", "response_header_rules")
        assert "B001" not in _ids(ctx)

    def test_b001_request_field_in_request_phase_ok(self):
        ctx = _lint('http.host eq "example.com"', "redirect_rules")
        assert "B001" not in _ids(ctx)


class TestBodyFieldRestriction:
    def test_b002_body_field_in_redirect(self):
        ctx = _lint("http.request.body.size gt 0", "redirect_rules")
        assert "B002" in _ids(ctx)

    def test_b002_body_field_in_waf_ok(self):
        ctx = _lint("http.request.body.size gt 0", "waf_custom_rules")
        assert "B002" not in _ids(ctx)

    def test_b002_body_field_in_rate_limit_ok(self):
        ctx = _lint("http.request.body.size gt 0", "rate_limiting_rules")
        assert "B002" not in _ids(ctx)


class TestPlanGatedField:
    def test_b003_enterprise_field_on_free(self):
        rule = {"ref": "test", "expression": "cf.bot_management.score gt 30"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="free")
        lint_phase_restrictions(rule, phase, ctx)
        ids = [r.rule_id for r in ctx.results]
        assert "B003" in ids

    def test_b003_enterprise_field_on_enterprise_ok(self):
        rule = {"ref": "test", "expression": "cf.bot_management.score gt 30"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="enterprise")
        lint_phase_restrictions(rule, phase, ctx)
        ids = [r.rule_id for r in ctx.results]
        assert "B003" not in ids

    def test_b003_not_triggered_for_all_plan_field(self):
        rule = {"ref": "test", "expression": "cf.threat_score gt 30"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="free")
        lint_phase_restrictions(rule, phase, ctx)
        ids = [r.rule_id for r in ctx.results]
        assert "B003" not in ids


class TestNoExpression:
    def test_no_crash_on_missing_expression(self):
        rule = {"ref": "test"}
        phase = PHASE_BY_NAME["redirect_rules"]
        ctx = LintContext()
        lint_phase_restrictions(rule, phase, ctx)
        assert len(ctx.results) == 0
