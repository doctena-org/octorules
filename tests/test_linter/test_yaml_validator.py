"""Tests for YAML structure validation (Category M)."""

from __future__ import annotations

from octorules.linter.engine import LintContext, Severity
from octorules.linter.yaml_validator import lint_yaml_structure

from .conftest import assert_lint, assert_no_lint


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_yaml_structure(rules_data, ctx)
    return ctx


class TestTopLevelKeys:
    def test_valid_phase_names(self):
        ctx = _lint({"redirect_rules": [], "cache_rules": []})
        assert len(ctx.results) == 0
        assert_no_lint(ctx, "M007")

    def test_unknown_phase_key(self):
        ctx = _lint({"bogus_phase": []})
        assert len(ctx.results) == 1
        m007 = assert_lint(ctx, "M007", count=1, severity=Severity.WARNING)
        assert "bogus_phase" in m007[0].message

    def test_deprecated_phase_name(self):
        ctx = _lint({"waf_managed_exceptions": []})
        m008 = assert_lint(ctx, "M008", count=1, severity=Severity.WARNING)
        assert "waf_managed_rules" in m008[0].message

    def test_cf_phase_identifier(self):
        ctx = _lint({"http_request_dynamic_redirect": []})
        m012 = assert_lint(ctx, "M012", count=1, severity=Severity.WARNING)
        assert "redirect_rules" in m012[0].suggestion

    def test_known_non_phase_keys_ignored(self):
        ctx = _lint({"custom_rulesets": [], "lists": [], "page_shield_policies": []})
        assert len(ctx.results) == 0


class TestPhaseRules:
    def test_phase_not_a_list(self):
        ctx = _lint({"redirect_rules": "not-a-list"})
        m010 = [r for r in ctx.results if r.rule_id == "M010"]
        assert len(m010) == 1

    def test_rule_not_a_dict(self):
        ctx = _lint({"redirect_rules": ["string-not-dict"]})
        m011 = [r for r in ctx.results if r.rule_id == "M011"]
        assert len(m011) == 1


class TestRuleFields:
    def test_missing_ref(self):
        ctx = _lint({"redirect_rules": [{"expression": "true"}]})
        m001 = [r for r in ctx.results if r.rule_id == "M001"]
        assert len(m001) == 1

    def test_invalid_ref_type(self):
        ctx = _lint({"redirect_rules": [{"ref": 123, "expression": "true"}]})
        m004 = [r for r in ctx.results if r.rule_id == "M004"]
        assert len(m004) == 1

    def test_empty_ref(self):
        ctx = _lint({"redirect_rules": [{"ref": "", "expression": "true"}]})
        m004 = [r for r in ctx.results if r.rule_id == "M004"]
        assert len(m004) == 1

    def test_missing_expression(self):
        ctx = _lint({"redirect_rules": [{"ref": "test"}]})
        m002 = [r for r in ctx.results if r.rule_id == "M002"]
        assert len(m002) == 1

    def test_invalid_expression_type(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": 42}]})
        m005 = [r for r in ctx.results if r.rule_id == "M005"]
        assert len(m005) == 1

    def test_empty_expression(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": ""}]})
        m005 = [r for r in ctx.results if r.rule_id == "M005"]
        assert len(m005) == 1

    def test_duplicate_refs(self):
        ctx = _lint(
            {
                "redirect_rules": [
                    {"ref": "dup", "expression": "true"},
                    {"ref": "dup", "expression": "false"},
                ]
            }
        )
        m003 = assert_lint(ctx, "M003", count=1, severity=Severity.ERROR, phase="redirect_rules")
        assert "dup" in m003[0].message

    def test_invalid_enabled_type(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": "true", "enabled": "yes"}]})
        m006 = [r for r in ctx.results if r.rule_id == "M006"]
        assert len(m006) == 1

    def test_valid_enabled_bool(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": "true", "enabled": False}]})
        m006 = [r for r in ctx.results if r.rule_id == "M006"]
        assert len(m006) == 0

    def test_description_too_long(self):
        ctx = _lint(
            {"redirect_rules": [{"ref": "test", "expression": "true", "description": "x" * 501}]}
        )
        m009 = [r for r in ctx.results if r.rule_id == "M009"]
        assert len(m009) == 1

    def test_description_ok_length(self):
        ctx = _lint(
            {"redirect_rules": [{"ref": "test", "expression": "true", "description": "x" * 500}]}
        )
        m009 = [r for r in ctx.results if r.rule_id == "M009"]
        assert len(m009) == 0


class TestValidRule:
    def test_no_errors_for_valid_rule(self):
        ctx = _lint(
            {
                "redirect_rules": [
                    {"ref": "my-rule", "expression": 'http.host eq "example.com"', "enabled": True}
                ]
            }
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0


class TestAlwaysTrueFalse:
    def test_m013_always_true(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": "true"}]})
        m013 = assert_lint(
            ctx, "M013", count=1, severity=Severity.WARNING, ref="test", phase="redirect_rules"
        )
        assert "always true" in m013[0].message

    def test_m013_always_true_parens(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": "(true)"}]})
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 1

    def test_m013_not_triggered_for_complex_expr(self):
        ctx = _lint(
            {"redirect_rules": [{"ref": "test", "expression": 'http.host eq "example.com"'}]}
        )
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 0

    def test_m014_always_false(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": "false"}]})
        m014 = [r for r in ctx.results if r.rule_id == "M014"]
        assert len(m014) == 1
        assert "never match" in m014[0].message

    def test_m014_always_false_parens(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": "(false)"}]})
        m014 = [r for r in ctx.results if r.rule_id == "M014"]
        assert len(m014) == 1


class TestExpressionLength:
    def test_m015_too_long(self):
        long_expr = "x" * 4097
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": long_expr}]})
        m015 = [r for r in ctx.results if r.rule_id == "M015"]
        assert len(m015) == 1
        assert "4097" in m015[0].message

    def test_m015_at_limit_ok(self):
        expr = "x" * 4096
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": expr}]})
        m015 = [r for r in ctx.results if r.rule_id == "M015"]
        assert len(m015) == 0

    def test_m015_short_ok(self):
        ctx = _lint({"redirect_rules": [{"ref": "test", "expression": 'http.host eq "a.com"'}]})
        m015 = [r for r in ctx.results if r.rule_id == "M015"]
        assert len(m015) == 0


class TestPhaseFilter:
    def test_phase_filter_skips_unmatched(self):
        ctx = _lint(
            {"redirect_rules": [{"expression": "true"}]},  # missing ref
            phase_filter=["cache_rules"],
        )
        m001 = [r for r in ctx.results if r.rule_id == "M001"]
        assert len(m001) == 0

    def test_phase_filter_includes_matched(self):
        ctx = _lint(
            {"redirect_rules": [{"expression": "true"}]},  # missing ref
            phase_filter=["redirect_rules"],
        )
        m001 = [r for r in ctx.results if r.rule_id == "M001"]
        assert len(m001) == 1


class TestDisabledRule:
    def test_m016_disabled_rule(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "disabled-rule",
                        "expression": 'http.host eq "example.com"',
                        "action": "block",
                        "enabled": False,
                    }
                ]
            }
        )
        m016 = assert_lint(
            ctx,
            "M016",
            count=1,
            severity=Severity.INFO,
            ref="disabled-rule",
            phase="waf_custom_rules",
        )
        assert "disabled" in m016[0].message.lower()

    def test_m016_enabled_rule_no_warning(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "active-rule",
                        "expression": 'http.host eq "example.com"',
                        "action": "block",
                        "enabled": True,
                    }
                ]
            }
        )
        m016 = [r for r in ctx.results if r.rule_id == "M016"]
        assert len(m016) == 0

    def test_m016_missing_enabled_no_warning(self):
        """No 'enabled' key at all — rule is implicitly enabled."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "implicit-enabled",
                        "expression": 'http.host eq "example.com"',
                        "action": "block",
                    }
                ]
            }
        )
        m016 = [r for r in ctx.results if r.rule_id == "M016"]
        assert len(m016) == 0
