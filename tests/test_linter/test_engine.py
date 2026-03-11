"""Tests for lint engine orchestrator."""

from __future__ import annotations

import textwrap

from octorules.linter.engine import (
    LintContext,
    LintResult,
    Severity,
    check_catch_all,
    is_always_false,
    is_always_true,
    lint_zone_file,
)
from octorules.linter.suppressions import parse_suppressions


class TestLintResult:
    def test_str_representation(self):
        r = LintResult(
            rule_id="M001",
            severity=Severity.ERROR,
            message="Missing ref",
            phase="redirect_rules",
            ref="test",
        )
        s = str(r)
        assert "ERROR" in s
        assert "M001" in s
        assert "Missing ref" in s
        assert "redirect_rules" in s

    def test_str_with_suggestion(self):
        r = LintResult(
            rule_id="G001",
            severity=Severity.WARNING,
            message="Method should be uppercase",
            suggestion="Use GET",
        )
        s = str(r)
        assert "[fix: Use GET]" in s


class TestLintContext:
    def test_add_respects_severity_filter(self):
        ctx = LintContext(severity_filter=Severity.WARNING)
        ctx.add(LintResult(rule_id="O001", severity=Severity.INFO, message="info"))
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="error"))
        ctx.add(LintResult(rule_id="G001", severity=Severity.WARNING, message="warning"))
        assert len(ctx.results) == 2
        assert all(r.severity <= Severity.WARNING for r in ctx.results)

    def test_add_respects_rule_filter(self):
        ctx = LintContext(rule_filter=["M001"])
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="m001"))
        ctx.add(LintResult(rule_id="M002", severity=Severity.ERROR, message="m002"))
        assert len(ctx.results) == 1
        assert ctx.results[0].rule_id == "M001"

    def test_add_respects_phase_filter(self):
        ctx = LintContext(phase_filter=["redirect_rules"])
        ctx.add(
            LintResult(rule_id="M001", severity=Severity.ERROR, message="r", phase="redirect_rules")
        )
        ctx.add(
            LintResult(rule_id="M001", severity=Severity.ERROR, message="c", phase="cache_rules")
        )
        assert len(ctx.results) == 1

    def test_errors_property(self):
        ctx = LintContext()
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="e"))
        ctx.add(LintResult(rule_id="G001", severity=Severity.WARNING, message="w"))
        assert len(ctx.errors) == 1
        assert len(ctx.warnings) == 1

    def test_has_errors(self):
        ctx = LintContext()
        assert not ctx.has_errors
        ctx.add(LintResult(rule_id="M001", severity=Severity.ERROR, message="e"))
        assert ctx.has_errors


class TestLintZoneFile:
    def test_valid_rules_no_errors(self):
        ctx = lint_zone_file(
            {
                "redirect_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.host eq "example.com"',
                        "action": "redirect",
                        "action_parameters": {
                            "from_value": {
                                "target_url": {"value": "/new"},
                                "status_code": 301,
                            }
                        },
                    }
                ]
            }
        )
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        assert len(errors) == 0

    def test_missing_ref_caught(self):
        ctx = lint_zone_file({"redirect_rules": [{"expression": "true"}]})
        m001 = [r for r in ctx.results if r.rule_id == "M001"]
        assert len(m001) == 1

    def test_unknown_phase_caught(self):
        ctx = lint_zone_file({"bogus_phase": []})
        m007 = [r for r in ctx.results if r.rule_id == "M007"]
        assert len(m007) == 1

    def test_severity_filter_works(self):
        ctx = lint_zone_file(
            {"redirect_rules": [{"expression": "true"}]},
            severity_filter=Severity.ERROR,
        )
        assert all(r.severity == Severity.ERROR for r in ctx.results)

    def test_file_path_and_zone_name(self):
        ctx = lint_zone_file(
            {"redirect_rules": []},
            file_path="/tmp/test.yaml",
            zone_name="example.com",
        )
        assert ctx.file_path == "/tmp/test.yaml"
        assert ctx.zone_name == "example.com"

    def test_invalid_action_caught(self):
        ctx = lint_zone_file(
            {
                "redirect_rules": [
                    {
                        "ref": "test",
                        "expression": "true",
                        "action": "block",  # invalid for redirect_rules
                    }
                ]
            }
        )
        c001 = [r for r in ctx.results if r.rule_id == "C001"]
        assert len(c001) == 1

    def test_response_field_in_request_phase(self):
        ctx = lint_zone_file(
            {"redirect_rules": [{"ref": "test", "expression": "http.response.code eq 200"}]}
        )
        b001 = [r for r in ctx.results if r.rule_id == "B001"]
        assert len(b001) == 1

    def test_custom_ruleset_gets_phase_restrictions(self):
        """Custom ruleset rules should be checked for field/phase restrictions (B001)."""
        ctx = lint_zone_file(
            {
                "custom_rulesets": [
                    {
                        "id": "a" * 32,
                        "name": "my-ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {
                                "ref": "bad-field",
                                "expression": "http.response.code eq 403",
                                "action": "block",
                            }
                        ],
                    }
                ]
            }
        )
        b001 = [r for r in ctx.results if r.rule_id == "B001"]
        assert len(b001) == 1
        assert b001[0].ref == "bad-field"

    def test_custom_ruleset_gets_action_validation(self):
        """Custom ruleset rules should be checked for invalid actions (C001)."""
        ctx = lint_zone_file(
            {
                "custom_rulesets": [
                    {
                        "id": "a" * 32,
                        "name": "my-ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {
                                "ref": "bad-action",
                                "expression": "true",
                                "action": "redirect",  # invalid for waf_custom_rules
                            }
                        ],
                    }
                ]
            }
        )
        c001 = [r for r in ctx.results if r.rule_id == "C001"]
        assert len(c001) == 1

    def test_custom_ruleset_gets_expression_analysis(self):
        """Custom ruleset rules should be checked for expression issues (G003)."""
        ctx = lint_zone_file(
            {
                "custom_rulesets": [
                    {
                        "id": "a" * 32,
                        "name": "my-ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {
                                "ref": "regex-anchor",
                                "expression": 'http.request.uri.path eq "^/api"',
                                "action": "block",
                            }
                        ],
                    }
                ]
            }
        )
        g003 = [r for r in ctx.results if r.rule_id == "G003"]
        assert len(g003) == 1

    def test_page_shield_gets_phase_restrictions(self):
        """Page Shield policies with plan-gated fields should fire B003 on free tier."""
        ctx = lint_zone_file(
            {
                "page_shield_policies": [
                    {
                        "description": "bot-check",
                        "action": "allow",
                        "expression": "cf.bot_management.score gt 30",
                        "enabled": True,
                        "value": "script-src 'self'",
                    }
                ]
            },
            plan_tier="free",
        )
        b003 = [r for r in ctx.results if r.rule_id == "B003"]
        assert len(b003) == 1
        assert b003[0].ref == "bot-check"

    def test_regex_anchor_in_literal(self):
        ctx = lint_zone_file(
            {
                "waf_custom_rules": [
                    {
                        "ref": "test",
                        "expression": 'http.request.uri.path eq "^/api"',
                        "action": "block",
                    }
                ]
            }
        )
        g003 = [r for r in ctx.results if r.rule_id == "G003"]
        assert len(g003) == 1


class TestSuppressions:
    """Tests for # octorules:disable suppression directives."""

    def test_rule_level_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            redirect_rules:
              # octorules:disable=M013
              - ref: catch-all
                expression: (true)
        """)
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("catch-all", set())

    def test_file_level_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            # octorules:disable=O002
            redirect_rules:
              - ref: my-rule
                expression: 'raw.http.request.uri.path eq "/x"'
        """)
        )
        suppressions = parse_suppressions(f)
        assert "O002" in suppressions.get("*", set())

    def test_multiple_ids_comma_separated(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            redirect_rules:
              # octorules:disable=M013,O001
              - ref: catch-all
                expression: (true)
        """)
        )
        suppressions = parse_suppressions(f)
        assert suppressions["catch-all"] == {"M013", "O001"}

    def test_no_directives(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            textwrap.dedent("""\
            redirect_rules:
              - ref: my-rule
                expression: 'http.host eq "example.com"'
        """)
        )
        suppressions = parse_suppressions(f)
        assert suppressions == {}

    def test_suppression_filters_results(self):
        ctx = LintContext(suppressions={"catch-all": {"M013"}})
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="catch-all",
            )
        )
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="other-rule",
            )
        )
        assert len(ctx.results) == 1
        assert ctx.results[0].ref == "other-rule"
        assert ctx.suppressed_count == 1

    def test_file_level_suppresses_all_refs(self):
        ctx = LintContext(suppressions={"*": {"O002"}})
        ctx.add(
            LintResult(
                rule_id="O002",
                severity=Severity.INFO,
                message="use normalized",
                ref="rule-a",
            )
        )
        ctx.add(
            LintResult(
                rule_id="O002",
                severity=Severity.INFO,
                message="use normalized",
                ref="rule-b",
            )
        )
        assert len(ctx.results) == 0
        assert ctx.suppressed_count == 2

    def test_suppression_does_not_affect_other_rules(self):
        ctx = LintContext(suppressions={"my-ref": {"M013"}})
        ctx.add(
            LintResult(
                rule_id="G010",
                severity=Severity.WARNING,
                message="deprecated field",
                ref="my-ref",
            )
        )
        assert len(ctx.results) == 1

    def test_lint_zone_file_with_suppressions(self):
        ctx = lint_zone_file(
            {
                "request_header_rules": [
                    {"ref": "catch-all", "expression": "(true)"},
                ]
            },
            suppressions={"catch-all": {"M013"}},
        )
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 0
        assert ctx.suppressed_count >= 1

    def test_missing_file_returns_empty(self):
        suppressions = parse_suppressions("/nonexistent/path.yaml")
        assert suppressions == {}

    def test_unknown_rule_id_warns(self, tmp_path, caplog):
        """Suppressing an unknown rule ID logs a warning and drops it."""
        import logging

        f = tmp_path / "test.yaml"
        f.write_text("# octorules:disable=X999\n- ref: foo\n  expression: 'true'\n")
        with caplog.at_level(logging.WARNING, logger="octorules.linter"):
            suppressions = parse_suppressions(f, known_rules={"M001", "M002"})
        assert "Unknown rule ID 'X999'" in caplog.text
        # X999 should not appear in suppressions
        all_ids = set()
        for ids in suppressions.values():
            all_ids |= ids
        assert "X999" not in all_ids

    def test_known_rule_id_not_warned(self, tmp_path, caplog):
        """Known rule IDs should not produce warnings."""
        import logging

        f = tmp_path / "test.yaml"
        f.write_text("# octorules:disable=M001\n- ref: foo\n  expression: 'true'\n")
        with caplog.at_level(logging.WARNING, logger="octorules.linter"):
            suppressions = parse_suppressions(f, known_rules={"M001", "M002"})
        assert "Unknown rule ID" not in caplog.text
        assert "M001" in suppressions.get("foo", set())


class TestDescriptionSuppressions:
    """Tests for Page Shield description-based suppression anchors."""

    def test_bare_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            "  - description: my-csp-policy\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("my-csp-policy", set())

    def test_bare_multiword_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            "  - description: Allow all scripts\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("Allow all scripts", set())

    def test_double_quoted_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            '  - description: "Allow all scripts"\n'
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("Allow all scripts", set())

    def test_single_quoted_description_suppression(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "page_shield_policies:\n"
            "  # octorules:disable=M013\n"
            "  - description: 'Block bad scripts'\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "M013" in suppressions.get("Block bad scripts", set())

    def test_description_suppression_filters_results(self):
        ctx = LintContext(suppressions={"Allow all scripts": {"M013"}})
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="Allow all scripts",
            )
        )
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message="always true",
                ref="Other policy",
            )
        )
        assert len(ctx.results) == 1
        assert ctx.results[0].ref == "Other policy"
        assert ctx.suppressed_count == 1

    def test_file_level_suppression_still_works_with_descriptions(self, tmp_path):
        f = tmp_path / "test.yaml"
        f.write_text(
            "# octorules:disable=O002\n"
            "page_shield_policies:\n"
            "  - description: my-policy\n"
            "    expression: 'true'\n"
        )
        suppressions = parse_suppressions(f)
        assert "O002" in suppressions.get("*", set())


class TestCheckCatchAll:
    """Tests for the DRY check_catch_all() helper."""

    def test_always_true_fires_m013(self):
        ctx = LintContext()
        check_catch_all("true", "waf_custom_rules", "test-ref", ctx)
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 1
        assert m013[0].phase == "waf_custom_rules"
        assert m013[0].ref == "test-ref"
        assert "catch-all rule" in m013[0].message

    def test_always_false_fires_m014(self):
        ctx = LintContext()
        check_catch_all("false", "redirect_rules", "dead-rule", ctx)
        m014 = [r for r in ctx.results if r.rule_id == "M014"]
        assert len(m014) == 1
        assert "never match" in m014[0].message

    def test_entity_policy(self):
        ctx = LintContext()
        check_catch_all("true", "page_shield_policies", "my-policy", ctx, entity="policy")
        m013 = [r for r in ctx.results if r.rule_id == "M013"]
        assert len(m013) == 1
        assert "catch-all policy" in m013[0].message

    def test_normal_expression_no_findings(self):
        ctx = LintContext()
        check_catch_all('http.host eq "example.com"', "waf_custom_rules", "r", ctx)
        assert len(ctx.results) == 0

    def test_parenthesized_true(self):
        ctx = LintContext()
        check_catch_all("((true))", "redirect_rules", "r", ctx)
        assert any(r.rule_id == "M013" for r in ctx.results)


class TestIsAlwaysTrue:
    def test_bare_true(self):
        assert is_always_true("true")

    def test_single_paren(self):
        assert is_always_true("(true)")

    def test_double_paren(self):
        assert is_always_true("((true))")

    def test_triple_paren(self):
        assert is_always_true("(((true)))")

    def test_many_parens(self):
        assert is_always_true("(((((true)))))")

    def test_not_true(self):
        assert not is_always_true("false")
        assert not is_always_true("(false)")

    def test_expression_not_always_true(self):
        assert not is_always_true('http.host eq "example.com"')

    def test_unbalanced_parens_not_stripped(self):
        assert not is_always_true("(true) and (true)")

    def test_empty(self):
        assert not is_always_true("")


class TestIsAlwaysFalse:
    def test_bare_false(self):
        assert is_always_false("false")

    def test_single_paren(self):
        assert is_always_false("(false)")

    def test_double_paren(self):
        assert is_always_false("((false))")

    def test_triple_paren(self):
        assert is_always_false("(((false)))")

    def test_many_parens(self):
        assert is_always_false("(((((false)))))")

    def test_not_false(self):
        assert not is_always_false("true")

    def test_expression_not_always_false(self):
        assert not is_always_false('http.host eq "example.com"')
