"""Tests for lint engine orchestrator."""

from __future__ import annotations

import textwrap

from octorules.linter.engine import LintContext, LintResult, Severity, lint_zone_file
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
