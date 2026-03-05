"""Tests for lint report formatters."""

from __future__ import annotations

import json

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.linter.report import format_json, format_sarif, format_text


def _make_ctx():
    ctx = LintContext(file_path="rules/example.com.yaml", zone_name="example.com")
    ctx.results = [
        LintResult(
            rule_id="M001",
            severity=Severity.ERROR,
            message="Missing ref",
            phase="redirect_rules",
        ),
        LintResult(
            rule_id="G001",
            severity=Severity.WARNING,
            message="Method should be uppercase",
            phase="waf_custom_rules",
            ref="test",
            suggestion="Use GET",
        ),
        LintResult(
            rule_id="O001",
            severity=Severity.INFO,
            message="Consider using 'in' operator",
            phase="waf_custom_rules",
            ref="test2",
        ),
    ]
    return ctx


class TestTextFormatter:
    def test_includes_header(self):
        ctx = _make_ctx()
        text = format_text(ctx)
        assert "example.com.yaml" in text

    def test_includes_severity_sections(self):
        ctx = _make_ctx()
        text = format_text(ctx)
        assert "Errors (1):" in text
        assert "Warnings (1):" in text
        assert "Info (1):" in text

    def test_includes_totals(self):
        ctx = _make_ctx()
        text = format_text(ctx)
        assert "1 error(s)" in text
        assert "1 warning(s)" in text

    def test_no_issues(self):
        ctx = LintContext()
        text = format_text(ctx)
        assert "No issues found" in text

    def test_stream_output(self):
        import io

        ctx = _make_ctx()
        buf = io.StringIO()
        result = format_text(ctx, buf)
        assert result == ""
        assert "M001" in buf.getvalue()


class TestJsonFormatter:
    def test_valid_json(self):
        ctx = _make_ctx()
        text = format_json(ctx)
        data = json.loads(text)
        assert "results" in data
        assert "summary" in data

    def test_result_fields(self):
        ctx = _make_ctx()
        data = json.loads(format_json(ctx))
        r0 = data["results"][0]
        assert r0["rule_id"] == "M001"
        assert r0["severity"] == "error"
        assert r0["message"] == "Missing ref"

    def test_summary_counts(self):
        ctx = _make_ctx()
        data = json.loads(format_json(ctx))
        assert data["summary"]["total"] == 3
        assert data["summary"]["errors"] == 1
        assert data["summary"]["warnings"] == 1
        assert data["summary"]["info"] == 1


class TestSarifFormatter:
    def test_valid_sarif_structure(self):
        ctx = _make_ctx()
        text = format_sarif(ctx)
        data = json.loads(text)
        assert data["version"] == "2.1.0"
        assert len(data["runs"]) == 1
        assert "tool" in data["runs"][0]
        assert "results" in data["runs"][0]

    def test_sarif_results_count(self):
        ctx = _make_ctx()
        data = json.loads(format_sarif(ctx))
        assert len(data["runs"][0]["results"]) == 3

    def test_sarif_severity_mapping(self):
        ctx = _make_ctx()
        data = json.loads(format_sarif(ctx))
        levels = [r["level"] for r in data["runs"][0]["results"]]
        assert "error" in levels
        assert "warning" in levels
        assert "note" in levels

    def test_sarif_rules_deduped(self):
        ctx = LintContext()
        ctx.results = [
            LintResult(rule_id="M001", severity=Severity.ERROR, message="a"),
            LintResult(rule_id="M001", severity=Severity.ERROR, message="b"),
        ]
        data = json.loads(format_sarif(ctx))
        rules = data["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) == 1

    def test_sarif_fix_suggestion(self):
        ctx = LintContext()
        ctx.results = [
            LintResult(
                rule_id="G001",
                severity=Severity.WARNING,
                message="test",
                suggestion="Use GET",
            ),
        ]
        data = json.loads(format_sarif(ctx))
        assert "fixes" in data["runs"][0]["results"][0]
