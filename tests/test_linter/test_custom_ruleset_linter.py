"""Tests for custom ruleset validation (Category T)."""

from __future__ import annotations

from octorules.linter.custom_ruleset_linter import lint_custom_rulesets
from octorules.linter.engine import LintContext


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_custom_rulesets(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestCustomRulesetStructure:
    def test_t001_missing_id(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {"name": "My Ruleset", "phase": "http_request_firewall_custom", "rules": []}
                ]
            }
        )
        assert "T001" in _ids(ctx)

    def test_t001_missing_name(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "T001" in _ids(ctx)

    def test_t001_missing_phase(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "rules": [],
                    }
                ]
            }
        )
        assert "T001" in _ids(ctx)

    def test_t001_all_present_no_error(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "T001" not in _ids(ctx)


class TestCustomRulesetIdFormat:
    def test_t002_invalid_id_format(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "not-a-hex-id",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "T002" in _ids(ctx)

    def test_t002_valid_hex_id(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [],
                    }
                ]
            }
        )
        assert "T002" not in _ids(ctx)


class TestCustomRulesetDuplicateRefs:
    def test_t003_duplicate_ref_within_ruleset(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "My Ruleset",
                        "phase": "http_request_firewall_custom",
                        "rules": [
                            {"ref": "rule1", "expression": "true", "action": "block"},
                            {"ref": "rule1", "expression": "true", "action": "log"},
                        ],
                    }
                ]
            }
        )
        assert "T003" in _ids(ctx)

    def test_t004_duplicate_ref_across_rulesets(self):
        ctx = _lint(
            {
                "custom_rulesets": [
                    {
                        "id": "abc12345def67890abc12345def67890",
                        "name": "Ruleset A",
                        "phase": "http_request_firewall_custom",
                        "rules": [{"ref": "shared-ref", "expression": "true", "action": "block"}],
                    },
                    {
                        "id": "def12345abc67890def12345abc67890",
                        "name": "Ruleset B",
                        "phase": "http_request_firewall_custom",
                        "rules": [{"ref": "shared-ref", "expression": "true", "action": "log"}],
                    },
                ]
            }
        )
        assert "T004" in _ids(ctx)


class TestNoCustomRulesets:
    def test_no_custom_rulesets_no_errors(self):
        ctx = _lint({"waf_custom_rules": []})
        assert _ids(ctx) == []
