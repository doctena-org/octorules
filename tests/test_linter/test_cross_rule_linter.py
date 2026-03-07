"""Tests for cross-rule linter (Category P)."""

from __future__ import annotations

from octorules.linter.cross_rule_linter import lint_cross_rules
from octorules.linter.engine import LintContext


def _lint(rules_data, **kwargs):
    ctx = LintContext(**kwargs)
    lint_cross_rules(rules_data, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestDuplicateExpressions:
    def test_p001_duplicate_expression(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "example.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "example.com"'},
                ]
            }
        )
        assert "P001" in _ids(ctx)

    def test_p001_whitespace_normalized(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host   eq   "example.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "example.com"'},
                ]
            }
        )
        assert "P001" in _ids(ctx)

    def test_p001_different_expressions_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "b.com"'},
                ]
            }
        )
        assert "P001" not in _ids(ctx)

    def test_p001_same_expr_different_action_params_id_ok(self):
        # Managed ruleset deployments with same expression but different IDs
        # are NOT duplicates
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "rule1",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "aaa"},
                    },
                    {
                        "ref": "rule2",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "bbb"},
                    },
                ]
            }
        )
        assert "P001" not in _ids(ctx)

    def test_p001_same_expr_same_action_params_id_flagged(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {
                        "ref": "rule1",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "same-id"},
                    },
                    {
                        "ref": "rule2",
                        "expression": '(cf.zone.plan eq "ENT")',
                        "action": "execute",
                        "action_parameters": {"id": "same-id"},
                    },
                ]
            }
        )
        assert "P001" in _ids(ctx)

    def test_p001_across_phases_not_flagged(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "example.com"'},
                ],
                "rate_limiting_rules": [
                    {"ref": "rule2", "expression": 'http.host eq "example.com"'},
                ],
            }
        )
        assert "P001" not in _ids(ctx)


class TestUnreachableRules:
    def test_p002_unreachable_after_block_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "blocker", "expression": "true", "action": "block"},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert "P002" in _ids(ctx)

    def test_p002_not_triggered_with_non_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"', "action": "block"},
                    {"ref": "rule2", "expression": 'http.host eq "b.com"', "action": "log"},
                ]
            }
        )
        assert "P002" not in _ids(ctx)

    def test_p002_not_triggered_with_non_terminating(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "true", "action": "log"},
                    {"ref": "rule2", "expression": 'http.host eq "a.com"', "action": "block"},
                ]
            }
        )
        assert "P002" not in _ids(ctx)

    def test_p002_disabled_rule_ignored(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "disabled", "expression": "true", "action": "block", "enabled": False},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert "P002" not in _ids(ctx)

    def test_p002_parenthesized_true(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "blocker", "expression": "(true)", "action": "block"},
                    {"ref": "after", "expression": 'http.host eq "a.com"', "action": "log"},
                ]
            }
        )
        assert "P002" in _ids(ctx)


class TestListReferences:
    def test_p003_unresolved_list_reference(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $unknown_list"},
                ],
                "lists": [],
            }
        )
        assert "P003" in _ids(ctx)
        p003 = [r for r in ctx.results if r.rule_id == "P003"]
        assert "unknown_list" in p003[0].message

    def test_p003_resolved_list_reference_ok(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_ips"},
                ],
                "lists": [{"name": "my_ips"}],
            }
        )
        assert "P003" not in _ids(ctx)

    def test_p003_no_list_refs_no_findings(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "example.com"'},
                ],
            }
        )
        assert "P003" not in _ids(ctx)

    def test_p003_multiple_refs_partial_resolution(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $known"},
                    {"ref": "rule2", "expression": "ip.src in $unknown"},
                ],
                "lists": [{"name": "known"}],
            }
        )
        p003 = [r for r in ctx.results if r.rule_id == "P003"]
        assert len(p003) == 1
        assert "unknown" in p003[0].message


class TestManagedLists:
    def test_p004_invalid_managed_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.invalid_list"},
                ],
            }
        )
        assert "P004" in _ids(ctx)

    def test_p004_valid_managed_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.anonymizer"},
                ],
            }
        )
        assert "P004" not in _ids(ctx)

    def test_p004_user_list_not_flagged(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_custom_list"},
                ],
                "lists": [{"name": "my_custom_list"}],
            }
        )
        assert "P004" not in _ids(ctx)

    def test_p003_doesnt_flag_managed_list(self):
        # Managed list names (with dots) should not trigger P003
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $cf.anonymizer"},
                ],
                "lists": [],
            }
        )
        assert "P003" not in _ids(ctx)


class TestListTypeMismatch:
    def test_p005_ip_field_with_asn_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert "P005" in _ids(ctx)

    def test_p005_asn_field_with_ip_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src.asnum in $my_ips"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert "P005" in _ids(ctx)

    def test_p005_correct_ip_field_with_ip_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_ips"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert "P005" not in _ids(ctx)

    def test_p005_correct_asn_field_with_asn_list(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.geoip.asnum in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert "P005" not in _ids(ctx)

    def test_p005_not_in_also_detected(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src not in $my_asns"},
                ],
                "lists": [{"name": "my_asns", "kind": "asn", "items": []}],
            }
        )
        assert "P005" in _ids(ctx)

    def test_p005_no_lists_section(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $my_list"},
                ],
            }
        )
        assert "P005" not in _ids(ctx)

    def test_p005_unknown_list_no_error(self):
        """Unknown list reference is handled by P003, not P005."""
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": "ip.src in $unknown"},
                ],
                "lists": [{"name": "my_ips", "kind": "ip", "items": []}],
            }
        )
        assert "P005" not in _ids(ctx)


class TestPhaseFilter:
    def test_filter_skips_unmatched_phase(self):
        ctx = _lint(
            {
                "waf_custom_rules": [
                    {"ref": "rule1", "expression": 'http.host eq "a.com"'},
                    {"ref": "rule2", "expression": 'http.host eq "a.com"'},
                ]
            },
            phase_filter=["redirect_rules"],
        )
        assert "P001" not in _ids(ctx)
