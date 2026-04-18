"""Tests for the diff engine (planner)."""

import logging
from types import SimpleNamespace

import pytest

from octorules.config import ZoneConfig
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    PhasePlan,
    RuleChange,
    RuleValidationError,
    ZonePlan,
    _diff_rules,
    _is_ignored,
    _rule_matches_target,
    _rules_by_ref,
    check_safety,
    compute_checksum,
    diff_custom_ruleset,
    diff_phase,
    filter_by_target,
    normalize_rule,
    plan_zone,
    prepare_desired_rules,
    validate_custom_ruleset,
    validate_rules,
    warn_unknown_phase_keys,
)

REDIRECT_PHASE = get_phase("redirect_rules")
CACHE_PHASE = get_phase("cache_rules")
WAF_PHASE = get_phase("waf_custom_rules")
BARE_PHASE = get_phase("bare_custom_rules")  # prepare_rule=None (AWS/Google style)


class TestNormalizeRule:
    def test_strips_api_fields(self):
        rule = {
            "id": "abc",
            "version": "1",
            "last_updated": "2024-01-01",
            "categories": [],
            "ref": "my-rule",
            "logging": {"enabled": True},
            "expression": "true",
            "action": "redirect",
        }
        normalized = normalize_rule(rule)
        assert "id" not in normalized
        assert "version" not in normalized
        assert "last_updated" not in normalized
        assert "categories" not in normalized
        assert "ref" not in normalized
        assert "logging" not in normalized
        assert normalized["expression"] == "true"
        assert normalized["action"] == "redirect"

    def test_preserves_user_fields(self):
        rule = {"expression": "true", "action": "redirect", "enabled": True}
        assert normalize_rule(rule) == rule

    def test_empty_rule(self):
        assert normalize_rule({}) == {}


class TestValidateRules:
    def test_valid_rules(self):
        rules = [
            {"ref": "r1", "expression": "true"},
            {"ref": "r2", "expression": "false"},
        ]
        validate_rules(rules, REDIRECT_PHASE)  # Should not raise

    def test_missing_ref(self):
        rules = [{"expression": "true"}]
        with pytest.raises(RuleValidationError, match="missing required 'ref' field"):
            validate_rules(rules, REDIRECT_PHASE)

    def test_missing_expression_passes(self):
        """Core no longer validates 'expression' — provider-specific check."""
        rules = [{"ref": "r1"}]
        validate_rules(rules, REDIRECT_PHASE)  # Should not raise

    def test_duplicate_ref(self):
        rules = [
            {"ref": "r1", "expression": "a"},
            {"ref": "r1", "expression": "b"},
        ]
        with pytest.raises(RuleValidationError, match="Duplicate ref 'r1'"):
            validate_rules(rules, REDIRECT_PHASE)

    def test_empty_rules(self):
        validate_rules([], REDIRECT_PHASE)  # Should not raise

    def test_error_message_includes_phase(self):
        rules = [{"expression": "true"}]
        with pytest.raises(RuleValidationError, match="redirect_rules"):
            validate_rules(rules, REDIRECT_PHASE)

    def test_error_message_includes_index(self):
        rules = [
            {"ref": "r1", "expression": "a"},
            {"expression": "b"},  # index 1, missing ref
        ]
        with pytest.raises(RuleValidationError, match="index 1"):
            validate_rules(rules, REDIRECT_PHASE)

    def test_empty_ref_rejected(self):
        rules = [{"ref": "", "expression": "true"}]
        with pytest.raises(RuleValidationError, match="invalid 'ref'"):
            validate_rules(rules, REDIRECT_PHASE)

    def test_non_string_ref_rejected(self):
        rules = [{"ref": 123, "expression": "true"}]
        with pytest.raises(RuleValidationError, match="invalid 'ref'"):
            validate_rules(rules, REDIRECT_PHASE)

    def test_empty_expression_passes(self):
        """Core no longer validates expression content — provider-specific."""
        rules = [{"ref": "r1", "expression": ""}]
        validate_rules(rules, REDIRECT_PHASE)  # Should not raise

    def test_non_string_expression_passes(self):
        """Core no longer validates expression type — provider-specific."""
        rules = [{"ref": "r1", "expression": True}]
        validate_rules(rules, REDIRECT_PHASE)  # Should not raise


class TestWarnUnknownPhaseKeys:
    def test_no_warnings_for_valid_keys(self, caplog):
        rules_data = {"redirect_rules": [], "cache_rules": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert caplog.text == ""

    def test_warns_on_unknown_key(self, caplog):
        rules_data = {"redirect_rules": [], "typo_rules": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert "typo_rules" in caplog.text
        assert "example.com" in caplog.text

    def test_multiple_unknown_keys_sorted(self, caplog):
        rules_data = {"zzz_rules": [], "aaa_rules": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "test.com")
        assert caplog.text.index("aaa_rules") < caplog.text.index("zzz_rules")

    def test_empty_data(self, caplog):
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys({}, "example.com")
        assert caplog.text == ""

    def test_close_typo_suggests(self, caplog):
        rules_data = {"redirect_rule": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert "Did you mean" in caplog.text
        assert "redirect_rules" in caplog.text

    def test_no_match_lists_valid(self, caplog):
        rules_data = {"zzz_totally_wrong": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert "Valid phases:" in caplog.text

    def test_provider_id_suggests_friendly_name(self, caplog):
        rules_data = {"http_request_dynamic_redirect": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert "Did you mean" in caplog.text
        assert "redirect_rules" in caplog.text

    def test_renamed_phase_warns_with_migration_guidance(self, caplog):
        """Using old name waf_managed_exceptions should produce a deprecation warning."""
        rules_data = {
            "waf_managed_exceptions": [{"ref": "r1", "expression": "true", "action": "block"}]
        }
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert "renamed" in caplog.text
        assert "waf_managed_rules" in caplog.text
        assert "deprecated" in caplog.text

    def test_renamed_phase_does_not_show_generic_unknown(self, caplog):
        """Renamed phase should NOT show generic 'Unknown phase' message."""
        rules_data = {"waf_managed_exceptions": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert "Unknown phase" not in caplog.text


class TestPrepareDesiredRules:
    def test_injects_default_action(self):
        rules = [{"ref": "r1", "expression": "true"}]
        prepared = prepare_desired_rules(rules, REDIRECT_PHASE)
        assert prepared[0]["action"] == "redirect"
        assert prepared[0]["enabled"] is True

    def test_preserves_explicit_action(self):
        rules = [{"ref": "r1", "expression": "true", "action": "custom"}]
        prepared = prepare_desired_rules(rules, REDIRECT_PHASE)
        assert prepared[0]["action"] == "custom"

    def test_preserves_explicit_enabled_false(self):
        rules = [{"ref": "r1", "expression": "true", "enabled": False}]
        prepared = prepare_desired_rules(rules, REDIRECT_PHASE)
        assert prepared[0]["enabled"] is False

    def test_waf_requires_action(self):
        rules = [{"ref": "r1", "expression": "true"}]
        with pytest.raises(ValueError, match="must specify an 'action'"):
            prepare_desired_rules(rules, WAF_PHASE)

    def test_waf_with_action_ok(self):
        rules = [{"ref": "r1", "expression": "true", "action": "block"}]
        prepared = prepare_desired_rules(rules, WAF_PHASE)
        assert prepared[0]["action"] == "block"

    def test_does_not_mutate_input(self):
        rules = [{"ref": "r1", "expression": "true"}]
        prepare_desired_rules(rules, REDIRECT_PHASE)
        assert "action" not in rules[0]

    def test_multiple_rules(self):
        rules = [
            {"ref": "r1", "expression": "a"},
            {"ref": "r2", "expression": "b", "enabled": False},
        ]
        prepared = prepare_desired_rules(rules, REDIRECT_PHASE)
        assert len(prepared) == 2
        assert prepared[0]["enabled"] is True
        assert prepared[1]["enabled"] is False
        assert all(r["action"] == "redirect" for r in prepared)

    def test_empty_rules(self):
        assert prepare_desired_rules([], REDIRECT_PHASE) == []

    def test_rate_limiting_requires_action(self):
        rl_phase = get_phase("rate_limiting_rules")
        rules = [{"ref": "r1", "expression": "true"}]
        with pytest.raises(ValueError, match="must specify an 'action'"):
            prepare_desired_rules(rules, rl_phase)

    def test_bot_fight_rules_requires_action(self):
        bf_phase = get_phase("bot_fight_rules")
        rules = [{"ref": "r1", "expression": "true"}]
        with pytest.raises(ValueError, match="must specify an 'action'"):
            prepare_desired_rules(rules, bf_phase)

    def test_bot_fight_rules_with_action_ok(self):
        bf_phase = get_phase("bot_fight_rules")
        rules = [{"ref": "r1", "expression": "true", "action": "block"}]
        prepared = prepare_desired_rules(rules, bf_phase)
        assert prepared[0]["action"] == "block"

    def test_sensitive_data_detection_requires_action(self):
        sd_phase = get_phase("sensitive_data_detection")
        rules = [{"ref": "r1", "expression": "true"}]
        with pytest.raises(ValueError, match="must specify an 'action'"):
            prepare_desired_rules(rules, sd_phase)

    def test_sensitive_data_detection_with_action_ok(self):
        sd_phase = get_phase("sensitive_data_detection")
        rules = [{"ref": "r1", "expression": "true", "action": "log"}]
        prepared = prepare_desired_rules(rules, sd_phase)
        assert prepared[0]["action"] == "log"

    def test_bare_phase_no_prepare_rule(self):
        """Phases without prepare_rule (AWS/Google) pass rules through unmodified."""
        assert BARE_PHASE.prepare_rule is None
        rules = [{"ref": "r1", "expression": "  a  and  b  ", "action": "block"}]
        prepared = prepare_desired_rules(rules, BARE_PHASE)
        # Expression is NOT normalized (no prepare_rule to collapse whitespace)
        assert prepared[0]["expression"] == "  a  and  b  "
        # No 'enabled' injected
        assert "enabled" not in prepared[0]
        # Explicit action preserved
        assert prepared[0]["action"] == "block"

    def test_bare_phase_requires_action(self):
        """Bare phases with default_action=None require action in YAML."""
        rules = [{"ref": "r1", "expression": "true"}]
        # validate_rules (called inside prepare_desired_rules) checks required fields,
        # but without prepare_rule there's no injection — so the rule just passes through
        # without an action field.
        prepared = prepare_desired_rules(rules, BARE_PHASE)
        assert "action" not in prepared[0]

    def test_bare_phase_does_not_mutate_input(self):
        rules = [{"ref": "r1", "expression": "x", "action": "allow"}]
        original = rules[0].copy()
        prepare_desired_rules(rules, BARE_PHASE)
        assert rules[0] == original


class TestDiffPhase:
    def test_no_changes(self):
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [
            {
                "id": "x",
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert not plan.has_changes
        assert plan.changes == []

    def test_addition(self):
        desired = [{"ref": "new-rule", "expression": "true"}]
        current = []
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].change_type == ChangeType.ADD
        assert plan.changes[0].ref == "new-rule"
        assert plan.changes[0].desired is not None
        assert plan.changes[0].current is None

    def test_removal(self):
        desired = []
        current = [{"ref": "old-rule", "expression": "true", "action": "redirect"}]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].change_type == ChangeType.REMOVE
        assert plan.changes[0].ref == "old-rule"
        assert plan.changes[0].current is not None
        assert plan.changes[0].desired is None

    def test_modification(self):
        desired = [{"ref": "r1", "expression": "new-expr", "action": "redirect", "enabled": True}]
        current = [{"ref": "r1", "expression": "old-expr", "action": "redirect", "enabled": True}]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        changes = [c for c in plan.changes if c.change_type == ChangeType.MODIFY]
        assert len(changes) == 1
        assert changes[0].ref == "r1"
        assert changes[0].current is not None
        assert changes[0].desired is not None

    def test_enabled_change_is_modification(self):
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": False}]
        current = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        assert plan.changes[0].change_type == ChangeType.MODIFY

    def test_description_change_is_modification(self):
        desired = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "description": "New desc",
            }
        ]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "description": "Old desc",
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes

    def test_reorder(self):
        desired = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        reorders = [c for c in plan.changes if c.change_type == ChangeType.REORDER]
        assert len(reorders) == 1

    def test_no_reorder_when_refs_differ(self):
        """Reorder should only be detected when refs are the same set."""
        desired = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r3", "expression": "true"},
        ]
        current = [
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        reorders = [c for c in plan.changes if c.change_type == ChangeType.REORDER]
        assert len(reorders) == 0

    def test_mixed_changes(self):
        desired = [
            {"ref": "keep", "expression": "modified", "action": "redirect", "enabled": True},
            {"ref": "new", "expression": "true"},
        ]
        current = [
            {"ref": "keep", "expression": "original", "action": "redirect", "enabled": True},
            {"ref": "remove-me", "expression": "true", "action": "redirect"},
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        types = {c.change_type for c in plan.changes}
        assert ChangeType.ADD in types
        assert ChangeType.REMOVE in types
        assert ChangeType.MODIFY in types

    def test_api_fields_ignored_in_comparison(self):
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [
            {
                "id": "abc-123",
                "version": "5",
                "last_updated": "2024-01-01T00:00:00Z",
                "categories": ["security"],
                "logging": {"enabled": False},
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert not plan.has_changes

    def test_empty_both(self):
        plan = diff_phase(REDIRECT_PHASE, [], [])
        assert not plan.has_changes
        assert plan.changes == []

    def test_action_parameters_change(self):
        desired = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": {"status_code": 302},
            }
        ]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": {"status_code": 301},
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        assert plan.changes[0].change_type == ChangeType.MODIFY


class TestPlanZone:
    def test_empty_desired_empty_current(self):
        zone_plan = plan_zone("example.com", {}, {})
        assert not zone_plan.has_changes

    def test_new_phase_rules(self):
        desired = {
            "redirect_rules": [{"ref": "r1", "expression": "true"}],
        }
        zone_plan = plan_zone("example.com", desired, {})
        assert zone_plan.has_changes
        assert zone_plan.total_changes == 1

    def test_removes_existing_phase(self):
        current = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect"}
            ],
        }
        zone_plan = plan_zone("example.com", {}, current)
        assert zone_plan.has_changes
        assert zone_plan.total_changes == 1

    def test_multiple_phases(self):
        desired = {
            "redirect_rules": [{"ref": "r1", "expression": "true"}],
            "cache_rules": [{"ref": "c1", "expression": "true"}],
        }
        zone_plan = plan_zone("example.com", desired, {})
        assert zone_plan.has_changes
        assert zone_plan.total_changes == 2
        assert len(zone_plan.phase_plans) == 2

    def test_unknown_provider_id_in_current_is_skipped(self):
        """Phases in current that aren't in our registry should be ignored."""
        current = {
            "http_some_unknown_phase": [{"ref": "r1", "expression": "true", "action": "whatever"}],
        }
        zone_plan = plan_zone("example.com", {}, current)
        assert not zone_plan.has_changes
        assert zone_plan.total_changes == 0

    def test_no_changes_same_rules(self):
        desired = {
            "redirect_rules": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        current = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        zone_plan = plan_zone("example.com", desired, current)
        assert not zone_plan.has_changes

    def test_has_changes_property(self):
        zone_plan = plan_zone("example.com", {}, {})
        assert zone_plan.has_changes is False
        assert zone_plan.total_changes == 0


class TestRenamedPhaseAlias:
    """Tests for waf_managed_exceptions -> waf_managed_rules alias in planning."""

    def test_alias_works_in_plan_zone(self):
        """Using old name waf_managed_exceptions in desired rules should still work."""
        desired = {
            "waf_managed_exceptions": [{"ref": "r1", "expression": "true", "action": "block"}],
        }
        current = {}
        zp = plan_zone("example.com", desired, current)
        assert zp.has_changes
        assert zp.total_changes == 1
        assert zp.phase_plans[0].phase.provider_id == "http_request_firewall_managed"

    def test_canonical_name_works_in_plan_zone(self):
        """Using canonical name waf_managed_rules should work normally."""
        desired = {
            "waf_managed_rules": [{"ref": "r1", "expression": "true", "action": "block"}],
        }
        current = {}
        zp = plan_zone("example.com", desired, current)
        assert zp.has_changes
        assert zp.total_changes == 1
        assert zp.phase_plans[0].phase.provider_id == "http_request_firewall_managed"

    def test_alias_diff_against_current(self):
        """Alias name should correctly diff against current rules from CF."""
        desired = {
            "waf_managed_exceptions": [
                {"ref": "r1", "expression": "true", "action": "block", "enabled": True}
            ],
        }
        current = {
            "http_request_firewall_managed": [
                {"ref": "r1", "expression": "true", "action": "block", "enabled": True}
            ],
        }
        zp = plan_zone("example.com", desired, current)
        assert not zp.has_changes

    def test_alias_with_allow_unmanaged(self):
        """Alias should work correctly with allow_unmanaged=True."""
        desired = {
            "waf_managed_exceptions": [
                {"ref": "r1", "expression": "true", "action": "block", "enabled": True}
            ],
        }
        current = {
            "http_request_firewall_managed": [
                {"ref": "r1", "expression": "true", "action": "block", "enabled": True},
                {"ref": "r2", "expression": "false", "action": "log", "enabled": True},
            ],
        }
        zp = plan_zone("example.com", desired, current, allow_unmanaged=True)
        # r2 is unmanaged but allow_unmanaged is True, so no changes
        assert not zp.has_changes

    def test_alias_does_not_cause_double_processing(self):
        """Using the alias should not cause the phase to be processed twice."""
        desired = {
            "waf_managed_exceptions": [{"ref": "r1", "expression": "true", "action": "block"}],
        }
        current = {}
        zp = plan_zone("example.com", desired, current)
        # Only one phase plan should be created, not two
        assert len(zp.phase_plans) == 1

    def test_alias_removal_detection(self):
        """Alias should not cause spurious removal when current has the phase."""
        desired = {
            "waf_managed_exceptions": [{"ref": "r1", "expression": "true", "action": "block"}],
        }
        current = {
            "http_request_firewall_managed": [
                {"ref": "r1", "expression": "true", "action": "block", "enabled": True},
                {"ref": "r2", "expression": "false", "action": "log", "enabled": True},
            ],
        }
        zp = plan_zone("example.com", desired, current)
        # r2 should be removed (not in desired), but only once
        removes = []
        for pp in zp.phase_plans:
            for c in pp.changes:
                if c.change_type == ChangeType.REMOVE:
                    removes.append(c.ref)
        assert removes == ["r2"]


class TestAllowUnmanaged:
    """Tests for allow_unmanaged behavior in diff/plan."""

    def test_diff_phase_removes_unmanaged_by_default(self):
        """By default, rules in current but not desired are REMOVE'd."""
        desired = [{"ref": "r1", "expression": "true"}]
        current = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        removes = [c for c in plan.changes if c.change_type == ChangeType.REMOVE]
        assert len(removes) == 1
        assert removes[0].ref == "r2"

    def test_diff_phase_keeps_unmanaged(self):
        """With allow_unmanaged, rules in current but not desired are kept."""
        desired = [{"ref": "r1", "expression": "true"}]
        current = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current, allow_unmanaged=True)
        removes = [c for c in plan.changes if c.change_type == ChangeType.REMOVE]
        assert len(removes) == 0

    def test_diff_phase_still_adds_and_modifies(self):
        """allow_unmanaged should not affect ADD or MODIFY."""
        desired = [
            {"ref": "r1", "expression": "changed", "action": "redirect", "enabled": True},
            {"ref": "r3", "expression": "true"},
        ]
        current = [
            {"ref": "r1", "expression": "original", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current, allow_unmanaged=True)
        types = {c.change_type for c in plan.changes}
        assert ChangeType.ADD in types
        assert ChangeType.MODIFY in types
        assert ChangeType.REMOVE not in types

    def test_plan_zone_skips_full_phase_removal(self):
        """With allow_unmanaged, phases in current but not desired are not removed."""
        desired = {}  # no desired rules
        current = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect"}
            ],
        }
        zp = plan_zone("example.com", desired, current, allow_unmanaged=True)
        assert not zp.has_changes

    def test_plan_zone_removes_phase_by_default(self):
        """Without allow_unmanaged, phases in current but not desired are removed."""
        desired = {}
        current = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect"}
            ],
        }
        zp = plan_zone("example.com", desired, current, allow_unmanaged=False)
        assert zp.has_changes
        assert zp.total_changes == 1


class TestBuildPhasePayload:
    def test_basic_payload(self):
        rules = [{"ref": "r1", "expression": "true", "description": "Test"}]
        payload = prepare_desired_rules(rules, REDIRECT_PHASE)
        assert len(payload) == 1
        assert payload[0]["action"] == "redirect"
        assert payload[0]["enabled"] is True
        assert payload[0]["ref"] == "r1"

    def test_empty_payload(self):
        payload = prepare_desired_rules([], REDIRECT_PHASE)
        assert payload == []

    def test_preserves_action_parameters(self):
        rules = [
            {
                "ref": "r1",
                "expression": "true",
                "action_parameters": {"status_code": 301},
            }
        ]
        payload = prepare_desired_rules(rules, REDIRECT_PHASE)
        assert payload[0]["action_parameters"] == {"status_code": 301}


ORIGIN_PHASE = get_phase("origin_rules")

# Example Origin Rule: routes /api requests on app.example.com to api.example.com
EXAMPLE_ORIGIN_RULE_YAML = {
    "ref": "api-redirect-dev",
    "description": "Route API calls to API backend",
    "expression": (
        '(http.host eq "app.example.com" and starts_with(http.request.uri.path, "/api"))'
    ),
    "action_parameters": {
        "host_header": "api.example.com",
    },
}

# What Cloudflare returns for the same rule (with API-injected fields)
EXAMPLE_ORIGIN_RULE_CF = {
    "id": "a1b2c3d4e5f6",
    "version": "3",
    "last_updated": "2025-06-15T10:30:00Z",
    "ref": "api-redirect-dev",
    "description": "Route API calls to API backend",
    "expression": (
        '(http.host eq "app.example.com" and starts_with(http.request.uri.path, "/api"))'
    ),
    "action": "route",
    "action_parameters": {
        "host_header": "api.example.com",
    },
    "enabled": True,
    "logging": {"enabled": False},
}


class TestOriginRule:
    """Tests for Origin Rule planning with host_header routing."""

    def test_plan_no_changes_when_synced(self):
        """A rule in YAML matching what CF returns should produce no diff."""
        plan = diff_phase(ORIGIN_PHASE, [EXAMPLE_ORIGIN_RULE_YAML], [EXAMPLE_ORIGIN_RULE_CF])
        assert not plan.has_changes

    def test_plan_detects_new_rule(self):
        """Adding this rule to a zone with no origin rules."""
        plan = diff_phase(ORIGIN_PHASE, [EXAMPLE_ORIGIN_RULE_YAML], [])
        assert plan.has_changes
        assert len(plan.changes) == 1
        assert plan.changes[0].change_type == ChangeType.ADD
        assert plan.changes[0].ref == "api-redirect-dev"

    def test_plan_detects_host_header_change(self):
        """Changing the host_header target should be detected as a modification."""
        modified_yaml = {
            **EXAMPLE_ORIGIN_RULE_YAML,
            "action_parameters": {"host_header": "staging-api.example.com"},
        }
        plan = diff_phase(ORIGIN_PHASE, [modified_yaml], [EXAMPLE_ORIGIN_RULE_CF])
        assert plan.has_changes
        mods = [c for c in plan.changes if c.change_type == ChangeType.MODIFY]
        assert len(mods) == 1
        assert mods[0].ref == "api-redirect-dev"

    def test_plan_detects_expression_change(self):
        """Updating the filter expression should be detected."""
        modified_yaml = {
            **EXAMPLE_ORIGIN_RULE_YAML,
            "expression": (
                '(http.host eq "app.example.com" and starts_with(http.request.uri.path, "/api/v2"))'
            ),
        }
        plan = diff_phase(ORIGIN_PHASE, [modified_yaml], [EXAMPLE_ORIGIN_RULE_CF])
        assert plan.has_changes

    def test_plan_detects_removal(self):
        """Removing the rule from YAML should be detected."""
        plan = diff_phase(ORIGIN_PHASE, [], [EXAMPLE_ORIGIN_RULE_CF])
        assert plan.has_changes
        assert plan.changes[0].change_type == ChangeType.REMOVE
        assert plan.changes[0].ref == "api-redirect-dev"

    def test_default_action_injected(self):
        """Origin rules should get action=route injected automatically."""
        prepared = prepare_desired_rules([EXAMPLE_ORIGIN_RULE_YAML], ORIGIN_PHASE)
        assert prepared[0]["action"] == "route"
        assert prepared[0]["enabled"] is True

    def test_payload_matches_cf_format(self):
        """The built payload should match what CF expects."""
        payload = prepare_desired_rules([EXAMPLE_ORIGIN_RULE_YAML], ORIGIN_PHASE)
        rule = payload[0]
        assert rule["action"] == "route"
        assert rule["ref"] == "api-redirect-dev"
        assert rule["action_parameters"]["host_header"] == "api.example.com"
        assert rule["enabled"] is True
        assert "id" not in rule
        assert "version" not in rule

    def test_zone_plan_with_origin_rules(self):
        """Full zone plan with origin rules phase."""
        desired = {"origin_rules": [EXAMPLE_ORIGIN_RULE_YAML]}
        current = {}
        zp = plan_zone("example.com", desired, current)
        assert zp.has_changes
        assert zp.total_changes == 1
        assert zp.phase_plans[0].phase.provider_id == "http_request_origin"

    def test_zone_plan_no_changes(self):
        """Full zone plan when CF already has the rule."""
        desired = {"origin_rules": [EXAMPLE_ORIGIN_RULE_YAML]}
        current = {"http_request_origin": [EXAMPLE_ORIGIN_RULE_CF]}
        zp = plan_zone("example.com", desired, current)
        assert not zp.has_changes


class TestComputeChecksum:
    def _make_zone_plan(self, zone_name, changes):
        """Helper to create a ZonePlan with changes."""
        pp = PhasePlan(phase=REDIRECT_PHASE, changes=changes)
        return ZonePlan(zone_name=zone_name, phase_plans=[pp] if changes else [])

    def test_deterministic(self):
        """Same plan should always produce the same checksum."""
        changes = [RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, desired={"expression": "true"})]
        zp = self._make_zone_plan("example.com", changes)
        h1 = compute_checksum([zp])
        h2 = compute_checksum([zp])
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest

    def test_zone_order_irrelevant(self):
        """Checksum should be the same regardless of zone ordering."""
        changes_a = [
            RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, desired={"expression": "true"})
        ]
        changes_b = [
            RuleChange(ChangeType.ADD, "r2", REDIRECT_PHASE, desired={"expression": "false"})
        ]
        zp_a = self._make_zone_plan("a.com", changes_a)
        zp_b = self._make_zone_plan("b.com", changes_b)
        assert compute_checksum([zp_a, zp_b]) == compute_checksum([zp_b, zp_a])

    def test_change_order_irrelevant(self):
        """Checksum should be the same regardless of change ordering within a phase."""
        c1 = RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, desired={"expression": "true"})
        c2 = RuleChange(ChangeType.ADD, "r2", REDIRECT_PHASE, desired={"expression": "false"})
        pp1 = PhasePlan(phase=REDIRECT_PHASE, changes=[c1, c2])
        pp2 = PhasePlan(phase=REDIRECT_PHASE, changes=[c2, c1])
        zp1 = ZonePlan(zone_name="test.com", phase_plans=[pp1])
        zp2 = ZonePlan(zone_name="test.com", phase_plans=[pp2])
        assert compute_checksum([zp1]) == compute_checksum([zp2])

    def test_different_plans_differ(self):
        """Different plans should produce different checksums."""
        c1 = [RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, desired={"expression": "true"})]
        c2 = [RuleChange(ChangeType.ADD, "r2", REDIRECT_PHASE, desired={"expression": "true"})]
        assert compute_checksum([self._make_zone_plan("test.com", c1)]) != compute_checksum(
            [self._make_zone_plan("test.com", c2)]
        )

    def test_api_fields_stripped(self):
        """API-only fields should be stripped from checksum computation."""
        c1 = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"id": "abc", "expression": "old", "action": "redirect"},
            desired={"expression": "new", "action": "redirect"},
        )
        c2 = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"id": "xyz", "version": "5", "expression": "old", "action": "redirect"},
            desired={"expression": "new", "action": "redirect"},
        )
        zp1 = self._make_zone_plan("test.com", [c1])
        zp2 = self._make_zone_plan("test.com", [c2])
        assert compute_checksum([zp1]) == compute_checksum([zp2])


class TestComputeChecksumExtensionChanges:
    # Regression for v0.25.2: compute_checksum assumed all plan changes had
    # change_type/ref/phase (RuleChange shape). Extension change dataclasses
    # (ZoneSecurityChange, BotManagementChange, UrlNormalizationChange,
    # LeakedCredentialChange, ContentScanningChange) use field/current/desired
    # instead and crashed the itemgetter("change_type", "ref") sort.

    @staticmethod
    def _ext_change(field, current=None, desired=None):
        return SimpleNamespace(field=field, current=current, desired=desired)

    @staticmethod
    def _ext_plan(changes):
        return SimpleNamespace(changes=list(changes))

    def _zone_with_ext(self, zone_name, ext_name, changes):
        return ZonePlan(
            zone_name=zone_name,
            extension_plans={ext_name: [self._ext_plan(changes)]},
        )

    def test_extension_change_does_not_crash(self):
        zp = self._zone_with_ext(
            "example.com",
            "zone_security",
            [self._ext_change("security_level", current="medium", desired="high")],
        )
        checksum = compute_checksum([zp])
        assert len(checksum) == 64

    def test_extension_change_deterministic(self):
        changes = [
            self._ext_change("security_level", current="medium", desired="high"),
            self._ext_change("challenge_ttl", current=1800, desired=3600),
        ]
        zp = self._zone_with_ext("example.com", "zone_security", changes)
        assert compute_checksum([zp]) == compute_checksum([zp])

    def test_extension_change_order_irrelevant(self):
        c_a = self._ext_change("security_level", current="medium", desired="high")
        c_b = self._ext_change("challenge_ttl", current=1800, desired=3600)
        zp_ab = self._zone_with_ext("example.com", "zone_security", [c_a, c_b])
        zp_ba = self._zone_with_ext("example.com", "zone_security", [c_b, c_a])
        assert compute_checksum([zp_ab]) == compute_checksum([zp_ba])

    def test_different_extension_values_differ(self):
        zp_low = self._zone_with_ext(
            "example.com",
            "zone_security",
            [self._ext_change("security_level", current="low", desired="medium")],
        )
        zp_high = self._zone_with_ext(
            "example.com",
            "zone_security",
            [self._ext_change("security_level", current="low", desired="high")],
        )
        assert compute_checksum([zp_low]) != compute_checksum([zp_high])

    def test_mixed_rule_and_extension_plans(self):
        rule_changes = [
            RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, desired={"expression": "true"})
        ]
        pp = PhasePlan(phase=REDIRECT_PHASE, changes=rule_changes)
        zp = ZonePlan(
            zone_name="example.com",
            phase_plans=[pp],
            extension_plans={
                "zone_security": [
                    self._ext_plan(
                        [self._ext_change("security_level", current="low", desired="high")]
                    )
                ]
            },
        )
        checksum = compute_checksum([zp])
        assert len(checksum) == 64


class TestCheckSafety:
    """Tests for safety threshold checks (Feature 4)."""

    def _zone_cfg(self, delete_threshold=30.0, update_threshold=30.0, min_existing=3):
        return ZoneConfig(
            name="test.com",
            zone_id="z1",
            sources=["rules"],
            delete_threshold=delete_threshold,
            update_threshold=update_threshold,
            min_existing=min_existing,
        )

    def _make_zone_plan(self, changes):
        pp = PhasePlan(phase=REDIRECT_PHASE, changes=changes)
        return ZonePlan(zone_name="test.com", phase_plans=[pp] if changes else [])

    def test_under_threshold_no_violation(self):
        """1 delete out of 10 rules = 10%, under 30% threshold."""
        changes = [RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert violations == []

    def test_delete_exceeded(self):
        """4 deletes out of 10 rules = 40%, exceeds 30% threshold."""
        changes = [RuleChange(ChangeType.REMOVE, f"r{i}", REDIRECT_PHASE) for i in range(4)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert violations[0].count == 4
        assert violations[0].percentage == 40.0

    def test_update_exceeded(self):
        """4 modifies out of 10 rules = 40%, exceeds 30% threshold."""
        changes = [RuleChange(ChangeType.MODIFY, f"r{i}", REDIRECT_PHASE) for i in range(4)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "update"

    def test_min_existing_skips_small_rulesets(self):
        """With only 2 existing rules and min_existing=3, skip checks."""
        changes = [RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": "r1"}, {"ref": "r2"}]}
        violations = check_safety(zp, current, self._zone_cfg(min_existing=3))
        assert violations == []

    def test_mixed_violations(self):
        """Both delete and update thresholds exceeded."""
        changes = [
            RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE),
            RuleChange(ChangeType.REMOVE, "r2", REDIRECT_PHASE),
            RuleChange(ChangeType.MODIFY, "r3", REDIRECT_PHASE),
            RuleChange(ChangeType.MODIFY, "r4", REDIRECT_PHASE),
        ]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(5)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 2
        kinds = {v.kind for v in violations}
        assert kinds == {"delete", "update"}

    def test_add_only_no_violation(self):
        """Adding rules never triggers safety checks."""
        changes = [RuleChange(ChangeType.ADD, f"new{i}", REDIRECT_PHASE) for i in range(5)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(5)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert violations == []

    def test_exactly_at_threshold_ok(self):
        """Exactly at threshold (30% = 3 out of 10) should be OK (strict >)."""
        changes = [RuleChange(ChangeType.REMOVE, f"r{i}", REDIRECT_PHASE) for i in range(3)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert violations == []

    def test_delete_violation_has_phases(self):
        """Delete violation should include the affected phase names."""
        changes = [RuleChange(ChangeType.REMOVE, f"r{i}", REDIRECT_PHASE) for i in range(4)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].phases == ["redirect_rules"]

    def test_update_violation_has_phases(self):
        """Update violation should include the affected phase names."""
        changes = [RuleChange(ChangeType.MODIFY, f"r{i}", REDIRECT_PHASE) for i in range(4)]
        zp = self._make_zone_plan(changes)
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].phases == ["redirect_rules"]

    def test_multiple_phases_in_violation(self):
        """Violation spanning multiple phases should list all phase names."""
        c1 = [RuleChange(ChangeType.REMOVE, f"r{i}", REDIRECT_PHASE) for i in range(2)]
        c2 = [RuleChange(ChangeType.REMOVE, f"c{i}", CACHE_PHASE) for i in range(2)]
        pp1 = PhasePlan(phase=REDIRECT_PHASE, changes=c1)
        pp2 = PhasePlan(phase=CACHE_PHASE, changes=c2)
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp1, pp2])
        current = {
            "http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(5)],
            "http_request_cache_settings": [{"ref": f"c{i}"} for i in range(5)],
        }
        violations = check_safety(zp, current, self._zone_cfg())
        delete_v = next(v for v in violations if v.kind == "delete")
        assert "redirect_rules" in delete_v.phases
        assert "cache_rules" in delete_v.phases

    def test_multiple_phases_summed(self):
        """Changes across multiple phases should be summed against total existing."""
        c1 = [RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE)]
        c2 = [RuleChange(ChangeType.REMOVE, "c1", CACHE_PHASE)]
        pp1 = PhasePlan(phase=REDIRECT_PHASE, changes=c1)
        pp2 = PhasePlan(phase=CACHE_PHASE, changes=c2)
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp1, pp2])
        # 2 deletes out of 5 total existing = 40%
        current = {
            "http_request_dynamic_redirect": [{"ref": "r1"}, {"ref": "r2"}],
            "http_request_cache_settings": [{"ref": "c1"}, {"ref": "c2"}, {"ref": "c3"}],
        }
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert violations[0].count == 2
        assert violations[0].existing == 5


class TestCFApiResilience:
    """Tests for resilience against Cloudflare API changes.

    These tests verify correct behavior when the CF API returns unexpected
    fields, missing fields, changed field types, or new phases.
    """

    # --- New/unknown fields from CF API ---

    def test_new_api_field_causes_false_positive_modify(self):
        """If CF adds a new field not in API_ONLY_FIELDS, it triggers MODIFY.

        This documents the current behavior: unknown new fields from CF are
        NOT stripped and will cause a false-positive MODIFY when compared
        against the desired rules that lack the field. This is the expected
        safe default -- the user sees a diff rather than silently ignoring it.
        """
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                # Hypothetical new field CF starts returning
                "risk_score": 0.5,
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        # The extra field causes a diff because normalize_rule only strips known API_ONLY_FIELDS
        assert plan.has_changes
        mods = [c for c in plan.changes if c.change_type == ChangeType.MODIFY]
        assert len(mods) == 1
        assert mods[0].ref == "r1"

    def test_multiple_new_api_fields(self):
        """Multiple unknown fields all trigger a single MODIFY change."""
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "risk_score": 0.5,
                "deployment_id": "dep-123",
                "source": "dashboard",
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        assert len([c for c in plan.changes if c.change_type == ChangeType.MODIFY]) == 1

    # --- Missing optional fields ---

    def test_description_added_is_modification(self):
        """Adding a description to desired when CF has none should be a MODIFY."""
        desired = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "description": "My redirect",
            }
        ]
        current = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        assert plan.changes[0].change_type == ChangeType.MODIFY

    def test_action_parameters_null_vs_missing(self):
        """CF returning action_parameters: null vs desired not having it is a MODIFY."""
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": None,
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        # None != missing key -- this is a modification
        assert plan.has_changes

    def test_action_parameters_empty_dict_vs_missing(self):
        """CF returning empty action_parameters vs desired not having it is a MODIFY."""
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": {},
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes

    # --- Field type changes ---

    def test_enabled_as_int_vs_bool(self):
        """If CF returns enabled as int (1) vs desired bool (True), Python treats 1==True."""
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": 1}]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        # In Python, True == 1, so no change detected (this is intentional)
        assert not plan.has_changes

    def test_enabled_as_string_vs_bool(self):
        """If CF returns enabled as string 'true' vs bool True, it's a MODIFY."""
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": "true"}]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        # String "true" != bool True
        assert plan.has_changes

    # --- action_parameters nested changes ---

    def test_nested_action_parameters_change(self):
        """Deep changes in action_parameters are detected."""
        desired = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": {
                    "from_value": {"target_url": {"value": "https://new.example.com"}},
                },
            }
        ]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": {
                    "from_value": {"target_url": {"value": "https://old.example.com"}},
                },
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes
        assert plan.changes[0].change_type == ChangeType.MODIFY

    def test_action_parameters_new_nested_key(self):
        """CF adding a new nested key in action_parameters is detected."""
        desired = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": {"status_code": 301},
            }
        ]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "redirect",
                "enabled": True,
                "action_parameters": {"status_code": 301, "preserve_query_string": True},
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        assert plan.has_changes

    # --- Rules without ref ---

    def test_current_rule_without_ref_skipped_in_diff(self):
        """CF rules without ref are silently skipped by _rules_by_ref()."""
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"expression": "some-managed-rule", "action": "block"},  # No ref
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        # The no-ref rule is invisible to the diff engine -- no REMOVE for it
        removes = [c for c in plan.changes if c.change_type == ChangeType.REMOVE]
        assert len(removes) == 0

    def test_reorder_detection_ignores_refless_rules(self):
        """Reorder detection only considers rules with ref fields."""
        desired = [
            {"ref": "r1", "expression": "a", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "b", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r1", "expression": "a", "action": "redirect", "enabled": True},
            {"expression": "managed", "action": "block"},  # No ref, ignored
            {"ref": "r2", "expression": "b", "action": "redirect", "enabled": True},
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        reorders = [c for c in plan.changes if c.change_type == ChangeType.REORDER]
        assert len(reorders) == 0

    # --- Unknown phases in current ---

    def test_unknown_provider_id_mixed_with_known(self):
        """Unknown phases don't interfere with known phase processing."""
        desired = {
            "redirect_rules": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
        }
        current = {
            "http_request_dynamic_redirect": [
                {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}
            ],
            "http_request_unknown_new_phase": [{"ref": "x1", "expression": "true", "action": "x"}],
        }
        zp = plan_zone("example.com", desired, current)
        assert not zp.has_changes

    # --- Checksum stability with API changes ---

    def test_checksum_stable_despite_different_api_field_values(self):
        """Checksum uses normalized rules, so different API field values don't matter."""
        c1 = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={
                "id": "old-id",
                "version": "1",
                "last_updated": "2025-01-01",
                "expression": "old",
                "action": "redirect",
            },
            desired={"expression": "new", "action": "redirect"},
        )
        c2 = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={
                "id": "different-id",
                "version": "99",
                "last_updated": "2026-02-01",
                "categories": ["test"],
                "logging": {"enabled": True},
                "expression": "old",
                "action": "redirect",
            },
            desired={"expression": "new", "action": "redirect"},
        )
        pp1 = PhasePlan(phase=REDIRECT_PHASE, changes=[c1])
        pp2 = PhasePlan(phase=REDIRECT_PHASE, changes=[c2])
        zp1 = ZonePlan(zone_name="test.com", phase_plans=[pp1])
        zp2 = ZonePlan(zone_name="test.com", phase_plans=[pp2])
        assert compute_checksum([zp1]) == compute_checksum([zp2])

    # --- Normalize rule caching ---

    def test_rule_change_caches_normalized_current(self):
        """normalized_current() is cached after first call."""
        rc = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"id": "x", "expression": "true", "action": "redirect"},
        )
        first = rc.normalized_current
        second = rc.normalized_current
        assert first is second  # Same object, not just equal

    def test_rule_change_caches_normalized_desired(self):
        """normalized_desired() is cached after first call."""
        rc = RuleChange(
            ChangeType.ADD,
            "r1",
            REDIRECT_PHASE,
            desired={"expression": "true", "action": "redirect"},
        )
        first = rc.normalized_desired
        second = rc.normalized_desired
        assert first is second

    def test_rule_change_none_current_returns_none(self):
        """normalized_current() returns None when current is None."""
        rc = RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, current=None)
        assert rc.normalized_current is None

    def test_rule_change_none_desired_returns_none(self):
        """normalized_desired() returns None when desired is None."""
        rc = RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE, desired=None)
        assert rc.normalized_desired is None

    # --- Safety checks with unusual API data ---

    def test_safety_check_with_refless_rules_in_current(self):
        """Safety counts include ref-less rules since they're in the current list."""
        changes = [RuleChange(ChangeType.REMOVE, f"r{i}", REDIRECT_PHASE) for i in range(4)]
        pp = PhasePlan(phase=REDIRECT_PHASE, changes=changes)
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp])
        # 10 rules total, including ref-less ones
        current = {
            "http_request_dynamic_redirect": [
                *[{"ref": f"r{i}"} for i in range(8)],
                {"expression": "managed-1"},  # No ref
                {"expression": "managed-2"},  # No ref
            ]
        }
        violations = check_safety(
            zp,
            current,
            ZoneConfig(
                name="test.com",
                zone_id="z1",
                sources=["rules"],
                delete_threshold=30.0,
                update_threshold=30.0,
                min_existing=3,
            ),
        )
        assert len(violations) == 1
        assert violations[0].existing == 10
        assert violations[0].percentage == 40.0  # 4 out of 10


class TestDiffPhasePreparedRules:
    """Tests for PhasePlan.prepared_rules populated by diff_phase."""

    def test_prepared_rules_stored_on_phase_plan(self):
        """diff_phase should store the prepared rules on PhasePlan."""
        phase = get_phase("redirect_rules")
        desired = [{"ref": "r1", "expression": "true"}]
        plan = diff_phase(phase, desired, [])
        assert plan.prepared_rules is not None
        assert len(plan.prepared_rules) == 1
        # Should have defaults injected
        assert plan.prepared_rules[0]["enabled"] is True
        assert plan.prepared_rules[0]["action"] == "redirect"

    def test_prepared_rules_available_for_no_changes(self):
        """Even when there are no changes, prepared_rules should be available."""
        phase = get_phase("redirect_rules")
        desired = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        current = [{"ref": "r1", "expression": "true", "action": "redirect", "enabled": True}]
        plan = diff_phase(phase, desired, current)
        assert plan.prepared_rules is not None
        assert not plan.has_changes


class TestNormalizeRuleCaching:
    """Tests for pre-populated normalized values on MODIFY changes."""

    def test_modify_change_has_cached_normalized(self):
        """MODIFY RuleChange should have normalized values pre-populated."""
        phase = get_phase("redirect_rules")
        desired = [{"ref": "r1", "expression": "new_expr", "action": "redirect", "enabled": True}]
        current = [{"ref": "r1", "expression": "old_expr", "action": "redirect", "enabled": True}]
        plan = diff_phase(phase, desired, current)
        assert plan.has_changes
        change = plan.changes[0]
        assert change.change_type == ChangeType.MODIFY
        # Check that cached_property is pre-populated (accessing __dict__ directly)
        assert "normalized_current" in change.__dict__
        assert "normalized_desired" in change.__dict__
        assert change.normalized_current["expression"] == "old_expr"
        assert change.normalized_desired["expression"] == "new_expr"

    def test_add_change_no_pre_populated_normalized(self):
        """ADD changes should NOT have pre-populated normalized values."""
        phase = get_phase("redirect_rules")
        desired = [{"ref": "r1", "expression": "true"}]
        plan = diff_phase(phase, desired, [])
        change = plan.changes[0]
        assert change.change_type == ChangeType.ADD
        # Not pre-populated -- will be computed lazily if accessed
        assert "normalized_desired" not in change.__dict__


class TestDiffRulesHelper:
    """Tests for the extracted _diff_rules() helper."""

    def test_basic_add_remove_modify(self):
        phase = get_phase("redirect_rules")
        desired = [
            {"ref": "r1", "expression": "new_expr", "action": "redirect", "enabled": True},
            {"ref": "r3", "expression": "added", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r1", "expression": "old_expr", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "removed", "action": "redirect", "enabled": True},
        ]
        changes = _diff_rules(phase, desired, current)
        types = {c.change_type for c in changes}
        assert ChangeType.ADD in types
        assert ChangeType.REMOVE in types
        assert ChangeType.MODIFY in types
        # Verify refs
        refs_by_type = {
            c.change_type: c.ref for c in changes if c.change_type != ChangeType.REORDER
        }
        assert refs_by_type[ChangeType.ADD] == "r3"
        assert refs_by_type[ChangeType.REMOVE] == "r2"
        assert refs_by_type[ChangeType.MODIFY] == "r1"

    def test_allow_unmanaged_skips_remove(self):
        phase = get_phase("redirect_rules")
        desired = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "unmanaged", "action": "redirect", "enabled": True},
        ]
        changes = _diff_rules(phase, desired, current, allow_unmanaged=True)
        assert not any(c.change_type == ChangeType.REMOVE for c in changes)

    def test_reorder_detection(self):
        phase = get_phase("redirect_rules")
        desired = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
        ]
        changes = _diff_rules(phase, desired, current)
        assert any(c.change_type == ChangeType.REORDER for c in changes)

    def test_allow_unmanaged_reorder_detected_for_managed_subset(self):
        """Reorder among managed refs is detected even with allow_unmanaged."""
        phase = get_phase("redirect_rules")
        desired = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "unmanaged", "expression": "x", "action": "redirect", "enabled": True},
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
        ]
        changes = _diff_rules(phase, desired, current, allow_unmanaged=True)
        assert any(c.change_type == ChangeType.REORDER for c in changes)

    def test_allow_unmanaged_no_false_reorder(self):
        """No reorder when managed refs are in the same order but unmanaged refs differ."""
        phase = get_phase("redirect_rules")
        desired = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "unmanaged", "expression": "x", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        changes = _diff_rules(phase, desired, current, allow_unmanaged=True)
        assert not any(c.change_type == ChangeType.REORDER for c in changes)


class TestRulesByRef:
    """Tests for _rules_by_ref helper."""

    def test_indexes_by_ref(self):
        rules = [{"ref": "r1", "action": "block"}, {"ref": "r2", "action": "log"}]
        result = _rules_by_ref(rules)
        assert result == {"r1": rules[0], "r2": rules[1]}

    def test_skips_missing_ref(self):
        rules = [{"ref": "r1", "action": "block"}, {"action": "log"}]
        result = _rules_by_ref(rules)
        assert len(result) == 1
        assert "r1" in result

    def test_duplicate_ref_warns(self, caplog):
        """Duplicate refs should log a warning and last-wins."""
        rules = [
            {"ref": "r1", "action": "block"},
            {"ref": "r1", "action": "log"},
        ]
        with caplog.at_level(logging.WARNING, logger="octorules"):
            result = _rules_by_ref(rules)
        assert len(result) == 1
        assert result["r1"]["action"] == "log"
        assert "Duplicate ref" in caplog.text


class TestValidateCustomRuleset:
    """Tests for validate_custom_ruleset()."""

    def _valid_entry(self, **overrides):
        entry = {
            "id": "rs-1",
            "name": "My Ruleset",
            "phase": "http_request_firewall_custom",
            "rules": [
                {"ref": "r1", "expression": "true", "action": "block"},
            ],
        }
        entry.update(overrides)
        return entry

    def test_valid_entry_passes(self):
        validate_custom_ruleset(self._valid_entry(), 0)

    def test_missing_id_and_capacity(self):
        """Missing id without capacity should require capacity for creates."""
        entry = self._valid_entry()
        del entry["id"]
        with pytest.raises(RuleValidationError, match="require a 'capacity' field"):
            validate_custom_ruleset(entry, 0)

    def test_missing_id_with_capacity_ok(self):
        """Missing id with capacity is valid (CREATE)."""
        entry = self._valid_entry()
        del entry["id"]
        entry["capacity"] = 100
        validate_custom_ruleset(entry, 0)  # Should not raise

    def test_missing_name(self):
        entry = self._valid_entry()
        del entry["name"]
        with pytest.raises(RuleValidationError, match="missing required 'name'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_phase(self):
        entry = self._valid_entry()
        del entry["phase"]
        with pytest.raises(RuleValidationError, match="missing required 'phase'"):
            validate_custom_ruleset(entry, 0)

    def test_invalid_phase(self):
        entry = self._valid_entry(phase="waf_custom")
        with pytest.raises(RuleValidationError, match="invalid 'phase' 'waf_custom'"):
            validate_custom_ruleset(entry, 0)

    def test_friendly_name_rejected_as_phase(self):
        """Phase field must be a CF phase ID, not the friendly name."""
        entry = self._valid_entry(phase="waf_custom_rules")
        with pytest.raises(RuleValidationError, match="invalid 'phase'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_rule_ref(self):
        entry = self._valid_entry(rules=[{"expression": "true", "action": "block"}])
        with pytest.raises(RuleValidationError, match="missing required 'ref'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_rule_action(self):
        entry = self._valid_entry(rules=[{"ref": "r1", "expression": "true"}])
        with pytest.raises(RuleValidationError, match="must specify an 'action'"):
            validate_custom_ruleset(entry, 0)

    def test_duplicate_ref(self):
        entry = self._valid_entry(
            rules=[
                {"ref": "r1", "expression": "a", "action": "block"},
                {"ref": "r1", "expression": "b", "action": "block"},
            ]
        )
        with pytest.raises(RuleValidationError, match="Duplicate ref 'r1'"):
            validate_custom_ruleset(entry, 0)


# ---------------------------------------------------------------------------
# Expression normalization integration tests
# ---------------------------------------------------------------------------

RATE_LIMIT_PHASE = get_phase("rate_limiting_rules")


class TestExpressionNormalizationIntegration:
    """Tests that multi-line expressions are normalized in planner functions."""

    def test_prepare_desired_rules_normalizes_expression(self):
        rules = [
            {
                "ref": "r1",
                "expression": '(http.host eq "example.com")\n  and (ip.src in {1.2.3.4})\n',
            }
        ]
        prepared = prepare_desired_rules(rules, REDIRECT_PHASE)
        assert prepared[0]["expression"] == (
            '(http.host eq "example.com") and (ip.src in {1.2.3.4})'
        )

    def test_prepare_desired_rules_normalizes_counting_expression(self):
        rules = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "block",
                "action_parameters": {
                    "requests_per_period": 100,
                    "period": 60,
                    "counting_expression": '(http.host eq "example.com")\n  and true\n',
                },
            }
        ]
        prepared = prepare_desired_rules(rules, RATE_LIMIT_PHASE)
        assert prepared[0]["action_parameters"]["counting_expression"] == (
            '(http.host eq "example.com") and true'
        )

    def test_prepare_does_not_mutate_original(self):
        original_ap = {
            "requests_per_period": 100,
            "period": 60,
            "counting_expression": "a\nb",
        }
        rules = [
            {
                "ref": "r1",
                "expression": "a\nb",
                "action": "block",
                "action_parameters": original_ap,
            }
        ]
        prepare_desired_rules(rules, RATE_LIMIT_PHASE)
        # Original should be untouched
        assert rules[0]["expression"] == "a\nb"
        assert original_ap["counting_expression"] == "a\nb"

    def test_diff_phase_no_modify_when_normalized_matches(self):
        """Multi-line desired matching single-line current should produce no MODIFY."""
        desired = [
            {
                "ref": "r1",
                "expression": '(http.host eq "example.com")\n  and (ip.src in {1.2.3.4})\n',
                "action": "redirect",
                "enabled": True,
            }
        ]
        current = [
            {
                "ref": "r1",
                "expression": '(http.host eq "example.com") and (ip.src in {1.2.3.4})',
                "action": "redirect",
                "enabled": True,
            }
        ]
        plan = diff_phase(REDIRECT_PHASE, desired, current)
        modify_changes = [c for c in plan.changes if c.change_type == ChangeType.MODIFY]
        assert len(modify_changes) == 0

    def test_diff_custom_ruleset_normalizes_expressions(self):
        desired = [
            {
                "ref": "r1",
                "expression": "true\n",
                "action": "block",
                "enabled": True,
            }
        ]
        current = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "block",
                "enabled": True,
            }
        ]
        plan = diff_custom_ruleset(
            "rs-1", "test-ruleset", "http_request_firewall_custom", desired, current
        )
        modify_changes = [c for c in plan.changes if c.change_type == ChangeType.MODIFY]
        assert len(modify_changes) == 0


class TestZonePlanTarget:
    """Tests for ZonePlan.target, display_name, and plan_key (multi-target support)."""

    def test_target_default_none(self):
        zp = ZonePlan(zone_name="example.com")
        assert zp.target is None

    def test_display_name_no_target(self):
        zp = ZonePlan(zone_name="example.com")
        assert zp.display_name == "example.com"

    def test_display_name_with_target(self):
        zp = ZonePlan(zone_name="example.com", target="cf-prod")
        assert zp.display_name == "example.com \u2192 cf-prod"

    def test_plan_key_no_target(self):
        zp = ZonePlan(zone_name="example.com")
        assert zp.plan_key == "example.com"

    def test_plan_key_with_target(self):
        zp = ZonePlan(zone_name="example.com", target="cf-prod")
        assert zp.plan_key == "example.com\x00cf-prod"

    def test_checksum_includes_target(self):
        """Checksum differs when target is set."""
        zp_no_target = ZonePlan(zone_name="example.com")
        zp_with_target = ZonePlan(zone_name="example.com", target="cf-prod")
        assert compute_checksum([zp_no_target]) != compute_checksum([zp_with_target])

    def test_checksum_sorted_by_zone_and_target(self):
        """Checksum is stable regardless of insertion order."""
        zp1 = ZonePlan(zone_name="a.com", target="prod")
        zp2 = ZonePlan(zone_name="a.com", target="staging")
        assert compute_checksum([zp1, zp2]) == compute_checksum([zp2, zp1])


# ---------------------------------------------------------------------------
# octorules: metadata tests
# ---------------------------------------------------------------------------
class TestIsIgnored:
    def test_true_when_ignored(self):
        assert _is_ignored({"octorules": {"ignored": True}}) is True

    def test_false_when_not_ignored(self):
        assert _is_ignored({"octorules": {"ignored": False}}) is False

    def test_false_when_no_metadata(self):
        assert _is_ignored({"ref": "r1"}) is False

    def test_false_when_metadata_not_dict(self):
        assert _is_ignored({"octorules": True}) is False

    def test_false_when_truthy_non_bool(self):
        """Only exact True counts — 'yes', 1, etc. do not."""
        assert _is_ignored({"octorules": {"ignored": "yes"}}) is False
        assert _is_ignored({"octorules": {"ignored": 1}}) is False

    def test_false_when_empty_dict(self):
        assert _is_ignored({"octorules": {}}) is False


class TestIgnoredFiltering:
    """Verify ignored rules are filtered out during prepare/diff."""

    def _rule(self, ref, *, ignored=False):
        r = {"ref": ref, "expression": "true", "action": "block"}
        if ignored:
            r["octorules"] = {"ignored": True}
        return r

    def test_prepare_desired_rules_filters_ignored(self):
        rules = [self._rule("keep"), self._rule("skip", ignored=True)]
        prepared = prepare_desired_rules(rules, WAF_PHASE)
        refs = [r["ref"] for r in prepared]
        assert refs == ["keep"]

    def test_prepare_desired_rules_all_ignored(self):
        rules = [self._rule("a", ignored=True), self._rule("b", ignored=True)]
        prepared = prepare_desired_rules(rules, WAF_PHASE)
        assert prepared == []

    def test_ignored_still_validated_ref(self):
        """Ignored rules still go through ref validation."""
        rules = [
            {"octorules": {"ignored": True}},  # missing ref
        ]
        with pytest.raises(RuleValidationError, match="missing required 'ref'"):
            prepare_desired_rules(rules, WAF_PHASE)

    def test_diff_phase_ignores_rule(self):
        """Ignored rules produce no ADD/MODIFY/REMOVE in the plan."""
        desired = [self._rule("live"), self._rule("skip", ignored=True)]
        current = []
        plan = diff_phase(WAF_PHASE, desired, current)
        refs = [c.ref for c in plan.changes]
        assert refs == ["live"]

    def test_diff_phase_ignored_rule_not_deleted_from_current(self):
        """Ignored rule existing in current should NOT produce a REMOVE.

        octodns convention: ignored means invisible on both sides.
        """
        desired = [self._rule("live"), self._rule("skip", ignored=True)]
        current = [
            {"ref": "live", "expression": "true", "action": "block", "enabled": True},
            {"ref": "skip", "expression": "true", "action": "block", "enabled": True},
        ]
        plan = diff_phase(WAF_PHASE, desired, current)
        assert not plan.has_changes

    def test_diff_phase_ignored_rule_only_in_current(self):
        """Ignored rule only in current (not in desired YAML) still gets deleted.

        Only refs explicitly marked ignored in YAML are excluded from current.
        """
        desired = [self._rule("live")]
        current = [
            {"ref": "live", "expression": "true", "action": "block", "enabled": True},
            {"ref": "unmanaged", "expression": "true", "action": "block", "enabled": True},
        ]
        plan = diff_phase(WAF_PHASE, desired, current)
        refs = [c.ref for c in plan.changes]
        assert "unmanaged" in refs  # normal REMOVE behavior

    def test_diff_custom_ruleset_ignores_rule(self):
        rules = [self._rule("a"), self._rule("b", ignored=True)]
        plan = diff_custom_ruleset("rs-1", "test", "http_request_firewall_custom", rules, [])
        refs = [c.ref for c in plan.changes]
        assert refs == ["a"]
        prepared_refs = [r["ref"] for r in plan.prepared_rules]
        assert prepared_refs == ["a"]

    def test_diff_custom_ruleset_ignored_not_deleted_from_current(self):
        """Ignored rule in custom ruleset should not be deleted from current."""
        desired = [self._rule("a"), self._rule("b", ignored=True)]
        current = [
            {"ref": "a", "expression": "true", "action": "block", "enabled": True},
            {"ref": "b", "expression": "true", "action": "block", "enabled": True},
        ]
        plan = diff_custom_ruleset("rs-1", "test", "http_request_firewall_custom", desired, current)
        assert not plan.has_changes


class TestOctoruleKeyStripping:
    """Verify the octorules: key never reaches prepared rules or comparison."""

    def test_prepare_base_strips_key(self):
        rules = [
            {
                "ref": "r1",
                "expression": "true",
                "action": "block",
                "octorules": {"ignored": False},
            }
        ]
        prepared = prepare_desired_rules(rules, WAF_PHASE)
        assert "octorules" not in prepared[0]

    def test_normalize_rule_excludes_key(self):
        rule = {
            "ref": "r1",
            "expression": "true",
            "action": "block",
            "octorules": {"included": ["cloudflare"]},
        }
        normalized = normalize_rule(rule)
        assert "octorules" not in normalized


class TestRuleMatchesTarget:
    def test_no_metadata_matches_all(self):
        assert _rule_matches_target({"ref": "r1"}, "cloudflare") is True

    def test_non_dict_metadata_matches_all(self):
        assert _rule_matches_target({"ref": "r1", "octorules": True}, "cloudflare") is True

    def test_targets_include(self):
        rule = {"ref": "r1", "octorules": {"included": ["cloudflare"]}}
        assert _rule_matches_target(rule, "cloudflare") is True
        assert _rule_matches_target(rule, "aws") is False

    def test_targets_empty_list(self):
        """Empty targets list matches nothing."""
        rule = {"ref": "r1", "octorules": {"included": []}}
        assert _rule_matches_target(rule, "cloudflare") is False

    def test_excluded_exclude(self):
        rule = {"ref": "r1", "octorules": {"excluded": ["cf-staging"]}}
        assert _rule_matches_target(rule, "cf-prod") is True
        assert _rule_matches_target(rule, "cf-staging") is False

    def test_excluded_empty_list(self):
        """Empty excluded list excludes nothing."""
        rule = {"ref": "r1", "octorules": {"excluded": []}}
        assert _rule_matches_target(rule, "anything") is True

    def test_no_targets_or_excluded(self):
        rule = {"ref": "r1", "octorules": {"ignored": False}}
        assert _rule_matches_target(rule, "cloudflare") is True

    def test_targets_not_list_raises(self):
        rule = {"ref": "r1", "octorules": {"included": "cloudflare"}}
        with pytest.raises(RuleValidationError, match="must be a list"):
            _rule_matches_target(rule, "cloudflare")

    def test_excluded_not_list_raises(self):
        rule = {"ref": "r1", "octorules": {"excluded": "staging"}}
        with pytest.raises(RuleValidationError, match="must be a list"):
            _rule_matches_target(rule, "staging")


class TestFilterByTarget:
    def test_filters_rules_by_target(self):
        desired = {
            "waf_custom_rules": [
                {"ref": "both", "expression": "true"},
                {"ref": "cf-only", "expression": "true", "octorules": {"included": ["cloudflare"]}},
                {"ref": "aws-only", "expression": "true", "octorules": {"included": ["aws"]}},
            ],
        }
        result = filter_by_target(desired, "cloudflare")
        refs = [r["ref"] for r in result["waf_custom_rules"]]
        assert refs == ["both", "cf-only"]

    def test_non_list_values_pass_through(self):
        desired = {"some_setting": "value", "waf_custom_rules": []}
        result = filter_by_target(desired, "cloudflare")
        assert result["some_setting"] == "value"

    def test_excluded_filter(self):
        desired = {
            "waf_custom_rules": [
                {"ref": "r1", "expression": "true", "octorules": {"excluded": ["staging"]}},
            ],
        }
        assert len(filter_by_target(desired, "prod")["waf_custom_rules"]) == 1
        assert len(filter_by_target(desired, "staging")["waf_custom_rules"]) == 0

    def test_empty_phase_after_filtering(self):
        desired = {
            "waf_custom_rules": [
                {"ref": "r1", "expression": "true", "octorules": {"included": ["aws"]}},
            ],
        }
        result = filter_by_target(desired, "cloudflare")
        assert result["waf_custom_rules"] == []


class TestTargetsExcludedMutualExclusion:
    def test_both_targets_and_excluded_raises(self):
        rules = [
            {
                "ref": "bad",
                "expression": "true",
                "octorules": {"included": ["a"], "excluded": ["b"]},
            }
        ]
        with pytest.raises(RuleValidationError, match="mutually exclusive"):
            validate_rules(rules, WAF_PHASE)

    def test_targets_only_ok(self):
        rules = [{"ref": "ok", "expression": "true", "octorules": {"included": ["cloudflare"]}}]
        validate_rules(rules, WAF_PHASE)  # should not raise

    def test_excluded_only_ok(self):
        rules = [{"ref": "ok", "expression": "true", "octorules": {"excluded": ["staging"]}}]
        validate_rules(rules, WAF_PHASE)  # should not raise

    def test_empty_targets_plus_excluded_raises(self):
        """Even targets: [] + excluded: [...] is mutually exclusive (presence, not truthiness)."""
        rules = [
            {
                "ref": "bad",
                "expression": "true",
                "octorules": {"included": [], "excluded": ["b"]},
            }
        ]
        with pytest.raises(RuleValidationError, match="mutually exclusive"):
            validate_rules(rules, WAF_PHASE)

    def test_targets_plus_empty_excluded_raises(self):
        rules = [
            {
                "ref": "bad",
                "expression": "true",
                "octorules": {"included": ["a"], "excluded": []},
            }
        ]
        with pytest.raises(RuleValidationError, match="mutually exclusive"):
            validate_rules(rules, WAF_PHASE)

    def test_custom_ruleset_mutual_exclusion(self):
        """validate_custom_ruleset also catches targets+excluded."""
        entry = {
            "id": "rs-1",
            "name": "test",
            "phase": "http_request_firewall_custom",
            "rules": [
                {
                    "ref": "bad",
                    "expression": "true",
                    "action": "block",
                    "octorules": {"included": ["a"], "excluded": ["b"]},
                }
            ],
        }
        with pytest.raises(RuleValidationError, match="mutually exclusive"):
            validate_custom_ruleset(entry, 0)


# ---------------------------------------------------------------------------
# Checksum determinism (stability across calls, unicode)
# ---------------------------------------------------------------------------
class TestChecksumDeterminism:
    """Extended determinism tests for compute_checksum."""

    def test_checksum_deterministic_across_calls(self):
        """Same plan always produces same checksum."""
        phase = get_phase("redirect_rules")
        waf = get_phase("waf_custom_rules")
        cache = get_phase("cache_rules")

        # Build a complex plan with many change types, custom rulesets, lists
        pp_redirect = PhasePlan(
            phase=phase,
            changes=[
                RuleChange(ChangeType.ADD, "r1", phase, desired={"expression": "a"}),
                RuleChange(ChangeType.REMOVE, "r2", phase, current={"expression": "b"}),
                RuleChange(
                    ChangeType.MODIFY,
                    "r3",
                    phase,
                    current={"expression": "old"},
                    desired={"expression": "new"},
                ),
                RuleChange(ChangeType.REORDER, "*", phase),
            ],
        )
        pp_waf = PhasePlan(
            phase=waf,
            changes=[
                RuleChange(ChangeType.ADD, "w1", waf, desired={"expression": "waf-expr"}),
            ],
        )
        pp_cache = PhasePlan(
            phase=cache,
            changes=[
                RuleChange(
                    ChangeType.MODIFY,
                    "c1",
                    cache,
                    current={"expression": "x"},
                    desired={"expression": "y"},
                ),
            ],
        )

        from octorules.planner import CustomRulesetPlan, ListPlan, _make_synthetic_phase

        cr_phase = _make_synthetic_phase("custom_ruleset", "MyRS", "http_request_firewall_custom")
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="MyRS",
            phase="http_request_firewall_custom",
            changes=[RuleChange(ChangeType.ADD, "cr1", cr_phase, desired={"expression": "true"})],
        )
        lp = ListPlan(
            list_name="blocklist",
            list_id="list-1",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "item1", phase, desired={"ip": "1.2.3.4"})],
        )

        zp1 = ZonePlan(
            zone_name="zone1.com",
            phase_plans=[pp_redirect, pp_waf],
            custom_ruleset_plans=[crp],
            list_plans=[lp],
        )
        zp2 = ZonePlan(zone_name="zone2.com", phase_plans=[pp_cache])

        checksums = [compute_checksum([zp1, zp2]) for _ in range(10)]
        assert len(set(checksums)) == 1, f"Expected all identical, got {set(checksums)}"
        assert len(checksums[0]) == 64

    def test_checksum_deterministic_with_unicode(self):
        """Checksum handles Unicode refs and expressions."""
        phase = get_phase("waf_custom_rules")
        changes = [
            RuleChange(
                ChangeType.ADD,
                "regel-\u00fc\u00e4\u00f6",
                phase,
                desired={
                    "expression": 'http.host eq "\u00e9xample.com"',
                    "description": "\u2603 Snowman rule",
                },
            ),
            RuleChange(
                ChangeType.MODIFY,
                "\u65e5\u672c\u8a9e-ref",
                phase,
                current={"expression": "\u65e7\u5f0f", "description": "\u53e4\u3044"},
                desired={"expression": "\u65b0\u5f0f", "description": "\u65b0\u3057\u3044"},
            ),
        ]
        pp = PhasePlan(phase=phase, changes=changes)
        zp = ZonePlan(zone_name="\u00fc\u00f1\u00ee\u00e7\u00f6\u00f0\u00e9.com", phase_plans=[pp])

        h1 = compute_checksum([zp])
        h2 = compute_checksum([zp])
        assert h1 == h2
        assert len(h1) == 64
        # Must be valid hex
        int(h1, 16)


# ---------------------------------------------------------------------------
# Refless current rules in diff
# ---------------------------------------------------------------------------
class TestDiffReflessCurrentRules:
    """Tests for _diff_rules when current rules lack a ref field."""

    def test_diff_handles_refless_current_rules(self):
        """Rules without ref in current are handled gracefully."""
        phase = get_phase("redirect_rules")
        desired = [
            {"ref": "r1", "expression": "new_expr", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r1", "expression": "old_expr", "action": "redirect", "enabled": True},
            {"expression": "true", "action": "block"},  # no ref
        ]
        changes = _diff_rules(phase, desired, current)
        # Should not crash; r1 should be matched and detected as MODIFY
        types = {c.change_type for c in changes}
        assert ChangeType.MODIFY in types
        refs = {c.ref for c in changes if c.change_type == ChangeType.MODIFY}
        assert "r1" in refs
        # The refless rule has no ref, so _rules_by_ref skips it — it is NOT
        # in current_refs, which means it won't appear as REMOVE either.
        # This is the expected "silently skipped" behaviour.
        assert not any(c.ref == "" for c in changes)

    def test_reorder_detection_with_refless_current(self):
        """Reorder detection works when current has refless rules."""
        phase = get_phase("redirect_rules")
        desired = [
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
        ]
        current = [
            {"ref": "r2", "expression": "true", "action": "redirect", "enabled": True},
            {"expression": "true", "action": "block"},  # no ref — ignored by _ref_order
            {"ref": "r1", "expression": "true", "action": "redirect", "enabled": True},
        ]
        changes = _diff_rules(phase, desired, current)
        # Reorder should be detected between r1 and r2
        assert any(c.change_type == ChangeType.REORDER for c in changes)


# ---------------------------------------------------------------------------
# Large ruleset reorder performance
# ---------------------------------------------------------------------------
class TestLargeRulesetReorderPerformance:
    """Performance regression test for reorder detection with many rules."""

    def test_large_ruleset_reorder_performance(self):
        """Reorder detection with 500 rules completes quickly."""
        import time

        phase = get_phase("redirect_rules")
        # Generate 500 rules with refs "r000" to "r499"
        desired = [
            {"ref": f"r{i:03d}", "expression": f"expr_{i}", "action": "redirect", "enabled": True}
            for i in range(500)
        ]
        # Reverse the order for current
        current = list(reversed(desired))

        start = time.monotonic()
        changes = _diff_rules(phase, desired, current)
        elapsed = time.monotonic() - start

        assert elapsed < 2.0, f"diff took {elapsed:.2f}s, expected < 2s"
        # Should detect reorder (same set of refs, different order)
        assert any(c.change_type == ChangeType.REORDER for c in changes)
        # No adds, removes, or modifies (content is identical)
        assert not any(c.change_type == ChangeType.ADD for c in changes)
        assert not any(c.change_type == ChangeType.REMOVE for c in changes)
        assert not any(c.change_type == ChangeType.MODIFY for c in changes)


# ---------------------------------------------------------------------------
# count_change_types
# ---------------------------------------------------------------------------
class TestCountChangeTypes:
    """Tests for count_change_types — tally logic for safety thresholds."""

    def test_empty(self):
        from octorules.planner import count_change_types

        assert count_change_types([]) == (0, 0, 0)

    def test_all_types(self):
        from octorules.planner import count_change_types

        changes = [
            RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE),
            RuleChange(ChangeType.REMOVE, "r2", REDIRECT_PHASE),
            RuleChange(ChangeType.MODIFY, "r3", REDIRECT_PHASE),
            RuleChange(ChangeType.ADD, "r4", REDIRECT_PHASE),
        ]
        adds, removes, modifies = count_change_types(changes)
        assert (adds, removes, modifies) == (2, 1, 1)

    def test_extra_creates_and_removes(self):
        from octorules.planner import count_change_types

        changes = [RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)]
        adds, removes, modifies = count_change_types(changes, extra_creates=3, extra_removes=2)
        assert (adds, removes, modifies) == (4, 2, 0)

    def test_reorder_not_counted(self):
        from octorules.planner import count_change_types

        changes = [RuleChange(ChangeType.REORDER, "", REDIRECT_PHASE)]
        assert count_change_types(changes) == (0, 0, 0)


# ---------------------------------------------------------------------------
# _validate_octorules_meta
# ---------------------------------------------------------------------------
class TestValidateOctorulesMeta:
    """Tests for octorules: metadata validation."""

    def test_included_and_excluded_raises(self):
        from octorules.planner import _validate_octorules_meta

        rule = {
            "ref": "r1",
            "octorules": {"included": ["a"], "excluded": ["b"]},
        }
        with pytest.raises(RuleValidationError, match="mutually exclusive"):
            _validate_octorules_meta(rule, "r1")

    def test_included_only_ok(self):
        from octorules.planner import _validate_octorules_meta

        _validate_octorules_meta({"ref": "r1", "octorules": {"included": ["a"]}}, "r1")

    def test_excluded_only_ok(self):
        from octorules.planner import _validate_octorules_meta

        _validate_octorules_meta({"ref": "r1", "octorules": {"excluded": ["b"]}}, "r1")

    def test_no_meta_ok(self):
        from octorules.planner import _validate_octorules_meta

        _validate_octorules_meta({"ref": "r1"}, "r1")

    def test_non_dict_meta_ignored(self):
        from octorules.planner import _validate_octorules_meta

        _validate_octorules_meta({"ref": "r1", "octorules": "ignored"}, "r1")


# ---------------------------------------------------------------------------
# _require_field / _require_string_field
# ---------------------------------------------------------------------------
class TestRequireField:
    """Tests for field validation helpers."""

    def test_missing_field_raises(self):
        from octorules.planner import _require_field

        with pytest.raises(RuleValidationError, match="missing required"):
            _require_field({}, "name", "context", str)

    def test_wrong_type_raises(self):
        from octorules.planner import _require_field

        with pytest.raises(RuleValidationError, match="invalid"):
            _require_field({"name": 123}, "name", "context", str)

    def test_valid_returns_value(self):
        from octorules.planner import _require_field

        assert _require_field({"name": "hello"}, "name", "context", str) == "hello"

    def test_string_field_empty_raises(self):
        from octorules.planner import _require_string_field

        with pytest.raises(RuleValidationError, match="non-empty"):
            _require_string_field({"name": ""}, "name", "context")

    def test_string_field_valid(self):
        from octorules.planner import _require_string_field

        assert _require_string_field({"name": "ok"}, "name", "context") == "ok"
