"""Tests for the diff engine (planner) – custom rulesets."""

from __future__ import annotations

import logging

import pytest

from octorules.config import ZoneConfig
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    CustomRulesetPlan,
    PhasePlan,
    RuleChange,
    RuleValidationError,
    ZonePlan,
    check_safety,
    compute_checksum,
    diff_custom_ruleset,
    plan_zone,
    validate_custom_ruleset,
    warn_unknown_phase_keys,
)

REDIRECT_PHASE = get_phase("redirect_rules")
CACHE_PHASE = get_phase("cache_rules")
WAF_PHASE = get_phase("waf_custom_rules")


class TestCustomRulesetPlan:
    """Tests for CustomRulesetPlan dataclass."""

    def test_has_changes_false(self):
        crp = CustomRulesetPlan(ruleset_id="rs1", ruleset_name="Test", phase="p")
        assert not crp.has_changes

    def test_has_changes_true(self):
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Test",
            phase="p",
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        assert crp.has_changes


class TestZonePlanWithCustomRulesets:
    """Tests for ZonePlan including custom ruleset plans."""

    def test_has_changes_with_custom_rulesets_only(self):
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Test",
            phase="p",
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        assert zp.has_changes

    def test_total_changes_includes_custom_rulesets(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Test",
            phase="p",
            changes=[
                RuleChange(ChangeType.ADD, "r2", REDIRECT_PHASE),
                RuleChange(ChangeType.MODIFY, "r3", REDIRECT_PHASE),
            ],
        )
        zp = ZonePlan(
            zone_name="test.com",
            phase_plans=[pp],
            custom_ruleset_plans=[crp],
        )
        assert zp.total_changes == 3

    def test_no_changes_without_custom_rulesets(self):
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[])
        assert not zp.has_changes
        assert zp.total_changes == 0


class TestDiffCustomRuleset:
    """Tests for diff_custom_ruleset function."""

    def test_no_changes(self):
        desired = [{"ref": "r1", "expression": "true", "action": "block", "enabled": True}]
        current = [{"ref": "r1", "expression": "true", "action": "block", "enabled": True}]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, current)
        assert not crp.has_changes

    def test_addition(self):
        desired = [{"ref": "r1", "expression": "true", "action": "block"}]
        current = []
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, current)
        assert crp.has_changes
        assert len(crp.changes) == 1
        assert crp.changes[0].change_type == ChangeType.ADD
        assert crp.changes[0].ref == "r1"

    def test_removal(self):
        desired = []
        current = [{"ref": "r1", "expression": "true", "action": "block"}]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, current)
        assert crp.has_changes
        assert len(crp.changes) == 1
        assert crp.changes[0].change_type == ChangeType.REMOVE

    def test_modification(self):
        desired = [{"ref": "r1", "expression": "new", "action": "block", "enabled": True}]
        current = [{"ref": "r1", "expression": "old", "action": "block", "enabled": True}]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, current)
        assert crp.has_changes
        mods = [c for c in crp.changes if c.change_type == ChangeType.MODIFY]
        assert len(mods) == 1

    def test_reorder(self):
        desired = [
            {"ref": "r1", "expression": "a", "action": "block", "enabled": True},
            {"ref": "r2", "expression": "b", "action": "block", "enabled": True},
        ]
        current = [
            {"ref": "r2", "expression": "b", "action": "block", "enabled": True},
            {"ref": "r1", "expression": "a", "action": "block", "enabled": True},
        ]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, current)
        assert crp.has_changes
        reorders = [c for c in crp.changes if c.change_type == ChangeType.REORDER]
        assert len(reorders) == 1

    def test_prepared_rules_stored(self):
        desired = [{"ref": "r1", "expression": "true", "action": "block"}]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, [])
        assert crp.prepared_rules is not None
        assert len(crp.prepared_rules) == 1
        assert crp.prepared_rules[0]["enabled"] is True

    def test_synthetic_phase_name(self):
        desired = [{"ref": "r1", "expression": "true", "action": "block"}]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, [])
        assert crp.changes[0].phase.friendly_name == "custom_ruleset:Block"

    def test_api_fields_ignored(self):
        desired = [{"ref": "r1", "expression": "true", "action": "block", "enabled": True}]
        current = [
            {
                "id": "uuid",
                "version": "5",
                "ref": "r1",
                "expression": "true",
                "action": "block",
                "enabled": True,
            }
        ]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, current)
        assert not crp.has_changes

    def test_mixed_changes(self):
        desired = [
            {"ref": "r1", "expression": "changed", "action": "block", "enabled": True},
            {"ref": "r3", "expression": "new", "action": "log"},
        ]
        current = [
            {"ref": "r1", "expression": "original", "action": "block", "enabled": True},
            {"ref": "r2", "expression": "removed", "action": "block"},
        ]
        crp = diff_custom_ruleset("rs1", "Block", "http_request_firewall_custom", desired, current)
        types = {c.change_type for c in crp.changes}
        assert ChangeType.ADD in types
        assert ChangeType.REMOVE in types
        assert ChangeType.MODIFY in types


class TestValidateCustomRuleset:
    """Tests for validate_custom_ruleset."""

    def test_valid_entry(self):
        entry = {
            "id": "rs1",
            "name": "Block",
            "phase": "http_request_firewall_custom",
            "rules": [{"ref": "r1", "expression": "true", "action": "block"}],
        }
        validate_custom_ruleset(entry, 0)  # Should not raise

    def test_missing_id(self):
        entry = {"name": "Block", "phase": "p", "rules": []}
        with pytest.raises(RuleValidationError, match="missing required 'id'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_name(self):
        entry = {"id": "rs1", "phase": "p", "rules": []}
        with pytest.raises(RuleValidationError, match="missing required 'name'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_phase(self):
        entry = {"id": "rs1", "name": "X", "rules": []}
        with pytest.raises(RuleValidationError, match="missing required 'phase'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_rule_ref(self):
        entry = {
            "id": "rs1",
            "name": "X",
            "phase": "p",
            "rules": [{"expression": "true", "action": "block"}],
        }
        with pytest.raises(RuleValidationError, match="missing required 'ref'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_rule_expression(self):
        entry = {
            "id": "rs1",
            "name": "X",
            "phase": "p",
            "rules": [{"ref": "r1", "action": "block"}],
        }
        with pytest.raises(RuleValidationError, match="missing required 'expression'"):
            validate_custom_ruleset(entry, 0)

    def test_missing_rule_action(self):
        entry = {
            "id": "rs1",
            "name": "X",
            "phase": "p",
            "rules": [{"ref": "r1", "expression": "true"}],
        }
        with pytest.raises(RuleValidationError, match="must specify an 'action'"):
            validate_custom_ruleset(entry, 0)

    def test_duplicate_ref(self):
        entry = {
            "id": "rs1",
            "name": "X",
            "phase": "p",
            "rules": [
                {"ref": "r1", "expression": "a", "action": "block"},
                {"ref": "r1", "expression": "b", "action": "log"},
            ],
        }
        with pytest.raises(RuleValidationError, match="Duplicate ref"):
            validate_custom_ruleset(entry, 0)

    def test_empty_rules_ok(self):
        entry = {"id": "rs1", "name": "X", "phase": "p", "rules": []}
        validate_custom_ruleset(entry, 0)

    def test_no_rules_key_ok(self):
        entry = {"id": "rs1", "name": "X", "phase": "p"}
        validate_custom_ruleset(entry, 0)


class TestWarnUnknownPhaseKeysCustomRulesets:
    """Test that custom_rulesets doesn't trigger unknown phase warning."""

    def test_custom_rulesets_not_warned(self, caplog):
        rules_data = {"redirect_rules": [], "custom_rulesets": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "account")
        assert "custom_rulesets" not in caplog.text


class TestWarnUnknownPhaseKeysNewPhases:
    """New phases should be recognized by warn_unknown_phase_keys."""

    @pytest.mark.parametrize(
        "phase_name",
        [
            "http_ddos_rules",
            "bulk_redirect_rules",
            "log_custom_fields",
            "network_ddos_rules",
            "network_firewall_rules",
            "network_firewall_managed",
            "network_firewall_ratelimit",
            "network_firewall_ids",
            "url_normalization",
        ],
    )
    def test_new_phase_not_warned(self, phase_name, caplog):
        rules_data = {phase_name: []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert caplog.text == ""


class TestPlanZoneNewPhases:
    """plan_zone works correctly with the new phases."""

    def test_plan_zone_with_network_firewall_rules(self):
        desired = {
            "network_firewall_rules": [{"ref": "mf1", "expression": "true", "action": "block"}],
        }
        zone_plan = plan_zone("example.com", desired, {})
        assert zone_plan.has_changes
        assert zone_plan.total_changes == 1

    def test_plan_zone_with_bulk_redirect_rules(self):
        desired = {
            "bulk_redirect_rules": [{"ref": "br1", "expression": "true"}],
        }
        zone_plan = plan_zone("example.com", desired, {})
        assert zone_plan.has_changes

    def test_plan_zone_with_http_ddos_rules(self):
        desired = {
            "http_ddos_rules": [{"ref": "d1", "expression": "true", "action": "managed_challenge"}],
        }
        zone_plan = plan_zone("example.com", desired, {})
        assert zone_plan.has_changes

    def test_plan_zone_with_log_custom_fields(self):
        desired = {
            "log_custom_fields": [{"ref": "lcf1", "expression": "true"}],
        }
        zone_plan = plan_zone("example.com", desired, {})
        assert zone_plan.has_changes

    def test_plan_zone_with_url_normalization(self):
        desired = {
            "url_normalization": [{"ref": "un1", "expression": "true", "action": "rewrite"}],
        }
        zone_plan = plan_zone("example.com", desired, {})
        assert zone_plan.has_changes

    def test_plan_zone_no_changes_matching_new_phase(self):
        desired = {
            "network_firewall_rules": [{"ref": "mf1", "expression": "true", "action": "block"}],
        }
        current = {
            "magic_transit": [
                {"ref": "mf1", "expression": "true", "action": "block", "enabled": True}
            ],
        }
        zone_plan = plan_zone("example.com", desired, current)
        assert not zone_plan.has_changes


class TestComputeChecksumWithCustomRulesets:
    """Tests for checksum including custom ruleset plans."""

    def test_checksum_includes_custom_rulesets(self):
        change = RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, desired={"expression": "true"})
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block",
            phase="p",
            changes=[change],
        )
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        h1 = compute_checksum([zp])
        assert len(h1) == 64

    def test_checksum_differs_with_custom_rulesets(self):
        c1 = RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE, desired={"expression": "true"})
        crp1 = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block",
            phase="p",
            changes=[c1],
        )
        c2 = RuleChange(ChangeType.ADD, "r2", REDIRECT_PHASE, desired={"expression": "false"})
        crp2 = CustomRulesetPlan(
            ruleset_id="rs2",
            ruleset_name="Rate",
            phase="p",
            changes=[c2],
        )
        zp1 = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp1])
        zp2 = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp2])
        assert compute_checksum([zp1]) != compute_checksum([zp2])


class TestCheckSafetyWithCustomRulesets:
    """Tests for safety checks including custom ruleset changes."""

    def test_custom_ruleset_deletes_counted(self):
        """Custom ruleset REMOVE changes should be counted in safety checks."""
        from octorules.planner import _make_synthetic_phase

        phase = _make_synthetic_phase("Block", "http_request_firewall_custom")
        changes = [RuleChange(ChangeType.REMOVE, f"r{i}", phase) for i in range(4)]
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block",
            phase="http_request_firewall_custom",
            changes=changes,
        )
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        current = {"http_request_firewall_custom": [{"ref": f"r{i}"} for i in range(10)]}
        cfg = ZoneConfig(
            name="test.com",
            zone_id="z1",
            sources=["rules"],
            delete_threshold=30.0,
            min_existing=3,
        )
        violations = check_safety(zp, current, cfg)
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert "custom_ruleset:Block" in violations[0].phases
