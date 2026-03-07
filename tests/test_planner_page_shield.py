"""Tests for the diff engine (planner) – page shield policies."""

from __future__ import annotations

import logging

import pytest

from octorules.config import ZoneConfig
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    PageShieldPolicyPlan,
    PhasePlan,
    RuleChange,
    RuleValidationError,
    ZonePlan,
    check_safety,
    compute_checksum,
    diff_page_shield_policies,
    validate_page_shield_policy,
    warn_unknown_phase_keys,
)

REDIRECT_PHASE = get_phase("redirect_rules")
CACHE_PHASE = get_phase("cache_rules")
WAF_PHASE = get_phase("waf_custom_rules")


class TestPageShieldPolicyPlan:
    """Tests for PageShieldPolicyPlan dataclass."""

    def test_no_changes_empty(self):
        pp = PageShieldPolicyPlan(description="CSP")
        assert not pp.has_changes
        assert pp.total_changes == 0

    def test_create_has_changes(self):
        pp = PageShieldPolicyPlan(description="CSP", create=True)
        assert pp.has_changes
        assert pp.total_changes == 1

    def test_delete_has_changes(self):
        pp = PageShieldPolicyPlan(description="CSP", policy_id="pol-1", delete=True)
        assert pp.has_changes
        assert pp.total_changes == 1

    def test_field_changes_has_changes(self):
        pp = PageShieldPolicyPlan(
            description="CSP",
            policy_id="pol-1",
            changes=[RuleChange(ChangeType.MODIFY, "action", REDIRECT_PHASE)],
        )
        assert pp.has_changes
        assert pp.total_changes == 1

    def test_total_changes_counting(self):
        pp = PageShieldPolicyPlan(
            description="CSP",
            create=True,
            changes=[
                RuleChange(ChangeType.ADD, "action", REDIRECT_PHASE),
                RuleChange(ChangeType.ADD, "value", REDIRECT_PHASE),
            ],
        )
        # 1 (create) + 2 (field adds) = 3
        assert pp.total_changes == 3


class TestValidatePageShieldPolicy:
    """Tests for validate_page_shield_policy."""

    def test_valid_entry(self):
        entry = {
            "description": "CSP on all",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "script-src 'self'",
        }
        validate_page_shield_policy(entry, 0)  # Should not raise

    def test_missing_description(self):
        entry = {"action": "allow", "expression": "true", "enabled": True, "value": "v"}
        with pytest.raises(RuleValidationError, match="missing required 'description'"):
            validate_page_shield_policy(entry, 0)

    def test_empty_description(self):
        entry = {
            "description": "",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "v",
        }
        with pytest.raises(RuleValidationError, match="invalid 'description'"):
            validate_page_shield_policy(entry, 0)

    def test_missing_action(self):
        entry = {"description": "CSP", "expression": "true", "enabled": True, "value": "v"}
        with pytest.raises(RuleValidationError, match="missing required 'action'"):
            validate_page_shield_policy(entry, 0)

    def test_invalid_action(self):
        entry = {
            "description": "CSP",
            "action": "block",
            "expression": "true",
            "enabled": True,
            "value": "v",
        }
        with pytest.raises(RuleValidationError, match="invalid 'action' 'block'"):
            validate_page_shield_policy(entry, 0)

    def test_missing_expression(self):
        entry = {"description": "CSP", "action": "allow", "enabled": True, "value": "v"}
        with pytest.raises(RuleValidationError, match="missing required 'expression'"):
            validate_page_shield_policy(entry, 0)

    def test_empty_expression(self):
        entry = {
            "description": "CSP",
            "action": "allow",
            "expression": "",
            "enabled": True,
            "value": "v",
        }
        with pytest.raises(RuleValidationError, match="invalid 'expression'"):
            validate_page_shield_policy(entry, 0)

    def test_missing_enabled(self):
        entry = {"description": "CSP", "action": "allow", "expression": "true", "value": "v"}
        with pytest.raises(RuleValidationError, match="missing required 'enabled'"):
            validate_page_shield_policy(entry, 0)

    def test_non_bool_enabled(self):
        entry = {
            "description": "CSP",
            "action": "allow",
            "expression": "true",
            "enabled": "yes",
            "value": "v",
        }
        with pytest.raises(RuleValidationError, match="invalid 'enabled'"):
            validate_page_shield_policy(entry, 0)

    def test_missing_value(self):
        entry = {"description": "CSP", "action": "allow", "expression": "true", "enabled": True}
        with pytest.raises(RuleValidationError, match="missing required 'value'"):
            validate_page_shield_policy(entry, 0)

    def test_empty_value(self):
        entry = {
            "description": "CSP",
            "action": "allow",
            "expression": "true",
            "enabled": True,
            "value": "",
        }
        with pytest.raises(RuleValidationError, match="invalid 'value'"):
            validate_page_shield_policy(entry, 0)

    def test_error_includes_index(self):
        entry = {"action": "allow", "expression": "true", "enabled": True, "value": "v"}
        with pytest.raises(RuleValidationError, match=r"page_shield_policies\[3\]"):
            validate_page_shield_policy(entry, 3)


class TestDiffPageShieldPolicies:
    """Tests for diff_page_shield_policies."""

    def test_no_changes(self):
        """Identical policies produce no plans."""
        desired = [
            {
                "description": "CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        current = [
            {
                "description": "CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        plans = diff_page_shield_policies(desired, current)
        assert plans == []

    def test_create_new_policy(self):
        """Policy in desired but not current should produce a create plan."""
        desired = [
            {
                "description": "New CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        current = []
        plans = diff_page_shield_policies(desired, current)
        assert len(plans) == 1
        assert plans[0].description == "New CSP"
        assert plans[0].create is True
        assert plans[0].policy_id is None

    def test_delete_existing_policy(self):
        """Policy in current but not desired should produce a delete plan."""
        desired = []
        current = [
            {
                "id": "pol-1",
                "description": "Old CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        plans = diff_page_shield_policies(desired, current)
        assert len(plans) == 1
        assert plans[0].description == "Old CSP"
        assert plans[0].delete is True
        assert plans[0].policy_id == "pol-1"

    def test_modify_policy_field(self):
        """Field change on existing policy should produce modify changes."""
        desired = [
            {
                "description": "CSP",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        current = [
            {
                "id": "pol-1",
                "description": "CSP",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        plans = diff_page_shield_policies(desired, current)
        assert len(plans) == 1
        assert plans[0].description == "CSP"
        assert plans[0].policy_id == "pol-1"
        assert not plans[0].create
        assert not plans[0].delete
        assert len(plans[0].changes) == 1
        assert plans[0].changes[0].ref == "action"

    def test_modify_multiple_fields(self):
        """Multiple field changes should produce multiple change entries."""
        desired = [
            {
                "description": "CSP",
                "action": "log",
                "expression": "new_expr",
                "enabled": False,
                "value": "new_v",
            },
        ]
        current = [
            {
                "id": "pol-1",
                "description": "CSP",
                "action": "allow",
                "expression": "old_expr",
                "enabled": True,
                "value": "old_v",
            },
        ]
        plans = diff_page_shield_policies(desired, current)
        assert len(plans) == 1
        assert len(plans[0].changes) == 4
        refs = {c.ref for c in plans[0].changes}
        assert refs == {"action", "expression", "enabled", "value"}

    def test_mixed_create_modify_delete(self):
        """Mix of create, modify, and delete."""
        desired = [
            {
                "description": "Keep",
                "action": "log",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
            {
                "description": "New",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        current = [
            {
                "id": "pol-1",
                "description": "Keep",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
            {
                "id": "pol-2",
                "description": "Delete",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        plans = diff_page_shield_policies(desired, current)
        descs = {p.description for p in plans}
        assert descs == {"Keep", "New", "Delete"}

        keep_plan = next(p for p in plans if p.description == "Keep")
        assert not keep_plan.create
        assert not keep_plan.delete
        assert len(keep_plan.changes) == 1  # action changed

        new_plan = next(p for p in plans if p.description == "New")
        assert new_plan.create is True

        del_plan = next(p for p in plans if p.description == "Delete")
        assert del_plan.delete is True

    def test_sorted_by_description(self):
        """Plans should be sorted by description."""
        desired = [
            {
                "description": "ZZZ",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
            {
                "description": "AAA",
                "action": "allow",
                "expression": "true",
                "enabled": True,
                "value": "v",
            },
        ]
        current = []
        plans = diff_page_shield_policies(desired, current)
        assert plans[0].description == "AAA"
        assert plans[1].description == "ZZZ"


class TestZonePlanWithPageShieldPolicies:
    """Tests for ZonePlan including page_shield_policy_plans."""

    def test_has_changes_with_policies_only(self):
        pp = PageShieldPolicyPlan(description="CSP", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[pp])
        assert zp.has_changes

    def test_total_changes_includes_policies(self):
        psp = PageShieldPolicyPlan(
            description="CSP",
            create=True,
            changes=[RuleChange(ChangeType.ADD, "action", REDIRECT_PHASE)],
        )
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp], page_shield_policy_plans=[psp])
        # 1 (phase) + 1 (create) + 1 (field add) = 3
        assert zp.total_changes == 3


class TestWarnUnknownPhaseKeysPageShield:
    """Test that page_shield_policies doesn't trigger unknown phase warning."""

    def test_page_shield_policies_not_warned(self, caplog):
        rules_data = {"redirect_rules": [], "page_shield_policies": []}
        with caplog.at_level(logging.WARNING, logger="octorules"):
            warn_unknown_phase_keys(rules_data, "example.com")
        assert "page_shield_policies" not in caplog.text


class TestComputeChecksumWithPageShieldPolicies:
    """Tests for checksum including page shield policy plans."""

    def test_checksum_includes_policies(self):
        psp = PageShieldPolicyPlan(
            description="CSP",
            create=True,
            changes=[
                RuleChange(ChangeType.ADD, "action", REDIRECT_PHASE, desired={"action": "allow"})
            ],
        )
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        h = compute_checksum([zp])
        assert len(h) == 64

    def test_checksum_differs_with_policies(self):
        psp1 = PageShieldPolicyPlan(description="CSP-A", create=True)
        psp2 = PageShieldPolicyPlan(description="CSP-B", create=True)
        zp1 = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp1])
        zp2 = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp2])
        assert compute_checksum([zp1]) != compute_checksum([zp2])


class TestCheckSafetyWithPageShieldPolicies:
    """Tests for safety checks including page shield policy changes."""

    def _zone_cfg(self, delete_threshold=30.0, update_threshold=30.0, min_existing=3):
        return ZoneConfig(
            name="test.com",
            zone_id="z1",
            sources=["rules"],
            delete_threshold=delete_threshold,
            update_threshold=update_threshold,
            min_existing=min_existing,
        )

    def _make_page_shield_phase(self, desc: str):
        from octorules.planner import _make_page_shield_phase

        return _make_page_shield_phase(desc)

    def test_page_shield_delete_counted(self):
        """Page shield delete=True should be counted as a delete in safety checks."""
        psp = PageShieldPolicyPlan(
            description="CSP",
            policy_id="pol-1",
            delete=True,
        )
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(3)]}
        violations = check_safety(zp, current, self._zone_cfg(delete_threshold=30.0))
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert "page_shield:CSP" in violations[0].phases

    def test_page_shield_remove_changes_counted(self):
        """REMOVE changes in page shield policy changes should count toward deletes."""
        synthetic = self._make_page_shield_phase("CSP")
        changes = [RuleChange(ChangeType.REMOVE, f"field{i}", synthetic) for i in range(4)]
        psp = PageShieldPolicyPlan(
            description="CSP",
            policy_id="pol-1",
            changes=changes,
        )
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert violations[0].count == 4
        assert "page_shield:CSP" in violations[0].phases

    def test_page_shield_modify_changes_counted(self):
        """MODIFY changes in page shield policies should count toward updates."""
        synthetic = self._make_page_shield_phase("CSP")
        changes = [RuleChange(ChangeType.MODIFY, f"field{i}", synthetic) for i in range(4)]
        psp = PageShieldPolicyPlan(
            description="CSP",
            policy_id="pol-1",
            changes=changes,
        )
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "update"
        assert violations[0].count == 4
        assert "page_shield:CSP" in violations[0].phases

    def test_page_shield_add_no_violation(self):
        """ADD changes in page shield policies should not trigger safety violations."""
        synthetic = self._make_page_shield_phase("CSP")
        changes = [RuleChange(ChangeType.ADD, f"field{i}", synthetic) for i in range(5)]
        psp = PageShieldPolicyPlan(
            description="CSP",
            policy_id="pol-1",
            changes=changes,
        )
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(5)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert violations == []

    def test_page_shield_and_phase_changes_combined(self):
        """Page shield and phase changes should be summed together for safety checks."""
        synthetic = self._make_page_shield_phase("CSP")
        phase_changes = [RuleChange(ChangeType.REMOVE, f"r{i}", REDIRECT_PHASE) for i in range(2)]
        pp = PhasePlan(phase=REDIRECT_PHASE, changes=phase_changes)
        psp_changes = [RuleChange(ChangeType.REMOVE, f"field{i}", synthetic) for i in range(2)]
        psp = PageShieldPolicyPlan(description="CSP", policy_id="pol-1", changes=psp_changes)
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp], page_shield_policy_plans=[psp])
        # 4 deletes out of 10 existing = 40%
        current = {"http_request_dynamic_redirect": [{"ref": f"r{i}"} for i in range(10)]}
        violations = check_safety(zp, current, self._zone_cfg())
        assert len(violations) == 1
        assert violations[0].kind == "delete"
        assert violations[0].count == 4
