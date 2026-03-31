"""Tests for the processor pipeline."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from octorules.config import ConfigError
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    CustomRulesetPlan,
    ListPlan,
    PageShieldPolicyPlan,
    PhasePlan,
    RuleChange,
    ZonePlan,
)
from octorules.processor import BaseProcessor, ChangeTypeFilter, PhaseFilter, RefFilter

REDIRECT_PHASE = get_phase("redirect_rules")


class TestBaseProcessor:
    def test_process_desired_default_noop(self):
        proc = BaseProcessor()
        desired = {"redirect_rules": [{"ref": "r1", "expression": "true"}]}
        result = proc.process_desired("example.com", desired, MagicMock())
        assert result is desired

    def test_process_changes_default_noop(self):
        proc = BaseProcessor()
        zp = ZonePlan(zone_name="example.com")
        result = proc.process_changes("example.com", zp, MagicMock())
        assert result is zp


class TestProcessorChain:
    def test_two_processors_run_in_order(self):
        """Processors run in declared order; output of first feeds into second."""
        order = []

        class ProcA(BaseProcessor):
            def process_desired(self, zone_name, desired, provider):
                order.append("A")
                desired = dict(desired)
                desired["from_a"] = True
                return desired

        class ProcB(BaseProcessor):
            def process_desired(self, zone_name, desired, provider):
                order.append("B")
                assert desired.get("from_a") is True  # A ran first
                desired = dict(desired)
                desired["from_b"] = True
                return desired

        procs = [ProcA(), ProcB()]
        desired = {"redirect_rules": []}
        for proc in procs:
            desired = proc.process_desired("example.com", desired, MagicMock())

        assert order == ["A", "B"]
        assert desired["from_a"] is True
        assert desired["from_b"] is True


class TestProcessDesired:
    def test_processor_adds_rule(self):
        """Processor that adds a rule to desired."""

        class AddRuleProcessor(BaseProcessor):
            def process_desired(self, zone_name, desired, provider):
                desired = dict(desired)
                rules = list(desired.get("redirect_rules", []))
                rules.append({"ref": "injected", "expression": "true", "action": "redirect"})
                desired["redirect_rules"] = rules
                return desired

        proc = AddRuleProcessor()
        desired = {"redirect_rules": [{"ref": "r1", "expression": "true", "action": "redirect"}]}
        result = proc.process_desired("example.com", desired, MagicMock())
        assert len(result["redirect_rules"]) == 2
        assert result["redirect_rules"][1]["ref"] == "injected"


class TestProcessChanges:
    def test_processor_removes_change(self):
        """Processor that filters out changes."""

        class FilterProcessor(BaseProcessor):
            def process_changes(self, zone_name, plan, provider):
                for pp in plan.phase_plans:
                    pp.changes = [c for c in pp.changes if c.ref != "skip-me"]
                return plan

        change_keep = RuleChange(change_type=ChangeType.ADD, ref="keep", phase=REDIRECT_PHASE)
        change_skip = RuleChange(change_type=ChangeType.ADD, ref="skip-me", phase=REDIRECT_PHASE)
        zp = ZonePlan(
            zone_name="example.com",
            phase_plans=[PhasePlan(phase=REDIRECT_PHASE, changes=[change_keep, change_skip])],
        )

        proc = FilterProcessor()
        result = proc.process_changes("example.com", zp, MagicMock())
        assert len(result.phase_plans[0].changes) == 1
        assert result.phase_plans[0].changes[0].ref == "keep"


class TestNoProcessors:
    def test_empty_processor_list_is_noop(self):
        """Zone with no processors: desired and plan pass through unchanged."""
        desired = {"redirect_rules": [{"ref": "r1", "expression": "true"}]}
        # No processors to apply
        result = desired
        assert result is desired


# --- PhaseFilter tests ---


class TestPhaseFilter:
    def test_include_keeps_only_listed_phases(self):
        pf = PhaseFilter(include=["redirect_rules", "cache_rules"])
        desired = {
            "redirect_rules": [{"ref": "r1"}],
            "cache_rules": [{"ref": "c1"}],
            "waf_custom_rules": [{"ref": "w1"}],
        }
        result = pf.process_desired("example.com", desired, MagicMock())
        assert set(result.keys()) == {"redirect_rules", "cache_rules"}

    def test_exclude_removes_listed_phases(self):
        pf = PhaseFilter(exclude=["waf_custom_rules"])
        desired = {
            "redirect_rules": [{"ref": "r1"}],
            "cache_rules": [{"ref": "c1"}],
            "waf_custom_rules": [{"ref": "w1"}],
        }
        result = pf.process_desired("example.com", desired, MagicMock())
        assert set(result.keys()) == {"redirect_rules", "cache_rules"}

    def test_include_empty_result(self):
        pf = PhaseFilter(include=["nonexistent_phase"])
        desired = {"redirect_rules": [{"ref": "r1"}]}
        result = pf.process_desired("example.com", desired, MagicMock())
        assert result == {}

    def test_exclude_keeps_all_when_no_match(self):
        pf = PhaseFilter(exclude=["nonexistent_phase"])
        desired = {"redirect_rules": [{"ref": "r1"}]}
        result = pf.process_desired("example.com", desired, MagicMock())
        assert set(result.keys()) == {"redirect_rules"}

    def test_both_include_and_exclude_raises(self):
        with pytest.raises(ConfigError, match="mutually exclusive"):
            PhaseFilter(include=["a"], exclude=["b"])

    def test_neither_include_nor_exclude_raises(self):
        with pytest.raises(ConfigError, match="one of"):
            PhaseFilter()


# --- RefFilter tests ---


class TestRefFilter:
    def test_include_keeps_matching_refs(self):
        rf = RefFilter(include=r"^prod-")
        desired = {
            "redirect_rules": [
                {"ref": "prod-redirect", "expression": "true"},
                {"ref": "test-redirect", "expression": "true"},
                {"ref": "prod-cache", "expression": "true"},
            ]
        }
        result = rf.process_desired("example.com", desired, MagicMock())
        refs = [r["ref"] for r in result["redirect_rules"]]
        assert refs == ["prod-redirect", "prod-cache"]

    def test_exclude_removes_matching_refs(self):
        rf = RefFilter(exclude=r"^test-")
        desired = {
            "redirect_rules": [
                {"ref": "prod-redirect", "expression": "true"},
                {"ref": "test-redirect", "expression": "true"},
            ]
        }
        result = rf.process_desired("example.com", desired, MagicMock())
        refs = [r["ref"] for r in result["redirect_rules"]]
        assert refs == ["prod-redirect"]

    def test_rules_without_ref_excluded_by_include(self):
        """Rules missing 'ref' have empty string — include pattern won't match."""
        rf = RefFilter(include=r"^prod-")
        desired = {"redirect_rules": [{"expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert result["redirect_rules"] == []

    def test_rules_without_ref_kept_by_exclude(self):
        """Rules missing 'ref' have empty string — exclude pattern won't match."""
        rf = RefFilter(exclude=r"^test-")
        desired = {"redirect_rules": [{"expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert len(result["redirect_rules"]) == 1

    def test_non_list_values_passed_through(self):
        """Non-list phase values (e.g. custom_rulesets dict) pass through."""
        rf = RefFilter(include=r"prod")
        desired = {
            "redirect_rules": [{"ref": "prod-r1"}],
            "custom_rulesets": {"id": "abc"},
        }
        result = rf.process_desired("example.com", desired, MagicMock())
        assert result["custom_rulesets"] == {"id": "abc"}

    def test_both_include_and_exclude_raises(self):
        with pytest.raises(ConfigError, match="mutually exclusive"):
            RefFilter(include="a", exclude="b")

    def test_neither_include_nor_exclude_raises(self):
        with pytest.raises(ConfigError, match="one of"):
            RefFilter()

    def test_none_ref_handled_by_include(self):
        """Rules with ref=None are treated as empty string, not crash."""
        rf = RefFilter(include=r"^prod-")
        desired = {"redirect_rules": [{"ref": None, "expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert result["redirect_rules"] == []

    def test_none_ref_handled_by_exclude(self):
        """Rules with ref=None are treated as empty string, not crash."""
        rf = RefFilter(exclude=r"^test-")
        desired = {"redirect_rules": [{"ref": None, "expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert len(result["redirect_rules"]) == 1

    def test_invalid_regex_raises_config_error(self):
        """Invalid regex patterns raise ConfigError, not re.error."""
        with pytest.raises(ConfigError, match="invalid regex pattern"):
            RefFilter(include="[invalid(regex")


# --- ChangeTypeFilter tests ---


class TestChangeTypeFilter:
    def _make_plan(self):
        """Build a ZonePlan with changes across all plan types."""
        add = RuleChange(change_type=ChangeType.ADD, ref="new", phase=REDIRECT_PHASE)
        remove = RuleChange(change_type=ChangeType.REMOVE, ref="old", phase=REDIRECT_PHASE)
        modify = RuleChange(change_type=ChangeType.MODIFY, ref="changed", phase=REDIRECT_PHASE)
        return ZonePlan(
            zone_name="example.com",
            phase_plans=[PhasePlan(phase=REDIRECT_PHASE, changes=[add, remove, modify])],
            custom_ruleset_plans=[
                CustomRulesetPlan(
                    ruleset_id="abc",
                    ruleset_name="test",
                    phase="http_request_firewall_custom",
                    changes=[
                        RuleChange(
                            change_type=ChangeType.REMOVE, ref="cr-old", phase=REDIRECT_PHASE
                        )
                    ],
                )
            ],
            list_plans=[
                ListPlan(
                    list_name="blocklist",
                    list_id="lid",
                    changes=[
                        RuleChange(
                            change_type=ChangeType.REMOVE, ref="1.2.3.4", phase=REDIRECT_PHASE
                        )
                    ],
                )
            ],
            page_shield_policy_plans=[
                PageShieldPolicyPlan(
                    description="csp",
                    changes=[
                        RuleChange(
                            change_type=ChangeType.REMOVE, ref="action", phase=REDIRECT_PHASE
                        )
                    ],
                )
            ],
        )

    def test_exclude_remove(self):
        ctf = ChangeTypeFilter(exclude=["REMOVE"])
        plan = self._make_plan()
        result = ctf.process_changes("example.com", plan, MagicMock())
        # Phase plans: ADD and MODIFY kept, REMOVE removed
        phase_types = {c.change_type for c in result.phase_plans[0].changes}
        assert phase_types == {ChangeType.ADD, ChangeType.MODIFY}
        # All REMOVE changes filtered from other plan types
        assert result.custom_ruleset_plans[0].changes == []
        assert result.list_plans[0].changes == []
        assert result.page_shield_policy_plans[0].changes == []

    def test_exclude_multiple_types(self):
        ctf = ChangeTypeFilter(exclude=["REMOVE", "ADD"])
        plan = self._make_plan()
        result = ctf.process_changes("example.com", plan, MagicMock())
        phase_types = {c.change_type for c in result.phase_plans[0].changes}
        assert phase_types == {ChangeType.MODIFY}

    def test_exclude_case_insensitive(self):
        ctf = ChangeTypeFilter(exclude=["remove"])
        plan = self._make_plan()
        result = ctf.process_changes("example.com", plan, MagicMock())
        phase_refs = [c.ref for c in result.phase_plans[0].changes]
        assert "old" not in phase_refs

    def test_empty_exclude_raises(self):
        with pytest.raises(ConfigError, match="non-empty"):
            ChangeTypeFilter(exclude=[])

    def test_exclude_filters_non_page_shield_extensions(self):
        """ChangeTypeFilter should filter changes in all extension_plans, not just page_shield."""
        ctf = ChangeTypeFilter(exclude=["REMOVE"])
        # Build a plan with a custom extension (not page_shield)
        ext_plan = PageShieldPolicyPlan(
            description="custom_ext",
            changes=[
                RuleChange(change_type=ChangeType.REMOVE, ref="ext-rm", phase=REDIRECT_PHASE),
                RuleChange(change_type=ChangeType.ADD, ref="ext-add", phase=REDIRECT_PHASE),
            ],
        )
        plan = ZonePlan(
            zone_name="example.com",
            extension_plans={"my_custom_ext": [ext_plan]},
        )
        result = ctf.process_changes("example.com", plan, MagicMock())
        # REMOVE should be filtered, ADD kept
        assert len(result.extension_plans["my_custom_ext"][0].changes) == 1
        assert result.extension_plans["my_custom_ext"][0].changes[0].change_type == ChangeType.ADD

    def test_exclude_filters_multiple_extensions(self):
        """ChangeTypeFilter should filter changes across multiple extension types."""
        ctf = ChangeTypeFilter(exclude=["ADD"])
        ext_a = PageShieldPolicyPlan(
            description="ext_a",
            changes=[
                RuleChange(change_type=ChangeType.ADD, ref="a1", phase=REDIRECT_PHASE),
                RuleChange(change_type=ChangeType.MODIFY, ref="a2", phase=REDIRECT_PHASE),
            ],
        )
        ext_b = PageShieldPolicyPlan(
            description="ext_b",
            changes=[
                RuleChange(change_type=ChangeType.ADD, ref="b1", phase=REDIRECT_PHASE),
                RuleChange(change_type=ChangeType.REMOVE, ref="b2", phase=REDIRECT_PHASE),
            ],
        )
        plan = ZonePlan(
            zone_name="example.com",
            extension_plans={"page_shield": [ext_a], "other_ext": [ext_b]},
        )
        result = ctf.process_changes("example.com", plan, MagicMock())
        # page_shield: only MODIFY kept
        assert len(result.extension_plans["page_shield"][0].changes) == 1
        assert result.extension_plans["page_shield"][0].changes[0].ref == "a2"
        # other_ext: only REMOVE kept
        assert len(result.extension_plans["other_ext"][0].changes) == 1
        assert result.extension_plans["other_ext"][0].changes[0].ref == "b2"

    def test_invalid_change_type_raises(self):
        with pytest.raises(ConfigError, match="unknown change type"):
            ChangeTypeFilter(exclude=["BOGUS"])
