"""Tests for the processor pipeline."""

from dataclasses import dataclass, field
from unittest.mock import MagicMock

import pytest

from octorules.config import ConfigError
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    CustomRulesetPlan,
    ListPlan,
    PhasePlan,
    RuleChange,
    ZonePlan,
)
from octorules.processor import (
    BaseProcessor,
    ChangeTypeFilter,
    PhaseFilter,
    PreserveFilter,
    RefFilter,
)


@dataclass
class _ExtPlan:
    """Minimal extension plan for testing — avoids importing provider packages."""

    description: str = ""
    changes: list = field(default_factory=list)


REDIRECT_PHASE = get_phase("fakeprov.redirect_rules")


class TestBaseProcessorProtocol:
    def test_protocol_is_runtime_checkable(self):
        """A class implementing both methods satisfies the protocol."""

        class FullProc:
            def process_desired(self, zone_name, desired, provider):
                return desired

            def process_changes(self, zone_name, plan, provider):
                return plan

        assert isinstance(FullProc(), BaseProcessor)

    def test_partial_impl_uses_getattr(self):
        """Processors need only implement the methods they use."""
        pf = PhaseFilter(include=["fakeprov.redirect_rules"])
        # PhaseFilter only has process_desired — getattr pattern handles missing methods
        assert hasattr(pf, "process_desired")
        assert not hasattr(pf, "process_changes")


class TestProcessorChain:
    def test_two_processors_run_in_order(self):
        """Processors run in declared order; output of first feeds into second."""
        order = []

        class ProcA:
            def process_desired(self, zone_name, desired, provider):
                order.append("A")
                desired = dict(desired)
                desired["from_a"] = True
                return desired

        class ProcB:
            def process_desired(self, zone_name, desired, provider):
                order.append("B")
                assert desired.get("from_a") is True  # A ran first
                desired = dict(desired)
                desired["from_b"] = True
                return desired

        procs = [ProcA(), ProcB()]
        desired = {"fakeprov.redirect_rules": []}
        for proc in procs:
            desired = proc.process_desired("example.com", desired, MagicMock())

        assert order == ["A", "B"]
        assert desired["from_a"] is True
        assert desired["from_b"] is True


class TestProcessDesired:
    def test_processor_adds_rule(self):
        """Processor that adds a rule to desired."""

        class AddRuleProcessor:
            def process_desired(self, zone_name, desired, provider):
                desired = dict(desired)
                rules = list(desired.get("fakeprov.redirect_rules", []))
                rules.append({"ref": "injected", "expression": "true", "action": "redirect"})
                desired["fakeprov.redirect_rules"] = rules
                return desired

        proc = AddRuleProcessor()
        desired = {
            "fakeprov.redirect_rules": [{"ref": "r1", "expression": "true", "action": "redirect"}]
        }
        result = proc.process_desired("example.com", desired, MagicMock())
        assert len(result["fakeprov.redirect_rules"]) == 2
        assert result["fakeprov.redirect_rules"][1]["ref"] == "injected"


class TestProcessChanges:
    def test_processor_removes_change(self):
        """Processor that filters out changes."""

        class FilterProcessor:
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
        desired = {"fakeprov.redirect_rules": [{"ref": "r1", "expression": "true"}]}
        # No processors to apply
        result = desired
        assert result is desired


# --- PhaseFilter tests ---
class TestPhaseFilter:
    def test_include_keeps_only_listed_phases(self):
        pf = PhaseFilter(include=["fakeprov.redirect_rules", "fakeprov.cache_rules"])
        desired = {
            "fakeprov.redirect_rules": [{"ref": "r1"}],
            "fakeprov.cache_rules": [{"ref": "c1"}],
            "fakeprov.waf_custom_rules": [{"ref": "w1"}],
        }
        result = pf.process_desired("example.com", desired, MagicMock())
        assert set(result.keys()) == {"fakeprov.redirect_rules", "fakeprov.cache_rules"}

    def test_exclude_removes_listed_phases(self):
        pf = PhaseFilter(exclude=["fakeprov.waf_custom_rules"])
        desired = {
            "fakeprov.redirect_rules": [{"ref": "r1"}],
            "fakeprov.cache_rules": [{"ref": "c1"}],
            "fakeprov.waf_custom_rules": [{"ref": "w1"}],
        }
        result = pf.process_desired("example.com", desired, MagicMock())
        assert set(result.keys()) == {"fakeprov.redirect_rules", "fakeprov.cache_rules"}

    def test_include_empty_result(self):
        """Including a real phase the zone does not use yields nothing."""
        pf = PhaseFilter(include=["fakeprov.cache_rules"])
        desired = {"fakeprov.redirect_rules": [{"ref": "r1"}]}
        result = pf.process_desired("example.com", desired, MagicMock())
        assert result == {}

    def test_exclude_keeps_all_when_no_match(self):
        """Excluding a real phase the zone does not use keeps everything."""
        pf = PhaseFilter(exclude=["fakeprov.cache_rules"])
        desired = {"fakeprov.redirect_rules": [{"ref": "r1"}]}
        result = pf.process_desired("example.com", desired, MagicMock())
        assert set(result.keys()) == {"fakeprov.redirect_rules"}

    def test_unknown_phase_raises(self):
        """A typo must not silently change the plan's scope.

        Passing through unknown names meant a mistyped `include` quietly
        dropped that phase from the plan, and a mistyped `exclude` quietly
        planned everything.
        """
        with pytest.raises(ConfigError, match="Unknown phase 'nonexistent_phase'"):
            PhaseFilter(include=["nonexistent_phase"])
        with pytest.raises(ConfigError, match="Unknown phase 'nonexistent_phase'"):
            PhaseFilter(exclude=["nonexistent_phase"])

    def test_unknown_phase_suggests_a_near_miss(self):
        with pytest.raises(ConfigError, match="Did you mean 'fakeprov.redirect_rules'"):
            PhaseFilter(include=["redirect_rulez"])

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
            "fakeprov.redirect_rules": [
                {"ref": "prod-redirect", "expression": "true"},
                {"ref": "test-redirect", "expression": "true"},
                {"ref": "prod-cache", "expression": "true"},
            ]
        }
        result = rf.process_desired("example.com", desired, MagicMock())
        refs = [r["ref"] for r in result["fakeprov.redirect_rules"]]
        assert refs == ["prod-redirect", "prod-cache"]

    def test_exclude_removes_matching_refs(self):
        rf = RefFilter(exclude=r"^test-")
        desired = {
            "fakeprov.redirect_rules": [
                {"ref": "prod-redirect", "expression": "true"},
                {"ref": "test-redirect", "expression": "true"},
            ]
        }
        result = rf.process_desired("example.com", desired, MagicMock())
        refs = [r["ref"] for r in result["fakeprov.redirect_rules"]]
        assert refs == ["prod-redirect"]

    def test_rules_without_ref_excluded_by_include(self):
        """Rules missing 'ref' have empty string — include pattern won't match."""
        rf = RefFilter(include=r"^prod-")
        desired = {"fakeprov.redirect_rules": [{"expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert result["fakeprov.redirect_rules"] == []

    def test_rules_without_ref_kept_by_exclude(self):
        """Rules missing 'ref' have empty string — exclude pattern won't match."""
        rf = RefFilter(exclude=r"^test-")
        desired = {"fakeprov.redirect_rules": [{"expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert len(result["fakeprov.redirect_rules"]) == 1

    def test_non_list_values_passed_through(self):
        """Non-list phase values (e.g. custom_rulesets dict) pass through."""
        rf = RefFilter(include=r"prod")
        desired = {
            "fakeprov.redirect_rules": [{"ref": "prod-r1"}],
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
        desired = {"fakeprov.redirect_rules": [{"ref": None, "expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert result["fakeprov.redirect_rules"] == []

    def test_none_ref_handled_by_exclude(self):
        """Rules with ref=None are treated as empty string, not crash."""
        rf = RefFilter(exclude=r"^test-")
        desired = {"fakeprov.redirect_rules": [{"ref": None, "expression": "true"}]}
        result = rf.process_desired("example.com", desired, MagicMock())
        assert len(result["fakeprov.redirect_rules"]) == 1

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
                    phase="fake_http_request_firewall_custom",
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
            extension_plans={
                "page_shield": [
                    _ExtPlan(
                        description="csp",
                        changes=[
                            RuleChange(
                                change_type=ChangeType.REMOVE,
                                ref="action",
                                phase=REDIRECT_PHASE,
                            )
                        ],
                    )
                ]
            },
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
        assert result.extension_plans["page_shield"][0].changes == []

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
        ext_plan = _ExtPlan(
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

    def test_untyped_extension_changes_are_kept(self):
        """Settings-extension changes carry field/current/desired with no
        change_type; the filter must keep them rather than crash with
        AttributeError, while still filtering typed changes alongside."""

        @dataclass
        class _SettingsChange:
            field: str
            current: object
            desired: object

        ctf = ChangeTypeFilter(exclude=["REMOVE"])
        ext_plan = _ExtPlan(
            description="bot_management",
            changes=[
                _SettingsChange(field="enable_js", current=False, desired=True),
                RuleChange(change_type=ChangeType.REMOVE, ref="typed-rm", phase=REDIRECT_PHASE),
            ],
        )
        plan = ZonePlan(
            zone_name="example.com",
            extension_plans={"fakeprov.bot_management": [ext_plan]},
        )
        result = ctf.process_changes("example.com", plan, MagicMock())
        remaining = result.extension_plans["fakeprov.bot_management"][0].changes
        assert len(remaining) == 1
        assert remaining[0].field == "enable_js"

    def test_exclude_filters_multiple_extensions(self):
        """ChangeTypeFilter should filter changes across multiple extension types."""
        ctf = ChangeTypeFilter(exclude=["ADD"])
        ext_a = _ExtPlan(
            description="ext_a",
            changes=[
                RuleChange(change_type=ChangeType.ADD, ref="a1", phase=REDIRECT_PHASE),
                RuleChange(change_type=ChangeType.MODIFY, ref="a2", phase=REDIRECT_PHASE),
            ],
        )
        ext_b = _ExtPlan(
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


# --- PreserveFilter tests ---
class TestPreserveFilter:
    def _make_plan(self, change_type=ChangeType.REMOVE):
        """ZonePlan with one *change_type* change (ref 'vendor-*') in every bucket."""

        def rc(ref):
            return RuleChange(change_type=change_type, ref=ref, phase=REDIRECT_PHASE)

        return ZonePlan(
            zone_name="example.com",
            phase_plans=[PhasePlan(phase=REDIRECT_PHASE, changes=[rc("vendor-x")])],
            custom_ruleset_plans=[
                CustomRulesetPlan(
                    ruleset_id="abc",
                    ruleset_name="test",
                    phase="fake_http_request_firewall_custom",
                    changes=[rc("vendor-cr")],
                )
            ],
            list_plans=[ListPlan(list_name="blocklist", list_id="lid", changes=[rc("vendor-li")])],
            extension_plans={
                "page_shield": [_ExtPlan(description="csp", changes=[rc("vendor-ext")])]
            },
        )

    def _phase_plan(self, *changes):
        return ZonePlan(
            zone_name="example.com",
            phase_plans=[PhasePlan(phase=REDIRECT_PHASE, changes=list(changes))],
        )

    def test_drops_matching_remove_keeps_others(self):
        pf = PreserveFilter(refs=r"^vendor-")
        zp = self._phase_plan(
            RuleChange(change_type=ChangeType.REMOVE, ref="vendor-x", phase=REDIRECT_PHASE),
            RuleChange(change_type=ChangeType.REMOVE, ref="mine-y", phase=REDIRECT_PHASE),
        )
        result = pf.process_changes("example.com", zp, MagicMock())
        assert [c.ref for c in result.phase_plans[0].changes] == ["mine-y"]

    def test_keeps_unlisted_change_type_for_matching_ref(self):
        """ADD is not in the default change_types, so a matching-ref ADD survives."""
        pf = PreserveFilter(refs=r"^vendor-")
        zp = self._phase_plan(
            RuleChange(change_type=ChangeType.ADD, ref="vendor-x", phase=REDIRECT_PHASE),
            RuleChange(change_type=ChangeType.REMOVE, ref="vendor-x", phase=REDIRECT_PHASE),
        )
        result = pf.process_changes("example.com", zp, MagicMock())
        assert [c.change_type for c in result.phase_plans[0].changes] == [ChangeType.ADD]

    def test_default_covers_remove_and_reorder(self):
        pf = PreserveFilter(refs=r"^vendor-")
        zp = self._phase_plan(
            RuleChange(change_type=ChangeType.REMOVE, ref="vendor-a", phase=REDIRECT_PHASE),
            RuleChange(change_type=ChangeType.REORDER, ref="vendor-b", phase=REDIRECT_PHASE),
            RuleChange(change_type=ChangeType.MODIFY, ref="vendor-c", phase=REDIRECT_PHASE),
        )
        result = pf.process_changes("example.com", zp, MagicMock())
        # REMOVE + REORDER preserved (dropped from plan); MODIFY is not a
        # preservation type, so it stays.
        assert [c.change_type for c in result.phase_plans[0].changes] == [ChangeType.MODIFY]

    def test_custom_change_types_only_remove(self):
        pf = PreserveFilter(refs=r"^vendor-", change_types=["REMOVE"])
        zp = self._phase_plan(
            RuleChange(change_type=ChangeType.REMOVE, ref="vendor-a", phase=REDIRECT_PHASE),
            RuleChange(change_type=ChangeType.REORDER, ref="vendor-b", phase=REDIRECT_PHASE),
        )
        result = pf.process_changes("example.com", zp, MagicMock())
        # Only REMOVE preserved; REORDER stays in the plan.
        assert [c.change_type for c in result.phase_plans[0].changes] == [ChangeType.REORDER]

    def test_applies_across_all_buckets(self):
        pf = PreserveFilter(refs=r"^vendor-", change_types=["REMOVE"])
        result = pf.process_changes("example.com", self._make_plan(), MagicMock())
        assert result.phase_plans[0].changes == []
        assert result.custom_ruleset_plans[0].changes == []
        assert result.list_plans[0].changes == []
        assert result.extension_plans["page_shield"][0].changes == []

    def test_non_matching_ref_kept_across_buckets(self):
        pf = PreserveFilter(refs=r"^nomatch-", change_types=["REMOVE"])
        result = pf.process_changes("example.com", self._make_plan(), MagicMock())
        assert len(result.phase_plans[0].changes) == 1
        assert len(result.custom_ruleset_plans[0].changes) == 1
        assert len(result.list_plans[0].changes) == 1
        assert len(result.extension_plans["page_shield"][0].changes) == 1

    def test_untyped_extension_change_kept(self):
        """Settings-extension changes (no change_type/ref) are kept, no crash —
        even with a catch-all ref pattern, since they have no change_type."""

        @dataclass
        class _SettingsChange:
            field: str
            current: object
            desired: object

        pf = PreserveFilter(refs=r".*")
        ext_plan = _ExtPlan(
            description="bot_management",
            changes=[
                _SettingsChange(field="enable_js", current=False, desired=True),
                RuleChange(change_type=ChangeType.REMOVE, ref="vendor-x", phase=REDIRECT_PHASE),
            ],
        )
        plan = ZonePlan(
            zone_name="example.com",
            extension_plans={"fakeprov.bot_management": [ext_plan]},
        )
        result = pf.process_changes("example.com", plan, MagicMock())
        remaining = result.extension_plans["fakeprov.bot_management"][0].changes
        assert len(remaining) == 1
        assert remaining[0].field == "enable_js"

    def test_none_ref_kept(self):
        """ref=None is treated as empty string — pattern won't match, change kept."""
        pf = PreserveFilter(refs=r"^vendor-")
        zp = self._phase_plan(
            RuleChange(change_type=ChangeType.REMOVE, ref=None, phase=REDIRECT_PHASE)
        )
        result = pf.process_changes("example.com", zp, MagicMock())
        assert len(result.phase_plans[0].changes) == 1

    def test_case_insensitive_change_types(self):
        pf = PreserveFilter(refs=r"^vendor-", change_types=["remove"])
        zp = self._phase_plan(
            RuleChange(change_type=ChangeType.REMOVE, ref="vendor-x", phase=REDIRECT_PHASE)
        )
        result = pf.process_changes("example.com", zp, MagicMock())
        assert result.phase_plans[0].changes == []

    def test_empty_refs_raises(self):
        with pytest.raises(ConfigError, match="'refs' is required"):
            PreserveFilter(refs="")

    def test_none_refs_raises(self):
        with pytest.raises(ConfigError, match="'refs' is required"):
            PreserveFilter(refs=None)

    def test_invalid_regex_raises(self):
        with pytest.raises(ConfigError, match="invalid regex pattern"):
            PreserveFilter(refs="[invalid(regex")

    def test_empty_change_types_raises(self):
        with pytest.raises(ConfigError, match="non-empty"):
            PreserveFilter(refs=r"^vendor-", change_types=[])

    def test_unknown_change_type_raises(self):
        with pytest.raises(ConfigError, match="unknown change type"):
            PreserveFilter(refs=r"^vendor-", change_types=["BOGUS"])


class TestPhaseFilterUnknownNames:
    """An unknown name used to pass through silently, so a typo in include:
    quietly dropped that phase from the plan."""

    def test_unknown_include_raises(self):
        from octorules.config import ConfigError

        with pytest.raises(ConfigError, match="Unknown phase"):
            PhaseFilter(include=["fakeprov.redirct_rules"])

    def test_unknown_exclude_raises(self):
        from octorules.config import ConfigError

        with pytest.raises(ConfigError, match="Unknown phase"):
            PhaseFilter(exclude=["nonsense.phase"])
