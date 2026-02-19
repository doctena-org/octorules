"""Tests for custom ruleset formatting."""

from __future__ import annotations

import io
import json

from octorules.formatter import (
    build_report_data,
    format_plan_html,
    format_plan_json,
    format_plan_markdown,
    format_zone_plan,
    print_plan,
)
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    CustomRulesetPlan,
    PhasePlan,
    RuleChange,
    ZonePlan,
)

REDIRECT_PHASE = get_phase("redirect_rules")


class TestCustomRulesetFormatting:
    """Tests for custom ruleset formatting across all output formats."""

    def _make_crp(self, changes=None):
        if changes is None:
            changes = [RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)]
        return CustomRulesetPlan(
            ruleset_id="1689aab98b8d4d6e",
            ruleset_name="Block attackers",
            phase="http_request_firewall_custom",
            changes=changes,
        )

    def test_text_format_includes_custom_rulesets(self):
        crp = self._make_crp()
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_zone_plan(zp, use_color=False)
        assert "custom_ruleset: Block attackers (1689aab9)" in output
        assert "add: r1" in output

    def test_text_format_zone_plan_total_changes(self):
        crp = self._make_crp()
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        assert "1 change(s)" in format_zone_plan(zp, use_color=False)

    def test_json_format_includes_custom_rulesets(self):
        crp = self._make_crp()
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = json.loads(format_plan_json([zp]))
        assert output["total_changes"] == 1
        zone = output["zones"][0]
        assert "custom_ruleset_plans" in zone
        assert zone["custom_ruleset_plans"][0]["ruleset_id"] == "1689aab98b8d4d6e"
        assert zone["custom_ruleset_plans"][0]["ruleset_name"] == "Block attackers"

    def test_json_format_no_custom_rulesets_key_when_empty(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp])
        output = json.loads(format_plan_json([zp]))
        assert "custom_ruleset_plans" not in output["zones"][0]

    def test_markdown_format_includes_custom_rulesets(self):
        crp = self._make_crp()
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_plan_markdown([zp])
        assert "custom_ruleset:Block attackers" in output
        assert "r1" in output

    def test_html_format_includes_custom_rulesets(self):
        crp = self._make_crp()
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_plan_html([zp])
        assert "custom_ruleset: Block attackers" in output
        assert "Create" in output

    def test_print_plan_text_with_custom_rulesets(self):
        crp = self._make_crp()
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        buf = io.StringIO()
        print_plan([zp], file=buf, fmt="text")
        output = buf.getvalue()
        assert "custom_ruleset: Block attackers" in output

    def test_report_includes_custom_rulesets(self):
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block",
            phase="http_request_firewall_custom",
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
            prepared_rules=[{"ref": "r1", "expression": "true", "action": "block"}],
        )
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        cr_phases = [p for p in zone["phases"] if p["phase"].startswith("custom_ruleset:")]
        assert len(cr_phases) == 1
        assert cr_phases[0]["status"] == "drifted"
        assert cr_phases[0]["adds"] == 1

    def test_text_format_modify_in_custom_ruleset(self):
        """MODIFY changes in custom rulesets should show field diffs."""
        change = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"ref": "r1", "action": "log", "expression": "true", "enabled": True},
            desired={"ref": "r1", "action": "block", "expression": "true", "enabled": True},
        )
        crp = self._make_crp(changes=[change])
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_zone_plan(zp, use_color=False)
        assert "custom_ruleset: Block attackers" in output
        assert "modify: r1" in output
        assert "action" in output

    def test_html_format_modify_in_custom_ruleset(self):
        """MODIFY changes in HTML should show ins/del tags."""
        change = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"ref": "r1", "action": "log", "expression": "true", "enabled": True},
            desired={"ref": "r1", "action": "block", "expression": "true", "enabled": True},
        )
        crp = self._make_crp(changes=[change])
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_plan_html([zp])
        assert "custom_ruleset: Block attackers" in output
        assert "<ins>" in output
        assert "<del>" in output
        assert "Update" in output

    def test_markdown_format_modify_in_custom_ruleset(self):
        """MODIFY changes in markdown should show strikethrough and bold."""
        change = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"ref": "r1", "action": "log", "expression": "true", "enabled": True},
            desired={"ref": "r1", "action": "block", "expression": "true", "enabled": True},
        )
        crp = self._make_crp(changes=[change])
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_plan_markdown([zp])
        assert "custom_ruleset:Block attackers" in output
        assert "~~" in output  # strikethrough for old value
        assert "**" in output  # bold for new value

    def test_html_format_reorder_in_custom_ruleset(self):
        """REORDER changes in HTML custom rulesets."""
        change = RuleChange(ChangeType.REORDER, "*", REDIRECT_PHASE)
        crp = self._make_crp(changes=[change])
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_plan_html([zp])
        assert "Reorder" in output
        assert "reorder rules" in output

    def test_html_format_remove_in_custom_ruleset(self):
        """REMOVE changes in HTML custom rulesets."""
        change = RuleChange(
            ChangeType.REMOVE,
            "r1",
            REDIRECT_PHASE,
            current={"ref": "r1", "action": "block", "expression": "true"},
        )
        crp = self._make_crp(changes=[change])
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = format_plan_html([zp])
        assert "Delete" in output
        assert "Summary: Deletes=1" in output

    def test_json_format_modify_in_custom_ruleset(self):
        """MODIFY changes in JSON should include current and desired."""
        change = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"ref": "r1", "action": "log", "expression": "true", "enabled": True},
            desired={"ref": "r1", "action": "block", "expression": "true", "enabled": True},
        )
        crp = self._make_crp(changes=[change])
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        output = json.loads(format_plan_json([zp]))
        cr = output["zones"][0]["custom_ruleset_plans"][0]
        assert cr["changes"][0]["type"] == "modify"
        assert "current" in cr["changes"][0]
        assert "desired" in cr["changes"][0]

    def test_report_in_sync_custom_ruleset(self):
        """Custom ruleset with no changes should show in_sync in report."""
        crp = CustomRulesetPlan(
            ruleset_id="rs1",
            ruleset_name="Block",
            phase="http_request_firewall_custom",
            changes=[],  # no changes
            prepared_rules=[{"ref": "r1", "expression": "true", "action": "block"}],
        )
        zp = ZonePlan(zone_name="test.com", custom_ruleset_plans=[crp])
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        cr_phases = [p for p in zone["phases"] if p["phase"].startswith("custom_ruleset:")]
        assert len(cr_phases) == 1
        assert cr_phases[0]["status"] == "in_sync"
