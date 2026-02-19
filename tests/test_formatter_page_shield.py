"""Tests for Page Shield policy plan formatting."""

from __future__ import annotations

import io
import json

from octorules.formatter import (
    build_report_data,
    format_page_shield_policy_plan,
    format_plan_html,
    format_plan_json,
    format_plan_markdown,
    format_zone_plan,
    print_plan,
)
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    PageShieldPolicyPlan,
    PhasePlan,
    RuleChange,
    ZonePlan,
)

REDIRECT_PHASE = get_phase("redirect_rules")


class TestPageShieldPolicyFormatting:
    """Tests for Page Shield policy plan formatting across all output formats."""

    def test_text_format_create_policy(self):
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_zone_plan(zp, use_color=False)
        assert "page_shield: CSP on all" in output
        assert "+ create policy" in output

    def test_text_format_delete_policy(self):
        psp = PageShieldPolicyPlan(description="Old CSP", policy_id="p1", delete=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_zone_plan(zp, use_color=False)
        assert "page_shield: Old CSP" in output
        assert "- delete policy" in output

    def test_text_format_modify_policy(self):
        change = RuleChange(
            ChangeType.MODIFY,
            "CSP on all",
            REDIRECT_PHASE,
            current={"action": "log", "expression": "true", "enabled": True, "value": "old"},
            desired={"action": "allow", "expression": "true", "enabled": True, "value": "old"},
        )
        psp = PageShieldPolicyPlan(description="CSP on all", policy_id="p1", changes=[change])
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_zone_plan(zp, use_color=False)
        assert "page_shield: CSP on all" in output
        assert "modify: CSP on all" in output
        assert "action" in output

    def test_text_format_total_changes(self):
        psp = PageShieldPolicyPlan(description="CSP", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        assert "1 change(s)" in format_zone_plan(zp, use_color=False)

    def test_format_page_shield_policy_plan_function(self):
        psp = PageShieldPolicyPlan(description="CSP", create=True)
        lines = format_page_shield_policy_plan(psp, use_color=False)
        assert any("page_shield: CSP" in line for line in lines)
        assert any("create policy" in line for line in lines)

    def test_json_format_includes_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = json.loads(format_plan_json([zp]))
        assert output["total_changes"] == 1
        zone = output["zones"][0]
        assert "page_shield_policy_plans" in zone
        assert zone["page_shield_policy_plans"][0]["description"] == "CSP on all"
        assert zone["page_shield_policy_plans"][0]["create"] is True

    def test_json_format_no_key_when_empty(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp])
        output = json.loads(format_plan_json([zp]))
        assert "page_shield_policy_plans" not in output["zones"][0]

    def test_json_format_modify_has_changes(self):
        change = RuleChange(
            ChangeType.MODIFY,
            "CSP",
            REDIRECT_PHASE,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        psp = PageShieldPolicyPlan(description="CSP", policy_id="p1", changes=[change])
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = json.loads(format_plan_json([zp]))
        psp_data = output["zones"][0]["page_shield_policy_plans"][0]
        assert psp_data["changes"][0]["type"] == "modify"
        assert "current" in psp_data["changes"][0]
        assert "desired" in psp_data["changes"][0]

    def test_markdown_format_create_policy(self):
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_plan_markdown([zp])
        assert "page_shield:CSP on all" in output
        assert "create policy" in output

    def test_markdown_format_delete_policy(self):
        psp = PageShieldPolicyPlan(description="Old CSP", policy_id="p1", delete=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_plan_markdown([zp])
        assert "page_shield:Old CSP" in output
        assert "delete policy" in output

    def test_markdown_format_modify_policy(self):
        change = RuleChange(
            ChangeType.MODIFY,
            "CSP",
            REDIRECT_PHASE,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        psp = PageShieldPolicyPlan(description="CSP", policy_id="p1", changes=[change])
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_plan_markdown([zp])
        assert "page_shield:CSP" in output
        assert "```diff" in output
        assert "- action: 'log'" in output
        assert "+ action: 'allow'" in output

    def test_html_format_create_policy(self):
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_plan_html([zp])
        assert "page_shield: CSP on all" in output
        assert "<table>" in output
        assert "Create" in output
        assert "create policy" in output

    def test_html_format_delete_policy(self):
        psp = PageShieldPolicyPlan(description="Old CSP", policy_id="p1", delete=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_plan_html([zp])
        assert "Delete" in output
        assert "delete policy" in output
        assert "Summary: Deletes=1" in output

    def test_html_format_modify_policy(self):
        change = RuleChange(
            ChangeType.MODIFY,
            "CSP",
            REDIRECT_PHASE,
            current={"action": "log"},
            desired={"action": "allow"},
        )
        psp = PageShieldPolicyPlan(description="CSP", policy_id="p1", changes=[change])
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        output = format_plan_html([zp])
        assert "Update" in output
        assert "&minus;&ensp;" in output
        assert "+&ensp;" in output

    def test_report_includes_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP on all", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        psp_phases = [p for p in zone["phases"] if p["phase"].startswith("page_shield:")]
        assert len(psp_phases) == 1
        assert psp_phases[0]["phase"] == "page_shield:CSP on all"
        assert psp_phases[0]["status"] == "drifted"
        assert psp_phases[0]["adds"] == 1

    def test_report_in_sync_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP stable", policy_id="p1", changes=[])
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        psp_phases = [p for p in zone["phases"] if p["phase"].startswith("page_shield:")]
        assert len(psp_phases) == 1
        assert psp_phases[0]["status"] == "in_sync"

    def test_print_plan_text_with_page_shield(self):
        psp = PageShieldPolicyPlan(description="CSP", create=True)
        zp = ZonePlan(zone_name="test.com", page_shield_policy_plans=[psp])
        buf = io.StringIO()
        print_plan([zp], file=buf, fmt="text")
        output = buf.getvalue()
        assert "page_shield: CSP" in output
