"""Tests for list plan formatting."""

import json

from octorules.formatter import (
    build_report_data,
    format_plan_html,
    format_plan_json,
    format_plan_markdown,
    format_zone_plan,
)
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    ListPlan,
    PhasePlan,
    RuleChange,
    ZonePlan,
)

REDIRECT_PHASE = get_phase("redirect_rules")


class TestListFormatting:
    """Tests for list plan formatting across all output formats."""

    def test_text_format_includes_lists(self):
        lp = ListPlan(
            list_name="blocked_ips",
            list_id="list-123",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_zone_plan(zp, use_color=False)
        assert "list: blocked_ips (ip)" in output
        assert "add: 1.2.3.4" in output

    def test_text_format_create_list(self):
        lp = ListPlan(list_name="new_list", list_kind="ip", create=True)
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_zone_plan(zp, use_color=False)
        assert "+ create list" in output

    def test_text_format_delete_list(self):
        lp = ListPlan(list_name="old_list", list_id="list-456", list_kind="ip", delete=True)
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_zone_plan(zp, use_color=False)
        assert "- delete list" in output

    def test_text_format_description_change(self):
        lp = ListPlan(
            list_name="my_list",
            list_id="list-789",
            list_kind="ip",
            description_change=("old desc", "new desc"),
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_zone_plan(zp, use_color=False)
        assert "old desc" in output
        assert "new desc" in output
        # Old on − line, new on + line
        lines = output.splitlines()
        assert any("−" in ln and "old desc" in ln for ln in lines)
        assert any("+" in ln and "new desc" in ln for ln in lines)

    def test_json_format_includes_lists(self):
        lp = ListPlan(
            list_name="blocked_ips",
            list_id="list-123",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = json.loads(format_plan_json([zp]))
        assert output["total_changes"] == 1
        zone = output["zones"][0]
        assert "list_plans" in zone
        assert zone["list_plans"][0]["list_name"] == "blocked_ips"
        assert zone["list_plans"][0]["list_kind"] == "ip"

    def test_json_format_no_lists_key_when_empty(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", phase_plans=[pp])
        output = json.loads(format_plan_json([zp]))
        assert "list_plans" not in output["zones"][0]

    def test_markdown_format_includes_lists(self):
        lp = ListPlan(
            list_name="blocked_ips",
            list_id="list-123",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_plan_markdown([zp])
        assert "list:blocked_ips" in output
        assert "1.2.3.4" in output

    def test_markdown_format_modify_in_list(self):
        """MODIFY changes in markdown should use diff code blocks."""
        change = RuleChange(
            ChangeType.MODIFY,
            "1.2.3.4",
            REDIRECT_PHASE,
            current={"comment": "old note"},
            desired={"comment": "new note"},
        )
        lp = ListPlan(
            list_name="blocked_ips",
            list_id="list-123",
            list_kind="ip",
            changes=[change],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_plan_markdown([zp])
        assert "list:blocked_ips" in output
        assert "```diff" in output
        assert "- comment: 'old note'" in output
        assert "+ comment: 'new note'" in output

    def test_markdown_format_description_change(self):
        """Description changes in markdown should use diff code blocks."""
        lp = ListPlan(
            list_name="my_list",
            list_id="list-789",
            list_kind="ip",
            description_change=("old desc", "new desc"),
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_plan_markdown([zp])
        assert "| ~ |" in output
        assert "`description`" in output
        assert "```diff" in output
        assert "- description: 'old desc'" in output
        assert "+ description: 'new desc'" in output

    def test_html_format_includes_lists(self):
        lp = ListPlan(
            list_name="blocked_ips",
            list_id="list-123",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", REDIRECT_PHASE)],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        output = format_plan_html([zp])
        assert "list: blocked_ips (ip)" in output
        assert "<table>" in output
        assert "Create" in output

    def test_report_includes_lists(self):
        lp = ListPlan(
            list_name="blocked_ips",
            list_id="list-123",
            list_kind="ip",
            changes=[RuleChange(ChangeType.ADD, "1.2.3.4", REDIRECT_PHASE)],
            prepared_items=[{"ip": "1.2.3.4"}],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        list_phases = [p for p in zone["phases"] if p["phase"].startswith("list:")]
        assert len(list_phases) == 1
        assert list_phases[0]["phase"] == "list:blocked_ips"
        assert list_phases[0]["status"] == "drifted"
        assert list_phases[0]["adds"] == 1

    def test_report_in_sync_list(self):
        """List with no changes should show in_sync in report."""
        lp = ListPlan(
            list_name="stable_list",
            list_id="list-999",
            list_kind="ip",
            changes=[],  # no changes
            prepared_items=[{"ip": "1.1.1.1"}],
        )
        zp = ZonePlan(zone_name="test.com", list_plans=[lp])
        data = build_report_data([zp], {"test.com": {}}, {"test.com": {}})
        zone = data["zones"][0]
        list_phases = [p for p in zone["phases"] if p["phase"].startswith("list:")]
        assert len(list_phases) == 1
        assert list_phases[0]["status"] == "in_sync"
