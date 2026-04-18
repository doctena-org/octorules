"""Tests for the formatter."""

import io
import json
from unittest.mock import MagicMock

from octorules._color import _GREEN, _RESET, Pen, supports_color
from octorules.formatter import (
    _change_to_dict,
    _rule_detail_pairs,
    build_report_data,
    format_change,
    format_phase_plan,
    format_plan_html,
    format_plan_json,
    format_plan_markdown,
    format_report_csv,
    format_report_json,
    format_zone_plan,
    print_plan,
    print_report,
)
from octorules.phases import get_phase
from octorules.planner import (
    ChangeType,
    PhasePlan,
    RuleChange,
    ZonePlan,
)

REDIRECT_PHASE = get_phase("redirect_rules")
CACHE_PHASE = get_phase("cache_rules")


class TestColor:
    """Basic Pen and supports_color tests (comprehensive tests in test_color.py)."""

    def test_pen_color_enabled(self):
        p = Pen(use_color=True)
        result = p.success("hello")
        assert result == f"{_GREEN}hello{_RESET}"

    def test_pen_color_disabled(self):
        p = Pen(use_color=False)
        result = p.success("hello")
        assert result == "hello"

    def test_supports_color_returns_bool(self):
        assert isinstance(supports_color(), bool)


class TestFormatChange:
    def test_add(self):
        change = RuleChange(ChangeType.ADD, "my-rule", REDIRECT_PHASE)
        lines = format_change(change, use_color=False)
        assert any("+ add: my-rule" in line for line in lines)

    def test_remove(self):
        change = RuleChange(ChangeType.REMOVE, "old-rule", REDIRECT_PHASE)
        lines = format_change(change, use_color=False)
        assert any("- remove: old-rule" in line for line in lines)

    def test_modify_shows_details(self):
        change = RuleChange(
            ChangeType.MODIFY,
            "changed-rule",
            REDIRECT_PHASE,
            current={"expression": "old-expr", "action": "redirect", "enabled": True},
            desired={"expression": "new-expr", "action": "redirect", "enabled": True},
        )
        lines = format_change(change, use_color=False)
        assert any("~ modify: changed-rule" in line for line in lines)
        # Old value on − line, new value on + line
        assert any("−" in ln and "old-expr" in ln for ln in lines)
        assert any("+" in ln and "new-expr" in ln for ln in lines)

    def test_modify_no_details_without_current_desired(self):
        change = RuleChange(ChangeType.MODIFY, "changed-rule", REDIRECT_PHASE)
        lines = format_change(change, use_color=False)
        assert len(lines) == 1

    def test_reorder(self):
        change = RuleChange(ChangeType.REORDER, "*", REDIRECT_PHASE)
        lines = format_change(change, use_color=False)
        assert any("reorder" in line for line in lines)

    def test_add_with_details(self):
        change = RuleChange(
            ChangeType.ADD,
            "new-rule",
            REDIRECT_PHASE,
            desired={"expression": "true", "action": "redirect", "enabled": True},
        )
        lines = format_change(change, use_color=False)
        assert any("+ add: new-rule" in line for line in lines)
        assert any("action:" in line and "'redirect'" in line for line in lines)
        assert any("expression:" in line and "'true'" in line for line in lines)
        # enabled=True should be skipped
        assert not any("enabled:" in line for line in lines)

    def test_remove_with_details(self):
        change = RuleChange(
            ChangeType.REMOVE,
            "old-rule",
            REDIRECT_PHASE,
            current={"expression": "true", "action": "redirect", "enabled": False},
        )
        lines = format_change(change, use_color=False)
        assert any("- remove: old-rule" in line for line in lines)
        assert any("action:" in line for line in lines)
        # enabled=False IS shown (it's meaningful)
        assert any("enabled:" in line for line in lines)

    def test_add_with_color(self):
        change = RuleChange(ChangeType.ADD, "my-rule", REDIRECT_PHASE)
        lines = format_change(change, use_color=True)
        combined = "\n".join(lines)
        assert _GREEN in combined
        assert _RESET in combined
        assert "my-rule" in combined


class TestFormatPhasePlan:
    def test_single_change(self):
        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        lines = format_phase_plan(phase_plan, use_color=False)
        assert any("redirect_rules" in line for line in lines)
        assert any("add: r1" in line for line in lines)

    def test_multiple_changes(self):
        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE),
                RuleChange(ChangeType.REMOVE, "r2", REDIRECT_PHASE),
            ],
        )
        lines = format_phase_plan(phase_plan, use_color=False)
        # Header + 2 change lines
        assert len(lines) == 3

    def test_includes_provider_id(self):
        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        lines = format_phase_plan(phase_plan, use_color=False)
        assert any("http_request_dynamic_redirect" in line for line in lines)


class TestFormatCustomRulesetPlan:
    def test_create(self):
        from octorules.formatter import format_custom_ruleset_plan
        from octorules.planner import CustomRulesetPlan

        crp = CustomRulesetPlan(
            ruleset_id="rs-1",
            ruleset_name="BlockBots",
            phase="redirect_rules",
            create=True,
        )
        lines = format_custom_ruleset_plan(crp, use_color=False)
        combined = "\n".join(lines)
        assert "BlockBots" in combined
        assert "create rule group" in combined

    def test_delete(self):
        from octorules.formatter import format_custom_ruleset_plan
        from octorules.planner import CustomRulesetPlan

        crp = CustomRulesetPlan(
            ruleset_id="rs-1",
            ruleset_name="OldRules",
            phase="redirect_rules",
            delete=True,
        )
        lines = format_custom_ruleset_plan(crp, use_color=False)
        combined = "\n".join(lines)
        assert "OldRules" in combined
        assert "delete rule group" in combined

    def test_with_changes(self):
        from octorules.formatter import format_custom_ruleset_plan
        from octorules.planner import CustomRulesetPlan

        crp = CustomRulesetPlan(
            ruleset_id="rs-1",
            ruleset_name="MyRules",
            phase="redirect_rules",
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        lines = format_custom_ruleset_plan(crp, use_color=False)
        combined = "\n".join(lines)
        assert "MyRules" in combined
        assert "r1" in combined


class TestFormatListPlan:
    def test_create(self):
        from octorules.formatter import format_list_plan
        from octorules.planner import ListPlan

        lp = ListPlan(list_name="blocklist", list_kind="ip", create=True)
        lines = format_list_plan(lp, use_color=False)
        combined = "\n".join(lines)
        assert "blocklist" in combined
        assert "create list" in combined

    def test_delete(self):
        from octorules.formatter import format_list_plan
        from octorules.planner import ListPlan

        lp = ListPlan(list_name="old_list", list_kind="ip", delete=True)
        lines = format_list_plan(lp, use_color=False)
        combined = "\n".join(lines)
        assert "old_list" in combined
        assert "delete list" in combined

    def test_description_change(self):
        from octorules.formatter import format_list_plan
        from octorules.planner import ListPlan

        lp = ListPlan(
            list_name="mylist",
            list_kind="ip",
            description_change=("old desc", "new desc"),
        )
        lines = format_list_plan(lp, use_color=False)
        combined = "\n".join(lines)
        assert "description" in combined
        assert "old desc" in combined
        assert "new desc" in combined


class TestFormatZonePlan:
    def test_no_changes(self):
        zone_plan = ZonePlan("example.com")
        result = format_zone_plan(zone_plan, use_color=False)
        assert "no changes" in result
        assert "example.com" in result

    def test_with_changes(self):
        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "new-rule", REDIRECT_PHASE)],
        )
        zone_plan = ZonePlan("example.com", phase_plans=[phase_plan])
        result = format_zone_plan(zone_plan, use_color=False)
        assert "example.com" in result
        assert "1 change(s)" in result
        assert "redirect_rules" in result

    def test_multiple_phases(self):
        pp1 = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        pp2 = PhasePlan(
            phase=CACHE_PHASE,
            changes=[RuleChange(ChangeType.ADD, "c1", CACHE_PHASE)],
        )
        zone_plan = ZonePlan("example.com", phase_plans=[pp1, pp2])
        result = format_zone_plan(zone_plan, use_color=False)
        assert "2 change(s)" in result
        assert "redirect_rules" in result
        assert "cache_rules" in result


class TestPrintPlan:
    def test_no_changes(self):
        buf = io.StringIO()
        print_plan([ZonePlan("example.com")], file=buf)
        output = buf.getvalue()
        assert "No changes detected" in output

    def test_with_changes(self):
        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zone_plan = ZonePlan("example.com", phase_plans=[phase_plan])
        buf = io.StringIO()
        print_plan([zone_plan], file=buf)
        output = buf.getvalue()
        assert "Total: 1 change(s)" in output

    def test_multiple_zones_skips_unchanged(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp1 = ZonePlan("a.com", phase_plans=[pp])
        zp2 = ZonePlan("b.com")
        buf = io.StringIO()
        print_plan([zp1, zp2], file=buf)
        output = buf.getvalue()
        assert "a.com" in output
        assert "b.com" not in output
        assert "1 change(s) across 2 zone(s)" in output

    def test_multiple_zones_no_changes(self):
        zp1 = ZonePlan("a.com")
        zp2 = ZonePlan("b.com")
        buf = io.StringIO()
        print_plan([zp1, zp2], file=buf)
        output = buf.getvalue()
        assert "No changes detected" in output

    def test_print_plan_json_routing(self):
        zp = ZonePlan("example.com")
        buf = io.StringIO()
        print_plan([zp], file=buf, fmt="json")
        data = json.loads(buf.getvalue())
        assert "zones" in data

    def test_print_plan_markdown_routing(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        buf = io.StringIO()
        print_plan([zp], file=buf, fmt="markdown")
        output = buf.getvalue()
        assert "### Zone:" in output

    def test_print_plan_text_routing(self):
        zp = ZonePlan("example.com")
        buf = io.StringIO()
        print_plan([zp], file=buf, fmt="text")
        output = buf.getvalue()
        assert "No changes detected" in output


class TestFormatPlanJson:
    def test_empty_plan(self):
        result = format_plan_json([ZonePlan("example.com")])
        data = json.loads(result)
        assert data["total_changes"] == 0
        assert data["has_changes"] is False
        assert len(data["zones"]) == 0

    def test_with_changes(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.ADD,
                    "r1",
                    REDIRECT_PHASE,
                    desired={"expression": "true", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_json([zp])
        data = json.loads(result)
        assert data["total_changes"] == 1
        assert data["has_changes"] is True
        change = data["zones"][0]["phase_plans"][0]["changes"][0]
        assert change["type"] == "add"
        assert change["ref"] == "r1"
        assert "desired" in change

    def test_valid_json(self):
        zp = ZonePlan("example.com")
        result = format_plan_json([zp])
        data = json.loads(result)
        assert isinstance(data, dict)
        assert data["zones"] == []  # empty plan → empty zones array
        assert data["total_changes"] == 0
        assert data["has_changes"] is False

    def test_modify_has_current_and_desired(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.MODIFY,
                    "r1",
                    REDIRECT_PHASE,
                    current={"expression": "old", "action": "redirect"},
                    desired={"expression": "new", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        data = json.loads(format_plan_json([zp]))
        change = data["zones"][0]["phase_plans"][0]["changes"][0]
        assert "current" in change
        assert "desired" in change

    def test_add_has_desired_only(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.ADD,
                    "r1",
                    REDIRECT_PHASE,
                    desired={"expression": "true"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        data = json.loads(format_plan_json([zp]))
        change = data["zones"][0]["phase_plans"][0]["changes"][0]
        assert "desired" in change
        assert "current" not in change


class TestFormatPlanMarkdown:
    def test_empty_plan_skips_unchanged(self):
        result = format_plan_markdown([ZonePlan("example.com")])
        assert "example.com" not in result
        assert "**No changes detected.**" in result

    def test_with_changes(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_markdown([zp])
        assert "### Zone: `example.com`" in result
        assert "| Op | Phase | Ref | Details |" in result
        assert "| + | redirect_rules | r1 |" in result

    def test_modify_shows_diffs(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.MODIFY,
                    "r1",
                    REDIRECT_PHASE,
                    current={"expression": "old", "action": "redirect"},
                    desired={"expression": "new", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_markdown([zp])
        # Table cell shows only field name
        assert "| ~ | redirect_rules | r1 | `expression` |" in result
        # Diff block after the table
        assert "```diff" in result
        assert "- expression: 'old'" in result
        assert "+ expression: 'new'" in result

    def test_reorder_shows_message(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.REORDER, "*", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_markdown([zp])
        assert "reorder" in result

    def test_multiple_zones_skips_unchanged(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp1 = ZonePlan("a.com", phase_plans=[pp])
        zp2 = ZonePlan("b.com")
        result = format_plan_markdown([zp1, zp2])
        assert "### Zone: `a.com`" in result
        assert "b.com" not in result
        assert "1 change(s) across 2 zone(s)" in result

    def test_add_shows_details(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.ADD,
                    "r1",
                    REDIRECT_PHASE,
                    desired={"expression": "true", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_markdown([zp])
        assert "`action`: 'redirect'" in result
        assert "`expression`: 'true'" in result

    def test_remove_shows_details(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.REMOVE,
                    "r1",
                    REDIRECT_PHASE,
                    current={"expression": "true", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_markdown([zp])
        assert "`action`: 'redirect'" in result

    def test_summary_no_changes(self):
        result = format_plan_markdown([ZonePlan("example.com")])
        assert "**No changes detected.**" in result


class TestFormatPlanHtml:
    def test_empty_plan_no_changes(self):
        result = format_plan_html([ZonePlan("example.com")])
        assert "example.com" not in result
        assert "No changes were planned" in result

    def test_embeddable_fragment(self):
        """Output is an embeddable HTML fragment, not a full document."""
        result = format_plan_html([ZonePlan("example.com")])
        assert "<!DOCTYPE" not in result
        assert "<html>" not in result
        assert "<head>" not in result
        assert "<body>" not in result
        assert "<style>" not in result

    def test_create_uses_full_name(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "example.com" in result
        assert "redirect_rules" in result
        assert "r1" in result
        assert "Create" in result

    def test_delete_uses_full_name(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "Delete" in result

    def test_modify_shows_old_then_new_on_separate_rows(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.MODIFY,
                    "r1",
                    REDIRECT_PHASE,
                    current={"expression": "old-expr", "action": "redirect"},
                    desired={"expression": "new-expr", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "Update" in result
        # Old value with − prefix, new value with + prefix
        assert "&minus;&ensp;<code>expression</code>: old-expr" in result
        assert "+&ensp;<code>expression</code>: new-expr" in result
        # Old value (−) appears first, new value (+) on continuation row
        assert result.index("&minus;") < result.index("+&ensp;")

    def test_reorder_shows_message(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.REORDER, "*", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "Reorder" in result
        assert "reorder rules" in result

    def test_multiple_zones_skips_unchanged(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp1 = ZonePlan("a.com", phase_plans=[pp])
        zp2 = ZonePlan("b.com")
        result = format_plan_html([zp1, zp2])
        assert "a.com" in result
        assert "b.com" not in result

    def test_create_shows_rule_details_single_row(self):
        """Create uses a single <tr> with <br/>-joined details (matches octodns)."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.ADD,
                    "r1",
                    REDIRECT_PHASE,
                    desired={"expression": "true", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        # Field names wrapped in <code> tags
        assert "<code>action</code>: redirect" in result
        assert "<code>expression</code>: true" in result
        # Details joined with <br/> in a single <td>
        assert "<code>action</code>: redirect<br/><code>expression</code>: true" in result
        # No colspan=2 continuation rows for Create
        # (only Update uses continuation rows)
        create_section = result[result.index("Create") : result.index("Summary")]
        assert "colspan=2" not in create_section

    def test_delete_shows_rule_details_single_row(self):
        """Delete uses a single <tr> with <br/>-joined details (matches octodns)."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.REMOVE,
                    "r1",
                    REDIRECT_PHASE,
                    current={"expression": "true", "action": "redirect"},
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "Delete" in result
        assert "<code>action</code>: redirect<br/><code>expression</code>: true" in result

    def test_xss_safety(self):
        """Script tags in zone names and refs must be escaped."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "<script>alert(1)</script>", REDIRECT_PHASE)],
        )
        zp = ZonePlan("<script>xss</script>", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_xss_safety_in_details(self):
        """Script tags in rule values must be escaped in Details."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(
                    ChangeType.ADD,
                    "r1",
                    REDIRECT_PHASE,
                    desired={
                        "expression": '<script>alert("xss")</script>',
                        "action": "redirect",
                    },
                )
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "<script>" not in result
        assert "&lt;script&gt;" in result

    def test_summary_inside_table(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "Summary: Creates=1" in result
        # Summary row is inside the table (before </table>)
        summary_pos = result.index("Summary:")
        table_end_pos = result.index("</table>")
        assert summary_pos < table_end_pos

    def test_operation_column_header(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "<th>Operation</th>" in result

    def test_no_external_dependencies(self):
        result = format_plan_html([ZonePlan("example.com")])
        assert "<link" not in result
        assert "<script" not in result

    def test_print_plan_html_routing(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        buf = io.StringIO()
        print_plan([zp], file=buf, fmt="html")
        output = buf.getvalue()
        assert "<table>" in output
        assert "example.com" in output


class TestBuildReportData:
    def test_empty_zones(self):
        """No rules anywhere -> summary shows all in_sync."""
        zp = ZonePlan("example.com")
        data = build_report_data([zp], {"example.com": {}}, {"example.com": {}})
        assert data["summary"]["total_zones"] == 1
        assert data["summary"]["in_sync"] == 1
        assert data["summary"]["drifted"] == 0
        assert data["zones"][0]["status"] == "in_sync"

    def test_drifted_zone(self):
        """YAML rules with no live -> yaml_only status."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        desired = {"example.com": {"redirect_rules": [{"ref": "r1", "expression": "true"}]}}
        current = {"example.com": {}}
        data = build_report_data([zp], desired, current)
        assert data["zones"][0]["status"] == "drifted"
        assert data["zones"][0]["phases"][0]["status"] == "yaml_only"
        assert data["summary"]["drifted"] == 1

    def test_in_sync_phase(self):
        """Matching rules -> in_sync."""
        zp = ZonePlan("example.com")  # no phase_plans means no changes
        desired = {"example.com": {"redirect_rules": [{"ref": "r1"}]}}
        current = {
            "example.com": {"http_request_dynamic_redirect": [{"ref": "r1", "action": "redirect"}]}
        }
        data = build_report_data([zp], desired, current)
        assert data["zones"][0]["phases"][0]["status"] == "in_sync"
        assert data["zones"][0]["phases"][0]["yaml_rules"] == 1
        assert data["zones"][0]["phases"][0]["live_rules"] == 1

    def test_live_only_status(self):
        """Live rules with no YAML -> live_only status."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.REMOVE, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        desired = {"example.com": {}}
        current = {
            "example.com": {"http_request_dynamic_redirect": [{"ref": "r1", "action": "redirect"}]}
        }
        data = build_report_data([zp], desired, current)
        assert data["zones"][0]["phases"][0]["status"] == "live_only"

    def test_yaml_only_status(self):
        """YAML rules with no live -> yaml_only status."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        desired = {"example.com": {"redirect_rules": [{"ref": "r1", "expression": "true"}]}}
        current = {"example.com": {}}
        data = build_report_data([zp], desired, current)
        assert data["zones"][0]["phases"][0]["status"] == "yaml_only"

    def test_multiple_zones(self):
        """Summary counts are correct for multiple zones."""
        zp1 = ZonePlan("a.com")
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp2 = ZonePlan("b.com", phase_plans=[pp])
        desired = {
            "a.com": {},
            "b.com": {"redirect_rules": [{"ref": "r1", "expression": "true"}]},
        }
        current = {"a.com": {}, "b.com": {}}
        data = build_report_data([zp1, zp2], desired, current)
        assert data["summary"]["total_zones"] == 2
        assert data["summary"]["in_sync"] == 1
        assert data["summary"]["drifted"] == 1

    def test_modify_count(self):
        """Modifies and adds counted correctly."""
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[
                RuleChange(ChangeType.ADD, "r2", REDIRECT_PHASE),
                RuleChange(
                    ChangeType.MODIFY,
                    "r1",
                    REDIRECT_PHASE,
                    current={"expression": "old"},
                    desired={"expression": "new"},
                ),
            ],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        desired = {
            "example.com": {
                "redirect_rules": [
                    {"ref": "r1", "expression": "new"},
                    {"ref": "r2", "expression": "true"},
                ]
            }
        }
        current = {
            "example.com": {"http_request_dynamic_redirect": [{"ref": "r1", "expression": "old"}]}
        }
        data = build_report_data([zp], desired, current)
        phase = data["zones"][0]["phases"][0]
        assert phase["adds"] == 1
        assert phase["modifies"] == 1
        assert phase["removes"] == 0
        assert phase["status"] == "drifted"

    def test_extension_returning_false_preserves_phase_drift(self):
        """Phase-level drift is NOT lost when a format extension returns False.

        Regression test: the fix changed
            zone_has_drift = bool(fmt.format_report(...))
        to
            zone_has_drift = zone_has_drift or bool(...)
        """
        from octorules.extensions import register_format_extension, unregister_format_extension

        class _FalseReportExtension:
            def format_report(self, plans, zone_has_drift, phases_data):
                return False

        register_format_extension("_test_false_ext", _FalseReportExtension())
        try:
            pp = PhasePlan(
                phase=REDIRECT_PHASE,
                changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
            )
            zp = ZonePlan(
                "example.com",
                phase_plans=[pp],
                extension_plans={"_test_false_ext": [MagicMock(has_changes=True)]},
            )
            desired = {
                "example.com": {
                    "redirect_rules": [{"ref": "r1", "expression": "true"}],
                }
            }
            current = {"example.com": {}}
            data = build_report_data([zp], desired, current)
            # Phase has drift (yaml_only), extension returns False —
            # zone must still be marked as drifted.
            assert data["zones"][0]["status"] == "drifted"
            assert data["summary"]["drifted"] == 1
        finally:
            unregister_format_extension("_test_false_ext")


class TestFormatReportCsv:
    def _sample_data(self):
        return {
            "zones": [
                {
                    "zone": "example.com",
                    "status": "drifted",
                    "phases": [
                        {
                            "phase": "redirect_rules",
                            "provider_id": "http_request_dynamic_redirect",
                            "status": "drifted",
                            "yaml_rules": 5,
                            "live_rules": 4,
                            "adds": 1,
                            "removes": 0,
                            "modifies": 1,
                        }
                    ],
                }
            ],
            "summary": {"total_zones": 1, "in_sync": 0, "drifted": 1},
        }

    def test_header_row(self):
        result = format_report_csv(self._sample_data())
        first_line = result.splitlines()[0]
        assert "Zone" in first_line
        assert "Phase" in first_line
        assert "Status" in first_line

    def test_data_row(self):
        result = format_report_csv(self._sample_data())
        lines = result.splitlines()
        assert len(lines) >= 2
        assert "example.com" in lines[1]
        assert "redirect_rules" in lines[1]
        assert "drifted" in lines[1]

    def test_summary_line(self):
        result = format_report_csv(self._sample_data())
        assert "# Summary:" in result
        assert "1 zones" in result


class TestFormatReportJson:
    def _sample_data(self):
        return {
            "zones": [{"zone": "example.com", "status": "in_sync", "phases": []}],
            "summary": {"total_zones": 1, "in_sync": 1, "drifted": 0},
        }

    def test_valid_json(self):
        result = format_report_json(self._sample_data())
        data = json.loads(result)
        assert "zones" in data

    def test_preserves_structure(self):
        original = self._sample_data()
        result = format_report_json(original)
        data = json.loads(result)
        assert data == original


class TestPrintReport:
    def test_csv_routing(self):
        data = {
            "zones": [{"zone": "a.com", "status": "in_sync", "phases": []}],
            "summary": {"total_zones": 1, "in_sync": 1, "drifted": 0},
        }
        buf = io.StringIO()
        print_report(data, file=buf, fmt="csv")
        output = buf.getvalue()
        assert "Zone" in output
        assert "# Summary:" in output

    def test_json_routing(self):
        data = {
            "zones": [{"zone": "a.com", "status": "in_sync", "phases": []}],
            "summary": {"total_zones": 1, "in_sync": 1, "drifted": 0},
        }
        buf = io.StringIO()
        print_report(data, file=buf, fmt="json")
        output = buf.getvalue()
        parsed = json.loads(output)
        assert parsed["zones"][0]["zone"] == "a.com"


class TestRuleDetailPairs:
    def test_none_returns_empty(self):
        assert _rule_detail_pairs(None) == []

    def test_empty_dict_returns_empty(self):
        assert _rule_detail_pairs({}) == []

    def test_priority_ordering(self):
        """action, description, expression come first in order."""
        rule = {"expression": "true", "action": "redirect", "description": "My rule"}
        pairs = _rule_detail_pairs(rule)
        keys = [k for k, _ in pairs]
        assert keys == ["action", "description", "expression"]

    def test_skips_enabled_true(self):
        rule = {"action": "redirect", "enabled": True, "expression": "true"}
        pairs = _rule_detail_pairs(rule)
        keys = [k for k, _ in pairs]
        assert "enabled" not in keys

    def test_keeps_enabled_false(self):
        rule = {"action": "redirect", "enabled": False, "expression": "true"}
        pairs = _rule_detail_pairs(rule)
        keys = [k for k, _ in pairs]
        assert "enabled" in keys

    def test_non_priority_fields_sorted(self):
        rule = {"expression": "true", "action": "redirect", "zone_name": "z", "beta": "b"}
        pairs = _rule_detail_pairs(rule)
        keys = [k for k, _ in pairs]
        # priority keys first, then beta, zone_name alphabetically
        assert keys == ["action", "expression", "beta", "zone_name"]


class TestChangeToDictHelper:
    def test_with_current_and_desired(self):
        change = RuleChange(
            ChangeType.MODIFY,
            "r1",
            REDIRECT_PHASE,
            current={"expression": "old", "action": "redirect"},
            desired={"expression": "new", "action": "redirect"},
        )
        d = _change_to_dict(change)
        assert d["type"] == "modify"
        assert d["ref"] == "r1"
        assert "current" in d
        assert "desired" in d

    def test_add_only_desired(self):
        change = RuleChange(
            ChangeType.ADD,
            "r1",
            REDIRECT_PHASE,
            desired={"expression": "true", "action": "redirect"},
        )
        d = _change_to_dict(change)
        assert d["type"] == "add"
        assert d["ref"] == "r1"
        assert "desired" in d
        assert "current" not in d
