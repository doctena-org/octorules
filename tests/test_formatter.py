"""Tests for the formatter."""

from __future__ import annotations

import io
import json

from octorules.formatter import (
    GREEN,
    RESET,
    _color,
    _supports_color,
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
from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

REDIRECT_PHASE = get_phase("redirect_rules")
CACHE_PHASE = get_phase("cache_rules")


class TestColor:
    def test_color_enabled(self):
        result = _color("hello", GREEN, use_color=True)
        assert result == f"{GREEN}hello{RESET}"

    def test_color_disabled(self):
        result = _color("hello", GREEN, use_color=False)
        assert result == "hello"

    def test_supports_color_on_stringio(self):
        # StringIO is not a tty, so _supports_color should return False
        # when stdout is replaced
        assert isinstance(_supports_color(), bool)


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
        detail_lines = [ln for ln in lines if "expression" in ln]
        assert detail_lines
        assert "old-expr" in detail_lines[0] and "new-expr" in detail_lines[0]

    def test_modify_no_details_without_current_desired(self):
        change = RuleChange(ChangeType.MODIFY, "changed-rule", REDIRECT_PHASE)
        lines = format_change(change, use_color=False)
        assert len(lines) == 1

    def test_reorder(self):
        change = RuleChange(ChangeType.REORDER, "*", REDIRECT_PHASE)
        lines = format_change(change, use_color=False)
        assert any("reorder" in line for line in lines)

    def test_add_with_color(self):
        change = RuleChange(ChangeType.ADD, "my-rule", REDIRECT_PHASE)
        lines = format_change(change, use_color=True)
        combined = "\n".join(lines)
        assert GREEN in combined
        assert RESET in combined
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

    def test_includes_cf_phase_name(self):
        phase_plan = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        lines = format_phase_plan(phase_plan, use_color=False)
        assert any("http_request_dynamic_redirect" in line for line in lines)


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
        json.loads(result)  # Should not raise

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
        assert "expression" in result
        assert "old" in result
        assert "new" in result

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

    def test_summary_no_changes(self):
        result = format_plan_markdown([ZonePlan("example.com")])
        assert "**No changes detected.**" in result


class TestFormatPlanHtml:
    def test_empty_plan_skips_unchanged(self):
        result = format_plan_html([ZonePlan("example.com")])
        assert "example.com" not in result
        assert "No changes" in result

    def test_embeddable_fragment(self):
        """Output is an embeddable HTML fragment, not a full document."""
        result = format_plan_html([ZonePlan("example.com")])
        assert "<!DOCTYPE" not in result
        assert "<html>" not in result
        assert "<head>" not in result
        assert "<body>" not in result
        assert "<style>" not in result

    def test_with_changes(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "example.com" in result
        assert "redirect_rules" in result
        assert "r1" in result
        assert "+" in result

    def test_modify_shows_field_diffs(self):
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
        result = format_plan_html([zp])
        assert "expression" in result

    def test_reorder_shows_message(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.REORDER, "*", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "reorder" in result

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

    def test_summary_after_tables(self):
        pp = PhasePlan(
            phase=REDIRECT_PHASE,
            changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
        )
        zp = ZonePlan("example.com", phase_plans=[pp])
        result = format_plan_html([zp])
        assert "Summary:" in result
        # Summary appears after zone tables
        table_pos = result.index("</table>")
        summary_pos = result.index("Summary:")
        assert summary_pos > table_pos

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
        """No rules anywhere → summary shows all in_sync."""
        zp = ZonePlan("example.com")
        data = build_report_data([zp], {"example.com": {}}, {"example.com": {}})
        assert data["summary"]["total_zones"] == 1
        assert data["summary"]["in_sync"] == 1
        assert data["summary"]["drifted"] == 0
        assert data["zones"][0]["status"] == "in_sync"

    def test_drifted_zone(self):
        """YAML rules with no live → yaml_only status."""
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
        """Matching rules → in_sync."""
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
        """Live rules with no YAML → live_only status."""
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
        """YAML rules with no live → yaml_only status."""
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
                            "cf_phase": "http_request_dynamic_redirect",
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
