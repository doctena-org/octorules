"""Tests for plan_output module."""

import io

from octorules.phases import get_phase
from octorules.plan_output import (
    PLAN_OUTPUT_CLASSES,
    PLAN_OUTPUT_FORMATS,
    PlanHtml,
    PlanJson,
    PlanMarkdown,
    PlanOutput,
    PlanText,
)
from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

REDIRECT_PHASE = get_phase("redirect_rules")


def _zone_with_changes():
    pp = PhasePlan(
        phase=REDIRECT_PHASE,
        changes=[RuleChange(ChangeType.ADD, "r1", REDIRECT_PHASE)],
    )
    return ZonePlan(zone_name="example.com", phase_plans=[pp])


class TestPlanOutput:
    def test_default_fmt_is_text(self):
        output = PlanOutput("test")
        assert output.fmt == "text"

    def test_path_attribute(self):
        output = PlanOutput("test", path="/tmp/out.txt")
        assert output.path == "/tmp/out.txt"
        assert output.name == "test"

    def test_path_default_none(self):
        output = PlanOutput("test")
        assert output.path is None

    def test_run_calls_print_plan(self, capsys):
        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        PlanOutput("test", fmt="text").run([zp])
        assert "No changes detected" in capsys.readouterr().out


class TestPlanText:
    def test_writes_stdout_no_changes(self, capsys):
        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        PlanText("text").run([zp])
        out = capsys.readouterr().out
        assert "No changes detected" in out

    def test_writes_stdout_with_changes(self, capsys):
        zp = _zone_with_changes()
        PlanText("text").run([zp])
        out = capsys.readouterr().out
        assert "example.com" in out

    def test_writes_to_fh(self):
        zp = _zone_with_changes()
        buf = io.StringIO()
        PlanText("text").run([zp], fh=buf)
        out = buf.getvalue()
        assert "example.com" in out

    def test_returns_plan_output_instance(self):
        assert isinstance(PlanText("t"), PlanOutput)
        assert PlanText("t").fmt == "text"


class TestPlanJson:
    def test_json_output_no_changes(self, capsys):
        import json

        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        PlanJson("json").run([zp])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert "zones" in data
        assert len(data["zones"]) == 0
        assert data["has_changes"] is False

    def test_json_output_with_changes(self, capsys):
        import json

        zp = _zone_with_changes()
        PlanJson("json").run([zp])
        out = capsys.readouterr().out
        data = json.loads(out)
        assert data["zones"][0]["zone"] == "example.com"

    def test_json_to_fh(self):
        import json

        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        buf = io.StringIO()
        PlanJson("json").run([zp], fh=buf)
        data = json.loads(buf.getvalue())
        assert "zones" in data


class TestPlanMarkdown:
    def test_markdown_output_no_changes(self, capsys):
        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        PlanMarkdown("md").run([zp])
        out = capsys.readouterr().out
        assert "No changes" in out

    def test_markdown_output_with_changes(self, capsys):
        zp = _zone_with_changes()
        PlanMarkdown("md").run([zp])
        out = capsys.readouterr().out
        assert "### Zone:" in out
        assert "example.com" in out

    def test_markdown_to_fh(self):
        zp = _zone_with_changes()
        buf = io.StringIO()
        PlanMarkdown("md").run([zp], fh=buf)
        assert "example.com" in buf.getvalue()


class TestPlanHtml:
    def test_html_output_no_changes(self, capsys):
        zp = ZonePlan(zone_name="example.com", phase_plans=[])
        PlanHtml("html").run([zp])
        out = capsys.readouterr().out
        assert "No changes" in out
        assert "<html>" not in out

    def test_html_output_with_changes(self, capsys):
        zp = _zone_with_changes()
        PlanHtml("html").run([zp])
        out = capsys.readouterr().out
        assert "<table>" in out
        assert "example.com" in out

    def test_html_to_fh(self):
        zp = _zone_with_changes()
        buf = io.StringIO()
        PlanHtml("html").run([zp], fh=buf)
        out = buf.getvalue()
        assert "<table>" in out


class TestFormats:
    def test_four_formats_registered(self):
        assert len(PLAN_OUTPUT_FORMATS) == 4

    def test_format_values(self):
        assert set(PLAN_OUTPUT_FORMATS.values()) == {"text", "markdown", "json", "html"}

    def test_backward_compat_classes_dict(self):
        """PLAN_OUTPUT_CLASSES still works for backward compatibility."""
        assert len(PLAN_OUTPUT_CLASSES) == 4
        for _key, factory in PLAN_OUTPUT_CLASSES.items():
            output = factory("test")
            assert isinstance(output, PlanOutput)
