"""Tests for the public settings-extension framework and the publicized API.

Covers the SettingsChange/SettingsPlan/SettingsFormatter data model and
formatter (lifted from octorules-cloudflare's private ``_settings_base``),
plus the publicized helpers and their deprecated underscore aliases.
"""

import yaml

from octorules.extensions import (
    SettingsChange,
    SettingsFormatter,
    SettingsPlan,
    make_synthetic_phase,
)


class _AlphaPlan(SettingsPlan):
    """Stand-in for one provider extension's plan type."""


class _BetaPlan(SettingsPlan):
    """Stand-in for a sibling extension's plan type."""


def _alpha_formatter(prefix: str = "alpha") -> SettingsFormatter:
    return SettingsFormatter(plan_type=_AlphaPlan, prefix=prefix)


class TestSettingsPlanDefaults:
    def test_empty_plan(self):
        plan = SettingsPlan()
        assert plan.changes == []
        assert plan.unsupported == []
        assert not plan.has_changes
        assert plan.total_changes == 0

    def test_no_op_changes_do_not_count(self):
        plan = SettingsPlan(
            changes=[
                SettingsChange(field="a", current=1, desired=1),
                SettingsChange(field="b", current=1, desired=2),
            ]
        )
        assert plan.has_changes
        assert plan.total_changes == 1


class TestFormatterPlanTypeGating:
    def test_foreign_plan_type_is_ignored(self):
        # Each formatter is parameterised with its own Plan subclass;
        # plans of a sibling extension must not render through it.
        foreign = _BetaPlan(changes=[SettingsChange(field="x", current=False, desired=True)])
        fmt = _alpha_formatter()
        assert fmt.format_text([foreign], use_color=False) == []
        assert fmt.format_json([foreign]) == []


class TestFormatterLabels:
    def test_prefixed_label(self):
        plan = _AlphaPlan(changes=[SettingsChange(field="mode", current="log", desired="block")])
        lines = _alpha_formatter().format_text([plan], use_color=False)
        assert lines == ["  ~ alpha.mode: 'log' -> 'block'"]

    def test_empty_prefix_uses_field_as_label(self):
        # Providers whose fields already carry a section path (e.g.
        # "bot_detection.execution_mode") pass prefix="" and keep their
        # existing labels.
        plan = _AlphaPlan(
            changes=[SettingsChange(field="ddos.execution_mode", current="log", desired="block")]
        )
        lines = _alpha_formatter(prefix="").format_text([plan], use_color=False)
        assert lines == ["  ~ ddos.execution_mode: 'log' -> 'block'"]


class TestFormatterOutputs:
    def test_format_json_shape(self):
        plan = _AlphaPlan(
            changes=[
                SettingsChange(field="mode", current="log", desired="block"),
                SettingsChange(field="noop", current=1, desired=1),
            ],
            unsupported=["gated"],
        )
        result = _alpha_formatter().format_json([plan])
        assert result == [
            {
                "changes": [{"field": "mode", "current": "log", "desired": "block"}],
                "unsupported": ["gated"],
            }
        ]

    def test_format_markdown_escapes_pipes(self):
        plan = _AlphaPlan(changes=[SettingsChange(field="m|ode", current="a|b", desired="c")])
        rows = _alpha_formatter().format_markdown([plan], [])
        assert rows == ["| ~ | alpha.m\\|ode | | 'a\\|b' -> 'c' |"]

    def test_format_html_counts_and_notes(self):
        plan = _AlphaPlan(
            changes=[SettingsChange(field="mode", current="log", desired="block")],
            unsupported=["gated"],
        )
        lines: list[str] = []
        counts = _alpha_formatter().format_html([plan], lines)
        assert counts == (0, 0, 1, 0)
        joined = "\n".join(lines)
        assert "<td>alpha.mode</td>" in joined
        assert "<td>Note</td>" in joined
        assert "<td>alpha.gated</td>" in joined
        assert joined.count("</table>") == 1

    def test_unsupported_only_plan_still_renders_notes(self):
        plan = _AlphaPlan(unsupported=["gated"])
        lines = _alpha_formatter().format_text([plan], use_color=False)
        assert lines == [
            "  # alpha.gated: declared in YAML but not exposed on this zone -- ignored"
        ]


class TestMakeSyntheticPhase:
    def test_shape(self):
        phase = make_synthetic_phase("lists", "blocked-ips", "test_list_phase")
        assert phase.friendly_name == "lists:blocked-ips"
        assert phase.provider_id == "test_list_phase"
        assert phase.default_action is None
        assert phase.zone_level is False
        assert phase.account_level is True

    def test_level_overrides(self):
        phase = make_synthetic_phase(
            "page_shield", "policies", "test_ps", zone_level=True, account_level=False
        )
        assert phase.zone_level is True
        assert phase.account_level is False


class TestLiteralize:
    def test_multiline_string_becomes_block(self):
        from octorules.dumper import _LiteralStr, literalize

        result = literalize("line one\nline two")
        assert isinstance(result, _LiteralStr)

    def test_recurses_into_nested_structures(self):
        from octorules.dumper import _LiteralStr, literalize

        result = literalize({"k": ["a\nb", "plain"]})
        assert isinstance(result["k"][0], _LiteralStr)
        assert result["k"][1] == "plain"
        assert not isinstance(result["k"][1], _LiteralStr)

    def test_single_line_string_unchanged(self):
        from octorules.dumper import _LiteralStr, literalize

        result = literalize("plain")
        assert result == "plain"
        assert not isinstance(result, _LiteralStr)

    def test_block_forces_literal_style(self):
        from octorules.dumper import _LiteralStr, literalize

        result = literalize("script-src 'self';   \n  img-src *;", block=True)
        assert isinstance(result, _LiteralStr)
        # Trailing whitespace stripped per line (PyYAML rejects block style otherwise)
        assert result == "script-src 'self';\n  img-src *;"

    def test_block_requires_string(self):
        import pytest

        from octorules.dumper import literalize

        with pytest.raises(TypeError):
            literalize({"not": "a string"}, block=True)

    def test_block_value_dumps_as_literal_yaml(self):
        from octorules.dumper import _Dumper, literalize

        text = yaml.dump({"value": literalize("a\nb", block=True)}, Dumper=_Dumper)
        assert "value: |-" in text


class TestPublicAliases:
    """The publicized helpers and their deprecated underscore aliases are
    the same objects — imports through either name keep working."""

    def test_normalize_value(self):
        from octorules.planner import _normalize_value, normalize_value

        assert _normalize_value is normalize_value
        assert normalize_value("ip.src  eq 1.2.3.4", key="expression") == "ip.src eq 1.2.3.4"
        assert normalize_value("a  b", key="description") == "a  b"

    def test_make_synthetic_phase_alias(self):
        from octorules.extensions import make_synthetic_phase
        from octorules.planner import _make_synthetic_phase

        assert _make_synthetic_phase is make_synthetic_phase

    def test_apply_parallel_alias(self):
        from octorules.commands._helpers import _apply_parallel
        from octorules.provider.utils import apply_parallel

        assert _apply_parallel is apply_parallel

    def test_formatter_aliases(self):
        from octorules.formatter import (
            _change_to_dict,
            _md_change_row,
            change_to_dict,
            md_change_row,
        )

        assert _change_to_dict is change_to_dict
        assert _md_change_row is md_change_row

    def test_formatter_markdown_html_aliases(self):
        from octorules.formatter import (
            _HTML_TABLE_HEADER,
            HTML_TABLE_HEADER,
            _html_render_changes,
            _html_summary_row,
            _md_escape,
            html_render_changes,
            html_summary_row,
            md_escape,
        )

        assert _md_escape is md_escape
        assert _html_render_changes is html_render_changes
        assert _html_summary_row is html_summary_row
        assert _HTML_TABLE_HEADER is HTML_TABLE_HEADER
        assert md_escape("a|b") == "a\\|b"
        assert HTML_TABLE_HEADER[0] == "<table>"

    def test_apply_parallel_sequential_smoke(self):
        from octorules.provider.utils import apply_parallel

        ran: list[str] = []
        tasks = [("one", lambda: ran.append("one")), ("two", lambda: ran.append("two"))]
        successes, error = apply_parallel(tasks, max_workers=1)
        assert successes == ["one", "two"]
        assert error is None
        assert ran == ["one", "two"]
