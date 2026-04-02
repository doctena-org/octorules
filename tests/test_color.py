"""Tests for octorules._color — Pen, ColoredFormatter, supports_color."""

from __future__ import annotations

import io
import logging

import pytest

from octorules._color import (
    _BOLD,
    _CYAN,
    _DIM,
    _GREEN,
    _RED,
    _RESET,
    _YELLOW,
    ColoredFormatter,
    Pen,
    supports_color,
)

# ---------------------------------------------------------------------------
# supports_color
# ---------------------------------------------------------------------------


class TestSupportsColor:
    def test_returns_bool(self):
        assert isinstance(supports_color(), bool)

    def test_default_checks_stdout(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        assert isinstance(supports_color(), bool)

    def test_explicit_tty_stream(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)

        class FakeTTY:
            def isatty(self):
                return True

        assert supports_color(FakeTTY()) is True

    def test_explicit_non_tty_stream(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        assert supports_color(io.StringIO()) is False

    def test_no_color_overrides_tty(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "")
        monkeypatch.delenv("FORCE_COLOR", raising=False)

        class FakeTTY:
            def isatty(self):
                return True

        assert supports_color(FakeTTY()) is False

    def test_force_color_overrides_non_tty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert supports_color(io.StringIO()) is True

    def test_no_color_beats_force_color(self, monkeypatch):
        monkeypatch.setenv("NO_COLOR", "")
        monkeypatch.setenv("FORCE_COLOR", "1")
        assert supports_color(io.StringIO()) is False

    def test_stream_without_isatty(self, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        assert supports_color(object()) is False


# ---------------------------------------------------------------------------
# Pen
# ---------------------------------------------------------------------------


class TestPen:
    def test_color_off_returns_plain(self):
        p = Pen(use_color=False)
        assert p.error("x") == "x"
        assert p.warning("x") == "x"
        assert p.success("x") == "x"
        assert p.info("x") == "x"
        assert p.header("x") == "x"
        assert p.muted("x") == "x"
        assert p.raw("x", _GREEN) == "x"

    def test_error_red(self):
        p = Pen(use_color=True)
        assert p.error("boom") == f"{_RED}boom{_RESET}"

    def test_warning_yellow(self):
        p = Pen(use_color=True)
        assert p.warning("careful") == f"{_YELLOW}careful{_RESET}"

    def test_success_green(self):
        p = Pen(use_color=True)
        assert p.success("done") == f"{_GREEN}done{_RESET}"

    def test_info_cyan(self):
        p = Pen(use_color=True)
        assert p.info("note") == f"{_CYAN}note{_RESET}"

    def test_header_bold(self):
        p = Pen(use_color=True)
        assert p.header("title") == f"{_BOLD}title{_RESET}"

    def test_muted_dim(self):
        p = Pen(use_color=True)
        assert p.muted("detail") == f"{_DIM}detail{_RESET}"

    def test_raw_with_custom_code(self):
        p = Pen(use_color=True)
        assert p.raw("text", "\033[35m") == "\033[35mtext\033[0m"

    def test_concatenation(self):
        """Pen output concatenates naturally with plain strings."""
        p = Pen(use_color=True)
        result = p.header("Zone: ") + "3 changes"
        assert result == f"{_BOLD}Zone: {_RESET}3 changes"

    def test_no_extra_attributes(self):
        """Pen uses __slots__ — no arbitrary attributes allowed."""
        p = Pen(use_color=True)
        with pytest.raises(AttributeError):
            p.extra = True  # type: ignore[attr-defined]


# ---------------------------------------------------------------------------
# ColoredFormatter
# ---------------------------------------------------------------------------


class TestColoredFormatter:
    def _record(self, level=logging.INFO, msg="hello", **extra):
        record = logging.LogRecord(
            name="test",
            level=level,
            pathname="",
            lineno=0,
            msg=msg,
            args=(),
            exc_info=None,
        )
        for k, v in extra.items():
            setattr(record, k, v)
        return record

    # -- color disabled --

    def test_disabled_returns_plain(self):
        fmt = ColoredFormatter(use_color=False)
        assert fmt.format(self._record(logging.ERROR, "fail")) == "fail"

    def test_disabled_ignores_extra(self):
        fmt = ColoredFormatter(use_color=False)
        rec = self._record(logging.INFO, "done", color="success")
        assert "\033" not in fmt.format(rec)

    # -- level-based coloring --

    def test_error_red(self):
        fmt = ColoredFormatter(use_color=True)
        assert fmt.format(self._record(logging.ERROR, "fail")) == f"{_RED}fail{_RESET}"

    def test_warning_yellow(self):
        fmt = ColoredFormatter(use_color=True)
        assert fmt.format(self._record(logging.WARNING, "warn")) == f"{_YELLOW}warn{_RESET}"

    def test_debug_dim(self):
        fmt = ColoredFormatter(use_color=True)
        assert fmt.format(self._record(logging.DEBUG, "trace")) == f"{_DIM}trace{_RESET}"

    def test_info_no_color_by_default(self):
        fmt = ColoredFormatter(use_color=True)
        result = fmt.format(self._record(logging.INFO, "plain"))
        assert result == "plain"
        assert "\033" not in result

    # -- per-message semantic override --

    def test_extra_success(self):
        fmt = ColoredFormatter(use_color=True)
        rec = self._record(logging.INFO, "done", color="success")
        assert fmt.format(rec) == f"{_GREEN}done{_RESET}"

    def test_extra_header(self):
        fmt = ColoredFormatter(use_color=True)
        rec = self._record(logging.INFO, "Syncing zone", color="header")
        assert fmt.format(rec) == f"{_BOLD}Syncing zone{_RESET}"

    def test_extra_overrides_level(self):
        """Explicit color name overrides level-based color."""
        fmt = ColoredFormatter(use_color=True)
        rec = self._record(logging.ERROR, "custom", color="success")
        assert fmt.format(rec) == f"{_GREEN}custom{_RESET}"

    def test_unknown_semantic_name_no_color(self):
        """Unrecognized color name produces no color (doesn't fall back to level)."""
        fmt = ColoredFormatter(use_color=True)
        rec = self._record(logging.ERROR, "oops", color="nonexistent")
        assert fmt.format(rec) == "oops"

    # -- thread safety --

    def test_thread_safe(self):
        """Formatter works correctly from multiple threads."""
        import concurrent.futures

        fmt = ColoredFormatter(use_color=True)

        def format_one(i):
            rec = self._record(logging.ERROR, f"msg-{i}")
            return fmt.format(rec)

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
            results = list(ex.map(format_one, range(20)))

        for i, result in enumerate(results):
            assert result == f"{_RED}msg-{i}{_RESET}"

    # -- integration: real handler --

    def test_with_real_handler(self):
        """ColoredFormatter works with a real StreamHandler."""
        buf = io.StringIO()
        handler = logging.StreamHandler(buf)
        handler.setFormatter(ColoredFormatter(use_color=True))

        logger = logging.getLogger("test_color_integration")
        logger.addHandler(handler)
        logger.setLevel(logging.DEBUG)
        try:
            logger.error("red message")
            logger.info("plain message")
            logger.info("green message", extra={"color": "success"})
        finally:
            logger.removeHandler(handler)

        output = buf.getvalue()
        assert f"{_RED}red message{_RESET}" in output
        assert "plain message" in output
        assert f"{_GREEN}green message{_RESET}" in output


# ---------------------------------------------------------------------------
# pen() factory function
# ---------------------------------------------------------------------------


class TestPenFactory:
    def test_pen_returns_pen_instance(self):
        from octorules._color import pen

        p = pen()
        assert isinstance(p, Pen)

    def test_pen_non_tty_returns_no_color(self, monkeypatch):
        import io

        from octorules._color import pen

        monkeypatch.delenv("NO_COLOR", raising=False)
        monkeypatch.delenv("FORCE_COLOR", raising=False)
        p = pen(io.StringIO())
        assert p.use_color is False

    def test_pen_raw_no_color(self):
        """Pen.raw() returns plain text when color is off."""
        p = Pen(use_color=False)
        assert p.raw("text", "\033[35m") == "text"
        assert "\033" not in p.raw("text", _GREEN)


# ---------------------------------------------------------------------------
# Integration: colored output in lint, audit, plan formatters
# ---------------------------------------------------------------------------


class TestLintFormatterColor:
    """Verify lint text output includes ANSI codes when use_color=True."""

    def test_lint_errors_colored(self):
        from octorules.linter.engine import LintContext, LintResult, Severity
        from octorules.linter.report import format_text

        ctx = LintContext(zone_name="test.com")
        ctx.results = [
            LintResult(rule_id="CF001", severity=Severity.ERROR, message="parse error"),
            LintResult(rule_id="CF200", severity=Severity.WARNING, message="bad action"),
            LintResult(rule_id="CF300", severity=Severity.INFO, message="note"),
        ]
        output = format_text(ctx, use_color=True)
        assert f"{_RED}[ERROR]{_RESET}" in output
        assert f"{_YELLOW}[WARNING]{_RESET}" in output
        assert f"{_CYAN}[INFO]{_RESET}" in output
        assert f"{_BOLD}" in output  # header + total

    def test_lint_no_color(self):
        from octorules.linter.engine import LintContext, LintResult, Severity
        from octorules.linter.report import format_text

        ctx = LintContext(zone_name="test.com")
        ctx.results = [
            LintResult(rule_id="CF001", severity=Severity.ERROR, message="err"),
        ]
        output = format_text(ctx, use_color=False)
        assert "\033" not in output
        assert "[ERROR]" in output

    def test_lint_clean_green(self):
        from octorules.linter.engine import LintContext
        from octorules.linter.report import format_text

        ctx = LintContext(zone_name="clean.com")
        output = format_text(ctx, use_color=True)
        assert f"{_GREEN}No issues found.{_RESET}" in output


class TestAuditFormatterColor:
    """Verify audit text output includes ANSI codes when use_color=True."""

    def test_audit_findings_colored(self):
        from octorules.audit import AuditFinding, FindingSeverity, format_findings

        findings = [
            AuditFinding(
                check="ip-overlap",
                severity=FindingSeverity.WARNING,
                message="overlap found",
                zone_name="test.com",
            ),
            AuditFinding(
                check="cdn-ranges",
                severity=FindingSeverity.ERROR,
                message="matches CDN",
                zone_name="test.com",
            ),
        ]
        output = format_findings(findings, use_color=True)
        assert f"{_BOLD}" in output  # section headers
        assert f"{_YELLOW}warning:{_RESET}" in output
        assert f"{_RED}error:{_RESET}" in output

    def test_audit_no_color(self):
        from octorules.audit import AuditFinding, FindingSeverity, format_findings

        findings = [
            AuditFinding(
                check="ip-overlap",
                severity=FindingSeverity.WARNING,
                message="overlap",
            ),
        ]
        output = format_findings(findings, use_color=False)
        assert "\033" not in output
        assert "warning:" in output


class TestPlanFormatterColor:
    """Verify plan text output includes ANSI codes when use_color=True."""

    def test_zone_plan_colored(self):
        from octorules.formatter import format_zone_plan
        from octorules.phases import get_phase
        from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

        phase = get_phase("redirect_rules")
        zp = ZonePlan(
            zone_name="color.com",
            phase_plans=[
                PhasePlan(
                    phase=phase,
                    changes=[RuleChange(ChangeType.ADD, "r1", phase)],
                )
            ],
        )
        output = format_zone_plan(zp, use_color=True)
        assert f"{_BOLD}" in output  # zone header + phase header
        assert f"{_GREEN}" in output  # add change

    def test_zone_plan_no_color(self):
        from octorules.formatter import format_zone_plan
        from octorules.phases import get_phase
        from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

        phase = get_phase("redirect_rules")
        zp = ZonePlan(
            zone_name="plain.com",
            phase_plans=[
                PhasePlan(
                    phase=phase,
                    changes=[RuleChange(ChangeType.ADD, "r1", phase)],
                )
            ],
        )
        output = format_zone_plan(zp, use_color=False)
        assert "\033" not in output
        assert "r1" in output

    def test_no_changes_muted(self):
        from octorules.formatter import format_zone_plan
        from octorules.planner import ZonePlan

        zp = ZonePlan(zone_name="idle.com")
        output = format_zone_plan(zp, use_color=True)
        assert f"{_DIM}no changes{_RESET}" in output
