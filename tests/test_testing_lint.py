"""Tests for octorules.testing.lint.

The polymorphic ``assert_lint`` / ``assert_no_lint`` helpers accept either
a ``LintContext`` (engine-driven flow) or a bare ``list[LintResult]``
(validator return value). These tests exercise both input shapes and the
optional ``count`` / ``severity`` / ``ref`` / ``phase`` filters.
"""

import pytest

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.testing.lint import assert_lint, assert_no_lint


def _result(rule_id: str, **kwargs) -> LintResult:
    """Minimal LintResult for tests."""
    defaults = {
        "rule_id": rule_id,
        "severity": Severity.WARNING,
        "message": f"{rule_id} fired",
        "phase": "",
        "ref": "",
        "field": "",
        "suggestion": "",
        "location": "",
    }
    defaults.update(kwargs)
    return LintResult(**defaults)


# ---------------------------------------------------------------------------
# Polymorphism: same call works on LintContext OR list[LintResult]
# ---------------------------------------------------------------------------
class TestPolymorphicInput:
    def test_assert_lint_accepts_lint_context(self):
        ctx = LintContext()
        ctx.results = [_result("X100")]
        matches = assert_lint(ctx, "X100")
        assert len(matches) == 1
        assert matches[0].rule_id == "X100"

    def test_assert_lint_accepts_bare_list(self):
        results = [_result("X100")]
        matches = assert_lint(results, "X100")
        assert len(matches) == 1
        assert matches[0].rule_id == "X100"

    def test_assert_no_lint_accepts_lint_context(self):
        ctx = LintContext()
        ctx.results = [_result("X100")]
        assert_no_lint(ctx, "Y200")  # different rule_id — must not raise

    def test_assert_no_lint_accepts_bare_list(self):
        results = [_result("X100")]
        assert_no_lint(results, "Y200")


# ---------------------------------------------------------------------------
# count=
# ---------------------------------------------------------------------------
class TestCountFilter:
    def test_exact_count_hit(self):
        results = [_result("X100"), _result("X100"), _result("X100")]
        matches = assert_lint(results, "X100", count=3)
        assert len(matches) == 3

    def test_count_mismatch_raises(self):
        results = [_result("X100"), _result("X100")]
        with pytest.raises(AssertionError, match="Expected 3"):
            assert_lint(results, "X100", count=3)

    def test_count_zero_means_one_or_more_when_unset(self):
        results = [_result("X100")]
        matches = assert_lint(results, "X100")  # no count → just "at least one"
        assert len(matches) == 1

    def test_no_match_raises_without_count(self):
        results = [_result("X100")]
        with pytest.raises(AssertionError, match="at least one"):
            assert_lint(results, "Y200")


# ---------------------------------------------------------------------------
# severity=
# ---------------------------------------------------------------------------
class TestSeverityFilter:
    def test_severity_match(self):
        results = [_result("X100", severity=Severity.ERROR)]
        assert_lint(results, "X100", severity=Severity.ERROR)

    def test_severity_mismatch_raises(self):
        results = [_result("X100", severity=Severity.WARNING)]
        with pytest.raises(AssertionError, match="Expected severity ERROR"):
            assert_lint(results, "X100", severity=Severity.ERROR)


# ---------------------------------------------------------------------------
# ref= / phase=
# ---------------------------------------------------------------------------
class TestRefAndPhaseFilters:
    def test_ref_match(self):
        results = [_result("X100", ref="rule-1")]
        assert_lint(results, "X100", ref="rule-1")

    def test_ref_mismatch_raises(self):
        results = [_result("X100", ref="rule-1")]
        with pytest.raises(AssertionError, match="ref='rule-2'"):
            assert_lint(results, "X100", ref="rule-2")

    def test_phase_match(self):
        results = [_result("X100", phase="aws.waf_custom_rules")]
        assert_lint(results, "X100", phase="aws.waf_custom_rules")

    def test_phase_mismatch_raises(self):
        results = [_result("X100", phase="aws.waf_custom_rules")]
        with pytest.raises(AssertionError, match="phase='other_phase'"):
            assert_lint(results, "X100", phase="other_phase")


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------
class TestEdgeCases:
    def test_empty_list_no_matches(self):
        with pytest.raises(AssertionError, match="at least one"):
            assert_lint([], "X100")

    def test_empty_context_no_matches(self):
        ctx = LintContext()
        with pytest.raises(AssertionError, match="at least one"):
            assert_lint(ctx, "X100")

    def test_assert_no_lint_passes_on_empty(self):
        assert_no_lint([], "X100")

    def test_assert_no_lint_raises_when_present(self):
        results = [_result("X100")]
        with pytest.raises(AssertionError, match="Expected no results for X100"):
            assert_no_lint(results, "X100")

    def test_returns_only_matching_results(self):
        results = [_result("X100"), _result("Y200"), _result("X100")]
        matches = assert_lint(results, "X100")
        assert len(matches) == 2
        assert all(m.rule_id == "X100" for m in matches)
