"""Assertion helpers for linter tests.

Single source of truth for ``assert_lint`` / ``assert_no_lint``. Provider
test suites import from here directly; previously the same ~75 lines
were copy-pasted into every ``tests/test_linter/conftest.py``.

Both helpers are polymorphic on input: pass either a ``LintContext``
(engine-driven flow, the CF style) or a ``list[LintResult]`` (validator
return value, the AWS/Google/Azure/Bunny style). The same assertions
apply in both cases.
"""

from octorules.linter.engine import LintContext, LintResult


def _results_of(target: LintContext | list[LintResult]) -> list[LintResult]:
    """Extract the result list from either a LintContext or a bare list."""
    return target.results if isinstance(target, LintContext) else target


def assert_lint(
    target: LintContext | list[LintResult],
    rule_id: str,
    *,
    count: int | None = None,
    severity=None,
    ref: str | None = None,
    phase: str | None = None,
) -> list[LintResult]:
    """Assert that *target* contains lint results matching the given criteria.

    Args:
        target: A ``LintContext`` (whose ``.results`` are inspected) or a
            ``list[LintResult]`` returned by a validator.
        rule_id: Required lint rule ID to check for (e.g. ``"CF003"``).
        count: If set, assert exactly this many results with this rule_id.
        severity: If set, assert all matching results have this severity.
        ref: If set, assert at least one matching result has this ref.
        phase: If set, assert at least one matching result has this phase.

    Returns:
        The list of matching LintResult objects, for further assertions.
    """
    results = _results_of(target)
    matches = [r for r in results if r.rule_id == rule_id]

    if count is not None:
        assert len(matches) == count, (
            f"Expected {count} result(s) for {rule_id}, got {len(matches)}. "
            f"All results: {[str(r) for r in results]}"
        )
    else:
        assert len(matches) > 0, (
            f"Expected at least one result for {rule_id}, got none. "
            f"All results: {[str(r) for r in results]}"
        )

    if severity is not None:
        for m in matches:
            assert m.severity == severity, (
                f"Expected severity {severity.name} for {rule_id}, got {m.severity.name}: {m}"
            )

    if ref is not None:
        assert any(m.ref == ref for m in matches), (
            f"Expected at least one {rule_id} result with ref={ref!r}. "
            f"Refs found: {[m.ref for m in matches]}"
        )

    if phase is not None:
        assert any(m.phase == phase for m in matches), (
            f"Expected at least one {rule_id} result with phase={phase!r}. "
            f"Phases found: {[m.phase for m in matches]}"
        )

    return matches


def assert_no_lint(target: LintContext | list[LintResult], rule_id: str) -> None:
    """Assert that *target* contains NO results for the given rule_id.

    Args:
        target: A ``LintContext`` or a ``list[LintResult]``.
        rule_id: The lint rule ID that should NOT appear.
    """
    matches = [r for r in _results_of(target) if r.rule_id == rule_id]
    assert len(matches) == 0, (
        f"Expected no results for {rule_id}, got {len(matches)}: {[str(r) for r in matches]}"
    )
