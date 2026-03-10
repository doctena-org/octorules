"""Shared test helpers for the linter test suite."""

from __future__ import annotations

from octorules.linter.engine import LintContext, LintResult


def assert_lint(
    ctx: LintContext,
    rule_id: str,
    *,
    count: int | None = None,
    severity=None,
    ref: str | None = None,
    phase: str | None = None,
) -> list[LintResult]:
    """Assert that ctx.results contains results matching the given criteria.

    Args:
        ctx: The LintContext whose results to inspect.
        rule_id: Required lint rule ID to check for (e.g. "M001").
        count: If set, assert exactly this many results with this rule_id.
        severity: If set, assert all matching results have this severity.
        ref: If set, assert at least one matching result has this ref.
        phase: If set, assert at least one matching result has this phase.

    Returns:
        The list of matching LintResult objects, for further assertions.
    """
    matches = [r for r in ctx.results if r.rule_id == rule_id]

    if count is not None:
        assert len(matches) == count, (
            f"Expected {count} result(s) for {rule_id}, got {len(matches)}. "
            f"All results: {[str(r) for r in ctx.results]}"
        )
    else:
        assert len(matches) > 0, (
            f"Expected at least one result for {rule_id}, got none. "
            f"All results: {[str(r) for r in ctx.results]}"
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


def assert_no_lint(ctx: LintContext, rule_id: str) -> None:
    """Assert that ctx.results contains NO results for the given rule_id.

    Args:
        ctx: The LintContext whose results to inspect.
        rule_id: The lint rule ID that should NOT appear.
    """
    matches = [r for r in ctx.results if r.rule_id == rule_id]
    assert len(matches) == 0, (
        f"Expected no results for {rule_id}, got {len(matches)}: {[str(r) for r in matches]}"
    )
