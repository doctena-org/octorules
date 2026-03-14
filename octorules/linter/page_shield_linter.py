"""Page Shield policy linter — Category S rules + expression analysis.

Validates page_shield_policies entries for structural correctness (S001-S004),
catch-all expressions (M013/M014), and delegates expression-level analysis
(E, F, G, O) to the AST linter.
"""

from __future__ import annotations

from typing import Any

from octorules.linter.engine import (
    LintContext,
    LintResult,
    Severity,
    check_catch_all,
)
from octorules.phases import Phase

RULE_IDS = frozenset({"M013", "M014", "S001", "S002", "S003", "S004"})

# Synthetic phase for page_shield_policies expression analysis
_PS_PHASE = Phase("page_shield_policies", "page_shield", "allow")

# Required fields on each policy entry
_REQUIRED_FIELDS = ("description", "action", "expression", "enabled", "value")

# Valid action values
_VALID_ACTIONS = frozenset({"allow", "log"})


def lint_page_shield_policies(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Page Shield policy checks on the rules data."""
    policies = rules_data.get("page_shield_policies")
    if not isinstance(policies, list):
        return

    if ctx.phase_filter and "page_shield_policies" not in ctx.phase_filter:
        return

    seen_descriptions: set[str] = set()
    for i, policy in enumerate(policies):
        if not isinstance(policy, dict):
            ctx.add(
                LintResult(
                    rule_id="S003",
                    severity=Severity.ERROR,
                    message=f"Policy at index {i} must be a mapping, got {type(policy).__name__}",
                    phase="page_shield_policies",
                )
            )
            continue

        desc = policy.get("description", "")
        desc_label = desc if isinstance(desc, str) and desc else f"index {i}"

        _check_policy_structure(policy, i, desc_label, seen_descriptions, ctx)
        _check_policy_expressions(policy, desc_label, ctx)

        if isinstance(desc, str) and desc:
            seen_descriptions.add(desc)


def _check_policy_structure(
    policy: dict[str, Any],
    index: int,
    desc_label: str,
    seen_descriptions: set[str],
    ctx: LintContext,
) -> None:
    """Check structural correctness of a single policy (S001-S004, M013/M014)."""
    # S001: Missing required fields
    for field_name in _REQUIRED_FIELDS:
        if field_name not in policy:
            ctx.add(
                LintResult(
                    rule_id="S001",
                    severity=Severity.ERROR,
                    message=f"Policy is missing required '{field_name}' field",
                    phase="page_shield_policies",
                    ref=desc_label,
                )
            )

    # S002: Invalid action
    action = policy.get("action")
    if action is not None and action not in _VALID_ACTIONS:
        ctx.add(
            LintResult(
                rule_id="S002",
                severity=Severity.ERROR,
                message=f"Invalid action {action!r} — must be 'allow' or 'log'",
                phase="page_shield_policies",
                ref=desc_label,
            )
        )

    # S003: Invalid field types
    desc = policy.get("description")
    if desc is not None and not isinstance(desc, str):
        ctx.add(
            LintResult(
                rule_id="S003",
                severity=Severity.ERROR,
                message=f"'description' must be a string, got {type(desc).__name__}",
                phase="page_shield_policies",
                ref=desc_label,
            )
        )

    enabled = policy.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        ctx.add(
            LintResult(
                rule_id="S003",
                severity=Severity.ERROR,
                message=(
                    f"'enabled' must be a boolean, got {type(enabled).__name__} ({enabled!r})"
                ),
                phase="page_shield_policies",
                ref=desc_label,
                field="enabled",
            )
        )

    value = policy.get("value")
    if value is not None and not isinstance(value, str):
        ctx.add(
            LintResult(
                rule_id="S003",
                severity=Severity.ERROR,
                message=f"'value' must be a string, got {type(value).__name__}",
                phase="page_shield_policies",
                ref=desc_label,
                field="value",
            )
        )

    # S004: Duplicate description
    if isinstance(desc, str) and desc and desc in seen_descriptions:
        ctx.add(
            LintResult(
                rule_id="S004",
                severity=Severity.WARNING,
                message=f"Duplicate description {desc!r} — descriptions are identity keys",
                phase="page_shield_policies",
                ref=desc_label,
            )
        )

    # M013 / M014: always-true / always-false expressions
    expr = policy.get("expression")
    if isinstance(expr, str):
        check_catch_all(expr, "page_shield_policies", desc_label, ctx, entity="policy")


def _check_policy_expressions(policy: dict[str, Any], desc_label: str, ctx: LintContext) -> None:
    """Delegate expression and phase-restriction analysis to the AST/phase linters."""
    from octorules.linter.ast_linter import lint_expressions
    from octorules.linter.phase_linter import lint_phase_restrictions

    expr = policy.get("expression")
    if not isinstance(expr, str) or not expr:
        return

    lint_expressions(policy, _PS_PHASE, ctx, ref_override=desc_label)
    lint_phase_restrictions(policy, _PS_PHASE, ctx, ref_override=desc_label)
