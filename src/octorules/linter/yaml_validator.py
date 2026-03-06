"""YAML structure validation — Category M rules.

Validates the structural correctness of zone rules files:
required fields, types, duplicates, unknown phases, etc.
"""

from __future__ import annotations

from typing import Any

from octorules.expression import normalize_expression
from octorules.linter.engine import (
    LintContext,
    LintResult,
    Severity,
    is_always_false,
    is_always_true,
)
from octorules.phases import (
    KNOWN_NON_PHASE_KEYS,
    PHASE_BY_CF,
    PHASE_BY_NAME,
    RENAMED_PHASES,
    suggest_phase,
)

# Maximum recommended description length
_MAX_DESCRIPTION_LENGTH = 500

# Maximum expression length (Cloudflare API limit)
_MAX_EXPRESSION_LENGTH = 4096


def lint_yaml_structure(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all Category M structural checks on a zone rules file."""
    _check_top_level_keys(rules_data, ctx)
    for phase_name, rules in rules_data.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue  # already flagged by _check_top_level_keys
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        _check_phase_rules(phase_name, rules, ctx)


def _check_top_level_keys(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Check for unknown, deprecated, or CF-identifier phase keys (M007, M008, M012)."""
    for key in sorted(rules_data.keys()):
        if key in KNOWN_NON_PHASE_KEYS:
            continue
        if key in RENAMED_PHASES:
            new_name = RENAMED_PHASES[key]
            ctx.add(
                LintResult(
                    rule_id="M008",
                    severity=Severity.WARNING,
                    message=f"Phase {key!r} has been renamed to {new_name!r}",
                    phase=key,
                    suggestion=f"Rename to {new_name!r}",
                )
            )
        elif key in PHASE_BY_CF:
            friendly = PHASE_BY_CF[key].friendly_name
            ctx.add(
                LintResult(
                    rule_id="M012",
                    severity=Severity.WARNING,
                    message=(
                        f"Cloudflare phase identifier {key!r} used instead of"
                        f" friendly name {friendly!r}"
                    ),
                    phase=key,
                    suggestion=f"Use {friendly!r} instead",
                )
            )
        elif key not in PHASE_BY_NAME:
            suggestion = suggest_phase(key)
            msg = f"Unknown top-level key {key!r}"
            fix = ""
            if suggestion:
                msg += f". Did you mean {suggestion!r}?"
                fix = f"Rename to {suggestion!r}"
            ctx.add(
                LintResult(
                    rule_id="M007",
                    severity=Severity.WARNING,
                    message=msg,
                    phase=key,
                    suggestion=fix,
                )
            )


def _check_phase_rules(phase_name: str, rules: Any, ctx: LintContext) -> None:
    """Validate rules list structure within a phase."""
    if not isinstance(rules, list):
        ctx.add(
            LintResult(
                rule_id="M010",
                severity=Severity.ERROR,
                message=f"Phase {phase_name!r} value must be a list, got {type(rules).__name__}",
                phase=phase_name,
            )
        )
        return

    seen_refs: set[str] = set()
    for i, rule in enumerate(rules):
        if not isinstance(rule, dict):
            ctx.add(
                LintResult(
                    rule_id="M011",
                    severity=Severity.ERROR,
                    message=f"Rule at index {i} must be a mapping, got {type(rule).__name__}",
                    phase=phase_name,
                )
            )
            continue

        ref = rule.get("ref")
        _check_rule_fields(phase_name, rule, i, ctx)

        # Check ref uniqueness
        if ref is not None and isinstance(ref, str) and ref:
            if ref in seen_refs:
                ctx.add(
                    LintResult(
                        rule_id="M003",
                        severity=Severity.ERROR,
                        message=f"Duplicate ref {ref!r} within phase",
                        phase=phase_name,
                        ref=ref,
                    )
                )
            seen_refs.add(ref)


def _check_rule_fields(phase_name: str, rule: dict, index: int, ctx: LintContext) -> None:
    """Check individual rule fields (M001-M006, M009)."""
    ref = rule.get("ref")
    ref_label = ref if isinstance(ref, str) and ref else f"index {index}"

    # M001: missing ref
    if "ref" not in rule:
        ctx.add(
            LintResult(
                rule_id="M001",
                severity=Severity.ERROR,
                message=f"Rule at index {index} is missing required 'ref' field",
                phase=phase_name,
            )
        )
    elif not isinstance(ref, str) or not ref:
        # M004: invalid ref type
        ctx.add(
            LintResult(
                rule_id="M004",
                severity=Severity.ERROR,
                message="Invalid 'ref' (must be a non-empty string)",
                phase=phase_name,
                ref=ref_label,
            )
        )

    # M002: missing expression
    if "expression" not in rule:
        ctx.add(
            LintResult(
                rule_id="M002",
                severity=Severity.ERROR,
                message="Rule is missing required 'expression' field",
                phase=phase_name,
                ref=ref_label,
            )
        )
    else:
        expr = rule["expression"]
        if not isinstance(expr, str) or not expr:
            # M005: invalid expression type
            ctx.add(
                LintResult(
                    rule_id="M005",
                    severity=Severity.ERROR,
                    message="Invalid 'expression' (must be a non-empty string)",
                    phase=phase_name,
                    ref=ref_label,
                )
            )
        elif len(expr) > _MAX_EXPRESSION_LENGTH:
            # M015: expression exceeds character limit
            ctx.add(
                LintResult(
                    rule_id="M015",
                    severity=Severity.ERROR,
                    message=(
                        f"Expression is {len(expr)} chars"
                        f" (Cloudflare limit: {_MAX_EXPRESSION_LENGTH})"
                    ),
                    phase=phase_name,
                    ref=ref_label,
                    field="expression",
                )
            )

    # M006: invalid enabled type
    if "enabled" in rule and not isinstance(rule["enabled"], bool):
        ctx.add(
            LintResult(
                rule_id="M006",
                severity=Severity.ERROR,
                message=(
                    f"'enabled' must be a boolean, got {type(rule['enabled']).__name__}"
                    f" ({rule['enabled']!r})"
                ),
                phase=phase_name,
                ref=ref_label,
                field="enabled",
            )
        )

    # M009: description too long
    desc = rule.get("description", "")
    if isinstance(desc, str) and len(desc) > _MAX_DESCRIPTION_LENGTH:
        ctx.add(
            LintResult(
                rule_id="M009",
                severity=Severity.WARNING,
                message=(
                    f"Description is {len(desc)} chars (max recommended: {_MAX_DESCRIPTION_LENGTH})"
                ),
                phase=phase_name,
                ref=ref_label,
                field="description",
            )
        )

    # M013 / M014: always-true / always-false expressions
    expr = rule.get("expression")
    if isinstance(expr, str):
        normalized_expr = normalize_expression(expr).lower()
        if is_always_true(normalized_expr):
            ctx.add(
                LintResult(
                    rule_id="M013",
                    severity=Severity.WARNING,
                    message="Expression is always true — this is a catch-all rule",
                    phase=phase_name,
                    ref=ref_label,
                    field="expression",
                    suggestion="Verify this is intentional (catch-all rules affect all traffic)",
                )
            )
        elif is_always_false(normalized_expr):
            ctx.add(
                LintResult(
                    rule_id="M014",
                    severity=Severity.WARNING,
                    message="Expression is always false — this rule will never match",
                    phase=phase_name,
                    ref=ref_label,
                    field="expression",
                    suggestion="Remove the rule or fix the expression",
                )
            )
