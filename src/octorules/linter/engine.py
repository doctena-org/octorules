"""Lint engine — orchestrates all linter modules and produces a unified report."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from octorules.linter.suppressions import is_suppressed
from octorules.phases import KNOWN_NON_PHASE_KEYS, PHASE_BY_NAME

log = logging.getLogger("octorules.linter")

# Expressions that are always true or always false (shared by yaml_validator and page_shield_linter)
ALWAYS_TRUE_EXPRESSIONS = frozenset({"true", "(true)", "((true))"})
ALWAYS_FALSE_EXPRESSIONS = frozenset({"false", "(false)", "((false))"})


def _strip_outer_parens(expr: str) -> str:
    """Strip balanced outer parentheses: '(((true)))' → 'true'."""
    while len(expr) >= 2 and expr[0] == "(" and expr[-1] == ")":
        # Verify the inner parens are balanced (the outer pair actually matches)
        depth = 0
        balanced = True
        for ch in expr[1:-1]:
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth < 0:
                    balanced = False
                    break
        if balanced and depth == 0:
            expr = expr[1:-1]
        else:
            break
    return expr


def is_always_true(normalized_lower_expr: str) -> bool:
    """Check if a normalized, lowercased expression is always true (any paren depth)."""
    return _strip_outer_parens(normalized_lower_expr) == "true"


def is_always_false(normalized_lower_expr: str) -> bool:
    """Check if a normalized, lowercased expression is always false (any paren depth)."""
    return _strip_outer_parens(normalized_lower_expr) == "false"


class Severity(IntEnum):
    """Lint result severity levels, ordered by importance."""

    ERROR = 1
    WARNING = 2
    INFO = 3


@dataclass(frozen=True)
class LintResult:
    """A single lint finding."""

    rule_id: str  # e.g. "M001", "C003"
    severity: Severity
    message: str
    phase: str = ""  # friendly phase name, empty for file-level
    ref: str = ""  # rule ref, empty for phase-level
    field: str = ""  # specific field path, e.g. "action_parameters.edge_ttl.default"
    suggestion: str = ""  # optional fix suggestion

    def __str__(self) -> str:
        parts = [f"[{self.severity.name}]", self.rule_id]
        if self.phase:
            parts.append(f"({self.phase}")
            if self.ref:
                parts.append(f"/ {self.ref}")
            parts[-1] += ")"
        parts.append(self.message)
        if self.suggestion:
            parts.append(f"[fix: {self.suggestion}]")
        return " ".join(parts)


@dataclass
class LintContext:
    """Context passed through linter modules during a lint run."""

    file_path: str = ""
    zone_name: str = ""
    plan_tier: str = "enterprise"  # free, pro, business, enterprise
    severity_filter: Severity = Severity.INFO  # show this severity and above
    phase_filter: list[str] | None = None
    rule_filter: list[str] | None = None  # specific rule IDs to check
    suppressions: dict[str, set[str]] = field(default_factory=dict)
    results: list[LintResult] = field(default_factory=list)
    suppressed_count: int = 0

    def add(self, result: LintResult) -> None:
        """Add a result if it passes filters and is not suppressed."""
        if result.severity > self.severity_filter:
            return
        if self.rule_filter and result.rule_id not in self.rule_filter:
            return
        if self.phase_filter and result.phase and result.phase not in self.phase_filter:
            return
        if self.suppressions and is_suppressed(self.suppressions, result.ref, result.rule_id):
            self.suppressed_count += 1
            return
        self.results.append(result)

    @property
    def errors(self) -> list[LintResult]:
        return [r for r in self.results if r.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[LintResult]:
        return [r for r in self.results if r.severity == Severity.WARNING]

    @property
    def has_errors(self) -> bool:
        return any(r.severity == Severity.ERROR for r in self.results)


def check_catch_all(
    expr: str,
    phase_name: str,
    ref: str,
    ctx: LintContext,
    *,
    entity: str = "rule",
) -> None:
    """M013/M014: detect always-true / always-false expressions.

    Args:
        expr: Raw expression string (must be a non-empty str).
        phase_name: Phase friendly name for the lint result.
        ref: Rule ref or policy description label.
        ctx: Lint context to add results to.
        entity: "rule" or "policy" — used in the message text.
    """
    from octorules.expression import normalize_expression

    normalized = normalize_expression(expr).lower()
    if is_always_true(normalized):
        ctx.add(
            LintResult(
                rule_id="M013",
                severity=Severity.WARNING,
                message=f"Expression is always true — this is a catch-all {entity}",
                phase=phase_name,
                ref=ref,
                field="expression",
                suggestion=f"Verify this is intentional (catch-all {entity}s affect all traffic)",
            )
        )
    elif is_always_false(normalized):
        ctx.add(
            LintResult(
                rule_id="M014",
                severity=Severity.WARNING,
                message=f"Expression is always false — this {entity} will never match",
                phase=phase_name,
                ref=ref,
                field="expression",
                suggestion=f"Remove the {entity} or fix the expression",
            )
        )


def _collect_known_rule_ids() -> frozenset[str]:
    """Collect all rule IDs from the RULE_IDS constants in each linter module."""
    from octorules.linter.action_validator import RULE_IDS as _av
    from octorules.linter.ast_linter import RULE_IDS as _al
    from octorules.linter.cross_rule_linter import RULE_IDS as _cr
    from octorules.linter.custom_ruleset_linter import RULE_IDS as _crl
    from octorules.linter.list_linter import RULE_IDS as _ll
    from octorules.linter.page_shield_linter import RULE_IDS as _psl
    from octorules.linter.phase_linter import RULE_IDS as _pl
    from octorules.linter.plan_linter import RULE_IDS as _pll
    from octorules.linter.yaml_validator import RULE_IDS as _yv

    return _av | _al | _cr | _crl | _ll | _psl | _pl | _pll | _yv


# Lazily cached — computed once on first access.
_known_rule_ids: frozenset[str] | None = None


def get_known_rule_ids() -> frozenset[str]:
    """Return the set of all known lint rule IDs."""
    global _known_rule_ids  # noqa: PLW0603
    if _known_rule_ids is None:
        _known_rule_ids = _collect_known_rule_ids()
    return _known_rule_ids


def lint_zone_file(
    rules_data: dict[str, Any],
    *,
    file_path: str = "",
    zone_name: str = "",
    plan_tier: str = "enterprise",
    severity_filter: Severity = Severity.INFO,
    phase_filter: list[str] | None = None,
    rule_filter: list[str] | None = None,
    suppressions: dict[str, set[str]] | None = None,
) -> LintContext:
    """Run all lint checks on a zone rules file.

    Runs four stages: YAML structure → per-rule checks (actions, expressions,
    phase restrictions) → plan-tier limits → cross-rule analysis.  When the
    optional ``octorules-wirefilter`` package is installed, expression checks
    use Cloudflare's actual wirefilter parser; otherwise a regex fallback
    provides best-effort field/operator extraction (fewer lint rules fire).

    Top-level keys ``custom_rulesets`` and ``page_shield_policies`` in
    *rules_data* are linted alongside phase sections.

    Args:
        rules_data: Parsed YAML data — phase friendly names as keys mapping
            to rule lists, plus optional ``custom_rulesets`` and
            ``page_shield_policies`` keys.
        file_path: Path to the source file (for reporting).
        zone_name: Zone name (for reporting).
        plan_tier: Cloudflare plan tier for entitlement checks.
        severity_filter: Minimum severity to report.
        phase_filter: Only lint these phases (friendly names).
        rule_filter: Only check these rule IDs.
        suppressions: Map of ref (or ``"*"``) to suppressed rule IDs,
            typically from ``parse_suppressions()``.

    Returns:
        LintContext with accumulated ``results`` (list of ``LintResult``).
    """
    from octorules.linter.action_validator import lint_actions
    from octorules.linter.ast_linter import lint_expressions
    from octorules.linter.cross_rule_linter import lint_cross_rules
    from octorules.linter.phase_linter import lint_phase_restrictions
    from octorules.linter.plan_linter import lint_plan_tier
    from octorules.linter.yaml_validator import lint_yaml_structure

    ctx = LintContext(
        file_path=file_path,
        zone_name=zone_name,
        plan_tier=plan_tier,
        severity_filter=severity_filter,
        phase_filter=phase_filter,
        rule_filter=rule_filter,
        suppressions=suppressions or {},
    )

    # Stage 1: YAML structure validation
    lint_yaml_structure(rules_data, ctx)

    # Stage 2: Per-phase, per-rule checks
    for phase_name, rules in rules_data.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue  # already flagged by yaml_validator
        if phase_filter and phase_name not in phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        phase = PHASE_BY_NAME[phase_name]
        for rule in rules:
            if not isinstance(rule, dict):
                continue

            # Action validation
            lint_actions(rule, phase, ctx)

            # Expression-level analysis
            lint_expressions(rule, phase, ctx)

            # Phase restriction checks
            lint_phase_restrictions(rule, phase, ctx)

    # Stage 2b: Custom ruleset rules (use waf_custom_rules phase for validation)
    from octorules.linter.custom_ruleset_linter import lint_custom_rulesets

    lint_custom_rulesets(rules_data, ctx)
    custom_rulesets = rules_data.get("custom_rulesets")
    if isinstance(custom_rulesets, list):
        waf_phase = PHASE_BY_NAME.get("waf_custom_rules")
        if waf_phase and (not phase_filter or "custom_rulesets" in phase_filter):
            for entry in custom_rulesets:
                if not isinstance(entry, dict):
                    continue
                for rule in entry.get("rules", []):
                    if not isinstance(rule, dict):
                        continue
                    lint_actions(rule, waf_phase, ctx)
                    lint_expressions(rule, waf_phase, ctx)
                    lint_phase_restrictions(rule, waf_phase, ctx)

    # Stage 2c: Page Shield policy checks
    from octorules.linter.page_shield_linter import lint_page_shield_policies

    lint_page_shield_policies(rules_data, ctx)

    # Stage 2d: List validation
    from octorules.linter.list_linter import lint_lists

    lint_lists(rules_data, ctx)

    # Stage 3: Plan-tier checks
    lint_plan_tier(rules_data, ctx)

    # Stage 4: Cross-rule analysis
    lint_cross_rules(rules_data, ctx)

    return ctx
