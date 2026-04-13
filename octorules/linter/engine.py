"""Lint engine — orchestrates all linter modules and produces a unified report."""

import logging
import threading
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from octorules.linter.suppressions import is_suppressed

log = logging.getLogger(__name__)


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

    rule_id: str  # e.g. "CF003", "CF203"
    severity: Severity
    message: str
    phase: str = ""  # friendly phase name, empty for file-level
    ref: str = ""  # rule ref, empty for phase-level
    field: str = ""  # specific field path, e.g. "action_parameters.edge_ttl.default"
    suggestion: str = ""  # optional fix suggestion
    location: str = ""  # YAML source location, e.g. "doctena.com.yaml:106"

    def __str__(self) -> str:
        parts = [f"[{self.severity.name}]", self.rule_id]
        if self.phase:
            parts.append(f"({self.phase}")
            if self.ref:
                parts.append(f"/ {self.ref}")
            if self.location:
                parts.append(f"/ {self.location}")
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
    _current_location: str = ""  # set by linter before processing each rule

    def set_location(self, rule_or_dict: object) -> None:
        """Set current YAML source location from a ContextDict rule.

        Call this before emitting results for a rule so ``add()`` auto-populates
        the ``location`` field.
        """
        self._current_location = getattr(rule_or_dict, "context", "")

    def clear_location(self) -> None:
        """Clear the current location (e.g. after processing a rule)."""
        self._current_location = ""

    def add(self, result: LintResult) -> None:
        """Add a result if it passes filters and is not suppressed.

        Auto-populates ``location`` from the current context if not already set.
        """
        if result.severity > self.severity_filter:
            return
        if self.rule_filter and result.rule_id not in self.rule_filter:
            return
        if self.phase_filter and result.phase and result.phase not in self.phase_filter:
            return
        if self.suppressions and is_suppressed(self.suppressions, result.ref, result.rule_id):
            self.suppressed_count += 1
            return
        # Auto-populate location if the result doesn't have one
        if not result.location and self._current_location:
            result = LintResult(
                rule_id=result.rule_id,
                severity=result.severity,
                message=result.message,
                phase=result.phase,
                ref=result.ref,
                field=result.field,
                suggestion=result.suggestion,
                location=self._current_location,
            )
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

    @property
    def has_warnings(self) -> bool:
        return any(r.severity == Severity.WARNING for r in self.results)


def check_catch_all(
    expr: str,
    phase_name: str,
    ref: str,
    ctx: LintContext,
    *,
    entity: str = "rule",
    always_true_id: str = "M013",
    always_false_id: str = "M014",
) -> None:
    """Detect always-true / always-false expressions.

    Args:
        expr: Raw expression string (must be a non-empty str).
        phase_name: Phase friendly name for the lint result.
        ref: Rule ref or policy description label.
        ctx: Lint context to add results to.
        entity: "rule" or "policy" — used in the message text.
        always_true_id: Rule ID for the always-true diagnostic.
        always_false_id: Rule ID for the always-false diagnostic.
    """
    from octorules.expression import normalize_expression

    normalized = normalize_expression(expr).lower()
    if is_always_true(normalized):
        ctx.add(
            LintResult(
                rule_id=always_true_id,
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
                rule_id=always_false_id,
                severity=Severity.WARNING,
                message=f"Expression is always false — this {entity} will never match",
                phase=phase_name,
                ref=ref,
                field="expression",
                suggestion=f"Remove the {entity} or fix the expression",
            )
        )


# Core rule IDs (provider-agnostic, always available).
CORE_RULE_IDS: frozenset[str] = frozenset({"CORE002", "CORE003", "CORE004", "CORE006"})

# Register core rules in the global registry so --list-rules shows them.
# Deferred to a function to avoid circular import (registry.py imports Severity
# from this module).  Called by get_known_rule_ids() and list_rules().
_core_rules_registered = False
_core_rules_lock = threading.Lock()


def _register_core_rules() -> None:
    global _core_rules_registered
    with _core_rules_lock:
        if _core_rules_registered:
            return

        from octorules.linter.rules.registry import RuleMeta, register_rules

        register_rules(
            [
                RuleMeta(
                    "CORE002",
                    "core",
                    "Orphaned rules file (no matching zone in config)",
                    Severity.WARNING,
                ),
                RuleMeta("CORE003", "core", "All rules in phase are disabled", Severity.WARNING),
                RuleMeta("CORE004", "core", "Same ref used in multiple phases", Severity.WARNING),
                RuleMeta("CORE006", "core", "Rules file has no actual rules", Severity.INFO),
            ]
        )
        _core_rules_registered = True


def get_known_rule_ids() -> frozenset[str]:
    """Return the union of all rule IDs from registered lint plugins + core rules."""
    _register_core_rules()
    from octorules.linter.plugin import get_registered_plugins

    ids: set[str] = set(CORE_RULE_IDS)
    for plugin in get_registered_plugins():
        ids |= plugin.rule_ids
    return frozenset(ids)


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

    Creates a ``LintContext`` and dispatches to all registered lint plugins.
    Each plugin's ``lint_fn(rules_data, ctx)`` mutates the context directly.

    When no plugins are registered (i.e. no provider packages installed),
    returns an empty context.

    Args:
        rules_data: Parsed YAML data — phase friendly names as keys mapping
            to rule lists, plus optional provider-specific keys.
        file_path: Path to the source file (for reporting).
        zone_name: Zone name (for reporting).
        plan_tier: Plan tier for entitlement checks.
        severity_filter: Minimum severity to report.
        phase_filter: Only lint these phases (friendly names).
        rule_filter: Only check these rule IDs.
        suppressions: Map of ref (or ``"*"``) to suppressed rule IDs,
            typically from ``parse_suppressions()``.

    Returns:
        LintContext with accumulated ``results`` (list of ``LintResult``).
    """
    from octorules.linter.plugin import get_registered_plugins

    ctx = LintContext(
        file_path=file_path,
        zone_name=zone_name,
        plan_tier=plan_tier,
        severity_filter=severity_filter,
        phase_filter=phase_filter,
        rule_filter=rule_filter,
        suppressions=suppressions or {},
    )

    for plugin in get_registered_plugins():
        plugin.lint_fn(rules_data, ctx)

    return ctx
