"""Lint engine — orchestrates all linter modules and produces a unified report."""

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

from octorules.linter.suppressions import is_suppressed
from octorules.registration import idempotent_registration

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
    location: str = ""  # YAML source location, e.g. "example.com.yaml:106"

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
    # Most-permissive default: lint assumes every plan-gated feature is
    # available, so entitlement checks only fire when a stricter tier is
    # set explicitly.  Semantics are generic (vocabulary is CF-derived);
    # providers without tiered plans never read it.
    plan_tier: str = "enterprise"  # free, pro, business, enterprise
    severity_filter: Severity = Severity.INFO  # show this severity and above
    phase_filter: list[str] | None = None
    rule_filter: list[str] | None = None  # specific rule IDs to check
    suppressions: dict[str, set[str]] = field(default_factory=dict)
    #: Enabled rule sets.  None means "every rule", which is what a caller
    #: that has no config (a single-file lint, a provider's own tests) gets.
    enabled_sets: frozenset[str] | None = None
    results: list[LintResult] = field(default_factory=list)
    suppressed_count: int = 0
    #: Directives that named a rule but could not waive it, and why —
    #: reported as CORE012 so a no-op suppression does not sit unnoticed.
    ineffective_suppressions: list[tuple[str, str]] = field(default_factory=list)
    _current_location: str = ""  # set by linter before processing each rule

    def _rule_is_active(self, rule_id: str) -> bool:
        """Whether *rule_id* belongs to an enabled set.

        Registers the core rules first: they load lazily, and without them
        set filtering would silently pass everything through depending on
        import order.
        """
        from octorules.linter.rules.registry import get_rule_meta

        _register_core_rules()
        meta = get_rule_meta(rule_id)
        if meta is None:
            return True  # undeclared rules always run
        return bool(meta.sets & set(self.enabled_sets or ()))

    def _note_ineffective(self, rule_id: str, reason: str) -> None:
        if (rule_id, reason) not in self.ineffective_suppressions:
            self.ineffective_suppressions.append((rule_id, reason))

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
        # `--rule X` is an explicit request for X, so it wins over the set
        # selection: asking for a rule and silently getting nothing back is
        # the sort of quiet no-op this filtering is meant to prevent.
        if (
            self.enabled_sets is not None
            and not (self.rule_filter and result.rule_id in self.rule_filter)
            and not self._rule_is_active(result.rule_id)
        ):
            return
        if self.suppressions and is_suppressed(self.suppressions, result.ref, result.rule_id):
            from octorules.linter.rules.registry import is_suppressible

            if not is_suppressible(result.rule_id):
                # A directive cannot waive this one; say so rather than
                # letting the author believe it took effect.
                self._note_ineffective(
                    result.rule_id,
                    f"{result.rule_id} cannot be suppressed in a zone file —"
                    " it decides whether plan manages this section."
                    " Exempt the zone in the config instead.",
                )
            else:
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
# CORE001/CORE005 are retired (moved to config-time validation) — do not reuse.
CORE_RULE_IDS: frozenset[str] = frozenset(
    {
        "CORE002",
        "CORE003",
        "CORE004",
        "CORE006",
        "CORE007",
        "CORE008",
        "CORE009",
        "CORE010",
        "CORE011",
        "CORE012",
    }
)


# Register core rules in the global registry so --list-rules shows them.
# Deferred to a function to avoid circular import (registry.py imports Severity
# from this module).  Called by get_known_rule_ids() and list_rules().
@idempotent_registration
def _register_core_rules() -> None:
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
            RuleMeta(
                "CORE007",
                "core",
                "Phase section fails the plan-time prepare pipeline",
                Severity.ERROR,
            ),
            RuleMeta("CORE008", "core", "Malformed lists entry", Severity.ERROR),
            RuleMeta("CORE009", "core", "Malformed custom_rulesets entry", Severity.ERROR),
            RuleMeta(
                "CORE010",
                "core",
                "Extension section fails its validation hook",
                Severity.ERROR,
            ),
            RuleMeta(
                "CORE011",
                "core",
                "Unknown zone-file section (would not be managed)",
                Severity.ERROR,
                # In both sets, for different reasons.  `default` keeps lint
                # reporting it always; `strict` is what makes *plan* enforce
                # it — drop strict and an unknown section warns instead of
                # aborting.
                # Not waivable from a zone file: this rule decides whether
                # plan manages a section, so a comment in a data file must
                # not switch off a deploy guard.  Exempt a zone through its
                # `lint:` config block instead.
                sets=frozenset({"default", "strict"}),
                suppressible=False,
            ),
            RuleMeta(
                "CORE012",
                "core",
                "Suppression directive has no effect",
                Severity.WARNING,
                # In every set: this reports on the user's own directives, and
                # one reason it fires is "no enabled set contains that rule".
                # Confining it to a set would let a set selection silence the
                # diagnostic that explains what that selection turned off.
                sets=frozenset({"default", "strict"}),
            ),
        ]
    )


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
    target_plugins: set[str] | None = None,
    enabled_sets: frozenset[str] | None = None,
) -> LintContext:
    """Run all lint checks on a zone rules file.

    Creates a ``LintContext`` and dispatches to registered lint plugins.
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
        target_plugins: Optional set of plugin names to run on this file.
            When provided, only registered plugins whose ``name`` is in
            the set are invoked — used by ``cmd_lint`` to route each
            zone's file to its target provider's plugin only, eliminating
            cross-provider schema collisions on shared top-level keys
            (``custom_rulesets``, ``lists``).  ``None`` runs every
            registered plugin (legacy behaviour).

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
        enabled_sets=enabled_sets,
    )

    for plugin in get_registered_plugins():
        if target_plugins is not None and plugin.name not in target_plugins:
            continue
        plugin.lint_fn(_plugin_view(rules_data, plugin.name), ctx)

    return ctx


def _plugin_view(rules_data: dict[str, Any], plugin_name: str) -> dict[str, Any]:
    """Unwrap a plugin's namespace-scoped core sections.

    Multi-provider files store ``lists`` / ``custom_rulesets`` per
    namespace (``"cloudflare:lists"``) while lint rules read the plain
    keys — each plugin gets its own sections unwrapped and the other
    namespaces' scoped sections hidden.  A plugin's name equals its
    provider's zone-file namespace by the package-name convention.
    Files without scoped sections (all single-provider files) pass
    through unchanged.
    """
    from octorules.phases import NAMESPACE_CORE_SECTIONS, PROVIDER_NAMESPACES

    scoped = [
        k
        for k in rules_data
        if "." in k
        and k.partition(".")[0] in PROVIDER_NAMESPACES
        and k.partition(".")[2] in NAMESPACE_CORE_SECTIONS
    ]
    if not scoped:
        return rules_data
    view = {k: v for k, v in rules_data.items() if k not in scoped}
    for key in scoped:
        ns, _, section = key.partition(".")
        if ns == plugin_name:
            view[section] = rules_data[key]
    return view
