"""Cross-rule linter — ruleset-level analysis (Category P).

Detects issues that only become visible when analyzing multiple rules together:
duplicate expressions, unreachable rules after terminating actions, etc.
"""

from __future__ import annotations

import functools
import re
from typing import Any

from octorules.expression import normalize_expression
from octorules.linter.engine import LintContext, LintResult, Severity, is_always_true
from octorules.phases import KNOWN_NON_PHASE_KEYS, PHASE_BY_NAME

RULE_IDS = frozenset({"P001", "P002", "P003", "P004", "P005"})

# Pattern for list references in expressions: $list_name (including dotted managed list names)
_LIST_REF_PATTERN = re.compile(r"\$([a-zA-Z_][a-zA-Z0-9_.]*)")


@functools.lru_cache(maxsize=1)
def _get_managed_lists() -> frozenset[str]:
    """Load valid managed list names from overlay.toml (cached)."""
    from octorules.linter.schemas._registry import load_managed_lists

    return load_managed_lists()


@functools.lru_cache(maxsize=1)
def _get_managed_list_kinds() -> dict[str, str]:
    """Load managed list name → kind mapping from overlay.toml (cached)."""
    from octorules.linter.schemas._registry import load_managed_list_kinds

    return load_managed_list_kinds()


# Actions that terminate request processing (subsequent rules won't execute)
_TERMINATING_ACTIONS = frozenset(
    {
        "block",
        "challenge",
        "js_challenge",
        "managed_challenge",
        "redirect",
        "rewrite",
    }
)


def lint_cross_rules(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run cross-rule analysis on the entire rules file."""
    for phase_name, rules in rules_data.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        _check_duplicate_expressions(phase_name, rules, ctx)
        _check_unreachable_after_terminating(phase_name, rules, ctx)

    # P003: Check list references across all phases
    _check_list_references(rules_data, ctx)

    # P004: Check managed list references
    _check_managed_lists(rules_data, ctx)

    # P005: Check list type / field type compatibility
    _check_list_type_mismatch(rules_data, ctx)


def _check_duplicate_expressions(phase_name: str, rules: list[dict], ctx: LintContext) -> None:
    """P001: Detect rules with identical expressions within a phase.

    Rules that share the same expression but have different actions or
    action_parameters (e.g. managed ruleset deployments with different IDs)
    are not considered duplicates.
    """
    seen: dict[tuple[str, str, str], str] = {}  # (expr, action, ap_id) → first ref
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        expr = rule.get("expression")
        if not isinstance(expr, str) or not expr:
            continue
        ref = rule.get("ref", "")
        action = str(rule.get("action", ""))
        ap = rule.get("action_parameters")
        ap_id = str(ap.get("id", "")) if isinstance(ap, dict) else ""

        normalized = normalize_expression(expr)
        key = (normalized, action, ap_id)
        if key in seen:
            ctx.add(
                LintResult(
                    rule_id="P001",
                    severity=Severity.WARNING,
                    message=(f"Duplicate expression — same as rule {seen[key]!r}"),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                )
            )
        else:
            seen[key] = ref


def _check_unreachable_after_terminating(
    phase_name: str, rules: list[dict], ctx: LintContext
) -> None:
    """P002: Detect rules that are unreachable after a 'true' + terminating action."""
    found_always_true_terminating = False
    terminating_ref = ""
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        ref = rule.get("ref", "")
        expr = rule.get("expression", "")
        action = rule.get("action", "")
        enabled = rule.get("enabled", True)

        if not enabled:
            continue

        if found_always_true_terminating:
            ctx.add(
                LintResult(
                    rule_id="P002",
                    severity=Severity.WARNING,
                    message=(
                        f"Rule is unreachable — preceded by always-true terminating rule"
                        f" {terminating_ref!r}"
                    ),
                    phase=phase_name,
                    ref=ref,
                )
            )
            continue

        # Check if this rule is always-true with a terminating action
        normalized_expr = normalize_expression(str(expr)).lower()
        if (
            is_always_true(normalized_expr)
            and isinstance(action, str)
            and action in _TERMINATING_ACTIONS
        ):
            found_always_true_terminating = True
            terminating_ref = ref


def _check_list_references(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """P003: Detect list references ($name) that don't exist in the lists section."""
    # Collect defined list names from the 'lists' section
    defined_lists: set[str] = set()
    lists_section = rules_data.get("lists")
    if isinstance(lists_section, list):
        for item in lists_section:
            if isinstance(item, dict):
                name = item.get("name", "")
                if name:
                    defined_lists.add(name)

    # Scan all expressions for $name references
    for phase_name, rules in rules_data.items():
        if not isinstance(rules, list):
            continue
        if phase_name == "lists":
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            expr = rule.get("expression", "")
            if not isinstance(expr, str):
                continue
            ref = rule.get("ref", "")
            for m in _LIST_REF_PATTERN.finditer(expr):
                list_name = m.group(1)
                # Skip managed list names (contain dots) — checked by P004
                if "." in list_name:
                    continue
                if list_name not in defined_lists:
                    ctx.add(
                        LintResult(
                            rule_id="P003",
                            severity=Severity.WARNING,
                            message=(f"List reference '${list_name}' not found in 'lists' section"),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )


def _check_managed_lists(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """P004: Detect invalid managed list references ($cf.*)."""
    for phase_name, rules in rules_data.items():
        if not isinstance(rules, list):
            continue
        if phase_name == "lists":
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            expr = rule.get("expression", "")
            if not isinstance(expr, str):
                continue
            ref = rule.get("ref", "")
            for m in _LIST_REF_PATTERN.finditer(expr):
                list_name = m.group(1)
                # Only check dotted names that start with cf.
                if not list_name.startswith("cf."):
                    continue
                managed = _get_managed_lists()
                if list_name not in managed:
                    ctx.add(
                        LintResult(
                            rule_id="P004",
                            severity=Severity.WARNING,
                            message=(
                                f"Unknown managed list '${list_name}'."
                                " Valid managed lists:"
                                f" {', '.join(sorted('$' + n for n in managed))}"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=(
                                "If this is a newly added Cloudflare managed list,"
                                " update the [managed_lists] section in overlay.toml"
                            ),
                        )
                    )


# Mapping from list kind to the set of compatible field prefixes
_LIST_KIND_FIELD_MAP: dict[str, frozenset[str]] = {
    "ip": frozenset({"ip.src"}),
    "asn": frozenset({"ip.src.asnum", "ip.geoip.asnum"}),
    "hostname": frozenset({"http.request.full_uri", "http.host"}),
    "redirect": frozenset({"http.request.full_uri"}),
}

# Pattern: field in $list_name or field not in $list_name (dots allowed for managed lists)
_FIELD_LIST_REF_PATTERN = re.compile(r"([\w.]+)\s+(?:not\s+)?in\s+\$([a-zA-Z_][a-zA-Z0-9_.]*)")


def _check_list_type_mismatch(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """P005: Detect list references where the field type doesn't match the list kind."""
    # Build kind map from lists section + managed lists
    list_kinds: dict[str, str] = dict(_get_managed_list_kinds())
    lists_section = rules_data.get("lists")
    if isinstance(lists_section, list):
        for item in lists_section:
            if isinstance(item, dict):
                name = item.get("name", "")
                kind = item.get("kind", "")
                if name and isinstance(kind, str):
                    list_kinds[name] = kind

    if not list_kinds:
        return

    for phase_name, rules in rules_data.items():
        if not isinstance(rules, list):
            continue
        if phase_name == "lists":
            continue
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            expr = rule.get("expression", "")
            if not isinstance(expr, str):
                continue
            ref = rule.get("ref", "")
            for m in _FIELD_LIST_REF_PATTERN.finditer(expr):
                field_name = m.group(1)
                list_name = m.group(2)
                kind = list_kinds.get(list_name)
                if kind is None:
                    continue  # unknown list, P003 handles this
                compatible_fields = _LIST_KIND_FIELD_MAP.get(kind)
                if compatible_fields is None:
                    continue
                if field_name not in compatible_fields:
                    ctx.add(
                        LintResult(
                            rule_id="P005",
                            severity=Severity.WARNING,
                            message=(
                                f"Field {field_name!r} used with ${list_name}"
                                f" (kind: {kind!r}) — expected field:"
                                f" {', '.join(sorted(compatible_fields))}"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
