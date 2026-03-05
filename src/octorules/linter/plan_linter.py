"""Plan linter — plan-level entitlement checks (Category H).

Validates rules against Cloudflare plan tier limitations:
regex availability, rule count limits, Enterprise-only features.
"""

from __future__ import annotations

from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.linter.expression_bridge import parse_expression
from octorules.phases import KNOWN_NON_PHASE_KEYS, PHASE_BY_NAME

# Rule count limits per phase per plan tier
_RULE_LIMITS: dict[str, dict[str, int]] = {
    "free": {
        "redirect_rules": 10,
        "url_rewrite_rules": 10,
        "request_header_rules": 10,
        "response_header_rules": 10,
        "config_rules": 10,
        "origin_rules": 10,
        "cache_rules": 10,
        "compression_rules": 10,
        "waf_custom_rules": 5,
    },
    "pro": {
        "redirect_rules": 25,
        "url_rewrite_rules": 25,
        "request_header_rules": 25,
        "response_header_rules": 25,
        "config_rules": 25,
        "origin_rules": 25,
        "cache_rules": 25,
        "compression_rules": 25,
        "waf_custom_rules": 20,
    },
    "business": {
        "redirect_rules": 50,
        "url_rewrite_rules": 50,
        "request_header_rules": 50,
        "response_header_rules": 50,
        "config_rules": 50,
        "origin_rules": 50,
        "cache_rules": 50,
        "compression_rules": 50,
        "waf_custom_rules": 100,
    },
    # Enterprise has no hard limits (or very high limits)
}

# Plans where regex is available in expressions
_REGEX_PLANS = frozenset({"business", "enterprise"})


def lint_plan_tier(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Check rules against plan tier limitations."""
    plan = ctx.plan_tier

    for phase_name, rules in rules_data.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue

        # H002: Rule count exceeds plan limit
        limits = _RULE_LIMITS.get(plan, {})
        limit = limits.get(phase_name)
        if limit is not None and len(rules) > limit:
            ctx.add(
                LintResult(
                    rule_id="H002",
                    severity=Severity.WARNING,
                    message=(
                        f"Phase {phase_name!r} has {len(rules)} rules,"
                        f" exceeding {plan} plan limit of {limit}"
                    ),
                    phase=phase_name,
                )
            )

        # H001: Regex usage on plans that don't support it
        if plan not in _REGEX_PLANS:
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                expr = rule.get("expression", "")
                if not isinstance(expr, str):
                    continue
                info = parse_expression(expr)
                if info.has_regex:
                    ref = rule.get("ref", "")
                    ctx.add(
                        LintResult(
                            rule_id="H001",
                            severity=Severity.WARNING,
                            message=(
                                f"Regex operator used in expression, but {plan} plan"
                                " does not include regex support"
                                " (requires Business or Enterprise)"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
