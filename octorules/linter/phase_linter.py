"""Phase linter — field/function availability per phase (Category B).

Detects when fields or functions are used in phases where they're not available,
e.g. response fields in request phases, body fields without body access.
"""

from __future__ import annotations

from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.linter.expression_bridge import parse_expression
from octorules.linter.schemas.fields import (
    BODY_PHASES,
    RESPONSE_PHASES,
    get_field,
    is_body_field,
    is_response_field,
)
from octorules.phases import Phase

RULE_IDS = frozenset({"B001", "B002", "B003"})

# Plan tier hierarchy for comparison
_PLAN_TIERS = {"free": 0, "pro": 1, "business": 2, "enterprise": 3}

# Request-only phases (where response fields are NOT available)
_REQUEST_ONLY_PHASES = frozenset(
    {
        "redirect_rules",
        "url_rewrite_rules",
        "request_header_rules",
        "config_rules",
        "origin_rules",
        "cache_rules",
        "waf_custom_rules",
        "waf_managed_rules",
        "rate_limiting_rules",
        "bot_fight_rules",
        "http_ddos_rules",
        "bulk_redirect_rules",
        "url_normalization",
    }
)


def lint_phase_restrictions(
    rule: dict[str, Any], phase: Phase, ctx: LintContext, *, ref_override: str | None = None
) -> None:
    """Check field/function availability for the rule's phase."""
    expr = rule.get("expression")
    if not isinstance(expr, str) or not expr:
        return

    ref = ref_override or rule.get("ref", "")
    phase_name = phase.friendly_name

    info = parse_expression(expr)

    for field_name in info.fields_used:
        # B001: Response field in request-only phase
        if is_response_field(field_name) and phase_name in _REQUEST_ONLY_PHASES:
            ctx.add(
                LintResult(
                    rule_id="B001",
                    severity=Severity.WARNING,
                    message=(
                        f"Response field {field_name!r} used in request phase {phase_name!r}."
                        " This field is only available in response phases:"
                        f" {', '.join(sorted(RESPONSE_PHASES))}"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                )
            )

        # B002: Body field in phase without body access
        if is_body_field(field_name) and phase_name not in BODY_PHASES:
            ctx.add(
                LintResult(
                    rule_id="B002",
                    severity=Severity.WARNING,
                    message=(
                        f"Request body field {field_name!r} used in phase {phase_name!r}."
                        " Body fields are only available in:"
                        f" {', '.join(sorted(BODY_PHASES))}"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                )
            )

        # B003: Field requires a higher plan tier
        field_def = get_field(field_name)
        if field_def and field_def.requires_plan:
            current_level = _PLAN_TIERS.get(ctx.plan_tier, 3)
            required_level = _PLAN_TIERS.get(field_def.requires_plan, 0)
            if current_level < required_level:
                ctx.add(
                    LintResult(
                        rule_id="B003",
                        severity=Severity.WARNING,
                        message=(
                            f"Field {field_name!r} requires {field_def.requires_plan!r}"
                            f" plan, but current plan is {ctx.plan_tier!r}"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )
