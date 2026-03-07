"""Custom ruleset validation — Category T rules.

Validates the structural correctness of custom_rulesets entries:
required fields, ID format, duplicate refs, etc.
"""

from __future__ import annotations

import re
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity

_HEX_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")


def lint_custom_rulesets(rules_data: dict[str, Any], ctx: LintContext) -> None:
    """Run all custom ruleset structural checks."""
    rulesets = rules_data.get("custom_rulesets")
    if not isinstance(rulesets, list):
        return

    if ctx.phase_filter and "custom_rulesets" not in ctx.phase_filter:
        return

    all_refs: dict[str, str] = {}  # ref → ruleset id (for T004)

    for i, entry in enumerate(rulesets):
        if not isinstance(entry, dict):
            continue

        rs_id = entry.get("id")
        rs_label = rs_id if isinstance(rs_id, str) and rs_id else f"index {i}"

        # T001: Missing required fields
        for field_name in ("id", "name", "phase"):
            val = entry.get(field_name)
            if val is None or (isinstance(val, str) and not val):
                ctx.add(
                    LintResult(
                        rule_id="T001",
                        severity=Severity.ERROR,
                        message=(
                            f"Custom ruleset at {rs_label} is missing required '{field_name}' field"
                        ),
                        phase="custom_rulesets",
                        ref=rs_label,
                    )
                )

        # T002: Invalid id format (should be 32-char hex)
        if isinstance(rs_id, str) and rs_id and not _HEX_ID_PATTERN.match(rs_id):
            ctx.add(
                LintResult(
                    rule_id="T002",
                    severity=Severity.WARNING,
                    message=(f"Custom ruleset id {rs_id!r} is not a valid 32-character hex string"),
                    phase="custom_rulesets",
                    ref=rs_label,
                    field="id",
                )
            )

        # T003: Duplicate ref within this ruleset
        rules = entry.get("rules")
        if isinstance(rules, list):
            seen_refs: set[str] = set()
            for rule in rules:
                if not isinstance(rule, dict):
                    continue
                ref = rule.get("ref")
                if not isinstance(ref, str) or not ref:
                    continue
                if ref in seen_refs:
                    ctx.add(
                        LintResult(
                            rule_id="T003",
                            severity=Severity.ERROR,
                            message=(f"Duplicate ref {ref!r} within custom ruleset {rs_label}"),
                            phase="custom_rulesets",
                            ref=ref,
                        )
                    )
                seen_refs.add(ref)

                # T004: Duplicate ref across custom rulesets
                if ref in all_refs and all_refs[ref] != rs_label:
                    ctx.add(
                        LintResult(
                            rule_id="T004",
                            severity=Severity.WARNING,
                            message=(f"Ref {ref!r} also appears in custom ruleset {all_refs[ref]}"),
                            phase="custom_rulesets",
                            ref=ref,
                        )
                    )
                all_refs[ref] = rs_label
