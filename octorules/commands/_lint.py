"""Lint command implementation."""

from __future__ import annotations

import logging
import sys

from octorules._context import is_quiet
from octorules.commands._helpers import (
    _filter_desired_by_phase,
    _get_zones,
    _write_output_file,
)
from octorules.config import Config

log = logging.getLogger(__name__)


def cmd_lint(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    lint_format: str = "text",
    lint_severity: str = "info",
    lint_rules: list[str] | None = None,
    lint_plan: str | None = None,
    zone_plans: dict[str, str] | None = None,
    output_file: str | None = None,
    exit_code: bool = False,
) -> int:
    """Lint rules files for errors and warnings. Returns exit code."""
    from octorules.linter.engine import Severity, get_known_rule_ids, lint_zone_file
    from octorules.linter.plugin import get_registered_plugins
    from octorules.linter.report import FORMATTERS
    from octorules.linter.suppressions import parse_suppressions

    known_rules = get_known_rule_ids()

    plugins = get_registered_plugins()
    if plugins:
        log.info("Lint plugins: %s", ", ".join(p.name for p in plugins))
    else:
        log.info("No lint plugins registered (install a provider package for lint rules)")

    severity_map = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}
    severity = severity_map[lint_severity]
    formatter = FORMATTERS[lint_format]

    zone_names = _get_zones(config, zone_filter)
    all_results: list = []
    total_suppressed = 0
    has_errors = False
    has_warnings = False

    for zone_name in zone_names:
        desired = _filter_desired_by_phase(config.load_zone_rules(zone_name), phase_filter)
        if not desired:
            log.info("  %s: no rules file (skipped)", zone_name)
            continue

        rules_file = config.rules_dir / f"{zone_name}.yaml"
        # Resolve plan tier: explicit --plan > API-detected > "enterprise"
        if lint_plan is not None:
            plan_tier = lint_plan
        elif zone_plans and zone_name in zone_plans:
            plan_tier = zone_plans[zone_name]
        else:
            plan_tier = "enterprise"

        suppressions = parse_suppressions(rules_file, known_rules=known_rules)

        ctx = lint_zone_file(
            desired,
            file_path=str(rules_file),
            zone_name=zone_name,
            plan_tier=plan_tier,
            severity_filter=severity,
            phase_filter=phase_filter,
            rule_filter=lint_rules,
            suppressions=suppressions,
        )

        total_suppressed += ctx.suppressed_count

        if ctx.results:
            output = formatter(ctx)
            if output and not is_quiet():
                print(output, end="")
            all_results.extend(ctx.results)
            if ctx.has_errors:
                has_errors = True
            if ctx.has_warnings:
                has_warnings = True
        else:
            log.info("  %s: no issues found", zone_name)

    if output_file and all_results:
        # Re-create a combined context for file output
        from octorules.linter.engine import LintContext

        combined = LintContext(
            file_path=output_file,
            zone_name=", ".join(zone_names),
            plan_tier=lint_plan or "auto",
        )
        combined.results = all_results
        if not _write_output_file(output_file, lambda f: formatter(combined, f)):
            return 1

    # Print summary to stderr so it's always visible regardless of log level
    summary_parts: list[str] = []
    summary_parts.append(f"{len(all_results)} issue(s) found")
    if total_suppressed > 0:
        summary_parts.append(f"{total_suppressed} suppressed")
    print(f"Lint: {', '.join(summary_parts)}.", file=sys.stderr)

    if exit_code:
        if has_errors:
            return 1
        if has_warnings:
            return 2
    elif has_errors:
        return 1
    return 0
