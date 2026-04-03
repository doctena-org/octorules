"""Lint command implementation."""

import logging
import sys

from octorules._context import is_quiet
from octorules.commands._helpers import (
    _filter_desired_by_phase,
    _get_zones,
    _write_output_file,
)
from octorules.config import Config
from octorules.linter.engine import LintContext, LintResult, Severity

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Core lint rules (provider-agnostic)
# ---------------------------------------------------------------------------
def _core_lint_zone(desired: dict, ctx: LintContext) -> None:
    """Run provider-agnostic lint checks on a single zone's rules.

    CORE003: All rules in a phase have ``enabled: false``.
    CORE004: Same ref string used in multiple phases.
    CORE006: Rules file has no actual rules (all phases empty).
    """
    from octorules.phases import KNOWN_NON_PHASE_KEYS

    all_refs: dict[str, list[str]] = {}  # ref -> list of phase names
    total_rules = 0

    for phase_name, rules in desired.items():
        if phase_name in KNOWN_NON_PHASE_KEYS:
            continue
        if not isinstance(rules, list):
            continue

        phase_rules = [r for r in rules if isinstance(r, dict)]
        total_rules += len(phase_rules)

        # CORE003: all rules disabled (only when 2+ rules — single disabled
        # rules are already covered by CF018/WA600 per-rule checks).
        if len(phase_rules) >= 2 and all(r.get("enabled") is False for r in phase_rules):
            ctx.add(
                LintResult(
                    rule_id="CORE003",
                    severity=Severity.WARNING,
                    message=(f"All {len(phase_rules)} rule(s) in {phase_name} are disabled"),
                    phase=phase_name,
                )
            )

        # Collect refs for CORE004
        for rule in phase_rules:
            ref = rule.get("ref")
            if isinstance(ref, str) and ref:
                all_refs.setdefault(ref, []).append(phase_name)

    # CORE004: ref collision across phases
    for ref, phases in all_refs.items():
        if len(phases) > 1:
            unique_phases = sorted(set(phases))
            if len(unique_phases) > 1:
                ctx.add(
                    LintResult(
                        rule_id="CORE004",
                        severity=Severity.WARNING,
                        message=(
                            f"Ref {ref!r} used in multiple phases: {', '.join(unique_phases)}"
                        ),
                        ref=ref,
                    )
                )

    # CORE006: empty rules file (no actual rules in any phase)
    if total_rules == 0:
        ctx.add(
            LintResult(
                rule_id="CORE006",
                severity=Severity.INFO,
                message="Rules file contains no rules (all phases empty)",
            )
        )


def _core_lint_orphaned_files(config: Config, processed_stems: set[str]) -> list[LintResult]:
    """CORE002: Detect rules files that weren't processed by lint.

    Compares rules dir contents against *processed_stems* — the set of
    file stems that were actually loaded and linted (both zone-scoped
    and account-scoped).  Files not in this set are flagged as orphans.
    """
    results: list[LintResult] = []
    for path in sorted(config.rules_dir.glob("*.yaml")):
        stem = path.stem
        if stem not in processed_stems:
            results.append(
                LintResult(
                    rule_id="CORE002",
                    severity=Severity.WARNING,
                    message=(
                        f"Rules file {path.name!r} does not match any configured zone"
                        " (file is ignored)"
                    ),
                )
            )
    return results


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
    if not plugins:
        log.info("No lint plugins registered (install a provider package for lint rules)")
    # Build rule_id → plugin name map for usage tracking.
    _rule_to_plugin: dict[str, str] = {}
    for p in plugins:
        for rid in p.rule_ids:
            _rule_to_plugin[rid] = p.name
    plugins_used: set[str] = set()

    severity_map = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}
    severity = severity_map[lint_severity]
    formatter = FORMATTERS[lint_format]

    zone_names = _get_zones(config, zone_filter)

    # Also discover account-scoped rules files (not in config.zones but
    # present in the rules directory).  Matches audit's behavior of
    # globbing all *.yaml files when no --zone filter is given.
    if zone_filter:
        all_stems = list(zone_names)
    else:
        configured = set(zone_names)
        extra_stems = sorted(
            p.stem for p in config.rules_dir.glob("*.yaml") if p.stem not in configured
        )
        all_stems = list(zone_names) + extra_stems

    all_results: list = []
    total_suppressed = 0
    has_errors = False
    has_warnings = False
    processed_stems: set[str] = set()

    for zone_name in all_stems:
        # Use load_rules_by_stem for account-scoped files not in config.zones.
        if zone_name in config.zones:
            raw_rules = config.load_zone_rules(zone_name)
        else:
            raw_rules = config.load_rules_by_stem(zone_name)
        desired = _filter_desired_by_phase(raw_rules, phase_filter)
        # Track as processed even if empty (not orphaned — file exists).
        processed_stems.add(zone_name)
        if not desired:
            rules_file = config.rules_dir / f"{zone_name}.yaml"
            if rules_file.exists():
                log.info("  %s: rules file empty (skipped)", zone_name)
            else:
                log.info("  %s: rules file not found (skipped)", zone_name)
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

        # Core rules (provider-agnostic, run after provider plugins)
        _core_lint_zone(desired, ctx)

        # Track which plugins were active (produced results or suppressed findings).
        if ctx.results or ctx.suppressed_count:
            for r in ctx.results:
                plugin_name = _rule_to_plugin.get(r.rule_id)
                if plugin_name:
                    plugins_used.add(plugin_name)
            # Suppressions also indicate the plugin ran — check suppression directives.
            for _ref, rule_ids in (suppressions or {}).items():
                for rid in rule_ids:
                    plugin_name = _rule_to_plugin.get(rid)
                    if plugin_name:
                        plugins_used.add(plugin_name)

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
        elif lint_format == "summary":
            # Summary format always prints a line per zone (even "clean").
            output = formatter(ctx)
            if output and not is_quiet():
                print(output, end="")
        else:
            log.info("  %s: no issues found", zone_name)

    # CORE002: orphaned rules files (after all zones processed).
    # Skip when --zone filter is used (user chose specific zones).
    orphaned = _core_lint_orphaned_files(config, processed_stems) if not zone_filter else []
    if orphaned:
        all_results.extend(orphaned)
        for r in orphaned:
            if not is_quiet():
                print(f"[{r.severity.name}] {r.rule_id} {r.message}")
            if r.severity == Severity.ERROR:
                has_errors = True
            elif r.severity == Severity.WARNING:
                has_warnings = True

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

    # Log which plugins were active vs unused.
    if plugins:
        labels = []
        for p in plugins:
            if p.name in plugins_used:
                labels.append(p.name)
            else:
                labels.append(f"{p.name} (unused)")
        log.info("Lint plugins: %s", ", ".join(labels))

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
