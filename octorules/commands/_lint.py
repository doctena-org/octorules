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
    CORE007: A phase section fails the plan-time prepare pipeline.
    CORE008: Malformed ``lists`` entry.
    CORE009: Malformed ``custom_rulesets`` entry.
    CORE010: An extension section fails its registered validation hook.
    CORE011: A section plan/sync would skip entirely.
    """
    import copy

    from octorules.extensions import call_validate_extensions
    from octorules.phases import (
        KNOWN_NON_PHASE_KEYS,
        PHASE_BY_NAME,
        PROVIDER_NAMESPACES,
        display_phase_name,
        get_phase,
        iter_scoped_sections,
        suggest_namespace_member,
        suggest_phase,
    )
    from octorules.planner import (
        RuleValidationError,
        prepare_desired_rules,
        validate_custom_ruleset,
        validate_list_entry,
    )

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

    # CORE007: run the real plan-time prepare pipeline per phase section —
    # the same code plan/sync executes, so lint reproduces prepare-time
    # failures offline. The deep copy keeps provider prepare hooks away
    # from the shared rules cache that later plan runs read.
    for phase_name, rules in desired.items():
        if phase_name in KNOWN_NON_PHASE_KEYS or not isinstance(rules, list):
            continue
        try:
            phase = get_phase(phase_name)
        except KeyError:
            continue  # unknown sections are flagged at plan time
        try:
            prepare_desired_rules(copy.deepcopy(rules), phase)
        except Exception as e:
            detail = str(e) if isinstance(e, RuleValidationError) else repr(e)
            ctx.add(
                LintResult(
                    rule_id="CORE007",
                    severity=Severity.ERROR,
                    message=f"Section fails plan-time prepare: {detail}",
                    phase=phase_name,
                )
            )

    # CORE008/CORE009: shape checks for core sections (plain and
    # namespace-scoped) — the same validators plan runs.
    for rule_id, section, validate in (
        ("CORE008", "lists", validate_list_entry),
        ("CORE009", "custom_rulesets", validate_custom_ruleset),
    ):
        for ns, entries in iter_scoped_sections(desired, section):
            if not isinstance(entries, list):
                continue
            label = f"{ns}.{section}" if ns else section
            for i, entry in enumerate(entries):
                try:
                    validate(entry, i)
                except Exception as e:
                    detail = str(e) if isinstance(e, RuleValidationError) else repr(e)
                    if isinstance(entry, dict):
                        ctx.set_location(entry)
                    ctx.add(
                        LintResult(
                            rule_id=rule_id,
                            severity=Severity.ERROR,
                            message=f"{label}: {detail}",
                        )
                    )
                    ctx.clear_location()

    # CORE011: sections plan/sync would skip outright.  The condition
    # mirrors the plan-time skip set exactly (`check_zone_sections`):
    # anything that is neither a registered phase (aliases included) nor a
    # known non-phase key is silently unmanaged, so lint must fail on it —
    # provider plugins cannot own this check because only the zone's own
    # target plugin runs, and four of the five providers have no file-level
    # unknown-section rule at all.
    # A plugin that already reported on a key knows more about it than core
    # does — CF010's removed-alias table and CF014's provider-id spellings
    # both name the exact replacement — so don't stack a generic error on
    # top.  Plugins run before this pass, so their findings are already in
    # ctx.results.  (A plugin finding the user suppressed is treated as
    # claimed too; suppress CORE011 alongside it if the section is
    # deliberate.)
    claimed = {r.phase for r in ctx.results if r.phase}
    for key in sorted(desired):
        if key in PHASE_BY_NAME or key in KNOWN_NON_PHASE_KEYS or key in claimed:
            continue
        ns, sep, member = key.partition(":")
        if sep and ns in PROVIDER_NAMESPACES:
            message = (
                f"Unknown section {display_phase_name(key)!r} — {member!r} is not a"
                f" section of the {ns!r} namespace; it will not be managed"
            )
            # Match against the namespace's own member names, not the flat
            # registry — nested spellings differ from flat friendly names.
            hint = suggest_namespace_member(ns, member)
            dotted = f"{ns}.{hint}" if hint else ""
            suggestion = f"Rename to {dotted!r}" if hint else ""
            if hint:
                message += f". Did you mean {dotted!r}?"
        else:
            message = f"Unknown top-level section {key!r} — it will not be managed"
            hint = suggest_phase(key)
            suggestion = f"Rename to {display_phase_name(hint)!r}" if hint else ""
            if hint:
                message += f". Did you mean {display_phase_name(hint)!r}?"
        ctx.add(
            LintResult(
                rule_id="CORE011",
                severity=Severity.ERROR,
                message=message,
                phase=key,
                suggestion=suggestion,
            )
        )

    # CORE010: registered validate-extension hooks (e.g. Page Shield).
    ext_errors: list[str] = []
    try:
        call_validate_extensions(desired, ctx.zone_name, ext_errors, [])
    except Exception as e:
        ext_errors.append(f"validate extension raised: {e!r}")
    for err in ext_errors:
        ctx.add(
            LintResult(
                rule_id="CORE010",
                severity=Severity.ERROR,
                message=err.strip(),
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


def list_rules(fmt: str = "text", filters: list[str] | None = None) -> int:
    """List all available lint rules and return exit code 0.

    When *filters* is provided, only rules whose ID starts with one of the
    filter prefixes are shown (e.g. ``["CF", "CORE"]``).

    Core rules are registered lazily to avoid circular imports.
    """
    import json as _json

    from octorules.linter.engine import _register_core_rules
    from octorules.linter.rules.registry import RULE_REGISTRY

    _register_core_rules()
    rules = sorted(RULE_REGISTRY.values(), key=lambda r: r.rule_id)
    if filters:
        prefixes = tuple(f.upper() for f in filters)
        rules = [r for r in rules if r.rule_id.upper().startswith(prefixes)]

    if fmt == "json":
        data = [
            {
                "id": r.rule_id,
                "category": r.category,
                "severity": r.default_severity.name,
                "description": r.description,
            }
            for r in rules
        ]
        print(_json.dumps({"rules": data, "total": len(data)}, indent=2))
    else:
        # Text table with minimum column widths matching header labels
        id_w = max(7, *(len(r.rule_id) for r in rules)) if rules else 7
        sev_w = 8  # len("SEVERITY")
        cat_w = max(8, *(len(r.category) for r in rules)) if rules else 8
        print(f"{'RULE_ID':<{id_w}}  {'SEVERITY':<{sev_w}}  {'CATEGORY':<{cat_w}}  DESCRIPTION")
        print(f"{'-------':<{id_w}}  {'--------':<{sev_w}}  {'--------':<{cat_w}}  -----------")
        for r in rules:
            print(
                f"{r.rule_id:<{id_w}}  {r.default_severity.name:<{sev_w}}  "
                f"{r.category:<{cat_w}}  {r.description}"
            )
        print(f"\n{len(rules)} rule(s) available.")
    return 0


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

    total_zones = len(all_stems)
    log.debug("Linting %d zone(s)", total_zones)
    for zi, zone_name in enumerate(all_stems, 1):
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

        # Per-zone plugin routing: when the zone declares a target provider,
        # only that provider's lint plugin runs on this file. Stops the AWS
        # plugin from validating Cloudflare's `custom_rulesets` block (and
        # vice versa) when both packages are installed and the rules
        # directory holds files for multiple providers. Files without a
        # zone config (extra_stems below) get `None` → all plugins run,
        # the legacy behaviour.
        target_plugins = config.target_plugins_for_zone(zone_name)

        ctx = lint_zone_file(
            desired,
            file_path=str(rules_file),
            zone_name=zone_name,
            plan_tier=plan_tier,
            severity_filter=severity,
            phase_filter=phase_filter,
            rule_filter=lint_rules,
            suppressions=suppressions,
            target_plugins=target_plugins,
        )

        # Core rules (provider-agnostic, run after provider plugins)
        _core_lint_zone(desired, ctx)
        log.debug("Linted %s: %d result(s)", zone_name, len(ctx.results))

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

        if total_zones > 1:
            log.debug("  [%d/%d] linted %s", zi, total_zones, zone_name)

    # CORE002: orphaned rules files (after all zones processed).
    # Skip when --zone filter is used (user chose specific zones).
    orphaned = _core_lint_orphaned_files(config, processed_stems) if not zone_filter else []
    if orphaned:
        all_results.extend(orphaned)
        # Format orphaned results through the same formatter for consistent output
        from octorules.linter.engine import LintContext as _LC

        orphan_ctx = _LC(file_path="(orphaned files)", zone_name="(orphaned)")
        orphan_ctx.results = orphaned
        output = formatter(orphan_ctx)
        if output and not is_quiet():
            print(output, end="")
        for r in orphaned:
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

    # Print summary to stderr (suppressed by --quiet)
    summary_parts: list[str] = []
    summary_parts.append(f"{len(all_results)} issue(s) found")
    if total_suppressed > 0:
        summary_parts.append(f"{total_suppressed} suppressed")
    if not is_quiet():
        print(f"Lint: {', '.join(summary_parts)}.", file=sys.stderr)

    if exit_code:
        if has_errors:
            return 1
        if has_warnings:
            return 2
    elif has_errors:
        return 1
    return 0


def cmd_lint_file(
    file_path: str,
    *,
    lint_format: str = "text",
    lint_severity: str = "info",
    lint_rules: list[str] | None = None,
    output_file: str | None = None,
    exit_code: bool = False,
) -> int:
    """Lint a single rules file without a config file. Returns exit code."""
    from pathlib import Path

    import yaml

    from octorules.linter.engine import Severity, get_known_rule_ids, lint_zone_file
    from octorules.linter.report import FORMATTERS
    from octorules.linter.suppressions import parse_suppressions

    path = Path(file_path)
    if not path.exists():
        log.error("File not found: %s", file_path)
        return 1

    try:
        with open(path) as fh:
            desired = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        log.error("Failed to parse YAML: %s", e)
        return 1

    if not isinstance(desired, dict) or not desired:
        log.info("  %s: no rules found (empty or non-dict)", path.name)
        if not is_quiet():
            print("Lint: 0 issue(s) found.", file=sys.stderr)
        return 0

    # Flatten provider-namespace blocks so lint rules see the canonical keys.
    from octorules.config import ConfigError, normalize_zone_format

    try:
        desired = normalize_zone_format(desired, source=path.name)
    except ConfigError as e:
        log.error("%s", e)
        return 1

    zone_name = path.stem
    plan_tier = "enterprise"

    severity_map = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}
    severity = severity_map[lint_severity]
    formatter = FORMATTERS[lint_format]

    known_rules = get_known_rule_ids()
    suppressions = parse_suppressions(path, known_rules=known_rules)

    ctx = lint_zone_file(
        desired,
        file_path=str(path),
        zone_name=zone_name,
        plan_tier=plan_tier,
        severity_filter=severity,
        rule_filter=lint_rules,
        suppressions=suppressions,
    )

    # Core rules (provider-agnostic, run after provider plugins)
    _core_lint_zone(desired, ctx)

    has_errors = False
    has_warnings = False

    if ctx.results:
        output = formatter(ctx)
        if output and not is_quiet():
            print(output, end="")
        if ctx.has_errors:
            has_errors = True
        if ctx.has_warnings:
            has_warnings = True
    elif lint_format == "summary":
        output = formatter(ctx)
        if output and not is_quiet():
            print(output, end="")
    else:
        log.info("  %s: no issues found", zone_name)

    if output_file and ctx.results:
        if not _write_output_file(output_file, lambda f: formatter(ctx, f)):
            return 1

    # Print summary to stderr (suppressed by --quiet)
    summary_parts: list[str] = []
    summary_parts.append(f"{len(ctx.results)} issue(s) found")
    if ctx.suppressed_count > 0:
        summary_parts.append(f"{ctx.suppressed_count} suppressed")
    if not is_quiet():
        print(f"Lint: {', '.join(summary_parts)}.", file=sys.stderr)

    if exit_code:
        if has_errors:
            return 1
        if has_warnings:
            return 2
    elif has_errors:
        return 1
    return 0
