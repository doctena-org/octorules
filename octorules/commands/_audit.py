"""Audit command implementation."""

import logging
import sys

from octorules._context import is_quiet
from octorules.commands._helpers import _filter_desired_by_phase
from octorules.commands._providers import _ensure_provider_loaded
from octorules.config import Config

log = logging.getLogger(__name__)


def cmd_audit(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    checks: list[str] | None = None,
    cdn_timeout: int = 15,
    cdn_stale_days: int = 60,
    severity: str = "info",
    exit_code: bool = False,
    audit_format: str = "text",
    output_file: str | None = None,
) -> int:
    """Run audit checks on rules files. Returns exit code.

    Processes every ``*.yaml`` file in the rules directory, not just
    configured zones.

    Offline checks (ip-overlap, ip-shadow, zone-drift) analyse local YAML
    rules.  The cdn-ranges check fetches CDN IP ranges from the internet.

    *severity* controls minimum severity to display (default: show all).
    *exit_code* enables granular exit codes: 1 = errors, 2 = warnings.
    Without *exit_code*, only errors return non-zero (matching linter).
    """
    from octorules.audit import (
        _SEVERITY_RANK,
        ALL_CHECKS,
        AUDIT_FORMATTERS,
        FindingSeverity,
        RuleIPInfo,
        audit_zone_rules,
        parse_audit_acceptances,
        run_audit,
    )
    from octorules.phases import ALL_FRIENDLY_NAMES

    # Load only configured providers for audit extension registration,
    # without constructing provider instances (no API credentials needed).
    for prov_name in config.providers:
        _ensure_provider_loaded(prov_name)

    selected_checks = frozenset(checks) if checks else ALL_CHECKS
    invalid = selected_checks - ALL_CHECKS
    if invalid:
        log.error(
            "Unknown audit check(s): %s. Valid: %s",
            ", ".join(sorted(invalid)),
            ", ".join(sorted(ALL_CHECKS)),
        )
        return 1

    severity_map = {
        "error": FindingSeverity.ERROR,
        "warning": FindingSeverity.WARNING,
        "info": FindingSeverity.INFO,
    }
    min_severity = severity_map[severity]

    # Discover all rules files in the directory.  When --zone is given,
    # restrict to those names; otherwise glob every *.yaml file.
    if zone_filter:
        file_stems = list(zone_filter)
    else:
        file_stems = sorted(p.stem for p in config.rules_dir.glob("*.yaml"))
    if not file_stems:
        log.info("No rules files found in %s", config.rules_dir)
        return 0

    all_rule_ips: list[RuleIPInfo] = []
    phase_order = list(ALL_FRIENDLY_NAMES)

    # Parse audit acceptances from each rules file.
    accepted_by_zone: dict[str, dict[str, set[str]]] = {}
    for stem in file_stems:
        rules_file = config.rules_dir / f"{stem}.yaml"
        accepted = parse_audit_acceptances(rules_file)
        if accepted:
            accepted_by_zone[stem] = accepted
            checks_accepted = sorted({c for checks in accepted.values() for c in checks})
            log.info("  %s: accepted audit checks: %s", stem, ", ".join(checks_accepted))

    log.debug("Auditing %d zone(s)", len(file_stems))
    for stem in file_stems:
        rules_data = config.load_rules_by_stem(stem)
        desired = _filter_desired_by_phase(rules_data, phase_filter)
        if not desired:
            log.info("  %s: no rules (skipped)", stem)
            continue

        infos = audit_zone_rules(desired, stem)
        all_rule_ips.extend(infos)
        log.info("  %s: extracted %d rule(s) with IP ranges", stem, len(infos))

    if not all_rule_ips:
        log.info("No IP ranges found in any rules — nothing to audit.")
        return 0

    findings = run_audit(
        all_rule_ips,
        phase_order,
        checks=selected_checks,
        cdn_timeout=cdn_timeout,
        cdn_stale_days=cdn_stale_days,
    )

    # Apply suppressions: a finding is suppressed when its zone accepts the
    # check either file-wide ("*") or for the finding's specific rule anchor
    # (the ref the directive was placed above).
    total_suppressed = 0
    if accepted_by_zone:
        unsuppressed = []
        for f in findings:
            acc = accepted_by_zone.get(f.zone_name, {}) if f.zone_name else {}
            if f.check in acc.get(f.ref, set()) or f.check in acc.get("*", set()):
                total_suppressed += 1
            else:
                unsuppressed.append(f)
        findings = unsuppressed

    # Classify for exit code (based on unsuppressed findings).
    has_errors = any(f.severity == FindingSeverity.ERROR for f in findings)
    has_warnings = any(f.severity == FindingSeverity.WARNING for f in findings)

    # Format and display (respects min_severity filter).
    formatter = AUDIT_FORMATTERS[audit_format]
    fmt_kwargs: dict = {"min_severity": min_severity}
    if audit_format == "text" and not output_file:
        from octorules._color import supports_color

        fmt_kwargs["use_color"] = supports_color()
    output = formatter(findings, **fmt_kwargs)

    if output_file and output:
        from octorules.commands._helpers import _write_output_file

        if not _write_output_file(output_file, lambda f: f.write(output)):
            return 1
    elif output and not is_quiet():
        print(output)

    # Summary
    visible_count = len(
        [f for f in findings if _SEVERITY_RANK[f.severity] <= _SEVERITY_RANK[min_severity]]
    )
    if not is_quiet():
        summary_parts: list[str] = []
        summary_parts.append(f"{visible_count} issue(s) found")
        if total_suppressed:
            summary_parts.append(f"{total_suppressed} suppressed")
        print(f"Audit: {', '.join(summary_parts)}.", file=sys.stderr)

    # Exit code logic (mirrors linter).
    if exit_code:
        if has_errors:
            return 1
        if has_warnings:
            return 2
        return 0
    elif has_errors:
        return 1
    return 0
