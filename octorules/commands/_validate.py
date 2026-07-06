"""Validate command implementation."""

import logging

from octorules.commands._helpers import (
    _filter_desired_by_phase,
    _get_zones,
    _write_output_file,
)
from octorules.config import Config
from octorules.extensions import call_validate_extensions
from octorules.phases import KNOWN_NON_PHASE_KEYS, get_phase, iter_scoped_sections
from octorules.planner import (
    RuleValidationError,
    prepare_desired_rules,
    validate_custom_ruleset,
    validate_list_entry,
    warn_unknown_phase_keys,
)

log = logging.getLogger(__name__)


def cmd_validate(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    output_file: str | None = None,
) -> int:
    """Validate config and rules files offline (no API calls). Returns exit code."""
    zone_names = _get_zones(config, zone_filter)
    errors: list[str] = []
    validated_count = 0
    lines: list[str] = []

    for zone_name in zone_names:
        desired = _filter_desired_by_phase(config.load_zone_rules(zone_name), phase_filter)
        if not desired:
            rules_file = config.rules_dir / f"{zone_name}.yaml"
            label = "rules file empty" if rules_file.exists() else "rules file not found"
            msg = f"{zone_name}: {label} (skipped)"
            log.info("%s", msg)
            lines.append(msg)
            continue

        warn_unknown_phase_keys(desired, zone_name)

        for friendly_name, rules in desired.items():
            if friendly_name in KNOWN_NON_PHASE_KEYS:
                continue  # validated separately below
            try:
                phase = get_phase(friendly_name)
            except KeyError:
                continue  # already warned by warn_unknown_phase_keys
            try:
                prepare_desired_rules(rules, phase)
                msg = f"  {zone_name}/{friendly_name}: OK ({len(rules)} rule(s))"
                log.info("%s", msg)
                lines.append(msg)
                validated_count += 1
            except (RuleValidationError, ValueError, KeyError, TypeError) as e:
                msg = f"  {zone_name}/{friendly_name}: {e}"
                errors.append(msg)

        # Validate custom_rulesets entries (plain and namespace-scoped)
        for ns, custom_rulesets in iter_scoped_sections(desired, "custom_rulesets"):
            if not isinstance(custom_rulesets, list):
                continue
            section_label = f"{ns}:custom_rulesets" if ns else "custom_rulesets"
            for i, entry in enumerate(custom_rulesets):
                try:
                    validate_custom_ruleset(entry, i)
                    rs_name = entry.get("name", entry.get("id", f"index {i}"))
                    n_rules = len(entry.get("rules", []))
                    msg = f"  {zone_name}/custom_ruleset:{rs_name}: OK ({n_rules} rule(s))"
                    log.info("%s", msg)
                    lines.append(msg)
                    validated_count += 1
                except RuleValidationError as e:
                    msg = f"  {zone_name}/{section_label}: {e}"
                    errors.append(msg)

        # Validate lists entries (plain and namespace-scoped)
        for ns, lists_entries in iter_scoped_sections(desired, "lists"):
            if not isinstance(lists_entries, list):
                continue
            section_label = f"{ns}:lists" if ns else "lists"
            for i, entry in enumerate(lists_entries):
                try:
                    validate_list_entry(entry, i)
                    list_name = entry.get("name", f"index {i}")
                    n_items = len(entry.get("items", []))
                    msg = f"  {zone_name}/list:{list_name}: OK ({n_items} item(s))"
                    log.info("%s", msg)
                    lines.append(msg)
                    validated_count += 1
                except RuleValidationError as e:
                    msg = f"  {zone_name}/{section_label}: {e}"
                    errors.append(msg)

        # Validate extension entries (e.g. page_shield_policies)
        pre_lines = len(lines)
        call_validate_extensions(desired, zone_name, errors, lines)
        validated_count += len(lines) - pre_lines

    if errors:
        log.error("Validation errors:")
        for err in errors:
            log.error("%s", err)
            lines.append(f"ERROR: {err}")
    elif validated_count == 0:
        log.warning("No rules found to validate")
        lines.append("No rules found to validate")
    else:
        log.info("All rules valid.")
        lines.append("All rules valid.")

    if output_file:
        if not _write_output_file(output_file, lambda f: f.write("\n".join(lines) + "\n")):
            return 1

    if errors:
        return 1
    return 0
