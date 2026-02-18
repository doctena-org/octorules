"""Export existing Cloudflare rules to YAML files."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from octorules.phases import CF_API_FIELDS, PHASE_BY_CF

log = logging.getLogger("octorules")


class _LiteralStr(str):
    """Marker subclass for strings that should use YAML literal block style."""


def _literal_representer(dumper: yaml.Dumper, data: _LiteralStr) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


_Dumper = type("_Dumper", (yaml.SafeDumper,), {})
_Dumper.add_representer(_LiteralStr, _literal_representer)


def dump_zone_rules(
    zone_name: str,
    rules_by_cf_phase: dict[str, list[dict]],
    output_dir: Path,
) -> Path | None:
    """Write a zone's rules to a YAML file.

    Returns the output path, or None on write failure.
    Zones with no rules produce a minimal ``---`` file.
    """
    output: dict[str, list[dict]] = {}

    for cf_phase, rules in rules_by_cf_phase.items():
        if cf_phase not in PHASE_BY_CF:
            continue
        phase = PHASE_BY_CF[cf_phase]
        cleaned_rules = [_clean_rule(rule, phase.default_action) for rule in rules]
        if cleaned_rules:
            output[phase.friendly_name] = cleaned_rules

    try:
        output_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log.error("Failed to create output directory %s: %s", output_dir, e)
        return None

    output_path = (output_dir / f"{zone_name}.yaml").resolve()
    # Prevent path traversal outside the output directory
    try:
        output_path.relative_to(output_dir.resolve())
    except ValueError:
        log.error("Zone name %r would write outside output directory", zone_name)
        return None

    try:
        with open(output_path, "w", encoding="utf-8") as f:
            if output:
                yaml.dump(
                    output,
                    f,
                    Dumper=_Dumper,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                    width=2147483647,
                    explicit_start=True,
                )
            else:
                f.write("--- {}\n")
                log.info("No rules found for %s, created empty file", zone_name)
    except OSError as e:
        log.error("Failed to write dump file %s: %s", output_path, e)
        return None

    return output_path


def _strip_trailing_whitespace(s: str) -> str:
    """Strip trailing whitespace from each line. PyYAML rejects block style otherwise."""
    return "\n".join(line.rstrip() for line in s.split("\n"))


def _literalize(value: object) -> object:
    """Recursively convert multiline strings to _LiteralStr for block style."""
    if isinstance(value, str) and "\n" in value:
        return _LiteralStr(_strip_trailing_whitespace(value))
    if isinstance(value, dict):
        return {k: _literalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_literalize(item) for item in value]
    return value


def _clean_rule(rule: dict, default_action: str | None) -> dict:
    """Remove API-only fields and optionally the action if it matches the default."""
    cleaned = {}
    for k, v in rule.items():
        if k in CF_API_FIELDS:
            continue
        # Skip action if it matches the phase default
        if k == "action" and default_action and v == default_action:
            continue
        cleaned[k] = _literalize(v)
    ordered = {}
    for key in ("ref", "description"):
        if key in cleaned:
            ordered[key] = cleaned.pop(key)
    ordered.update(cleaned)
    return ordered
