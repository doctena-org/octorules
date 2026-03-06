"""Export existing Cloudflare rules to YAML files."""

from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml

from octorules.phases import (
    CF_API_FIELDS,
    LIST_ITEM_API_FIELDS,
    PAGE_SHIELD_POLICY_API_FIELDS,
    PHASE_BY_CF,
)

# Maximum YAML width — effectively disables line wrapping for expressions.
_YAML_NO_WRAP_WIDTH = 2147483647

log = logging.getLogger("octorules")


class _LiteralStr(str):
    """Marker subclass for strings that should use YAML literal block style."""


class _IncludeTag:
    """Marker for values that should be serialized as a YAML !include tag."""

    def __init__(self, path: str) -> None:
        self.path = path


def _literal_representer(dumper: yaml.Dumper, data: _LiteralStr) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


def _include_representer(dumper: yaml.Dumper, data: _IncludeTag) -> yaml.ScalarNode:
    return dumper.represent_scalar("!include", data.path, style="")


def _str_representer(dumper: yaml.Dumper, data: str) -> yaml.ScalarNode:
    """Use double-quoted style for strings containing single quotes."""
    if "'" in data:
        return dumper.represent_scalar("tag:yaml.org,2002:str", data, style='"')
    return dumper.represent_scalar("tag:yaml.org,2002:str", data)


_Dumper = type("_Dumper", (yaml.SafeDumper,), {})
_Dumper.add_representer(str, _str_representer)
_Dumper.add_representer(_LiteralStr, _literal_representer)
_Dumper.add_representer(_IncludeTag, _include_representer)


def _write_list_file(output_dir: Path, lists_dir: Path, list_name: str, entry: dict) -> str | None:
    """Write a full list entry (name, kind, description, items) to a file.

    Returns the relative include path (relative to ``output_dir``)
    or ``None`` if the write fails.
    """
    file_path = (lists_dir / f"{list_name}.yaml").resolve()
    # Prevent path traversal outside the lists directory
    try:
        file_path.relative_to(lists_dir.resolve())
    except ValueError:
        log.error("List name %r would write outside lists directory", list_name)
        return None
    try:
        lists_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        log.error("Failed to create lists directory %s: %s", lists_dir, e)
        return None
    try:
        text = yaml.dump(
            entry,
            None,
            Dumper=_Dumper,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
            width=_YAML_NO_WRAP_WIDTH,
        )
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(text)
    except OSError as e:
        log.error("Failed to write list file %s: %s", file_path, e)
        return None
    return os.path.relpath(file_path, output_dir)


def dump_zone_rules(
    zone_name: str,
    rules_by_cf_phase: dict[str, list[dict]],
    output_dir: Path,
    custom_rulesets: dict[str, dict] | None = None,
    lists: dict[str, dict] | None = None,
    page_shield_policies: list[dict] | None = None,
    lists_dir: Path | None = None,
) -> Path | None:
    """Write a zone's rules to a YAML file.

    Returns the output path, or None on write failure.
    Zones with no rules produce a minimal ``---`` file.
    """
    if lists_dir is None:
        lists_dir = output_dir / "custom_lists"
    output: dict[str, list[dict]] = {}

    for cf_phase, rules in rules_by_cf_phase.items():
        if cf_phase not in PHASE_BY_CF:
            continue
        phase = PHASE_BY_CF[cf_phase]
        cleaned_rules = [_clean_rule(rule, phase.default_action) for rule in rules]
        if cleaned_rules:
            output[phase.friendly_name] = cleaned_rules

    if custom_rulesets:
        cr_list = []
        for rs_id, rs_data in sorted(custom_rulesets.items(), key=lambda x: x[1].get("name", "")):
            rules = rs_data.get("rules", [])
            cleaned = [_clean_rule(_ensure_ref(r), None) for r in rules]
            entry: dict = {
                "id": rs_id,
                "name": rs_data.get("name", ""),
                "phase": rs_data.get("phase", ""),
            }
            if cleaned:
                entry["rules"] = cleaned
            cr_list.append(entry)
        if cr_list:
            output["custom_rulesets"] = cr_list

    if lists:
        lists_list: list[dict | _IncludeTag] = []
        for name in sorted(lists.keys()):
            list_data = lists[name]
            entry: dict = {"name": name, "kind": list_data.get("kind", "")}
            desc = list_data.get("description", "")
            if desc:
                entry["description"] = desc
            items = list_data.get("items", [])
            cleaned_items = [_clean_list_item(item) for item in items]
            entry["items"] = cleaned_items if cleaned_items else []
            if cleaned_items:
                include_path = _write_list_file(output_dir, lists_dir, name, entry)
                if include_path:
                    lists_list.append(_IncludeTag(include_path))
                else:
                    lists_list.append(entry)  # fallback: inline
            else:
                lists_list.append(entry)
        if lists_list:
            output["lists"] = lists_list

    if page_shield_policies:
        policies_list = []
        for policy in sorted(page_shield_policies, key=lambda p: p.get("description", "")):
            cleaned = {
                k: _literalize(v)
                for k, v in policy.items()
                if k not in PAGE_SHIELD_POLICY_API_FIELDS
            }
            policies_list.append(cleaned)
        if policies_list:
            output["page_shield_policies"] = policies_list

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
                text = yaml.dump(
                    output,
                    None,
                    Dumper=_Dumper,
                    default_flow_style=False,
                    sort_keys=False,
                    allow_unicode=True,
                    width=_YAML_NO_WRAP_WIDTH,
                    explicit_start=True,
                )
                f.write(_add_blank_lines(text))
            else:
                f.write("--- {}\n")
                log.info("No rules found for %s, created empty file", zone_name)
    except OSError as e:
        log.error("Failed to write dump file %s: %s", output_path, e)
        return None

    return output_path


def _add_blank_lines(text: str) -> str:
    """Add blank lines between top-level sections and between items within sections."""
    lines = text.split("\n")
    result: list[str] = []
    for i, line in enumerate(lines):
        if i > 0 and line:
            prev = lines[i - 1]
            # Blank line before top-level keys (section headers), but not after ---
            if line[0].isalpha() and prev != "---":
                result.append("")
            # Blank line between top-level list items (not the first item after header)
            elif line.startswith("- ") and not prev.endswith(":"):
                result.append("")
        result.append(line)
    return "\n".join(result)


def _strip_trailing_whitespace(s: str) -> str:
    """Strip trailing whitespace from each line. PyYAML rejects block style otherwise."""
    return "\n".join(line.rstrip() for line in s.split("\n"))


def _literalize(value: object) -> object:
    """Recursively convert multiline strings to _LiteralStr for block style."""
    if isinstance(value, str) and "\n" in value:
        return _LiteralStr(_strip_trailing_whitespace(value).strip("\n"))
    if isinstance(value, dict):
        return {k: _literalize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_literalize(item) for item in value]
    return value


def _ensure_ref(rule: dict) -> dict:
    """If a rule has no 'ref' but has 'id', copy 'id' to 'ref' before cleaning."""
    if "ref" not in rule and "id" in rule:
        rule = rule.copy()
        rule["ref"] = rule["id"]
    return rule


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


def _clean_list_item(item: dict) -> dict:
    """Remove API-only fields from a list item and apply _literalize."""
    if not isinstance(item, dict):
        return {}
    return {k: _literalize(v) for k, v in item.items() if k not in LIST_ITEM_API_FIELDS}
