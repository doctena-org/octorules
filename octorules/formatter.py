"""Colored terminal output for plan results."""

import json
import sys
from collections.abc import Callable
from html import escape as html_escape
from typing import IO

import yaml

from octorules._color import _CYAN, _GREEN, _RED, _YELLOW, Pen, supports_color
from octorules.expression import format_expression_display
from octorules.extensions import get_format_extensions
from octorules.phases import display_phase_name
from octorules.planner import (
    ChangeType,
    CustomRulesetPlan,
    ListPlan,
    PhasePlan,
    RuleChange,
    RuleDict,
    ZonePlan,
)

_CHANGE_SYMBOLS: dict[ChangeType, str] = {
    ChangeType.ADD: "+",
    ChangeType.REMOVE: "-",
    ChangeType.MODIFY: "~",
    ChangeType.REORDER: "↕",
}

_CHANGE_COLORS: dict[ChangeType, str] = {
    ChangeType.ADD: _GREEN,
    ChangeType.REMOVE: _RED,
    ChangeType.MODIFY: _YELLOW,
    ChangeType.REORDER: _CYAN,
}


def _change_symbol(change_type: ChangeType) -> str:
    return _CHANGE_SYMBOLS[change_type]


def _change_color(change_type: ChangeType) -> str:
    return _CHANGE_COLORS[change_type]


_PRIORITY_KEYS: tuple[str, ...] = ("action", "description", "expression")


def _ordered_rule_keys(keys: set[str]) -> list[str]:
    """Apply the rule-field display order: small scalar fields first
    (action, description, expression), then everything else alphabetically.
    """
    priority = [k for k in _PRIORITY_KEYS if k in keys]
    remaining = sorted(keys - set(_PRIORITY_KEYS))
    return priority + remaining


def _compute_field_diffs(change: RuleChange) -> list[tuple[str, object, object]]:
    """Compute field-level diffs between normalized current and desired rules.

    Returns list of (key, old_value, new_value) tuples for changed fields,
    in display order (priority keys first, then alphabetical).
    """
    old = change.normalized_current
    new = change.normalized_desired
    if not old or not new:
        return []
    diffs = []
    for key in _ordered_rule_keys(old.keys() | new.keys()):
        old_val = old.get(key)
        new_val = new.get(key)
        if old_val != new_val:
            diffs.append((key, old_val, new_val))
    return diffs


def _rule_detail_pairs(rule: RuleDict | None) -> list[tuple[str, object]]:
    """Extract key-value pairs from a normalized rule for Details display.

    Orders: action, description, expression first, then remaining
    alphabetically.  Skips 'enabled' when True (the default) since it
    is not informative.
    """
    if not rule:
        return []
    pairs: list[tuple[str, object]] = []
    for key in _ordered_rule_keys(set(rule.keys())):
        val = rule[key]
        if key == "enabled" and val is True:
            continue
        pairs.append((key, val))
    return pairs


def _format_add_remove_details(rule: RuleDict | None, use_color: bool) -> list[str]:
    """Format rule details for an ADD or REMOVE change."""
    p = Pen(use_color)
    details = []
    for key, val in _rule_detail_pairs(rule):
        details.append(p.muted(f"      {key}: ") + f"{val!r}")
    return details


def _format_diff_value(
    key: str, val: object, prefix: str, color_code: str, use_color: bool
) -> list[str]:
    """Format a single diff value, pretty-printing long expression strings.

    Returns one or more lines.  The first line includes the key; continuation
    lines are indented and prefixed with the same ``prefix`` character.
    """
    p = Pen(use_color)
    if isinstance(val, str) and len(val) > 80:
        formatted = format_expression_display(val)
        if "\n" in formatted:
            flines = formatted.split("\n")
            pad = " " * (len(prefix) + 1)
            result = [p.muted(f"    {prefix} {key}: ") + p.raw(flines[0], color_code)]
            for fl in flines[1:]:
                result.append(p.muted(f"    {pad}") + p.raw(fl, color_code))
            return result
    label = p.muted(f"    {prefix} {key}: ")
    return [label + p.raw(f"{val!r}", color_code)]


def _format_modify_details(change: RuleChange, use_color: bool) -> list[str]:
    """Format field-level diffs for a MODIFY change."""
    details = []
    for key, old_val, new_val in _compute_field_diffs(change):
        details.extend(_format_diff_value(key, old_val, "−", _RED, use_color))  # noqa: RUF001
        details.extend(_format_diff_value(key, new_val, "+", _GREEN, use_color))
    return details


def format_change(change: RuleChange, use_color: bool = True) -> list[str]:
    """Format a single rule change as lines of output."""
    p = Pen(use_color)
    symbol = _change_symbol(change.change_type)
    color = _change_color(change.change_type)
    label = change.change_type.value

    if change.change_type == ChangeType.REORDER:
        return [p.raw(f"  {symbol} reorder rules", color)]

    lines = [p.raw(f"  {symbol} {label}: {change.ref}", color)]
    if change.change_type == ChangeType.MODIFY:
        lines.extend(_format_modify_details(change, use_color))
    elif change.change_type == ChangeType.ADD:
        lines.extend(_format_add_remove_details(change.normalized_desired, use_color))
    elif change.change_type == ChangeType.REMOVE:
        lines.extend(_format_add_remove_details(change.normalized_current, use_color))
    return lines


def format_phase_plan(phase_plan: PhasePlan, use_color: bool = True) -> list[str]:
    """Format a phase plan as lines of output."""
    p = Pen(use_color)
    lines = []
    header = (
        f"  {display_phase_name(phase_plan.phase.friendly_name)} ({phase_plan.phase.provider_id})"
    )
    lines.append(p.header(header))
    for change in phase_plan.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_custom_ruleset_plan(crp: CustomRulesetPlan, use_color: bool = True) -> list[str]:
    """Format a custom ruleset plan as lines of output."""
    p = Pen(use_color)
    lines = []
    id_short = (crp.ruleset_id or "")[:8]
    header = f"  custom_ruleset: {crp.ruleset_name} ({id_short})"
    lines.append(p.header(header))
    if crp.create:
        lines.append(p.success("  + create rule group"))
    if crp.delete:
        lines.append(p.error("  - delete rule group"))
    for change in crp.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_list_plan(lp: ListPlan, use_color: bool = True) -> list[str]:
    """Format a list plan as lines of output."""
    p = Pen(use_color)
    lines = []
    header = f"  list: {lp.list_name} ({lp.list_kind})"
    lines.append(p.header(header))
    if lp.create:
        lines.append(p.success("  + create list"))
        # On create the description is part of the new list, not a
        # standalone update — fold it in as an added field rather than
        # rendering a misleading description diff with a None old value.
        if lp.description_change is not None:
            new_desc = lp.description_change[1]
            lines.append(p.muted("    + ") + p.success(f"description: {new_desc!r}"))
    if lp.delete:
        lines.append(p.error("  - delete list"))
    if not lp.create and lp.description_change is not None:
        old_desc, new_desc = lp.description_change
        lines.append(p.warning("  ~ description:"))
        lines.append(p.muted("    − ") + p.error(repr(old_desc)))  # noqa: RUF001
        lines.append(p.muted("    + ") + p.success(repr(new_desc)))
    for change in lp.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_zone_plan(zone_plan: ZonePlan, use_color: bool = True) -> str:
    """Format a full zone plan as a string."""
    p = Pen(use_color)
    lines: list[str] = []

    if not zone_plan.has_changes:
        lines.append(p.header(f"Zone {zone_plan.display_name}: ") + p.muted("no changes"))
        return "\n".join(lines)

    lines.append(
        p.header(f"Zone {zone_plan.display_name}: ") + f"{zone_plan.total_changes} change(s)"
    )

    # Warn when ALL changes are removals (potential accidental mass deletion)
    from octorules.planner import ChangeType

    all_changes = []
    for pp in zone_plan.phase_plans:
        all_changes.extend(pp.changes)
    if all_changes and all(c.change_type == ChangeType.REMOVE for c in all_changes):
        lines.append(
            p.error(
                f"  WARNING: all {len(all_changes)} change(s) are deletions"
                f" — verify this is intentional"
            )
        )

    for phase_plan in zone_plan.phase_plans:
        lines.extend(format_phase_plan(phase_plan, use_color))

    for crp in zone_plan.custom_ruleset_plans:
        lines.extend(format_custom_ruleset_plan(crp, use_color))

    for lp in zone_plan.list_plans:
        lines.extend(format_list_plan(lp, use_color))

    for name, fmt in get_format_extensions().items():
        plans = zone_plan.extension_plans.get(name, [])
        if plans:
            lines.extend(fmt.format_text(plans, use_color))

    return "\n".join(lines)


def _total_changes(zone_plans: list[ZonePlan]) -> int:
    """Sum total changes across all zone plans."""
    return sum(zp.total_changes for zp in zone_plans)


def change_to_dict(c: RuleChange) -> dict:
    """Convert a RuleChange to a JSON-serializable dict."""
    d: dict = {"type": c.change_type.value, "ref": c.ref}
    if (v := c.normalized_current) is not None:
        d["current"] = v
    if (v := c.normalized_desired) is not None:
        d["desired"] = v
    return d


# Deprecated alias for the public name above.
_change_to_dict = change_to_dict


def format_plan_json(zone_plans: list[ZonePlan]) -> str:
    """Format the plan as structured JSON.

    Only zones with changes are included in the output.
    """
    total_changes = _total_changes(zone_plans)
    zones = []
    for zp in zone_plans:
        if not zp.has_changes:
            continue
        phase_plans = []
        for pp in zp.phase_plans:
            phase_plans.append(
                {
                    "phase": display_phase_name(pp.phase.friendly_name),
                    "provider_id": pp.phase.provider_id,
                    "changes": [change_to_dict(c) for c in pp.changes],
                }
            )
        cr_plans = []
        for crp in zp.custom_ruleset_plans:
            cr_plans.append(
                {
                    "ruleset_id": crp.ruleset_id,
                    "ruleset_name": crp.ruleset_name,
                    "phase": crp.phase,
                    "create": crp.create,
                    "delete": crp.delete,
                    "changes": [change_to_dict(c) for c in crp.changes],
                }
            )
        lp_plans = []
        for lp in zp.list_plans:
            lp_changes = [change_to_dict(c) for c in lp.changes]
            lp_entry: dict = {
                "list_name": lp.list_name,
                "list_kind": lp.list_kind,
                "create": lp.create,
                "delete": lp.delete,
            }
            if lp.description_change is not None:
                lp_entry["description_change"] = list(lp.description_change)
            if lp_changes:
                lp_entry["changes"] = lp_changes
            lp_plans.append(lp_entry)
        zone_entry: dict = {
            "zone": zp.zone_name,
            "phase_plans": phase_plans,
            "total_changes": zp.total_changes,
        }
        if zp.target is not None:
            zone_entry["target"] = zp.target
        if cr_plans:
            zone_entry["custom_ruleset_plans"] = cr_plans
        if lp_plans:
            zone_entry["list_plans"] = lp_plans
        for ext_name, fmt in get_format_extensions().items():
            ext_plans = zp.extension_plans.get(ext_name, [])
            if ext_plans:
                zone_entry[f"{ext_name}_policy_plans"] = fmt.format_json(ext_plans)
        zones.append(zone_entry)
    result = {
        "zones": zones,
        "total_changes": total_changes,
        "has_changes": total_changes > 0,
    }
    return json.dumps(result, indent=2)


def md_escape(text: str) -> str:
    """Escape pipe characters for markdown tables."""
    return str(text).replace("|", "\\|")


# Deprecated alias for the public name above.
_md_escape = md_escape


def md_change_row(
    c: RuleChange,
    phase_label: str,
    pending_diffs: list[list[tuple[str, object, object]]],
    *,
    has_reorder: bool = True,
) -> str:
    """Build a single markdown table row for a RuleChange."""
    op = _change_symbol(c.change_type)
    ref = md_escape(c.ref)
    escaped_phase = md_escape(phase_label)
    if c.change_type == ChangeType.MODIFY and c.current and c.desired:
        field_diffs = _compute_field_diffs(c)
        if field_diffs:
            details = "; ".join(f"`{key}`" for key, _, _ in field_diffs)
            pending_diffs.append(field_diffs)
        else:
            details = ""
    elif has_reorder and c.change_type == ChangeType.REORDER:
        details = "reorder rules"
    else:
        rule = c.normalized_desired if c.change_type == ChangeType.ADD else c.normalized_current
        pairs = _rule_detail_pairs(rule)
        if pairs:
            parts = [f"`{key}`: {_md_format_value(val)}" for key, val in pairs]
            details = md_escape("; ".join(parts))
        else:
            details = ""
    return f"| {op} | {escaped_phase} | {ref} | {details} |"


# Deprecated alias for the public name above.
_md_change_row = md_change_row


def _md_diff_value(key: str, val: object, prefix: str) -> list[str]:
    """Format a diff value for a markdown ``diff`` code block.

    ``dict`` / ``list`` values render as block-style YAML with the key as
    the first line and the value indented under it; every line carries
    the diff prefix so GitHub colours the whole block. Long expression
    strings are pretty-printed the same way.
    """
    yaml_text = _yaml_pretty(val)
    if yaml_text is not None:
        result = [f"{prefix} {key}:"]
        for yl in yaml_text.split("\n"):
            result.append(f"{prefix}{yl}")
        return result
    if isinstance(val, str) and len(val) > 80:
        formatted = format_expression_display(val)
        if "\n" in formatted:
            flines = formatted.split("\n")
            result = [f"{prefix} {key}: {flines[0]}"]
            for fl in flines[1:]:
                result.append(f"{prefix} {fl}")
            return result
    return [f"{prefix} {key}: {val!r}"]


def format_plan_markdown(zone_plans: list[ZonePlan]) -> str:
    """Format the plan as markdown for PR comments.

    Only zones with changes are shown; unchanged zones are omitted to keep
    the output concise.
    """
    total_changes = _total_changes(zone_plans)
    lines: list[str] = []

    for zp in zone_plans:
        if not zp.has_changes:
            continue
        lines.append(f"### Zone: `{zp.display_name}`")
        lines.append("")
        lines.append("| Op | Phase | Ref | Details |")
        lines.append("|---|---|---|---|")
        pending_diffs: list[list[tuple[str, object, object]]] = []
        for pp in zp.phase_plans:
            for c in pp.changes:
                lines.append(
                    md_change_row(c, display_phase_name(pp.phase.friendly_name), pending_diffs)
                )
        for crp in zp.custom_ruleset_plans:
            phase_label = f"custom_ruleset:{crp.ruleset_name}"
            if crp.create:
                lines.append(f"| + | {phase_label} | | create rule group |")
            if crp.delete:
                lines.append(f"| - | {phase_label} | | delete rule group |")
            for c in crp.changes:
                lines.append(md_change_row(c, phase_label, pending_diffs))
        for lp in zp.list_plans:
            phase_label = f"list:{lp.list_name}"
            if lp.create:
                # Fold the description into the create row rather than
                # emitting a separate `~ description` diff with a `- None`
                # old value (the list does not exist yet).
                if lp.description_change is not None:
                    new_desc = md_escape(str(lp.description_change[1]))
                    lines.append(f"| + | {phase_label} | | create list — description: {new_desc} |")
                else:
                    lines.append(f"| + | {phase_label} | | create list |")
            if lp.delete:
                lines.append(f"| - | {phase_label} | | delete list |")
            if not lp.create and lp.description_change is not None:
                old_desc, new_desc = lp.description_change
                lines.append(f"| ~ | {phase_label} | | `description` |")
                pending_diffs.append([("description", old_desc, new_desc)])
            for c in lp.changes:
                lines.append(md_change_row(c, phase_label, pending_diffs, has_reorder=False))
        for ext_name, fmt in get_format_extensions().items():
            ext_plans = zp.extension_plans.get(ext_name, [])
            if ext_plans:
                lines.extend(fmt.format_markdown(ext_plans, pending_diffs))
        for diff_group in pending_diffs:
            lines.append("")
            lines.append("```diff")
            for key, old_val, new_val in diff_group:
                lines.extend(_md_diff_value(key, old_val, "-"))
                lines.extend(_md_diff_value(key, new_val, "+"))
            lines.append("```")
        lines.append("")

    if total_changes == 0:
        lines.append("**No changes detected.**")
    else:
        lines.append(f"**Total: {total_changes} change(s) across {len(zone_plans)} zone(s).**")
    return "\n".join(lines)


_HTML_OP_NAMES: dict[ChangeType, str] = {
    ChangeType.ADD: "Create",
    ChangeType.REMOVE: "Delete",
    ChangeType.MODIFY: "Update",
    ChangeType.REORDER: "Reorder",
}


def _html_op_name(change_type: ChangeType) -> str:
    """Human-readable operation name for HTML output."""
    return _HTML_OP_NAMES[change_type]


class _LiteralStr(str):
    """Marker subclass. PyYAML emits these as ``|`` literal block scalars
    so multi-line strings (long wirefilter expressions, pre-formatted by
    ``format_expression_display``) render with their newlines preserved.
    """


def _literal_str_representer(dumper: yaml.Dumper, data: _LiteralStr) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", str(data), style="|")


class _IndentingDumper(yaml.SafeDumper):
    """SafeDumper variant that indents list dashes under their parent key."""

    def increase_indent(self, flow=False, indentless=False):
        return super().increase_indent(flow, False)


_IndentingDumper.add_representer(_LiteralStr, _literal_str_representer)


def _preformat_long_strings(val: object) -> object:
    """Recursively walk ``val``. Replace any long string whose
    ``format_expression_display`` form spans multiple lines with a
    ``_LiteralStr`` marker so the YAML dumper emits it as a literal
    block scalar. Preserves the readable line-wrapping for wirefilter
    expressions like ``ip.src in {...}`` lists.
    """
    if isinstance(val, dict):
        return {k: _preformat_long_strings(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_preformat_long_strings(v) for v in val]
    if isinstance(val, str) and not isinstance(val, _LiteralStr) and len(val) > 80:
        formatted = format_expression_display(val)
        if "\n" in formatted:
            return _LiteralStr(formatted)
    return val


def _rule_yaml(pairs: list[tuple[str, object]]) -> str:
    """Render a list of ``(key, value)`` pairs as a block-style YAML
    document with sibling top-level keys. Preserves the insertion order
    of ``pairs`` (priority keys first, then alphabetical — see
    ``_rule_detail_pairs``). Long wirefilter expressions inside the
    values render as ``|`` literal block scalars for readability.
    """
    ordered: dict[str, object] = {k: _preformat_long_strings(v) for k, v in pairs}
    return yaml.dump(
        ordered,
        Dumper=_IndentingDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=2147483647,
        indent=2,
    ).rstrip("\n")


def _yaml_pretty(val: object) -> str | None:
    """Return block-style YAML for non-empty dict/list values, indented by
    two spaces on every line so the output nests visually under the field
    key label; else ``None``.
    """
    if not isinstance(val, dict | list) or not val:
        return None
    text = yaml.dump(
        _preformat_long_strings(val),
        Dumper=_IndentingDumper,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=2147483647,
        indent=2,
    )
    return "\n".join(f"  {ln}" for ln in text.rstrip("\n").split("\n"))


def _flatten_string_newlines(val: object) -> object:
    """Recursively replace newlines inside string values with ``\\n`` so
    PyYAML keeps the value on one physical line (markdown table cells
    can't span multiple rows).
    """
    if isinstance(val, dict):
        return {k: _flatten_string_newlines(v) for k, v in val.items()}
    if isinstance(val, list):
        return [_flatten_string_newlines(v) for v in val]
    if isinstance(val, str) and "\n" in val:
        return val.replace("\n", "\\n")
    return val


def _md_format_value(val: object) -> str:
    """Format a single value for a markdown table cell as one-line YAML.

    Markdown tables can't render block content in cells, so dicts and
    lists use flow-style YAML (e.g. ``{enabled: true}``) instead of
    block style. Scalars also go through YAML so ``True`` / ``None`` /
    string-``"true"`` render with the same conventions as everywhere
    else in the plan output.

    The value is wrapped in a single-element list before dumping so
    PyYAML doesn't append its ``...`` document-end marker (which would
    otherwise trail bare scalars).
    """
    text = yaml.dump(
        [_flatten_string_newlines(val)],
        Dumper=_IndentingDumper,
        default_flow_style=True,
        sort_keys=False,
        allow_unicode=True,
        width=2147483647,
    ).strip()
    # Strip the surrounding [...] wrapper list markers.
    return text[1:-1]


def html_render_changes(
    changes: list[RuleChange],
    lines: list[str],
) -> tuple[int, int, int, int]:
    """Render HTML table rows for a list of RuleChanges.

    Returns (creates, removes, modifies, reorders) counts.
    """
    e = html_escape
    creates = removes = modifies = reorders = 0

    for c in changes:
        op = _html_op_name(c.change_type)

        if c.change_type in (ChangeType.ADD, ChangeType.REMOVE):
            if c.change_type == ChangeType.ADD:
                creates += 1
                detail_pairs = _rule_detail_pairs(c.normalized_desired)
                marker = "+"
            else:
                removes += 1
                detail_pairs = _rule_detail_pairs(c.normalized_current)
                marker = "-"
            lines.append("  <tr>")
            lines.append(f"    <td>{e(op)}</td>")
            lines.append(f"    <td>{e(c.ref)}</td>")
            if detail_pairs:
                yaml_text = _rule_yaml(detail_pairs)
                prefixed = "\n".join(f"{marker} {ln}" for ln in yaml_text.split("\n"))
                lines.append(f"    <td><pre>{e(prefixed)}</pre></td>")
            else:
                lines.append("    <td></td>")
            lines.append("  </tr>")
        elif c.change_type == ChangeType.REORDER:
            reorders += 1
            lines.append("  <tr>")
            lines.append(f"    <td>{e(op)}</td>")
            lines.append("    <td></td>")
            lines.append("    <td>reorder rules</td>")
            lines.append("  </tr>")
        elif c.change_type == ChangeType.MODIFY:
            modifies += 1
            diffs = _compute_field_diffs(c)
            if diffs:
                old_pairs = [(k, old_v) for k, old_v, _ in diffs]
                new_pairs = [(k, new_v) for k, _, new_v in diffs]
                old_yaml = _rule_yaml(old_pairs)
                new_yaml = _rule_yaml(new_pairs)
                old_block = "\n".join(f"- {ln}" for ln in old_yaml.split("\n"))
                new_block = "\n".join(f"+ {ln}" for ln in new_yaml.split("\n"))
                lines.append("  <tr>")
                lines.append(f"    <td>{e(op)}</td>")
                lines.append(f"    <td>{e(c.ref)}</td>")
                lines.append(f"    <td><pre>{e(old_block)}</pre></td>")
                lines.append("  </tr>")
                lines.append("  <tr>")
                lines.append("    <td colspan=2></td>")
                lines.append(f"    <td><pre>{e(new_block)}</pre></td>")
                lines.append("  </tr>")
            else:
                lines.append("  <tr>")
                lines.append(f"    <td>{e(op)}</td>")
                lines.append(f"    <td>{e(c.ref)}</td>")
                lines.append("    <td></td>")
                lines.append("  </tr>")

    return creates, removes, modifies, reorders


# Deprecated alias for the public name above.
_html_render_changes = html_render_changes


def html_summary_row(creates: int, removes: int, modifies: int, reorders: int) -> list[str]:
    """Build the summary <tr> lines for an HTML table."""
    parts = []
    if creates:
        parts.append(f"Creates={creates}")
    if modifies:
        parts.append(f"Updates={modifies}")
    if removes:
        parts.append(f"Deletes={removes}")
    if reorders:
        parts.append(f"Reorders={reorders}")
    summary = ", ".join(parts) if parts else "No changes"
    return [
        "  <tr>",
        f"    <td colspan=3>Summary: {summary}</td>",
        "  </tr>",
    ]


# Deprecated alias for the public name above.
_html_summary_row = html_summary_row


HTML_TABLE_HEADER = [
    "<table>",
    "  <tr>",
    "    <th>Operation</th>",
    "    <th>Ref</th>",
    "    <th>Details</th>",
    "  </tr>",
]

# Deprecated alias for the public name above.
_HTML_TABLE_HEADER = HTML_TABLE_HEADER


def format_plan_html(zone_plans: list[ZonePlan]) -> str:
    """Format the plan as embeddable HTML fragment for PR comments.

    Outputs clean HTML tables (no DOCTYPE/html/head/body/style wrapper) so the
    output can be embedded directly in GitHub PR comments or other markdown
    contexts.  Follows the same structure as octodns PlanHtml.
    Only zones with changes are shown.
    """
    e = html_escape
    lines: list[str] = []

    for zp in zone_plans:
        if not zp.has_changes:
            continue

        lines.append(f"<h2>{e(zp.display_name)}</h2>")

        for pp in zp.phase_plans:
            lines.append(f"<h3>{e(display_phase_name(pp.phase.friendly_name))}</h3>")
            lines.extend(HTML_TABLE_HEADER)
            creates, removes, modifies, reorders = html_render_changes(pp.changes, lines)
            lines.extend(html_summary_row(creates, removes, modifies, reorders))
            lines.append("</table>")

        for crp in zp.custom_ruleset_plans:
            lines.append(f"<h3>custom_ruleset: {e(crp.ruleset_name)}</h3>")
            lines.extend(HTML_TABLE_HEADER)

            crp_creates = crp_removes = 0

            if crp.create:
                crp_creates += 1
                lines.append("  <tr>")
                lines.append("    <td>Create</td>")
                lines.append("    <td></td>")
                lines.append("    <td>create rule group</td>")
                lines.append("  </tr>")
            if crp.delete:
                crp_removes += 1
                lines.append("  <tr>")
                lines.append("    <td>Delete</td>")
                lines.append("    <td></td>")
                lines.append("    <td>delete rule group</td>")
                lines.append("  </tr>")

            c_creates, c_removes, c_modifies, c_reorders = html_render_changes(crp.changes, lines)
            crp_creates += c_creates
            crp_removes += c_removes
            lines.extend(html_summary_row(crp_creates, crp_removes, c_modifies, c_reorders))
            lines.append("</table>")

        for lp in zp.list_plans:
            lines.append(f"<h3>list: {e(lp.list_name)} ({e(lp.list_kind)})</h3>")
            lines.extend(HTML_TABLE_HEADER)

            lp_creates = lp_removes = lp_modifies = 0

            if lp.create:
                lp_creates += 1
                lines.append("  <tr>")
                lines.append("    <td>Create</td>")
                lines.append("    <td></td>")
                # On create, fold the description into the create row
                # instead of a separate Update row whose old value is a
                # misleading `description: None` (the list is new).
                if lp.description_change is not None:
                    new_desc = lp.description_change[1]
                    body = f"create list\n+ description: {new_desc}"
                    lines.append(f"    <td><pre>{e(body)}</pre></td>")
                else:
                    lines.append("    <td>create list</td>")
                lines.append("  </tr>")
            if lp.delete:
                lp_removes += 1
                lines.append("  <tr>")
                lines.append("    <td>Delete</td>")
                lines.append("    <td></td>")
                lines.append("    <td>delete list</td>")
                lines.append("  </tr>")
            if not lp.create and lp.description_change is not None:
                lp_modifies += 1
                old_desc, new_desc = lp.description_change
                lines.append("  <tr>")
                lines.append("    <td>Update</td>")
                lines.append("    <td></td>")
                lines.append(f"    <td>&minus;&ensp;description: {e(str(old_desc))}</td>")
                lines.append("  </tr>")
                lines.append("  <tr>")
                lines.append("    <td colspan=2></td>")
                lines.append(f"    <td>+&ensp;description: {e(str(new_desc))}</td>")
                lines.append("  </tr>")

            c_creates, c_removes, c_modifies, _ = html_render_changes(lp.changes, lines)
            lp_creates += c_creates
            lp_removes += c_removes
            lp_modifies += c_modifies
            lines.extend(html_summary_row(lp_creates, lp_removes, lp_modifies, 0))
            lines.append("</table>")

        for ext_name, fmt in get_format_extensions().items():
            ext_plans = zp.extension_plans.get(ext_name, [])
            if ext_plans:
                fmt.format_html(ext_plans, lines)

    if not any(zp.has_changes for zp in zone_plans):
        lines.append("<b>No changes were planned</b>")

    return "\n".join(lines)


_FORMAT_RENDERERS: dict[str, Callable] = {
    "json": format_plan_json,
    "markdown": format_plan_markdown,
    "html": format_plan_html,
}


def print_plan(zone_plans: list[ZonePlan], file: IO[str] | None = None, fmt: str = "text") -> None:
    """Print the full plan for all zones.

    Only zones with changes are shown; unchanged zones are omitted.
    When the global quiet flag is set and *file* was not explicitly
    provided (i.e. output would go to stdout), the function returns
    immediately so that ``--quiet`` suppresses plan tables.
    """
    from octorules._context import is_quiet

    if file is None:
        if is_quiet():
            return
        file = sys.stdout

    renderer = _FORMAT_RENDERERS.get(fmt)
    if renderer is not None:
        print(renderer(zone_plans), file=file)
        return

    use_color = supports_color() and file is sys.stdout
    p = Pen(use_color)
    total_changes = _total_changes(zone_plans)

    changed = [zp for zp in zone_plans if zp.has_changes]
    for i, zp in enumerate(changed):
        print(format_zone_plan(zp, use_color), file=file)
        # Blank line between zones, but not after the last one.
        if i < len(changed) - 1:
            print(file=file)

    # Summary goes to stderr when printing to terminal (consistent with
    # lint/audit), but stays in the file when writing to a plan output.
    summary_file = sys.stderr if file is sys.stdout else file
    if summary_file is sys.stderr:
        file.flush()  # Ensure zone diffs appear before summary
    if total_changes == 0:
        print(p.muted("No changes detected."), file=summary_file)
    else:
        summary = f"Total: {total_changes} change(s) across {len(zone_plans)} zone(s)."
        print(p.header(summary), file=summary_file)
