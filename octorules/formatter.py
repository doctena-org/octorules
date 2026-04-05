"""Colored terminal output for plan results."""

import csv
import io
import json
import sys
from collections.abc import Callable
from html import escape as html_escape
from typing import IO

from octorules._color import _CYAN, _GREEN, _RED, _YELLOW, Pen, supports_color
from octorules.expression import format_expression_display
from octorules.extensions import get_format_extensions
from octorules.phases import PHASE_BY_NAME, PHASE_BY_PROVIDER_ID
from octorules.planner import (
    ChangeType,
    CustomRulesetPlan,
    ListPlan,
    PhasePlan,
    RuleChange,
    RuleDict,
    ZonePlan,
    count_change_types,
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


def _compute_field_diffs(change: RuleChange) -> list[tuple[str, object, object]]:
    """Compute field-level diffs between normalized current and desired rules.

    Returns list of (key, old_value, new_value) tuples for changed fields.
    """
    old = change.normalized_current
    new = change.normalized_desired
    if not old or not new:
        return []
    diffs = []
    for key in sorted(old.keys() | new.keys()):
        old_val = old.get(key)
        new_val = new.get(key)
        if old_val != new_val:
            diffs.append((key, old_val, new_val))
    return diffs


def _rule_detail_pairs(rule: RuleDict | None) -> list[tuple[str, object]]:
    """Extract key-value pairs from a normalized rule for Details display.

    Orders: action, description, expression first, then remaining alphabetically.
    Skips 'enabled' when True (the default) since it's not informative.
    """
    if not rule:
        return []
    priority_keys = ["action", "description", "expression"]
    pairs: list[tuple[str, object]] = []
    seen: set[str] = set()
    for key in priority_keys:
        if key in rule:
            val = rule[key]
            if key == "enabled" and val is True:
                continue
            pairs.append((key, val))
            seen.add(key)
    for key in sorted(rule.keys()):
        if key in seen:
            continue
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
    header = f"  {phase_plan.phase.friendly_name} ({phase_plan.phase.provider_id})"
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
    if lp.delete:
        lines.append(p.error("  - delete list"))
    if lp.description_change is not None:
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


def _change_to_dict(c: RuleChange) -> dict:
    """Convert a RuleChange to a JSON-serializable dict."""
    d: dict = {"type": c.change_type.value, "ref": c.ref}
    if (v := c.normalized_current) is not None:
        d["current"] = v
    if (v := c.normalized_desired) is not None:
        d["desired"] = v
    return d


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
                    "phase": pp.phase.friendly_name,
                    "provider_id": pp.phase.provider_id,
                    "changes": [_change_to_dict(c) for c in pp.changes],
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
                    "changes": [_change_to_dict(c) for c in crp.changes],
                }
            )
        lp_plans = []
        for lp in zp.list_plans:
            lp_changes = [_change_to_dict(c) for c in lp.changes]
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


def _md_escape(text: str) -> str:
    """Escape pipe characters for markdown tables."""
    return str(text).replace("|", "\\|")


def _md_change_row(
    c: RuleChange,
    phase_label: str,
    pending_diffs: list[list[tuple[str, object, object]]],
    *,
    has_reorder: bool = True,
) -> str:
    """Build a single markdown table row for a RuleChange."""
    op = _change_symbol(c.change_type)
    ref = _md_escape(c.ref)
    escaped_phase = _md_escape(phase_label)
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
            parts = [f"`{key}`: {val!r}" for key, val in pairs]
            details = _md_escape("; ".join(parts))
        else:
            details = ""
    return f"| {op} | {escaped_phase} | {ref} | {details} |"


def _md_diff_value(key: str, val: object, prefix: str) -> list[str]:
    """Format a diff value for a markdown ``diff`` code block.

    Long expression strings are pretty-printed with each continuation line
    prefixed so GitHub renders the whole block in the correct colour.
    """
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
                lines.append(_md_change_row(c, pp.phase.friendly_name, pending_diffs))
        for crp in zp.custom_ruleset_plans:
            phase_label = f"custom_ruleset:{crp.ruleset_name}"
            if crp.create:
                lines.append(f"| + | {phase_label} | | create rule group |")
            if crp.delete:
                lines.append(f"| - | {phase_label} | | delete rule group |")
            for c in crp.changes:
                lines.append(_md_change_row(c, phase_label, pending_diffs))
        for lp in zp.list_plans:
            phase_label = f"list:{lp.list_name}"
            if lp.create:
                lines.append(f"| + | {phase_label} | | create list |")
            if lp.delete:
                lines.append(f"| - | {phase_label} | | delete list |")
            if lp.description_change is not None:
                old_desc, new_desc = lp.description_change
                lines.append(f"| ~ | {phase_label} | | `description` |")
                pending_diffs.append([("description", old_desc, new_desc)])
            for c in lp.changes:
                lines.append(_md_change_row(c, phase_label, pending_diffs, has_reorder=False))
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


def _html_diff_value(key: str, val: object, prefix: str) -> str:
    """Format a diff value for an HTML table cell.

    Long expression strings are pretty-printed inside ``<pre>`` so that
    GitHub renders them with preserved whitespace and indentation.
    """
    e = html_escape
    if isinstance(val, str) and len(val) > 80:
        formatted = format_expression_display(val)
        if "\n" in formatted:
            return f"{prefix}&ensp;<code>{e(key)}</code>:<pre>{e(formatted)}</pre>"
    return f"{prefix}&ensp;<code>{e(key)}</code>: {e(str(val))}"


def _html_render_changes(
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
            else:
                removes += 1
                detail_pairs = _rule_detail_pairs(c.normalized_current)
            lines.append("  <tr>")
            lines.append(f"    <td>{e(op)}</td>")
            lines.append(f"    <td>{e(c.ref)}</td>")
            if detail_pairs:
                parts = [f"<code>{e(key)}</code>: {e(str(val))}" for key, val in detail_pairs]
                lines.append(f"    <td>{'<br/>'.join(parts)}</td>")
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
            for i, (key, old_val, new_val) in enumerate(diffs):
                if i == 0:
                    lines.append("  <tr>")
                    lines.append(f"    <td>{e(op)}</td>")
                    lines.append(f"    <td>{e(c.ref)}</td>")
                else:
                    lines.append("  <tr>")
                    lines.append("    <td colspan=2></td>")
                lines.append(f"    <td>{_html_diff_value(key, old_val, '&minus;')}</td>")
                lines.append("  </tr>")
                lines.append("  <tr>")
                lines.append("    <td colspan=2></td>")
                lines.append(f"    <td>{_html_diff_value(key, new_val, '+')}</td>")
                lines.append("  </tr>")
            if not diffs:
                lines.append("  <tr>")
                lines.append(f"    <td>{e(op)}</td>")
                lines.append(f"    <td>{e(c.ref)}</td>")
                lines.append("    <td></td>")
                lines.append("  </tr>")

    return creates, removes, modifies, reorders


def _html_summary_row(creates: int, removes: int, modifies: int, reorders: int) -> list[str]:
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


_HTML_TABLE_HEADER = [
    "<table>",
    "  <tr>",
    "    <th>Operation</th>",
    "    <th>Ref</th>",
    "    <th>Details</th>",
    "  </tr>",
]


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
            lines.append(f"<h3>{e(pp.phase.friendly_name)}</h3>")
            lines.extend(_HTML_TABLE_HEADER)
            creates, removes, modifies, reorders = _html_render_changes(pp.changes, lines)
            lines.extend(_html_summary_row(creates, removes, modifies, reorders))
            lines.append("</table>")

        for crp in zp.custom_ruleset_plans:
            lines.append(f"<h3>custom_ruleset: {e(crp.ruleset_name)}</h3>")
            lines.extend(_HTML_TABLE_HEADER)

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

            c_creates, c_removes, c_modifies, c_reorders = _html_render_changes(crp.changes, lines)
            crp_creates += c_creates
            crp_removes += c_removes
            lines.extend(_html_summary_row(crp_creates, crp_removes, c_modifies, c_reorders))
            lines.append("</table>")

        for lp in zp.list_plans:
            lines.append(f"<h3>list: {e(lp.list_name)} ({e(lp.list_kind)})</h3>")
            lines.extend(_HTML_TABLE_HEADER)

            lp_creates = lp_removes = lp_modifies = 0

            if lp.create:
                lp_creates += 1
                lines.append("  <tr>")
                lines.append("    <td>Create</td>")
                lines.append("    <td></td>")
                lines.append("    <td>create list</td>")
                lines.append("  </tr>")
            if lp.delete:
                lp_removes += 1
                lines.append("  <tr>")
                lines.append("    <td>Delete</td>")
                lines.append("    <td></td>")
                lines.append("    <td>delete list</td>")
                lines.append("  </tr>")
            if lp.description_change is not None:
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

            c_creates, c_removes, c_modifies, _ = _html_render_changes(lp.changes, lines)
            lp_creates += c_creates
            lp_removes += c_removes
            lp_modifies += c_modifies
            lines.extend(_html_summary_row(lp_creates, lp_removes, lp_modifies, 0))
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

    for zp in zone_plans:
        if not zp.has_changes:
            continue
        print(format_zone_plan(zp, use_color), file=file)
        print(file=file)

    if total_changes == 0:
        print(p.muted("No changes detected."), file=file)
    else:
        summary = f"Total: {total_changes} change(s) across {len(zone_plans)} zone(s)."
        print(p.header(summary), file=file)


def build_report_data(
    zone_plans: list[ZonePlan],
    desired_by_zone: dict[str, dict],
    current_by_zone: dict[str, dict],
) -> dict:
    """Build structured drift report data across all zones and phases.

    Enumerates all phases present in either desired or current (not just changed
    phases from ZonePlan), so in_sync phases are included in the report.
    """
    # Index phase plans by (zone, provider_id) for quick lookup
    changes_index: dict[tuple[str, str], PhasePlan] = {}
    cr_index: dict[tuple[str, str], CustomRulesetPlan] = {}
    for zp in zone_plans:
        for pp in zp.phase_plans:
            changes_index[(zp.zone_name, pp.phase.provider_id)] = pp
        for crp in zp.custom_ruleset_plans:
            cr_index[(zp.zone_name, crp.ruleset_id)] = crp

    zones_data = []
    summary_in_sync = 0
    summary_drifted = 0

    for zp in zone_plans:
        zone_name = zp.zone_name
        desired = desired_by_zone.get(zp.plan_key, {})
        current = current_by_zone.get(zp.plan_key, {})

        # Build the union of all phases present in either desired or current
        all_provider_ids: set[str] = set()
        for friendly_name in desired:
            if friendly_name in PHASE_BY_NAME:
                all_provider_ids.add(PHASE_BY_NAME[friendly_name].provider_id)
        for provider_id in current:
            if provider_id in PHASE_BY_PROVIDER_ID:
                all_provider_ids.add(provider_id)

        phases_data = []
        zone_has_drift = False

        for provider_id in sorted(all_provider_ids):
            if provider_id not in PHASE_BY_PROVIDER_ID:
                continue
            phase = PHASE_BY_PROVIDER_ID[provider_id]
            friendly_name = phase.friendly_name

            yaml_rules = len(desired.get(friendly_name, []))
            live_rules = len(current.get(provider_id, []))

            # Count changes from the phase plan if one exists
            pp = changes_index.get((zone_name, provider_id))
            adds, removes, modifies = count_change_types(pp.changes) if pp else (0, 0, 0)

            # Determine status
            has_yaml = friendly_name in desired
            has_live = provider_id in current and len(current[provider_id]) > 0

            if has_yaml and not has_live and yaml_rules > 0:
                status = "yaml_only"
            elif has_live and not has_yaml:
                status = "live_only"
            elif adds > 0 or removes > 0 or modifies > 0:
                status = "drifted"
            else:
                status = "in_sync"

            if status != "in_sync":
                zone_has_drift = True

            phases_data.append(
                {
                    "phase": friendly_name,
                    "provider_id": provider_id,
                    "status": status,
                    "yaml_rules": yaml_rules,
                    "live_rules": live_rules,
                    "adds": adds,
                    "removes": removes,
                    "modifies": modifies,
                }
            )

        # Include custom ruleset data in report
        for crp in zp.custom_ruleset_plans:
            cr_adds, cr_removes, cr_modifies = count_change_types(
                crp.changes,
                extra_creates=int(crp.create),
                extra_removes=int(crp.delete),
            )
            cr_status = "drifted" if (cr_adds or cr_removes or cr_modifies) else "in_sync"
            if cr_status != "in_sync":
                zone_has_drift = True
            phases_data.append(
                {
                    "phase": f"custom_ruleset:{crp.ruleset_name}",
                    "provider_id": crp.phase,
                    "status": cr_status,
                    "yaml_rules": len(crp.prepared_rules) if crp.prepared_rules else 0,
                    "live_rules": 0,
                    "adds": cr_adds,
                    "removes": cr_removes,
                    "modifies": cr_modifies,
                }
            )

        # Include list data in report
        for lp in zp.list_plans:
            lp_adds, lp_removes, lp_modifies = count_change_types(
                lp.changes,
                extra_creates=int(lp.create),
                extra_removes=int(lp.delete),
            )
            if lp.description_change is not None:
                lp_modifies += 1
            lp_status = "drifted" if (lp_adds or lp_removes or lp_modifies) else "in_sync"
            if lp_status != "in_sync":
                zone_has_drift = True
            phases_data.append(
                {
                    "phase": f"list:{lp.list_name}",
                    "provider_id": "account_lists",
                    "status": lp_status,
                    "yaml_rules": len(lp.prepared_items) if lp.prepared_items else 0,
                    "live_rules": 0,
                    "adds": lp_adds,
                    "removes": lp_removes,
                    "modifies": lp_modifies,
                }
            )

        # Include extension data in report
        for ext_name, fmt in get_format_extensions().items():
            ext_plans = zp.extension_plans.get(ext_name, [])
            if ext_plans:
                zone_has_drift = zone_has_drift or bool(
                    fmt.format_report(ext_plans, zone_has_drift, phases_data)
                )

        zone_status = "drifted" if zone_has_drift else "in_sync"
        if zone_status == "in_sync":
            summary_in_sync += 1
        else:
            summary_drifted += 1

        zones_data.append(
            {
                "zone": zone_name,
                "status": zone_status,
                "phases": phases_data,
            }
        )

    return {
        "zones": zones_data,
        "summary": {
            "total_zones": len(zone_plans),
            "in_sync": summary_in_sync,
            "drifted": summary_drifted,
        },
    }


def format_report_csv(report_data: dict) -> str:
    """Format report data as CSV with header, data rows, and summary comment."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    header = [
        "Zone",
        "Phase",
        "Provider ID",
        "Status",
        "YAML Rules",
        "Live Rules",
        "Adds",
        "Removes",
        "Modifies",
    ]
    writer.writerow(header)
    for zone in report_data["zones"]:
        for phase in zone["phases"]:
            writer.writerow(
                [
                    zone["zone"],
                    phase["phase"],
                    phase["provider_id"],
                    phase["status"],
                    phase["yaml_rules"],
                    phase["live_rules"],
                    phase["adds"],
                    phase["removes"],
                    phase["modifies"],
                ]
            )
    s = report_data["summary"]
    buf.write(
        f"# Summary: {s['total_zones']} zones, {s['in_sync']} in_sync, {s['drifted']} drifted\n"
    )
    return buf.getvalue()


def format_report_json(report_data: dict) -> str:
    """Format report data as pretty-printed JSON."""
    return json.dumps(report_data, indent=2)


def print_report(report_data: dict, file: IO[str] | None = None, fmt: str = "csv") -> None:
    """Print the drift report in the requested format."""
    from octorules._context import is_quiet

    if file is None:
        if is_quiet():
            return
        file = sys.stdout

    if fmt == "json":
        print(format_report_json(report_data), file=file)
    else:
        print(format_report_csv(report_data), end="", file=file)
