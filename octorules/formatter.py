"""Colored terminal output for plan results."""

from __future__ import annotations

import csv
import io
import json
import sys
from html import escape as html_escape
from typing import IO

from octorules.expression import format_expression_display
from octorules.phases import PHASE_BY_NAME, PHASE_BY_PROVIDER_ID
from octorules.planner import (
    ChangeType,
    CustomRulesetPlan,
    ListPlan,
    PageShieldPolicyPlan,
    PhasePlan,
    RuleChange,
    ZonePlan,
)

# ANSI color codes
GREEN = "\033[32m"
RED = "\033[31m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


def _supports_color() -> bool:
    """Check if the terminal supports color."""
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _color(text: str, code: str, use_color: bool = True) -> str:
    if not use_color:
        return text
    return f"{code}{text}{RESET}"


_CHANGE_SYMBOLS: dict[ChangeType, str] = {
    ChangeType.ADD: "+",
    ChangeType.REMOVE: "-",
    ChangeType.MODIFY: "~",
    ChangeType.REORDER: "↕",
}

_CHANGE_COLORS: dict[ChangeType, str] = {
    ChangeType.ADD: GREEN,
    ChangeType.REMOVE: RED,
    ChangeType.MODIFY: YELLOW,
    ChangeType.REORDER: CYAN,
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


def _rule_detail_pairs(rule: dict | None) -> list[tuple[str, object]]:
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


def _format_add_remove_details(rule: dict | None, use_color: bool) -> list[str]:
    """Format rule details for an ADD or REMOVE change."""
    details = []
    for key, val in _rule_detail_pairs(rule):
        details.append(_color(f"      {key}: ", DIM, use_color) + f"{val!r}")
    return details


def _format_diff_value(
    key: str, val: object, prefix: str, color_code: str, use_color: bool
) -> list[str]:
    """Format a single diff value, pretty-printing long expression strings.

    Returns one or more lines.  The first line includes the key; continuation
    lines are indented and prefixed with the same ``prefix`` character.
    """
    if isinstance(val, str) and len(val) > 80:
        formatted = format_expression_display(val)
        if "\n" in formatted:
            flines = formatted.split("\n")
            pad = " " * (len(prefix) + 1)
            result = [
                _color(f"    {prefix} {key}: ", DIM, use_color)
                + _color(flines[0], color_code, use_color)
            ]
            for fl in flines[1:]:
                result.append(
                    _color(f"    {pad}", DIM, use_color) + _color(fl, color_code, use_color)
                )
            return result
    label = _color(f"    {prefix} {key}: ", DIM, use_color)
    return [label + _color(f"{val!r}", color_code, use_color)]


def _format_modify_details(change: RuleChange, use_color: bool) -> list[str]:
    """Format field-level diffs for a MODIFY change."""
    details = []
    for key, old_val, new_val in _compute_field_diffs(change):
        details.extend(_format_diff_value(key, old_val, "−", RED, use_color))
        details.extend(_format_diff_value(key, new_val, "+", GREEN, use_color))
    return details


def format_change(change: RuleChange, use_color: bool = True) -> list[str]:
    """Format a single rule change as lines of output."""
    symbol = _change_symbol(change.change_type)
    color = _change_color(change.change_type)
    label = change.change_type.value

    if change.change_type == ChangeType.REORDER:
        return [_color(f"  {symbol} reorder rules", color, use_color)]

    lines = [_color(f"  {symbol} {label}: {change.ref}", color, use_color)]
    if change.change_type == ChangeType.MODIFY:
        lines.extend(_format_modify_details(change, use_color))
    elif change.change_type == ChangeType.ADD:
        lines.extend(_format_add_remove_details(change.normalized_desired, use_color))
    elif change.change_type == ChangeType.REMOVE:
        lines.extend(_format_add_remove_details(change.normalized_current, use_color))
    return lines


def format_phase_plan(phase_plan: PhasePlan, use_color: bool = True) -> list[str]:
    """Format a phase plan as lines of output."""
    lines = []
    header = f"  {phase_plan.phase.friendly_name} ({phase_plan.phase.provider_id})"
    lines.append(_color(header, BOLD, use_color))
    for change in phase_plan.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_custom_ruleset_plan(crp: CustomRulesetPlan, use_color: bool = True) -> list[str]:
    """Format a custom ruleset plan as lines of output."""
    lines = []
    id_short = crp.ruleset_id[:8]
    header = f"  custom_ruleset: {crp.ruleset_name} ({id_short})"
    lines.append(_color(header, BOLD, use_color))
    for change in crp.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_list_plan(lp: ListPlan, use_color: bool = True) -> list[str]:
    """Format a list plan as lines of output."""
    lines = []
    header = f"  list: {lp.list_name} ({lp.list_kind})"
    lines.append(_color(header, BOLD, use_color))
    if lp.create:
        lines.append(_color("  + create list", GREEN, use_color))
    if lp.delete:
        lines.append(_color("  - delete list", RED, use_color))
    if lp.description_change is not None:
        old_desc, new_desc = lp.description_change
        lines.append(_color("  ~ description:", YELLOW, use_color))
        lines.append(_color("    − ", DIM, use_color) + _color(repr(old_desc), RED, use_color))
        lines.append(_color("    + ", DIM, use_color) + _color(repr(new_desc), GREEN, use_color))
    for change in lp.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_page_shield_policy_plan(pp: PageShieldPolicyPlan, use_color: bool = True) -> list[str]:
    """Format a Page Shield policy plan as lines of output."""
    lines = []
    header = f"  page_shield: {pp.description}"
    lines.append(_color(header, BOLD, use_color))
    if pp.create:
        lines.append(_color("  + create policy", GREEN, use_color))
    if pp.delete:
        lines.append(_color("  - delete policy", RED, use_color))
    for change in pp.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_zone_plan(zone_plan: ZonePlan, use_color: bool = True) -> str:
    """Format a full zone plan as a string."""
    lines: list[str] = []

    if not zone_plan.has_changes:
        lines.append(
            _color(f"Zone {zone_plan.display_name}: ", BOLD, use_color)
            + _color("no changes", DIM, use_color)
        )
        return "\n".join(lines)

    lines.append(
        _color(f"Zone {zone_plan.display_name}: ", BOLD, use_color)
        + f"{zone_plan.total_changes} change(s)"
    )

    for phase_plan in zone_plan.phase_plans:
        lines.extend(format_phase_plan(phase_plan, use_color))

    for crp in zone_plan.custom_ruleset_plans:
        lines.extend(format_custom_ruleset_plan(crp, use_color))

    for lp in zone_plan.list_plans:
        lines.extend(format_list_plan(lp, use_color))

    for psp in zone_plan.page_shield_policy_plans:
        lines.extend(format_page_shield_policy_plan(psp, use_color))

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
        psp_plans = []
        for psp in zp.page_shield_policy_plans:
            psp_entry: dict = {
                "description": psp.description,
                "create": psp.create,
                "delete": psp.delete,
            }
            if psp.policy_id:
                psp_entry["policy_id"] = psp.policy_id
            psp_changes = [_change_to_dict(c) for c in psp.changes]
            if psp_changes:
                psp_entry["changes"] = psp_changes
            psp_plans.append(psp_entry)
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
        if psp_plans:
            zone_entry["page_shield_policy_plans"] = psp_plans
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
        for psp in zp.page_shield_policy_plans:
            phase_label = f"page_shield:{psp.description}"
            if psp.create:
                lines.append(f"| + | {_md_escape(phase_label)} | | create policy |")
            if psp.delete:
                lines.append(f"| - | {_md_escape(phase_label)} | | delete policy |")
            for c in psp.changes:
                lines.append(_md_change_row(c, phase_label, pending_diffs, has_reorder=False))
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
            creates, removes, modifies, reorders = _html_render_changes(crp.changes, lines)
            lines.extend(_html_summary_row(creates, removes, modifies, reorders))
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

        for psp in zp.page_shield_policy_plans:
            lines.append(f"<h3>page_shield: {e(psp.description)}</h3>")
            lines.extend(_HTML_TABLE_HEADER)

            psp_creates = psp_removes = psp_modifies = 0

            if psp.create:
                psp_creates += 1
                lines.append("  <tr>")
                lines.append("    <td>Create</td>")
                lines.append("    <td></td>")
                lines.append("    <td>create policy</td>")
                lines.append("  </tr>")
            if psp.delete:
                psp_removes += 1
                lines.append("  <tr>")
                lines.append("    <td>Delete</td>")
                lines.append("    <td></td>")
                lines.append("    <td>delete policy</td>")
                lines.append("  </tr>")

            c_creates, c_removes, c_modifies, _ = _html_render_changes(psp.changes, lines)
            psp_creates += c_creates
            psp_removes += c_removes
            psp_modifies += c_modifies
            lines.extend(_html_summary_row(psp_creates, psp_removes, psp_modifies, 0))
            lines.append("</table>")

    if not any(zp.has_changes for zp in zone_plans):
        lines.append("<b>No changes were planned</b>")

    return "\n".join(lines)


_FORMAT_RENDERERS: dict[str, callable] = {
    "json": format_plan_json,
    "markdown": format_plan_markdown,
    "html": format_plan_html,
}


def print_plan(zone_plans: list[ZonePlan], file: IO[str] | None = None, fmt: str = "text") -> None:
    """Print the full plan for all zones.

    Only zones with changes are shown; unchanged zones are omitted.
    """
    if file is None:
        file = sys.stdout

    renderer = _FORMAT_RENDERERS.get(fmt)
    if renderer is not None:
        print(renderer(zone_plans), file=file)
        return

    use_color = _supports_color() and file is sys.stdout
    total_changes = _total_changes(zone_plans)

    for zp in zone_plans:
        if not zp.has_changes:
            continue
        print(format_zone_plan(zp, use_color), file=file)
        print(file=file)

    if total_changes == 0:
        print(_color("No changes detected.", DIM, use_color), file=file)
    else:
        summary = f"Total: {total_changes} change(s) across {len(zone_plans)} zone(s)."
        print(_color(summary, BOLD, use_color), file=file)


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
            adds = removes = modifies = 0
            if pp:
                for c in pp.changes:
                    if c.change_type == ChangeType.ADD:
                        adds += 1
                    elif c.change_type == ChangeType.REMOVE:
                        removes += 1
                    elif c.change_type == ChangeType.MODIFY:
                        modifies += 1

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
            cr_adds = cr_removes = cr_modifies = 0
            for c in crp.changes:
                if c.change_type == ChangeType.ADD:
                    cr_adds += 1
                elif c.change_type == ChangeType.REMOVE:
                    cr_removes += 1
                elif c.change_type == ChangeType.MODIFY:
                    cr_modifies += 1
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
            lp_adds = lp_removes = lp_modifies = 0
            if lp.create:
                lp_adds += 1
            if lp.delete:
                lp_removes += 1
            if lp.description_change is not None:
                lp_modifies += 1
            for c in lp.changes:
                if c.change_type == ChangeType.ADD:
                    lp_adds += 1
                elif c.change_type == ChangeType.REMOVE:
                    lp_removes += 1
                elif c.change_type == ChangeType.MODIFY:
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

        # Include Page Shield policy data in report
        for psp in zp.page_shield_policy_plans:
            psp_adds = psp_removes = psp_modifies = 0
            if psp.create:
                psp_adds += 1
            if psp.delete:
                psp_removes += 1
            for c in psp.changes:
                if c.change_type == ChangeType.ADD:
                    psp_adds += 1
                elif c.change_type == ChangeType.REMOVE:
                    psp_removes += 1
                elif c.change_type == ChangeType.MODIFY:
                    psp_modifies += 1
            psp_status = "drifted" if (psp_adds or psp_removes or psp_modifies) else "in_sync"
            if psp_status != "in_sync":
                zone_has_drift = True
            phases_data.append(
                {
                    "phase": f"page_shield:{psp.description}",
                    "provider_id": "page_shield_policies",
                    "status": psp_status,
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": psp_adds,
                    "removes": psp_removes,
                    "modifies": psp_modifies,
                }
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
    if file is None:
        file = sys.stdout

    if fmt == "json":
        print(format_report_json(report_data), file=file)
    else:
        print(format_report_csv(report_data), end="", file=file)
