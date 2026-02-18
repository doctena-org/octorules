"""Colored terminal output for plan results."""

from __future__ import annotations

import csv
import io
import json
import sys
from html import escape as html_escape
from typing import IO

from octorules.phases import PHASE_BY_CF, PHASE_BY_NAME
from octorules.planner import ChangeType, PhasePlan, RuleChange, ZonePlan

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


def _change_symbol(change_type: ChangeType) -> str:
    return {
        ChangeType.ADD: "+",
        ChangeType.REMOVE: "-",
        ChangeType.MODIFY: "~",
        ChangeType.REORDER: "↕",
    }[change_type]


def _change_color(change_type: ChangeType) -> str:
    return {
        ChangeType.ADD: GREEN,
        ChangeType.REMOVE: RED,
        ChangeType.MODIFY: YELLOW,
        ChangeType.REORDER: CYAN,
    }[change_type]


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


def _format_modify_details(change: RuleChange, use_color: bool) -> list[str]:
    """Format field-level diffs for a MODIFY change."""
    details = []
    for key, old_val, new_val in _compute_field_diffs(change):
        details.append(
            _color(f"      {key}: ", DIM, use_color)
            + _color(f"{old_val!r}", RED, use_color)
            + " → "
            + _color(f"{new_val!r}", GREEN, use_color)
        )
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
    header = f"  {phase_plan.phase.friendly_name} ({phase_plan.phase.cf_phase})"
    lines.append(_color(header, BOLD, use_color))
    for change in phase_plan.changes:
        lines.extend(format_change(change, use_color))
    return lines


def format_zone_plan(zone_plan: ZonePlan, use_color: bool = True) -> str:
    """Format a full zone plan as a string."""
    lines: list[str] = []

    if not zone_plan.has_changes:
        lines.append(
            _color(f"Zone {zone_plan.zone_name}: ", BOLD, use_color)
            + _color("no changes", DIM, use_color)
        )
        return "\n".join(lines)

    lines.append(
        _color(f"Zone {zone_plan.zone_name}: ", BOLD, use_color)
        + f"{zone_plan.total_changes} change(s)"
    )

    for phase_plan in zone_plan.phase_plans:
        lines.extend(format_phase_plan(phase_plan, use_color))

    return "\n".join(lines)


def _total_changes(zone_plans: list[ZonePlan]) -> int:
    """Sum total changes across all zone plans."""
    return sum(zp.total_changes for zp in zone_plans)


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
            changes = []
            for c in pp.changes:
                change_data: dict = {
                    "type": c.change_type.value,
                    "ref": c.ref,
                }
                norm_current = c.normalized_current
                if norm_current is not None:
                    change_data["current"] = norm_current
                norm_desired = c.normalized_desired
                if norm_desired is not None:
                    change_data["desired"] = norm_desired
                changes.append(change_data)
            phase_plans.append(
                {
                    "phase": pp.phase.friendly_name,
                    "cf_phase": pp.phase.cf_phase,
                    "changes": changes,
                }
            )
        zones.append(
            {
                "zone": zp.zone_name,
                "phase_plans": phase_plans,
                "total_changes": zp.total_changes,
            }
        )
    result = {
        "zones": zones,
        "total_changes": total_changes,
        "has_changes": total_changes > 0,
    }
    return json.dumps(result, indent=2)


def _md_escape(text: str) -> str:
    """Escape pipe characters for markdown tables."""
    return str(text).replace("|", "\\|")


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
        lines.append(f"### Zone: `{zp.zone_name}`")
        lines.append("")
        lines.append("| Op | Phase | Ref | Details |")
        lines.append("|---|---|---|---|")
        for pp in zp.phase_plans:
            for c in pp.changes:
                op = _change_symbol(c.change_type)
                phase = pp.phase.friendly_name
                ref = _md_escape(c.ref)
                if c.change_type == ChangeType.MODIFY and c.current and c.desired:
                    diffs = []
                    for key, old_val, new_val in _compute_field_diffs(c):
                        old_esc = _md_escape(repr(old_val))
                        new_esc = _md_escape(repr(new_val))
                        diffs.append(f"`{key}`: ~~{old_esc}~~ → **{new_esc}**")
                    details = "; ".join(diffs)
                elif c.change_type == ChangeType.REORDER:
                    details = "reorder rules"
                else:
                    rule = (
                        c.normalized_desired
                        if c.change_type == ChangeType.ADD
                        else c.normalized_current
                    )
                    pairs = _rule_detail_pairs(rule)
                    if pairs:
                        parts = [f"`{key}`: {val!r}" for key, val in pairs]
                        details = _md_escape("; ".join(parts))
                    else:
                        details = ""
                lines.append(f"| {op} | {phase} | {ref} | {details} |")
        lines.append("")

    if total_changes == 0:
        lines.append("**No changes detected.**")
    else:
        lines.append(f"**Total: {total_changes} change(s) across {len(zone_plans)} zone(s).**")
    return "\n".join(lines)


def _html_op_name(change_type: ChangeType) -> str:
    """Human-readable operation name for HTML output."""
    return {
        ChangeType.ADD: "Create",
        ChangeType.REMOVE: "Delete",
        ChangeType.MODIFY: "Update",
        ChangeType.REORDER: "Reorder",
    }[change_type]


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

        lines.append(f"<h2>{e(zp.zone_name)}</h2>")

        for pp in zp.phase_plans:
            lines.append(f"<h3>{e(pp.phase.friendly_name)}</h3>")
            lines.append("<table>")
            lines.append("  <tr>")
            lines.append("    <th>Operation</th>")
            lines.append("    <th>Ref</th>")
            lines.append("    <th>Details</th>")
            lines.append("  </tr>")

            creates = removes = modifies = reorders = 0

            for c in pp.changes:
                op = _html_op_name(c.change_type)

                if c.change_type in (ChangeType.ADD, ChangeType.REMOVE):
                    if c.change_type == ChangeType.ADD:
                        creates += 1
                        detail_pairs = _rule_detail_pairs(c.normalized_desired)
                    else:
                        removes += 1
                        detail_pairs = _rule_detail_pairs(c.normalized_current)
                    # Single row per Create/Delete (matches octodns)
                    lines.append("  <tr>")
                    lines.append(f"    <td>{e(op)}</td>")
                    lines.append(f"    <td>{e(c.ref)}</td>")
                    if detail_pairs:
                        parts = [
                            f"<code>{e(key)}</code>: {e(str(val))}" for key, val in detail_pairs
                        ]
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
                        # First diff row carries the operation and ref
                        if i == 0:
                            lines.append("  <tr>")
                            lines.append(f"    <td>{e(op)}</td>")
                            lines.append(f"    <td>{e(c.ref)}</td>")
                        else:
                            lines.append("  <tr>")
                            lines.append("    <td colspan=2></td>")
                        lines.append(
                            f"    <td><code>{e(key)}</code>: <ins>{e(str(new_val))}</ins></td>"
                        )
                        lines.append("  </tr>")
                        # Continuation row with old value
                        lines.append("  <tr>")
                        lines.append("    <td colspan=2></td>")
                        lines.append(
                            f"    <td><code>{e(key)}</code>: <del>{e(str(old_val))}</del></td>"
                        )
                        lines.append("  </tr>")
                    if not diffs:
                        lines.append("  <tr>")
                        lines.append(f"    <td>{e(op)}</td>")
                        lines.append(f"    <td>{e(c.ref)}</td>")
                        lines.append("    <td></td>")
                        lines.append("  </tr>")

            # Summary row inside the table (matches octodns style)
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
            lines.append("  <tr>")
            lines.append(f"    <td colspan=3>Summary: {summary}</td>")
            lines.append("  </tr>")
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
    # Index phase plans by (zone, cf_phase) for quick lookup
    changes_index: dict[tuple[str, str], PhasePlan] = {}
    for zp in zone_plans:
        for pp in zp.phase_plans:
            changes_index[(zp.zone_name, pp.phase.cf_phase)] = pp

    zones_data = []
    summary_in_sync = 0
    summary_drifted = 0

    for zp in zone_plans:
        zone_name = zp.zone_name
        desired = desired_by_zone.get(zone_name, {})
        current = current_by_zone.get(zone_name, {})

        # Build the union of all phases present in either desired or current
        all_cf_phases: set[str] = set()
        for friendly_name in desired:
            if friendly_name in PHASE_BY_NAME:
                all_cf_phases.add(PHASE_BY_NAME[friendly_name].cf_phase)
        for cf_phase in current:
            if cf_phase in PHASE_BY_CF:
                all_cf_phases.add(cf_phase)

        phases_data = []
        zone_has_drift = False

        for cf_phase in sorted(all_cf_phases):
            if cf_phase not in PHASE_BY_CF:
                continue
            phase = PHASE_BY_CF[cf_phase]
            friendly_name = phase.friendly_name

            yaml_rules = len(desired.get(friendly_name, []))
            live_rules = len(current.get(cf_phase, []))

            # Count changes from the phase plan if one exists
            pp = changes_index.get((zone_name, cf_phase))
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
            has_live = cf_phase in current and len(current[cf_phase]) > 0

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
                    "cf_phase": cf_phase,
                    "status": status,
                    "yaml_rules": yaml_rules,
                    "live_rules": live_rules,
                    "adds": adds,
                    "removes": removes,
                    "modifies": modifies,
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
        "CF Phase",
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
                    phase["cf_phase"],
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
