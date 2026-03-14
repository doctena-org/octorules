"""Lint report formatters — text, JSON, and SARIF output."""

from __future__ import annotations

import json
from typing import IO, Any

from octorules.linter.engine import LintContext, Severity


def format_text(ctx: LintContext, stream: IO[str] | None = None) -> str:
    """Format lint results as human-readable text.

    If stream is provided, writes to it and returns empty string.
    Otherwise returns the formatted string.
    """
    lines: list[str] = []
    header = f"octorules lint: {ctx.file_path or ctx.zone_name or 'stdin'}"
    lines.append(header)
    lines.append("=" * len(header))

    if not ctx.results:
        lines.append("No issues found.")
    else:
        # Group by severity
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        warnings = [r for r in ctx.results if r.severity == Severity.WARNING]
        infos = [r for r in ctx.results if r.severity == Severity.INFO]

        for label, group in [("Errors", errors), ("Warnings", warnings), ("Info", infos)]:
            if group:
                lines.append(f"{label} ({len(group)}):")
                for r in group:
                    lines.append(f"  {r}")
                lines.append("")

        total_line = f"Total: {len(errors)} error(s), {len(warnings)} warning(s), {len(infos)} info"
        if ctx.suppressed_count:
            total_line += f" ({ctx.suppressed_count} suppressed)"
        lines.append(total_line)

    lines.append("")  # blank line after each zone for visual separation
    text = "\n".join(lines) + "\n"
    if stream:
        stream.write(text)
        return ""
    return text


def format_json(ctx: LintContext, stream: IO[str] | None = None) -> str:
    """Format lint results as JSON."""
    data = _to_json_data(ctx)
    text = json.dumps(data, indent=2) + "\n"
    if stream:
        stream.write(text)
        return ""
    return text


def format_sarif(ctx: LintContext, stream: IO[str] | None = None) -> str:
    """Format lint results as SARIF (Static Analysis Results Interchange Format).

    Compatible with GitHub Code Scanning.
    """
    sarif = _to_sarif(ctx)
    text = json.dumps(sarif, indent=2) + "\n"
    if stream:
        stream.write(text)
        return ""
    return text


def _to_json_data(ctx: LintContext) -> dict[str, Any]:
    """Convert lint context to a JSON-serializable dict."""
    return {
        "file": ctx.file_path,
        "zone": ctx.zone_name,
        "plan_tier": ctx.plan_tier,
        "results": [
            {
                "rule_id": r.rule_id,
                "severity": r.severity.name.lower(),
                "message": r.message,
                "phase": r.phase,
                "ref": r.ref,
                "field": r.field,
                "suggestion": r.suggestion,
            }
            for r in ctx.results
        ],
        "summary": {
            "total": len(ctx.results),
            "errors": len(ctx.errors),
            "warnings": len(ctx.warnings),
            "info": len([r for r in ctx.results if r.severity == Severity.INFO]),
            "suppressed": ctx.suppressed_count,
        },
    }


_SEVERITY_TO_SARIF = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "note",
}


def _to_sarif(ctx: LintContext) -> dict[str, Any]:
    """Convert lint context to SARIF format."""
    rules_seen: dict[str, dict] = {}
    results: list[dict] = []

    for r in ctx.results:
        if r.rule_id not in rules_seen:
            rules_seen[r.rule_id] = {
                "id": r.rule_id,
                "shortDescription": {"text": r.rule_id},
            }

        result: dict[str, Any] = {
            "ruleId": r.rule_id,
            "level": _SEVERITY_TO_SARIF[r.severity],
            "message": {"text": r.message},
        }
        if r.suggestion:
            result["fixes"] = [
                {
                    "description": {"text": r.suggestion},
                }
            ]
        # Location
        if ctx.file_path:
            location: dict[str, Any] = {
                "physicalLocation": {
                    "artifactLocation": {"uri": ctx.file_path},
                }
            }
            # Add logical location
            logical_parts = []
            if r.phase:
                logical_parts.append(r.phase)
            if r.ref:
                logical_parts.append(r.ref)
            if r.field:
                logical_parts.append(r.field)
            if logical_parts:
                location["logicalLocations"] = [{"fullyQualifiedName": "/".join(logical_parts)}]
            result["locations"] = [location]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "octorules-lint",
                        "informationUri": "https://github.com/doctena-org/octorules",
                        "rules": list(rules_seen.values()),
                    }
                },
                "results": results,
            }
        ],
    }


# Format name → formatter function mapping
FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
}
