"""Lint report formatters — text, JSON, and SARIF output."""

from __future__ import annotations

import json
import sys
from typing import IO, Any

from octorules._color import Pen, supports_color
from octorules.linter.engine import LintContext, LintResult, Severity

_SEVERITY_PEN_METHOD = {
    Severity.ERROR: "error",
    Severity.WARNING: "warning",
    Severity.INFO: "info",
}


def _format_result(r: LintResult, p: Pen) -> str:
    """Format a single lint result with optional color."""
    method = _SEVERITY_PEN_METHOD[r.severity]
    parts = [getattr(p, method)(f"[{r.severity.name}]")]
    parts.append(p.muted(r.rule_id))
    if r.phase:
        loc = f"({r.phase}"
        if r.ref:
            loc += f" / {r.ref}"
        if r.location:
            loc += f" / {r.location}"
        loc += ")"
        parts.append(p.muted(loc))
    parts.append(r.message)
    if r.suggestion:
        parts.append(p.muted(f"[fix: {r.suggestion}]"))
    return " ".join(parts)


def format_text(
    ctx: LintContext, stream: IO[str] | None = None, *, use_color: bool | None = None
) -> str:
    """Format lint results as human-readable text.

    If stream is provided, writes to it and returns empty string.
    Otherwise returns the formatted string.

    *use_color* defaults to auto-detection (TTY + NO_COLOR/FORCE_COLOR).
    """
    if use_color is None:
        target = stream if stream is not None else sys.stdout
        use_color = supports_color() and target is sys.stdout

    p = Pen(use_color)
    lines: list[str] = []
    header = f"octorules lint: {ctx.file_path or ctx.zone_name or 'stdin'}"
    lines.append(p.header(header))
    lines.append("=" * len(header))

    if not ctx.results:
        lines.append(p.success("No issues found."))
    else:
        errors = [r for r in ctx.results if r.severity == Severity.ERROR]
        warnings = [r for r in ctx.results if r.severity == Severity.WARNING]
        infos = [r for r in ctx.results if r.severity == Severity.INFO]

        for label, group, method in [
            ("Errors", errors, "error"),
            ("Warnings", warnings, "warning"),
            ("Info", infos, "info"),
        ]:
            if group:
                lines.append(getattr(p, method)(f"{label} ({len(group)}):"))
                for r in group:
                    lines.append(f"  {_format_result(r, p)}")
                lines.append("")

        total_line = f"Total: {len(errors)} error(s), {len(warnings)} warning(s), {len(infos)} info"
        if ctx.suppressed_count:
            total_line += f" ({ctx.suppressed_count} suppressed)"
        lines.append(p.header(total_line))

    lines.append("")
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
                "location": r.location,
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
            phys: dict[str, Any] = {
                "artifactLocation": {"uri": ctx.file_path},
            }
            # Extract line number from location "file.yaml:42"
            if r.location and ":" in r.location:
                try:
                    line_no = int(r.location.rsplit(":", 1)[1])
                    phys["region"] = {"startLine": line_no}
                except (ValueError, IndexError):
                    pass
            location: dict[str, Any] = {"physicalLocation": phys}
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


def format_summary(ctx: LintContext, stream: IO[str] | None = None, **_kwargs) -> str:
    """Format lint results as a one-line summary (counts only).

    Useful for CI pipelines that only need pass/fail without detail.
    """
    errors = len([r for r in ctx.results if r.severity == Severity.ERROR])
    warnings = len([r for r in ctx.results if r.severity == Severity.WARNING])
    infos = len([r for r in ctx.results if r.severity == Severity.INFO])
    parts = []
    if errors:
        parts.append(f"{errors} error(s)")
    if warnings:
        parts.append(f"{warnings} warning(s)")
    if infos:
        parts.append(f"{infos} info")
    text = ", ".join(parts) if parts else "clean"
    zone = ctx.zone_name or ctx.file_path or "stdin"
    line = f"{zone}: {text}\n"
    if stream:
        stream.write(line)
        return ""
    return line


# Format name → formatter function mapping
FORMATTERS = {
    "text": format_text,
    "json": format_json,
    "sarif": format_sarif,
    "summary": format_summary,
}
