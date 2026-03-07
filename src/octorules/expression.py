"""Expression whitespace normalization and display formatting.

Collapses whitespace outside double-quoted strings to single spaces,
allowing users to write readable multi-line YAML block scalars that
get normalized before sending to Cloudflare and before linting.

Also provides a display formatter that reverses the collapse for
human-readable plan output.
"""

from __future__ import annotations

import logging

log = logging.getLogger("octorules")


def normalize_expression(expr: str) -> str:
    """Collapse whitespace outside double-quoted strings to single spaces.

    Inside double-quoted strings, all characters (including whitespace) are
    preserved verbatim.  Escaped quotes (``\\"``) do not close the string.

    Whitespace immediately after ``{`` and before ``}`` is stripped to match
    Cloudflare's canonical form (e.g. ``{"a" "b"}`` not ``{ "a" "b" }``).
    """
    result: list[str] = []
    in_quote = False
    escaped = False
    ws_run = False
    after_open_brace = False

    for ch in expr:
        if escaped:
            result.append(ch)
            escaped = False
            after_open_brace = False
            continue

        if ch == "\\":
            if in_quote:
                result.append(ch)
                escaped = True
            else:
                # Backslash outside quotes — just emit it
                if ws_run:
                    if not after_open_brace:
                        result.append(" ")
                    ws_run = False
                after_open_brace = False
                result.append(ch)
            continue

        if ch == '"':
            if in_quote:
                result.append(ch)
                in_quote = False
            else:
                if ws_run:
                    if not after_open_brace:
                        result.append(" ")
                    ws_run = False
                after_open_brace = False
                result.append(ch)
                in_quote = True
            continue

        if in_quote:
            result.append(ch)
            continue

        # Outside quotes: collapse whitespace
        if ch in (" ", "\t", "\n", "\r"):
            ws_run = True
        elif ch == "}":
            # Drop pending whitespace before }
            ws_run = False
            after_open_brace = False
            result.append(ch)
        else:
            if ws_run:
                if not after_open_brace:
                    result.append(" ")
                ws_run = False
            after_open_brace = ch == "{"
            result.append(ch)

    if in_quote:
        log.warning("Unmatched quote in expression: %.80s...", expr if len(expr) > 80 else expr)

    return "".join(result).strip()


# ---------------------------------------------------------------------------
# Display formatting (reverse of normalization — for plan output readability)
# ---------------------------------------------------------------------------


def _find_closing_brace(expr: str, start: int) -> int:
    """Return index of ``}`` matching the ``{`` at *start*, or -1."""
    in_quote = False
    escaped = False
    for i in range(start + 1, len(expr)):
        ch = expr[i]
        if escaped:
            escaped = False
            continue
        if in_quote:
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            continue
        if ch == '"':
            in_quote = True
            continue
        if ch == "}":
            return i
    return -1


def _split_set_items(content: str) -> list[str]:
    """Split set content into items, preserving quoted strings."""
    items: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for ch in content:
        if escaped:
            current.append(ch)
            escaped = False
            continue
        if in_quote:
            current.append(ch)
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            continue
        if ch == '"':
            in_quote = True
            current.append(ch)
            continue
        if ch == " ":
            if current:
                items.append("".join(current))
                current = []
            continue
        current.append(ch)
    if current:
        items.append("".join(current))
    return items


def format_expression_display(expr: str, max_line: int = 80) -> str:
    """Format a normalized expression for human-readable multi-line display.

    Short expressions (≤ *max_line* chars) are returned unchanged.  Long
    expressions are broken before ``and``/``or`` operators and at set
    literal boundaries (``{…}``), with indentation reflecting paren depth.
    """
    if len(expr) <= max_line:
        return expr

    out: list[str] = []
    in_quote = False
    escaped = False
    depth = 0
    i = 0
    n = len(expr)

    while i < n:
        ch = expr[i]

        if escaped:
            out.append(ch)
            escaped = False
            i += 1
            continue

        if in_quote:
            out.append(ch)
            if ch == "\\":
                escaped = True
            elif ch == '"':
                in_quote = False
            i += 1
            continue

        if ch == '"':
            in_quote = True
            out.append(ch)
            i += 1
            continue

        if ch == "(":
            out.append(ch)
            depth += 1
            i += 1
            continue

        if ch == ")":
            depth = max(0, depth - 1)
            out.append(ch)
            i += 1
            continue

        # Set literal — format items one-per-line if the set is long
        if ch == "{":
            end = _find_closing_brace(expr, i)
            if end != -1 and end - i > max_line // 2:
                items = _split_set_items(expr[i + 1 : end])
                if len(items) > 1:
                    item_indent = "  " * (depth + 1)
                    close_indent = "  " * depth
                    out.append("{\n")
                    for item in items:
                        out.append(f"{item_indent}{item}\n")
                    out.append(f"{close_indent}}}")
                    i = end + 1
                    continue
            out.append(ch)
            i += 1
            continue

        if ch == "}":
            out.append(ch)
            i += 1
            continue

        # Break before `and` / `or` operators
        if expr[i : i + 5] == " and ":
            out.append("\n")
            out.append("  " * depth)
            out.append("and ")
            i += 5
            continue

        if expr[i : i + 4] == " or ":
            out.append("\n")
            out.append("  " * depth)
            out.append("or ")
            i += 4
            continue

        out.append(ch)
        i += 1

    return "".join(out)


# ---------------------------------------------------------------------------
# CSP value formatting (for page_shield_policies dump output)
# ---------------------------------------------------------------------------


def format_csp_value(value: str, max_line: int = 80) -> str:
    """Format a CSP value string for readable multi-line YAML.

    Short values (≤ *max_line* chars) are returned unchanged.  Long values
    are formatted with one source per line: directive names at the base
    indentation level and their sources indented by 2 spaces.

    The result normalizes back to the original via ``normalize_expression()``.
    """
    if len(value) <= max_line:
        return value

    # Split on "; " (directive boundary), keeping the semicolons
    parts = value.split("; ")
    lines: list[str] = []
    for i, part in enumerate(parts):
        tokens = part.split(" ")
        # Directive name (e.g. "script-src") on its own line
        lines.append(tokens[0])
        for j, token in enumerate(tokens[1:], 1):
            # Attach semicolon to the last token of non-final directives
            if i < len(parts) - 1 and j == len(tokens) - 1:
                lines.append(f"  {token};")
            else:
                lines.append(f"  {token}")
    return "\n".join(lines)
