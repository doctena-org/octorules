"""Expression whitespace normalization and display formatting.

Collapses whitespace outside double-quoted strings to single spaces,
allowing users to write readable multi-line YAML block scalars that
get normalized before sending to Cloudflare and before linting.

Also provides a display formatter that reverses the collapse for
human-readable plan output.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator

log = logging.getLogger("octorules")


class QuoteAwareScanner:
    """Iterate over characters in an expression, tracking double-quote state.

    Yields ``(index, char, in_quote)`` tuples.  Escaped quotes (``\\"``)
    inside double-quoted strings do not toggle the quoting state.

    After iteration, ``unmatched_quote`` is True if the string ended
    inside an unclosed quote.

    Usage::

        scanner = QuoteAwareScanner(expr)
        for i, ch, in_quote in scanner:
            ...
        if scanner.unmatched_quote:
            log.warning("unmatched quote")
    """

    __slots__ = ("_expr", "unmatched_quote")

    def __init__(self, expr: str) -> None:
        self._expr = expr
        self.unmatched_quote = False

    def __iter__(self) -> Iterator[tuple[int, str, bool]]:
        in_quote = False
        escaped = False
        for i, ch in enumerate(self._expr):
            if escaped:
                escaped = False
                yield i, ch, in_quote
                continue
            if ch == "\\" and in_quote:
                escaped = True
                yield i, ch, in_quote
                continue
            if ch == '"':
                in_quote = not in_quote
            yield i, ch, in_quote
        self.unmatched_quote = in_quote


def normalize_expression(expr: str) -> str:
    """Collapse whitespace outside double-quoted strings to single spaces.

    Inside double-quoted strings, all characters (including whitespace) are
    preserved verbatim.  Escaped quotes (``\\"``) do not close the string.

    Whitespace immediately after ``{`` and before ``}`` is stripped to match
    Cloudflare's canonical form (e.g. ``{"a" "b"}`` not ``{ "a" "b" }``).
    """
    result: list[str] = []
    ws_run = False
    after_open_brace = False

    scanner = QuoteAwareScanner(expr)
    for _i, ch, in_quote in scanner:
        if in_quote or (ch == '"'):
            # Flush pending whitespace before entering/exiting quotes
            if ws_run:
                if not after_open_brace:
                    result.append(" ")
                ws_run = False
            after_open_brace = False
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
        elif ch == "\\":
            # Backslash outside quotes — just emit it
            if ws_run:
                if not after_open_brace:
                    result.append(" ")
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

    if scanner.unmatched_quote:
        log.warning("Unmatched quote in expression: %.80s...", expr if len(expr) > 80 else expr)

    return "".join(result).strip()


# ---------------------------------------------------------------------------
# Display formatting (reverse of normalization — for plan output readability)
# ---------------------------------------------------------------------------


def _find_closing_brace(expr: str, start: int) -> int:
    """Return index of ``}`` matching the ``{`` at *start*, or -1."""
    for i, ch, in_quote in QuoteAwareScanner(expr[start + 1 :]):
        if not in_quote and ch == "}":
            return start + 1 + i
    return -1


def _split_set_items(content: str) -> list[str]:
    """Split set content into items, preserving quoted strings."""
    items: list[str] = []
    current: list[str] = []
    for _i, ch, in_quote in QuoteAwareScanner(content):
        if in_quote:
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
    depth = 0
    i = 0
    n = len(expr)

    # Use index-based iteration so we can skip ahead for multi-char tokens
    scanner = QuoteAwareScanner(expr)
    scan_iter = iter(scanner)
    while i < n:
        try:
            _idx, ch, in_quote = next(scan_iter)
        except StopIteration:
            break

        if in_quote:
            out.append(ch)
            i += 1
            continue

        if ch == '"':
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
                    # Skip ahead in both the string and the scanner
                    skip = end - i
                    for _ in range(skip):
                        try:
                            next(scan_iter)
                        except StopIteration:
                            break
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
            # Skip 4 more chars (" and" minus the current " ")
            for _ in range(4):
                try:
                    next(scan_iter)
                except StopIteration:
                    break
            i += 5
            continue

        if expr[i : i + 4] == " or ":
            out.append("\n")
            out.append("  " * depth)
            out.append("or ")
            for _ in range(3):
                try:
                    next(scan_iter)
                except StopIteration:
                    break
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
