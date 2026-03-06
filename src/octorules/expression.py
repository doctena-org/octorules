"""Expression whitespace normalization.

Collapses whitespace outside double-quoted strings to single spaces,
allowing users to write readable multi-line YAML block scalars that
get normalized before sending to Cloudflare and before linting.
"""

from __future__ import annotations


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

    return "".join(result).strip()
