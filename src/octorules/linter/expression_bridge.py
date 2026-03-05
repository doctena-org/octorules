"""Expression bridge — wirefilter FFI integration with graceful fallback.

When the optional octorules-wirefilter package is installed, this module
delegates expression parsing to the actual wirefilter engine (same parser
Cloudflare uses). When not installed, falls back to a best-effort regex
parser that extracts fields, operators, and values from expressions.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from dataclasses import dataclass, field

log = logging.getLogger("octorules.linter")

# Try to import the optional wirefilter FFI bindings
try:
    from octorules_wirefilter import parse_expression as _wf_parse

    WIREFILTER_AVAILABLE = True
except ImportError:
    WIREFILTER_AVAILABLE = False


@dataclass
class ExpressionInfo:
    """Extracted information from a parsed expression."""

    raw: str
    fields_used: list[str] = field(default_factory=list)
    functions_used: list[str] = field(default_factory=list)
    operators_used: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    regex_literals: list[str] = field(default_factory=list)
    ip_literals: list[str] = field(default_factory=list)
    int_literals: list[int] = field(default_factory=list)
    has_regex: bool = False
    parse_error: str = ""
    """Empty on success.  On wirefilter parse failure, contains the error
    message (e.g. ``"unknown field `bogus`"``).  On FFI crash, contains
    ``"ExceptionType: message"`` and the linter fields are regex-extracted."""
    parse_error_type: str = ""
    """Classifies the parse result source:

    - ``""`` — success (wirefilter or regex, no error).
    - ``"wirefilter_parse"`` — wirefilter rejected the expression (semantic
      error); fields are regex-extracted as fallback.
    - ``"wirefilter_crash"`` — FFI call raised an exception; fields are
      regex-extracted as fallback.
    - ``"regex_fallback"`` — wirefilter not installed; fields are
      regex-extracted (no error, best-effort mode).
    """


# --- Regex patterns for best-effort expression analysis ---

# Known CF fields pattern (dotted names like http.request.uri.path)
_FIELD_PATTERN = re.compile(r"\b((?:http|ip|ssl|cf|raw)\.[a-z][a-z0-9_.]*[a-z0-9])\b")

# Known operators (not function-style — these don't use parenthesized arguments)
_OPERATORS = frozenset(
    {
        "eq",
        "ne",
        "lt",
        "le",
        "gt",
        "ge",
        "contains",
        "matches",
        "in",
        "not",
        "and",
        "or",
        "xor",
        "==",
        "!=",
        "~",
        "~~",
        "wildcard",
        "strict",
        "bitwise_and",
    }
)

# Tokens that are both CF operators and look like function calls (take parenthesized args).
# These should be classified as functions when followed by '(' .
_OPERATOR_FUNCTIONS = frozenset({"starts_with", "ends_with"})

# Function call pattern
_FUNCTION_PATTERN = re.compile(r"\b([a-z_][a-z0-9_]*)\s*\(")

# String literal (double-quoted)
_STRING_LITERAL_PATTERN = re.compile(r'"((?:[^"\\]|\\.)*)"')

# Regex literal (CF uses ~"pattern" or matches "pattern")
_REGEX_LITERAL_PATTERN = re.compile(r'(?:~\s*"((?:[^"\\]|\\.)*)"|matches\s+"((?:[^"\\]|\\.)*)")')

# Integer literal
_INT_LITERAL_PATTERN = re.compile(r"\b(\d+)\b")

# IP literal — IPv4 with optional CIDR
_IPV4_LITERAL_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b")

# IPv6 candidate — hex digits and colons, must contain at least one ':'
# followed by optional CIDR.  Validated with ipaddress module after extraction.
_IPV6_CANDIDATE_PATTERN = re.compile(
    r"(?<![a-zA-Z0-9_.])([0-9a-fA-F]*:[0-9a-fA-F:]*(?:/\d{1,3})?)(?![a-zA-Z0-9_.])"
)

# Set/list literal: { "val1" "val2" }
_SET_LITERAL_PATTERN = re.compile(r"\{([^}]*)\}")


def parse_expression(expr: str, phase: str | None = None) -> ExpressionInfo:
    """Parse a Cloudflare ruleset expression and extract components.

    Uses wirefilter FFI when available, falls back to regex analysis.
    The optional *phase* selects the appropriate wirefilter scheme so
    that transform-phase functions (e.g. ``http.request.uri.path``) are
    recognised as callable rather than as plain fields.
    """
    if WIREFILTER_AVAILABLE:
        return _parse_with_wirefilter(expr, phase=phase)
    info = _parse_with_regex(expr)
    info.parse_error_type = "regex_fallback"
    return info


def _parse_with_wirefilter(expr: str, *, phase: str | None = None) -> ExpressionInfo:
    """Parse using the wirefilter FFI bindings.

    On parse failure, falls back to regex extraction so the linter's
    semantic rules (F001, E001, etc.) still fire on the expression.
    The wirefilter parse error is preserved in ``parse_error``.

    Why fall back instead of returning empty results?  Wirefilter rejects
    some expressions that are semantically wrong but syntactically
    extractable — e.g. ``http.host gt 5`` (type mismatch) or
    ``bogus_fn(http.host)`` (unknown function).  If we returned empty
    lists, the AST linter would have no fields/operators to inspect and
    rules like F001 and E001 would silently skip.  By running regex
    extraction on the rejected expression we give the linter enough
    material to produce its own diagnostics, while ``parse_error`` still
    records the authoritative wirefilter rejection.
    """
    info = ExpressionInfo(raw=expr)
    try:
        result = _wf_parse(expr, phase=phase)
        if isinstance(result, dict):
            if "error" in result:
                # Wirefilter rejected the expression — fall back to regex
                # so the linter still gets fields/operators to analyze.
                # See docstring above for rationale.
                log.warning("Wirefilter parse error, falling back to regex: %s", result["error"])
                info = _parse_with_regex(expr)
                info.parse_error = result["error"]
                info.parse_error_type = "wirefilter_parse"
                return info
            info.fields_used = result.get("fields", [])
            info.functions_used = result.get("functions", [])
            info.operators_used = result.get("operators", [])
            info.string_literals = result.get("string_literals", [])
            info.regex_literals = result.get("regex_literals", [])
            info.ip_literals = result.get("ip_literals", [])
            info.int_literals = result.get("int_literals", [])
            info.has_regex = bool(info.regex_literals)
    except Exception as e:
        # FFI call crashed — fall back to regex extraction.
        log.warning("Wirefilter FFI crashed, falling back to regex: %s", e, exc_info=True)
        info = _parse_with_regex(expr)
        info.parse_error = f"{type(e).__name__}: {e}"
        info.parse_error_type = "wirefilter_crash"
    return info


def _parse_with_regex(expr: str) -> ExpressionInfo:
    """Best-effort regex-based expression analysis (fallback)."""
    info = ExpressionInfo(raw=expr)

    # Extract fields
    info.fields_used = list(dict.fromkeys(_FIELD_PATTERN.findall(expr)))

    # Extract function calls (anything followed by '(')
    raw_funcs = _FUNCTION_PATTERN.findall(expr)
    # Filter out pure operators, but keep operator-functions (starts_with, ends_with)
    info.functions_used = list(dict.fromkeys(f for f in raw_funcs if f not in _OPERATORS))

    # Extract operators used
    all_ops = _OPERATORS | _OPERATOR_FUNCTIONS
    for op in all_ops:
        if op in ("and", "or", "not", "xor") or op in _OPERATOR_FUNCTIONS:
            if re.search(rf"\b{op}\b", expr):
                info.operators_used.append(op)
        elif op in expr:
            info.operators_used.append(op)

    # Extract regex literals
    for match in _REGEX_LITERAL_PATTERN.finditer(expr):
        val = match.group(1) or match.group(2)
        if val:
            info.regex_literals.append(val)
    info.has_regex = bool(info.regex_literals) or "matches" in expr or "~" in expr

    # Extract string literals (excluding those already captured as regex)
    for match in _STRING_LITERAL_PATTERN.finditer(expr):
        val = match.group(1)
        if val and val not in info.regex_literals:
            info.string_literals.append(val)

    # Extract IP literals (IPv4 + IPv6)
    info.ip_literals = _IPV4_LITERAL_PATTERN.findall(expr)
    for candidate in _IPV6_CANDIDATE_PATTERN.findall(expr):
        # Validate candidate is a real IPv6 address/network
        try:
            ipaddress.ip_address(candidate)
            info.ip_literals.append(candidate)
            continue
        except ValueError:
            pass
        # Try as network (e.g. 2001:db8::/32)
        try:
            ipaddress.ip_network(candidate, strict=False)
            info.ip_literals.append(candidate)
        except ValueError:
            pass

    # Extract integer literals
    for match in _INT_LITERAL_PATTERN.finditer(expr):
        try:
            info.int_literals.append(int(match.group(1)))
        except ValueError:
            pass

    return info
