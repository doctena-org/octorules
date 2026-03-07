"""AST linter — expression-level lint rules (Categories E, F, G, O).

Operates on parsed expression information to detect:
- Function constraint violations (E)
- Type system / semantic issues (F)
- Value constraint warnings (G)
- Best practice / style suggestions (O)
"""

from __future__ import annotations

import ipaddress
import re
import time
from typing import Any

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.linter.expression_bridge import ExpressionInfo, parse_expression
from octorules.linter.schemas.fields import FIELDS
from octorules.linter.schemas.functions import get_function
from octorules.phases import Phase

# Deprecated fields and their replacements
_DEPRECATED_FIELDS: dict[str, str] = {
    "ip.geoip.asnum": "ip.src.asnum",
    "ip.geoip.continent": "ip.src.continent",
    "ip.geoip.country": "ip.src.country",
    "ip.geoip.subdivision_1_iso_code": "ip.src.subdivision_1_iso_code",
    "ip.geoip.subdivision_2_iso_code": "ip.src.subdivision_2_iso_code",
    "ip.geoip.is_in_european_union": "ip.src.is_in_european_union",
}

# Reserved/bogon networks (RFC 1918, loopback, link-local, etc.)
_RESERVED_NETWORKS: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str]] = [
    # IPv4
    (ipaddress.IPv4Network("10.0.0.0/8"), "RFC 1918 private"),
    (ipaddress.IPv4Network("172.16.0.0/12"), "RFC 1918 private"),
    (ipaddress.IPv4Network("192.168.0.0/16"), "RFC 1918 private"),
    (ipaddress.IPv4Network("127.0.0.0/8"), "loopback"),
    (ipaddress.IPv4Network("169.254.0.0/16"), "link-local"),
    (ipaddress.IPv4Network("100.64.0.0/10"), "CGNAT (RFC 6598)"),
    (ipaddress.IPv4Network("0.0.0.0/8"), "this network"),
    (ipaddress.IPv4Network("192.0.2.0/24"), "documentation (RFC 5737)"),
    (ipaddress.IPv4Network("198.51.100.0/24"), "documentation (RFC 5737)"),
    (ipaddress.IPv4Network("203.0.113.0/24"), "documentation (RFC 5737)"),
    (ipaddress.IPv4Network("192.0.0.0/24"), "IANA special purpose"),
    (ipaddress.IPv4Network("192.88.99.0/24"), "6to4 relay anycast"),
    (ipaddress.IPv4Network("198.18.0.0/15"), "benchmark testing (RFC 2544)"),
    (ipaddress.IPv4Network("224.0.0.0/4"), "multicast"),
    (ipaddress.IPv4Network("240.0.0.0/4"), "reserved for future use"),
    # IPv6
    (ipaddress.IPv6Network("::/128"), "unspecified"),
    (ipaddress.IPv6Network("::1/128"), "loopback"),
    (ipaddress.IPv6Network("::ffff:0:0/96"), "IPv4-mapped"),
    (ipaddress.IPv6Network("64:ff9b::/96"), "NAT64 (RFC 6052)"),
    (ipaddress.IPv6Network("100::/64"), "discard (RFC 6666)"),
    (ipaddress.IPv6Network("2001:db8::/32"), "documentation (RFC 3849)"),
    (ipaddress.IPv6Network("2001::/23"), "IANA special purpose"),
    (ipaddress.IPv6Network("2001::/32"), "Teredo"),
    (ipaddress.IPv6Network("2002::/16"), "6to4"),
    (ipaddress.IPv6Network("fc00::/7"), "unique local"),
    (ipaddress.IPv6Network("fe80::/10"), "link-local"),
    (ipaddress.IPv6Network("ff00::/8"), "multicast"),
    (ipaddress.IPv6Network("::ffff:0:0:0/96"), "IPv4-translated"),
]


def _check_ip_reserved(ip_str: str) -> str | None:
    """Return a description if *ip_str* falls within a reserved/bogon range, else None."""
    try:
        net = ipaddress.ip_network(ip_str, strict=False)
    except ValueError:
        return None
    for reserved, description in _RESERVED_NETWORKS:
        if net.version != reserved.version:
            continue
        if net.subnet_of(reserved):
            return description
    return None


def _find_overlapping_ips(ip_strings: list[str]) -> list[tuple[str, str]]:
    """Return (narrower, broader) pairs for overlapping IP ranges.

    Checks all pairs (O(n²) — fine for typical expression IP counts).
    Only compares within the same address family.
    """
    networks: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    for s in ip_strings:
        try:
            networks.append((s, ipaddress.ip_network(s, strict=False)))
        except ValueError:
            continue

    overlaps: list[tuple[str, str]] = []
    for i, (s_a, net_a) in enumerate(networks):
        for j, (s_b, net_b) in enumerate(networks):
            if i >= j:
                continue
            if net_a.version != net_b.version:
                continue
            if not net_a.overlaps(net_b):
                continue
            # Report the more-specific (narrower) first, broader second
            if net_a.prefixlen >= net_b.prefixlen:
                overlaps.append((s_a, s_b))
            else:
                overlaps.append((s_b, s_a))
    return overlaps


# Valid HTTP methods (uppercase)
_HTTP_METHODS = frozenset(
    {
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "CONNECT",
        "TRACE",
        "PURGE",
        "LOCK",
        "UNLOCK",
        "PROPFIND",
        "PROPPATCH",
        "MKCOL",
        "COPY",
        "MOVE",
    }
)

# Common lowercase HTTP methods that should be uppercase
_LOWERCASE_METHODS = frozenset({m.lower() for m in _HTTP_METHODS})

# Valid 2-letter ISO country codes pattern
_COUNTRY_CODE_PATTERN = re.compile(r"^[A-Z]{2}$")

# Regex anchor characters
_REGEX_ANCHORS = re.compile(r"[\^$]")

# Pattern to detect method comparisons
_METHOD_COMPARISON = re.compile(r"http\.request\.method\s+(?:eq|==|!=|ne|in)\s+")

# Patterns for extracting values from 'in' sets
_IN_SET_PATTERN = re.compile(r"\bin\s*\{([^}]+)\}")
_QUOTED_STRING = re.compile(r'"(?:[^"\\]|\\.)*"')

# Pattern for extracting string values compared against a specific field.
# Matches: field eq "value", field ne "value", field == "value", field != "value"
_FIELD_EQ_PATTERN_TEMPLATE = r'{field}\s+(?:eq|ne|==|!=)\s+"((?:[^"\\]|\\.)*)"'
# Matches: field in {"val1" "val2" ...}
_FIELD_IN_PATTERN_TEMPLATE = r"{field}\s+in\s*\{{([^}}]+)\}}"


def _extract_field_string_values(expr: str, field: str) -> list[str]:
    """Extract string values specifically compared against *field* in *expr*.

    Handles ``field eq "value"`` and ``field in {"v1" "v2"}`` patterns.
    Returns unquoted string values.
    """
    escaped = re.escape(field)
    values: list[str] = []

    # field eq/ne "value"
    for m in re.finditer(_FIELD_EQ_PATTERN_TEMPLATE.format(field=escaped), expr):
        values.append(m.group(1))

    # field in {"val1" "val2" ...}
    for m in re.finditer(_FIELD_IN_PATTERN_TEMPLATE.format(field=escaped), expr):
        for qm in _QUOTED_STRING.finditer(m.group(1)):
            values.append(qm.group(0).strip('"'))

    return values


# Pattern for extracting integer values compared against a specific field.
# Matches: field eq 123, field ne 42, field gt 10, field >= 5, etc.
_FIELD_INT_PATTERN_TEMPLATE = r"{field}\s+(?:eq|ne|==|!=|gt|ge|lt|le)\s+(\d+)"
# Matches: field in {1 2 3 10..20}
_FIELD_INT_IN_PATTERN_TEMPLATE = r"{field}\s+in\s*\{{([^}}]+)\}}"


def _extract_field_int_values(expr: str, field: str) -> list[int]:
    """Extract integer values specifically compared against *field* in *expr*.

    Handles ``field eq 123`` and ``field in {1 2 3}`` patterns.
    Does not extract range endpoints (``N..M``) — only bare integers.
    """
    escaped = re.escape(field)
    values: list[int] = []

    # field eq/ne/gt/ge/lt/le 123
    for m in re.finditer(_FIELD_INT_PATTERN_TEMPLATE.format(field=escaped), expr):
        values.append(int(m.group(1)))

    # field in {1 2 3}
    for m in re.finditer(_FIELD_INT_IN_PATTERN_TEMPLATE.format(field=escaped), expr):
        content = m.group(1)
        for token in content.split():
            # Skip range tokens like 10..20 and quoted strings
            if ".." in token or token.startswith('"'):
                continue
            try:
                values.append(int(token))
            except ValueError:
                continue

    return values


def _extract_function_call_args(expr: str, func_name: str) -> list[list[str]]:
    """Extract raw argument strings for each call to *func_name* in *expr*.

    Returns a list of call-sites, where each call-site is a list of
    comma-separated arg strings.  Does not handle nested parentheses
    (acceptable: CF functions we target don't nest).
    """
    results: list[list[str]] = []
    pattern = re.compile(rf"{re.escape(func_name)}\s*\(([^)]*)\)")
    for m in pattern.finditer(expr):
        raw_args = m.group(1)
        args = [a.strip() for a in raw_args.split(",")]
        results.append(args)
    return results


def lint_expressions(
    rule: dict[str, Any], phase: Phase, ctx: LintContext, *, ref_override: str | None = None
) -> None:
    """Run expression-level lint rules on a single rule."""
    expr = rule.get("expression")
    if not isinstance(expr, str) or not expr:
        return

    ref = ref_override or rule.get("ref", "")
    phase_name = phase.friendly_name

    # Parse the filter expression using the default scheme — filter
    # expressions always use http.request.uri.path as a field, even in
    # transform phases.  The transform scheme (where it's a function) is
    # only needed for action_parameters expressions.
    info = parse_expression(expr)

    # A001: Surface wirefilter parse errors (unknown fields, bad syntax, etc.)
    if info.parse_error:
        ctx.add(
            LintResult(
                rule_id="A001",
                severity=Severity.WARNING,
                message=f"Expression parse error: {info.parse_error}",
                phase=phase_name,
                ref=ref,
                field="expression",
            )
        )

    # A002: Expression nesting depth exceeded
    if info.depth_exceeded:
        ctx.add(
            LintResult(
                rule_id="A002",
                severity=Severity.WARNING,
                message="Expression nesting depth exceeds 100 levels",
                phase=phase_name,
                ref=ref,
                field="expression",
                suggestion="Simplify the expression to reduce nesting depth",
            )
        )

    # Category G — Value constraints
    _lint_value_constraints(info, phase_name, ref, ctx)

    # Category F — Type system / semantic issues
    _lint_type_constraints(info, phase_name, ref, ctx)

    # Category E — Function constraints
    _lint_function_constraints(info, phase_name, ref, ctx)

    # Category O — Style suggestions
    _lint_style(info, phase_name, ref, ctx)

    # H003: Max 64 regex patterns per rule
    if len(info.regex_literals) > 64:
        ctx.add(
            LintResult(
                rule_id="H003",
                severity=Severity.WARNING,
                message=(
                    f"Expression contains {len(info.regex_literals)} regex patterns"
                    " (Cloudflare limit is 64 per rule)"
                ),
                phase=phase_name,
                ref=ref,
                field="expression",
                suggestion="Split into multiple rules to stay under the 64 regex limit",
            )
        )


def _find_in_set_duplicates(expr: str) -> list[str]:
    """Find duplicate values within ``in {…}`` sets in the raw expression.

    Parses quoted strings and whitespace-separated tokens (IPs, integers)
    from each ``in`` set and returns deduplicated list of repeated values.
    """
    duplicates: list[str] = []
    for m in _IN_SET_PATTERN.finditer(expr):
        content = m.group(1)
        values: list[str] = []
        pos = 0
        for qm in _QUOTED_STRING.finditer(content):
            # Unquoted tokens before this quoted string
            before = content[pos : qm.start()].strip()
            if before:
                values.extend(before.split())
            values.append(qm.group(0))
            pos = qm.end()
        # Remaining unquoted tokens
        remaining = content[pos:].strip()
        if remaining:
            values.extend(remaining.split())

        seen: set[str] = set()
        for val in values:
            if val in seen:
                display = val.strip('"') if val.startswith('"') else val
                if display not in duplicates:
                    duplicates.append(display)
            seen.add(val)
    return duplicates


def _lint_value_constraints(
    info: ExpressionInfo, phase_name: str, ref: str, ctx: LintContext
) -> None:
    """Check value constraints (G001-G022)."""
    expr = info.raw

    # G010: Deprecated field — suggest replacement
    for field_name in info.fields_used:
        replacement = _DEPRECATED_FIELDS.get(field_name)
        if replacement:
            ctx.add(
                LintResult(
                    rule_id="G010",
                    severity=Severity.WARNING,
                    message=f"Field {field_name!r} is deprecated; use {replacement!r} instead",
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion=f"Replace with {replacement!r}",
                )
            )

    # G011: Reserved/bogon IP address
    for ip_str in info.ip_literals:
        reserved_desc = _check_ip_reserved(ip_str)
        if reserved_desc:
            ctx.add(
                LintResult(
                    rule_id="G011",
                    severity=Severity.WARNING,
                    message=(
                        f"IP {ip_str!r} is a reserved/bogon address ({reserved_desc})"
                        " — Cloudflare will never see traffic from this range"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion="Use a public IP address or range",
                )
            )

    # G012: Overlapping IP ranges
    if len(info.ip_literals) >= 2:
        for narrower, broader in _find_overlapping_ips(info.ip_literals):
            ctx.add(
                LintResult(
                    rule_id="G012",
                    severity=Severity.WARNING,
                    message=(
                        f"IP range {narrower!r} overlaps with {broader!r}"
                        " — the narrower range is redundant"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion=f"Remove {narrower!r} (already covered by {broader!r})",
                )
            )

    # G001: HTTP method should be uppercase
    if "http.request.method" in expr:
        for lit in info.string_literals:
            if lit in _LOWERCASE_METHODS and lit not in _HTTP_METHODS:
                ctx.add(
                    LintResult(
                        rule_id="G001",
                        severity=Severity.WARNING,
                        message=f"HTTP method {lit!r} should be uppercase ({lit.upper()!r})",
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use {lit.upper()!r}",
                    )
                )

    # G002: URI path should start with /
    # Only check values specifically compared against http.request.uri.path,
    # not all string_literals (which may belong to other fields).
    if "http.request.uri.path" in info.fields_used:
        for lit in _extract_field_string_values(expr, "http.request.uri.path"):
            if lit and not lit.startswith("/"):
                ctx.add(
                    LintResult(
                        rule_id="G002",
                        severity=Severity.WARNING,
                        message=f"URI path value {lit!r} should start with '/'",
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use '/{lit}'",
                    )
                )

    # G003: Regex anchor in literal value (suggests using 'matches' operator)
    # No has_regex guard needed: string_literals only contains values from
    # literal operators (in, eq); regex arguments go to regex_literals.
    for lit in info.string_literals:
        if _REGEX_ANCHORS.search(lit):
            ctx.add(
                LintResult(
                    rule_id="G003",
                    severity=Severity.WARNING,
                    message=(
                        f"String literal {lit!r} contains regex anchor characters."
                        " If this is a regex, use the 'matches' operator instead"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion="Use 'matches' operator for regex patterns",
                )
            )

    # G004: Invalid country code format
    if "ip.geoip.country" in expr or "ip.src.country" in expr:
        for lit in info.string_literals:
            if len(lit) == 2 and lit.isalpha():
                if not _COUNTRY_CODE_PATTERN.match(lit):
                    ctx.add(
                        LintResult(
                            rule_id="G004",
                            severity=Severity.WARNING,
                            message=(
                                f"Country code {lit!r} should be uppercase ISO 3166-1 alpha-2"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=f"Use {lit.upper()!r}",
                        )
                    )

    # G005: Score values out of typical range (per-field)
    _SCORE_RANGES: dict[str, tuple[int, int]] = {
        "cf.threat_score": (0, 100),
        "cf.bot_management.score": (1, 99),
        "cf.waf.score": (1, 99),
        "cf.waf.score.sqli": (1, 99),
        "cf.waf.score.xss": (1, 99),
        "cf.waf.score.rce": (1, 99),
        "cf.edge.server_port": (1, 65535),
        "cf.llm.prompt.injection_score": (1, 99),
    }
    for score_field, (lo, hi) in _SCORE_RANGES.items():
        if score_field not in info.fields_used:
            continue
        for val in _extract_field_int_values(expr, score_field):
            if val < lo or val > hi:
                ctx.add(
                    LintResult(
                        rule_id="G005",
                        severity=Severity.WARNING,
                        message=(
                            f"Score value {val} for {score_field!r}"
                            f" is outside typical range ({lo}-{hi})"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # G006: Response code out of valid range
    if "http.response.code" in info.fields_used:
        for val in _extract_field_int_values(expr, "http.response.code"):
            if val < 100 or val > 599:
                ctx.add(
                    LintResult(
                        rule_id="G006",
                        severity=Severity.WARNING,
                        message=f"Response code {val} is outside valid range (100-599)",
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # G007: Header name should be lowercase
    # Check if expression references header maps (http.request.headers, http.response.headers)
    uses_headers = any(
        f.endswith(".headers") or f.endswith(".headers.names") or f.endswith(".headers.values")
        for f in info.fields_used
    )
    if uses_headers or ".headers[" in expr:
        # Header map bracket keys are always header names — flag uppercase directly.
        _g007_flagged: set[str] = set()
        for m in re.finditer(r'\.headers\["([^"]+)"\]', expr):
            val = m.group(1)
            if val != val.lower() and val not in _g007_flagged:
                _g007_flagged.add(val)
                ctx.add(
                    LintResult(
                        rule_id="G007",
                        severity=Severity.INFO,
                        message=(f"Header name {val!r} should be lowercase ({val.lower()!r})"),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use {val.lower()!r}",
                    )
                )
        # Also check string_literals that look like header names (heuristic)
        for lit in info.string_literals:
            if (
                lit != lit.lower()
                and "-" in lit
                and " " not in lit
                and len(lit) <= 80
                and lit not in _g007_flagged
            ):
                _g007_flagged.add(lit)
                ctx.add(
                    LintResult(
                        rule_id="G007",
                        severity=Severity.INFO,
                        message=(f"Header name {lit!r} should be lowercase ({lit.lower()!r})"),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use {lit.lower()!r}",
                    )
                )

    # G009: Duplicate values in 'in' set
    # Must operate on the raw expression because wirefilter deduplicates in its AST.
    if "in" in info.operators_used:
        for dupe in _find_in_set_duplicates(expr):
            ctx.add(
                LintResult(
                    rule_id="G009",
                    severity=Severity.WARNING,
                    message=f"Duplicate value {dupe!r} in 'in' set",
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion=f"Remove duplicate {dupe!r}",
                )
            )

    # G008: File extension should not start with dot
    if "http.request.uri.path.extension" in expr:
        for lit in info.string_literals:
            if lit.startswith(".") and len(lit) <= 6:
                ctx.add(
                    LintResult(
                        rule_id="G008",
                        severity=Severity.WARNING,
                        message=(f"Extension value {lit!r} should not start with a dot"),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use {lit.lstrip('.')!r}",
                    )
                )

    # G013: Value domain validation — field-specific value constraints
    _STRING_VALUE_DOMAINS: dict[str, tuple[str, object]] = {
        "http.host": ("not_contains", "/", "hostname cannot contain '/'"),
        "http.request.full_uri": ("starts_with", ("http://", "https://")),
        "raw.http.request.full_uri": ("starts_with", ("http://", "https://")),
        "http.request.method": (
            "in",
            frozenset(
                {
                    "GET",
                    "HEAD",
                    "POST",
                    "PUT",
                    "DELETE",
                    "CONNECT",
                    "OPTIONS",
                    "TRACE",
                    "PATCH",
                    "PURGE",
                }
            ),
        ),
        "http.request.version": (
            "in",
            frozenset({"HTTP/1.0", "HTTP/1.1", "HTTP/2", "HTTP/3"}),
        ),
        "http.request.body.mime": ("mime",),
        "http.response.content_type.media_type": ("mime",),
        "ip.src.continent": ("in", frozenset({"AF", "AN", "AS", "EU", "NA", "OC", "SA", "T1"})),
        "cf.waf.score.class": (
            "in",
            frozenset({"attack", "likely_attack", "likely_clean", "clean"}),
        ),
        "cf.tls_version": (
            "in",
            frozenset({"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3", "none"}),
        ),
        "cf.response.error_type": (
            "in",
            frozenset(
                {
                    "1xxx",
                    "5xx",
                    "always_online",
                    "country_challenge",
                    "ip_ban",
                    "iuam",
                    "legacy_challenge",
                    "managed_challenge",
                    "ratelimit",
                    "waf",
                }
            ),
        ),
        "raw.http.request.uri.path": ("starts_with", ("/",)),
        "raw.http.request.uri.path.extension": ("extension",),
    }
    _INT_VALUE_DOMAINS: dict[str, tuple[int, int]] = {
        "http.request.timestamp.msec": (0, 999),
    }

    for field_name in info.fields_used:
        if field_name in _STRING_VALUE_DOMAINS:
            spec = _STRING_VALUE_DOMAINS[field_name]
            check_type = spec[0]
            for val in _extract_field_string_values(expr, field_name):
                flagged = False
                if check_type == "not_contains":
                    char = spec[1]
                    if char in val:
                        flagged = True
                        hint = spec[2]
                elif check_type == "starts_with":
                    prefixes = spec[1]
                    if not any(val.startswith(p) for p in prefixes):
                        flagged = True
                        hint = f"should start with one of: {', '.join(prefixes)}"
                elif check_type == "in":
                    valid_set = spec[1]
                    if val not in valid_set:
                        flagged = True
                        hint = f"expected one of: {', '.join(sorted(valid_set))}"
                elif check_type == "mime":
                    if val != val.lower() or "/" not in val:
                        flagged = True
                        hint = "should be lowercase and contain '/'"
                elif check_type == "extension":
                    if "." in val or "/" in val or val != val.lower():
                        flagged = True
                        hint = "should be lowercase with no dots or slashes"
                if flagged:
                    ctx.add(
                        LintResult(
                            rule_id="G013",
                            severity=Severity.WARNING,
                            message=(
                                f"Value {val!r} for field {field_name!r} looks invalid — {hint}"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )

        if field_name in _INT_VALUE_DOMAINS:
            lo, hi = _INT_VALUE_DOMAINS[field_name]
            for val in _extract_field_int_values(expr, field_name):
                if val < lo or val > hi:
                    ctx.add(
                        LintResult(
                            rule_id="G013",
                            severity=Severity.WARNING,
                            message=(
                                f"Value {val} for field {field_name!r}"
                                f" is outside valid range ({lo}-{hi})"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )

    # G014: Timestamp bounds
    if "http.request.timestamp.sec" in info.fields_used:
        _TIMESTAMP_MIN = 1262300400  # Jan 1, 2010
        _TIMESTAMP_MAX = int(time.time()) + 365 * 86400  # 1 year in future
        for val in _extract_field_int_values(expr, "http.request.timestamp.sec"):
            if val < _TIMESTAMP_MIN:
                ctx.add(
                    LintResult(
                        rule_id="G014",
                        severity=Severity.WARNING,
                        message=(
                            f"Timestamp {val} is before Jan 2010"
                            " — likely not a valid request timestamp"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )
            elif val > _TIMESTAMP_MAX:
                ctx.add(
                    LintResult(
                        rule_id="G014",
                        severity=Severity.WARNING,
                        message=(
                            f"Timestamp {val} is more than 1 year in the future"
                            " — likely not a valid request timestamp"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # G015: Integer range overlap in 'in' sets
    if "in" in info.operators_used:
        for m in _IN_SET_PATTERN.finditer(expr):
            content = m.group(1)
            # Skip if content has quoted strings (this is for int ranges)
            if '"' in content:
                continue
            overlaps = _find_int_range_overlaps(content)
            for narrow, broad in overlaps:
                ctx.add(
                    LintResult(
                        rule_id="G015",
                        severity=Severity.WARNING,
                        message=(
                            f"Integer value/range {narrow} is already covered"
                            f" by range {broad} in 'in' set"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Remove {narrow} (covered by {broad})",
                    )
                )

    # G016: lower()/upper() value mismatch
    _LOWER_VALUE_RE = re.compile(r'lower\s*\([^)]+\)\s+(?:eq|ne|==|!=)\s+"((?:[^"\\]|\\.)*)"')
    _LOWER_IN_RE = re.compile(r"lower\s*\([^)]+\)\s+in\s*\{([^}]+)\}")
    _UPPER_VALUE_RE = re.compile(r'upper\s*\([^)]+\)\s+(?:eq|ne|==|!=)\s+"((?:[^"\\]|\\.)*)"')
    _UPPER_IN_RE = re.compile(r"upper\s*\([^)]+\)\s+in\s*\{([^}]+)\}")

    if "lower" in info.functions_used:
        for m_val in _LOWER_VALUE_RE.finditer(expr):
            val = m_val.group(1)
            if val != val.lower():
                ctx.add(
                    LintResult(
                        rule_id="G016",
                        severity=Severity.WARNING,
                        message=(
                            f"Value {val!r} contains uppercase characters"
                            " but is compared against lower() output"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use {val.lower()!r}",
                    )
                )
        for m_in in _LOWER_IN_RE.finditer(expr):
            for qm in _QUOTED_STRING.finditer(m_in.group(1)):
                val = qm.group(0).strip('"')
                if val != val.lower():
                    ctx.add(
                        LintResult(
                            rule_id="G016",
                            severity=Severity.WARNING,
                            message=(
                                f"Value {val!r} contains uppercase characters"
                                " but is compared against lower() output"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=f"Use {val.lower()!r}",
                        )
                    )

    if "upper" in info.functions_used:
        for m_val in _UPPER_VALUE_RE.finditer(expr):
            val = m_val.group(1)
            if val != val.upper():
                ctx.add(
                    LintResult(
                        rule_id="G016",
                        severity=Severity.WARNING,
                        message=(
                            f"Value {val!r} contains lowercase characters"
                            " but is compared against upper() output"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use {val.upper()!r}",
                    )
                )
        for m_in in _UPPER_IN_RE.finditer(expr):
            for qm in _QUOTED_STRING.finditer(m_in.group(1)):
                val = qm.group(0).strip('"')
                if val != val.upper():
                    ctx.add(
                        LintResult(
                            rule_id="G016",
                            severity=Severity.WARNING,
                            message=(
                                f"Value {val!r} contains lowercase characters"
                                " but is compared against upper() output"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=f"Use {val.upper()!r}",
                        )
                    )

    # G017: len() compared to negative value
    for m_len in re.finditer(r"len\s*\([^)]+\)\s+(?:eq|ne|lt|le|gt|ge|==|!=)\s+(-?\d+)", expr):
        val = int(m_len.group(1))
        if val < 0:
            ctx.add(
                LintResult(
                    rule_id="G017",
                    severity=Severity.WARNING,
                    message=f"len() compared to negative value {val} (len always returns >= 0)",
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                )
            )

    # G018: Invalid double-asterisk in wildcard pattern
    if "wildcard" in info.operators_used or "strict_wildcard" in info.operators_used:
        for lit in info.string_literals:
            if "**" in lit:
                ctx.add(
                    LintResult(
                        rule_id="G018",
                        severity=Severity.WARNING,
                        message=f"Invalid double-asterisk '**' in wildcard pattern {lit!r}",
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=(
                            "Use a single '*' — double asterisk is not"
                            " valid in Cloudflare wildcards"
                        ),
                    )
                )
    # Also check raw expression for wildcard "pattern**" syntax
    if re.search(r'\b(?:strict\s+)?wildcard\s+"[^"]*\*\*', expr):
        # Only fire if not already caught above
        if "wildcard" not in info.operators_used and "strict_wildcard" not in info.operators_used:
            ctx.add(
                LintResult(
                    rule_id="G018",
                    severity=Severity.WARNING,
                    message="Invalid double-asterisk '**' in wildcard pattern",
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion=(
                        "Use a single '*' — double asterisk is not valid in Cloudflare wildcards"
                    ),
                )
            )

    # G019: Integer range start > end
    if "in" in info.operators_used:
        for m_set in _IN_SET_PATTERN.finditer(expr):
            content = m_set.group(1)
            for m_range in re.finditer(r"(\d+)\.\.(\d+)", content):
                start, end = int(m_range.group(1)), int(m_range.group(2))
                if start > end:
                    ctx.add(
                        LintResult(
                            rule_id="G019",
                            severity=Severity.ERROR,
                            message=(f"Integer range {start}..{end} has start greater than end"),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=f"Use {end}..{start}",
                        )
                    )

    # G020: split() limit outside 1-128
    for call_args in _extract_function_call_args(expr, "split"):
        if len(call_args) >= 3:
            try:
                limit = int(call_args[2].strip().strip('"'))
                if limit < 1 or limit > 128:
                    ctx.add(
                        LintResult(
                            rule_id="G020",
                            severity=Severity.WARNING,
                            message=(f"split() limit {limit} is outside valid range (1-128)"),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
            except ValueError:
                pass

    # G021: cidr/cidr6 bit range validation
    for call_args in _extract_function_call_args(expr, "cidr"):
        # cidr(field, prefix_bits, suffix_bits) — both should be 0-32
        for arg_str in call_args[1:]:
            try:
                bits = int(arg_str.strip())
                if bits < 0 or bits > 32:
                    ctx.add(
                        LintResult(
                            rule_id="G021",
                            severity=Severity.WARNING,
                            message=f"cidr() bit value {bits} is outside valid range (0-32)",
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
            except ValueError:
                pass
    for call_args in _extract_function_call_args(expr, "cidr6"):
        # cidr6(field, prefix_bits) — 1-128
        if len(call_args) >= 2:
            try:
                bits = int(call_args[1].strip())
                if bits < 0 or bits > 128:
                    ctx.add(
                        LintResult(
                            rule_id="G021",
                            severity=Severity.WARNING,
                            message=f"cidr6() bit value {bits} is outside valid range (0-128)",
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
            except ValueError:
                pass

    # G022: remove_query_args() first arg must be a query field
    _VALID_QUERY_FIELDS = frozenset(
        {
            "http.request.uri.query",
            "raw.http.request.uri.query",
        }
    )
    for call_args in _extract_function_call_args(expr, "remove_query_args"):
        if call_args:
            first_arg = call_args[0].strip()
            if first_arg and first_arg not in _VALID_QUERY_FIELDS:
                ctx.add(
                    LintResult(
                        rule_id="G022",
                        severity=Severity.WARNING,
                        message=(
                            f"remove_query_args() first argument {first_arg!r}"
                            " should be http.request.uri.query"
                            " or raw.http.request.uri.query"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # G023: Invalid regex pattern in 'matches' operator
    for regex_lit in info.regex_literals:
        try:
            re.compile(regex_lit)
        except re.error as e:
            ctx.add(
                LintResult(
                    rule_id="G023",
                    severity=Severity.WARNING,
                    message=(f"Invalid regex pattern {regex_lit!r}: {e}"),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                )
            )

    # G024: substring() bounds validation
    # Note: CF substring supports negative indices (count from end),
    # so only flag when both are non-negative and end < start.
    for call_args in _extract_function_call_args(expr, "substring"):
        if len(call_args) >= 3:
            try:
                start = int(call_args[1].strip())
                end = int(call_args[2].strip())
                if start >= 0 and end >= 0 and end < start:
                    ctx.add(
                        LintResult(
                            rule_id="G024",
                            severity=Severity.WARNING,
                            message=(
                                f"substring() end index {end} is less than start index {start}"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
            except ValueError:
                pass

    # G025: lookup_json_string/lookup_json_integer path validation
    for func_name in ("lookup_json_string", "lookup_json_integer"):
        for call_args in _extract_function_call_args(expr, func_name):
            if len(call_args) >= 2:
                path_arg = call_args[1].strip().strip('"')
                if path_arg and not path_arg.startswith("/"):
                    ctx.add(
                        LintResult(
                            rule_id="G025",
                            severity=Severity.WARNING,
                            message=(f"{func_name}() JSON path {path_arg!r} should start with '/'"),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=f"Use '/{path_arg}'",
                        )
                    )


def _find_int_range_overlaps(content: str) -> list[tuple[str, str]]:
    """Find integer values/ranges that overlap in an ``in {…}`` set content.

    Parses bare integers and ``N..M`` ranges, then checks all pairs for
    strict containment (not exact equality, which is G009's job).
    Returns ``(narrower, broader)`` pairs.
    """
    # Parse entries: bare ints and N..M ranges
    entries: list[tuple[int, int, str]] = []  # (lo, hi, original_str)
    for token in content.split():
        if ".." in token:
            parts = token.split("..", 1)
            try:
                lo, hi = int(parts[0]), int(parts[1])
                entries.append((min(lo, hi), max(lo, hi), token))
            except ValueError:
                continue
        else:
            try:
                v = int(token)
                entries.append((v, v, token))
            except ValueError:
                continue

    overlaps: list[tuple[str, str]] = []
    for i, (lo_a, hi_a, str_a) in enumerate(entries):
        for j, (lo_b, hi_b, str_b) in enumerate(entries):
            if i >= j:
                continue
            # Skip exact same range (that's G009's job)
            if lo_a == lo_b and hi_a == hi_b:
                continue
            # Check if a is strictly contained within b
            if lo_a >= lo_b and hi_a <= hi_b:
                overlaps.append((str_a, str_b))
            elif lo_b >= lo_a and hi_b <= hi_a:
                overlaps.append((str_b, str_a))
    return overlaps


def _lint_type_constraints(
    info: ExpressionInfo, phase_name: str, ref: str, ctx: LintContext
) -> None:
    """Check type system / semantic issues (F001, F002)."""
    from difflib import get_close_matches

    from octorules.linter.schemas.fields import FieldType, get_field

    expr = info.raw
    _NUMERIC_OPS = {"gt", "ge", "lt", "le"}

    for field_name in info.fields_used:
        fd = get_field(field_name)
        if fd is None:
            # F002: Unknown field name
            suggestion = ""
            matches = get_close_matches(field_name, list(FIELDS.keys()), n=1, cutoff=0.75)
            if matches:
                suggestion = f"Did you mean {matches[0]!r}?"
            ctx.add(
                LintResult(
                    rule_id="F002",
                    severity=Severity.WARNING,
                    message=f"Unknown field {field_name!r} in expression",
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion=suggestion,
                )
            )
            continue

        escaped = re.escape(field_name)

        if fd.field_type == FieldType.STRING:
            # String fields: flag numeric ops with int literals
            for op in _NUMERIC_OPS:
                if re.search(rf"{escaped}\s+{op}\s+\d", expr):
                    ctx.add(
                        LintResult(
                            rule_id="F001",
                            severity=Severity.ERROR,
                            message=(
                                f"Numeric operator '{op}' used with string field {field_name!r}"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=(
                                f"Use string operators (eq, ne, contains, matches)"
                                f" with {field_name!r}"
                            ),
                        )
                    )
                    break

        elif fd.field_type == FieldType.INT:
            # Int fields: flag string literal comparison
            if re.search(rf'{escaped}\s+(?:eq|ne|==|!=)\s+"', expr):
                ctx.add(
                    LintResult(
                        rule_id="F001",
                        severity=Severity.ERROR,
                        message=(f"String literal compared with integer field {field_name!r}"),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use numeric value with {field_name!r}",
                    )
                )
            # Int fields: flag contains/matches
            if re.search(rf"{escaped}\s+(?:contains|matches)\s+", expr):
                ctx.add(
                    LintResult(
                        rule_id="F001",
                        severity=Severity.ERROR,
                        message=(f"String operator used with integer field {field_name!r}"),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=(
                            f"Use numeric operators (eq, ne, gt, lt, etc.) with {field_name!r}"
                        ),
                    )
                )

        elif fd.field_type == FieldType.IP:
            # IP fields: flag lt/le/gt/ge and contains/matches
            for op in _NUMERIC_OPS:
                if re.search(rf"{escaped}\s+{op}\s+", expr):
                    ctx.add(
                        LintResult(
                            rule_id="F001",
                            severity=Severity.ERROR,
                            message=(
                                f"Comparison operator '{op}' not supported on IP field"
                                f" {field_name!r}"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=f"Use 'eq', 'ne', or 'in' with {field_name!r}",
                        )
                    )
                    break
            if re.search(rf"{escaped}\s+(?:contains|matches)\s+", expr):
                ctx.add(
                    LintResult(
                        rule_id="F001",
                        severity=Severity.ERROR,
                        message=(f"String operator used with IP field {field_name!r}"),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use 'eq', 'ne', or 'in' with {field_name!r}",
                    )
                )

        elif fd.field_type == FieldType.BOOL:
            # Bool fields: flag eq "string" comparisons
            if re.search(rf'{escaped}\s+(?:eq|ne|==|!=)\s+"', expr):
                ctx.add(
                    LintResult(
                        rule_id="F001",
                        severity=Severity.ERROR,
                        message=(f"String literal compared with boolean field {field_name!r}"),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use bare field name or 'not {field_name}' for boolean fields",
                    )
                )

        elif fd.field_type in (
            FieldType.ARRAY_STRING,
            FieldType.ARRAY_INT,
            FieldType.MAP_STRING_STRING,
            FieldType.MAP_STRING_INT,
            FieldType.MAP_ARRAY_STRING,
            FieldType.MAP_ARRAY_INT,
            FieldType.ARRAY_ARRAY_STRING,
        ):
            # Array/Map fields: flag scalar comparison operators
            _scalar_ops = {"eq", "ne", "gt", "ge", "lt", "le", "==", "!=", "contains", "matches"}
            for op in _scalar_ops:
                if re.search(rf"{escaped}\s+{re.escape(op)}\s+", expr):
                    _is_map = "MAP" in fd.field_type.name
                    _is_array = "ARRAY" in fd.field_type.name
                    type_label = (
                        "map"
                        if _is_map and not _is_array
                        else ("array" if _is_array and not _is_map else "array/map")
                    )
                    suggestion = (
                        (
                            f"Use 'any()/all()' or 'has_key()/has_value()'"
                            f" with {type_label} field {field_name!r}"
                        )
                        if _is_map
                        else (
                            f"Use 'any()/all()' or indexing with {type_label} field {field_name!r}"
                        )
                    )
                    ctx.add(
                        LintResult(
                            rule_id="F001",
                            severity=Severity.ERROR,
                            message=(
                                f"Scalar operator '{op}' used with"
                                f" {type_label} field {field_name!r}"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                            suggestion=suggestion,
                        )
                    )
                    break

    # F003: Array [*] used on multiple distinct arrays
    # CF constraint: [*] can only appear on the same array in a single expression.
    star_pattern = re.compile(r"([a-z][a-z0-9_.]*)\[\*\]")
    star_arrays = set(star_pattern.findall(expr))
    if len(star_arrays) > 1:
        ctx.add(
            LintResult(
                rule_id="F003",
                severity=Severity.WARNING,
                message=(
                    f"Array unpacking [*] used on {len(star_arrays)} different arrays:"
                    f" {', '.join(sorted(star_arrays))}."
                    " Cloudflare requires [*] to be applied to the same array within"
                    " an expression"
                ),
                phase=phase_name,
                ref=ref,
                field="expression",
            )
        )


def _lint_function_constraints(
    info: ExpressionInfo, phase_name: str, ref: str, ctx: LintContext
) -> None:
    """Check function constraints (E001-E006)."""
    for func_name in info.functions_used:
        func_def = get_function(func_name)
        if func_def is None:
            # E001: Unknown function — only warn, could be a new function
            # We skip this for common things that look like functions but aren't
            if func_name not in ("not", "true", "false"):
                ctx.add(
                    LintResult(
                        rule_id="E001",
                        severity=Severity.WARNING,
                        message=f"Unknown function {func_name!r} in expression",
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )
            continue

        # E002: Function not available in this phase
        if func_def.restricted_phases and phase_name not in func_def.restricted_phases:
            ctx.add(
                LintResult(
                    rule_id="E002",
                    severity=Severity.WARNING,
                    message=(
                        f"Function {func_name!r} is not available in phase {phase_name!r}."
                        f" Available in: {', '.join(sorted(func_def.restricted_phases))}"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                )
            )

        # B003: Function requires a higher plan tier
        if func_def.requires_plan:
            _PLAN_TIERS = {"free": 0, "pro": 1, "business": 2, "enterprise": 3}
            current_level = _PLAN_TIERS.get(ctx.plan_tier, 3)
            required_level = _PLAN_TIERS.get(func_def.requires_plan, 0)
            if current_level < required_level:
                ctx.add(
                    LintResult(
                        rule_id="B003",
                        severity=Severity.WARNING,
                        message=(
                            f"Function {func_name!r} requires {func_def.requires_plan!r}"
                            f" plan, but current plan is {ctx.plan_tier!r}"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # E003: regex_replace/wildcard_replace usage limits
    expr = info.raw
    regex_replace_count = len(re.findall(r"\bregex_replace\s*\(", expr))
    wildcard_replace_count = len(re.findall(r"\bwildcard_replace\s*\(", expr))
    if regex_replace_count > 1:
        ctx.add(
            LintResult(
                rule_id="E003",
                severity=Severity.ERROR,
                message=f"regex_replace used {regex_replace_count} times (limit is 1 per rule)",
                phase=phase_name,
                ref=ref,
                field="expression",
            )
        )
    if wildcard_replace_count > 1:
        ctx.add(
            LintResult(
                rule_id="E003",
                severity=Severity.ERROR,
                message=(
                    f"wildcard_replace used {wildcard_replace_count} times (limit is 1 per rule)"
                ),
                phase=phase_name,
                ref=ref,
                field="expression",
            )
        )
    if regex_replace_count >= 1 and wildcard_replace_count >= 1:
        ctx.add(
            LintResult(
                rule_id="E003",
                severity=Severity.ERROR,
                message="Cannot use both regex_replace and wildcard_replace in the same rule",
                phase=phase_name,
                ref=ref,
                field="expression",
            )
        )

    # E004: encode_base64 invalid flags
    _VALID_ENCODE_BASE64_FLAGS = frozenset({"u", "p", "up"})
    for call_args in _extract_function_call_args(expr, "encode_base64"):
        if len(call_args) >= 2:
            flag = call_args[1].strip().strip('"')
            if flag and flag not in _VALID_ENCODE_BASE64_FLAGS:
                ctx.add(
                    LintResult(
                        rule_id="E004",
                        severity=Severity.WARNING,
                        message=(
                            f"encode_base64() flag {flag!r} is invalid."
                            f" Valid flags: {', '.join(sorted(_VALID_ENCODE_BASE64_FLAGS))}"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # E005: url_decode invalid options
    _VALID_URL_DECODE_FLAGS = frozenset({"r", "u", "ur"})
    for call_args in _extract_function_call_args(expr, "url_decode"):
        if len(call_args) >= 2:
            flag = call_args[1].strip().strip('"')
            if flag and flag not in _VALID_URL_DECODE_FLAGS:
                ctx.add(
                    LintResult(
                        rule_id="E005",
                        severity=Severity.WARNING,
                        message=(
                            f"url_decode() option {flag!r} is invalid."
                            f" Valid options: {', '.join(sorted(_VALID_URL_DECODE_FLAGS))}"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # E006: wildcard_replace invalid flags
    _VALID_WILDCARD_REPLACE_FLAGS = frozenset({"s", ""})
    for call_args in _extract_function_call_args(expr, "wildcard_replace"):
        if len(call_args) >= 4:
            flag = call_args[3].strip().strip('"')
            if flag not in _VALID_WILDCARD_REPLACE_FLAGS:
                ctx.add(
                    LintResult(
                        rule_id="E006",
                        severity=Severity.WARNING,
                        message=(
                            f"wildcard_replace() flag {flag!r} is invalid."
                            " Valid flags: 's' (case-sensitive) or empty"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                    )
                )

    # E007: Function source argument must be a field, not a string literal
    _SOURCE_MUST_BE_FIELD_FUNCS = (
        "decode_base64",
        "url_decode",
        "starts_with",
        "ends_with",
        "wildcard_replace",
    )
    for func_name in _SOURCE_MUST_BE_FIELD_FUNCS:
        for call_args in _extract_function_call_args(expr, func_name):
            if call_args:
                first_arg = call_args[0].strip()
                if first_arg.startswith('"') and first_arg.endswith('"'):
                    ctx.add(
                        LintResult(
                            rule_id="E007",
                            severity=Severity.WARNING,
                            message=(
                                f"{func_name}() source argument must be a field reference,"
                                f" not a string literal"
                            ),
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )

    # G026: bit_slice value validation
    for call_args in _extract_function_call_args(expr, "bit_slice"):
        # bit_slice(field, offset, size) — offset max 2040, size max 32
        if len(call_args) >= 3:
            try:
                offset = int(call_args[1].strip())
                if offset < 0 or offset > 2040:
                    ctx.add(
                        LintResult(
                            rule_id="G026",
                            severity=Severity.WARNING,
                            message=f"bit_slice() offset {offset} is outside valid range (0-2040)",
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
            except ValueError:
                pass
            try:
                size = int(call_args[2].strip())
                if size < 1 or size > 32:
                    ctx.add(
                        LintResult(
                            rule_id="G026",
                            severity=Severity.WARNING,
                            message=f"bit_slice() size {size} is outside valid range (1-32)",
                            phase=phase_name,
                            ref=ref,
                            field="expression",
                        )
                    )
            except ValueError:
                pass


def _split_top_level(expr: str) -> list[tuple[str, str]]:
    """Split expression into top-level clauses at depth-0 ``and``/``or`` boundaries.

    Returns ``(connective, clause)`` pairs where connective is ``""`` for the
    first clause, and ``"and"`` or ``"or"`` for subsequent clauses.
    Strips matching outer parentheses first.
    """
    # Strip matching outer parens
    stripped = expr.strip()
    while stripped.startswith("(") and stripped.endswith(")"):
        # Check if outer parens actually match
        depth = 0
        matched = True
        for i, ch in enumerate(stripped):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
            if depth == 0 and i < len(stripped) - 1:
                matched = False
                break
        if matched:
            stripped = stripped[1:-1].strip()
        else:
            break

    clauses: list[tuple[str, str]] = []
    depth = 0
    current_start = 0
    current_connective = ""
    i = 0
    while i < len(stripped):
        ch = stripped[i]
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == '"':
            # Skip quoted string
            i += 1
            while i < len(stripped) and stripped[i] != '"':
                if stripped[i] == "\\":
                    i += 1
                i += 1
        elif depth == 0:
            # Check for 'and' or 'or' as whole words
            for kw in ("and", "or"):
                kw_len = len(kw)
                if (
                    stripped[i : i + kw_len] == kw
                    and (i == 0 or not stripped[i - 1].isalnum())
                    and (i + kw_len >= len(stripped) or not stripped[i + kw_len].isalnum())
                ):
                    clause_text = stripped[current_start:i].strip()
                    if clause_text:
                        clauses.append((current_connective, clause_text))
                    current_connective = kw
                    current_start = i + kw_len
                    i += kw_len - 1
                    break
        i += 1

    # Last clause
    remaining = stripped[current_start:].strip()
    if remaining:
        clauses.append((current_connective, remaining))

    return clauses


def _lint_style(info: ExpressionInfo, phase_name: str, ref: str, ctx: LintContext) -> None:
    """Check style and best practice suggestions (O001-O006)."""
    expr = info.raw

    # O001: Multiple OR of same field could use 'in' operator
    # Only suggest when all top-level connectives are 'or'
    clauses = _split_top_level(expr)
    connectives = {c for c, _ in clauses if c}
    is_or_chain = len(clauses) >= 2 and connectives == {"or"}
    if is_or_chain:
        for field_name in info.fields_used:
            eq_count = len(re.findall(rf"{re.escape(field_name)}\s+(?:eq|==)\s+", expr))
            if eq_count >= 3:
                ctx.add(
                    LintResult(
                        rule_id="O001",
                        severity=Severity.INFO,
                        message=(
                            f"Field {field_name!r} compared with eq/== {eq_count} times."
                            " Consider using the 'in' operator"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f'Use {field_name} in {{"val1" "val2" ...}}',
                    )
                )

    # O003: Double negation (including `not (not ...)` with parens)
    if re.search(r"\bnot\s+not\b", expr) or re.search(r"\bnot\s*\(\s*not\b", expr):
        ctx.add(
            LintResult(
                rule_id="O003",
                severity=Severity.INFO,
                message="Redundant double negation 'not not' in expression",
                phase=phase_name,
                ref=ref,
                field="expression",
                suggestion="Remove the double negation",
            )
        )

    # O002: Suggest normalized field instead of raw
    for field_name in info.fields_used:
        if field_name.startswith("raw."):
            normalized = field_name.removeprefix("raw.")
            if normalized in FIELDS:
                ctx.add(
                    LintResult(
                        rule_id="O002",
                        severity=Severity.INFO,
                        message=(
                            f"Consider using normalized field {normalized!r}"
                            f" instead of raw field {field_name!r}"
                        ),
                        phase=phase_name,
                        ref=ref,
                        field="expression",
                        suggestion=f"Use {normalized!r}",
                    )
                )

    # O004: Negated comparison simplification
    _INVERSE_OPS = {
        "eq": "ne",
        "ne": "eq",
        "lt": "ge",
        "ge": "lt",
        "gt": "le",
        "le": "gt",
        "==": "!=",
        "!=": "==",
    }
    for m in re.finditer(r"\bnot\s+(\S+(?:\.\S+)*)\s+(eq|ne|lt|le|gt|ge|==|!=)\s+", expr):
        op = m.group(2)
        field_name = m.group(1)
        inverse = _INVERSE_OPS.get(op, "")
        if inverse:
            ctx.add(
                LintResult(
                    rule_id="O004",
                    severity=Severity.INFO,
                    message=(
                        f"'not {field_name} {op}' can be simplified to '{field_name} {inverse}'"
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion=f"Use '{field_name} {inverse}' instead of 'not {field_name} {op}'",
                )
            )

    # O005: Illogical condition detection (contradictory AND / tautological OR)
    clauses = _split_top_level(expr)
    if len(clauses) >= 2:
        connectives = {c for c, _ in clauses if c}
        # Only check when all connectives are the same type (no mixed and/or)
        if len(connectives) == 1:
            connective = connectives.pop()
            if connective == "and":
                # Contradictory: same field eq different values
                field_eq_vals: dict[str, set[str]] = {}
                for _, clause in clauses:
                    clause = clause.strip().strip("()")
                    m_eq = re.match(
                        r'(\S+(?:\.\S+)*)\s+(?:eq|==)\s+"((?:[^"\\]|\\.)*)"$',
                        clause.strip(),
                    )
                    if m_eq:
                        field_eq_vals.setdefault(m_eq.group(1), set()).add(m_eq.group(2))
                for fld, vals in field_eq_vals.items():
                    if len(vals) >= 2:
                        ctx.add(
                            LintResult(
                                rule_id="O005",
                                severity=Severity.WARNING,
                                message=(
                                    f"Contradictory condition: {fld!r} cannot equal"
                                    f" both {' and '.join(repr(v) for v in sorted(vals))}"
                                    " at the same time"
                                ),
                                phase=phase_name,
                                ref=ref,
                                field="expression",
                            )
                        )
            elif connective == "or":
                # Tautological: same field ne different values
                field_ne_vals: dict[str, set[str]] = {}
                for _, clause in clauses:
                    clause = clause.strip().strip("()")
                    m_ne = re.match(
                        r'(\S+(?:\.\S+)*)\s+(?:ne|!=)\s+"((?:[^"\\]|\\.)*)"$',
                        clause.strip(),
                    )
                    if m_ne:
                        field_ne_vals.setdefault(m_ne.group(1), set()).add(m_ne.group(2))
                    # Also check "not field eq" and "not field in {}"
                    m_not_eq = re.match(
                        r'not\s+(\S+(?:\.\S+)*)\s+(?:eq|==)\s+"((?:[^"\\]|\\.)*)"$',
                        clause.strip(),
                    )
                    if m_not_eq:
                        field_ne_vals.setdefault(m_not_eq.group(1), set()).add(m_not_eq.group(2))
                for fld, vals in field_ne_vals.items():
                    if len(vals) >= 2:
                        ctx.add(
                            LintResult(
                                rule_id="O005",
                                severity=Severity.WARNING,
                                message=(
                                    f"Likely tautology: {fld!r} != "
                                    f"{' or != '.join(repr(v) for v in sorted(vals))}"
                                    " is always true if the values differ"
                                ),
                                phase=phase_name,
                                ref=ref,
                                field="expression",
                            )
                        )

    # O006: Regex literal escapes — suggest raw string format
    for m_regex in re.finditer(r'\bmatches\s+"((?:[^"\\]|\\.)*)"', expr):
        pattern_content = m_regex.group(1)
        # Check there's no 'r' prefix (i.e., not r"...")
        match_start = m_regex.start()
        quote_pos = expr.index('"', match_start + len("matches"))
        if quote_pos > 0 and expr[quote_pos - 1] == "r":
            continue  # raw string format — ok
        if "\\" in pattern_content:
            ctx.add(
                LintResult(
                    rule_id="O006",
                    severity=Severity.INFO,
                    message=(
                        "Regex pattern contains backslash escapes in a literal string."
                        ' Consider using raw string format (r"...") for clarity'
                    ),
                    phase=phase_name,
                    ref=ref,
                    field="expression",
                    suggestion='Use r"..." format for regex patterns with backslashes',
                )
            )
