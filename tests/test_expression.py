"""Tests for expression whitespace normalization."""

from __future__ import annotations

import pytest

from octorules.expression import format_csp_value, format_expression_display, normalize_expression

# ---------------------------------------------------------------------------
# Identity / no-op cases
# ---------------------------------------------------------------------------


class TestIdentity:
    def test_single_line_already_clean(self):
        expr = '(http.host eq "example.com")'
        assert normalize_expression(expr) == expr

    def test_ip_set(self):
        expr = "ip.src in {1.2.3.4}"
        assert normalize_expression(expr) == expr

    def test_empty_string(self):
        assert normalize_expression("") == ""

    def test_true(self):
        assert normalize_expression("true") == "true"


# ---------------------------------------------------------------------------
# Whitespace collapsing
# ---------------------------------------------------------------------------


class TestWhitespaceCollapsing:
    def test_multiple_spaces(self):
        assert normalize_expression("a   b") == "a b"

    def test_tabs(self):
        assert normalize_expression("a\tb") == "a b"

    def test_newlines(self):
        assert normalize_expression("a\nb") == "a b"

    def test_crlf(self):
        assert normalize_expression("a\r\nb") == "a b"

    def test_mixed_whitespace(self):
        assert normalize_expression("a \t\n\r b") == "a b"

    def test_leading_trailing_stripped(self):
        assert normalize_expression("  hello  ") == "hello"

    def test_trailing_newline(self):
        assert normalize_expression("true\n") == "true"

    def test_only_whitespace(self):
        assert normalize_expression("   \t\n  ") == ""


# ---------------------------------------------------------------------------
# Multi-line expressions (primary use case)
# ---------------------------------------------------------------------------


class TestMultiLineExpressions:
    def test_block_scalar_strip(self):
        expr = '(http.host eq "example.com")\n  and not (http.request.uri.path eq "/health")\n'
        expected = '(http.host eq "example.com") and not (http.request.uri.path eq "/health")'
        assert normalize_expression(expr) == expected

    def test_deep_indentation(self):
        expr = (
            '(http.host eq "a.com")\n'
            "    and (\n"
            "        ip.src in {1.2.3.4}\n"
            "        or ip.src in {5.6.7.8}\n"
            "    )\n"
        )
        expected = '(http.host eq "a.com") and ( ip.src in {1.2.3.4} or ip.src in {5.6.7.8} )'
        assert normalize_expression(expr) == expected

    def test_confluence_style(self):
        expr = (
            '(http.host eq "app.example.com")\n'
            "and not (\n"
            '  http.request.uri.path matches "^/api/"\n'
            '  or http.request.uri.path eq "/health"\n'
            ")\n"
        )
        expected = (
            '(http.host eq "app.example.com") '
            'and not ( http.request.uri.path matches "^/api/" '
            'or http.request.uri.path eq "/health" )'
        )
        assert normalize_expression(expr) == expected

    def test_asn_set_multiline(self):
        expr = "ip.geoip.asnum in {\n  45903\n  14061\n  51167\n}"
        expected = "ip.geoip.asnum in {45903 14061 51167}"
        assert normalize_expression(expr) == expected


# ---------------------------------------------------------------------------
# Quote preservation
# ---------------------------------------------------------------------------


class TestQuotePreservation:
    def test_spaces_inside_quotes(self):
        expr = 'http.host eq "hello world"'
        assert normalize_expression(expr) == expr

    def test_multiple_quoted_strings(self):
        expr = 'http.host in {"hello world" "foo bar"}'
        assert normalize_expression(expr) == expr

    def test_empty_quoted_string(self):
        expr = 'http.host eq ""'
        assert normalize_expression(expr) == expr

    def test_newline_inside_quotes(self):
        expr = 'http.host eq "hello\nworld"'
        assert normalize_expression(expr) == expr

    def test_tab_inside_quotes(self):
        expr = 'http.host eq "hello\tworld"'
        assert normalize_expression(expr) == expr

    def test_multiple_spaces_inside_quotes(self):
        expr = 'http.host eq "hello   world"'
        assert normalize_expression(expr) == expr

    def test_adjacent_empty_quotes(self):
        expr = '""'
        assert normalize_expression(expr) == '""'


# ---------------------------------------------------------------------------
# Escaped quotes
# ---------------------------------------------------------------------------


class TestEscapedQuotes:
    def test_escaped_quote_inside_string(self):
        expr = r'http.host eq "say \"hello\""'
        assert normalize_expression(expr) == expr

    def test_multiple_escaped_quotes(self):
        expr = r'http.host eq "a\"b\"c"'
        assert normalize_expression(expr) == expr

    def test_escaped_backslash_before_closing_quote(self):
        # "test\\" — the \\ is an escaped backslash, so the next " closes the string
        expr = r'http.host eq "test\\"'
        assert normalize_expression(expr) == expr

    def test_escaped_backslash_then_escaped_quote(self):
        # "\\\""  — escaped backslash followed by escaped quote
        expr = r'http.host eq "\\\""'
        assert normalize_expression(expr) == expr


# ---------------------------------------------------------------------------
# Real production expressions
# ---------------------------------------------------------------------------


class TestProductionExpressions:
    def test_asn_ip_header_multiline(self):
        expr = (
            "(ip.geoip.asnum in {45903 14061 51167})\n"
            "and not (ip.src in {1.2.3.4 10.0.0.0/8})\n"
            'and (http.request.headers["cloudgatewayprovider"][0] eq "Denturgent")\n'
        )
        expected = (
            "(ip.geoip.asnum in {45903 14061 51167}) "
            "and not (ip.src in {1.2.3.4 10.0.0.0/8}) "
            'and (http.request.headers["cloudgatewayprovider"][0] eq "Denturgent")'
        )
        assert normalize_expression(expr) == expected

    def test_wp_admin_block_scalar(self):
        expr = (
            '(http.host eq "www.doctena.com")\nand (http.request.uri.path contains "/wp-admin")\n'
        )
        expected = (
            '(http.host eq "www.doctena.com") and (http.request.uri.path contains "/wp-admin")'
        )
        assert normalize_expression(expr) == expected

    def test_trailing_newline_only(self):
        expr = '(http.host eq "doctena.be")\n'
        expected = '(http.host eq "doctena.be")'
        assert normalize_expression(expr) == expected


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------


class TestRegexPatterns:
    def test_regex_match_preserved(self):
        expr = 'http.request.uri.path matches "^/(nl|fr|en|de)/booking/"'
        assert normalize_expression(expr) == expr

    def test_regex_with_anchors(self):
        expr = 'http.request.uri.path matches "^/doctors/[0-9]+/appointments/[0-9]+$"'
        assert normalize_expression(expr) == expr


# ---------------------------------------------------------------------------
# Header access
# ---------------------------------------------------------------------------


class TestHeaderAccess:
    def test_header_array_index(self):
        expr = 'http.request.headers["cloudgatewayprovider"][0] eq "Denturgent"'
        assert normalize_expression(expr) == expr


# ---------------------------------------------------------------------------
# Set literals
# ---------------------------------------------------------------------------


class TestSetLiterals:
    def test_asn_set_with_newlines(self):
        expr = "ip.geoip.asnum in {\n45903\n14061\n51167\n}"
        expected = "ip.geoip.asnum in {45903 14061 51167}"
        assert normalize_expression(expr) == expected

    def test_string_set_with_newlines(self):
        expr = 'ip.geoip.country in {\n"BY"\n"BO"\n"CN"\n}'
        expected = 'ip.geoip.country in {"BY" "BO" "CN"}'
        assert normalize_expression(expr) == expected

    def test_ip_set(self):
        expr = "ip.src in {\n1.2.3.4\n10.0.0.0/8\n}"
        expected = "ip.src in {1.2.3.4 10.0.0.0/8}"
        assert normalize_expression(expr) == expected

    def test_set_already_compact(self):
        """Already in CF canonical form — no change."""
        expr = 'http.host in {"a.com" "b.com"}'
        assert normalize_expression(expr) == expr

    def test_set_with_spaces_around_braces(self):
        """Spaces around braces are stripped to match CF form."""
        expr = 'http.host in { "a.com" "b.com" }'
        expected = 'http.host in {"a.com" "b.com"}'
        assert normalize_expression(expr) == expected

    def test_empty_set(self):
        expr = "http.host in {}"
        assert normalize_expression(expr) == expr

    def test_empty_set_with_whitespace(self):
        expr = "http.host in { }"
        expected = "http.host in {}"
        assert normalize_expression(expr) == expected

    def test_single_item_set(self):
        expr = "ip.src in {1.2.3.4}"
        assert normalize_expression(expr) == expr

    def test_single_item_set_with_spaces(self):
        expr = "ip.src in { 1.2.3.4 }"
        expected = "ip.src in {1.2.3.4}"
        assert normalize_expression(expr) == expected

    def test_multiline_set_indented(self):
        """Real-world one-per-line YAML format."""
        expr = 'http.host in {\n  "a.com"\n  "b.com"\n  "c.com"\n}'
        expected = 'http.host in {"a.com" "b.com" "c.com"}'
        assert normalize_expression(expr) == expected

    def test_braces_inside_quotes_untouched(self):
        """Curly braces inside quoted strings are not special."""
        expr = 'http.host eq "hello { world }"'
        assert normalize_expression(expr) == expr


# ---------------------------------------------------------------------------
# Idempotency
# ---------------------------------------------------------------------------

_ALL_TEST_INPUTS = [
    '(http.host eq "example.com")',
    "ip.src in {1.2.3.4}",
    "",
    "true",
    "a   b",
    "a\tb",
    "a\nb",
    "a\r\nb",
    "  hello  ",
    "true\n",
    "   \t\n  ",
    '(http.host eq "example.com")\n  and not (http.request.uri.path eq "/health")\n',
    'http.host eq "hello world"',
    'http.host in {"hello world" "foo bar"}',
    'http.host eq ""',
    'http.host eq "hello\nworld"',
    r'http.host eq "say \"hello\""',
    r'http.host eq "a\"b\"c"',
    r'http.host eq "test\\"',
    r'http.host eq "\\\""',
    "ip.geoip.asnum in {\n45903\n14061\n51167\n}",
    'ip.geoip.country in {\n"BY"\n"BO"\n"CN"\n}',
    'http.host in { "a.com" "b.com" }',
    "ip.src in { 1.2.3.4 }",
    "http.host in { }",
    'http.host eq "hello { world }"',
    'http.request.uri.path matches "^/(nl|fr|en|de)/booking/"',
    'http.request.headers["cloudgatewayprovider"][0] eq "Denturgent"',
]


@pytest.mark.parametrize("expr", _ALL_TEST_INPUTS)
def test_idempotent(expr: str):
    once = normalize_expression(expr)
    twice = normalize_expression(once)
    assert once == twice


# ---------------------------------------------------------------------------
# Large inputs
# ---------------------------------------------------------------------------


class TestLargeInputs:
    def test_long_expression(self):
        # 4000+ chars
        parts = [f'(http.host eq "example{i}.com")' for i in range(150)]
        expr = " or\n".join(parts) + "\n"
        result = normalize_expression(expr)
        assert len(result) > 4000
        assert "\n" not in result
        # Should be a single line with " or " between parts
        assert result.count(" or ") == 149

    def test_many_quoted_strings(self):
        parts = [f'"string{i}"' for i in range(120)]
        expr = "http.host in {" + "\n".join(parts) + "}"
        result = normalize_expression(expr)
        assert "\n" not in result
        assert result.startswith('http.host in {"string0"')
        assert result.endswith('"string119"}')
        for i in range(120):
            assert f'"string{i}"' in result


# ---------------------------------------------------------------------------
# Display formatting (format_expression_display)
# ---------------------------------------------------------------------------


class TestDisplayShortExpressions:
    """Short expressions (≤ 80 chars) are returned unchanged."""

    def test_short_expression(self):
        expr = '(http.host eq "example.com")'
        assert format_expression_display(expr) == expr

    def test_empty(self):
        assert format_expression_display("") == ""

    def test_true(self):
        assert format_expression_display("true") == "true"

    def test_exactly_80(self):
        expr = "a" * 80
        assert format_expression_display(expr) == expr

    def test_81_no_operators(self):
        # Over 80 but no operators — returned as-is
        expr = "a" * 81
        assert format_expression_display(expr) == expr


class TestDisplayOperatorBreaking:
    """Long expressions break before `and`/`or` operators."""

    def test_and_break(self):
        expr = (
            '(http.host eq "example.com")'
            ' and (http.request.uri.path eq "/very/long/path/that/exceeds")'
        )
        result = format_expression_display(expr)
        lines = result.split("\n")
        assert len(lines) == 2
        assert lines[0] == '(http.host eq "example.com")'
        # depth=0 after closing paren, so no indent before `and`
        assert lines[1].startswith("and ")

    def test_or_break(self):
        expr = (
            '(http.host eq "example.com")'
            ' or (http.request.uri.path eq "/very/long/path/that/exceeds")'
        )
        result = format_expression_display(expr)
        lines = result.split("\n")
        assert len(lines) == 2
        # depth=0 after closing paren
        assert lines[1].startswith("or ")

    def test_multiple_operators(self):
        expr = (
            '(http.host eq "a.example.com")'
            ' and (http.host eq "b.example.com")'
            ' or (http.host eq "c.example.com")'
        )
        result = format_expression_display(expr)
        lines = result.split("\n")
        assert len(lines) == 3
        assert "and" in lines[1]
        assert "or" in lines[2]

    def test_nested_paren_depth(self):
        expr = "(A and (B or C or D or E or F or G or H or I or J or K or L or M or N or O or P))"
        result = format_expression_display(expr)
        lines = result.split("\n")
        # First break: `and` at depth 1 → 2-space indent
        assert lines[1].startswith("  and ")
        # Subsequent `or` breaks inside (( → depth 2 → 4-space indent
        for line in lines[2:]:
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            assert indent == 4  # depth 2 → 2*2 spaces

    def test_and_inside_quotes_not_broken(self):
        expr = (
            'http.request.uri.path eq "/this/and/that/path"'
            ' and http.host eq "foo.example.com/and/more"'
        )
        result = format_expression_display(expr)
        # ` and ` inside quotes is NOT a break point
        assert '"/this/and/that/path"' in result


class TestDisplaySetBreaking:
    """Long set literals are broken one-item-per-line."""

    def test_asn_set(self):
        asns = " ".join(str(n) for n in range(45900, 45960))
        expr = f"(ip.geoip.asnum in {{{asns}}})"
        result = format_expression_display(expr)
        assert "\n" in result
        lines = result.split("\n")
        # First line ends with {
        assert lines[0].endswith("{")
        # Each ASN on its own line, indented
        for asn in range(45900, 45960):
            assert any(str(asn) in line for line in lines)
        # Last content line is closing brace
        assert lines[-1].strip() == "})"

    def test_string_set(self):
        hosts = " ".join(f'"{f"host{i}.example.com"}"' for i in range(20))
        expr = f"http.host in {{{hosts}}}"
        result = format_expression_display(expr)
        assert "\n" in result
        for i in range(20):
            assert f'"host{i}.example.com"' in result

    def test_short_set_not_broken(self):
        expr = (
            '(http.host in {"a.com" "b.com"})'
            " and (ip.src eq 1.2.3.4"
            ' and http.request.uri.path eq "/some/long/path/here")'
        )
        result = format_expression_display(expr)
        # The set is short, should stay inline
        assert '{"a.com" "b.com"}' in result

    def test_ip_set(self):
        ips = " ".join(f"10.0.{i}.0/24" for i in range(30))
        expr = f"ip.src in {{{ips}}}"
        result = format_expression_display(expr)
        assert "\n" in result
        for i in range(30):
            assert f"10.0.{i}.0/24" in result


class TestDisplayCombined:
    """Expressions with both operators and set literals."""

    def test_asn_and_ip_set(self):
        asns = " ".join(str(n) for n in range(45900, 45950))
        ips = " ".join(f"10.0.{i}.1" for i in range(15))
        expr = f"(ip.geoip.asnum in {{{asns}}}) and not (ip.src in {{{ips}}})"
        result = format_expression_display(expr)
        lines = result.split("\n")
        # Should have set items, an `and` break, and more set items
        assert any("and not" in line for line in lines)
        # Both sets should be broken
        assert result.count("\n") > 50  # many lines

    def test_production_asn_expression(self):
        """The exact kind of expression from the PR comment."""
        asns = " ".join(
            str(n)
            for n in [
                45903,
                14061,
                51167,
                135175,
                213186,
                58678,
                46844,
                40676,
                18450,
                53850,
                8100,
                54600,
                36352,
                18978,
                50360,
                52048,
            ]
        )
        ips = " ".join(
            ip
            for ip in [
                "157.245.78.96",
                "165.22.200.51",
                "134.122.62.225",
                "64.227.72.142",
                "134.122.48.116",
            ]
        )
        expr = (
            f"(ip.geoip.asnum in {{{asns}}}"
            f" and not(ip.src in {{{ips}}}"
            f' or http.request.headers["cloudgatewayprovider"][0] eq "Denturgent"'
            f' or http.request.headers["cloudgatewayprovider"][0] eq "UptimeRobot") )'
        )
        result = format_expression_display(expr)
        lines = result.split("\n")
        # Should be multi-line
        assert len(lines) > 10
        # ASN set should be broken
        assert "45903" in result
        assert "54600" in result
        # Operators should be on their own lines
        assert any(line.strip().startswith("and not") for line in lines)
        assert any(line.strip().startswith("or ") for line in lines)

    def test_country_set_with_exclusions(self):
        countries = " ".join(
            f'"{c}"'
            for c in [
                "BY",
                "BO",
                "CN",
                "IN",
                "ID",
                "JP",
                "KP",
                "KR",
                "LY",
                "PA",
                "RU",
                "SG",
                "VE",
                "T1",
                "IQ",
                "IL",
            ]
        )
        expr = (
            f"(ip.geoip.country in {{{countries}}}"
            f' and not (http.request.headers["cloudgatewayprovider"][0] eq "Denturgent"'
            f' or http.request.headers["cloudgatewayprovider"][0] eq "UptimeRobot"))'
        )
        result = format_expression_display(expr)
        assert "\n" in result
        # Country codes preserved
        assert '"BY"' in result
        assert '"IL"' in result


class TestDisplayPreservesQuotes:
    """Quoted content is never broken."""

    def test_and_in_quoted_string(self):
        # Make it long enough to trigger formatting
        expr = (
            'http.request.uri.path eq "/this/and/that/and/more/and/extra/padding/path"'
            ' and http.host eq "foo.example.com"'
        )
        result = format_expression_display(expr)
        assert '"/this/and/that/and/more/and/extra/padding/path"' in result

    def test_braces_in_quoted_string(self):
        expr = (
            'http.host eq "hello { world } test"'
            " and ip.src eq 1.2.3.4"
            ' and http.request.uri.path eq "/some/really/long/path/to/exceed/the/limit"'
        )
        result = format_expression_display(expr)
        assert '"hello { world } test"' in result


class TestDisplayEdgeCases:
    def test_unmatched_brace(self):
        expr = "ip.src in {1.2.3.4 " + "a " * 50  # no closing brace
        result = format_expression_display(expr)
        # Should not crash, just return something reasonable
        assert "1.2.3.4" in result

    def test_empty_set(self):
        expr = "http.host in {} and ip.src eq 1.2.3.4 and " + "a " * 40
        result = format_expression_display(expr)
        assert "{}" in result

    def test_custom_max_line(self):
        expr = "(A and B and C)"
        # With max_line=5, it should break
        result = format_expression_display(expr, max_line=5)
        assert "\n" in result


# ---------------------------------------------------------------------------
# CSP value formatting
# ---------------------------------------------------------------------------


class TestFormatCSPValue:
    def test_short_value_unchanged(self):
        csp = "script-src 'self' 'unsafe-inline'"
        assert format_csp_value(csp) == csp

    def test_single_directive_one_per_line(self):
        csp = "script-src 'self' 'unsafe-inline' alpha.com *.alpha.com bravo.com *.bravo.com"
        result = format_csp_value(csp, max_line=40)
        lines = result.split("\n")
        assert lines[0] == "script-src"
        assert lines[1] == "  'self'"
        assert lines[2] == "  'unsafe-inline'"
        assert lines[3] == "  alpha.com"
        # All source lines indented by 2 spaces
        for line in lines[1:]:
            assert line.startswith("  ")

    def test_multiple_directives_split(self):
        csp = (
            "script-src 'self' alpha.com *.alpha.com bravo.com *.bravo.com; worker-src 'self' blob:"
        )
        result = format_csp_value(csp, max_line=50)
        lines = result.split("\n")
        assert lines[0] == "script-src"
        assert lines[1] == "  'self'"
        # Last source of first directive has semicolon
        assert "  *.bravo.com;" in lines
        # Second directive starts unindented
        assert "worker-src" in lines
        assert lines[-1] == "  blob:"

    def test_round_trip_single_directive(self):
        csp = "script-src 'self' " + " ".join(f"{d}.com *.{d}.com" for d in "abcdefghij")
        formatted = format_csp_value(csp)
        normalized = normalize_expression(formatted)
        assert normalized == csp

    def test_round_trip_multiple_directives(self):
        csp = (
            "script-src 'self' 'unsafe-inline' alpha.com *.alpha.com"
            " bravo.com *.bravo.com; worker-src 'self' blob:"
        )
        formatted = format_csp_value(csp)
        normalized = normalize_expression(formatted)
        assert normalized == csp

    def test_round_trip_real_csp(self):
        """Round-trip a real production CSP value."""
        csp = (
            "script-src 'unsafe-inline' doctena.com *.doctena.com"
            " cookiefirst.com *.cookiefirst.com google.com *.google.com"
            " gstatic.com *.gstatic.com zdassets.com *.zdassets.com"
            " 'unsafe-eval' ajax.cloudflare.com cdnjs.cloudflare.com"
            " *.cdnjs.cloudflare.com static.cloudflareinsights.com;"
            " worker-src 'self' blob:"
        )
        formatted = format_csp_value(csp, max_line=80)
        normalized = normalize_expression(formatted)
        assert normalized == csp

    def test_empty_value(self):
        assert format_csp_value("") == ""

    def test_no_trailing_semicolon_lost(self):
        csp = "script-src 'self'; style-src 'self'"
        formatted = format_csp_value(csp, max_line=20)
        normalized = normalize_expression(formatted)
        assert normalized == csp

    def test_idempotent(self):
        csp = "script-src 'self' " + " ".join(f"{d}.com" for d in "abcdefghijklmnop")
        formatted1 = format_csp_value(csp)
        formatted2 = format_csp_value(formatted1)
        # Already formatted input shouldn't change further
        assert normalize_expression(formatted2) == csp
