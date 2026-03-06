"""Tests for expression whitespace normalization."""

from __future__ import annotations

import pytest

from octorules.expression import normalize_expression

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
