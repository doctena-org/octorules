"""Tests for expression bridge (regex fallback and wirefilter FFI)."""

from __future__ import annotations

import pytest

from octorules.linter.expression_bridge import (
    WIREFILTER_AVAILABLE,
    _parse_with_regex,
    parse_expression,
)


class TestRegexParser:
    def test_extracts_fields(self):
        info = parse_expression('http.host eq "example.com" and ip.src in {1.2.3.4}')
        assert "http.host" in info.fields_used
        assert "ip.src" in info.fields_used

    def test_extracts_string_literals(self):
        info = parse_expression('http.host eq "example.com"')
        assert "example.com" in info.string_literals

    def test_extracts_functions(self):
        info = parse_expression('starts_with(http.request.uri.path, "/blog/")')
        assert "starts_with" in info.functions_used

    def test_extracts_ip_literals(self):
        info = parse_expression("ip.src in {1.2.3.4 10.0.0.0/8}")
        assert "1.2.3.4" in info.ip_literals
        assert "10.0.0.0/8" in info.ip_literals

    def test_detects_regex(self):
        info = parse_expression('http.request.uri.path matches "^/api/.*"')
        assert info.has_regex

    def test_no_regex_in_literal(self):
        info = parse_expression('http.host eq "example.com"')
        assert not info.has_regex

    def test_extracts_operators(self):
        info = parse_expression('http.host eq "a" and ip.src in {1.2.3.4}')
        assert "and" in info.operators_used
        assert "in" in info.operators_used

    def test_complex_expression(self):
        expr = (
            '(http.request.method eq "POST" and '
            'starts_with(http.request.uri.path, "/api/")) or '
            'http.request.uri.path.extension in {"jpg" "png" "css"}'
        )
        info = parse_expression(expr)
        assert "http.request.method" in info.fields_used
        assert "http.request.uri.path" in info.fields_used
        assert "http.request.uri.path.extension" in info.fields_used
        assert "starts_with" in info.functions_used
        assert "POST" in info.string_literals

    def test_deduplicated_fields(self):
        info = parse_expression('http.host eq "a" or http.host eq "b" or http.host eq "c"')
        assert info.fields_used.count("http.host") == 1

    def test_empty_expression(self):
        info = parse_expression("")
        assert info.fields_used == []
        assert info.functions_used == []

    def test_extracts_ipv6_address(self):
        info = parse_expression("ip.src eq 2001:db8::1")
        assert "2001:db8::1" in info.ip_literals

    def test_extracts_ipv6_network(self):
        info = parse_expression("ip.src in {2001:db8::/32 ::1}")
        assert "2001:db8::/32" in info.ip_literals
        assert "::1" in info.ip_literals

    def test_extracts_ipv6_loopback(self):
        info = parse_expression("ip.src eq ::1")
        assert "::1" in info.ip_literals

    def test_extracts_mixed_ipv4_and_ipv6(self):
        info = parse_expression("ip.src in {10.0.0.1 2001:db8::1}")
        assert "10.0.0.1" in info.ip_literals
        assert "2001:db8::1" in info.ip_literals

    def test_ipv6_no_false_positive_on_field(self):
        """Colons in non-IP contexts should not be extracted."""
        info = parse_expression('http.host eq "example.com"')
        # No IPv6 should appear
        assert all(":" not in ip for ip in info.ip_literals)


class TestRegexOperatorExtraction:
    """Test operator extraction for wildcard, strict, and bitwise_and via regex fallback."""

    def test_extracts_wildcard_operator(self):
        info = _parse_with_regex('http.host wildcard "*.example.com"')
        assert "wildcard" in info.operators_used

    def test_extracts_strict_wildcard(self):
        info = _parse_with_regex('http.host strict wildcard "*.example.com"')
        assert "strict" in info.operators_used
        assert "wildcard" in info.operators_used

    def test_extracts_bitwise_and(self):
        info = _parse_with_regex("cf.waf.score bitwise_and 0x01 eq 0x01")
        assert "bitwise_and" in info.operators_used


@pytest.mark.skipif(not WIREFILTER_AVAILABLE, reason="octorules-wirefilter not installed")
class TestWirefilterBridge:
    """Tests that run only when wirefilter FFI is available.

    Validates the bridge layer maps Rust parse results to ExpressionInfo.
    """

    def test_wirefilter_is_available(self):
        assert WIREFILTER_AVAILABLE

    def test_fields_via_wirefilter(self):
        info = parse_expression('http.host eq "example.com"')
        assert info.parse_error == ""
        assert "http.host" in info.fields_used

    def test_functions_via_wirefilter(self):
        info = parse_expression('lower(http.host) eq "example.com"')
        assert "lower" in info.functions_used
        assert "http.host" in info.fields_used

    def test_operators_via_wirefilter(self):
        info = parse_expression('http.host eq "a" and cf.threat_score gt 10')
        assert "eq" in info.operators_used
        assert "and" in info.operators_used
        assert "gt" in info.operators_used

    def test_string_literals_via_wirefilter(self):
        info = parse_expression('http.host in {"alpha" "beta"}')
        assert "alpha" in info.string_literals
        assert "beta" in info.string_literals

    def test_regex_detection_via_wirefilter(self):
        info = parse_expression('http.request.uri.path matches "^/api/.*"')
        assert info.has_regex
        assert "^/api/.*" in info.regex_literals

    def test_ip_literals_via_wirefilter(self):
        info = parse_expression("ip.src in {1.2.3.4 10.0.0.0/8}")
        assert "1.2.3.4" in info.ip_literals
        assert "10.0.0.0/8" in info.ip_literals

    def test_int_literals_via_wirefilter(self):
        info = parse_expression("cf.threat_score gt 50")
        assert 50 in info.int_literals

    def test_parse_error_returns_error(self):
        info = parse_expression('unknown_field eq "x"')
        assert info.parse_error != ""

    def test_default_scheme_uri_path_as_field(self):
        """Without phase, http.request.uri.path parses as a field."""
        info = parse_expression('http.request.uri.path eq "/test"')
        assert info.parse_error == ""
        assert "http.request.uri.path" in info.fields_used

    def test_transform_scheme_uri_path_as_function(self):
        """In a transform phase, http.request.uri.path is a function."""
        info = parse_expression(
            'http.request.uri.path(http.request.uri) eq "/rewritten"',
            phase="url_rewrite_rules",
        )
        assert info.parse_error == ""
        assert "http.request.uri.path" in info.functions_used

    def test_non_transform_phase_uses_default(self):
        """A non-transform phase still uses the default scheme."""
        info = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="http_request_firewall_custom",
        )
        assert info.parse_error == ""
        assert "http.request.uri.path" in info.fields_used
