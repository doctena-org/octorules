"""Tests for expression bridge (regex fallback and wirefilter FFI)."""

from __future__ import annotations

import logging

import pytest

from octorules.linter.expression_bridge import (
    WIREFILTER_AVAILABLE,
    _parse_with_regex,
    _parse_with_wirefilter,
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
        assert "strict_wildcard" in info.operators_used

    def test_extracts_bitwise_and(self):
        info = _parse_with_regex("cf.waf.score bitwise_and 0x01 eq 0x01")
        assert "bitwise_and" in info.operators_used


class TestRawStringExtraction:
    """Test raw string (r"...", r#"..."#) handling in regex fallback."""

    def test_raw_string_regex_matches(self):
        info = _parse_with_regex('http.request.uri.path matches r"^/api/v[0-9]+"')
        assert "^/api/v[0-9]+" in info.regex_literals
        assert "^/api/v[0-9]+" not in info.string_literals

    def test_raw_string_hash_regex_matches(self):
        info = _parse_with_regex('http.request.uri.path matches r#"^/api"#')
        assert "^/api" in info.regex_literals
        assert "^/api" not in info.string_literals

    def test_raw_string_tilde(self):
        info = _parse_with_regex('http.request.uri.path ~ r#"^/test"#')
        assert "^/test" in info.regex_literals

    def test_raw_string_not_in_string_literals(self):
        info = _parse_with_regex('http.host eq "test" and http.request.uri.path matches r#"^/api"#')
        assert "test" in info.string_literals
        assert "^/api" in info.regex_literals
        assert "^/api" not in info.string_literals

    def test_regular_string_still_works(self):
        info = _parse_with_regex('http.host eq "example.com"')
        assert "example.com" in info.string_literals
        assert info.regex_literals == []


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

    def test_raw_string_regex_via_wirefilter(self):
        info = parse_expression('http.request.uri.path matches r#"^/api/v[0-9]+"#')
        assert info.has_regex
        assert "^/api/v[0-9]+" in info.regex_literals
        assert "^/api/v[0-9]+" not in info.string_literals

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

    def test_default_scheme_always_used(self):
        """All expressions use the default scheme where uri.path is a field.

        The transform scheme (where uri.path is a callable function) is not
        used because wirefilter can't register a name as both field and
        function, and field usage is overwhelmingly more common.
        """
        info = parse_expression(
            'http.request.uri.path eq "/test"',
            phase="url_rewrite_rules",
        )
        assert info.parse_error == ""
        assert "http.request.uri.path" in info.fields_used

    def test_transform_phase_uri_path_field_in_starts_with(self):
        """starts_with(http.request.uri.path, ...) works in transform phases."""
        info = parse_expression(
            'starts_with(http.request.uri.path, "/api")',
            phase="request_header_rules",
        )
        assert info.parse_error == ""
        assert "http.request.uri.path" in info.fields_used
        assert "starts_with" in info.functions_used


class TestWirefilterFFICrashFallback:
    """Tests for FFI crash → regex fallback with logged warning."""

    def test_ffi_crash_falls_back_to_regex(self, monkeypatch):
        """When the FFI call raises, fall back to regex and preserve error."""

        def _boom(expr, phase=None):
            raise RuntimeError("segfault in FFI")

        monkeypatch.setattr("octorules.linter.expression_bridge._wf_parse", _boom)
        info = _parse_with_wirefilter('http.host eq "example.com"')
        # Should have fallen back to regex extraction
        assert "http.host" in info.fields_used
        # parse_error should include the exception type
        assert "RuntimeError" in info.parse_error
        assert "segfault in FFI" in info.parse_error
        assert info.parse_error_type == "wirefilter_crash"

    def test_ffi_crash_logs_warning(self, monkeypatch, caplog):
        """FFI crash should produce a warning log with exc_info."""

        def _boom(expr, phase=None):
            raise ValueError("bad input")

        monkeypatch.setattr("octorules.linter.expression_bridge._wf_parse", _boom)
        with caplog.at_level(logging.WARNING, logger="octorules.linter"):
            _parse_with_wirefilter('http.host eq "test"')
        assert any("Wirefilter FFI crashed" in r.message for r in caplog.records)
        assert any(
            r.exc_info is not None for r in caplog.records if "Wirefilter FFI crashed" in r.message
        )

    def test_wirefilter_error_dict_falls_back_to_regex(self, monkeypatch):
        """When wirefilter returns {error: ...}, fall back to regex with parse_error."""

        def _return_error(expr, phase=None):
            return {"error": "unknown field `bogus`"}

        monkeypatch.setattr("octorules.linter.expression_bridge._wf_parse", _return_error)
        info = _parse_with_wirefilter('http.host eq "example.com"')
        assert "http.host" in info.fields_used  # regex fallback extracted the field
        assert info.parse_error == "unknown field `bogus`"
        assert info.parse_error_type == "wirefilter_parse"


class TestParseErrorType:
    """Tests for the parse_error_type classification field."""

    def test_regex_fallback_when_wirefilter_unavailable(self, monkeypatch):
        monkeypatch.setattr("octorules.linter.expression_bridge.WIREFILTER_AVAILABLE", False)
        info = parse_expression('http.host eq "example.com"')
        assert info.parse_error_type == "regex_fallback"
        assert info.parse_error == ""

    @pytest.mark.skipif(not WIREFILTER_AVAILABLE, reason="octorules-wirefilter not installed")
    def test_success_via_wirefilter(self):
        info = parse_expression('http.host eq "example.com"')
        assert info.parse_error_type == ""
        assert info.parse_error == ""

    def test_wirefilter_parse_error_type(self, monkeypatch):
        def _return_error(expr, phase=None):
            return {"error": "unknown field `bogus`"}

        monkeypatch.setattr("octorules.linter.expression_bridge._wf_parse", _return_error)
        info = _parse_with_wirefilter('http.host eq "example.com"')
        assert info.parse_error_type == "wirefilter_parse"

    def test_wirefilter_crash_type(self, monkeypatch):
        def _boom(expr, phase=None):
            raise RuntimeError("boom")

        monkeypatch.setattr("octorules.linter.expression_bridge._wf_parse", _boom)
        info = _parse_with_wirefilter('http.host eq "example.com"')
        assert info.parse_error_type == "wirefilter_crash"

    def test_regex_only_has_no_error_type(self):
        """Direct _parse_with_regex call returns empty parse_error_type."""
        info = _parse_with_regex('http.host eq "example.com"')
        assert info.parse_error_type == ""
        assert info.parse_error == ""


class TestRegexParserEdgeCases:
    """Edge case tests for the regex expression parser."""

    def test_unicode_in_string_literal(self):
        info = _parse_with_regex('http.host eq "café.example.com"')
        assert "café.example.com" in info.string_literals

    def test_escaped_quotes_in_string_literal(self):
        info = _parse_with_regex(r'http.host eq "say \"hello\""')
        assert r"say \"hello\"" in info.string_literals

    def test_very_long_expression(self):
        """Parser should handle expressions up to 4096 chars without error."""
        # Build a long OR chain: http.host eq "aaa..." or http.host eq "bbb..."
        parts = [f'http.host eq "{"x" * 50}_{i}"' for i in range(60)]
        expr = " or ".join(parts)
        assert len(expr) > 4000
        info = _parse_with_regex(expr)
        assert "http.host" in info.fields_used
        assert "or" in info.operators_used
        assert len(info.string_literals) == 60

    def test_full_form_ipv6(self):
        info = _parse_with_regex("ip.src eq 2001:0db8:0000:0000:0000:0000:0000:0001")
        assert "2001:0db8:0000:0000:0000:0000:0000:0001" in info.ip_literals

    def test_empty_set_literal(self):
        """Empty set {} should not crash the parser."""
        info = _parse_with_regex("http.host in {}")
        assert info.fields_used == ["http.host"]
        assert "in" in info.operators_used

    def test_integer_only_expression(self):
        info = _parse_with_regex("cf.threat_score gt 50")
        assert 50 in info.int_literals
        assert "cf.threat_score" in info.fields_used
