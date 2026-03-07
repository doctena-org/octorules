"""Tests for AST linter — expression-level rules (Categories A, E, F, G, O)."""

from __future__ import annotations

import pytest

from octorules.linter.ast_linter import lint_expressions
from octorules.linter.engine import LintContext
from octorules.linter.expression_bridge import WIREFILTER_AVAILABLE
from octorules.phases import PHASE_BY_NAME


def _lint(expression, phase_name="waf_custom_rules", ref="test"):
    rule = {"ref": ref, "expression": expression}
    phase = PHASE_BY_NAME[phase_name]
    ctx = LintContext()
    lint_expressions(rule, phase, ctx)
    return ctx


def _ids(ctx):
    return [r.rule_id for r in ctx.results]


class TestValueConstraints:
    def test_g001_lowercase_method(self):
        ctx = _lint('http.request.method eq "get"')
        assert "G001" in _ids(ctx)

    def test_g001_uppercase_method_ok(self):
        ctx = _lint('http.request.method eq "GET"')
        assert "G001" not in _ids(ctx)

    def test_g002_no_false_positive_on_other_field_values(self):
        # Values for cf.zone.name should not trigger G002
        ctx = _lint('cf.zone.name eq "doctena.com" and http.request.uri.path eq "/api"')
        g002 = [r for r in ctx.results if r.rule_id == "G002"]
        assert len(g002) == 0

    def test_g002_fires_on_bad_path_eq(self):
        ctx = _lint('http.request.uri.path eq "api"')
        assert "G002" in _ids(ctx)

    def test_g002_fires_on_bad_path_in_set(self):
        ctx = _lint('http.request.uri.path in {"/ok" "bad"}')
        g002 = [r for r in ctx.results if r.rule_id == "G002"]
        assert len(g002) == 1
        assert "bad" in g002[0].message

    def test_g003_regex_anchor_in_literal(self):
        ctx = _lint('http.request.uri.path eq "^/api"')
        assert "G003" in _ids(ctx)

    def test_g003_no_false_positive_on_matches(self):
        # With 'matches' operator, regex anchors are expected
        ctx = _lint('http.request.uri.path matches "^/api"')
        assert "G003" not in _ids(ctx)

    def test_g003_fires_when_expression_also_has_regex(self):
        # PR #83 regression: G003 must fire for regex anchor in 'in' set
        # even when the expression also uses 'matches' elsewhere
        ctx = _lint(
            '(http.request.uri.path in {"/foo" "^/bar"}) or '
            '(http.request.uri.path matches "^/staging/.*")'
        )
        assert "G003" in _ids(ctx)
        g003 = [r for r in ctx.results if r.rule_id == "G003"]
        assert any("^/bar" in r.message for r in g003)

    def test_g003_no_false_positive_dollar_in_path(self):
        # A '$' in a string literal used with 'in' should fire
        ctx = _lint('http.request.uri.path in {"/ok" "/test$"}')
        assert "G003" in _ids(ctx)

    def test_g009_duplicate_string_in_set(self):
        ctx = _lint('http.request.uri.path in {"/foo" "/bar" "/foo"}')
        assert "G009" in _ids(ctx)
        g009 = [r for r in ctx.results if r.rule_id == "G009"]
        assert any("/foo" in r.message for r in g009)

    def test_g009_duplicate_ip_in_set(self):
        ctx = _lint("ip.src in {1.2.3.4 5.6.7.8 1.2.3.4}")
        assert "G009" in _ids(ctx)
        g009 = [r for r in ctx.results if r.rule_id == "G009"]
        assert any("1.2.3.4" in r.message for r in g009)

    def test_g009_duplicate_int_in_set(self):
        ctx = _lint("ip.geoip.asnum in {123 456 123}")
        assert "G009" in _ids(ctx)

    def test_g009_no_false_positive_unique_values(self):
        ctx = _lint('http.request.uri.path in {"/a" "/b" "/c"}')
        assert "G009" not in _ids(ctx)

    def test_g009_multiple_in_sets_independent(self):
        # Duplicates within one set should fire; no cross-set false positives
        ctx = _lint(
            '(http.request.uri.path in {"/a" "/a"}) and (http.request.method in {"GET" "POST"})'
        )
        g009 = [r for r in ctx.results if r.rule_id == "G009"]
        assert len(g009) == 1
        assert any("/a" in r.message for r in g009)

    def test_g009_multiple_duplicates_reported(self):
        ctx = _lint("ip.src in {1.1.1.1 2.2.2.2 1.1.1.1 2.2.2.2}")
        g009 = [r for r in ctx.results if r.rule_id == "G009"]
        assert len(g009) == 2

    def test_g004_lowercase_country_code(self):
        ctx = _lint('ip.geoip.country eq "de"')
        assert "G004" in _ids(ctx)

    def test_g004_uppercase_country_code_ok(self):
        ctx = _lint('ip.geoip.country eq "DE"')
        assert "G004" not in _ids(ctx)

    def test_g005_score_out_of_range(self):
        ctx = _lint("cf.threat_score gt 200")
        assert "G005" in _ids(ctx)

    def test_g005_score_in_range(self):
        ctx = _lint("cf.threat_score gt 50")
        assert "G005" not in _ids(ctx)

    def test_g005_per_field_no_false_positive(self):
        # Integer 200 belongs to http.response.code, not cf.waf.score
        ctx = _lint(
            "cf.waf.score gt 50 and http.response.code eq 200",
            "response_header_rules",
        )
        g005 = [r for r in ctx.results if r.rule_id == "G005"]
        assert len(g005) == 0

    def test_g005_bot_management_score_range(self):
        # cf.bot_management.score valid range is 1-99
        ctx = _lint("cf.bot_management.score gt 0")
        assert "G005" in _ids(ctx)
        ctx2 = _lint("cf.bot_management.score gt 1")
        assert "G005" not in _ids(ctx2)

    def test_g006_invalid_response_code(self):
        ctx = _lint("http.response.code eq 999", "response_header_rules")
        assert "G006" in _ids(ctx)

    def test_g006_valid_response_code(self):
        ctx = _lint("http.response.code eq 200", "response_header_rules")
        assert "G006" not in _ids(ctx)

    def test_g008_extension_with_dot(self):
        ctx = _lint('http.request.uri.path.extension in {".jpg" ".png"}')
        assert "G008" in _ids(ctx)

    def test_g008_extension_without_dot(self):
        ctx = _lint('http.request.uri.path.extension in {"jpg" "png"}')
        assert "G008" not in _ids(ctx)


class TestDeprecatedFields:
    def test_g010_ip_geoip_asnum(self):
        ctx = _lint("ip.geoip.asnum eq 13335")
        assert "G010" in _ids(ctx)
        g010 = [r for r in ctx.results if r.rule_id == "G010"]
        assert "ip.src.asnum" in g010[0].message

    def test_g010_ip_geoip_continent(self):
        ctx = _lint('ip.geoip.continent eq "EU"')
        assert "G010" in _ids(ctx)

    def test_g010_ip_geoip_country(self):
        ctx = _lint('ip.geoip.country eq "DE"')
        assert "G010" in _ids(ctx)

    def test_g010_ip_geoip_subdivision_1(self):
        ctx = _lint('ip.geoip.subdivision_1_iso_code eq "BY"')
        assert "G010" in _ids(ctx)

    def test_g010_ip_geoip_subdivision_2(self):
        ctx = _lint('ip.geoip.subdivision_2_iso_code eq "MU"')
        assert "G010" in _ids(ctx)

    def test_g010_ip_geoip_eu(self):
        ctx = _lint("ip.geoip.is_in_european_union")
        assert "G010" in _ids(ctx)

    def test_g010_ip_src_country_ok(self):
        ctx = _lint('ip.src.country eq "DE"')
        assert "G010" not in _ids(ctx)

    def test_g010_unrelated_field_ok(self):
        ctx = _lint('http.host eq "example.com"')
        assert "G010" not in _ids(ctx)

    def test_g010_two_deprecated_fields(self):
        ctx = _lint('ip.geoip.country eq "DE" and ip.geoip.continent eq "EU"')
        g010 = [r for r in ctx.results if r.rule_id == "G010"]
        assert len(g010) == 2


class TestBogonIPs:
    def test_g011_rfc1918_10(self):
        ctx = _lint("ip.src in {10.0.0.1}")
        assert "G011" in _ids(ctx)

    def test_g011_rfc1918_172(self):
        ctx = _lint("ip.src == 172.16.0.1")
        assert "G011" in _ids(ctx)

    def test_g011_rfc1918_192(self):
        ctx = _lint("ip.src == 192.168.1.1")
        assert "G011" in _ids(ctx)

    def test_g011_loopback(self):
        ctx = _lint("ip.src == 127.0.0.1")
        assert "G011" in _ids(ctx)

    def test_g011_link_local(self):
        ctx = _lint("ip.src == 169.254.0.1")
        assert "G011" in _ids(ctx)

    def test_g011_cgnat(self):
        ctx = _lint("ip.src == 100.64.0.1")
        assert "G011" in _ids(ctx)

    def test_g011_documentation(self):
        ctx = _lint("ip.src == 192.0.2.1")
        assert "G011" in _ids(ctx)

    def test_g011_cidr_private(self):
        ctx = _lint("ip.src in {10.0.0.0/8}")
        assert "G011" in _ids(ctx)

    def test_g011_public_ip_ok(self):
        ctx = _lint("ip.src == 1.1.1.1")
        assert "G011" not in _ids(ctx)

    def test_g011_public_cidr_ok(self):
        ctx = _lint("ip.src in {8.8.8.0/24}")
        assert "G011" not in _ids(ctx)

    def test_g011_message_includes_description(self):
        ctx = _lint("ip.src == 10.0.0.1")
        g011 = [r for r in ctx.results if r.rule_id == "G011"]
        assert "RFC 1918 private" in g011[0].message

    def test_g011_multiple_bogons(self):
        ctx = _lint("ip.src in {10.0.0.1 192.168.1.1}")
        g011 = [r for r in ctx.results if r.rule_id == "G011"]
        assert len(g011) == 2


class TestOverlappingIPs:
    def test_g012_single_ip_within_cidr(self):
        ctx = _lint("ip.src in {10.0.0.1 10.0.0.0/8}")
        assert "G012" in _ids(ctx)

    def test_g012_cidr_within_cidr(self):
        ctx = _lint("ip.src in {10.0.0.0/24 10.0.0.0/8}")
        assert "G012" in _ids(ctx)

    def test_g012_same_base_different_prefix(self):
        ctx = _lint("ip.src in {192.168.1.0/24 192.168.0.0/16}")
        assert "G012" in _ids(ctx)

    def test_g012_non_overlapping_ok(self):
        ctx = _lint("ip.src in {1.1.1.0/24 8.8.8.0/24}")
        assert "G012" not in _ids(ctx)

    def test_g012_single_ip_ok(self):
        ctx = _lint("ip.src == 1.1.1.1")
        assert "G012" not in _ids(ctx)

    def test_g012_adjacent_non_overlapping_ok(self):
        ctx = _lint("ip.src in {10.0.0.0/25 10.0.0.128/25}")
        assert "G012" not in _ids(ctx)

    def test_g012_message_content(self):
        ctx = _lint("ip.src in {10.0.0.1 10.0.0.0/8}")
        g012 = [r for r in ctx.results if r.rule_id == "G012"]
        assert len(g012) == 1
        assert "10.0.0.1" in g012[0].message
        assert "10.0.0.0/8" in g012[0].message


class TestHeaderNameCase:
    def test_g007_uppercase_header_name(self):
        ctx = _lint('any(http.request.headers["X-Custom-Header"][*] eq "val")')
        assert "G007" in _ids(ctx)

    def test_g007_lowercase_header_ok(self):
        ctx = _lint('any(http.request.headers["x-custom-header"][*] eq "val")')
        assert "G007" not in _ids(ctx)


class TestTypeConstraints:
    def test_f001_numeric_op_on_string_field(self):
        ctx = _lint("http.host gt 5")
        assert "F001" in _ids(ctx)

    def test_f001_string_on_numeric_field(self):
        ctx = _lint('cf.threat_score eq "high"')
        assert "F001" in _ids(ctx)

    def test_f001_valid_string_comparison(self):
        ctx = _lint('http.host eq "example.com"')
        assert "F001" not in _ids(ctx)

    def test_f001_valid_numeric_comparison(self):
        ctx = _lint("cf.threat_score gt 50")
        assert "F001" not in _ids(ctx)


class TestStyleSuggestions:
    def test_o001_multiple_or_to_in(self):
        ctx = _lint('http.host eq "a" or http.host eq "b" or http.host eq "c"')
        assert "O001" in _ids(ctx)

    def test_o001_not_triggered_for_few(self):
        ctx = _lint('http.host eq "a" or http.host eq "b"')
        assert "O001" not in _ids(ctx)

    def test_o002_raw_field_suggestion(self):
        ctx = _lint('raw.http.request.uri.path eq "/test"')
        assert "O002" in _ids(ctx)

    def test_o003_double_negation(self):
        ctx = _lint('not not http.host eq "example.com"')
        assert "O003" in _ids(ctx)

    def test_o003_single_not_ok(self):
        ctx = _lint('not http.host eq "example.com"')
        assert "O003" not in _ids(ctx)


class TestFunctionConstraints:
    def test_e001_unknown_function(self):
        ctx = _lint('bogus_function(http.host, "x")')
        assert "E001" in _ids(ctx)

    def test_e001_known_function_ok(self):
        ctx = _lint('starts_with(http.request.uri.path, "/api/")')
        assert "E001" not in _ids(ctx)

    def test_e001_encode_base64_ok(self):
        ctx = _lint('encode_base64(http.request.uri.path) eq "L2Fw"')
        assert "E001" not in _ids(ctx)

    def test_e001_decode_base64_ok(self):
        ctx = _lint('decode_base64(http.request.uri.path) eq "/api"')
        assert "E001" not in _ids(ctx)

    def test_e001_cidr_ok(self):
        ctx = _lint("cidr(ip.src, 24, 0) == 10.0.0.0")
        assert "E001" not in _ids(ctx)

    def test_e001_cidr6_ok(self):
        ctx = _lint("cidr6(ip.src, 48) == 2001:db8::")
        assert "E001" not in _ids(ctx)

    def test_e001_join_ok(self):
        ctx = _lint('join(http.request.headers.names, ",") eq "a,b"')
        assert "E001" not in _ids(ctx)

    def test_e001_split_ok(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 3)[*] eq "api")')
        assert "E001" not in _ids(ctx)

    def test_e001_has_key_ok(self):
        ctx = _lint('has_key(http.request.headers, "x-api-key")')
        assert "E001" not in _ids(ctx)

    def test_e001_wildcard_replace_ok(self):
        ctx = _lint('wildcard_replace(http.host, "*.example.com", "${1}.cdn.com") eq "a.cdn.com"')
        assert "E001" not in _ids(ctx)


class TestNoExpression:
    def test_no_crash_on_missing_expression(self):
        rule = {"ref": "test"}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext()
        lint_expressions(rule, phase, ctx)
        assert len(ctx.results) == 0

    def test_no_crash_on_non_string_expression(self):
        rule = {"ref": "test", "expression": 42}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext()
        lint_expressions(rule, phase, ctx)
        assert len(ctx.results) == 0


class TestBogonIPsNewRanges:
    def test_g011_iana_special_purpose(self):
        ctx = _lint("ip.src == 192.0.0.1")
        assert "G011" in _ids(ctx)

    def test_g011_6to4_relay(self):
        ctx = _lint("ip.src == 192.88.99.1")
        assert "G011" in _ids(ctx)

    def test_g011_benchmark_testing(self):
        ctx = _lint("ip.src == 198.18.0.1")
        assert "G011" in _ids(ctx)

    def test_g011_multicast(self):
        ctx = _lint("ip.src == 224.0.0.1")
        assert "G011" in _ids(ctx)

    def test_g011_reserved_future(self):
        ctx = _lint("ip.src == 240.0.0.1")
        assert "G011" in _ids(ctx)


class TestValueDomains:
    def test_g013_full_uri_must_start_with_http(self):
        ctx = _lint('http.request.full_uri eq "ftp://example.com"')
        assert "G013" in _ids(ctx)

    def test_g013_full_uri_https_ok(self):
        ctx = _lint('http.request.full_uri eq "https://example.com"')
        assert "G013" not in _ids(ctx)

    def test_g013_http_version_must_start_with_http(self):
        ctx = _lint('http.request.version eq "2.0"')
        assert "G013" in _ids(ctx)

    def test_g013_http_version_ok(self):
        ctx = _lint('http.request.version eq "HTTP/2"')
        assert "G013" not in _ids(ctx)

    def test_g013_mime_must_contain_slash(self):
        ctx = _lint('http.request.body.mime eq "texthtml"')
        assert "G013" in _ids(ctx)

    def test_g013_mime_ok(self):
        ctx = _lint('http.request.body.mime eq "text/html"')
        assert "G013" not in _ids(ctx)

    def test_g013_mime_uppercase_flagged(self):
        ctx = _lint('http.request.body.mime eq "Text/HTML"')
        assert "G013" in _ids(ctx)

    def test_g013_continent_invalid(self):
        ctx = _lint('ip.src.continent eq "XX"')
        assert "G013" in _ids(ctx)

    def test_g013_continent_valid(self):
        ctx = _lint('ip.src.continent eq "EU"')
        assert "G013" not in _ids(ctx)

    def test_g013_continent_t1_valid(self):
        ctx = _lint('ip.src.continent eq "T1"')
        assert "G013" not in _ids(ctx)

    def test_g013_waf_score_class_invalid(self):
        ctx = _lint('cf.waf.score.class eq "bad"')
        assert "G013" in _ids(ctx)

    def test_g013_waf_score_class_valid(self):
        ctx = _lint('cf.waf.score.class eq "attack"')
        assert "G013" not in _ids(ctx)

    def test_g013_error_type_invalid(self):
        ctx = _lint('cf.response.error_type eq "unknown"')
        assert "G013" in _ids(ctx)

    def test_g013_error_type_valid(self):
        ctx = _lint('cf.response.error_type eq "waf"')
        assert "G013" not in _ids(ctx)

    def test_g013_raw_uri_path_must_start_with_slash(self):
        ctx = _lint('raw.http.request.uri.path eq "api"')
        g013 = [r for r in ctx.results if r.rule_id == "G013"]
        assert len(g013) == 1

    def test_g013_raw_extension_no_dots(self):
        ctx = _lint('raw.http.request.uri.path.extension eq ".js"')
        assert "G013" in _ids(ctx)

    def test_g013_raw_extension_ok(self):
        ctx = _lint('raw.http.request.uri.path.extension eq "js"')
        assert "G013" not in _ids(ctx)

    def test_g013_timestamp_msec_out_of_range(self):
        ctx = _lint("http.request.timestamp.msec eq 1500")
        assert "G013" in _ids(ctx)

    def test_g013_timestamp_msec_in_range(self):
        ctx = _lint("http.request.timestamp.msec eq 500")
        assert "G013" not in _ids(ctx)


class TestTimestampBounds:
    def test_g014_too_old(self):
        ctx = _lint("http.request.timestamp.sec gt 1000")
        assert "G014" in _ids(ctx)

    def test_g014_valid(self):
        # A recent-ish timestamp (Jan 2024)
        ctx = _lint("http.request.timestamp.sec gt 1704067200")
        assert "G014" not in _ids(ctx)

    def test_g014_too_far_future(self):
        # Year 2099
        ctx = _lint("http.request.timestamp.sec gt 4102444800")
        assert "G014" in _ids(ctx)

    def test_g014_near_future_ok(self):
        # 6 months from now — should be fine
        import time

        ts = int(time.time()) + 180 * 86400
        ctx = _lint(f"http.request.timestamp.sec gt {ts}")
        assert "G014" not in _ids(ctx)


class TestIntRangeOverlap:
    def test_g015_value_in_range(self):
        ctx = _lint("ip.src.asnum in {100 50..200}")
        assert "G015" in _ids(ctx)

    def test_g015_subrange(self):
        ctx = _lint("ip.src.asnum in {60..70 50..200}")
        assert "G015" in _ids(ctx)

    def test_g015_no_overlap(self):
        ctx = _lint("ip.src.asnum in {10..20 50..100}")
        assert "G015" not in _ids(ctx)

    def test_g015_identical_not_flagged(self):
        # Exact duplicates are G009's job
        ctx = _lint("ip.src.asnum in {100 100}")
        assert "G015" not in _ids(ctx)

    def test_g015_single_ok(self):
        ctx = _lint("ip.src.asnum in {100}")
        assert "G015" not in _ids(ctx)


class TestNegatedComparison:
    def test_o004_not_eq_to_ne(self):
        ctx = _lint('not http.host eq "example.com"')
        assert "O004" in _ids(ctx)
        o004 = [r for r in ctx.results if r.rule_id == "O004"]
        assert "ne" in o004[0].message

    def test_o004_not_lt_to_ge(self):
        ctx = _lint("not cf.threat_score lt 50")
        assert "O004" in _ids(ctx)
        o004 = [r for r in ctx.results if r.rule_id == "O004"]
        assert "ge" in o004[0].message

    def test_o004_ne_not_flagged(self):
        ctx = _lint('http.host ne "example.com"')
        assert "O004" not in _ids(ctx)

    def test_o004_suggestion_content(self):
        ctx = _lint('not http.host eq "example.com"')
        o004 = [r for r in ctx.results if r.rule_id == "O004"]
        assert o004[0].suggestion is not None
        assert "ne" in o004[0].suggestion


class TestIllogicalCondition:
    def test_o005_contradictory_and(self):
        ctx = _lint('http.host eq "a.com" and http.host eq "b.com"')
        assert "O005" in _ids(ctx)

    def test_o005_tautological_or(self):
        ctx = _lint('http.host ne "a.com" or http.host ne "b.com"')
        assert "O005" in _ids(ctx)

    def test_o005_valid_and_different_fields(self):
        ctx = _lint('http.host eq "a.com" and http.referer eq "b.com"')
        assert "O005" not in _ids(ctx)

    def test_o005_same_value_and_ok(self):
        ctx = _lint('http.host eq "a.com" and http.host eq "a.com"')
        assert "O005" not in _ids(ctx)

    def test_o005_mixed_connectives_skip(self):
        # Mixed and/or without parens — don't flag (ambiguous precedence)
        ctx = _lint('http.host eq "a.com" and http.host eq "b.com" or http.host eq "c.com"')
        assert "O005" not in _ids(ctx)

    def test_o005_parens_isolate(self):
        # Outer parens stripped, inner parens preserved
        ctx = _lint('(http.host eq "a.com") and (http.host eq "b.com")')
        assert "O005" in _ids(ctx)


class TestRegexEscapes:
    def test_o006_literal_with_backslash(self):
        ctx = _lint(r'http.request.uri.path matches "\\.(js|css)$"')
        assert "O006" in _ids(ctx)

    def test_o006_no_backslash_ok(self):
        ctx = _lint('http.request.uri.path matches "^/api/"')
        assert "O006" not in _ids(ctx)


class TestHasValueFunction:
    def test_e001_has_value_ok(self):
        ctx = _lint('has_value(http.request.headers.names, "x-api-key")')
        assert "E001" not in _ids(ctx)


class TestIPv6BogonRanges:
    def test_g011_ipv6_loopback(self):
        ctx = _lint("ip.src == ::1")
        assert "G011" in _ids(ctx)

    def test_g011_ipv6_documentation(self):
        ctx = _lint("ip.src in {2001:db8::1}")
        assert "G011" in _ids(ctx)

    def test_g011_ipv6_unique_local(self):
        ctx = _lint("ip.src == fd12:3456:789a::1")
        assert "G011" in _ids(ctx)

    def test_g011_ipv6_link_local(self):
        ctx = _lint("ip.src == fe80::1")
        assert "G011" in _ids(ctx)

    def test_g011_ipv6_multicast(self):
        ctx = _lint("ip.src == ff02::1")
        assert "G011" in _ids(ctx)

    def test_g011_ipv6_public_ok(self):
        ctx = _lint("ip.src == 2606:4700::1")
        assert "G011" not in _ids(ctx)

    def test_g011_ipv6_via_regex_fallback(self, monkeypatch):
        """Verify G011 fires for IPv6 even without wirefilter FFI."""
        from octorules.linter import expression_bridge

        monkeypatch.setattr(expression_bridge, "WIREFILTER_AVAILABLE", False)
        # Force regex path — ::1 is loopback
        ctx = _lint("ip.src == ::1")
        assert "G011" in _ids(ctx)


class TestLowerUpperMismatch:
    def test_g016_lower_uppercase_value(self):
        ctx = _lint('lower(http.host) eq "EXAMPLE.COM"')
        assert "G016" in _ids(ctx)

    def test_g016_lower_lowercase_ok(self):
        ctx = _lint('lower(http.host) eq "example.com"')
        assert "G016" not in _ids(ctx)

    def test_g016_upper_lowercase_value(self):
        ctx = _lint('upper(http.host) eq "example.com"')
        assert "G016" in _ids(ctx)

    def test_g016_upper_uppercase_ok(self):
        ctx = _lint('upper(http.host) eq "EXAMPLE.COM"')
        assert "G016" not in _ids(ctx)

    def test_g016_lower_in_set(self):
        ctx = _lint('lower(http.host) in {"ok" "BAD"}')
        assert "G016" in _ids(ctx)


class TestLenNegative:
    def test_g017_negative_triggers(self):
        ctx = _lint("len(http.host) gt -1")
        assert "G017" in _ids(ctx)

    def test_g017_zero_ok(self):
        ctx = _lint("len(http.host) gt 0")
        assert "G017" not in _ids(ctx)

    def test_g017_positive_ok(self):
        ctx = _lint("len(http.host) gt 10")
        assert "G017" not in _ids(ctx)


class TestF001FullRegistry:
    def test_f001_ip_gt(self):
        ctx = _lint("ip.src gt 5")
        assert "F001" in _ids(ctx)

    def test_f001_int_contains(self):
        ctx = _lint('cf.threat_score contains "x"')
        assert "F001" in _ids(ctx)

    def test_f001_bool_string(self):
        ctx = _lint('cf.bot_management.verified_bot eq "true"')
        assert "F001" in _ids(ctx)

    def test_f001_string_numeric_ok(self):
        ctx = _lint('http.host eq "example.com"')
        assert "F001" not in _ids(ctx)


class TestE003ReplaceLimits:
    def test_e003_regex_replace_twice(self):
        ctx = _lint(
            'regex_replace(http.host, "a", "b") eq regex_replace(http.host, "c", "d")',
            "url_rewrite_rules",
        )
        assert "E003" in _ids(ctx)

    def test_e003_wildcard_replace_twice(self):
        ctx = _lint(
            'wildcard_replace(http.host, "*a*", "b") eq wildcard_replace(http.host, "*c*", "d")',
            "url_rewrite_rules",
        )
        assert "E003" in _ids(ctx)

    def test_e003_both_present(self):
        ctx = _lint(
            'regex_replace(http.host, "a", "b") eq wildcard_replace(http.host, "*c*", "d")',
            "url_rewrite_rules",
        )
        assert "E003" in _ids(ctx)

    def test_e003_single_ok(self):
        ctx = _lint(
            'regex_replace(http.host, "a", "b") eq "c"',
            "url_rewrite_rules",
        )
        assert "E003" not in _ids(ctx)


class TestE002PhaseRestrictions:
    def test_e002_regex_replace_in_waf(self):
        ctx = _lint('regex_replace(http.host, "a", "b") eq "c"', "waf_custom_rules")
        assert "E002" in _ids(ctx)

    def test_e002_regex_replace_in_transform_ok(self):
        ctx = _lint('regex_replace(http.host, "a", "b") eq "c"', "url_rewrite_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_sha256_in_waf(self):
        ctx = _lint('sha256(http.host) eq "abc"', "waf_custom_rules")
        assert "E002" in _ids(ctx)

    def test_e002_uuidv4_in_transform_ok(self):
        ctx = _lint('uuidv4() eq "abc"', "url_rewrite_rules")
        assert "E002" not in _ids(ctx)


class TestG005ExtendedRanges:
    def test_g005_port_out_of_range(self):
        ctx = _lint("cf.edge.server_port eq 0")
        assert "G005" in _ids(ctx)

    def test_g005_port_valid(self):
        ctx = _lint("cf.edge.server_port eq 443")
        assert "G005" not in _ids(ctx)


class TestG018WildcardDoubleAsterisk:
    def test_g018_double_asterisk_fires(self):
        ctx = _lint('http.host wildcard "**.example.com"')
        assert "G018" in _ids(ctx)

    def test_g018_single_asterisk_ok(self):
        ctx = _lint('http.host wildcard "*.example.com"')
        assert "G018" not in _ids(ctx)

    def test_g018_strict_wildcard_double(self):
        ctx = _lint('http.host strict wildcard "test**"')
        assert "G018" in _ids(ctx)


class TestG006PerField:
    def test_g006_no_false_positive_on_other_int(self):
        # cf.threat_score value 50 should NOT trigger G006
        ctx = _lint(
            "http.response.code eq 200 and cf.threat_score gt 50",
            "response_header_rules",
        )
        g006 = [r for r in ctx.results if r.rule_id == "G006"]
        assert len(g006) == 0


class TestG007BracketUppercase:
    def test_g007_bracket_uppercase_no_dash(self):
        # Map bracket keys are always header names — uppercase without dash should fire
        ctx = _lint('any(http.request.headers["Authorization"][*] eq "val")')
        assert "G007" in _ids(ctx)

    def test_g007_bracket_lowercase_ok(self):
        ctx = _lint('any(http.request.headers["authorization"][*] eq "val")')
        assert "G007" not in _ids(ctx)


class TestO001OrContext:
    def test_o001_and_chain_no_trigger(self):
        # AND chain with 3 eq — should NOT trigger O001
        ctx = _lint('http.host eq "a" and http.host eq "b" and http.host eq "c"')
        assert "O001" not in _ids(ctx)


class TestO003Parens:
    def test_o003_not_paren_not(self):
        ctx = _lint('not (not http.host eq "example.com")')
        assert "O003" in _ids(ctx)


class TestG019ReversedRange:
    def test_g019_start_gt_end(self):
        ctx = _lint("http.response.code in {500..200}", "response_header_rules")
        assert "G019" in _ids(ctx)

    def test_g019_valid_range_ok(self):
        ctx = _lint("http.response.code in {200..299}", "response_header_rules")
        assert "G019" not in _ids(ctx)

    def test_g019_equal_range_ok(self):
        ctx = _lint("http.response.code in {200..200}", "response_header_rules")
        assert "G019" not in _ids(ctx)


class TestH003RegexCount:
    def test_h003_too_many_regex(self):
        patterns = " or ".join(f'http.request.uri.path matches "^/p{i}/"' for i in range(65))
        ctx = _lint(patterns)
        assert "H003" in _ids(ctx)

    def test_h003_under_limit_ok(self):
        patterns = " or ".join(f'http.request.uri.path matches "^/p{i}/"' for i in range(10))
        ctx = _lint(patterns)
        assert "H003" not in _ids(ctx)


class TestE004EncodeBase64Flags:
    def test_e004_invalid_flag(self):
        ctx = _lint('encode_base64(http.host, "x") eq "abc"', "url_rewrite_rules")
        assert "E004" in _ids(ctx)

    def test_e004_valid_flag(self):
        ctx = _lint('encode_base64(http.host, "u") eq "abc"', "url_rewrite_rules")
        assert "E004" not in _ids(ctx)


class TestE005UrlDecodeFlags:
    def test_e005_invalid_option(self):
        ctx = _lint('url_decode(http.host, "z") eq "abc"')
        assert "E005" in _ids(ctx)

    def test_e005_valid_option(self):
        ctx = _lint('url_decode(http.host, "r") eq "abc"')
        assert "E005" not in _ids(ctx)


class TestE006WildcardReplaceFlags:
    def test_e006_invalid_flag(self):
        ctx = _lint(
            'wildcard_replace(http.host, "*.example.com", "${1}.cdn.com", "x") eq "a"',
            "url_rewrite_rules",
        )
        assert "E006" in _ids(ctx)

    def test_e006_valid_flag(self):
        ctx = _lint(
            'wildcard_replace(http.host, "*.example.com", "${1}.cdn.com", "s") eq "a"',
            "url_rewrite_rules",
        )
        assert "E006" not in _ids(ctx)


class TestG020SplitLimit:
    def test_g020_limit_too_high(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 200)[*] eq "api")')
        assert "G020" in _ids(ctx)

    def test_g020_limit_zero(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 0)[*] eq "api")')
        assert "G020" in _ids(ctx)

    def test_g020_limit_ok(self):
        ctx = _lint('any(split(http.request.uri.path, "/", 3)[*] eq "api")')
        assert "G020" not in _ids(ctx)


class TestG021CidrBits:
    def test_g021_cidr_out_of_range(self):
        ctx = _lint("cidr(ip.src, 33, 0) == 10.0.0.0")
        assert "G021" in _ids(ctx)

    def test_g021_cidr_valid(self):
        ctx = _lint("cidr(ip.src, 24, 0) == 10.0.0.0")
        assert "G021" not in _ids(ctx)

    def test_g021_cidr6_out_of_range(self):
        ctx = _lint("cidr6(ip.src, 129) == 2001:db8::")
        assert "G021" in _ids(ctx)

    def test_g021_cidr6_valid(self):
        ctx = _lint("cidr6(ip.src, 48) == 2001:db8::")
        assert "G021" not in _ids(ctx)


class TestG022RemoveQueryArgs:
    def test_g022_wrong_field(self):
        ctx = _lint(
            'remove_query_args(http.host, "key") eq "abc"',
            "url_rewrite_rules",
        )
        assert "G022" in _ids(ctx)

    def test_g022_correct_field(self):
        ctx = _lint(
            'remove_query_args(http.request.uri.query, "key") eq "abc"',
            "url_rewrite_rules",
        )
        assert "G022" not in _ids(ctx)


@pytest.mark.skipif(not WIREFILTER_AVAILABLE, reason="octorules-wirefilter not installed")
class TestA001ParseErrors:
    def test_a001_invalid_syntax(self):
        """Incomplete expression triggers A001 when wirefilter is available."""
        ctx = _lint("http.host eq")
        assert "A001" in _ids(ctx)

    def test_a001_unknown_field_triggers(self):
        """Wirefilter rejects unknown field, fires A001."""
        ctx = _lint('http.hoost eq "x"')
        assert "A001" in _ids(ctx)

    def test_a001_valid_expression_no_error(self):
        """Clean expression — A001 does not fire."""
        ctx = _lint('http.host eq "example.com"')
        assert "A001" not in _ids(ctx)

    def test_a001_not_fired_without_wirefilter(self, monkeypatch):
        """A001 should not fire when wirefilter is unavailable."""
        from octorules.linter import expression_bridge

        monkeypatch.setattr(expression_bridge, "WIREFILTER_AVAILABLE", False)
        ctx = _lint('http.hoost eq "x"')
        assert "A001" not in _ids(ctx)

    def test_a001_semantic_checks_still_fire(self):
        """E001 fires alongside A001 for unknown function in invalid expression."""
        ctx = _lint('bogus_fn(http.host) eq "x"')
        assert "A001" in _ids(ctx)
        assert "E001" in _ids(ctx)

    def test_a001_suppressed_for_true_literal(self):
        """'true' is valid Cloudflare syntax; wirefilter rejects it but M013 covers it."""
        ctx = _lint("true")
        assert "A001" not in _ids(ctx)
        assert "M013" not in _ids(ctx)  # M013 fires in yaml_validator, not ast_linter

    def test_a001_suppressed_for_false_literal(self):
        ctx = _lint("false")
        assert "A001" not in _ids(ctx)

    def test_a001_suppressed_for_parenthesized_true(self):
        ctx = _lint("(true)")
        assert "A001" not in _ids(ctx)

    def test_a001_suppressed_for_starts_with_function_call(self):
        """starts_with() function-call syntax is valid Cloudflare, wirefilter rejects it."""
        ctx = _lint('starts_with(http.request.uri.path, "/api")')
        assert "A001" not in _ids(ctx)

    def test_a001_suppressed_for_ends_with_function_call(self):
        ctx = _lint('ends_with(http.request.uri.path, "/")')
        assert "A001" not in _ids(ctx)

    def test_a001_suppressed_for_mixed_contains_and_starts_with(self):
        """Transform-phase expression mixing contains operator and starts_with() call."""
        ctx = _lint(
            '(http.host eq "dev.example.com" and '
            'not http.request.uri.path contains "." and '
            'not starts_with(http.request.uri.path, "/api"))',
            "url_rewrite_rules",
        )
        assert "A001" not in _ids(ctx)


class TestF002UnknownField:
    def test_f002_unknown_field_with_suggestion(self):
        """Typo in field name triggers F002 with 'Did you mean?' suggestion."""
        ctx = _lint('http.hoost eq "x"')
        assert "F002" in _ids(ctx)
        f002 = [r for r in ctx.results if r.rule_id == "F002"]
        assert len(f002) == 1
        assert "http.hoost" in f002[0].message
        assert f002[0].suggestion
        assert "http.host" in f002[0].suggestion

    def test_f002_known_field_ok(self):
        """Known field does not trigger F002."""
        ctx = _lint('http.host eq "example.com"')
        assert "F002" not in _ids(ctx)

    def test_f002_deprecated_field_not_flagged(self):
        """Deprecated fields are in FIELDS, so G010 fires, not F002."""
        ctx = _lint('ip.geoip.country eq "DE"')
        assert "F002" not in _ids(ctx)
        assert "G010" in _ids(ctx)

    def test_f002_bogus_field_no_suggestion(self):
        """Very wrong name gets F002 with no suggestion."""
        ctx = _lint('cf.zzzzzzz eq "x"')
        assert "F002" in _ids(ctx)
        f002 = [r for r in ctx.results if r.rule_id == "F002"]
        assert f002[0].suggestion == ""

    def test_f002_close_typo_has_suggestion(self):
        """Near-miss field name gets a suggestion."""
        ctx = _lint("ip.scr eq 1.2.3.4")
        assert "F002" in _ids(ctx)
        f002 = [r for r in ctx.results if r.rule_id == "F002"]
        assert "ip.src" in (f002[0].suggestion or "")

    def test_f002_jwt_exp_field_known(self):
        """JWT exp claim fields should be recognized (not trigger F002)."""
        from octorules.linter.schemas.fields import get_field

        assert get_field("http.request.jwt.claims.exp.sec") is not None
        assert get_field("http.request.jwt.claims.exp.sec.names") is not None
        assert get_field("http.request.jwt.claims.exp.sec.values") is not None


class TestF001ArrayMapFields:
    def test_f001_array_string_eq(self):
        """Scalar 'eq' on array field should fire F001."""
        ctx = _lint('http.request.headers.names eq "x-custom"')
        assert "F001" in _ids(ctx)
        f001 = [r for r in ctx.results if r.rule_id == "F001"]
        assert "array" in f001[0].message.lower()

    def test_f001_array_int_gt(self):
        """Scalar 'gt' on array<int> field should fire F001."""
        ctx = _lint("cf.bot_management.detection_ids gt 5")
        assert "F001" in _ids(ctx)

    def test_f001_map_field_contains(self):
        """Scalar 'contains' on map field should fire F001."""
        ctx = _lint('http.request.headers contains "x"')
        assert "F001" in _ids(ctx)
        f001 = [r for r in ctx.results if r.rule_id == "F001"]
        assert "map" in f001[0].message.lower()

    def test_f001_array_field_any_ok(self):
        """Using any() with array field should not fire F001 for any()."""
        ctx = _lint('any(http.request.headers.names[*] eq "x-custom")')
        assert "F001" not in _ids(ctx)

    def test_f001_map_field_has_key_ok(self):
        """Using has_key/indexing should not fire F001."""
        # Expression like http.request.cookies["session"] is valid
        # Our regex-based F001 checks for direct "field op" pattern
        ctx = _lint('http.request.uri.args["key"][0] eq "value"')
        assert "F001" not in _ids(ctx)


class TestG005ScoreRanges:
    """Tests for G005 score range corrections (cf.waf.score, cf.llm.prompt.injection_score)."""

    def test_g005_waf_score_100_out_of_range(self):
        """cf.waf.score range is 1-99 per CF docs, so 100 should fire."""
        ctx = _lint("cf.waf.score eq 100")
        assert "G005" in _ids(ctx)

    def test_g005_waf_score_99_ok(self):
        """cf.waf.score 99 is at the boundary, should not fire."""
        ctx = _lint("cf.waf.score lt 99")
        assert "G005" not in _ids(ctx)

    def test_g005_llm_injection_score_100_out_of_range(self):
        """cf.llm.prompt.injection_score range is 1-99 per CF docs."""
        ctx = _lint("cf.llm.prompt.injection_score eq 100")
        assert "G005" in _ids(ctx)

    def test_g005_llm_injection_score_50_ok(self):
        ctx = _lint("cf.llm.prompt.injection_score gt 50")
        assert "G005" not in _ids(ctx)


class TestG013TlsVersion:
    """Tests for G013 cf.tls_version value domain."""

    def test_g013_tls_version_invalid(self):
        ctx = _lint('cf.tls_version eq "SSLv3"')
        assert "G013" in _ids(ctx)

    def test_g013_tls_version_valid_12(self):
        ctx = _lint('cf.tls_version eq "TLSv1.2"')
        assert "G013" not in _ids(ctx)

    def test_g013_tls_version_valid_13(self):
        ctx = _lint('cf.tls_version eq "TLSv1.3"')
        assert "G013" not in _ids(ctx)

    def test_g013_tls_version_valid_none(self):
        ctx = _lint('cf.tls_version eq "none"')
        assert "G013" not in _ids(ctx)

    def test_g013_tls_version_in_set(self):
        ctx = _lint('cf.tls_version in {"TLSv1.2" "TLSv1.3"}')
        assert "G013" not in _ids(ctx)


class TestG013HttpHost:
    """Tests for G013 http.host must not contain /."""

    def test_g013_host_with_slash(self):
        ctx = _lint('http.host eq "example.com/path"')
        assert "G013" in _ids(ctx)
        g013 = [r for r in ctx.results if r.rule_id == "G013"]
        assert "cannot contain '/'" in g013[0].message

    def test_g013_host_valid(self):
        ctx = _lint('http.host eq "example.com"')
        assert "G013" not in _ids(ctx)

    def test_g013_host_with_port_valid(self):
        ctx = _lint('http.host eq "example.com:8080"')
        assert "G013" not in _ids(ctx)


class TestG013HttpMethod:
    """Tests for G013 http.request.method valid method set."""

    def test_g013_method_invalid(self):
        ctx = _lint('http.request.method eq "GETT"')
        assert "G013" in _ids(ctx)

    def test_g013_method_get_valid(self):
        ctx = _lint('http.request.method eq "GET"')
        assert "G013" not in _ids(ctx)

    def test_g013_method_purge_valid(self):
        ctx = _lint('http.request.method eq "PURGE"')
        assert "G013" not in _ids(ctx)

    def test_g013_method_patch_valid(self):
        ctx = _lint('http.request.method eq "PATCH"')
        assert "G013" not in _ids(ctx)


class TestG013HttpVersion:
    """Tests for G013 http.request.version exact values."""

    def test_g013_version_invalid(self):
        ctx = _lint('http.request.version eq "HTTP/0.9"')
        assert "G013" in _ids(ctx)

    def test_g013_version_http11_valid(self):
        ctx = _lint('http.request.version eq "HTTP/1.1"')
        assert "G013" not in _ids(ctx)

    def test_g013_version_http2_valid(self):
        ctx = _lint('http.request.version eq "HTTP/2"')
        assert "G013" not in _ids(ctx)

    def test_g013_version_http3_valid(self):
        ctx = _lint('http.request.version eq "HTTP/3"')
        assert "G013" not in _ids(ctx)


class TestG023RegexValidation:
    """Tests for G023 — invalid regex pattern in matches operator."""

    def test_g023_invalid_regex_unbalanced_parens(self):
        ctx = _lint('http.host matches "(unclosed"')
        g023 = [r for r in ctx.results if r.rule_id == "G023"]
        assert len(g023) > 0
        assert "unterminated subpattern" in g023[0].message

    def test_g023_invalid_regex_bad_quantifier(self):
        ctx = _lint('http.host matches "*invalid"')
        g023 = [r for r in ctx.results if r.rule_id == "G023"]
        assert len(g023) > 0
        assert "Invalid regex" in g023[0].message

    def test_g023_valid_regex_ok(self):
        ctx = _lint('http.host matches ".*example\\.com$"')
        assert "G023" not in _ids(ctx)

    def test_g023_invalid_regex_bad_char_class(self):
        ctx = _lint('http.host matches "[z-a]"')
        g023 = [r for r in ctx.results if r.rule_id == "G023"]
        assert len(g023) > 0


class TestG024SubstringBounds:
    """Tests for G024 — substring() bounds validation."""

    def test_g024_negative_start_allowed(self):
        """CF substring() supports negative indices — no G024."""
        ctx = _lint('substring(http.request.uri.path, -1, 5) eq "/api"')
        assert "G024" not in _ids(ctx)

    def test_g024_end_less_than_start(self):
        ctx = _lint('substring(http.request.uri.path, 10, 5) eq "/api"')
        assert "G024" in _ids(ctx)
        g024 = [r for r in ctx.results if r.rule_id == "G024"]
        assert "less than start" in g024[0].message

    def test_g024_valid_bounds(self):
        ctx = _lint('substring(http.request.uri.path, 0, 4) eq "/api"')
        assert "G024" not in _ids(ctx)

    def test_g024_valid_no_end(self):
        ctx = _lint('substring(http.request.uri.path, 5) eq "test"')
        assert "G024" not in _ids(ctx)


class TestG025LookupJsonPath:
    """Tests for G025 — lookup_json_* path validation."""

    def test_g025_invalid_path_no_slash(self):
        ctx = _lint('lookup_json_string(http.request.body.raw, "name") eq "test"')
        assert "G025" in _ids(ctx)
        g025 = [r for r in ctx.results if r.rule_id == "G025"]
        assert "should start with '/'" in g025[0].message

    def test_g025_valid_path(self):
        ctx = _lint('lookup_json_string(http.request.body.raw, "/name") eq "test"')
        assert "G025" not in _ids(ctx)

    def test_g025_lookup_json_integer_invalid(self):
        ctx = _lint('lookup_json_integer(http.request.body.raw, "count") gt 5')
        assert "G025" in _ids(ctx)

    def test_g025_lookup_json_integer_valid(self):
        ctx = _lint('lookup_json_integer(http.request.body.raw, "/count") gt 5')
        assert "G025" not in _ids(ctx)

    def test_g025_nested_path(self):
        ctx = _lint('lookup_json_string(http.request.body.raw, "/data/name") eq "test"')
        assert "G025" not in _ids(ctx)


class TestG026BitSlice:
    """Tests for G026 — bit_slice offset/size validation."""

    def test_g026_valid_bit_slice(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 16) eq 1234", "network_firewall_rules")
        assert "G026" not in _ids(ctx)

    def test_g026_offset_too_large(self):
        ctx = _lint(
            "bit_slice(raw.http.request.body.raw, 2048, 16) eq 1234", "network_firewall_rules"
        )
        assert "G026" in _ids(ctx)
        g026 = [r for r in ctx.results if r.rule_id == "G026"]
        assert "offset" in g026[0].message

    def test_g026_size_too_large(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 64) eq 1234", "network_firewall_rules")
        assert "G026" in _ids(ctx)
        g026 = [r for r in ctx.results if r.rule_id == "G026"]
        assert "size" in g026[0].message

    def test_g026_size_zero(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 0) eq 1234", "network_firewall_rules")
        assert "G026" in _ids(ctx)

    def test_g026_max_valid_offset_and_size(self):
        ctx = _lint(
            "bit_slice(raw.http.request.body.raw, 2040, 32) eq 1234", "network_firewall_rules"
        )
        assert "G026" not in _ids(ctx)


class TestE007FunctionSourceMustBeField:
    """Tests for E007 — function source argument must be a field reference."""

    def test_e007_decode_base64_with_literal(self):
        ctx = _lint('decode_base64("dGVzdA==") eq "test"')
        assert "E007" in _ids(ctx)

    def test_e007_decode_base64_with_field(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"')
        assert "E007" not in _ids(ctx)

    def test_e007_url_decode_with_literal(self):
        ctx = _lint('url_decode("hello%20world") eq "hello world"')
        assert "E007" in _ids(ctx)

    def test_e007_url_decode_with_field(self):
        ctx = _lint('url_decode(http.request.uri.path) eq "/test"')
        assert "E007" not in _ids(ctx)

    def test_e007_starts_with_with_literal(self):
        ctx = _lint('starts_with("hello", "he")')
        assert "E007" in _ids(ctx)

    def test_e007_starts_with_with_field(self):
        ctx = _lint('starts_with(http.request.uri.path, "/api")')
        assert "E007" not in _ids(ctx)

    def test_e007_ends_with_with_literal(self):
        ctx = _lint('ends_with("hello", "lo")')
        assert "E007" in _ids(ctx)

    def test_e007_ends_with_with_field(self):
        ctx = _lint('ends_with(http.request.uri.path, ".js")')
        assert "E007" not in _ids(ctx)


class TestF003ArrayStarUnpacking:
    """Tests for F003 — array [*] used on multiple distinct arrays."""

    def test_f003_single_array_star_ok(self):
        ctx = _lint('any(http.request.headers.names[*] eq "x-api-key")')
        assert "F003" not in _ids(ctx)

    def test_f003_same_array_star_ok(self):
        ctx = _lint(
            'any(http.request.headers.names[*] eq "x-api-key")'
            ' and any(http.request.headers.names[*] eq "authorization")'
        )
        assert "F003" not in _ids(ctx)

    def test_f003_different_arrays_flagged(self):
        ctx = _lint(
            'any(http.request.headers.names[*] eq "x-api-key")'
            ' and any(http.request.headers.values[*] eq "secret")'
        )
        assert "F003" in _ids(ctx)

    def test_f003_no_star_no_flag(self):
        ctx = _lint('http.request.headers.names[0] eq "content-type"')
        assert "F003" not in _ids(ctx)


class TestFunctionPhaseRestrictions:
    """Tests for function phase restrictions added in coverage audit."""

    def test_e002_split_in_wrong_phase(self):
        ctx = _lint('split(http.cookie, ";", 10)[0] eq "session"', "waf_custom_rules")
        assert "E002" in _ids(ctx)

    def test_e002_split_in_correct_phase(self):
        ctx = _lint('split(http.cookie, ";", 10)[0] eq "session"', "response_header_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_split_in_custom_error_phase(self):
        ctx = _lint('split(http.cookie, ";", 10)[0] eq "session"', "custom_error_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_join_in_wrong_phase(self):
        ctx = _lint('join(http.request.headers.names, ",") eq "a,b"', "redirect_rules")
        assert "E002" in _ids(ctx)

    def test_e002_join_in_correct_phase(self):
        ctx = _lint('join(http.request.headers.names, ",") eq "a,b"', "url_rewrite_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_cidr_in_wrong_phase(self):
        ctx = _lint("cidr(ip.src, 24, 0) in {192.168.0.0/24}", "redirect_rules")
        assert "E002" in _ids(ctx)

    def test_e002_cidr_in_correct_phase(self):
        ctx = _lint("cidr(ip.src, 24, 0) in {192.168.0.0/24}", "waf_custom_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_cidr_in_rate_limiting(self):
        ctx = _lint("cidr(ip.src, 24, 0) in {192.168.0.0/24}", "rate_limiting_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_bit_slice_in_wrong_phase(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 16) eq 1234", "waf_custom_rules")
        assert "E002" in _ids(ctx)

    def test_e002_bit_slice_in_correct_phase(self):
        ctx = _lint("bit_slice(raw.http.request.body.raw, 0, 16) eq 1234", "network_firewall_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_decode_base64_in_wrong_phase(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "redirect_rules")
        assert "E002" in _ids(ctx)

    def test_e002_decode_base64_in_transform_phase(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "request_header_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_decode_base64_in_waf_phase(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "waf_custom_rules")
        assert "E002" not in _ids(ctx)

    def test_e002_decode_base64_in_rate_limiting(self):
        ctx = _lint('decode_base64(http.cookie) eq "test"', "rate_limiting_rules")
        assert "E002" not in _ids(ctx)


class TestFunctionPlanRestrictions:
    """Tests for B003 — function plan requirement checks."""

    def test_b003_sha256_requires_enterprise(self):
        ctx = _lint(
            'sha256(http.request.body.raw) eq "abc"',
            "request_header_rules",
        )
        # Default plan_tier is 'enterprise', so should not fire
        assert "B003" not in [r.rule_id for r in ctx.results if "sha256" in r.message]

    def test_b003_sha256_on_free_plan(self):
        rule = {"ref": "test", "expression": 'sha256(http.request.body.raw) eq "abc"'}
        phase = PHASE_BY_NAME["request_header_rules"]
        ctx = LintContext(plan_tier="free")
        lint_expressions(rule, phase, ctx)
        b003 = [r for r in ctx.results if r.rule_id == "B003" and "sha256" in r.message]
        assert len(b003) == 1
        assert "enterprise" in b003[0].message

    def test_b003_is_timed_hmac_requires_pro(self):
        expr = 'is_timed_hmac_valid_v0(http.request.uri.path, "secret", 300, 0)'
        rule = {"ref": "test", "expression": expr}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="free")
        lint_expressions(rule, phase, ctx)
        b003 = [
            r for r in ctx.results if r.rule_id == "B003" and "is_timed_hmac_valid_v0" in r.message
        ]
        assert len(b003) == 1
        assert "pro" in b003[0].message

    def test_b003_is_timed_hmac_on_pro_ok(self):
        expr = 'is_timed_hmac_valid_v0(http.request.uri.path, "secret", 300, 0)'
        rule = {"ref": "test", "expression": expr}
        phase = PHASE_BY_NAME["waf_custom_rules"]
        ctx = LintContext(plan_tier="pro")
        lint_expressions(rule, phase, ctx)
        b003 = [
            r for r in ctx.results if r.rule_id == "B003" and "is_timed_hmac_valid_v0" in r.message
        ]
        assert len(b003) == 0


class TestA002DepthExceeded:
    def test_a002_fires_when_depth_exceeded(self, monkeypatch):
        from octorules.linter import ast_linter
        from octorules.linter.expression_bridge import ExpressionInfo

        fake_info = ExpressionInfo(raw="deeply nested", depth_exceeded=True)
        monkeypatch.setattr(ast_linter, "parse_expression", lambda expr: fake_info)
        ctx = _lint("deeply nested")
        assert "A002" in _ids(ctx)

    def test_a002_not_fired_normal_expression(self, monkeypatch):
        from octorules.linter import ast_linter
        from octorules.linter.expression_bridge import ExpressionInfo

        fake_info = ExpressionInfo(raw="simple", depth_exceeded=False)
        monkeypatch.setattr(ast_linter, "parse_expression", lambda expr: fake_info)
        ctx = _lint("simple")
        assert "A002" not in _ids(ctx)
