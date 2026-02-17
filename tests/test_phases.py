"""Tests for the phase registry."""

from __future__ import annotations

import pytest

from octorules.phases import (
    ALL_CF_PHASES,
    ALL_FRIENDLY_NAMES,
    PHASES,
    get_phase,
    get_phase_by_cf,
    suggest_phase,
    unknown_phase_message,
)


class TestPhaseRegistry:
    def test_eleven_phases(self):
        assert len(PHASES) == 11

    def test_all_friendly_names_unique(self):
        assert len(ALL_FRIENDLY_NAMES) == len(set(ALL_FRIENDLY_NAMES))

    def test_all_cf_phases_unique(self):
        assert len(ALL_CF_PHASES) == len(set(ALL_CF_PHASES))

    def test_get_phase_redirect(self):
        phase = get_phase("redirect_rules")
        assert phase.cf_phase == "http_request_dynamic_redirect"
        assert phase.default_action == "redirect"

    def test_get_phase_cache(self):
        phase = get_phase("cache_rules")
        assert phase.cf_phase == "http_request_cache_settings"
        assert phase.default_action == "set_cache_settings"

    def test_waf_no_default_action(self):
        phase = get_phase("waf_custom_rules")
        assert phase.default_action is None

    def test_rate_limiting_no_default_action(self):
        phase = get_phase("rate_limiting_rules")
        assert phase.default_action is None

    def test_unknown_phase_raises(self):
        with pytest.raises(KeyError, match="Unknown phase"):
            get_phase("nonexistent_rules")

    def test_unknown_phase_with_suggestion(self):
        with pytest.raises(KeyError, match="Did you mean 'redirect_rules'"):
            get_phase("redirect_rule")

    def test_unknown_phase_no_suggestion_lists_valid(self):
        with pytest.raises(KeyError, match="Valid phases:"):
            get_phase("zzz_totally_wrong")

    def test_get_phase_by_cf(self):
        phase = get_phase_by_cf("http_request_dynamic_redirect")
        assert phase.friendly_name == "redirect_rules"

    def test_get_phase_by_cf_unknown(self):
        with pytest.raises(KeyError, match="Unknown CF phase"):
            get_phase_by_cf("http_nonexistent")

    @pytest.mark.parametrize(
        "name,cf_phase",
        [
            ("redirect_rules", "http_request_dynamic_redirect"),
            ("url_rewrite_rules", "http_request_transform"),
            ("request_header_rules", "http_request_late_transform"),
            ("response_header_rules", "http_response_headers_transform"),
            ("config_rules", "http_config_settings"),
            ("origin_rules", "http_request_origin"),
            ("cache_rules", "http_request_cache_settings"),
            ("compression_rules", "http_response_compression"),
            ("custom_error_rules", "http_custom_errors"),
            ("waf_custom_rules", "http_request_firewall_custom"),
            ("rate_limiting_rules", "http_ratelimit"),
        ],
    )
    def test_phase_mapping(self, name, cf_phase):
        phase = get_phase(name)
        assert phase.cf_phase == cf_phase


class TestSuggestPhase:
    def test_close_typo(self):
        assert suggest_phase("redirect_rule") == "redirect_rules"

    def test_missing_suffix(self):
        assert suggest_phase("cache_rule") == "cache_rules"

    def test_swapped_word(self):
        assert suggest_phase("origin_rule") == "origin_rules"

    def test_no_match(self):
        assert suggest_phase("zzz_totally_wrong") is None

    def test_exact_match(self):
        assert suggest_phase("redirect_rules") == "redirect_rules"

    def test_partial_prefix(self):
        # "waf_custom" is close enough to "waf_custom_rules"
        assert suggest_phase("waf_custom") == "waf_custom_rules"

    def test_cf_phase_suggests_friendly_name(self):
        assert suggest_phase("http_request_dynamic_redirect") == "redirect_rules"

    def test_cf_phase_cache_suggests_friendly(self):
        assert suggest_phase("http_request_cache_settings") == "cache_rules"


class TestUnknownPhaseMessage:
    def test_with_suggestion(self):
        msg = unknown_phase_message("redirect_rule")
        assert "Did you mean 'redirect_rules'?" in msg

    def test_without_suggestion(self):
        msg = unknown_phase_message("zzz_totally_wrong")
        assert "Valid phases:" in msg
        assert "redirect_rules" in msg

    def test_cf_phase_suggests_friendly(self):
        msg = unknown_phase_message("http_request_dynamic_redirect")
        assert "Did you mean 'redirect_rules'?" in msg
