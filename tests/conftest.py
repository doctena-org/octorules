"""Shared fixtures for octorules tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from octorules.expression import normalize_expression
from octorules.phases import (
    PHASES,
    Phase,
    register_api_fields,
    register_non_phase_key,
    register_phase_alias,
    register_phases,
    unregister_api_fields,
    unregister_non_phase_key,
    unregister_phase_alias,
)


def _test_prepare_rule(rule: dict, phase: Phase) -> dict:
    """Cloudflare-like rule preparation for core tests.

    Mirrors what ``octorules_cloudflare._cf_prepare_rule`` does so core tests
    can exercise phase-dependent logic without requiring octorules-cloudflare.
    """
    rule["expression"] = normalize_expression(rule["expression"])
    ap = rule.get("action_parameters")
    if isinstance(ap, dict) and isinstance(ap.get("counting_expression"), str):
        ap = ap.copy()
        ap["counting_expression"] = normalize_expression(ap["counting_expression"])
        rule["action_parameters"] = ap
    if "enabled" not in rule:
        rule["enabled"] = True
    if "action" not in rule:
        if phase.default_action is None:
            raise ValueError(
                f"Rule {rule.get('ref', '?')!r} in phase {phase.friendly_name!r} "
                f"must specify an 'action' (no default for this phase)"
            )
        rule["action"] = phase.default_action
    return rule


# ---------------------------------------------------------------------------
# Test phase definitions — mirrors the 23 Cloudflare phases so core tests
# can exercise phase-dependent logic without requiring octorules-cloudflare.
# ---------------------------------------------------------------------------

# Phase specs: (friendly_name, provider_id, default_action, zone_level, account_level)
_TEST_PHASE_SPECS: list[tuple] = [
    ("redirect_rules", "http_request_dynamic_redirect", "redirect", True, False),
    ("url_rewrite_rules", "http_request_transform", "rewrite", True, False),
    ("request_header_rules", "http_request_late_transform", "rewrite", True, False),
    ("response_header_rules", "http_response_headers_transform", "rewrite", True, False),
    ("config_rules", "http_config_settings", "set_config", True, False),
    ("origin_rules", "http_request_origin", "route", True, False),
    ("cache_rules", "http_request_cache_settings", "set_cache_settings", True, False),
    ("compression_rules", "http_response_compression", "compress_response", True, False),
    ("custom_error_rules", "http_custom_errors", "serve_error", True, True),
    ("waf_custom_rules", "http_request_firewall_custom", None, True, True),
    ("waf_managed_rules", "http_request_firewall_managed", None, True, True),
    ("rate_limiting_rules", "http_ratelimit", None, True, True),
    ("bot_fight_rules", "http_request_sbfm", None, True, False),
    ("sensitive_data_detection", "http_response_firewall_managed", None, True, False),
    ("http_ddos_rules", "ddos_l7", None, True, True),
    ("bulk_redirect_rules", "http_request_redirect", "redirect", False, True),
    ("log_custom_fields", "http_log_custom_fields", "log_custom_field", True, False),
    ("network_ddos_rules", "ddos_l4", None, False, True),
    ("network_firewall_rules", "magic_transit", None, False, True),
    ("network_firewall_managed", "magic_transit_managed", None, False, True),
    ("network_firewall_ratelimit", "magic_transit_ratelimit", None, False, True),
    ("network_firewall_ids", "magic_transit_ids_managed", None, False, True),
    ("url_normalization", "http_request_sanitize", None, True, False),
]

_TEST_PHASES: list[Phase] = [
    Phase(name, pid, action, zone_level=zl, account_level=al, prepare_rule=_test_prepare_rule)
    for name, pid, action, zl, al in _TEST_PHASE_SPECS
]

# Non-phase keys that core tests depend on (normally registered by providers).
_TEST_NON_PHASE_KEYS = ("custom_rulesets", "lists", "page_shield_policies")

# API fields that core tests depend on (normally registered by providers).
_TEST_API_FIELDS: dict[str, set[str]] = {
    "rule": {"id", "version", "last_updated", "categories", "logging"},
    "list_item": {"id", "created_on", "modified_on"},
    "page_shield_policy": {"id", "last_updated"},
}

_TEST_PHASES_REGISTERED = False


def _do_register() -> None:
    """Register test phases, aliases, non-phase keys, and API fields."""
    global _TEST_PHASES_REGISTERED
    if _TEST_PHASES_REGISTERED:
        return
    register_phases(_TEST_PHASES)
    register_phase_alias("waf_managed_exceptions", "waf_managed_rules")
    for key in _TEST_NON_PHASE_KEYS:
        register_non_phase_key(key)
    for category, fields in _TEST_API_FIELDS.items():
        register_api_fields(category, fields)
    _TEST_PHASES_REGISTERED = True


@pytest.fixture(autouse=True, scope="session")
def _register_test_phases():
    """Register test phases once at session start, before module-level get_phase() calls."""
    _do_register()
    yield
    # Teardown: restore empty core state
    global _TEST_PHASES_REGISTERED
    PHASES.clear()
    from octorules.phases import _rebuild_derived

    unregister_phase_alias("waf_managed_exceptions")
    for key in _TEST_NON_PHASE_KEYS:
        unregister_non_phase_key(key)
    for category in _TEST_API_FIELDS:
        unregister_api_fields(category)
    _rebuild_derived()
    _TEST_PHASES_REGISTERED = False


# Eagerly register so module-level get_phase() calls in test files work.
_do_register()


@pytest.fixture
def tmp_config(tmp_path: Path):
    """Create a minimal config file and rules dir, return config path."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "providers:\n"
        "  cloudflare:\n"
        "    token: test-token-123\n"
        "  rules:\n"
        "    directory: ./rules\n"
        "zones:\n"
        "  example.com:\n"
        "    sources:\n"
        "      - rules\n"
    )
    return config_file
