"""Shared fixtures for octorules tests."""

from pathlib import Path

import pytest

from octorules.expression import normalize_expression
from octorules.phases import (
    PHASES,
    Phase,
    register_api_fields,
    register_namespace,
    register_non_phase_key,
    register_phase_alias,
    register_phases,
    unregister_api_fields,
    unregister_namespace,
    unregister_non_phase_key,
    unregister_phase_alias,
)


def _test_prepare_rule(rule: dict, phase: Phase) -> dict:
    """Cloudflare-like rule preparation for core tests.

    Mirrors what ``octorules_cloudflare._cf_prepare_rule`` does so core tests
    can exercise phase-dependent logic without requiring octorules-cloudflare.

    Deliberately does NOT mirror the CF hook's ``logging.enabled: true``
    default injection: that default is only symmetric because Cloudflare's
    API echoes the field back on GET. Core test fixtures' *current* rules
    don't do that, so injecting here would skew every desired-vs-current
    fixture in the suite.
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
# Test phase definitions.
#
# The first 23 phases use Cloudflare-style names and all set prepare_rule to
# exercise the full preparation pipeline.  The additional "bare_*" phases
# have NO prepare_rule (matching AWS/Google providers, which register phases
# without a prepare hook).  This ensures core handles both patterns:
#   - With prepare_rule: expression normalization, enabled defaulting, etc.
#   - Without prepare_rule (None): rules passed through unmodified.
# ---------------------------------------------------------------------------

# Phase specs: (friendly_name, provider_id, default_action, zone_level, account_level)
_TEST_PHASE_SPECS: list[tuple] = [
    ("fakeprov.redirect_rules", "fake_http_request_dynamic_redirect", "redirect", True, False),
    ("fakeprov.url_rewrite_rules", "fake_http_request_transform", "rewrite", True, False),
    ("fakeprov.request_header_rules", "fake_http_request_late_transform", "rewrite", True, False),
    (
        "fakeprov.response_header_rules",
        "fake_http_response_headers_transform",
        "rewrite",
        True,
        False,
    ),
    ("fakeprov.config_rules", "fake_http_config_settings", "set_config", True, False),
    ("fakeprov.origin_rules", "fake_http_request_origin", "route", True, False),
    ("fakeprov.cache_rules", "fake_http_request_cache_settings", "set_cache_settings", True, False),
    (
        "fakeprov.compression_rules",
        "fake_http_response_compression",
        "compress_response",
        True,
        False,
    ),
    ("fakeprov.custom_error_rules", "fake_http_custom_errors", "serve_error", True, True),
    ("fakeprov.waf_custom_rules", "fake_http_request_firewall_custom", None, True, True),
    ("fakeprov.waf_managed_rules", "fake_http_request_firewall_managed", None, True, True),
    ("fakeprov.rate_limiting_rules", "fake_http_ratelimit", None, True, True),
    ("fakeprov.bot_fight_rules", "fake_http_request_sbfm", None, True, False),
    ("fakeprov.sensitive_data_detection", "fake_http_response_firewall_managed", None, True, False),
    ("fakeprov.http_ddos_rules", "fake_ddos_l7", None, True, True),
    ("fakeprov.bulk_redirect_rules", "fake_http_request_redirect", "redirect", False, True),
    ("fakeprov.log_custom_fields", "fake_http_log_custom_fields", "log_custom_field", True, False),
    ("fakeprov.network_ddos_rules", "fake_ddos_l4", None, False, True),
    ("fakeprov.network_firewall_rules", "fake_magic_transit", None, False, True),
    ("fakeprov.network_firewall_managed", "fake_magic_transit_managed", None, False, True),
    ("fakeprov.network_firewall_ratelimit", "fake_magic_transit_ratelimit", None, False, True),
    ("fakeprov.network_firewall_ids", "fake_magic_transit_ids_managed", None, False, True),
    ("fakeprov.url_normalization", "fake_http_request_sanitize", None, True, False),
]

# Phases that mirror AWS/Google style — no prepare_rule, zone-level only.
_TEST_BARE_PHASE_SPECS: list[tuple] = [
    ("bareprov.custom_rules", "bare_custom", None, True, False),
    ("bareprov.rate_rules", "bare_rate", None, True, False),
    ("bareprov.managed_rules", "bare_managed", None, True, False),
]

_TEST_PHASES: list[Phase] = [
    Phase(
        name,
        pid,
        action,
        zone_level=zl,
        account_level=al,
        prepare_rule=_test_prepare_rule,
        rule_required_fields=("expression", "action"),
    )
    for name, pid, action, zl, al in _TEST_PHASE_SPECS
] + [
    Phase(name, pid, action, zone_level=zl, account_level=al)
    for name, pid, action, zl, al in _TEST_BARE_PHASE_SPECS
]

# Non-phase keys that core tests depend on (normally registered by providers).
_TEST_NON_PHASE_KEYS = ("custom_rulesets", "lists", "fakeprov.page_shield_policies")

# API fields that core tests depend on (normally registered by providers).
# Mirror the octorules-cloudflare set. ``logging`` is intentionally **not**
# here — it's user-controllable and Cloudflare's PUT default is ``true``,
# so stripping it round-trips quiet rules into firewall_event emitters.
_TEST_API_FIELDS: dict[str, set[str]] = {
    "rule": {"id", "version", "last_updated", "categories"},
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
    # Register the fakes' namespaces so core's tests exercise the nested
    # zone-file form without depending on a real provider being installed.
    register_namespace(
        "fakeprov",
        [n.split(".", 1)[1] for n, *_ in _TEST_PHASE_SPECS] + ["page_shield_policies"],
    )
    register_namespace("bareprov", [n.split(".", 1)[1] for n, *_ in _TEST_BARE_PHASE_SPECS])
    register_phase_alias("waf_managed_exceptions", "fakeprov.waf_managed_rules")
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
    from octorules.phases import _rebuild_derived

    PHASES.clear()
    unregister_namespace("fakeprov")
    unregister_namespace("bareprov")
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
