"""Phase registry — maps friendly YAML names to Cloudflare phase identifiers."""

from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches


@dataclass(frozen=True)
class Phase:
    friendly_name: str
    cf_phase: str
    default_action: str | None  # None means user must specify in YAML
    account_level: bool = False  # True for phases supported at account level


PHASES: list[Phase] = [
    Phase("redirect_rules", "http_request_dynamic_redirect", "redirect"),
    Phase("url_rewrite_rules", "http_request_transform", "rewrite"),
    Phase("request_header_rules", "http_request_late_transform", "rewrite"),
    Phase("response_header_rules", "http_response_headers_transform", "rewrite"),
    Phase("config_rules", "http_config_settings", "set_config"),
    Phase("origin_rules", "http_request_origin", "route"),
    Phase("cache_rules", "http_request_cache_settings", "set_cache_settings"),
    Phase("compression_rules", "http_response_compression", "compress_response"),
    Phase("custom_error_rules", "http_custom_errors", "serve_error", account_level=True),
    Phase("waf_custom_rules", "http_request_firewall_custom", None, account_level=True),
    Phase("waf_managed_exceptions", "http_request_firewall_managed", None, account_level=True),
    Phase("rate_limiting_rules", "http_ratelimit", None, account_level=True),
]

PHASE_BY_NAME: dict[str, Phase] = {p.friendly_name: p for p in PHASES}
PHASE_BY_CF: dict[str, Phase] = {p.cf_phase: p for p in PHASES}

ALL_FRIENDLY_NAMES: list[str] = [p.friendly_name for p in PHASES]
ALL_CF_PHASES: list[str] = [p.cf_phase for p in PHASES]
ACCOUNT_CF_PHASES: list[str] = [p.cf_phase for p in PHASES if p.account_level]

# Fields injected by the CF API that should be stripped when processing rules.
# Note: 'ref' is NOT included — it's user-defined and needed for identification.
CF_API_FIELDS: frozenset[str] = frozenset(
    {"id", "version", "last_updated", "categories", "logging"}
)


def suggest_phase(name: str) -> str | None:
    """Return the closest matching phase name, or None if nothing is close.

    Also detects when a CF API phase identifier is used and returns the friendly name.
    """
    if name in PHASE_BY_CF:
        return PHASE_BY_CF[name].friendly_name
    matches = get_close_matches(name, ALL_FRIENDLY_NAMES, n=1, cutoff=0.6)
    return matches[0] if matches else None


def unknown_phase_message(name: str) -> str:
    """Build a human-readable error message for an unknown phase name."""
    hint = suggest_phase(name)
    if hint:
        return f"Unknown phase {name!r}. Did you mean {hint!r}?"
    return f"Unknown phase {name!r}. Valid phases: {', '.join(ALL_FRIENDLY_NAMES)}"


def get_phase(friendly_name: str) -> Phase:
    """Look up a phase by friendly name. Raises KeyError if not found."""
    if friendly_name not in PHASE_BY_NAME:
        raise KeyError(unknown_phase_message(friendly_name))
    return PHASE_BY_NAME[friendly_name]


def get_phase_by_cf(cf_phase: str) -> Phase:
    """Look up a phase by Cloudflare phase identifier. Raises KeyError if not found."""
    if cf_phase not in PHASE_BY_CF:
        raise KeyError(f"Unknown CF phase {cf_phase!r}")
    return PHASE_BY_CF[cf_phase]
