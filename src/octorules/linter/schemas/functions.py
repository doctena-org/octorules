"""Function registry — Cloudflare wirefilter function signatures.

Defines all known functions, their argument types, return types,
and phase restrictions.

Source: https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FunctionDef:
    """Definition of a Cloudflare wirefilter function."""

    name: str
    # Phases where this function is available (empty = all phases)
    restricted_phases: frozenset[str] = frozenset()
    # Whether this function requires a specific plan tier
    requires_plan: str = ""


FUNCTIONS: dict[str, FunctionDef] = {}


def _fn(name: str, **kwargs: object) -> FunctionDef:
    fd = FunctionDef(name=name, **kwargs)  # type: ignore[arg-type]
    FUNCTIONS[name] = fd
    return fd


# Phase sets for function restrictions
_TRANSFORM_PHASES = frozenset(
    {
        "url_rewrite_rules",
        "request_header_rules",
        "response_header_rules",
    }
)
_TRANSFORM_AND_REDIRECT_PHASES = frozenset(
    {
        "url_rewrite_rules",
        "request_header_rules",
        "response_header_rules",
        "redirect_rules",
    }
)
_TRANSFORM_AND_WAF_AND_ERROR_PHASES = frozenset(
    {
        "url_rewrite_rules",
        "request_header_rules",
        "response_header_rules",
        "waf_custom_rules",
        "custom_error_rules",
    }
)
_RESPONSE_TRANSFORM_AND_ERROR_PHASES = frozenset(
    {
        "response_header_rules",
        "custom_error_rules",
    }
)
_WAF_AND_RATELIMIT_PHASES = frozenset(
    {
        "waf_custom_rules",
        "rate_limiting_rules",
    }
)
_TRANSFORM_AND_WAF_AND_RATELIMIT_PHASES = frozenset(
    {
        "url_rewrite_rules",
        "request_header_rules",
        "response_header_rules",
        "waf_custom_rules",
        "rate_limiting_rules",
    }
)
_NETWORK_PHASES = frozenset(
    {
        "network_firewall_rules",
        "network_ddos_rules",
        "network_firewall_managed",
        "network_firewall_ratelimit",
        "network_firewall_ids",
    }
)

# --- BEGIN GENERATED FUNCTIONS --- #
_fn("any")
_fn("all")
_fn("concat")
_fn("lower")
_fn("upper")
_fn("url_decode")
_fn("uuidv4", restricted_phases=_TRANSFORM_PHASES)
_fn("starts_with")
_fn("ends_with")
_fn("contains")
_fn("len")
_fn("substring")
_fn("regex_replace", restricted_phases=_TRANSFORM_AND_REDIRECT_PHASES)
_fn("remove_bytes")
_fn("to_string", restricted_phases=_TRANSFORM_AND_REDIRECT_PHASES)
_fn("lookup_json_string")
_fn("lookup_json_integer")
_fn("sha256", restricted_phases=_TRANSFORM_PHASES, requires_plan="enterprise")
_fn("sha512")
_fn("hmac")
_fn("is_timed_hmac_valid_v0", requires_plan="pro")
_fn("ip_in_range")
_fn("wildcard")
_fn("encode_base64", restricted_phases=_TRANSFORM_PHASES)
_fn("decode_base64", restricted_phases=_TRANSFORM_AND_WAF_AND_RATELIMIT_PHASES)
_fn("cidr", restricted_phases=_WAF_AND_RATELIMIT_PHASES)
_fn("cidr6", restricted_phases=_WAF_AND_RATELIMIT_PHASES)
_fn("join", restricted_phases=_TRANSFORM_AND_WAF_AND_ERROR_PHASES)
_fn("split", restricted_phases=_RESPONSE_TRANSFORM_AND_ERROR_PHASES)
_fn("has_key")
_fn("has_value")
_fn("remove_query_args", restricted_phases=_TRANSFORM_PHASES)
_fn("bit_slice", restricted_phases=_NETWORK_PHASES)
_fn("wildcard_replace", restricted_phases=_TRANSFORM_AND_REDIRECT_PHASES)
# --- END GENERATED FUNCTIONS --- #

# --- Functions NOT in the CF docs reference page --- #
# These are registered in the wirefilter engine and accepted by the API, but not
# listed on https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
# DO NOT remove them — each is needed to prevent false-positive E001 "unknown
# function" warnings on valid expressions.

# contains — wirefilter registers this as a function for use inside any()/all()
# wrappers (e.g. `any(http.request.headers.values[*] contains "token")`).
# CF docs lists it as an operator, but wirefilter reports it as a function.
# (Already registered above in the generated block.)

# sha512 — registered in the wirefilter engine, accepted by the API. Not on the
# public CF docs page but functionally equivalent to sha256 with longer output.
# (Already registered above in the generated block.)

# hmac — registered in wirefilter for raw HMAC computation. The documented
# is_timed_hmac_valid_v0 wraps this internally. Accepted by the API.
# (Already registered above in the generated block.)

# ip_in_range — internal wirefilter function for IP range matching. Used
# implicitly by the `in` operator with CIDR notation. Accepted by the API.
# (Already registered above in the generated block.)

# wildcard — wirefilter registers the `wildcard` operator also as a function
# for use inside any()/all() wrappers. Accepted by the API.
# (Already registered above in the generated block.)

# http.request.uri.path — in transform phases, Cloudflare treats this field
# name as a callable function (Bytes → Bytes). Registered here so E001 doesn't
# fire on valid transform-phase expressions.
_fn("http.request.uri.path", restricted_phases=_TRANSFORM_PHASES)

# cf.bot_management.score — Cloudflare's expression engine also exposes this
# as a function in certain contexts. Enterprise-only.
_fn("cf.bot_management.score", requires_plan="enterprise")


def get_function(name: str) -> FunctionDef | None:
    """Look up a function definition by name."""
    return FUNCTIONS.get(name)
