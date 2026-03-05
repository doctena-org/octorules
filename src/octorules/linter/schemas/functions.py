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

# String functions
_fn("lower")
_fn("upper")
_fn("concat")
_fn("to_string", restricted_phases=_TRANSFORM_AND_REDIRECT_PHASES)
_fn("len")
_fn("ends_with")
_fn("starts_with")
_fn("contains")
_fn("substring")
_fn("regex_replace", restricted_phases=_TRANSFORM_AND_REDIRECT_PHASES)
_fn("remove_bytes")
_fn("url_decode")
_fn("uuidv4", restricted_phases=_TRANSFORM_PHASES)
_fn("any")
_fn("all")
_fn("lookup_json_string")
_fn("lookup_json_integer")

# Hash functions
_fn("sha256", restricted_phases=_TRANSFORM_PHASES)
_fn("sha512")
_fn("hmac")

# Transform-specific functions (only in transform phases)
_fn("http.request.uri.path", restricted_phases=_TRANSFORM_PHASES)

# Threat/security functions
_fn("is_timed_hmac_valid_v0")

# Hostname / wildcard
_fn("wildcard")

# IP
_fn("ip_in_range")
_fn("cidr")
_fn("cidr6")

# Encoding
_fn("encode_base64", restricted_phases=_TRANSFORM_PHASES)
_fn("decode_base64")

# Array / Map
_fn("join")
_fn("split")
_fn("has_key")
_fn("has_value")

# String replacement / query manipulation
_fn("wildcard_replace", restricted_phases=_TRANSFORM_AND_REDIRECT_PHASES)
_fn("remove_query_args", restricted_phases=_TRANSFORM_PHASES)

# Network firewall
_fn("bit_slice")

# Bot management
_fn("cf.bot_management.score", requires_plan="enterprise")


def get_function(name: str) -> FunctionDef | None:
    """Look up a function definition by name."""
    return FUNCTIONS.get(name)
