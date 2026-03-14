"""Phase registry — maps friendly YAML names to Cloudflare phase identifiers.

The registry is extensible via ``register_phase()`` / ``register_phases()``.
Registration must happen early (before consumers cache derived data).
All derived collections (``ALL_CF_PHASES``, ``PHASE_BY_NAME``, etc.) are
mutated **in-place** so existing imports see updates.
"""

from __future__ import annotations

from dataclasses import dataclass
from difflib import get_close_matches


@dataclass(frozen=True)
class Phase:
    friendly_name: str
    cf_phase: str
    default_action: str | None  # None means user must specify in YAML
    zone_level: bool = True  # True for phases that work at zone level
    account_level: bool = False  # True for phases that work at account level


# ---------------------------------------------------------------------------
# Core phase definitions
# ---------------------------------------------------------------------------

_BUILTIN_PHASES: list[Phase] = [
    Phase("redirect_rules", "http_request_dynamic_redirect", "redirect"),
    Phase("url_rewrite_rules", "http_request_transform", "rewrite"),
    Phase("request_header_rules", "http_request_late_transform", "rewrite"),
    Phase("response_header_rules", "http_response_headers_transform", "rewrite"),
    Phase("config_rules", "http_config_settings", "set_config"),
    Phase("origin_rules", "http_request_origin", "route"),
    Phase("cache_rules", "http_request_cache_settings", "set_cache_settings"),
    Phase("compression_rules", "http_response_compression", "compress_response"),
    Phase(
        "custom_error_rules",
        "http_custom_errors",
        "serve_error",
        zone_level=True,
        account_level=True,
    ),
    Phase(
        "waf_custom_rules",
        "http_request_firewall_custom",
        None,
        zone_level=True,
        account_level=True,
    ),
    Phase(
        "waf_managed_rules",
        "http_request_firewall_managed",
        None,
        zone_level=True,
        account_level=True,
    ),
    Phase(
        "rate_limiting_rules",
        "http_ratelimit",
        None,
        zone_level=True,
        account_level=True,
    ),
    Phase("bot_fight_rules", "http_request_sbfm", None),
    Phase("sensitive_data_detection", "http_response_firewall_managed", None),
    Phase(
        "http_ddos_rules",
        "ddos_l7",
        None,
        zone_level=True,
        account_level=True,
    ),
    Phase(
        "bulk_redirect_rules",
        "http_request_redirect",
        "redirect",
        zone_level=False,
        account_level=True,
    ),
    Phase("log_custom_fields", "http_log_custom_fields", "log_custom_field"),
    Phase(
        "network_ddos_rules",
        "ddos_l4",
        None,
        zone_level=False,
        account_level=True,
    ),
    Phase(
        "network_firewall_rules",
        "magic_transit",
        None,
        zone_level=False,
        account_level=True,
    ),
    Phase(
        "network_firewall_managed",
        "magic_transit_managed",
        None,
        zone_level=False,
        account_level=True,
    ),
    Phase(
        "network_firewall_ratelimit",
        "magic_transit_ratelimit",
        None,
        zone_level=False,
        account_level=True,
    ),
    Phase(
        "network_firewall_ids",
        "magic_transit_ids_managed",
        None,
        zone_level=False,
        account_level=True,
    ),
    Phase("url_normalization", "http_request_sanitize", None),
]

# ---------------------------------------------------------------------------
# Mutable registry and derived collections
# ---------------------------------------------------------------------------

# The mutable registry — starts as a copy of builtins.
PHASES: list[Phase] = list(_BUILTIN_PHASES)

PHASE_BY_NAME: dict[str, Phase] = {}
PHASE_BY_CF: dict[str, Phase] = {}
ALL_FRIENDLY_NAMES: list[str] = []
ALL_CF_PHASES: list[str] = []
ZONE_CF_PHASES: list[str] = []
ACCOUNT_CF_PHASES: list[str] = []

# Phase names that were renamed — old name → current friendly name.
RENAMED_PHASES: dict[str, str] = {
    "waf_managed_exceptions": "waf_managed_rules",
}


def _rebuild_derived() -> None:
    """Rebuild all derived dicts/lists in-place from ``PHASES``.

    Mutates the module-level collections so any code that imported them
    at module level sees the updates.
    """
    PHASE_BY_NAME.clear()
    PHASE_BY_NAME.update({p.friendly_name: p for p in PHASES})
    # Re-apply backward-compatibility aliases
    for alias, canonical in RENAMED_PHASES.items():
        if canonical in PHASE_BY_NAME:
            PHASE_BY_NAME[alias] = PHASE_BY_NAME[canonical]

    PHASE_BY_CF.clear()
    PHASE_BY_CF.update({p.cf_phase: p for p in PHASES})

    ALL_FRIENDLY_NAMES.clear()
    ALL_FRIENDLY_NAMES.extend(p.friendly_name for p in PHASES)

    ALL_CF_PHASES.clear()
    ALL_CF_PHASES.extend(p.cf_phase for p in PHASES)

    ZONE_CF_PHASES.clear()
    ZONE_CF_PHASES.extend(p.cf_phase for p in PHASES if p.zone_level)

    ACCOUNT_CF_PHASES.clear()
    ACCOUNT_CF_PHASES.extend(p.cf_phase for p in PHASES if p.account_level)


# Initial build
_rebuild_derived()

# ---------------------------------------------------------------------------
# Registration API
# ---------------------------------------------------------------------------


def register_phase(phase: Phase) -> None:
    """Register a new phase. Raises ValueError if the name or cf_phase already exists."""
    if phase.friendly_name in PHASE_BY_NAME:
        raise ValueError(f"Phase {phase.friendly_name!r} is already registered")
    if phase.cf_phase in PHASE_BY_CF:
        raise ValueError(f"CF phase {phase.cf_phase!r} is already registered")
    PHASES.append(phase)
    _rebuild_derived()


def register_phases(phases: list[Phase]) -> None:
    """Register multiple phases at once. Atomic: all succeed or none are added."""
    # Validate all first
    for phase in phases:
        if phase.friendly_name in PHASE_BY_NAME:
            raise ValueError(f"Phase {phase.friendly_name!r} is already registered")
        if phase.cf_phase in PHASE_BY_CF:
            raise ValueError(f"CF phase {phase.cf_phase!r} is already registered")
    # Check for duplicates within the batch
    names = [p.friendly_name for p in phases]
    cf_phases = [p.cf_phase for p in phases]
    if len(set(names)) != len(names):
        raise ValueError("Duplicate friendly_name in batch")
    if len(set(cf_phases)) != len(cf_phases):
        raise ValueError("Duplicate cf_phase in batch")
    PHASES.extend(phases)
    _rebuild_derived()


def unregister_phase(friendly_name: str) -> None:
    """Remove a phase by friendly name. Raises KeyError if not found."""
    if friendly_name not in PHASE_BY_NAME:
        raise KeyError(f"Phase {friendly_name!r} is not registered")
    if friendly_name in RENAMED_PHASES.values():
        raise ValueError(f"Cannot unregister {friendly_name!r}: it has backward-compat aliases")
    PHASES[:] = [p for p in PHASES if p.friendly_name != friendly_name]
    _rebuild_derived()


# ---------------------------------------------------------------------------
# Top-level YAML keys that are valid but are not phase names.
# ---------------------------------------------------------------------------

KNOWN_NON_PHASE_KEYS: frozenset[str] = frozenset(
    {"custom_rulesets", "lists", "page_shield_policies"}
)

# Fields injected by the CF API that should be stripped when processing rules.
# Note: 'ref' is NOT included — it's user-defined and needed for identification.
CF_API_FIELDS: frozenset[str] = frozenset(
    {"id", "version", "last_updated", "categories", "logging"}
)

# Fields injected by the CF API on list items that should be stripped.
LIST_ITEM_API_FIELDS: frozenset[str] = frozenset({"id", "created_on", "modified_on"})

# Fields injected by the CF API on page shield policies that should be stripped.
PAGE_SHIELD_POLICY_API_FIELDS: frozenset[str] = frozenset({"id", "last_updated"})


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


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
