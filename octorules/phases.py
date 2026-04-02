"""Phase registry — maps friendly YAML names to provider phase identifiers.

The registry is extensible via ``register_phase()`` / ``register_phases()``.
Registration must happen early (before consumers cache derived data).
All derived collections (``ALL_PROVIDER_IDS``, ``PHASE_BY_NAME``, etc.) are
mutated **in-place** so existing imports see updates.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from difflib import get_close_matches

# Lock protecting all mutable registries in this module.  Under CPython the
# import lock already serializes import-time registration, but the explicit
# lock future-proofs against free-threaded builds (Python 3.13t+).
_REGISTRY_LOCK = threading.Lock()


@dataclass(frozen=True)
class Phase:
    friendly_name: str
    provider_id: str
    default_action: str | None  # None means user must specify in YAML
    zone_level: bool = True  # True for phases that work at zone level
    account_level: bool = False  # True for phases that work at account level
    # Optional per-rule preparation hook, called by ``prepare_desired_rules()``
    # after stripping ``octorules:`` metadata.  Receives ``(rule_dict, phase)``
    # and must return the prepared dict.  Providers register this to handle
    # expression normalization, default fields, action injection, etc.
    prepare_rule: Callable[[dict, Phase], dict] | None = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Core phase definitions — empty by default; providers register their phases.
# ---------------------------------------------------------------------------

_BUILTIN_PHASES: list[Phase] = []

# ---------------------------------------------------------------------------
# Mutable registry and derived collections
# ---------------------------------------------------------------------------

# The mutable registry — starts as a copy of builtins.
PHASES: list[Phase] = list(_BUILTIN_PHASES)

PHASE_BY_NAME: dict[str, Phase] = {}
PHASE_BY_PROVIDER_ID: dict[str, Phase] = {}
ALL_FRIENDLY_NAMES: list[str] = []
ALL_PROVIDER_IDS: list[str] = []
ZONE_PROVIDER_IDS: list[str] = []
ACCOUNT_PROVIDER_IDS: list[str] = []

# Phase names that were renamed — old name → current friendly name.
# Providers register aliases via ``register_phase_alias()``.
RENAMED_PHASES: dict[str, str] = {}


def register_phase_alias(old: str, new: str) -> None:
    """Register a backward-compat alias: *old* → *new*.

    After registration, ``PHASE_BY_NAME[old]`` resolves to the same Phase as *new*.
    """
    with _REGISTRY_LOCK:
        RENAMED_PHASES[old] = new
        _rebuild_derived()


def unregister_phase_alias(old: str) -> None:
    """Remove a phase alias (for test teardown)."""
    with _REGISTRY_LOCK:
        RENAMED_PHASES.pop(old, None)
        _rebuild_derived()


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

    PHASE_BY_PROVIDER_ID.clear()
    PHASE_BY_PROVIDER_ID.update({p.provider_id: p for p in PHASES})

    ALL_FRIENDLY_NAMES.clear()
    ALL_FRIENDLY_NAMES.extend(p.friendly_name for p in PHASES)

    ALL_PROVIDER_IDS.clear()
    ALL_PROVIDER_IDS.extend(p.provider_id for p in PHASES)

    ZONE_PROVIDER_IDS.clear()
    ZONE_PROVIDER_IDS.extend(p.provider_id for p in PHASES if p.zone_level)

    ACCOUNT_PROVIDER_IDS.clear()
    ACCOUNT_PROVIDER_IDS.extend(p.provider_id for p in PHASES if p.account_level)


# Initial build
_rebuild_derived()

# ---------------------------------------------------------------------------
# Registration API
# ---------------------------------------------------------------------------


def register_phase(phase: Phase) -> None:
    """Register a new phase. Raises ValueError if the name or provider_id already exists."""
    with _REGISTRY_LOCK:
        if phase.friendly_name in PHASE_BY_NAME:
            raise ValueError(f"Phase {phase.friendly_name!r} is already registered")
        if phase.provider_id in PHASE_BY_PROVIDER_ID:
            raise ValueError(f"Provider ID {phase.provider_id!r} is already registered")
        PHASES.append(phase)
        _rebuild_derived()


def register_phases(phases: list[Phase]) -> None:
    """Register multiple phases at once. Atomic: all succeed or none are added."""
    with _REGISTRY_LOCK:
        # Validate all first
        for phase in phases:
            if phase.friendly_name in PHASE_BY_NAME:
                raise ValueError(f"Phase {phase.friendly_name!r} is already registered")
            if phase.provider_id in PHASE_BY_PROVIDER_ID:
                raise ValueError(f"Provider ID {phase.provider_id!r} is already registered")
        # Check for duplicates within the batch
        names = [p.friendly_name for p in phases]
        provider_ids = [p.provider_id for p in phases]
        if len(set(names)) != len(names):
            raise ValueError("Duplicate friendly_name in batch")
        if len(set(provider_ids)) != len(provider_ids):
            raise ValueError("Duplicate provider_id in batch")
        PHASES.extend(phases)
        _rebuild_derived()


def unregister_phase(friendly_name: str) -> None:
    """Remove a phase by friendly name. Raises KeyError if not found."""
    with _REGISTRY_LOCK:
        if friendly_name not in PHASE_BY_NAME:
            raise KeyError(f"Phase {friendly_name!r} is not registered")
        if friendly_name in RENAMED_PHASES.values():
            raise ValueError(f"Cannot unregister {friendly_name!r}: it has backward-compat aliases")
        PHASES[:] = [p for p in PHASES if p.friendly_name != friendly_name]
        _rebuild_derived()


# ---------------------------------------------------------------------------
# Top-level YAML keys that are valid but are not phase names.
# Providers register their keys via ``register_non_phase_key()``.
# ---------------------------------------------------------------------------

# Mutable set — mutated **in-place** so that code which did
# ``from octorules.phases import KNOWN_NON_PHASE_KEYS`` sees updates.
KNOWN_NON_PHASE_KEYS: set[str] = set()


def register_non_phase_key(key: str) -> None:
    """Register a top-level YAML key that is not a phase name."""
    with _REGISTRY_LOCK:
        KNOWN_NON_PHASE_KEYS.add(key)


def unregister_non_phase_key(key: str) -> None:
    """Remove a non-phase key (for test teardown)."""
    with _REGISTRY_LOCK:
        KNOWN_NON_PHASE_KEYS.discard(key)


# ---------------------------------------------------------------------------
# Provider-registered API field sets
# ---------------------------------------------------------------------------

# Fields injected by the provider API that should be stripped when processing.
# Providers register their fields via ``register_api_fields()``.
# Empty defaults in core; providers register their fields at import.

_api_fields: dict[str, set[str]] = {
    "rule": set(),
    "list_item": set(),
    "page_shield_policy": set(),
}


def register_api_fields(category: str, fields: set[str]) -> None:
    """Register provider API fields to strip for *category*.

    Categories: ``"rule"``, ``"list_item"``, ``"page_shield_policy"``.
    """
    with _REGISTRY_LOCK:
        if category not in _api_fields:
            raise ValueError(f"Unknown API field category {category!r}")
        _api_fields[category].update(fields)


def unregister_api_fields(category: str) -> None:
    """Clear API fields for *category* (for test teardown)."""
    with _REGISTRY_LOCK:
        if category in _api_fields:
            _api_fields[category].clear()


def get_api_fields(category: str) -> frozenset[str]:
    """Return the registered API fields for *category* as a frozenset."""
    if category not in _api_fields:
        raise ValueError(f"Unknown API field category {category!r}")
    return frozenset(_api_fields[category])


def strip_api_fields(obj: dict, category: str) -> dict:
    """Return a copy of *obj* without keys registered as API-only for *category*."""
    excluded = get_api_fields(category)
    return {k: v for k, v in obj.items() if k not in excluded}


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------


def suggest_phase(name: str) -> str | None:
    """Return the closest matching phase name, or None if nothing is close.

    Also detects when a provider phase identifier is used and returns the friendly name.
    """
    if name in PHASE_BY_PROVIDER_ID:
        return PHASE_BY_PROVIDER_ID[name].friendly_name
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


def get_phase_by_provider_id(provider_id: str) -> Phase:
    """Look up a phase by provider identifier. Raises KeyError if not found."""
    if provider_id not in PHASE_BY_PROVIDER_ID:
        raise KeyError(f"Unknown provider phase {provider_id!r}")
    return PHASE_BY_PROVIDER_ID[provider_id]
