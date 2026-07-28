"""Phase registry — maps friendly YAML names to provider phase identifiers.

The registry is extensible via ``register_phase()`` / ``register_phases()``.
Registration must happen early (before consumers cache derived data).
All derived collections (``ALL_PROVIDER_IDS``, ``PHASE_BY_NAME``, etc.) are
mutated **in-place** so existing imports see updates.
"""

import threading
from collections.abc import Callable, Iterable
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
    prepare_rule: Callable[[dict, "Phase"], dict] | None = field(default=None, repr=False)
    # Rule fields (beyond ``ref``) that must be present on rules inside
    # ``custom_rulesets`` entries targeting this phase.  Declared by the
    # provider that owns the phase; ``validate_custom_ruleset()`` enforces
    # them at plan time.  Empty means only ``ref`` is required.
    rule_required_fields: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Core phase definitions — empty by default; providers register their phases.
# ---------------------------------------------------------------------------

_BUILTIN_PHASES: list[Phase] = []

# ---------------------------------------------------------------------------
# Mutable registry and derived collections
# ---------------------------------------------------------------------------

# The single source of truth — providers append via register_phase(s).
PHASES: list[Phase] = list(_BUILTIN_PHASES)

# Derived collections — rebuilt in-place on every registration so that
# code which imported them at module level sees updates.
PHASE_BY_NAME: dict[str, Phase] = {}
PHASE_BY_PROVIDER_ID: dict[str, Phase] = {}
ALL_FRIENDLY_NAMES: list[str] = []
ALL_PROVIDER_IDS: list[str] = []
ZONE_PROVIDER_IDS: list[str] = []
ACCOUNT_PROVIDER_IDS: list[str] = []


def _rebuild_derived() -> None:
    """Rebuild all derived collections in-place from PHASES."""
    PHASE_BY_NAME.clear()
    PHASE_BY_NAME.update({p.friendly_name: p for p in PHASES})
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


_rebuild_derived()


# ---------------------------------------------------------------------------
# Registration API
# ---------------------------------------------------------------------------
def register_phase(phase: Phase) -> None:
    """Register a new phase.

    Idempotent: re-registering a phase with the same ``friendly_name`` and
    ``provider_id`` is a no-op (the first registration wins).  Raises
    ValueError if the name or provider_id is taken by a phase with a
    *different* identity (different name/id pair).
    """
    with _REGISTRY_LOCK:
        existing_by_name = PHASE_BY_NAME.get(phase.friendly_name)
        existing_by_id = PHASE_BY_PROVIDER_ID.get(phase.provider_id)
        if existing_by_name is not None:
            if existing_by_name.provider_id == phase.provider_id:
                return  # idempotent — same name+id pair
            raise ValueError(f"Phase {phase.friendly_name!r} is already registered")
        if existing_by_id is not None:
            if existing_by_id.friendly_name == phase.friendly_name:
                return  # idempotent — same name+id pair
            raise ValueError(f"Provider ID {phase.provider_id!r} is already registered")
        PHASES.append(phase)
        _rebuild_derived()


def register_phases(phases: list[Phase]) -> None:
    """Register multiple phases at once. Atomic: all succeed or none are added.

    Idempotent: phases already registered with identical attributes are skipped.
    Raises ValueError if a name or provider_id is taken by a *different* phase.
    """
    with _REGISTRY_LOCK:
        to_add: list[Phase] = []
        for phase in phases:
            existing_by_name = PHASE_BY_NAME.get(phase.friendly_name)
            existing_by_id = PHASE_BY_PROVIDER_ID.get(phase.provider_id)
            if existing_by_name is not None:
                if existing_by_name.provider_id == phase.provider_id:
                    continue  # idempotent — same name+id pair
                raise ValueError(f"Phase {phase.friendly_name!r} is already registered")
            if existing_by_id is not None:
                if existing_by_id.friendly_name == phase.friendly_name:
                    continue  # idempotent — same name+id pair
                raise ValueError(f"Provider ID {phase.provider_id!r} is already registered")
            to_add.append(phase)
        # Check for duplicates within the new batch
        names = [p.friendly_name for p in to_add]
        provider_ids = [p.provider_id for p in to_add]
        if len(set(names)) != len(names):
            raise ValueError("Duplicate friendly_name in batch")
        if len(set(provider_ids)) != len(provider_ids):
            raise ValueError("Duplicate provider_id in batch")
        PHASES.extend(to_add)
        if to_add:
            _rebuild_derived()


def unregister_phase(friendly_name: str) -> None:
    """Remove a phase by friendly name. Raises KeyError if not found."""
    with _REGISTRY_LOCK:
        if friendly_name not in PHASE_BY_NAME:
            raise KeyError(f"Phase {friendly_name!r} is not registered")
        PHASES[:] = [p for p in PHASES if p.friendly_name != friendly_name]
        _rebuild_derived()


# ---------------------------------------------------------------------------
# Top-level YAML keys that are valid but are not phase names.
# Providers register their keys via ``register_non_phase_key()``.
# ---------------------------------------------------------------------------

# Core sections a namespace block may carry without an explicit mapping.
# Core owns them outright — it ships their validators (CORE008/CORE009,
# ``validate_list_entry``, ``validate_custom_ruleset``) and the
# ``lists_dir`` config — so they are valid section *names* everywhere,
# whether or not a provider happens to register them.  Whether a given
# provider can actually manage them is a separate question, answered by
# the SUPPORTS_LISTS / SUPPORTS_CUSTOM_RULESETS capability check at plan
# time; treating them as unknown sections here made a plain ``lists:``
# section abort plan under ``strict_sections`` on every provider that
# didn't register it (aws, azure, google, bunny).
NAMESPACE_CORE_SECTIONS = frozenset({"lists", "custom_rulesets"})

# Mutable set — mutated **in-place** so that code which did
# ``from octorules.phases import KNOWN_NON_PHASE_KEYS`` sees updates.
KNOWN_NON_PHASE_KEYS: set[str] = set(NAMESPACE_CORE_SECTIONS)


def register_non_phase_key(key: str) -> None:
    """Register a top-level YAML key that is not a phase name."""
    with _REGISTRY_LOCK:
        KNOWN_NON_PHASE_KEYS.add(key)


def unregister_non_phase_key(key: str) -> None:
    """Remove a non-phase key (for test teardown)."""
    with _REGISTRY_LOCK:
        KNOWN_NON_PHASE_KEYS.discard(key)


# ---------------------------------------------------------------------------
# Provider namespaces — the nested zone-file format
# ---------------------------------------------------------------------------

# Zone files nest a provider's sections under one namespace block
# (``cloudflare: {waf_custom_rules: […], bot_management: {…}}``).  Loading
# flattens that to the dotted internal key — ``cloudflare.waf_custom_rules``
# — which is the one spelling used everywhere afterwards: the phase
# registry, zone data, plan checksums and every diagnostic.  There is no
# separate display form to translate to.

# namespace -> {nested member: dotted internal key}
PROVIDER_NAMESPACES: dict[str, dict[str, str]] = {}

# dotted internal key -> (namespace, nested member) — derived, for dump
# grouping and key-ownership checks.  Mutated in place like the other maps.
NAMESPACE_OF_KEY: dict[str, tuple[str, str]] = {}


def register_namespace(namespace: str, members: "Iterable[str]") -> None:
    """Register a provider's zone-file namespace.

    *members* are the section names a user may write inside the
    ``namespace:`` block, e.g. ``["cloudflare.waf_custom_rules", "waf_settings"]``.
    Each becomes the internal key ``"<namespace>.<member>"``; there is no
    mapping to supply, because the nested spelling and the internal
    spelling are the same thing.

    Idempotent for an identical re-registration; a conflicting one
    raises ValueError.
    """
    if isinstance(members, dict):
        # The pre-1.0 signature took {nested: flat}.  Iterating a dict would
        # silently keep the keys and discard the values, wiring up something
        # that merely looks right, so refuse it outright.
        raise TypeError(
            f"register_namespace({namespace!r}, ...) takes member names, not a mapping;"
            f" pass {sorted(members)!r}"
        )
    keys = {m: f"{namespace}.{m}" for m in members}
    with _REGISTRY_LOCK:
        existing = PROVIDER_NAMESPACES.get(namespace)
        if existing is not None:
            if existing == keys:
                return
            raise ValueError(f"Namespace {namespace!r} is already registered with different keys")
        for nested, flat in keys.items():
            # lists/custom_rulesets are implicit members of every
            # namespace block — no provider owns the core sections, and
            # several providers historically register them as non-phase
            # keys, so mapping entries for them are tolerated but carry
            # no ownership.
            if nested in NAMESPACE_CORE_SECTIONS or flat in NAMESPACE_CORE_SECTIONS:
                continue
            owner = NAMESPACE_OF_KEY.get(flat)
            if owner is not None and owner[0] != namespace:
                raise ValueError(f"Key {flat!r} is already owned by namespace {owner[0]!r}")
        PROVIDER_NAMESPACES[namespace] = dict(keys)
        for nested, flat in keys.items():
            if nested in NAMESPACE_CORE_SECTIONS or flat in NAMESPACE_CORE_SECTIONS:
                continue
            NAMESPACE_OF_KEY[flat] = (namespace, nested)
        # The namespace itself and its scoped core sections are valid
        # top-level keys wherever the flat view is inspected.
        KNOWN_NON_PHASE_KEYS.add(namespace)
        for section in NAMESPACE_CORE_SECTIONS:
            KNOWN_NON_PHASE_KEYS.add(f"{namespace}.{section}")


def iter_scoped_sections(data: dict, section: str):
    """Yield ``(namespace, value)`` pairs for *section* in a flat zone view.

    Multi-provider files carry the core sections per namespace
    (``"<ns>.lists"``); single-provider files carry them plain (yielded
    with namespace ``None``).
    """
    if section in data:
        yield None, data[section]
    for key, value in data.items():
        ns, sep, name = key.partition(".")
        if sep and name == section and ns in PROVIDER_NAMESPACES:
            yield ns, value


def unregister_namespace(namespace: str) -> None:
    """Remove a namespace registration (for test teardown)."""
    with _REGISTRY_LOCK:
        keys = PROVIDER_NAMESPACES.pop(namespace, None)
        if keys:
            for flat in keys.values():
                entry = NAMESPACE_OF_KEY.get(flat)
                if entry is not None and entry[0] == namespace:
                    del NAMESPACE_OF_KEY[flat]
        KNOWN_NON_PHASE_KEYS.discard(namespace)
        for section in NAMESPACE_CORE_SECTIONS:
            KNOWN_NON_PHASE_KEYS.discard(f"{namespace}.{section}")


# ---------------------------------------------------------------------------
# Provider-registered API field sets
# ---------------------------------------------------------------------------

# Fields injected by the provider API that should be stripped when processing.
# Providers register their fields via ``register_api_fields()``.
# Empty defaults in core; providers register their fields at import.

_api_fields: dict[str, set[str]] = {
    "rule": set(),
    "action_parameters": set(),
    "list_item": set(),
}


def register_api_fields(category: str, fields: set[str]) -> None:
    """Register provider API fields to strip for *category*.

    Core pre-declares ``"rule"``, ``"action_parameters"``, and
    ``"list_item"``.  Providers may register additional categories for
    their own entity kinds — an unknown *category* is created on first
    registration.  Reads (:func:`get_api_fields`, :func:`strip_api_fields`)
    stay strict and raise on categories that were never registered, so a
    misspelled category here surfaces at the provider's own read site.
    """
    with _REGISTRY_LOCK:
        _api_fields.setdefault(category, set()).update(fields)


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
    if matches:
        return matches[0]
    # Fall back to matching the member alone.  Every phase name carries its
    # namespace, so a name typed the way it appears inside the block
    # ("waf_custom_rulez") is a poor match for the full "cloudflare.
    # waf_custom_rules" but an excellent one for the member.
    by_member: dict[str, str] = {}
    for full in ALL_FRIENDLY_NAMES:
        _, sep, member = full.partition(".")
        if sep:
            by_member.setdefault(member, full)
    member_matches = get_close_matches(name, list(by_member), n=1, cutoff=0.6)
    return by_member[member_matches[0]] if member_matches else None


def suggest_namespace_member(namespace: str, member: str) -> str | None:
    """Closest nested member name within *namespace*, or None.

    Separate from :func:`suggest_phase` because the candidate set differs:
    nested member names are not the flat friendly names (google nests
    ``custom_rules`` for flat ``gcloud_armor_custom_rules``), so matching
    a mistyped member against the flat registry would miss for every
    provider whose nested spelling drops a flat prefix.
    """
    mapping = PROVIDER_NAMESPACES.get(namespace)
    if not mapping:
        return None
    candidates = sorted(set(mapping) | NAMESPACE_CORE_SECTIONS)
    matches = get_close_matches(member, candidates, n=1, cutoff=0.6)
    return matches[0] if matches else None


def unknown_phase_message(name: str) -> str:
    """Build a human-readable error message for an unknown phase name."""
    hint = suggest_phase(name)
    if hint:
        return f"Unknown phase {name!r}. Did you mean {hint!r}?"
    valid = ", ".join(sorted(ALL_FRIENDLY_NAMES))
    return f"Unknown phase {name!r}. Valid phases: {valid}"


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
