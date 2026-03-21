"""Extension hook registries for provider-specific features.

Providers register hooks at import time to extend core functionality
without coupling the core to any specific provider.  Five registries:

- **plan_zone_hook**: Called during zone planning to add extension plans.
- **apply_extension**: Called during sync to apply extension-specific changes.
- **format_extension**: Provides formatters for extension plan types.
- **validate_extension**: Called during offline validation.
- **dump_extension**: Called during dump to export extension data.

Extension plans are stored generically in ``ZonePlan.extension_plans``
as ``dict[str, list]``, keyed by extension name (e.g. ``"page_shield"``).
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pathlib import Path

    from octorules.planner import ZonePlan
    from octorules.provider.base import BaseProvider, Scope

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Hook type aliases
# ---------------------------------------------------------------------------

# Prefetch: (all_desired, scope, provider) -> opaque context or None
# Called BEFORE get_all_phase_rules to start concurrent fetches.
PlanZonePrefetchHook = Callable[[dict, "Scope", "BaseProvider"], object]

# Finalize: (zone_plan, all_desired, scope, provider, prefetch_ctx) -> None
# Called AFTER plan_zone to process the prefetched data.
PlanZoneFinalizeHook = Callable[["ZonePlan", dict, "Scope", "BaseProvider", object], None]

# (zone_plan, plans, scope, provider) -> (synced_labels, error_msg)
ApplyExtensionFn = Callable[
    ["ZonePlan", list, "Scope", "BaseProvider"],
    tuple[list[str], str | None],
]

# (desired, zone_name, errors, lines) -> None
# Appends to errors/lines in place.
ValidateExtensionFn = Callable[[dict, str, list[str], list[str]], None]

# (scope, provider, out_dir) -> dict | None
# Returns data to merge into dump output, or None.
DumpExtensionFn = Callable[["Scope", "BaseProvider", "Path"], dict | None]


class FormatExtension(Protocol):
    """Protocol for extension-specific plan formatters."""

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        """Return lines of colored terminal output."""
        ...

    def format_json(self, plans: list) -> list[dict]:
        """Return JSON-serializable dicts for each plan."""
        ...

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        """Return markdown table rows + diff blocks."""
        ...

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        """Append HTML to *lines*. Return (creates, removes, modifies, reorders)."""
        ...

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        """Append report entries to *phases_data*. Return updated zone_has_drift."""
        ...


# ---------------------------------------------------------------------------
# Registries (module-level mutable collections)
# ---------------------------------------------------------------------------

_plan_zone_hooks: list[tuple[PlanZonePrefetchHook, PlanZoneFinalizeHook]] = []
_apply_extensions: dict[str, ApplyExtensionFn] = {}
_format_extensions: dict[str, FormatExtension] = {}
_validate_extensions: list[ValidateExtensionFn] = []
_dump_extensions: list[DumpExtensionFn] = []


# ---------------------------------------------------------------------------
# Registration functions
# ---------------------------------------------------------------------------


def register_plan_zone_hook(
    prefetch: PlanZonePrefetchHook,
    finalize: PlanZoneFinalizeHook,
) -> None:
    """Register a two-phase plan hook.

    *prefetch* is called before ``get_all_phase_rules()`` to start concurrent
    background work (e.g. API fetches).  *finalize* is called after
    ``plan_zone()`` with the opaque context returned by *prefetch*.
    """
    pair = (prefetch, finalize)
    if pair not in _plan_zone_hooks:
        _plan_zone_hooks.append(pair)


def register_apply_extension(name: str, fn: ApplyExtensionFn) -> None:
    """Register an apply function for extension *name*."""
    _apply_extensions[name] = fn


def register_format_extension(name: str, fmt: FormatExtension) -> None:
    """Register a formatter for extension *name*."""
    _format_extensions[name] = fmt


def register_validate_extension(fn: ValidateExtensionFn) -> None:
    """Register a validation hook."""
    if fn not in _validate_extensions:
        _validate_extensions.append(fn)


def register_dump_extension(fn: DumpExtensionFn) -> None:
    """Register a dump hook."""
    if fn not in _dump_extensions:
        _dump_extensions.append(fn)


# ---------------------------------------------------------------------------
# Unregister (for test teardown)
# ---------------------------------------------------------------------------


def unregister_plan_zone_hook(
    prefetch: PlanZonePrefetchHook,
    finalize: PlanZoneFinalizeHook,
) -> None:
    """Remove a plan zone hook pair."""
    try:
        _plan_zone_hooks.remove((prefetch, finalize))
    except ValueError:
        pass


def unregister_apply_extension(name: str) -> None:
    """Remove an apply extension."""
    _apply_extensions.pop(name, None)


def unregister_format_extension(name: str) -> None:
    """Remove a format extension."""
    _format_extensions.pop(name, None)


def unregister_validate_extension(fn: ValidateExtensionFn) -> None:
    """Remove a validation hook."""
    try:
        _validate_extensions.remove(fn)
    except ValueError:
        pass


def unregister_dump_extension(fn: DumpExtensionFn) -> None:
    """Remove a dump hook."""
    try:
        _dump_extensions.remove(fn)
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# Invocation helpers (called by core commands)
# ---------------------------------------------------------------------------


def call_plan_zone_prefetch(
    all_desired: dict,
    scope: Scope,
    provider: BaseProvider,
) -> list[tuple]:
    """Call prefetch hooks. Returns list of (finalize_fn, context) pairs.

    Snapshots the hook list so finalize uses the same hooks even if
    registrations change between prefetch and finalize.
    """
    pairs: list[tuple] = []
    for prefetch, finalize in _plan_zone_hooks:
        try:
            ctx = prefetch(all_desired, scope, provider)
        except Exception:
            log.exception("Error in plan zone prefetch hook %s", prefetch)
            raise
        pairs.append((finalize, ctx))
    return pairs


def call_plan_zone_finalize(
    zone_plan: ZonePlan,
    all_desired: dict,
    scope: Scope,
    provider: BaseProvider,
    prefetch_pairs: list[tuple],
) -> None:
    """Call finalize hooks with their paired prefetch contexts."""
    for finalize, ctx in prefetch_pairs:
        try:
            finalize(zone_plan, all_desired, scope, provider, ctx)
        except Exception:
            log.exception("Error in plan zone finalize hook %s", finalize)
            raise


def call_apply_extensions(
    zone_plan: ZonePlan,
    scope: Scope,
    provider: BaseProvider,
) -> tuple[list[str], str | None]:
    """Call apply functions for all extensions that have plans.

    Returns (synced_labels, first_error).
    """
    all_synced: list[str] = []
    for name, fn in _apply_extensions.items():
        plans = zone_plan.extension_plans.get(name, [])
        if not plans:
            continue
        synced, error = fn(zone_plan, plans, scope, provider)
        all_synced.extend(synced)
        if error:
            return all_synced, error
    return all_synced, None


def call_validate_extensions(
    desired: dict, zone_name: str, errors: list[str], lines: list[str]
) -> None:
    """Call all registered validation hooks."""
    for fn in _validate_extensions:
        fn(desired, zone_name, errors, lines)


def call_dump_extensions(
    scope: Scope,
    provider: BaseProvider,
    out_dir: Path,
) -> dict:
    """Call all registered dump hooks. Returns merged dict of extra data."""
    result: dict = {}
    for fn in _dump_extensions:
        data = fn(scope, provider, out_dir)
        if data:
            result.update(data)
    return result


def get_format_extensions() -> dict[str, FormatExtension]:
    """Return the registered format extensions."""
    return _format_extensions
