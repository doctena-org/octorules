"""Extension hook registries for provider-specific features.

Providers register hooks at import time to extend core functionality
without coupling the core to any specific provider.  Six registries:

- **plan_zone_hook**: Called during zone planning to add extension plans.
- **apply_extension**: Called during sync to apply extension-specific changes.
- **format_extension**: Provides formatters for extension plan types.
- **validate_extension**: Called during offline validation.
- **dump_extension**: Called during dump to export extension data.
- **audit_extension**: Called during audit to extract IP ranges from rules.

Extension plans are stored generically in ``ZonePlan.extension_plans``
as ``dict[str, list]``, keyed by extension name (e.g. ``"page_shield"``).
"""

import logging
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from pathlib import Path

    from octorules.audit import RuleIPInfo
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

# (rules_data, phase_name) -> list[RuleIPInfo]
# Extracts IP ranges from provider-specific rules in a given phase.
AuditExtensionFn = Callable[[dict, str], list["RuleIPInfo"]]


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
# Hook signature validation
# ---------------------------------------------------------------------------

# Expected parameter names for each hook type, derived from the actual
# provider implementations.  Validated at registration time so signature
# mismatches surface immediately instead of at runtime.
_PREFETCH_PARAMS = ("all_desired", "scope", "provider")
_FINALIZE_PARAMS = ("zp", "all_desired", "scope", "provider", "ctx")
_APPLY_PARAMS = ("zp", "plans", "scope", "provider")
_VALIDATE_PARAMS = ("desired", "zone_name", "errors", "lines")
_DUMP_PARAMS = ("scope", "provider", "out_dir")
_AUDIT_PARAMS = ("rules_data", "phase_name")


def _validate_hook_signature(
    hook_type: str,
    fn: Callable,
    expected_params: tuple[str, ...],
) -> None:
    """Validate a hook callable has the expected parameter names.

    Raises :class:`TypeError` at registration time if the signature doesn't
    match, giving a clear message instead of an opaque runtime failure.

    Allows extra ``**kwargs`` on the hook (forward-compatible) and ignores
    ``*args`` so only named parameters are checked.
    """
    import inspect

    sig = inspect.signature(fn)
    params = [
        name
        for name, p in sig.parameters.items()
        if p.kind not in (inspect.Parameter.VAR_KEYWORD, inspect.Parameter.VAR_POSITIONAL)
    ]
    if tuple(params) != expected_params:
        raise TypeError(
            f"{hook_type} hook {fn.__qualname__!r} has incorrect signature. "
            f"Expected parameters: {expected_params}, got: {tuple(params)}"
        )


# ---------------------------------------------------------------------------
# Registries (module-level mutable collections)
# ---------------------------------------------------------------------------

# Lock protecting all mutable registries in this module.
_REGISTRY_LOCK = threading.Lock()

_plan_zone_hooks: list[tuple[PlanZonePrefetchHook, PlanZoneFinalizeHook]] = []
_apply_extensions: dict[str, ApplyExtensionFn] = {}
_format_extensions: dict[str, FormatExtension] = {}
_validate_extensions: list[ValidateExtensionFn] = []
_dump_extensions: list[DumpExtensionFn] = []
_audit_extensions: dict[str, AuditExtensionFn] = {}


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
    _validate_hook_signature("plan_zone_prefetch", prefetch, _PREFETCH_PARAMS)
    _validate_hook_signature("plan_zone_finalize", finalize, _FINALIZE_PARAMS)
    with _REGISTRY_LOCK:
        pair = (prefetch, finalize)
        if pair not in _plan_zone_hooks:
            _plan_zone_hooks.append(pair)


def register_apply_extension(name: str, fn: ApplyExtensionFn) -> None:
    """Register an apply function for extension *name*."""
    _validate_hook_signature("apply_extension", fn, _APPLY_PARAMS)
    with _REGISTRY_LOCK:
        _apply_extensions[name] = fn


def register_format_extension(name: str, fmt: FormatExtension) -> None:
    """Register a formatter for extension *name*.

    No signature validation is performed — ``FormatExtension`` is a
    structural (duck-typed) protocol and is validated by the caller at
    use time.
    """
    with _REGISTRY_LOCK:
        _format_extensions[name] = fmt


def register_validate_extension(fn: ValidateExtensionFn) -> None:
    """Register a validation hook."""
    _validate_hook_signature("validate_extension", fn, _VALIDATE_PARAMS)
    with _REGISTRY_LOCK:
        if fn not in _validate_extensions:
            _validate_extensions.append(fn)


def register_dump_extension(fn: DumpExtensionFn) -> None:
    """Register a dump hook."""
    _validate_hook_signature("dump_extension", fn, _DUMP_PARAMS)
    with _REGISTRY_LOCK:
        if fn not in _dump_extensions:
            _dump_extensions.append(fn)


def register_audit_extension(name: str, fn: AuditExtensionFn) -> None:
    """Register an IP-extraction function for audit checks.

    *fn* receives ``(rules_data, phase_name)`` and returns a list of
    :class:`RuleIPInfo` objects describing the IPs referenced by each rule
    in that phase.
    """
    _validate_hook_signature("audit_extension", fn, _AUDIT_PARAMS)
    with _REGISTRY_LOCK:
        _audit_extensions[name] = fn


# ---------------------------------------------------------------------------
# Unregister (for test teardown)
# ---------------------------------------------------------------------------
def unregister_plan_zone_hook(
    prefetch: PlanZonePrefetchHook,
    finalize: PlanZoneFinalizeHook,
) -> None:
    """Remove a plan zone hook pair."""
    with _REGISTRY_LOCK:
        try:
            _plan_zone_hooks.remove((prefetch, finalize))
        except ValueError:
            pass


def unregister_apply_extension(name: str) -> None:
    """Remove an apply extension."""
    with _REGISTRY_LOCK:
        _apply_extensions.pop(name, None)


def unregister_format_extension(name: str) -> None:
    """Remove a format extension."""
    with _REGISTRY_LOCK:
        _format_extensions.pop(name, None)


def unregister_validate_extension(fn: ValidateExtensionFn) -> None:
    """Remove a validation hook."""
    with _REGISTRY_LOCK:
        try:
            _validate_extensions.remove(fn)
        except ValueError:
            pass


def unregister_dump_extension(fn: DumpExtensionFn) -> None:
    """Remove a dump hook."""
    with _REGISTRY_LOCK:
        try:
            _dump_extensions.remove(fn)
        except ValueError:
            pass


def unregister_audit_extension(name: str) -> None:
    """Remove an audit extension."""
    with _REGISTRY_LOCK:
        _audit_extensions.pop(name, None)


# ---------------------------------------------------------------------------
# Invocation helpers (called by core commands)
# ---------------------------------------------------------------------------
def call_plan_zone_prefetch(
    all_desired: dict,
    scope: "Scope",
    provider: "BaseProvider",
) -> list[tuple]:
    """Call prefetch hooks concurrently. Returns list of (finalize_fn, context) pairs.

    Snapshots the hook list so finalize uses the same hooks even if
    registrations change between prefetch and finalize.

    All prefetch hooks are submitted to a thread pool and run concurrently.
    If any hook raises an exception, all pending futures are cancelled and
    the first exception propagates immediately.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    with _REGISTRY_LOCK:
        hooks = list(_plan_zone_hooks)
    log.debug("Prefetching %d extension(s)", len(hooks))

    if not hooks:
        return []

    # Single hook — no thread pool overhead needed.
    if len(hooks) == 1:
        prefetch, finalize = hooks[0]
        try:
            ctx = prefetch(all_desired, scope, provider)
        except Exception:
            log.exception("Error in plan zone prefetch hook %s", prefetch)
            raise
        return [(finalize, ctx)]

    # Multiple hooks — run concurrently.
    results: dict[int, object] = {}
    with ThreadPoolExecutor(max_workers=len(hooks)) as executor:
        future_to_idx = {}
        for idx, (prefetch, _finalize) in enumerate(hooks):
            future = executor.submit(prefetch, all_desired, scope, provider)
            future_to_idx[future] = idx

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                # Cancel remaining futures and propagate the error.
                for f in future_to_idx:
                    f.cancel()
                prefetch_fn = hooks[idx][0]
                log.exception("Error in plan zone prefetch hook %s", prefetch_fn)
                raise

    # Rebuild pairs in original registration order.
    return [(hooks[idx][1], results[idx]) for idx in range(len(hooks))]


def call_plan_zone_finalize(
    zone_plan: "ZonePlan",
    all_desired: dict,
    scope: "Scope",
    provider: "BaseProvider",
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
    zone_plan: "ZonePlan",
    scope: "Scope",
    provider: "BaseProvider",
) -> tuple[list[str], str | None]:
    """Call apply functions for all extensions that have plans.

    Returns (synced_labels, first_error).
    """
    with _REGISTRY_LOCK:
        extensions = dict(_apply_extensions)
    all_synced: list[str] = []
    for name, fn in extensions.items():
        plans = zone_plan.extension_plans.get(name, [])
        if not plans:
            continue
        log.debug("Applying extension %s", name)
        synced, error = fn(zone_plan, plans, scope, provider)
        all_synced.extend(synced)
        if error:
            return all_synced, error
    return all_synced, None


def call_validate_extensions(
    desired: dict, zone_name: str, errors: list[str], lines: list[str]
) -> None:
    """Call all registered validation hooks."""
    with _REGISTRY_LOCK:
        hooks = list(_validate_extensions)
    for fn in hooks:
        fn(desired, zone_name, errors, lines)


def call_dump_extensions(
    scope: "Scope",
    provider: "BaseProvider",
    out_dir: "Path",
) -> dict:
    """Call all registered dump hooks. Returns merged dict of extra data."""
    with _REGISTRY_LOCK:
        hooks = list(_dump_extensions)
    result: dict = {}
    for fn in hooks:
        data = fn(scope, provider, out_dir)
        if data:
            result.update(data)
    return result


def call_audit_extensions(
    rules_data: dict,
    phase_name: str,
    *,
    strict: bool = False,
) -> tuple[list["RuleIPInfo"], list[str]]:
    """Call all registered audit extractors for a phase.

    Returns ``(results, failed)`` where *results* is a flat list of
    :class:`RuleIPInfo` from all providers and *failed* is a list of
    extension names that raised an exception.

    Error handling policy:

    - **Plan/sync hooks** (prefetch, finalize, apply): errors are always
      **fatal** — the operation aborts immediately.  This guarantees
      planning and syncing never proceed with incomplete data.
    - **Audit hooks**: errors are **best-effort** by default — partial
      results are returned and the failed extension is recorded.  Set
      *strict=True* to make audit errors fatal (raises immediately).
    """
    with _REGISTRY_LOCK:
        extensions = dict(_audit_extensions)
    results: list = []
    failed: list[str] = []
    for name, fn in extensions.items():
        try:
            results.extend(fn(rules_data, phase_name))
        except Exception:
            log.exception("Error in audit extension %s for phase %s", name, phase_name)
            if strict:
                raise
            failed.append(name)
    return results, failed


def get_format_extensions() -> dict[str, FormatExtension]:
    """Return a snapshot of the registered format extensions."""
    with _REGISTRY_LOCK:
        return dict(_format_extensions)
