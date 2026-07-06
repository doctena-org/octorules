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

Besides the registries, this module provides the shared data model and
plan-output formatter for *settings extensions* — provider sections that
diff a flat ``{field: value}`` dict of desired YAML settings against live
zone configuration: :class:`SettingsChange`, :class:`SettingsPlan`, and
:class:`SettingsFormatter`.  :func:`make_synthetic_phase` supports
extensions that plan non-standard rulesets (custom rulesets, lists,
Page Shield).
"""

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass
from dataclasses import field as _dc_field
from typing import TYPE_CHECKING, Protocol

from octorules.phases import Phase

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


# ---------------------------------------------------------------------------
# Synthetic phases for extension plans
# ---------------------------------------------------------------------------
def make_synthetic_phase(
    prefix: str,
    name: str,
    provider_id: str,
    *,
    zone_level: bool = False,
    account_level: bool = True,
) -> Phase:
    """Create a synthetic Phase for non-standard rulesets (custom, lists, page shield)."""
    return Phase(
        friendly_name=f"{prefix}:{name}",
        provider_id=provider_id,
        default_action=None,
        zone_level=zone_level,
        account_level=account_level,
    )


# ---------------------------------------------------------------------------
# Settings extensions — shared data model
# ---------------------------------------------------------------------------
@dataclass
class SettingsChange:
    """A single field change in a settings section."""

    field: str
    current: object
    desired: object

    @property
    def has_changes(self) -> bool:
        return self.current != self.desired


@dataclass
class SettingsPlan:
    """Plan for all field-level changes in a settings section."""

    changes: list[SettingsChange] = _dc_field(default_factory=list)
    # Fields declared in YAML that the live config does not expose
    # (plan/product gated) -- reported as notes, never as changes.
    unsupported: list[str] = _dc_field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(c.has_changes for c in self.changes)

    @property
    def total_changes(self) -> int:
        return sum(1 for c in self.changes if c.has_changes)


class SettingsFormatter:
    """Formats settings diffs for plan output.

    Parameterised by the concrete *plan_type* (so each formatter only
    renders its own plans), the YAML-facing *prefix* used in change
    labels, and the *phase* / *provider_id* strings used in report mode.

    An empty *prefix* renders each change's ``field`` as the whole label —
    for providers whose fields already carry a section path
    (e.g. ``"bot_detection.execution_mode"``).
    """

    def __init__(self, plan_type: type, prefix: str, phase: str, provider_id: str) -> None:
        self._plan_type = plan_type
        self._prefix = prefix
        self._phase = phase
        self._provider_id = provider_id

    def _label(self, field: str) -> str:
        return f"{self._prefix}.{field}" if self._prefix else field

    def _active_plans(self, plans: list):
        for plan in plans:
            if isinstance(plan, self._plan_type) and (plan.has_changes or plan.unsupported):
                yield plan

    def format_text(self, plans: list, use_color: bool) -> list[str]:
        from octorules._color import Pen

        p = Pen(use_color)
        lines: list[str] = []
        for plan in self._active_plans(plans):
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = self._label(change.field)
                line = f"  ~ {label}: {change.current!r} -> {change.desired!r}"
                lines.append(p.warning(line))
            for name in plan.unsupported:
                line = (
                    f"  # {self._label(name)}: declared in YAML but not exposed"
                    " on this zone -- ignored"
                )
                lines.append(p.muted(line))
        return lines

    def format_json(self, plans: list) -> list[dict]:
        result: list[dict] = []
        for plan in self._active_plans(plans):
            changes = []
            for change in plan.changes:
                if not change.has_changes:
                    continue
                changes.append(
                    {
                        "field": change.field,
                        "current": change.current,
                        "desired": change.desired,
                    }
                )
            entry: dict = {}
            if changes:
                entry["changes"] = changes
            if plan.unsupported:
                entry["unsupported"] = list(plan.unsupported)
            if entry:
                result.append(entry)
        return result

    def format_markdown(
        self, plans: list, pending_diffs: list[list[tuple[str, object, object]]]
    ) -> list[str]:
        from octorules.formatter import md_escape

        lines: list[str] = []
        for plan in self._active_plans(plans):
            for change in plan.changes:
                if not change.has_changes:
                    continue
                label = md_escape(self._label(change.field))
                cur = md_escape(repr(change.current))
                des = md_escape(repr(change.desired))
                lines.append(f"| ~ | {label} | | {cur} -> {des} |")
            for name in plan.unsupported:
                label = md_escape(self._label(name))
                lines.append(f"| # | {label} | | not exposed on this zone -- ignored |")
        return lines

    def format_html(self, plans: list, lines: list[str]) -> tuple[int, int, int, int]:
        from html import escape as html_escape

        from octorules.formatter import HTML_TABLE_HEADER, html_summary_row

        total_modifies = 0
        for plan in self._active_plans(plans):
            lines.extend(HTML_TABLE_HEADER)
            plan_modifies = 0
            for change in plan.changes:
                if not change.has_changes:
                    continue
                plan_modifies += 1
                label = html_escape(self._label(change.field))
                cur = html_escape(repr(change.current))
                des = html_escape(repr(change.desired))
                lines.append("  <tr>")
                lines.append("    <td>Modify</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append(f"    <td>{cur} &rarr; {des}</td>")
                lines.append("  </tr>")
            for name in plan.unsupported:
                label = html_escape(self._label(name))
                lines.append("  <tr>")
                lines.append("    <td>Note</td>")
                lines.append(f"    <td>{label}</td>")
                lines.append("    <td>not exposed on this zone -- ignored</td>")
                lines.append("  </tr>")
            lines.extend(html_summary_row(0, 0, plan_modifies, 0))
            lines.append("</table>")
            total_modifies += plan_modifies
        return 0, 0, total_modifies, 0

    def format_report(self, plans: list, zone_has_drift: bool, phases_data: list[dict]) -> bool:
        total_modifies = 0
        for plan in plans:
            if not isinstance(plan, self._plan_type) or not plan.has_changes:
                continue
            total_modifies += plan.total_changes
        if total_modifies:
            zone_has_drift = True
            phases_data.append(
                {
                    "phase": self._phase,
                    "provider_id": self._provider_id,
                    "status": "drifted",
                    "yaml_rules": 0,
                    "live_rules": 0,
                    "adds": 0,
                    "removes": 0,
                    "modifies": total_modifies,
                }
            )
        return zone_has_drift
