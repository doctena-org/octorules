"""Extension hook registries for provider-specific features.

Providers register hooks at import time to extend core functionality
without coupling the core to any specific provider.  Three registries:

- **format_extension**: Provides formatters for extension plan types.
- **validate_extension**: Called during offline validation.
- **audit_extension**: Called during audit to extract IP ranges from rules.

Dump is deliberately **not** a registry.  Hooks here are dispatched at
every provider, not only the one that registered them, and the other
registries survive that because they are scoped by something: plan hooks
early-out on their own absent desired section, apply only runs for
extensions that produced a plan, format matches on plan type, and
validate/audit never see a provider.  A dump hook reads from the API, so
it has no desired data to scope by and would run against providers whose
methods it does not have.  Dump therefore lives on the provider itself,
as :meth:`BaseProvider.dump_extra_sections`.

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
from typing import TYPE_CHECKING, ClassVar, Protocol

from octorules.phases import Phase

if TYPE_CHECKING:
    from octorules.audit import RuleIPInfo
    from octorules.planner import ZonePlan
    from octorules.provider.base import BaseProvider, Scope

log = logging.getLogger(__name__)
# ---------------------------------------------------------------------------
# Hook type aliases
# ---------------------------------------------------------------------------


# (desired, zone_name, errors, lines) -> None
# Appends to errors/lines in place.
ValidateExtensionFn = Callable[[dict, str, list[str], list[str]], None]

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


# ---------------------------------------------------------------------------
# Hook signature validation
# ---------------------------------------------------------------------------

# Expected parameter names for each hook type, derived from the actual
# provider implementations.  Validated at registration time so signature
# mismatches surface immediately instead of at runtime.
_VALIDATE_PARAMS = ("desired", "zone_name", "errors", "lines")
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

_format_extensions: dict[str, FormatExtension] = {}
_validate_extensions: list[ValidateExtensionFn] = []
_audit_extensions: dict[str, AuditExtensionFn] = {}


# ---------------------------------------------------------------------------
# Registration functions
# ---------------------------------------------------------------------------
_FORMAT_METHODS = ("format_text", "format_json", "format_markdown", "format_html")


def register_format_extension(name: str, fmt: FormatExtension) -> None:
    """Register a formatter for extension *name*.

    ``FormatExtension`` is a structural protocol, so *fmt* is checked for the
    four methods rather than for a signature. Without the check a formatter
    missing one of them registers cleanly and fails much later, inside plan
    rendering, as an ``AttributeError`` naming neither the extension nor the
    output mode that asked for it — and only for the one mode that is missing,
    so text output can look fine while ``--format html`` crashes.
    """
    missing = [m for m in _FORMAT_METHODS if not callable(getattr(fmt, m, None))]
    if missing:
        raise TypeError(
            f"format extension {name!r} ({type(fmt).__module__}.{type(fmt).__name__})"
            f" is missing {', '.join(missing)}; a FormatExtension must implement"
            f" {', '.join(_FORMAT_METHODS)}"
        )
    with _REGISTRY_LOCK:
        _format_extensions[name] = fmt


def register_validate_extension(fn: ValidateExtensionFn) -> None:
    """Register a validation hook."""
    _validate_hook_signature("validate_extension", fn, _VALIDATE_PARAMS)
    with _REGISTRY_LOCK:
        if fn not in _validate_extensions:
            _validate_extensions.append(fn)


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
    """Start each applicable extension's prefetch. Returns (extension, ctx) pairs.

    Walks the provider's own extensions, so an extension is only ever handed
    the provider that owns it.  Core applies the section check, which every
    hook used to repeat by hand.

    Prefetch exists to overlap API work with the main phase-rules fetch, so
    the extensions run concurrently.  If one raises, pending futures are
    cancelled and the first exception propagates.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    exts = applicable_extensions(provider, all_desired)
    log.debug("Prefetching %d extension(s)", len(exts))
    if not exts:
        return []

    if len(exts) == 1:
        ext = exts[0]
        try:
            return [(ext, ext.prefetch(all_desired, scope, provider))]
        except Exception:
            log.exception("Error in %s prefetch", type(ext).__name__)
            raise

    results: dict[int, object] = {}
    with ThreadPoolExecutor(max_workers=len(exts)) as executor:
        future_to_idx = {
            executor.submit(ext.prefetch, all_desired, scope, provider): idx
            for idx, ext in enumerate(exts)
        }
        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception:
                for f in future_to_idx:
                    f.cancel()
                log.exception("Error in %s prefetch", type(exts[idx]).__name__)
                raise

    return [(exts[idx], results[idx]) for idx in range(len(exts))]


def call_plan_zone_finalize(
    zone_plan: "ZonePlan",
    all_desired: dict,
    scope: "Scope",
    provider: "BaseProvider",
    prefetch_pairs: list[tuple],
) -> None:
    """Let each extension turn its prefetched result into plans."""
    for ext, ctx in prefetch_pairs:
        try:
            ext.finalize(zone_plan, all_desired, scope, provider, ctx)
        except Exception:
            log.exception("Error in %s finalize", type(ext).__name__)
            raise


def call_apply_extensions(
    zone_plan: "ZonePlan",
    scope: "Scope",
    provider: "BaseProvider",
) -> tuple[list[str], str | None]:
    """Apply each of the provider's extensions that produced plans.

    Returns (synced_labels, first_error).
    """
    all_synced: list[str] = []
    for ext in getattr(provider, "extensions", None) or []:
        plans = zone_plan.extension_plans.get(ext.plan_key(), [])
        if not plans:
            continue
        log.debug("Applying extension %s", ext.plan_key())
        synced, error = ext.apply(zone_plan, plans, scope, provider)
        all_synced.extend(synced)
        if error:
            return all_synced, error
    return all_synced, None


def call_validate_extensions(
    desired: dict, zone_name: str, errors: list[str], lines: list[str]
) -> None:
    """Call all registered validation hooks.

    A hook reports through two lists. *errors* collects configurations that
    cannot do what they claim; lint reports them as CORE010 errors. *lines*
    collects warnings — settings that are legal and deployable but carry a
    security consequence that is easy to miss — and lint reports them as
    CORE013 warnings.

    *lines* was previously passed by the lint command as a throwaway list and
    discarded, so anything a hook put there had no effect. It is a real channel
    now, which means a hook must not use it for progress or success messages;
    those belong in the log.
    """
    with _REGISTRY_LOCK:
        hooks = list(_validate_extensions)
    for fn in hooks:
        fn(desired, zone_name, errors, lines)


def call_audit_extensions(
    rules_data: dict,
    phase_name: str,
) -> tuple[list["RuleIPInfo"], list[str]]:
    """Call all registered audit extractors for a phase.

    Returns ``(results, failed)`` where *results* is a flat list of
    :class:`RuleIPInfo` from all providers and *failed* is a list of
    extension names that raised an exception.

    Error handling policy:

    - **Plan/sync hooks** (prefetch, finalize, apply): errors are always
      **fatal** — the operation aborts immediately.  This guarantees
      planning and syncing never proceed with incomplete data.
    - **Audit hooks**: errors are **best-effort** — partial results are
      returned and the failed extension is recorded; the audit command
      reports each failure as a non-suppressible ERROR finding.
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
# Provider extensions — a provider-owned feature and its whole lifecycle
# ---------------------------------------------------------------------------
class ProviderExtension:
    """One provider-owned zone-file section, and everything done with it.

    A provider exposes its own extensions via
    :attr:`BaseProvider.extensions`; core walks that list rather than a
    global registry.  Dispatch is therefore structural — an extension can
    only ever be handed the provider that owns it, so a section can never
    be requested from a provider unable to serve it.

    Subclasses set :attr:`section` and override only the stages they need;
    every stage defaults to doing nothing.  These are the stages core
    dispatches *through the provider*.  Formatters and validators stay in
    their own registries: a formatter is looked up by plan bucket from
    ``format_zone_plan(zone_plan)``, which holds no provider, and lint calls
    validators with no provider either — so neither can be reached from
    ``provider.extensions``.  Core skips an extension whose
    :attr:`section` is absent from the zone's desired data, so subclasses
    do not repeat that check.

    ``prefetch`` / ``finalize`` stay two-phase: ``prefetch`` starts API
    work that overlaps the main phase-rules fetch, and ``finalize`` turns
    the result into plans once the zone plan exists.
    """

    #: Zone-file section this extension owns.  Required.
    section: ClassVar[str] = ""
    #: Further sections that also make this extension applicable.  For an
    #: extension whose one API fetch serves several sections (bunny's shield
    #: config covers ``bunny_shield_config`` and ``bunny_waf_managed_rules``),
    #: naming them here keeps it running when only a secondary one is present.
    extra_sections: ClassVar[tuple[str, ...]] = ()
    #: Key for this extension's plans in ``ZonePlan.extension_plans``.
    #: Defaults to :attr:`section` when left empty.
    name: ClassVar[str] = ""

    @classmethod
    def plan_key(cls) -> str:
        """Key under which this extension's plans are stored."""
        return cls.name or cls.section

    def prefetch(self, desired: object, scope: "Scope", provider: "BaseProvider") -> object:
        """Start background work for this section. Returns an opaque context."""
        return None

    def finalize(
        self,
        zp: "ZonePlan",
        desired: object,
        scope: "Scope",
        provider: "BaseProvider",
        ctx: object,
    ) -> None:
        """Turn the prefetched result into plans on *zp*."""
        return None

    def apply(
        self,
        zp: "ZonePlan",
        plans: list,
        scope: "Scope",
        provider: "BaseProvider",
    ) -> tuple[list[str], str | None]:
        """Apply this extension's plans. Returns (synced_labels, error)."""
        return [], None

    def dump(self, scope: "Scope", provider: "BaseProvider") -> dict | None:
        """Return this section's current state for dump output."""
        return None


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
    renders its own plans) and the YAML-facing *prefix* used in change
    labels.

    An empty *prefix* renders each change's ``field`` as the whole label —
    for providers whose fields already carry a section path
    (e.g. ``"bot_detection.execution_mode"``).
    """

    def __init__(self, plan_type: type, prefix: str) -> None:
        self._plan_type = plan_type
        self._prefix = prefix

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


# ---------------------------------------------------------------------------
# Provider-extension dispatch
# ---------------------------------------------------------------------------
def applicable_extensions(provider: "BaseProvider", desired: dict) -> list["ProviderExtension"]:
    """The provider's extensions whose section is present in *desired*.

    Centralises the check every hook used to write by hand.  An extension
    with no ``section`` set is always applicable (it decides for itself).
    """
    result: list[ProviderExtension] = []
    for ext in getattr(provider, "extensions", None) or []:
        sections = (ext.section, *ext.extra_sections) if ext.section else ()
        if sections and all(desired.get(s) is None for s in sections):
            continue
        result.append(ext)
    return result
