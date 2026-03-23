"""Command implementations for the octorules CLI."""

from __future__ import annotations

import importlib
import json as _json
import logging
import re
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import IO

from octorules import __version__
from octorules.config import (
    Config,
    ConfigError,
    ZoneConfig,
    _load_class,
    resolve_zone_ids,
    slugify,
)
from octorules.dumper import dump_zone_rules
from octorules.extensions import (
    call_apply_extensions,
    call_dump_extensions,
    call_plan_zone_finalize,
    call_plan_zone_prefetch,
    call_validate_extensions,
)
from octorules.formatter import build_report_data, print_report
from octorules.phases import (
    KNOWN_NON_PHASE_KEYS,
    PHASE_BY_NAME,
    PHASE_BY_PROVIDER_ID,
    get_phase,
    unknown_phase_message,
)
from octorules.plan_output import PlanText
from octorules.planner import (
    RuleDict,
    RuleValidationError,
    ZonePlan,
    check_safety,
    compute_checksum,
    diff_custom_rulesets_full,
    diff_lists_full,
    filter_by_target,
    plan_zone,
    prepare_desired_rules,
    validate_custom_ruleset,
    validate_list_entry,
    warn_unknown_phase_keys,
)
from octorules.processor import BaseProcessor
from octorules.provider.base import (
    SUPPORTS_CUSTOM_RULESETS,
    SUPPORTS_LISTS,
    SUPPORTS_ZONE_DISCOVERY,
    BaseProvider,
    Scope,
    provider_supports,
)
from octorules.provider.exceptions import (
    ProviderAuthError,
    ProviderError,
)

# Mapping from YAML top-level keys to SUPPORTS feature constants.
# Used by _validate_feature_support() to catch unsupported features early.
_FEATURE_KEYS: dict[str, str] = {
    "custom_rulesets": SUPPORTS_CUSTOM_RULESETS,
    "lists": SUPPORTS_LISTS,
}

log = logging.getLogger(__name__)


def _get_cloudflare_provider() -> type | None:
    """Lazy import of CloudflareProvider from octorules-cloudflare.

    Returns the class if the package is installed, None otherwise.
    Deferred to avoid triggering phase registration at import time.
    """
    try:
        from octorules_cloudflare import CloudflareProvider

        return CloudflareProvider
    except ImportError:
        return None


def _load_provider_class(dotted_path: str) -> type:
    """Import a provider class from a dotted module path.

    Example: ``'octorules_cloudflare.CloudflareProvider'``
    """
    return _load_class(dotted_path, "provider class")


def _discover_provider_modules() -> None:
    """Import all installed provider modules via entry-points.

    This triggers side-effects like phase registration and lint plugin
    registration without constructing provider instances (no API credentials
    needed).  Used by ``cmd_lint`` so lint plugins are available offline.
    """
    from importlib.metadata import entry_points

    for ep in entry_points(group="octorules.providers"):
        try:
            ep.load()
        except Exception as e:
            log.debug("Failed to load provider entry-point %s: %s", ep.name, e)


def _resolve_provider_class(name: str, class_path: str | None) -> type:
    """Determine the provider class for a named provider.

    Resolution order:
    1. Explicit ``class_path`` from config.
    2. Entry-point discovery (``octorules.providers`` group).
    3. Deprecated fallback to module-level ``CloudflareProvider`` (with warning).
    """
    if class_path:
        return _load_provider_class(class_path)

    # Entry-point discovery
    from importlib.metadata import entry_points

    eps = entry_points(group="octorules.providers")
    for ep in eps:
        if ep.name == name:
            return ep.load()

    # Deprecated fallback: when no entry point matched, fall back to the
    # lazily-imported CloudflareProvider (from octorules-cloudflare).
    cf_cls = _get_cloudflare_provider()
    if cf_cls is not None:
        log.warning(
            "No 'class' specified for provider %r and no entry point found. "
            "Set 'class: octorules_cloudflare.CloudflareProvider' explicitly.",
            name,
        )
        return cf_cls

    raise ConfigError(
        f"No provider class found for {name!r}. "
        f"Install a provider package or set 'class' explicitly."
    )


def _init_processors(config: Config) -> dict[str, BaseProcessor]:
    """Create all processors from config."""
    processors: dict[str, BaseProcessor] = {}
    for name, pc in config.processors.items():
        cls = _load_class(pc.class_path, "processor")
        processors[name] = cls(**pc.kwargs)
    return processors


def _validate_multi_target(config: Config, providers: dict[str, BaseProvider]) -> None:
    """Validate that multi-target zones use the same provider class.

    Raises ConfigError if a zone has targets pointing to providers of
    different classes.
    """
    for zone_name, zone_cfg in config.zones.items():
        if len(zone_cfg.targets) <= 1:
            continue
        classes = {type(providers[t]) for t in zone_cfg.targets}
        if len(classes) > 1:
            class_names = ", ".join(f"{t}={type(providers[t]).__name__}" for t in zone_cfg.targets)
            raise ConfigError(
                f"'zones.{zone_name}' has targets with different provider classes "
                f"({class_names}). Multi-target requires same provider class."
            )


def _discover_zones(config: Config, providers: dict[str, BaseProvider]) -> None:
    """Expand zone templates via provider zone discovery.

    For each ``'*'`` template, queries the target providers' ``list_zones()``
    and adds matching zones (those with a YAML rules file) to config.
    """
    if not config.zone_templates:
        return

    discovered: dict[str, list[str]] = {}
    seen_targets: set[str] = set()

    for template in config.zone_templates.values():
        for target in template.targets:
            if target in seen_targets:
                continue
            seen_targets.add(target)
            prov = providers.get(target)
            if prov is None:
                continue
            if not provider_supports(prov, SUPPORTS_ZONE_DISCOVERY):
                log.warning("Provider %s does not support zone discovery", target)
                continue
            try:
                zones = prov.list_zones()
                discovered[target] = zones
            except ProviderError as e:
                log.warning("Failed to discover zones from %s: %s", target, e)

    if discovered:
        config.expand_templates(discovered)


def _init_providers(
    config: Config, *, _provider_cls: type | None = None
) -> dict[str, BaseProvider]:
    """Create all providers from config and resolve missing zone IDs.

    For each ``ProviderConfig`` in ``config.providers``:
    1. Determine the class via entry-points, explicit ``class``, or fallback.
    2. Import the top-level package to trigger phase/linter registration.
    3. Instantiate with ``**pc.kwargs``.

    Then validates multi-target constraints, discovers zones, and resolves
    zone IDs using per-provider resolve functions.

    ``_provider_cls`` is an internal override for backward compatibility: when
    set, *all* providers use that class (used by ``_init_provider()``).
    """
    providers: dict[str, BaseProvider] = {}
    for name, pc in config.providers.items():
        if _provider_cls is not None:
            cls = _provider_cls
        else:
            cls = _resolve_provider_class(name, pc.class_path)
        # Import top-level package to trigger phase/linter registration.
        # Guard with hasattr — test mocks may not have __module__.
        if hasattr(cls, "__module__"):
            pkg = cls.__module__.split(".")[0]
            importlib.import_module(pkg)
        providers[name] = cls(**pc.kwargs)

    _validate_multi_target(config, providers)
    _discover_zones(config, providers)

    # Resolve zone IDs with per-provider resolve functions
    resolve_fns = {name: prov.resolve_zone_id for name, prov in providers.items()}
    resolve_zone_ids(config, resolve_fns)

    return providers


def _get_zone_provider(zone_cfg: ZoneConfig, providers: dict[str, BaseProvider]) -> BaseProvider:
    """Look up the provider for a zone from its ``targets`` list."""
    if zone_cfg.targets:
        return providers[zone_cfg.targets[0]]
    if len(providers) == 1:
        return next(iter(providers.values()))
    raise ConfigError(f"Zone {zone_cfg.name!r} has no target and multiple providers are configured")


def _get_zone_providers(
    zone_cfg: ZoneConfig, providers: dict[str, BaseProvider]
) -> list[tuple[str, BaseProvider]]:
    """Get all (target_name, provider) pairs for a zone.

    Single-target zones return one pair. Multi-target zones return one pair
    per target. Zones without explicit targets fall back to the single provider.
    """
    if zone_cfg.targets:
        return [(t, providers[t]) for t in zone_cfg.targets]
    if len(providers) == 1:
        name = next(iter(providers))
        return [(name, providers[name])]
    raise ConfigError(f"Zone {zone_cfg.name!r} has no target and multiple providers are configured")


def _init_provider(config: Config, *, provider_cls: type | None = None) -> BaseProvider:
    """Create a single provider from config and resolve zone IDs.

    .. deprecated::
        Use ``_init_providers()`` instead.  This wrapper only handles configs
        with a single provider.

    When *provider_cls* is given, it overrides class resolution (used in tests).
    """
    import warnings

    warnings.warn(
        "_init_provider() is deprecated, use _init_providers() instead",
        DeprecationWarning,
        stacklevel=2,
    )
    if provider_cls is not None:
        first_pc = next(iter(config.providers.values()), None)
        kwargs = first_pc.kwargs if first_pc else {}
        provider = provider_cls(**kwargs)
        resolve_zone_ids(config, provider.resolve_zone_id)
        return provider
    providers = _init_providers(config)
    if len(providers) == 1:
        return next(iter(providers.values()))
    raise ConfigError("_init_provider() cannot handle multiple providers; use _init_providers()")


def _get_zones(config: Config, zone_filter: list[str] | None) -> list[str]:
    """Return the list of zone names to process. Raises ConfigError if filter is invalid."""
    if zone_filter:
        for zone in zone_filter:
            if zone not in config.zones:
                available = ", ".join(sorted(config.zones))
                raise ConfigError(f"Zone {zone!r} not found in config. Available: {available}")
        return zone_filter
    return list(config.zones.keys())


def _validate_phases(phases: list[str] | None) -> list[str] | None:
    """Validate phase names against known phases. Raises ConfigError if invalid."""
    if not phases:
        return None
    for p in phases:
        if p not in PHASE_BY_NAME:
            raise ConfigError(unknown_phase_message(p))
    return phases


def _filter_desired_by_phase(
    desired: dict[str, list[RuleDict]], phases: list[str] | None
) -> dict[str, list[RuleDict]]:
    """Filter desired rules dict to only include specified phases."""
    if phases is None:
        return desired
    return {k: v for k, v in desired.items() if k in phases}


def _filter_current_by_phase(
    current: dict[str, list[RuleDict]], phases: list[str] | None
) -> dict[str, list[RuleDict]]:
    """Filter current rules dict to only include phases matching the friendly names."""
    if phases is None:
        return current
    allowed_provider_ids = {PHASE_BY_NAME[p].provider_id for p in phases if p in PHASE_BY_NAME}
    return {k: v for k, v in current.items() if k in allowed_provider_ids}


def _write_output_file(path: str, write_fn: Callable[[IO[str]], None]) -> bool:
    """Write output to a file. Returns True on success, False on error."""
    raw = str(Path(path))
    if ".." in raw or "~" in raw:
        log.error("Potentially unsafe output path: %s", path)
        return False
    try:
        with open(Path(path).resolve(), "w", encoding="utf-8") as f:
            write_fn(f)
        return True
    except OSError as e:
        log.error("Failed to write output file %s: %s", path, e)
        return False


def _emit_plan_outputs(config: Config, zone_plans: list[ZonePlan]) -> bool:
    """Run all configured plan_outputs, or default PlanText to stdout.

    Returns True on success, False if any file write failed.
    """
    outputs = config.plan_outputs
    if not outputs:
        PlanText("_default").run(zone_plans)
        return True
    ok = True
    for output in outputs.values():
        if output.path:
            if not _write_output_file(output.path, lambda f, out=output: out.run(zone_plans, fh=f)):
                ok = False
        else:
            output.run(zone_plans)
    return ok


def _phase_filter_to_provider_ids(phase_filter: list[str] | None) -> list[str] | None:
    """Convert friendly phase names to provider phase identifiers for API filtering."""
    if phase_filter is None:
        return None
    return [PHASE_BY_NAME[p].provider_id for p in phase_filter if p in PHASE_BY_NAME]


from octorules.provider.utils import format_api_error as _format_api_error  # noqa: E402


def _map_ordered(
    fn, items: list, max_workers: int, executor: ThreadPoolExecutor | None = None
) -> list:
    """Run fn(item) for each item, returning results in input order.

    Uses ThreadPoolExecutor when max_workers > 1, otherwise runs sequentially.
    An optional *executor* can be provided to reuse a thread pool across calls.
    Exceptions from callables propagate directly; callers should ensure fn
    handles expected errors internally (e.g. returning sentinel values).
    """
    if max_workers <= 1:
        return [fn(item) for item in items]

    def _run(ex: ThreadPoolExecutor) -> list:
        results: dict[int, object] = {}
        futures = {ex.submit(fn, item): i for i, item in enumerate(items)}
        for future in as_completed(futures):
            idx = futures[future]
            results[idx] = future.result()
        return [results[i] for i in range(len(items))]

    if executor is not None:
        return _run(executor)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        return _run(ex)


def _apply_parallel(
    tasks: list[tuple[str, Callable[[], None]]],
    max_workers: int = 0,
) -> tuple[list[str], str | None]:
    """Run independent API-call tasks, collecting successes.

    Each task is ``(label, fn)`` where *fn()* performs the API call and raises
    on failure.  Returns ``(successful_labels, first_error_message)``.

    * ``ProviderAuthError`` -> cancel remaining, re-raise.
    * First ``ProviderError`` / ``TimeoutError`` -> record
      error; in the parallel path remaining in-flight tasks still finish so we
      collect as many successes as possible.  In the sequential path we stop
      immediately (matching the original serial behaviour).
    """
    if not tasks:
        return [], None

    def _run_one(label: str, fn: Callable[[], None]) -> tuple[str, str | None]:
        try:
            fn()
        except ProviderAuthError:
            raise
        except ProviderError as e:
            return label, _format_api_error(e)
        except TimeoutError as e:
            return label, str(e)
        return label, None

    # Sequential fast-path (isinstance guard: test mocks may pass non-int)
    if not isinstance(max_workers, int) or max_workers <= 1 or len(tasks) <= 1:
        successes: list[str] = []
        for label, fn in tasks:
            label, error = _run_one(label, fn)
            if error:
                return successes, f"{label}: {error}"
            successes.append(label)
        return successes, None

    # Parallel path
    successes = []
    first_error: str | None = None
    workers = min(max_workers, len(tasks))
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(_run_one, lbl, fn): lbl for lbl, fn in tasks}
        for future in as_completed(futures):
            try:
                label, error = future.result()
            except ProviderAuthError:
                for f in futures:
                    f.cancel()
                raise
            if error:
                if first_error is None:
                    first_error = f"{label}: {error}"
            else:
                successes.append(label)
    return successes, first_error


_TaskList = list[tuple[str, Callable[[], None]]]


def _run_staged_tasks(
    stages: list[tuple[bool, _TaskList | Callable[[], _TaskList]]],
    max_workers: int,
) -> tuple[list[str], str | None]:
    """Run task stages sequentially, parallelising within each stage.

    *stages* is a list of ``(collect, tasks_or_builder)`` pairs.  Each element
    is either a concrete task list or a zero-arg callable that returns one
    (use a callable when the stage depends on state produced by an earlier
    stage, e.g. IDs assigned during creates).

    Each task list contains ``(label, fn)`` tuples executed via
    :func:`_apply_parallel`.  Stages run in order; within each stage tasks
    are parallelised.

    When *collect* is True the stage's successful labels are included in the
    returned list; when False they are discarded (useful for setup stages such
    as creates whose labels should not appear in the "synced" report).

    Returns ``(synced_labels, first_error)``.  Processing stops after the
    first stage that produces an error.
    """
    synced: list[str] = []
    for collect, tasks_or_builder in stages:
        tasks = tasks_or_builder() if callable(tasks_or_builder) else tasks_or_builder
        if not tasks:
            continue
        stage_synced, error = _apply_parallel(tasks, max_workers)
        if collect:
            synced.extend(stage_synced)
        if error:
            return synced, error
    return synced, None


def _plan_single_zone(
    config: Config,
    provider: BaseProvider,
    zone_name: str,
    phase_filter: list[str] | None,
    processors: dict[str, BaseProcessor] | None = None,
    target_name: str | None = None,
) -> tuple[str, ZonePlan, dict, dict]:
    """Plan a single zone. Returns (zone_name, zone_plan, desired, current)."""
    zone_cfg = config.zones[zone_name]
    scope = Scope(zone_id=zone_cfg.zone_id, label=zone_name)
    all_desired = config.load_zone_rules(zone_name)

    # Warn about unsupported features early (uses already-loaded data)
    for yaml_key, feature in _FEATURE_KEYS.items():
        if yaml_key in all_desired and not provider_supports(provider, feature):
            log.warning(
                "Zone %s uses %r but provider %s does not support it",
                zone_name,
                yaml_key,
                type(provider).__name__,
            )

    desired = _filter_desired_by_phase(all_desired, phase_filter)

    # Apply process_desired hooks
    if processors and zone_cfg.processors:
        for proc_name in zone_cfg.processors:
            desired = processors[proc_name].process_desired(zone_name, desired, provider)

    # Filter rules by target metadata
    if target_name is not None:
        desired = filter_by_target(desired, target_name)

    provider_ids = _phase_filter_to_provider_ids(phase_filter)

    # Start extension prefetch (e.g. Page Shield API call) concurrently
    ext_contexts = call_plan_zone_prefetch(all_desired, scope, provider)

    current = provider.get_all_phase_rules(scope, provider_ids=provider_ids)

    # Exclude phases that failed to fetch — planning against missing data
    # would incorrectly treat all existing rules as deletions.
    failed_phases = getattr(current, "failed_phases", [])
    if failed_phases:
        failed_friendly = {
            PHASE_BY_PROVIDER_ID[p].friendly_name
            for p in failed_phases
            if p in PHASE_BY_PROVIDER_ID
        }
        skipped = failed_friendly & set(desired.keys())
        for name in sorted(skipped):
            log.warning("Skipping %s for %s: failed to fetch current state", name, zone_name)
        if skipped:
            desired = {k: v for k, v in desired.items() if k not in failed_friendly}

    zp = plan_zone(zone_name, desired, current, allow_unmanaged=zone_cfg.allow_unmanaged)

    # Apply process_changes hooks
    if processors and zone_cfg.processors:
        for proc_name in zone_cfg.processors:
            zp = processors[proc_name].process_changes(zone_name, zp, provider)

    # Finalize extension hooks (join prefetched data, compute diffs)
    call_plan_zone_finalize(zp, all_desired, scope, provider, ext_contexts)

    return (zone_name, zp, desired, current)


def _plan_single_zone_safe(
    config: Config,
    provider: BaseProvider,
    zone_name: str,
    phase_filter: list[str] | None,
    processors: dict[str, BaseProcessor] | None = None,
    target_name: str | None = None,
) -> tuple[str, ZonePlan, dict, dict] | None:
    """Plan a single zone, returning None on transient API errors.

    ProviderAuthError propagates immediately
    (permanent error indicating a bad token or missing permissions).
    """
    try:
        return _plan_single_zone(
            config, provider, zone_name, phase_filter, processors, target_name=target_name
        )
    except ProviderAuthError:
        raise
    except ProviderError as e:
        log.error("Failed to plan %s: %s", zone_name, _format_api_error(e))
        return None


def _plan_zones(
    config: Config,
    providers: dict[str, BaseProvider],
    zone_names: list[str],
    phase_filter: list[str] | None,
    executor: ThreadPoolExecutor | None = None,
    processors: dict[str, BaseProcessor] | None = None,
) -> tuple[list[ZonePlan], dict[str, dict], dict[str, dict], list[str]]:
    """Plan all zones, optionally in parallel.

    Looks up the correct provider per zone via ``_get_zone_providers()``.
    For multi-target zones, creates a ZonePlan per target.
    Returns (zone_plans, desired_by_zone, current_by_zone, failed_zones).
    """
    zone_plans: list[ZonePlan] = []
    desired_by_zone: dict[str, dict] = {}
    current_by_zone: dict[str, dict] = {}
    failed_zones: list[str] = []

    # Build work items: (zone_name, display_target, target_name, provider)
    work_items: list[tuple[str, str | None, str, BaseProvider]] = []
    for zn in zone_names:
        zone_cfg = config.zones[zn]
        target_pairs = _get_zone_providers(zone_cfg, providers)
        if len(target_pairs) == 1:
            work_items.append((zn, None, target_pairs[0][0], target_pairs[0][1]))
        else:
            for tname, prov in target_pairs:
                work_items.append((zn, tname, tname, prov))

    def _plan_one(
        item: tuple[str, str | None, str, BaseProvider],
    ) -> tuple[str, ZonePlan, dict, dict] | None:
        zn, target, tname, provider = item
        result = _plan_single_zone_safe(
            config, provider, zn, phase_filter, processors, target_name=tname
        )
        if result is not None:
            name, zp, desired, current = result
            zp.target = target
        return result

    results = _map_ordered(
        _plan_one,
        work_items,
        config.max_workers,
        executor=executor,
    )

    for item, result in zip(work_items, results):
        zn = item[0]
        if result is None:
            if zn not in failed_zones:
                failed_zones.append(zn)
        else:
            name, zp, desired, current = result
            zone_plans.append(zp)
            desired_by_zone[zp.plan_key] = desired
            current_by_zone[zp.plan_key] = current

    return zone_plans, desired_by_zone, current_by_zone, failed_zones


def _plan_account(
    config: Config,
    provider: BaseProvider,
    phase_filter: list[str] | None,
) -> tuple[ZonePlan | None, dict, dict]:
    """Plan account-level rulesets. Returns (zone_plan, desired, current) or (None, {}, {})."""
    acct_id = provider.account_id
    acct_name = provider.account_name
    if not isinstance(acct_id, str) or not isinstance(acct_name, str):
        log.debug("No account info available, skipping account planning")
        return None, {}, {}

    account_label = slugify(acct_name)
    scope = Scope(account_id=provider.account_id, label=provider.account_name)
    all_desired = config.load_account_rules(provider.account_name)
    desired = _filter_desired_by_phase(all_desired, phase_filter)
    provider_ids = _phase_filter_to_provider_ids(phase_filter)

    # Determine which secondary fetches are needed before starting phase rules
    custom_rulesets_desired = all_desired.get("custom_rulesets", [])
    lists_desired = all_desired.get("lists")

    if custom_rulesets_desired and not provider_supports(provider, SUPPORTS_CUSTOM_RULESETS):
        log.warning(
            "Skipping custom_rulesets for account %s: provider does not support custom_rulesets",
            provider.account_name,
        )
        custom_rulesets_desired = []
    if lists_desired is not None and not provider_supports(provider, SUPPORTS_LISTS):
        log.warning(
            "Skipping lists for account %s: provider does not support lists",
            provider.account_name,
        )
        lists_desired = None

    bg = None
    cr_future = None
    lists_future = None
    bg_workers = (1 if custom_rulesets_desired else 0) + (1 if lists_desired is not None else 0)
    if bg_workers:
        bg = ThreadPoolExecutor(max_workers=bg_workers)
        if custom_rulesets_desired:
            cr_future = bg.submit(provider.get_all_custom_rulesets, scope)
        if lists_desired is not None:
            lists_future = bg.submit(provider.get_all_lists, scope)

    try:
        try:
            current = provider.get_all_phase_rules(scope, provider_ids=provider_ids)
        except ProviderAuthError:
            raise
        except ProviderError as e:
            log.error(
                "Failed to plan account %s: %s",
                provider.account_name,
                _format_api_error(e),
            )
            return None, {}, {}

        if not desired and not current:
            log.debug("No account rules to manage for %s", provider.account_name)
            return None, {}, {}

        # Exclude failed phases
        failed_phases = getattr(current, "failed_phases", [])
        if failed_phases:
            failed_friendly = {
                PHASE_BY_PROVIDER_ID[p].friendly_name
                for p in failed_phases
                if p in PHASE_BY_PROVIDER_ID
            }
            skipped = failed_friendly & set(desired.keys())
            for name in sorted(skipped):
                log.warning(
                    "Skipping %s for account %s: failed to fetch current state",
                    name,
                    provider.account_name,
                )
            if skipped:
                desired = {k: v for k, v in desired.items() if k not in failed_friendly}

        zp = plan_zone(account_label, desired, current, allow_unmanaged=True)

        # Plan custom rulesets
        if cr_future is not None:
            try:
                custom_rulesets_current = cr_future.result()
            except ProviderAuthError:
                raise
            except ProviderError as e:
                log.warning(
                    "Failed to fetch custom rulesets for account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )
                custom_rulesets_current = {}

            # Re-key by name for diff_custom_rulesets_full
            current_by_name = {
                v.get("name", ""): {"id": k, **v} for k, v in custom_rulesets_current.items()
            }
            cr_plans = diff_custom_rulesets_full(custom_rulesets_desired, current_by_name)
            for crp in cr_plans:
                if crp.has_changes:
                    zp.custom_ruleset_plans.append(crp)

        # Plan lists
        if lists_future is not None:
            try:
                current_lists = lists_future.result()
            except ProviderAuthError:
                raise
            except ProviderError as e:
                log.warning(
                    "Failed to fetch lists for account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )
                current_lists = {}

            list_plans = diff_lists_full(lists_desired, current_lists)
            for lp in list_plans:
                if lp.has_changes:
                    zp.list_plans.append(lp)

        return zp, desired, current
    finally:
        if bg is not None:
            bg.shutdown(wait=True)


class _PlanAllResult:
    """Aggregated result from planning zones and/or account."""

    __slots__ = (
        "zone_plans",
        "desired_by_zone",
        "current_by_zone",
        "failed",
        "scope_map",
        "account_labels",
        "provider_map",
    )

    def __init__(self) -> None:
        self.zone_plans: list[ZonePlan] = []
        self.desired_by_zone: dict[str, dict] = {}
        self.current_by_zone: dict[str, dict] = {}
        self.failed: list[str] = []
        self.scope_map: dict[str, Scope] = {}
        self.account_labels: list[str] = []
        self.provider_map: dict[tuple[str, str | None], BaseProvider] = {}

    @property
    def account_label(self) -> str | None:
        """Backward-compat: return the first account label, or None."""
        return self.account_labels[0] if self.account_labels else None

    def _add_zones(
        self, zp_list: list[ZonePlan], d_by_z: dict, c_by_z: dict, zone_failed: list[str]
    ) -> None:
        self.zone_plans.extend(zp_list)
        self.desired_by_zone.update(d_by_z)
        self.current_by_zone.update(c_by_z)
        self.failed.extend(zone_failed)

    def _add_account(
        self,
        acct_plan: ZonePlan | None,
        acct_desired: dict,
        acct_current: dict,
        provider: BaseProvider,
    ) -> None:
        if acct_plan is not None:
            self.zone_plans.append(acct_plan)
            self.desired_by_zone[acct_plan.plan_key] = acct_desired
            self.current_by_zone[acct_plan.plan_key] = acct_current
            self.account_labels.append(acct_plan.zone_name)
            self.scope_map[acct_plan.zone_name] = Scope(
                account_id=provider.account_id, label=provider.account_name
            )
            self.provider_map[(acct_plan.zone_name, None)] = provider


def _plan_all_scopes(
    config: Config,
    providers: dict[str, BaseProvider] | BaseProvider,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None,
    scope_filter: str = "all",
    executor: ThreadPoolExecutor | None = None,
    processors: dict[str, BaseProcessor] | None = None,
) -> _PlanAllResult:
    """Plan zones and/or account based on scope_filter.

    ``providers`` can be a dict of named providers or a single BaseProvider
    (backward compat).  Runs account planning concurrently with zone planning.
    """
    # Backward compat: single provider → wrap in dict
    if isinstance(providers, dict):
        prov_dict = providers
    else:
        prov_dict = {"_default": providers}

    result = _PlanAllResult()
    do_zones = scope_filter in ("all", "zones")
    do_account = scope_filter in ("all", "account")

    # Build the provider map for zones
    if do_zones:
        zone_names = _get_zones(config, zone_filter)
        for zn in zone_names:
            zone_cfg = config.zones[zn]
            target_pairs = _get_zone_providers(zone_cfg, prov_dict)
            if len(target_pairs) == 1:
                result.provider_map[(zn, None)] = target_pairs[0][1]
            else:
                for target_name, prov in target_pairs:
                    result.provider_map[(zn, target_name)] = prov

    # Collect providers that have account info (for account planning)
    acct_providers = []
    if do_account:
        for prov in prov_dict.values():
            if isinstance(prov.account_id, str) and isinstance(prov.account_name, str):
                acct_providers.append(prov)

    if do_zones and acct_providers:
        with ThreadPoolExecutor(max_workers=len(acct_providers)) as acct_executor:
            acct_futures = [
                acct_executor.submit(_plan_account, config, prov, phase_filter)
                for prov in acct_providers
            ]
            result._add_zones(
                *_plan_zones(config, prov_dict, zone_names, phase_filter, executor, processors)
            )
            for prov, future in zip(acct_providers, acct_futures):
                result._add_account(*future.result(), prov)
    else:
        if do_zones:
            result._add_zones(
                *_plan_zones(config, prov_dict, zone_names, phase_filter, executor, processors)
            )
        for prov in acct_providers:
            result._add_account(*_plan_account(config, prov, phase_filter), prov)

    return result


def _cmd_plan_or_compare(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    checksum: bool = False,
    *,
    changes_exit_code: int = 2,
    scope_filter: str = "all",
) -> int:
    """Shared implementation for plan and compare commands."""
    providers = _init_providers(config)
    processors = _init_processors(config)
    r = _plan_all_scopes(
        config, providers, zone_filter, phase_filter, scope_filter, processors=processors
    )

    if not _emit_plan_outputs(config, r.zone_plans):
        return 1

    if checksum:
        log.info("checksum=%s", compute_checksum(r.zone_plans))

    if r.failed:
        return 1
    has_changes = any(zp.has_changes for zp in r.zone_plans)
    return changes_exit_code if has_changes else 0


def cmd_plan(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    checksum: bool = False,
    exit_code: bool = False,
    scope_filter: str = "all",
) -> int:
    """Run the plan command. Returns 0 by default, or 2 with --exit-code."""
    return _cmd_plan_or_compare(
        config,
        zone_filter,
        phase_filter,
        checksum,
        changes_exit_code=2 if exit_code else 0,
        scope_filter=scope_filter,
    )


def cmd_compare(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    checksum: bool = False,
    scope_filter: str = "all",
) -> int:
    """Run the compare command. Returns 0 if identical, 1 if differences."""
    return _cmd_plan_or_compare(
        config,
        zone_filter,
        phase_filter,
        checksum,
        changes_exit_code=1,
        scope_filter=scope_filter,
    )


def cmd_report(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    report_format: str = "csv",
    scope_filter: str = "all",
) -> int:
    """Run the report command. Returns 0 normally, 1 if any zone failed."""
    providers = _init_providers(config)
    processors = _init_processors(config)
    r = _plan_all_scopes(
        config, providers, zone_filter, phase_filter, scope_filter, processors=processors
    )

    report_data = build_report_data(r.zone_plans, r.desired_by_zone, r.current_by_zone)
    print_report(report_data, fmt=report_format)

    return 1 if r.failed else 0


def _make_account_zone_config(config: Config) -> ZoneConfig:
    """Build a synthetic ZoneConfig with provider-level defaults for account scope."""
    return ZoneConfig(name="__account__")


def _check_safety_violations(
    zone_plans: list[ZonePlan],
    current_by_zone: dict[str, dict],
    config: Config,
    account_labels: list[str] | None = None,
) -> list:
    """Check all zone plans against safety thresholds.

    Returns list of SafetyViolation objects (empty if safe).
    Skips zones with no changes or always_dry_run enabled.
    """
    acct_set = set(account_labels) if account_labels else set()
    violations = []
    for zp in zone_plans:
        if not zp.has_changes:
            continue
        if zp.zone_name in config.zones:
            zone_cfg = config.zones[zp.zone_name]
            if zone_cfg.always_dry_run:
                continue
        elif zp.zone_name in acct_set:
            zone_cfg = _make_account_zone_config(config)
        else:
            continue
        violations.extend(check_safety(zp, current_by_zone[zp.plan_key], zone_cfg))
    return violations


def _log_safety_violations(violations: list) -> None:
    """Log safety threshold violations."""
    log.error("Safety threshold exceeded! Use --force to override.")
    for v in violations:
        phases_str = ", ".join(v.phases) if v.phases else "unknown"
        log.error(
            "  %s: %d %s(s) out of %d existing rules (%.1f%% > %.1f%% threshold) in %s",
            v.zone_name,
            v.count,
            v.kind,
            v.existing,
            v.percentage,
            v.threshold,
            phases_str,
        )


def _apply_custom_rulesets(
    zp: ZonePlan,
    scope: Scope,
    provider: BaseProvider,
) -> tuple[list[str], str | None]:
    """Apply custom ruleset changes. Returns (synced_labels, error_msg).

    Order: creates first, then rule updates, then deletes.
    Each stage is parallelised via ``_apply_parallel``; stages run sequentially
    so that creates complete before rule updates read ``ruleset_id``.
    """
    # Stage 1: Creates (not collected — setup only)
    create_tasks: list[tuple[str, Callable[[], None]]] = []
    for crp in zp.custom_ruleset_plans:
        if not crp.create:
            continue
        label = f"custom_ruleset:{crp.ruleset_name}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: creating rule group", zp.zone_name, label)

        def create_fn(_crp=crp, _label=label) -> None:
            result = provider.create_custom_ruleset(
                scope, _crp.ruleset_name, _crp.phase, _crp.capacity or 0
            )
            _crp.ruleset_id = result.get("id", "")
            log.info("  %s/%s: created (id=%s)", zp.zone_name, _label, _crp.ruleset_id)
            if _crp.prepared_rules:
                provider.put_custom_ruleset(scope, _crp.ruleset_id, _crp.prepared_rules)
                log.info("  %s/%s: rules applied", zp.zone_name, _label)

        create_tasks.append((full_label, create_fn))

    # Stage 2: Rule updates (existing rulesets with changes, not create/delete)
    update_tasks: list[tuple[str, Callable[[], None]]] = []
    for crp in zp.custom_ruleset_plans:
        if crp.create or crp.delete:
            continue
        if not crp.has_changes:
            continue
        label = f"custom_ruleset:{crp.ruleset_name}"
        full_label = f"{zp.zone_name}/{label}"
        n_changes = len(crp.changes)
        log.info("  %s/%s: applying %d change(s)", zp.zone_name, label, n_changes)
        if crp.prepared_rules is None:
            log.warning("  %s/%s: no prepared rules, skipping", zp.zone_name, label)
            continue

        def update_fn(rid=crp.ruleset_id, rules=crp.prepared_rules, _lbl=label) -> None:
            provider.put_custom_ruleset(scope, rid, rules)
            log.info("  %s/%s: done", zp.zone_name, _lbl)

        update_tasks.append((full_label, update_fn))

    # Stage 3: Deletes last
    delete_tasks: list[tuple[str, Callable[[], None]]] = []
    for crp in zp.custom_ruleset_plans:
        if not crp.delete or not crp.ruleset_id:
            continue
        label = f"custom_ruleset:{crp.ruleset_name}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: deleting rule group", zp.zone_name, label)

        def del_fn(_crp=crp, _label=label) -> None:
            provider.delete_custom_ruleset(scope, _crp.ruleset_id)
            log.info("  %s/%s: deleted", zp.zone_name, _label)

        delete_tasks.append((full_label, del_fn))

    return _run_staged_tasks(
        [
            (False, create_tasks),
            (True, update_tasks),
            (True, delete_tasks),
        ],
        provider.max_workers,
    )


def _apply_lists(
    zp: ZonePlan,
    scope: Scope,
    provider: BaseProvider,
) -> tuple[list[str], str | None]:
    """Apply list changes. Returns (synced_labels, error_msg).

    Order: creates first, then item updates, then description updates, then deletes.
    Each stage is parallelised via ``_apply_parallel``; stages run sequentially
    so that creates complete before item updates read ``list_id``.
    """
    # Stage 1: Creates (not collected — setup only)
    create_tasks: _TaskList = []
    for lp in zp.list_plans:
        if not lp.create:
            continue
        label = f"list:{lp.list_name}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: creating list (%s)", zp.zone_name, label, lp.list_kind)

        def create_fn(_lp=lp, _label=label) -> None:
            desc = _lp.description_change[1] if _lp.description_change else ""
            result = provider.create_list(scope, _lp.list_name, _lp.list_kind, desc)
            _lp.list_id = result.get("id", "")
            log.info("  %s/%s: created (id=%s)", zp.zone_name, _label, _lp.list_id)

        create_tasks.append((full_label, create_fn))

    # Stages 2-4 are built lazily because they read list_id values assigned
    # by create tasks in stage 1.

    def _build_item_tasks() -> _TaskList:
        """Stage 2: Item updates."""
        tasks: _TaskList = []
        for lp in zp.list_plans:
            if not lp.changes or not lp.list_id:
                continue
            label = f"list:{lp.list_name}"
            full_label = f"{zp.zone_name}/{label}"
            n_changes = len(lp.changes)
            log.info("  %s/%s: applying %d item change(s)", zp.zone_name, label, n_changes)
            if lp.prepared_items is None:
                log.warning("  %s/%s: no prepared items, skipping", zp.zone_name, label)
                continue

            def item_fn(_lp=lp, _label=label) -> None:
                op_id = provider.put_list_items(scope, _lp.list_id, _lp.prepared_items)
                provider.poll_bulk_operation(scope, op_id)
                log.info("  %s/%s: items updated", zp.zone_name, _label)

            tasks.append((full_label, item_fn))
        return tasks

    def _build_desc_tasks() -> _TaskList:
        """Stage 3: Description updates (skip if create already set it)."""
        tasks: _TaskList = []
        for lp in zp.list_plans:
            if lp.description_change is None or lp.create or lp.delete:
                continue
            if not lp.list_id:
                continue
            label = f"list:{lp.list_name}"
            full_label = f"{zp.zone_name}/{label}"
            _, new_desc = lp.description_change
            log.info("  %s/%s: updating description", zp.zone_name, label)

            def desc_fn(_lp=lp, _new_desc=new_desc, _label=label) -> None:
                provider.update_list_description(scope, _lp.list_id, _new_desc or "")
                log.info("  %s/%s: description updated", zp.zone_name, _label)

            tasks.append((full_label, desc_fn))
        return tasks

    def _build_delete_tasks() -> _TaskList:
        """Stage 4: Deletes last."""
        tasks: _TaskList = []
        for lp in zp.list_plans:
            if not lp.delete or not lp.list_id:
                continue
            label = f"list:{lp.list_name}"
            full_label = f"{zp.zone_name}/{label}"
            log.info("  %s/%s: deleting list", zp.zone_name, label)

            def del_fn(_lp=lp, _label=label) -> None:
                provider.delete_list(scope, _lp.list_id)
                log.info("  %s/%s: deleted", zp.zone_name, _label)

            tasks.append((full_label, del_fn))
        return tasks

    return _run_staged_tasks(
        [
            (False, create_tasks),
            (True, _build_item_tasks),
            (True, _build_desc_tasks),
            (True, _build_delete_tasks),
        ],
        provider.max_workers,
    )


def _apply_single_zone(
    zp: ZonePlan,
    desired: dict,
    scope: Scope,
    provider: BaseProvider,
) -> tuple[str, list[str], str | None]:
    """Apply changes for a single zone. Returns (zone_name, synced_phases, error_msg).

    Phases within a zone are applied in parallel when max_workers > 1.
    ProviderAuthError propagates immediately.
    """
    log.info("Syncing %s", zp.zone_name)

    # Apply lists first (rules reference lists via $list_name)
    all_synced: list[str] = []
    if zp.list_plans:
        list_synced, list_error = _apply_lists(zp, scope, provider)
        all_synced.extend(list_synced)
        if list_error:
            return zp.zone_name, all_synced, list_error

    # Apply extension changes (e.g. Page Shield policies)
    if zp.extension_plans:
        ext_synced, ext_error = call_apply_extensions(zp, scope, provider)
        all_synced.extend(ext_synced)
        if ext_error:
            return zp.zone_name, all_synced, ext_error

    # Apply custom rulesets next (before deploy rules reference them)
    if zp.custom_ruleset_plans:
        cr_synced, cr_error = _apply_custom_rulesets(zp, scope, provider)
        all_synced.extend(cr_synced)
        if cr_error:
            return zp.zone_name, all_synced, cr_error

    phases = zp.phase_plans
    if not phases:
        return zp.zone_name, all_synced, None

    max_w = provider.max_workers

    tasks: list[tuple[str, Callable[[], None]]] = []
    for pp in phases:
        phase = pp.phase
        friendly_name = phase.friendly_name
        full_label = f"{zp.zone_name}/{friendly_name}"
        n_changes = len(pp.changes)
        log.info("  %s/%s: applying %d change(s)", zp.zone_name, friendly_name, n_changes)
        if pp.prepared_rules is not None:
            payload = pp.prepared_rules
        else:
            phase_rules = desired.get(friendly_name, [])
            payload = prepare_desired_rules(phase_rules, phase)

        def fn(_payload=payload, _phase=phase, _label=friendly_name) -> None:
            kw = scope.api_kwargs
            scope_key = next(iter(kw))
            log.debug(
                "  PUT %s %s (%s=%s) rules=%d",
                _phase.provider_id,
                zp.zone_name,
                scope_key,
                kw[scope_key],
                len(_payload),
            )
            provider.put_phase_rules(scope, _phase.provider_id, _payload)
            log.info("  %s/%s: done", zp.zone_name, _label)

        tasks.append((full_label, fn))

    phase_synced, phase_error = _apply_parallel(tasks, max_w)
    all_synced.extend(phase_synced)
    return zp.zone_name, all_synced, phase_error


@dataclass
class SyncResult:
    """Result of a single zone sync operation."""

    zone_name: str
    target: str | None
    synced: list[str]
    error: str | None
    total_changes: int


def _apply_zone_changes(
    actionable: list[ZonePlan],
    desired_by_zone: dict[str, dict],
    config: Config,
    providers: dict[str, BaseProvider],
    scope_map: dict[str, Scope] | None = None,
    provider_map: dict[tuple[str, str | None], BaseProvider] | None = None,
    executor: ThreadPoolExecutor | None = None,
) -> tuple[int, list[SyncResult]]:
    """Apply planned changes to provider. Returns (exit_code, sync_results)."""
    total = len(actionable)
    log.info("Applying changes to %d zone(s)...", total)

    # Build list of (zone_plan, desired, scope, provider) to apply
    to_apply: list[tuple[ZonePlan, dict, Scope, BaseProvider]] = []
    for zp in actionable:
        pmap_key = (zp.zone_name, zp.target)
        if zp.zone_name in config.zones:
            zone_cfg = config.zones[zp.zone_name]
            scope = Scope(zone_id=zone_cfg.zone_id, label=zp.zone_name)
            prov = (
                provider_map[pmap_key]
                if provider_map and pmap_key in provider_map
                else _get_zone_provider(zone_cfg, providers)
            )
        elif scope_map and zp.zone_name in scope_map:
            zone_cfg = _make_account_zone_config(config)
            scope = scope_map[zp.zone_name]
            prov = (
                provider_map[pmap_key]
                if provider_map and pmap_key in provider_map
                else next(iter(providers.values()))
            )
        else:
            log.warning("Skipping %s (no config found)", zp.display_name)
            continue

        if zone_cfg.always_dry_run:
            log.warning("Skipping %s (always_dry_run is enabled)", zp.display_name)
            continue

        to_apply.append((zp, desired_by_zone[zp.plan_key], scope, prov))

    if not to_apply:
        log.info("Done.")
        return 0, []

    # Apply zones in parallel, phases within each zone sequentially
    all_synced: list[str] = []
    had_error = False
    sync_results: list[SyncResult] = []

    def _apply_one(
        item: tuple[ZonePlan, dict, Scope, BaseProvider],
    ) -> tuple[str, list[str], str | None]:
        zp, desired, scope, prov = item
        return _apply_single_zone(zp, desired, scope, prov)

    try:
        results = _map_ordered(_apply_one, to_apply, config.max_workers, executor=executor)
    except ProviderAuthError as e:
        log.error("Authentication/permission error during sync: %s", _format_api_error(e))
        if all_synced:
            log.error("Successfully synced before failure: %s", ", ".join(all_synced))
        return 1, sync_results

    for (zp, _desired, _scope, _prov), (zone_name, synced, error) in zip(to_apply, results):
        all_synced.extend(synced)
        sync_results.append(
            SyncResult(
                zone_name=zone_name,
                target=zp.target,
                synced=synced,
                error=error,
                total_changes=zp.total_changes,
            )
        )
        if error:
            log.error("API error syncing %s: %s", zone_name, error)
            had_error = True

    if had_error:
        if all_synced:
            log.error("Successfully synced before failure: %s", ", ".join(all_synced))
        return 1, sync_results

    log.info("Done.")
    return 0, sync_results


_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")


def cmd_sync(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    checksum: str | None = None,
    force: bool = False,
    scope_filter: str = "all",
    audit_log: str | None = None,
) -> int:
    """Run the sync command. Returns exit code."""
    if checksum is not None and not _CHECKSUM_RE.match(checksum):
        raise ConfigError(
            f"Invalid checksum format: {checksum!r} (expected 64-character hex string)"
        )
    providers = _init_providers(config)
    processors = _init_processors(config)
    # Shared executor reused across plan + apply phases
    shared_ex: ThreadPoolExecutor | None = None
    if config.max_workers > 1:
        shared_ex = ThreadPoolExecutor(max_workers=config.max_workers)
    try:
        return _cmd_sync_inner(
            config,
            providers,
            zone_filter,
            phase_filter,
            checksum,
            force,
            scope_filter,
            shared_ex,
            processors,
            audit_log=audit_log,
        )
    finally:
        if shared_ex is not None:
            shared_ex.shutdown(wait=True)


def _write_audit_log(path: str, results: list[SyncResult]) -> None:
    """Write sync results as JSON lines to an audit log file."""
    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).isoformat()
    try:
        with open(Path(path).resolve(), "w", encoding="utf-8") as f:
            for r in results:
                entry = {
                    "timestamp": ts,
                    "zone": r.zone_name,
                    "target": r.target,
                    "synced": r.synced,
                    "total_changes": r.total_changes,
                    "status": "error" if r.error else "ok",
                    "error": r.error,
                }
                f.write(_json.dumps(entry, separators=(",", ":")) + "\n")
        log.info("Audit log written to %s", path)
    except OSError as e:
        log.error("Failed to write audit log %s: %s", path, e)


def _cmd_sync_inner(
    config: Config,
    providers: dict[str, BaseProvider],
    zone_filter: list[str] | None,
    phase_filter: list[str] | None,
    checksum: str | None,
    force: bool,
    scope_filter: str,
    executor: ThreadPoolExecutor | None,
    processors: dict[str, BaseProcessor] | None = None,
    audit_log: str | None = None,
) -> int:
    """Inner sync logic using an optional shared executor."""
    r = _plan_all_scopes(
        config, providers, zone_filter, phase_filter, scope_filter, executor, processors
    )

    if r.failed:
        log.error("Aborting sync: failed to plan %d zone(s)", len(r.failed))
        return 1

    if not _emit_plan_outputs(config, r.zone_plans):
        return 1

    has_changes = any(zp.has_changes for zp in r.zone_plans)
    if not has_changes:
        return 0

    if checksum:
        actual = compute_checksum(r.zone_plans)
        if actual != checksum:
            log.error("Checksum mismatch: expected %s, got %s", checksum, actual)
            return 1

    if not force:
        violations = _check_safety_violations(
            r.zone_plans, r.current_by_zone, config, account_labels=r.account_labels
        )
        if violations:
            _log_safety_violations(violations)
            return 1

    actionable = [zp for zp in r.zone_plans if zp.has_changes]
    exit_code, sync_results = _apply_zone_changes(
        actionable,
        r.desired_by_zone,
        config,
        providers,
        scope_map=r.scope_map,
        provider_map=r.provider_map,
        executor=executor,
    )
    if audit_log and sync_results:
        _write_audit_log(audit_log, sync_results)
    return exit_code


def cmd_lint(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    lint_format: str = "text",
    lint_severity: str = "info",
    lint_rules: list[str] | None = None,
    lint_plan: str | None = None,
    zone_plans: dict[str, str] | None = None,
    output_file: str | None = None,
    exit_code: bool = False,
) -> int:
    """Lint rules files for errors and warnings. Returns exit code."""
    from octorules.linter.engine import Severity, get_known_rule_ids, lint_zone_file
    from octorules.linter.plugin import get_registered_plugins
    from octorules.linter.report import FORMATTERS
    from octorules.linter.suppressions import parse_suppressions

    known_rules = get_known_rule_ids()

    plugins = get_registered_plugins()
    if plugins:
        log.info("Lint plugins: %s", ", ".join(p.name for p in plugins))
    else:
        log.info("No lint plugins registered (install a provider package for lint rules)")

    severity_map = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}
    severity = severity_map[lint_severity]
    formatter = FORMATTERS[lint_format]

    zone_names = _get_zones(config, zone_filter)
    all_results: list = []
    total_suppressed = 0
    has_errors = False
    has_warnings = False

    for zone_name in zone_names:
        desired = _filter_desired_by_phase(config.load_zone_rules(zone_name), phase_filter)
        if not desired:
            log.info("  %s: no rules file (skipped)", zone_name)
            continue

        rules_file = config.rules_dir / f"{zone_name}.yaml"
        # Resolve plan tier: explicit --plan > API-detected > "enterprise"
        if lint_plan is not None:
            plan_tier = lint_plan
        elif zone_plans and zone_name in zone_plans:
            plan_tier = zone_plans[zone_name]
        else:
            plan_tier = "enterprise"

        suppressions = parse_suppressions(rules_file, known_rules=known_rules)

        ctx = lint_zone_file(
            desired,
            file_path=str(rules_file),
            zone_name=zone_name,
            plan_tier=plan_tier,
            severity_filter=severity,
            phase_filter=phase_filter,
            rule_filter=lint_rules,
            suppressions=suppressions,
        )

        total_suppressed += ctx.suppressed_count

        if ctx.results:
            output = formatter(ctx)
            if output:
                print(output, end="")
            all_results.extend(ctx.results)
            if ctx.has_errors:
                has_errors = True
            if ctx.warnings:
                has_warnings = True
        else:
            log.info("  %s: no issues found", zone_name)

    if output_file and all_results:
        # Re-create a combined context for file output
        from octorules.linter.engine import LintContext

        combined = LintContext(
            file_path=output_file,
            zone_name=", ".join(zone_names),
            plan_tier=lint_plan or "auto",
        )
        combined.results = all_results
        if not _write_output_file(output_file, lambda f: formatter(combined, f)):
            return 1

    # Print summary to stderr so it's always visible regardless of log level
    summary_parts: list[str] = []
    summary_parts.append(f"{len(all_results)} issue(s) found")
    if total_suppressed > 0:
        summary_parts.append(f"{total_suppressed} suppressed")
    print(f"Lint: {', '.join(summary_parts)}.", file=sys.stderr)

    if exit_code:
        if has_errors:
            return 1
        if has_warnings:
            return 2
    elif has_errors:
        return 1
    return 0


def cmd_validate(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    output_file: str | None = None,
) -> int:
    """Validate config and rules files offline (no API calls). Returns exit code."""
    zone_names = _get_zones(config, zone_filter)
    errors: list[str] = []
    validated_count = 0
    lines: list[str] = []

    for zone_name in zone_names:
        desired = _filter_desired_by_phase(config.load_zone_rules(zone_name), phase_filter)
        if not desired:
            msg = f"{zone_name}: no rules file (skipped)"
            log.info("%s", msg)
            lines.append(msg)
            continue

        warn_unknown_phase_keys(desired, zone_name)

        for friendly_name, rules in desired.items():
            if friendly_name in KNOWN_NON_PHASE_KEYS:
                continue  # validated separately below
            try:
                phase = get_phase(friendly_name)
            except KeyError:
                continue  # already warned by warn_unknown_phase_keys
            try:
                prepare_desired_rules(rules, phase)
                msg = f"  {zone_name}/{friendly_name}: OK ({len(rules)} rule(s))"
                log.info("%s", msg)
                lines.append(msg)
                validated_count += 1
            except (RuleValidationError, ValueError, KeyError, TypeError) as e:
                msg = f"  {zone_name}/{friendly_name}: {e}"
                errors.append(msg)

        # Validate custom_rulesets entries
        custom_rulesets = desired.get("custom_rulesets", [])
        if isinstance(custom_rulesets, list):
            for i, entry in enumerate(custom_rulesets):
                try:
                    validate_custom_ruleset(entry, i)
                    rs_name = entry.get("name", entry.get("id", f"index {i}"))
                    n_rules = len(entry.get("rules", []))
                    msg = f"  {zone_name}/custom_ruleset:{rs_name}: OK ({n_rules} rule(s))"
                    log.info("%s", msg)
                    lines.append(msg)
                    validated_count += 1
                except RuleValidationError as e:
                    msg = f"  {zone_name}/custom_rulesets: {e}"
                    errors.append(msg)

        # Validate lists entries
        lists_entries = desired.get("lists")
        if isinstance(lists_entries, list):
            for i, entry in enumerate(lists_entries):
                try:
                    validate_list_entry(entry, i)
                    list_name = entry.get("name", f"index {i}")
                    n_items = len(entry.get("items", []))
                    msg = f"  {zone_name}/list:{list_name}: OK ({n_items} item(s))"
                    log.info("%s", msg)
                    lines.append(msg)
                    validated_count += 1
                except RuleValidationError as e:
                    msg = f"  {zone_name}/lists: {e}"
                    errors.append(msg)

        # Validate extension entries (e.g. page_shield_policies)
        pre_lines = len(lines)
        call_validate_extensions(desired, zone_name, errors, lines)
        validated_count += len(lines) - pre_lines

    if errors:
        log.error("Validation errors:")
        for err in errors:
            log.error("%s", err)
            lines.append(f"ERROR: {err}")
    elif validated_count == 0:
        log.warning("No rules found to validate")
        lines.append("No rules found to validate")
    else:
        log.info("All rules valid.")
        lines.append("All rules valid.")

    if output_file:
        if not _write_output_file(output_file, lambda f: f.write("\n".join(lines) + "\n")):
            return 1

    if errors:
        return 1
    return 0


def cmd_dump(
    config: Config,
    zone_filter: list[str] | None,
    output_dir: str | None,
    scope_filter: str = "all",
    phase_filter: list[str] | None = None,
) -> int:
    """Run the dump command. Returns exit code."""
    providers = _init_providers(config)
    out_dir = Path(output_dir) if output_dir else config.rules_dir
    lists_dir = out_dir / "custom_lists" if output_dir else config.lists_dir
    provider_ids = _phase_filter_to_provider_ids(phase_filter)
    had_errors = False
    do_zones = scope_filter in ("all", "zones")

    # Collect providers that have account info
    acct_providers = [
        prov
        for prov in providers.values()
        if isinstance(prov.account_id, str) and isinstance(prov.account_name, str)
    ]
    do_account = scope_filter in ("all", "account") and bool(acct_providers)

    def _fetch_and_dump(zone_name: str) -> tuple[str, Path | None, str | None]:
        zone_cfg = config.zones[zone_name]
        provider = _get_zone_provider(zone_cfg, providers)
        scope = Scope(zone_id=zone_cfg.zone_id, label=zone_name)

        try:
            rules = provider.get_all_phase_rules(scope, provider_ids=provider_ids)
        except ProviderAuthError:
            raise
        except ProviderError as e:
            return zone_name, None, _format_api_error(e)

        # Call extension dump hooks (e.g. Page Shield)
        ext_data = call_dump_extensions(scope, provider, out_dir)

        result = dump_zone_rules(
            zone_name,
            rules,
            out_dir,
            lists_dir=lists_dir,
            **ext_data,
        )
        return zone_name, result, None

    def _dump_account(provider: BaseProvider) -> tuple[bool, str | None]:
        account_label = slugify(provider.account_name)
        scope = Scope(account_id=provider.account_id, label=provider.account_name)

        supports_cr = provider_supports(provider, SUPPORTS_CUSTOM_RULESETS)
        supports_lists = provider_supports(provider, SUPPORTS_LISTS)

        # Start secondary fetches concurrently with phase rules
        bg_workers = (1 if supports_cr else 0) + (1 if supports_lists else 0)
        cr_future = None
        lists_future = None
        bg = ThreadPoolExecutor(max_workers=max(bg_workers, 1))

        try:
            if supports_cr:
                cr_future = bg.submit(provider.get_all_custom_rulesets, scope)
            if supports_lists:
                lists_future = bg.submit(provider.get_all_lists, scope)

            try:
                rules = provider.get_all_phase_rules(scope, provider_ids=provider_ids)
            except ProviderAuthError:
                raise
            except ProviderError as e:
                log.error(
                    "Failed to dump account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )
                return True, None

            # Fetch custom rulesets
            custom_rulesets: dict[str, dict] | None = None
            if cr_future is not None:
                try:
                    custom_rulesets = cr_future.result() or None
                except ProviderAuthError:
                    raise
                except ProviderError as e:
                    log.warning(
                        "Failed to fetch custom rulesets for account %s: %s",
                        provider.account_name,
                        _format_api_error(e),
                    )

            # Fetch lists
            lists: dict[str, dict] | None = None
            if lists_future is not None:
                try:
                    lists = lists_future.result() or None
                except ProviderAuthError:
                    raise
                except ProviderError as e:
                    log.warning(
                        "Failed to fetch lists for account %s: %s",
                        provider.account_name,
                        _format_api_error(e),
                    )

            # Call extension dump hooks (e.g. Page Shield)
            ext_data = call_dump_extensions(scope, provider, out_dir)

            result = dump_zone_rules(
                account_label,
                rules,
                out_dir,
                custom_rulesets=custom_rulesets,
                lists=lists,
                lists_dir=lists_dir,
                **ext_data,
            )
            if result:
                log.info("Dumped account %s -> %s", provider.account_name, result)
            return False, result
        finally:
            bg.shutdown(wait=True)

    if do_zones and do_account:
        # Run account dumps concurrently with zone dumps
        with ThreadPoolExecutor(max_workers=len(acct_providers)) as acct_executor:
            acct_futures = [acct_executor.submit(_dump_account, prov) for prov in acct_providers]
            zone_names = _get_zones(config, zone_filter)
            results = _map_ordered(_fetch_and_dump, zone_names, config.max_workers)
            for zone_name, result, error in results:
                if error:
                    log.error("Failed to dump %s: %s", zone_name, error)
                    had_errors = True
                elif result:
                    log.info("Dumped %s -> %s", zone_name, result)
            for future in acct_futures:
                acct_error, _ = future.result()
                if acct_error:
                    had_errors = True
    else:
        if do_zones:
            zone_names = _get_zones(config, zone_filter)
            results = _map_ordered(_fetch_and_dump, zone_names, config.max_workers)
            for zone_name, result, error in results:
                if error:
                    log.error("Failed to dump %s: %s", zone_name, error)
                    had_errors = True
                elif result:
                    log.info("Dumped %s -> %s", zone_name, result)
        if do_account:
            for prov in acct_providers:
                acct_error, _ = _dump_account(prov)
                if acct_error:
                    had_errors = True

    return 1 if had_errors else 0


def cmd_versions() -> int:
    """Print versions of octorules and key dependencies. Returns exit code."""
    import platform
    from importlib.metadata import PackageNotFoundError, packages_distributions, version

    # Discover installed octorules provider/extension packages
    extras: list[tuple[str, str]] = []
    for pkg_name in sorted(packages_distributions()):
        if pkg_name.startswith("octorules_"):
            try:
                label = pkg_name.replace("_", "-")
                extras.append((label, version(label)))
            except PackageNotFoundError:
                pass

    # Compute column width from all labels
    labels = [("octorules", __version__), *extras]
    try:
        import yaml

        labels.append(("pyyaml", yaml.__version__))
    except (ImportError, AttributeError):
        labels.append(("pyyaml", "(not installed)"))
    labels.append(("python", platform.python_version()))

    width = max(len(name) for name, _ in labels) + 2
    for name, ver in labels:
        print(f"{name:<{width}s}{ver}")
    return 0
