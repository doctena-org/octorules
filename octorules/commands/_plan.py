"""Planning pipeline and plan/compare/report commands."""

import logging
from concurrent.futures import ThreadPoolExecutor

import octorules.commands._helpers as _helpers_mod
import octorules.commands._providers as _providers_mod
from octorules.commands._helpers import (
    _FEATURE_KEYS,
    _FUTURE_TIMEOUT,
    _emit_plan_outputs,
    _filter_desired_by_phase,
    _format_api_error,
    _phase_filter_to_provider_ids,
)
from octorules.commands._providers import (
    _get_zone_providers,
)
from octorules.config import Config, ConfigError, slugify
from octorules.extensions import (
    call_plan_zone_finalize,
    call_plan_zone_prefetch,
)
from octorules.formatter import build_report_data, print_report
from octorules.phases import PHASE_BY_PROVIDER_ID
from octorules.planner import (
    ZonePlan,
    compute_checksum,
    diff_custom_rulesets_full,
    diff_lists_full,
    filter_by_target,
    plan_zone,
)
from octorules.processor import BaseProcessor
from octorules.provider.base import (
    SUPPORTS_CUSTOM_RULESETS,
    SUPPORTS_LISTS,
    BaseProvider,
    Scope,
    provider_supports,
)
from octorules.provider.exceptions import (
    ProviderAuthError,
    ProviderError,
)

log = logging.getLogger(__name__)


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
            hook = getattr(processors[proc_name], "process_desired", None)
            if hook is not None:
                result = hook(zone_name, desired, provider)
                if not isinstance(result, dict):
                    raise ConfigError(
                        f"Processor {proc_name!r}.process_desired() returned "
                        f"{type(result).__name__}, expected dict"
                    )
                desired = result

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
            hook = getattr(processors[proc_name], "process_changes", None)
            if hook is not None:
                result = hook(zone_name, zp, provider)
                if not isinstance(result, ZonePlan):
                    raise ConfigError(
                        f"Processor {proc_name!r}.process_changes() returned "
                        f"{type(result).__name__}, expected ZonePlan"
                    )
                zp = result

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

    log.info("Planning %d zone(s)...", len(zone_names), extra={"color": "header"})

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
            _name, zp, _desired, _current = result
            zp.target = target
        return result

    results = _helpers_mod._map_ordered(
        _plan_one,
        work_items,
        config.max_workers,
        executor=executor,
    )

    for item, result in zip(work_items, results, strict=True):
        zn = item[0]
        if result is None:
            if zn not in failed_zones:
                failed_zones.append(zn)
        else:
            _name, zp, desired, current = result
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
                custom_rulesets_current = cr_future.result(timeout=_FUTURE_TIMEOUT)
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
                current_lists = lists_future.result(timeout=_FUTURE_TIMEOUT)
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
        "account_labels",
        "current_by_zone",
        "desired_by_zone",
        "failed",
        "provider_map",
        "scope_map",
        "zone_plans",
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
    # Backward compat: single provider -> wrap in dict
    if isinstance(providers, dict):
        prov_dict = providers
    else:
        prov_dict = {"_default": providers}

    result = _PlanAllResult()
    do_zones = scope_filter in ("all", "zones")
    do_account = scope_filter in ("all", "account")

    # Build the provider map for zones
    if do_zones:
        zone_names = _helpers_mod._get_zones(config, zone_filter)
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
            for prov, future in zip(acct_providers, acct_futures, strict=True):
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
    config.resolve_secrets()
    providers = _providers_mod._init_providers(config)
    processors = _providers_mod._init_processors(config)
    r = _plan_all_scopes(
        config, providers, zone_filter, phase_filter, scope_filter, processors=processors
    )

    if not _emit_plan_outputs(config, r.zone_plans):
        return 1

    # Rule count context: how many total rules exist vs how many changed.
    total_changes = sum(zp.total_changes for zp in r.zone_plans)
    if total_changes > 0:
        total_rules = sum(
            len(rules)
            for desired in r.desired_by_zone.values()
            for rules in desired.values()
            if isinstance(rules, list)
        )
        if total_rules > total_changes:
            log.info(
                "%d of %d rule(s) changed, %d unchanged.",
                total_changes,
                total_rules,
                total_rules - total_changes,
            )

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
    config.resolve_secrets()
    providers = _providers_mod._init_providers(config)
    processors = _providers_mod._init_processors(config)
    r = _plan_all_scopes(
        config, providers, zone_filter, phase_filter, scope_filter, processors=processors
    )

    report_data = build_report_data(r.zone_plans, r.desired_by_zone, r.current_by_zone)
    print_report(report_data, fmt=report_format)

    return 1 if r.failed else 0
