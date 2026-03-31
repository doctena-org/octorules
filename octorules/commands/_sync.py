"""Safety checks, apply pipeline, and sync command."""

from __future__ import annotations

import json as _json
import logging
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import octorules.commands._helpers as _helpers_mod
import octorules.commands._providers as _providers_mod
from octorules.commands._helpers import (
    _apply_parallel,
    _emit_plan_outputs,
    _format_api_error,
    _run_staged_tasks,
    _TaskList,
)
from octorules.commands._plan import _plan_all_scopes
from octorules.commands._providers import _get_zone_provider
from octorules.config import Config, ConfigError, ZoneConfig
from octorules.extensions import call_apply_extensions
from octorules.planner import (
    ZonePlan,
    check_safety,
    compute_checksum,
    prepare_desired_rules,
)
from octorules.processor import BaseProcessor
from octorules.provider.base import BaseProvider, Scope
from octorules.provider.exceptions import (
    ProviderAuthError,
)

log = logging.getLogger(__name__)

_CHECKSUM_RE = re.compile(r"^[0-9a-f]{64}$")


def _make_account_zone_config(config: Config) -> ZoneConfig:
    """Build a synthetic ZoneConfig with provider-level defaults for account scope.

    Uses the first provider's safety thresholds instead of ZoneConfig defaults,
    so that provider-level ``safety`` settings are respected for account-scoped
    syncs.
    """
    if config.providers:
        prov_cfg = next(iter(config.providers.values()))
        return ZoneConfig(
            name="__account__",
            delete_threshold=prov_cfg.delete_threshold,
            update_threshold=prov_cfg.update_threshold,
            min_existing=prov_cfg.min_existing,
        )
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
    # Stage 1: Creates (not collected -- setup only)
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
    # Stage 1: Creates (not collected -- setup only)
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
        results = _helpers_mod._map_ordered(
            _apply_one, to_apply, config.max_workers, executor=executor
        )
    except ProviderAuthError as e:
        log.error("Authentication/permission error during sync: %s", _format_api_error(e))
        if all_synced:
            log.error("Successfully synced before failure: %s", ", ".join(all_synced))
        return 1, sync_results

    for (zp, _desired, _scope, _prov), (zone_name, synced, error) in zip(
        to_apply, results, strict=True
    ):
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
    config.resolve_secrets()
    providers = _providers_mod._init_providers(config)
    processors = _providers_mod._init_processors(config)
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
