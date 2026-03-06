"""CLI entry point: plan, sync, dump, validate, versions."""

from __future__ import annotations

import argparse
import logging
import sys
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import IO

from cloudflare import (
    APIConnectionError,
    APIError,
    AuthenticationError,
    PermissionDeniedError,
)

from octorules import __version__
from octorules.config import Config, ConfigError, ZoneConfig, resolve_zone_ids, slugify
from octorules.dumper import dump_zone_rules
from octorules.formatter import build_report_data, print_report
from octorules.phases import (
    KNOWN_NON_PHASE_KEYS,
    PHASE_BY_CF,
    PHASE_BY_NAME,
    get_phase,
    unknown_phase_message,
)
from octorules.plan_output import PlanText
from octorules.planner import (
    RuleValidationError,
    ZonePlan,
    check_safety,
    compute_checksum,
    diff_custom_ruleset,
    diff_lists_full,
    diff_page_shield_policies,
    plan_zone,
    prepare_desired_rules,
    validate_custom_ruleset,
    validate_list_entry,
    validate_page_shield_policy,
    warn_unknown_phase_keys,
)
from octorules.provider import CloudflareProvider, Scope

log = logging.getLogger("octorules")


def _init_provider(config: Config) -> CloudflareProvider:
    """Create a CloudflareProvider from config and resolve missing zone IDs."""
    provider = CloudflareProvider(
        config.token,
        max_retries=config.max_retries,
        timeout=config.timeout,
        max_workers=config.max_workers,
    )
    resolve_zone_ids(config, provider.resolve_zone_id)
    return provider


def build_parser() -> argparse.ArgumentParser:
    # Shared parent parser: allows global flags both before and after the subcommand.
    # Uses SUPPRESS defaults so subparser values don't overwrite the main parser's.
    shared = argparse.ArgumentParser(add_help=False)
    shared.add_argument("--config", default=argparse.SUPPRESS)
    shared.add_argument("--zone", action="append", dest="zones", default=argparse.SUPPRESS)
    shared.add_argument("--phase", action="append", dest="phases", default=argparse.SUPPRESS)
    shared.add_argument("--scope", choices=["all", "zones", "account"], default=argparse.SUPPRESS)
    shared.add_argument("--debug", action="store_true", default=argparse.SUPPRESS)
    shared.add_argument("--quiet", action="store_true", default=argparse.SUPPRESS)

    parser = argparse.ArgumentParser(
        prog="octorules",
        description="Manage Cloudflare Rules as IaC",
    )
    parser.add_argument("--version", action="version", version=f"octorules {__version__}")
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)",
    )
    parser.add_argument(
        "--zone",
        action="append",
        dest="zones",
        help="Process only specified zone(s); can be repeated (default: all zones)",
    )

    parser.add_argument(
        "--phase",
        action="append",
        dest="phases",
        help=(
            "Only process specified phase(s); can be repeated"
            " (e.g. --phase redirect_rules --phase cache_rules)."
            " Also limits API calls to matching phases."
        ),
    )

    parser.add_argument(
        "--scope",
        choices=["all", "zones", "account"],
        default="all",
        help="Process zones only, account only, or both (default: all)",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Only show errors",
    )

    sub = parser.add_subparsers(dest="command")

    plan_parser = sub.add_parser("plan", parents=[shared], help="Show planned changes (dry-run)")
    plan_parser.add_argument(
        "--checksum",
        action="store_true",
        help="Print a SHA-256 checksum of the plan",
    )
    plan_parser.add_argument(
        "--exit-code",
        action="store_true",
        help="Exit with 2 when changes are detected (useful for CI)",
    )

    sync_parser = sub.add_parser("sync", parents=[shared], help="Apply changes to Cloudflare")
    sync_parser.add_argument(
        "--doit",
        action="store_true",
        required=True,
        help="Confirm that changes should be applied",
    )
    sync_parser.add_argument(
        "--checksum",
        metavar="HASH",
        help="Verify plan checksum before applying",
    )
    sync_parser.add_argument(
        "--force",
        action="store_true",
        help="Bypass safety threshold checks",
    )

    validate_parser = sub.add_parser(
        "validate", parents=[shared], help="Validate config and rules files (offline)"
    )
    validate_parser.add_argument(
        "--output",
        dest="validate_output",
        help="Write validation results to a file",
    )

    dump_parser = sub.add_parser(
        "dump", parents=[shared], help="Export existing Cloudflare rules to YAML"
    )
    dump_parser.add_argument(
        "--output-dir",
        help="Output directory for dumped rules (default: rules_dir from config)",
    )

    compare_parser = sub.add_parser(
        "compare", parents=[shared], help="Compare local rules against live Cloudflare state"
    )
    compare_parser.add_argument(
        "--checksum",
        action="store_true",
        help="Print a SHA-256 checksum of the comparison plan",
    )

    report_parser = sub.add_parser(
        "report", parents=[shared], help="Drift report: deployed vs YAML source of truth"
    )
    report_parser.add_argument(
        "--output-format",
        choices=["csv", "json"],
        default="csv",
        dest="report_format",
        help="Report output format (default: csv)",
    )

    lint_parser = sub.add_parser(
        "lint", parents=[shared], help="Lint rules files for errors and warnings"
    )
    lint_parser.add_argument(
        "--format",
        dest="lint_format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    lint_parser.add_argument(
        "--severity",
        dest="lint_severity",
        choices=["error", "warning", "info"],
        default="info",
        help="Minimum severity to report (default: info)",
    )
    lint_parser.add_argument(
        "--rule",
        action="append",
        dest="lint_rules",
        help="Only check specific rule ID(s); can be repeated",
    )
    lint_parser.add_argument(
        "--plan",
        dest="lint_plan",
        choices=["free", "pro", "business", "enterprise"],
        default=None,
        help="Cloudflare plan tier override for entitlement checks. "
        "When omitted, auto-detected from the Cloudflare API per zone.",
    )
    lint_parser.add_argument(
        "--output",
        dest="lint_output",
        help="Write lint results to a file",
    )
    lint_parser.add_argument(
        "--exit-code",
        action="store_true",
        dest="lint_exit_code",
        help="Exit with 1 when errors are found, 2 when warnings are found (useful for CI)",
    )

    sub.add_parser("versions", parents=[shared], help="Show versions of octorules and dependencies")

    # Provide defaults for subcommand-specific attributes so getattr is never needed
    parser.set_defaults(
        checksum=False,
        force=False,
        validate_output=None,
        output_dir=None,
        report_format="csv",
        scope="all",
        lint_format="text",
        lint_severity="info",
        lint_rules=None,
        lint_plan="enterprise",
        lint_output=None,
        lint_exit_code=False,
    )

    return parser


def _get_zones(config: Config, zone_filter: list[str] | None) -> list[str]:
    """Return the list of zone names to process. Raises ConfigError if filter is invalid."""
    if zone_filter:
        for zone in zone_filter:
            if zone not in config.zones:
                raise ConfigError(f"Zone {zone!r} not found in config")
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
    desired: dict[str, list[dict]], phases: list[str] | None
) -> dict[str, list[dict]]:
    """Filter desired rules dict to only include specified phases."""
    if phases is None:
        return desired
    return {k: v for k, v in desired.items() if k in phases}


def _filter_current_by_phase(
    current: dict[str, list[dict]], phases: list[str] | None
) -> dict[str, list[dict]]:
    """Filter current rules dict to only include phases matching the friendly names."""
    if phases is None:
        return current
    allowed_cf_phases = {PHASE_BY_NAME[p].cf_phase for p in phases if p in PHASE_BY_NAME}
    return {k: v for k, v in current.items() if k in allowed_cf_phases}


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


def _phase_filter_to_cf_phases(phase_filter: list[str] | None) -> list[str] | None:
    """Convert friendly phase names to CF phase identifiers for API filtering."""
    if phase_filter is None:
        return None
    return [PHASE_BY_NAME[p].cf_phase for p in phase_filter if p in PHASE_BY_NAME]


def _format_api_error(e: APIError | APIConnectionError) -> str:
    """Format an API error, including the HTTP status code when available."""
    if hasattr(e, "status_code"):
        return f"[HTTP {e.status_code}] {e}"
    return str(e)


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

    * ``AuthenticationError`` / ``PermissionDeniedError`` → cancel remaining,
      re-raise.
    * First ``APIError`` / ``APIConnectionError`` / ``TimeoutError`` → record
      error; in the parallel path remaining in-flight tasks still finish so we
      collect as many successes as possible.  In the sequential path we stop
      immediately (matching the original serial behaviour).
    """
    if not tasks:
        return [], None

    def _run_one(label: str, fn: Callable[[], None]) -> tuple[str, str | None]:
        try:
            fn()
        except (AuthenticationError, PermissionDeniedError):
            raise
        except (APIError, APIConnectionError) as e:
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
            except (AuthenticationError, PermissionDeniedError):
                for f in futures:
                    f.cancel()
                raise
            if error:
                if first_error is None:
                    first_error = f"{label}: {error}"
            else:
                successes.append(label)
    return successes, first_error


def _plan_single_zone(
    config: Config,
    provider: CloudflareProvider,
    zone_name: str,
    phase_filter: list[str] | None,
) -> tuple[str, ZonePlan, dict, dict]:
    """Plan a single zone. Returns (zone_name, zone_plan, desired, current)."""
    zone_cfg = config.zones[zone_name]
    scope = Scope(zone_id=zone_cfg.zone_id, label=zone_name)
    all_desired = config.load_zone_rules(zone_name)
    desired = _filter_desired_by_phase(all_desired, phase_filter)
    cf_phases = _phase_filter_to_cf_phases(phase_filter)

    # Start page shield fetch concurrently with phase rules
    ps_desired = all_desired.get("page_shield_policies")
    ps_future = None
    bg = None
    if ps_desired is not None:
        bg = ThreadPoolExecutor(max_workers=1)
        ps_future = bg.submit(provider.get_all_page_shield_policies, scope)

    try:
        current = provider.get_all_phase_rules(scope, cf_phases=cf_phases)

        # Exclude phases that failed to fetch — planning against missing data
        # would incorrectly treat all existing rules as deletions.
        failed_phases = getattr(current, "failed_phases", [])
        if failed_phases:
            failed_friendly = {
                PHASE_BY_CF[cf].friendly_name for cf in failed_phases if cf in PHASE_BY_CF
            }
            skipped = failed_friendly & set(desired.keys())
            for name in sorted(skipped):
                log.warning("Skipping %s for %s: failed to fetch current state", name, zone_name)
            if skipped:
                desired = {k: v for k, v in desired.items() if k not in failed_friendly}

        zp = plan_zone(zone_name, desired, current, allow_unmanaged=zone_cfg.allow_unmanaged)

        # Plan Page Shield policies
        if ps_future is not None:
            try:
                current_policies = ps_future.result()
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                log.warning(
                    "Failed to fetch Page Shield policies for %s: %s",
                    zone_name,
                    _format_api_error(e),
                )
                current_policies = []

            policy_plans = diff_page_shield_policies(ps_desired, current_policies)
            for pp in policy_plans:
                if pp.has_changes:
                    zp.page_shield_policy_plans.append(pp)

        return (zone_name, zp, desired, current)
    finally:
        if bg is not None:
            bg.shutdown(wait=True)


def _plan_single_zone_safe(
    config: Config,
    provider: CloudflareProvider,
    zone_name: str,
    phase_filter: list[str] | None,
) -> tuple[str, ZonePlan, dict, dict] | None:
    """Plan a single zone, returning None on transient API errors.

    AuthenticationError and PermissionDeniedError propagate immediately
    (these are permanent and indicate a bad token or missing permissions).
    """
    try:
        return _plan_single_zone(config, provider, zone_name, phase_filter)
    except (AuthenticationError, PermissionDeniedError):
        raise
    except (APIError, APIConnectionError) as e:
        log.error("Failed to plan %s: %s", zone_name, _format_api_error(e))
        return None


def _plan_zones(
    config: Config,
    provider: CloudflareProvider,
    zone_names: list[str],
    phase_filter: list[str] | None,
    executor: ThreadPoolExecutor | None = None,
) -> tuple[list[ZonePlan], dict[str, dict], dict[str, dict], list[str]]:
    """Plan all zones, optionally in parallel.

    Returns (zone_plans, desired_by_zone, current_by_zone, failed_zones).
    """
    zone_plans: list[ZonePlan] = []
    desired_by_zone: dict[str, dict] = {}
    current_by_zone: dict[str, dict] = {}
    failed_zones: list[str] = []

    results = _map_ordered(
        lambda zn: _plan_single_zone_safe(config, provider, zn, phase_filter),
        zone_names,
        config.max_workers,
        executor=executor,
    )

    for zone_name, result in zip(zone_names, results):
        if result is None:
            failed_zones.append(zone_name)
        else:
            name, zp, desired, current = result
            zone_plans.append(zp)
            desired_by_zone[name] = desired
            current_by_zone[name] = current

    return zone_plans, desired_by_zone, current_by_zone, failed_zones


def _plan_account(
    config: Config,
    provider: CloudflareProvider,
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
    cf_phases = _phase_filter_to_cf_phases(phase_filter)

    # Determine which secondary fetches are needed before starting phase rules
    custom_rulesets_desired = all_desired.get("custom_rulesets", [])
    lists_desired = all_desired.get("lists")

    bg = None
    cr_future = None
    lists_future = None
    bg_workers = (1 if custom_rulesets_desired else 0) + (1 if lists_desired is not None else 0)
    if bg_workers:
        bg = ThreadPoolExecutor(max_workers=bg_workers)
        if custom_rulesets_desired:
            desired_ids = [entry["id"] for entry in custom_rulesets_desired if "id" in entry]
            cr_future = bg.submit(provider.get_all_custom_rulesets, scope, ruleset_ids=desired_ids)
        if lists_desired is not None:
            lists_future = bg.submit(provider.get_all_lists, scope)

    try:
        try:
            current = provider.get_all_phase_rules(scope, cf_phases=cf_phases)
        except (AuthenticationError, PermissionDeniedError):
            raise
        except (APIError, APIConnectionError) as e:
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
                PHASE_BY_CF[cf].friendly_name for cf in failed_phases if cf in PHASE_BY_CF
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
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                log.warning(
                    "Failed to fetch custom rulesets for account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )
                custom_rulesets_current = {}

            for entry in custom_rulesets_desired:
                rs_id = entry.get("id", "")
                rs_name = entry.get("name", "")
                rs_phase = entry.get("phase", "")
                desired_rules = entry.get("rules", [])
                current_data = custom_rulesets_current.get(rs_id, {})
                current_rules = current_data.get("rules", [])
                crp = diff_custom_ruleset(rs_id, rs_name, rs_phase, desired_rules, current_rules)
                if crp.has_changes:
                    zp.custom_ruleset_plans.append(crp)

        # Plan lists
        if lists_future is not None:
            try:
                current_lists = lists_future.result()
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
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
    provider = _init_provider(config)
    failed: list[str] = []

    zone_plans: list[ZonePlan] = []
    do_zones = scope_filter in ("all", "zones")
    do_account = scope_filter in ("all", "account")

    if do_zones and do_account:
        # Run account planning concurrently with zone planning
        with ThreadPoolExecutor(max_workers=1) as acct_executor:
            acct_future = acct_executor.submit(_plan_account, config, provider, phase_filter)
            zone_names = _get_zones(config, zone_filter)
            zp_list, _, _, zone_failed = _plan_zones(config, provider, zone_names, phase_filter)
            zone_plans.extend(zp_list)
            failed.extend(zone_failed)
            acct_plan, _, _ = acct_future.result()
            if acct_plan is not None:
                zone_plans.append(acct_plan)
    else:
        if do_zones:
            zone_names = _get_zones(config, zone_filter)
            zp_list, _, _, zone_failed = _plan_zones(config, provider, zone_names, phase_filter)
            zone_plans.extend(zp_list)
            failed.extend(zone_failed)
        if do_account:
            acct_plan, _, _ = _plan_account(config, provider, phase_filter)
            if acct_plan is not None:
                zone_plans.append(acct_plan)

    if not _emit_plan_outputs(config, zone_plans):
        return 1

    if checksum:
        log.info("checksum=%s", compute_checksum(zone_plans))

    if failed:
        return 1
    has_changes = any(zp.has_changes for zp in zone_plans)
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
    provider = _init_provider(config)
    failed: list[str] = []

    zone_plans: list[ZonePlan] = []
    desired_by_zone: dict[str, dict] = {}
    current_by_zone: dict[str, dict] = {}

    do_zones = scope_filter in ("all", "zones")
    do_account = scope_filter in ("all", "account")

    def _collect_account(acct_plan, acct_desired, acct_current):
        if acct_plan is not None:
            zone_plans.append(acct_plan)
            desired_by_zone[acct_plan.zone_name] = acct_desired
            current_by_zone[acct_plan.zone_name] = acct_current

    if do_zones and do_account:
        with ThreadPoolExecutor(max_workers=1) as acct_executor:
            acct_future = acct_executor.submit(_plan_account, config, provider, phase_filter)
            zone_names = _get_zones(config, zone_filter)
            zp_list, d_by_z, c_by_z, zone_failed = _plan_zones(
                config, provider, zone_names, phase_filter
            )
            zone_plans.extend(zp_list)
            desired_by_zone.update(d_by_z)
            current_by_zone.update(c_by_z)
            failed.extend(zone_failed)
            _collect_account(*acct_future.result())
    else:
        if do_zones:
            zone_names = _get_zones(config, zone_filter)
            zp_list, d_by_z, c_by_z, zone_failed = _plan_zones(
                config, provider, zone_names, phase_filter
            )
            zone_plans.extend(zp_list)
            desired_by_zone.update(d_by_z)
            current_by_zone.update(c_by_z)
            failed.extend(zone_failed)
        if do_account:
            _collect_account(*_plan_account(config, provider, phase_filter))

    report_data = build_report_data(zone_plans, desired_by_zone, current_by_zone)
    print_report(report_data, fmt=report_format)

    return 1 if failed else 0


def _make_account_zone_config(config: Config) -> ZoneConfig:
    """Build a synthetic ZoneConfig with provider-level defaults for account scope."""
    return ZoneConfig(name="__account__")


def _check_safety_violations(
    zone_plans: list[ZonePlan],
    current_by_zone: dict[str, dict],
    config: Config,
    account_label: str | None = None,
) -> list:
    """Check all zone plans against safety thresholds.

    Returns list of SafetyViolation objects (empty if safe).
    Skips zones with no changes or always_dry_run enabled.
    """
    violations = []
    for zp in zone_plans:
        if not zp.has_changes:
            continue
        if zp.zone_name in config.zones:
            zone_cfg = config.zones[zp.zone_name]
            if zone_cfg.always_dry_run:
                continue
        elif account_label and zp.zone_name == account_label:
            zone_cfg = _make_account_zone_config(config)
        else:
            continue
        violations.extend(check_safety(zp, current_by_zone[zp.zone_name], zone_cfg))
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
    provider: CloudflareProvider,
) -> tuple[list[str], str | None]:
    """Apply custom ruleset changes. Returns (synced_labels, error_msg).

    Custom rulesets are applied before phase deploy rules so the child
    rulesets contain the expected rules when deploy rules reference them.
    """
    max_w = provider.max_workers

    tasks: list[tuple[str, Callable[[], None]]] = []
    for crp in zp.custom_ruleset_plans:
        if not crp.has_changes:
            continue
        label = f"custom_ruleset:{crp.ruleset_name}"
        full_label = f"{zp.zone_name}/{label}"
        n_changes = len(crp.changes)
        log.info("  %s/%s: applying %d change(s)", zp.zone_name, label, n_changes)
        if crp.prepared_rules is None:
            log.warning("  %s/%s: no prepared rules, skipping", zp.zone_name, label)
            continue

        def fn(rid=crp.ruleset_id, rules=crp.prepared_rules, _lbl=label):
            provider.put_custom_ruleset(scope, rid, rules)
            log.info("  %s/%s: done", zp.zone_name, _lbl)

        tasks.append((full_label, fn))

    return _apply_parallel(tasks, max_w)


def _apply_lists(
    zp: ZonePlan,
    scope: Scope,
    provider: CloudflareProvider,
) -> tuple[list[str], str | None]:
    """Apply list changes. Returns (synced_labels, error_msg).

    Order: creates first, then item updates, then description updates, then deletes.
    Each stage is parallelised via ``_apply_parallel``; stages run sequentially
    so that creates complete before item updates read ``list_id``.
    """
    max_w = provider.max_workers
    synced: list[str] = []

    # Stage 1: Creates (don't add to synced — matches original behaviour)
    create_tasks: list[tuple[str, Callable[[], None]]] = []
    for lp in zp.list_plans:
        if not lp.create:
            continue
        label = f"list:{lp.list_name}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: creating list (%s)", zp.zone_name, label, lp.list_kind)

        def create_fn(_lp=lp, _label=label):
            desc = _lp.description_change[1] if _lp.description_change else ""
            result = provider.create_list(scope, _lp.list_name, _lp.list_kind, desc)
            _lp.list_id = result.get("id", "")
            log.info("  %s/%s: created (id=%s)", zp.zone_name, _label, _lp.list_id)

        create_tasks.append((full_label, create_fn))

    if create_tasks:
        _, create_error = _apply_parallel(create_tasks, max_w)
        if create_error:
            return synced, create_error

    # Stage 2: Item updates
    item_tasks: list[tuple[str, Callable[[], None]]] = []
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

        def item_fn(_lp=lp, _label=label):
            op_id = provider.put_list_items(scope, _lp.list_id, _lp.prepared_items)
            provider.poll_bulk_operation(scope, op_id)
            log.info("  %s/%s: items updated", zp.zone_name, _label)

        item_tasks.append((full_label, item_fn))

    if item_tasks:
        item_synced, item_error = _apply_parallel(item_tasks, max_w)
        synced.extend(item_synced)
        if item_error:
            return synced, item_error

    # Stage 3: Description updates (skip if create already set it)
    desc_tasks: list[tuple[str, Callable[[], None]]] = []
    for lp in zp.list_plans:
        if lp.description_change is None or lp.create or lp.delete:
            continue
        if not lp.list_id:
            continue
        label = f"list:{lp.list_name}"
        full_label = f"{zp.zone_name}/{label}"
        _, new_desc = lp.description_change
        log.info("  %s/%s: updating description", zp.zone_name, label)

        def desc_fn(_lp=lp, _new_desc=new_desc, _label=label):
            provider.update_list_description(scope, _lp.list_id, _new_desc or "")
            log.info("  %s/%s: description updated", zp.zone_name, _label)

        desc_tasks.append((full_label, desc_fn))

    if desc_tasks:
        desc_synced, desc_error = _apply_parallel(desc_tasks, max_w)
        synced.extend(desc_synced)
        if desc_error:
            return synced, desc_error

    # Stage 4: Deletes last
    delete_tasks: list[tuple[str, Callable[[], None]]] = []
    for lp in zp.list_plans:
        if not lp.delete or not lp.list_id:
            continue
        label = f"list:{lp.list_name}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: deleting list", zp.zone_name, label)

        def del_fn(_lp=lp, _label=label):
            provider.delete_list(scope, _lp.list_id)
            log.info("  %s/%s: deleted", zp.zone_name, _label)

        delete_tasks.append((full_label, del_fn))

    if delete_tasks:
        del_synced, del_error = _apply_parallel(delete_tasks, max_w)
        synced.extend(del_synced)
        if del_error:
            return synced, del_error

    return synced, None


def _apply_page_shield_policies(
    zp: ZonePlan,
    scope: Scope,
    provider: CloudflareProvider,
) -> tuple[list[str], str | None]:
    """Apply Page Shield policy changes. Returns (synced_labels, error_msg).

    Order: creates first, then updates, then deletes.  Each stage is
    parallelised via ``_apply_parallel``.
    """
    max_w = provider.max_workers
    synced: list[str] = []

    # Stage 1: Creates
    create_tasks: list[tuple[str, Callable[[], None]]] = []
    for psp in zp.page_shield_policy_plans:
        if not psp.create:
            continue
        label = f"page_shield:{psp.description}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: creating policy", zp.zone_name, label)
        # Build kwargs from changes (all fields are ADDs for create)
        kwargs: dict = {"description": psp.description}
        for c in psp.changes:
            if c.normalized_desired:
                for k, v in c.normalized_desired.items():
                    kwargs[k] = v

        def create_fn(_psp=psp, _kwargs=dict(kwargs), _label=label):
            result = provider.create_page_shield_policy(scope, **_kwargs)
            _psp.policy_id = result.get("id", "")
            log.info("  %s/%s: created (id=%s)", zp.zone_name, _label, _psp.policy_id)

        create_tasks.append((full_label, create_fn))

    if create_tasks:
        create_synced, create_error = _apply_parallel(create_tasks, max_w)
        synced.extend(create_synced)
        if create_error:
            return synced, create_error

    # Stage 2: Updates (has field changes but not create/delete)
    update_tasks: list[tuple[str, Callable[[], None]]] = []
    for psp in zp.page_shield_policy_plans:
        if psp.create or psp.delete or not psp.changes:
            continue
        if not psp.policy_id:
            continue
        label = f"page_shield:{psp.description}"
        full_label = f"{zp.zone_name}/{label}"
        n_changes = len(psp.changes)
        log.info("  %s/%s: applying %d change(s)", zp.zone_name, label, n_changes)
        # Build the full updated policy from current + changes
        kwargs = {"description": psp.description}
        for c in psp.changes:
            if c.normalized_desired:
                for k, v in c.normalized_desired.items():
                    kwargs[k] = v

        def update_fn(_psp=psp, _kwargs=dict(kwargs), _label=label):
            provider.update_page_shield_policy(scope, _psp.policy_id, **_kwargs)
            log.info("  %s/%s: updated", zp.zone_name, _label)

        update_tasks.append((full_label, update_fn))

    if update_tasks:
        update_synced, update_error = _apply_parallel(update_tasks, max_w)
        synced.extend(update_synced)
        if update_error:
            return synced, update_error

    # Stage 3: Deletes last
    delete_tasks: list[tuple[str, Callable[[], None]]] = []
    for psp in zp.page_shield_policy_plans:
        if not psp.delete or not psp.policy_id:
            continue
        label = f"page_shield:{psp.description}"
        full_label = f"{zp.zone_name}/{label}"
        log.info("  %s/%s: deleting policy", zp.zone_name, label)

        def del_fn(_psp=psp, _label=label):
            provider.delete_page_shield_policy(scope, _psp.policy_id)
            log.info("  %s/%s: deleted", zp.zone_name, _label)

        delete_tasks.append((full_label, del_fn))

    if delete_tasks:
        del_synced, del_error = _apply_parallel(delete_tasks, max_w)
        synced.extend(del_synced)
        if del_error:
            return synced, del_error

    return synced, None


def _apply_single_zone(
    zp: ZonePlan,
    desired: dict,
    scope: Scope,
    provider: CloudflareProvider,
) -> tuple[str, list[str], str | None]:
    """Apply changes for a single zone. Returns (zone_name, synced_phases, error_msg).

    Phases within a zone are applied in parallel when max_workers > 1.
    AuthenticationError/PermissionDeniedError propagate immediately.
    """
    log.info("Syncing %s", zp.zone_name)

    # Apply lists first (rules reference lists via $list_name)
    all_synced: list[str] = []
    if zp.list_plans:
        list_synced, list_error = _apply_lists(zp, scope, provider)
        all_synced.extend(list_synced)
        if list_error:
            return zp.zone_name, all_synced, list_error

    # Apply Page Shield policies (zone-level, before custom rulesets and phases)
    if zp.page_shield_policy_plans:
        ps_synced, ps_error = _apply_page_shield_policies(zp, scope, provider)
        all_synced.extend(ps_synced)
        if ps_error:
            return zp.zone_name, all_synced, ps_error

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

        def fn(_payload=payload, _phase=phase, _label=friendly_name):
            kw = scope.api_kwargs
            scope_key = next(iter(kw))
            log.debug(
                "  PUT %s %s (%s=%s) rules=%d",
                _phase.cf_phase,
                zp.zone_name,
                scope_key,
                kw[scope_key],
                len(_payload),
            )
            provider.put_phase_rules(scope, _phase.cf_phase, _payload)
            log.info("  %s/%s: done", zp.zone_name, _label)

        tasks.append((full_label, fn))

    phase_synced, phase_error = _apply_parallel(tasks, max_w)
    all_synced.extend(phase_synced)
    return zp.zone_name, all_synced, phase_error


def _apply_zone_changes(
    actionable: list[ZonePlan],
    desired_by_zone: dict[str, dict],
    config: Config,
    provider: CloudflareProvider,
    scope_map: dict[str, Scope] | None = None,
    executor: ThreadPoolExecutor | None = None,
) -> int:
    """Apply planned changes to Cloudflare in parallel across zones. Returns exit code."""
    total = len(actionable)
    log.info("Applying changes to %d zone(s)...", total)

    # Build list of (zone_plan, desired, scope) to apply
    to_apply: list[tuple[ZonePlan, dict, Scope]] = []
    for zp in actionable:
        if zp.zone_name in config.zones:
            zone_cfg = config.zones[zp.zone_name]
            scope = Scope(zone_id=zone_cfg.zone_id, label=zp.zone_name)
        elif scope_map and zp.zone_name in scope_map:
            zone_cfg = _make_account_zone_config(config)
            scope = scope_map[zp.zone_name]
        else:
            log.warning("Skipping %s (no config found)", zp.zone_name)
            continue

        if zone_cfg.always_dry_run:
            log.warning("Skipping %s (always_dry_run is enabled)", zp.zone_name)
            continue

        to_apply.append((zp, desired_by_zone[zp.zone_name], scope))

    if not to_apply:
        log.info("Done.")
        return 0

    # Apply zones in parallel, phases within each zone sequentially
    all_synced: list[str] = []
    had_error = False

    def _apply_one(item: tuple[ZonePlan, dict, Scope]) -> tuple[str, list[str], str | None]:
        zp, desired, scope = item
        return _apply_single_zone(zp, desired, scope, provider)

    try:
        results = _map_ordered(_apply_one, to_apply, config.max_workers, executor=executor)
    except (AuthenticationError, PermissionDeniedError) as e:
        log.error("Authentication/permission error during sync: %s", _format_api_error(e))
        if all_synced:
            log.error("Successfully synced before failure: %s", ", ".join(all_synced))
        return 1

    for zone_name, synced, error in results:
        all_synced.extend(synced)
        if error:
            log.error("API error syncing %s: %s", zone_name, error)
            had_error = True

    if had_error:
        if all_synced:
            log.error("Successfully synced before failure: %s", ", ".join(all_synced))
        return 1

    log.info("Done.")
    return 0


def cmd_sync(
    config: Config,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None = None,
    checksum: str | None = None,
    force: bool = False,
    scope_filter: str = "all",
) -> int:
    """Run the sync command. Returns exit code."""
    provider = _init_provider(config)
    # Shared executor reused across plan + apply phases
    shared_ex: ThreadPoolExecutor | None = None
    if config.max_workers > 1:
        shared_ex = ThreadPoolExecutor(max_workers=config.max_workers)
    try:
        return _cmd_sync_inner(
            config, provider, zone_filter, phase_filter, checksum, force, scope_filter, shared_ex
        )
    finally:
        if shared_ex is not None:
            shared_ex.shutdown(wait=True)


def _cmd_sync_inner(
    config: Config,
    provider: CloudflareProvider,
    zone_filter: list[str] | None,
    phase_filter: list[str] | None,
    checksum: str | None,
    force: bool,
    scope_filter: str,
    executor: ThreadPoolExecutor | None,
) -> int:
    """Inner sync logic using an optional shared executor."""
    failed: list[str] = []

    zone_plans: list[ZonePlan] = []
    desired_by_zone: dict[str, dict] = {}
    current_by_zone: dict[str, dict] = {}
    scope_map: dict[str, Scope] = {}
    account_label: str | None = None
    do_zones = scope_filter in ("all", "zones")
    do_account = scope_filter in ("all", "account")

    def _collect_account(acct_plan, acct_desired, acct_current):
        nonlocal account_label
        if acct_plan is not None:
            zone_plans.append(acct_plan)
            desired_by_zone[acct_plan.zone_name] = acct_desired
            current_by_zone[acct_plan.zone_name] = acct_current
            account_label = acct_plan.zone_name
            scope_map[acct_plan.zone_name] = Scope(
                account_id=provider.account_id, label=provider.account_name
            )

    if do_zones and do_account:
        with ThreadPoolExecutor(max_workers=1) as acct_executor:
            acct_future = acct_executor.submit(_plan_account, config, provider, phase_filter)
            zone_names = _get_zones(config, zone_filter)
            zp_list, d_by_z, c_by_z, zone_failed = _plan_zones(
                config, provider, zone_names, phase_filter, executor=executor
            )
            zone_plans.extend(zp_list)
            desired_by_zone.update(d_by_z)
            current_by_zone.update(c_by_z)
            failed.extend(zone_failed)
            _collect_account(*acct_future.result())
    else:
        if do_zones:
            zone_names = _get_zones(config, zone_filter)
            zp_list, d_by_z, c_by_z, zone_failed = _plan_zones(
                config, provider, zone_names, phase_filter, executor=executor
            )
            zone_plans.extend(zp_list)
            desired_by_zone.update(d_by_z)
            current_by_zone.update(c_by_z)
            failed.extend(zone_failed)
        if do_account:
            _collect_account(*_plan_account(config, provider, phase_filter))

    if failed:
        log.error("Aborting sync: failed to plan %d zone(s)", len(failed))
        return 1

    if not _emit_plan_outputs(config, zone_plans):
        return 1

    has_changes = any(zp.has_changes for zp in zone_plans)
    if not has_changes:
        return 0

    if checksum:
        actual = compute_checksum(zone_plans)
        if actual != checksum:
            log.error("Checksum mismatch: expected %s, got %s", checksum, actual)
            return 1

    if not force:
        violations = _check_safety_violations(
            zone_plans, current_by_zone, config, account_label=account_label
        )
        if violations:
            _log_safety_violations(violations)
            return 1

    actionable = [zp for zp in zone_plans if zp.has_changes]
    return _apply_zone_changes(
        actionable, desired_by_zone, config, provider, scope_map=scope_map, executor=executor
    )


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
    from octorules.linter.engine import Severity, lint_zone_file
    from octorules.linter.expression_bridge import WIREFILTER_AVAILABLE
    from octorules.linter.report import FORMATTERS
    from octorules.linter.suppressions import parse_suppressions

    if WIREFILTER_AVAILABLE:
        log.info("Expression parser: wirefilter")
    else:
        log.info(
            "Expression parser: regex fallback (install octorules-wirefilter for full parsing)"
        )

    severity_map = {"error": Severity.ERROR, "warning": Severity.WARNING, "info": Severity.INFO}
    severity = severity_map[lint_severity]
    formatter = FORMATTERS[lint_format]

    zone_names = _get_zones(config, zone_filter)
    all_results: list = []
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

        suppressions = parse_suppressions(rules_file)

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

    if not all_results:
        log.info("No lint issues found.")

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
            except (RuleValidationError, ValueError) as e:
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

        # Validate page_shield_policies entries
        ps_entries = desired.get("page_shield_policies")
        if isinstance(ps_entries, list):
            for i, entry in enumerate(ps_entries):
                try:
                    validate_page_shield_policy(entry, i)
                    desc = entry.get("description", f"index {i}")
                    msg = f"  {zone_name}/page_shield:{desc}: OK"
                    log.info("%s", msg)
                    lines.append(msg)
                    validated_count += 1
                except RuleValidationError as e:
                    msg = f"  {zone_name}/page_shield_policies: {e}"
                    errors.append(msg)

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
    provider = _init_provider(config)
    out_dir = Path(output_dir) if output_dir else config.rules_dir
    lists_dir = out_dir / "custom_lists" if output_dir else config.lists_dir
    cf_phases = _phase_filter_to_cf_phases(phase_filter)
    had_errors = False
    do_zones = scope_filter in ("all", "zones")
    do_account = (
        scope_filter in ("all", "account")
        and isinstance(provider.account_id, str)
        and isinstance(provider.account_name, str)
    )

    def _fetch_and_dump(zone_name: str) -> tuple[str, Path | None, str | None]:
        zone_cfg = config.zones[zone_name]
        scope = Scope(zone_id=zone_cfg.zone_id, label=zone_name)

        # Start page shield fetch concurrently with phase rules
        with ThreadPoolExecutor(max_workers=1) as bg:
            ps_future = bg.submit(provider.get_all_page_shield_policies, scope)

            try:
                rules = provider.get_all_phase_rules(scope, cf_phases=cf_phases)
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                return zone_name, None, _format_api_error(e)

            # Fetch Page Shield policies
            page_shield_policies: list[dict] | None = None
            try:
                page_shield_policies = ps_future.result() or None
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                log.warning(
                    "Failed to fetch Page Shield policies for %s: %s",
                    zone_name,
                    _format_api_error(e),
                )

            result = dump_zone_rules(
                zone_name,
                rules,
                out_dir,
                page_shield_policies=page_shield_policies,
                lists_dir=lists_dir,
            )
            return zone_name, result, None

    def _dump_account() -> tuple[bool, str | None]:
        account_label = slugify(provider.account_name)
        scope = Scope(account_id=provider.account_id, label=provider.account_name)

        # Start secondary fetches concurrently with phase rules
        with ThreadPoolExecutor(max_workers=2) as bg:
            cr_future = bg.submit(provider.get_all_custom_rulesets, scope)
            lists_future = bg.submit(provider.get_all_lists, scope)

            try:
                rules = provider.get_all_phase_rules(scope, cf_phases=cf_phases)
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                log.error(
                    "Failed to dump account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )
                return True, None

            # Fetch custom rulesets
            custom_rulesets: dict[str, dict] | None = None
            try:
                custom_rulesets = cr_future.result() or None
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                log.warning(
                    "Failed to fetch custom rulesets for account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )

            # Fetch lists
            lists: dict[str, dict] | None = None
            try:
                lists = lists_future.result() or None
            except (AuthenticationError, PermissionDeniedError):
                raise
            except (APIError, APIConnectionError) as e:
                log.warning(
                    "Failed to fetch lists for account %s: %s",
                    provider.account_name,
                    _format_api_error(e),
                )

            result = dump_zone_rules(
                account_label,
                rules,
                out_dir,
                custom_rulesets=custom_rulesets,
                lists=lists,
                lists_dir=lists_dir,
            )
            if result:
                log.info("Dumped account %s → %s", provider.account_name, result)
            return False, result

    if do_zones and do_account:
        # Run account dump concurrently with zone dumps
        with ThreadPoolExecutor(max_workers=1) as acct_executor:
            acct_future = acct_executor.submit(_dump_account)
            zone_names = _get_zones(config, zone_filter)
            results = _map_ordered(_fetch_and_dump, zone_names, config.max_workers)
            for zone_name, result, error in results:
                if error:
                    log.error("Failed to dump %s: %s", zone_name, error)
                    had_errors = True
                elif result:
                    log.info("Dumped %s → %s", zone_name, result)
            acct_error, _ = acct_future.result()
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
                    log.info("Dumped %s → %s", zone_name, result)
        if do_account:
            acct_error, _ = _dump_account()
            if acct_error:
                had_errors = True

    return 1 if had_errors else 0


def cmd_versions() -> int:
    """Print versions of octorules and key dependencies. Returns exit code."""
    import platform

    print(f"octorules     {__version__}")
    try:
        import cloudflare

        print(f"cloudflare    {cloudflare.__version__}")
    except (ImportError, AttributeError):
        print("cloudflare    (not installed)")
    try:
        import yaml

        print(f"pyyaml        {yaml.__version__}")
    except (ImportError, AttributeError):
        print("pyyaml        (not installed)")
    print(f"python        {platform.python_version()}")
    return 0


def _setup_logging(*, debug: bool = False, quiet: bool = False) -> None:
    """Configure the octorules logger."""
    if debug:
        level = logging.DEBUG
    elif quiet:
        level = logging.WARNING
    else:
        level = logging.INFO
    logger = logging.getLogger("octorules")
    logger.setLevel(level)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(handler)
    else:
        for handler in logger.handlers:
            handler.setLevel(level)


def main(argv: list[str] | None = None) -> None:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        sys.exit(1)

    _setup_logging(debug=args.debug, quiet=args.quiet)

    # When --zone is specified without explicit --scope, skip account processing.
    if args.zones and args.scope == "all":
        args.scope = "zones"

    # versions doesn't need config
    if args.command == "versions":
        sys.exit(cmd_versions())

    try:
        config = Config.from_file(args.config)
        phase_filter = _validate_phases(args.phases)

        if args.command == "plan":
            sys.exit(
                cmd_plan(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    exit_code=args.exit_code,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "sync":
            sys.exit(
                cmd_sync(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    force=args.force,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "compare":
            sys.exit(
                cmd_compare(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    checksum=args.checksum,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "report":
            sys.exit(
                cmd_report(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    report_format=args.report_format,
                    scope_filter=args.scope,
                )
            )
        elif args.command == "lint":
            zone_plans: dict[str, str] = {}
            if args.lint_plan is None:
                try:
                    provider = _init_provider(config)
                    zone_plans = provider.zone_plans
                except (APIError, APIConnectionError) as e:
                    log.warning(
                        "Could not resolve zone plans from Cloudflare API (%s); "
                        "using 'enterprise' as default. Pass --plan to set explicitly.",
                        _format_api_error(e),
                    )
            sys.exit(
                cmd_lint(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    lint_format=args.lint_format,
                    lint_severity=args.lint_severity,
                    lint_rules=args.lint_rules,
                    lint_plan=args.lint_plan,
                    zone_plans=zone_plans,
                    output_file=args.lint_output,
                    exit_code=args.lint_exit_code,
                )
            )
        elif args.command == "validate":
            sys.exit(
                cmd_validate(
                    config,
                    args.zones,
                    phase_filter=phase_filter,
                    output_file=args.validate_output,
                )
            )
        elif args.command == "dump":
            sys.exit(
                cmd_dump(
                    config,
                    args.zones,
                    args.output_dir,
                    scope_filter=args.scope,
                    phase_filter=phase_filter,
                )
            )
    except ConfigError as e:
        log.error("Config error: %s", e)
        sys.exit(1)
    except (AuthenticationError, PermissionDeniedError) as e:
        log.error("Cloudflare authentication failed: %s", _format_api_error(e))
        sys.exit(1)
