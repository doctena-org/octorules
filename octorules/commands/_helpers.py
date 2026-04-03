"""Shared utility functions for command implementations."""

import logging
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import IO

from octorules.config import Config, ConfigError
from octorules.pathutil import validate_path_within
from octorules.phases import PHASE_BY_NAME, unknown_phase_message
from octorules.plan_output import PlanText
from octorules.planner import RuleDict
from octorules.provider.base import SUPPORTS_CUSTOM_RULESETS, SUPPORTS_LISTS
from octorules.provider.exceptions import ProviderAuthError, ProviderError
from octorules.provider.utils import format_api_error as _format_api_error

log = logging.getLogger(__name__)

# Mapping from YAML top-level keys to SUPPORTS feature constants.
# Used by _plan_single_zone() to catch unsupported features early.
_FEATURE_KEYS: dict[str, str] = {
    "custom_rulesets": SUPPORTS_CUSTOM_RULESETS,
    "lists": SUPPORTS_LISTS,
}

# Timeouts for future.result() calls when joining background fetches.
_FUTURE_TIMEOUT = 120

# Type alias for staged task lists.
_TaskList = list[tuple[str, Callable[[], None]]]


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


def _phase_filter_to_provider_ids(phase_filter: list[str] | None) -> list[str] | None:
    """Convert friendly phase names to provider phase identifiers for API filtering."""
    if phase_filter is None:
        return None
    return [PHASE_BY_NAME[p].provider_id for p in phase_filter if p in PHASE_BY_NAME]


def _write_output_file(
    path: str, write_fn: Callable[[IO[str]], None], *, base_dir: Path | None = None
) -> bool:
    """Write output to a file. Returns True on success, False on error.

    When *base_dir* is given, the resolved path must remain within it
    (protects config-specified paths like ``plan_outputs``).  When
    *base_dir* is ``None``, any writable path is accepted (appropriate
    for user-specified ``--output`` CLI arguments).
    """
    resolved = Path(path).resolve()
    if base_dir is not None and not validate_path_within(resolved, base_dir):
        log.error(
            "Output path escapes base directory: %s (resolves to %s, base is %s)",
            path,
            resolved,
            base_dir.resolve(),
        )
        return False
    try:
        with open(resolved, "w", encoding="utf-8") as f:
            write_fn(f)
        return True
    except OSError as e:
        log.error("Failed to write output file %s: %s", path, e)
        return False


def _emit_plan_outputs(config: Config, zone_plans: list) -> bool:
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
            if not _write_output_file(
                output.path,
                lambda f, out=output: out.run(zone_plans, fh=f),
                base_dir=config.rules_dir.parent,
            ):
                ok = False
        else:
            output.run(zone_plans)
    return ok


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
