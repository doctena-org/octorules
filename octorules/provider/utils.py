"""Provider utilities — shared helpers for provider implementations."""

import functools
import logging
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from concurrent.futures import TimeoutError as FuturesTimeoutError
from typing import Any, TypeVar

from octorules.provider.exceptions import (
    ProviderAuthError,
    ProviderConnectionError,
    ProviderError,
)

log = logging.getLogger(__name__)

_T = TypeVar("_T")


def format_api_error(e: ProviderError) -> str:
    """Format a provider error, including the HTTP status code when available.

    Works with any provider SDK whose exceptions chain the original HTTP
    error as ``__cause__`` with a ``status_code`` attribute.
    """
    cause = e.__cause__
    if cause is not None and hasattr(cause, "status_code"):
        return f"[HTTP {cause.status_code}] {e}"
    return str(e)


def make_error_wrapper(
    *,
    auth_errors: tuple[type[BaseException], ...] = (),
    connection_errors: tuple[type[BaseException], ...] = (),
    generic_errors: tuple[type[BaseException], ...] = (),
    classify: Callable[[BaseException], type[ProviderError] | None] | None = None,
) -> Callable:
    """Create a decorator that wraps SDK exceptions as provider-agnostic exceptions.

    Args:
        auth_errors: Exception types that map to ``ProviderAuthError``.
        connection_errors: Exception types that map to ``ProviderConnectionError``.
        generic_errors: Exception types that map to ``ProviderError``.
        classify: Optional callback for exceptions that need runtime inspection
            (e.g. boto3 ``ClientError`` where the error *code* determines the
            category).  Called with the caught exception; should return the
            target exception class (``ProviderAuthError``, etc.) or ``None``
            to fall through to ``generic_errors``.

    Returns:
        A decorator that wraps a function's SDK exceptions.

    Example::

        _wrap = make_error_wrapper(
            auth_errors=(AuthenticationError, PermissionDeniedError),
            generic_errors=(APIError, APIConnectionError),
        )

        class MyProvider:
            @_wrap
            def get_phase_rules(self, scope, provider_id):
                ...
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        def wrapper(*args: object, **kwargs: object) -> object:
            try:
                return fn(*args, **kwargs)
            except ProviderError:
                # Already wrapped — re-raise as-is (e.g. from nested calls)
                raise
            except auth_errors as e:
                raise ProviderAuthError(str(e)) from e
            except connection_errors as e:
                raise ProviderConnectionError(str(e)) from e
            except generic_errors as e:
                if classify is not None:
                    target = classify(e)
                    if target is not None:
                        raise target(str(e)) from e
                raise ProviderError(str(e)) from e

        return wrapper

    return decorator


# ---------------------------------------------------------------------------
# SDK model conversion
# ---------------------------------------------------------------------------
def to_plain_dict(obj: object) -> dict[str, Any]:
    """Convert an SDK model object to a plain dict.

    Handles Pydantic v2 (``model_dump``), proto-plus / Pydantic v1
    (``to_dict``), and plain dicts.  Falls back to ``dict(obj)`` as a
    last resort.

    Raises:
        ProviderError: If conversion fails.
    """
    if isinstance(obj, dict):
        return obj
    # Pydantic v2
    if hasattr(obj, "model_dump"):
        return obj.model_dump(exclude_none=True)
    # proto-plus or Pydantic v1
    if hasattr(obj, "to_dict"):
        try:
            return type(obj).to_dict(obj)
        except (TypeError, AttributeError):
            return obj.to_dict()
    try:
        return dict(obj)  # type: ignore[call-overload]
    except (TypeError, ValueError) as exc:
        raise ProviderError(f"Cannot convert {type(obj).__name__} to dict: {exc}") from exc


# ---------------------------------------------------------------------------
# Field mapping helpers
# ---------------------------------------------------------------------------
def normalize_fields(rule: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    """Rename keys in *rule* per *mapping* (sdk_name -> octorules_name).

    Keys not present in *mapping* are preserved unchanged.
    Returns a new dict.
    """
    return {mapping.get(k, k): v for k, v in rule.items()}


def denormalize_fields(rule: dict[str, Any], mapping: dict[str, str]) -> dict[str, Any]:
    """Reverse of :func:`normalize_fields` (octorules_name -> sdk_name).

    Returns a new dict.
    """
    reverse = {v: k for k, v in mapping.items()}
    return {reverse.get(k, k): v for k, v in rule.items()}


# ---------------------------------------------------------------------------
# Parallel fetch orchestrator
# ---------------------------------------------------------------------------

_DEFAULT_FETCH_TIMEOUT = 300.0  # seconds


def fetch_parallel(
    items: Sequence[Any],
    *,
    submit_fn: Callable,
    key_fn: Callable,
    result_fn: Callable,
    label: str,
    scope_label: str = "",
    max_workers: int = 4,
    timeout: float = _DEFAULT_FETCH_TIMEOUT,
    auth_errors: tuple[type[BaseException], ...] = (ProviderAuthError,),
) -> tuple[dict[str, _T], list[str]]:
    """Run *submit_fn* for each item in parallel, collecting results.

    Args:
        items: Items to iterate over.
        submit_fn: ``submit_fn(executor, item)`` -> ``Future``.
        key_fn: ``key_fn(item)`` -> hashable key for log messages and
            the ``failed`` list.
        result_fn: ``result_fn(item, future_result)`` -> ``(key, value)``
            pair to insert into the result dict, or ``None`` to skip.
        label: Human label for log messages (e.g. "phase", "custom ruleset").
        scope_label: Pre-formatted scope string for log messages.
        max_workers: Max concurrent workers.
        timeout: Per-future timeout in seconds.
        auth_errors: Exception types that cause immediate cancellation of
            all pending futures and re-raise.

    Returns:
        ``(results_dict, failed_keys)`` -- results for successful fetches
        and keys of items that failed with transient errors.
    """
    if not items:
        return {}, []
    workers = min(max_workers, len(items))
    results: dict[str, _T] = {}
    failed: list[str] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        future_to_item: dict = {}
        for item in items:
            f = submit_fn(executor, item)
            future_to_item[f] = item
        for future in as_completed(future_to_item):
            item = future_to_item[future]
            key = key_fn(item)
            try:
                value = future.result(timeout=timeout)
            except auth_errors:
                for f in future_to_item:
                    f.cancel()
                raise
            except (FuturesTimeoutError, TimeoutError):
                log.warning("Timed out fetching %s %s for %s", label, key, scope_label)
                failed.append(key)
                continue
            except ProviderError as exc:
                log.warning("Failed to fetch %s %s for %s: %s", label, key, scope_label, exc)
                failed.append(key)
                continue
            pair = result_fn(item, value)
            if pair is not None:
                results[pair[0]] = pair[1]
    return results, failed


# ---------------------------------------------------------------------------
# Parallel apply orchestrator
# ---------------------------------------------------------------------------
def apply_parallel(
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
            return label, format_api_error(e)
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
