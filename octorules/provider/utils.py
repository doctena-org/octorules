"""Provider utilities — shared helpers for provider implementations."""

from __future__ import annotations

import functools
from collections.abc import Callable

from octorules.provider.exceptions import (
    ProviderAuthError,
    ProviderConnectionError,
    ProviderError,
)


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
