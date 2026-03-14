"""Provider exception hierarchy.

Re-exports Cloudflare SDK exceptions for backward compatibility and defines
base exception classes for future provider-agnostic error handling (Phase 4).
"""

from __future__ import annotations

# Base exception classes — provider-agnostic (Phase 4 migration target)


class ProviderError(Exception):
    """Base class for all provider errors."""


class ProviderAuthError(ProviderError):
    """Authentication or permission error from the provider."""


class ProviderConnectionError(ProviderError):
    """Connection error from the provider."""


# Re-exports from cloudflare SDK — these are the exception types currently used
# throughout commands.py and cli.py.  Importing from here instead of directly
# from ``cloudflare`` keeps the SDK dependency confined to provider/.
from cloudflare import (  # noqa: E402
    APIConnectionError,
    APIError,
    AuthenticationError,
    BadRequestError,
    NotFoundError,
    PermissionDeniedError,
)

__all__ = [
    # Base classes
    "ProviderError",
    "ProviderAuthError",
    "ProviderConnectionError",
    # Cloudflare SDK re-exports
    "APIConnectionError",
    "APIError",
    "AuthenticationError",
    "BadRequestError",
    "NotFoundError",
    "PermissionDeniedError",
]
