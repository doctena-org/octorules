"""Provider-agnostic exception hierarchy.

These base exception types are used by commands.py and cli.py to catch
provider errors without depending on any specific SDK.  Provider
implementations (e.g. octorules-cloudflare) map their SDK exceptions
to these base types.
"""


class ProviderError(Exception):
    """Base class for all provider errors (transient API failures, etc.)."""


class ProviderAuthError(ProviderError):
    """Authentication or permission error from the provider."""


class ProviderConnectionError(ProviderError):
    """Connection error from the provider."""


__all__ = [
    "ProviderAuthError",
    "ProviderConnectionError",
    "ProviderError",
]
