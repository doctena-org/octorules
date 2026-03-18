"""Provider interface and backward-compatible re-exports.

Public API:
    BaseProvider, Scope, PhaseRulesResult — always available
    CloudflareProvider — available when octorules-cloudflare is installed
"""

from __future__ import annotations

from octorules.provider.base import (
    SUPPORTS_CUSTOM_RULESETS,
    SUPPORTS_LISTS,
    SUPPORTS_PAGE_SHIELD,
    SUPPORTS_ZONE_DISCOVERY,
    BaseProvider,
    PhaseRulesResult,
    Scope,
    provider_supports,
)

__all__ = [
    "BaseProvider",
    "CloudflareProvider",
    "PhaseRulesResult",
    "SUPPORTS_CUSTOM_RULESETS",
    "SUPPORTS_LISTS",
    "SUPPORTS_PAGE_SHIELD",
    "SUPPORTS_ZONE_DISCOVERY",
    "Scope",
    "provider_supports",
]


def __getattr__(name: str):
    """Lazy import CloudflareProvider from octorules-cloudflare for backward compat.

    Using ``__getattr__`` instead of a top-level import avoids a circular
    dependency: ``octorules_cloudflare.provider`` imports
    ``octorules.provider.base``, which triggers this ``__init__``.  If we
    did ``from octorules_cloudflare import CloudflareProvider`` at the top
    level, we'd hit the partially-initialized ``octorules_cloudflare``
    module and get ``None``.
    """
    if name == "CloudflareProvider":
        try:
            from octorules_cloudflare import CloudflareProvider

            return CloudflareProvider
        except ImportError:
            raise ImportError(
                "CloudflareProvider requires the octorules-cloudflare package. "
                "Install it with: pip install octorules-cloudflare"
            ) from None
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
