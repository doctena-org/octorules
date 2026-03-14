"""Provider interface and backward-compatible re-exports.

Public API:
    BaseProvider, Scope, PhaseRulesResult — always available
    CloudflareProvider — available when octorules-cloudflare is installed
"""

from __future__ import annotations

from octorules.provider.base import BaseProvider, PhaseRulesResult, Scope

# Lazy import CloudflareProvider from octorules-cloudflare for backward compat.
# When the package is installed, ``from octorules.provider import CloudflareProvider``
# continues to work.  When it's not installed, CloudflareProvider is None.
try:
    from octorules_cloudflare import CloudflareProvider
except ImportError:
    CloudflareProvider = None  # type: ignore[assignment,misc]


__all__ = [
    "BaseProvider",
    "CloudflareProvider",
    "PhaseRulesResult",
    "Scope",
]
