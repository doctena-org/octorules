"""Provider interface.

Public API:
    BaseProvider, Scope, PhaseRulesResult — always available
"""

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
    "SUPPORTS_CUSTOM_RULESETS",
    "SUPPORTS_LISTS",
    "SUPPORTS_PAGE_SHIELD",
    "SUPPORTS_ZONE_DISCOVERY",
    "BaseProvider",
    "PhaseRulesResult",
    "Scope",
    "provider_supports",
]
