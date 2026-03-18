"""Provider interface and shared data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar, Protocol, runtime_checkable

# Feature negotiation constants — providers declare which optional features
# they support via a ``SUPPORTS`` class variable.
SUPPORTS_CUSTOM_RULESETS = "custom_rulesets"
SUPPORTS_LISTS = "lists"
SUPPORTS_PAGE_SHIELD = "page_shield"
SUPPORTS_ZONE_DISCOVERY = "zone_discovery"

_SUPPORTS_ALL = frozenset(
    {SUPPORTS_CUSTOM_RULESETS, SUPPORTS_LISTS, SUPPORTS_PAGE_SHIELD, SUPPORTS_ZONE_DISCOVERY}
)


def provider_supports(provider: BaseProvider, feature: str) -> bool:
    """Check whether *provider* declares support for *feature*.

    Providers that don't define ``SUPPORTS`` (or define it as a non-set
    type) are assumed to support everything (backward compatibility with
    third-party providers).
    """
    supports = getattr(provider, "SUPPORTS", None)
    if not isinstance(supports, (set, frozenset)):
        return True
    return feature in supports


@dataclass
class Scope:
    zone_id: str | None = None
    account_id: str | None = None
    label: str = ""
    _api_kwargs: dict[str, str] | None = field(default=None, repr=False, compare=False)

    @property
    def api_kwargs(self) -> dict[str, str]:
        if self._api_kwargs is not None:
            return self._api_kwargs
        if self.account_id:
            kw = {"account_id": self.account_id}
        elif self.zone_id:
            kw = {"zone_id": self.zone_id}
        else:
            raise ValueError("Scope must have either zone_id or account_id")
        self._api_kwargs = kw
        return kw

    @property
    def is_account(self) -> bool:
        return self.account_id is not None


class PhaseRulesResult(dict):
    """Dict mapping provider_id -> rules, with tracking of phases that failed to fetch.

    Behaves as a normal dict everywhere, but carries a ``failed_phases`` list so
    callers can distinguish "phase has no rules" from "phase fetch failed".
    """

    failed_phases: list[str]

    def __init__(self, data=None, *, failed_phases: list[str] | None = None):
        super().__init__(data or {})
        self.failed_phases = failed_phases or []


@runtime_checkable
class BaseProvider(Protocol):
    """Protocol defining the provider interface.

    All provider implementations must satisfy this protocol.
    Use ``isinstance(provider, BaseProvider)`` for runtime checks.

    **Optional features and SUPPORTS:**

    Providers declare which optional features they support via a ``SUPPORTS``
    class variable containing feature constant strings (e.g.
    ``SUPPORTS_CUSTOM_RULESETS``).  The framework checks
    ``provider_supports()`` before calling optional methods, so unsupported
    methods are never called during normal operation.

    Providers that don't implement an optional feature should still define
    the methods to satisfy the protocol.  The convention is:

    * **Read / enumerate methods** (``list_*``, ``get_*``, ``get_all_*``)
      — return the empty collection (``[]``, ``{}``) so planning sees
      "nothing exists" and produces no changes.
    * **Mutation methods** (``create_*``, ``update_*``, ``put_*``,
      ``delete_*``) — raise ``ProviderError`` as a safety net; these
      should never be reached if ``SUPPORTS`` is correct.
    """

    # Set of optional features this provider supports.  Providers that
    # omit SUPPORTS are assumed to support everything (backward compat).
    SUPPORTS: ClassVar[frozenset[str]]

    # -- Properties --

    @property
    def max_workers(self) -> int: ...

    @property
    def account_id(self) -> str | None: ...

    @property
    def account_name(self) -> str | None: ...

    @property
    def zone_plans(self) -> dict[str, str]: ...

    # -- Zone/account resolution --

    def resolve_zone_id(self, zone_name: str) -> str: ...

    def list_zones(self) -> list[str]: ...

    # -- Phase rules --

    def get_phase_rules(self, scope: Scope, provider_id: str) -> list[dict]: ...

    def put_phase_rules(self, scope: Scope, provider_id: str, rules: list[dict]) -> int: ...

    def get_all_phase_rules(
        self, scope: Scope, *, provider_ids: list[str] | None = None
    ) -> PhaseRulesResult: ...

    # -- Custom rulesets --

    def list_custom_rulesets(self, scope: Scope) -> list[dict]: ...

    def get_custom_ruleset(self, scope: Scope, ruleset_id: str) -> list[dict]: ...

    def put_custom_ruleset(self, scope: Scope, ruleset_id: str, rules: list[dict]) -> int: ...

    def get_all_custom_rulesets(
        self, scope: Scope, *, ruleset_ids: list[str] | None = None
    ) -> dict[str, dict]: ...

    # -- Lists API --

    def list_lists(self, scope: Scope) -> list[dict]: ...

    def create_list(self, scope: Scope, name: str, kind: str, description: str = "") -> dict: ...

    def delete_list(self, scope: Scope, list_id: str) -> None: ...

    def update_list_description(self, scope: Scope, list_id: str, description: str) -> None: ...

    def get_list_items(self, scope: Scope, list_id: str) -> list[dict]: ...

    def put_list_items(self, scope: Scope, list_id: str, items: list[dict]) -> str: ...

    def poll_bulk_operation(
        self, scope: Scope, operation_id: str, *, timeout: float = 120.0
    ) -> str: ...

    def get_all_lists(
        self, scope: Scope, *, list_names: list[str] | None = None
    ) -> dict[str, dict]: ...

    # -- Page Shield Policies API --

    def list_page_shield_policies(self, scope: Scope) -> list[dict]: ...

    def create_page_shield_policy(
        self,
        scope: Scope,
        *,
        description: str,
        action: str,
        expression: str,
        enabled: bool,
        value: str,
    ) -> dict: ...

    def update_page_shield_policy(
        self,
        scope: Scope,
        policy_id: str,
        *,
        description: str,
        action: str,
        expression: str,
        enabled: bool,
        value: str,
    ) -> dict: ...

    def delete_page_shield_policy(self, scope: Scope, policy_id: str) -> None: ...

    def get_all_page_shield_policies(self, scope: Scope) -> list[dict]: ...
