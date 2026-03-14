"""Provider interface and shared data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable


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
    """Dict mapping cf_phase -> rules, with tracking of phases that failed to fetch.

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

    All provider implementations (e.g. CloudflareProvider) must satisfy this
    protocol. Use ``isinstance(provider, BaseProvider)`` for runtime checks.
    """

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

    # -- Phase rules --

    def get_phase_rules(self, scope: Scope, cf_phase: str) -> list[dict]: ...

    def put_phase_rules(self, scope: Scope, cf_phase: str, rules: list[dict]) -> int: ...

    def get_all_phase_rules(
        self, scope: Scope, *, cf_phases: list[str] | None = None
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
