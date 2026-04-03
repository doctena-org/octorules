"""Built-in processor filters for common WAF pipeline transformations."""

import re
from typing import TYPE_CHECKING

from octorules.config import ConfigError
from octorules.planner import ChangeType

if TYPE_CHECKING:
    from octorules.planner import ZonePlan
    from octorules.provider.base import BaseProvider


class PhaseFilter:
    """Filter desired rules by phase name.

    Args:
        include: Phases to keep (allowlist). Mutually exclusive with exclude.
        exclude: Phases to remove (rejectlist). Mutually exclusive with include.
    """

    def __init__(
        self,
        *,
        include: list[str] | None = None,
        exclude: list[str] | None = None,
    ) -> None:
        if include and exclude:
            raise ConfigError("PhaseFilter: 'include' and 'exclude' are mutually exclusive")
        if not include and not exclude:
            raise ConfigError("PhaseFilter: one of 'include' or 'exclude' is required")
        self._include = set(include) if include else None
        self._exclude = set(exclude) if exclude else None

    def process_desired(self, zone_name: str, desired: dict, provider: "BaseProvider") -> dict:
        if self._include is not None:
            return {p: rules for p, rules in desired.items() if p in self._include}
        return {p: rules for p, rules in desired.items() if p not in self._exclude}


class RefFilter:
    """Filter rules by regex pattern on the 'ref' field.

    Args:
        include: Regex pattern — only keep matching rules.
        exclude: Regex pattern — remove matching rules.
    """

    def __init__(
        self,
        *,
        include: str | None = None,
        exclude: str | None = None,
    ) -> None:
        if include and exclude:
            raise ConfigError("RefFilter: 'include' and 'exclude' are mutually exclusive")
        if not include and not exclude:
            raise ConfigError("RefFilter: one of 'include' or 'exclude' is required")
        try:
            self._include = re.compile(include) if include else None
            self._exclude = re.compile(exclude) if exclude else None
        except re.error as e:
            raise ConfigError(f"RefFilter: invalid regex pattern: {e}") from None

    def process_desired(self, zone_name: str, desired: dict, provider: "BaseProvider") -> dict:
        result = {}
        for phase, rules in desired.items():
            if not isinstance(rules, list):
                result[phase] = rules
                continue
            if self._include is not None:
                result[phase] = [r for r in rules if self._include.search(r.get("ref") or "")]
            else:
                result[phase] = [r for r in rules if not self._exclude.search(r.get("ref") or "")]
        return result


class ChangeTypeFilter:
    """Filter planned changes by type.

    Removes changes of the specified types from all plan components
    (phase plans, custom ruleset plans, list plans, page shield policy plans).

    Args:
        exclude: Change types to block (e.g. ["REMOVE", "REORDER"]).
    """

    def __init__(self, *, exclude: list[str]) -> None:
        if not exclude:
            raise ConfigError("ChangeTypeFilter: 'exclude' must be a non-empty list")
        try:
            self._exclude = {ChangeType[t.upper()] for t in exclude}
        except KeyError as e:
            valid = ", ".join(ct.name for ct in ChangeType)
            raise ConfigError(
                f"ChangeTypeFilter: unknown change type {e}. Valid types: {valid}"
            ) from None

    def process_changes(
        self, zone_name: str, plan: "ZonePlan", provider: "BaseProvider"
    ) -> "ZonePlan":
        for pp in plan.phase_plans:
            pp.changes = [c for c in pp.changes if c.change_type not in self._exclude]
        for crp in plan.custom_ruleset_plans:
            crp.changes = [c for c in crp.changes if c.change_type not in self._exclude]
        for lp in plan.list_plans:
            lp.changes = [c for c in lp.changes if c.change_type not in self._exclude]
        for ext_plans in plan.extension_plans.values():
            for ep in ext_plans:
                ep.changes = [c for c in ep.changes if c.change_type not in self._exclude]
        return plan
