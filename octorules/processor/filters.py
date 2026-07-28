"""Built-in processor filters for common WAF pipeline transformations."""

import re
from collections.abc import Callable
from typing import TYPE_CHECKING

from octorules.config import ConfigError
from octorules.planner import ChangeType

if TYPE_CHECKING:
    from octorules.planner import ZonePlan
    from octorules.provider.base import BaseProvider


def _filter_plan_changes(plan: "ZonePlan", keep: Callable[[object], bool]) -> "ZonePlan":
    """Apply *keep* to every change across all plan buckets, in place.

    Walks the four change-bearing components of a :class:`ZonePlan` — phase
    plans, custom-ruleset plans, list plans, and extension plans — and keeps
    only the changes for which ``keep(change)`` returns ``True``.

    *keep* receives a single change object. Extension changes are not all
    typed: settings extensions (e.g. bot management) use field-level changes
    with no ``change_type``/``ref``. Predicates must tolerate such objects
    (use ``getattr`` with a default rather than attribute access).
    """
    for pp in plan.phase_plans:
        pp.changes = [c for c in pp.changes if keep(c)]
    for crp in plan.custom_ruleset_plans:
        crp.changes = [c for c in crp.changes if keep(c)]
    for lp in plan.list_plans:
        lp.changes = [c for c in lp.changes if keep(c)]
    for ext_plans in plan.extension_plans.values():
        for ep in ext_plans:
            ep.changes = [c for c in ep.changes if keep(c)]
    return plan


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

        def _resolve(names: list[str]) -> set[str]:
            """Validate phase names against the registry.

            An unknown name used to pass through silently, so a typo in
            ``include`` quietly dropped that phase from the plan — the same
            class of silent-unmanage this filter exists to make deliberate.
            ``--phase`` and ChangeTypeFilter both reject unknown values; this
            now matches them.
            """
            from octorules.phases import PHASE_BY_NAME, unknown_phase_message

            resolved = set()
            for name in names:
                if name not in PHASE_BY_NAME:
                    raise ConfigError(f"PhaseFilter: {unknown_phase_message(name)}")
                resolved.add(name)
            return resolved

        self._include = _resolve(include) if include else None
        self._exclude = _resolve(exclude) if exclude else None

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
    (phase plans, custom ruleset plans, list plans, extension plans).
    Extension changes without a ``change_type`` attribute (settings
    extensions use plain field changes) are never filtered.

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
        # Untyped extension changes (settings extensions use field-level
        # changes without a change_type) have ``getattr(...) is None``, which
        # can never be in the excluded set, so they are kept.
        return _filter_plan_changes(
            plan, lambda c: getattr(c, "change_type", None) not in self._exclude
        )


class PreserveFilter:
    """Preserve rules whose ``ref`` matches a pattern from selected change types.

    Drops planned changes whose ``ref`` matches *refs* and whose
    ``change_type`` is in *change_types*. This protects externally managed
    rules (e.g. rules a security vendor or another team injects out-of-band)
    from deletion or reordering while other drift is still planned — a scoped
    middle ground between ``allow_unmanaged`` false (every unmanaged rule
    becomes a REMOVE) and true (all REMOVEs suppressed).

    Reads only ``ref`` and ``change_type``, both present on every
    :class:`RuleChange`, so it is provider-agnostic.

    Args:
        refs: Regex matched (``re.search``) against each change's ``ref``.
        change_types: Change types to suppress for matching refs. Defaults to
            ``["REMOVE", "REORDER"]``. ADD/MODIFY are not meaningful for
            preservation (an unmanaged rule is never added or modified).
    """

    def __init__(self, *, refs: str, change_types: list[str] | None = None) -> None:
        if not refs:
            raise ConfigError("PreserveFilter: 'refs' is required")
        try:
            self._refs = re.compile(refs)
        except re.error as e:
            raise ConfigError(f"PreserveFilter: invalid regex pattern: {e}") from None
        types = change_types if change_types is not None else ["REMOVE", "REORDER"]
        if not types:
            raise ConfigError("PreserveFilter: 'change_types' must be a non-empty list")
        try:
            self._types = {ChangeType[t.upper()] for t in types}
        except KeyError as e:
            valid = ", ".join(ct.name for ct in ChangeType)
            raise ConfigError(
                f"PreserveFilter: unknown change type {e}. Valid types: {valid}"
            ) from None

    def process_changes(
        self, zone_name: str, plan: "ZonePlan", provider: "BaseProvider"
    ) -> "ZonePlan":
        def keep(c: object) -> bool:
            ct = getattr(c, "change_type", None)
            return not (ct in self._types and self._refs.search(getattr(c, "ref", "") or ""))

        return _filter_plan_changes(plan, keep)
