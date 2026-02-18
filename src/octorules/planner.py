"""Diff engine — compares desired rules against current rules per phase."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from typing import TYPE_CHECKING

from octorules.phases import (
    CF_API_FIELDS,
    PHASE_BY_CF,
    PHASE_BY_NAME,
    Phase,
    get_phase,
    unknown_phase_message,
)

if TYPE_CHECKING:
    from octorules.config import ZoneConfig

log = logging.getLogger("octorules")


class ChangeType(Enum):
    ADD = "add"
    REMOVE = "remove"
    MODIFY = "modify"
    REORDER = "reorder"


# Fields stripped for comparison: CF_API_FIELDS plus 'ref' (used for matching, not comparison)
API_ONLY_FIELDS = CF_API_FIELDS | {"ref"}


@dataclass
class RuleChange:
    change_type: ChangeType
    ref: str
    phase: Phase
    current: dict | None = None
    desired: dict | None = None

    @cached_property
    def normalized_current(self) -> dict | None:
        """Return normalized current rule, cached after first access."""
        if self.current is None:
            return None
        return normalize_rule(self.current)

    @cached_property
    def normalized_desired(self) -> dict | None:
        """Return normalized desired rule, cached after first access."""
        if self.desired is None:
            return None
        return normalize_rule(self.desired)


@dataclass
class PhasePlan:
    phase: Phase
    changes: list[RuleChange] = field(default_factory=list)
    prepared_rules: list[dict] | None = field(default=None, repr=False, compare=False)

    @property
    def has_changes(self) -> bool:
        return len(self.changes) > 0


@dataclass
class ZonePlan:
    zone_name: str
    phase_plans: list[PhasePlan] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return any(pp.has_changes for pp in self.phase_plans)

    @property
    def total_changes(self) -> int:
        return sum(len(pp.changes) for pp in self.phase_plans)


class RuleValidationError(Exception):
    """Raised when a rule fails validation."""


def _normalize_value(v: object) -> object:
    """Normalize a value for comparison: strip trailing whitespace from multiline strings."""
    if isinstance(v, str) and "\n" in v:
        return "\n".join(line.rstrip() for line in v.split("\n"))
    return v


def normalize_rule(rule: dict) -> dict:
    """Strip API-only fields and normalize values for comparison."""
    return {k: _normalize_value(v) for k, v in rule.items() if k not in API_ONLY_FIELDS}


def validate_rules(rules: list[dict], phase: Phase) -> None:
    """Validate a list of desired rules for a phase.

    Checks:
    - Every rule has a 'ref' field
    - Every rule has an 'expression' field
    - No duplicate refs within the phase
    """
    seen_refs: set[str] = set()
    for i, rule in enumerate(rules):
        if "ref" not in rule:
            raise RuleValidationError(
                f"Rule at index {i} in {phase.friendly_name!r} is missing required 'ref' field"
            )
        ref = rule["ref"]
        if not isinstance(ref, str) or not ref:
            raise RuleValidationError(
                f"Rule at index {i} in {phase.friendly_name!r} has invalid 'ref'"
                " (must be a non-empty string)"
            )
        if "expression" not in rule:
            raise RuleValidationError(
                f"Rule {ref!r} in {phase.friendly_name!r} is missing required 'expression' field"
            )
        expr = rule["expression"]
        if not isinstance(expr, str) or not expr:
            raise RuleValidationError(
                f"Rule {ref!r} in {phase.friendly_name!r} has invalid 'expression'"
                " (must be a non-empty string)"
            )
        if ref in seen_refs:
            raise RuleValidationError(f"Duplicate ref {ref!r} in {phase.friendly_name!r}")
        seen_refs.add(ref)


_RENAMED_PHASES: dict[str, str] = {"waf_managed_exceptions": "waf_managed_rules"}


def warn_unknown_phase_keys(rules_data: dict, zone_name: str) -> None:
    """Warn about unknown top-level keys in a zone rules file."""
    # Warn about renamed phases (they still work via aliases but are deprecated)
    for key in sorted(set(rules_data.keys()) & _RENAMED_PHASES.keys()):
        new_name = _RENAMED_PHASES[key]
        log.warning(
            "Phase %r has been renamed to %r in rules for %s. "
            "Please update your YAML file. The old name still works but is deprecated.",
            key,
            new_name,
            zone_name,
        )
    # Warn about truly unknown phases
    unknown = set(rules_data.keys()) - PHASE_BY_NAME.keys()
    for key in sorted(unknown):
        log.warning("%s in rules for %s", unknown_phase_message(key), zone_name)


def _rules_by_ref(rules: list[dict]) -> dict[str, dict]:
    """Index a list of rules by their ref field."""
    result = {}
    for rule in rules:
        ref = rule.get("ref")
        if ref:
            result[ref] = rule
    return result


def _ref_order(rules: list[dict]) -> list[str]:
    """Extract the ordered list of refs."""
    return [r["ref"] for r in rules if "ref" in r]


def prepare_desired_rules(rules: list[dict], phase: Phase) -> list[dict]:
    """Prepare desired rules: validate, inject default action, set enabled default."""
    validate_rules(rules, phase)

    prepared = []
    for rule in rules:
        rule = rule.copy()
        # Default enabled to true
        if "enabled" not in rule:
            rule["enabled"] = True
        # Inject default action if phase has one and rule doesn't specify
        if "action" not in rule:
            if phase.default_action is None:
                raise ValueError(
                    f"Rule {rule.get('ref', '?')!r} in phase {phase.friendly_name!r} "
                    f"must specify an 'action' (no default for this phase)"
                )
            rule["action"] = phase.default_action
        prepared.append(rule)
    return prepared


def diff_phase(
    phase: Phase,
    desired_rules: list[dict],
    current_rules: list[dict],
    *,
    allow_unmanaged: bool = False,
) -> PhasePlan:
    """Compute the diff for a single phase."""
    plan = PhasePlan(phase=phase)

    desired = prepare_desired_rules(desired_rules, phase)
    plan.prepared_rules = desired
    desired_by_ref = _rules_by_ref(desired)
    current_by_ref = _rules_by_ref(current_rules)

    desired_refs = set(desired_by_ref.keys())
    current_refs = set(current_by_ref.keys())

    # Additions
    for ref in desired_refs - current_refs:
        plan.changes.append(
            RuleChange(
                change_type=ChangeType.ADD,
                ref=ref,
                phase=phase,
                desired=desired_by_ref[ref],
            )
        )

    # Removals (skipped when allow_unmanaged is True)
    if not allow_unmanaged:
        for ref in current_refs - desired_refs:
            plan.changes.append(
                RuleChange(
                    change_type=ChangeType.REMOVE,
                    ref=ref,
                    phase=phase,
                    current=current_by_ref[ref],
                )
            )

    # Modifications (same ref, different content)
    for ref in desired_refs & current_refs:
        norm_desired = normalize_rule(desired_by_ref[ref])
        norm_current = normalize_rule(current_by_ref[ref])
        if norm_desired != norm_current:
            change = RuleChange(
                change_type=ChangeType.MODIFY,
                ref=ref,
                phase=phase,
                current=current_by_ref[ref],
                desired=desired_by_ref[ref],
            )
            # Pre-populate cached properties to avoid re-normalizing
            change.__dict__["normalized_current"] = norm_current
            change.__dict__["normalized_desired"] = norm_desired
            plan.changes.append(change)

    # Reorder detection (same set of refs, but different order)
    desired_order = _ref_order(desired)
    current_order = _ref_order(current_rules)
    if set(desired_order) == set(current_order) and desired_order != current_order:
        plan.changes.append(
            RuleChange(
                change_type=ChangeType.REORDER,
                ref="*",
                phase=phase,
            )
        )

    return plan


def plan_zone(
    zone_name: str,
    desired_rules_by_phase: dict[str, list[dict]],
    current_rules_by_cf_phase: dict[str, list[dict]],
    *,
    allow_unmanaged: bool = False,
) -> ZonePlan:
    """Compute the full plan for a zone across all phases."""
    zone_plan = ZonePlan(zone_name=zone_name)

    warn_unknown_phase_keys(desired_rules_by_phase, zone_name)

    # Process phases that appear in desired config
    processed_cf_phases: set[str] = set()
    for friendly_name, desired_rules in desired_rules_by_phase.items():
        if friendly_name not in PHASE_BY_NAME:
            continue
        phase = get_phase(friendly_name)
        processed_cf_phases.add(phase.cf_phase)
        current_rules = current_rules_by_cf_phase.get(phase.cf_phase, [])
        phase_plan = diff_phase(
            phase, desired_rules, current_rules, allow_unmanaged=allow_unmanaged
        )
        if phase_plan.has_changes:
            zone_plan.phase_plans.append(phase_plan)

    # Check for phases that exist in current but not in desired (full removal)
    # Skip when allow_unmanaged is True (unmanaged phases are left alone)
    if not allow_unmanaged:
        for cf_phase, current_rules in current_rules_by_cf_phase.items():
            if cf_phase not in PHASE_BY_CF:
                continue
            if cf_phase in processed_cf_phases:
                continue
            phase = PHASE_BY_CF[cf_phase]
            if current_rules:
                phase_plan = diff_phase(phase, [], current_rules)
                if phase_plan.has_changes:
                    zone_plan.phase_plans.append(phase_plan)

    return zone_plan


def _serialize_change(change: RuleChange) -> dict:
    """Serialize a RuleChange to a deterministic dict for checksum computation."""
    d: dict = {
        "change_type": change.change_type.value,
        "ref": change.ref,
        "phase": change.phase.friendly_name,
    }
    if change.normalized_current is not None:
        d["current"] = change.normalized_current
    if change.normalized_desired is not None:
        d["desired"] = change.normalized_desired
    return d


def compute_checksum(zone_plans: list[ZonePlan]) -> str:
    """Compute a SHA-256 checksum of the plan for plan/apply verification."""
    data = []
    for zp in sorted(zone_plans, key=lambda z: z.zone_name):
        zone_data = {
            "zone_name": zp.zone_name,
            "phase_plans": [],
        }
        for pp in sorted(zp.phase_plans, key=lambda p: p.phase.friendly_name):
            phase_data = {
                "phase": pp.phase.friendly_name,
                "changes": sorted(
                    [_serialize_change(c) for c in pp.changes],
                    key=lambda c: (c["change_type"], c["ref"]),
                ),
            }
            zone_data["phase_plans"].append(phase_data)
        data.append(zone_data)
    serialized = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


@dataclass
class SafetyViolation:
    zone_name: str
    kind: str  # "delete" or "update"
    count: int
    existing: int
    percentage: float
    threshold: float
    phases: list[str] = field(default_factory=list)


def check_safety(
    zone_plan: ZonePlan,
    current_rules_by_cf_phase: dict[str, list[dict]],
    zone_config: ZoneConfig,
) -> list[SafetyViolation]:
    """Check if the plan exceeds safety thresholds for a zone.

    Returns a list of SafetyViolation objects (empty if safe).
    """
    # Sum existing rules across all phases
    existing_count = sum(len(rules) for rules in current_rules_by_cf_phase.values())
    if existing_count < zone_config.min_existing:
        return []

    # Count REMOVE and MODIFY changes per phase
    delete_count = 0
    update_count = 0
    delete_phases: list[str] = []
    update_phases: list[str] = []
    for pp in zone_plan.phase_plans:
        phase_deletes = 0
        phase_updates = 0
        for c in pp.changes:
            if c.change_type == ChangeType.REMOVE:
                phase_deletes += 1
            elif c.change_type == ChangeType.MODIFY:
                phase_updates += 1
        if phase_deletes:
            delete_count += phase_deletes
            delete_phases.append(pp.phase.friendly_name)
        if phase_updates:
            update_count += phase_updates
            update_phases.append(pp.phase.friendly_name)

    violations: list[SafetyViolation] = []
    if existing_count > 0:
        delete_pct = delete_count / existing_count * 100
        if delete_pct > zone_config.delete_threshold:
            violations.append(
                SafetyViolation(
                    zone_name=zone_plan.zone_name,
                    kind="delete",
                    count=delete_count,
                    existing=existing_count,
                    percentage=delete_pct,
                    threshold=zone_config.delete_threshold,
                    phases=delete_phases,
                )
            )
        update_pct = update_count / existing_count * 100
        if update_pct > zone_config.update_threshold:
            violations.append(
                SafetyViolation(
                    zone_name=zone_plan.zone_name,
                    kind="update",
                    count=update_count,
                    existing=existing_count,
                    percentage=update_pct,
                    threshold=zone_config.update_threshold,
                    phases=update_phases,
                )
            )
    return violations
