"""Diff engine — compares desired rules against current rules per phase."""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from functools import cached_property
from operator import itemgetter
from typing import TYPE_CHECKING

from octorules.expression import normalize_expression
from octorules.phases import (
    CF_API_FIELDS,
    KNOWN_NON_PHASE_KEYS,
    LIST_ITEM_API_FIELDS,
    PAGE_SHIELD_POLICY_API_FIELDS,
    PHASE_BY_CF,
    PHASE_BY_NAME,
    RENAMED_PHASES,
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
class CustomRulesetPlan:
    ruleset_id: str
    ruleset_name: str
    phase: str
    changes: list[RuleChange] = field(default_factory=list)
    prepared_rules: list[dict] | None = field(default=None, repr=False, compare=False)

    @property
    def has_changes(self) -> bool:
        return len(self.changes) > 0


@dataclass
class ListPlan:
    list_name: str
    list_id: str | None = None  # None for CREATE (not yet in CF)
    list_kind: str = ""  # ip, asn, hostname, redirect
    create: bool = False  # list needs to be created
    delete: bool = False  # list will be deleted
    description_change: tuple[str | None, str | None] | None = None  # (current, desired)
    changes: list[RuleChange] = field(default_factory=list)  # item changes
    prepared_items: list[dict] | None = field(default=None, repr=False, compare=False)

    @property
    def has_changes(self) -> bool:
        return (
            self.create
            or self.delete
            or self.description_change is not None
            or len(self.changes) > 0
        )

    @property
    def total_changes(self) -> int:
        count = len(self.changes)
        if self.create:
            count += 1
        if self.delete:
            count += 1
        if self.description_change is not None:
            count += 1
        return count


@dataclass
class PageShieldPolicyPlan:
    description: str
    policy_id: str | None = None  # None for CREATE
    create: bool = False
    delete: bool = False
    changes: list[RuleChange] = field(default_factory=list)  # field-level changes

    @property
    def has_changes(self) -> bool:
        return self.create or self.delete or len(self.changes) > 0

    @property
    def total_changes(self) -> int:
        count = len(self.changes)
        if self.create:
            count += 1
        if self.delete:
            count += 1
        return count


@dataclass
class ZonePlan:
    zone_name: str
    phase_plans: list[PhasePlan] = field(default_factory=list)
    custom_ruleset_plans: list[CustomRulesetPlan] = field(default_factory=list)
    list_plans: list[ListPlan] = field(default_factory=list)
    page_shield_policy_plans: list[PageShieldPolicyPlan] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return (
            any(pp.has_changes for pp in self.phase_plans)
            or any(crp.has_changes for crp in self.custom_ruleset_plans)
            or any(lp.has_changes for lp in self.list_plans)
            or any(psp.has_changes for psp in self.page_shield_policy_plans)
        )

    @property
    def total_changes(self) -> int:
        return (
            sum(len(pp.changes) for pp in self.phase_plans)
            + sum(len(crp.changes) for crp in self.custom_ruleset_plans)
            + sum(lp.total_changes for lp in self.list_plans)
            + sum(psp.total_changes for psp in self.page_shield_policy_plans)
        )


class RuleValidationError(Exception):
    """Raised when a rule fails validation."""


# Keys whose string values need whitespace normalization for comparison.
# Includes wirefilter expressions and CSP value strings (which the dumper
# may reformat as multi-line block scalars).
_NORMALIZE_KEYS = frozenset({"expression", "counting_expression", "value"})


def _normalize_value(v: object, *, key: str = "") -> object:
    """Normalize a value for comparison.

    Only applies expression normalization to known expression keys.
    """
    if key in _NORMALIZE_KEYS and isinstance(v, str):
        return normalize_expression(v)
    return v


def normalize_rule(rule: dict) -> dict:
    """Strip API-only fields and normalize expression values for comparison."""
    return {k: _normalize_value(v, key=k) for k, v in rule.items() if k not in API_ONLY_FIELDS}


def _require_string_field(entry: dict, field_name: str, context: str) -> str:
    """Validate that *entry* has a non-empty string *field_name*.

    Returns the field value. Raises RuleValidationError with *context* on failure.
    """
    if field_name not in entry:
        raise RuleValidationError(f"{context} is missing required {field_name!r} field")
    value = entry[field_name]
    if not isinstance(value, str) or not value:
        raise RuleValidationError(
            f"{context} has invalid {field_name!r} (must be a non-empty string)"
        )
    return value


def validate_rules(rules: list[dict], phase: Phase) -> None:
    """Validate a list of desired rules for a phase.

    Checks:
    - Every rule has a 'ref' field
    - Every rule has an 'expression' field
    - No duplicate refs within the phase
    """
    seen_refs: set[str] = set()
    for i, rule in enumerate(rules):
        ctx = f"Rule at index {i} in {phase.friendly_name!r}"
        ref = _require_string_field(rule, "ref", ctx)
        _require_string_field(rule, "expression", f"Rule {ref!r} in {phase.friendly_name!r}")
        if ref in seen_refs:
            raise RuleValidationError(f"Duplicate ref {ref!r} in {phase.friendly_name!r}")
        seen_refs.add(ref)


def warn_unknown_phase_keys(rules_data: dict, zone_name: str) -> None:
    """Warn about unknown top-level keys in a zone rules file."""
    # Warn about renamed phases (they still work via aliases but are deprecated)
    for key in sorted(set(rules_data.keys()) & RENAMED_PHASES.keys()):
        new_name = RENAMED_PHASES[key]
        log.warning(
            "Phase %r has been renamed to %r in rules for %s. "
            "Please update your YAML file. The old name still works but is deprecated.",
            key,
            new_name,
            zone_name,
        )
    # Warn about truly unknown phases
    unknown = set(rules_data.keys()) - PHASE_BY_NAME.keys() - KNOWN_NON_PHASE_KEYS
    for key in sorted(unknown):
        log.warning("%s in rules for %s", unknown_phase_message(key), zone_name)


def _rules_by_ref(rules: list[dict]) -> dict[str, dict]:
    """Index a list of rules by their ref field.

    If duplicate refs exist, the last one wins and a warning is logged.
    """
    result: dict[str, dict] = {}
    for rule in rules:
        ref = rule.get("ref")
        if ref:
            if ref in result:
                log.warning("Duplicate ref %r in rules — later entry overwrites earlier", ref)
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
        # Normalize expression whitespace (multi-line YAML → single line)
        rule["expression"] = normalize_expression(rule["expression"])
        # Normalize counting_expression if present
        ap = rule.get("action_parameters")
        if isinstance(ap, dict) and isinstance(ap.get("counting_expression"), str):
            ap = ap.copy()
            ap["counting_expression"] = normalize_expression(ap["counting_expression"])
            rule["action_parameters"] = ap
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


def _diff_rules(
    phase: Phase,
    desired_rules: list[dict],
    current_rules: list[dict],
    *,
    allow_unmanaged: bool = False,
) -> list[RuleChange]:
    """Compute add/remove/modify/reorder changes between desired and current rules.

    Works for both real phases and synthetic phases (custom rulesets). When
    allow_unmanaged=True, REMOVE changes are suppressed and reorder detection
    is scoped to the managed (desired) refs only.
    """
    changes: list[RuleChange] = []
    desired_by_ref = _rules_by_ref(desired_rules)
    current_by_ref = _rules_by_ref(current_rules)

    desired_refs = set(desired_by_ref.keys())
    current_refs = set(current_by_ref.keys())

    # Additions
    for ref in desired_refs - current_refs:
        changes.append(
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
            changes.append(
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
            changes.append(change)

    # Reorder detection (same set of refs, but different order).
    # When allow_unmanaged=True, filter current to only managed refs.
    desired_order = _ref_order(desired_rules)
    current_order = _ref_order(current_rules)
    if allow_unmanaged:
        current_order = [r for r in current_order if r in desired_refs]
    if set(desired_order) == set(current_order) and desired_order != current_order:
        changes.append(
            RuleChange(
                change_type=ChangeType.REORDER,
                ref="*",
                phase=phase,
            )
        )

    return changes


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
    plan.changes = _diff_rules(phase, desired, current_rules, allow_unmanaged=allow_unmanaged)
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


def validate_custom_ruleset(entry: dict, index: int) -> None:
    """Validate a custom_rulesets entry from YAML.

    Checks: id, name, phase, and rules list are present and valid.
    """
    ctx = f"custom_rulesets[{index}]"
    rid = _require_string_field(entry, "id", ctx)
    _require_string_field(entry, "name", ctx)
    _require_string_field(entry, "phase", ctx)
    phase = entry["phase"]
    if phase not in PHASE_BY_CF:
        raise RuleValidationError(
            f"{ctx} has invalid 'phase' {phase!r}."
            f" Use a valid CF phase ID (e.g. 'http_request_firewall_custom')"
        )
    rules = entry.get("rules", [])
    if not isinstance(rules, list):
        raise RuleValidationError(f"{ctx} 'rules' must be a list")
    # Validate individual rules
    seen_refs: set[str] = set()
    label = entry.get("name") or rid
    for ri, rule in enumerate(rules):
        rule_ctx = f"Rule at index {ri} in custom ruleset {label!r}"
        ref = _require_string_field(rule, "ref", rule_ctx)
        _require_string_field(rule, "expression", f"Rule {ref!r} in custom ruleset {label!r}")
        if "action" not in rule:
            raise RuleValidationError(
                f"Rule {ref!r} in custom ruleset {label!r} must specify an 'action'"
            )
        if ref in seen_refs:
            raise RuleValidationError(f"Duplicate ref {ref!r} in custom ruleset {label!r}")
        seen_refs.add(ref)


def _make_synthetic_phase(ruleset_name: str, cf_phase: str) -> Phase:
    """Create a synthetic Phase for a custom ruleset (used in RuleChange)."""
    return Phase(
        friendly_name=f"custom_ruleset:{ruleset_name}",
        cf_phase=cf_phase,
        default_action=None,
        zone_level=False,
        account_level=True,
    )


def diff_custom_ruleset(
    ruleset_id: str,
    ruleset_name: str,
    phase: str,
    desired_rules: list[dict],
    current_rules: list[dict],
) -> CustomRulesetPlan:
    """Compute the diff for a single custom ruleset."""
    plan = CustomRulesetPlan(
        ruleset_id=ruleset_id,
        ruleset_name=ruleset_name,
        phase=phase,
    )

    # Prepare desired rules: normalize expressions, default enabled to True
    prepared = []
    for rule in desired_rules:
        rule = rule.copy()
        rule["expression"] = normalize_expression(rule["expression"])
        if "enabled" not in rule:
            rule["enabled"] = True
        prepared.append(rule)
    plan.prepared_rules = prepared

    synthetic_phase = _make_synthetic_phase(ruleset_name, phase)
    plan.changes = _diff_rules(synthetic_phase, prepared, current_rules)
    return plan


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
        zone_data: dict = {
            "zone_name": zp.zone_name,
            "phase_plans": [],
        }
        for pp in sorted(zp.phase_plans, key=lambda p: p.phase.friendly_name):
            phase_data = {
                "phase": pp.phase.friendly_name,
                "changes": sorted(
                    [_serialize_change(c) for c in pp.changes],
                    key=itemgetter("change_type", "ref"),
                ),
            }
            zone_data["phase_plans"].append(phase_data)
        if zp.custom_ruleset_plans:
            cr_plans = []
            for crp in sorted(zp.custom_ruleset_plans, key=lambda c: c.ruleset_id):
                cr_data = {
                    "ruleset_id": crp.ruleset_id,
                    "changes": sorted(
                        [_serialize_change(c) for c in crp.changes],
                        key=itemgetter("change_type", "ref"),
                    ),
                }
                cr_plans.append(cr_data)
            zone_data["custom_ruleset_plans"] = cr_plans
        if zp.list_plans:
            lp_data = []
            for lp in sorted(zp.list_plans, key=lambda lp_: lp_.list_name):
                entry: dict = {
                    "list_name": lp.list_name,
                    "create": lp.create,
                    "delete": lp.delete,
                }
                if lp.description_change is not None:
                    entry["description_change"] = list(lp.description_change)
                if lp.changes:
                    entry["changes"] = sorted(
                        [_serialize_change(c) for c in lp.changes],
                        key=itemgetter("change_type", "ref"),
                    )
                lp_data.append(entry)
            zone_data["list_plans"] = lp_data
        if zp.page_shield_policy_plans:
            psp_data = []
            for psp in sorted(zp.page_shield_policy_plans, key=lambda p: p.description):
                entry: dict = {
                    "description": psp.description,
                    "create": psp.create,
                    "delete": psp.delete,
                }
                if psp.changes:
                    entry["changes"] = sorted(
                        [_serialize_change(c) for c in psp.changes],
                        key=itemgetter("change_type", "ref"),
                    )
                psp_data.append(entry)
            zone_data["page_shield_policy_plans"] = psp_data
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

    # Count REMOVE and MODIFY changes across all plan types
    delete_count = 0
    update_count = 0
    delete_phases: list[str] = []
    update_phases: list[str] = []

    def _tally(
        changes: list[RuleChange],
        label: str,
        extra_deletes: int = 0,
    ) -> None:
        nonlocal delete_count, update_count
        deletes = extra_deletes
        updates = 0
        for c in changes:
            if c.change_type == ChangeType.REMOVE:
                deletes += 1
            elif c.change_type == ChangeType.MODIFY:
                updates += 1
        if deletes:
            delete_count += deletes
            delete_phases.append(label)
        if updates:
            update_count += updates
            update_phases.append(label)

    for pp in zone_plan.phase_plans:
        _tally(pp.changes, pp.phase.friendly_name)
    for crp in zone_plan.custom_ruleset_plans:
        _tally(crp.changes, f"custom_ruleset:{crp.ruleset_name}")
    for lp in zone_plan.list_plans:
        _tally(lp.changes, f"list:{lp.list_name}", extra_deletes=int(lp.delete))
    for psp in zone_plan.page_shield_policy_plans:
        _tally(psp.changes, f"page_shield:{psp.description}", extra_deletes=int(psp.delete))

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


# --- List helpers ---

_VALID_LIST_KINDS = frozenset({"ip", "asn", "hostname", "redirect"})


def _item_identity(item: dict, kind: str) -> str:
    """Extract the identity key from a list item based on kind."""
    if kind == "ip":
        return item.get("ip", "")
    if kind == "asn":
        asn = item.get("asn")
        if asn is None:
            return ""
        return str(asn)
    if kind == "hostname":
        hostname = item.get("hostname", {})
        if isinstance(hostname, dict):
            return hostname.get("url_hostname", "")
        return ""
    if kind == "redirect":
        redirect = item.get("redirect", {})
        if isinstance(redirect, dict):
            return redirect.get("source_url", "")
        return ""
    return ""


def _items_by_identity(items: list[dict], kind: str) -> dict[str, dict]:
    """Index items by their identity key.

    Items with empty identity keys are skipped with a warning.  Duplicate keys
    log a warning and the later entry overwrites the earlier one.
    """
    result: dict[str, dict] = {}
    for item in items:
        key = _item_identity(item, kind)
        if key:
            if key in result:
                log.warning(
                    "Duplicate list item identity %r (kind=%s) — later entry overwrites", key, kind
                )
            result[key] = item
        else:
            log.warning("Skipping list item with empty identity key (kind=%s): %s", kind, item)
    return result


def normalize_list_item(item: dict) -> dict:
    """Strip LIST_ITEM_API_FIELDS for comparison. No expression normalization needed."""
    return {k: v for k, v in item.items() if k not in LIST_ITEM_API_FIELDS}


def _make_list_phase(list_name: str) -> Phase:
    """Create a synthetic Phase for list item changes."""
    return Phase(
        friendly_name=f"list:{list_name}",
        cf_phase="account_lists",
        default_action=None,
        zone_level=False,
        account_level=True,
    )


def validate_list_entry(entry: dict, index: int) -> None:
    """Validate a lists entry from YAML.

    Checks: name required, kind required (one of valid kinds), items must be a list,
    each item must have the field matching kind, no duplicate identity values.
    """
    if "name" not in entry:
        raise RuleValidationError(f"lists[{index}] is missing required 'name' field")
    name = entry["name"]
    if not isinstance(name, str) or not name:
        raise RuleValidationError(f"lists[{index}] has invalid 'name' (must be a non-empty string)")
    if "kind" not in entry:
        raise RuleValidationError(f"lists[{index}] ({name!r}) is missing required 'kind' field")
    kind = entry["kind"]
    if kind not in _VALID_LIST_KINDS:
        raise RuleValidationError(
            f"lists[{index}] ({name!r}) has invalid 'kind' {kind!r}."
            f" Must be one of: {', '.join(sorted(_VALID_LIST_KINDS))}"
        )
    items = entry.get("items", [])
    if not isinstance(items, list):
        raise RuleValidationError(f"lists[{index}] ({name!r}) 'items' must be a list")
    seen: set[str] = set()
    for i, item in enumerate(items):
        identity = _item_identity(item, kind)
        if not identity:
            raise RuleValidationError(
                f"lists[{index}] ({name!r}) item at index {i}"
                f" is missing required field for kind {kind!r}"
            )
        if identity in seen:
            raise RuleValidationError(f"lists[{index}] ({name!r}) has duplicate item {identity!r}")
        seen.add(identity)


def diff_list(
    list_name: str,
    list_id: str | None,
    list_kind: str,
    desired_items: list[dict],
    current_items: list[dict],
    *,
    desired_description: str | None = None,
    current_description: str | None = None,
) -> ListPlan:
    """Compute the diff for a single list's items."""
    plan = ListPlan(
        list_name=list_name,
        list_id=list_id,
        list_kind=list_kind,
    )
    synthetic_phase = _make_list_phase(list_name)

    # If no list_id, this is a create
    if list_id is None:
        plan.create = True
        for item in desired_items:
            identity = _item_identity(item, list_kind)
            plan.changes.append(
                RuleChange(
                    change_type=ChangeType.ADD,
                    ref=identity,
                    phase=synthetic_phase,
                    desired=item,
                )
            )
        plan.prepared_items = desired_items
        if desired_description:
            plan.description_change = (None, desired_description)
        return plan

    # Item-level diff
    desired_by_id = _items_by_identity(desired_items, list_kind)
    current_by_id = _items_by_identity(current_items, list_kind)

    desired_keys = set(desired_by_id.keys())
    current_keys = set(current_by_id.keys())

    # Additions
    for key in desired_keys - current_keys:
        plan.changes.append(
            RuleChange(
                change_type=ChangeType.ADD,
                ref=key,
                phase=synthetic_phase,
                desired=desired_by_id[key],
            )
        )

    # Removals
    for key in current_keys - desired_keys:
        plan.changes.append(
            RuleChange(
                change_type=ChangeType.REMOVE,
                ref=key,
                phase=synthetic_phase,
                current=current_by_id[key],
            )
        )

    # Modifications
    for key in desired_keys & current_keys:
        norm_desired = normalize_list_item(desired_by_id[key])
        norm_current = normalize_list_item(current_by_id[key])
        if norm_desired != norm_current:
            change = RuleChange(
                change_type=ChangeType.MODIFY,
                ref=key,
                phase=synthetic_phase,
                current=current_by_id[key],
                desired=desired_by_id[key],
            )
            change.__dict__["normalized_current"] = norm_current
            change.__dict__["normalized_desired"] = norm_desired
            plan.changes.append(change)

    # Description change
    if desired_description != current_description:
        if desired_description is not None or current_description is not None:
            plan.description_change = (current_description, desired_description)

    # Always set prepared_items to full desired list
    plan.prepared_items = desired_items

    return plan


def diff_lists_full(
    desired_lists: list[dict],
    current_lists: dict[str, dict],
) -> list[ListPlan]:
    """Compute the full diff for all lists including creates and deletes.

    Args:
        desired_lists: List of desired list entries from YAML.
        current_lists: Dict of {name: {id, kind, description, items}} from CF.

    Returns list of ListPlan objects.
    """
    plans: list[ListPlan] = []
    desired_names = {entry["name"] for entry in desired_lists}

    # Lists in desired
    for entry in desired_lists:
        name = entry["name"]
        kind = entry["kind"]
        desired_items = entry.get("items", [])
        desired_description = entry.get("description")
        current = current_lists.get(name)

        if current is None:
            # CREATE
            lp = diff_list(
                name,
                None,
                kind,
                desired_items,
                [],
                desired_description=desired_description,
            )
            plans.append(lp)
        else:
            # EXISTING — diff items
            lp = diff_list(
                name,
                current["id"],
                kind,
                desired_items,
                current.get("items", []),
                desired_description=desired_description,
                current_description=current.get("description"),
            )
            if lp.has_changes:
                plans.append(lp)

    # Lists in current but not in desired → DELETE
    for name, current in current_lists.items():
        if name not in desired_names:
            lp = ListPlan(
                list_name=name,
                list_id=current["id"],
                list_kind=current.get("kind", ""),
                delete=True,
            )
            plans.append(lp)

    return plans


# --- Page Shield Policy helpers ---

_VALID_PAGE_SHIELD_ACTIONS = frozenset({"allow", "log"})

_PAGE_SHIELD_DIFF_FIELDS = ("action", "expression", "enabled", "value")


def _make_page_shield_phase(description: str) -> Phase:
    """Create a synthetic Phase for a page shield policy (used in RuleChange)."""
    return Phase(
        friendly_name=f"page_shield:{description}",
        cf_phase="page_shield_policies",
        default_action=None,
        zone_level=True,
        account_level=False,
    )


def normalize_page_shield_policy(policy: dict) -> dict:
    """Strip PAGE_SHIELD_POLICY_API_FIELDS and normalize expression for comparison."""
    return {
        k: _normalize_value(v, key=k)
        for k, v in policy.items()
        if k not in PAGE_SHIELD_POLICY_API_FIELDS
    }


def validate_page_shield_policy(entry: dict, index: int) -> None:
    """Validate a page_shield_policies entry from YAML.

    Checks: description required (non-empty string), action required (allow/log),
    expression required (string), enabled required (bool), value required (string).
    """
    ctx = f"page_shield_policies[{index}]"
    desc = _require_string_field(entry, "description", ctx)
    ctx_desc = f"{ctx} ({desc!r})"
    _require_string_field(entry, "action", ctx_desc)
    action = entry["action"]
    if action not in _VALID_PAGE_SHIELD_ACTIONS:
        raise RuleValidationError(
            f"{ctx_desc} has invalid 'action' {action!r}."
            f" Must be one of: {', '.join(sorted(_VALID_PAGE_SHIELD_ACTIONS))}"
        )
    _require_string_field(entry, "expression", ctx_desc)
    if "enabled" not in entry:
        raise RuleValidationError(f"{ctx_desc} is missing required 'enabled' field")
    if not isinstance(entry["enabled"], bool):
        raise RuleValidationError(f"{ctx_desc} has invalid 'enabled' (must be a boolean)")
    _require_string_field(entry, "value", ctx_desc)


def _diff_fields(desired: dict, current: dict, fields: tuple[str, ...]) -> list[RuleChange]:
    """Compute field-level diffs between desired and current dicts.

    Returns a list of MODIFY RuleChanges for fields that differ.
    """
    changes: list[RuleChange] = []
    synthetic = _make_page_shield_phase(desired.get("description", ""))
    for fname in fields:
        d_val = _normalize_value(desired.get(fname), key=fname)
        c_val = _normalize_value(current.get(fname), key=fname)
        if d_val != c_val:
            change = RuleChange(
                change_type=ChangeType.MODIFY,
                ref=fname,
                phase=synthetic,
                current={fname: c_val},
                desired={fname: d_val},
            )
            change.__dict__["normalized_current"] = {fname: c_val}
            change.__dict__["normalized_desired"] = {fname: d_val}
            changes.append(change)
    return changes


def diff_page_shield_policies(
    desired_policies: list[dict],
    current_policies: list[dict],
) -> list[PageShieldPolicyPlan]:
    """Compute the full diff for page shield policies using description as identity key.

    Args:
        desired_policies: List of desired policy entries from YAML.
        current_policies: List of current policy dicts from CF (with id stripped).

    Returns list of PageShieldPolicyPlan objects, sorted by description.
    """
    plans: list[PageShieldPolicyPlan] = []

    # Index current by description
    current_by_desc: dict[str, dict] = {}
    for p in current_policies:
        desc = p.get("description", "")
        if desc:
            current_by_desc[desc] = p

    desired_descs: set[str] = set()

    # Desired policies
    for entry in desired_policies:
        entry = entry.copy()
        if isinstance(entry.get("expression"), str):
            entry["expression"] = normalize_expression(entry["expression"])
        desc = entry["description"]
        desired_descs.add(desc)
        current = current_by_desc.get(desc)

        if current is None:
            # CREATE
            synthetic = _make_page_shield_phase(desc)
            field_changes = []
            for field in _PAGE_SHIELD_DIFF_FIELDS:
                val = entry.get(field)
                if val is not None:
                    field_changes.append(
                        RuleChange(
                            change_type=ChangeType.ADD,
                            ref=field,
                            phase=synthetic,
                            desired={field: val},
                        )
                    )
            pp = PageShieldPolicyPlan(
                description=desc,
                create=True,
                changes=field_changes,
            )
            plans.append(pp)
        else:
            # EXISTING — field-level diff
            policy_id = current.get("id")
            field_changes = _diff_fields(entry, current, _PAGE_SHIELD_DIFF_FIELDS)
            if field_changes:
                pp = PageShieldPolicyPlan(
                    description=desc,
                    policy_id=policy_id,
                    changes=field_changes,
                )
                plans.append(pp)

    # Current not in desired → DELETE
    for desc, current in current_by_desc.items():
        if desc not in desired_descs:
            pp = PageShieldPolicyPlan(
                description=desc,
                policy_id=current.get("id"),
                delete=True,
            )
            plans.append(pp)

    return sorted(plans, key=lambda p: p.description)
