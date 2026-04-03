"""Lint rule registry — central catalog of rule IDs, descriptions, and severities.

The registry starts empty.  Provider packages populate it at import time
via ``register_rules()``, matching the ``register_phase()`` pattern.
"""

from dataclasses import dataclass

from octorules.linter.engine import Severity


@dataclass(frozen=True)
class RuleMeta:
    """Metadata for a lint rule."""

    rule_id: str
    category: str
    description: str
    default_severity: Severity


RULE_REGISTRY: dict[str, RuleMeta] = {}


def register_rules(rules: list[RuleMeta]) -> None:
    """Merge rule definitions into the global registry."""
    for rule in rules:
        RULE_REGISTRY[rule.rule_id] = rule


def unregister_rules(rule_ids: list[str]) -> None:
    """Remove rules from the registry (for test teardown)."""
    for rule_id in rule_ids:
        RULE_REGISTRY.pop(rule_id, None)


def get_rule_meta(rule_id: str) -> RuleMeta | None:
    """Look up a rule's metadata by ID."""
    return RULE_REGISTRY.get(rule_id)


def all_rule_ids() -> list[str]:
    """Return all registered rule IDs, sorted."""
    return sorted(RULE_REGISTRY.keys())
