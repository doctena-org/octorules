"""Lint rule registry — central catalog of rule IDs, descriptions, and severities.

The registry starts empty.  Provider packages populate it at import time
via ``register_rules()``, matching the ``register_phase()`` pattern.
"""

from dataclasses import dataclass

from octorules.linter.engine import Severity

#: The named sets a rule may belong to, and the only names
#: ``manager.lint.sets`` accepts.  Both sides validate against this list: a
#: typo'd set name puts a rule in no active set, which stops it reporting
#: without saying so.
KNOWN_RULE_SETS = frozenset({"default", "strict"})


@dataclass(frozen=True)
class RuleMeta:
    """Metadata for a lint rule."""

    rule_id: str
    category: str
    description: str
    default_severity: Severity
    #: Named sets this rule belongs to.  ``manager.lint.sets`` selects which
    #: sets are active, so a rule outside every selected set does not run.
    sets: frozenset[str] = frozenset({"default"})
    #: Whether an ``octorules:disable=`` directive in a zone file may waive
    #: this rule.  False for rules that decide whether plan manages a
    #: section: a comment in a data file must not switch off a deploy-time
    #: guard, and the exemption belongs in the config instead.
    suppressible: bool = True

    def __post_init__(self) -> None:
        unknown = sorted(self.sets - KNOWN_RULE_SETS)
        if unknown:
            raise ValueError(
                f"{self.rule_id}: unknown rule set(s) {', '.join(unknown)} —"
                f" known sets are {', '.join(sorted(KNOWN_RULE_SETS))}"
            )


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


def is_suppressible(rule_id: str) -> bool:
    """Whether a zone-file directive may waive *rule_id*.

    Unknown rules default to suppressible: a provider that has not declared
    the rule should not have its findings become unwaivable by accident.
    """
    meta = RULE_REGISTRY.get(rule_id)
    return True if meta is None else meta.suppressible
