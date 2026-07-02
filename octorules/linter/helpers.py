"""Shared helpers for provider linter packages.

Provider packages mirror each other's lint checks by convention and keep
their own rule IDs, severities, and message wording. The pieces below are
pure logic with no provider-specific shape, so they live here and the
providers wrap them.
"""

import ipaddress
from collections.abc import Hashable, Iterable, Iterator, Mapping, Sequence
from itertools import pairwise
from typing import TypeVar

from octorules.linter.engine import LintContext, LintResult, Severity
from octorules.phases import PHASE_BY_NAME

_K = TypeVar("_K", bound=Hashable)
_R = TypeVar("_R")

CATCH_ALL_CIDRS: frozenset[str] = frozenset({"0.0.0.0/0", "::/0"})
"""The IPv4/IPv6 catch-all prefixes.

Overlap and containment checks exclude these — they contain every other
network and would otherwise flag against each entry. Dedicated rules flag
catch-all entries on their own.
"""


def find_duplicate_priorities(
    priorities: Mapping[int, Sequence[str]],
) -> list[tuple[int, list[str]]]:
    """Return ``(priority, refs)`` pairs claimed by more than one rule.

    *priorities* maps each priority value to the refs of the rules that
    use it. Pairs are returned in ascending priority order with refs in
    their original order.
    """
    return [(pri, list(refs)) for pri, refs in sorted(priorities.items()) if len(refs) > 1]


def find_first_priority_gap(priorities: Iterable[int]) -> tuple[int, int] | None:
    """Return the first gap in the sorted distinct *priorities*, or ``None``.

    A gap is an adjacent pair ``(lower, upper)`` of distinct sorted values
    with ``upper - lower > 1``. Only the first gap is returned — one
    finding per phase is enough signal, and later gaps usually follow
    from the first.
    """
    pris = sorted(set(priorities))
    for lo, hi in pairwise(pris):
        if hi - lo > 1:
            return (lo, hi)
    return None


def lint_result(
    rule_id: str,
    severity: Severity,
    message: str,
    phase: str,
    ref: str = "",
    *,
    field: str = "",
    suggestion: str = "",
) -> LintResult:
    """Build a :class:`LintResult` with positional ergonomics.

    Every provider package historically defined this same thin factory as
    a private ``_result()``; import it from here instead.
    """
    return LintResult(
        rule_id=rule_id,
        severity=severity,
        message=message,
        phase=phase,
        ref=ref,
        field=field,
        suggestion=suggestion,
    )


def is_strict_int(val: object) -> bool:
    """True for real integers only — ``bool`` is a subclass of ``int`` in
    Python and must not pass integer-field validation."""
    return isinstance(val, int) and not isinstance(val, bool)


def iter_provider_phases(
    rules_data: Mapping[str, object],
    ctx: LintContext,
    phase_names: Iterable[str],
    *,
    skip_suffixes: tuple[str, ...] = (),
) -> Iterator[tuple[str, list]]:
    """Yield the ``(phase_name, rules)`` pairs a provider linter should visit.

    Skips keys that aren't the provider's (*phase_names*), phases not in
    the registry, phases excluded by ``ctx.phase_filter``, non-list values,
    and phase names ending in any of *skip_suffixes*.
    """
    names = frozenset(phase_names)
    for phase_name, rules in rules_data.items():
        if phase_name not in names:
            continue
        if phase_name not in PHASE_BY_NAME:
            continue
        if ctx.phase_filter and phase_name not in ctx.phase_filter:
            continue
        if not isinstance(rules, list):
            continue
        if skip_suffixes and any(phase_name.endswith(s) for s in skip_suffixes):
            continue
        yield phase_name, rules


def find_overlapping_cidrs(
    items: Iterable[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]],
) -> list[tuple[str, object, str, object]]:
    """Sweep-line containment detection over ``(value, network)`` pairs.

    Returns ``(value, network, parent_value, parent_network)`` for every
    item contained in (or equal to) an earlier-sorted item, in O(n log n).
    ``network == parent_network`` means an exact duplicate; anything else
    is a redundant contained range. Mixed IPv4/IPv6 input is handled —
    families never match each other. Callers should exclude
    :data:`CATCH_ALL_CIDRS` first (a dedicated rule flags those) and keep
    their own rule IDs and message wording.
    """
    sorted_items = sorted(
        items, key=lambda x: (x[1].version, int(x[1].network_address), x[1].prefixlen)
    )
    active: list[tuple[str, ipaddress.IPv4Network | ipaddress.IPv6Network]] = []
    findings: list[tuple[str, object, str, object]] = []
    for val, net in sorted_items:
        while active and (
            active[-1][1].version != net.version
            or int(active[-1][1].broadcast_address) < int(net.network_address)
        ):
            active.pop()
        if active:
            findings.append((val, net, active[-1][0], active[-1][1]))
        active.append((val, net))
    return findings


def normalize_host_bits(value: str) -> str | None:
    """Return the host-bits-cleared network when *value* is a CIDR with
    host bits set (e.g. ``10.0.0.1/24`` → ``10.0.0.0/24``), else ``None``.

    ``None`` also covers unparseable input — callers that need to flag
    garbage separately should parse first.
    """
    try:
        ipaddress.ip_network(value, strict=True)
        return None
    except ValueError:
        pass
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError:
        return None


def find_duplicates_by_key(pairs: Iterable[tuple[_K, _R]]) -> dict[_K, list[_R]]:
    """Group ``(key, ref)`` pairs by key and return only keys with >1 ref.

    The generic shape behind duplicate-statement / duplicate-condition /
    cross-phase-uniqueness checks: the provider computes the key (a
    canonical ``json.dumps`` of a statement, a metric name, a priority)
    and formats its own finding from the surviving groups. Insertion
    order is preserved for stable messages.
    """
    seen: dict[_K, list[_R]] = {}
    for key, ref in pairs:
        seen.setdefault(key, []).append(ref)
    return {k: refs for k, refs in seen.items() if len(refs) > 1}


def count_phase_rules(
    rules_data: Mapping[str, object],
    phase_names: Iterable[str],
    *,
    exclude: Iterable[str] = (),
    dict_only: bool = True,
) -> int:
    """Total rule count across the provider's phases in *rules_data*.

    *exclude* names phases that don't count toward the limit (e.g. managed
    rules). With *dict_only* (the default) only dict-shaped entries count;
    pass ``False`` to count raw list lengths.
    """
    names = frozenset(phase_names) - frozenset(exclude)
    total = 0
    for phase_name, rules in rules_data.items():
        if phase_name not in names or not isinstance(rules, list):
            continue
        total += sum(1 for r in rules if isinstance(r, dict)) if dict_only else len(rules)
    return total
