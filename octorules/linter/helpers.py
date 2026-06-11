"""Shared helpers for provider linter packages.

Provider packages mirror each other's lint checks by convention and keep
their own rule IDs, severities, and message wording. The pieces below are
pure logic with no provider-specific shape, so they live here and the
providers wrap them.
"""

from collections.abc import Iterable, Mapping, Sequence
from itertools import pairwise

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
