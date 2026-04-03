"""Processor pipeline for transforming desired rules and planned changes.

Processors hook into the plan/sync pipeline.  Any object with
``process_desired`` and/or ``process_changes`` methods satisfies the
:class:`BaseProcessor` protocol.
"""

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from octorules.planner import ZonePlan
    from octorules.provider.base import BaseProvider


@runtime_checkable
class BaseProcessor(Protocol):
    """Protocol for rule processors.

    Implementations may define one or both methods.  Missing methods
    default to identity (return input unchanged) — the call sites in
    :mod:`octorules.commands._plan` use :func:`getattr` with a fallback.
    """

    def process_desired(self, zone_name: str, desired: dict, provider: "BaseProvider") -> dict:
        """Transform desired rules before planning."""
        ...

    def process_changes(
        self, zone_name: str, plan: "ZonePlan", provider: "BaseProvider"
    ) -> "ZonePlan":
        """Transform planned changes after planning."""
        ...


from octorules.processor.filters import ChangeTypeFilter, PhaseFilter, RefFilter  # noqa: E402

__all__ = ["BaseProcessor", "ChangeTypeFilter", "PhaseFilter", "RefFilter"]
