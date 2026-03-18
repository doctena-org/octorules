"""Processor pipeline for transforming desired rules and planned changes."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from octorules.planner import ZonePlan
    from octorules.provider.base import BaseProvider


class BaseProcessor:
    """Base class for rule processors.

    Processors hook into the plan/sync pipeline to transform desired rules
    and planned changes.  Subclasses override one or both methods.
    """

    def process_desired(self, zone_name: str, desired: dict, provider: BaseProvider) -> dict:
        """Transform desired rules before planning.

        Called after phase filtering, before ``plan_zone()``.
        Return the (possibly modified) desired dict.
        """
        return desired

    def process_changes(self, zone_name: str, plan: ZonePlan, provider: BaseProvider) -> ZonePlan:
        """Transform planned changes after planning.

        Called after ``plan_zone()``, before the plan is returned.
        Return the (possibly modified) ZonePlan.
        """
        return plan


from octorules.processor.filters import ChangeTypeFilter, PhaseFilter, RefFilter  # noqa: E402

__all__ = ["BaseProcessor", "ChangeTypeFilter", "PhaseFilter", "RefFilter"]
