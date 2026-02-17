"""Config-driven plan output handlers (octodns-style class: registry)."""

from __future__ import annotations

from typing import IO

from octorules.formatter import print_plan
from octorules.planner import ZonePlan


class PlanOutput:
    """Base class for plan output handlers."""

    def __init__(self, name: str, path: str | None = None):
        self.name = name
        self.path = path

    def run(self, zone_plans: list[ZonePlan], fh: IO[str] | None = None) -> None:
        raise NotImplementedError


class PlanText(PlanOutput):
    def run(self, zone_plans: list[ZonePlan], fh: IO[str] | None = None) -> None:
        print_plan(zone_plans, file=fh, fmt="text")


class PlanMarkdown(PlanOutput):
    def run(self, zone_plans: list[ZonePlan], fh: IO[str] | None = None) -> None:
        print_plan(zone_plans, file=fh, fmt="markdown")


class PlanJson(PlanOutput):
    def run(self, zone_plans: list[ZonePlan], fh: IO[str] | None = None) -> None:
        print_plan(zone_plans, file=fh, fmt="json")


class PlanHtml(PlanOutput):
    def run(self, zone_plans: list[ZonePlan], fh: IO[str] | None = None) -> None:
        print_plan(zone_plans, file=fh, fmt="html")


PLAN_OUTPUT_CLASSES: dict[str, type[PlanOutput]] = {
    "octorules.plan_output.PlanText": PlanText,
    "octorules.plan_output.PlanMarkdown": PlanMarkdown,
    "octorules.plan_output.PlanJson": PlanJson,
    "octorules.plan_output.PlanHtml": PlanHtml,
}
