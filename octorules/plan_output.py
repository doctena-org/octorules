"""Config-driven plan output handlers."""

from dataclasses import dataclass
from typing import IO

from octorules.formatter import print_plan
from octorules.planner import ZonePlan

# Valid format names, keyed by the class path used in config files.
# The class path is kept for backward compatibility with existing configs.
PLAN_OUTPUT_FORMATS: dict[str, str] = {
    "octorules.plan_output.PlanText": "text",
    "octorules.plan_output.PlanMarkdown": "markdown",
    "octorules.plan_output.PlanJson": "json",
    "octorules.plan_output.PlanHtml": "html",
}


@dataclass
class PlanOutput:
    """A plan output destination: format + optional file path."""

    name: str
    fmt: str = "text"
    path: str | None = None

    def run(self, zone_plans: list[ZonePlan], fh: IO[str] | None = None) -> None:
        print_plan(zone_plans, file=fh, fmt=self.fmt)


# Backward-compatible aliases so existing imports don't break.
# These are thin constructors, not classes.
def PlanText(name: str, path: str | None = None) -> PlanOutput:
    return PlanOutput(name, fmt="text", path=path)


def PlanMarkdown(name: str, path: str | None = None) -> PlanOutput:
    return PlanOutput(name, fmt="markdown", path=path)


def PlanJson(name: str, path: str | None = None) -> PlanOutput:
    return PlanOutput(name, fmt="json", path=path)


def PlanHtml(name: str, path: str | None = None) -> PlanOutput:
    return PlanOutput(name, fmt="html", path=path)


# Backward compat: PLAN_OUTPUT_CLASSES still works, returns PlanOutput constructors.
PLAN_OUTPUT_CLASSES: dict[str, type[PlanOutput]] = {
    k: {"text": PlanText, "markdown": PlanMarkdown, "json": PlanJson, "html": PlanHtml}[v]
    for k, v in PLAN_OUTPUT_FORMATS.items()
}
