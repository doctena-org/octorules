"""Function registry — Cloudflare wirefilter function signatures.

Defines all known functions, their argument types, return types,
and phase restrictions.

The registry is populated at import time from wirefilter + overlay.toml if
wirefilter is installed, or from schemas.json (frozen fallback) otherwise.

Source: https://developers.cloudflare.com/ruleset-engine/rules-language/functions/
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FunctionDef:
    """Definition of a Cloudflare wirefilter function."""

    name: str
    # Phases where this function is available (empty = all phases)
    restricted_phases: frozenset[str] = frozenset()
    # Whether this function requires a specific plan tier
    requires_plan: str = ""


FUNCTIONS: dict[str, FunctionDef] = {}


def _fn(name: str, **kwargs: object) -> FunctionDef:
    fd = FunctionDef(name=name, **kwargs)  # type: ignore[arg-type]
    FUNCTIONS[name] = fd
    return fd


# --- Load functions from wirefilter + overlay (or frozen fallback) --- #
def _load_functions() -> None:
    from octorules.linter.schemas._registry import load_schema

    schema = load_schema()
    for entry in schema["functions"]:
        kwargs: dict[str, object] = {}
        if entry.get("restricted_phases"):
            kwargs["restricted_phases"] = frozenset(entry["restricted_phases"])
        if entry.get("requires_plan"):
            kwargs["requires_plan"] = entry["requires_plan"]
        _fn(entry["name"], **kwargs)


_load_functions()


def get_function(name: str) -> FunctionDef | None:
    """Look up a function definition by name."""
    return FUNCTIONS.get(name)
