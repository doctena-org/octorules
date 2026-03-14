"""Field registry — Cloudflare wirefilter field definitions.

Each field has a name, type, and set of phases where it's available.
Used for expression analysis: type checking, phase restrictions, value validation.

The registry is populated at import time from wirefilter + overlay.toml if
wirefilter is installed, or from schemas.json (frozen fallback) otherwise.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class FieldType(Enum):
    """Wirefilter field types."""

    STRING = "String"
    INT = "Int"
    BOOL = "Bool"
    IP = "IP"
    BYTES = "Bytes"
    MAP_STRING_STRING = "Map<String, String>"
    MAP_STRING_INT = "Map<String, Int>"
    ARRAY_STRING = "Array<String>"
    ARRAY_INT = "Array<Int>"
    MAP_ARRAY_STRING = "Map<Array<String>>"
    MAP_ARRAY_INT = "Map<Array<Int>>"
    ARRAY_ARRAY_STRING = "Array<Array<String>>"


# Map wirefilter type name → FieldType enum member
_TYPE_MAP: dict[str, FieldType] = {ft.name: ft for ft in FieldType}


@dataclass(frozen=True)
class FieldDef:
    """Definition of a Cloudflare wirefilter field."""

    name: str
    field_type: FieldType
    # Phases where this field is available (empty = all phases)
    phases: frozenset[str] = frozenset()
    # Whether this is a response-only field
    is_response: bool = False
    # Whether this field requires a specific plan tier
    requires_plan: str = ""  # empty = all plans


FIELDS: dict[str, FieldDef] = {}


def _f(name: str, ftype: FieldType, **kwargs: object) -> FieldDef:
    fd = FieldDef(name=name, field_type=ftype, **kwargs)  # type: ignore[arg-type]
    FIELDS[name] = fd
    return fd


# --- Load fields from wirefilter + overlay (or frozen fallback) --- #
def _load_fields() -> None:
    from octorules.linter.schemas._registry import load_schema

    schema = load_schema()
    for entry in schema["fields"]:
        kwargs: dict[str, object] = {}
        if entry.get("requires_plan"):
            kwargs["requires_plan"] = entry["requires_plan"]
        if entry.get("is_response"):
            kwargs["is_response"] = True
        _f(entry["name"], _TYPE_MAP[entry["type"]], **kwargs)


_load_fields()


# --- Fields NOT in the schema --- #
# These are intentionally kept as Python code because they are not returned
# by wirefilter's get_schema_info(). DO NOT remove them — each serves a
# specific purpose documented below.

# http.request.uri.path — present in the wirefilter scheme as a field, but
# in transform phases Cloudflare treats it as a callable function. The
# wirefilter side registers it as a field; transform-phase handling is on
# the Python side.
_f("http.request.uri.path", FieldType.STRING)

# Deprecated ip.geoip.* fields — Cloudflare replaced these with ip.src.*
# equivalents. We keep them registered so the linter can detect usage and emit
# G010 "deprecated field — use replacement" warnings. If removed, users would
# get F002 "unknown field" instead of the more helpful G010 with a suggested
# replacement.
_f("ip.geoip.asnum", FieldType.INT)
_f("ip.geoip.continent", FieldType.STRING)
_f("ip.geoip.country", FieldType.STRING)
_f("ip.geoip.subdivision_1_iso_code", FieldType.STRING)
_f("ip.geoip.subdivision_2_iso_code", FieldType.STRING)
_f("ip.geoip.is_in_european_union", FieldType.BOOL)

# Account-level zone fields — used in account-level rulesets (e.g. WAF custom
# rules deployed at account scope can match on cf.zone.name). Not in the
# per-zone CF docs reference page because they only apply to account-level
# expressions. Removing them would cause false-positive F002 warnings.
_f("cf.zone.name", FieldType.STRING)
_f("cf.zone.plan", FieldType.STRING)


# --- Response-only phases ---
# Phases where response fields are available
RESPONSE_PHASES = frozenset(
    {
        "response_header_rules",
        "compression_rules",
        "sensitive_data_detection",
        "custom_error_rules",
        "log_custom_fields",
    }
)

# Phases where request body fields are available
BODY_PHASES = frozenset(
    {
        "waf_custom_rules",
        "waf_managed_rules",
        "rate_limiting_rules",
        "custom_error_rules",
    }
)


def get_field(name: str) -> FieldDef | None:
    """Look up a field definition by name."""
    return FIELDS.get(name)


def is_response_field(name: str) -> bool:
    """Check if a field is response-only."""
    fd = FIELDS.get(name)
    return fd.is_response if fd else False


def is_body_field(name: str) -> bool:
    """Check if a field is a request body field."""
    return name.startswith("http.request.body.")
