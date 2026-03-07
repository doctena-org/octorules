#!/usr/bin/env python3
"""Regenerate generated blocks in fields.py and functions.py from wirefilter.

Reads the authoritative field/function list from octorules_wirefilter.get_schema_info()
and merges with Python-only metadata from overlay.toml.

Usage:
    python scripts/sync_schemas.py           # regenerate in place
    python scripts/sync_schemas.py --check   # compare only, exit 1 if different
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

try:
    import importlib.metadata

    _wf_version = importlib.metadata.version("octorules-wirefilter")
    from octorules_wirefilter import get_schema_info
except ImportError:
    print(
        "ERROR: octorules_wirefilter is not installed.\n"
        "Install it with: pip install octorules-wirefilter\n"
        "Or build from source: cd ../octorules-wirefilter && maturin develop",
        file=sys.stderr,
    )
    sys.exit(1)

SCHEMAS_DIR = Path(__file__).resolve().parent.parent / "src" / "octorules" / "linter" / "schemas"
OVERLAY_PATH = SCHEMAS_DIR / "overlay.toml"
FIELDS_PATH = SCHEMAS_DIR / "fields.py"
FUNCTIONS_PATH = SCHEMAS_DIR / "functions.py"
VERSION_PATH = SCHEMAS_DIR / ".wirefilter-version"

BEGIN_FIELDS = "# --- BEGIN GENERATED FIELDS --- #"
END_FIELDS = "# --- END GENERATED FIELDS --- #"
BEGIN_FUNCTIONS = "# --- BEGIN GENERATED FUNCTIONS --- #"
END_FUNCTIONS = "# --- END GENERATED FUNCTIONS --- #"

# Map wirefilter type names to Python FieldType enum names.
WIRE_TO_FIELD_TYPE = {
    "STRING": "FieldType.STRING",
    "INT": "FieldType.INT",
    "BOOL": "FieldType.BOOL",
    "IP": "FieldType.IP",
    "ARRAY_STRING": "FieldType.ARRAY_STRING",
    "ARRAY_INT": "FieldType.ARRAY_INT",
    "ARRAY_ARRAY_STRING": "FieldType.ARRAY_ARRAY_STRING",
    "MAP_ARRAY_STRING": "FieldType.MAP_ARRAY_STRING",
    "MAP_ARRAY_INT": "FieldType.MAP_ARRAY_INT",
}


def load_overlay() -> dict:
    with open(OVERLAY_PATH, "rb") as f:
        return tomllib.load(f)


def generate_fields_block(schema: dict, overlay: dict) -> str:
    """Generate the fields block for fields.py."""
    field_overlay = overlay.get("fields", {})
    lines: list[str] = []
    for entry in schema["fields"]:
        name = entry["name"]
        ftype = WIRE_TO_FIELD_TYPE[entry["type"]]
        kwargs: list[str] = []
        meta = field_overlay.get(name, {})
        if meta.get("requires_plan"):
            kwargs.append(f'requires_plan="{meta["requires_plan"]}"')
        if meta.get("is_response"):
            kwargs.append("is_response=True")
        if kwargs:
            line = f'_f("{name}", {ftype}, {", ".join(kwargs)})'
        else:
            line = f'_f("{name}", {ftype})'
        if len(line) > 100:
            # Break into multi-line call
            all_args = [f'"{name}"', ftype] + kwargs
            line = "_f(\n" + "".join(f"    {a},\n" for a in all_args) + ")"
        lines.append(line)
    return "\n".join(lines)


def generate_functions_block(schema: dict, overlay: dict) -> str:
    """Generate the functions block for functions.py."""
    func_overlay = overlay.get("functions", {})
    # Include functions from wirefilter + any overlay-only functions
    all_names = list(schema["functions"])
    # Add overlay-only functions (like http.request.uri.path which is transform-specific)
    for name in func_overlay:
        if name not in all_names:
            all_names.append(name)

    # Group by category for readability (replicating existing structure)
    lines: list[str] = []
    for name in all_names:
        meta = func_overlay.get(name, {})
        kwargs: list[str] = []
        phases = meta.get("restricted_phases")
        if phases:
            if set(phases) == {
                "url_rewrite_rules",
                "request_header_rules",
                "response_header_rules",
                "redirect_rules",
            }:
                kwargs.append("restricted_phases=_TRANSFORM_AND_REDIRECT_PHASES")
            elif set(phases) == {
                "url_rewrite_rules",
                "request_header_rules",
                "response_header_rules",
            }:
                kwargs.append("restricted_phases=_TRANSFORM_PHASES")
            else:
                phase_items = [f'"{p}"' for p in sorted(phases)]
                one_line = "frozenset({" + ", ".join(phase_items) + "})"
                if len(f"    restricted_phases={one_line},") <= 100:
                    kwargs.append(f"restricted_phases={one_line}")
                else:
                    # Match ruff's formatting: frozenset(\n    {\n        items\n    }\n)
                    inner = "".join(f"\n            {p}," for p in phase_items)
                    kwargs.append(
                        f"restricted_phases=frozenset(\n        {{{inner}\n        }}\n    )"
                    )
        if meta.get("requires_plan"):
            kwargs.append(f'requires_plan="{meta["requires_plan"]}"')
        if kwargs:
            line = f'_fn("{name}", {", ".join(kwargs)})'
            if len(line) > 100:
                all_args = [f'"{name}"'] + kwargs
                line = "_fn(\n" + "".join(f"    {a},\n" for a in all_args) + ")"
            lines.append(line)
        else:
            lines.append(f'_fn("{name}")')
    return "\n".join(lines)


def replace_block(content: str, begin: str, end: str, new_block: str) -> str:
    """Replace content between begin and end markers (exclusive)."""
    begin_idx = content.index(begin)
    end_idx = content.index(end)
    before = content[: begin_idx + len(begin)]
    after = content[end_idx:]
    return before + "\n" + new_block + "\n" + after


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync schema files from wirefilter")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare generated output to committed files, exit 1 if different",
    )
    args = parser.parse_args()

    schema = get_schema_info()
    overlay = load_overlay()

    # Generate new blocks
    new_fields = generate_fields_block(schema, overlay)
    new_functions = generate_functions_block(schema, overlay)

    # Read current files
    fields_content = FIELDS_PATH.read_text()
    functions_content = FUNCTIONS_PATH.read_text()

    # Replace blocks
    new_fields_content = replace_block(fields_content, BEGIN_FIELDS, END_FIELDS, new_fields)
    new_functions_content = replace_block(
        functions_content, BEGIN_FUNCTIONS, END_FUNCTIONS, new_functions
    )

    if args.check:
        # Warn if installed wirefilter differs from what generated the schemas
        if VERSION_PATH.exists():
            expected_version = VERSION_PATH.read_text().strip()
            if _wf_version != expected_version:
                print(
                    f"WARNING: schemas were generated with wirefilter {expected_version}, "
                    f"but {_wf_version} is installed.",
                    file=sys.stderr,
                )

        fields_ok = new_fields_content == fields_content
        functions_ok = new_functions_content == functions_content
        if fields_ok and functions_ok:
            print(f"OK: schemas are in sync with wirefilter {_wf_version}.")
            sys.exit(0)
        else:
            if not fields_ok:
                print(f"DIFF: {FIELDS_PATH} is out of sync.", file=sys.stderr)
            if not functions_ok:
                print(f"DIFF: {FUNCTIONS_PATH} is out of sync.", file=sys.stderr)
            hint = "Run 'python scripts/sync_schemas.py' to regenerate."
            if VERSION_PATH.exists():
                expected_version = VERSION_PATH.read_text().strip()
                if _wf_version != expected_version:
                    hint = (
                        f"Installed wirefilter {_wf_version} differs from "
                        f"{expected_version} (used to generate schemas).\n"
                        f"Run: pip install octorules-wirefilter=={expected_version} "
                        f"&& python scripts/sync_schemas.py\n"
                        f"Or regenerate with the new version: python scripts/sync_schemas.py"
                    )
            print(hint, file=sys.stderr)
            sys.exit(1)
    else:
        FIELDS_PATH.write_text(new_fields_content)
        FUNCTIONS_PATH.write_text(new_functions_content)
        VERSION_PATH.write_text(_wf_version + "\n")
        print(f"Updated {FIELDS_PATH}")
        print(f"Updated {FUNCTIONS_PATH}")
        print(f"Recorded wirefilter version: {_wf_version}")


if __name__ == "__main__":
    main()
