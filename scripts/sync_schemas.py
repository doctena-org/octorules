#!/usr/bin/env python3
"""Regenerate schemas.json from wirefilter + overlay.toml.

Reads the authoritative field/function list from octorules_wirefilter.get_schema_info()
and merges with Python-only metadata from overlay.toml to produce schemas.json — the
frozen fallback used when wirefilter is not installed.

Usage:
    python scripts/sync_schemas.py           # regenerate schemas.json
    python scripts/sync_schemas.py --check   # compare only, exit 1 if different
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]

try:
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
SCHEMAS_JSON = SCHEMAS_DIR / "schemas.json"


def load_overlay() -> dict:
    with open(OVERLAY_PATH, "rb") as f:
        return tomllib.load(f)


def build_schema() -> dict:
    """Build the merged schema data from wirefilter + overlay."""
    schema = get_schema_info()
    overlay = load_overlay()
    field_overlay = overlay.get("fields", {})
    func_overlay = overlay.get("functions", {})

    fields = []
    for entry in schema["fields"]:
        name = entry["name"]
        meta = field_overlay.get(name, {})
        f: dict = {"name": name, "type": entry["type"]}
        if meta.get("requires_plan"):
            f["requires_plan"] = meta["requires_plan"]
        if meta.get("is_response"):
            f["is_response"] = True
        fields.append(f)

    # Include functions from wirefilter + any overlay-only functions
    all_func_names = list(schema["functions"])
    for name in func_overlay:
        if name not in all_func_names:
            all_func_names.append(name)

    functions = []
    for name in all_func_names:
        meta = func_overlay.get(name, {})
        f = {"name": name}
        if meta.get("restricted_phases"):
            f["restricted_phases"] = sorted(meta["restricted_phases"])
        if meta.get("requires_plan"):
            f["requires_plan"] = meta["requires_plan"]
        functions.append(f)

    return {
        "_generated_with": f"octorules-wirefilter {_wf_version}",
        "fields": fields,
        "functions": functions,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Sync schemas.json from wirefilter")
    parser.add_argument(
        "--check",
        action="store_true",
        help="Compare generated output to committed schemas.json, exit 1 if different",
    )
    args = parser.parse_args()

    new_data = build_schema()
    new_json = json.dumps(new_data, indent=2) + "\n"

    if args.check:
        if SCHEMAS_JSON.exists():
            current = SCHEMAS_JSON.read_text()
        else:
            current = ""

        if new_json == current:
            print(f"OK: schemas.json is in sync with wirefilter {_wf_version}.")
            sys.exit(0)
        else:
            # Check for version mismatch
            try:
                current_data = json.loads(current) if current else {}
                current_ver = current_data.get("_generated_with", "unknown")
            except json.JSONDecodeError:
                current_ver = "unknown"

            print("DIFF: schemas.json is out of sync.", file=sys.stderr)
            print(
                f"  Committed: {current_ver}",
                file=sys.stderr,
            )
            print(f"  Installed: octorules-wirefilter {_wf_version}", file=sys.stderr)
            print(
                "Run 'python scripts/sync_schemas.py' to regenerate.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        SCHEMAS_JSON.write_text(new_json)
        print(f"Updated {SCHEMAS_JSON}")
        print(f"Generated with wirefilter {_wf_version}")


if __name__ == "__main__":
    main()
