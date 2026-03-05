#!/usr/bin/env python3
"""Auto-generate field registrations from Cloudflare docs YAML.

Fetches the machine-readable field reference from the cloudflare-docs
repository and replaces the field registration blocks in:

  - octorules-wirefilter: src/scheme.rs  (Rust wirefilter scheme, separate repo)
  - src/octorules/linter/schemas/fields.py  (Python field registry)

Usage:
  python scripts/generate_fields.py              # update files in-place
  python scripts/generate_fields.py --dry-run    # print diff, don't write
  python scripts/generate_fields.py --check      # exit 1 if stale
  python scripts/generate_fields.py --yaml-path fields.yaml  # local YAML
"""

from __future__ import annotations

import argparse
import difflib
import sys
from pathlib import Path
from urllib.request import urlopen

import yaml

# ---------------------------------------------------------------------------
# Paths (relative to repo root)
# ---------------------------------------------------------------------------

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEME_RS = REPO_ROOT / "packages" / "wirefilter" / "src" / "scheme.rs"
FIELDS_PY = REPO_ROOT / "src" / "octorules" / "linter" / "schemas" / "fields.py"

YAML_URL = (
    "https://raw.githubusercontent.com/cloudflare/cloudflare-docs/"
    "HEAD/src/content/fields/index.yaml"
)

# Sentinel markers used to delimit the generated block in each file.
BEGIN_SENTINEL = "--- BEGIN GENERATED FIELDS ---"
END_SENTINEL = "--- END GENERATED FIELDS ---"

# ---------------------------------------------------------------------------
# Type mapping: CF docs data_type → (Rust Type, Python FieldType)
# ---------------------------------------------------------------------------

TYPE_MAP: dict[str, tuple[str, str]] = {
    "String": ("Type::Bytes", "FieldType.STRING"),
    "Integer": ("Type::Int", "FieldType.INT"),
    "Number": ("Type::Int", "FieldType.INT"),
    "Boolean": ("Type::Bool", "FieldType.BOOL"),
    "IP address": ("Type::Ip", "FieldType.IP"),
    "Bytes": ("Type::Bytes", "FieldType.BYTES"),
    "Array<String>": ("Type::Array(Type::Bytes.into())", "FieldType.ARRAY_STRING"),
    "Array<Integer>": ("Type::Array(Type::Int.into())", "FieldType.ARRAY_INT"),
    "Array<Number>": ("Type::Array(Type::Int.into())", "FieldType.ARRAY_INT"),
    "Map<Array<String>>": (
        "Type::Map(Type::Array(Type::Bytes.into()).into())",
        "FieldType.MAP_ARRAY_STRING",
    ),
    "Map<Array<Integer>>": (
        "Type::Map(Type::Array(Type::Int.into()).into())",
        "FieldType.MAP_ARRAY_INT",
    ),
    "Array<Array<String>>": (
        "Type::Array(Type::Array(Type::Bytes.into()).into())",
        "FieldType.ARRAY_ARRAY_STRING",
    ),
}

# Plan label → requires_plan value
PLAN_MAP: dict[str, str] = {
    "Enterprise": "enterprise",
    "Enterprise add-on": "enterprise",
    "Business or above": "business",
    "Pro or above": "pro",
}

# http.request.uri.path is scheme-specific (field in default, function in
# transform) so it's excluded from the generated common fields block.
EXCLUDED_COMMON_FIELDS = {"http.request.uri.path"}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


class FieldEntry:
    """A single field parsed from the CF docs YAML."""

    __slots__ = ("name", "rust_type", "py_type", "is_response", "requires_plan")

    def __init__(
        self,
        name: str,
        rust_type: str,
        py_type: str,
        is_response: bool = False,
        requires_plan: str = "",
    ):
        self.name = name
        self.rust_type = rust_type
        self.py_type = py_type
        self.is_response = is_response
        self.requires_plan = requires_plan


# ---------------------------------------------------------------------------
# YAML → FieldEntry classification
# ---------------------------------------------------------------------------


def classify_field(entry: dict) -> FieldEntry | None:
    """Convert a single YAML entry to a FieldEntry, or None if unmappable."""
    name = entry.get("name", "")
    data_type = entry.get("data_type", "")

    mapping = TYPE_MAP.get(data_type)
    if mapping is None:
        return None

    rust_type, py_type = mapping
    categories = entry.get("categories", [])
    is_response = "Response" in categories

    plan_label = entry.get("plan_info_label", "")
    requires_plan = PLAN_MAP.get(plan_label, "")

    return FieldEntry(
        name=name,
        rust_type=rust_type,
        py_type=py_type,
        is_response=is_response,
        requires_plan=requires_plan,
    )


def load_fields(yaml_text: str) -> list[FieldEntry]:
    """Parse the YAML and return classified fields, sorted by name."""
    data = yaml.safe_load(yaml_text)
    entries = data.get("entries", [])
    fields: list[FieldEntry] = []
    for e in entries:
        fe = classify_field(e)
        if fe is not None and fe.name not in EXCLUDED_COMMON_FIELDS:
            fields.append(fe)
    fields.sort(key=lambda f: f.name)
    return fields


# ---------------------------------------------------------------------------
# Code generation
# ---------------------------------------------------------------------------


def generate_rust_fields(fields: list[FieldEntry]) -> str:
    """Generate the Rust field registration block."""
    lines: list[str] = []
    for f in fields:
        lines.append(f'    b.add_field("{f.name}", {f.rust_type}).unwrap();')
    return "\n".join(lines)


def generate_python_fields(fields: list[FieldEntry]) -> str:
    """Generate the Python _f() registration block."""
    lines: list[str] = []
    for f in fields:
        extras: list[str] = []
        if f.is_response:
            extras.append("is_response=True")
        if f.requires_plan:
            extras.append(f'requires_plan="{f.requires_plan}"')
        extra_str = ", " + ", ".join(extras) if extras else ""
        lines.append(f'_f("{f.name}", {f.py_type}{extra_str})')
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Sentinel replacement
# ---------------------------------------------------------------------------


def replace_between_sentinels(
    content: str,
    new_block: str,
    begin: str = BEGIN_SENTINEL,
    end: str = END_SENTINEL,
) -> str:
    """Replace text between sentinel markers, preserving the markers.

    The markers are identified by substring match on their line.
    """
    lines = content.splitlines()
    out: list[str] = []
    inside = False
    begin_found = False
    end_found = False

    for line in lines:
        if begin in line and not inside:
            out.append(line)
            inside = True
            begin_found = True
            # Insert the new block after the begin sentinel
            out.append(new_block)
            continue
        if end in line and inside:
            out.append(line)
            inside = False
            end_found = True
            continue
        if not inside:
            out.append(line)
        # else: skip old generated content

    if not begin_found:
        raise ValueError(f"Begin sentinel {begin!r} not found")
    if not end_found:
        raise ValueError(f"End sentinel {end!r} not found")

    return "\n".join(out) + "\n"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def fetch_yaml(yaml_path: str | None) -> str:
    """Fetch YAML from URL or local path."""
    if yaml_path:
        return Path(yaml_path).read_text()
    with urlopen(YAML_URL) as resp:
        return resp.read().decode()


def show_diff(old: str, new: str, path: str) -> bool:
    """Print unified diff. Returns True if there are changes."""
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    diff = list(difflib.unified_diff(old_lines, new_lines, fromfile=path, tofile=path))
    if diff:
        sys.stdout.writelines(diff)
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Print diff, don't write")
    parser.add_argument("--check", action="store_true", help="Exit 1 if files are stale")
    parser.add_argument("--yaml-path", help="Local YAML file instead of fetching from GitHub")
    args = parser.parse_args()

    yaml_text = fetch_yaml(args.yaml_path)
    fields = load_fields(yaml_text)
    print(f"Loaded {len(fields)} fields from YAML")

    rust_block = generate_rust_fields(fields)
    py_block = generate_python_fields(fields)

    # Read current files
    rs_old = SCHEME_RS.read_text()
    py_old = FIELDS_PY.read_text()

    # Replace between sentinels
    rs_new = replace_between_sentinels(rs_old, rust_block)
    py_new = replace_between_sentinels(py_old, py_block)

    has_changes = False
    has_changes |= show_diff(rs_old, rs_new, str(SCHEME_RS))
    has_changes |= show_diff(py_old, py_new, str(FIELDS_PY))

    if args.check:
        if has_changes:
            print("\nFiles are stale — run 'python scripts/generate_fields.py' to update")
            return 1
        print("Files are up to date")
        return 0

    if args.dry_run:
        if not has_changes:
            print("No changes needed")
        return 0

    # Write updated files
    SCHEME_RS.write_text(rs_new)
    FIELDS_PY.write_text(py_new)
    print(f"Updated {SCHEME_RS}")
    print(f"Updated {FIELDS_PY}")

    # Count fields in the new scheme.rs to help update test assertions
    field_count = rust_block.count("b.add_field(")
    print(f"\nGenerated {field_count} common fields (scheme.rs)")
    print(f"DEFAULT_SCHEME field count = {field_count} + 1 (http.request.uri.path)")
    print(f"TRANSFORM_SCHEME field count = {field_count}")
    print("Remember to update field count assertions in scheme.rs tests!")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
