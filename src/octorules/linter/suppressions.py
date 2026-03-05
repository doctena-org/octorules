"""Suppression parser — extract ``# octorules:disable=RULE`` directives from YAML files.

Supports two scopes:

* **File-level** — a directive before any ``- ref:`` line suppresses the rule
  for the entire file.
* **Rule-level** — a directive immediately before (or on the same line as) a
  ``- ref:`` line suppresses the rule for that specific ref only.

Syntax::

    # octorules:disable=M013
    # octorules:disable=M013,O001

Multiple rule IDs can be comma-separated.  Whitespace around ``=`` and IDs is
tolerated.
"""

from __future__ import annotations

import re
from pathlib import Path

# Matches: # octorules:disable=M013  or  # octorules:disable=M013,O001
_DIRECTIVE_RE = re.compile(r"#\s*octorules:disable\s*=\s*([A-Z]\d{3}(?:\s*,\s*[A-Z]\d{3})*)")

# Matches a YAML list item with a ref key
_REF_RE = re.compile(r"^\s*-\s*ref:\s*(\S+)")


def parse_suppressions(file_path: str | Path) -> dict[str, set[str]]:
    """Parse suppression directives from a YAML file.

    Returns a dict mapping ref (or ``"*"`` for file-level) to a set of
    suppressed rule IDs.
    """
    suppressions: dict[str, set[str]] = {}
    pending_ids: set[str] = set()

    try:
        lines = Path(file_path).read_text().splitlines()
    except OSError:
        return suppressions

    seen_first_ref = False

    for line in lines:
        # Check for directive comments
        m_dir = _DIRECTIVE_RE.search(line)
        if m_dir:
            ids = {rid.strip() for rid in m_dir.group(1).split(",")}
            pending_ids.update(ids)

        # Check for ref line
        m_ref = _REF_RE.match(line)
        if m_ref:
            seen_first_ref = True
            if pending_ids:
                ref = m_ref.group(1)
                suppressions.setdefault(ref, set()).update(pending_ids)
                pending_ids.clear()
        elif not m_dir and line.strip() and not line.strip().startswith("#"):
            # Non-comment, non-empty, non-ref line: if we had pending IDs
            # before any ref was seen, they're file-level suppressions.
            if pending_ids and not seen_first_ref:
                suppressions.setdefault("*", set()).update(pending_ids)
                pending_ids.clear()
            elif pending_ids and seen_first_ref:
                # Directive wasn't followed by a ref — discard to avoid
                # accidental suppression of the wrong rule.
                pending_ids.clear()

    # Any remaining pending IDs at EOF that were never matched to a ref
    if pending_ids and not seen_first_ref:
        suppressions.setdefault("*", set()).update(pending_ids)

    return suppressions


def is_suppressed(suppressions: dict[str, set[str]], ref: str, rule_id: str) -> bool:
    """Check if a specific rule_id is suppressed for a given ref."""
    if rule_id in suppressions.get("*", set()):
        return True
    if ref and rule_id in suppressions.get(ref, set()):
        return True
    return False
