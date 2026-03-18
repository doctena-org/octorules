"""Suppression parser — extract ``# octorules:disable=RULE`` directives from YAML files.

Supports two scopes:

* **File-level** — a directive before any ``- ref:`` or ``- description:`` line
  suppresses the rule for the entire file.
* **Rule-level** — a directive immediately before (or on the same line as) a
  ``- ref:`` or ``- description:`` line suppresses the rule for that specific
  ref/description only.

Syntax::

    # octorules:disable=CF015
    # octorules:disable=CF015,CF510

Multiple rule IDs can be comma-separated.  Whitespace around ``=`` and IDs is
tolerated.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

log = logging.getLogger(__name__)

# Matches: # octorules:disable=CF015  or  # octorules:disable=CF015,CF510
# Supports both single-letter (M013) and multi-letter (CF015) prefixes.
_DIRECTIVE_RE = re.compile(
    r"#\s*octorules:disable\s*=\s*([A-Z]{1,3}\d{3}(?:\s*,\s*[A-Z]{1,3}\d{3})*)"
)

# Matches a YAML list item with a ref key
_REF_RE = re.compile(r"^\s*-\s*ref:\s*(\S+)")

# Matches a YAML list item with a description key (for Page Shield policies).
# Handles bare (with or without spaces), double-quoted, and single-quoted descriptions.
_DESC_RE = re.compile(r"^\s*-\s*description:\s*(?:\"(.+?)\"|'(.+?)'|(.+?))\s*$")


def parse_suppressions(
    file_path: str | Path,
    *,
    known_rules: set[str] | None = None,
) -> dict[str, set[str]]:
    """Parse suppression directives from a YAML file.

    Returns a dict mapping ref (or ``"*"`` for file-level) to a set of
    suppressed rule IDs.

    If *known_rules* is provided, rule IDs not in the set are logged as
    warnings and silently dropped.
    """
    suppressions: dict[str, set[str]] = {}
    pending_ids: set[str] = set()

    try:
        lines = Path(file_path).read_text().splitlines()
    except OSError:
        return suppressions

    seen_first_anchor = False

    for line in lines:
        # Check for directive comments
        m_dir = _DIRECTIVE_RE.search(line)
        if m_dir:
            ids = {rid.strip() for rid in m_dir.group(1).split(",")}
            if known_rules is not None:
                unknown = ids - known_rules
                for uid in sorted(unknown):
                    log.warning("Unknown rule ID %r in suppression directive (%s)", uid, file_path)
                ids -= unknown
            pending_ids.update(ids)

        # Check for ref or description anchor line
        anchor: str | None = None
        m_ref = _REF_RE.match(line)
        if m_ref:
            anchor = m_ref.group(1)
        else:
            m_desc = _DESC_RE.match(line)
            if m_desc:
                # First non-None group among the 3 alternatives
                anchor = m_desc.group(1) or m_desc.group(2) or m_desc.group(3)

        if anchor is not None:
            seen_first_anchor = True
            if pending_ids:
                suppressions.setdefault(anchor, set()).update(pending_ids)
                pending_ids.clear()
        elif not m_dir and line.strip() and not line.strip().startswith("#"):
            # Non-comment, non-empty, non-anchor line: if we had pending IDs
            # before any anchor was seen, they're file-level suppressions.
            if pending_ids and not seen_first_anchor:
                suppressions.setdefault("*", set()).update(pending_ids)
                pending_ids.clear()
            elif pending_ids and seen_first_anchor:
                # Directive wasn't followed by an anchor — discard to avoid
                # accidental suppression of the wrong rule.
                pending_ids.clear()

    # Any remaining pending IDs at EOF that were never matched to an anchor
    if pending_ids and not seen_first_anchor:
        suppressions.setdefault("*", set()).update(pending_ids)

    return suppressions


def is_suppressed(suppressions: dict[str, set[str]], ref: str, rule_id: str) -> bool:
    """Check if a specific rule_id is suppressed for a given ref."""
    if rule_id in suppressions.get("*", set()):
        return True
    if ref and rule_id in suppressions.get(ref, set()):
        return True
    return False
