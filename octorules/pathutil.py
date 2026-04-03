"""Path validation utilities."""

from pathlib import Path


def validate_path_within(path: Path, base: Path) -> bool:
    """Check that *path* does not escape *base* directory.

    Both paths are resolved before comparison.  Returns ``True`` if
    *path* is within *base*, ``False`` otherwise.
    """
    try:
        path.resolve().relative_to(base.resolve())
        return True
    except ValueError:
        return False
