"""Versions command implementation."""

from __future__ import annotations

from octorules import __version__


def cmd_versions() -> int:
    """Print versions of octorules and key dependencies. Returns exit code."""
    from octorules._context import is_quiet

    if is_quiet():
        return 0

    import platform
    from importlib.metadata import PackageNotFoundError, packages_distributions, version

    # Discover installed octorules provider/extension packages
    extras: list[tuple[str, str]] = []
    for pkg_name in sorted(packages_distributions()):
        if pkg_name.startswith("octorules_"):
            try:
                label = pkg_name.replace("_", "-")
                extras.append((label, version(label)))
            except PackageNotFoundError:
                pass

    # Compute column width from all labels
    labels = [("octorules", __version__), *extras]
    try:
        import yaml

        labels.append(("pyyaml", yaml.__version__))
    except (ImportError, AttributeError):
        labels.append(("pyyaml", "(not installed)"))
    labels.append(("python", platform.python_version()))

    width = max(len(name) for name, _ in labels) + 2
    for name, ver in labels:
        print(f"{name:<{width}s}{ver}")
    return 0
