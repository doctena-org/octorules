"""Lint plugin API — extensible provider-specific linter registration.

Providers register a ``LintPlugin`` whose ``lint_fn`` is called by
``lint_zone_file()`` for every zone file.  The plugin mutates a
``LintContext`` directly (via ``ctx.add()``).

This mirrors the ``register_phase()`` pattern in ``octorules.phases``.
"""

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from octorules.linter.engine import LintContext


@dataclass(frozen=True)
class LintPlugin:
    """A registered linter plugin."""

    name: str
    lint_fn: Callable[[dict[str, Any], LintContext], None]
    rule_ids: frozenset[str]


_PLUGINS: list[LintPlugin] = []


def register_linter(plugin: LintPlugin) -> None:
    """Register a lint plugin. Raises ValueError if name is already registered."""
    for existing in _PLUGINS:
        if existing.name == plugin.name:
            raise ValueError(f"Lint plugin {plugin.name!r} is already registered")
    _PLUGINS.append(plugin)


def unregister_linter(name: str) -> None:
    """Remove a lint plugin by name (for test teardown). Raises KeyError if not found."""
    for i, plugin in enumerate(_PLUGINS):
        if plugin.name == name:
            _PLUGINS.pop(i)
            return
    raise KeyError(f"Lint plugin {name!r} is not registered")


def get_registered_plugins() -> list[LintPlugin]:
    """Return a copy of the registered plugin list."""
    return list(_PLUGINS)


def provider_name_for_class_path(class_path: str | None) -> str | None:
    """Map a provider class path to its lint-plugin name by convention.

    The convention across the ``octorules-*`` ecosystem is that every
    provider package is named ``octorules_<plugin_name>`` and its lint
    plugin registers under the same ``<plugin_name>`` (e.g.
    ``octorules_cloudflare.provider.CloudflareProvider`` → ``"cloudflare"``).
    Returns ``None`` when the class path doesn't follow the convention,
    which signals callers to fall back to running all registered
    plugins for that file.
    """
    if not class_path:
        return None
    pkg = class_path.split(".", 1)[0]
    if pkg.startswith("octorules_"):
        return pkg.removeprefix("octorules_")
    return None
