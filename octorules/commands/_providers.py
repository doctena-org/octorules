"""Provider and processor initialization."""

import importlib
import json
import logging
from pathlib import Path

from octorules.config import (
    Config,
    ConfigError,
    ZoneConfig,
    _load_class,
    resolve_zone_ids,
)
from octorules.processor import BaseProcessor
from octorules.provider.base import (
    SUPPORTS_ZONE_DISCOVERY,
    BaseProvider,
    provider_supports,
)
from octorules.provider.exceptions import ProviderError

log = logging.getLogger(__name__)

_ZONE_PLANS_CACHE = ".zone_plans_cache.json"


# ---------------------------------------------------------------------------
# Lazy per-provider loading
# ---------------------------------------------------------------------------
def _ensure_provider_loaded(name: str) -> None:
    """Load a single provider module by name.

    Python's import system caches modules, so calling ``ep.load()`` on an
    already-imported provider is a no-op.  No application-level caching needed.
    """
    from importlib.metadata import entry_points

    for ep in entry_points(group="octorules.providers"):
        if ep.name == name:
            try:
                ep.load()
            except (ImportError, AttributeError, ModuleNotFoundError, ValueError) as e:
                log.warning("Failed to load provider %s: %s", name, e)
            return


def _load_provider_class(dotted_path: str) -> type:
    """Import a provider class from a dotted module path.

    Example: ``'octorules_cloudflare.CloudflareProvider'``
    """
    return _load_class(dotted_path, "provider class")


def _discover_provider_modules() -> None:
    """Import all installed provider modules via entry-points.

    This triggers side-effects like phase registration and lint plugin
    registration without constructing provider instances (no API credentials
    needed).  Used by ``cmd_lint`` so lint plugins are available offline.
    """
    from importlib.metadata import entry_points

    for ep in entry_points(group="octorules.providers"):
        try:
            ep.load()
        except (ImportError, AttributeError, ModuleNotFoundError, ValueError) as e:
            # ValueError covers phase registration collisions when a provider
            # is loaded in a process that already registered the same phases.
            log.warning("Failed to load provider entry-point %s: %s", ep.name, e)


def _resolve_provider_class(name: str, class_path: str | None) -> type:
    """Determine the provider class for a named provider.

    Resolution order:
    1. Explicit ``class_path`` from config.
    2. Entry-point discovery (``octorules.providers`` group).
    """
    if class_path:
        return _load_provider_class(class_path)

    from importlib.metadata import entry_points

    eps = entry_points(group="octorules.providers")
    for ep in eps:
        if ep.name == name:
            return ep.load()

    raise ConfigError(
        f"No provider class found for {name!r}. "
        f"Install a provider package or set 'class' explicitly."
    )


def _init_processors(config: Config) -> dict[str, BaseProcessor]:
    """Create all processors from config."""
    processors: dict[str, BaseProcessor] = {}
    for name, pc in config.processors.items():
        cls = _load_class(pc.class_path, "processor")
        processors[name] = cls(**pc.kwargs)
    return processors


def _validate_multi_target(config: Config, providers: dict[str, BaseProvider]) -> None:
    """Validate that multi-target zones use the same provider class.

    Raises ConfigError if a zone has targets pointing to providers of
    different classes.
    """
    for zone_name, zone_cfg in config.zones.items():
        if len(zone_cfg.targets) <= 1:
            continue
        classes = {type(providers[t]) for t in zone_cfg.targets}
        if len(classes) > 1:
            class_names = ", ".join(f"{t}={type(providers[t]).__name__}" for t in zone_cfg.targets)
            raise ConfigError(
                f"'zones.{zone_name}' has targets with different provider classes "
                f"({class_names}). Multi-target requires same provider class."
            )


def _discover_zones(config: Config, providers: dict[str, BaseProvider]) -> None:
    """Expand zone templates via provider zone discovery.

    For each ``'*'`` template, queries the target providers' ``list_zones()``
    and adds matching zones (those with a YAML rules file) to config.
    """
    if not config.zone_templates:
        return

    discovered: dict[str, list[str]] = {}
    seen_targets: set[str] = set()

    for template in config.zone_templates.values():
        for target in template.targets:
            if target in seen_targets:
                continue
            seen_targets.add(target)
            prov = providers.get(target)
            if prov is None:
                continue
            if not provider_supports(prov, SUPPORTS_ZONE_DISCOVERY):
                log.warning("Provider %s does not support zone discovery", target)
                continue
            try:
                zones = prov.list_zones()
                discovered[target] = zones
            except ProviderError as e:
                log.warning("Failed to discover zones from %s: %s", target, e)

    if discovered:
        config.expand_templates(discovered)


def _init_providers(
    config: Config,
    zone_filter: list[str] | None = None,
) -> dict[str, BaseProvider]:
    """Create all providers from config and resolve missing zone IDs.

    For each ``ProviderConfig`` in ``config.providers``:
    1. Determine the class via entry-points or explicit ``class``.
    2. Import the top-level package to trigger phase/linter registration.
    3. Instantiate with ``**pc.kwargs``.

    Then validates multi-target constraints, discovers zones, and resolves
    zone IDs using per-provider resolve functions.

    When *zone_filter* is provided, only the listed zones are resolved
    (plus any account-scoped zones).  This avoids unnecessary API calls
    when ``--zone`` restricts the operation to a subset.
    """
    providers: dict[str, BaseProvider] = {}
    for name, pc in config.providers.items():
        cls = _resolve_provider_class(name, pc.class_path)
        # Import top-level package to trigger phase/linter registration.
        # Guard with hasattr — test mocks may not have __module__.
        if hasattr(cls, "__module__"):
            pkg = cls.__module__.split(".")[0]
            importlib.import_module(pkg)
        providers[name] = cls(**pc.kwargs)

    _validate_multi_target(config, providers)
    _discover_zones(config, providers)

    # Resolve zone IDs with per-provider resolve functions
    resolve_fns = {name: prov.resolve_zone_id for name, prov in providers.items()}
    resolve_zone_ids(config, resolve_fns, zone_filter=zone_filter)

    return providers


def _collect_zone_plans(providers: dict[str, BaseProvider]) -> dict[str, str]:
    """Merge zone_plans from all providers into a single dict."""
    merged: dict[str, str] = {}
    for prov in providers.values():
        merged.update(prov.zone_plans)
    return merged


def _zone_plans_cache_path(config: Config) -> Path | None:
    """Return the cache file path, or None if config has no file path."""
    if config._config_path is None:
        return None
    return config._config_path.parent / _ZONE_PLANS_CACHE


def write_zone_plans_cache(config: Config, providers: dict[str, BaseProvider]) -> None:
    """Write merged zone_plans to a cache file next to the config.

    Best-effort — errors are logged and swallowed.
    """
    cache_path = _zone_plans_cache_path(config)
    if cache_path is None:
        return
    merged = _collect_zone_plans(providers)
    if not merged:
        return
    try:
        cache_path.write_text(json.dumps(merged, sort_keys=True, indent=2) + "\n")
        log.debug("Wrote zone plans cache: %s", cache_path)
    except OSError as e:
        log.debug("Could not write zone plans cache: %s", e)


def read_zone_plans_cache(config: Config) -> dict[str, str]:
    """Read zone_plans from cache, returning empty dict on any failure."""
    cache_path = _zone_plans_cache_path(config)
    if cache_path is None or not cache_path.is_file():
        return {}
    try:
        data = json.loads(cache_path.read_text())
        if isinstance(data, dict) and all(isinstance(v, str) for v in data.values()):
            log.debug("Loaded zone plans cache: %s (%d zones)", cache_path, len(data))
            return data
    except (OSError, json.JSONDecodeError, ValueError) as e:
        log.debug("Could not read zone plans cache: %s", e)
    return {}


def _get_zone_provider(zone_cfg: ZoneConfig, providers: dict[str, BaseProvider]) -> BaseProvider:
    """Look up the provider for a zone from its ``targets`` list."""
    if zone_cfg.targets:
        return providers[zone_cfg.targets[0]]
    if len(providers) == 1:
        return next(iter(providers.values()))
    raise ConfigError(f"Zone {zone_cfg.name!r} has no target and multiple providers are configured")


def _get_zone_providers(
    zone_cfg: ZoneConfig, providers: dict[str, BaseProvider]
) -> list[tuple[str, BaseProvider]]:
    """Get all (target_name, provider) pairs for a zone.

    Single-target zones return one pair. Multi-target zones return one pair
    per target. Zones without explicit targets fall back to the single provider.
    """
    if zone_cfg.targets:
        return [(t, providers[t]) for t in zone_cfg.targets]
    if len(providers) == 1:
        name = next(iter(providers))
        return [(name, providers[name])]
    raise ConfigError(f"Zone {zone_cfg.name!r} has no target and multiple providers are configured")
