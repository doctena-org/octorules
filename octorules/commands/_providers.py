"""Provider and processor initialization."""

from __future__ import annotations

import importlib
import logging

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


def _get_cloudflare_provider() -> type | None:
    """Lazy import of CloudflareProvider from octorules-cloudflare.

    Returns the class if the package is installed, None otherwise.
    Deferred to avoid triggering phase registration at import time.
    """
    try:
        from octorules_cloudflare import CloudflareProvider

        return CloudflareProvider
    except ImportError:
        return None


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
        except Exception as e:
            log.warning("Failed to load provider entry-point %s: %s", ep.name, e)


def _resolve_provider_class(name: str, class_path: str | None) -> type:
    """Determine the provider class for a named provider.

    Resolution order:
    1. Explicit ``class_path`` from config.
    2. Entry-point discovery (``octorules.providers`` group).
    3. Deprecated fallback to module-level ``CloudflareProvider`` (with warning).
    """
    if class_path:
        return _load_provider_class(class_path)

    # Entry-point discovery
    from importlib.metadata import entry_points

    eps = entry_points(group="octorules.providers")
    for ep in eps:
        if ep.name == name:
            return ep.load()

    # Deprecated fallback (since v0.16.0, removal planned for v1.0.0):
    # When no entry point matched, fall back to the lazily-imported
    # CloudflareProvider from octorules-cloudflare.
    cf_cls = _get_cloudflare_provider()
    if cf_cls is not None:
        log.warning(
            "No 'class' specified for provider %r and no entry point found. "
            "Set 'class: octorules_cloudflare.CloudflareProvider' explicitly.",
            name,
        )
        return cf_cls

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
    config: Config, *, _provider_cls: type | None = None
) -> dict[str, BaseProvider]:
    """Create all providers from config and resolve missing zone IDs.

    For each ``ProviderConfig`` in ``config.providers``:
    1. Determine the class via entry-points, explicit ``class``, or fallback.
    2. Import the top-level package to trigger phase/linter registration.
    3. Instantiate with ``**pc.kwargs``.

    Then validates multi-target constraints, discovers zones, and resolves
    zone IDs using per-provider resolve functions.

    ``_provider_cls`` is an internal override for backward compatibility: when
    set, *all* providers use that class (used by ``_init_provider()``).
    """
    providers: dict[str, BaseProvider] = {}
    for name, pc in config.providers.items():
        if _provider_cls is not None:
            cls = _provider_cls
        else:
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
    resolve_zone_ids(config, resolve_fns)

    return providers


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


def _init_provider(config: Config, *, provider_cls: type | None = None) -> BaseProvider:
    """Create a single provider from config and resolve zone IDs.

    .. deprecated::
        Use ``_init_providers()`` instead.  This wrapper only handles configs
        with a single provider.

    When *provider_cls* is given, it overrides class resolution (used in tests).
    """
    import warnings

    warnings.warn(
        "_init_provider() is deprecated, use _init_providers() instead",
        DeprecationWarning,
        stacklevel=2,
    )
    if provider_cls is not None:
        first_pc = next(iter(config.providers.values()), None)
        kwargs = first_pc.kwargs if first_pc else {}
        provider = provider_cls(**kwargs)
        resolve_zone_ids(config, provider.resolve_zone_id)
        return provider
    providers = _init_providers(config)
    if len(providers) == 1:
        return next(iter(providers.values()))
    raise ConfigError("_init_provider() cannot handle multiple providers; use _init_providers()")
