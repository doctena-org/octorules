"""Configuration loading and env/ resolution."""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from octorules.plan_output import PLAN_OUTPUT_CLASSES, PlanOutput

log = logging.getLogger("octorules")


class ConfigError(Exception):
    """Raised when configuration is invalid."""


def _make_include_loader(base_path: Path, visited: set[Path]) -> type:
    """Create a YAML loader subclass with !include support.

    Args:
        base_path: Directory to resolve relative include paths against.
        visited: Set of already-visited file paths for circular include detection.
    """

    class IncludeLoader(yaml.SafeLoader):
        pass

    def _include_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> object:
        rel_path = loader.construct_scalar(node)
        include_path = (base_path / rel_path).resolve()
        # Prevent path traversal outside the base directory tree
        try:
            include_path.relative_to(base_path.resolve())
        except ValueError:
            raise ConfigError(
                f"Include path escapes base directory: {rel_path!r} "
                f"(resolves to {include_path}, base is {base_path.resolve()})"
            )
        if include_path in visited:
            raise ConfigError(f"Circular include detected: {include_path}")
        if not include_path.exists():
            raise ConfigError(f"Include file not found: {include_path}")
        return _yaml_load(include_path, visited)

    IncludeLoader.add_constructor("!include", _include_constructor)
    return IncludeLoader


def _yaml_load(path: Path, visited: set[Path] | None = None) -> object:
    """Load a YAML file with !include directive support.

    Uses a SafeLoader subclass directly (instead of yaml.load) to support
    the custom !include constructor while keeping safe YAML parsing.
    """
    path = path.resolve()
    if visited is None:
        visited = set()
    visited = visited | {path}
    loader_cls = _make_include_loader(path.parent, visited)
    try:
        with open(path, encoding="utf-8") as f:
            loader = loader_cls(f)
            try:
                return loader.get_single_data()
            finally:
                loader.dispose()
    except yaml.YAMLError as e:
        raise ConfigError(f"Invalid YAML in {path}: {e}") from e


def resolve_value(value: str) -> str:
    """Resolve a value, expanding ``env/`` prefix to an environment variable.

    Strings starting with ``env/`` are treated as references to environment
    variables.  For example, ``env/CLOUDFLARE_API_TOKEN`` is resolved to the
    value of ``$CLOUDFLARE_API_TOKEN``.  Raises ``ConfigError`` if the
    environment variable is not set.  All other strings are returned as-is.
    """
    if isinstance(value, str) and value.startswith("env/"):
        env_var = value[4:]
        result = os.environ.get(env_var)
        if result is None:
            raise ConfigError(f"Environment variable {env_var!r} is not set (from {value!r})")
        return result
    return value


def slugify(name: str) -> str:
    """Convert a name to a filesystem-safe slug."""
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")


def _validate_safety(
    delete_threshold: float, update_threshold: float, min_existing: int, context: str
) -> None:
    """Validate safety threshold values."""
    if not 0 <= delete_threshold <= 100:
        raise ConfigError(
            f"'{context}.delete_threshold' must be between 0 and 100 (got {delete_threshold})"
        )
    if not 0 <= update_threshold <= 100:
        raise ConfigError(
            f"'{context}.update_threshold' must be between 0 and 100 (got {update_threshold})"
        )
    if min_existing < 0:
        raise ConfigError(f"'{context}.min_existing' must be >= 0 (got {min_existing})")


@dataclass
class ZoneConfig:
    name: str
    zone_id: str | None = None
    sources: list[str] = field(default_factory=list)
    always_dry_run: bool = False
    allow_unmanaged: bool = False
    delete_threshold: float = 30.0
    update_threshold: float = 30.0
    min_existing: int = 3


def _parse_zone(
    zone_name: str,
    zone_data: object,
    global_delete_threshold: float,
    global_update_threshold: float,
    global_min_existing: int,
    provider_names: set[str],
) -> ZoneConfig:
    """Parse a single zone entry from the config file."""
    if not isinstance(zone_data, dict):
        raise ConfigError(f"Zone {zone_name!r} must be a mapping")

    # Parse and validate sources
    raw_sources = zone_data.get("sources", [])
    if not isinstance(raw_sources, list):
        raise ConfigError(f"'zones.{zone_name}.sources' must be a list")
    sources: list[str] = []
    for entry in raw_sources:
        if not isinstance(entry, str):
            raise ConfigError(f"'zones.{zone_name}.sources' entries must be strings")
        if entry not in provider_names:
            raise ConfigError(f"'zones.{zone_name}.sources' references unknown provider {entry!r}")
        sources.append(entry)

    raw_dry_run = zone_data.get("always_dry_run", False)
    if not isinstance(raw_dry_run, bool):
        raise ConfigError(
            f"'zones.{zone_name}.always_dry_run' must be a boolean"
            f" (got {type(raw_dry_run).__name__})"
        )
    always_dry_run = raw_dry_run

    raw_unmanaged = zone_data.get("allow_unmanaged", False)
    if not isinstance(raw_unmanaged, bool):
        raise ConfigError(
            f"'zones.{zone_name}.allow_unmanaged' must be a boolean"
            f" (got {type(raw_unmanaged).__name__})"
        )
    allow_unmanaged = raw_unmanaged

    # Per-zone safety overrides
    zone_safety = zone_data.get("safety", {})
    if zone_safety is None:
        zone_safety = {}
    if not isinstance(zone_safety, dict):
        raise ConfigError(f"'zones.{zone_name}.safety' must be a mapping")
    delete_threshold = float(zone_safety.get("delete_threshold", global_delete_threshold))
    update_threshold = float(zone_safety.get("update_threshold", global_update_threshold))
    min_existing = int(zone_safety.get("min_existing", global_min_existing))
    _validate_safety(delete_threshold, update_threshold, min_existing, f"zones.{zone_name}.safety")

    return ZoneConfig(
        name=zone_name,
        sources=sources,
        always_dry_run=always_dry_run,
        allow_unmanaged=allow_unmanaged,
        delete_threshold=delete_threshold,
        update_threshold=update_threshold,
        min_existing=min_existing,
    )


def _parse_plan_outputs(raw_dict: dict, context: str) -> dict[str, PlanOutput]:
    """Parse plan_outputs section into PlanOutput instances."""
    outputs: dict[str, PlanOutput] = {}
    for name, entry in raw_dict.items():
        entry_ctx = f"{context}.{name}"
        if not isinstance(entry, dict):
            raise ConfigError(f"'{entry_ctx}' must be a mapping")
        if "class" not in entry:
            raise ConfigError(f"'{entry_ctx}' is missing required 'class' key")
        class_str = entry["class"]
        cls = PLAN_OUTPUT_CLASSES.get(class_str)
        if cls is None:
            raise ConfigError(f"'{entry_ctx}.class': unknown class {class_str!r}")
        path = entry.get("path")
        outputs[name] = cls(name, path=path)
    return outputs


@dataclass
class Config:
    token: str = field(repr=False)
    rules_dir: Path
    lists_dir: Path | None = None
    zones: dict[str, ZoneConfig] = field(default_factory=dict)
    max_workers: int = 1
    max_retries: int = 2
    timeout: float | None = None
    plan_outputs: dict[str, PlanOutput] = field(default_factory=dict)
    _rules_cache: dict[str, dict] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.lists_dir is None:
            self.lists_dir = Path(self.rules_dir) / "custom_lists"

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """Load config from a YAML file.

        The config file is a YAML mapping with three main sections:

        * ``providers`` — Cloudflare credentials (``token`` supports the
          ``env/VARNAME`` syntax to read from environment variables), rules
          directory, and safety thresholds.
        * ``zones`` — per-zone settings (sources, safety overrides).
        * ``manager`` — concurrency and plan output configuration.
        """
        path = Path(path)
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")

        raw = _yaml_load(path)

        if not isinstance(raw, dict):
            raise ConfigError("Config file must be a YAML mapping")

        # --- providers section ---
        providers_section = raw.get("providers", {})
        if not isinstance(providers_section, dict):
            raise ConfigError("'providers' must be a mapping")

        provider_names = set(providers_section.keys())

        # providers.cloudflare
        cf_section = providers_section.get("cloudflare", {})
        if not isinstance(cf_section, dict):
            raise ConfigError("'providers.cloudflare' must be a mapping")

        raw_token = cf_section.get("token")
        if not raw_token:
            raise ConfigError("'providers.cloudflare.token' is required")
        token = resolve_value(raw_token)

        max_retries = int(cf_section.get("max_retries", 2))
        if max_retries < 0:
            raise ConfigError("'providers.cloudflare.max_retries' must be >= 0")
        if max_retries > 10:
            raise ConfigError("'providers.cloudflare.max_retries' must be <= 10")

        raw_timeout = cf_section.get("timeout")
        if raw_timeout is not None:
            timeout = float(raw_timeout)
            if timeout <= 0:
                raise ConfigError("'providers.cloudflare.timeout' must be > 0")
            if timeout > 300:
                raise ConfigError("'providers.cloudflare.timeout' must be <= 300")
        else:
            timeout = None

        # providers.cloudflare.safety (provider-level defaults)
        global_safety = cf_section.get("safety", {})
        if global_safety is None:
            global_safety = {}
        if not isinstance(global_safety, dict):
            raise ConfigError("'providers.cloudflare.safety' must be a mapping")
        global_delete_threshold = float(global_safety.get("delete_threshold", 30.0))
        global_update_threshold = float(global_safety.get("update_threshold", 30.0))
        global_min_existing = int(global_safety.get("min_existing", 3))
        _validate_safety(
            global_delete_threshold,
            global_update_threshold,
            global_min_existing,
            "providers.cloudflare.safety",
        )

        # providers.rules
        rules_section = providers_section.get("rules", {})
        if rules_section is None:
            rules_section = {}
        if not isinstance(rules_section, dict):
            raise ConfigError("'providers.rules' must be a mapping")
        raw_rules_dir = rules_section.get("directory", "./rules")
        rules_dir = (path.parent / raw_rules_dir).resolve()
        if not rules_dir.is_dir():
            log.warning("rules directory does not exist: %s", rules_dir)

        # providers.lists
        lists_section = providers_section.get("lists", {})
        if lists_section is None:
            lists_section = {}
        if not isinstance(lists_section, dict):
            raise ConfigError("'providers.lists' must be a mapping")
        raw_lists_dir = lists_section.get("directory")
        if raw_lists_dir is not None:
            lists_dir = (path.parent / raw_lists_dir).resolve()
            try:
                lists_dir.relative_to(rules_dir)
            except ValueError:
                raise ConfigError(
                    f"'providers.lists.directory' must be within the rules directory "
                    f"({rules_dir}), got {lists_dir}"
                )
        else:
            lists_dir = rules_dir / "custom_lists"

        # --- zones section ---
        zones: dict[str, ZoneConfig] = {}
        raw_zones = raw.get("zones", {})
        if not isinstance(raw_zones, dict):
            raise ConfigError("'zones' must be a mapping")

        for zone_name, zone_data in raw_zones.items():
            zones[zone_name] = _parse_zone(
                zone_name,
                zone_data,
                global_delete_threshold,
                global_update_threshold,
                global_min_existing,
                provider_names,
            )

        # Manager section
        manager_section = raw.get("manager", {})
        if manager_section is None:
            manager_section = {}
        if not isinstance(manager_section, dict):
            raise ConfigError("'manager' must be a mapping")
        max_workers = int(manager_section.get("max_workers", 1))
        if max_workers < 1:
            raise ConfigError("'manager.max_workers' must be >= 1")

        raw_plan_outputs = manager_section.get("plan_outputs")
        if raw_plan_outputs is not None:
            if not isinstance(raw_plan_outputs, dict):
                raise ConfigError("'manager.plan_outputs' must be a mapping")
            plan_outputs = _parse_plan_outputs(raw_plan_outputs, "manager.plan_outputs")
        else:
            plan_outputs = {}

        return cls(
            token=token,
            rules_dir=rules_dir,
            lists_dir=lists_dir,
            zones=zones,
            max_workers=max_workers,
            max_retries=max_retries,
            timeout=timeout,
            plan_outputs=plan_outputs,
        )

    def _load_rules_file(self, cache_key: str, file_stem: str, label: str) -> dict:
        """Load a rules YAML file, with caching and path-traversal protection.

        Args:
            cache_key: Key for ``_rules_cache`` (e.g. ``"zone:example.com"``).
            file_stem: Filename without extension (e.g. ``"example.com"``).
            label: Human label for error/log messages (e.g. ``"zone 'example.com'"``).
        """
        if cache_key in self._rules_cache:
            return self._rules_cache[cache_key]
        rules_file = (self.rules_dir / f"{file_stem}.yaml").resolve()
        try:
            rules_file.relative_to(self.rules_dir.resolve())
        except ValueError:
            raise ConfigError(f"{label} resolves outside rules directory")
        if not rules_file.exists():
            log.debug("No rules file for %s (expected %s)", label, rules_file)
            self._rules_cache[cache_key] = {}
            return self._rules_cache[cache_key]
        data = _yaml_load(rules_file)
        if not isinstance(data, dict):
            raise ConfigError(
                f"Rules file {rules_file} is not a YAML mapping (got {type(data).__name__})"
            )
        self._rules_cache[cache_key] = data
        return data

    def load_zone_rules(self, zone_name: str) -> dict:
        """Load the rules YAML file for a given zone.

        Only loads rules if "rules" is in the zone's sources list.
        Results are cached for the lifetime of this Config instance.
        """
        cache_key = f"zone:{zone_name}"
        zone_cfg = self.zones.get(zone_name)
        if zone_cfg and zone_cfg.sources and "rules" not in zone_cfg.sources:
            log.debug("Zone %s does not include 'rules' in sources, skipping rules file", zone_name)
            self._rules_cache[cache_key] = {}
            return self._rules_cache[cache_key]
        return self._load_rules_file(cache_key, zone_name, f"zone {zone_name}")

    def load_account_rules(self, account_name: str) -> dict:
        """Load the rules YAML file for an account (by slugified name).

        Results are cached for the lifetime of this Config instance.
        """
        slug = slugify(account_name)
        return self._load_rules_file(f"account:{account_name}", slug, f"account {account_name}")


def resolve_zone_ids(
    config: Config,
    resolve_fn: Callable[[str], str],
    max_workers: int | None = None,
) -> None:
    """Resolve zone IDs by calling resolve_fn(zone_name) for zones without one.

    Since zone_id is never set from config files, this resolves all zones
    loaded via Config.from_file(). Mutates zone_cfg.zone_id in-place.

    Args:
        max_workers: Concurrency for resolution. Uses config.max_workers when None.
    """
    to_resolve = {name: cfg for name, cfg in config.zones.items() if cfg.zone_id is None}
    if not to_resolve:
        return

    workers = max_workers if max_workers is not None else config.max_workers
    if workers <= 1 or len(to_resolve) <= 1:
        for zone_name, zone_cfg in to_resolve.items():
            zone_cfg.zone_id = resolve_fn(zone_name)
        return

    with ThreadPoolExecutor(max_workers=min(workers, len(to_resolve))) as executor:
        futures = {executor.submit(resolve_fn, name): name for name in to_resolve}
        for future in as_completed(futures):
            zone_name = futures[future]
            to_resolve[zone_name].zone_id = future.result()
