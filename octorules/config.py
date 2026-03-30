"""Configuration loading and secret handler resolution."""

from __future__ import annotations

import importlib
import logging
import re
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from octorules.plan_output import PLAN_OUTPUT_CLASSES, PlanOutput

log = logging.getLogger(__name__)


class ConfigError(Exception):
    """Raised when configuration is invalid."""


class ContextDict(dict):
    """Dict subclass that carries YAML source location (file:line).

    Used to propagate filename and line number from YAML parsing into
    ``ConfigError`` messages, so users can locate the offending line.
    """

    __slots__ = ("context",)

    def __init__(self, *args: object, context: str = "", **kwargs: object) -> None:
        super().__init__(*args, **kwargs)
        self.context = context


def _ctx(obj: object) -> str:
    """Extract YAML source context from a ContextDict, or return empty string."""
    context = getattr(obj, "context", "")
    return f" (at {context})" if context else ""


def _make_include_loader(base_path: Path, visited: set[Path]) -> type:
    """Create a YAML loader subclass with !include support.

    Args:
        base_path: Directory to resolve relative include paths against.
        visited: Set of already-visited file paths for circular include detection.
    """

    class IncludeLoader(yaml.SafeLoader):
        def construct_yaml_map(self, node) -> Iterator[ContextDict]:
            mark = node.start_mark
            ctx = f"{Path(mark.name).name}:{mark.line + 1}" if mark and mark.name else ""
            data = ContextDict(context=ctx)
            yield data
            value = self.construct_mapping(node)
            data.update(value)

    IncludeLoader.add_constructor("tag:yaml.org,2002:map", IncludeLoader.construct_yaml_map)

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
            ) from None
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


def _load_class(dotted_path: str, label: str = "class") -> type:
    """Import a class from a dotted module path.

    Generic helper used by provider, processor, and secret handler class loading.
    """
    module_path, _, class_name = dotted_path.rpartition(".")
    if not module_path:
        raise ConfigError(f"Invalid {label} path: {dotted_path!r} (must be module.ClassName)")
    module = importlib.import_module(module_path)
    try:
        return getattr(module, class_name)
    except AttributeError:
        raise ConfigError(
            f"{label.capitalize()} {class_name!r} not found in module {module_path!r}"
        ) from None


def _resolve_secret(value: str, handlers: dict[str, object], source: str) -> str:
    """Resolve ``handler/reference`` via the handler registry.

    If the prefix before the first ``/`` is not a registered handler,
    the string is returned unchanged (e.g. ``./rules``, ``https://...``).
    """
    if not isinstance(value, str) or "/" not in value:
        return value
    prefix, _, ref = value.partition("/")
    handler = handlers.get(prefix)
    if handler is None:
        log.debug("No secret handler for prefix %r, passing value through unchanged", prefix)
        return value  # not a secret ref
    return handler.fetch(ref, source)


def _resolve_deep(
    value: object,
    handlers: dict[str, object] | None = None,
    source: str = "",
) -> object:
    """Recursively resolve secret references in nested structures."""
    if handlers is None:
        handlers = _default_handlers()
    if isinstance(value, str):
        return _resolve_secret(value, handlers, source)
    if isinstance(value, dict):
        return {
            k: _resolve_deep(v, handlers, f"{source}.{k}" if source else k)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [_resolve_deep(item, handlers, source) for item in value]
    return value


def _default_handlers() -> dict[str, object]:
    from octorules.secret.environ import EnvironSecrets

    return {"env": EnvironSecrets("env")}


def resolve_value(value: str) -> str:
    """Resolve a value, expanding ``env/`` prefix to an environment variable.

    Backward-compatible wrapper around :func:`_resolve_secret`.  Existing
    tests and external callers that import this function continue to work.
    """
    return _resolve_secret(value, _default_handlers(), value)


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
class ProviderConfig:
    """Configuration for a single provider."""

    name: str
    class_path: str | None = None
    kwargs: dict = field(default_factory=dict, repr=False)
    delete_threshold: float = 30.0
    update_threshold: float = 30.0
    min_existing: int = 3


@dataclass
class ProcessorConfig:
    """Configuration for a single processor."""

    name: str
    class_path: str
    kwargs: dict = field(default_factory=dict, repr=False)


@dataclass
class ZoneConfig:
    name: str
    zone_id: str | None = None
    sources: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    processors: list[str] = field(default_factory=list)
    always_dry_run: bool = False
    allow_unmanaged: bool = False
    delete_threshold: float = 30.0
    update_threshold: float = 30.0
    min_existing: int = 3


def _parse_zone(
    zone_name: str,
    zone_data: object,
    provider_names: set[str],
    providers: dict[str, ProviderConfig],
    processor_names: set[str] | None = None,
) -> ZoneConfig:
    """Parse a single zone entry from the config file.

    Args:
        provider_names: All top-level keys in the providers section (for sources validation).
        providers: Actual provider configs (for targets validation and safety defaults).
        processor_names: Valid processor names (for processors list validation).
    """
    if not isinstance(zone_data, dict):
        raise ConfigError(f"Zone {zone_name!r} must be a mapping{_ctx(zone_data)}")

    zd_ctx = _ctx(zone_data)

    # Parse and validate sources
    raw_sources = zone_data.get("sources", [])
    if not isinstance(raw_sources, list):
        raise ConfigError(f"'zones.{zone_name}.sources' must be a list{zd_ctx}")
    sources: list[str] = []
    for entry in raw_sources:
        if not isinstance(entry, str):
            raise ConfigError(f"'zones.{zone_name}.sources' entries must be strings{zd_ctx}")
        if entry not in provider_names:
            raise ConfigError(
                f"'zones.{zone_name}.sources' references unknown provider {entry!r}{zd_ctx}"
            )
        sources.append(entry)

    # Parse and validate targets
    raw_targets = zone_data.get("targets", [])
    if not isinstance(raw_targets, list):
        raise ConfigError(f"'zones.{zone_name}.targets' must be a list{zd_ctx}")
    targets: list[str] = []
    for entry in raw_targets:
        if not isinstance(entry, str):
            raise ConfigError(f"'zones.{zone_name}.targets' entries must be strings{zd_ctx}")
        if entry not in providers:
            raise ConfigError(
                f"'zones.{zone_name}.targets' references unknown provider {entry!r}{zd_ctx}"
            )
        targets.append(entry)

    # Auto-assign target when omitted
    if not targets:
        if len(providers) == 1:
            targets = list(providers.keys())
        elif len(providers) > 1:
            raise ConfigError(
                f"'zones.{zone_name}' must specify 'targets' when multiple providers "
                f"are configured (providers: {', '.join(sorted(providers))}){zd_ctx}"
            )

    raw_dry_run = zone_data.get("always_dry_run", False)
    if not isinstance(raw_dry_run, bool):
        raise ConfigError(
            f"'zones.{zone_name}.always_dry_run' must be a boolean"
            f" (got {type(raw_dry_run).__name__}){zd_ctx}"
        )
    always_dry_run = raw_dry_run

    raw_unmanaged = zone_data.get("allow_unmanaged", False)
    if not isinstance(raw_unmanaged, bool):
        raise ConfigError(
            f"'zones.{zone_name}.allow_unmanaged' must be a boolean"
            f" (got {type(raw_unmanaged).__name__}){zd_ctx}"
        )
    allow_unmanaged = raw_unmanaged

    # Parse and validate processors list
    raw_processors = zone_data.get("processors", [])
    if not isinstance(raw_processors, list):
        raise ConfigError(f"'zones.{zone_name}.processors' must be a list{zd_ctx}")
    processors: list[str] = []
    for entry in raw_processors:
        if not isinstance(entry, str):
            raise ConfigError(f"'zones.{zone_name}.processors' entries must be strings{zd_ctx}")
        if processor_names is not None and entry not in processor_names:
            raise ConfigError(
                f"'zones.{zone_name}.processors' references unknown processor {entry!r}{zd_ctx}"
            )
        processors.append(entry)

    # Safety defaults come from the target provider
    if targets and targets[0] in providers:
        target_prov = providers[targets[0]]
        default_delete = target_prov.delete_threshold
        default_update = target_prov.update_threshold
        default_min = target_prov.min_existing
    else:
        default_delete = 30.0
        default_update = 30.0
        default_min = 3

    # Per-zone safety overrides
    zone_safety = zone_data.get("safety", {})
    if zone_safety is None:
        zone_safety = {}
    if not isinstance(zone_safety, dict):
        raise ConfigError(f"'zones.{zone_name}.safety' must be a mapping{zd_ctx}")
    ctx = f"zones.{zone_name}.safety"
    zs_ctx = _ctx(zone_safety)
    raw_delete = zone_safety.get("delete_threshold", default_delete)
    try:
        delete_threshold = float(raw_delete)
    except (ValueError, TypeError) as exc:
        raise ConfigError(
            f"'{ctx}.delete_threshold' must be numeric (got {raw_delete!r}){zs_ctx}"
        ) from exc
    raw_update = zone_safety.get("update_threshold", default_update)
    try:
        update_threshold = float(raw_update)
    except (ValueError, TypeError) as exc:
        raise ConfigError(
            f"'{ctx}.update_threshold' must be numeric (got {raw_update!r}){zs_ctx}"
        ) from exc
    raw_min = zone_safety.get("min_existing", default_min)
    try:
        min_existing = int(raw_min)
    except (ValueError, TypeError) as exc:
        raise ConfigError(
            f"'{ctx}.min_existing' must be an integer (got {raw_min!r}){zs_ctx}"
        ) from exc
    _validate_safety(delete_threshold, update_threshold, min_existing, ctx)

    return ZoneConfig(
        name=zone_name,
        sources=sources,
        targets=targets,
        processors=processors,
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
        e_ctx = _ctx(entry)
        if not isinstance(entry, dict):
            raise ConfigError(f"'{entry_ctx}' must be a mapping{e_ctx}")
        if "class" not in entry:
            raise ConfigError(f"'{entry_ctx}' is missing required 'class' key{e_ctx}")
        class_str = entry["class"]
        cls = PLAN_OUTPUT_CLASSES.get(class_str)
        if cls is None:
            raise ConfigError(f"'{entry_ctx}.class': unknown class {class_str!r}{e_ctx}")
        path = entry.get("path")
        outputs[name] = cls(name, path=path)
    return outputs


@dataclass
class Config:
    rules_dir: Path
    lists_dir: Path | None = None
    zones: dict[str, ZoneConfig] = field(default_factory=dict)
    max_workers: int = 1
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    processors: dict[str, ProcessorConfig] = field(default_factory=dict)
    plan_outputs: dict[str, PlanOutput] = field(default_factory=dict)
    zone_templates: dict[str, ZoneConfig] = field(default_factory=dict)
    _rules_cache: dict[str, dict] = field(default_factory=dict, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.lists_dir is None:
            self.lists_dir = Path(self.rules_dir) / "custom_lists"

    def expand_templates(self, discovered: dict[str, list[str]]) -> None:
        """Expand zone templates with discovered zone names.

        Args:
            discovered: Maps target provider name to zone names returned by
                ``list_zones()``.
        """
        for template in self.zone_templates.values():
            for target in template.targets:
                for zone_name in discovered.get(target, []):
                    if zone_name in self.zones:
                        continue  # explicit wins
                    rules_file = self.rules_dir / f"{zone_name}.yaml"
                    if not rules_file.exists():
                        continue
                    self.zones[zone_name] = ZoneConfig(
                        name=zone_name,
                        sources=list(template.sources),
                        targets=list(template.targets),
                        processors=list(template.processors),
                        always_dry_run=template.always_dry_run,
                        allow_unmanaged=template.allow_unmanaged,
                        delete_threshold=template.delete_threshold,
                        update_threshold=template.update_threshold,
                        min_existing=template.min_existing,
                    )

    @classmethod
    def from_file(cls, path: str | Path) -> Config:
        """Load config from a YAML file.

        The config file is a YAML mapping with four main sections:

        * ``secret_handlers`` (optional) — pluggable secret backends.
          String values use ``handler/reference`` syntax; the built-in
          ``env`` handler is always available.
        * ``providers`` — one or more named provider sections (all keys
          except ``class`` and ``safety`` are forwarded to the provider
          constructor as kwargs; string values support the ``handler/ref``
          syntax recursively in nested structures), plus shared ``rules``
          and ``lists`` directory settings.
        * ``zones`` — per-zone settings (sources, targets, safety overrides).
        * ``manager`` — concurrency and plan output configuration.
        """
        path = Path(path)
        if not path.exists():
            raise ConfigError(f"Config file not found: {path}")

        raw = _yaml_load(path)

        if not isinstance(raw, dict):
            raise ConfigError("Config file must be a YAML mapping")

        raw_ctx = _ctx(raw)

        # --- secret handlers ---
        from octorules.secret.environ import EnvironSecrets

        handlers: dict[str, object] = {"env": EnvironSecrets("env")}

        # Entry-point discovery
        from importlib.metadata import entry_points

        for ep in entry_points(group="octorules.secret_handlers"):
            if ep.name not in handlers:
                handlers[ep.name] = ep.load()(ep.name)

        # Config-declared handlers (optional)
        raw_sh = raw.get("secret_handlers", {}) or {}
        if not isinstance(raw_sh, dict):
            raise ConfigError(f"'secret_handlers' must be a mapping{_ctx(raw_sh)}")
        for sh_name, sh_data in raw_sh.items():
            sh_prefix = f"secret_handlers.{sh_name}"
            if not isinstance(sh_data, dict):
                raise ConfigError(f"'{sh_prefix}' must be a mapping{_ctx(sh_data)}")
            if "class" not in sh_data:
                raise ConfigError(f"'{sh_prefix}' is missing required 'class' key{_ctx(sh_data)}")
            sh_class_path = sh_data["class"]
            if not isinstance(sh_class_path, str):
                raise ConfigError(f"'{sh_prefix}.class' must be a string{_ctx(sh_data)}")
            sh_class = _load_class(sh_class_path, "secret handler")
            sh_kwargs: dict = {
                k: _resolve_deep(v, handlers, f"{sh_prefix}.{k}")
                for k, v in sh_data.items()
                if k != "class"
            }
            handlers[sh_name] = sh_class(sh_name, **sh_kwargs)

        # --- providers section ---
        providers_section = raw.get("providers", {})
        if not isinstance(providers_section, dict):
            raise ConfigError(f"'providers' must be a mapping{raw_ctx}")

        # All keys in the providers section (for sources validation)
        provider_names = set(providers_section.keys())

        # Detect provider sections dynamically — any key that isn't a
        # shared section (rules, lists) is a provider key.
        _SHARED_KEYS = {"rules", "lists"}
        prov_keys = [k for k in providers_section if k not in _SHARED_KEYS]
        if not prov_keys:
            raise ConfigError(
                "'providers' must contain a provider section"
                f" (e.g. 'cloudflare', 'aws'){_ctx(providers_section)}"
            )

        # Parse each provider
        _FRAMEWORK_KEYS = {"class", "safety"}
        providers: dict[str, ProviderConfig] = {}

        for prov_name in prov_keys:
            prov_prefix = f"providers.{prov_name}"

            prov_section = providers_section[prov_name]
            if not isinstance(prov_section, dict):
                raise ConfigError(f"'{prov_prefix}' must be a mapping{_ctx(prov_section)}")

            ps_ctx = _ctx(prov_section)

            # Extract framework-handled keys
            provider_class: str | None = prov_section.get("class")
            if provider_class is not None and not isinstance(provider_class, str):
                raise ConfigError(f"'{prov_prefix}.class' must be a string{ps_ctx}")

            # Provider-level safety defaults (framework-only, not forwarded)
            prov_safety = prov_section.get("safety", {})
            if prov_safety is None:
                prov_safety = {}
            if not isinstance(prov_safety, dict):
                raise ConfigError(f"'{prov_prefix}.safety' must be a mapping{ps_ctx}")

            safety_ctx = f"{prov_prefix}.safety"
            psafety_ctx = _ctx(prov_safety)
            try:
                delete_threshold = float(prov_safety.get("delete_threshold", 30.0))
            except (ValueError, TypeError) as exc:
                raise ConfigError(
                    f"'{safety_ctx}.delete_threshold' must be numeric"
                    f" (got {prov_safety['delete_threshold']!r}){psafety_ctx}"
                ) from exc
            try:
                update_threshold = float(prov_safety.get("update_threshold", 30.0))
            except (ValueError, TypeError) as exc:
                raise ConfigError(
                    f"'{safety_ctx}.update_threshold' must be numeric"
                    f" (got {prov_safety['update_threshold']!r}){psafety_ctx}"
                ) from exc
            try:
                min_existing = int(prov_safety.get("min_existing", 3))
            except (ValueError, TypeError) as exc:
                raise ConfigError(
                    f"'{safety_ctx}.min_existing' must be an integer"
                    f" (got {prov_safety['min_existing']!r}){psafety_ctx}"
                ) from exc
            _validate_safety(delete_threshold, update_threshold, min_existing, safety_ctx)

            # Build provider kwargs: resolve secret references recursively
            provider_kwargs: dict = {}
            for k, v in prov_section.items():
                if k in _FRAMEWORK_KEYS:
                    continue
                provider_kwargs[k] = _resolve_deep(v, handlers, f"providers.{prov_name}.{k}")

            providers[prov_name] = ProviderConfig(
                name=prov_name,
                class_path=provider_class,
                kwargs=provider_kwargs,
                delete_threshold=delete_threshold,
                update_threshold=update_threshold,
                min_existing=min_existing,
            )

        # providers.rules
        rules_section = providers_section.get("rules", {})
        if rules_section is None:
            rules_section = {}
        if not isinstance(rules_section, dict):
            raise ConfigError(f"'providers.rules' must be a mapping{_ctx(rules_section)}")
        raw_rules_dir = rules_section.get("directory", "./rules")
        rules_dir = (path.parent / raw_rules_dir).resolve()
        if not rules_dir.is_dir():
            log.warning("rules directory does not exist: %s", rules_dir)

        # providers.lists
        lists_section = providers_section.get("lists", {})
        if lists_section is None:
            lists_section = {}
        if not isinstance(lists_section, dict):
            raise ConfigError(f"'providers.lists' must be a mapping{_ctx(lists_section)}")
        raw_lists_dir = lists_section.get("directory")
        if raw_lists_dir is not None:
            lists_dir = (path.parent / raw_lists_dir).resolve()
            try:
                lists_dir.relative_to(rules_dir)
            except ValueError:
                raise ConfigError(
                    f"'providers.lists.directory' must be within the rules directory "
                    f"({rules_dir}), got {lists_dir}"
                ) from None
        else:
            lists_dir = rules_dir / "custom_lists"

        # --- processors section ---
        processors: dict[str, ProcessorConfig] = {}
        raw_processors = raw.get("processors", {})
        if raw_processors is None:
            raw_processors = {}
        if not isinstance(raw_processors, dict):
            raise ConfigError(f"'processors' must be a mapping{_ctx(raw_processors)}")
        _PROC_FRAMEWORK_KEYS = {"class"}
        for proc_name, proc_data in raw_processors.items():
            proc_prefix = f"processors.{proc_name}"
            if not isinstance(proc_data, dict):
                raise ConfigError(f"'{proc_prefix}' must be a mapping{_ctx(proc_data)}")
            if "class" not in proc_data:
                raise ConfigError(
                    f"'{proc_prefix}' is missing required 'class' key{_ctx(proc_data)}"
                )
            proc_class = proc_data["class"]
            if not isinstance(proc_class, str):
                raise ConfigError(f"'{proc_prefix}.class' must be a string{_ctx(proc_data)}")
            proc_kwargs: dict = {}
            for k, v in proc_data.items():
                if k in _PROC_FRAMEWORK_KEYS:
                    continue
                proc_kwargs[k] = _resolve_deep(v, handlers, f"processors.{proc_name}.{k}")
            processors[proc_name] = ProcessorConfig(
                name=proc_name,
                class_path=proc_class,
                kwargs=proc_kwargs,
            )
        processor_names = set(processors.keys())

        # --- zones section ---
        zones: dict[str, ZoneConfig] = {}
        zone_templates: dict[str, ZoneConfig] = {}
        raw_zones = raw.get("zones", {})
        if not isinstance(raw_zones, dict):
            raise ConfigError(f"'zones' must be a mapping{_ctx(raw_zones)}")

        for zone_name, zone_data in raw_zones.items():
            zc = _parse_zone(
                zone_name,
                zone_data,
                provider_names,
                providers,
                processor_names=processor_names,
            )
            if zone_name == "*":
                zone_templates[zone_name] = zc
            else:
                zones[zone_name] = zc

        # Manager section
        manager_section = raw.get("manager", {})
        if manager_section is None:
            manager_section = {}
        if not isinstance(manager_section, dict):
            raise ConfigError(f"'manager' must be a mapping{_ctx(manager_section)}")
        mgr_ctx = _ctx(manager_section)
        max_workers = int(manager_section.get("max_workers", 1))
        if max_workers < 1:
            raise ConfigError(f"'manager.max_workers' must be >= 1{mgr_ctx}")

        raw_plan_outputs = manager_section.get("plan_outputs")
        if raw_plan_outputs is not None:
            if not isinstance(raw_plan_outputs, dict):
                raise ConfigError(
                    f"'manager.plan_outputs' must be a mapping{_ctx(raw_plan_outputs)}"
                )
            plan_outputs = _parse_plan_outputs(raw_plan_outputs, "manager.plan_outputs")
        else:
            plan_outputs = {}

        # Inject max_workers into each provider's kwargs so providers can use
        # it for internal concurrency (e.g. parallel phase fetching).
        for pc in providers.values():
            pc.kwargs.setdefault("max_workers", max_workers)

        return cls(
            rules_dir=rules_dir,
            lists_dir=lists_dir,
            zones=zones,
            max_workers=max_workers,
            providers=providers,
            processors=processors,
            plan_outputs=plan_outputs,
            zone_templates=zone_templates,
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
            raise ConfigError(f"{label} resolves outside rules directory") from None
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

    def load_rules_by_stem(self, file_stem: str) -> dict:
        """Load a rules YAML file by filename stem.

        Unlike :meth:`load_zone_rules`, this does not check the zone's
        ``sources`` list — it unconditionally loads ``{file_stem}.yaml``
        from the rules directory.  Useful for offline tools (audit, lint)
        that need to process every file regardless of config.
        """
        return self._load_rules_file(f"stem:{file_stem}", file_stem, file_stem)


def resolve_zone_ids(
    config: Config,
    resolve_fn: Callable[[str], str] | dict[str, Callable[[str], str]],
    max_workers: int | None = None,
) -> None:
    """Resolve zone IDs by calling resolve_fn(zone_name) for zones without one.

    Since zone_id is never set from config files, this resolves all zones
    loaded via Config.from_file(). Mutates zone_cfg.zone_id in-place.

    ``resolve_fn`` may be a single callable (applied to all zones) or a
    ``{provider_name: callable}`` dict for per-provider resolution.

    Args:
        max_workers: Concurrency for resolution. Uses config.max_workers when None.
    """
    to_resolve = {name: cfg for name, cfg in config.zones.items() if cfg.zone_id is None}
    if not to_resolve:
        return

    # Build per-zone resolve functions
    if callable(resolve_fn):
        per_zone_fn: dict[str, Callable[[str], str]] = {n: resolve_fn for n in to_resolve}
    else:
        per_zone_fn = {}
        for name, cfg in to_resolve.items():
            target = cfg.targets[0] if cfg.targets else None
            if target and target in resolve_fn:
                per_zone_fn[name] = resolve_fn[target]
            elif len(resolve_fn) == 1:
                per_zone_fn[name] = next(iter(resolve_fn.values()))
            else:
                raise ConfigError(f"Zone {name!r} has no target provider; cannot resolve zone ID")

    workers = max_workers if max_workers is not None else config.max_workers
    if workers <= 1 or len(to_resolve) <= 1:
        for zone_name, zone_cfg in to_resolve.items():
            zone_cfg.zone_id = per_zone_fn[zone_name](zone_name)
        return

    with ThreadPoolExecutor(max_workers=min(workers, len(to_resolve))) as executor:
        futures = {executor.submit(per_zone_fn[name], name): name for name in to_resolve}
        for future in as_completed(futures):
            zone_name = futures[future]
            to_resolve[zone_name].zone_id = future.result()
