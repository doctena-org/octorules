"""Configuration loading and secret handler resolution."""

import importlib
import logging
import re
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from octorules.pathutil import validate_path_within
from octorules.phases import (
    NAMESPACE_CORE_SECTIONS,
    PROVIDER_NAMESPACES,
)
from octorules.plan_output import PLAN_OUTPUT_CLASSES, PlanOutput

log = logging.getLogger(__name__)

# Keys in a provider section that are handled by the framework (not forwarded
# to the provider constructor as kwargs, and not resolved as secrets).
_PROVIDER_FRAMEWORK_KEYS = {"class", "safety"}


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
            # CORE001: Detect duplicate YAML keys before constructing the map.
            seen_keys: set[str] = set()
            for key_node, _value_node in node.value:
                key = self.construct_object(key_node, deep=False)
                if isinstance(key, str) and key in seen_keys:
                    key_mark = key_node.start_mark
                    loc = f"{Path(key_mark.name).name}:{key_mark.line + 1}" if key_mark else ctx
                    raise ConfigError(f"Duplicate YAML key {key!r} at {loc}")
                if isinstance(key, str):
                    seen_keys.add(key)
            data = ContextDict(context=ctx)
            yield data
            value = self.construct_mapping(node)
            data.update(value)

    IncludeLoader.add_constructor("tag:yaml.org,2002:map", IncludeLoader.construct_yaml_map)

    def _include_constructor(loader: yaml.SafeLoader, node: yaml.Node) -> object:
        rel_path = loader.construct_scalar(node)
        include_path = (base_path / rel_path).resolve()
        # Prevent path traversal outside the base directory tree
        if not validate_path_within(include_path, base_path):
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


#: Sets enabled when ``manager.lint`` says nothing.  Strict is on by default:
#: a section octorules would silently skip should stop a deploy, and opting
#: into safety is the wrong default for a tool that writes to production.
DEFAULT_LINT_SETS: tuple[str, ...] = ("default", "strict")


def _parse_lint_sets(section: object, where: str, ctx: str = "") -> frozenset[str] | None:
    """Parse a ``lint: {sets: [...]}`` block. Returns None when absent."""
    if section is None:
        return None
    if not isinstance(section, dict):
        raise ConfigError(f"'{where}' must be a mapping (got {type(section).__name__}){ctx}")
    if "sets" not in section:
        return None
    raw = section["sets"]
    if isinstance(raw, str):
        raise ConfigError(
            f"'{where}.sets' must be a list of set names, not a string —"
            f" use [{raw!r}] to enable a single set{ctx}"
        )
    if not isinstance(raw, list) or not all(isinstance(s, str) for s in raw):
        raise ConfigError(f"'{where}.sets' must be a list of set names{ctx}")
    return frozenset(raw)


def normalize_zone_format(data: dict, *, source: str = "") -> dict:
    """Normalize a zone rules mapping to the canonical flat form.

    Provider namespace blocks (``cloudflare: {waf_custom_rules: […],
    bot_management: {…}}``) flatten to the dotted internal key
    (``cloudflare.waf_custom_rules``), which is the only spelling the rest
    of the system uses.

    ``lists`` / ``custom_rulesets`` inside a namespace stay plain while
    the file uses a single namespace; with several namespaces they become
    ``"<ns>.lists"`` etc. so each provider keeps its own, and top-level
    spellings of those sections are rejected as ambiguous.

    Raises :class:`ConfigError` when the same section appears both plainly
    and nested under a namespace, and when a section is written as a
    top-level dotted key.

    The dotted spelling is the *internal* key, not an input form.  It
    would otherwise be accepted by accident — the loader passes unknown
    top-level keys through, and ``cloudflare.waf_custom_rules`` stopped
    being unknown — which would give one section two grammars and allow a
    file to interleave providers instead of grouping them, undoing the
    point of the namespace block.  ``dump`` only ever writes the nested
    form, so accepting the dotted one would also let a dump/edit/sync
    round trip silently restyle the author's file.

    The removed flat spelling needs no special case: with internal keys
    dotted, ``cloudflare_bot_management`` is simply not a section, so it
    surfaces as an unknown section — and because it differs from
    ``cloudflare.bot_management`` by one character, the existing fuzzy
    matcher already suggests the right name.
    """
    label = source or "zone rules"
    for key in data:
        ns, sep, member = key.partition(".")
        if sep and ns in PROVIDER_NAMESPACES:
            raise ConfigError(
                f"{label}: {key!r} is the internal spelling, not a zone-file key."
                f" Nest it instead:\n  {ns}:\n    {member}: ..."
            )

    namespaces = [k for k in data if k in PROVIDER_NAMESPACES]
    if not namespaces:
        return data

    if len(namespaces) > 1:
        for section in NAMESPACE_CORE_SECTIONS:
            if section in data:
                raise ConfigError(
                    f"{label}: top-level {section!r} is ambiguous in a multi-provider"
                    f" file — nest it under one of: {', '.join(sorted(namespaces))}"
                )

    # Preserve the ContextDict wrapper (file:line context) when rebuilding.
    result: dict = ContextDict(context=data.context) if isinstance(data, ContextDict) else {}
    result.update({k: v for k, v in data.items() if k not in PROVIDER_NAMESPACES})
    for ns in namespaces:
        block = data[ns]
        if not isinstance(block, dict):
            raise ConfigError(
                f"{label}: namespace {ns!r} must be a mapping, got {type(block).__name__}"
            )
        mapping = PROVIDER_NAMESPACES[ns]
        for member, value in block.items():
            if member in NAMESPACE_CORE_SECTIONS:
                target = member if len(namespaces) == 1 else f"{ns}.{member}"
            elif member in mapping:
                target = mapping[member]
            else:
                log.warning("%s: unknown key %r in namespace %r", label, member, ns)
                target = f"{ns}.{member}"
            if target in result:
                raise ConfigError(
                    f"{label}: section {target!r} is present both flat and nested under {ns!r}"
                )
            result[target] = value
    return result


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
    if delete_threshold < update_threshold:
        log.warning(
            "%s.delete_threshold (%.1f) < update_threshold (%.1f)"
            " — deletes are less restricted than updates, which is unusual",
            context,
            delete_threshold,
            update_threshold,
        )


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
    # Per-target provider-resource ids (multi-provider zones: each target
    # resolves its own).  ``zone_id`` keeps the first target's id for
    # single-target consumers.
    zone_ids: dict[str, str] = field(default_factory=dict)
    # Per-target provider-resource NAME overrides — e.g. the AWS Web ACL
    # guarding example.com can't be named "example.com" (Web ACL names are
    # restricted to [A-Za-z0-9_-]):
    #   zone_names: {aws: example-com-alb}
    zone_names: dict[str, str] = field(default_factory=dict)
    sources: list[str] = field(default_factory=list)
    targets: list[str] = field(default_factory=list)
    processors: list[str] = field(default_factory=list)
    always_dry_run: bool = False
    allow_unmanaged: bool = False
    # Per-zone override of manager.lint.sets; None inherits.
    lint_sets: frozenset[str] | None = None
    delete_threshold: float = 30.0
    update_threshold: float = 30.0
    min_existing: int = 3

    def zone_id_for(self, target: str | None) -> str | None:
        """Provider-resource id for *target*, falling back to ``zone_id``."""
        if target is not None and target in self.zone_ids:
            return self.zone_ids[target]
        return self.zone_id

    def zone_name_for(self, target: str | None) -> str:
        """Provider-resource name for *target*, falling back to the zone name."""
        if target is not None:
            return self.zone_names.get(target, self.name)
        return self.name


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

    # Per-target provider-resource name overrides
    raw_zone_names = zone_data.get("zone_names", {})
    if raw_zone_names is None:
        raw_zone_names = {}
    if not isinstance(raw_zone_names, dict):
        raise ConfigError(f"'zones.{zone_name}.zone_names' must be a mapping{zd_ctx}")
    zone_names: dict[str, str] = {}
    for target_key, resource_name in raw_zone_names.items():
        if target_key not in targets:
            raise ConfigError(
                f"'zones.{zone_name}.zone_names' references {target_key!r}, which is"
                f" not one of the zone's targets{zd_ctx}"
            )
        if not isinstance(resource_name, str) or not resource_name:
            raise ConfigError(
                f"'zones.{zone_name}.zone_names.{target_key}' must be a non-empty string{zd_ctx}"
            )
        zone_names[target_key] = resource_name

    # A template expands to every discovered zone, so one provider-resource
    # name would make all of them drive the same resource — each zone's plan
    # would then render the others' rules as deletions.  Reject rather than
    # silently drop it at expansion time.
    if zone_name == "*" and zone_names:
        raise ConfigError(
            f"'zones.*.zone_names' is not supported on a zone template — a"
            f" provider-resource name cannot be shared across discovered zones;"
            f" set zone_names on each explicit zone{zd_ctx}"
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

    lint_sets = _parse_lint_sets(zone_data.get("lint"), f"zones.{zone_name}.lint", zd_ctx)

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

    # Warn on unrecognized zone keys (catches typos like 'sorces' instead of 'sources')
    _KNOWN_ZONE_KEYS = {
        "sources",
        "targets",
        "processors",
        "always_dry_run",
        "allow_unmanaged",
        "safety",
        "lint_sets",
        "zone_id",
        "zone_names",
    }
    unknown_zone_keys = set(zone_data.keys()) - _KNOWN_ZONE_KEYS
    for key in sorted(unknown_zone_keys):
        log.warning("Unknown key '%s' in zones.%s (ignored)%s", key, zone_name, zd_ctx)

    return ZoneConfig(
        name=zone_name,
        zone_names=zone_names,
        sources=sources,
        targets=targets,
        processors=processors,
        always_dry_run=always_dry_run,
        allow_unmanaged=allow_unmanaged,
        lint_sets=lint_sets,
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
    # Escalate skipped zone-file sections from warnings to ConfigError.
    lint_sets: frozenset[str] = frozenset(DEFAULT_LINT_SETS)
    providers: dict[str, ProviderConfig] = field(default_factory=dict)
    processors: dict[str, ProcessorConfig] = field(default_factory=dict)
    plan_outputs: dict[str, PlanOutput] = field(default_factory=dict)
    zone_templates: dict[str, ZoneConfig] = field(default_factory=dict)
    _rules_cache: dict[str, dict] = field(default_factory=dict, repr=False, compare=False)
    _file_cache: dict[Path, dict] = field(default_factory=dict, repr=False, compare=False)
    _cache_lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)
    _secret_handlers_raw: dict = field(default_factory=dict, repr=False, compare=False)
    _config_path: Path | None = field(default=None, repr=False, compare=False)
    _secrets_resolved: bool = field(default=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if self.lists_dir is None:
            self.lists_dir = Path(self.rules_dir) / "custom_lists"

    def lint_sets_for(self, zone_name: str) -> frozenset[str]:
        """Effective enabled lint sets for *zone_name* (zone override wins)."""
        zone = self.zones.get(zone_name)
        if zone is not None and zone.lint_sets is not None:
            return zone.lint_sets
        return self.lint_sets

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
                        lint_sets=template.lint_sets,
                        delete_threshold=template.delete_threshold,
                        update_threshold=template.update_threshold,
                        min_existing=template.min_existing,
                    )

    def resolve_secrets(self) -> None:
        """Resolve secret references in provider and processor kwargs.

        Must be called before instantiating providers (e.g. before
        ``_init_providers()``).  Commands that only read rules files
        (lint, validate, audit) can skip this call entirely.

        Safe to call multiple times — subsequent calls are no-ops.
        """
        if self._secrets_resolved:
            return

        # Build secret handlers
        from octorules.secret.environ import EnvironSecrets

        handlers: dict[str, object] = {"env": EnvironSecrets("env")}

        from importlib.metadata import entry_points

        for ep in entry_points(group="octorules.secret_handlers"):
            if ep.name not in handlers:
                try:
                    cls = ep.load()
                    handlers[ep.name] = cls(ep.name)
                except (ImportError, AttributeError, ModuleNotFoundError) as e:
                    raise ConfigError(f"Failed to load secret handler {ep.name!r}: {e}") from e

        # Config-declared handlers
        for sh_name, sh_data in self._secret_handlers_raw.items():
            sh_prefix = f"secret_handlers.{sh_name}"
            sh_class_path = sh_data["class"]
            sh_class = _load_class(sh_class_path, "secret handler")
            sh_kwargs: dict = {
                k: _resolve_deep(v, handlers, f"{sh_prefix}.{k}")
                for k, v in sh_data.items()
                if k != "class"
            }
            handlers[sh_name] = sh_class(sh_name, **sh_kwargs)

        # Resolve provider kwargs
        for pc in self.providers.values():
            pc.kwargs = {
                k: _resolve_deep(v, handlers, f"providers.{pc.name}.{k}")
                if k not in _PROVIDER_FRAMEWORK_KEYS
                else v
                for k, v in pc.kwargs.items()
            }

        # Resolve processor kwargs
        for proc in self.processors.values():
            proc.kwargs = {
                k: _resolve_deep(v, handlers, f"processors.{proc.name}.{k}")
                for k, v in proc.kwargs.items()
            }

        self._secrets_resolved = True

    @classmethod
    def from_file(cls, path: str | Path) -> "Config":
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

        # --- secret handlers (schema validation only; resolution deferred) ---
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

            # Build provider kwargs (raw; secrets resolved later via resolve_secrets())
            provider_kwargs: dict = {}
            for k, v in prov_section.items():
                if k in _PROVIDER_FRAMEWORK_KEYS:
                    continue
                provider_kwargs[k] = v

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
                proc_kwargs[k] = v
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
        try:
            max_workers = int(manager_section.get("max_workers", 1))
        except (ValueError, TypeError) as exc:
            raise ConfigError(
                f"'manager.max_workers' must be an integer"
                f" (got {manager_section['max_workers']!r}){mgr_ctx}"
            ) from exc
        if max_workers < 1:
            raise ConfigError(f"'manager.max_workers' must be >= 1{mgr_ctx}")

        lint_sets = _parse_lint_sets(manager_section.get("lint"), "manager.lint", mgr_ctx)
        if lint_sets is None:
            lint_sets = frozenset(DEFAULT_LINT_SETS)

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

        # Warn on unrecognized top-level keys (catches typos like 'provider:')
        _KNOWN_TOP_LEVEL_KEYS = {
            "secret_handlers",
            "providers",
            "zones",
            "zone_templates",
            "manager",
            "processors",
        }
        unknown_top = set(raw.keys()) - _KNOWN_TOP_LEVEL_KEYS
        for key in sorted(unknown_top):
            log.warning("Unknown top-level config key '%s' (ignored)%s", key, raw_ctx)

        return cls(
            rules_dir=rules_dir,
            lists_dir=lists_dir,
            zones=zones,
            max_workers=max_workers,
            lint_sets=lint_sets,
            providers=providers,
            processors=processors,
            plan_outputs=plan_outputs,
            zone_templates=zone_templates,
            _secret_handlers_raw=dict(raw_sh),
            _config_path=path,
        )

    def _load_rules_file(self, cache_key: str, file_stem: str, label: str) -> dict:
        """Load a rules YAML file, with caching and path-traversal protection.

        Args:
            cache_key: Key for ``_rules_cache`` (e.g. ``"zone:example.com"``).
            file_stem: Filename without extension (e.g. ``"example.com"``).
            label: Human label for error/log messages (e.g. ``"zone 'example.com'"``).
        """
        # Fast path: check cache under lock, return immediately if hit.
        with self._cache_lock:
            if cache_key in self._rules_cache:
                return self._rules_cache[cache_key]

        # Slow path: resolve and validate the file path (no lock needed).
        rules_file = (self.rules_dir / f"{file_stem}.yaml").resolve()
        if not validate_path_within(rules_file, self.rules_dir):
            raise ConfigError(f"{label} resolves outside rules directory") from None

        if not rules_file.exists():
            log.info("No rules file for %s (expected %s)", label, rules_file)
            with self._cache_lock:
                self._rules_cache[cache_key] = {}
                return self._rules_cache[cache_key]

        # Check the file-level cache under lock; if miss, release lock
        # and do I/O outside the lock so other threads can proceed.
        with self._cache_lock:
            if rules_file in self._file_cache:
                data = self._file_cache[rules_file]
                self._rules_cache[cache_key] = data
                return data

        # File I/O and YAML parsing outside the lock — this is the
        # expensive part that we don't want to serialize.
        data = _yaml_load(rules_file)
        if not isinstance(data, dict):
            raise ConfigError(
                f"Rules file {rules_file} is not a YAML mapping (got {type(data).__name__})"
            )
        data = normalize_zone_format(data, source=rules_file.name)

        # Re-acquire lock to write caches. Another thread may have
        # loaded the same file concurrently — that's harmless (same
        # file produces the same data, and dict assignment is atomic).
        with self._cache_lock:
            self._file_cache[rules_file] = data
            self._rules_cache[cache_key] = data
            return data

    def target_plugins_for_zone(self, zone_name: str) -> set[str] | None:
        """Return the lint-plugin names that own this zone's rules file.

        Used by ``cmd_lint`` to route each zone's file to the plugin(s)
        belonging to its target provider(s), so the AWS lint plugin
        doesn't validate Cloudflare's ``custom_rulesets`` block (and
        vice versa) when both packages are installed.

        Resolution: ``zones[zone_name].targets`` → list of target names,
        each looked up in ``providers[...]``.  For each provider, the
        plugin name is inferred from either (a) the explicit ``class:``
        attribute via the ``octorules_<plugin_name>`` package convention,
        or (b) when no ``class:`` is set, the provider-config key name
        itself when it matches a registered lint plugin (the
        entry-point-name convention used by ``_resolve_provider_class``).

        Returns:
            A set of plugin names when every target resolves cleanly,
            otherwise ``None``.  ``None`` tells the lint engine to fall
            back to running every registered plugin — appropriate for
            zones with no targets, custom (non-``octorules_*``) provider
            classes, or files outside ``config.zones`` entirely.
        """
        from octorules.linter.plugin import (
            get_registered_plugins,
            provider_name_for_class_path,
        )

        zone_cfg = self.zones.get(zone_name)
        if zone_cfg is None or not zone_cfg.targets:
            return None
        registered = {p.name for p in get_registered_plugins()}
        names: set[str] = set()
        for target in zone_cfg.targets:
            prov = self.providers.get(target)
            if prov is None:
                return None  # unknown target — be conservative
            if prov.class_path:
                plugin_name = provider_name_for_class_path(prov.class_path)
                if plugin_name is None:
                    return None  # non-conventional class path
                names.add(plugin_name)
                continue
            # No explicit class: fall back to the provider-config key name,
            # which by entry-point convention matches the plugin name.
            if prov.name in registered:
                names.add(prov.name)
                continue
            return None  # can't resolve — let the engine run all plugins
        return names or None

    def load_zone_rules(self, zone_name: str) -> dict:
        """Load the rules YAML file for a given zone.

        Only loads rules if "rules" is in the zone's sources list.
        Results are cached for the lifetime of this Config instance.
        """
        cache_key = f"zone:{zone_name}"
        zone_cfg = self.zones.get(zone_name)
        if zone_cfg and zone_cfg.sources and "rules" not in zone_cfg.sources:
            log.debug("Zone %s does not include 'rules' in sources, skipping rules file", zone_name)
            with self._cache_lock:
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
    zone_filter: list[str] | None = None,
) -> None:
    """Resolve zone IDs by calling resolve_fn(zone_name) for zones without one.

    Since zone_id is never set from config files, this resolves all zones
    loaded via Config.from_file(). Mutates zone_cfg.zone_id in-place.

    ``resolve_fn`` may be a single callable (applied to all zones) or a
    ``{provider_name: callable}`` dict for per-provider resolution.

    Args:
        max_workers: Concurrency for resolution. Uses config.max_workers when None.
        zone_filter: When provided, only resolve these zone names (plus any
            account-scoped zones).  Reduces API calls when ``--zone`` is used.
    """
    candidates = config.zones.items()
    if zone_filter:
        filter_set = set(zone_filter)
        candidates = ((name, cfg) for name, cfg in candidates if name in filter_set)
    to_resolve = {name: cfg for name, cfg in candidates if cfg.zone_id is None}
    if not to_resolve:
        return

    # Build (zone, target) work items: each target resolves the zone's
    # provider-resource name for that target (``zone_names`` override,
    # defaulting to the zone name).  The first target is *primary*: its
    # failure aborts (the pre-existing contract) and its id also lands in
    # ``zone_cfg.zone_id``; a secondary target's failure only warns and
    # that target falls back to the primary id at Scope time.
    ItemT = tuple[str, str | None, Callable[[str], str], str, bool]
    items: list[ItemT] = []
    for name, cfg in to_resolve.items():
        if callable(resolve_fn):
            first = cfg.targets[0] if cfg.targets else None
            items.append((name, first, resolve_fn, cfg.zone_name_for(first), True))
            continue
        if not cfg.targets:
            if len(resolve_fn) == 1:
                items.append((name, None, next(iter(resolve_fn.values())), name, True))
                continue
            raise ConfigError(f"Zone {name!r} has no target provider; cannot resolve zone ID")
        for idx, target in enumerate(cfg.targets):
            if target in resolve_fn:
                fn = resolve_fn[target]
            elif len(resolve_fn) == 1:
                fn = next(iter(resolve_fn.values()))
            else:
                raise ConfigError(f"Zone {name!r} has no target provider; cannot resolve zone ID")
            items.append((name, target, fn, cfg.zone_name_for(target), idx == 0))

    workers = max_workers if max_workers is not None else config.max_workers
    log.debug("Resolving %d zone target(s) with %d workers", len(items), workers)
    t0 = time.monotonic()

    def _resolve_item(item: ItemT) -> str | None:
        name, target, fn, resource, primary = item
        try:
            return fn(resource)
        except Exception as e:
            if primary:
                if isinstance(e, ConfigError):
                    raise
                raise ConfigError(f"Failed to resolve zone {name!r}: {e}") from e
            log.warning(
                "Could not resolve zone %s for target %s (%s); that target"
                " falls back to the primary target's id",
                name,
                target,
                e,
            )
            return None

    def _store(item: ItemT, zone_id: str | None) -> None:
        name, target, _fn, _resource, primary = item
        if zone_id is None:
            return
        cfg = to_resolve[name]
        if target is not None:
            cfg.zone_ids[target] = zone_id
        if primary:
            cfg.zone_id = zone_id
        log.debug("Resolved %s (%s) -> %s", name, target or "-", zone_id)

    if workers <= 1 or len(items) <= 1:
        for item in items:
            _store(item, _resolve_item(item))
    else:
        with ThreadPoolExecutor(max_workers=min(workers, len(items))) as executor:
            futures = {executor.submit(_resolve_item, it): it for it in items}
            for future in as_completed(futures):
                _store(futures[future], future.result())

    log.debug(
        "Zone resolution complete: %d zone(s) in %.1fs", len(to_resolve), time.monotonic() - t0
    )
