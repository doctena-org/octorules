# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.27.1] - 2026-05-18

### Added
- `examples/rules/` restructured into per-provider subdirectories so
  each `config-<provider>.yaml` lints its zones in isolation. The
  multi-provider `config.yaml` example uses `examples/rules/multi/`.
- Per-zone lint-plugin routing — each zone's rule file is linted only
  by its target provider's plugin. Eliminates cross-provider schema
  collisions when multiple `octorules-*` packages are installed.
- New example rules across all five providers covering previously
  unshown phases.

### Changed
- PR-comment plan output renders nested rule fields as YAML instead
  of Python `repr`, with `+`/`-` diff markers on every cell line.
- `Update` rows group all changed fields into one diff block per side
  instead of one row pair per field.
- Long wirefilter expressions render as multi-line literal blocks,
  preserving readability for `ip.src in {…}` lists.
- MODIFY diffs reorder fields to match ADD/REMOVE (scalars first,
  large nested blocks last).

### Performance
- `audit ip-shadow` reworked to use an indexed supernet lookup.
  5,000-rule multi-phase zones drop from ~22 s to ~40 ms.

## [0.27.0] - 2026-05-13

### Changed
- A rule with no `logging:` block in YAML is now treated as equivalent
  to `logging: {enabled: true}` (Cloudflare's API default), eliminating
  spurious MODIFY diffs. Explicit `logging: {enabled: false}` still
  diffs against current `true` state. Pairs with `octorules-cloudflare 0.8.2`.

## [0.26.2] - 2026-04-29

### Fixed
- `audit cdn-ranges`: a single failing CDN source no longer aborts the
  whole fetch. Per-source exceptions are caught and logged at WARNING;
  successful sources still populate the result. Previously a transient
  failure on one endpoint would lose every other range fetched in
  parallel.

### Changed
- `octorules completion` (shell-completion preamble): replaced a bare
  `except Exception: pass` with a narrow exception list and a DEBUG
  log line. Behavior is identical in the happy path; failure modes
  are now diagnosable.

## [0.26.1] - 2026-04-27

### Added
- `audit cdn-ranges` now matches Bunny edge-server IPs and Azure Front
  Door ingress/egress IPs, in addition to the existing Cloudflare,
  AWS CloudFront, and Google Cloud coverage. Bunny is fetched from its
  two plain-text endpoints (IPv4 + IPv6); Azure Front Door is resolved
  by scraping the Microsoft Download Center page for the current
  rotating `ServiceTags_Public_YYYYMMDD.json` URL.
- Public `octorules.USER_AGENT` constant (`octorules/<version>`).
  Used for any HTTP traffic originated by core or maintainer scripts.
  Provider packages that wrap raw HTTP clients (e.g. Bunny over httpx)
  may opt in; vendor-SDK-based providers (CF, AWS, Google, Azure) keep
  their SDK's own User-Agent.
- New module `octorules.testing.lint` exposing `assert_lint` and
  `assert_no_lint` — polymorphic assertion helpers for linter tests.
  Both accept either a `LintContext` (engine-driven flow) or a bare
  `list[LintResult]` (validator return). Provider test suites import
  from here directly; previously the same ~75 lines were duplicated
  across six `tests/test_linter/conftest.py` files.

## [0.26.0] - 2026-04-18

### Added
- New public module `octorules.reserved_ips` with `RESERVED_NETWORKS`
  (28 entries: RFC 1918 private, loopback, link-local, CGNAT,
  documentation, multicast, etc.) and `is_reserved(ip_str)`. Providers
  delegate their reserved/bogon-IP checks here so the list is
  maintained in one place.
- New public module `octorules.registration` with
  `@idempotent_registration` — a thread-safe decorator for zero-arg
  registration functions that may be invoked multiple times (tests,
  entry-point discovery, explicit imports). Serializes concurrent
  first calls under a per-function Lock.

## [0.25.4] - 2026-04-14

### Fixed
- Provider loggers (e.g. `octorules_cloudflare._leaked_credentials`) were not
  configured when providers were imported after `_setup_logging`. Added
  `configure_provider_logging()` called after provider import to extend
  logging to late-discovered modules.

## [0.25.3] - 2026-04-14

### Fixed
- Audit summary: removed spurious blank line before summary, standardized
  zero-case wording to "0 issue(s) found" (was "no issues found").
- Plan summary: moved to stderr (consistent with lint/audit), removed
  trailing blank line after last zone diff.

## [0.25.2] - 2026-04-13

### Fixed
- `compute_checksum` crash on extension changes (e.g. `ZoneSecurityChange`,
  `BotManagementChange`) that lack the `change_type`/`ref`/`phase` attributes
  expected by `_serialize_change()`. Now gracefully serializes extension-specific
  fields (`field`, `current`, `desired`).

## [0.25.1] - 2026-04-13

### Changed
- Removed unused `ALWAYS_TRUE_EXPRESSIONS` / `ALWAYS_FALSE_EXPRESSIONS`
  constants from linter engine (superseded by `is_always_true()` /
  `is_always_false()` functions).

## [0.25.0] - 2026-04-10

### Added
- Zone plans cache — `plan`, `sync`, and `dump` commands write
  `.zone_plans_cache.json` next to the config file after provider
  initialization. The `lint` command reads this cache for automatic per-zone
  plan tier detection without requiring API credentials or the `--plan` flag.

### Fixed
- CDN range overlap detection (`check_cdn_ranges`) could miss broad CDN
  prefixes (e.g. `/8`) when a narrower range with a later start address didn't
  overlap — the sweep optimization broke out of the loop prematurely.
- `manager.max_workers` with non-integer values (e.g. `abc`, `[1, 2]`) now
  raises a descriptive `ConfigError` instead of an unhandled
  `ValueError`/`TypeError`.

### Changed
- CORE006 ("Rules file has no actual rules") severity changed from WARNING to
  INFO to match actual emission behavior.
- Core linter rule registration is now thread-safe (`threading.Lock`).

## [0.24.0] - 2026-04-08

### Added
- `rule` subcommand — browse/search the lint rule catalog (`octorules rule
  --all`, `octorules rule CF201`, `--format json`)
- `--config-only` flag on `lint` — validates config file structure without
  linting rules files
- Single-file lint mode — `octorules lint rules/example.yaml` lints one file
  without a config
- `--syslog ADDRESS` flag — sends logs to syslog (UDP or Unix socket) alongside
  stderr
- Progress indication — `[3/13] planned doctena.com` during multi-zone
  operations
- Lazy provider discovery — `lint` and `audit` load only configured providers
- Zone tab-completion — `--zone <TAB>` completes zone names via shtab
- Unknown config key warnings — typos like `sorces:` produce warnings instead of
  being silently ignored
- All-deletions warning — plan output warns when all changes are removals
- CORE rules (CORE002-006) registered in RULE_REGISTRY for `rule` catalog
- Debug logging across all commands

### Changed
- `--quiet` now suppresses stderr summary and exit lines (unless exit code is
  non-zero)
- `--format` replaces `--output-format` on all commands (consistent naming)
- `--output FILE` metavar on lint/audit/validate (was leaking internal dest
  names)
- Shared flags (`--config`, `--zone`, etc.) hidden in subcommand help (only
  shown in main help)
- `versions` subcommand no longer inherits irrelevant shared flags
- Orphaned lint warnings (CORE002) now formatted through the same formatter as
  all other lint results
- Audit terminology standardized: "issue(s) found" and "suppressed" (was
  "finding(s)" and "accepted")
- Auth error now followed by "Check that your API credentials are configured
  correctly."

### Removed
- `compare` subcommand — use `plan --exit-code` instead (exits 2 on changes)
- `report` subcommand — was a formatting variant of `plan`
- `validate` subcommand — use `lint --config-only` for config validation

### Fixed
- Pre-existing test-ordering issue where provider discovery contaminated dump
  tests

## [0.23.4] - 2026-04-07

### Changed
- `check_ip_overlap` rewritten as sweep-line algorithm — O(n log n) instead of
  O(n^2), ~99% faster on large IP lists.
- `check_cdn_ranges` uses sorted-interval binary search — O((n+m) log m)
  instead of O(n * m), ~99% faster on large IP lists.
- `fetch_cdn_ranges` uses baked-in package data when fresh, only fetching from
  live APIs when data is older than `cdn_stale_days`. When APIs are needed,
  all three are fetched concurrently instead of sequentially.

## [0.23.3] - 2026-04-07

### Added
- `zone_filter` parameter on `resolve_zone_ids` and `_init_providers` — when
  `--zone` is used, only the requested zones are resolved, avoiding unnecessary
  API calls for unrelated zones.
- Extension prefetch hooks now run concurrently via `ThreadPoolExecutor`,
  reducing per-zone planning time when multiple extensions are registered
  (e.g. Cloudflare's 6 extensions overlap instead of running sequentially).
- Debug logging across all commands (plan, sync, lint, audit, dump) — zone
  resolution timing, per-zone plan stages, worker counts, and extension
  prefetch counts are now visible with `--debug`.

## [0.23.2] - 2026-04-07

### Added
- `action_parameters` category in `register_api_fields` — providers can now
  register API-only fields inside `action_parameters` that are stripped during
  dump and plan normalization.

## [0.23.1] - 2026-04-07

### Fixed
- Extension registry `call_*` functions now snapshot the hook list under lock
  before iteration, preventing potential `RuntimeError` if a registration
  occurs concurrently. `get_format_extensions()` returns a copy.

## [0.23.0] - 2026-04-05

### Added
- `"regex"` added to valid list kinds in the planner — enables AWS Regex
  Pattern Set support via `kind: regex`.
- Per-provider example configs (`examples/config-*.yaml`) and rules files
  (`examples/rules/my-*.yaml`) for all five providers.

### Changed
- README: Azure and Bunny added to provider ecosystem table;
  zone-name-to-rules-file mapping documented; `lists` feature description
  updated to include regex pattern sets.

### Fixed
- `ZonePlan.has_changes` and `total_changes` used `cached_property` on mutable
  lists — changed to `property` to prevent stale cached values after plan
  mutations.
- `build_report_data` extension drift: `format_report` return value overwrote
  phase-level drift state — now uses `or` for monotonic accumulation.
- `_filter_desired_by_phase` dropped non-phase keys (`custom_rulesets`,
  `lists`) when `--phase` was used, causing `validate` and `audit` to silently
  skip them.
- `--plan` help text in `lint` subcommand incorrectly claimed auto-detection
  from provider API — updated to reflect actual default (`enterprise`).
- Account planning futures lacked timeout — added `_FUTURE_TIMEOUT` (120s)
  matching other futures in the planning pipeline.
- `Config._rules_cache` and `_file_cache` were unprotected against concurrent
  access — added `threading.Lock` with narrowed scope to allow concurrent
  file I/O.
- Suppression parser `_DESC_RE` only matched `description:` as the first key
  in a YAML list item — now also matches non-first-key positions.
- Dead `"Block"` entry in `check_ip_shadow` `blocking_actions` frozenset —
  removed (all comparisons are lowercased).
- Extension dump data (`page_shield_policies`, `cloudflare_zone_security`,
  etc.) was silently dropped during `octorules dump` — `_dump.py` passed
  extension data as `**kwargs` instead of `extra_sections=`, causing the
  dumper to ignore it.

## [0.22.1] - 2026-04-03

### Added
- `octorules.retry` module: shared `retry_with_backoff()` with exponential
  backoff and jitter for provider operations.
- `octorules.pathutil` module: shared `validate_path_within()` for path
  traversal protection.
- Provider utilities in `octorules.provider.utils`: `to_plain_dict()`,
  `normalize_fields()`, `denormalize_fields()`, `fetch_parallel()` — shared
  helpers for all providers.
- `strict` parameter on `call_audit_extensions()` to control whether audit
  hook errors are fatal.
- `cached_property` on `ZonePlan.has_changes` and `ZonePlan.total_changes`
  for performance.
- File-level cache in `Config._load_rules_file()` to avoid re-reading shared
  rules files.
- Idempotent phase registration: re-registering the same phase (same name +
  provider_id) is a no-op.

### Changed
- Processor hooks (`process_desired`, `process_changes`) now validate return
  types — returning the wrong type raises `ConfigError` with a clear message
  naming the processor.
- `BaseProcessor` is now a `Protocol` instead of a base class — processors
  no longer need to inherit from it.
- `PlanOutput` is now a single dataclass with a `fmt` field; `PlanText`,
  `PlanJson`, etc. are factory functions.
- Exception types narrowed in `_discover_provider_modules()`, `_fetch_json()`,
  and secret handler loading.
- `_setup_logging()` and `cmd_versions()` use `sys.modules` scan instead of
  `packages_distributions()` (~130ms faster per call).
- Subprocess-based provider tests converted to in-process (test suite ~3x
  faster).

### Removed
- `from __future__ import annotations` removed from all source files
  (Python 3.10+ native syntax).
- `PageShieldPolicyPlan` backward-compat stub and
  `ZonePlan.page_shield_policy_plans` property — use
  `extension_plans["page_shield"]` directly.
- `ZonePlan.__init__` monkey-patch for deprecated
  `page_shield_policy_plans` kwarg.
- `_init_provider()` deprecated function — use `_init_providers()`.
- `_get_cloudflare_provider()` and implicit CloudflareProvider fallback in
  `_resolve_provider_class()`.
- `CloudflareProvider` lazy re-export from `octorules.provider` — import
  from `octorules_cloudflare` directly.

## [0.22.0] - 2026-04-02

### Added
- Core lint rules (provider-agnostic, always active):
  - CORE001: Duplicate YAML key detection (raises ``ConfigError``).
  - CORE002: Orphaned rules files not matching any configured zone.
  - CORE003: All rules in a phase have ``enabled: false``.
  - CORE004: Same ref string used in multiple phases within a zone.
  - CORE005: Safety threshold sanity warning when ``delete_threshold`` <
    ``update_threshold``.
  - CORE006: Rules file contains no actual rules.
- Colored terminal output for lint results (severity labels, section headers),
  audit findings (severity, check headers), and sync progress (zone headers
  in bold, completion messages in green, errors in red, warnings in yellow).
- Exit code summary and timing printed to stderr after every command
  (e.g. ``octorules plan: exit 0 (no changes) 0.3s``).
- ``--format summary`` for ``lint`` and ``audit`` commands — prints counts
  only, useful for CI pipelines that only need pass/fail.
- ``--format json`` for ``sync`` command — prints structured JSON results
  (zone, status, synced phases, errors) to stdout.
- ``--config-only`` flag for ``validate`` command — checks config file
  structure without loading rules files.
- ``octorules completion`` subcommand — generates shell completion scripts
  for bash, zsh, and tcsh (powered by ``shtab``).
- Progress counter logged at start of planning (``Planning N zone(s)...``).
- Rule count context logged after plan (``N of M rule(s) changed, K
  unchanged``).

### Changed
- Lint plugin summary labels unused plugins: ``Lint plugins: cloudflare,
  aws (unused)`` — clarifies which plugins ran vs which had no matching phases.
- Phase and extension registries are now protected by `threading.Lock` for
  forward-compatibility with free-threaded Python builds.
- `supports_color()` respects `NO_COLOR` and `FORCE_COLOR` environment
  variables (https://no-color.org/) and accepts an optional ``stream``
  parameter (defaults to ``sys.stdout``).
- `resolve_zone_ids()` wraps non-`ConfigError` exceptions with zone context
  instead of propagating bare tracebacks.
- CDN IP range parsers now log warnings on unexpected API response shapes
  instead of silently returning empty lists.
- `dump_zone_rules()` logs a warning when skipping unknown provider phase IDs
  instead of silently dropping rules.
- Pre-commit hook now runs `ruff check` and `ruff format --check` in addition
  to the CDN ranges staleness check.
- Removed CI `concurrency` blocks from lint and test workflows.
- ``_cmd_sync_inner()`` now returns ``(exit_code, sync_results)`` instead
  of just ``exit_code``.  This is a private API but re-exported in
  ``commands.__all__`` — callers that unpack the return value will need
  to update.
- ``shtab`` added as a core dependency (shell completion generation).

## [0.21.1] - 2026-03-31

### Changed
- `ChangeTypeFilter` now filters changes across all extension types, not only
  Page Shield.
- Account-scope syncs now inherit safety thresholds (`delete_threshold`,
  `update_threshold`, `min_existing`) from the first provider's configuration
  instead of using hardcoded defaults.
- `--cdn-timeout` and `--cdn-stale-days` now reject zero and negative values.

### Fixed
- `_FRAMEWORK_KEYS` was defined twice in `config.py`; extracted to a single
  module-level constant `_PROVIDER_FRAMEWORK_KEYS`.
- `_FORMAT_RENDERERS` type annotation used lowercase `callable` instead of
  `Callable`.

## [0.21.0] - 2026-03-30

### Added
- `has_warnings` property on `LintContext` for consistent API with `has_errors`.
- `strip_api_fields()` utility in `octorules.phases` for provider field
  filtering.
- Extension hook signature validation at registration time — `TypeError` is
  raised immediately if a hook callable doesn't match the expected parameters.
- Safety threshold documentation with examples in README.
- Troubleshooting table in README.

### Changed
- `--quiet` now suppresses all informational stdout output (plan tables, lint
  results, audit findings), not just log messages. File output (`--output`) is
  unaffected.
- Secret resolution deferred to `Config.resolve_secrets()`; `lint`, `validate`,
  and `audit` commands no longer require provider credentials.
- Missing rules file logged at INFO instead of DEBUG.
- Provider entry-point load failures logged at WARNING instead of DEBUG.
- Deprecated `CloudflareProvider` fallback annotated with removal timeline
  (v1.0.0).
- `PageShieldPolicyPlan` backward-compat stub annotated with removal timeline
  (v1.0.0).
- Document that `# octorules:accept=` and `# octorules:disable=` directives
  are case-sensitive (check names lowercase, rule IDs uppercase).

### Fixed
- Path traversal protection in `_write_output_file()` uses `Path.resolve()` +
  `relative_to()` instead of substring check.

## [0.20.0] - 2026-03-30

### Added
- `octorules audit --severity`: minimum severity to report (error/warning/info).
- `octorules audit --exit-code`: granular exit codes (1 = errors, 2 = warnings).
- `octorules audit --format`: output format (text or json).
- `octorules audit --output`: write results to a file.
- `# octorules:accept=<check>` directives to suppress known audit findings per zone file.

### Changed
- **Breaking (internal):** `commands.py` split into `commands/` package (10 submodules). All public imports from `octorules.commands` are unchanged; `mock.patch` targets in downstream tests must use submodule paths (e.g. `octorules.commands._providers._init_providers`).
- Audit severity prefix in output changed from `[WARNING]` to `warning:` to prevent GitHub Actions log annotation mangling.
- Audit warnings no longer cause exit code 1 by default. Use `--exit-code` for granular exit codes (1 = errors, 2 = warnings).

## [0.19.1] - 2026-03-30

### Changed
- `call_audit_extensions()` now returns `(results, failed_names)` tuple for
  best-effort error handling — partial results are returned and failed
  extension names are logged as warnings instead of being silently swallowed.
- `_fetch_json()` now validates HTTP status before parsing; non-200 responses
  return `None` with a warning instead of attempting JSON parse on error pages.
- Add `strict=True` to `zip()` calls in plan/sync pipelines (B905).
- Path-escape `ConfigError` raises now use `from None` (B904).
- Extract `_FUTURE_TIMEOUT` constant for `future.result()` calls (was
  hardcoded `120` in four places).

### Added
- Ruff `B` (bugbear) and `RUF` lint rule categories to `pyproject.toml`.
- Per-file ruff ignores for test files (intentional unicode, regex patterns).
- CLI integration tests for `octorules audit` subcommand.
- Tests for audit extension error handling, `_fetch_json` HTTP status,
  and `audit_zone_rules` with no registered extensions.

## [0.19.0] - 2026-03-25

### Added
- New `octorules audit` subcommand for cross-rule, cross-list, cross-zone IP
  analysis. Four checks: `ip-overlap`, `ip-shadow`, `cdn-ranges`, `zone-drift`.
- Audit extension registry (`register_audit_extension`) in `extensions.py` —
  providers register IP extractors at import time, same pattern as lint plugins.
- Provider-agnostic list resolution: rules that reference IP lists (via
  `$list_name` in Cloudflare or `IPSetReferenceStatement` in AWS) have their
  IPs resolved from the `lists` section automatically. Unreferenced lists are
  still audited as standalone entries.
- Baked-in CDN IP ranges (`octorules/data/cdn_ranges/`) with API-first fetch
  and offline fallback. Staleness warning when baked-in data exceeds
  `--cdn-stale-days` (default 60).
- `Config.load_rules_by_stem()` public method for loading rules files by
  filename stem without checking zone sources.
- `scripts/sync_cdn_ranges.py` maintainer script to refresh baked-in CDN data.
- Pre-commit hook (`scripts/hooks/pre-commit`) for CDN data staleness check.

## [0.18.1] - 2026-03-24

### Changed
- Replace bare `except StopIteration` with `next(iter, None)` sentinel pattern
  in `expression.py` display formatter (4 occurrences). More Pythonic and
  future-proof.
- Provider plugin integration tests now cover all three providers (Cloudflare,
  AWS, Google) instead of Cloudflare only. Tests use `find_spec` for
  availability checks and subprocesses to avoid phase registration collisions.
- Custom ruleset validation error now lists actual registered phase IDs instead
  of a hardcoded Cloudflare example.
- Add `timeout=120` to all `future.result()` calls in account planning and
  dump operations (custom rulesets + lists), matching the Page Shield pattern.

### Added
- `TestMultiProviderCoexistence` tests: verify all providers register phases
  without collision, API fields merge correctly, and no phase names overlap.
- `TestEntryPointDiscovery` tests: verify `_resolve_provider_class` and
  `_discover_provider_modules` find real providers via entry points.
- `bare_*` test phases (no `prepare_rule`) in conftest to exercise the
  `prepare_rule=None` planner path used by AWS/Google providers.
- Config validation edge case tests: circular `!include` detection, deeply
  nested includes, special-character filenames, safety threshold inheritance.
- Concurrent `_apply_parallel` error scenario tests: partial failures,
  auth error propagation, exception handling under `ThreadPoolExecutor`.

## [0.18.0] - 2026-03-23

### Added
- **Custom ruleset lifecycle** (`diff_custom_rulesets_full`). Full create/update/delete
  diffing for custom rulesets, matching the lists pattern. `CustomRulesetPlan` now
  has `create`, `delete`, `capacity`, and `total_changes` fields.
- `create_custom_ruleset` and `delete_custom_ruleset` on `BaseProvider` protocol.
- **`--audit-log PATH`** for `sync` command. Writes JSON lines with per-zone sync
  results (zone, synced phases, status, error, timestamp).
- **Feature support warning** in `_plan_single_zone`. Warns when YAML uses
  features (custom_rulesets, lists) not supported by the zone's provider.

### Fixed
- Config safety parsing: error messages no longer risk `KeyError` when the
  invalid value comes from a default (store raw value before conversion).

### Changed
- `validate_custom_ruleset`: `id` is now optional. New rulesets require `capacity`
  instead. Existing YAML with `id` fields continues to work unchanged.
- `_apply_custom_rulesets`: staged execution (creates → updates → deletes),
  matching the lists apply pattern.
- `count_change_types` helper extracts duplicated ADD/REMOVE/MODIFY tallying
  from formatter and planner into a single function.
- `_run_staged_tasks` orchestrator extracts the repeated create→update→delete
  apply pattern from `_apply_custom_rulesets` and `_apply_lists`.
- `RuleDict` type alias for `dict[str, Any]` used across planner, formatter,
  and commands for clearer type annotations.

## [0.17.0] - 2026-03-19

### Added
- **`octorules.provider.utils`** — shared provider helpers:
  - `make_error_wrapper` factory for mapping SDK exceptions to provider-agnostic
    exception types. Eliminates boilerplate in provider implementations.
  - `format_api_error` for consistent error formatting with HTTP status codes.
- **Lint result location** (`LintResult.location`). Lint results now carry the
  YAML source location (e.g. `doctena.com.yaml:106`), shown inside the
  parentheses in text output and as `region.startLine` in SARIF.
- **Extension hook system** (`octorules.extensions`). Five registries that allow
  provider packages to plug in provider-specific features without coupling the
  core: `register_plan_zone_hook` (two-phase prefetch/finalize for concurrent
  API calls), `register_apply_extension`, `register_format_extension`,
  `register_validate_extension`, `register_dump_extension`.
- **`ZonePlan.extension_plans`** generic dict for extension-specific plan data.
  `has_changes` and `total_changes` iterate extension plans generically.
- **`dump_zone_rules` accepts `extra_sections`** for extension dump data.

### Fixed
- **`octorules: {ignored: true}` no longer deletes the rule from the provider.**
  Ignored rules are now excluded from both desired and current during diff,
  matching the octodns convention. Previously, an ignored rule that existed
  upstream would be planned for deletion.

### Changed
- **Page Shield extracted to octorules-cloudflare.** All Page Shield planning,
  applying, formatting, validation, and dumping code moved to
  `octorules_cloudflare.page_shield`. Core retains backward-compat
  `PageShieldPolicyPlan` stub and `ZonePlan.page_shield_policy_plans` property.
- **Page Shield methods removed from `BaseProvider` protocol.** Providers no
  longer need to implement `list_page_shield_policies`,
  `create_page_shield_policy`, `update_page_shield_policy`,
  `delete_page_shield_policy`, `get_all_page_shield_policies`.
- `format_csp_value` moved from `octorules.expression` to
  `octorules_cloudflare.page_shield`.
- `format_page_shield_policy_plan` removed from `octorules.formatter`
  (replaced by extension formatter).
- `compute_checksum` and `check_safety` now iterate `extension_plans`
  generically instead of hardcoding Page Shield.

## [0.16.0] - 2026-03-17

### Added
- **Rule-level metadata** (`octorules:` key). Per-rule metadata that controls
  octorules behavior without affecting the provider API:
  - `octorules: {ignored: true}` — keep a rule in YAML for documentation while
    skipping it during plan/sync. Ignored rules are still validated and linted.
  - `octorules: {included: [...]}` / `octorules: {excluded: [...]}` — restrict a
    rule to specific providers or targets in multi-provider/multi-target setups.
    `included` and `excluded` are mutually exclusive (matching octodns convention).
  The `octorules:` key is stripped before sending rules to the provider API and
  excluded from diff comparison.
- **`Manager` class** (`octorules.manager`): high-level orchestrator for
  programmatic use. Wraps config loading and all commands (`plan`, `sync`,
  `compare`, `dump`, `validate`, `report`, `lint`) behind a single entry
  point with context manager support. Each command initialises providers
  internally (matching CLI behaviour). Exported from `octorules` top-level
  package.
- **YAML context tracking.** `ConfigError` messages from `Config.from_file()`
  and `_parse_zone()` now include `filename:line` context (e.g.
  `(at config.yaml:12)`), making it easy to locate the offending YAML line
  in large configs with `!include` directives. Powered by `ContextDict`, a
  dict subclass that carries PyYAML `Mark` source locations through the
  parsing pipeline.
- **Built-in processor filters.** Three ready-to-use processors in
  `octorules.processor.filters`: `PhaseFilter` (include/exclude phases by
  name), `RefFilter` (include/exclude rules by ref regex), and
  `ChangeTypeFilter` (block specific change types like REMOVE as a safety
  guard). All filters validate their config at init time and raise
  `ConfigError` on invalid arguments.
- **Pluggable secret handlers.** Config values can now reference secrets from
  any backend — Vault, AWS Secrets Manager, GCP Secret Manager, etc. — via the
  `handler/reference` syntax (e.g. `vault/secret/data/cf#token`). The built-in
  `env/` handler remains the default. Custom handlers are declared in a new
  `secret_handlers:` config section or auto-discovered via the
  `octorules.secret_handlers` entry-point group. Handler kwargs are
  bootstrapped through already-registered handlers (e.g. `env/VAULT_TOKEN`).
- `BaseSecrets` base class and `EnvironSecrets` built-in handler
  (`octorules.secret`).
- `SecretsException(ConfigError)` for secret resolution failures.
- `_load_class()` moved from `commands.py` to `config.py` (shared by provider,
  processor, and secret handler loading).
- **Multi-target zones.** A zone can now target multiple providers of the same
  class (e.g. `cf-prod` + `cf-staging`). Each target produces an independent
  plan and is applied separately. `ZonePlan.target` tracks which target a plan
  belongs to; `display_name` renders as `zone -> target` in output.
- **Processor pipeline.** New `processors` config section for hooking into the
  plan/sync pipeline. Processors transform desired rules before planning
  (`process_desired`) and filter changes after planning (`process_changes`).
  Configured per-zone via `processors:` list.
- **Zone discovery.** Zones can be discovered automatically from providers that
  support `SUPPORTS_ZONE_DISCOVERY`. Use `'*'` as a zone template in config;
  discovered zones that have a matching YAML rules file are added at init time.
  Explicit zone configs always take precedence.
- `SUPPORTS_ZONE_DISCOVERY` feature constant and `list_zones()` method on
  `BaseProvider` protocol.
- `ProcessorConfig` dataclass and `BaseProcessor` base class
  (`octorules.processor`).
- `Config.zone_templates` field and `Config.expand_templates()` method for
  zone discovery.
- `ZonePlan.target`, `ZonePlan.display_name`, `ZonePlan.plan_key` properties.
- `_validate_multi_target()`, `_get_zone_providers()`, `_init_processors()`,
  `_discover_zones()`, `_load_class()` helpers in `commands.py`.
- **`ProviderConfig` dataclass** (`octorules.config`): holds per-provider
  `class_path`, `kwargs`, and safety thresholds.
- **`ZoneConfig.targets`**: list of provider names a zone deploys to.
- **Entry-point auto-discovery.** Providers register via
  `octorules.providers` entry-point group; `_resolve_provider_class()` discovers
  them automatically when `class:` is omitted.
- **Recursive `env/` resolution.** `_resolve_deep()` resolves `env/VARNAME`
  prefixes in nested dicts and lists (previously only top-level string values).
- **Per-provider zone ID resolution.** `resolve_zone_ids()` accepts a
  `dict[str, Callable]` mapping provider names to resolve functions.
- **Multi-account planning.** `_plan_all_scopes()` runs `_plan_account()` for
  every provider that has an `account_id`, concurrently with zone planning.
- **`_PlanAllResult.provider_map`**: tracks which provider handles each
  zone/account.
- **BaseProvider protocol** (`octorules.provider.base`): `@runtime_checkable`
  Protocol defining all 22 methods + 4 properties that provider implementations
  must satisfy.
- **Provider exception hierarchy** (`octorules.provider.exceptions`):
  `ProviderError`, `ProviderAuthError`, `ProviderConnectionError` — provider-
  agnostic base exceptions.
- **Provider factory** (`_load_provider_class`): dynamic import from dotted
  path (e.g. `octorules_aws.AwsWafProvider`).
- **Phase registration API** (`register_phase`, `register_phases`,
  `unregister_phase`): extensible phase registry so provider packages can
  register their own phases at import time.  All derived collections
  (`ALL_PROVIDER_IDS`, `PHASE_BY_NAME`, etc.) are mutated in-place.
- **API field registry** (`register_api_fields`, `unregister_api_fields`,
  `get_api_fields`): providers register API fields to strip per category
  (`"rule"`, `"list_item"`, `"page_shield_policy"`).
- **Phase alias registry** (`register_phase_alias`, `unregister_phase_alias`):
  providers register backward-compat phase name aliases.
- `Config.provider_class` field — optional `class:` key under
  `providers.<name>` for dynamic provider loading.
- `[project.optional-dependencies] cloudflare` extra pointing to
  `octorules-cloudflare>=0.1`.
- **`Phase.prepare_rule` hook.** Optional callable on `Phase` for provider-
  specific rule preparation (expression normalization, default fields, action
  injection). Called by the planner after stripping `octorules:` metadata.
  Providers register this when registering phases; the core planner contains
  zero provider-specific logic.
- `_discover_provider_modules()`: imports installed provider packages via
  entry-points without constructing instances, used by `cmd_lint` to register
  lint plugins offline.

### Fixed
- Zone discovery now catches only `ProviderError` instead of bare `Exception`,
  preventing programming errors from being silently swallowed.
- `cmd_versions()` now catches only `PackageNotFoundError` instead of bare
  `Exception`.
- `cmd_lint` no longer initializes provider API clients. Lint is fully
  offline — no credentials needed, even in multi-provider configs.
- `--plan` auto-detection removed from lint command. Use `--plan free` (etc.)
  explicitly for Cloudflare plan-tier checks; defaults to `enterprise`.

### Changed
- **BREAKING: Multi-provider support.** `Config.providers` is now a
  `dict[str, ProviderConfig]` supporting multiple named providers (replaces
  single-provider `provider_class`/`provider_kwargs` fields). Zones route to
  providers via `targets:` list; auto-assigned when a single provider is
  configured.
- `_init_providers()` replaces `_init_provider()` as the primary provider
  factory (the latter is kept as a deprecated backward-compat wrapper).
- `_plan_zones()`, `_plan_all_scopes()`, `_apply_zone_changes()`,
  `_cmd_sync_inner()`, `cmd_dump()`, `cmd_report()` now accept/use a providers
  dict instead of a single provider instance.
- `_check_safety_violations()` accepts `account_labels: list[str]` (was singular
  `account_label`). `_PlanAllResult.account_label` is now a backward-compat
  property over `account_labels`.
- **BREAKING: Provider split.** The Cloudflare SDK (`cloudflare~=4.3`) is no
  longer a direct dependency.  Install `octorules[cloudflare]` (which pulls in
  [octorules-cloudflare](https://github.com/doctena-org/octorules-cloudflare))
  to use Cloudflare. `import octorules` works without any provider installed.
- **BREAKING: Provider-agnostic data model.** `Phase.cf_phase` renamed to
  `Phase.provider_id`. Derived collections renamed: `PHASE_BY_CF` →
  `PHASE_BY_PROVIDER_ID`, `ALL_CF_PHASES` → `ALL_PROVIDER_IDS`,
  `ZONE_CF_PHASES` → `ZONE_PROVIDER_IDS`, `ACCOUNT_CF_PHASES` →
  `ACCOUNT_PROVIDER_IDS`. `get_phase_by_cf()` → `get_phase_by_provider_id()`.
- **BREAKING: JSON/CSV output keys.** `"cf_phase"` → `"provider_id"` in JSON
  plan output and report data. CSV header `"CF Phase"` → `"Provider ID"`.
- **BREAKING: API field constants removed.** `CF_API_FIELDS`,
  `LIST_ITEM_API_FIELDS`, `PAGE_SHIELD_POLICY_API_FIELDS` replaced by a
  provider-registered field registry (`register_api_fields()` /
  `get_api_fields()`). Providers register their fields at import time.
- **BREAKING: `RENAMED_PHASES` starts empty.** Phase aliases are now
  provider-registered via `register_phase_alias()` / `unregister_phase_alias()`.
  The Cloudflare provider registers `waf_managed_exceptions` →
  `waf_managed_rules` at plugin init.
- **Flat layout.** Package moved from `src/octorules/` to `octorules/` at the
  repo root, matching the octodns convention.
- `commands.py` and `cli.py` now catch provider-agnostic `ProviderAuthError`
  and `ProviderError` instead of Cloudflare SDK exceptions.
- **BREAKING: octodns-style kwargs passthrough.** All keys in the provider
  config section (except `class` and `safety`) are forwarded as keyword
  arguments to the provider constructor. `Config.token`, `Config.max_retries`,
  `Config.timeout` fields removed; replaced by `Config.provider_kwargs` dict.
  `env/` prefix resolution applies to all string values, not just `token`.
- `_init_provider()` calls `provider_cls(**config.provider_kwargs)` instead
  of hardcoded positional args. Falls back to `CloudflareProvider` (re-exported
  from octorules-cloudflare) when no `class` is configured.
- All `provider: CloudflareProvider` type hints in `commands.py` changed to
  `provider: BaseProvider`.
- `cmd_versions` now auto-discovers installed `octorules-*` packages via
  `importlib.metadata` instead of hardcoding `import cloudflare`.
- `BaseProvider` protocol methods use `provider_id` / `provider_ids` instead
  of `cf_phase` / `cf_phases`.
- `_plan_zones()` builds work items per-target for multi-target zones.
- `compute_checksum()` sorts by `(zone_name, target)` and includes `target` in
  serialized zone data.
- Formatter renderers use `zp.display_name` instead of `zp.zone_name`. JSON
  renderer includes `target` field when set.
- `_load_provider_class()` now delegates to generic `_load_class()` helper
  (shared with processor loading).
- `_PlanAllResult.provider_map` type changed from `dict[str, BaseProvider]` to
  `dict[tuple[str, str | None], BaseProvider]` (keyed by `(zone_name, target)`).
- **BREAKING: Provider-agnostic planner.** The core planner no longer validates
  `expression` fields, normalizes expressions, defaults `enabled`, or injects
  `phase.default_action`. All provider-specific rule preparation is delegated
  to the `Phase.prepare_rule` hook. Providers that relied on core expression
  normalization must register their own `prepare_rule` callable.

### Removed
- `CloudflareProvider` class, all CF SDK helpers, and CF SDK exception
  re-exports moved to
  [octorules-cloudflare](https://github.com/doctena-org/octorules-cloudflare).
- Provider-specific tests (`test_provider.py`, `test_provider_lists.py`,
  `test_provider_custom_rulesets.py`, `test_provider_page_shield.py`,
  `tests/mocks.py`) moved to octorules-cloudflare.
- `CF_API_FIELDS`, `LIST_ITEM_API_FIELDS`, `PAGE_SHIELD_POLICY_API_FIELDS`
  constants (replaced by `get_api_fields()` registry).
- Hardcoded `RENAMED_PHASES` dict (replaced by `register_phase_alias()`).
- `scripts/sync_schemas.py`, `scripts/generate_fields.py`,
  `scripts/hooks/pre-commit`, `docs/schemas.md` moved to octorules-cloudflare
  (they reference CF-specific linter schemas).

## [0.15.1] - 2026-03-14

### Added
- **Registry error path tests**: 6 tests covering wirefilter-unavailable fallback,
  empty overlay handling, and fallback-vs-wirefilter field consistency.
- **Report stream tests**: 5 tests covering `format_json()` and `format_sarif()`
  stream writing and SARIF output without `file_path`.
- **Suppression/filter interaction tests**: 3 tests verifying precedence between
  `--rule` filter, severity filter, and suppression directives.
- **Concurrency stress test**: 50-zone concurrent `resolve_zone_id` test verifying
  thread-safe `zone_plans` population.

### Changed
- **provider.py DRY refactor**: extracted `_fetch_parallel()` helper, replacing
  3 near-identical `ThreadPoolExecutor` + `as_completed` blocks in
  `get_all_phase_rules`, `get_all_custom_rulesets`, and `get_all_lists`.
- **config.py DRY refactor**: extracted `_load_rules_file()` helper, replacing
  duplicated YAML loading, caching, and path-traversal logic between
  `load_zone_rules()` and `load_account_rules()`.
- **`_check_enum()` helper** in `action_validator.py` — consolidates 5 inline
  enum validation blocks into a single reusable function.
- **Narrowed exception handling** in `expression_bridge.py`: FFI crash handler
  now catches `(RuntimeError, TypeError, ValueError, OSError)` instead of
  bare `Exception`.
- Upper bound `<1.0` added to `octorules-wirefilter` optional dependency.

## [0.15.0] - 2026-03-11

### Added
- **P005 now validates managed lists** (`$cf.*`): field/kind mismatch detection
  extended to Cloudflare managed lists (all `ip` kind). Managed list kinds are
  tracked in `overlay.toml` via the new `[managed_lists.kinds]` section.
- **Page Shield suppression support**: `# octorules:disable=RULE` directives now
  work with `- description:` lines (bare, double-quoted, and single-quoted),
  enabling per-policy suppression for Page Shield policies.
- **`tests/test_commands.py`**: 11 unit tests for the new `_plan_all_scopes()`
  helper and `_PlanAllResult` dataclass.
- **Provider retry/backoff tests**: 9 new tests covering `AuthenticationError`
  immediate propagation, `JSONDecodeError` no-retry, `APIConnectionError` retry,
  linear backoff timing, graduated backoff sequence, and API error during polling.
- **Config upper bounds**: `max_retries` capped at 10, `timeout` capped at 300s.
  Prevents misconfiguration (e.g. milliseconds instead of seconds).
- **Suppressions unit tests** (`tests/test_linter/test_suppressions.py`): 17 tests
  covering `parse_suppressions()` and `is_suppressed()` directly — empty files,
  OSError, unknown IDs, pending IDs at EOF, mixed anchor types, whitespace tolerance.
- **Dumper error path tests**: 5 tests for mkdir failure, path traversal zone names,
  file write OSError, and list write failures.
- **`octorules versions` documented in README**.
- **Registry unit tests** (`tests/test_linter/test_registry.py`): 8 tests covering
  `load_managed_lists()`, `load_managed_list_kinds()`, `load_schema()`, and
  `_load_fallback()` — the schema loading backbone previously without direct tests.
- **`--scope` flag documented in README** common flags table.

### Changed
- **commands.py DRY refactor**: extracted `_PlanAllResult` class and
  `_plan_all_scopes()` helper, replacing 3 near-identical zone/account planning
  blocks in `_cmd_plan_or_compare`, `cmd_report`, and `_cmd_sync_inner`.
- **Test fixture DRY**: shared mock classes (`MockRule`, `MockRuleset`,
  `MockRuleWithToDict`, `MockRuleIterableOnly`) moved to `tests/mocks.py`,
  eliminating duplication across 4 provider test files.
- **`global` caching replaced with `@functools.lru_cache`** in
  `cross_rule_linter.py` (2 loaders) and `engine.py` (1 loader) — eliminates
  module-level sentinel variables, `global` statements, and `noqa` comments.

### Fixed
- **`__import__("re")` cleanup** in `action_validator.py`: replaced inline
  `__import__("re")` hack with standard `import re` at module top.
- Stale TODO prefixes removed from test docstrings in `test_expression.py`
  and `test_provider.py`.

## [0.14.0] - 2026-03-10

### Added
- **Phase-specific parameter validation**: `response_header_rules` now rejects
  `action_parameters.uri` (URI rewrites are not available in the response phase).
  Catches rules accidentally misplaced under the wrong phase due to YAML editing
  mistakes (e.g. deleting a phase key while its rules remain, causing them to fall
  under the previous phase). Implemented via `PHASE_PARAMETER_OVERRIDES` in the
  action schema — extensible to other phases if needed.
- **Full lint parity for custom rulesets and Page Shield policies**: custom
  ruleset rules now receive phase restriction checks (B001, B002, B003) in
  addition to action and expression analysis. Page Shield policies now receive
  both expression analysis and phase restriction checks.
- **`check_catch_all()` helper** in lint engine — deduplicates M013/M014
  always-true/always-false detection across `yaml_validator`, `page_shield_linter`,
  and `cross_rule_linter`. Accepts an `entity` parameter for context-aware
  messages ("rule" vs "policy").
- **Explicit `RULE_IDS` frozensets** on all 9 linter modules — `engine.py`
  collects them lazily for suppression validation and rule filtering.
- **Managed list names in `overlay.toml`** — `[managed_lists]` section with
  source URL and last-verified date, replacing hardcoded names.
- **`QuoteAwareScanner`** class in `expression.py` — robust character-by-character
  scanner that correctly handles escaped quotes, replacing the previous inline
  state machine.
- **`assert_lint()` / `assert_no_lint()` test helpers** in
  `tests/test_linter/conftest.py` — consistent assertion helpers with count,
  severity, ref, and phase checking, with clear error messages.

### Changed
- **C004** (unknown `action_parameters` key) promoted from WARNING to **ERROR**.
  Cloudflare's API rejects unknown keys; WARNING was too lenient.
- **C011** (invalid skip phase) promoted from WARNING to **ERROR**.
- **C012** (invalid skip product) promoted from WARNING to **ERROR**.
- **C014** (unknown rate limit characteristic) promoted from WARNING to **ERROR**.
- **CLI refactored**: command implementations extracted from `cli.py` to new
  `commands.py` module (~1500 LOC). `cli.py` retains argument parsing and
  re-exports for backward compatibility.
- **Planner DRY refactor**: extracted `_prepare_base_rules()` (shared
  expression normalization + `enabled` defaulting) and `_make_synthetic_phase()`
  (shared Phase construction for custom rulesets, lists, page shield).
- **Provider graduated backoff**: `poll_bulk_operation()` uses `(1, 2, 3, 5)`
  second intervals instead of fixed 2s polling.
- `lint_phase_restrictions()` now accepts optional `ref_override` parameter
  (parity with `lint_expressions()`).

### Fixed
- **ASN list accepted boolean values**: `asn: true` in YAML was silently
  accepted as ASN 1 because Python's `isinstance(True, int)` returns `True`.
  Now explicitly rejects booleans.
- **Origin port accepted boolean values**: `port: true` was silently accepted
  as port 1 for the same reason. Now reports a type error.
- **Custom ruleset rules skipped phase restriction checks**: B001 (response
  field in request phase), B002 (body field without body access), and B003
  (plan-gated field) were never checked for custom ruleset rules.
- **Page Shield policies skipped phase restriction checks**: B003 (plan-gated
  field) was never checked for Page Shield policy expressions.

## [0.13.2] - 2026-03-09

### Fixed
- **`FileNotFoundError` on `overlay.toml` in installed package**: `overlay.toml`
  and `schemas.json` were not included in the published wheel (missing
  `[tool.setuptools.package-data]` in `pyproject.toml`). This caused a crash
  at import time when wirefilter was installed, breaking `octorules lint` in CI.

## [0.13.1] - 2026-03-07

### Changed
- **Schema loading is now dynamic**: field and function registries are built
  at import time from wirefilter + `overlay.toml` when wirefilter is installed,
  eliminating version-skew between local dev and CI. Falls back to a frozen
  `schemas.json` snapshot when wirefilter is absent.
- `sync_schemas.py` now generates `schemas.json` (data) instead of Python code
  blocks in `fields.py` / `functions.py`.
- Publish workflow is gated on lint + test via reusable workflows — broken
  code can no longer reach PyPI.
- `--check` step removed from CI test workflow (pre-commit hook keeps the
  fallback fresh; live loading makes the check unnecessary).

### Added
- `_registry.py`: import-time schema loader (wirefilter-first, JSON fallback).
- `schemas.json`: frozen schema snapshot for the no-wirefilter fallback path.
- `docs/schemas.md`: full architecture documentation (data sources, data flow,
  editing overlay.toml, fallback behavior).
- `scripts/hooks/pre-commit`: auto-regenerates `schemas.json` when
  `overlay.toml` or `pyproject.toml` is modified.
- `lint.yaml` and `test.yaml` now support `workflow_call` (reusable workflows).

### Fixed
- Missing `overlay.toml` entries for JWT `exp` claim fields
  (`requires_plan = "enterprise"`) — pre-existing oversight since these fields
  were added to wirefilter.
- `overlay.toml` missing metadata for 8 functions (`decode_base64`, `cidr`,
  `cidr6`, `join`, `split`, `bit_slice`, `is_timed_hmac_valid_v0`, `sha256`).

## [0.13.0] - 2026-03-07

### Added
- Suppression parser validates rule IDs against the known rule registry and
  warns on unknown IDs (e.g. typos like `X999`).
- `octorules lint` now logs `"Lint: N issue(s) suppressed"` at INFO when
  suppressions are active.
- CLI: `--checksum` value is validated as a 64-character lowercase hex string
  before use; invalid formats raise a clear `ConfigError`.
- CLI: "zone not found" error now lists available zones from the config.
- `_require_field()` generic type validator in planner — generalizes
  `_require_string_field()` to any type (used for `bool` in page shield).

### Fixed
- `normalize_expression()` now logs a warning on unmatched quotes instead of
  silently returning a malformed result.
- P004 message changed from "Invalid managed list" to "Unknown managed list"
  with a suggestion to report newly added Cloudflare managed lists.
- `_VALID_MANAGED_LISTS` in cross-rule linter now documents its source URL
  and last-updated date.

### Changed
- `put_list_items` docstring documents why no count-check is performed
  (async bulk operation with polling).
- `pyproject.toml` documents wirefilter degraded-mode behavior in optional
  dependency comment.
- `config.py` docstrings enhanced: `resolve_value()` documents `env/VARNAME`
  syntax; `Config.from_file()` documents config file structure.

## [0.12.6] - 2026-03-07

### Added
- **New Category Q — List Validation** (6 rules):
  - **Q001**: Missing or duplicate list name.
  - **Q002**: Missing or invalid list kind (must be `ip`, `asn`, `hostname`, or `redirect`).
  - **Q003**: List item missing required field for its kind.
  - **Q004**: Invalid IP address in IP list.
  - **Q005**: Invalid ASN value in ASN list (must be integer 0–4294967295).
  - **Q006**: Duplicate items within a list.
- **New Category T — Custom Ruleset Validation** (4 rules):
  - **T001**: Missing required fields (`id`, `name`, `phase`) in custom ruleset.
  - **T002**: Invalid custom ruleset ID format (must be 32-character hex).
  - **T003**: Duplicate ref within a custom ruleset.
  - **T004**: Duplicate ref across custom rulesets.
- **A002**: Expression nesting depth exceeds 100 levels (wirefilter).
- **C016**: Missing `id` in `execute` action's `action_parameters`.
- **C017**: Invalid `execute` ID format (not 32-character hex).
- **C018**: Compression terminal algorithm (`none`, `auto`) must be last
  in the algorithms list.
- **J005**: Security warning when SSL mode is set to `off`.
- **L007**: Request header transforms (`request_header_rules`) do not support the
  `add` operation — only `set` and `remove` are valid.
- **M016**: Informational notice when a rule has `enabled: false`.
- **P005**: List type / field type mismatch — detects when a field (e.g. `ip.src`)
  is used with a list of incompatible kind (e.g. `asn`).
- CSP value formatting in `octorules dump`: long page shield `value` fields
  are formatted as multi-line YAML block scalars with one source per line,
  directive names unindented, sources indented by 2 spaces.

Total lint rules: **127** (was 109).

### Fixed
- **`check_safety` missed page shield REMOVE changes**: the safety threshold
  check only counted `MODIFY` changes on page shield policies, silently
  ignoring `REMOVE` changes. All four plan types (phases, custom rulesets,
  lists, page shield) now use a shared `_tally()` helper that counts both
  `REMOVE` and `MODIFY` consistently.
- **ASN list identity `None` → `"None"`**: when a list item had `asn: null`
  (or the CF API returned `null`), the identity key became the string
  `"None"` instead of empty, causing phantom ADD+REMOVE diffs. Now returns
  empty string for `None` ASN values.
- **`JSONDecodeError` crash in `get_list_items`**: if the Cloudflare API
  returned invalid JSON for list items, a `json.JSONDecodeError` would
  escape the retry loop (only `APIError`/`APIConnectionError` were caught).
  Now caught and raised as `ValueError` with context.
- **C002 silent skip for non-string action**: `lint_actions` silently returned
  when `action` was not a string (e.g. `action: 123`). Now reports C002
  with a clear "must be a string" message.
- Duplicate refs in `_rules_by_ref` now log a warning instead of silently
  overwriting.
- Duplicate identity keys in `_items_by_identity` now log a warning instead
  of silently overwriting.
- Malformed list items (empty identity key) now log a warning instead of
  being silently dropped from diffs.
- **`allow_unmanaged` reorder false negative**: when `allow_unmanaged=True`,
  reorder was never detected because `current_order` contained unmanaged refs
  not in `desired_order`, making the set comparison always fail. Now filters
  `current_order` to only managed refs before comparing.
- `_normalize_value` over-normalized: previously applied `normalize_expression()`
  to **all** string fields (description, ref, action, etc.). Now scoped to
  only `expression`, `counting_expression`, and `value` keys via `_NORMALIZE_KEYS`.
- `_ruleset_to_dict` silent empty return: now logs a warning when ruleset
  conversion fails, aiding debugging of unexpected API responses.

### Changed
- Extracted `_require_string_field()` helper — deduplicates validation logic
  across `validate_rules`, `validate_custom_ruleset`, and
  `validate_page_shield_policy` (was ~60 lines of near-identical checks).
- `check_safety` uses a shared `_tally()` closure — deduplicates 4 identical
  count loops (phases, custom rulesets, lists, page shield).
- `compute_checksum` and `_serialize_change` sorting uses `operator.itemgetter`
  instead of lambda.
- `normalize_list_item` no longer calls `_normalize_value` — list items have
  no expression fields, so the call was a no-op at best.

## [0.12.5] - 2026-03-06

### Added
- **C015**: Block response validation — `status_code` must be 400–499, `content_type`
  and `content` must be strings.
- **E007**: Function source argument must be a field reference, not a string literal.
  Checks `decode_base64`, `url_decode`, `starts_with`, `ends_with`, `wildcard_replace`.
- **F003**: Array `[*]` unpacking used on multiple distinct arrays in the same
  expression. Cloudflare only allows `[*]` on one array per expression.
- **G026**: `bit_slice()` offset (0–2040) and size (1–32) range validation.
- **B003** now also checks function plan tier requirements (previously field-only).
  `sha256` requires Enterprise, `is_timed_hmac_valid_v0` requires Pro.
- Function phase restrictions: `decode_base64` (transform + WAF + rate limiting),
  `split` (response transform + custom error), `join` (transform + WAF + custom
  error), `cidr`/`cidr6` (WAF + rate limiting), `bit_slice` (network phases only).
- 3 JWT `exp` claim fields: `http.request.jwt.claims.exp.sec`,
  `http.request.jwt.claims.exp.sec.names`, `http.request.jwt.claims.exp.sec.values`.
- Documentation for 12 extra fields in `fields.py` and 7 extra functions in
  `functions.py` that are intentionally kept outside the generated blocks
  (deprecated `ip.geoip.*` aliases, account-level zone fields,
  wirefilter-internal functions like `contains`, `sha512`, `hmac`).

### Fixed
- G018 (invalid `**` in wildcard pattern) now correctly detects `strict wildcard`
  expressions when wirefilter is installed. The wirefilter visitor emits
  `strict_wildcard` as the operator name; the regex fallback and AST linter
  previously checked for `strict`, causing the primary detection path to silently
  skip strict wildcard patterns.
- Regex fallback parser now correctly extracts raw string literals (`r"..."`,
  `r#"..."#`) as `regex_literals` instead of misclassifying them as
  `string_literals`. Fixes G001 (max 64 regex) undercounting and G023 (regex
  validation) missing raw-string patterns when wirefilter is not installed.
- Removed spurious `~~` from regex fallback operator set (not a valid wirefilter
  or Cloudflare operator).
- `_strip_outer_parens()` helper for consistent always-true/always-false detection
  across `is_always_true()` and `is_always_false()` engine functions.
- `ThreadPoolExecutor` in `cli.py` now uses `with` statement for proper shutdown.
- Unused imports removed from `cli.py`, `cross_rule_linter.py`, `config.py`,
  `page_shield_linter.py`, `yaml_validator.py`.

## [0.12.4] - 2026-03-06

### Fixed
- P001 duplicate expression detection now uses `normalize_expression()` instead
  of naive whitespace collapsing. Brace whitespace is stripped to match
  Cloudflare's canonical form (e.g. `{ "AT" "BE" }` → `{"AT" "BE"}`), improving
  duplicate detection accuracy for expressions with set literals.
- M013/M014 always-true/always-false detection in `yaml_validator` and
  `page_shield_linter` now uses `normalize_expression()` for consistent
  whitespace handling.
- Config parser rejects non-boolean values for `always_dry_run` and
  `allow_unmanaged` (e.g. `"yes"` string) with a clear error message instead
  of silently coercing via `bool()`.
- `BadRequestError` and `PermissionDeniedError` when fetching phase rules are
  now logged at INFO instead of DEBUG, so users see why phases were skipped
  without enabling debug mode.

### Added
- PEP 561 `py.typed` marker for type checker integration.

## [0.12.3] - 2026-03-06

### Changed
- Python 3.14 added to CI test matrix.
- `octorules-wirefilter` optional dependency bumped to `>=0.3.0` (PyO3 0.28,
  Python 3.14 wheel support).

## [0.12.2] - 2026-03-06

### Added
- Expression display formatting in plan output: long expressions in diffs are
  now broken at `and`/`or` operators and set literal boundaries (`{…}`) with
  indentation reflecting nesting depth. Applies to all output formats (HTML,
  markdown, text). Short expressions (≤ 80 chars) are unchanged.

## [0.12.1] - 2026-03-06

### Added
- Expression whitespace normalization: multi-line YAML block scalars (`|`, `|-`)
  are collapsed to single-line expressions before sending to Cloudflare and
  before linting. Quoted string contents are preserved verbatim. Whitespace
  after `{` and before `}` is stripped to match Cloudflare's canonical form
  (e.g. `{"a" "b"}` not `{ "a" "b" }`).

### Fixed
- `octorules lint`: zone status lines (`no issues found`, `no rules file`)
  now use consistent two-space indent in text output.
- `octorules dump`: multiline strings now use `|-` (strip) block scalar style
  instead of `|` (keep), preventing spurious trailing newlines in dumped
  expressions.
- `octorules dump`: strings containing single quotes (e.g. CSP values with
  `'self'`, `'unsafe-inline'`) now use YAML double-quoted style instead of
  single-quoted style with `''` escapes.
- Wirefilter parsing: filter expressions now always use the default scheme
  (where `http.request.uri.path` is a field). Previously, transform phases
  (`url_rewrite_rules`, `request_header_rules`, `response_header_rules`) used
  a transform scheme where `http.request.uri.path` was registered as a function,
  causing spurious parse errors on common expressions like
  `starts_with(http.request.uri.path, "/api")`.
- Wirefilter parsing: standalone `true`/`false` expressions (including
  parenthesized forms like `(true)`) are now handled directly instead of
  being sent to wirefilter, which rejects them as unknown identifiers.
- Wirefilter parse error logging: expected failures on action_parameters
  value expressions (e.g. `regex_replace(...)`) are logged at DEBUG instead
  of WARNING. Unexpected failures on filter expressions remain WARNING.
  Removed the now-unnecessary A001 suppressions for `starts_with`/`ends_with`
  and `true`/`false`.

## [0.12.0] - 2026-03-05

### Added
- Schema sync script (`scripts/sync_schemas.py`): regenerates generated blocks
  in `fields.py` and `functions.py` from wirefilter's `get_schema_info()` FFI
  function, merged with Python-only metadata from `overlay.toml`. Supports
  `--check` flag for CI validation.
- `overlay.toml`: Python-only metadata (`requires_plan`, `is_response`,
  `restricted_phases`) not present in the Rust wirefilter side.
- Generated markers in `functions.py` (`BEGIN/END GENERATED FUNCTIONS`).
- `octorules lint` now logs which expression parser is active at startup
  (`wirefilter` or `regex fallback`), so users can confirm at a glance.
- Per-expression wirefilter parse errors now emit a log before falling back
  to regex extraction.

### Fixed
- `_clean_list_item` in `dumper.py` now guards against non-dict items instead
  of raising `AttributeError`.

### Changed
- `dumper.py`: YAML width magic number `2147483647` extracted to
  `_YAML_NO_WRAP_WIDTH` module-level constant.

## [0.11.0] - 2026-03-05

### Added
- **Linter** (`octorules lint`): offline static analysis with 105 rules across
  17 categories (A, B, C, D, E, F, G, H, I, J, K, L, M, N, O, P, S). 4-stage
  pipeline, text/JSON/SARIF output, `--plan` tier awareness, `--exit-code` for
  CI. See the [octorules-cloudflare lint rule reference](https://github.com/doctena-org/octorules-cloudflare/blob/main/docs/lint/README.md) for Cloudflare-specific rules.
- **Inline suppression** (`# octorules:disable=RULE`): shellcheck-style
  comments to suppress specific lint rules per-rule or per-file.
- **Page Shield policy linting** (Category S): S001–S004 for structure,
  actions, types, and duplicate detection.
- **Wirefilter FFI** ([octorules-wirefilter](https://github.com/doctena-org/octorules-wirefilter)):
  optional Rust bindings for Cloudflare's wirefilter parser with phase-aware
  schemes. Falls back to regex extraction when unavailable.
- **Scheme generator** (`scripts/generate_fields.py`): auto-generates field
  registrations from the Cloudflare docs YAML (170 fields).
- Lint engine now validates `custom_rulesets` rules (expressions and actions)
  using the `waf_custom_rules` phase schema.

### Fixed
- Path traversal check in `_write_output_file` now inspects the raw path
  before `resolve()`, preventing `..` from being silently normalized away.
- Path traversal check in `config.py` similarly checks raw path before resolve.
- Deduplicated `_is_suppressed()` in lint engine — now reuses
  `suppressions.is_suppressed()` instead of maintaining an identical copy.
- Dead action validation: `network_ddos_rules` and `network_firewall_rules`
  action schemas now use friendly phase names (was using CF identifiers
  `ddos_l4`, `ddos_l7`, `magic_transit` which never matched).
- Token field in config dataclass now uses `repr=False` to prevent accidental
  leakage in logs/tracebacks.

### Changed
- Centralized `KNOWN_NON_PHASE_KEYS` and `RENAMED_PHASES` constants in
  `phases.py` — removed duplicate definitions from planner and ensured all
  linter modules import from the canonical source.
- Centralized `ALWAYS_TRUE_EXPRESSIONS` and `ALWAYS_FALSE_EXPRESSIONS` in
  `linter/engine.py`.
- Moved `_VALID_HEADER_OPERATIONS` to module level in `action_validator.py`
  (was re-created on every call).

## [0.10.1] - 2026-02-19

### Changed
- Plan output diffs use standard diff convention (`-`/`+` prefixes) across
  all formats (text, HTML, markdown) instead of inline `old → new`,
  `<ins>`/`<del>`, or `~~strikethrough~~` formatting.
- Markdown MODIFY diffs now render as fenced `` ```diff `` code blocks after
  the table instead of inline markup in table cells.
- List dump externalization: `!include` is now at the list entry level instead
  of the `items` field. External files contain the full list definition (name,
  kind, description, items) instead of just items.
- Development status classifier updated from Alpha to Beta.

### Added
- This changelog.
- Tests for `_write_output_file` path traversal guard.
- Markdown MODIFY test coverage for lists, custom rulesets, and page shield.

## [0.10.0] - 2026-02-19

### Added
- **Custom rulesets**: full lifecycle management for account-level WAF custom
  rulesets (two-tier deploy-rules + child-rulesets model).
- **Lists**: IP, ASN, hostname, and redirect list management with bulk
  operations and async polling.
- **Page Shield policies**: create, update, and delete CSP policies.
- Parallel apply stages (lists, page shield, custom rulesets, phases).
- Connection pool scaling based on worker count and phase count.
- Pagination retry with exponential backoff for list item fetching.
- `--scope` flag (`all`/`zones`/`account`) for all CLI commands.
- `report` command for drift reporting (CSV and JSON output).
- `validate` command extended with `--output` flag and list/page shield
  validation.

## [0.9.1] - 2026-02-18

### Fixed
- CLI global flags (`--config`, `--zone`, etc.) now work after the subcommand.
- Automatically narrow scope to zones-only when `--zone` is specified.
- Handle Cloudflare 400 "unknown phase" errors gracefully (e.g. SBFM on
  zones without the entitlement).

## [0.9.0] - 2026-02-18

### Added
- Zone-level WAF support: `zone_level`/`account_level` dual flags on Phase.
- `bot_fight_rules` and `sensitive_data_detection` phases.
- Scope-aware phase filtering to eliminate wasted API calls.
- Plan output diff highlighting (HTML and Markdown).

### Changed
- Renamed `waf_managed_exceptions` to `waf_managed_rules` (backward-compatible
  alias preserved).

## [0.8.1] - 2026-02-18

### Fixed
- Path traversal guards at file open sites (`_yaml_load`, `_write_output_file`).

## [0.8.0] - 2026-02-18

### Added
- Rule details shown in plan output for Create/Delete (HTML, Markdown, Text).
- HTML: single row with `<br/>`-joined details (matches octodns style).

### Changed
- Upgraded path traversal checks to use `Path.relative_to()` consistently.

## [0.7.0] - 2026-02-18

### Added
- Parallel phase fetching with `ThreadPoolExecutor` (up to 4 workers per
  scope).
- Account-level phase filtering (skip unsupported phases).
- Parallel zone ID resolution.
- Concurrent account + zone planning.

### Changed
- Default `max_workers` raised from 1 to 4.
- Dependency version ranges tightened.
- GitHub Actions pinned to commit SHAs.

### Fixed
- Unsafe `yaml.load` replaced with `SafeLoader`.
- Path traversal protection for `!include`, zone rules, and dump output.

## [0.6.0] - 2026-02-17

### Changed
- Match octodns `PlanHtml` output style: full operation names, old/new on
  separate rows, summary row inside the table, `str()` instead of `repr()`,
  "Operation" column header.

## [0.5.0] - 2026-02-17

### Changed
- All plan output formats (text, markdown, HTML, JSON) skip unchanged zones.
- `PlanHtml` converted from full HTML document to embeddable fragment.

## [0.4.1] - 2026-02-17

### Fixed
- YAML block style for expressions with trailing whitespace (PyYAML rejects
  literal block style when lines have trailing spaces).

## [0.4.0] - 2026-02-17

### Added
- `--zone` supports multiple values (`--zone a.com --zone b.com`).
- `plan` returns exit 0 by default; `--exit-code` flag for CI (exit 2 on
  changes).
- Dumped YAML files start with `---` header.
- Disable PyYAML line wrapping for expressions.

### Changed
- Log messages show `zone=domain.tld (ID=zone_id)` consistently.

## [0.3.1] - 2026-02-17

### Changed
- Improved YAML dump readability: `ref` and `description` first, literal
  block style for multiline expressions.

## [0.3.0] - 2026-02-17

### Added
- Initial release: Cloudflare Rules as IaC with plan, sync, dump, and
  validate commands.
