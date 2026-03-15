# Changelog

All notable changes to this project will be documented in this file.

## [0.16.0] - 2026-03-15

### Changed
- **BREAKING: Provider split.** The Cloudflare SDK (`cloudflare~=4.3`) is no
  longer a direct dependency.  Install `octorules[cloudflare]` (which pulls in
  [octorules-cloudflare](https://github.com/doctena-org/octorules-cloudflare))
  to use Cloudflare. `import octorules` works without any provider installed.
- **Flat layout.** Package moved from `src/octorules/` to `octorules/` at the
  repo root, matching the octodns convention.
- `commands.py` and `cli.py` now catch provider-agnostic `ProviderAuthError`
  and `ProviderError` instead of Cloudflare SDK exceptions.
- `_init_provider()` uses the module-level `CloudflareProvider` (re-exported
  from octorules-cloudflare when installed) or reads `providers.cloudflare.class`
  from config for dynamic provider loading.

### Added
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
  (`ALL_CF_PHASES`, `PHASE_BY_NAME`, etc.) are mutated in-place.
- `Config.provider_class` field — optional `class:` key under
  `providers.cloudflare` for dynamic provider loading.
- `[project.optional-dependencies] cloudflare` extra pointing to
  `octorules-cloudflare>=0.1`.

### Removed
- `CloudflareProvider` class, all CF SDK helpers, and CF SDK exception
  re-exports moved to
  [octorules-cloudflare](https://github.com/doctena-org/octorules-cloudflare).
- Provider-specific tests (`test_provider.py`, `test_provider_lists.py`,
  `test_provider_custom_rulesets.py`, `test_provider_page_shield.py`,
  `tests/mocks.py`) moved to octorules-cloudflare.

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
  CI. See [docs/lint-rules/](docs/lint-rules/README.md) for full rule reference.
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

## [0.10.0] - 2025-04-28

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

## [0.9.1] - 2025-03-15

### Fixed
- CLI global flags (`--config`, `--zone`, etc.) now work after the subcommand.
- Automatically narrow scope to zones-only when `--zone` is specified.
- Handle Cloudflare 400 "unknown phase" errors gracefully (e.g. SBFM on
  zones without the entitlement).

## [0.9.0] - 2025-03-10

### Added
- Zone-level WAF support: `zone_level`/`account_level` dual flags on Phase.
- `bot_fight_rules` and `sensitive_data_detection` phases.
- Scope-aware phase filtering to eliminate wasted API calls.
- Plan output diff highlighting (HTML and Markdown).

### Changed
- Renamed `waf_managed_exceptions` to `waf_managed_rules` (backward-compatible
  alias preserved).

## [0.8.1] - 2025-02-20

### Fixed
- Path traversal guards at file open sites (`_yaml_load`, `_write_output_file`).

## [0.8.0] - 2025-02-15

### Added
- Rule details shown in plan output for Create/Delete (HTML, Markdown, Text).
- HTML: single row with `<br/>`-joined details (matches octodns style).

### Changed
- Upgraded path traversal checks to use `Path.relative_to()` consistently.

## [0.7.0] - 2025-01-25

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

## [0.6.0] - 2025-01-10

### Changed
- Match octodns `PlanHtml` output style: full operation names, old/new on
  separate rows, summary row inside the table, `str()` instead of `repr()`,
  "Operation" column header.

## [0.5.0] - 2024-12-20

### Changed
- All plan output formats (text, markdown, HTML, JSON) skip unchanged zones.
- `PlanHtml` converted from full HTML document to embeddable fragment.

## [0.4.1] - 2024-12-10

### Fixed
- YAML block style for expressions with trailing whitespace (PyYAML rejects
  literal block style when lines have trailing spaces).

## [0.4.0] - 2024-12-05

### Added
- `--zone` supports multiple values (`--zone a.com --zone b.com`).
- `plan` returns exit 0 by default; `--exit-code` flag for CI (exit 2 on
  changes).
- Dumped YAML files start with `---` header.
- Disable PyYAML line wrapping for expressions.

### Changed
- Log messages show `zone=domain.tld (ID=zone_id)` consistently.

## [0.3.0] - 2024-11-20

### Changed
- Improved YAML dump readability: `ref` and `description` first, literal
  block style for multiline expressions.

## [0.1.0] - 2024-11-01

### Added
- Initial release: Cloudflare Rules as IaC with plan, sync, dump, and
  validate commands.
