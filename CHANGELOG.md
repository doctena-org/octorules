# Changelog

All notable changes to this project will be documented in this file.

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
