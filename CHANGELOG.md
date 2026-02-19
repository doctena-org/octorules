# Changelog

All notable changes to this project will be documented in this file.

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
