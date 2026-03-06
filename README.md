# octorules

## Cloudflare Rules as code - Manage rules across zones declaratively

In the vein of [infrastructure as code](https://en.wikipedia.org/wiki/Infrastructure_as_Code), octorules provides tools & patterns to manage Cloudflare Rules (Redirect Rules, Cache Rules, Origin Rules, WAF Custom Rules, WAF Managed Rules, Rate Limiting, Bot Fight Mode, Sensitive Data Detection, Page Shield policies, HTTP DDoS overrides, Bulk Redirects, Logpush Custom Fields, Network DDoS, Magic Firewall, URL Normalization, and more) as YAML files. The resulting config can live in a repository and be deployed just like the rest of your code, maintaining a clear history and using your existing review & workflow.

[octodns](https://github.com/octodns/octodns) manages DNS records, but can't touch Cloudflare's newer Rules products. **octorules** fills that gap — one YAML file per domain, plan-before-apply, fail-fast on errors.

## Getting started

### Installation

```bash
pip install octorules[wirefilter]    # strongly recommended
```

The `wirefilter` extra installs [octorules-wirefilter](https://github.com/doctena-org/octorules-wirefilter),
a Rust-based FFI bridge to Cloudflare's actual wirefilter engine. This enables
authoritative expression parsing and unlocks the full linter rule set. Without
it, a regex-based fallback parser is used (fewer lint rules, no type checking).

Prebuilt wheels are available for Linux (x86_64, aarch64), macOS (x86_64, ARM64),
and Windows (x86_64). If wheels are not available for your platform, you can
install without it:

```bash
pip install octorules    # regex-based expression parser only
```

### Configuration

Create a config file pointing at your zones:

```yaml
# config.yaml
providers:
  cloudflare:
    token: env/CLOUDFLARE_API_TOKEN
  rules:
    directory: ./rules

zones:
  example.com:
    sources:
      - rules
```

The `env/` prefix resolves values from environment variables at runtime — keep secrets out of YAML.

YAML files support `!include` directives to split large configs:

```yaml
zones:
  example.com: !include zones/example.yaml
```

```yaml
# rules/example.com.yaml
redirect_rules: !include shared/redirects.yaml
```

Includes resolve relative to the file containing the directive. Nested includes and circular include detection are supported. Includes are confined to the directory tree of the parent file.

### Defining rules

Create a rules file for each zone:

```yaml
# rules/example.com.yaml
redirect_rules:
  - ref: blog-redirect
    description: "Redirect /blog to blog subdomain"
    expression: 'starts_with(http.request.uri.path, "/blog/")'
    action_parameters:
      from_value:
        target_url:
          expression: 'concat("https://blog.example.com", http.request.uri.path)'
        status_code: 301

cache_rules:
  - ref: cache-static-assets
    description: "Cache static assets for 24h"
    expression: 'http.request.uri.path.extension in {"jpg" "png" "css" "js"}'
    action_parameters:
      cache: true
      edge_ttl:
        mode: override_origin
        default: 86400
```

Each rule requires a **`ref`** (stable identifier, unique within a phase) and an **`expression`** ([Cloudflare ruleset expression](https://developers.cloudflare.com/ruleset-engine/rules-language/expressions/)). Optional fields include `description`, `enabled` (defaults to `true`), `action`, and `action_parameters`.

#### Multi-line expressions

Complex expressions can use YAML block scalars (`|-`) for readability. octorules normalizes whitespace (collapsing newlines and indentation to single spaces outside quoted strings) before sending to Cloudflare and before linting, so formatting is purely cosmetic:

```yaml
waf_custom_rules:
  - ref: geo-block
    description: Block by country outside active regions
    action: block
    expression: |-
      (ip.geoip.asnum in {
        9009
        64080
      } and not ip.geoip.country in {
        "AT"
        "BE"
        "DE"
        "FR"
      })
```

This is equivalent to the single-line form `(ip.geoip.asnum in {9009 64080} and not ip.geoip.country in {"AT" "BE" "DE" "FR"})`. Use `|-` (strip trailing newline) rather than `|` (preserves trailing newline).

### Usage

```bash
# Preview changes (dry-run)
octorules plan --config config.yaml

# Apply changes
octorules sync --doit --config config.yaml

# Validate offline (no API calls, useful in CI)
octorules validate --config config.yaml

# Export existing rules to YAML
octorules dump --config config.yaml

# Lint rules files offline (105 rules, text/JSON/SARIF output)
octorules lint --config config.yaml
```

## Supported phases

octorules supports **23 Cloudflare phases** — 18 HTTP request/response phases and 5 network-level (Magic Transit) phases. Phases execute in a fixed order: URL normalization and redirects first, then transforms, then WAF/rate limiting, then origin fetch, then response-side phases.

```
Request  ─▸ url_normalization ─▸ redirect_rules ─▸ url_rewrite_rules ─▸ request_header_rules
         ─▸ origin_rules ─▸ config_rules ─▸ cache_rules
         ─▸ waf_custom_rules ─▸ waf_managed_rules ─▸ rate_limiting_rules
         ─▸ bot_fight_rules ─▸ http_ddos_rules
         ─▸▸ Origin fetch ◂◂─
         ─▸ custom_error_rules ─▸ response_header_rules ─▸ compression_rules
         ─▸ sensitive_data_detection ─▸ log_custom_fields ─▸ Response
```

Phases with a default action (e.g., `redirect_rules` → `redirect`) don't need `action` in the YAML — it's injected automatically. For phases without a default (e.g., `waf_custom_rules`), you must specify `action` explicitly.

Phases marked as both Zone and Account work at either scope. Account-only phases are skipped for zone scopes and vice versa, eliminating wasted API calls.

For the full phase reference — execution order diagram, valid actions per phase, field/function availability, and key behaviors — see [docs/lint-rules/README.md § Cloudflare Phases Reference](docs/lint-rules/README.md#cloudflare-phases-reference).

> **Note:** `waf_managed_exceptions` was renamed to `waf_managed_rules`. The old name still works as an alias but is deprecated — update your YAML files to use the new name.

## Custom rulesets (account-level)

At the account level, WAF custom rules and rate limiting rules use a two-tier structure: the phase entrypoint contains **deploy rules** (`action: execute`) that reference child **custom rulesets** by ID. The individual blocking/logging rules live inside those child rulesets.

octorules manages both tiers. Deploy rules are managed via the normal phase sections (`waf_custom_rules`, `rate_limiting_rules`). The individual rules inside each custom ruleset are managed via a separate `custom_rulesets` section:

```yaml
# Account rules file (e.g. rules/my-account.yaml)

# Deploy rules (phase entrypoint — references child rulesets by ID)
waf_custom_rules:
  - ref: deploy-known-attackers
    description: Deploy known attackers ruleset
    action: execute
    action_parameters:
      id: abc12345def67890abc12345def67890
      version: latest
    enabled: true
    expression: (http.host eq "api.example.com")

# Individual rules inside each custom ruleset
custom_rulesets:
  - id: abc12345def67890abc12345def67890
    name: Known attackers
    phase: http_request_firewall_custom
    rules:
      - ref: block-bad-asn
        description: Block by AS number
        action: block
        expression: (ip.geoip.asnum in {12345 67890})
      - ref: block-bad-ua
        description: Block by user-agent
        action: block
        expression: (http.user_agent contains "BadBot")
```

The `id` field in each `custom_rulesets` entry links it to the deploy rule's `action_parameters.id`. Rules inside use `ref` for identification (same pattern as phase rules). Every rule must specify an `action` explicitly.

Use `octorules dump --scope account` to export existing custom rulesets to YAML. The dump automatically discovers all `kind=custom` rulesets in your account and includes their individual rules.

> **Note:** octorules manages rules *within* existing custom rulesets. Creating or deleting rulesets themselves must be done via the Cloudflare dashboard. Zone-level rulesets do not have `kind=custom` children — this is account-level only.

## Lists (account-level)

Cloudflare account-level [Lists](https://developers.cloudflare.com/waf/tools/lists/) (IP lists, ASN lists, hostname lists, redirect lists) can be referenced in rule expressions via `$list_name` syntax. octorules manages full lifecycle of lists declaratively: create, delete, update metadata, and manage items.

Add a top-level `lists` key to your account rules file:

```yaml
# rules/my-account.yaml
lists:
  - name: blocked_ips
    kind: ip
    description: "Known bad IPs"
    items:
      - ip: "1.2.3.4"
        comment: "Scanner"
      - ip: "5.6.7.0/24"
        comment: "Botnet range"

  - name: partner_asns
    kind: asn
    description: "Partner AS numbers"
    items:
      - asn: 12345
        comment: "Partner A"
      - asn: 67890
        comment: "Partner B"
```

Each list entry requires:

| Field | Description |
|-------|-------------|
| `name` | List name — matches CF list name and `$list_name` in expressions |
| `kind` | One of `ip`, `asn`, `hostname`, `redirect` |
| `description` | Optional — updated if changed |
| `items` | List of items (can be empty `[]` to clear all items) |

**How it works:**

- The presence of a `lists:` key means ALL lists are managed — lists in Cloudflare not in YAML are planned for deletion (subject to safety thresholds).
- If the `lists:` key is absent, lists are ignored entirely.
- Item updates are asynchronous — octorules polls the bulk operation until completion.
- During sync, lists are applied **before** rulesets and phases, so newly created lists are available for rule expressions that reference them.
- Use `octorules dump --scope account` to export existing lists to YAML. The dump externalizes list items into separate files (referenced via `!include` tags) under `providers.lists.directory` (default: `{rules_dir}/custom_lists`). This directory must be within the rules directory.

Reference lists in rule expressions:

```yaml
waf_custom_rules:
  - ref: block-bad-ips
    description: Block IPs from blocklist
    action: block
    expression: (ip.src in $blocked_ips)
```

## Page Shield policies (zone-level)

Cloudflare [Page Shield](https://developers.cloudflare.com/page-shield/) manages Content Security Policies (CSP) at the zone level. octorules manages full lifecycle of Page Shield policies declaratively: create, update, and delete.

Add a top-level `page_shield_policies` key to your zone rules file:

```yaml
# rules/example.com.yaml
page_shield_policies:
  - description: "CSP on all example.com"
    action: allow
    expression: "true"
    enabled: true
    value: >-
      script-src 'self' 'unsafe-inline' 'unsafe-eval' https:;
      worker-src 'self' blob:

  - description: "Log CSP on staging"
    action: log
    expression: '(http.host eq "staging.example.com")'
    enabled: true
    value: "default-src 'self'"
```

Each policy entry requires:

| Field | Description |
|-------|-------------|
| `description` | Policy description — used as the identity key for matching |
| `action` | `allow` or `log` |
| `expression` | Cloudflare filter expression |
| `enabled` | Boolean |
| `value` | CSP directive string |

**How it works:**

- The `description` field is the identity key (like `ref` for rules and `name` for lists). Policies are matched between YAML and Cloudflare by description.
- The presence of a `page_shield_policies:` key means ALL policies are managed — policies in Cloudflare not in YAML are planned for deletion.
- If the `page_shield_policies:` key is absent, policies are ignored entirely.
- During sync, policies are applied **after** lists and **before** custom rulesets and phases.
- Use `octorules dump` to export existing Page Shield policies to YAML.

## Linting

`octorules lint` runs offline static analysis on your rules files — no API calls, no credentials needed. It catches structural errors, invalid actions, expression mistakes, plan-tier violations, and cross-rule issues before you push to Cloudflare.

```bash
# Lint all zones (text output)
octorules lint

# JSON output, only errors and warnings
octorules lint --format json --severity warning

# SARIF for GitHub Code Scanning
octorules lint --format sarif --output results.sarif

# Check against Free plan limits
octorules lint --plan free

# CI mode: exit 1 on errors, 2 on warnings
octorules lint --exit-code
```

### Pipeline

The linter runs 4 stages in order:

| Stage | What it checks | Rule categories |
|-------|---------------|-----------------|
| 1. YAML structure | Required fields, types, duplicates, unknown keys | M (15 rules) |
| 2. Per-rule checks | Actions, expressions, phase restrictions | A, C, D, I, J, K, L, N, B, E, F, G, O (79 rules) |
| 2b. Page Shield policies | Policy structure, expressions, catch-all detection | S (4 rules) |
| 3. Plan-tier limits | Regex availability, rule count limits | H (3 rules) |
| 4. Cross-rule analysis | Duplicate expressions, unreachable rules, list references | P (4 rules) |

### Rule categories

| Prefix | Category | Rules |
|--------|----------|-------|
| A | Parse / syntax errors | 1 |
| M | Structure | 15 |
| C | Action validation | 14 |
| D | Rate limiting | 6 |
| I | Cache rules | 4 |
| J | Config rules | 4 |
| K | Redirect rules | 2 |
| L | Transform rules | 5 |
| N | Origin rules | 1 |
| B | Phase restrictions | 3 |
| E | Function constraints | 6 |
| F | Type system | 2 |
| G | Value constraints | 25 |
| H | Plan/entitlement | 3 |
| S | Page Shield structure | 4 |
| O | Best practice / style | 6 |
| P | Cross-rule | 4 |

**105 rules total.** See [docs/lint-rules/README.md](docs/lint-rules/README.md) for the full reference (index with quick-reference table + per-stage detail files).

### Suppressing lint rules

Add a YAML comment to suppress specific rules (like shellcheck):

```yaml
  # octorules:disable=M013
  - ref: add-security-headers
    expression: (true)
```

See [docs/lint-rules/README.md](docs/lint-rules/README.md#suppressing-rules) for file-level suppression and multi-rule syntax.

### Expression parsing

When the `wirefilter` extra is installed (see [Installation](#installation)), expressions are parsed by Cloudflare's actual wirefilter engine via [octorules-wirefilter](https://github.com/doctena-org/octorules-wirefilter), providing authoritative type checking, field validation, and syntax verification. Without it, a regex-based fallback parser extracts fields, functions, operators, and literals but cannot perform type checking.

The linter logs which parser is active at startup (`Expression parser: wirefilter` or `Expression parser: regex fallback`). If wirefilter rejects a specific expression, it falls back to regex for that expression with a warning. Standalone `true`/`false` expressions and value expressions in `action_parameters` (e.g. `regex_replace(...)`) are handled separately since wirefilter only parses boolean filter expressions.

## CLI reference

### `octorules plan`

Dry-run: shows what would change without touching Cloudflare. Exit code 2 when changes are detected. Output format and destination are controlled via `manager.plan_outputs` in the config file (defaults to text on stdout).

```bash
octorules plan [--zone example.com] [--phase redirect_rules] [--checksum]
```

### `octorules sync --doit`

Applies changes to Cloudflare. Requires `--doit` as a safety flag. Atomic PUT per phase, fail-fast on errors.

```bash
octorules sync --doit [--zone example.com] [--phase redirect_rules] [--checksum HASH] [--force]
```

### `octorules compare`

Compare local rules against live Cloudflare state. Exit code 1 when differences exist.

```bash
octorules compare [--zone example.com] [--checksum]
```

### `octorules report`

Drift report showing deployed vs YAML source of truth.

```bash
octorules report [--zone example.com] [--output-format csv|json]
```

### `octorules validate`

Validates config and rules files offline (no API calls). Useful in CI to catch errors early.

```bash
octorules validate [--zone example.com] [--phase redirect_rules]
```

### `octorules dump`

Exports existing Cloudflare rules to YAML files. Useful for bootstrapping or importing an existing setup.

```bash
octorules dump [--zone example.com] [--output-dir ./rules]
```

### `octorules lint`

Lint rules files offline for errors, warnings, and style issues. Supports text, JSON, and SARIF output.

```bash
octorules lint [--format text|json|sarif] [--severity error|warning|info] [--plan free|pro|business|enterprise] [--rule RULE_ID] [--output PATH] [--exit-code]
```

| Flag | Description |
|------|-------------|
| `--format` | Output format: `text` (default), `json`, `sarif` |
| `--severity` | Minimum severity to report (default: `info`) |
| `--plan` | Cloudflare plan tier for entitlement checks (default: auto-detect from API) |
| `--rule` | Only check specific rule ID(s); can be repeated |
| `--output` | Write results to a file instead of stdout |
| `--exit-code` | Exit with 1 on errors, 2 on warnings (for CI) |

### Common flags

| Flag | Description |
|------|-------------|
| `--config PATH` | Path to config file (default: `config.yaml`) |
| `--zone NAME` | Process a single zone (default: all) |
| `--phase NAME` | Limit to specific phase(s); can be repeated |
| `--debug` | Enable debug logging |
| `--quiet` | Only show errors |

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success / no changes |
| 1 | Error (or lint errors found with `--exit-code`) |
| 2 | Changes detected (`plan`) / lint warnings found (`lint --exit-code`) |

## Config reference

```yaml
providers:
  cloudflare:
    token: env/CLOUDFLARE_API_TOKEN  # env/ prefix reads from environment
    max_retries: 2                   # API retry count (default: 2)
    timeout: 30                      # API timeout in seconds (optional)
    safety:
      delete_threshold: 30.0        # Max % of rules that can be deleted (default: 30)
      update_threshold: 30.0        # Max % of rules that can be updated (default: 30)
      min_existing: 3               # Min rules before thresholds apply (default: 3)
  rules:
    directory: ./rules               # Path to rules directory
  lists:
    directory: ./rules/custom_lists  # Path for externalized list items (default: {rules_dir}/custom_lists)

manager:
  max_workers: 4                     # Parallel processing (default: 1)
  plan_outputs:                      # Config-driven plan output (replaces --format/--output)
    text:
      class: octorules.plan_output.PlanText
    html:
      class: octorules.plan_output.PlanHtml
      path: /tmp/plan.html           # Optional: write to file instead of stdout

zones:
  example.com:
    sources:
      - rules
    allow_unmanaged: false           # Keep rules not in YAML (default: false)
    always_dry_run: true             # Never apply changes (default: false)
    safety:                          # Per-zone overrides
      delete_threshold: 50.0
```

## How it works

1. **Plan** — Reads your YAML rules, fetches current rules from Cloudflare, computes a diff by matching rules on `ref` (phases), `name` (lists), or `description` (Page Shield policies).
2. **Sync** — Executes the plan in order: lists, Page Shield policies, custom rulesets, then phases. Each phase uses an atomic PUT (full replacement of the phase ruleset). Fail-fast on errors.
3. **Dump** — Fetches all rules from Cloudflare and writes them to YAML files, stripping API-only fields (`id`, `version`, `last_updated`, etc.). For account scopes, also fetches individual rules inside custom rulesets and lists with their items. For zone scopes, also fetches Page Shield policies.

Performance (all parallelism controlled via `manager.max_workers`, default: 1):
- **Parallel phase fetching** — phases within each scope are fetched concurrently.
- **Parallel phase apply** — phase PUTs within a zone are applied concurrently during sync.
- **Parallel apply stages** — list item updates, custom ruleset PUTs, and Page Shield policy operations within each stage run concurrently.
- **Parallel zone processing** — multiple zones are planned/synced concurrently.
- **Parallel zone ID resolution** — zone name lookups run concurrently.
- **Concurrent account planning** — account-level rules are planned in parallel with zone rules.
- **Scope-aware phase filtering** — only zone-level phases are fetched for zone scopes, and only account-level phases for account scopes, eliminating wasted API calls.
- **Connection pool scaling** — HTTP connection pool is sized to match `max_workers`.
- **Rules caching** — YAML rule files are parsed once and cached for the duration of each run.

Safety features:
- **`--doit` flag** — sync requires explicit confirmation.
- **Delete thresholds** — blocks mass deletions above a configurable percentage.
- **Checksum verification** — `plan --checksum` produces a hash; `sync --checksum HASH` verifies the plan hasn't changed.
- **Auth error propagation** — authentication and permission errors fail immediately instead of being silently swallowed.
- **Failed phase filtering** — phases that can't be fetched are excluded from planning to prevent accidental mass deletions.
- **Pagination retry** — list item fetches retry transient errors per page, preserving items already fetched.
- **Path traversal protection** — `!include` directives and file operations are confined to their expected directories.

## CI/CD integration

For GitHub Actions, see [octorules-sync](https://github.com/doctena-org/octorules-sync) — a ready-made action that runs plan on PRs and sync on merge to main.


## Development

### Local setup

```bash
git clone git@github.com:doctena-org/octorules.git
cd octorules
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Running tests and linting

```bash
pytest
ruff check src/ tests/
ruff format --check src/ tests/
```

### Releasing a new version

1. Update the version in `pyproject.toml` (single source of truth).
2. Commit and push to `main`.
3. Tag the release and push the tag:

```bash
git tag v0.10.0
git push origin v0.10.0
```

Pushing a `v*` tag triggers the [publish workflow](.github/workflows/publish.yaml), which builds the package, publishes it to [PyPI](https://pypi.org/project/octorules/), and creates a GitHub Release.

## License

octorules is licensed under the [Apache License 2.0](LICENSE).
