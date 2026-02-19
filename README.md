# octorules

## Cloudflare Rules as code - Manage rules across zones declaratively

In the vein of [infrastructure as code](https://en.wikipedia.org/wiki/Infrastructure_as_Code), octorules provides tools & patterns to manage Cloudflare Rules (Redirect Rules, Cache Rules, Origin Rules, WAF Custom Rules, WAF Managed Rules, Rate Limiting, Bot Fight Mode, Sensitive Data Detection, Page Shield policies, HTTP DDoS overrides, Bulk Redirects, Logpush Custom Fields, Network DDoS, Magic Firewall, URL Normalization, and more) as YAML files. The resulting config can live in a repository and be deployed just like the rest of your code, maintaining a clear history and using your existing review & workflow.

[octodns](https://github.com/octodns/octodns) manages DNS records, but can't touch Cloudflare's newer Rules products. **octorules** fills that gap — one YAML file per domain, plan-before-apply, fail-fast on errors.

## Getting started

### Installation

```bash
pip install octorules
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
```

## Supported phases

| YAML Key | Cloudflare Phase | Default Action | Zone | Account |
|---|---|---|---|---|
| `redirect_rules` | `http_request_dynamic_redirect` | `redirect` | Yes | — |
| `url_rewrite_rules` | `http_request_transform` | `rewrite` | Yes | — |
| `request_header_rules` | `http_request_late_transform` | `rewrite` | Yes | — |
| `response_header_rules` | `http_response_headers_transform` | `rewrite` | Yes | — |
| `config_rules` | `http_config_settings` | `set_config` | Yes | — |
| `origin_rules` | `http_request_origin` | `route` | Yes | — |
| `cache_rules` | `http_request_cache_settings` | `set_cache_settings` | Yes | — |
| `compression_rules` | `http_response_compression` | `compress_response` | Yes | — |
| `custom_error_rules` | `http_custom_errors` | `serve_error` | Yes | Yes |
| `waf_custom_rules` | `http_request_firewall_custom` | *(must specify)* | Yes | Yes |
| `waf_managed_rules` | `http_request_firewall_managed` | *(must specify)* | Yes | Yes |
| `rate_limiting_rules` | `http_ratelimit` | *(must specify)* | Yes | Yes |
| `bot_fight_rules` | `http_request_sbfm` | *(must specify)* | Yes | — |
| `sensitive_data_detection` | `http_response_firewall_managed` | *(must specify)* | Yes | — |
| `http_ddos_rules` | `ddos_l7` | *(must specify)* | Yes | Yes |
| `bulk_redirect_rules` | `http_request_redirect` | `redirect` | — | Yes |
| `log_custom_fields` | `http_log_custom_fields` | `log_custom_field` | Yes | — |
| `network_ddos_rules` | `ddos_l4` | *(must specify)* | — | Yes |
| `network_firewall_rules` | `magic_transit` | *(must specify)* | — | Yes |
| `network_firewall_managed` | `magic_transit_managed` | *(must specify)* | — | Yes |
| `network_firewall_ratelimit` | `magic_transit_ratelimit` | *(must specify)* | — | Yes |
| `network_firewall_ids` | `magic_transit_ids_managed` | *(must specify)* | — | Yes |
| `url_normalization` | `http_request_sanitize` | *(must specify)* | Yes | — |

Phases with a default action don't need `action` in the YAML — it's injected automatically. For phases without a default action, you must specify `action` explicitly (e.g., `block`, `challenge`, `log`).

Phases marked with both Zone and Account support work at either scope. Account-only phases are skipped for zone scopes, and zone-only phases are skipped for account scopes, eliminating wasted API calls.

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
| 1 | Error |
| 2 | Changes detected (`plan`) |

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

```yaml
# .github/workflows/rules.yaml
jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install octorules
      - run: octorules validate

  plan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install octorules
      - run: octorules plan --checksum

  deploy:
    if: github.ref == 'refs/heads/main'
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install octorules
      - run: octorules sync --doit
```

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
