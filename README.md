# octorules

## Cloudflare Rules as code - Manage rules across zones declaratively

In the vein of [infrastructure as code](https://en.wikipedia.org/wiki/Infrastructure_as_Code), octorules provides tools & patterns to manage Cloudflare Rules (Redirect Rules, Cache Rules, Origin Rules, WAF Custom Rules, Rate Limiting, and more) as YAML files. The resulting config can live in a repository and be deployed just like the rest of your code, maintaining a clear history and using your existing review & workflow.

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

| YAML Key | Cloudflare Phase | Default Action |
|---|---|---|
| `redirect_rules` | `http_request_dynamic_redirect` | `redirect` |
| `url_rewrite_rules` | `http_request_transform` | `rewrite` |
| `request_header_rules` | `http_request_late_transform` | `rewrite` |
| `response_header_rules` | `http_response_headers_transform` | `rewrite` |
| `config_rules` | `http_config_settings` | `set_config` |
| `origin_rules` | `http_request_origin` | `route` |
| `cache_rules` | `http_request_cache_settings` | `set_cache_settings` |
| `compression_rules` | `http_response_compression` | `compress_response` |
| `custom_error_rules` | `http_custom_errors` | `serve_error` |
| `waf_custom_rules` | `http_request_firewall_custom` | *(must specify)* |
| `waf_managed_exceptions` | `http_request_firewall_managed` | *(must specify)* |
| `rate_limiting_rules` | `http_ratelimit` | *(must specify)* |

Phases with a default action don't need `action` in the YAML — it's injected automatically. For `waf_custom_rules`, `waf_managed_exceptions`, and `rate_limiting_rules`, you must specify `action` explicitly (e.g., `block`, `challenge`, `log`).

Only `custom_error_rules`, `waf_custom_rules`, `waf_managed_exceptions`, and `rate_limiting_rules` are supported at account level — zone-only phases are automatically skipped for account scopes.

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

manager:
  max_workers: 4                     # Parallel zone processing (default: 4)
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

1. **Plan** — Reads your YAML rules, fetches current rules from Cloudflare, computes a diff by matching rules on `ref`.
2. **Sync** — Executes the plan by doing an atomic PUT per phase (full replacement of the phase ruleset). Fail-fast on errors.
3. **Dump** — Fetches all rules from Cloudflare and writes them to YAML files, stripping API-only fields (`id`, `version`, `last_updated`, etc.).

Performance:
- **Parallel phase fetching** — phases within each scope are fetched concurrently (up to 4 workers).
- **Parallel zone processing** — multiple zones are planned/synced concurrently (configurable via `max_workers`, default: 4).
- **Parallel zone ID resolution** — zone name lookups run concurrently.
- **Concurrent account planning** — account-level rules are planned in parallel with zone rules.
- **Account phase filtering** — only account-compatible phases are fetched for account scopes, eliminating wasted API calls.

Safety features:
- **`--doit` flag** — sync requires explicit confirmation.
- **Delete thresholds** — blocks mass deletions above a configurable percentage.
- **Checksum verification** — `plan --checksum` produces a hash; `sync --checksum HASH` verifies the plan hasn't changed.
- **Auth error propagation** — authentication and permission errors fail immediately instead of being silently swallowed.
- **Failed phase filtering** — phases that can't be fetched are excluded from planning to prevent accidental mass deletions.
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
git tag v0.7.0
git push origin v0.7.0
```

Pushing a `v*` tag triggers the [publish workflow](.github/workflows/publish.yaml), which builds the package, publishes it to [PyPI](https://pypi.org/project/octorules/), and creates a GitHub Release.

## License

octorules is licensed under the [Apache License 2.0](LICENSE).
