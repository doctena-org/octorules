# octorules

## WAF rules as code — manage rules across providers declaratively

In the vein of [infrastructure as code](https://en.wikipedia.org/wiki/Infrastructure_as_Code), octorules provides tools & patterns to manage WAF and security rules as YAML files. The resulting config can live in a repository and be deployed just like the rest of your code, maintaining a clear history and using your existing review & workflow.

[octodns](https://github.com/octodns/octodns) manages DNS records, but can't touch WAF rules. **octorules** fills that gap — one YAML file per domain/policy, plan-before-apply, fail-fast on errors.

### Provider ecosystem

octorules is provider-agnostic. Each provider is a separate package:

| Package | Provider | Status |
|---|---|---|
| [octorules-cloudflare](https://github.com/doctena-org/octorules-cloudflare) | Cloudflare Rules (23 phases) | Stable |
| [octorules-aws](https://github.com/doctena-org/octorules-aws) | AWS WAF v2 (4 phases) | Beta |
| [octorules-google](https://github.com/doctena-org/octorules-google) | Google Cloud Armor (4 phases) | Beta |
| [octorules-azure](https://github.com/doctena-org/octorules-azure) | Azure WAF — Front Door & App Gateway (3 phases) | Alpha |
| [octorules-bunny](https://github.com/doctena-org/octorules-bunny) | Bunny.net Shield WAF (4 phases) | Alpha |

## Getting started

### Installation

Install the provider package for your WAF. This pulls in octorules core automatically:

```bash
pip install octorules-cloudflare    # Cloudflare (includes wirefilter expression engine)
pip install octorules-aws           # AWS WAF v2
pip install octorules-google        # Google Cloud Armor (includes cel-python)
pip install octorules-azure         # Azure WAF (Front Door / Application Gateway)
pip install octorules-bunny         # Bunny.net Shield WAF
```

Core only (offline lint, no provider):

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

The `env/` prefix resolves values from environment variables at runtime — keep secrets out of YAML. This is the built-in secret handler; see [Secret handlers](#secret-handlers) for pluggable backends (Vault, AWS Secrets Manager, etc.).

> **Complete examples** — the [`examples/`](examples/) directory contains detailed config and rules files for all five providers (Cloudflare, AWS, Google, Azure, Bunny), including multi-provider setups, every config field, and every phase/rule format. Start there rather than writing config from scratch.

All keys under a provider section (except `class` and `safety`) are forwarded as keyword arguments to the provider constructor — octodns-style passthrough. See each provider's documentation for available settings.

#### Multi-provider setup

To manage rules across multiple providers, add each provider as a named section under `providers:` and assign zones to providers via `targets:`:

```yaml
providers:
  cloudflare:
    token: env/CLOUDFLARE_API_TOKEN
  aws:
    region: us-west-2
    waf_scope: REGIONAL
  rules:
    directory: ./rules

zones:
  example.com:
    sources:
      - rules
    targets:
      - cloudflare
  my-web-acl:
    sources:
      - rules
    targets:
      - aws
```

When only one provider is configured, `targets` is auto-assigned and can be omitted.

#### Multi-target zones

A zone can target multiple providers of the **same class** (e.g. two Cloudflare accounts, or prod + staging). octorules plans and applies independently for each target:

```yaml
providers:
  cf-prod:
    class: octorules_cloudflare.CloudflareProvider
    token: env/CF_PROD_TOKEN
  cf-staging:
    class: octorules_cloudflare.CloudflareProvider
    token: env/CF_STAGING_TOKEN
  rules:
    directory: ./rules

zones:
  example.com:
    sources:
      - rules
    targets:
      - cf-prod
      - cf-staging
```

Each target produces its own plan. Safety thresholds default from the first target's provider.

#### Provider auto-discovery

Provider classes are auto-discovered via the `octorules.providers` entry-point group (installed provider packages register themselves). To override auto-discovery, set `class:` explicitly:

```yaml
providers:
  custom:
    class: my_package.MyProvider
    api_key: env/MY_API_KEY
```

#### YAML includes

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

Create a rules file for each zone. The filename must match the zone name used as the key under `zones:` in `config.yaml`, which maps to the provider's own concept of a "zone":

| Provider | Zone concept | Example zone name | Rules file |
|---|---|---|---|
| Cloudflare | DNS domain | `example.com` | `rules/example.com.yaml` |
| AWS WAF | Web ACL name | `my-web-acl` | `rules/my-web-acl.yaml` |
| Google Cloud Armor | Security policy name | `my-security-policy` | `rules/my-security-policy.yaml` |
| Azure WAF | WAF policy name | `my-waf-policy` | `rules/my-waf-policy.yaml` |
| Bunny Shield | Pull zone name | `my-pull-zone` | `rules/my-pull-zone.yaml` |

The mapping is: `zones.<name>` in `config.yaml` → `rules/<name>.yaml` on disk → `resolve_zone_id("<name>")` at runtime, which resolves the name to the provider's internal ID.

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

Each rule requires a **`ref`** (stable identifier, unique within a phase) and an **`expression`** (provider-specific filter expression). Optional fields include `description`, `enabled` (defaults to `true`), `action`, and `action_parameters`.

Phase names, available actions, and expression syntax are provider-specific — see your provider's documentation for details.

#### Rule-level metadata

Rules support an `octorules:` key for per-rule metadata that controls octorules behavior without affecting the provider API.

**Ignoring rules** — keep a rule in YAML (for documentation, version control, review) while skipping it during plan/sync:

```yaml
waf_custom_rules:
  - ref: experimental-geo-block
    description: "Testing geo-block — not ready for production"
    expression: 'ip.geoip.country in {"RU" "CN"}'
    action: block
    octorules:
      ignored: true
```

Ignored rules are still validated and linted (catch errors before un-ignoring), but are invisible to the planner on both sides — they produce no ADD/MODIFY/REMOVE changes, and if the rule exists upstream it will not be deleted or overwritten. This matches the octodns convention: the rule can be edited manually on the provider without octorules interfering.

**Targeting providers** — in multi-provider or multi-target setups, restrict a rule to specific targets:

```yaml
waf_custom_rules:
  # Only deploy to Cloudflare
  - ref: cf-specific-rule
    expression: 'http.request.uri.path matches "^/api/.*"'
    action: block
    octorules:
      included:
        - cloudflare

  # Deploy everywhere EXCEPT staging
  - ref: prod-only-rule
    expression: 'ip.src in $blocklist'
    action: block
    octorules:
      excluded:
        - cf-staging
```

`included` and `excluded` are mutually exclusive (matching octodns convention). Names match the provider config key (e.g. `cloudflare`, `aws`, `cf-prod`). Rules without `included`/`excluded` apply to all targets.

The `octorules:` key is always stripped before sending rules to the provider API.

#### Multi-line expressions

Complex expressions can use YAML block scalars (`|-`) for readability. octorules normalizes whitespace (collapsing newlines and indentation to single spaces outside quoted strings) before sending to the provider and before linting, so formatting is purely cosmetic:

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

Use `|-` (strip trailing newline) rather than `|` (preserves trailing newline).

### Usage

octorules uses separate commands for planning and applying — like Terraform's
`plan`/`apply` split.  WAF rules have a high blast radius (a bad rule can
block all traffic), so the two-step workflow forces an explicit review before
changes reach the provider.  This also enables CI patterns where `plan` runs
on PR open (posting results as a PR comment) and `sync` runs on merge with
checksum verification to catch drift.

```bash
# Preview changes (dry-run)
octorules plan --config config.yaml

# Apply changes
octorules sync --doit --config config.yaml

# Validate config only (no API calls, useful in CI)
octorules lint --config-only --config config.yaml

# Export existing rules to YAML
octorules dump --config config.yaml

# Lint rules files offline
octorules lint --config config.yaml

# Audit for IP overlaps, CDN conflicts, and zone drift
octorules audit --config config.yaml
```

## Secret handlers

Config string values use `handler/reference` syntax to resolve secrets at load time. The built-in `env` handler resolves environment variables (`env/MY_TOKEN` → `$MY_TOKEN`). You can add custom handlers for Vault, AWS Secrets Manager, GCP Secret Manager, etc.

### Config-declared handlers

```yaml
secret_handlers:
  vault:
    class: octorules_vault.VaultSecrets
    url: https://vault.internal
    token: env/VAULT_TOKEN           # bootstrap: resolved via env handler

providers:
  cloudflare:
    token: vault/secret/data/cf#token  # resolved via vault handler
```

Handler kwargs are resolved through already-registered handlers (env + entry-points), so you can bootstrap credentials with `env/`.

### Entry-point discovery

Secret handlers can also be auto-discovered via the `octorules.secret_handlers` entry-point group:

```toml
# In your handler package's pyproject.toml
[project.entry-points."octorules.secret_handlers"]
vault = "octorules_vault:VaultSecrets"
```

### Writing a secret handler

Subclass `BaseSecrets` from `octorules.secret`:

```python
from octorules.secret import BaseSecrets, SecretsException

class VaultSecrets(BaseSecrets):
    def __init__(self, name, url="", token=""):
        super().__init__(name)
        self.client = VaultClient(url=url, token=token)

    def fetch(self, ref, source):
        try:
            return self.client.read(ref)
        except VaultError as e:
            raise SecretsException(f"Vault lookup failed for {ref!r}: {e}")
```

### Resolution rules

1. Split string on first `/` → `(prefix, reference)`
2. Look up `prefix` in the handler registry
3. Found → call `handler.fetch(reference, source_context)`
4. Not found → return string unchanged (paths like `./rules` or `https://...` pass through safely)

## Processors

Processors hook into the plan/sync pipeline to transform rules before planning and filter changes after planning. They're useful for injecting shared rules, enforcing policy, or suppressing changes across zones.

```yaml
processors:
  add_standard_headers:
    class: my_package.StandardHeaderProcessor
    header_name: X-Frame-Options

zones:
  example.com:
    sources:
      - rules
    processors:
      - add_standard_headers
```

A processor is a Python class with two optional hooks:

- **`process_desired(zone_name, desired, provider)`** — transform the desired rules dict before planning. Return the modified dict.
- **`process_changes(zone_name, plan, provider)`** — transform the ZonePlan after planning. Return the modified plan.

Both default to no-op (pass-through). Processors run in the order listed. The `class` key is required; all other keys are forwarded as kwargs.

### Built-in filters

octorules ships three ready-to-use processors in `octorules.processor.filters`:

**PhaseFilter** — include or exclude phases by name:

```yaml
processors:
  waf_only:
    class: octorules.processor.filters.PhaseFilter
    include:
      - waf_custom_rules
      - waf_managed_rules
      - rate_limiting_rules
```

**RefFilter** — include or exclude rules by regex on the `ref` field:

```yaml
processors:
  skip_test_rules:
    class: octorules.processor.filters.RefFilter
    exclude: "^test-"
```

**ChangeTypeFilter** — block specific change types (safety guard):

```yaml
processors:
  no_deletes:
    class: octorules.processor.filters.ChangeTypeFilter
    exclude:
      - REMOVE
```

Valid change types: `ADD`, `REMOVE`, `MODIFY`, `REORDER`.

## Zone discovery

Zones can be discovered automatically from providers that support it (declared via `SUPPORTS_ZONE_DISCOVERY`). Use the `'*'` wildcard as a zone template:

```yaml
zones:
  '*':
    sources:
      - rules
    targets:
      - cloudflare

  # Explicit zones override discovered ones
  special.com:
    sources:
      - rules
    targets:
      - cloudflare
    always_dry_run: true
```

At init time, octorules calls `list_zones()` on target providers that support discovery, then expands the template for each discovered zone that has a matching YAML rules file in the rules directory. Explicit zone configs always take precedence.

## Optional features

Providers declare optional feature support via a `SUPPORTS` class variable. The framework checks support before calling optional methods. Features include:

| Feature | Description | Providers |
|---------|-------------|-----------|
| `custom_rulesets` | Account-level WAF rulesets (rule groups) | Cloudflare, AWS |
| `lists` | IP/ASN/hostname/redirect/regex lists (IP sets, regex pattern sets) | Cloudflare, AWS |
| `page_shield` | Content Security Policy management | Cloudflare |
| `zone_discovery` | Automatic zone enumeration via `list_zones()` | Cloudflare, AWS, Google, Azure, Bunny |

See each provider's documentation for feature details and YAML syntax.

## Linting

`octorules lint` runs offline static analysis on your rules files — no API calls, no credentials needed. Lint rules are provider-registered; install a provider package to get its rules.

```bash
# Lint all zones (text output)
octorules lint

# JSON output, only errors and warnings
octorules lint --format json --severity warning

# SARIF for GitHub Code Scanning
octorules lint --format sarif --output results.sarif

# CI mode: exit 1 on errors, 2 on warnings
octorules lint --exit-code

# Counts only (no details, CI-friendly)
octorules lint --format summary
```

Suppression comments work like shellcheck. Both lint and audit directives use the `octorules:` prefix and are case-sensitive:

```yaml
  # octorules:disable=CF015
  - ref: add-security-headers
    expression: (true)
```

Multiple rule IDs can be comma-separated: `# octorules:disable=CF018, CF423`

### Core lint rules

These provider-agnostic rules always run, regardless of which provider packages are installed:

| Rule | Severity | Description |
|------|----------|-------------|
| CORE001 | ERROR | Duplicate YAML key (silent data loss — last value wins) |
| CORE002 | WARNING | Rules file in rules directory doesn't match any configured zone |
| CORE003 | WARNING | All rules in a phase are disabled (2+ rules, all `enabled: false`) |
| CORE004 | WARNING | Same `ref` string used in multiple phases within a zone |
| CORE005 | WARNING | Safety `delete_threshold` is lower than `update_threshold` (config load) |
| CORE006 | INFO | Rules file contains no actual rules (all phases empty) |

CORE001 and CORE005 fire at config load time (before lint). The rest fire during `octorules lint`.

Provider-specific rules (CF, WA, GA prefixes) are documented in each provider's `docs/lint.md`.

## CLI reference

### `octorules plan`

Dry-run: shows what would change without touching the provider. Exit code 2 when changes are detected (with `--exit-code`). Output format and destination are controlled via `manager.plan_outputs` in the config file (defaults to text on stdout).

```bash
octorules plan [--zone example.com] [--phase redirect_rules] [--checksum] [--exit-code]
```

### `octorules sync --doit`

Applies changes to the provider. Requires `--doit` as a safety flag. Atomic PUT per phase, fail-fast on errors.

```bash
octorules sync --doit [--zone example.com] [--phase redirect_rules] [--checksum HASH] [--force]
```

| Flag | Description |
|------|-------------|
| `--doit` | Required safety flag to confirm changes should be applied |
| `--checksum HASH` | Verify plan hasn't drifted since `plan --checksum` |
| `--force` | Bypass safety threshold checks |
| `--audit-log PATH` | Write JSON lines audit log of sync results |
| `--format json` | Print structured JSON results to stdout (zone, status, synced phases, errors) |

### `octorules rule`

Browse and search the lint rule catalog.

```bash
octorules rule --all                  # List all rules
octorules rule CF                     # Filter by prefix
octorules rule CF201                  # Show one rule
octorules rule --all --format json    # JSON output
```

### `octorules dump`

Exports existing provider rules to YAML files. Useful for bootstrapping or importing an existing setup.

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
| `--plan` | Plan tier for entitlement checks (default: `enterprise`) |

When `--plan` is not specified, `lint` reads `.zone_plans_cache.json` (written
automatically by `plan`, `sync`, and `dump`) for automatic per-zone tier
detection. If neither `--plan` nor the cache provides a tier, `enterprise` is
assumed (most permissive, fewest false positives). Add `.zone_plans_cache.json`
to your `.gitignore` — it contains no secrets, just zone-to-tier mappings.

| `--rule` | Only check specific rule ID(s); can be repeated |
| `--output` | Write results to a file instead of stdout |
| `--exit-code` | Exit with 1 on errors, 2 on warnings (for CI) |

### `octorules audit`

Audit rules for cross-rule IP overlaps, shadowed rules, CDN range conflicts, and cross-zone inconsistencies. Processes every `*.yaml` file in the rules directory (not just configured zones). No API credentials needed.

```bash
octorules audit [--check ...] [--severity error|warning|info] [--format text|json] [--output FILE] [--exit-code] [--cdn-timeout N] [--cdn-stale-days N]
```

| Flag | Description |
|------|-------------|
| `--check` | Only run specific check(s); can be repeated (default: all) |
| `--severity` | Minimum severity to report (default: `info`) |
| `--format` | Output format: `text` (default), `json` |
| `--output` | Write results to a file instead of stdout |
| `--exit-code` | Exit with 1 on errors, 2 on warnings (for CI) |
| `--cdn-timeout` | Timeout in seconds for CDN range API fetches (default: 15) |
| `--cdn-stale-days` | Warn if baked-in CDN ranges are older than N days (default: 60) |

**Checks:**

- **ip-overlap** -- Cross-rule and cross-list IP range overlaps within a zone.
- **ip-shadow** -- Rules shadowed by broader rules in earlier phases (e.g. a rate-limit rule whose IPs are already blocked by a WAF rule).
- **cdn-ranges** -- Rules that match known CDN provider IP ranges (Cloudflare, AWS CloudFront, Google Cloud). Fetches fresh ranges from public APIs; falls back to baked-in data when offline.
- **zone-drift** -- Same CIDR treated differently across zones (e.g. blocked in zone A, allowed in zone B).

Acceptance comments suppress known findings (check names must be lowercase):

```yaml
  # octorules:accept=zone-drift
  # octorules:accept=ip-overlap,cdn-ranges
```

### `octorules versions`

Print versions of octorules and key dependencies.

```bash
octorules versions
```

### Common flags

| Flag | Description |
|------|-------------|
| `--config PATH` | Path to config file (default: `config.yaml`) |
| `--zone NAME` | Process a single zone (default: all) |
| `--phase NAME` | Limit to specific phase(s); can be repeated |
| `--scope SCOPE` | Scope: `all` (default), `zones`, or `account` |
| `--debug` | Enable debug logging |
| `--quiet` | Suppress all informational stdout output (plan tables, lint results, audit findings). Only errors and the exit code are reported. File output (`--output`) is unaffected |

### Environment variables

| Variable | Effect |
|----------|--------|
| `NO_COLOR` | Disable colored terminal output (any value, including empty) |
| `FORCE_COLOR` | Force colored output even when stdout is not a TTY |

`NO_COLOR` takes precedence over `FORCE_COLOR`. See https://no-color.org/.

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success / no changes |
| 1 | Error (or lint errors found with `--exit-code`) |
| 2 | Changes detected (`plan --exit-code`) / lint warnings found (`lint --exit-code`) |

After every command, a summary line is printed to stderr:
```
octorules plan: exit 0 (no changes) 0.3s
```

### Tab completion

Tab completion is built in (bash, zsh, tcsh). Generate the completion
script once and place it in the standard location:

```bash
# Bash
octorules completion bash > ~/.local/share/bash-completion/completions/octorules

# Zsh (add fpath+=~/.zfunc before compinit in .zshrc)
octorules completion zsh > ~/.zfunc/_octorules
```

Regenerate after upgrading octorules (new subcommands/flags).

## Config reference

```yaml
secret_handlers:                     # Optional — custom secret backends
  vault:
    class: octorules_vault.VaultSecrets  # Required: dotted class path
    url: https://vault.internal          # All other keys forwarded as kwargs
    token: env/VAULT_TOKEN               # Handler kwargs resolved via env + entry-points

providers:
  my_provider:                       # Provider name (any name works)
    token: env/API_TOKEN             # All keys forwarded to provider constructor
    class: my_package.MyProvider     # Optional: override auto-discovered provider
    safety:                          # Framework-owned (NOT forwarded to provider)
      delete_threshold: 30.0         # Max % of rules that can be deleted (default: 30)
      update_threshold: 30.0         # Max % of rules that can be updated (default: 30)
      min_existing: 3                # Min rules before thresholds apply (default: 3)
  rules:
    directory: ./rules               # Path to rules directory
  lists:
    directory: ./rules/custom_lists  # Path for externalized list items (default: {rules_dir}/custom_lists)

processors:
  my_proc:
    class: my_package.MyProcessor    # Required: dotted class path
    setting: value                   # All other keys forwarded as kwargs

manager:
  max_workers: 4                     # Parallel processing (default: 1)
  plan_outputs:                      # Config-driven plan output
    text:
      class: octorules.plan_output.PlanText
    html:
      class: octorules.plan_output.PlanHtml
      path: /tmp/plan.html           # Optional: write to file instead of stdout

zones:
  example.com:
    sources:
      - rules
    targets:
      - my_provider
    processors:
      - my_proc
    allow_unmanaged: false           # Keep rules not in YAML (default: false)
    always_dry_run: true             # Never apply changes (default: false)
    safety:                          # Per-zone overrides
      delete_threshold: 50.0

  '*':                               # Zone discovery template
    sources:
      - rules
    targets:
      - my_provider
```

## Programmatic usage

The `Manager` class provides a Python API for all octorules operations:

```python
from octorules import Manager

with Manager("config.yaml") as mgr:
    # Preview changes (returns exit code)
    rc = mgr.plan(exit_code=True)

    # Apply changes
    mgr.sync(force=True)

    # Lint specific zones
    mgr.lint(zones=["example.com"], severity="warning")

    # Export rules
    mgr.dump(output_dir="/tmp/rules")
```

All methods accept the same options as the CLI (`zones`, `phases`, `scope`, etc.) and return the same exit codes. The Manager handles provider/processor initialization and executor lifecycle.

## How it works

1. **Plan** — Reads your YAML rules, fetches current rules from the provider, computes a diff by matching rules on `ref` (phases), `name` (lists), or `description` (policies). Processors transform desired rules before diffing and filter changes after.
2. **Sync** — Executes the plan in order: lists, policies, custom rulesets, then phases. Each phase uses an atomic PUT (full replacement of the phase ruleset). Fail-fast on errors.
3. **Dump** — Fetches all rules from the provider and writes them to YAML files, stripping API-only fields (`id`, `version`, `last_updated`, etc.).

Performance (all parallelism controlled via `manager.max_workers`, default: 1):
- **Parallel phase fetching** — phases within each scope are fetched concurrently.
- **Parallel phase apply** — phase PUTs within a zone are applied concurrently during sync.
- **Parallel apply stages** — list item updates, custom ruleset PUTs, and policy operations within each stage run concurrently.
- **Parallel zone processing** — multiple zones are planned/synced concurrently.
- **Parallel zone ID resolution** — zone name lookups run concurrently.
- **Concurrent account planning** — account-level rules are planned in parallel with zone rules.
- **Scope-aware phase filtering** — only zone-level phases are fetched for zone scopes, and only account-level phases for account scopes, eliminating wasted API calls.
- **Rules caching** — YAML rule files are parsed once and cached for the duration of each run.

Safety features:
- **`--doit` flag** — sync requires explicit confirmation.
- **Delete thresholds** — blocks mass deletions above a configurable percentage.
- **Checksum verification** — `plan --checksum` produces a hash; `sync --checksum HASH` verifies the plan hasn't changed.
- **Auth error propagation** — authentication and permission errors fail immediately instead of being silently swallowed.
- **Failed phase filtering** — phases that can't be fetched are excluded from planning to prevent accidental mass deletions.
- **Path traversal protection** — `!include` directives and file operations are confined to their expected directories.

#### How safety thresholds work

Safety thresholds prevent accidental mass changes. When a plan would delete
or update more than a configurable percentage of existing rules in any phase,
the sync is blocked.

- **`delete_threshold`** (default `30.0`) — maximum percentage of rules that
  can be deleted in a single sync.  If a phase has 10 rules and the plan
  deletes 4, that's 40% — above the default threshold.
- **`update_threshold`** (default `30.0`) — same, for rule updates.
- **`min_existing`** (default `3`) — thresholds only apply once a phase has
  at least this many rules.  With fewer rules, any number of changes is
  allowed (avoids blocking initial setup).

Thresholds can be set per-provider or per-zone:

```yaml
providers:
  cloudflare:
    safety:
      delete_threshold: 50.0   # allow up to 50% deletions
      update_threshold: 30.0
      min_existing: 5

zones:
  example.com:
    safety:
      delete_threshold: 10.0   # stricter for this zone
```

When a threshold is exceeded, octorules exits with an error explaining which
phase exceeded the limit and by how much.  To override, either raise the
threshold or use `--force`.

### Troubleshooting

| Error | Cause | Recovery |
|-------|-------|----------|
| `ProviderAuthError` | Invalid or expired API token | Check token permissions and expiry |
| `delete_threshold exceeded` | Plan would delete too many rules | Review the plan; raise `delete_threshold` or use `--force` |
| `HTTP 429 Too Many Requests` | Provider API rate limit hit | Wait and retry; reduce `max_workers` |
| Partial zone failure | One zone failed, others succeeded | Re-run for the failed zone only (`--zone <name>`) |
| `Checksum mismatch` | State changed between plan and sync | Re-run `plan` to get a fresh checksum |
| `No rules file for zone` | Zone configured but YAML file missing | Create `rules/<zone>.yaml` or remove zone from config |

## Writing a provider

A provider is a Python package that:

1. **Implements `BaseProvider`** — the `@runtime_checkable` Protocol in `octorules.provider.base` defining 26 methods + 4 properties.
2. **Declares `SUPPORTS`** — a `frozenset[str]` of optional features (`custom_rulesets`, `lists`, `page_shield`, `zone_discovery`).
3. **Registers phases** — calls `register_phases()` at import time with the provider's phase definitions. Each `Phase` can include a `prepare_rule` callable for provider-specific rule preparation (expression normalization, default fields, action injection). The core planner calls this hook — it contains no provider-specific logic itself.
4. **Registers a linter plugin** — optional; provides provider-specific lint rules. Linters should only check their own phases (not phases owned by other providers).
5. **Declares an entry point** — in `pyproject.toml`:

```toml
[project.entry-points."octorules.providers"]
my_provider = "my_package:MyProvider"
```

Unsupported optional methods must still exist to satisfy the Protocol. The convention: read methods (`list_*`, `get_*`, `get_all_*`) return empty collections; mutation methods (`create_*`, `update_*`, `put_*`, `delete_*`) raise `ProviderError`.

### Provider utilities

`octorules.provider.utils` and related modules provide shared helpers so providers don't reinvent common patterns:

- **`retry_with_backoff()`** (`octorules.retry`) — exponential backoff with jitter for retrying transient API errors.
- **`fetch_parallel()`** (`octorules.provider.utils`) — concurrent fetching with error propagation and worker capping.
- **`to_plain_dict()`** — convert provider SDK objects to plain dicts.
- **`normalize_fields()` / `denormalize_fields()`** — bidirectional field name mapping between YAML and provider API formats.
- **`validate_path_within()`** (`octorules.pathutil`) — path traversal protection for file operations.
- **`make_error_wrapper()`** — decorator factory for mapping provider SDK exceptions to `ProviderError`/`ProviderAuthError`.

Extension hooks (plan, apply, format, validate, dump, audit) registered via `octorules.extensions` are validated at registration time — the framework checks the callable's signature against the expected parameters and raises `TypeError` immediately if they don't match, so provider authors get clear errors during development rather than at runtime.

## CI/CD integration

For GitHub Actions, see [octorules-sync](https://github.com/doctena-org/octorules-sync) — a ready-made action that runs plan on PRs and sync on merge to main.

## Development

### Local setup

```bash
git clone git@github.com:doctena-org/octorules.git
cd octorules
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,wirefilter]"
```

### Pre-commit hook

```bash
ln -sf ../../scripts/hooks/pre-commit .git/hooks/pre-commit
```

### Running tests and linting

```bash
pytest
ruff check octorules/ tests/
ruff format --check octorules/ tests/
```

### Releasing a new version

1. Update the version in `pyproject.toml` (single source of truth).
2. Commit and push to `main`.
3. Tag the release and push the tag:

```bash
git tag -a v0.17.0 -m "v0.17.0"
git push origin v0.17.0
```

Pushing a `v*` tag triggers the release workflow, which runs the full lint and test suites before building, publishing to [PyPI](https://pypi.org/project/octorules/), and creating a GitHub Release.

## License

octorules is licensed under the [Apache License 2.0](LICENSE).
