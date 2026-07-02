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

> **Examples** — the [`examples/`](examples/) directory here contains the multi-provider orchestration config (`config.yaml`) plus representative rules under `rules/multi/`. **Complete, per-phase single-provider examples live in each provider package's own `examples/` directory** — see [octorules-cloudflare](https://github.com/doctena-org/octorules-cloudflare/tree/main/examples), [octorules-aws](https://github.com/doctena-org/octorules-aws/tree/main/examples), [octorules-azure](https://github.com/doctena-org/octorules-azure/tree/main/examples), [octorules-google](https://github.com/doctena-org/octorules-google/tree/main/examples), and [octorules-bunny](https://github.com/doctena-org/octorules-bunny/tree/main/examples). Start there rather than writing config from scratch.

All keys under a provider section (except `class` and `safety`) are forwarded as keyword arguments to the provider constructor — octodns-style passthrough. See each provider's documentation for available settings.

#### Multi-provider setup

To manage rules across multiple providers, add each provider as a named section under `providers:` and assign zones to providers via `targets:`. When only one provider is configured, `targets` is auto-assigned and can be omitted. See [`examples/config.yaml`](examples/config.yaml) for a full multi-provider config with all five providers.

#### Multi-target zones

A zone can target multiple providers of the **same class** (e.g. two Cloudflare accounts, or prod + staging). List multiple names under `targets:` — octorules plans and applies independently for each. Requires explicit `class:` since auto-discovery can't distinguish two instances of the same provider. See [`examples/config.yaml`](examples/config.yaml) for a commented example.

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
| Cloudflare | DNS domain | `example.com` | `<rules-dir>/example.com.yaml` |
| AWS WAF | Web ACL name | `my-web-acl` | `<rules-dir>/my-web-acl.yaml` |
| Google Cloud Armor | Security policy name | `my-security-policy` | `<rules-dir>/my-security-policy.yaml` |
| Azure WAF | WAF policy name | `my-waf-policy` | `<rules-dir>/my-waf-policy.yaml` |
| Bunny Shield | Pull zone name | `my-pull-zone` | `<rules-dir>/my-pull-zone.yaml` |

The mapping is: `zones.<name>` in `config.yaml` → `<rules-dir>/<name>.yaml` on disk → `resolve_zone_id("<name>")` at runtime, which resolves the name to the provider's internal ID. `<rules-dir>` defaults to `./rules/` and is set under `providers.rules.directory` — point it wherever each customer's rules live (the [`examples/`](examples/) directory here ships `rules/multi/` for the multi-provider `config.yaml`; each provider package ships its own single-provider example under its `examples/` directory).

Each rule requires a **`ref`** (stable identifier, unique within a phase) and an **`expression`** (provider-specific filter expression). Optional fields include `description`, `enabled` (defaults to `true`), `action`, and `action_parameters`. Phase names, available actions, and expression syntax are provider-specific — see your provider's documentation and that provider package's own `examples/` directory for complete per-provider examples.

octorules lints each rule file only against the plugin matching its zone's target provider. With per-provider lint plugins installed in the same venv (e.g. both `octorules-cloudflare` and `octorules-aws`), a Cloudflare zone file never gets validated against the AWS schema and vice versa — eliminating cross-provider false positives on same-named blocks (`custom_rulesets`, `lists`).

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

octorules ships four ready-to-use processors in `octorules.processor.filters`:

| Filter | Description |
|--------|-------------|
| **PhaseFilter** | Include or exclude phases by name (`include`/`exclude` lists) |
| **RefFilter** | Include or exclude rules by regex on the `ref` field |
| **ChangeTypeFilter** | Block specific change types: `ADD`, `REMOVE`, `MODIFY`, `REORDER` |
| **PreserveFilter** | Protect rules whose `ref` matches a regex from `REMOVE`/`REORDER` changes |

`allow_unmanaged` is all-or-nothing: off, every live rule absent from your YAML
is planned for removal; on, nothing unmanaged is ever removed. **PreserveFilter**
is the scoped middle ground — keep `allow_unmanaged` off so genuine drift is
still cleaned up, but spare rules whose `ref` matches a pattern (e.g. rules a
security vendor or another team injects out-of-band) from deletion and
reordering. It reads only `ref` and `change_type`, so it works across every
provider.

See [`examples/config.yaml`](examples/config.yaml) for working examples of all four.

## Zone discovery

Zones can be discovered automatically from providers that support it. Use `'*'` as a zone template in your config — octorules calls `list_zones()` on target providers at init time and expands the template for each discovered zone that has a matching YAML rules file. Explicit zone configs always take precedence. See the wildcard entry in [`examples/config.yaml`](examples/config.yaml).

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

`octorules lint` runs offline static analysis on your rules files — no API calls, no credentials needed. Lint rules are provider-registered; install a provider package to get its rules. See [`octorules lint`](#octorules-lint) in the CLI reference for flags and options.

Suppression comments work like shellcheck — add `# octorules:disable=CF015` (comma-separated for multiple rules) before a rule to suppress specific findings. Audit findings use `# octorules:accept=ip-overlap`.

### Core lint rules

| Rule | Severity | Description |
|------|----------|-------------|
| CORE002 | WARNING | Orphaned rules file (no matching zone in config) |
| CORE003 | WARNING | All rules in a phase are disabled (2+ rules, all `enabled: false`) |
| CORE004 | WARNING | Same `ref` string used in multiple phases within a zone |
| CORE006 | INFO | Rules file contains no actual rules (all phases empty) |

Provider-specific rules (CF, WA, GA, AZ, BN prefixes) are documented in each provider's `docs/lint.md`.

### Config validation (not lint rules)

These checks run at config load time and emit log warnings or raise errors. They are **not** lint diagnostics — they cannot be suppressed with `# octorules:disable=...` and do not appear in lint output.

| Check | Level | Description |
|-------|-------|-------------|
| Duplicate YAML key | ERROR | Raises `ConfigError` on duplicate keys (silent data loss — last value wins) |
| Inverted safety thresholds | WARNING | Logs a warning when `delete_threshold` < `update_threshold` (deletes less restricted than updates) |

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

Lint rules files offline for errors, warnings, and style issues. Supports text, JSON, SARIF, and summary output.

```bash
octorules lint [FILE] [--config-only] [--format text|json|sarif] [--severity error|warning|info] [--plan free|pro|business|enterprise] [--rule RULE_ID] [--output PATH] [--exit-code]
```

| Flag | Description |
|------|-------------|
| `FILE` | Lint a single rules file (no config needed). When omitted, uses the config file to discover all zones |
| `--config-only` | Only validate config file structure (skip rules files) |
| `--format` | Output format: `text` (default), `json`, `sarif`, `summary` |
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
| `--format` | Output format: `text` (default), `json`, `summary` |
| `--output` | Write results to a file instead of stdout |
| `--exit-code` | Exit with 1 on errors, 2 on warnings (for CI) |
| `--cdn-timeout` | Timeout in seconds for CDN range API fetches (default: 15) |
| `--cdn-stale-days` | Warn if baked-in CDN ranges are older than N days (default: 60) |

**Checks:**

- **ip-overlap** -- Cross-rule and cross-list IP range overlaps within a zone.
- **ip-shadow** -- Rules shadowed by broader rules in earlier phases (e.g. a rate-limit rule whose IPs are already blocked by a WAF rule).
- **cdn-ranges** -- Rules that match known CDN provider IP ranges (Cloudflare, AWS CloudFront, Google Cloud, Bunny, Azure Front Door). Fetches fresh ranges from public APIs; falls back to baked-in data when offline. (Azure's list is scraped from the Microsoft Download Center page — the JSON URL rotates weekly.)
- **zone-drift** -- Same CIDR treated differently across zones (e.g. blocked in zone A, allowed in zone B).

Acceptance comments suppress known findings (check names must be lowercase).
Like the `disable=` lint directives, they are positional: a comment attaches to
the rule anchor (a `ref:` or `description:` line) that follows it, scoping the
acceptance to that rule. A comment placed before any rule (e.g. at the top of
the file) is file-wide:

```yaml
# octorules:accept=zone-drift          # file-wide (before any rule)

waf_custom_rules:
  # octorules:accept=ip-overlap,cdn-ranges   # scoped to the rule below
  - ref: r1
    expression: ...
```

To scope an acceptance to a finding on a **list** (whose finding ref is
`list:<name>`), place the comment above the list's `name:` in the list's own
file — `!include`d files are followed:

```yaml
# custom_lists/block_known_attackers.yaml
# octorules:accept=cdn-ranges
name: block_known_attackers
kind: ip
items: [...]
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
| `--zone NAME` | Process only specified zone(s); can be repeated (default: all) |
| `--phase NAME` | Limit to specific phase(s); can be repeated |
| `--scope SCOPE` | Scope: `all` (default), `zones`, or `account` |
| `--debug` | Enable debug logging |
| `--quiet` | Suppress all informational stdout output (plan tables, lint results, audit findings). Only errors and the exit code are reported. File output (`--output`) is unaffected |
| `--syslog ADDRESS` | Send logs to syslog (`host:port` for UDP, or `/path/to/socket`) |

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

Safety thresholds prevent accidental mass changes. When a plan would delete or update more than a configurable percentage of existing rules in any phase, the sync is blocked. Defaults: `delete_threshold: 30.0`, `update_threshold: 30.0`, `min_existing: 3` (thresholds only apply once a phase has at least this many rules). Can be set per-provider or per-zone — see [Config reference](#config-reference). Override with `--force`.

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

1. **Implements `BaseProvider`** — the `@runtime_checkable` Protocol in `octorules.provider.base` defining 19 methods + 4 properties.
2. **Declares `SUPPORTS`** — a `frozenset[str]` of optional features (`custom_rulesets`, `lists`, `page_shield`, `zone_discovery`).
3. **Registers phases** — calls `register_phases()` at import time with the provider's phase definitions. Each `Phase` can include a `prepare_rule` callable for provider-specific rule preparation (expression normalization, default fields, action injection) and a `rule_required_fields` tuple declaring which fields rules inside `custom_rulesets` entries must set. The core planner calls these — it contains no provider-specific logic itself.
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
- **Linter helpers** (`octorules.linter.helpers`) — shared logic for the lint checks providers mirror by convention: `lint_result()`, `iter_provider_phases()`, `find_overlapping_cidrs()` (sweep-line CIDR containment), `normalize_host_bits()`, `find_duplicates_by_key()`, `count_phase_rules()`, `is_strict_int()`, `find_duplicate_priorities()`, `find_first_priority_gap()`, and `CATCH_ALL_CIDRS`.

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
pre-commit install
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
