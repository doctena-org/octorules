# Lint Rule Reference

`octorules lint` performs offline static analysis of your rules files. **127 rules** across **19 categories**, organized into a 4-stage pipeline.

### Suppressing rules

Add a `# octorules:disable=RULE` comment immediately before a rule to suppress a specific finding. Multiple rule IDs can be comma-separated.

**Per-rule suppression** — suppresses the rule for a single ref:

```yaml
request_header_rules:
  # octorules:disable=M013
  - ref: add-security-headers
    expression: (true)
    action_parameters:
      headers:
        Strict-Transport-Security:
          operation: set
          value: max-age=31536000
```

**File-level suppression** — place the directive before any rules to suppress across the entire file:

```yaml
# octorules:disable=O002
---
origin_rules:
  - ref: route-api
    expression: 'raw.http.request.uri.path eq "/api"'
```

**Multiple rules:**

```yaml
  # octorules:disable=M013,O001
  - ref: catch-all
    expression: (true)
```

Suppressed findings are excluded from the report but counted in the summary line (e.g., `Total: 0 error(s), 0 warning(s), 0 info (2 suppressed)`).

### Severity levels

| Level | Meaning |
|-------|---------|
| **ERROR** | Invalid config that will fail at Cloudflare |
| **WARNING** | Likely mistake or suboptimal pattern |
| **INFO** | Style suggestion |

## Pipeline

| Stage | What it checks | Categories | Rules | Details |
|-------|---------------|------------|-------|---------|
| 1. YAML structure | Required fields, types, duplicates, unknown keys | M | 16 | [stage1-yaml-structure.md](stage1-yaml-structure.md) |
| 2. Per-rule checks | Actions, expressions, phase restrictions, values, style | A, C, D, I, J, K, L, N, E, F, G, B, O | 89 | [stage2-per-rule.md](stage2-per-rule.md) |
| 2b. Custom rulesets | Custom ruleset structure, duplicate refs | T | 4 | [stage2b-custom-rulesets.md](stage2b-custom-rulesets.md) |
| 2c. Page Shield | Policy structure, expressions, catch-all detection | S | 4 | [stage2b-page-shield.md](stage2b-page-shield.md) |
| 2d. List validation | List structure, item validity, duplicates | Q | 6 | [stage2d-lists.md](stage2d-lists.md) |
| 3. Plan-tier limits | Regex availability, rule count limits | H | 3 | [stage3-plan-tier.md](stage3-plan-tier.md) |
| 4. Cross-rule analysis | Duplicates, unreachable rules, list references | P | 5 | [stage4-cross-rule.md](stage4-cross-rule.md) |

## Categories

| Prefix | Category | Rules |
|--------|----------|-------|
| A | Parse / syntax errors | 2 |
| M | Structure | 16 |
| C | Action validation | 18 |
| D | Rate limiting | 6 |
| I | Cache rules | 4 |
| J | Config rules | 5 |
| K | Redirect rules | 2 |
| L | Transform rules | 6 |
| N | Origin rules | 1 |
| E | Function constraints | 7 |
| F | Type system | 3 |
| G | Value constraints | 26 |
| B | Phase restrictions | 3 |
| O | Best practice / style | 6 |
| H | Plan/entitlement | 3 |
| S | Page Shield structure | 4 |
| P | Cross-rule | 5 |
| Q | List validation | 6 |
| T | Custom ruleset validation | 4 |

---

## Cloudflare Phases Reference

Cloudflare processes every HTTP request through a fixed sequence of **phases**. Each phase has its own ruleset, and rules within a phase execute top-to-bottom. Understanding phase order is critical — it determines which fields are available, which actions are valid, and when a terminating action (like `block`) stops further processing.

### Execution order

```
Request arrives at Cloudflare edge
  │
  ├─  1. url_normalization          Normalize URL encoding
  ├─  2. bulk_redirect_rules        Account-level bulk redirects
  ├─  3. redirect_rules             Dynamic redirects
  ├─  4. url_rewrite_rules          Rewrite URI path/query
  ├─  5. request_header_rules       Modify request headers
  ├─  6. origin_rules               Override origin host/port/SNI
  ├─  7. config_rules               Set zone config (SSL, security level, polish, etc.)
  ├─  8. cache_rules                Cache settings (TTL, bypass, etc.)
  ├─  9. waf_custom_rules           Custom WAF rules (block, challenge, skip, log)
  ├─ 10. waf_managed_rules          Managed WAF rulesets (OWASP, CF Managed, etc.)
  ├─ 11. rate_limiting_rules        Rate limiting
  ├─ 12. bot_fight_rules            Super Bot Fight Mode
  ├─ 13. http_ddos_rules            L7 DDoS protection overrides
  │
  ├─── Origin fetch ────────────────── request leaves CF, response returns
  │
  ├─ 14. custom_error_rules         Custom error pages (serve_error)
  ├─ 15. response_header_rules      Modify response headers
  ├─ 16. compression_rules          Response compression algorithms
  ├─ 17. sensitive_data_detection    Detect sensitive data in responses
  ├─ 18. log_custom_fields          Custom log fields
  │
  └─ Response delivered to client
```

Network-level phases (Magic Transit) run before HTTP processing and are not shown above:

```
Network packet arrives
  │
  ├─ network_ddos_rules             L3/L4 DDoS protection (ddos_l4)
  ├─ network_firewall_rules         Magic Transit firewall (magic_transit)
  ├─ network_firewall_managed       Magic Transit managed rules
  ├─ network_firewall_ratelimit     Magic Transit rate limiting
  └─ network_firewall_ids           Magic Transit IDS
```

### Phase details

| # | YAML Key | CF Phase ID | Default Action | Valid Actions | Scope |
|---|----------|-------------|----------------|---------------|-------|
| 1 | `url_normalization` | `http_request_sanitize` | *(must specify)* | `none` | Zone |
| 2 | `bulk_redirect_rules` | `http_request_redirect` | `redirect` | `redirect` | Account |
| 3 | `redirect_rules` | `http_request_dynamic_redirect` | `redirect` | `redirect` | Zone |
| 4 | `url_rewrite_rules` | `http_request_transform` | `rewrite` | `rewrite` | Zone |
| 5 | `request_header_rules` | `http_request_late_transform` | `rewrite` | `rewrite` | Zone |
| 6 | `origin_rules` | `http_request_origin` | `route` | `route` | Zone |
| 7 | `config_rules` | `http_config_settings` | `set_config` | `set_config` | Zone |
| 8 | `cache_rules` | `http_request_cache_settings` | `set_cache_settings` | `set_cache_settings` | Zone |
| 9 | `waf_custom_rules` | `http_request_firewall_custom` | *(must specify)* | `block`, `challenge`, `js_challenge`, `managed_challenge`, `skip`, `log`, `execute` | Zone + Account |
| 10 | `waf_managed_rules` | `http_request_firewall_managed` | *(must specify)* | `execute`, `skip`, `block`, `log` | Zone + Account |
| 11 | `rate_limiting_rules` | `http_ratelimit` | *(must specify)* | `block`, `challenge`, `js_challenge`, `managed_challenge`, `log`, `execute` | Zone + Account |
| 12 | `bot_fight_rules` | `http_request_sbfm` | *(must specify)* | `block`, `challenge`, `js_challenge`, `managed_challenge` | Zone |
| 13 | `http_ddos_rules` | `ddos_l7` | *(must specify)* | `block`, `challenge`, `log` | Zone + Account |
| 14 | `custom_error_rules` | `http_custom_errors` | `serve_error` | `serve_error` | Zone + Account |
| 15 | `response_header_rules` | `http_response_headers_transform` | `rewrite` | `rewrite` | Zone |
| 16 | `compression_rules` | `http_response_compression` | `compress_response` | `compress_response` | Zone |
| 17 | `sensitive_data_detection` | `http_response_firewall_managed` | *(must specify)* | `log` | Zone |
| 18 | `log_custom_fields` | `http_log_custom_fields` | `log_custom_field` | `log_custom_field` | Zone |

### Field availability by phase

Not all fields are available in all phases. The linter checks these restrictions automatically (rules B001, B002, B003).

| Field group | Available in | Linter rule |
|-------------|-------------|-------------|
| **Request fields** (`http.request.*`, `http.host`, `ip.src.*`, `cf.*`, `ssl`) | All phases | — |
| **Response fields** (`http.response.*`, `cf.response.*`) | Phases 14–18 (after origin fetch): `custom_error_rules`, `response_header_rules`, `compression_rules`, `sensitive_data_detection`, `log_custom_fields` | [B001](stage2-per-rule.md#b001--response-field-used-in-request-phase) |
| **Request body fields** (`http.request.body.*`) | `waf_custom_rules`, `waf_managed_rules`, `rate_limiting_rules`, `custom_error_rules` | [B002](stage2-per-rule.md#b002--request-body-field-in-phase-without-body-access) |
| **Plan-gated fields** (`cf.bot_management.*`, `cf.waf.*`, etc.) | Depend on plan tier (Free/Pro/Business/Enterprise) | [B003](stage2-per-rule.md#b003--fieldfunction-requires-higher-plan-tier) |
| **Plan-gated functions** (`sha256` Enterprise, `is_timed_hmac_valid_v0` Pro) | Depend on plan tier | [B003](stage2-per-rule.md#b003--fieldfunction-requires-higher-plan-tier) |

### Function availability by phase

Some functions are restricted to specific phases. The linter checks this via rule [E002](stage2-per-rule.md#e002--function-not-available-in-this-phase).

| Functions | Available in |
|-----------|-------------|
| `regex_replace`, `wildcard_replace`, `to_string` | Transform + redirect phases: `url_rewrite_rules`, `request_header_rules`, `response_header_rules`, `redirect_rules` |
| `uuidv4`, `sha256`, `encode_base64`, `remove_query_args` | Transform phases only: `url_rewrite_rules`, `request_header_rules`, `response_header_rules` |
| `decode_base64` | Transform + WAF + rate limiting: `url_rewrite_rules`, `request_header_rules`, `response_header_rules`, `waf_custom_rules`, `rate_limiting_rules` |
| `split` | Response transform + custom error phases: `response_header_rules`, `custom_error_rules` |
| `join` | Transform + WAF + custom error phases: `url_rewrite_rules`, `request_header_rules`, `response_header_rules`, `waf_custom_rules`, `custom_error_rules` |
| `cidr`, `cidr6` | WAF + rate limiting phases: `waf_custom_rules`, `rate_limiting_rules` |
| `bit_slice` | Network phases only: `network_firewall_rules`, `network_ddos_rules`, `network_firewall_managed`, `network_firewall_ratelimit`, `network_firewall_ids` |
| All other functions (`lower`, `upper`, `len`, `contains`, `starts_with`, `ends_with`, `any`, `all`, etc.) | All phases |

### Key behaviors

**Terminating actions** — `block`, `redirect`, `challenge`, `js_challenge`, and `managed_challenge` stop the request from proceeding to later phases. A `block` in `waf_custom_rules` (phase 9) means `rate_limiting_rules` (phase 11) never runs. The linter detects unreachable rules *within* a phase via [P002](stage4-cross-rule.md#p002--unreachable-rule-after-terminating-action), but cross-phase ordering is the user's responsibility.

**`skip` action** — Only available in `waf_custom_rules` and `waf_managed_rules`. Can skip specific phases (`action_parameters.phases`) or legacy products (`action_parameters.products`). The linter validates these values via [C011](stage2-per-rule.md#c011--invalid-skip-phases-value) and [C012](stage2-per-rule.md#c012--invalid-skip-products-value).

**Transform expressions** — In transform phases (`url_rewrite_rules`, `request_header_rules`, `response_header_rules`), `action_parameters` can contain `expression` fields that use function-call syntax (e.g., `concat(...)`, `regex_replace(...)`). These are *different* from the rule's match `expression` — they define how values are computed, not whether the rule fires. The linter validates these via [L006](stage2-per-rule.md#l006--expression-parse-error-in-transform-action_parameters).

**Expression language** — All phases use the same [Cloudflare Rules Language](https://developers.cloudflare.com/ruleset-engine/rules-language/) (wirefilter syntax). Expressions have a 4,096 character limit ([M015](stage1-yaml-structure.md#m015--expression-exceeds-4096-character-limit)) and a 64 regex pattern limit per rule ([H003](stage3-plan-tier.md#h003--expression-exceeds-64-regex-pattern-limit)). The `matches` operator (regex) is not available on the Free plan ([H001](stage3-plan-tier.md#h001--regex-operator-not-available-on-free-plan)).

**Rule count limits** — Each phase has per-plan rule count limits. The linter checks these via [H002](stage3-plan-tier.md#h002--rule-count-exceeds-plan-limit-for-phase).

---

## Rule ID Quick Reference

| ID | Description | Severity |
|----|-------------|----------|
| [A001](stage2-per-rule.md#a001--expression-parse-error-wirefilter) | Expression parse error (wirefilter) | WARNING |
| [A002](stage2-per-rule.md#a002--expression-nesting-depth-exceeded) | Expression nesting depth exceeded | WARNING |
| [M001](stage1-yaml-structure.md#m001--missing-ref-field) | Missing ref field | ERROR |
| [M002](stage1-yaml-structure.md#m002--missing-expression-field) | Missing expression field | ERROR |
| [M003](stage1-yaml-structure.md#m003--duplicate-ref-within-phase) | Duplicate ref within phase | ERROR |
| [M004](stage1-yaml-structure.md#m004--invalid-ref-type) | Invalid ref type | ERROR |
| [M005](stage1-yaml-structure.md#m005--invalid-expression-type) | Invalid expression type | ERROR |
| [M006](stage1-yaml-structure.md#m006--invalid-enabled-type) | Invalid enabled type | ERROR |
| [M007](stage1-yaml-structure.md#m007--unknown-top-level-phase-key) | Unknown top-level phase key | WARNING |
| [M008](stage1-yaml-structure.md#m008--deprecated-phase-name) | Deprecated phase name | WARNING |
| [M009](stage1-yaml-structure.md#m009--description-exceeds-500-characters) | Description exceeds 500 characters | WARNING |
| [M010](stage1-yaml-structure.md#m010--phase-value-is-not-a-list) | Phase value is not a list | ERROR |
| [M011](stage1-yaml-structure.md#m011--rule-entry-is-not-a-dict) | Rule entry is not a dict | ERROR |
| [M012](stage1-yaml-structure.md#m012--cloudflare-phase-identifier-used-instead-of-friendly-name) | CF phase identifier used instead of friendly name | WARNING |
| [M013](stage1-yaml-structure.md#m013--expression-is-always-true-catch-all) | Expression is always true (catch-all) | WARNING |
| [M014](stage1-yaml-structure.md#m014--expression-is-always-false-dead-rule) | Expression is always false (dead rule) | WARNING |
| [M015](stage1-yaml-structure.md#m015--expression-exceeds-4096-character-limit) | Expression exceeds 4,096 character limit | ERROR |
| [M016](stage1-yaml-structure.md#m016--rule-is-disabled) | Rule is disabled (enabled: false) | INFO |
| [C001](stage2-per-rule.md#c001--invalid-action-for-phase) | Invalid action for phase | ERROR |
| [C002](stage2-per-rule.md#c002--missing-required-action) | Missing required action | ERROR |
| [C003](stage2-per-rule.md#c003--missing-required-action_parameters) | Missing required action_parameters | ERROR |
| [C004](stage2-per-rule.md#c004--unknown-action_parameters-key) | Unknown action_parameters key | WARNING |
| [C005](stage2-per-rule.md#c005--invalid-action_parameters-type) | Invalid action_parameters type | ERROR |
| [C006](stage2-per-rule.md#c006--invalid-status_code-type-or-value) | Invalid status_code type or value | ERROR |
| [C007](stage2-per-rule.md#c007--missing-required-status_code-for-redirect) | Missing required status_code for redirect | ERROR |
| [C008](stage2-per-rule.md#c008--conflicting-static-value-and-dynamic-expression) | Conflicting static value and dynamic expression | ERROR |
| [C009](stage2-per-rule.md#c009--unnecessary-action_parameters) | Unnecessary action_parameters | WARNING |
| [C010](stage2-per-rule.md#c010--serve_error-content-exceeds-10kb-limit) | serve_error content exceeds 10KB limit | ERROR |
| [C011](stage2-per-rule.md#c011--invalid-skip-phases-value) | Invalid skip phases value | WARNING |
| [C012](stage2-per-rule.md#c012--invalid-skip-products-value) | Invalid skip products value | WARNING |
| [C013](stage2-per-rule.md#c013--invalid-compress_response-algorithm) | Invalid compress_response algorithm | ERROR |
| [C014](stage2-per-rule.md#c014--invalid-rate-limit-characteristic) | Invalid rate limit characteristic | WARNING |
| [C015](stage2-per-rule.md#c015--invalid-block-response-parameter) | Invalid block response parameter | ERROR |
| [C016](stage2-per-rule.md#c016--missing-id-in-execute-action_parameters) | Missing id in execute action_parameters | ERROR |
| [C017](stage2-per-rule.md#c017--invalid-execute-id-format) | Invalid execute id format | WARNING |
| [C018](stage2-per-rule.md#c018--compression-terminal-algorithm-must-be-last) | Compression terminal algorithm must be last | WARNING |
| [D001](stage2-per-rule.md#d001--invalid-rate-limiting-period) | Invalid rate limiting period | ERROR |
| [D002](stage2-per-rule.md#d002--missing-rate-limiting-characteristics) | Missing rate limiting characteristics | WARNING |
| [D003](stage2-per-rule.md#d003--missing-requests_per_period-threshold) | Missing requests_per_period threshold | ERROR |
| [D004](stage2-per-rule.md#d004--mitigation-timeout-exceeds-period) | Mitigation timeout exceeds period | WARNING |
| [D005](stage2-per-rule.md#d005--invalid-counting_expression) | Invalid counting_expression | ERROR |
| [D006](stage2-per-rule.md#d006--invalid-counting_expression-content) | Invalid counting_expression content | WARNING |
| [I001](stage2-per-rule.md#i001--invalid-ttl-mode-value) | Invalid TTL mode value | ERROR |
| [I002](stage2-per-rule.md#i002--missing-ttl-with-override-mode) | Missing TTL with override mode | ERROR |
| [I003](stage2-per-rule.md#i003--negative-ttl-value) | Negative TTL value | ERROR |
| [I004](stage2-per-rule.md#i004--conflicting-bypass-and-eligible-settings) | Conflicting bypass and eligible settings | WARNING |
| [J001](stage2-per-rule.md#j001--invalid-security_level-value) | Invalid security_level value | ERROR |
| [J002](stage2-per-rule.md#j002--invalid-ssl-value) | Invalid ssl value | ERROR |
| [J003](stage2-per-rule.md#j003--invalid-polish-value) | Invalid polish value | ERROR |
| [J004](stage2-per-rule.md#j004--security-warning-security_level-set-to-off) | Security warning: security_level off | WARNING |
| [J005](stage2-per-rule.md#j005--security-warning-ssl-set-to-off) | Security warning: ssl set to off | WARNING |
| [K001](stage2-per-rule.md#k001--invalid-redirect-status-code) | Invalid redirect status code | ERROR |
| [K002](stage2-per-rule.md#k002--missing-target_url-in-redirect) | Missing target_url in redirect | ERROR |
| [L002](stage2-per-rule.md#l002--empty-header-name-in-transform) | Empty header name in transform | ERROR |
| [L003](stage2-per-rule.md#l003--missing-operation-in-header-transform) | Missing operation in header transform | ERROR |
| [L004](stage2-per-rule.md#l004--invalid-header-transform-operation) | Invalid header transform operation | ERROR |
| [L005](stage2-per-rule.md#l005--header-setadd-missing-value-or-expression) | Header set/add missing value or expression | ERROR |
| [L006](stage2-per-rule.md#l006--expression-parse-error-in-transform-action_parameters) | Expression parse error in transform action_parameters | WARNING |
| [L007](stage2-per-rule.md#l007--request-headers-do-not-support-add-operation) | Request headers do not support add operation | ERROR |
| [N001](stage2-per-rule.md#n001--port-number-out-of-range) | Port number out of range (1-65535) | ERROR |
| [B001](stage2-per-rule.md#b001--response-field-used-in-request-phase) | Response field used in request phase | WARNING |
| [B002](stage2-per-rule.md#b002--request-body-field-in-phase-without-body-access) | Request body field in phase without body access | WARNING |
| [B003](stage2-per-rule.md#b003--fieldfunction-requires-higher-plan-tier) | Field/function requires higher plan tier | WARNING |
| [E001](stage2-per-rule.md#e001--unknown-function-in-expression) | Unknown function in expression | WARNING |
| [E002](stage2-per-rule.md#e002--function-not-available-in-this-phase) | Function not available in this phase | WARNING |
| [E003](stage2-per-rule.md#e003--regex_replacewildcard_replace-usage-limit) | regex_replace/wildcard_replace usage limit | ERROR |
| [E004](stage2-per-rule.md#e004--invalid-encode_base64-flags) | Invalid encode_base64 flags | WARNING |
| [E005](stage2-per-rule.md#e005--invalid-url_decode-options) | Invalid url_decode options | WARNING |
| [E006](stage2-per-rule.md#e006--invalid-wildcard_replace-flags) | Invalid wildcard_replace flags | WARNING |
| [E007](stage2-per-rule.md#e007--function-source-argument-must-be-field) | Function source argument must be field | WARNING |
| [F001](stage2-per-rule.md#f001--operator-type-incompatibility) | Operator-type incompatibility | ERROR |
| [F002](stage2-per-rule.md#f002--unknown-field-name-in-expression) | Unknown field name in expression | WARNING |
| [F003](stage2-per-rule.md#f003--array-star-unpacking-on-multiple-arrays) | Array [*] unpacking on multiple arrays | WARNING |
| [G001](stage2-per-rule.md#g001--http-method-should-be-uppercase) | HTTP method should be uppercase | WARNING |
| [G002](stage2-per-rule.md#g002--uri-path-should-start-with-) | URI path should start with / | WARNING |
| [G003](stage2-per-rule.md#g003--regex-anchor-in-literal-value) | Regex anchor in literal value | WARNING |
| [G004](stage2-per-rule.md#g004--invalid-country-code-format) | Invalid country code format | WARNING |
| [G005](stage2-per-rule.md#g005--score-value-out-of-typical-range) | Score value out of typical range | WARNING |
| [G006](stage2-per-rule.md#g006--response-code-out-of-valid-range) | Response code out of valid range | WARNING |
| [G007](stage2-per-rule.md#g007--header-name-should-be-lowercase) | Header name should be lowercase | INFO |
| [G008](stage2-per-rule.md#g008--file-extension-should-not-start-with-a-dot) | File extension should not start with dot | WARNING |
| [G009](stage2-per-rule.md#g009--duplicate-value-in-in-set) | Duplicate value in `in` set | WARNING |
| [G010](stage2-per-rule.md#g010--deprecated-field) | Deprecated field — use replacement | WARNING |
| [G011](stage2-per-rule.md#g011--reservedbogon-ip-address) | Reserved/bogon IP address | WARNING |
| [G012](stage2-per-rule.md#g012--overlapping-ip-ranges) | Overlapping IP ranges | WARNING |
| [G013](stage2-per-rule.md#g013--invalid-value-for-field-domain) | Invalid value for field domain | WARNING |
| [G014](stage2-per-rule.md#g014--timestamp-value-out-of-reasonable-bounds) | Timestamp value out of reasonable bounds | WARNING |
| [G015](stage2-per-rule.md#g015--integer-range-overlap-in-in-set) | Integer range overlap in `in` set | WARNING |
| [G016](stage2-per-rule.md#g016--value-incompatible-with-lowerupper) | Value incompatible with lower()/upper() | WARNING |
| [G017](stage2-per-rule.md#g017--len-compared-to-negative-value) | len() compared to negative value | WARNING |
| [G018](stage2-per-rule.md#g018--invalid-double-asterisk-in-wildcard) | Invalid double-asterisk in wildcard | WARNING |
| [G019](stage2-per-rule.md#g019--integer-range-start-greater-than-end) | Integer range start > end | ERROR |
| [G020](stage2-per-rule.md#g020--split-limit-outside-valid-range) | split() limit outside 1-128 | WARNING |
| [G021](stage2-per-rule.md#g021--cidrcidr6-bit-value-out-of-range) | cidr/cidr6 bit value out of range | WARNING |
| [G022](stage2-per-rule.md#g022--remove_query_args-wrong-first-argument) | remove_query_args() wrong first argument | WARNING |
| [G023](stage2-per-rule.md#g023--invalid-regex-pattern-in-matches-operator) | Invalid regex pattern in matches operator | WARNING |
| [G024](stage2-per-rule.md#g024--substring-index-out-of-bounds-or-inverted) | substring() index out of bounds or inverted | WARNING |
| [G025](stage2-per-rule.md#g025--lookup_json-path-should-start-with-) | lookup_json path should start with / | WARNING |
| [G026](stage2-per-rule.md#g026--bit_slice-offset-or-size-out-of-range) | bit_slice offset or size out of range | WARNING |
| [H001](stage3-plan-tier.md#h001--regex-operator-not-available-on-free-plan) | Regex not available on Free plan | WARNING |
| [H002](stage3-plan-tier.md#h002--rule-count-exceeds-plan-limit-for-phase) | Rule count exceeds plan limit | WARNING |
| [H003](stage3-plan-tier.md#h003--expression-exceeds-64-regex-pattern-limit) | Expression exceeds 64 regex limit | WARNING |
| [O001](stage2-per-rule.md#o001--consider-using-in-operator-for-multiple-or-values) | Consider using in operator | INFO |
| [O002](stage2-per-rule.md#o002--use-normalized-field-instead-of-raw-field) | Use normalized field instead of raw | INFO |
| [O003](stage2-per-rule.md#o003--redundant-double-negation) | Redundant double negation | INFO |
| [O004](stage2-per-rule.md#o004--negated-comparison-can-be-simplified) | Negated comparison can be simplified | INFO |
| [O005](stage2-per-rule.md#o005--illogical-condition) | Illogical condition | WARNING |
| [O006](stage2-per-rule.md#o006--regex-pattern-uses-literal-escapes) | Regex literal escapes | INFO |
| [S001](stage2b-page-shield.md#s001--missing-required-field) | Missing required Page Shield field | ERROR |
| [S002](stage2b-page-shield.md#s002--invalid-action) | Invalid Page Shield action | ERROR |
| [S003](stage2b-page-shield.md#s003--invalid-field-type) | Invalid Page Shield field type | ERROR |
| [S004](stage2b-page-shield.md#s004--duplicate-description) | Duplicate Page Shield description | WARNING |
| [P001](stage4-cross-rule.md#p001--duplicate-expression-across-rules) | Duplicate expression across rules | WARNING |
| [P002](stage4-cross-rule.md#p002--unreachable-rule-after-terminating-action) | Unreachable rule after terminating action | WARNING |
| [P003](stage4-cross-rule.md#p003--unresolved-list-reference) | Unresolved list reference | WARNING |
| [P004](stage4-cross-rule.md#p004--unknown-managed-list-name) | Unknown managed list name | WARNING |
| [P005](stage4-cross-rule.md#p005--list-type--field-type-mismatch) | List type / field type mismatch | WARNING |
| [Q001](stage2d-lists.md#q001--missing-or-duplicate-list-name) | Missing or duplicate list name | ERROR |
| [Q002](stage2d-lists.md#q002--missing-or-invalid-list-kind) | Missing or invalid list kind | ERROR |
| [Q003](stage2d-lists.md#q003--list-item-missing-required-field) | List item missing required field | ERROR |
| [Q004](stage2d-lists.md#q004--invalid-ip-address-in-ip-list) | Invalid IP address in IP list | ERROR |
| [Q005](stage2d-lists.md#q005--invalid-asn-value-in-asn-list) | Invalid ASN value in ASN list | ERROR |
| [Q006](stage2d-lists.md#q006--duplicate-items-within-list) | Duplicate items within list | WARNING |
| [T001](stage2b-custom-rulesets.md#t001--missing-required-field) | Missing required custom ruleset field | ERROR |
| [T002](stage2b-custom-rulesets.md#t002--invalid-id-format) | Invalid custom ruleset id format | WARNING |
| [T003](stage2b-custom-rulesets.md#t003--duplicate-ref-within-custom-ruleset) | Duplicate ref within custom ruleset | ERROR |
| [T004](stage2b-custom-rulesets.md#t004--duplicate-ref-across-custom-rulesets) | Duplicate ref across custom rulesets | WARNING |
