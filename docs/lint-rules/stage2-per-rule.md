# Stage 2: Per-Rule Checks

Runs four sub-checks for each rule in each phase: action validation, expression analysis, phase restriction checks, and parse error surfacing.

## Category A — Parse / Syntax Errors (2 rules)

### A001 — Expression parse error (wirefilter)

| Severity | Category |
|----------|----------|
| WARNING | parse |

Triggers when the wirefilter FFI parser rejects the rule's expression. Catches unknown fields, invalid syntax, type mismatches, unbalanced parentheses, and other errors that Cloudflare would reject.

Requires the optional `octorules[wirefilter]` package. Standalone `true`/`false` expressions are handled before wirefilter and will not trigger this rule. Value expressions in `action_parameters` (e.g. `regex_replace(...)`) are also excluded since wirefilter only parses boolean filter expressions.

```yaml
waf_custom_rules:
  - ref: bad-syntax
    expression: 'http.host eq'   # incomplete expression
```

Fix: Correct the expression syntax.

### A002 — Expression nesting depth exceeded

| Severity | Category |
|----------|----------|
| WARNING | parse |

Triggers when the wirefilter parser reports that expression nesting depth exceeds 100 levels. Extremely deeply nested expressions may cause performance issues at the Cloudflare edge.

Requires the optional `octorules[wirefilter]` package.

Fix: Simplify the expression to reduce nesting depth. Break complex logic into multiple rules if needed.

---

## Category C — Action Validation (18 rules)

### C001 — Invalid action for phase

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when the rule's `action` is not in the set of valid actions for its phase.

```yaml
cache_rules:
  - ref: my-rule
    expression: 'true'
    action: block           # block is not valid for cache_rules
```

Fix: Use a valid action for the phase, or omit `action` if the phase has a default.

### C002 — Missing required action

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when `action` is not specified and the phase has no default action (e.g., `waf_custom_rules`, `rate_limiting_rules`).

```yaml
waf_custom_rules:
  - ref: my-rule
    expression: 'true'
    # missing action — waf_custom_rules has no default
```

Fix: Add an explicit `action` (e.g., `block`, `challenge`, `log`).

### C003 — Missing required action_parameters

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when the action's schema requires parameters but none are provided.

```yaml
redirect_rules:
  - ref: my-redirect
    expression: 'true'
    # missing action_parameters — redirect requires from_value
```

Fix: Add the required `action_parameters`.

### C004 — Unknown action_parameters key

| Severity | Category |
|----------|----------|
| WARNING | action |

Triggers when `action_parameters` contains a key not recognized by the action's schema.

Fix: Remove the unrecognized key or check for typos.

### C005 — Invalid action_parameters type

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when `action_parameters` is not a mapping (e.g., a string or list).

Fix: Use a mapping for `action_parameters`.

### C006 — Invalid status_code type or value

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when `status_code` is not an integer, or when it's outside the valid range for the context (e.g., 400–599 for custom error rules).

Fix: Use a valid integer status code.

### C007 — Missing required status_code for redirect

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when a redirect's `from_value` dict is missing `status_code`.

Fix:

```yaml
action_parameters:
  from_value:
    target_url:
      expression: 'concat("https://example.com", http.request.uri.path)'
    status_code: 301
```

### C008 — Conflicting static value and dynamic expression

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when a parameter dict contains both `value` and `expression` keys simultaneously (e.g., in redirect `target_url`, URI transform components, or header transforms).

Fix: Use either `value` (static) or `expression` (dynamic), not both.

### C009 — Unnecessary action_parameters

| Severity | Category |
|----------|----------|
| WARNING | action |

Triggers when the action does not accept parameters but non-empty `action_parameters` are provided.

Fix: Remove `action_parameters` for this action.

### C010 — serve_error content exceeds 10KB limit

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when the `content` field in a `serve_error` action's parameters exceeds 10,240 bytes (UTF-8 encoded).

```yaml
custom_error_rules:
  - ref: error-page
    expression: 'true'
    action_parameters:
      content: "<html>... very large HTML ...</html>"   # >10KB
      status_code: 503
```

Fix: Reduce the content size to under 10KB. Consider linking to external assets instead of inlining them.

### C011 — Invalid skip phases value

| Severity | Category |
|----------|----------|
| WARNING | action |

Triggers when a `skip` action's `phases` list contains an unrecognized Cloudflare phase identifier.

```yaml
waf_custom_rules:
  - ref: skip-rule
    action: skip
    action_parameters:
      phases:
        - http_request_firewall_custom
        - bogus_phase                     # not a valid CF phase
```

Fix: Use valid Cloudflare phase identifiers (e.g. `http_request_firewall_custom`, `http_ratelimit`, `http_request_firewall_managed`).

### C012 — Invalid skip products value

| Severity | Category |
|----------|----------|
| WARNING | action |

Triggers when a `skip` action's `products` list contains an unrecognized product name.

```yaml
waf_custom_rules:
  - ref: skip-rule
    action: skip
    action_parameters:
      products:
        - waf
        - bogus_product                   # not a valid product
```

Fix: Use valid product names: `bic`, `hot`, `rateLimit`, `securityLevel`, `uaBlock`, `waf`, `zoneLockdown`.

### C013 — Invalid compress_response algorithm

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when a `compress_response` action's `algorithms` list contains an unrecognized compression algorithm.

```yaml
compression_rules:
  - ref: compress-rule
    expression: 'true'
    action_parameters:
      algorithms:
        - name: gzip
        - name: deflate                    # not a valid algorithm
```

Fix: Use valid algorithms: `gzip`, `brotli`, `zstd`, `none`, `auto`.

### C014 — Invalid rate limit characteristic

| Severity | Category |
|----------|----------|
| WARNING | action |

Triggers when a rate limiting rule's `characteristics` list contains an unrecognized value.

```yaml
rate_limiting_rules:
  - ref: rate-limit
    action: block
    action_parameters:
      characteristics:
        - ip.src
        - bogus.field                      # not a valid characteristic
      period: 60
      requests_per_period: 100
```

Fix: Use valid characteristics: `ip.src`, `cf.colo.id`, `cf.unique_visitor_id`, `ip.geoip.country`, `ip.geoip.asnum`, `ip.src.country`, `ip.src.asnum`, or header references like `http.request.headers["x-api-key"]`.

### C015 — Invalid block response parameter

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when a `block` action's `action_parameters.response` contains invalid values:
- `status_code` must be an integer in the 400–499 range.
- `content_type` must be a string.
- `content` must be a string.

```yaml
waf_custom_rules:
  - ref: block-with-response
    action: block
    expression: 'ip.src in {1.2.3.4}'
    action_parameters:
      response:
        status_code: 503   # must be 400-499
        content_type: text/html
        content: "<h1>Blocked</h1>"
```

Fix: Use a status code in the 400–499 range. Cloudflare only allows 4xx responses for block actions.

### C016 — Missing id in execute action_parameters

| Severity | Category |
|----------|----------|
| ERROR | action |

Triggers when an `execute` action's `action_parameters` is missing the required `id` field. The `id` identifies which managed ruleset or custom ruleset to execute.

```yaml
waf_custom_rules:
  - ref: deploy-custom
    expression: 'true'
    action: execute
    action_parameters: {}   # missing id
```

Fix:

```yaml
action_parameters:
  id: abc12345def67890abc12345def67890
```

### C017 — Invalid execute id format

| Severity | Category |
|----------|----------|
| WARNING | action |

Triggers when an `execute` action's `id` is not a valid 32-character lowercase hex string.

```yaml
action_parameters:
  id: not-a-valid-id
```

Fix: Use the correct 32-character hex ruleset ID from Cloudflare.

### C018 — Compression terminal algorithm must be last

| Severity | Category |
|----------|----------|
| WARNING | action |

Triggers when a `compress_response` action's `algorithms` list has a terminal algorithm (`none`, `auto`) that is not the last entry. Terminal algorithms stop the algorithm negotiation — any algorithms listed after them will never be used.

```yaml
compression_rules:
  - ref: compress
    expression: 'true'
    action_parameters:
      algorithms:
        - name: auto     # terminal — stops negotiation
        - name: gzip     # never reached
```

Fix: Move terminal algorithms to the end of the list, or remove subsequent entries.

---

## Category D — Rate Limiting (6 rules)

### D001 — Invalid rate limiting period

| Severity | Category |
|----------|----------|
| ERROR | rate_limit |

Triggers when `period` is not one of the valid values: 10, 60, 120, 300, 600, or 3600 seconds.

Fix: Use a valid period value.

### D002 — Missing rate limiting characteristics

| Severity | Category |
|----------|----------|
| WARNING | rate_limit |

Triggers when `characteristics` is not specified. Without it, the rate limit applies globally across all clients.

Fix:

```yaml
action_parameters:
  characteristics:
    - ip.src
  requests_per_period: 100
  period: 60
```

### D003 — Missing requests_per_period threshold

| Severity | Category |
|----------|----------|
| ERROR | rate_limit |

Triggers when neither `requests_per_period` nor `score_per_period` is specified.

Fix: Add `requests_per_period` or `score_per_period`.

### D004 — Mitigation timeout exceeds period

| Severity | Category |
|----------|----------|
| WARNING | rate_limit |

Triggers when `mitigation_timeout` is greater than `period`.

Fix: Set `mitigation_timeout` to be less than or equal to `period`.

### D005 — Invalid counting_expression

| Severity | Category |
|----------|----------|
| ERROR | rate_limit |

Triggers when `counting_expression` is present but is not a string.

Fix: Use a string expression for `counting_expression`.

### D006 — Invalid counting_expression content

| Severity | Category |
|----------|----------|
| WARNING | rate_limit |

Triggers when `counting_expression` is a non-empty string but fails to parse as a valid wirefilter expression.

Fix: Correct the expression syntax in `counting_expression`.

---

## Category I — Cache Rules (4 rules)

### I001 — Invalid TTL mode value

| Severity | Category |
|----------|----------|
| ERROR | cache |

Triggers when `edge_ttl.mode` or `browser_ttl.mode` is not a valid value. Valid edge TTL modes: `respect_origin`, `override_origin`, `bypass_by_default`. Valid browser TTL modes: `respect_origin`, `override_origin`, `bypass`.

Fix: Use a valid TTL mode.

### I002 — Missing TTL with override mode

| Severity | Category |
|----------|----------|
| ERROR | cache |

Triggers when TTL mode is `override_origin` but no `default` value is specified.

Fix:

```yaml
action_parameters:
  edge_ttl:
    mode: override_origin
    default: 86400
```

### I003 — Negative TTL value

| Severity | Category |
|----------|----------|
| ERROR | cache |

Triggers when the TTL `default` value is negative.

Fix: Use a non-negative TTL value.

### I004 — Conflicting bypass and eligible settings

| Severity | Category |
|----------|----------|
| WARNING | cache |

Triggers when `cache: false` is set alongside `edge_ttl` or `browser_ttl` values. TTL settings have no effect when caching is disabled.

Fix: Either remove the TTL settings or set `cache: true`.

---

## Category J — Config Rules (5 rules)

### J001 — Invalid security_level value

| Severity | Category |
|----------|----------|
| ERROR | config |

Triggers when `security_level` is not one of: `off`, `essentially_off`, `low`, `medium`, `high`, `under_attack`.

Fix: Use a valid security level.

### J002 — Invalid ssl value

| Severity | Category |
|----------|----------|
| ERROR | config |

Triggers when `ssl` is not one of: `off`, `flexible`, `full`, `strict`, `origin_pull`.

Fix: Use a valid SSL mode.

### J003 — Invalid polish value

| Severity | Category |
|----------|----------|
| ERROR | config |

Triggers when `polish` is not one of: `off`, `lossless`, `lossy`.

Fix: Use a valid polish value.

### J004 — Security warning: security_level set to off

| Severity | Category |
|----------|----------|
| WARNING | config |

Triggers when `security_level` is explicitly set to `off`.

Fix: Confirm this is intentional. If not, use a higher security level.

### J005 — Security warning: ssl set to off

| Severity | Category |
|----------|----------|
| WARNING | config |

Triggers when `ssl` is explicitly set to `off`. This disables SSL/TLS encryption, allowing traffic to travel unencrypted between Cloudflare and your origin.

```yaml
config_rules:
  - ref: disable-ssl
    expression: 'http.host eq "legacy.example.com"'
    action_parameters:
      ssl: off
```

Fix: Confirm this is intentional. If not, use `flexible`, `full`, `strict`, or `origin_pull`.

---

## Category K — Redirect Rules (2 rules)

### K001 — Invalid redirect status code

| Severity | Category |
|----------|----------|
| ERROR | redirect |

Triggers when the redirect `status_code` is not one of: 301, 302, 303, 307, 308.

Fix: Use a valid redirect status code.

### K002 — Missing target_url in redirect

| Severity | Category |
|----------|----------|
| ERROR | redirect |

Triggers when the redirect `from_value` dict is missing `target_url`.

Fix:

```yaml
action_parameters:
  from_value:
    target_url:
      value: "https://example.com/new-path"
    status_code: 301
```

---

## Category L — Transform Rules (6 rules)

### L002 — Empty header name in transform

| Severity | Category |
|----------|----------|
| ERROR | transform |

Triggers when a header name in a transform's `headers` dict is empty or blank.

Fix: Provide a non-empty header name.

### L003 — Missing operation in header transform

| Severity | Category |
|----------|----------|
| ERROR | transform |

Triggers when a header transform value dict is missing the `operation` key.

Fix:

```yaml
action_parameters:
  headers:
    x-custom-header:
      operation: set
      value: "custom-value"
```

### L004 — Invalid header transform operation

| Severity | Category |
|----------|----------|
| ERROR | transform |

Triggers when a header transform's `operation` value is not one of the valid operations: `set`, `remove`, `add`.

Fix: Use a valid operation value.

### L005 — Header set/add missing value or expression

| Severity | Category |
|----------|----------|
| ERROR | transform |

Triggers when a header transform with `operation: set` or `operation: add` has neither a `value` nor an `expression` key.

```yaml
request_header_rules:
  - ref: missing-value
    expression: 'true'
    action_parameters:
      headers:
        x-custom:
          operation: set     # missing value or expression
```

Fix:

```yaml
action_parameters:
  headers:
    x-custom:
      operation: set
      value: "my-value"
```

### L006 — Expression parse error in transform action_parameters

| Severity | Category |
|----------|----------|
| WARNING | transform |

Triggers when an expression embedded in transform `action_parameters` (e.g., `uri.path.expression`, `uri.query.expression`, or `headers.*.expression`) fails to parse.

Known transform function-call patterns (`regex_replace()`, `concat()`, `lower()`, etc.) are suppressed because wirefilter doesn't support the function-call syntax that Cloudflare accepts in transform phases.

```yaml
url_rewrite_rules:
  - ref: bad-rewrite
    expression: 'true'
    action_parameters:
      uri:
        path:
          expression: 'invalid syntax <<<'
```

Fix: Correct the expression syntax.

### L007 — Request headers do not support add operation

| Severity | Category |
|----------|----------|
| ERROR | transform |

Triggers when a header transform in `request_header_rules` uses `operation: add`. Cloudflare only supports `set` and `remove` for request header modifications. The `add` operation (append a value) is only available in `response_header_rules`.

```yaml
request_header_rules:
  - ref: add-header
    expression: 'true'
    action_parameters:
      headers:
        x-custom:
          operation: add       # not valid for request headers
          value: "my-value"
```

Fix: Use `operation: set` instead, or move the rule to `response_header_rules` if you need `add`.

---

## Category N — Origin Rules (1 rule)

### N001 — Port number out of range

| Severity | Category |
|----------|----------|
| ERROR | origin |

Triggers when `origin.port` is outside the 1–65535 range.

Fix: Use a valid port number between 1 and 65535.

---

## Category E — Function Constraints (6 rules)

### E001 — Unknown function in expression

| Severity | Category |
|----------|----------|
| WARNING | function |

Triggers when a function name in the expression is not recognized by the Cloudflare wirefilter function registry.

Fix: Check for typos or use a supported function.

### E002 — Function not available in this phase

| Severity | Category |
|----------|----------|
| WARNING | function |

Triggers when a function is valid but restricted to specific phases and is used in a different phase.

Fix: Move the rule to a phase where the function is available, or use an alternative function.

### E003 — regex_replace/wildcard_replace usage limit

| Severity | Category |
|----------|----------|
| ERROR | function |

Triggers when:
- `regex_replace` is used more than once per rule.
- `wildcard_replace` is used more than once per rule.
- Both `regex_replace` and `wildcard_replace` are used in the same rule.

Fix: Use only one replace function call per rule.

### E004 — Invalid encode_base64 flags

| Severity | Category |
|----------|----------|
| WARNING | function |

Triggers when `encode_base64()` is called with an invalid flag argument. Valid flags: `u` (URL-safe), `p` (no padding), `up` (both).

Fix: Use a valid flag value.

### E005 — Invalid url_decode options

| Severity | Category |
|----------|----------|
| WARNING | function |

Triggers when `url_decode()` is called with an invalid option. Valid options: `r` (recursive), `u` (uppercase percent-encoding), `ur` (both).

Fix: Use a valid option value.

### E006 — Invalid wildcard_replace flags

| Severity | Category |
|----------|----------|
| WARNING | function |

Triggers when `wildcard_replace()` is called with an invalid flag (4th argument). Valid flags: `s` (case-sensitive) or empty.

Fix: Use `s` for case-sensitive matching or omit the flag argument.

### E007 — Function source argument must be field

| Severity | Category |
|----------|----------|
| WARNING | function |

Triggers when certain functions receive a string literal instead of a field reference as their first (source) argument. Affected functions: `decode_base64`, `url_decode`, `starts_with`, `ends_with`, `wildcard_replace`.

```yaml
expression: 'starts_with("example.com", "/api")'
```

Fix: Pass a field reference as the first argument:

```yaml
expression: 'starts_with(http.request.uri.path, "/api")'
```

---

## Category F — Type System (3 rules)

### F001 — Operator-type incompatibility

| Severity | Category |
|----------|----------|
| ERROR | type |

Uses the full field type registry to detect operator-type mismatches:
- **String fields**: numeric operators (`gt`, `ge`, `lt`, `le`) with numeric values.
- **Integer fields**: string literal comparison (`eq "..."`) or string operators (`contains`, `matches`).
- **IP fields**: comparison operators (`gt`, `ge`, `lt`, `le`) or string operators (`contains`, `matches`).
- **Boolean fields**: string literal comparison (`eq "..."`).
- **Array/Map fields**: scalar operators (`eq`, `ne`, `gt`, `contains`, `matches`, etc.) used directly on the field.

```yaml
# String field with numeric operator
expression: 'http.host gt 5'

# Numeric field with string value
expression: 'cf.threat_score eq "high"'

# Array field with scalar operator
expression: 'http.request.headers.names eq "x-custom"'
```

Fix: Match operator and value types to the field type. For array/map fields, use `any()`, `all()`, `has_key()`, `has_value()`, or indexing.

### F002 — Unknown field name in expression

| Severity | Category |
|----------|----------|
| WARNING | type |

Triggers when a field name in the expression is not found in the Cloudflare field registry (170 known fields). Includes fuzzy matching — if a close match is found, a "Did you mean?" suggestion is provided.

```yaml
expression: 'http.hoost eq "example.com"'
```

Fix: Correct the field name. Check for typos.

### F003 — Array [*] unpacking on multiple arrays

| Severity | Category |
|----------|----------|
| WARNING | type |

Triggers when `[*]` (array unpacking) is used on more than one distinct array field in the same expression. Cloudflare only allows `[*]` to be applied to a single array within one expression.

```yaml
expression: 'any(http.request.headers.names[*] eq "x-custom") and any(http.request.cookies.names[*] eq "session")'
```

Fix: Split into separate rules, or restructure the expression to only unpack one array.

---

## Category G — Value Constraints (26 rules)

### G001 — HTTP method should be uppercase

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `http.request.method` is compared against a lowercase HTTP method.

```yaml
expression: 'http.request.method eq "get"'
```

Fix:

```yaml
expression: 'http.request.method eq "GET"'
```

### G002 — URI path should start with /

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `http.request.uri.path` is compared against a string that doesn't start with `/`.

```yaml
expression: 'http.request.uri.path eq "blog"'
```

Fix:

```yaml
expression: 'http.request.uri.path eq "/blog"'
```

### G003 — Regex anchor in literal value

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when a string literal contains `^` or `$` but is used with a non-regex operator (`eq`, `in`, `==`). Suggests using the `matches` operator instead.

```yaml
expression: 'http.request.uri.path eq "^/api/"'
```

Fix:

```yaml
expression: 'http.request.uri.path matches "^/api/"'
```

### G004 — Invalid country code format

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `ip.geoip.country` or `ip.src.country` is compared against a string that isn't a valid uppercase 2-letter ISO 3166-1 alpha-2 code.

```yaml
expression: 'ip.geoip.country eq "us"'
```

Fix:

```yaml
expression: 'ip.geoip.country eq "US"'
```

### G005 — Score value out of typical range

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when a score field is compared against a value outside its typical range. Each field has its own range: `cf.threat_score` (0–100), `cf.bot_management.score` (1–99), `cf.waf.score` (1–99), `cf.waf.score.sqli`/`xss`/`rce` (1–99), `cf.llm.prompt.injection_score` (1–99), `cf.edge.server_port` (1–65535). Only values specifically compared against the score field are checked — integer literals for other fields in the same expression are not flagged.

Fix: Use a score value within the field's valid range.

### G006 — Response code out of valid range

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `http.response.code` is compared against a value less than 100 or greater than 599.

Fix: Use a valid HTTP status code (100–599).

### G007 — Header name should be lowercase

| Severity | Category |
|----------|----------|
| INFO | value |

Triggers when header fields are compared against a header name that is not all-lowercase.

```yaml
expression: 'any(http.request.headers.names[*] eq "X-Custom-Header")'
```

Fix:

```yaml
expression: 'any(http.request.headers.names[*] eq "x-custom-header")'
```

### G008 — File extension should not start with a dot

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `http.request.uri.path.extension` is compared against a value starting with `.`.

```yaml
expression: 'http.request.uri.path.extension eq ".jpg"'
```

Fix:

```yaml
expression: 'http.request.uri.path.extension eq "jpg"'
```

### G009 — Duplicate value in `in` set

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when the same value appears more than once inside an `in {…}` set.

```yaml
expression: 'ip.src in {1.2.3.4 5.6.7.8 1.2.3.4}'
```

Fix:

```yaml
expression: 'ip.src in {1.2.3.4 5.6.7.8}'
```

### G010 — Deprecated field

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when the expression uses a deprecated `ip.geoip.*` field that has a newer `ip.src.*` replacement.

```yaml
expression: 'ip.geoip.country eq "US"'
```

Fix:

```yaml
expression: 'ip.src.country eq "US"'
```

Deprecated fields and replacements:
- `ip.geoip.asnum` → `ip.src.asnum`
- `ip.geoip.continent` → `ip.src.continent`
- `ip.geoip.country` → `ip.src.country`
- `ip.geoip.subdivision_1_iso_code` → `ip.src.subdivision_1_iso_code`
- `ip.geoip.subdivision_2_iso_code` → `ip.src.subdivision_2_iso_code`
- `ip.geoip.is_in_european_union` → `ip.src.is_in_european_union`

### G011 — Reserved/bogon IP address

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when an IP address or CIDR range in the expression falls within a reserved/bogon range. Cloudflare operates as a reverse proxy, so traffic from these ranges will never reach CF rules.

```yaml
expression: 'ip.src in {192.168.1.0/24}'
```

Fix: Use a public IP address or range.

Detected ranges: RFC 1918 private (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), loopback (127.0.0.0/8), link-local (169.254.0.0/16), CGNAT (100.64.0.0/10), documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), IANA special purpose (192.0.0.0/24), 6to4 relay anycast (192.88.99.0/24), benchmark testing (198.18.0.0/15), multicast (224.0.0.0/4), reserved for future use (240.0.0.0/4).

### G012 — Overlapping IP ranges

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when two IP ranges in the same expression overlap — the narrower range is redundant because it's already covered by the broader range.

```yaml
expression: 'ip.src in {10.0.0.1 10.0.0.0/8}'
```

Fix:

```yaml
expression: 'ip.src in {10.0.0.0/8}'
```

### G013 — Invalid value for field domain

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when a value compared against a field doesn't match the field's expected domain. Checked fields include:
- `http.host`: must not contain `/` (hostnames never have slashes — use `http.request.full_uri` for path matching)
- `http.request.method`: must be a recognized HTTP method (GET, HEAD, POST, PUT, DELETE, CONNECT, OPTIONS, TRACE, PATCH, PURGE)
- `http.request.full_uri` / `raw.http.request.full_uri`: must start with `http://` or `https://`
- `http.request.version`: must be one of HTTP/1.0, HTTP/1.1, HTTP/2, HTTP/3
- `http.request.body.mime` / `http.response.content_type.media_type`: must be lowercase and contain `/`
- `ip.src.continent`: must be one of AF, AN, AS, EU, NA, OC, SA, T1
- `cf.waf.score.class`: must be one of attack, likely_attack, likely_clean, clean
- `cf.tls_version`: must be one of TLSv1, TLSv1.1, TLSv1.2, TLSv1.3, none
- `cf.response.error_type`: must be one of 1xxx, 5xx, always_online, etc.
- `raw.http.request.uri.path`: must start with `/`
- `raw.http.request.uri.path.extension`: must be lowercase with no dots or slashes
- `http.request.timestamp.msec`: must be 0–999

Fix: Use a value that matches the field's expected domain.

### G014 — Timestamp value out of reasonable bounds

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `http.request.timestamp.sec` is compared against a value before Jan 2010 or more than 1 year in the future.

```yaml
expression: 'http.request.timestamp.sec gt 1000'
```

Fix: Use a realistic Unix timestamp value.

### G015 — Integer range overlap in `in` set

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when an integer value or range within an `in {…}` set is already covered by another range in the same set.

```yaml
expression: 'ip.src.asnum in {100 50..200}'
```

Fix:

```yaml
expression: 'ip.src.asnum in {50..200}'
```

### G016 — Value incompatible with lower()/upper()

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when a value compared against `lower()` contains uppercase characters, or a value compared against `upper()` contains lowercase characters.

```yaml
expression: 'lower(http.host) eq "EXAMPLE.COM"'
```

Fix: Use `"example.com"` (all lowercase) with `lower()`.

### G017 — len() compared to negative value

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `len()` is compared to a negative number. `len()` always returns >= 0.

Fix: Use 0 or a positive value.

### G018 — Invalid double-asterisk in wildcard

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when a wildcard pattern contains `**` (double asterisk), which is not valid in Cloudflare's wildcard syntax.

Fix: Use a single `*`.

### G019 — Integer range start greater than end

| Severity | Category |
|----------|----------|
| ERROR | value |

Triggers when an integer range in an `in {…}` set has start > end (e.g., `500..200`).

Fix: Swap the range bounds (e.g., `200..500`).

### G020 — split() limit outside valid range

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when the third argument to `split()` is less than 1 or greater than 128.

Fix: Use a limit between 1 and 128.

### G021 — cidr/cidr6 bit value out of range

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `cidr()` bit arguments are outside 0-32 or `cidr6()` bit argument is outside 0-128.

Fix: Use valid bit values for the IP address family.

### G022 — remove_query_args() wrong first argument

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when the first argument to `remove_query_args()` is not `http.request.uri.query` or `raw.http.request.uri.query`.

Fix: Pass the correct query field as the first argument.

### G023 — Invalid regex pattern in matches operator

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when a regex literal in a `matches` expression fails to compile. Catches unbalanced parentheses, bad quantifiers, invalid character classes, and other regex syntax errors before deployment.

```yaml
expression: 'http.request.uri.path matches "(unclosed"'
```

Fix: Correct the regex syntax. Test your pattern with a regex validator first.

### G024 — substring() index out of bounds or inverted

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `substring()` is called with non-negative start and end indices where end < start. Cloudflare's `substring()` supports negative indices (counting from end of string), so negative indices are not flagged.

```yaml
expression: 'substring(http.request.uri.path, 10, 5) eq "/api"'
```

Fix: Ensure end index >= start index, or use negative indices for end-relative offsets.

### G025 — lookup_json path should start with /

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `lookup_json_string()` or `lookup_json_integer()` is called with a JSON Pointer path that doesn't start with `/`. JSON Pointer paths (RFC 6901) must begin with a forward slash.

```yaml
expression: 'lookup_json_string(http.request.body.raw, "name") eq "test"'
```

Fix:

```yaml
expression: 'lookup_json_string(http.request.body.raw, "/name") eq "test"'
```

### G026 — bit_slice offset or size out of range

| Severity | Category |
|----------|----------|
| WARNING | value |

Triggers when `bit_slice()` is called with an offset or size outside the valid range. The offset must be between 0 and 2040, and the size must be between 1 and 32. `bit_slice` is only available in network (Magic Transit) phases.

```yaml
network_firewall_rules:
  - ref: bad-bit-slice
    expression: 'bit_slice(ip.hdr, 3000, 8) eq 0x45'   # offset > 2040
```

Fix: Use valid offset (0–2040) and size (1–32) values.

---

## Category B — Phase Restrictions (3 rules)

### B001 — Response field used in request phase

| Severity | Category |
|----------|----------|
| WARNING | phase |

Triggers when a response-only field (e.g., `http.response.code`, `http.response.headers.*`) is used in a request-phase expression.

Fix: Use a response phase (`response_header_rules`, `compression_rules`, `custom_error_rules`, `sensitive_data_detection`, `log_custom_fields`) or remove the response field.

### B002 — Request body field in phase without body access

| Severity | Category |
|----------|----------|
| WARNING | phase |

Triggers when a `http.request.body.*` field is used in a phase that doesn't have body access. Body-access phases: `waf_custom_rules`, `waf_managed_rules`, `rate_limiting_rules`, `custom_error_rules`.

Fix: Move the rule to a phase with body access.

### B003 — Field/function requires higher plan tier

| Severity | Category |
|----------|----------|
| WARNING | phase |

Triggers when a field or function requires a plan tier higher than the configured `--plan` tier. Examples:
- **Fields**: `cf.bot_management.score` requires Enterprise, `cf.waf.score` requires Enterprise.
- **Functions**: `sha256` requires Enterprise, `is_timed_hmac_valid_v0` requires Pro.

Fix: Upgrade to the required plan tier, or use an alternative field/function.

---

## Category O — Best Practice / Style (6 rules)

### O001 — Consider using in operator for multiple OR values

| Severity | Category |
|----------|----------|
| INFO | style |

Triggers when a field appears 3 or more times with `eq` or `==` in the same expression.

```yaml
expression: 'http.host eq "a.com" or http.host eq "b.com" or http.host eq "c.com"'
```

Fix:

```yaml
expression: 'http.host in {"a.com" "b.com" "c.com"}'
```

### O002 — Use normalized field instead of raw field

| Severity | Category |
|----------|----------|
| INFO | style |

Triggers when a `raw.*` field is used and a normalized equivalent exists.

```yaml
expression: 'raw.http.request.uri.path eq "/blog"'
```

Fix:

```yaml
expression: 'http.request.uri.path eq "/blog"'
```

### O003 — Redundant double negation

| Severity | Category |
|----------|----------|
| INFO | style |

Triggers when the expression contains `not not`.

```yaml
expression: 'not not http.host eq "example.com"'
```

Fix:

```yaml
expression: 'http.host eq "example.com"'
```

### O004 — Negated comparison can be simplified

| Severity | Category |
|----------|----------|
| INFO | style |

Triggers when an expression uses `not field op value` where the operator has a direct inverse.

```yaml
expression: 'not http.host eq "example.com"'
```

Fix:

```yaml
expression: 'http.host ne "example.com"'
```

Inverse mappings: eq↔ne, lt↔ge, gt↔le, ==↔!=.

### O005 — Illogical condition

| Severity | Category |
|----------|----------|
| WARNING | style |

Triggers in two cases:
- **Contradictory AND**: same field compared with `eq` to two different values joined by `and` — can never be true.
- **Tautological OR**: same field compared with `ne` (or `not field eq`) to two different values joined by `or` — always true.

```yaml
# Contradictory (always false)
expression: 'http.host eq "a.com" and http.host eq "b.com"'

# Tautological (always true)
expression: 'http.host ne "a.com" or http.host ne "b.com"'
```

Fix: Review the logic and correct the conditions.

### O006 — Regex pattern uses literal escapes

| Severity | Category |
|----------|----------|
| INFO | style |

Triggers when a `matches` operator uses a literal string (`"..."`) containing backslash escapes. Raw string format (`r"..."`) is clearer for regex patterns.

```yaml
expression: 'http.request.uri.path matches "\\.(js|css)$"'
```

Fix:

```yaml
expression: 'http.request.uri.path matches r"\.(js|css)$"'
```
