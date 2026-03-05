# Stage 1: YAML Structure Validation

Validates top-level keys, required fields, types, and structural correctness before any deeper analysis runs.

## Category M — Structure (15 rules)

### M001 — Missing ref field

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when:

```yaml
redirect_rules:
  - expression: 'http.host eq "example.com"'
    # no ref field
```

Fix:

```yaml
redirect_rules:
  - ref: my-redirect
    expression: 'http.host eq "example.com"'
```

### M002 — Missing expression field

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when:

```yaml
redirect_rules:
  - ref: my-redirect
    # no expression field
```

Fix:

```yaml
redirect_rules:
  - ref: my-redirect
    expression: 'http.host eq "example.com"'
```

### M003 — Duplicate ref within phase

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when two or more rules in the same phase share the same `ref` value.

```yaml
redirect_rules:
  - ref: my-rule
    expression: 'http.host eq "a.com"'
  - ref: my-rule          # duplicate
    expression: 'http.host eq "b.com"'
```

Fix: Give each rule a unique `ref` within its phase.

### M004 — Invalid ref type

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when `ref` is not a non-empty string (e.g., `ref: 123` or `ref: ""`).

Fix: Use a non-empty string for `ref`.

### M005 — Invalid expression type

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when `expression` is not a non-empty string (e.g., `expression: true` or `expression: ""`).

Fix: Use a non-empty string for `expression`.

### M006 — Invalid enabled type

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when `enabled` is present but not a boolean.

```yaml
- ref: my-rule
  expression: 'true'
  enabled: "yes"           # must be true or false
```

Fix: Use `enabled: true` or `enabled: false`.

### M007 — Unknown top-level phase key

| Severity | Category |
|----------|----------|
| WARNING | structure |

Triggers when a top-level key is not a recognized phase name or known non-phase key (`custom_rulesets`, `lists`, `page_shield_policies`). Includes "did you mean?" suggestions.

```yaml
redirecr_rules:            # typo
  - ref: my-rule
    expression: 'true'
```

Fix: Use the correct phase name (e.g., `redirect_rules`).

### M008 — Deprecated phase name

| Severity | Category |
|----------|----------|
| WARNING | structure |

Triggers when using a deprecated phase alias.

```yaml
waf_managed_exceptions:    # renamed to waf_managed_rules
  - ref: my-rule
    expression: 'true'
```

Fix: Use the current name `waf_managed_rules`.

### M009 — Description exceeds 500 characters

| Severity | Category |
|----------|----------|
| WARNING | structure |

Triggers when a rule's `description` field is longer than 500 characters.

Fix: Shorten the description.

### M010 — Phase value is not a list

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when a phase key's value is not a list.

```yaml
redirect_rules:
  ref: my-rule             # should be a list of rules
```

Fix: Wrap rules in a list.

```yaml
redirect_rules:
  - ref: my-rule
    expression: 'true'
```

### M011 — Rule entry is not a dict

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when an entry in a phase list is not a mapping.

```yaml
redirect_rules:
  - "just a string"        # must be a dict
```

Fix: Use a proper mapping with `ref` and `expression` keys.

### M012 — Cloudflare phase identifier used instead of friendly name

| Severity | Category |
|----------|----------|
| WARNING | structure |

Triggers when using the internal Cloudflare phase ID instead of the octorules friendly name.

```yaml
http_ratelimit:            # use rate_limiting_rules instead
  - ref: my-rule
    expression: 'true'
```

Fix: Use the friendly name (e.g., `rate_limiting_rules` instead of `http_ratelimit`).

### M013 — Expression is always true (catch-all)

| Severity | Category |
|----------|----------|
| WARNING | structure |

Triggers when the expression is `true`, `(true)`, or `((true))`. Flags catch-all rules that match all traffic.

Fix: Intentional catch-all rules can ignore this warning. Otherwise, add a specific expression.

### M014 — Expression is always false (dead rule)

| Severity | Category |
|----------|----------|
| WARNING | structure |

Triggers when the expression is `false`, `(false)`, or `((false))`. Flags rules that never match.

Fix: Remove the rule or fix the expression.

### M015 — Expression exceeds 4,096 character limit

| Severity | Category |
|----------|----------|
| ERROR | structure |

Triggers when the expression string is longer than 4,096 characters (the Cloudflare API limit).

Fix: Simplify the expression or split the rule into multiple rules.
