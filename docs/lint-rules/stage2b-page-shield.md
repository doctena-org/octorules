# Stage 2b: Page Shield Policy Checks

Validates `page_shield_policies` entries for structural correctness and expression quality. Runs after per-phase checks with a dedicated module since Page Shield policies have a different structure (no `ref` field; `description` is the identity key).

Also checks M013/M014 (always-true/always-false) on policy expressions and delegates full expression analysis (E, F, G, O rules) to the AST linter.

## Category S — Page Shield Structure (4 rules)

### S001 — Missing required field

| Severity | Category |
|----------|----------|
| ERROR | page_shield |

Triggers when a policy is missing one of the 5 required fields: `description`, `action`, `expression`, `enabled`, `value`.

```yaml
page_shield_policies:
  - action: allow
    expression: "true"
    enabled: true
    value: "script-src 'self'"
    # missing description
```

Fix: Add all required fields.

### S002 — Invalid action

| Severity | Category |
|----------|----------|
| ERROR | page_shield |

Triggers when `action` is not `allow` or `log`.

```yaml
page_shield_policies:
  - description: "My policy"
    action: block           # must be allow or log
    expression: "true"
    enabled: true
    value: "script-src 'self'"
```

Fix: Use `action: allow` or `action: log`.

### S003 — Invalid field type

| Severity | Category |
|----------|----------|
| ERROR | page_shield |

Triggers when:
- `description` is not a string
- `enabled` is not a boolean
- `value` is not a string
- A policy entry is not a mapping

Fix: Use the correct type for each field.

### S004 — Duplicate description

| Severity | Category |
|----------|----------|
| WARNING | page_shield |

Triggers when two policies share the same `description`. Descriptions are identity keys — duplicates cause ambiguous matching.

```yaml
page_shield_policies:
  - description: "CSP policy"
    action: allow
    expression: "true"
    enabled: true
    value: "script-src 'self'"
  - description: "CSP policy"    # duplicate
    action: log
    expression: "true"
    enabled: true
    value: "default-src 'self'"
```

Fix: Give each policy a unique description.
