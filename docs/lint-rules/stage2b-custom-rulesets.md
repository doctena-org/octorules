# Stage 2b: Custom Ruleset Validation

Validates the `custom_rulesets` section for structural correctness. Checks required fields, ID format, and duplicate refs both within and across custom rulesets.

Individual rules inside custom rulesets are also validated through the standard per-rule checks (expression analysis, action validation, etc.) using the `waf_custom_rules` phase schema.

## Category T — Custom Ruleset Validation (4 rules)

### T001 — Missing required field

| Severity | Category |
|----------|----------|
| ERROR | custom_ruleset |

Triggers when a custom ruleset entry is missing one of the required fields: `id`, `name`, `phase`.

```yaml
custom_rulesets:
  - name: "My Ruleset"
    phase: http_request_firewall_custom
    rules: []
    # missing id
```

Fix: Add all required fields.

### T002 — Invalid id format

| Severity | Category |
|----------|----------|
| WARNING | custom_ruleset |

Triggers when a custom ruleset's `id` is not a valid 32-character lowercase hex string.

```yaml
custom_rulesets:
  - id: "not-a-hex-id"
    name: "My Ruleset"
    phase: http_request_firewall_custom
    rules: []
```

Fix: Use the correct 32-character hex ID from Cloudflare (e.g., `abc12345def67890abc12345def67890`).

### T003 — Duplicate ref within custom ruleset

| Severity | Category |
|----------|----------|
| ERROR | custom_ruleset |

Triggers when two rules within the same custom ruleset share the same `ref` value.

```yaml
custom_rulesets:
  - id: abc12345def67890abc12345def67890
    name: "My Ruleset"
    phase: http_request_firewall_custom
    rules:
      - ref: rule1
        expression: 'true'
        action: block
      - ref: rule1             # duplicate
        expression: 'true'
        action: log
```

Fix: Give each rule a unique `ref` within its custom ruleset.

### T004 — Duplicate ref across custom rulesets

| Severity | Category |
|----------|----------|
| WARNING | custom_ruleset |

Triggers when the same `ref` value appears in rules across different custom rulesets. While technically allowed by Cloudflare, this can cause confusion when reading logs or debugging rule behavior.

```yaml
custom_rulesets:
  - id: abc12345def67890abc12345def67890
    name: "Ruleset A"
    phase: http_request_firewall_custom
    rules:
      - ref: shared-ref
        expression: 'true'
        action: block
  - id: def12345abc67890def12345abc67890
    name: "Ruleset B"
    phase: http_request_firewall_custom
    rules:
      - ref: shared-ref       # same ref in different ruleset
        expression: 'true'
        action: log
```

Fix: Use unique ref values across all custom rulesets for clarity.
